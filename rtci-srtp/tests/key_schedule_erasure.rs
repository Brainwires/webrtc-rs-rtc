//! RFC 7714 section 13.1: "All keys MUST be properly erased when no longer needed." What an
//! SRTP context keeps in the Rust heap, and whether it is erased when the context is dropped.
//!
//! `key_erasure.rs` checks the master keys and salts. This test checks every key a context
//! derives from them, in every form it may be kept (`key_material`): the session encryption,
//! authentication and salting keys of SRTP and SRTCP, each AES key's expanded schedule (its
//! round keys, FIPS-197 section 5.2) and, for AES-GCM, the GHASH key `H`; each HMAC-SHA1 key's
//! two hash states. They are computed by the test with its own AES, key derivation and SHA-1.
//!
//! A test allocator records every block allocated while the contexts are made and used, so the
//! blocks still live can be searched just before the drop ("found live": the bytes are in the
//! Rust heap, so the check can see them), and searches every block freed during the drop
//! ("left in freed memory": the bytes were not erased). Memory the provider allocates in C
//! (AWS-LC's `EVP_AEAD_CTX`) and stack frames are not seen here; `key_residue.rs` reads the
//! stack frames and (Linux) searches the whole process.

mod key_material;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crypto::RTCCryptoProvider;
use key_material::{Needle, context_needles, rtcp, rtp};
use rtci_srtp::context::Context;
use rtci_srtp::keying::{KeyDerivationRate, Keying};
use rtci_srtp::protection_profile::ProtectionProfile;

/// A master key and salt no other memory of the process holds by chance.
const MASTER_KEY: [u8; 32] = [
    0x3b, 0x91, 0x0c, 0xe4, 0x5a, 0x27, 0xd8, 0x66, 0xa1, 0x4f, 0x08, 0xbc, 0x73, 0x1e, 0xc9, 0x52,
    0x84, 0x2d, 0xf6, 0x39, 0x0b, 0xae, 0x57, 0x13, 0xe8, 0x6c, 0x95, 0x40, 0xd1, 0x7a, 0x2f, 0xb6,
];
const MASTER_SALT: [u8; 14] = [
    0x5e, 0xc2, 0x18, 0x97, 0x4b, 0xf0, 0x63, 0xad, 0x21, 0x8e, 0xd5, 0x0a, 0x76, 0xb9,
];

const MAX_NEEDLES: usize = 256;
const MAX_LIVE: usize = 16_384;

static CHECKING: AtomicBool = AtomicBool::new(false);
static TRACKING: AtomicBool = AtomicBool::new(false);
static NEEDLES: RwLock<Vec<Needle>> = RwLock::new(Vec::new());
/// Per needle: blocks freed while checking that held it.
static FREED: [AtomicU32; MAX_NEEDLES] = [const { AtomicU32::new(0) }; MAX_NEEDLES];
/// Blocks allocated while tracking and not yet freed: (address, size), 0 = empty.
static LIVE: [(AtomicUsize, AtomicUsize); MAX_LIVE] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_LIVE];
static LIVE_LOST: AtomicUsize = AtomicUsize::new(0);
static LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);

struct Recording;

unsafe impl GlobalAlloc for Recording {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && TRACKING.load(Ordering::SeqCst) {
            let slot = LIVE.iter().find(|(address, _)| {
                address
                    .compare_exchange(0, ptr as usize, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            });
            match slot {
                Some((_, size)) => {
                    size.store(layout.size(), Ordering::SeqCst);
                    LIVE_COUNT.fetch_add(1, Ordering::SeqCst);
                }
                None => {
                    LIVE_LOST.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if LIVE_COUNT.load(Ordering::SeqCst) > 0 {
            for (address, size) in &LIVE {
                if address.load(Ordering::SeqCst) == ptr as usize {
                    size.store(0, Ordering::SeqCst);
                    address.store(0, Ordering::SeqCst);
                    LIVE_COUNT.fetch_sub(1, Ordering::SeqCst);
                    break;
                }
            }
        }
        if CHECKING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until it is freed below.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            // A read lock: frees on several threads at once all check (a `try_lock` skipped
            // a block whenever two frees met, which could hide a key). The needles are written
            // only while not checking; the lock does not allocate.
            {
                let needles = NEEDLES.read().unwrap_or_else(|e| e.into_inner());
                for (i, needle) in needles.iter().enumerate() {
                    if needle.found_in(block) {
                        FREED[i].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Recording = Recording;

/// One test at a time looks at the allocator.
static SERIAL: Mutex<()> = Mutex::new(());

#[allow(clippy::vec_init_then_push)]
fn providers() -> Vec<Arc<dyn RTCCryptoProvider>> {
    let mut providers: Vec<Arc<dyn RTCCryptoProvider>> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(Arc::new(crypto::providers::RingProvider::new()));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push(Arc::new(crypto::providers::AwsLcRsProvider::new()));
    providers
}

/// What became of one needle.
#[derive(Clone, Copy)]
struct Finding {
    needle: Needle,
    live: bool,
    freed: u32,
}

/// Makes a sending and a receiving context of `profile` with `provider`, protects and
/// unprotects RTP and RTCP with them, then drops them; returns, for every key the contexts
/// derive, whether it was found in a live block before the drop and in how many blocks freed
/// during it.
fn session(provider: &Arc<dyn RTCCryptoProvider>, profile: ProtectionProfile) -> Vec<Finding> {
    let (key, salt) = key_material::per_profile(profile, &MASTER_KEY, &MASTER_SALT);
    let master_key = &key[..profile.key_len()];
    let master_salt = &salt[..if profile.is_aead() { 12 } else { 14 }];
    let needles = context_needles(profile, master_key, master_salt);
    assert!(needles.len() <= MAX_NEEDLES);
    for counter in &FREED {
        counter.store(0, Ordering::SeqCst);
    }
    *NEEDLES.write().unwrap_or_else(|e| e.into_inner()) = needles.clone();

    TRACKING.store(true, Ordering::SeqCst);
    let keying = Keying {
        key_derivation_rate: KeyDerivationRate::ZERO,
        mki: None,
    };
    let context = || {
        Box::new(
            Context::with_keying(
                master_key,
                master_salt,
                profile,
                keying.clone(),
                None,
                None,
                provider.clone(),
            )
            .expect("a context"),
        )
    };
    let mut sender = context();
    let mut receiver = context();
    for sequence_number in 0..4 {
        let protected = sender.encrypt_rtp(&rtp(sequence_number)).expect("SRTP");
        receiver.decrypt_rtp(&protected).expect("unprotected SRTP");
        let protected = sender.encrypt_rtcp(&rtcp()).expect("SRTCP");
        receiver
            .decrypt_rtcp(&protected)
            .expect("unprotected SRTCP");
    }
    TRACKING.store(false, Ordering::SeqCst);

    let mut live = vec![false; needles.len()];
    for (address, size) in &LIVE {
        let (ptr, len) = (address.load(Ordering::SeqCst), size.load(Ordering::SeqCst));
        if ptr == 0 || len == 0 {
            continue;
        }
        // SAFETY: the block is live (its dealloc would have cleared the slot) and nothing else
        // runs while the serial lock is held; the bytes are only read.
        let block = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
        for (i, needle) in needles.iter().enumerate() {
            live[i] |= needle.found_in(block);
        }
    }

    CHECKING.store(true, Ordering::SeqCst);
    drop(sender);
    drop(receiver);
    CHECKING.store(false, Ordering::SeqCst);
    for (address, size) in &LIVE {
        size.store(0, Ordering::SeqCst);
        address.store(0, Ordering::SeqCst);
    }
    LIVE_COUNT.store(0, Ordering::SeqCst);
    assert_eq!(
        0,
        LIVE_LOST.load(Ordering::SeqCst),
        "the live table overflowed"
    );

    needles
        .iter()
        .enumerate()
        .map(|(i, needle)| Finding {
            needle: *needle,
            live: live[i],
            freed: FREED[i].load(Ordering::SeqCst),
        })
        .collect()
}

/// Every profile with every provider of the build, printed as a table.
fn every_session() -> Vec<(&'static str, ProtectionProfile, Vec<Finding>)> {
    key_material::check_local_primitives();
    let mut out = Vec::new();
    for provider in providers() {
        for profile in ProtectionProfile::ALL {
            let findings = session(&provider, profile);
            for f in &findings {
                println!(
                    "HEAP {:<12} {:<22} {:<58} live {:<5} left in freed memory {}",
                    provider.name(),
                    format!("{profile:?}"),
                    f.needle.describe(),
                    f.live,
                    f.freed
                );
            }
            out.push((provider.name(), profile, findings));
        }
    }
    out
}

fn left_behind(
    sessions: &[(&'static str, ProtectionProfile, Vec<Finding>)],
    keep: impl Fn(&str, ProtectionProfile, &Finding) -> bool,
) -> Vec<String> {
    sessions
        .iter()
        .flat_map(|(provider, profile, findings)| {
            findings
                .iter()
                .filter(|f| f.freed > 0 && keep(provider, *profile, f))
                .map(move |f| format!("{provider} {profile:?}: {}", f.needle.describe()))
        })
        .collect()
}

/// The keys the crate itself holds (the AES-CM session encryption keys, the authentication
/// and salting keys, the master key) are never left in freed memory, whatever the provider and
/// profile: they live in zeroizing buffers (`SecretVec`).
#[test]
fn keys_the_crate_holds_are_erased_with_every_provider() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let sessions = every_session();
    let left = left_behind(&sessions, |_, _, f| f.needle.crate_held);
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// AWS-LC's key objects that live in the Rust heap (its HMAC contexts) are erased: a needle
/// found in a live block is in no block freed by the drop. Its AES-GCM contexts are in C memory,
/// which `key_residue.rs` searches.
#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn aws_lc_leaves_no_key_in_freed_rust_memory() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let sessions = every_session();
    let left = left_behind(&sessions, |provider, _, _| provider == "aws-lc-rs");
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// With the ring provider no key is left in freed memory, for every profile: the keys the
/// crate holds, the HMAC-SHA1 states of the AES-CM and NULL profiles' authentication keys
/// (RustCrypto `hmac` and `sha1`, which `rtci-crypto` uses for the ring provider, with their
/// `zeroize` features: overwritten when a context is dropped; left in freed memory in 0.1.0) and ring's own AES-GCM key objects
/// (`ring::aead::LessSafeKey`: the session key and every AES round key), which `rtci-crypto`
/// keeps in an allocation of its own and overwrites after ring has dropped them (left in freed
/// memory in 0.1.0, a known limit of that provider). Each is found live first: the needles are
/// the forms the objects keep, so "not found after the drop" means erased.
#[cfg(feature = "crypto-ring")]
#[test]
fn with_ring_no_key_is_left_in_freed_rust_memory() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let sessions = every_session();
    let ring = || {
        sessions
            .iter()
            .filter(|(provider, _, _)| *provider == "ring")
    };
    let hmac_states_live =
        ring()
            .filter(|(_, profile, _)| !profile.is_aead())
            .all(|(_, _, findings)| {
                findings
                    .iter()
                    .any(|f| f.live && f.needle.form.starts_with("HMAC inner state"))
            });
    assert!(
        hmac_states_live,
        "the HMAC-SHA1 states are found live with ring, for every AES-CM and NULL profile"
    );
    let aead_keys_live =
        ring()
            .filter(|(_, profile, _)| profile.is_aead())
            .all(|(_, _, findings)| {
                findings.iter().any(|f| {
                    f.live && !f.needle.crate_held && f.needle.key.ends_with("encryption key")
                })
            });
    assert!(
        aead_keys_live,
        "ring's AES-GCM key objects are found live (the session key or a round key), for both \
         AEAD profiles"
    );
    let left = left_behind(&sessions, |provider, _, _| provider == "ring");
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// The check itself: an expanded key boxed and dropped without erasure is seen, both live and
/// in freed memory.
#[test]
fn the_allocator_sees_a_key_schedule_left_behind() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let key = [0x42u8; 16];
    let needles = {
        let mut all = context_needles(ProtectionProfile::AeadAes128Gcm, &key, &[0x24; 12]);
        all.retain(|n| n.key == "master key" && n.form == "round key 5");
        all
    };
    assert_eq!(1, needles.len());
    for counter in &FREED {
        counter.store(0, Ordering::SeqCst);
    }
    *NEEDLES.write().unwrap_or_else(|e| e.into_inner()) = needles.clone();
    let careless = Box::new(key_material::Schedule::expand(&key).bytes);
    assert!(needles[0].found_in(&careless[..]), "found live");
    CHECKING.store(true, Ordering::SeqCst);
    drop(careless);
    CHECKING.store(false, Ordering::SeqCst);
    assert!(FREED[0].load(Ordering::SeqCst) > 0, "found in freed memory");
}

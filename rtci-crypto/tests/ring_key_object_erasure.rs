//! The ring provider's key objects are erased when they are dropped (RFC 7714 section 13.1,
//! RFC 8446 section 7.1): its AES-GCM and ChaCha20-Poly1305 AEAD keys
//! (`ring::aead::LessSafeKey`), its record-number (QUIC header-protection) keys
//! (`ring::aead::quic::HeaderProtectionKey`) and its HMAC-SHA-2 keys (`ring::hmac::Key`).
//!
//! ring keeps each key schedule inline in the object and does not overwrite it on drop;
//! `rtci-crypto` keeps the object in an allocation of its own and overwrites that allocation
//! after the drop. A test allocator records the blocks allocated while an object is made and
//! used, searches them before the drop ("found live": the bytes the object keeps are the ones
//! looked for, so the search can see them), and searches every block freed from the start of
//! the construction to the end of the drop ("left in freed memory").
//!
//! What is looked for, in the form ring keeps it: an AES key as the first round key, which is
//! the key itself in the AES-NI and ARMv8 key schedules (every CI runner has one of the two;
//! a machine without them uses ring's bit-sliced schedule, where the live check fails and says
//! so); a ChaCha20 key as its eight little-endian words, which are its bytes on a
//! little-endian machine; an HMAC key as its two SHA-2 states after one block of
//! `key XOR ipad` and `key XOR opad`, in native byte order (computed here with the `sha2`
//! compression function, not ring's). Every needle is kept complemented, so the test's own
//! copies never match.
//!
//! The control: ring's own `LessSafeKey` boxed and dropped as it is leaves the key in the freed
//! block (this is what 0.1.0 did).

#![cfg(feature = "crypto-ring")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

use rtci_crypto::providers::RingProvider;
use rtci_crypto::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, HeaderMask, HeaderMaskAlgorithm, HmacAlgorithm,
    Mac, RTCCrypto, RTCCryptoProvider, SignatureScheme, SigningKey,
};
use sha2::digest::generic_array::GenericArray;
use std::sync::Arc;

const MAX_NEEDLES: usize = 8;
const MAX_LIVE: usize = 4096;

static TRACKING: AtomicBool = AtomicBool::new(false);
static CHECKING: AtomicBool = AtomicBool::new(false);
/// The needles, complemented.
static NEEDLES: RwLock<Vec<Vec<u8>>> = RwLock::new(Vec::new());
/// Per needle: blocks freed while checking that held it.
static FREED: [AtomicU32; MAX_NEEDLES] = [const { AtomicU32::new(0) }; MAX_NEEDLES];
/// Blocks allocated while tracking and not yet freed: (address, size), 0 = empty.
static LIVE: [(AtomicUsize, AtomicUsize); MAX_LIVE] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_LIVE];
static LIVE_LOST: AtomicUsize = AtomicUsize::new(0);

fn holds(block: &[u8], complemented: &[u8]) -> bool {
    block.len() >= complemented.len()
        && block
            .windows(complemented.len())
            .any(|w| w.iter().zip(complemented).all(|(b, n)| *b == !*n))
}

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
                Some((_, size)) => size.store(layout.size(), Ordering::SeqCst),
                None => {
                    LIVE_LOST.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        for (address, size) in &LIVE {
            if address.load(Ordering::SeqCst) == ptr as usize {
                size.store(0, Ordering::SeqCst);
                address.store(0, Ordering::SeqCst);
                break;
            }
        }
        if CHECKING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until it is freed below;
            // its bytes are only read.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            // A read lock: frees on several threads at once all check (a `try_lock` skipped
            // a block whenever two frees met, which could hide a key). The needles are written
            // only while not checking; the lock does not allocate.
            {
                let needles = NEEDLES.read().unwrap_or_else(|e| e.into_inner());
                for (i, needle) in needles.iter().enumerate() {
                    if holds(block, needle) {
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

/// One test at a time uses the allocator.
static SERIAL: Mutex<()> = Mutex::new(());

/// A key object of the provider, to be used and dropped.
enum Object {
    Aead(Box<dyn AeadCipher>),
    Mask(Box<dyn HeaderMask>),
    Mac(Box<dyn Mac>),
    Signing(Arc<dyn SigningKey>, SignatureScheme),
    /// An ECDHE key exchange, completed with the peer's public key when the object is
    /// finished (after the live search); the shared secret it gives must be `expected`
    /// (complemented).
    Exchange {
        exchange: Option<Box<dyn ActiveKeyExchange>>,
        peer_public: Vec<u8>,
        expected: Vec<u8>,
    },
    /// The control: something boxed and dropped as it is.
    Plain(Box<dyn std::any::Any>),
}

impl Object {
    fn exercise(&mut self) {
        match self {
            Object::Aead(aead) => {
                let mut data = *b"sixteen bytes!!!";
                let mut tag = [0u8; 16];
                aead.seal_in_place(&[7; 12], b"aad", &mut data, &mut tag)
                    .expect("sealed");
                aead.open_in_place(&[7; 12], b"aad", &mut data, &tag)
                    .expect("opened");
            }
            Object::Mask(mask) => {
                mask.mask(&[9; 16]).expect("a mask");
            }
            Object::Mac(mac) => {
                let mut tag = vec![0u8; mac.output_len()];
                mac.sign(&[b"input"], &mut tag).expect("a MAC");
            }
            Object::Signing(key, scheme) => {
                key.sign(*scheme, b"message").expect("a signature");
            }
            Object::Exchange { .. } => {}
            Object::Plain(object) => {
                std::hint::black_box(&**object);
            }
        }
    }

    /// What is done with the object after the live search, before it is dropped.
    fn finish(&mut self) {
        if let Object::Exchange {
            exchange,
            peer_public,
            expected,
        } = self
        {
            let shared = exchange
                .take()
                .expect("not yet completed")
                .complete(peer_public)
                .expect("a shared secret");
            assert!(
                shared
                    .as_ref()
                    .iter()
                    .zip(expected.iter())
                    .all(|(s, e)| *s == !*e)
                    && shared.len() == expected.len(),
                "the shared secret is the one computed before"
            );
        }
    }
}

/// What became of the needles of one object: found live before the drop, and in how many
/// blocks freed from construction to drop.
struct Outcome {
    live: Vec<bool>,
    freed: Vec<u32>,
}

fn run(needles: &[Vec<u8>], make: impl FnOnce() -> Object) -> Outcome {
    assert!(needles.len() <= MAX_NEEDLES);
    let complemented: Vec<Vec<u8>> = needles
        .iter()
        .map(|n| n.iter().map(|b| !b).collect())
        .collect();
    *NEEDLES.write().unwrap_or_else(|e| e.into_inner()) = complemented.clone();
    for counter in &FREED {
        counter.store(0, Ordering::SeqCst);
    }
    LIVE_LOST.store(0, Ordering::SeqCst);

    TRACKING.store(true, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let mut object = make();
    object.exercise();
    object.exercise();
    TRACKING.store(false, Ordering::SeqCst);
    let mut live = vec![false; needles.len()];
    for (address, size) in &LIVE {
        let (ptr, len) = (address.load(Ordering::SeqCst), size.load(Ordering::SeqCst));
        if ptr == 0 || len == 0 {
            continue;
        }
        // SAFETY: the block is live (its dealloc would have cleared the slot) and nothing else
        // runs while the serial lock is held; its bytes are only read.
        let block = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
        for (i, needle) in complemented.iter().enumerate() {
            live[i] |= holds(block, needle);
        }
    }
    object.finish();
    drop(object);
    CHECKING.store(false, Ordering::SeqCst);
    for (address, size) in &LIVE {
        size.store(0, Ordering::SeqCst);
        address.store(0, Ordering::SeqCst);
    }
    assert_eq!(
        0,
        LIVE_LOST.load(Ordering::SeqCst),
        "the live table overflowed"
    );
    Outcome {
        live,
        freed: (0..needles.len())
            .map(|i| FREED[i].load(Ordering::SeqCst))
            .collect(),
    }
}

/// Keys no other memory of the process holds by chance.
const KEY_128: [u8; 16] = [
    0x6d, 0x1e, 0xa3, 0x58, 0xc4, 0x0b, 0x97, 0x2f, 0xe8, 0x35, 0x71, 0xbd, 0x0c, 0x5a, 0xf2, 0x86,
];
const KEY_256: [u8; 32] = [
    0x93, 0x4c, 0x27, 0xd1, 0x6a, 0xb5, 0x0e, 0xf8, 0x31, 0xc7, 0x5d, 0x82, 0x1b, 0xe6, 0x49, 0xa0,
    0x7f, 0x14, 0xcb, 0x3e, 0x95, 0x62, 0xd8, 0x0a, 0xb3, 0x47, 0xec, 0x21, 0x8d, 0x56, 0xfa, 0x19,
];

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA384_IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];
const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The two HMAC states of `key` (shorter than a block): the hash state after one block of
/// `key XOR ipad`, then of `key XOR opad`, as native-endian words.
fn hmac_states(algorithm: HmacAlgorithm, key: &[u8]) -> Vec<Vec<u8>> {
    [0x36u8, 0x5c]
        .iter()
        .map(|pad| match algorithm {
            HmacAlgorithm::Sha256 => {
                let mut block = [*pad; 64];
                block.iter_mut().zip(key).for_each(|(b, k)| *b ^= k);
                let mut state = SHA256_IV;
                sha2::compress256(&mut state, &[GenericArray::clone_from_slice(&block)]);
                state.iter().flat_map(|w| w.to_ne_bytes()).collect()
            }
            HmacAlgorithm::Sha384 | HmacAlgorithm::Sha512 => {
                let mut block = [*pad; 128];
                block.iter_mut().zip(key).for_each(|(b, k)| *b ^= k);
                let mut state = if algorithm == HmacAlgorithm::Sha384 {
                    SHA384_IV
                } else {
                    SHA512_IV
                };
                sha2::compress512(&mut state, &[GenericArray::clone_from_slice(&block)]);
                state.iter().flat_map(|w| w.to_ne_bytes()).collect()
            }
            other => unreachable!("{other:?}: not a ring HMAC in the ring provider"),
        })
        .collect()
}

fn crypto() -> &'static dyn RTCCrypto {
    static PROVIDER: RingProvider = RingProvider::new();
    PROVIDER.crypto()
}

/// Every ring key object of the provider, with the needles of its key.
fn cases() -> Vec<(String, Vec<Vec<u8>>, Box<dyn Fn() -> Object>)> {
    let mut cases: Vec<(String, Vec<Vec<u8>>, Box<dyn Fn() -> Object>)> = Vec::new();
    for (algorithm, key) in [
        (AeadAlgorithm::Aes128Gcm, &KEY_128[..]),
        (AeadAlgorithm::Aes256Gcm, &KEY_256[..]),
        (AeadAlgorithm::ChaCha20Poly1305, &KEY_256[..]),
    ] {
        cases.push((
            format!("AEAD {algorithm:?}"),
            vec![key.to_vec()],
            Box::new(move || Object::Aead(crypto().new_aead(algorithm, key).expect("an AEAD"))),
        ));
    }
    for (algorithm, key) in [
        (HeaderMaskAlgorithm::Aes128, &KEY_128[..]),
        (HeaderMaskAlgorithm::Aes256, &KEY_256[..]),
        (HeaderMaskAlgorithm::ChaCha20, &KEY_256[..]),
    ] {
        cases.push((
            format!("header protection {algorithm:?}"),
            vec![key.to_vec()],
            Box::new(move || {
                Object::Mask(
                    crypto()
                        .new_header_mask(algorithm, key)
                        .expect("a header mask"),
                )
            }),
        ));
    }
    for algorithm in [
        HmacAlgorithm::Sha256,
        HmacAlgorithm::Sha384,
        HmacAlgorithm::Sha512,
    ] {
        cases.push((
            format!("HMAC {algorithm:?}"),
            hmac_states(algorithm, &KEY_256),
            Box::new(move || Object::Mac(crypto().new_hmac(algorithm, &KEY_256).expect("an HMAC"))),
        ));
    }
    cases
}

/// Every key object of the ring provider (AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
/// AEADs; AES-128, AES-256 and ChaCha20 header protection; HMAC-SHA-256, -384 and -512) keeps
/// its key in the heap while alive (found live: the forms looked for are right) and leaves it
/// in no block freed from its construction to its drop.
#[test]
fn ring_key_objects_are_erased_when_dropped() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut not_live = Vec::new();
    let mut left = Vec::new();
    for (what, needles, make) in cases() {
        let outcome = run(&needles, make);
        println!(
            "RING {what:<32} live {:?} left in freed memory {:?}",
            outcome.live, outcome.freed
        );
        if !outcome.live.iter().all(|live| *live) {
            not_live.push(what.clone());
        }
        if outcome.freed.iter().any(|freed| *freed > 0) {
            left.push(what);
        }
    }
    assert!(
        not_live.is_empty(),
        "not found while alive (the search cannot vouch for these): {not_live:#?}"
    );
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// The control: ring's own AES-128-GCM key object, boxed and dropped without the crate's
/// overwrite, leaves the key in the freed block; the search sees it.
#[test]
fn a_ring_key_object_dropped_as_it_is_leaves_its_key() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let outcome = run(&[KEY_128.to_vec()], || {
        let key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &KEY_128)
            .expect("an AES-128-GCM key");
        Object::Plain(Box::new(ring::aead::LessSafeKey::new(key)))
    });
    assert!(outcome.live[0], "found live");
    assert!(outcome.freed[0] > 0, "found in freed memory");
}

/// RFC 8446 section 7.1, RFC 5246 section 8.1: the ring provider's ECDHE private key (the
/// scalar seed `ring::agreement::EphemeralPrivateKey` keeps inline; X25519 and P-256) is found
/// live in the key-exchange object and is left in no block freed while the exchange completes
/// and its shared secret is dropped; neither is the shared secret. The private key is drawn
/// from a known seed through the test-support seam; the code path is the provider's.
#[cfg(feature = "test-support")]
#[test]
fn ring_ecdhe_private_key_and_shared_secret_are_erased() {
    use rtci_crypto::KeyExchangeAlgorithm;
    use rtci_crypto::providers::ring_key_exchange_with_seed;
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const SEED: [u8; 32] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19,
        0x0c, 0xfe,
    ];
    const PEER_SEED: [u8; 32] = [
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
        0xf4, 0x5c, 0x47, 0x2e, 0x10, 0x3a, 0x22, 0x91, 0xc8, 0x0e, 0x6b, 0x55, 0x04, 0x43, 0x3d,
        0x7f, 0x12,
    ];
    let mut not_live = Vec::new();
    let mut left = Vec::new();
    for algorithm in [KeyExchangeAlgorithm::X25519, KeyExchangeAlgorithm::P256] {
        let peer = ring_key_exchange_with_seed(algorithm, &PEER_SEED).expect("the peer");
        let peer_public = peer.public_key().to_vec();
        drop(peer);
        let shared = ring_key_exchange_with_seed(algorithm, &SEED)
            .expect("a key exchange")
            .complete(&peer_public)
            .expect("a shared secret");
        let expected: Vec<u8> = shared.as_ref().iter().map(|b| !b).collect();
        let shared_plain = shared.as_ref().to_vec();
        drop(shared);
        let outcome = run(&[SEED.to_vec(), shared_plain.clone()], || {
            Object::Exchange {
                exchange: Some(
                    ring_key_exchange_with_seed(algorithm, &SEED).expect("a key exchange"),
                ),
                peer_public: peer_public.clone(),
                expected: expected.clone(),
            }
        });
        println!(
            "RING ECDHE {algorithm:?}: private key live {}, left in freed memory: private key {}, shared secret {}",
            outcome.live[0], outcome.freed[0], outcome.freed[1]
        );
        if !outcome.live[0] {
            not_live.push(format!("{algorithm:?}"));
        }
        if outcome.freed.iter().any(|freed| *freed > 0) {
            left.push(format!("{algorithm:?}: {:?}", outcome.freed));
        }
    }
    assert!(
        not_live.is_empty(),
        "the private key was not found while alive: {not_live:#?}"
    );
    assert!(
        left.is_empty(),
        "left in freed memory (private key, shared secret): {left:#?}"
    );
}

/// The ring provider's signing key objects, which the crate makes from the PKCS#8 the
/// application supplies (the application's own copies are its to protect): an Ed25519 key
/// (its secret prefix, the second half of SHA-512 of the seed, RFC 8032 section 5.1.5) and an
/// ECDSA P-256 key (its scalar in the Montgomery form ring keeps, `d * 2^256 mod n`, as
/// little-endian words) are found live and left in no freed block once the key is dropped.
#[test]
fn ring_signing_key_objects_are_erased_when_dropped() {
    use num_bigint::BigUint;
    use sha2::{Digest, Sha512};
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    #[allow(deprecated)]
    let fixed = |bytes: &'static [u8]| ring::test::rand::FixedSliceRandom { bytes };
    const ED_SEED: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    const P256_D: [u8; 32] = [
        0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58, 0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77,
        0x1a, 0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac, 0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72,
        0xb4, 0x64,
    ];
    let ed_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&fixed(&ED_SEED))
        .expect("an Ed25519 PKCS#8");
    let ed_prefix = Sha512::digest(ED_SEED)[32..].to_vec();
    let p256_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &fixed(&P256_D),
    )
    .expect("a P-256 PKCS#8");
    let n = BigUint::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .expect("the P-256 order");
    let montgomery = (BigUint::from_bytes_be(&P256_D) << 256u32) % &n;
    let mut p256_needle = montgomery.to_bytes_le();
    p256_needle.resize(32, 0);
    let mut not_live = Vec::new();
    let mut left = Vec::new();
    for (scheme, pkcs8, needle) in [
        (
            SignatureScheme::Ed25519,
            ed_pkcs8.as_ref().to_vec(),
            ed_prefix,
        ),
        (
            SignatureScheme::EcdsaP256Sha256,
            p256_pkcs8.as_ref().to_vec(),
            p256_needle,
        ),
    ] {
        let outcome = run(std::slice::from_ref(&needle), || {
            Object::Signing(
                crypto()
                    .import_signing_key(scheme, &pkcs8)
                    .expect("a signing key"),
                scheme,
            )
        });
        println!(
            "RING signing key {scheme:?}: live {:?} left in freed memory {:?}",
            outcome.live, outcome.freed
        );
        if !outcome.live[0] {
            not_live.push(format!("{scheme:?}"));
        }
        if outcome.freed[0] > 0 {
            left.push(format!("{scheme:?}"));
        }
    }
    assert!(
        not_live.is_empty(),
        "not found while alive (the search cannot vouch for these): {not_live:#?}"
    );
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

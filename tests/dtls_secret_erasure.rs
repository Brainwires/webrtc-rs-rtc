//! Every secret of a DTLS association is erased when it is no longer needed: RFC 5246 section
//! 8.1 (the premaster secret "should be deleted from memory once the master_secret has been
//! computed"), RFC 8446 section 7.1 (a secret "SHOULD be erased" once what derives from it is
//! computed), RFC 7714 section 13.1 for the SRTP keys a DTLS-SRTP
//! association exports (RFC 5764 section 4.2), and the project's rule that memory a secret was
//! in is overwritten before it is freed.
//!
//! How it looks. The association runs over a crypto provider that wraps the real one and
//! records, kept only inverted (each byte complemented, so the record itself never matches),
//! every secret that crosses the provider boundary: each (EC)DHE shared secret, every key an
//! HMAC, AEAD, CBC or header-mask object is made with, and what each HMAC is first asked to
//! sign. From those the test computes, with the provider's own HMAC (not `rtci-dtls`'s PRF),
//! what the association derives from them: the DTLS 1.2 PRF outputs (master secret, key block,
//! exporter output) with their intermediate `A(i)` values (RFC 5246 section 5), and every DTLS
//! 1.3 `HKDF-Expand-Label` output (RFC 8446 section 7.1: traffic secrets, keys, IVs,
//! record-number keys, finished keys, resumption and exporter secrets). It also knows what the
//! application gives: the PSKs.
//!
//! A test allocator keeps every block freed while the association runs (a quarantine: no
//! block is handed back to the system until the end), then searches each one for every secret
//! found. A block that still holds one was freed without being erased. That includes the
//! blocks of the ring provider's own key objects (its AES-GCM, ChaCha20-Poly1305,
//! header-protection and HMAC keys): ring does not erase them itself, so `rtci-crypto` keeps
//! each in an allocation of its own and overwrites it after the drop (until 0.2 they were
//! left out of the search, a known limit of that provider). Memory AWS-LC allocates in C is
//! not in the Rust heap; on Linux the process-memory test below searches the whole process.
//!
//! The needles are checked against what the association used (the key block recomputed holds
//! the record keys the provider was handed, the exporter output recomputed is what the
//! association exported), so a wrong computation cannot make a test pass by finding nothing.

#![cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rtci::crypto::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher,
    CryptoAlgorithm, CryptoError, HashAlgorithm, HeaderMask, HeaderMaskAlgorithm, HmacAlgorithm,
    KeyExchangeAlgorithm, Mac, PublicKey, RTCCrypto, RTCCryptoProvider, RTCRandom, SecretVec,
    SignatureScheme, SigningKey, StreamCipher, StreamCipherAlgorithm,
};
use rtci::dtls::cipher_suite::CipherSuiteId;
use rtci::dtls::config::{ConfigBuilder, DtlsVersion, HandshakeConfig};
use rtci::dtls::crypto::Certificate;
use rtci::dtls::endpoint::{Endpoint, EndpointEvent};
use rtci::dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rtci::dtls::session::{ExternalPsk, MemorySessionStore};
use rtci::dtls::state::State;
use rtci::shared::TransportProtocol;
use rtci::srtp::config::{Config, LABEL_EXTRACTOR_DTLS_SRTP};
use rtci::srtp::context::Context;
use rtci::srtp::protection_profile::ProtectionProfile;

// ---------------------------------------------------------------------------------------------
// The quarantine allocator.

/// Blocks the quarantine can hold; a session frees a few thousand.
const QUARANTINE: usize = 1 << 17;

static WINDOW: AtomicBool = AtomicBool::new(false);
static QUARANTINED: AtomicUsize = AtomicUsize::new(0);
static OVERFLOWED: AtomicUsize = AtomicUsize::new(0);
static BLOCK_ADDRESS: [AtomicUsize; QUARANTINE] = [const { AtomicUsize::new(0) }; QUARANTINE];
static BLOCK_SIZE: [AtomicUsize; QUARANTINE] = [const { AtomicUsize::new(0) }; QUARANTINE];
static BLOCK_ALIGN: [AtomicUsize; QUARANTINE] = [const { AtomicUsize::new(0) }; QUARANTINE];

/// Blocks allocated while the window is open and not yet freed: an open-addressing table of
/// (address, size); 0 is an empty slot, `usize::MAX` a freed one.
const LIVE_SLOTS: usize = 1 << 18;
static LIVE_ADDRESS: [AtomicUsize; LIVE_SLOTS] = [const { AtomicUsize::new(0) }; LIVE_SLOTS];
static LIVE_SIZE: [AtomicUsize; LIVE_SLOTS] = [const { AtomicUsize::new(0) }; LIVE_SLOTS];
static LIVE_FULL: AtomicUsize = AtomicUsize::new(0);
/// The live table is kept up to date (frees after the window closes too, until the search).
static TRACKING: AtomicBool = AtomicBool::new(false);

fn live_slot(address: usize) -> usize {
    (address >> 4).wrapping_mul(0x9e37_79b9_7f4a_7c15) % LIVE_SLOTS
}

fn note_alloc(address: usize, size: usize) {
    let start = live_slot(address);
    for probe in 0..LIVE_SLOTS {
        let slot = (start + probe) % LIVE_SLOTS;
        let current = LIVE_ADDRESS[slot].load(Ordering::SeqCst);
        if (current == 0 || current == usize::MAX)
            && LIVE_ADDRESS[slot]
                .compare_exchange(current, address, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            LIVE_SIZE[slot].store(size, Ordering::SeqCst);
            return;
        }
    }
    LIVE_FULL.fetch_add(1, Ordering::SeqCst);
}

fn note_free(address: usize) {
    let start = live_slot(address);
    for probe in 0..LIVE_SLOTS {
        let slot = (start + probe) % LIVE_SLOTS;
        let current = LIVE_ADDRESS[slot].load(Ordering::SeqCst);
        if current == address {
            LIVE_ADDRESS[slot].store(usize::MAX, Ordering::SeqCst);
            return;
        }
        if current == 0 {
            return;
        }
    }
}

struct Quarantine;

unsafe impl GlobalAlloc for Quarantine {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && WINDOW.load(Ordering::SeqCst) {
            note_alloc(ptr as usize, layout.size());
        }
        ptr
    }

    // `realloc` is the default one: `alloc`, copy, `dealloc`, so a block a buffer grew out of
    // is quarantined too.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING.load(Ordering::SeqCst) {
            note_free(ptr as usize);
        }
        if WINDOW.load(Ordering::SeqCst) {
            let slot = QUARANTINED.fetch_add(1, Ordering::SeqCst);
            if slot < QUARANTINE {
                BLOCK_ADDRESS[slot].store(ptr as usize, Ordering::SeqCst);
                BLOCK_SIZE[slot].store(layout.size(), Ordering::SeqCst);
                BLOCK_ALIGN[slot].store(layout.align(), Ordering::SeqCst);
                return;
            }
            OVERFLOWED.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Quarantine = Quarantine;

/// One test at a time uses the allocator, the records and the provider-object registry.
static SERIAL: Mutex<()> = Mutex::new(());

fn open_window() {
    for slot in 0..LIVE_SLOTS {
        LIVE_ADDRESS[slot].store(0, Ordering::SeqCst);
    }
    LIVE_FULL.store(0, Ordering::SeqCst);
    TRACKING.store(true, Ordering::SeqCst);
    QUARANTINED.store(0, Ordering::SeqCst);
    OVERFLOWED.store(0, Ordering::SeqCst);
    WINDOW.store(true, Ordering::SeqCst);
}

/// Closes the window, searches every quarantined block for `needles` and frees it. Returns
/// one line per (needle, block) found.
fn close_window(needles: &[Needle]) -> Vec<String> {
    WINDOW.store(false, Ordering::SeqCst);
    let held = QUARANTINED.load(Ordering::SeqCst).min(QUARANTINE);
    assert_eq!(
        0,
        OVERFLOWED.load(Ordering::SeqCst),
        "the quarantine overflowed: blocks were freed unsearched"
    );
    let prefixes = Prefixes::of(needles);
    let mut ours = Vec::new();
    assert_eq!(
        0,
        LIVE_FULL.load(Ordering::SeqCst),
        "the live-block table overflowed"
    );
    // Blocks allocated during the association and still allocated after it was dropped:
    // a secret in one of them was never released (a leak, or a cache that outlives it).
    for slot in 0..LIVE_SLOTS {
        let address = LIVE_ADDRESS[slot].load(Ordering::SeqCst);
        if address == 0 || address == usize::MAX {
            continue;
        }
        let size = LIVE_SIZE[slot].load(Ordering::SeqCst);
        // SAFETY: the block is allocated (its free would have cleared the slot) and nothing
        // else runs while the serial lock is held; its bytes are only read.
        let block = unsafe { std::slice::from_raw_parts(address as *const u8, size) };
        for needle in prefixes.found_in(needles, block) {
            ours.push(format!(
                "{} in a block of {size} bytes still allocated after the drop",
                needle.describe()
            ));
        }
    }
    TRACKING.store(false, Ordering::SeqCst);
    for slot in 0..held {
        let address = BLOCK_ADDRESS[slot].load(Ordering::SeqCst);
        let size = BLOCK_SIZE[slot].load(Ordering::SeqCst);
        let align = BLOCK_ALIGN[slot].load(Ordering::SeqCst);
        // SAFETY: the block was handed to `dealloc` and kept: nothing else uses it until it is
        // freed below. Its bytes are only read.
        let block = unsafe { std::slice::from_raw_parts(address as *const u8, size) };
        for needle in prefixes.found_in(needles, block) {
            let line = format!("{} in a freed block of {size} bytes", needle.describe());
            if std::env::var_os("RTCI_ERASURE_DUMP").is_some() {
                let at = (0..size).find(|i| needle.at(block, *i)).unwrap_or_default();
                let hex: String = block[..size.min(192)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("DUMP {line} at {at}: {hex}");
            }
            ours.push(line);
        }
        // SAFETY: allocated by `System` with this layout (it came through `dealloc`).
        unsafe {
            System.dealloc(
                address as *mut u8,
                Layout::from_size_align_unchecked(size, align),
            )
        };
    }
    ours.sort();
    ours.dedup();
    ours
}

// ---------------------------------------------------------------------------------------------
// What to look for.

/// One secret, kept inverted.
#[derive(Clone)]
struct Needle {
    what: String,
    inverted: Vec<u8>,
}

impl Needle {
    fn new(what: impl Into<String>, inverted: &[u8]) -> Self {
        Self {
            what: what.into(),
            inverted: inverted.to_vec(),
        }
    }

    fn describe(&self) -> String {
        format!("{} ({} bytes)", self.what, self.inverted.len())
    }

    fn at(&self, haystack: &[u8], i: usize) -> bool {
        haystack.len() >= i + self.inverted.len()
            && haystack[i..i + self.inverted.len()]
                .iter()
                .zip(&self.inverted)
                .all(|(h, n)| *h == !*n)
    }

    fn prefix(&self) -> u16 {
        u16::from_le_bytes([!self.inverted[0], !self.inverted[1]])
    }
}

/// A table of the needles' first two bytes, so a search looks closer only where one starts.
struct Prefixes(Vec<bool>);

impl Prefixes {
    fn of(needles: &[Needle]) -> Self {
        let mut table = vec![false; 1 << 16];
        for needle in needles {
            table[needle.prefix() as usize] = true;
        }
        Self(table)
    }

    fn found_in<'a>(&self, needles: &'a [Needle], haystack: &[u8]) -> Vec<&'a Needle> {
        let mut found: Vec<&Needle> = Vec::new();
        for i in 0..haystack.len().saturating_sub(1) {
            let prefix = u16::from_le_bytes([haystack[i], haystack[i + 1]]);
            if !self.0[prefix as usize] {
                continue;
            }
            for needle in needles {
                if needle.prefix() == prefix
                    && needle.at(haystack, i)
                    && !found.iter().any(|f| std::ptr::eq(*f, needle))
                {
                    found.push(needle);
                }
            }
        }
        found
    }
}

fn invert(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| !b).collect()
}

/// The shortest secret looked for: shorter strings (the 4-byte implicit nonces of the AES-GCM
/// and AES-CCM suites) could match by chance in megabytes of freed memory.
const SHORTEST: usize = 12;

// ---------------------------------------------------------------------------------------------
// The recording provider.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Hmac(HmacAlgorithm),
    Aead(AeadAlgorithm),
    Cbc,
    Stream,
    HeaderMask,
    Block,
    SharedSecret,
}

/// A secret the provider was handed or gave back, inverted; for an HMAC key, the first inputs
/// it signed, inverted.
struct Record {
    kind: Kind,
    inverted: Vec<u8>,
    inputs: Vec<Vec<u8>>,
}

static RECORDS: Mutex<Vec<Record>> = Mutex::new(Vec::new());

fn record(kind: Kind, secret: &[u8]) -> usize {
    let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
    records.push(Record {
        kind,
        inverted: invert(secret),
        inputs: Vec::new(),
    });
    records.len() - 1
}

struct Recording {
    inner: Arc<dyn RTCCryptoProvider>,
    crypto: RecordingCrypto,
}

impl Recording {
    fn wrap(inner: Arc<dyn RTCCryptoProvider>) -> Arc<dyn RTCCryptoProvider> {
        Arc::new(Self {
            crypto: RecordingCrypto {
                inner: inner.clone(),
            },
            inner,
        })
    }
}

impl RTCCryptoProvider for Recording {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        self.inner.random()
    }
}

struct RecordingCrypto {
    inner: Arc<dyn RTCCryptoProvider>,
}

impl RTCCrypto for RecordingCrypto {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        self.inner.crypto().supports(algorithm)
    }

    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.crypto().hash(algorithm, data)
    }

    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        key: &[u8],
        block: &mut [u8],
    ) -> Result<(), CryptoError> {
        record(Kind::Block, key);
        self.inner.crypto().block_encrypt(algorithm, key, block)
    }

    fn new_hmac(&self, algorithm: HmacAlgorithm, key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        let index = record(Kind::Hmac(algorithm), key);
        let inner = self.inner.crypto().new_hmac(algorithm, key)?;
        Ok(Box::new(RecordingMac { inner, index }))
    }

    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        record(Kind::Stream, key);
        self.inner.crypto().new_stream_cipher(algorithm, key)
    }

    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        record(Kind::Aead(algorithm), key);
        self.inner.crypto().new_aead(algorithm, key)
    }

    fn new_header_mask(
        &self,
        algorithm: HeaderMaskAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn HeaderMask>, CryptoError> {
        record(Kind::HeaderMask, key);
        self.inner.crypto().new_header_mask(algorithm, key)
    }

    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        record(Kind::Cbc, key);
        self.inner.crypto().new_cbc(algorithm, key)
    }

    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let inner = self.inner.crypto().start_key_exchange(algorithm)?;
        Ok(Box::new(RecordingExchange { inner }))
    }

    fn key_exchange_respond(
        &self,
        algorithm: KeyExchangeAlgorithm,
        peer_share: &[u8],
    ) -> Result<(Vec<u8>, SecretVec), CryptoError> {
        let (share, secret) = self
            .inner
            .crypto()
            .key_exchange_respond(algorithm, peer_share)?;
        record(Kind::SharedSecret, secret.as_ref());
        Ok((share, secret))
    }

    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.inner.crypto().generate_signing_key(scheme)
    }

    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.inner.crypto().import_signing_key(scheme, pkcs8_der)
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        public_key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner
            .crypto()
            .verify_signature(scheme, public_key, message, signature)
    }
}

/// An HMAC that records what it is first asked to sign: the seed of a PRF, the `HkdfLabel` of
/// an `HKDF-Expand`.
struct RecordingMac {
    inner: Box<dyn Mac>,
    index: usize,
}

impl RecordingMac {
    fn note(&self, input: &[&[u8]]) {
        let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
        let inputs = &mut records[self.index].inputs;
        if inputs.len() < 4 {
            inputs.push(
                input
                    .iter()
                    .flat_map(|part| part.iter())
                    .map(|b| !b)
                    .collect(),
            );
        }
    }
}

impl Mac for RecordingMac {
    fn output_len(&self) -> usize {
        self.inner.output_len()
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        self.note(input);
        self.inner.sign(input, output)
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        self.note(input);
        self.inner.verify(input, expected)
    }
}

struct RecordingExchange {
    inner: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for RecordingExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError> {
        let secret = self.inner.complete(peer_public_key)?;
        record(Kind::SharedSecret, secret.as_ref());
        Ok(secret)
    }
}

// ---------------------------------------------------------------------------------------------
// From the records to the needles.

/// The DTLS 1.2 PRF labels whose output is key material (RFC 5246 sections 6.3 and 8.1, RFC
/// 7627 section 4, RFC 5705 section 4 for the exporter); the Finished labels give
/// verify_data, which is sent.
const KEY_PRF_LABELS: [&[u8]; 4] = [
    b"master secret",
    b"extended master secret",
    b"key expansion",
    b"EXTRACTOR",
];

/// The blocks of P_hash computed: enough for the longest key block (AES-256-CBC-SHA, 136
/// bytes) and an SRTP exporter output.
const PRF_BLOCKS: usize = 5;

/// HMAC with the real provider, from inverted key and input; the output inverted.
fn hmac_inverted(
    provider: &dyn RTCCryptoProvider,
    algorithm: HmacAlgorithm,
    key_inverted: &[u8],
    input_inverted: &[&[u8]],
) -> Vec<u8> {
    let key = SecretVec::new(invert(key_inverted));
    let input: Vec<SecretVec> = input_inverted
        .iter()
        .map(|part| SecretVec::new(invert(part)))
        .collect();
    let parts: Vec<&[u8]> = input.iter().map(|part| part.as_ref()).collect();
    let mut mac = provider
        .crypto()
        .new_hmac(algorithm, key.as_ref())
        .expect("an HMAC");
    let mut output = SecretVec::new(vec![0u8; mac.output_len()]);
    mac.sign(&parts, output.as_mut()).expect("a MAC");
    invert(output.as_ref())
}

/// What the test derives from the records, inverted.
#[derive(Default)]
struct Derived {
    needles: Vec<Needle>,
    /// Each DTLS 1.2 key block (`P_hash` of "key expansion"), whole.
    key_blocks: Vec<Vec<u8>>,
    /// Each DTLS 1.2 master secret computed from a premaster secret.
    master_secrets: Vec<Vec<u8>>,
    /// The first block of each DTLS 1.2 exporter output.
    exporter_blocks: Vec<Vec<u8>>,
    /// Each DTLS 1.3 `HKDF-Expand-Label` output, by label.
    expanded: Vec<(String, Vec<u8>)>,
}

impl Derived {
    /// Adds a needle; one already there with the same bytes takes `what` as another name.
    fn push(&mut self, what: impl Into<String>, inverted: &[u8]) {
        if inverted.len() < SHORTEST || inverted.iter().all(|b| *b == 0xff) {
            return;
        }
        let what = what.into();
        match self.needles.iter_mut().find(|n| n.inverted == inverted) {
            Some(needle) => {
                if !needle.what.split(" = ").any(|name| name == what) {
                    needle.what = format!("{} = {what}", needle.what);
                }
            }
            None => self.needles.push(Needle::new(what, inverted)),
        }
    }
}

/// The label of an `HkdfLabel` (RFC 8446 section 7.1, prefixed "dtls13" by RFC 9147 section
/// 5.9) at the start of `input`, with the output length it asks for.
fn hkdf_label(input: &[u8]) -> Option<(String, usize)> {
    let length = usize::from(u16::from_be_bytes([*input.first()?, *input.get(1)?]));
    let label_len = usize::from(*input.get(2)?);
    let label = input.get(3..3 + label_len)?;
    let label = label.strip_prefix(b"dtls13")?;
    Some((String::from_utf8_lossy(label).into_owned(), length))
}

fn derive_needles(provider: &dyn RTCCryptoProvider, extra: &[Needle]) -> Derived {
    let records = std::mem::take(&mut *RECORDS.lock().unwrap_or_else(|e| e.into_inner()));
    let mut derived = Derived::default();
    for needle in extra {
        derived.push(needle.what.clone(), &needle.inverted);
    }
    for (index, record) in records.iter().enumerate() {
        let what = match record.kind {
            Kind::Hmac(_) => {
                let first = record
                    .inputs
                    .first()
                    .map(|input| {
                        String::from_utf8_lossy(&invert(&input[..input.len().min(12)])).into_owned()
                    })
                    .unwrap_or_default();
                format!("an HMAC key (record {index}, first input {first:?})")
            }
            Kind::Aead(_) => "an AEAD key".to_owned(),
            Kind::Cbc => "a CBC key".to_owned(),
            Kind::Stream => "a stream cipher key".to_owned(),
            Kind::HeaderMask => "a record-number key".to_owned(),
            Kind::Block => "a block cipher key".to_owned(),
            Kind::SharedSecret => "an (EC)DHE shared secret".to_owned(),
        };
        derived.push(what, &record.inverted);
        let Kind::Hmac(algorithm) = record.kind else {
            continue;
        };
        for input in &record.inputs {
            let plain_start: Vec<u8> = input.iter().take(64).map(|b| !b).collect();
            if let Some(label) = KEY_PRF_LABELS
                .iter()
                .find(|label| plain_start.starts_with(label))
            {
                // P_hash (RFC 5246 section 5): A(1) = HMAC(secret, seed), A(i) = HMAC(secret,
                // A(i-1)); block i = HMAC(secret, A(i) + seed).
                let label = String::from_utf8_lossy(label).into_owned();
                let mut a = hmac_inverted(provider, algorithm, &record.inverted, &[input]);
                let mut output = Vec::new();
                for i in 1..=PRF_BLOCKS {
                    let block = hmac_inverted(provider, algorithm, &record.inverted, &[&a, input]);
                    derived.push(format!("A({i}) of the PRF \"{label}\""), &a[..16]);
                    derived.push(format!("block {i} of the PRF \"{label}\""), &block[..16]);
                    output.extend_from_slice(&block);
                    a = hmac_inverted(provider, algorithm, &record.inverted, &[&a]);
                }
                match label.as_str() {
                    "key expansion" => {
                        // Every key and IV of the block starts at a multiple of 4.
                        for at in (0..output.len() - SHORTEST).step_by(4) {
                            derived.push(
                                format!("key block bytes {at}..{}", at + SHORTEST),
                                &output[at..at + SHORTEST],
                            );
                        }
                        derived.key_blocks.push(output);
                    }
                    "master secret" | "extended master secret" => {
                        derived.master_secrets.push(output[..48].to_vec());
                    }
                    _ => derived.exporter_blocks.push(output[..32].to_vec()),
                }
            } else if let Some((label, length)) = hkdf_label(&plain_start) {
                let output = hmac_inverted(provider, algorithm, &record.inverted, &[input]);
                let length = length.min(output.len());
                derived.push(
                    format!("HKDF-Expand-Label \"{label}\""),
                    &output[..length.min(16)],
                );
                derived.expanded.push((label, output[..length].to_vec()));
            }
        }
    }
    derived
}

// ---------------------------------------------------------------------------------------------
// Associations.

const CLIENT: &str = "127.0.0.1:44201";
const SERVER: &str = "127.0.0.1:44202";
const SECOND_CLIENT: &str = "127.0.0.1:44203";

/// The PSK the application provisions, inverted (the plain bytes are made only when handed
/// over).
const PSK_INVERTED: [u8; 32] = [
    0x5d, 0xa2, 0x13, 0xee, 0x47, 0x90, 0x2b, 0xc6, 0x71, 0x0e, 0xb8, 0x34, 0xf9, 0x66, 0xd1, 0x08,
    0x9b, 0x24, 0xe7, 0x52, 0x3a, 0xcd, 0x80, 0x1f, 0x6c, 0xb5, 0x49, 0xf2, 0x07, 0xaa, 0x3e, 0xd4,
];

fn plain_psk() -> Vec<u8> {
    invert(&PSK_INVERTED)
}

fn psk_needles() -> Vec<Needle> {
    // RFC 4279 section 2: the premaster secret of a plain PSK suite.
    let mut premaster = vec![0xff, !32];
    premaster.extend_from_slice(&[0xff; 32]);
    premaster.extend_from_slice(&[0xff, !32]);
    premaster.extend_from_slice(&PSK_INVERTED);
    vec![
        Needle::new("the PSK", &PSK_INVERTED),
        Needle::new("the PSK premaster secret", &premaster),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Auth {
    Certificates,
    Psk,
    ExternalPsk,
}

/// A client and a server endpoint, boxed so that what they hold is in the heap the
/// quarantine sees.
struct Association {
    client: Box<Endpoint>,
    server: Box<Endpoint>,
}

impl Association {
    fn server_addr() -> SocketAddr {
        SERVER.parse().expect("an address")
    }

    fn client_state(&self) -> &State {
        self.client
            .get_connection_state(Self::server_addr())
            .expect("an association")
    }

    /// Moves datagrams both ways until nothing is left to send, a bounded number of times.
    fn pump(&mut self, now: Instant) -> Result<bool, Box<dyn std::error::Error>> {
        let client_addr: SocketAddr = CLIENT.parse()?;
        let server_addr = Self::server_addr();
        let mut completed = false;
        for _ in 0..8 {
            let mut moved = false;
            while let Some(packet) = self.client.poll_transmit() {
                moved = true;
                self.server
                    .read(now, client_addr, packet.transport.ecn, packet.message)?;
            }
            while let Some(packet) = self.server.poll_transmit() {
                moved = true;
                completed |= self
                    .client
                    .read(now, server_addr, packet.transport.ecn, packet.message)?
                    .iter()
                    .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
            }
            if !moved {
                break;
            }
        }
        Ok(completed)
    }
}

impl Association {
    /// A second client, at another address, makes a DTLS 1.2 association with the same server
    /// at `now`; it is dropped when done. Returns whether its handshake completed.
    fn second_client(
        &mut self,
        configs: &Configs,
        now: Instant,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let client_addr: SocketAddr = SECOND_CLIENT.parse()?;
        let server_addr = Self::server_addr();
        let mut client = Box::new(Endpoint::new(client_addr, TransportProtocol::UDP, None));
        client.connect(now, server_addr, configs.client.clone(), None)?;
        let mut completed = false;
        for _ in 0..8 {
            let mut moved = false;
            while let Some(packet) = client.poll_transmit() {
                moved = true;
                self.server
                    .read(now, client_addr, packet.transport.ecn, packet.message)?;
            }
            while let Some(packet) = self.server.poll_transmit() {
                moved = true;
                completed |= client
                    .read(now, server_addr, packet.transport.ecn, packet.message)?
                    .iter()
                    .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
            }
            if !moved {
                break;
            }
        }
        Ok(completed)
    }
}

/// The certificate the server signs with, made with the real provider before the window
/// opens.
fn certificate(provider: &Arc<dyn RTCCryptoProvider>) -> Certificate {
    Certificate::generate_self_signed(vec!["localhost".into()], provider.crypto())
        .expect("a self-signed certificate")
}

struct Configs {
    client: Arc<HandshakeConfig>,
    server: Arc<HandshakeConfig>,
}

fn configs(
    provider: &Arc<dyn RTCCryptoProvider>,
    certificate: &Certificate,
    version: DtlsVersion,
    suite: Option<CipherSuiteId>,
    auth: Auth,
    store: Option<Arc<MemorySessionStore>>,
) -> Result<Configs, Box<dyn std::error::Error>> {
    let mut client = ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_insecure_skip_verify(true)
        .with_protocol_versions(version, version)
        .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80])
        .with_server_name("localhost".to_owned());
    let mut server = ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_insecure_skip_verify(true)
        .with_protocol_versions(version, version)
        .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80]);
    if let Some(suite) = suite {
        client = client.with_cipher_suites(vec![suite]);
        server = server.with_cipher_suites(vec![suite]);
    }
    match auth {
        Auth::Certificates => {
            server = server.with_certificates(vec![certificate.clone()]);
        }
        Auth::Psk => {
            let callback: Arc<dyn Fn(&[u8]) -> rtci::shared::error::Result<Vec<u8>> + Send + Sync> =
                Arc::new(|_hint: &[u8]| Ok(plain_psk()));
            client = client
                .with_psk(Some(callback.clone()))
                .with_psk_identity_hint(Some(b"device".to_vec()));
            server = server.with_psk(Some(callback));
        }
        Auth::ExternalPsk => {
            client =
                client.with_external_psks(vec![ExternalPsk::new(b"device".to_vec(), plain_psk())]);
            server = server
                .with_certificates(vec![certificate.clone()])
                .with_external_psks(vec![ExternalPsk::new(b"device".to_vec(), plain_psk())]);
        }
    }
    if let Some(store) = store {
        client = client.with_session_store(Some(store));
        server = server.with_session_tickets(1);
    }
    Ok(Configs {
        client: Arc::new(client.build(true, None)?),
        server: Arc::new(server.build(false, None)?),
    })
}

fn associate(configs: &Configs, now: Instant) -> Result<Association, Box<dyn std::error::Error>> {
    let mut association = Association {
        client: Box::new(Endpoint::new(CLIENT.parse()?, TransportProtocol::UDP, None)),
        server: Box::new(Endpoint::new(
            SERVER.parse()?,
            TransportProtocol::UDP,
            Some(configs.server.clone()),
        )),
    };
    association.client.connect(
        now,
        Association::server_addr(),
        configs.client.clone(),
        None,
    )?;
    let completed = association.pump(now)?;
    assert!(completed, "the handshake completes");
    Ok(association)
}

/// What the engine does with a completed association: exports the SRTP keying material (RFC
/// 5764 section 4.2), makes the two SRTP contexts from it and drops everything. Returns the
/// exported material, inverted.
fn srtp_from(association: &Association) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let state = association.client_state();
    let profile = ProtectionProfile::from_dtls_srtp_id(state.srtp_protection_profile() as u16)
        .expect("a negotiated profile");
    let mut config = Config {
        profile,
        ..Default::default()
    };
    let material = state.export_keying_material(
        LABEL_EXTRACTOR_DTLS_SRTP,
        &[],
        config.keying_material_len(),
    )?;
    let inverted = invert(material.as_ref());
    config.set_session_keys_from_keying_material(material.as_ref(), state.is_client())?;
    let provider = state_provider();
    let local = Context::new(
        &config.keys.local_master_key,
        &config.keys.local_master_salt,
        profile,
        None,
        None,
        provider.crypto(),
    )?;
    drop(local);
    Ok(inverted)
}

fn state_provider() -> Arc<dyn RTCCryptoProvider> {
    rtci::crypto::default_provider().expect("a provider")
}

#[allow(clippy::vec_init_then_push)]
fn providers() -> Vec<Arc<dyn RTCCryptoProvider>> {
    let mut providers: Vec<Arc<dyn RTCCryptoProvider>> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(Arc::new(rtci::crypto::providers::RingProvider::new()));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push(Arc::new(rtci::crypto::providers::AwsLcRsProvider::new()));
    providers
}

/// What one scenario left: the needles derived and the secrets found in freed blocks.
struct Outcome {
    derived: Derived,
    left: Vec<String>,
}

/// Runs `scenario` inside the window with a recording wrapper around `inner`, then derives the
/// needles and searches the quarantine. `scenario` returns needles of its own (inverted): what
/// it exported, and so on.
fn scan(
    inner: &Arc<dyn RTCCryptoProvider>,
    name: &str,
    extra: Vec<Needle>,
    scenario: impl FnOnce(
        &Arc<dyn RTCCryptoProvider>,
    ) -> Result<Vec<Needle>, Box<dyn std::error::Error>>,
) -> Outcome {
    RECORDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let provider = Recording::wrap(inner.clone());
    open_window();
    let outcome = scenario(&provider);
    drop(provider);
    WINDOW.store(false, Ordering::SeqCst);
    let mut own = match outcome {
        Ok(own) => own,
        Err(err) => {
            // Free the quarantine before failing.
            close_window(&[]);
            panic!("{name}: {err}");
        }
    };
    own.extend(extra);
    let derived = derive_needles(inner.as_ref(), &own);
    let left = close_window(&derived.needles);
    for line in &left {
        println!("LEFT {:<10} {name}: {line}", inner.name());
    }
    println!(
        "SCAN {:<10} {name}: {} secrets looked for, {} left",
        inner.name(),
        derived.needles.len(),
        left.len()
    );
    Outcome { derived, left }
}

/// The needles are what the association used: each record key the provider was handed is in
/// a key block (DTLS 1.2) or is an `HKDF-Expand-Label` "key" output (DTLS 1.3), and the
/// exporter output computed is the material exported.
fn check_needles(name: &str, derived: &Derived, exported: &[Vec<u8>], record_keys: &[Vec<u8>]) {
    for key in record_keys {
        let in_a_key_block = derived
            .key_blocks
            .iter()
            .any(|block| block.windows(key.len()).any(|w| w == key.as_slice()));
        let expanded = derived
            .expanded
            .iter()
            .any(|(label, output)| label == "key" && output == key);
        assert!(
            in_a_key_block || expanded,
            "{name}: a record key the provider was handed was not computed"
        );
    }
    for material in exported {
        let computed = derived
            .exporter_blocks
            .iter()
            .any(|block| material.starts_with(&block[..16]))
            || derived
                .expanded
                .iter()
                .any(|(label, output)| label == "exporter" && material.starts_with(output));
        assert!(
            computed,
            "{name}: the exported material is not what the test computes"
        );
    }
}

fn record_keys_of(derived_records: &[(Kind, Vec<u8>)]) -> Vec<Vec<u8>> {
    derived_records
        .iter()
        .filter(|(kind, _)| matches!(kind, Kind::Aead(_) | Kind::Cbc))
        .map(|(_, key)| key.clone())
        .collect()
}

/// The record keys recorded so far (before `derive_needles` takes the records).
fn snapshot_record_keys() -> Vec<(Kind, Vec<u8>)> {
    RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|record| (record.kind, record.inverted.clone()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The tests.

/// One full DTLS 1.2 handshake with `suite`, the SRTP keys exported and made into a context,
/// everything dropped; the secrets left, with the checks on the needles.
fn dtls12_full_handshake(
    provider: &Arc<dyn RTCCryptoProvider>,
    suite: CipherSuiteId,
    auth: Auth,
) -> Outcome {
    let certificate = certificate(provider);
    let name = format!("DTLS 1.2 {suite:?}");
    let keys = Mutex::new(Vec::new());
    let exported = Mutex::new(Vec::new());
    let extra = if auth == Auth::Psk {
        psk_needles()
    } else {
        Vec::new()
    };
    let outcome = scan(provider, &name, extra, |provider| {
        let now = Instant::now();
        let configs = configs(
            provider,
            &certificate,
            DtlsVersion::Dtls1_2,
            Some(suite),
            auth,
            None,
        )?;
        let association = associate(&configs, now)?;
        let material = srtp_from(&association)?;
        drop(association);
        drop(configs);
        *keys.lock().unwrap() = snapshot_record_keys();
        exported.lock().unwrap().push(material.clone());
        Ok(vec![Needle::new(
            "the exported SRTP keying material",
            &material,
        )])
    });
    check_needles(
        &name,
        &outcome.derived,
        &exported.lock().unwrap(),
        &record_keys_of(&keys.lock().unwrap()),
    );
    assert!(
        !outcome.derived.master_secrets.is_empty(),
        "{name}: a master secret was computed"
    );
    outcome
}

/// RFC 5246 section 8.1, RFC 7627, RFC 5705 with RFC 5764 section 4.2: the premaster secret,
/// the master secret, the PRF's intermediate values, the key block and each record key and IV
/// of a DTLS 1.2 association, and the SRTP keying material exported from it, are left in no
/// block freed during the association or when it is dropped, for every cipher suite family
/// (the AES-GCM, AES-CCM and ChaCha20-Poly1305 AEADs, AES-CBC with HMAC-SHA1).
#[test]
fn dtls12_secrets_are_erased_for_every_cipher_suite_family() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        for suite in [
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        ] {
            let outcome = dtls12_full_handshake(&provider, suite, Auth::Certificates);
            left.extend(
                outcome
                    .left
                    .iter()
                    .map(|line| format!("{} {suite:?}: {line}", provider.name())),
            );
        }
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// RFC 4279 section 2 with RFC 5246 section 8.1: the PSK the application's callback gives and
/// the premaster secret made from it are erased, like the rest of the association's secrets.
#[test]
fn dtls12_psk_and_its_premaster_secret_are_erased() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let outcome = dtls12_full_handshake(
            &provider,
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            Auth::Psk,
        );
        left.extend(
            outcome
                .left
                .iter()
                .map(|line| format!("{}: {line}", provider.name())),
        );
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// RFC 5077 (session tickets) with RFC 5246 section 7.3: a full handshake that issues a
/// ticket and a second one that resumes from it. The ticket key, the master secret sealed
/// into the ticket and opened from it, and every secret of both associations are erased.
#[test]
fn dtls12_ticket_keys_and_resumed_master_secrets_are_erased() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let certificate = certificate(&provider);
        let resumed = Mutex::new(false);
        let outcome = scan(
            &provider,
            "DTLS 1.2 ticket resumption",
            Vec::new(),
            |provider| {
                let now = Instant::now();
                let store = Arc::new(MemorySessionStore::new());
                let configs = configs(
                    provider,
                    &certificate,
                    DtlsVersion::Dtls1_2,
                    Some(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
                    Auth::Certificates,
                    Some(store.clone()),
                )?;
                let first = associate(&configs, now)?;
                let mut own = vec![Needle::new("exported (first)", &srtp_from(&first)?)];
                drop(first);
                let second = associate(&configs, now)?;
                *resumed.lock().unwrap() = second.client_state().resumed();
                own.push(Needle::new("exported (resumed)", &srtp_from(&second)?));
                drop(second);
                drop(configs);
                drop(store);
                Ok(own)
            },
        );
        assert!(*resumed.lock().unwrap(), "the second handshake resumed");
        assert!(
            outcome
                .derived
                .needles
                .iter()
                .any(|n| n.what.contains("an AEAD key")),
            "the ticket key and the record keys were recorded"
        );
        left.extend(
            outcome
                .left
                .iter()
                .map(|line| format!("{}: {line}", provider.name())),
        );
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// `State::marshal_binary` and `unmarshal_binary` hold the master secret on the way: nothing
/// they make is left in memory they free. (The serialized bytes are the application's to
/// protect: here they are kept in a zeroizing buffer.)
#[test]
fn dtls12_state_serialization_leaves_no_master_secret_behind() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let certificate = certificate(&provider);
        let outcome = scan(
            &provider,
            "DTLS 1.2 state serialization",
            Vec::new(),
            |provider| {
                let now = Instant::now();
                let configs = configs(
                    provider,
                    &certificate,
                    DtlsVersion::Dtls1_2,
                    Some(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
                    Auth::Certificates,
                    None,
                )?;
                let association = associate(&configs, now)?;
                let bytes = SecretVec::new(association.client_state().marshal_binary()?);
                let mut restored = State::new(provider.clone(), true);
                restored.unmarshal_binary(bytes.as_ref())?;
                let own = vec![Needle::new(
                    "exported (restored)",
                    &srtp_from(&association)?,
                )];
                drop(restored);
                drop(bytes);
                drop(association);
                drop(configs);
                Ok(own)
            },
        );
        left.extend(
            outcome
                .left
                .iter()
                .map(|line| format!("{}: {line}", provider.name())),
        );
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// RFC 8446 section 7.1 and RFC 9147: the (EC)DHE shared secret, every secret of the key
/// schedule, each traffic key, IV and record-number key, the exporter output, and the
/// secrets a KeyUpdate replaces in both directions (RFC 9147 section 8), of DTLS 1.3
/// associations with an AES-GCM and an AES-CCM suite, are left in no freed block.
#[test]
fn dtls13_secrets_are_erased_across_key_updates() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let certificate = certificate(&provider);
        for suite in [
            CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Aes_128_Ccm_Sha256,
        ] {
            let name = format!("DTLS 1.3 {suite:?}");
            let keys = Mutex::new(Vec::new());
            let exported = Mutex::new(Vec::new());
            let outcome = scan(&provider, &name, Vec::new(), |provider| {
                let now = Instant::now();
                let configs = configs(
                    provider,
                    &certificate,
                    DtlsVersion::Dtls1_3,
                    Some(suite),
                    Auth::Certificates,
                    None,
                )?;
                let mut association = associate(&configs, now)?;
                let material = srtp_from(&association)?;
                for request_peer in [true, false] {
                    association.client.update_keys(
                        now,
                        Association::server_addr(),
                        request_peer,
                    )?;
                    association.pump(now)?;
                }
                drop(association);
                drop(configs);
                *keys.lock().unwrap() = snapshot_record_keys();
                exported.lock().unwrap().push(material.clone());
                Ok(vec![Needle::new(
                    "the exported SRTP keying material",
                    &material,
                )])
            });
            check_needles(
                &name,
                &outcome.derived,
                &exported.lock().unwrap(),
                &record_keys_of(&keys.lock().unwrap()),
            );
            let updates = outcome
                .derived
                .expanded
                .iter()
                .filter(|(label, _)| label == "traffic upd")
                .count();
            assert!(updates >= 2, "{name}: both directions updated their keys");
            left.extend(
                outcome
                    .left
                    .iter()
                    .map(|line| format!("{} {suite:?}: {line}", provider.name())),
            );
        }
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// RFC 8446 sections 4.6.1 and 7.1, 2.2: a DTLS 1.3 association resumed from a ticket of an
/// earlier one (the resumption master secret, the ticket's PSK, the ticket key it is sealed
/// under, the binder key) and one authenticated with an external PSK (the PSK itself): their
/// secrets are left in no freed block.
#[test]
fn dtls13_resumption_and_external_psk_secrets_are_erased() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let certificate = certificate(&provider);
        let resumed = Mutex::new((false, false));
        let outcome = scan(
            &provider,
            "DTLS 1.3 resumption",
            psk_needles(),
            |provider| {
                let now = Instant::now();
                let store = Arc::new(MemorySessionStore::new());
                let tickets = configs(
                    provider,
                    &certificate,
                    DtlsVersion::Dtls1_3,
                    None,
                    Auth::Certificates,
                    Some(store.clone()),
                )?;
                let first = associate(&tickets, now)?;
                let mut own = vec![Needle::new("exported (first)", &srtp_from(&first)?)];
                drop(first);
                let second = associate(&tickets, now)?;
                own.push(Needle::new("exported (resumed)", &srtp_from(&second)?));
                let from_ticket = second.client_state().resumed();
                drop(second);
                drop(tickets);
                drop(store);
                let external = configs(
                    provider,
                    &certificate,
                    DtlsVersion::Dtls1_3,
                    None,
                    Auth::ExternalPsk,
                    None,
                )?;
                let third = associate(&external, now)?;
                own.push(Needle::new("exported (external PSK)", &srtp_from(&third)?));
                *resumed.lock().unwrap() = (from_ticket, third.client_state().resumed());
                drop(third);
                drop(external);
                Ok(own)
            },
        );
        assert_eq!(
            (true, true),
            *resumed.lock().unwrap(),
            "resumed from the ticket, then with the external PSK"
        );
        assert!(
            outcome
                .derived
                .expanded
                .iter()
                .any(|(label, _)| label == "resumption"),
            "a ticket's PSK was computed"
        );
        left.extend(
            outcome
                .left
                .iter()
                .map(|line| format!("{}: {line}", provider.name())),
        );
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// The first HMAC-SHA-256 key recorded from `from` on: the cookie secret, when a server's
/// HelloVerifyRequest is the first thing after `from` that MACs with SHA-256.
fn first_sha256_key_from(from: usize) -> Vec<u8> {
    RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .skip(from)
        .find(|record| record.kind == Kind::Hmac(HmacAlgorithm::Sha256))
        .map(|record| record.inverted.clone())
        .unwrap_or_default()
}

fn records_so_far() -> usize {
    RECORDS.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// The cookie secrets of RFC 6347 section 4.2.1 (and RFC 9147 section 5.1), the current one
/// and the one before it, are erased with the endpoint. A second client arrives once the
/// first secret has served its lifetime, so the server rotates: the first secret becomes the
/// previous one, a new one signs. Both are looked for after the server is dropped (0.1.0
/// never erased the previous one).
#[test]
fn cookie_secrets_are_erased_with_the_endpoint() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    for provider in providers() {
        let certificate = certificate(&provider);
        let cookie_secrets = Mutex::new(Vec::new());
        let outcome = scan(&provider, "cookie exchange", Vec::new(), |provider| {
            let now = Instant::now();
            let configs = configs(
                provider,
                &certificate,
                DtlsVersion::Dtls1_2,
                None,
                Auth::Certificates,
                None,
            )?;
            let mut association = associate(&configs, now)?;
            // The cookie MACs are HMAC-SHA-256 under the cookie secret; the first HMAC key of
            // the handshake is that secret (the server makes a HelloVerifyRequest first).
            let first = first_sha256_key_from(0);
            // A second client, one lifetime later: the server makes a new secret and keeps
            // the first as the previous one.
            // (A secret signs for 60 s, `rtci-dtls/src/cookie.rs`; the inequality of the two
            // secrets below shows the rotation happened.)
            let later = now + Duration::from_secs(61);
            let from = records_so_far();
            let completed = association.second_client(&configs, later)?;
            assert!(completed, "the second handshake completes");
            let second = first_sha256_key_from(from);
            *cookie_secrets.lock().unwrap() = vec![first, second];
            drop(association);
            drop(configs);
            Ok(Vec::new())
        });
        let secrets = cookie_secrets.lock().unwrap().clone();
        assert!(
            secrets.iter().all(|secret| secret.len() == 32),
            "both cookie secrets were recorded"
        );
        assert_ne!(
            secrets[0], secrets[1],
            "the server rotated its cookie secret"
        );
        for (secret, which) in secrets.iter().zip(["previous", "current"]) {
            assert!(
                outcome
                    .derived
                    .needles
                    .iter()
                    .any(|n| n.inverted == *secret),
                "the {which} cookie secret is one of the needles"
            );
        }
        left.extend(
            outcome
                .left
                .iter()
                .map(|line| format!("{}: {line}", provider.name())),
        );
    }
    assert!(left.is_empty(), "left in freed memory: {left:#?}");
}

/// The check itself: secrets copied into vectors that are freed without erasure are seen.
#[test]
fn the_quarantine_sees_secrets_left_behind() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let provider = providers().remove(0);
    let certificate = certificate(&provider);
    let outcome = scan(&provider, "careless copies", Vec::new(), |provider| {
        let now = Instant::now();
        let configs = configs(
            provider,
            &certificate,
            DtlsVersion::Dtls1_2,
            Some(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
            Auth::Certificates,
            None,
        )?;
        let association = associate(&configs, now)?;
        let material = srtp_from(&association)?;
        // A careless copy of the exported material and of the first record key, freed as is.
        let careless = invert(&material);
        drop(careless);
        let key = snapshot_record_keys()
            .into_iter()
            .find(|(kind, _)| matches!(kind, Kind::Aead(_)))
            .map(|(_, key)| invert(&key))
            .expect("a record key");
        drop(key);
        drop(association);
        drop(configs);
        Ok(vec![Needle::new(
            "the exported SRTP keying material",
            &material,
        )])
    });
    assert!(
        outcome
            .left
            .iter()
            .any(|line| line.contains("the exported SRTP keying material")),
        "the careless copy of the material is found: {:#?}",
        outcome.left
    );
    assert!(
        outcome.left.iter().any(|line| line.contains("an AEAD key")),
        "the careless copy of a record key is found: {:#?}",
        outcome.left
    );
}

// ---------------------------------------------------------------------------------------------
// The whole process (Linux).

/// Linux only: the whole process, through `/proc/self/maps` and `/proc/self/mem`.
#[cfg(target_os = "linux")]
mod process_memory_tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::sync::mpsc;

    const WORKER_STACK: &str = "the worker thread's stack";

    struct Region {
        start: usize,
        end: usize,
        name: String,
    }

    fn writable_regions() -> Vec<Region> {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
        maps.lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let range = fields.next()?;
                let perms = fields.next()?;
                if !perms.starts_with("rw") {
                    return None;
                }
                let name = fields.nth(3).unwrap_or("anonymous").to_owned();
                let (start, end) = range.split_once('-')?;
                Some(Region {
                    start: usize::from_str_radix(start, 16).ok()?,
                    end: usize::from_str_radix(end, 16).ok()?,
                    name,
                })
            })
            .collect()
    }

    /// Where each needle is found in the process: one region name per hit. The searching
    /// thread's stack (`test_stack` is an address on it) and the scan buffer are left out;
    /// the region holding `worker_stack` is named as the worker's stack.
    fn search(needles: &[Needle], test_stack: usize, worker_stack: usize) -> Vec<String> {
        const CHUNK: usize = 1 << 20;
        let longest = needles.iter().map(|n| n.inverted.len()).max().unwrap_or(0);
        let prefixes = Prefixes::of(needles);
        let mem = File::open("/proc/self/mem").expect("/proc/self/mem");
        let mut buffer = vec![0u8; CHUNK + longest];
        let buffer_range = buffer.as_ptr() as usize..buffer.as_ptr() as usize + buffer.len();
        let holes = [(buffer_range.start, buffer_range.end)];
        let mut found = Vec::new();
        for region in writable_regions() {
            if (region.start..region.end).contains(&test_stack) {
                continue;
            }
            let name = if (region.start..region.end).contains(&worker_stack) {
                WORKER_STACK.to_owned()
            } else {
                region.name.clone()
            };
            let mut segments = Vec::new();
            let mut at = region.start;
            for &(start, end) in &holes {
                if end <= at || start >= region.end {
                    continue;
                }
                if start > at {
                    segments.push((at, start));
                }
                at = at.max(end);
            }
            if at < region.end {
                segments.push((at, region.end));
            }
            for (start, end) in segments {
                let mut at = start;
                while at < end {
                    let len = (end - at).min(CHUNK + longest);
                    if mem.read_exact_at(&mut buffer[..len], at as u64).is_ok() {
                        for needle in prefixes.found_in(needles, &buffer[..len]) {
                            found.push(format!("{} in {name}", needle.describe()));
                            if std::env::var_os("RTCI_ERASURE_DUMP").is_some() {
                                let i = (0..len)
                                    .find(|i| needle.at(&buffer[..len], *i))
                                    .unwrap_or(0);
                                let from = i.saturating_sub(96);
                                let hex: String = buffer[from..(i + 64).min(len)]
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect();
                                println!(
                                    "PDUMP {} at {:#x} in {name} {:#x}-{:#x} (from -{}): {hex}",
                                    needle.describe(),
                                    at + i,
                                    region.start,
                                    region.end,
                                    i - from
                                );
                            }
                        }
                    }
                    at += CHUNK;
                }
            }
        }
        buffer.fill(0);
        found.sort();
        found.dedup();
        found
    }

    /// A DTLS 1.2 (AES-GCM and AES-CBC) and a DTLS 1.3 association on a worker thread, their
    /// SRTP keys exported; searched for while they are alive, then after the worker has
    /// dropped them and exited. Returns what was found before and after.
    fn session(
        inner: &Arc<dyn RTCCryptoProvider>,
        version: DtlsVersion,
        suite: CipherSuiteId,
    ) -> (Derived, Vec<String>, Vec<String>) {
        RECORDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let certificate = certificate(inner);
        let (ready_tx, ready_rx) = mpsc::channel::<(Vec<u8>, usize)>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let worker_inner = inner.clone();
        let worker = std::thread::spawn(move || {
            let provider = Recording::wrap(worker_inner);
            let now = Instant::now();
            let configs = configs(
                &provider,
                &certificate,
                version,
                Some(suite),
                Auth::Certificates,
                None,
            )
            .expect("configurations");
            let association = associate(&configs, now).expect("an association");
            let state = association.client_state();
            let material = state
                .export_keying_material(LABEL_EXTRACTOR_DTLS_SRTP, &[], 60)
                .expect("keying material");
            let marker = 0u8;
            ready_tx
                .send((invert(material.as_ref()), &marker as *const u8 as usize))
                .expect("the test thread waits");
            go_rx.recv().expect("the test thread says when");
            drop(material);
            drop(association);
            drop(configs);
            drop(provider);
            drop(certificate);
        });
        let (exported, worker_stack) = ready_rx.recv().expect("the worker is ready");
        let derived = derive_needles(
            inner.as_ref(),
            &[Needle::new("the exported keying material", &exported)],
        );
        let test_stack = &derived as *const _ as usize;
        let before = search(&derived.needles, test_stack, worker_stack);
        go_tx.send(()).expect("the worker waits");
        worker.join().expect("the worker ends");
        let after = search(&derived.needles, test_stack, worker_stack);
        (derived, before, after)
    }

    /// No secret of a DTLS association outlives it in the process's heap and data: found while
    /// the association is alive (the master secret or the traffic secrets, and the exported
    /// material: the search sees what it looks for), gone once it is dropped, with both
    /// providers (the ring provider's own key objects included, since 0.2). What dead
    /// frames of the worker thread's stack still hold is printed, not asserted: the
    /// providers' own stack buffers (an ECDH output, a nonce built from an IV) are not erased
    /// by them, and what a frame keeps depends on what ran over it since.
    #[test]
    fn dtls_secrets_do_not_outlive_their_association_in_process_memory() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut left = Vec::new();
        for provider in providers() {
            for (version, suite) in [
                (
                    DtlsVersion::Dtls1_2,
                    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                ),
                (
                    DtlsVersion::Dtls1_2,
                    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
                ),
                (DtlsVersion::Dtls1_3, CipherSuiteId::Tls_Aes_128_Gcm_Sha256),
            ] {
                let (derived, before, after) = session(&provider, version, suite);
                for line in &before {
                    println!("BEFORE {:<10} {suite:?}: {line}", provider.name());
                }
                for line in &after {
                    println!("AFTER  {:<10} {suite:?}: {line}", provider.name());
                }
                assert!(
                    before
                        .iter()
                        .any(|line| line.contains("the exported keying material")),
                    "{} {suite:?}: the live exported material is found",
                    provider.name()
                );
                assert!(
                    before.iter().any(|line| line.contains("an HMAC key")),
                    "{} {suite:?}: a live secret of the association is found",
                    provider.name()
                );
                assert!(!derived.needles.is_empty());
                left.extend(
                    after
                        .iter()
                        .filter(|line| !line.ends_with(WORKER_STACK))
                        .map(|line| format!("{} {suite:?}: {line}", provider.name())),
                );
            }
        }
        assert!(left.is_empty(), "found after the drop: {left:#?}");
    }
}

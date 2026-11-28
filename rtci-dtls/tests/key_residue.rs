//! DTLS key material in the dead stack frames of the thread that handled it: the DTLS
//! counterpart of `rtci-srtp/tests/key_residue.rs`. RFC 7714 section 13.1 ("All keys MUST be
//! properly erased when no longer needed") for the SRTP keys a DTLS-SRTP association exports,
//! RFC 5246 section 8.1 and RFC 8446 section 7.1 for the secrets the handshake derives on the
//! way, and the project's rule that memory a secret was in is overwritten before it is given
//! up. A key left in a dead frame is not erased: the next value built over that frame and
//! moved into the heap carries it in bytes no field owns (padding, the payload of a `None`,
//! the unused arm of a union), and the heap frees that block unerased. Two such leaks were
//! seen on Windows (handoff notes of the train-35 DTLS rows: an exporter output carried by an
//! `Option<Instant>`, an AES-CCM write key by a 692-byte buffer); this measures the source.
//!
//! How it measures. Each step of an association runs on a worker thread of its own whose
//! stack the test owns (`owned_stack`, shared with the SRTP measurement): making the
//! endpoints and the ClientHello, every delivery of one side's datagrams to the other during
//! the handshake, exporting the DTLS-SRTP keying material (RFC 5764 section 4.2), protecting
//! and unprotecting application data, DTLS 1.3 key updates (RFC 9147 section 8), the
//! close_notify exchange, and the teardown; for ticket resumption the same again for the
//! resumed association. The association is handed from one worker to the next in boxes, so
//! what a worker's dead frames hold is what THAT step left. The workers stay alive and parked
//! until the end: then the secrets are known and every worker's dead frames are read.
//!
//! What is looked for. The association runs over a crypto provider that wraps the real one
//! and records, inverted, every secret that crosses the provider boundary (each (EC)DHE shared
//! secret, every key an HMAC, AEAD, CBC or record-number mask object is made with, and what
//! each HMAC is first asked to sign), as `tests/dtls_secret_erasure.rs` does. From those the
//! test computes with the provider's HMAC the DTLS 1.2 PRF outputs (master secret, key block,
//! exporter output, each `A(i)`; RFC 5246 section 5) and every DTLS 1.3 `HKDF-Expand-Label`
//! output (RFC 8446 section 7.1), and turns each secret into the forms an implementation holds
//! it in (`residue_forms`: AES round keys of both schedules and the GHASH key forms, HMAC
//! padded keys and SHA-1 / SHA-256 states). All of that runs on a scratch worker whose stack
//! is overwritten and unmapped before anything is searched. The needles are checked against
//! what the association used (each record key is in a recomputed key block or is an
//! `HKDF-Expand-Label` "key" output; the recomputed exporter output is what was exported), and
//! a control step leaves the exported material on a stack and must be found, so "nothing
//! found" cannot come from a wrong computation.
//!
//! What it does not see: registers, signal frames, the heap (the quarantine tests of
//! `tests/dtls_secret_erasure.rs` are the heap side), and Windows (unix only: the owned stack
//! needs `pthread_attr_setstack`). The recording wrapper adds one frame per provider call; it
//! handles keys only through references and writes them only inverted.
//!
//! What is asserted is in each test's documentation; what the dead frames hold after each step
//! is printed either way (`STAGE`, `FORM`, `SUMMARY`, `INVENTORY` lines;
//! `scripts/key-residue-report.sh dtls` collects them).

#[cfg(unix)]
#[path = "../../rtci-srtp/tests/owned_stack/mod.rs"]
mod owned_stack;
#[cfg(unix)]
mod residue_forms;

/// Unix only: a thread on a stack of the test's own needs `pthread_attr_setstack`.
#[cfg(all(unix, any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
mod residue_tests {
    use std::net::SocketAddr;
    use std::ops::Range;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::owned_stack::{Parked, on_scratch_stack, run_parked};
    use super::residue_forms::{
        Finder, HmacHash, MAX_NEEDLE, Needle, aes_forms, check_local_primitives, hmac_forms,
        uninvert, wipe,
    };
    use crypto::{
        ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm,
        CbcCipher, CryptoAlgorithm, CryptoError, HashAlgorithm, HeaderMask, HeaderMaskAlgorithm,
        HmacAlgorithm, KeyExchangeAlgorithm, Mac, PublicKey, RTCCrypto, RTCCryptoProvider,
        RTCRandom, SecretVec, SignatureScheme, SigningKey, StreamCipher, StreamCipherAlgorithm,
    };
    use rtci_dtls::cipher_suite::CipherSuiteId;
    use rtci_dtls::config::{ConfigBuilder, DtlsVersion, HandshakeConfig};
    use rtci_dtls::crypto::Certificate;
    use rtci_dtls::endpoint::{Endpoint, EndpointEvent};
    use rtci_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
    use rtci_dtls::session::MemorySessionStore;
    use rtci_dtls::state::State;
    use shared::TransportProtocol;

    /// One measurement at a time: the records are global.
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

    fn invert(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(|b| !b).collect()
    }

    // -----------------------------------------------------------------------------------------
    // The recording provider (as in tests/dtls_secret_erasure.rs).

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kind {
        Hmac(HmacAlgorithm),
        Aead(AeadAlgorithm),
        Cbc,
        Stream,
        HeaderMask(HeaderMaskAlgorithm),
        Block,
        SharedSecret,
    }

    /// A secret the provider was handed or gave back, inverted; for an HMAC key, the first
    /// inputs it signed, inverted.
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

        fn new_hmac(
            &self,
            algorithm: HmacAlgorithm,
            key: &[u8],
        ) -> Result<Box<dyn Mac>, CryptoError> {
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
            record(Kind::HeaderMask(algorithm), key);
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

    /// An HMAC that records what it is first asked to sign: the seed of a PRF, the
    /// `HkdfLabel` of an `HKDF-Expand`.
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

    // -----------------------------------------------------------------------------------------
    // From the records to the needles (on a scratch worker).

    /// The DTLS 1.2 PRF labels (RFC 5246 sections 6.3, 7.4.9 and 8.1, RFC 7627 section 4, RFC
    /// 5705 section 4), with the name of the secret each is keyed with.
    const PRF_LABELS: [(&[u8], &str); 6] = [
        (b"master secret", "the premaster secret"),
        (b"extended master secret", "the premaster secret"),
        (b"key expansion", "the master secret"),
        (b"EXTRACTOR", "the master secret"),
        (b"client finished", "the master secret"),
        (b"server finished", "the master secret"),
    ];

    /// The labels whose output is key material (the Finished ones give verify_data, which is
    /// sent).
    const KEY_PRF_LABELS: [&[u8]; 4] = [
        b"master secret",
        b"extended master secret",
        b"key expansion",
        b"EXTRACTOR",
    ];

    /// The blocks of P_hash computed: enough for the longest key block (AES-256-CBC-SHA, 136
    /// bytes) and an SRTP exporter output.
    const PRF_BLOCKS: usize = 5;

    /// The shortest secret looked for (the 4-byte implicit nonces of the AES-GCM and AES-CCM
    /// suites are left out).
    const SHORTEST: usize = 12;

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

    /// The label of an `HkdfLabel` (RFC 8446 section 7.1, prefixed "dtls13" by RFC 9147
    /// section 5.9) at the start of `input`, with the output length it asks for.
    fn hkdf_label(input: &[u8]) -> Option<(String, usize)> {
        let length = usize::from(u16::from_be_bytes([*input.first()?, *input.get(1)?]));
        let label_len = usize::from(*input.get(2)?);
        let label = input.get(3..3 + label_len)?;
        let label = label.strip_prefix(b"dtls13")?;
        Some((String::from_utf8_lossy(label).into_owned(), length))
    }

    /// How a secret's forms are made.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Forms {
        /// The bytes as they are.
        Raw,
        Hmac(HmacHash),
        Aes {
            gcm: bool,
        },
    }

    /// What a secret is, for what is asserted about it.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Class {
        /// Not a key: an IV (the per-record nonce is the IV XORed with the sequence number,
        /// so the nonce of sequence number 0 IS the IV, and `RecordKeys::nonce` copies the
        /// whole IV into its frame first), or PRF output past the keys of a key block. An AEAD
        /// does not need its nonce to be secret; it is counted and printed, not asserted.
        NotKey,
        /// A secret of key derivation: (EC)DHE shared secret, premaster and master secret, PRF
        /// intermediates, HKDF secrets, Finished and binder keys, cookie secrets, the exported
        /// keying material. The record path never uses one.
        Derivation,
        /// A record key, its key schedule or MAC key (AEAD, CBC, HMAC-SHA1 record MAC,
        /// record-number mask): used for every record, inside the handshake too.
        RecordKey,
    }

    /// One secret, inverted, with the ways it is used.
    struct Secret {
        name: String,
        inverted: Vec<u8>,
        forms: Vec<Forms>,
        class: Class,
    }

    #[derive(Default)]
    struct Derived {
        secrets: Vec<Secret>,
        /// Each DTLS 1.2 key block, whole, inverted.
        key_blocks: Vec<Vec<u8>>,
        /// Each DTLS 1.2 master secret computed from a premaster secret.
        master_secrets: usize,
        /// The first block of each DTLS 1.2 exporter output, inverted.
        exporter_blocks: Vec<Vec<u8>>,
        /// Each DTLS 1.3 `HKDF-Expand-Label` output, by label, inverted.
        expanded: Vec<(String, Vec<u8>)>,
    }

    impl Derived {
        /// Adds a secret; one already there with the same bytes takes the name and the use too.
        fn push(&mut self, name: impl Into<String>, inverted: &[u8], forms: Forms, class: Class) {
            if inverted.len() < SHORTEST || inverted.iter().all(|b| *b == 0xff) {
                return;
            }
            let name = name.into();
            match self.secrets.iter_mut().find(|s| s.inverted == inverted) {
                Some(secret) => {
                    if !secret.name.split(" = ").any(|n| n == name) {
                        secret.name = format!("{} = {name}", secret.name);
                    }
                    if !secret.forms.contains(&forms) {
                        secret.forms.push(forms);
                    }
                    // A record key that is also a block of a PRF is a record key.
                    secret.class = secret.class.max(class);
                }
                None => self.secrets.push(Secret {
                    name,
                    inverted: inverted.to_vec(),
                    forms: vec![forms],
                    class,
                }),
            }
        }
    }

    fn hmac_hash(algorithm: HmacAlgorithm) -> HmacHash {
        match algorithm {
            HmacAlgorithm::Sha1 => HmacHash::Sha1,
            HmacAlgorithm::Sha256 => HmacHash::Sha256,
            _ => HmacHash::Wide,
        }
    }

    fn derive(
        provider: &dyn RTCCryptoProvider,
        records: &[Record],
        exported: &[Vec<u8>],
        psk: bool,
    ) -> Derived {
        let mut derived = Derived::default();
        if psk {
            derived.push("the PSK", &PSK_INVERTED, Forms::Raw, Class::Derivation);
        }
        for material in exported {
            derived.push(
                "the exported keying material",
                material,
                Forms::Raw,
                Class::Derivation,
            );
        }
        // The record keys, to tell the keys of a key block from its IVs.
        let record_keys: Vec<&[u8]> = records
            .iter()
            .filter(|r| {
                matches!(
                    r.kind,
                    Kind::Aead(_) | Kind::Cbc | Kind::Hmac(HmacAlgorithm::Sha1)
                )
            })
            .map(|r| r.inverted.as_slice())
            .collect();
        for record in records {
            let class = match record.kind {
                Kind::Hmac(HmacAlgorithm::Sha1) => Class::RecordKey,
                Kind::Hmac(_) | Kind::SharedSecret => Class::Derivation,
                _ => Class::RecordKey,
            };
            let (name, forms) = match record.kind {
                Kind::Hmac(algorithm) => {
                    let first: Vec<u8> = record
                        .inputs
                        .first()
                        .map(|input| input.iter().take(64).map(|b| !b).collect())
                        .unwrap_or_default();
                    let name = if let Some((_, secret)) = PRF_LABELS
                        .iter()
                        .find(|(label, _)| first.starts_with(label))
                    {
                        (*secret).to_owned()
                    } else if let Some((label, _)) = hkdf_label(&first) {
                        format!("the secret HKDF-Expand-Label \"{label}\" is keyed with")
                    } else {
                        format!("an HMAC-{algorithm:?} key of another use (HKDF-Extract, cookie)")
                    };
                    (name, Forms::Hmac(hmac_hash(algorithm)))
                }
                Kind::Aead(algorithm) => (
                    format!("an {algorithm:?} key"),
                    match algorithm {
                        AeadAlgorithm::ChaCha20Poly1305 => Forms::Raw,
                        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => {
                            Forms::Aes { gcm: true }
                        }
                        _ => Forms::Aes { gcm: false },
                    },
                ),
                Kind::Cbc => ("an AES-CBC key".to_owned(), Forms::Aes { gcm: false }),
                Kind::Stream => ("a stream cipher key".to_owned(), Forms::Aes { gcm: false }),
                Kind::HeaderMask(algorithm) => (
                    format!("a record-number key ({algorithm:?})"),
                    match algorithm {
                        HeaderMaskAlgorithm::ChaCha20 => Forms::Raw,
                        _ => Forms::Aes { gcm: false },
                    },
                ),
                Kind::Block => ("a block cipher key".to_owned(), Forms::Aes { gcm: false }),
                Kind::SharedSecret => ("an (EC)DHE shared secret".to_owned(), Forms::Raw),
            };
            derived.push(name, &record.inverted, forms, class);
            let Kind::Hmac(algorithm) = record.kind else {
                continue;
            };
            for input in &record.inputs {
                let plain_start: Vec<u8> = input.iter().take(64).map(|b| !b).collect();
                if let Some(label) = KEY_PRF_LABELS
                    .iter()
                    .find(|label| plain_start.starts_with(label))
                {
                    // P_hash (RFC 5246 section 5): A(1) = HMAC(secret, seed), A(i) =
                    // HMAC(secret, A(i-1)); block i = HMAC(secret, A(i) + seed).
                    let label = String::from_utf8_lossy(label).into_owned();
                    let mut a = hmac_inverted(provider, algorithm, &record.inverted, &[input]);
                    let mut output = Vec::new();
                    let mut blocks = Vec::new();
                    for i in 1..=PRF_BLOCKS {
                        let block =
                            hmac_inverted(provider, algorithm, &record.inverted, &[&a, input]);
                        derived.push(
                            format!("A({i}) of the PRF \"{label}\""),
                            &a,
                            Forms::Raw,
                            Class::Derivation,
                        );
                        blocks.push(block.clone());
                        output.extend_from_slice(&block);
                        a = hmac_inverted(provider, algorithm, &record.inverted, &[&a]);
                    }
                    let expansion = label == "key expansion";
                    // Where the record keys lie in a key block: the rest is IVs and output
                    // past the keys.
                    let keys_at: Vec<Range<usize>> = if expansion {
                        record_keys
                            .iter()
                            .flat_map(|key| {
                                output
                                    .windows(key.len())
                                    .enumerate()
                                    .filter(|(_, w)| w == key)
                                    .map(|(at, _)| at..at + key.len())
                                    .collect::<Vec<_>>()
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let in_a_key = |bytes: Range<usize>| {
                        if keys_at
                            .iter()
                            .any(|key| key.start < bytes.end && bytes.start < key.end)
                        {
                            Class::RecordKey
                        } else {
                            Class::NotKey
                        }
                    };
                    for (i, block) in blocks.iter().enumerate() {
                        let class = if expansion {
                            in_a_key(i * block.len()..(i + 1) * block.len())
                        } else {
                            Class::Derivation
                        };
                        derived.push(
                            format!("block {} of the PRF \"{label}\"", i + 1),
                            block,
                            Forms::Raw,
                            class,
                        );
                    }
                    match label.as_str() {
                        "key expansion" => {
                            // Every key and IV of the block starts at a multiple of 4.
                            for at in (0..output.len() - SHORTEST).step_by(4) {
                                derived.push(
                                    format!("key block bytes {at}..{}", at + SHORTEST),
                                    &output[at..at + SHORTEST],
                                    Forms::Raw,
                                    in_a_key(at..at + SHORTEST),
                                );
                            }
                            derived.key_blocks.push(output);
                        }
                        "master secret" | "extended master secret" => {
                            derived.push(
                                "the master secret",
                                &output[..48],
                                Forms::Raw,
                                Class::Derivation,
                            );
                            derived.master_secrets += 1;
                        }
                        _ => derived.exporter_blocks.push(output[..32].to_vec()),
                    }
                } else if let Some((label, length)) = hkdf_label(&plain_start) {
                    let output = hmac_inverted(provider, algorithm, &record.inverted, &[input]);
                    let length = length.min(output.len());
                    let class = match label.as_str() {
                        "key" | "sn" => Class::RecordKey,
                        "iv" => Class::NotKey,
                        _ => Class::Derivation,
                    };
                    derived.push(
                        format!("HKDF-Expand-Label \"{label}\" output"),
                        &output[..length],
                        Forms::Raw,
                        class,
                    );
                    derived.expanded.push((label, output[..length].to_vec()));
                }
            }
        }
        derived
    }

    /// Every form of every secret: the needles.
    fn needles_of(derived: &Derived) -> (Vec<Needle>, Vec<Class>) {
        let mut out: Vec<Needle> = Vec::new();
        let mut classes: Vec<Class> = Vec::new();
        let mut plain = [0u8; MAX_NEEDLE];
        for secret in &derived.secrets {
            let len = uninvert(&secret.inverted, &mut plain);
            let before = out.len();
            for forms in &secret.forms {
                match forms {
                    Forms::Raw => out.push(Needle::plain(&secret.name, "the key", &plain[..len])),
                    Forms::Hmac(hash) => hmac_forms(&mut out, &secret.name, &plain[..len], *hash),
                    Forms::Aes { gcm } if matches!(len, 16 | 24 | 32) => {
                        aes_forms(&mut out, &secret.name, &plain[..len], *gcm)
                    }
                    Forms::Aes { .. } => {
                        out.push(Needle::plain(&secret.name, "the key", &plain[..len]))
                    }
                }
            }
            wipe(&mut plain);
            classes.resize(classes.len() + out.len() - before, secret.class);
        }
        // One needle per byte string: a secret used two ways has its plain form once.
        let mut unique: Vec<Needle> = Vec::new();
        let mut unique_classes: Vec<Class> = Vec::new();
        for (needle, class) in out.into_iter().zip(classes) {
            if needle.len() < SHORTEST {
                continue;
            }
            match unique
                .iter()
                .position(|u| u.inverted() == needle.inverted())
            {
                Some(at) => unique_classes[at] = unique_classes[at].max(class),
                None => {
                    unique.push(needle);
                    unique_classes.push(class);
                }
            }
        }
        (unique, unique_classes)
    }

    /// The needles are what the association used: each record key the provider was handed is
    /// in a key block (DTLS 1.2) or is an `HKDF-Expand-Label` "key" output (DTLS 1.3), and the
    /// exporter output computed is the material exported.
    fn check_needles(
        name: &str,
        derived: &Derived,
        records: &[(Kind, Vec<u8>)],
        exported: &[Vec<u8>],
    ) {
        for (_, key) in records
            .iter()
            .filter(|(kind, _)| matches!(kind, Kind::Aead(_) | Kind::Cbc))
        {
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
        assert!(!exported.is_empty(), "{name}: keying material was exported");
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

    // -----------------------------------------------------------------------------------------
    // Associations.

    const CLIENT: &str = "127.0.0.1:44301";
    const SERVER: &str = "127.0.0.1:44302";
    const EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";
    /// The DTLS-SRTP keying material of AES_CM_128_HMAC_SHA1_80: two keys and two salts.
    const EXPORTED_LEN: usize = 60;
    const RECORDS_EACH_WAY: usize = 4;

    fn client_addr() -> SocketAddr {
        CLIENT.parse().expect("an address")
    }

    fn server_addr() -> SocketAddr {
        SERVER.parse().expect("an address")
    }

    struct Configs {
        client: Arc<HandshakeConfig>,
        server: Arc<HandshakeConfig>,
        #[allow(dead_code)]
        store: Option<Arc<MemorySessionStore>>,
    }

    /// What `ConfigBuilder::with_psk` takes.
    type PskCallback = Arc<dyn Fn(&[u8]) -> shared::error::Result<Vec<u8>> + Send + Sync>;

    /// The PSK of the PSK scenario, inverted (the plain bytes are made only when handed over).
    const PSK_INVERTED: [u8; 32] = [
        0x5d, 0xa2, 0x13, 0xee, 0x47, 0x90, 0x2b, 0xc6, 0x71, 0x0e, 0xb8, 0x34, 0xf9, 0x66, 0xd1,
        0x08, 0x9b, 0x24, 0xe7, 0x52, 0x3a, 0xcd, 0x80, 0x1f, 0x6c, 0xb5, 0x49, 0xf2, 0x07, 0xaa,
        0x3e, 0xd4,
    ];

    fn configs(
        provider: &Arc<dyn RTCCryptoProvider>,
        certificate: &Certificate,
        version: DtlsVersion,
        suite: CipherSuiteId,
        tickets: bool,
        psk: bool,
    ) -> Configs {
        let mut client = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
            .with_protocol_versions(version, version)
            .with_cipher_suites(vec![suite])
            .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80])
            .with_server_name("localhost".to_owned());
        let mut server = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
            .with_protocol_versions(version, version)
            .with_cipher_suites(vec![suite])
            .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80])
            .with_certificates(vec![certificate.clone()]);
        if psk {
            // RFC 4279: the application's callback hands the PSK over in a heap buffer.
            let callback: PskCallback = Arc::new(|_hint: &[u8]| Ok(invert(&PSK_INVERTED)));
            client = client
                .with_psk(Some(callback.clone()))
                .with_psk_identity_hint(Some(b"device".to_vec()));
            server = server.with_psk(Some(callback));
        }
        let store = tickets.then(|| Arc::new(MemorySessionStore::new()));
        if let Some(store) = &store {
            client = client.with_session_store(Some(store.clone()));
            server = server.with_session_tickets(1);
        }
        Configs {
            client: Arc::new(client.build(true, None).expect("a client configuration")),
            server: Arc::new(server.build(false, None).expect("a server configuration")),
            store,
        }
    }

    /// A client and a server endpoint, boxed: handing them from worker to worker moves only
    /// pointers.
    struct Association {
        client: Box<Endpoint>,
        server: Box<Endpoint>,
    }

    impl Association {
        fn client_state(&self) -> &State {
            self.client
                .get_connection_state(server_addr())
                .expect("the client's association")
        }

        fn server_state(&self) -> &State {
            self.server
                .get_connection_state(client_addr())
                .expect("the server's association")
        }
    }

    /// What the steps hand each other: pointers only.
    #[derive(Default)]
    struct Carry {
        provider: Option<Arc<dyn RTCCryptoProvider>>,
        certificate: Option<Box<Certificate>>,
        configs: Option<Box<Configs>>,
        association: Option<Association>,
        /// The exported keying material of each export, inverted.
        exported: Vec<Vec<u8>>,
        /// Whether the last delivery moved a datagram.
        moved: bool,
        /// Whether the client reported the handshake complete.
        completed: bool,
        resumed: bool,
    }

    /// The endpoints in the shape of an association `connect` makes.
    fn connect(c: &mut Carry, now: Instant) {
        let configs = c.configs.as_ref().expect("configurations");
        let mut client = Box::new(Endpoint::new(client_addr(), TransportProtocol::UDP, None));
        let server = Box::new(Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(configs.server.clone()),
        ));
        client
            .connect(now, server_addr(), configs.client.clone(), None)
            .expect("connect");
        c.association = Some(Association { client, server });
        c.completed = false;
    }

    /// Delivers every datagram one side has queued to the other. Returns the application data
    /// records the receiver reported.
    fn deliver(c: &mut Carry, now: Instant, from_client: bool) -> usize {
        let association = c.association.as_mut().expect("an association");
        let (from, to, from_addr) = if from_client {
            (
                &mut association.client,
                &mut association.server,
                client_addr(),
            )
        } else {
            (
                &mut association.server,
                &mut association.client,
                server_addr(),
            )
        };
        c.moved = false;
        let mut data = 0;
        while let Some(packet) = from.poll_transmit() {
            c.moved = true;
            let events = to
                .read(now, from_addr, packet.transport.ecn, packet.message)
                .expect("a datagram read");
            for event in &events {
                match event {
                    EndpointEvent::HandshakeComplete if !from_client => c.completed = true,
                    EndpointEvent::ApplicationData(_) => data += 1,
                    _ => {}
                }
            }
        }
        data
    }

    /// Deliveries both ways until neither side has anything to send.
    fn pump(c: &mut Carry, now: Instant) {
        for _ in 0..8 {
            deliver(c, now, true);
            let client_sent = c.moved;
            deliver(c, now, false);
            if !client_sent && !c.moved {
                break;
            }
        }
    }

    fn export(c: &mut Carry) {
        let association = c.association.as_ref().expect("an association");
        for state in [association.client_state(), association.server_state()] {
            let material = state
                .export_keying_material(EXPORTER_LABEL, &[], EXPORTED_LEN)
                .expect("keying material");
            c.exported.push(invert(material.as_ref()));
        }
        c.resumed = association.client_state().resumed();
    }

    fn records(c: &mut Carry, now: Instant) {
        let payload = b"application data of a DTLS record";
        let association = c.association.as_mut().expect("an association");
        for _ in 0..RECORDS_EACH_WAY {
            association
                .client
                .write(now, server_addr(), payload)
                .expect("a record written");
        }
        assert_eq!(
            RECORDS_EACH_WAY,
            deliver(c, now, true),
            "records to the server"
        );
        let association = c.association.as_mut().expect("an association");
        for _ in 0..RECORDS_EACH_WAY {
            association
                .server
                .write(now, client_addr(), payload)
                .expect("a record written");
        }
        assert_eq!(
            RECORDS_EACH_WAY,
            deliver(c, now, false),
            "records to the client"
        );
    }

    /// The client closes (RFC 5246 section 7.2.1): its close_notify to the server, the
    /// server's close_notify back. `Endpoint::close` has already forgotten the client's
    /// association, so the reply reaches a client endpoint with no association for the server
    /// and no server configuration, which refuses it (`NoServerConfig`): it is read and the
    /// refusal ignored, as an application would drop it.
    fn close(c: &mut Carry, now: Instant) {
        let association = c.association.as_mut().expect("an association");
        association.client.close(now).expect("close_notify");
        deliver(c, now, true);
        let association = c.association.as_mut().expect("an association");
        while let Some(packet) = association.server.poll_transmit() {
            let _ =
                association
                    .client
                    .read(now, server_addr(), packet.transport.ecn, packet.message);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Steps on workers.

    /// The steps so far, each a worker parked on a stack the test owns.
    struct Steps {
        session: String,
        workers: Vec<Parked<Box<Carry>>>,
        /// The kind of each step: what the inventory and the assertions count by.
        kinds: Vec<&'static str>,
        carry: Option<Box<Carry>>,
    }

    impl Steps {
        fn new(session: String, carry: Carry) -> Self {
            Self {
                session,
                workers: Vec::new(),
                kinds: Vec::new(),
                carry: Some(Box::new(carry)),
            }
        }

        /// Runs `work` on a worker of its own and parks it.
        fn run(
            &mut self,
            kind: &'static str,
            name: String,
            work: impl FnOnce(&mut Carry) + Send + 'static,
        ) -> &Carry {
            let mut carry = self.carry.take().expect("the carry");
            let name: &'static str = Box::leak(name.into_boxed_str());
            let mut worker = run_parked(name, move || {
                work(&mut carry);
                carry
            });
            self.carry = Some(worker.take());
            self.workers.push(worker);
            self.kinds.push(kind);
            self.carry.as_deref().expect("the carry")
        }

        /// A handshake: the endpoints, then one delivery per step until nothing moves.
        fn handshake(&mut self, prefix: &str, now: Instant) {
            self.run("connect", format!("{prefix}connect"), move |c| {
                connect(c, now)
            });
            for k in 1..=16 {
                let from_client = k % 2 == 1;
                let direction = if from_client {
                    "client to server"
                } else {
                    "server to client"
                };
                let moved = self
                    .run(
                        "handshake",
                        format!("{prefix}delivery {k} ({direction})"),
                        move |c| {
                            deliver(c, now, from_client);
                        },
                    )
                    .moved;
                if !moved {
                    break;
                }
            }
            assert!(
                self.carry.as_ref().expect("the carry").completed,
                "{}: {prefix}the handshake completes",
                self.session
            );
        }
    }

    /// What one step left in its worker's dead frames.
    struct Residue {
        needle: usize,
        copies: usize,
        depth: Range<usize>,
    }

    struct Stage {
        name: &'static str,
        kind: &'static str,
        used: usize,
        residue: Vec<Residue>,
    }

    fn dead_frames(finder: &Finder<'_>, worker: &Parked<Box<Carry>>, kind: &'static str) -> Stage {
        worker.verify();
        let dead = worker.dead();
        let mut residue: Vec<Residue> = Vec::new();
        finder.each(dead, |needle, offset| {
            let depth = dead.len() - offset;
            match residue.iter_mut().find(|r| r.needle == needle) {
                Some(found) => {
                    found.copies += 1;
                    found.depth = found.depth.start.min(depth)..found.depth.end.max(depth);
                }
                None => residue.push(Residue {
                    needle,
                    copies: 1,
                    depth: depth..depth,
                }),
            }
        });
        residue.sort_by_key(|r| r.needle);
        Stage {
            name: worker.name,
            kind,
            used: worker.used(),
            residue,
        }
    }

    /// What is measured.
    #[derive(Clone, Copy, Debug)]
    enum Scenario {
        /// A full handshake, export, records, close, teardown.
        Full(DtlsVersion, CipherSuiteId),
        /// A full handshake that issues a ticket, then a second association resumed from it.
        Resumed(DtlsVersion, CipherSuiteId),
        /// A full DTLS 1.2 handshake with a PSK suite (RFC 4279).
        Psk(CipherSuiteId),
    }

    impl Scenario {
        fn all() -> Vec<Scenario> {
            use CipherSuiteId::*;
            use DtlsVersion::*;
            vec![
                Scenario::Full(Dtls1_2, Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
                Scenario::Full(Dtls1_2, Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm),
                Scenario::Full(Dtls1_2, Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256),
                Scenario::Full(Dtls1_2, Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha),
                Scenario::Psk(Tls_Psk_With_Aes_128_Gcm_Sha256),
                Scenario::Resumed(Dtls1_2, Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
                Scenario::Full(Dtls1_3, Tls_Aes_128_Gcm_Sha256),
                Scenario::Full(Dtls1_3, Tls_Aes_128_Ccm_Sha256),
                Scenario::Full(Dtls1_3, Tls_ChaCha20_Poly1305_Sha256),
                Scenario::Resumed(Dtls1_3, Tls_Aes_128_Gcm_Sha256),
            ]
        }

        fn name(self) -> String {
            match self {
                Scenario::Full(version, suite) => format!("{version:?} {suite:?}"),
                Scenario::Resumed(version, suite) => format!("{version:?} {suite:?} resumed"),
                Scenario::Psk(suite) => format!("Dtls1_2 {suite:?}"),
            }
        }
    }

    /// What one scenario showed.
    struct Measured {
        session: String,
        needles: Vec<Needle>,
        /// The class of each needle.
        classes: Vec<Class>,
        stages: Vec<Stage>,
    }

    /// Runs `scenario` with `provider`, each step on a worker of its own, and searches every
    /// worker's dead frames once the secrets are known.
    fn scenario(
        provider: &Arc<dyn RTCCryptoProvider>,
        scenario: Scenario,
        control: bool,
    ) -> Measured {
        let session = format!("{}|{}", provider.name(), scenario.name());
        let (version, suite, resumption, psk) = match scenario {
            Scenario::Full(version, suite) => (version, suite, false, false),
            Scenario::Resumed(version, suite) => (version, suite, true, false),
            Scenario::Psk(suite) => (DtlsVersion::Dtls1_2, suite, false, true),
        };
        RECORDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        // The server's certificate, made with the real provider on a scratch worker.
        let inner = provider.clone();
        let certificate = on_scratch_stack(move || {
            Box::new(
                Certificate::generate_self_signed(vec!["localhost".into()], inner.crypto())
                    .expect("a self-signed certificate"),
            )
        });
        let carry = Carry {
            provider: Some(Recording::wrap(provider.clone())),
            certificate: Some(certificate),
            ..Carry::default()
        };
        let mut steps = Steps::new(session.clone(), carry);
        let now = Instant::now();
        steps.run("connect", "configurations".to_owned(), move |c| {
            let provider = c.provider.as_ref().expect("the provider");
            let certificate = c.certificate.as_ref().expect("the certificate");
            c.configs = Some(Box::new(configs(
                provider,
                certificate,
                version,
                suite,
                resumption,
                psk,
            )));
        });
        steps.handshake("", now);
        steps.run("export", "export".to_owned(), export);
        if control {
            steps.run("control", "control".to_owned(), leave_the_exported_material);
        }
        steps.run("records", "records".to_owned(), move |c| records(c, now));
        if version == DtlsVersion::Dtls1_3 && !resumption {
            for request_peer in [true, false] {
                let name = if request_peer {
                    "key update (the peer asked to update too)"
                } else {
                    "key update"
                };
                steps.run("key update", name.to_owned(), move |c| {
                    c.association
                        .as_mut()
                        .expect("an association")
                        .client
                        .update_keys(now, server_addr(), request_peer)
                        .expect("a key update");
                    pump(c, now);
                });
            }
        }
        if resumption {
            steps.run("teardown", "first association torn down".to_owned(), |c| {
                c.association = None;
            });
            steps.handshake("resumed: ", now);
            steps.run("export", "resumed: export".to_owned(), export);
            assert!(
                steps.carry.as_ref().expect("the carry").resumed,
                "{session}: the second association resumed"
            );
            steps.run("records", "resumed: records".to_owned(), move |c| {
                records(c, now)
            });
        }
        steps.run("close", "close".to_owned(), move |c| close(c, now));
        steps.run("teardown", "teardown".to_owned(), |c| {
            c.association = None;
            c.configs = None;
            c.provider = None;
            c.certificate = None;
        });

        // The secrets are known now: derive them and their forms on a scratch worker.
        let mut carry = steps.carry.take().expect("the carry");
        let exported = std::mem::take(&mut carry.exported);
        let inner = provider.clone();
        let name = session.clone();
        let check = !resumption;
        let (needles, classes) = on_scratch_stack(move || {
            let records = std::mem::take(&mut *RECORDS.lock().unwrap_or_else(|e| e.into_inner()));
            let derived = derive(inner.as_ref(), &records, &exported, psk);
            if check {
                let kinds: Vec<(Kind, Vec<u8>)> = records
                    .iter()
                    .map(|r| (r.kind, r.inverted.clone()))
                    .collect();
                check_needles(&name, &derived, &kinds, &exported);
                if version == DtlsVersion::Dtls1_2 {
                    assert!(
                        derived.master_secrets > 0,
                        "{name}: a master secret was computed"
                    );
                } else {
                    let updates = derived
                        .expanded
                        .iter()
                        .filter(|(label, _)| label == "traffic upd")
                        .count();
                    assert!(updates >= 2, "{name}: both directions updated their keys");
                }
            }
            needles_of(&derived)
        });
        let finder = Finder::new(&needles);
        let stages = steps
            .workers
            .iter()
            .zip(&steps.kinds)
            .map(|(worker, kind)| dead_frames(&finder, worker, kind))
            .collect();
        drop(finder);
        for worker in steps.workers.drain(..) {
            worker.finish();
        }
        Measured {
            session,
            needles,
            classes,
            stages,
        }
    }

    /// The control step: the exported keying material in the clear in a local of a frame that
    /// returns without erasing it. The search must find it there (`measure`).
    fn leave_the_exported_material(c: &mut Carry) {
        #[inline(never)]
        fn on_the_stack(inverted: &[u8]) {
            let mut plain = [0u8; MAX_NEEDLE];
            for (dst, src) in plain.iter_mut().zip(inverted) {
                // SAFETY: `dst` is a valid, aligned, exclusive reference.
                unsafe { std::ptr::write_volatile(dst, !*src) };
            }
            std::hint::black_box(&mut plain);
        }
        #[inline(never)]
        fn deeper(inverted: &[u8]) {
            let mut distance = [0u8; 4096];
            std::hint::black_box(&mut distance);
            on_the_stack(inverted);
        }
        deeper(&c.exported[0]);
    }

    // -----------------------------------------------------------------------------------------
    // The inventory and what is asserted.

    /// Everything one test measured.
    struct Inventory {
        /// Key forms found in dead stack frames, over every scenario and step (the control
        /// left out), of every class.
        forms: usize,
        /// The same per kind of step and class.
        by_step: Vec<(&'static str, Class, usize)>,
        /// Record-key forms in the scenarios of the AES-GCM suites, any step.
        gcm_record_keys: usize,
        /// Forms of the AES-CBC suites' cipher keys (key, round keys, key-block bytes), any
        /// step: RustCrypto's AES in rtci-crypto, with either provider.
        cbc_cipher_keys: usize,
        /// Forms of the AES-CBC suites' HMAC-SHA1 MAC keys (padded keys, states), any step:
        /// the provider's HMAC.
        cbc_mac_keys: usize,
        /// Record-key forms in the scenarios of the AES-CCM suites, any step: RustCrypto's AES
        /// in rtci-crypto, with either provider.
        ccm_record_keys: usize,
        /// The deepest AES-CCM record-key form (bytes below the floor) and where.
        ccm_deepest: (usize, String),
    }

    impl Inventory {
        fn in_step(&self, step: &str, class: Class) -> usize {
            self.by_step
                .iter()
                .filter(|(name, c, _)| *name == step && *c == class)
                .map(|(_, _, forms)| *forms)
                .sum()
        }

        fn of_class(&self, class: Class) -> usize {
            self.by_step
                .iter()
                .filter(|(_, c, _)| *c == class)
                .map(|(_, _, forms)| *forms)
                .sum()
        }
    }

    /// Every scenario with the provider named `name`, printed.
    fn measure(name: &str) -> Inventory {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        check_local_primitives();
        let mut inventory = Inventory {
            forms: 0,
            by_step: Vec::new(),
            gcm_record_keys: 0,
            cbc_cipher_keys: 0,
            cbc_mac_keys: 0,
            ccm_record_keys: 0,
            ccm_deepest: (0, String::new()),
        };
        // The deepest form of each class: (distance below the floor, where).
        let mut deepest: Vec<(Class, usize, String)> = Vec::new();
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        let mut summary: Vec<(String, usize, usize)> = Vec::new();
        // A scenario that fails (a panic in a step or a check) is reported and the others
        // still measured; the test then fails on it after the inventory is printed.
        let mut failed: Vec<String> = Vec::new();
        for provider in providers().into_iter().filter(|p| p.name() == name) {
            for (n, s) in Scenario::all().into_iter().enumerate() {
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    scenario(&provider, s, n == 0)
                }));
                let m = match run {
                    Ok(m) => m,
                    Err(panic) => {
                        let why = panic
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                            .unwrap_or_default();
                        let line = format!("{}|{}: {why}", provider.name(), s.name());
                        println!("SCENARIO FAILED {line}");
                        failed.push(line);
                        continue;
                    }
                };
                for stage in &m.stages {
                    println!(
                        "STAGE {}|{}|stack used {} bytes|{} key forms left",
                        m.session,
                        stage.name,
                        stage.used,
                        stage.residue.len()
                    );
                    if stage.kind == "control" {
                        if stage
                            .residue
                            .iter()
                            .any(|r| m.needles[r.needle].key == "the exported keying material")
                        {
                            println!(
                                "CONTROL the exported keying material left on a stack is found"
                            );
                        } else {
                            let line = format!(
                                "{}: CONTROL: the exported keying material left on the control \
                                 step's stack was not found: the search does not see what it must",
                                m.session
                            );
                            println!("{line}");
                            failed.push(line);
                        }
                        continue;
                    }
                    for residue in &stage.residue {
                        let needle = &m.needles[residue.needle];
                        let class = m.classes[residue.needle];
                        let form = format!(
                            "{}|{}|{:?}|{}|{}",
                            m.session, stage.name, class, needle.key, needle.form
                        );
                        match deepest.iter_mut().find(|(c, _, _)| *c == class) {
                            Some((_, depth, at)) if *depth < residue.depth.end => {
                                *depth = residue.depth.end;
                                *at = form.clone();
                            }
                            Some(_) => {}
                            None => deepest.push((class, residue.depth.end, form.clone())),
                        }
                        if class == Class::RecordKey {
                            let hmac = needle.form.starts_with("HMAC")
                                || needle.form.starts_with("key XOR");
                            if m.session.contains("Ccm") {
                                inventory.ccm_record_keys += 1;
                                if residue.depth.end > inventory.ccm_deepest.0 {
                                    inventory.ccm_deepest = (residue.depth.end, form.clone());
                                }
                            } else if m.session.contains("Cbc") && hmac {
                                inventory.cbc_mac_keys += 1;
                            } else if m.session.contains("Cbc") {
                                inventory.cbc_cipher_keys += 1;
                            } else if m.session.contains("Gcm") {
                                inventory.gcm_record_keys += 1;
                            }
                        }
                        match inventory
                            .by_step
                            .iter_mut()
                            .find(|(k, c, _)| *k == stage.kind && *c == class)
                        {
                            Some((_, _, forms)) => *forms += 1,
                            None => inventory.by_step.push((stage.kind, class, 1)),
                        }
                        for byte in form.bytes().chain(*b"\n") {
                            digest = (digest ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
                        }
                        println!(
                            "FORM {form}|{} copies|{} to {} bytes below the floor",
                            residue.copies, residue.depth.start, residue.depth.end
                        );
                        let key = format!("{}|{}|{}", provider.name(), stage.kind, needle.key);
                        match summary.iter_mut().find(|(k, _, _)| *k == key) {
                            Some((_, forms, copies)) => {
                                *forms += 1;
                                *copies += residue.copies;
                            }
                            None => summary.push((key, 1, residue.copies)),
                        }
                    }
                    inventory.forms += stage.residue.len();
                }
            }
        }
        for (key, forms, copies) in &summary {
            println!("SUMMARY {key}|{forms} key forms|{copies} copies");
        }
        for (class, depth, at) in &deepest {
            println!("DEEPEST {name} {class:?}: {depth} bytes below the floor: {at}");
        }
        println!(
            "INVENTORY dtls {name}: {} key forms in dead stack frames {:?}, digest {digest:016x}, {} build",
            inventory.forms,
            inventory.by_step,
            if cfg!(debug_assertions) {
                "unoptimised"
            } else {
                "optimised"
            }
        );
        assert!(
            failed.is_empty(),
            "scenarios that did not complete their measurement: {failed:#?}"
        );
        inventory
    }

    /// The steps that run no record protection: making the endpoints and the first flight,
    /// the export, the teardown.
    const SETUP_STEPS: [&str; 3] = ["connect", "export", "teardown"];
    /// Every kind of step.
    const ALL_STEPS: [&str; 7] = [
        "connect",
        "handshake",
        "export",
        "records",
        "key update",
        "close",
        "teardown",
    ];

    /// What holds with every provider and in every build: no secret of key derivation (see
    /// [`Class::Derivation`]) after any step, and no key at all after the steps that run no
    /// record protection. Record keys left by the record path (inside the handshake too: the
    /// Finished and later records) are counted and printed (`NOT ASSERTED`), and so are IVs.
    fn check(inventory: &Inventory) {
        for step in ALL_STEPS {
            assert_eq!(
                0,
                inventory.in_step(step, Class::Derivation),
                "secrets of key derivation left in dead stack frames by the `{step}` steps \
                 (the FORM lines above name each)"
            );
        }
        for step in SETUP_STEPS {
            assert_eq!(
                0,
                inventory.in_step(step, Class::RecordKey),
                "record keys left in dead stack frames by the `{step}` steps, which protect no \
                 record (the FORM lines above name each)"
            );
        }
        println!(
            "RECORD PATH: {} record-key forms (AES-GCM {}, AES-CBC cipher keys {}, AES-CBC MAC \
             keys {}, AES-CCM {}, the rest ChaCha20-Poly1305) and {} IV forms (not asserted) left \
             by steps that protect records",
            inventory.of_class(Class::RecordKey),
            inventory.gcm_record_keys,
            inventory.cbc_cipher_keys,
            inventory.cbc_mac_keys,
            inventory.ccm_record_keys,
            inventory.of_class(Class::NotKey)
        );
    }

    /// The environment variable that moves the AES-CCM record path from asserted to printed:
    /// `1` for a compiler on which it was measured to leave a key (rustc 1.89, optimised: one
    /// round key of a DTLS 1.3 AES-CCM record key, run 46012389383; none with 1.99.1 and
    /// 1.100). `scripts/key-residue-report.sh` and the `key_residue` CI job set it for
    /// compilers older than 1.99.1, the first measured to hold.
    const CCM_KNOWN_LIMIT: &str = "RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT";

    /// The AES-CCM record path (RustCrypto's AES in rtci-crypto, with either provider):
    /// asserted to leave no key form; in an optimised build unless [`CCM_KNOWN_LIMIT`] is `1`,
    /// then printed with its count and depth. (In an unoptimised build rtci-crypto overwrites
    /// the stack after every RustCrypto AES record operation, `scrub_record_stack`, so the
    /// compiler does not matter there.)
    fn check_ccm(inventory: &Inventory) {
        if !cfg!(debug_assertions) && std::env::var_os(CCM_KNOWN_LIMIT).is_some_and(|v| v == "1") {
            println!(
                "NOT ASSERTED ({CCM_KNOWN_LIMIT}=1): {} AES-CCM record-key forms, the deepest \
                 {} bytes below the floor: {}",
                inventory.ccm_record_keys, inventory.ccm_deepest.0, inventory.ccm_deepest.1
            );
        } else {
            assert_eq!(
                0, inventory.ccm_record_keys,
                "AES-CCM record keys left in dead stack frames (the FORM lines above name each; \
                 in an optimised build {CCM_KNOWN_LIMIT}=1 states this as the limit of a \
                 compiler older than rustc 1.99.1)"
            );
        }
    }

    /// RFC 7714 section 13.1, RFC 5246 section 8.1, RFC 8446 section 7.1, with the ring
    /// provider (the default): a DTLS association's key derivation leaves none of its secrets
    /// in the dead stack frames of the thread that ran it. For DTLS 1.2 with each cipher
    /// suite family (AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CBC with HMAC-SHA1), DTLS 1.3
    /// with AES-GCM, AES-CCM and ChaCha20-Poly1305 and key updates, and ticket resumption in
    /// both: after every step no (EC)DHE, premaster, master, PRF, HKDF, Finished, binder,
    /// cookie secret or exported keying material is found in any form, and after the steps
    /// that protect no record, no key at all ([`check`]). In every build also no record key of
    /// an AES suite after any step: AES-GCM, AES-CBC (cipher and MAC keys) and AES-CCM
    /// ([`check_ccm`]: in an optimised build printed instead with
    /// `RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT=1`, set for compilers older than rustc 1.99.1). Not
    /// asserted: ring's ChaCha20-Poly1305 record path, which copies the key to the stack for
    /// every record, and the IVs (a record's nonce is its IV at sequence number 0).
    #[cfg(feature = "crypto-ring")]
    #[test]
    fn with_ring_dtls_key_handling_leaves_no_key_in_dead_stack_frames() {
        let inventory = measure("ring");
        check(&inventory);
        assert_eq!(
            0,
            inventory.gcm_record_keys + inventory.cbc_cipher_keys + inventory.cbc_mac_keys,
            "record keys of an AES-GCM or AES-CBC suite left in dead stack frames (the FORM \
             lines above name each)"
        );
        check_ccm(&inventory);
    }

    /// The same with the AWS-LC provider ([`check`]), and in every build no form of a key of
    /// the record path rtci-crypto composes from RustCrypto's AES with either provider: the
    /// AES-CBC cipher keys and AES-CCM ([`check_ccm`]). AWS-LC's own record path
    /// leaves a GHASH table entry of the AES-GCM key and the HMAC-SHA1 states of the AES-CBC MAC
    /// key for every record: the known limit below.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    fn with_aws_lc_dtls_key_handling_leaves_no_key_in_dead_stack_frames() {
        let inventory = measure("aws-lc-rs");
        check(&inventory);
        assert_eq!(
            0, inventory.cbc_cipher_keys,
            "AES-CBC cipher keys left in dead stack frames (the FORM lines above name each)"
        );
        check_ccm(&inventory);
    }

    /// The requirement as a test with the AWS-LC provider: no key form after any step, the
    /// record path included (IVs left out). Run with `-- --ignored known_limit_ --nocapture`.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    #[ignore = "known limit: the AWS-LC provider's record path leaves keys in dead stack frames (docs/test-exclusions.md)"]
    fn known_limit_with_aws_lc_the_dtls_record_path_leaves_keys_in_dead_stack_frames() {
        let inventory = measure("aws-lc-rs");
        check(&inventory);
        assert_eq!(
            0,
            inventory.of_class(Class::RecordKey),
            "record keys left in dead stack frames (the FORM lines above name each)"
        );
    }
}

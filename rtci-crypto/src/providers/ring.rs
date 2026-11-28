use crate::common;
use crate::common::check_tag_len;
use crate::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher,
    CryptoAlgorithm, CryptoError, HEADER_MASK_LEN, HEADER_MASK_SAMPLE_LEN, HashAlgorithm,
    HeaderMask, HeaderMaskAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, Mac, PublicKey,
    PublicKeyEncoding, RTCCrypto, RTCCryptoProvider, RTCRandom, SecretVec, SignatureScheme,
    SigningKey, StreamCipher, StreamCipherAlgorithm, constant_time_eq,
};
use ::hmac::Mac as RustCryptoMac;
use ring::aead;
use ring::agreement;
use ring::digest;
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};
use sha1::Sha1;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{Ordering, compiler_fence};

/// The built-in Ring provider bundle.
#[derive(Default)]
pub struct RingProvider {
    crypto: RingCrypto,
    random: RingRandom,
}

impl RingProvider {
    /// Creates a Ring provider.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            crypto: RingCrypto,
            random: RingRandom,
        }
    }
}

impl RTCCryptoProvider for RingProvider {
    fn name(&self) -> &'static str {
        "ring"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

/// Ring-backed cryptographic operations, with documented RustCrypto fallbacks for primitives Ring
/// does not expose (MD5, AES block/CTR/CBC, and AES-CCM).
#[derive(Default)]
pub struct RingCrypto;

/// Ring's operating-system-backed secure random source.
#[derive(Default)]
pub struct RingRandom;

impl RTCRandom for RingRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        common::fill_random(output)
    }

    fn fill_secret(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        use ring::rand::SecureRandom;
        SystemRandom::new()
            .fill(output)
            .map_err(|_| CryptoError::RandomnessFailed)
    }
}

impl RTCCrypto for RingCrypto {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        matches!(
            algorithm,
            CryptoAlgorithm::Hash(
                HashAlgorithm::Md5
                    | HashAlgorithm::Sha256
                    | HashAlgorithm::Sha1
                    | HashAlgorithm::Sha224
                    | HashAlgorithm::Sha384
                    | HashAlgorithm::Sha512
            ) | CryptoAlgorithm::Hmac(
                HmacAlgorithm::Sha1
                    | HmacAlgorithm::Sha256
                    | HmacAlgorithm::Sha384
                    | HmacAlgorithm::Sha512
            ) | CryptoAlgorithm::HeaderMask(
                HeaderMaskAlgorithm::Aes128
                    | HeaderMaskAlgorithm::Aes256
                    | HeaderMaskAlgorithm::ChaCha20
            ) | CryptoAlgorithm::Aead(
                AeadAlgorithm::Aes128Gcm
                    | AeadAlgorithm::Aes256Gcm
                    | AeadAlgorithm::Aes128Ccm
                    | AeadAlgorithm::Aes128Ccm8
                    | AeadAlgorithm::ChaCha20Poly1305,
            ) | CryptoAlgorithm::StreamCipher(
                StreamCipherAlgorithm::Aes128Ctr
                    | StreamCipherAlgorithm::Aes256Ctr
                    | StreamCipherAlgorithm::Aes192Ctr,
            ) | CryptoAlgorithm::BlockCipher(
                BlockCipherAlgorithm::Aes128
                    | BlockCipherAlgorithm::Aes256
                    | BlockCipherAlgorithm::Aes192,
            ) | CryptoAlgorithm::Cbc(CbcAlgorithm::Aes256Cbc)
                | CryptoAlgorithm::KeyExchange(
                    KeyExchangeAlgorithm::P256
                        | KeyExchangeAlgorithm::P384
                        | KeyExchangeAlgorithm::X25519,
                )
                | CryptoAlgorithm::Signature(
                    SignatureScheme::Ed25519
                        | SignatureScheme::EcdsaP256Sha256
                        | SignatureScheme::EcdsaP384Sha256
                        | SignatureScheme::EcdsaP384Sha384
                        | SignatureScheme::RsaPkcs1Sha1
                        | SignatureScheme::RsaPkcs1Sha256
                        | SignatureScheme::RsaPkcs1Sha384
                        | SignatureScheme::RsaPkcs1Sha512
                        | SignatureScheme::RsaPssSha256
                        | SignatureScheme::RsaPssSha384
                        | SignatureScheme::RsaPssSha512,
                )
                | CryptoAlgorithm::SigningKeyGeneration(
                    SignatureScheme::Ed25519 | SignatureScheme::EcdsaP256Sha256,
                )
                | CryptoAlgorithm::SigningKeyImport(
                    SignatureScheme::Ed25519
                        | SignatureScheme::EcdsaP256Sha256
                        | SignatureScheme::RsaPkcs1Sha256,
                )
        )
    }

    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            HashAlgorithm::Md5 => Ok(common::md5(data)),
            HashAlgorithm::Sha256 => Ok(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
            HashAlgorithm::Sha1 => Ok(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
                .as_ref()
                .to_vec()),
            // ring has no SHA-224.
            HashAlgorithm::Sha224 => Ok(common::sha224(data)),
            HashAlgorithm::Sha384 => Ok(digest::digest(&digest::SHA384, data).as_ref().to_vec()),
            HashAlgorithm::Sha512 => Ok(digest::digest(&digest::SHA512, data).as_ref().to_vec()),
        }
    }

    fn new_hmac(&self, algorithm: HmacAlgorithm, key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        match algorithm {
            // ring's SHA-1 is a software implementation and measures 3.3x slower than
            // RustCrypto's; see common::RustCryptoHmacSha1. SHA-256 stays on ring, which uses
            // the hardware instructions.
            HmacAlgorithm::Sha1 => Ok(Box::new(RustCryptoHmacSha1::new(key))),
            HmacAlgorithm::Sha256 | HmacAlgorithm::Sha384 | HmacAlgorithm::Sha512 => {
                Ok(Box::new(RingHmac {
                    key: ErasedOnDrop::new(hmac::Key::new(hmac_algorithm(algorithm), key)),
                    output_len: algorithm.output_len(),
                }))
            }
        }
    }

    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        key: &[u8],
        block: &mut [u8],
    ) -> Result<(), CryptoError> {
        common::block_encrypt(algorithm, key, block)
    }

    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        common::new_stream_cipher(algorithm, key)
    }

    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        match algorithm {
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::Aes128Ccm8 => common::new_ccm(algorithm, key),
            AeadAlgorithm::Aes128Gcm => RingAead::create(&aead::AES_128_GCM, key),
            AeadAlgorithm::Aes256Gcm => RingAead::create(&aead::AES_256_GCM, key),
            AeadAlgorithm::ChaCha20Poly1305 => RingAead::create(&aead::CHACHA20_POLY1305, key),
        }
    }

    fn new_header_mask(
        &self,
        algorithm: HeaderMaskAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn HeaderMask>, CryptoError> {
        common::check_key_len(algorithm.key_len(), key.len())?;
        let backend_algorithm = match algorithm {
            HeaderMaskAlgorithm::Aes128 => &aead::quic::AES_128,
            HeaderMaskAlgorithm::Aes256 => &aead::quic::AES_256,
            HeaderMaskAlgorithm::ChaCha20 => &aead::quic::CHACHA20,
        };
        let key = aead::quic::HeaderProtectionKey::new(backend_algorithm, key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Box::new(RingHeaderMask {
            key: ErasedOnDrop::new(key),
        }))
    }

    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        common::new_cbc(algorithm, key)
    }

    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        RingKeyExchange::start(algorithm)
    }

    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        RingSigningKey::generate(scheme)
    }

    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        RingSigningKey::import(scheme, pkcs8_der)
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        public_key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_public_key_encoding(scheme, public_key.encoding)?;
        signature::UnparsedPublicKey::new(verification_algorithm(scheme), public_key.bytes)
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// A ring key object kept in an allocation of this crate's own, overwritten with zeros when
/// it is dropped (RFC 7714 section 13.1, RFC 8446 section 7.1).
///
/// ring keeps a key schedule inline in each key object (`aead::LessSafeKey`: the AES round
/// keys and the GHASH table, or the ChaCha20 key; `aead::quic::HeaderProtectionKey`: the AES
/// round keys or the ChaCha20 key; `hmac::Key`: the two SHA-2 states after `key XOR ipad` and
/// `key XOR opad`) and does not overwrite it when the object is dropped (ring issue #15
/// settled against destructor-based erasure). So the object is moved, once, into a
/// `Box<MaybeUninit<T>>` that this type owns, is only ever lent out as `&T`, and when this is
/// dropped the value is dropped in place and THEN the `size_of::<T>()` bytes of the slot are
/// overwritten with volatile writes, before the box frees the allocation.
///
/// Soundness. After `assume_init_drop` the slot holds no live value: its bytes are the memory
/// of a `MaybeUninit<T>` that this type owns, which may hold any bytes at all. Writing zeros
/// there is a write to our own allocation through a raw byte pointer, so it is defined
/// behaviour whatever ring's layout is (it does not depend on ring's fields, and an all-zero
/// `T` is never read: `MaybeUninit` has no drop glue and the box is freed next). The volatile
/// writes and the fence keep the compiler from removing them as stores to memory about to be
/// freed.
///
/// What this type cannot reach, and so does not erase: a copy moved out of it (which is why
/// it never hands the value out by move, only `&T`), and the copies that building the value
/// left in the stack frames of the functions that built it. The engine's callers build a key
/// object from a frame of their own and call [`crate::scrub_stack`] right after it. Bytes a
/// provider type keeps outside the object (a heap allocation of its own, a global cache) are
/// out of reach too; ring 0.17's AEAD, header-protection and HMAC keys keep none.
struct ErasedOnDrop<T> {
    slot: Box<MaybeUninit<T>>,
}

impl<T> ErasedOnDrop<T> {
    fn new(value: T) -> Self {
        let mut slot = Box::<T>::new_uninit();
        MaybeUninit::write(&mut *slot, value);
        Self { slot }
    }

    fn get(&self) -> &T {
        // SAFETY: `new` initialized the slot, and the value is dropped only in `drop`.
        unsafe { self.slot.assume_init_ref() }
    }

    /// Hands the value to an API that consumes it by value (ring's `agree_ephemeral` takes the
    /// ECDHE private key so), overwriting the slot it leaves. The value returned is a copy in
    /// the caller's frame, which this type cannot reach: the caller scrubs the stack after
    /// the consuming call. Only for such APIs; everything else borrows with [`Self::get`].
    fn into_inner(mut self) -> T {
        // SAFETY: `new` initialized the slot; the value is read out once, the slot is then
        // overwritten and freed without being dropped (`forget` below skips `Drop`).
        let value = unsafe { self.slot.assume_init_read() };
        self.overwrite();
        // SAFETY: `self.slot` is read out once and `self` is forgotten, so the box is freed
        // exactly once (as a `Box<MaybeUninit<T>>`, which drops no value).
        let slot = unsafe { std::ptr::read(&self.slot) };
        std::mem::forget(self);
        drop(slot);
        value
    }

    /// Overwrites the slot with zeros. Only once it holds no value.
    fn overwrite(&mut self) {
        let bytes = self.slot.as_mut_ptr().cast::<u8>();
        for offset in 0..size_of::<T>() {
            // SAFETY: `offset` is inside the slot, which this type owns and which holds no
            // value any more; a `u8` has no validity requirement.
            unsafe { std::ptr::write_volatile(bytes.add(offset), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T> Drop for ErasedOnDrop<T> {
    fn drop(&mut self) {
        // SAFETY: `new` initialized the slot; the value is dropped here, once, and never used
        // again.
        unsafe { self.slot.assume_init_drop() };
        self.overwrite();
    }
}

/// A keyed HMAC holding a `ring::hmac::Key`.
///
/// `Key::new` performs the ipad/opad derivation; `Context::with_key` only clones the resulting
/// state. Keeping the key here is what moves that derivation off the per-packet path.
struct RingHmac {
    key: ErasedOnDrop<hmac::Key>,
    output_len: usize,
}

impl Mac for RingHmac {
    fn output_len(&self) -> usize {
        self.output_len
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        common::check_tag_len(self.output_len, output.len())?;
        let mut context = hmac::Context::with_key(self.key.get());
        for part in input {
            context.update(part);
        }
        output.copy_from_slice(context.sign().as_ref());
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        common::check_tag_len(self.output_len, expected.len())?;
        let mut actual = vec![0; self.output_len];
        self.sign(input, &mut actual)?;
        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

fn hmac_algorithm(algorithm: HmacAlgorithm) -> hmac::Algorithm {
    match algorithm {
        HmacAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HmacAlgorithm::Sha512 => hmac::HMAC_SHA512,
        HmacAlgorithm::Sha384 => hmac::HMAC_SHA384,
    }
}

/// A record-number mask generator on the backend's QUIC header-protection key, which is the
/// computation RFC 9147 section 4.2.3 defines (AES-ECB of the sample, or the ChaCha20 block
/// function keyed by it).
struct RingHeaderMask {
    key: ErasedOnDrop<aead::quic::HeaderProtectionKey>,
}

impl HeaderMask for RingHeaderMask {
    fn mask(
        &mut self,
        sample: &[u8; HEADER_MASK_SAMPLE_LEN],
    ) -> Result<[u8; HEADER_MASK_LEN], CryptoError> {
        self.key
            .get()
            .new_mask(sample)
            .map_err(|_| CryptoError::Provider("header mask generation failed".into()))
    }
}

struct RingAead {
    key: ErasedOnDrop<aead::LessSafeKey>,
}

impl RingAead {
    fn create(
        algorithm: &'static aead::Algorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        common::check_key_len(algorithm.key_len(), key.len())?;
        let key = aead::UnboundKey::new(algorithm, key)
            .map(aead::LessSafeKey::new)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Box::new(Self {
            key: ErasedOnDrop::new(key),
        }))
    }
}

impl AeadCipher for RingAead {
    fn tag_len(&self) -> usize {
        16
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        common::check_nonce_len(12, nonce.len())?;
        common::check_tag_len(self.tag_len(), tag_out.len())?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| {
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: nonce.len(),
            }
        })?;
        let tag = self
            .key
            .get()
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), plaintext_and_ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        tag_out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        common::check_nonce_len(12, nonce.len())?;
        common::check_tag_len(self.tag_len(), tag.len())?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| {
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: nonce.len(),
            }
        })?;
        let tag = aead::Tag::try_from(tag).map_err(|_| CryptoError::InvalidTagLength {
            expected: self.tag_len(),
            actual: tag.len(),
        })?;
        self.key
            .get()
            .open_in_place_separate_tag(
                nonce,
                aead::Aad::from(aad),
                tag,
                ciphertext_and_plaintext,
                0..,
            )
            .map(|_| ())
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

struct RingKeyExchange {
    algorithm: KeyExchangeAlgorithm,
    backend_algorithm: &'static agreement::Algorithm,
    /// ring's ephemeral private key keeps the scalar inline and does not erase it; it is
    /// consumed by value by `agree_ephemeral`, so it leaves its slot through `into_inner`.
    private_key: ErasedOnDrop<agreement::EphemeralPrivateKey>,
    public_key: Vec<u8>,
}

impl RingKeyExchange {
    fn start(algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        Self::start_with(algorithm, &SystemRandom::new())
    }

    fn start_with(
        algorithm: KeyExchangeAlgorithm,
        rng: &dyn ring::rand::SecureRandom,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let backend_algorithm = agreement_algorithm(algorithm)?;
        let private_key = agreement::EphemeralPrivateKey::generate(backend_algorithm, rng)
            .map_err(|_| CryptoError::RandomnessFailed)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::Provider("key exchange public-key generation failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Box::new(Self {
            algorithm,
            backend_algorithm,
            private_key: ErasedOnDrop::new(private_key),
            public_key,
        }))
    }
}

impl ActiveKeyExchange for RingKeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError> {
        let this = *self;
        let peer = agreement::UnparsedPublicKey::new(this.backend_algorithm, peer_public_key);
        agreement::agree_ephemeral(this.private_key.into_inner(), &peer, |secret| {
            SecretVec::new(secret.to_vec())
        })
        .map_err(|_| CryptoError::InvalidPublicKey)
    }
}

enum RingSigningKeyKind {
    Ed25519(signature::Ed25519KeyPair),
    EcdsaP256(signature::EcdsaKeyPair),
    Rsa(signature::RsaKeyPair),
}

struct RingSigningKey {
    scheme: SignatureScheme,
    /// ring's key pairs keep the private key inline (an RSA key also in limb buffers of its
    /// own) and do not erase it.
    kind: ErasedOnDrop<RingSigningKeyKind>,
    public_key: Vec<u8>,
    public_key_encoding: PublicKeyEncoding,
    pkcs8_der: SecretVec,
}

impl RingSigningKey {
    fn generate(scheme: SignatureScheme) -> Result<Arc<dyn SigningKey>, CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8 = match scheme {
            SignatureScheme::Ed25519 => signature::Ed25519KeyPair::generate_pkcs8(&rng),
            SignatureScheme::EcdsaP256Sha256 => signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &rng,
            ),
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    CryptoAlgorithm::SigningKeyGeneration(scheme),
                ));
            }
        }
        .map_err(|_| CryptoError::RandomnessFailed)?;
        Self::import(scheme, pkcs8.as_ref())
    }

    fn import(
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        let rng = SystemRandom::new();
        let (kind, public_key, public_key_encoding) = match scheme {
            SignatureScheme::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public_key().as_ref().to_vec();
                (
                    RingSigningKeyKind::Ed25519(key),
                    public,
                    PublicKeyEncoding::Ed25519Raw,
                )
            }
            SignatureScheme::EcdsaP256Sha256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8_der,
                    &rng,
                )
                .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public_key().as_ref().to_vec();
                (
                    RingSigningKeyKind::EcdsaP256(key),
                    public,
                    PublicKeyEncoding::EcUncompressedPoint,
                )
            }
            SignatureScheme::RsaPkcs1Sha256 => {
                let key = signature::RsaKeyPair::from_pkcs8(pkcs8_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public().as_ref().to_vec();
                (
                    RingSigningKeyKind::Rsa(key),
                    public,
                    PublicKeyEncoding::RsaPkcs1Der,
                )
            }
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    CryptoAlgorithm::SigningKeyImport(scheme),
                ));
            }
        };
        Ok(Arc::new(Self {
            scheme,
            kind: ErasedOnDrop::new(kind),
            public_key,
            public_key_encoding,
            pkcs8_der: SecretVec::new(pkcs8_der.to_vec()),
        }))
    }
}

impl SigningKey for RingSigningKey {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        // An RSA key with the rsaEncryption OID signs PKCS#1 v1.5 and RSASSA-PSS alike
        // (RFC 8446 section 4.2.3, the rsa_pss_rsae schemes).
        self.scheme == scheme
            || (matches!(self.kind.get(), RingSigningKeyKind::Rsa(_))
                && matches!(
                    scheme,
                    SignatureScheme::RsaPssSha256
                        | SignatureScheme::RsaPssSha384
                        | SignatureScheme::RsaPssSha512
                ))
    }

    fn public_key(&self) -> PublicKey<'_> {
        PublicKey {
            encoding: self.public_key_encoding,
            bytes: &self.public_key,
        }
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.supports(scheme) {
            return Err(CryptoError::UnsupportedAlgorithm(
                CryptoAlgorithm::Signature(scheme),
            ));
        }
        match self.kind.get() {
            RingSigningKeyKind::Ed25519(key) => Ok(key.sign(message).as_ref().to_vec()),
            RingSigningKeyKind::EcdsaP256(key) => key
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| CryptoError::Provider("signature generation failed".into())),
            RingSigningKeyKind::Rsa(key) => {
                let encoding: &'static dyn signature::RsaEncoding = match scheme {
                    SignatureScheme::RsaPssSha256 => &signature::RSA_PSS_SHA256,
                    SignatureScheme::RsaPssSha384 => &signature::RSA_PSS_SHA384,
                    SignatureScheme::RsaPssSha512 => &signature::RSA_PSS_SHA512,
                    _ => &signature::RSA_PKCS1_SHA256,
                };
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(encoding, &SystemRandom::new(), message, &mut signature)
                    .map_err(|_| CryptoError::Provider("signature generation failed".into()))?;
                Ok(signature)
            }
        }
    }

    fn to_pkcs8_der(&self) -> Result<Option<SecretVec>, CryptoError> {
        Ok(Some(self.pkcs8_der.clone()))
    }
}

fn agreement_algorithm(
    algorithm: KeyExchangeAlgorithm,
) -> Result<&'static agreement::Algorithm, CryptoError> {
    match algorithm {
        KeyExchangeAlgorithm::P256 => Ok(&agreement::ECDH_P256),
        KeyExchangeAlgorithm::P384 => Ok(&agreement::ECDH_P384),
        KeyExchangeAlgorithm::X25519 => Ok(&agreement::X25519),
        // ring has no ML-KEM.
        KeyExchangeAlgorithm::X25519MlKem768 => Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::KeyExchange(algorithm),
        )),
    }
}

fn verification_algorithm(
    scheme: SignatureScheme,
) -> &'static dyn signature::VerificationAlgorithm {
    match scheme {
        SignatureScheme::Ed25519 => &signature::ED25519,
        SignatureScheme::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::EcdsaP384Sha256 => &signature::ECDSA_P384_SHA256_ASN1,
        SignatureScheme::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::RsaPkcs1Sha1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        SignatureScheme::RsaPkcs1Sha256 => {
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
        }
        SignatureScheme::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RsaPkcs1Sha512 => {
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
        }
        SignatureScheme::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
        SignatureScheme::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
        SignatureScheme::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
    }
}

fn verify_public_key_encoding(
    scheme: SignatureScheme,
    encoding: PublicKeyEncoding,
) -> Result<(), CryptoError> {
    let valid = matches!(
        (scheme, encoding),
        (SignatureScheme::Ed25519, PublicKeyEncoding::Ed25519Raw)
            | (
                SignatureScheme::EcdsaP256Sha256
                    | SignatureScheme::EcdsaP384Sha256
                    | SignatureScheme::EcdsaP384Sha384,
                PublicKeyEncoding::EcUncompressedPoint
            )
            | (
                SignatureScheme::RsaPkcs1Sha1
                    | SignatureScheme::RsaPkcs1Sha256
                    | SignatureScheme::RsaPkcs1Sha384
                    | SignatureScheme::RsaPkcs1Sha512
                    | SignatureScheme::RsaPssSha256
                    | SignatureScheme::RsaPssSha384
                    | SignatureScheme::RsaPssSha512,
                PublicKeyEncoding::RsaPkcs1Der
            )
    );
    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidPublicKey)
    }
}

type HmacSha1 = ::hmac::HmacReset<Sha1>;

/// HMAC-SHA1 backed by RustCrypto (`hmac`, `sha1`), keyed once and computed in place.
///
/// `ring` exposes SHA-1 only as `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the SHA
/// instructions for it, measuring 4469 ns against RustCrypto's 1373 ns over a 1212-byte SRTP
/// packet: 3.3x, and the whole of the SRTP AES-CM/HMAC regression. The built-in providers are
/// already composite (AES-CTR, CCM, CBC and MD5 come from RustCrypto too), so HMAC-SHA1 is
/// composed the same way rather than making the slower backend the default. `aws-lc-rs` has
/// fast SHA-1 and keeps its own.
///
/// The keyed state is the key in another form: the SHA-1 states after `key XOR ipad` and
/// `key XOR opad` compute any MAC under it (RFC 7714 section 13.1 for SRTP; the record MAC keys
/// of the DTLS CBC suite). Where it lives:
///
/// * This object is boxed by `new_hmac`, and a MAC is computed in it, in place
///   (`HmacReset`: `update`, then `finalize_reset`, which puts the inner state back from the
///   copy the object keeps). No copy of the object is made per MAC. Until 0.2 each MAC was
///   computed on a clone of the keyed object in a stack frame, which left both states in a
///   dead frame for every packet (found by `rtci-srtp/tests/key_residue.rs`).
/// * `finalize_reset` works on one copy of the outer state, in its own frame; with the
///   `zeroize` features of `hmac` and `sha1` that copy, like every hash state of the object,
///   is overwritten when it is dropped. That is the crates' doing, not this one's.
pub(crate) struct RustCryptoHmacSha1 {
    keyed: HmacSha1,
}

impl RustCryptoHmacSha1 {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            // HMAC accepts any key length: it hashes longer keys and zero-pads shorter ones.
            keyed: <HmacSha1 as ::hmac::KeyInit>::new_from_slice(key)
                .expect("HMAC accepts keys of any length"),
        }
    }
}

impl Mac for RustCryptoHmacSha1 {
    fn output_len(&self) -> usize {
        20
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        check_tag_len(20, output.len())?;
        for part in input {
            self.keyed.update(part);
        }
        output.copy_from_slice(&self.keyed.finalize_reset().into_bytes());
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        check_tag_len(20, expected.len())?;
        let mut actual = [0u8; 20];
        self.sign(input, &mut actual)?;
        if crate::constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

/// Test support: the ring provider's key exchange with its private key drawn from `seed`
/// (exactly the seed length of the curve), so that a test knows the private scalar. Not part
/// of the supported API.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[allow(deprecated)]
pub fn ring_key_exchange_with_seed(
    algorithm: KeyExchangeAlgorithm,
    seed: &[u8],
) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
    RingKeyExchange::start_with(
        algorithm,
        &ring::test::rand::FixedSliceRandom { bytes: seed },
    )
}

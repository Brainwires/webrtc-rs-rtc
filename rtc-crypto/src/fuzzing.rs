//! Deterministic providers for fuzz targets.
//!
//! A fuzz target must behave the same way every time it is given the same input, or a crash it
//! finds cannot be replayed. The built-in providers draw randomness from the OS, so this module
//! wraps one with a seeded generator and, optionally, with fixed public-key operations: a key
//! exchange that always derives the same secret, and signatures that are a hash of the message
//! (an ECDSA signature draws its nonce from the OS). Gated behind `cfg(fuzzing)` (and the crate's
//! own tests); not part of the supported API. Nothing here is secure: it exists only so a fuzzer
//! can complete handshakes reproducibly.
use std::sync::{Arc, Mutex};

use crate::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher,
    CryptoAlgorithm, CryptoError, HashAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, Mac,
    PublicKey, RTCCrypto, RTCCryptoProvider, RTCRandom, SecretVec, SignatureScheme, SigningKey,
    StreamCipher, StreamCipherAlgorithm,
};

/// A splitmix64 generator behind a mutex, so it can serve `&self` callers.
struct SeededRandom(Mutex<u64>);

impl RTCRandom for SeededRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut state = self.0.lock().map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// A key exchange with a fixed public key and a fixed shared secret, so both ends of an
/// in-memory handshake agree without an ephemeral key drawn from the OS.
struct FixedKeyExchange {
    algorithm: KeyExchangeAlgorithm,
    public_key: Vec<u8>,
}

impl FixedKeyExchange {
    fn new(algorithm: KeyExchangeAlgorithm) -> Self {
        let public_key = match algorithm {
            KeyExchangeAlgorithm::X25519 => vec![0x09; 32],
            // Uncompressed SEC1 points: the tag byte followed by two coordinates.
            KeyExchangeAlgorithm::P256 => [&[0x04][..], &[0x11; 64][..]].concat(),
            KeyExchangeAlgorithm::P384 => [&[0x04][..], &[0x22; 96][..]].concat(),
        };
        Self {
            algorithm,
            public_key,
        }
    }
}

impl ActiveKeyExchange for FixedKeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError> {
        if peer_public_key.is_empty() {
            return Err(CryptoError::InvalidPublicKey);
        }
        let len = match self.algorithm {
            KeyExchangeAlgorithm::P384 => 48,
            _ => 32,
        };
        Ok(SecretVec::new(vec![0x5a; len]))
    }
}

/// The stand-in signature over `message`: its SHA-256, twice. Long enough to look like a real
/// signature to length checks, and the same on every run.
fn fixed_signature(inner: &dyn RTCCrypto, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest = inner.hash(HashAlgorithm::Sha256, message)?;
    Ok([digest.as_slice(), digest.as_slice()].concat())
}

/// A real imported key whose `sign` returns [`fixed_signature`] instead.
struct FixedSigningKey {
    inner: Arc<dyn SigningKey>,
    provider: Arc<dyn RTCCryptoProvider>,
}

impl SigningKey for FixedSigningKey {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        self.inner.supports(scheme)
    }

    fn public_key(&self) -> PublicKey<'_> {
        self.inner.public_key()
    }

    fn sign(&self, _scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        fixed_signature(self.provider.crypto(), message)
    }

    fn to_pkcs8_der(&self) -> Result<Option<SecretVec>, CryptoError> {
        self.inner.to_pkcs8_der()
    }
}

/// Forwards every operation to the wrapped implementation, except the public-key operations
/// when `fixed` is set.
struct DeterministicCrypto {
    inner: Arc<dyn RTCCryptoProvider>,
    fixed: bool,
}

impl RTCCrypto for DeterministicCrypto {
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
        self.inner.crypto().block_encrypt(algorithm, key, block)
    }

    fn new_hmac(&self, algorithm: HmacAlgorithm, key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        self.inner.crypto().new_hmac(algorithm, key)
    }

    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        self.inner.crypto().new_stream_cipher(algorithm, key)
    }

    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        self.inner.crypto().new_aead(algorithm, key)
    }

    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        self.inner.crypto().new_cbc(algorithm, key)
    }

    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        if self.fixed {
            Ok(Box::new(FixedKeyExchange::new(algorithm)))
        } else {
            self.inner.crypto().start_key_exchange(algorithm)
        }
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
        let key = self.inner.crypto().import_signing_key(scheme, pkcs8_der)?;
        if self.fixed {
            Ok(Arc::new(FixedSigningKey {
                inner: key,
                provider: self.inner.clone(),
            }))
        } else {
            Ok(key)
        }
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        public_key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if !self.fixed {
            return self
                .inner
                .crypto()
                .verify_signature(scheme, public_key, message, signature);
        }
        // Checks the stand-in signature, so a corrupted one is still refused.
        if fixed_signature(self.inner.crypto(), message)? == signature {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

/// A provider whose randomness comes from a fixed seed.
pub struct DeterministicProvider {
    crypto: DeterministicCrypto,
    random: SeededRandom,
}

impl DeterministicProvider {
    /// Wraps `inner`, replacing its randomness with a generator seeded from `seed`. With
    /// `fixed`, every key exchange also derives the same shared secret and imported keys sign
    /// with a hash of the message (which `verify_signature` checks), so a handshake between two
    /// such providers produces the same bytes on every run.
    pub fn new(inner: Arc<dyn RTCCryptoProvider>, seed: u64, fixed: bool) -> Self {
        Self {
            crypto: DeterministicCrypto { inner, fixed },
            random: SeededRandom(Mutex::new(seed)),
        }
    }
}

impl RTCCryptoProvider for DeterministicProvider {
    fn name(&self) -> &'static str {
        "deterministic-fuzzing"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

/// The built-in provider wrapped by [`DeterministicProvider`].
///
/// # Errors
///
/// Fails when no built-in provider is enabled.
pub fn deterministic_provider(
    seed: u64,
    fixed: bool,
) -> Result<Arc<dyn RTCCryptoProvider>, CryptoError> {
    Ok(Arc::new(DeterministicProvider::new(
        crate::default_provider()?,
        seed,
        fixed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_bytes() {
        let a = deterministic_provider(7, false).unwrap();
        let b = deterministic_provider(7, false).unwrap();
        let (mut x, mut y) = ([0u8; 37], [0u8; 37]);
        a.random().fill(&mut x).unwrap();
        b.random().fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 37]);
    }

    #[test]
    fn fixed_key_exchange_agrees() {
        let p = deterministic_provider(1, true).unwrap();
        let a = p
            .crypto()
            .start_key_exchange(KeyExchangeAlgorithm::X25519)
            .unwrap();
        let b = p
            .crypto()
            .start_key_exchange(KeyExchangeAlgorithm::X25519)
            .unwrap();
        let (pa, pb) = (a.public_key().to_vec(), b.public_key().to_vec());
        assert_eq!(
            a.complete(&pb).unwrap().as_ref(),
            b.complete(&pa).unwrap().as_ref()
        );
    }
}

//! OpenSSL AES-CTR stream cipher, behind the `openssl` feature.
//!
//! Upstream removed `rtc-srtp`'s `openssl` / `vendored-openssl` features when SRTP moved onto
//! `rtc-crypto` (fd81f68f). The Brainwires fork keeps them (it never removes a feature; see
//! FORK.md), with the OpenSSL code here so `rtc-crypto` stays the only crate that names a
//! crypto implementation. `rtc-srtp` with `openssl` takes the AES-CM profiles' keystream from
//! [`openssl_aes_ctr`]; key derivation, HMAC-SHA1 and the AEAD profiles stay on the selected
//! provider.

use crate::{CryptoError, StreamCipher, StreamCipherAlgorithm};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

/// Builds an AES-128/256-CTR [`StreamCipher`] backed by OpenSSL, keyed once.
///
/// # Errors
///
/// Fails for a non-CTR algorithm, a key of the wrong length, or an OpenSSL error.
pub fn openssl_aes_ctr(
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>, CryptoError> {
    Ok(Box::new(OpensslAesCtr::new(algorithm, key)?))
}

/// AES-128/256-CTR from OpenSSL.
struct OpensslAesCtr {
    ctx: CipherCtx,
}

fn openssl_error(error: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::Provider(format!("openssl: {error}"))
}

impl OpensslAesCtr {
    fn new(algorithm: StreamCipherAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        let (cipher, key_len) = match algorithm {
            StreamCipherAlgorithm::Aes128Ctr => (Cipher::aes_128_ctr(), 16),
            StreamCipherAlgorithm::Aes256Ctr => (Cipher::aes_256_ctr(), 32),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CryptoError::Provider(format!(
                    "openssl: unsupported stream cipher {algorithm:?}"
                )));
            }
        };
        if key.len() != key_len {
            return Err(CryptoError::InvalidKeyLength {
                expected: key_len,
                actual: key.len(),
            });
        }
        let mut ctx = CipherCtx::new().map_err(openssl_error)?;
        ctx.encrypt_init(Some(cipher), Some(key), None)
            .map_err(openssl_error)?;
        Ok(Self { ctx })
    }
}

impl StreamCipher for OpensslAesCtr {
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        self.ctx
            .encrypt_init(None, None, Some(iv))
            .map_err(openssl_error)?;
        // CTR is a stream mode: the output is exactly as long as the input, and OpenSSL
        // needs room for one extra block.
        let mut out = vec![0u8; data.len() + 16];
        let n = self
            .ctx
            .cipher_update(data, Some(&mut out))
            .map_err(openssl_error)?;
        let m = self
            .ctx
            .cipher_final(&mut out[n..])
            .map_err(openssl_error)?;
        if n + m != data.len() {
            return Err(CryptoError::Provider(format!(
                "openssl: AES-CTR produced {} bytes for {}",
                n + m,
                data.len()
            )));
        }
        data.copy_from_slice(&out[..data.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OpenSSL keystream must match the selected provider's, byte for byte.
    #[test]
    fn openssl_ctr_matches_the_provider_keystream() {
        let provider = crate::default_provider().expect("a built-in crypto provider for tests");
        for (algorithm, key_len) in [
            (StreamCipherAlgorithm::Aes128Ctr, 16),
            (StreamCipherAlgorithm::Aes256Ctr, 32),
        ] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            let iv = [7u8; 16];
            let mut a: Vec<u8> = (0..100u8).collect();
            let mut b = a.clone();
            OpensslAesCtr::new(algorithm, &key)
                .unwrap()
                .apply_keystream(&iv, &mut a)
                .unwrap();
            provider
                .crypto()
                .new_stream_cipher(algorithm, &key)
                .unwrap()
                .apply_keystream(&iv, &mut b)
                .unwrap();
            assert_eq!(a, b, "{algorithm:?}");
        }
    }
}

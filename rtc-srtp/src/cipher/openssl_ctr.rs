//! OpenSSL AES-CTR keystream for the AES-CM SRTP profiles, behind the `openssl` feature.
//!
//! Upstream removed the `openssl` / `vendored-openssl` features when SRTP moved onto
//! `rtc-crypto` (fd81f68f). The Brainwires fork keeps them (it never removes a feature; see
//! FORK.md): with `openssl` enabled the AES-CM profiles' keystream comes from OpenSSL, as it
//! did before, while key derivation, HMAC-SHA1 and the AEAD profiles stay on the selected
//! `rtc-crypto` provider.

use crypto::{CryptoError, StreamCipher, StreamCipherAlgorithm};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

/// AES-128/256-CTR from OpenSSL, keyed once per SRTP context.
pub(crate) struct OpensslAesCtr {
    ctx: CipherCtx,
}

fn openssl_error(error: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::Provider(format!("openssl: {error}"))
}

impl OpensslAesCtr {
    pub(crate) fn new(algorithm: StreamCipherAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
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
        let provider = crypto::default_provider().expect("a built-in crypto provider for tests");
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

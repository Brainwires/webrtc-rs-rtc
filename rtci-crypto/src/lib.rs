//! Provider-neutral cryptography for the webrtc-rs RTC stack.
//!
//! The open traits in this crate allow applications to supply cryptography and randomness without
//! registering global state. Built-in providers are selected with additive Cargo features.
//!
//! Key material: every struct holding secret key material derives `Zeroize` and
//! `ZeroizeOnDrop`, or holds each secret in [`SecretVec`]; secret keys are drawn with
//! [`RTCRandom::fill_secret`]; [`on_erased_stack`] runs key set-up and overwrites the stack it
//! ran on, and [`scrub_stack`] is the overwrite by itself. The RustCrypto primitives the
//! built-in providers use (`aes`, `ctr`, and the `hmac` / `sha1` of the ring provider's
//! HMAC-SHA1) erase their key schedules and hash states when dropped, and their keyed objects
//! are used in place: an AES-CTR keystream runs over a reference to the boxed schedule, an
//! HMAC-SHA1 is computed in the boxed keyed object. ring's own key objects (AEAD,
//! header-protection and HMAC keys) do not erase themselves, so the ring provider keeps each in
//! an allocation of its own and overwrites it after the drop (`docs/key-erasure.md`).

mod algorithm;
mod erased_stack;
mod error;
mod hkdf;
#[cfg(feature = "openssl")]
mod openssl_ctr;
mod provider;
mod rsa_pkcs1;
mod secret;
mod traits;

#[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
mod common;
pub mod providers;

#[cfg(feature = "test-support")]
pub mod conformance;

/// Deterministic providers for fuzz targets. Gated behind `cfg(fuzzing)`; not part of the
/// supported API.
#[cfg(all(
    any(fuzzing, test),
    any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")
))]
pub mod fuzzing;

pub use algorithm::*;
pub use erased_stack::on_erased_stack;
pub use error::CryptoError;
pub use hkdf::{hkdf_expand, hkdf_expand_label, hkdf_extract};
#[cfg(feature = "openssl")]
pub use openssl_ctr::openssl_aes_ctr;
pub use provider::default_provider;
pub use rsa_pkcs1::{rsa_pkcs1_hash, verify_rsa_pkcs1_without_digest_parameters};
pub use secret::{SecretVec, scrub_stack};
pub use traits::*;

/// Compares equal-length byte strings without data-dependent early exit.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    left.len() == right.len() && bool::from(left.ct_eq(right))
}

const _: () = {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn assert_dyn_compatible(
        _provider: &dyn RTCCryptoProvider,
        _crypto: &dyn RTCCrypto,
        _random: &dyn RTCRandom,
        _mac: &dyn Mac,
        _stream: &dyn StreamCipher,
        _aead: &dyn AeadCipher,
        _cbc: &dyn CbcCipher,
        _mask: &dyn HeaderMask,
        _exchange: &dyn ActiveKeyExchange,
        _signing_key: &dyn SigningKey,
    ) {
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretVec::new(vec![1, 2, 3, 4]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("len: 4"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }

    #[test]
    fn secret_into_bytes_is_explicit() {
        let secret = SecretVec::new(vec![1, 2, 3]);
        assert_eq!(secret.into_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn errors_have_provider_neutral_text() {
        assert_eq!(
            CryptoError::AuthenticationFailed.to_string(),
            "authentication failed"
        );
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "signature verification failed"
        );
    }

    #[test]
    fn constant_time_equality_checks_length_and_content() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"same", b"same-longer"));
    }
}

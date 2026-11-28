pub mod cipher_aead_aes_gcm;
#[cfg(test)]
mod cipher_aead_aes_gcm_profile_test;
pub mod cipher_aes_cm_hmac_sha1;

use std::sync::Arc;

use bytes::BytesMut;
use crypto::{
    CryptoError, RTCCrypto, RTCCryptoProvider, SecretVec, StreamCipher, StreamCipherAlgorithm,
};

use crate::cryptex::CryptexLayout;
use crate::header_extension::EncryptedHeaderExtensions;
use crate::key_derivation::Prf;
use crate::keying::KeyDerivationRate;
use shared::error::{Error, Result};

pub(crate) fn crypto_error(error: CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

/// An AES counter-mode keystream generator (RFC 3711 section 4.1.1) keyed with `key`.
///
/// With the `openssl` feature (kept by the Brainwires fork) the keystream comes from OpenSSL;
/// otherwise from the selected provider.
pub(crate) fn new_aes_cm(
    crypto: &dyn RTCCrypto,
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>> {
    #[cfg(feature = "openssl")]
    {
        let _ = crypto;
        crypto::openssl_aes_ctr(algorithm, key).map_err(crypto_error)
    }
    #[cfg(not(feature = "openssl"))]
    {
        crypto
            .new_stream_cipher(algorithm, key)
            .map_err(crypto_error)
    }
}

/// What a cipher derives session keys from: the PRF, the key derivation rate and, when the
/// rate is not zero, the master key and salt and the crypto implementation, which are then
/// needed again each time the packet index crosses a multiple of the rate (RFC 3711 section
/// 4.3.1). With a zero rate nothing is retained: the keys are derived once, at construction.
pub(crate) struct KeySource {
    pub(crate) prf: Prf,
    pub(crate) rate: KeyDerivationRate,
    retained: Option<RetainedMaster>,
}

struct RetainedMaster {
    master_key: SecretVec,
    master_salt: SecretVec,
    provider: Arc<dyn RTCCryptoProvider>,
}

impl KeySource {
    pub(crate) fn new(
        prf: Prf,
        rate: KeyDerivationRate,
        master_key: &[u8],
        master_salt: &[u8],
        provider: Option<Arc<dyn RTCCryptoProvider>>,
    ) -> Result<Self> {
        let retained = if rate.is_zero() {
            None
        } else {
            let provider = provider.ok_or_else(|| {
                Error::Other(
                    "a non-zero SRTP key derivation rate needs a retained crypto provider"
                        .to_owned(),
                )
            })?;
            Some(RetainedMaster {
                master_key: SecretVec::new(master_key.to_vec()),
                master_salt: SecretVec::new(master_salt.to_vec()),
                provider,
            })
        };
        Ok(Self {
            prf,
            rate,
            retained,
        })
    }

    /// Runs `derive` with the retained crypto implementation, master key and master salt.
    pub(crate) fn derive<K>(
        &self,
        derive: impl FnOnce(&dyn RTCCrypto, &[u8], &[u8]) -> Result<K>,
    ) -> Result<K> {
        // Not reached with a zero rate: every packet is then in epoch zero, which is derived at
        // construction and never evicted.
        let retained = self.retained.as_ref().ok_or_else(|| {
            Error::Other("SRTP session keys cannot be derived again: no master key retained".into())
        })?;
        // As when the cipher is built (`new_cipher`): the stack the derivation ran on is
        // overwritten afterwards. The keys it returns hold their key material in the heap.
        crypto::on_erased_stack(|| {
            derive(
                retained.provider.crypto(),
                retained.master_key.as_ref(),
                retained.master_salt.as_ref(),
            )
        })
    }
}

/// The session keys of the key derivation epochs (`index DIV kdr`) in use: the latest one and
/// the one before it, so packets reordered across a boundary do not derive the keys back and
/// forth. With a zero rate there is one epoch, zero, for the life of the master key.
pub(crate) struct Epochs<K> {
    current: (u64, K),
    previous: Option<(u64, K)>,
}

impl<K> Epochs<K> {
    pub(crate) fn new(epoch: u64, keys: K) -> Self {
        Self {
            current: (epoch, keys),
            previous: None,
        }
    }

    /// The keys of `epoch`, derived with `derive` when they are not held.
    pub(crate) fn get(
        &mut self,
        epoch: u64,
        derive: impl FnOnce(u64) -> Result<K>,
    ) -> Result<&mut K> {
        if self.current.0 != epoch {
            match self.previous.take() {
                Some(previous) if previous.0 == epoch => {
                    self.previous = Some(std::mem::replace(&mut self.current, previous));
                }
                _ => {
                    let keys = derive(epoch)?;
                    self.previous = Some(std::mem::replace(&mut self.current, (epoch, keys)));
                }
            }
        }
        Ok(&mut self.current.1)
    }
}

/// What a packet carries besides what the cipher computes.
#[derive(Clone, Copy)]
pub(crate) struct PacketOptions<'a> {
    /// The Master Key Identifier of the key in use: appended when protecting, skipped (it
    /// selected the key already) when unprotecting. Empty when the context uses no MKI.
    pub(crate) mki: &'a [u8],
    /// The header extension elements encrypted as RFC 6904 has it. Not used on the Cryptex
    /// paths: a packet is protected with one or the other (RFC 9335 section 5).
    pub(crate) header_extensions: &'a EncryptedHeaderExtensions,
}

impl PacketOptions<'static> {
    /// No MKI and no RFC 6904 encryption.
    #[cfg(test)]
    pub(crate) const NONE: Self = Self {
        mki: &[],
        header_extensions: &EncryptedHeaderExtensions::NONE,
    };
}

///NOTE: Auth tag and AEAD auth tag are placed at the different position in SRTCP
///
///In non-AEAD cipher, the authentication tag is placed *after* the ESRTCP word
///(Encrypted-flag and SRTCP index).
///
///> AES_128_CM_HMAC_SHA1_80
///> | RTCP Header | Encrypted payload |E| SRTCP Index | Auth tag |
///>                                   ^               |----------|
///>                                   |                ^
///>                                   |                authTagLen=10
///>                                   aeadAuthTagLen=0
///
///In AEAD cipher, the AEAD authentication tag is embedded in the ciphertext.
///It is *before* the ESRTCP word (Encrypted-flag and SRTCP index).
///
///> AEAD_AES_128_GCM
///> | RTCP Header | Encrypted payload | AEAD auth tag |E| SRTCP Index |
///>                                   |---------------|               ^
///>                                    ^                              authTagLen=0
///>                                    aeadAuthTagLen=16
///
///See https://tools.ietf.org/html/rfc7714 for the full specifications.
///
/// Cipher represents a implementation of one
/// of the SRTP Specific ciphers.
///
/// An MKI, when the context uses one, is neither encrypted nor authenticated (RFC 3711
/// sections 3.1 and 3.4, RFC 7714 sections 8.2 and 9.2). It sits before the authentication tag
/// with the HMAC profiles, and is the last field of the packet with the AEAD ones.
pub(crate) trait Cipher: Send {
    /// Get RTP authenticated tag length.
    fn rtp_auth_tag_len(&self) -> usize;

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize;

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize;

    /// Retrieved RTCP index. `input` is at least the profile's minimum SRTCP length plus
    /// `mki_len`.
    fn get_rtcp_index(&self, input: &[u8], mki_len: usize) -> usize;

    /// Encrypt RTP payload.
    fn encrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut>;

    /// Decrypt RTP payload.
    fn decrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut>;

    /// Encrypt an RTP packet with Cryptex (RFC 9335 section 6.2): the CSRCs, the header
    /// extension data and the payload, as one plaintext. `packet` already carries the
    /// Cryptex profile (see [`crate::cryptex::sender_packet`]).
    fn encrypt_rtp_cryptex(
        &mut self,
        packet: &[u8],
        header: &rtp::Header,
        roc: u32,
        layout: CryptexLayout,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut>;

    /// Decrypt an RTP packet protected with Cryptex (RFC 9335 section 6.3). The result
    /// still carries the Cryptex profile.
    fn decrypt_rtp_cryptex(
        &mut self,
        packet: &[u8],
        header: &rtp::Header,
        roc: u32,
        layout: CryptexLayout,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut>;

    /// Protect an RTCP packet. With `encrypt` false it is authenticated and sent with the E
    /// flag clear (RFC 3711 section 3.4, RFC 7714 section 9.3).
    fn encrypt_rtcp(
        &mut self,
        payload: &[u8],
        srtcp_index: usize,
        ssrc: u32,
        encrypt: bool,
        mki: &[u8],
    ) -> Result<BytesMut>;

    /// Decrypt RTCP payload.
    fn decrypt_rtcp(
        &mut self,
        payload: &[u8],
        srtcp_index: usize,
        ssrc: u32,
        mki_len: usize,
    ) -> Result<BytesMut>;
}

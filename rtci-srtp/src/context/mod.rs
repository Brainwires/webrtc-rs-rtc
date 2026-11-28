#[cfg(test)]
mod context_test;
#[cfg(test)]
mod cryptex_test;
#[cfg(test)]
mod discard_events_test;
#[cfg(test)]
mod header_extension_test;
#[cfg(test)]
mod key_lifetime_test;
#[cfg(test)]
mod keying_test;
#[cfg(test)]
mod profiles_test;
#[cfg(test)]
mod rfc3711_rows_test;
#[cfg(test)]
mod rfc7714_test;
#[cfg(test)]
mod srtcp_test;
#[cfg(test)]
mod srtp_test;
#[cfg(test)]
mod srtp_upstream_test;
#[cfg(test)]
mod test_support;

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use crypto::{RTCCrypto, RTCCryptoProvider};
use shared::replay_detector::*;

use crate::cipher::cipher_aead_aes_gcm::*;
use crate::cipher::cipher_aes_cm_hmac_sha1::*;
use crate::cipher::*;
use crate::cryptex::Cryptex;
use crate::header_extension::EncryptedHeaderExtensions;
use crate::keying::*;
use crate::option::*;
use crate::protection_profile::*;
use shared::error::{Error, Result};

/// SRTCP protection and unprotection.
pub mod srtcp;
/// SRTP protection and unprotection.
pub mod srtp;

const MAX_ROC: u32 = u32::MAX;
const SEQ_NUM_MEDIAN: u16 = 1 << 15;
const SEQ_NUM_MAX: u16 = u16::MAX;
/// How many packet indexes behind the highest one sent the sender still tracks individually
/// (the NACK responder's default buffer). An index protects one packet only (RFC 3711 Section
/// 3.3.1, RFC 7714 Section 8.1): the same packet again is protected again (the output is the
/// same), a different one is refused, and so is any index older than this window.
pub(crate) const SRTP_SEND_INDEX_WINDOW: usize = 1024;
/// How many SSRCs one context keeps SRTP state for, and separately SRTCP state for. Packets for
/// a further SSRC are refused (existing state is never evicted).
pub(crate) const MAX_SSRC_STATES: usize = 1024;
/// How many master keys one context holds at a time (see [`Context::add_master_key`]).
pub const MAX_MASTER_KEYS: usize = 64;

/// Encrypt/Decrypt state for a single SRTP SSRC
#[derive(Default)]
pub(crate) struct SrtpSsrcState {
    ssrc: u32,
    index: u64,
    rollover_has_processed: bool,
    replay_detector: Option<Box<dyn ReplayDetector>>,
    /// The packet indexes this (sending) context has encrypted, created on first encryption.
    sent_indexes: Option<SentIndexes>,
}

/// What an SRTP index may protect, as decided by [`SentIndexes::check`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendIndexUse {
    /// Not used yet: protect the packet and record it.
    New,
    /// Already used for this very packet: protecting it again yields the same bytes.
    SamePacket,
    /// Used for a different packet, or too old to tell: refuse.
    Refused,
}

/// The packet indexes a sending context protected within [`SRTP_SEND_INDEX_WINDOW`] of the
/// highest one, each with a digest of the packet it protected.
pub(crate) struct SentIndexes {
    highest: Option<u64>,
    /// `(index, digest)` by `index % SRTP_SEND_INDEX_WINDOW`; `None` when never written.
    slots: Vec<Option<(u64, u64)>>,
}

impl SentIndexes {
    pub(crate) fn new() -> Self {
        SentIndexes {
            highest: None,
            slots: vec![None; SRTP_SEND_INDEX_WINDOW],
        }
    }

    fn slot(index: u64) -> usize {
        (index % SRTP_SEND_INDEX_WINDOW as u64) as usize
    }

    /// Whether `index` may protect the packet whose digest is `digest`.
    pub(crate) fn check(&self, index: u64, digest: u64) -> SendIndexUse {
        // Within the window every index has a slot of its own, so a slot holding another index
        // holds an older one, and `index` is unused.
        if let Some((used, used_digest)) = self.slots[Self::slot(index)]
            && used == index
        {
            return if used_digest == digest {
                SendIndexUse::SamePacket
            } else {
                SendIndexUse::Refused
            };
        }
        match self.highest {
            Some(highest) if index + SRTP_SEND_INDEX_WINDOW as u64 <= highest => {
                SendIndexUse::Refused
            }
            _ => SendIndexUse::New,
        }
    }

    /// Records that `index` protected the packet whose digest is `digest`.
    pub(crate) fn record(&mut self, index: u64, digest: u64) {
        self.slots[Self::slot(index)] = Some((index, digest));
        if self.highest.is_none_or(|highest| index > highest) {
            self.highest = Some(index);
        }
    }
}

/// Encrypt/Decrypt state for a single SRTCP SSRC
#[derive(Default)]
pub(crate) struct SrtcpSsrcState {
    /// The index the next SRTCP packet of this SSRC is sent with: zero before the first one,
    /// then one more, modulo 2^31, after each packet (RFC 3711 section 3.4). It is not reset
    /// when the master key changes.
    srtcp_index: usize,
    ssrc: u32,
    replay_detector: Option<Box<dyn ReplayDetector>>,
}

/// One master key of a context, as the session keys derived from it, with the number of
/// packets processed under it (RFC 3711 section 3.2.1).
struct MasterKey {
    /// The key's MKI; empty when the context uses none.
    mki: Vec<u8>,
    cipher: Box<dyn Cipher>,
    /// SRTP and SRTCP packets protected, or authenticated on reception, with this key.
    packets: [u64; 2],
    /// Whether [`ContextEvent::KeyLifetimeExpiring`] was raised, per packet kind.
    expiring_reported: [bool; 2],
    /// Whether [`ContextEvent::KeyExhausted`] was raised, per packet kind.
    exhausted_reported: [bool; 2],
}

fn kind_index(kind: PacketKind) -> usize {
    match kind {
        PacketKind::Rtp => 0,
        PacketKind::Rtcp => 1,
    }
}

impl SrtpSsrcState {
    pub fn next_rollover_count(&self, sequence_number: u16) -> (u32, i32, bool) {
        let local_roc = (self.index >> 16) as u32;
        let local_seq = self.index as u16;

        let mut guess_roc = local_roc;

        let diff = if self.rollover_has_processed {
            let seq = (sequence_number as i32).wrapping_sub(local_seq as i32);
            // When local_roc is equal to 0, and entering seq-local_seq > SEQ_NUM_MEDIAN
            // judgment, it will cause guess_roc calculation error
            if self.index > SEQ_NUM_MEDIAN as _ {
                if local_seq < SEQ_NUM_MEDIAN {
                    if seq > SEQ_NUM_MEDIAN as i32 {
                        guess_roc = local_roc.wrapping_sub(1);
                        seq.wrapping_sub(SEQ_NUM_MAX as i32 + 1)
                    } else {
                        seq
                    }
                } else if local_seq - SEQ_NUM_MEDIAN > sequence_number {
                    guess_roc = local_roc.wrapping_add(1);
                    seq.wrapping_add(SEQ_NUM_MAX as i32 + 1)
                } else {
                    seq
                }
            } else {
                // local_roc is equal to 0
                seq
            }
        } else {
            0i32
        };

        (guess_roc, diff, (guess_roc == 0 && local_roc == MAX_ROC))
    }

    /// https://tools.ietf.org/html/rfc3550#appendix-A.1
    ///
    /// The highest index only moves forward: RFC 3711 Section 3.3.1 and Appendix A update `s_l`
    /// and the ROC only for a packet ahead of them.
    pub fn update_rollover_count(&mut self, sequence_number: u16, diff: i32) {
        if !self.rollover_has_processed {
            self.index |= sequence_number as u64;
            self.rollover_has_processed = true;
        } else if diff > 0 {
            self.index = self.index.wrapping_add(diff as _);
        }
    }
}

/// Context represents a SRTP cryptographic context
/// Context can only be used for one-way operations
/// it must either used ONLY for encryption or ONLY for decryption
///
/// # Key lifetime
///
/// A master key protects a limited number of packets (RFC 3711 section 9.2): 2^48 SRTP and
/// 2^31 SRTCP by default, less if [`set_key_lifetime`](Self::set_key_lifetime) says so. The
/// context counts them. Shortly before a key runs out it raises
/// [`ContextEvent::KeyLifetimeExpiring`]; at the limit it refuses every further packet with
/// [`Error::ErrExceededMaxPackets`], in both directions, and raises
/// [`ContextEvent::KeyExhausted`]. Read the events with [`poll_event`](Self::poll_event) and
/// re-key: build new contexts from a new DTLS-SRTP handshake, or, with an MKI,
/// [`add_master_key`](Self::add_master_key) and [`set_sending_mki`](Self::set_sending_mki).
pub struct Context {
    profile: ProtectionProfile,
    /// The master-key table: one entry without an MKI, one or more with.
    keys: Vec<MasterKey>,
    /// The entry of `keys` packets are protected with.
    sending_key: usize,
    /// The length of the MKI field of every packet; `None` when the context uses no MKI. Fixed
    /// for the context's lifetime (RFC 3711 section 3.2.1).
    mki_len: Option<usize>,
    /// Fixed for the context's lifetime (RFC 3711 section 4.3.1).
    key_derivation_rate: KeyDerivationRate,
    /// Kept by [`with_keying`](Self::with_keying), for further master keys and derivations.
    provider: Option<Arc<dyn RTCCryptoProvider>>,
    key_lifetime: KeyLifetime,

    srtp_ssrc_states: HashMap<u32, SrtpSsrcState>,
    srtcp_ssrc_states: HashMap<u32, SrtcpSsrcState>,

    new_srtp_replay_detector: ContextOption,
    new_srtcp_replay_detector: ContextOption,

    cryptex: Cryptex,
    /// Whether [`ContextEvent::CryptexRequiredViolation`] was raised since the Cryptex settings
    /// last changed.
    cryptex_violation_reported: bool,
    encrypted_header_extensions: EncryptedHeaderExtensions,
    /// Whether SRTCP packets are encrypted when protected (the E flag).
    srtcp_encryption: bool,
    events: VecDeque<ContextEvent>,
    /// Received packets discarded as replays or for failed authentication, by reason.
    discarded: [u64; 2],
    /// Keys the digests of protected packets kept per sending SSRC (see [`SentIndexes`]).
    sent_digest_hasher: RandomState,
}

impl Context {
    /// Creates an SRTP context.
    ///
    /// The crypto implementation is supplied by the caller; this crate never resolves a default.
    /// Borrowed, not owned: it is only needed to build the keyed cipher/MAC objects below, which
    /// are what the context retains.
    ///
    /// `None` for a replay option means replay protection with a window of
    /// [`DEFAULT_REPLAY_PROTECTION_WINDOW`] packets (RFC 3711 section 3.3.2); pass
    /// [`srtp_no_replay_protection`] / [`srtcp_no_replay_protection`] to go without.
    ///
    /// The context has one master key, no MKI and a zero key derivation rate, which is what
    /// DTLS-SRTP uses; see [`with_keying`](Self::with_keying) for the rest.
    pub fn new(
        master_key: &[u8],
        master_salt: &[u8],
        profile: ProtectionProfile,
        srtp_ctx_opt: Option<ContextOption>,
        srtcp_ctx_opt: Option<ContextOption>,
        crypto: &dyn RTCCrypto,
    ) -> Result<Context> {
        Self::build(
            master_key,
            master_salt,
            profile,
            Keying::default(),
            srtp_ctx_opt,
            srtcp_ctx_opt,
            crypto,
            None,
        )
    }

    /// Creates an SRTP context that uses a Master Key Identifier, a non-zero key derivation
    /// rate, or both (RFC 3711 sections 3.1, 4.3.1 and 8.1).
    ///
    /// With [`Keying::mki`] set, every packet the context protects carries the MKI of the
    /// master key in use, and every packet it unprotects is processed with the master key its
    /// MKI names; further keys are added with [`add_master_key`](Self::add_master_key). With a
    /// non-zero [`Keying::key_derivation_rate`] the session keys are derived again each time the
    /// packet index crosses a multiple of the rate.
    ///
    /// Unlike [`new`](Self::new) the provider is retained, to key those later derivations, and
    /// with a non-zero rate so are the master keys and salts (zeroized when dropped).
    ///
    /// With a non-zero rate a received packet whose estimated index falls in another derivation
    /// epoch costs a key derivation before it can be authenticated, so a forged packet costs
    /// more than with a zero rate (a few AES blocks and key schedules; the keys of the last two
    /// epochs are kept).
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), and when the MKI is empty or longer than [`MAX_MKI_LEN`].
    pub fn with_keying(
        master_key: &[u8],
        master_salt: &[u8],
        profile: ProtectionProfile,
        keying: Keying,
        srtp_ctx_opt: Option<ContextOption>,
        srtcp_ctx_opt: Option<ContextOption>,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Context> {
        Self::build(
            master_key,
            master_salt,
            profile,
            keying,
            srtp_ctx_opt,
            srtcp_ctx_opt,
            provider.crypto(),
            Some(provider.clone()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        master_key: &[u8],
        master_salt: &[u8],
        profile: ProtectionProfile,
        keying: Keying,
        srtp_ctx_opt: Option<ContextOption>,
        srtcp_ctx_opt: Option<ContextOption>,
        crypto: &dyn RTCCrypto,
        provider: Option<Arc<dyn RTCCryptoProvider>>,
    ) -> Result<Context> {
        if let Some(mki) = &keying.mki {
            check_mki(mki)?;
        }
        let cipher = new_cipher(
            profile,
            master_key,
            master_salt,
            crypto,
            keying.key_derivation_rate,
            provider.clone(),
        )?;

        Ok(Context {
            profile,
            mki_len: keying.mki.as_ref().map(Vec::len),
            keys: vec![MasterKey::new(keying.mki.unwrap_or_default(), cipher)],
            sending_key: 0,
            key_derivation_rate: keying.key_derivation_rate,
            provider,
            key_lifetime: profile.default_key_lifetime(),
            srtp_ssrc_states: HashMap::new(),
            srtcp_ssrc_states: HashMap::new(),
            new_srtp_replay_detector: srtp_ctx_opt
                .unwrap_or_else(|| srtp_window(DEFAULT_REPLAY_PROTECTION_WINDOW)),
            new_srtcp_replay_detector: srtcp_ctx_opt
                .unwrap_or_else(|| srtcp_window(DEFAULT_REPLAY_PROTECTION_WINDOW)),
            cryptex: Cryptex::default(),
            cryptex_violation_reported: false,
            encrypted_header_extensions: EncryptedHeaderExtensions::default(),
            srtcp_encryption: true,
            events: VecDeque::new(),
            discarded: [0; 2],
            sent_digest_hasher: RandomState::new(),
        })
    }

    /// The protection profile the context was created with.
    pub fn profile(&self) -> ProtectionProfile {
        self.profile
    }

    /// How this context uses Cryptex (RFC 9335); see [`Cryptex`].
    pub fn cryptex(&self) -> Cryptex {
        self.cryptex
    }

    /// Sets how this context uses Cryptex (RFC 9335). It applies from the next packet.
    pub fn set_cryptex(&mut self, cryptex: Cryptex) {
        self.cryptex = cryptex;
        self.cryptex_violation_reported = false;
    }

    /// The header extension elements this context encrypts and decrypts as RFC 6904 has it.
    pub fn encrypted_header_extensions(&self) -> EncryptedHeaderExtensions {
        self.encrypted_header_extensions
    }

    /// Sets the header extension elements whose payload is encrypted (RFC 6904): the ids the
    /// session negotiated with `urn:ietf:params:rtp-hdrext:encrypt`. It applies from the next
    /// packet, in the direction the context is used for. The empty set turns it off.
    ///
    /// A packet protected with Cryptex is not also processed this way (RFC 9335 section 5).
    /// When unprotecting, the header passed to
    /// [`decrypt_rtp_with_header`](Self::decrypt_rtp_with_header) was parsed from the protected
    /// packet, so its encrypted elements are ciphertext: read them from the returned packet.
    pub fn set_encrypted_header_extensions(&mut self, ids: EncryptedHeaderExtensions) {
        self.encrypted_header_extensions = ids;
    }

    /// Whether SRTCP packets are encrypted when protected.
    pub fn srtcp_encryption(&self) -> bool {
        self.srtcp_encryption
    }

    /// Sets whether SRTCP packets are encrypted when protected (the default) or only
    /// authenticated, with the E flag clear (RFC 3711 section 3.4, RFC 7714 section 9.3).
    /// Unprotecting follows each packet's E flag whatever this says; authentication is never
    /// optional.
    pub fn set_srtcp_encryption(&mut self, encrypt: bool) {
        self.srtcp_encryption = encrypt;
    }

    /// The key derivation rate the context was created with.
    pub fn key_derivation_rate(&self) -> KeyDerivationRate {
        self.key_derivation_rate
    }

    /// How many packets a master key of this context may protect.
    pub fn key_lifetime(&self) -> KeyLifetime {
        self.key_lifetime
    }

    /// Sets how many packets a master key of this context may protect, for instance the
    /// lifetime key management agreed on (RFC 5764 section 4.1.2: 2^31 packets for the
    /// DTLS-SRTP profiles).
    ///
    /// # Errors
    ///
    /// A lifetime of zero, or above 2^48 SRTP or 2^31 SRTCP packets, is refused.
    pub fn set_key_lifetime(&mut self, lifetime: KeyLifetime) -> Result<()> {
        lifetime.validate()?;
        self.key_lifetime = lifetime;
        Ok(())
    }

    /// How much of the lifetime of the master key packets are protected with is used.
    pub fn key_usage(&self) -> KeyUsage {
        self.usage_of(&self.keys[self.sending_key])
    }

    /// How much of the lifetime of the master key with this MKI is used; `None` when the
    /// context has no such key.
    pub fn key_usage_of(&self, mki: &[u8]) -> Option<KeyUsage> {
        self.mki_len?;
        self.keys
            .iter()
            .find(|key| key.mki == mki)
            .map(|key| self.usage_of(key))
    }

    fn usage_of(&self, key: &MasterKey) -> KeyUsage {
        KeyUsage {
            srtp_packets: key.packets[kind_index(PacketKind::Rtp)],
            srtcp_packets: key.packets[kind_index(PacketKind::Rtcp)],
            lifetime: self.key_lifetime,
        }
    }

    /// The next thing the context has to tell the application; see [`ContextEvent`].
    pub fn poll_event(&mut self) -> Option<ContextEvent> {
        self.events.pop_front()
    }

    /// How many received packets were discarded so far: (replays, authentication failures)
    /// (RFC 3711 section 3.3).
    pub fn discarded_packets(&self) -> (u64, u64) {
        (self.discarded[0], self.discarded[1])
    }

    /// Records the outcome of unprotecting a packet: a replay or an authentication failure
    /// is counted, logged and reported (RFC 3711 section 3.3, steps 2 and 5: "the event
    /// SHOULD be logged").
    pub(crate) fn note_unprotect_result<T>(
        &mut self,
        kind: PacketKind,
        ssrc: u32,
        index: u64,
        result: Result<T>,
    ) -> Result<T> {
        let reason = match &result {
            Err(Error::SrtpSsrcDuplicated(..) | Error::SrtcpSsrcDuplicated(..)) => {
                DiscardReason::Replay
            }
            Err(
                Error::ErrFailedToVerifyAuthTag
                | Error::RtpFailedToVerifyAuthTag
                | Error::RtcpFailedToVerifyAuthTag,
            ) => DiscardReason::AuthenticationFailed,
            _ => return result,
        };
        let slot = match reason {
            DiscardReason::Replay => 0,
            _ => 1,
        };
        self.discarded[slot] = self.discarded[slot].saturating_add(1);
        let pending = self
            .events
            .iter()
            .filter(|event| matches!(event, ContextEvent::PacketDiscarded { .. }))
            .count();
        if pending < MAX_PENDING_DISCARD_EVENTS {
            self.events.push_back(ContextEvent::PacketDiscarded {
                kind,
                ssrc,
                index,
                reason,
            });
        }
        result
    }

    /// Adds a master key under `mki` (RFC 3711 section 8.1). Packets carrying that MKI are
    /// unprotected with it from now on; packets are protected with it once
    /// [`set_sending_mki`](Self::set_sending_mki) selects it. The rollover counters, the SRTCP
    /// indexes and the replay lists carry over (RFC 3711 sections 3.3.1 and 3.4).
    ///
    /// A master key must never be one used before (RFC 3711 section 9.2); that is for key
    /// management to ensure, the context cannot tell.
    ///
    /// # Errors
    ///
    /// Fails when the context was not created with an MKI ([`with_keying`](Self::with_keying)),
    /// when `mki` is not of the context's MKI length or already names a key, when the key or
    /// salt length is not the profile's, or when [`MAX_MASTER_KEYS`] keys are held.
    pub fn add_master_key(
        &mut self,
        mki: &[u8],
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<()> {
        let (Some(mki_len), Some(provider)) = (self.mki_len, self.provider.clone()) else {
            return Err(Error::Other(
                "this SRTP context uses no MKI: it has one master key".to_owned(),
            ));
        };
        if mki.len() != mki_len {
            return Err(Error::Other(format!(
                "MKI of {} octets in a context whose MKIs have {mki_len}",
                mki.len()
            )));
        }
        if self.keys.iter().any(|key| key.mki == mki) {
            return Err(Error::Other(
                "the MKI already names a master key".to_owned(),
            ));
        }
        if self.keys.len() >= MAX_MASTER_KEYS {
            return Err(Error::Other(format!(
                "the SRTP context already holds {MAX_MASTER_KEYS} master keys"
            )));
        }
        let cipher = new_cipher(
            self.profile,
            master_key,
            master_salt,
            provider.crypto(),
            self.key_derivation_rate,
            Some(provider.clone()),
        )?;
        self.keys.push(MasterKey::new(mki.to_vec(), cipher));
        Ok(())
    }

    /// Removes the master key under `mki`, erasing the session keys derived from it. Packets
    /// carrying that MKI are refused from now on.
    ///
    /// # Errors
    ///
    /// Fails when no key has that MKI, or when it is the key packets are protected with.
    pub fn remove_master_key(&mut self, mki: &[u8]) -> Result<()> {
        let at = self.key_by_mki(mki)?;
        if at == self.sending_key {
            return Err(Error::Other(
                "the master key in use for sending cannot be removed".to_owned(),
            ));
        }
        self.keys.remove(at);
        if self.sending_key > at {
            self.sending_key -= 1;
        }
        Ok(())
    }

    /// Protects packets with the master key under `mki` from the next packet on.
    ///
    /// # Errors
    ///
    /// Fails when no key has that MKI.
    pub fn set_sending_mki(&mut self, mki: &[u8]) -> Result<()> {
        self.sending_key = self.key_by_mki(mki)?;
        Ok(())
    }

    /// The MKI of the master key packets are protected with; `None` when the context uses no
    /// MKI.
    pub fn sending_mki(&self) -> Option<&[u8]> {
        self.mki_len?;
        Some(&self.keys[self.sending_key].mki)
    }

    /// The MKIs of the master keys the context holds; empty when it uses no MKI.
    pub fn mkis(&self) -> impl Iterator<Item = &[u8]> {
        self.keys
            .iter()
            .filter(|_| self.mki_len.is_some())
            .map(|key| key.mki.as_slice())
    }

    fn key_by_mki(&self, mki: &[u8]) -> Result<usize> {
        if self.mki_len.is_none() {
            return Err(Error::Other(
                "this SRTP context uses no MKI: it has one master key".to_owned(),
            ));
        }
        self.keys
            .iter()
            .position(|key| key.mki == mki)
            .ok_or_else(|| Error::Other("no master key has this MKI".to_owned()))
    }

    /// The length of the MKI field of this context's packets; zero without an MKI.
    fn mki_field_len(&self) -> usize {
        self.mki_len.unwrap_or(0)
    }

    /// The master key a received packet names. The MKI sits `trailing_tag_len` octets before
    /// the end: before the authentication tag of the HMAC profiles, at the very end with the
    /// AEAD ones. The caller has checked that the packet holds it.
    ///
    /// The MKI is not authenticated (RFC 3711 section 3.1); it only selects the key the
    /// packet is then authenticated with.
    fn receiving_key(&self, packet: &[u8], trailing_tag_len: usize) -> Result<usize> {
        let Some(mki_len) = self.mki_len else {
            return Ok(0);
        };
        let end = packet.len() - trailing_tag_len;
        let mki = &packet[end - mki_len..end];
        self.keys
            .iter()
            .position(|key| key.mki == mki)
            .ok_or_else(|| Error::Other("SRTP packet carries an unknown MKI".to_owned()))
    }

    /// Refuses a packet for a master key that reached its lifetime (RFC 3711 section 9.2), and
    /// says so once per key and packet kind.
    fn check_key_lifetime(&mut self, key: usize, kind: PacketKind) -> Result<()> {
        let limit = self.key_lifetime.limit(kind);
        let master_key = &mut self.keys[key];
        let at = kind_index(kind);
        if master_key.packets[at] < limit {
            return Ok(());
        }
        if !master_key.exhausted_reported[at] {
            master_key.exhausted_reported[at] = true;
            self.events.push_back(ContextEvent::KeyExhausted {
                mki: master_key.mki.clone(),
                kind,
            });
        }
        Err(Error::ErrExceededMaxPackets)
    }

    /// Counts a packet processed with a master key, and asks for a new key once the last
    /// sixteenth of its lifetime is reached.
    fn count_packet(&mut self, key: usize, kind: PacketKind) {
        let limit = self.key_lifetime.limit(kind);
        let master_key = &mut self.keys[key];
        let at = kind_index(kind);
        master_key.packets[at] += 1;
        let remaining = limit.saturating_sub(master_key.packets[at]);
        if remaining <= (limit / 16).max(1) && !master_key.expiring_reported[at] {
            master_key.expiring_reported[at] = true;
            self.events.push_back(ContextEvent::KeyLifetimeExpiring {
                mki: master_key.mki.clone(),
                kind,
                remaining,
            });
        }
    }

    /// Fails with [`Error::SrtpTooManySsrcs`] if `ssrc` has no SRTP state yet and the context
    /// already holds [`MAX_SSRC_STATES`] of them.
    fn check_srtp_ssrc_capacity(&self, ssrc: u32) -> Result<()> {
        if self.srtp_ssrc_states.len() >= MAX_SSRC_STATES
            && !self.srtp_ssrc_states.contains_key(&ssrc)
        {
            return Err(Error::SrtpTooManySsrcs(ssrc, MAX_SSRC_STATES));
        }
        Ok(())
    }

    /// Fails with [`Error::SrtpTooManySsrcs`] if `ssrc` has no SRTCP state yet and the context
    /// already holds [`MAX_SSRC_STATES`] of them.
    fn check_srtcp_ssrc_capacity(&self, ssrc: u32) -> Result<()> {
        if self.srtcp_ssrc_states.len() >= MAX_SSRC_STATES
            && !self.srtcp_ssrc_states.contains_key(&ssrc)
        {
            return Err(Error::SrtpTooManySsrcs(ssrc, MAX_SSRC_STATES));
        }
        Ok(())
    }

    fn get_srtp_ssrc_state(&mut self, ssrc: u32) -> Result<&mut SrtpSsrcState> {
        self.check_srtp_ssrc_capacity(ssrc)?;
        // `or_insert_with` so the replay detector (a boxed sliding-window
        // detector backed by a heap-allocated bit buffer) is only constructed on
        // the first packet for a given SSRC. `or_insert` would build — and then
        // immediately drop — a fresh detector on every decrypted packet.
        let new_srtp_replay_detector = &self.new_srtp_replay_detector;
        Ok(self
            .srtp_ssrc_states
            .entry(ssrc)
            .or_insert_with(|| SrtpSsrcState {
                ssrc,
                replay_detector: Some(new_srtp_replay_detector()),
                ..Default::default()
            }))
    }

    fn get_srtcp_ssrc_state(&mut self, ssrc: u32) -> Result<&mut SrtcpSsrcState> {
        self.check_srtcp_ssrc_capacity(ssrc)?;
        let new_srtcp_replay_detector = &self.new_srtcp_replay_detector;
        Ok(self
            .srtcp_ssrc_states
            .entry(ssrc)
            .or_insert_with(|| SrtcpSsrcState {
                ssrc,
                replay_detector: Some(new_srtcp_replay_detector()),
                ..Default::default()
            }))
    }

    /// roc returns SRTP rollover counter value of specified SSRC.
    fn get_roc(&self, ssrc: u32) -> Option<u32> {
        self.srtp_ssrc_states
            .get(&ssrc)
            .map(|s| (s.index >> 16) as _)
    }

    /// set_roc sets SRTP rollover counter value of specified SSRC.
    fn set_roc(&mut self, ssrc: u32, roc: u32) {
        if let Ok(state) = self.get_srtp_ssrc_state(ssrc) {
            state.index = (roc as u64) << 16;
            state.rollover_has_processed = false;
        }
    }

    /// The SRTCP index the next packet of the specified SSRC is sent with.
    fn get_index(&self, ssrc: u32) -> Option<usize> {
        self.srtcp_ssrc_states.get(&ssrc).map(|s| s.srtcp_index)
    }

    /// Sets the SRTCP index the next packet of the specified SSRC is sent with.
    fn set_index(&mut self, ssrc: u32, index: usize) {
        if let Ok(state) = self.get_srtcp_ssrc_state(ssrc) {
            state.srtcp_index = index % (MAX_SRTCP_INDEX + 1);
        }
    }

    /// Sets the number of packets counted against the sending master key, to test what happens
    /// at the end of a key's lifetime without sending 2^31 packets.
    #[cfg(test)]
    fn set_packets_processed(&mut self, kind: PacketKind, packets: u64) {
        self.keys[self.sending_key].packets[kind_index(kind)] = packets;
    }

    /// A context around a given cipher, for test vectors that state session keys.
    #[cfg(test)]
    fn from_cipher(profile: ProtectionProfile, cipher: Box<dyn Cipher>) -> Context {
        Context {
            profile,
            mki_len: None,
            keys: vec![MasterKey::new(Vec::new(), cipher)],
            sending_key: 0,
            key_derivation_rate: KeyDerivationRate::ZERO,
            provider: None,
            key_lifetime: profile.default_key_lifetime(),
            srtp_ssrc_states: HashMap::new(),
            srtcp_ssrc_states: HashMap::new(),
            new_srtp_replay_detector: srtp_window(DEFAULT_REPLAY_PROTECTION_WINDOW),
            new_srtcp_replay_detector: srtcp_window(DEFAULT_REPLAY_PROTECTION_WINDOW),
            cryptex: Cryptex::default(),
            cryptex_violation_reported: false,
            encrypted_header_extensions: EncryptedHeaderExtensions::default(),
            srtcp_encryption: true,
            events: VecDeque::new(),
            discarded: [0; 2],
            sent_digest_hasher: RandomState::new(),
        }
    }
}

impl MasterKey {
    fn new(mki: Vec<u8>, cipher: Box<dyn Cipher>) -> Self {
        Self {
            mki,
            cipher,
            packets: [0; 2],
            expiring_reported: [false; 2],
            exhausted_reported: [false; 2],
        }
    }
}

fn check_mki(mki: &[u8]) -> Result<()> {
    if mki.is_empty() || mki.len() > MAX_MKI_LEN {
        return Err(Error::Other(format!(
            "an MKI has 1 to {MAX_MKI_LEN} octets, not {}",
            mki.len()
        )));
    }
    Ok(())
}

fn new_cipher(
    profile: ProtectionProfile,
    master_key: &[u8],
    master_salt: &[u8],
    crypto: &dyn RTCCrypto,
    rate: KeyDerivationRate,
    provider: Option<Arc<dyn RTCCryptoProvider>>,
) -> Result<Box<dyn Cipher>> {
    let key_len = profile.key_len();
    let salt_len = profile.salt_len();

    if master_key.len() != key_len {
        return Err(Error::SrtpMasterKeyLength(key_len, master_key.len()));
    } else if master_salt.len() != salt_len {
        return Err(Error::SrtpSaltLength(salt_len, master_salt.len()));
    }
    profile.ensure_crypto_supported(crypto)?;

    // Deriving the session keys and building their ciphers and MACs puts the master key, the
    // session keys, their AES schedules, GHASH keys and HMAC states into the stack frames of
    // the functions that do it, this crate's and the provider's. RFC 7714 section 13.1: "All
    // keys MUST be properly erased when no longer needed". So all of it runs in frames below
    // one that overwrites the stack under it afterwards; what comes back is a box.
    crypto::on_erased_stack(|| {
        build_cipher(profile, master_key, master_salt, crypto, rate, provider)
    })
}

fn build_cipher(
    profile: ProtectionProfile,
    master_key: &[u8],
    master_salt: &[u8],
    crypto: &dyn RTCCrypto,
    rate: KeyDerivationRate,
    provider: Option<Arc<dyn RTCCryptoProvider>>,
) -> Result<Box<dyn Cipher>> {
    Ok(if profile.is_aead() {
        // `CipherAeadAesGcm::new` selects AES-128 vs AES-256 from the profile itself.
        Box::new(CipherAeadAesGcm::new(
            profile,
            master_key,
            master_salt,
            crypto,
            rate,
            provider,
        )?)
    } else {
        Box::new(CipherAesCmHmacSha1::new(
            profile,
            master_key,
            master_salt,
            crypto,
            rate,
            provider,
        )?)
    })
}

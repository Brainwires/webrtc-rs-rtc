//! The TLS 1.3 key schedule (RFC 8446 section 7) with the DTLS 1.3 label prefix (RFC 9147
//! section 5.9), and the handshake transcript it is keyed to.

use super::suite::Suite13;
use crypto::{RTCCrypto, SecretVec, hkdf_expand_label, hkdf_extract};
use shared::error::{Error, Result};

/// The label prefix of DTLS 1.3 (RFC 9147 section 5.9): no trailing space, unlike TLS 1.3's.
pub(crate) const DTLS13_LABEL_PREFIX: &str = "dtls13";
/// The label prefix of TLS 1.3 (RFC 8446 section 7.1), which the RFC 8448 traces use.
#[cfg(test)]
pub(crate) const TLS13_LABEL_PREFIX: &str = "tls13 ";

/// The handshake type of the synthetic message that stands for the first ClientHello after a
/// HelloRetryRequest (RFC 8446 section 4.4.1).
pub(crate) const HANDSHAKE_TYPE_MESSAGE_HASH: u8 = 254;

fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

/// The handshake transcript: the TLS 1.3 form of every handshake message so far, that is,
/// type, 24-bit length and body, without the DTLS message_seq and fragment fields (RFC 9147
/// section 5.2).
#[derive(Clone, Default)]
pub(crate) struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Appends one whole handshake message.
    pub(crate) fn add(&mut self, handshake_type: u8, body: &[u8]) {
        self.bytes.push(handshake_type);
        self.bytes
            .extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        self.bytes.extend_from_slice(body);
    }

    /// Replaces what has been recorded, which is the first ClientHello, with the synthetic
    /// message_hash message that carries its hash: what a HelloRetryRequest does to the
    /// transcript (RFC 8446 section 4.4.1).
    pub(crate) fn replace_with_message_hash(
        &mut self,
        crypto: &dyn RTCCrypto,
        suite: Suite13,
    ) -> Result<()> {
        let hash = self.hash(crypto, suite)?;
        self.set_message_hash(&hash);
        Ok(())
    }

    /// Starts the transcript from the hash of a first ClientHello this side no longer has:
    /// a server that kept no state for it reads the hash back from its cookie (RFC 9147
    /// section 5.1).
    pub(crate) fn set_message_hash(&mut self, client_hello_hash: &[u8]) {
        self.bytes.clear();
        self.add(HANDSHAKE_TYPE_MESSAGE_HASH, client_hello_hash);
    }

    /// `Transcript-Hash` of everything recorded.
    pub(crate) fn hash(&self, crypto: &dyn RTCCrypto, suite: Suite13) -> Result<Vec<u8>> {
        crypto.hash(suite.hash(), &self.bytes).map_err(crypto_error)
    }

    /// `Transcript-Hash` of everything recorded followed by `more`.
    pub(crate) fn hash_with(
        &self,
        crypto: &dyn RTCCrypto,
        suite: Suite13,
        more: &[u8],
    ) -> Result<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        bytes.extend_from_slice(more);
        crypto.hash(suite.hash(), &bytes).map_err(crypto_error)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The secrets of one handshake, derived stage by stage as RFC 8446 section 7.1 draws them.
pub(crate) struct KeySchedule {
    suite: Suite13,
    prefix: &'static str,
    /// The Early Secret, then the Handshake Secret, then the Main Secret.
    current: SecretVec,
    pub(crate) client_handshake_traffic: Option<SecretVec>,
    pub(crate) server_handshake_traffic: Option<SecretVec>,
    pub(crate) client_application_traffic: Option<SecretVec>,
    pub(crate) server_application_traffic: Option<SecretVec>,
    pub(crate) exporter: Option<SecretVec>,
}

impl KeySchedule {
    /// Starts the schedule with no PSK: the Early Secret is extracted from a string of zeros.
    pub(crate) fn new(
        crypto: &dyn RTCCrypto,
        suite: Suite13,
        prefix: &'static str,
    ) -> Result<Self> {
        let zeros = vec![0u8; suite.hash_len()];
        Self::with_psk(crypto, suite, prefix, &zeros)
    }

    /// Starts the schedule from a PSK: the Early Secret is `HKDF-Extract(0, PSK)` (RFC 8446
    /// section 7.1).
    pub(crate) fn with_psk(
        crypto: &dyn RTCCrypto,
        suite: Suite13,
        prefix: &'static str,
        psk: &[u8],
    ) -> Result<Self> {
        let early = hkdf_extract(crypto, suite.hmac(), &[], psk).map_err(crypto_error)?;
        Ok(Self {
            suite,
            prefix,
            current: early,
            client_handshake_traffic: None,
            server_handshake_traffic: None,
            client_application_traffic: None,
            server_application_traffic: None,
            exporter: None,
        })
    }

    pub(crate) fn suite(&self) -> Suite13 {
        self.suite
    }

    /// `HKDF-Expand-Label`, on a stack that is overwritten afterwards
    /// (`crypto::on_erased_stack`): the HMAC leaves the keyed hash states of `secret` and its
    /// output in the provider's frames (tests/key_residue.rs). Every secret of the schedule but
    /// the extracted ones comes through here, and each extraction is followed by a call here,
    /// whose overwrite covers what the extraction left.
    fn expand_label(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<SecretVec> {
        crypto::on_erased_stack(|| {
            hkdf_expand_label(
                crypto,
                self.suite.hmac(),
                secret,
                self.prefix,
                label,
                context,
                length,
            )
        })
        .map_err(crypto_error)
    }

    /// `Derive-Secret(Secret, Label, Messages)`, given the transcript hash of the messages.
    fn derive_secret(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<SecretVec> {
        self.expand_label(
            crypto,
            secret,
            label,
            transcript_hash,
            self.suite.hash_len(),
        )
    }

    /// `binder_key = Derive-Secret(Early Secret, "ext binder" | "res binder", "")` (RFC 8446
    /// section 7.1): for a PSK provisioned out of band, or one from a ticket.
    pub(crate) fn binder_key(&self, crypto: &dyn RTCCrypto, external: bool) -> Result<SecretVec> {
        let empty_hash = crypto.hash(self.suite.hash(), &[]).map_err(crypto_error)?;
        let label = if external { "ext binder" } else { "res binder" };
        self.derive_secret(crypto, self.current.as_ref(), label, &empty_hash)
    }

    /// `client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)`
    /// (RFC 8446 section 7.1): the keys of 0-RTT data, epoch 1 (RFC 9147 section 6.1).
    pub(crate) fn client_early_traffic_secret(
        &self,
        crypto: &dyn RTCCrypto,
        client_hello_hash: &[u8],
    ) -> Result<SecretVec> {
        self.derive_secret(
            crypto,
            self.current.as_ref(),
            "c e traffic",
            client_hello_hash,
        )
    }

    /// Moves from the current secret to the next one in the chain:
    /// `HKDF-Extract(Derive-Secret(current, "derived", ""), input)`.
    fn advance(&mut self, crypto: &dyn RTCCrypto, input: &[u8]) -> Result<()> {
        let empty_hash = crypto.hash(self.suite.hash(), &[]).map_err(crypto_error)?;
        let salt = self.derive_secret(crypto, self.current.as_ref(), "derived", &empty_hash)?;
        // Not on an erased stack of its own: every caller derives a secret with
        // `expand_label` right after, whose overwrite reaches the frames this HMAC left
        // (tests/key_residue.rs measures it: wrapping this changed nothing it finds).
        self.current =
            hkdf_extract(crypto, self.suite.hmac(), salt.as_ref(), input).map_err(crypto_error)?;
        Ok(())
    }

    /// Derives the Handshake Secret from the (EC)DHE shared secret, and from it the two
    /// handshake traffic secrets, over the transcript up to and including the ServerHello.
    pub(crate) fn enter_handshake(
        &mut self,
        crypto: &dyn RTCCrypto,
        shared_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<()> {
        self.advance(crypto, shared_secret)?;
        self.client_handshake_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "c hs traffic",
            transcript_hash,
        )?);
        self.server_handshake_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "s hs traffic",
            transcript_hash,
        )?);
        Ok(())
    }

    /// Derives the Main Secret, and from it the first application traffic secrets and the
    /// exporter secret, over the transcript up to and including the server's Finished.
    pub(crate) fn enter_application(
        &mut self,
        crypto: &dyn RTCCrypto,
        transcript_hash: &[u8],
    ) -> Result<()> {
        let zeros = vec![0u8; self.suite.hash_len()];
        self.advance(crypto, &zeros)?;
        self.client_application_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "c ap traffic",
            transcript_hash,
        )?);
        self.server_application_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "s ap traffic",
            transcript_hash,
        )?);
        self.exporter = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "exp master",
            transcript_hash,
        )?);
        // The Main Secret stays for the resumption master secret, which comes from the
        // transcript through the client's Finished.
        Ok(())
    }

    /// `resumption_master_secret = Derive-Secret(Main Secret, "res master", ClientHello ...
    /// client Finished)` (RFC 8446 section 7.1). The Main Secret has no other use left, so it
    /// is dropped.
    pub(crate) fn take_resumption_master_secret(
        &mut self,
        crypto: &dyn RTCCrypto,
        transcript_hash: &[u8],
    ) -> Result<SecretVec> {
        if self.current.is_empty() || self.exporter.is_none() {
            return Err(Error::ErrCipherSuiteUnset);
        }
        let secret =
            self.derive_secret(crypto, self.current.as_ref(), "res master", transcript_hash);
        self.current = SecretVec::new(vec![]);
        secret
    }

    /// The PSK of one ticket: `HKDF-Expand-Label(resumption_master_secret, "resumption",
    /// ticket_nonce, Hash.length)` (RFC 8446 section 4.6.1).
    pub(crate) fn resumption_psk(
        &self,
        crypto: &dyn RTCCrypto,
        resumption_master_secret: &[u8],
        ticket_nonce: &[u8],
    ) -> Result<SecretVec> {
        self.expand_label(
            crypto,
            resumption_master_secret,
            "resumption",
            ticket_nonce,
            self.suite.hash_len(),
        )
    }

    /// The verify_data of a Finished: `HMAC(finished_key, Transcript-Hash)`, the key expanded
    /// from the sender's handshake traffic secret (RFC 8446 section 4.4.4).
    pub(crate) fn finished_verify_data(
        &self,
        crypto: &dyn RTCCrypto,
        base_key: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        let finished_key =
            self.expand_label(crypto, base_key, "finished", &[], self.suite.hash_len())?;
        // The finished key's HMAC states stay in the provider's frames: see `expand_label`.
        crypto::on_erased_stack(|| {
            let mut mac = crypto
                .new_hmac(self.suite.hmac(), finished_key.as_ref())
                .map_err(crypto_error)?;
            let mut verify_data = vec![0u8; mac.output_len()];
            mac.sign(&[transcript_hash], &mut verify_data)
                .map_err(crypto_error)?;
            Ok(verify_data)
        })
    }

    /// `application_traffic_secret_N+1` from `application_traffic_secret_N` (RFC 8446
    /// section 7.2): what a KeyUpdate moves a direction to.
    pub(crate) fn next_application_traffic_secret(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
    ) -> Result<SecretVec> {
        self.expand_label(crypto, secret, "traffic upd", &[], self.suite.hash_len())
    }

    /// The key, IV and record-number key of a traffic secret (RFC 8446 section 7.3, RFC 9147
    /// section 4.2.3).
    pub(crate) fn traffic_keys(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
    ) -> Result<TrafficKeys> {
        Ok(TrafficKeys {
            key: self.expand_label(crypto, secret, "key", &[], self.suite.key_len())?,
            iv: self.expand_label(crypto, secret, "iv", &[], 12)?,
            sequence_number_key: self.expand_label(
                crypto,
                secret,
                "sn",
                &[],
                self.suite.header_mask().key_len(),
            )?,
        })
    }

    /// `TLS-Exporter(label, context_value, key_length)` (RFC 8446 section 7.5).
    pub(crate) fn export(
        &self,
        crypto: &dyn RTCCrypto,
        exporter_secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<SecretVec> {
        let empty_hash = crypto.hash(self.suite.hash(), &[]).map_err(crypto_error)?;
        let secret = self.derive_secret(crypto, exporter_secret, label, &empty_hash)?;
        let context_hash = crypto
            .hash(self.suite.hash(), context)
            .map_err(crypto_error)?;
        self.expand_label(crypto, secret.as_ref(), "exporter", &context_hash, length)
    }

    /// Overwrites and drops every secret (RFC 8446 section 6.2: a failed connection's
    /// secrets are forgotten).
    /// Whether [`Self::forget`] has run: no secret is left.
    #[cfg(test)]
    pub(crate) fn is_forgotten(&self) -> bool {
        self.current.as_ref().is_empty()
            && self.client_handshake_traffic.is_none()
            && self.server_handshake_traffic.is_none()
            && self.client_application_traffic.is_none()
            && self.server_application_traffic.is_none()
            && self.exporter.is_none()
    }

    /// RFC 8446 section 7.1: "Once all the values which are to be derived from a given secret
    /// have been computed, that secret SHOULD be erased." The handshake traffic secrets give
    /// the handshake epoch's record keys and the two Finished messages: once both Finished are
    /// computed (sent or checked), nothing more comes from them.
    pub(crate) fn forget_handshake_secrets(&mut self) {
        self.client_handshake_traffic = None;
        self.server_handshake_traffic = None;
    }

    /// Whether the handshake traffic secrets are gone ([`Self::forget_handshake_secrets`]).
    #[cfg(test)]
    pub(crate) fn handshake_secrets_forgotten(&self) -> bool {
        self.client_handshake_traffic.is_none() && self.server_handshake_traffic.is_none()
    }

    /// Whether the application traffic secrets were handed over (the association keeps them
    /// for its key updates) and no copy is left here.
    #[cfg(test)]
    pub(crate) fn application_secrets_handed_over(&self) -> bool {
        self.client_application_traffic.is_none() && self.server_application_traffic.is_none()
    }

    pub(crate) fn forget(&mut self) {
        self.current = SecretVec::new(vec![]);
        self.client_handshake_traffic = None;
        self.server_handshake_traffic = None;
        self.client_application_traffic = None;
        self.server_application_traffic = None;
        self.exporter = None;
    }
}

/// The keys of one direction in one epoch.
pub(crate) struct TrafficKeys {
    pub(crate) key: SecretVec,
    pub(crate) iv: SecretVec,
    pub(crate) sequence_number_key: SecretVec,
}

/// What a CertificateVerify signs (RFC 8446 section 4.4.3): 64 spaces, the context string, a
/// zero byte and the transcript hash.
pub(crate) fn certificate_verify_input(from_server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let context: &[u8] = if from_server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    let mut input = vec![0x20u8; 64];
    input.extend_from_slice(context);
    input.push(0);
    input.extend_from_slice(transcript_hash);
    input
}

/// `TLS-Exporter` for a completed DTLS 1.3 handshake, from its exporter secret.
pub(crate) fn export_keying_material(
    crypto: &dyn RTCCrypto,
    suite: Suite13,
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<SecretVec> {
    // On a stack that is overwritten afterwards: see `KeySchedule::expand_label`.
    crypto::on_erased_stack(|| export(crypto, suite, exporter_secret, label, context, length))
}

fn export(
    crypto: &dyn RTCCrypto,
    suite: Suite13,
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<SecretVec> {
    let empty_hash = crypto.hash(suite.hash(), &[]).map_err(crypto_error)?;
    let expand = |secret: &[u8], label: &str, context: &[u8], length: usize| {
        hkdf_expand_label(
            crypto,
            suite.hmac(),
            secret,
            DTLS13_LABEL_PREFIX,
            label,
            context,
            length,
        )
        .map_err(crypto_error)
    };
    let secret = expand(exporter_secret, label, &empty_hash, suite.hash_len())?;
    let context_hash = crypto.hash(suite.hash(), context).map_err(crypto_error)?;
    expand(secret.as_ref(), "exporter", &context_hash, length)
}

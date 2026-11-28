use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::rtc_error::{RTCError, RTCErrorDetailType};
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::dtls::fingerprint::{
    RTCDtlsFingerprint, format_fingerprint, preferred_fingerprints,
};
use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
use crate::peer_connection::transport::dtls::role::{DEFAULT_DTLS_ROLE_ANSWER, RTCDtlsRole};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crypto::RTCCryptoProvider;
use dtls::cipher_suite::CipherSuiteId;
use dtls::config::{ClientAuthType, VerifyPeerCertificateFn};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rustls::pki_types::CertificateDer;
use shared::error::{Error, Result};
use shared::{TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::SystemTime;

pub(crate) mod fingerprint;
pub(crate) mod parameters;
pub(crate) mod resumption;
pub(crate) mod role;
pub(crate) mod state;

/// The initial DTLS retransmission timer of a peer connection: what RFC 9147 section 5.8.2
/// recommends for DTLS-SRTP, where latencies of real-time paths are short.
pub(crate) const DTLS_SRTP_FLIGHT_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(400);
/// The least the timer is set to from ICE's round trip time: on a local path 1.5 times the
/// round trip is less than the time the peer needs to answer a flight.
pub(crate) const MINIMUM_FLIGHT_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(100);

/// The DTLS cipher suites a peer connection offers when the application configures none: the
/// TLS 1.3 suites, with which DTLS 1.3 (RFC 9147) is negotiated and preferred, and for DTLS
/// 1.2 the `dtls` crate's defaults without the AES-256-CBC-SHA suites. Browsers negotiate GCM,
/// and the CBC suites' MAC-then-encrypt record handling is the part of DTLS with a history of padding
/// and length bugs (rtc#96 was one). An application that needs CBC can still list it with
/// `SettingEngineBuilder::with_dtls_cipher_suites`.
pub(crate) fn webrtc_default_cipher_suites() -> Vec<CipherSuiteId> {
    vec![
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
        CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    ]
}

/// Whether two remote fingerprint lists name the same certificates (order and hex case aside).
pub(crate) fn same_fingerprints(a: &[RTCDtlsFingerprint], b: &[RTCDtlsFingerprint]) -> bool {
    let normalize = |list: &[RTCDtlsFingerprint]| {
        let mut v: Vec<(String, String)> = list
            .iter()
            .map(|fp| (fp.algorithm.to_lowercase(), fp.value.to_lowercase()))
            .collect();
        v.sort();
        v
    };
    normalize(a) == normalize(b)
}

/// The DTLS-SRTP profiles offered when the application configures none: the GCM ones, the
/// 256-bit key first (RFC 3711 section 9.2: keys "as large as possible"; RFC 6188 section 6:
/// AES-256 where the highest security is wanted), and AES_CM with the 80-bit tag. Not `SRTP_AES128_CM_HMAC_SHA1_32`: RFC 3711 section 9.5 allows
/// the 32-bit tag only where its two conditions hold (forgery of a packet does no harm worth
/// more than 2^-32, and the payload's integrity is not needed), which the engine cannot know
/// of any session; an application that knows sets it with
/// `SettingEngineBuilder::with_srtp_protection_profiles`.
pub(crate) fn default_srtp_protection_profiles() -> Vec<SrtpProtectionProfile> {
    vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ]
}

/// DTLSTransport allows an application access to information about the DTLS
/// transport over which RTP and RTCP packets are sent and received by
/// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
/// and received by data channels.
pub(crate) struct DtlsTransport {
    pub(crate) id: RTCTransportId,
    pub(crate) ice_transport_id: RTCTransportId,

    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) dtls_role: RTCDtlsRole,
    pub(crate) dtls_handshake_config: Option<Arc<::dtls::config::HandshakeConfig>>,
    pub(crate) dtls_endpoint: Option<::dtls::endpoint::Endpoint>,

    pub(crate) state: RTCDtlsTransportState,
    pub(crate) certificates: Vec<RTCCertificate>,

    /// Set by the certificate check when the peer's certificate matched none of the remote
    /// description's fingerprints: the transport's failure is then `fingerprint-failure`
    /// rather than `dtls-failure` (W3C webrtc-pc section 5.5).
    pub(crate) fingerprint_mismatch: Arc<std::sync::atomic::AtomicBool>,
    /// The error the transport failed with (W3C `RTCDtlsTransport` `error` event), until the
    /// peer connection has announced it.
    pub(crate) failure: Option<crate::peer_connection::rtc_error::RTCError>,
    /// The SRTP key lifetime the setting engine sets, if any (`DtlsHandler::key_lifetime`).
    pub(crate) srtp_key_lifetime: Option<srtp::keying::KeyLifetime>,
    /// `SettingEngineBuilder::with_dtls_connection_id`: the length of the connection id this
    /// side asks the peer to send (RFC 9146, RFC 9147 section 9); `None` keeps the DTLS
    /// crate's default (the extension, asking for none).
    pub(crate) connection_id_length: Option<usize>,
    /// ALPN with the RFC 8833 identifiers (`SettingEngineBuilder::with_dtls_alpn`).
    pub(crate) alpn: bool,
    /// The application protocol the association's handshake selected (RFC 7301).
    pub(crate) application_protocol: Option<String>,
    /// The ICE selected pair the association last sent on, to tell a new path (RFC 9147
    /// section 9) from the first selection.
    pub(crate) selected_pair_id: Option<String>,

    // The peer's certificate chain in DER form, retained at handshake completion so
    // `get_remote_certificates()` has something to return. Previously the bytes reached
    // `update_dtls_stats_from_profile`, were hex-encoded into `RTCCertificateStats`, and then
    // dropped; only the derived fingerprint id survived, which cannot be turned back into a
    // certificate.
    pub(crate) remote_certificates: Vec<Vec<u8>>,

    // The remote DTLS parameters (fingerprints, `setup` role) the current session was built
    // for, so an ICE restart that leaves them unchanged keeps the session (Brainwires fork).
    pub(crate) remote_dtls_parameters: Option<RTCDtlsParameters>,

    /// The peer's `a=tls-id` (RFC 8842 section 4) for the current association, when it sends
    /// one: a different value in a later description asks for a new association.
    pub(crate) remote_tls_id: Option<String>,
    /// This endpoint's `a=tls-id` for the current association: the same in every offer and
    /// answer while the association is kept, replaced when a new one is decided.
    pub(crate) local_tls_id: String,
    /// The `tls-id` an offer that asks for a new association carries (`create_offer` has no
    /// side effects): it becomes `local_tls_id` when the answer starts that association.
    pub(crate) staged_local_tls_id: Option<String>,
    /// `staged_local_tls_id` was staged by an offer of this side (`offer_tls_id`), not by the
    /// answer to a remote offer (`stage_answer_tls_id`).
    pub(crate) staged_tls_id_offered: bool,
    /// The `tls-id` an offer of this side had staged (created, not applied) when a remote
    /// offer staged its answer's in its place (`stage_answer_tls_id`): back in place if that
    /// remote offer is rolled back (`restore_offer_tls_id`), gone once it is answered.
    pub(crate) replaced_offer_tls_id: Option<String>,
    /// The application asked for a new association (`RTCPeerConnection::renew_dtls_association`):
    /// the next offer carries a new `tls-id` (RFC 8842 section 5.5).
    pub(crate) renewal_requested: bool,
    /// The renewal was asked for by the connection itself, for SRTP re-keying (an SRTP master
    /// key neared its lifetime): what `OnLocalCandidatesNeeded` reports as its reason.
    pub(crate) renewal_for_srtp_rekeying: bool,
    /// Where the automatic SRTP re-keying of the current association stands
    /// (`RTCPeerConnection::renew_before_the_key_lifetime_ends`).
    pub(crate) srtp_rekeying: SrtpRekeying,
    /// Until when a [`SrtpRekeying::Deferred`] server waits for the client's re-keying offer.
    pub(crate) srtp_rekeying_deferred_until: Option<std::time::Instant>,

    /// Whether the session has an RTP media section, which needs SRTP keys from the
    /// association (RFC 5764; RFC 8827 section 6.5: no media without SRTP).
    pub(crate) srtp_required: bool,
    /// Whether the current association negotiated `use_srtp`; `None` until its handshake
    /// completes.
    pub(crate) srtp_negotiated: Option<bool>,
    /// The retransmission timer the client's handshake was started with: 400 ms, or 1.5
    /// times the round trip time ICE measured (RFC 9147 section 5.8.2).
    pub(crate) flight_interval: Option<std::time::Duration>,
    /// How the client's first retransmission timer is chosen
    /// (`SettingEngineBuilder::with_dtls_flight_interval`).
    pub(crate) flight_interval_rule:
        crate::peer_connection::configuration::setting_engine::DtlsFlightInterval,
    /// When the current association's handshake began on this side: the client's first
    /// flight, or the first handshake datagram the server read. `None` once it completed.
    pub(crate) handshake_began: Option<std::time::Instant>,
    /// The time a re-keying of this transport needs, measured on the handshake of the
    /// current association: its duration (its round trips and flights, and any
    /// retransmission it took), as much again for the ICE checks of the restart a new
    /// association comes with (a check and its nomination: two round trips, no more than
    /// the handshake's own), and one DTLS retransmission timer for a lost flight. The SRTP re-keying margin is at least the
    /// packets the keys protect in that time (`SrtpHandlerContext::rekeying_margin_reached`).
    pub(crate) rekeying_handshake_time: Option<std::time::Duration>,

    // From SettingEngine
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    /// Offer `use_srtp` on every association, as browsers do, and not only on one that carries
    /// SRTP media (`SettingEngineBuilder::with_dtls_use_srtp_on_every_association`).
    pub(crate) use_srtp_always: bool,
    /// Whether the handshake config of the current association offers (as the client) or
    /// accepts (as the server) `use_srtp`.
    pub(crate) srtp_configured: bool,
    /// Empty means "use the WebRTC default set", [`webrtc_default_cipher_suites`] (see
    /// [`SettingEngineBuilder::with_dtls_cipher_suites`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_dtls_cipher_suites)).
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) replay_protection: ReplayProtection,

    /// The peer connection's DTLS session (RFC 5764 section 3), shared by its transports;
    /// `None` unless `SettingEngineBuilder::with_dtls_session_resumption` turns it on.
    pub(crate) resumption: Option<Arc<resumption::DtlsSessionGroup>>,
    /// The current association was admitted to the connection's session: it is the
    /// transport's first, set up by the negotiation that set up the transports, can run DTLS
    /// 1.3, for the same remote fingerprints as the session's (`DtlsSessionGroup::admit`). It
    /// takes part once that negotiation is over and its role has another transport
    /// ([`Self::engage_session`]).
    pub(crate) resumption_candidate: bool,
    /// The current association takes part in the connection's session: its handshake config
    /// resumes from it (`DtlsSessionGroup::configure`).
    pub(crate) resumption_member: bool,
    /// Names this transport to its session group.
    pub(crate) resumption_token: Arc<()>,
}

/// The ALPN identifier of WebRTC (RFC 8833 section 2): DTLS-SRTP keys and data channels.
pub(crate) const ALPN_WEBRTC: &str = "webrtc";
/// The ALPN identifier of confidential WebRTC (RFC 8833 section 2), offered beside
/// `webrtc` by a client that is not aware of a need for confidentiality.
pub(crate) const ALPN_C_WEBRTC: &str = "c-webrtc";

pub(crate) struct RTCDtlsTransportConfig {
    pub(crate) id: RTCTransportId,
    pub(crate) ice_transport_id: RTCTransportId,
    pub(crate) certificates: Vec<RTCCertificate>,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) use_srtp_always: bool,
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) replay_protection: ReplayProtection,
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
}

/// What a remote description means for the DTLS association the transport has (RFC 8842
/// section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DtlsAssociationUpdate {
    /// The association goes on (or the transport has not started).
    Kept,
    /// A new association replaces it: the endpoint was reset and a handshake is due.
    New,
}

/// Why a remote description may need a new DTLS association besides what it says itself.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DtlsRemoteUpdate {
    /// The description answers this endpoint's offer (else it is the peer's offer).
    pub(crate) we_offer: bool,
    /// The exchange restarts ICE: an association that failed or was closed is replaced too.
    pub(crate) ice_restart: bool,
    /// The transport the association ran on was closed (every m-section of its BUNDLE group
    /// was rejected, RFC 8843 section 7.1.3, RFC 9429 section 5.10): the peer starts a new
    /// association on the new one even with the same certificate and `setup` role.
    pub(crate) transport_closed: bool,
}

/// A new `tls-id` value (RFC 8842 section 4): 128 bits from the provider's random source as
/// 32 hex digits, within the attribute's `20*255(ALPHA / DIGIT / "+" / "/" / "-" / "_")`.
/// The automatic SRTP re-keying of an association (RFC 5764 section 4.4): a new association is
/// asked for once one of its keys nears its lifetime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SrtpRekeying {
    /// No key of the association is near its lifetime.
    #[default]
    Idle,
    /// The lifetime warning came and this side is the DTLS server: it waits briefly for the
    /// client's re-keying offer (`DtlsTransport::srtp_rekeying_deferred_until`, at most
    /// `SRTP_REKEYING_SERVER_WAIT` and an eighth of the time the keys have left), or until a
    /// thirty-second of the lifetime is left if that comes first
    /// (`SettingEngineBuilder::with_srtp_rekeying_dtls_client_first`).
    Deferred,
    /// A new association is wanted: asked for as soon as none is being negotiated or
    /// established.
    Wanted,
}

fn generate_tls_id(crypto_provider: &Arc<dyn RTCCryptoProvider>) -> Result<String> {
    let mut random = [0u8; 16];
    crypto_provider
        .random()
        .fill(&mut random)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

impl DtlsTransport {
    /// The application protocol the DTLS handshake's ALPN selected (RFC 7301, RFC 8833
    /// `webrtc` or `c-webrtc`), once the association is up: `None` when the peer used no
    /// ALPN, which RFC 8833 section 2 has taken as `webrtc`.
    pub(crate) fn application_protocol(&self) -> Option<&str> {
        self.application_protocol.as_deref()
    }

    pub(crate) fn new(config: RTCDtlsTransportConfig) -> Result<Self> {
        let RTCDtlsTransportConfig {
            id,
            ice_transport_id,
            mut certificates,
            answering_dtls_role,
            srtp_protection_profiles,
            use_srtp_always,
            dtls_cipher_suites,
            allow_insecure_verification_algorithm,
            disable_certificate_fingerprint_verification,
            replay_protection,
            crypto_provider,
        } = config;
        // Wall-clock time for X.509 validity: the expiry of configured certificates, the
        // validity period of a generated one.
        let now = SystemTime::now(); // Exemption: wall-clock is correct here to check X.509 certificate expiry
        if !certificates.is_empty() {
            for cert in &certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }
        } else {
            // W3C constructor: "generate one or more new RTCCertificate instances", as
            // generateCertificate does (random names and serial, 30 days).
            let cert = RTCCertificate::generate_certificate(
                crypto_provider.crypto(),
                crypto::SignatureScheme::EcdsaP256Sha256,
                None,
                now,
            )?;
            certificates = vec![cert];
        };

        Ok(Self {
            id,
            ice_transport_id,
            dtls_role: RTCDtlsRole::Auto,
            dtls_handshake_config: None,
            dtls_endpoint: None,
            state: RTCDtlsTransportState::New,
            certificates,
            fingerprint_mismatch: Arc::default(),
            failure: None,
            srtp_key_lifetime: None,
            connection_id_length: None,
            alpn: true,
            application_protocol: None,
            selected_pair_id: None,
            remote_certificates: vec![],
            remote_dtls_parameters: None,
            remote_tls_id: None,
            local_tls_id: generate_tls_id(&crypto_provider)?,
            staged_local_tls_id: None,
            staged_tls_id_offered: false,
            replaced_offer_tls_id: None,
            renewal_requested: false,
            renewal_for_srtp_rekeying: false,
            srtp_rekeying: SrtpRekeying::Idle,
            srtp_rekeying_deferred_until: None,
            srtp_required: false,
            srtp_negotiated: None,
            flight_interval: None,
            flight_interval_rule: Default::default(),
            handshake_began: None,
            rekeying_handshake_time: None,

            answering_dtls_role,
            srtp_protection_profiles,
            use_srtp_always,
            srtp_configured: false,
            dtls_cipher_suites,
            allow_insecure_verification_algorithm,
            disable_certificate_fingerprint_verification,
            replay_protection,
            crypto_provider,
            resumption: None,
            resumption_candidate: false,
            resumption_member: false,
            resumption_token: Arc::new(()),
        })
    }

    /// The session group, when the current association takes part in it.
    pub(crate) fn session_group(&self) -> Option<&Arc<resumption::DtlsSessionGroup>> {
        self.resumption.as_ref().filter(|_| self.resumption_member)
    }

    /// The `RTCError` of the association's failure (W3C webrtc-pc section 11.2):
    /// `fingerprint-failure` when the peer's certificate matched no fingerprint, else
    /// `dtls-failure` with the fatal alert this side sent or received, if one was.
    pub(crate) fn failure_error(&self) -> RTCError {
        if self
            .fingerprint_mismatch
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return RTCError::new(
                RTCErrorDetailType::FingerprintFailure,
                "the remote certificate matches no fingerprint of the remote description",
            );
        }
        let (sent_alert, received_alert) = self
            .dtls_endpoint
            .as_ref()
            .and_then(|endpoint| {
                endpoint
                    .get_connections_keys()
                    .next()
                    .and_then(|remote| endpoint.connection_fatal_alerts(remote))
            })
            .unwrap_or_default();
        RTCError {
            sent_alert,
            received_alert,
            ..RTCError::new(
                RTCErrorDetailType::DtlsFailure,
                match (sent_alert, received_alert) {
                    (_, Some(alert)) => format!("fatal alert {alert} received"),
                    (Some(alert), None) => format!("fatal alert {alert} sent"),
                    (None, None) => "the DTLS handshake failed".to_owned(),
                },
            )
        }
    }

    pub(crate) fn state_change(&mut self, state: RTCDtlsTransportState) {
        if state == RTCDtlsTransportState::Connecting {
            // A new association: what the last one failed with is not this one's.
            self.fingerprint_mismatch
                .store(false, std::sync::atomic::Ordering::Relaxed);
            self.failure = None;
            self.handshake_began = None;
        }
        if matches!(
            state,
            RTCDtlsTransportState::Failed | RTCDtlsTransportState::Closed
        ) && let Some(group) = self.session_group()
        {
            // The transports waiting for this one's session start (RFC 5764 section 3).
            group.ended(&self.resumption_token, None);
        }
        self.state = state;
    }

    /// Whether negotiation has brought this transport up — i.e. `start()` has built its
    /// endpoint. The struct itself is constructed with the peer connection, so this is the
    /// closer analogue of "the DTLS transport exists" in the protocol sense.
    pub(crate) fn is_started(&self) -> bool {
        self.dtls_endpoint.is_some()
    }

    /// W3C `DtlsTransport.state`.
    ///
    /// The field has carried this value all along; only the setter (`state_change`) existed.
    pub(crate) fn state(&self) -> RTCDtlsTransportState {
        self.state
    }

    /// W3C `DtlsTransport.getRemoteCertificates()`: the peer's certificate chain, DER-encoded.
    ///
    /// Empty until the DTLS handshake completes. DER is the analogue of the browser's
    /// `sequence<ArrayBuffer>`.
    pub(crate) fn get_remote_certificates(&self) -> &[Vec<u8>] {
        &self.remote_certificates
    }

    fn derive_role(&self, ice_role: RTCIceRole, remote_dtls_role: RTCDtlsRole) -> RTCDtlsRole {
        // If remote has an explicit role use the inverse
        match remote_dtls_role {
            RTCDtlsRole::Client => return RTCDtlsRole::Server,
            RTCDtlsRole::Server => return RTCDtlsRole::Client,
            _ => {}
        };

        // If SettingEngine has an explicit role
        match self.answering_dtls_role {
            RTCDtlsRole::Server => return RTCDtlsRole::Server,
            RTCDtlsRole::Client => return RTCDtlsRole::Client,
            _ => {}
        };

        // Remote was auto and no explicit role was configured via SettingEngine
        if ice_role == RTCIceRole::Controlling {
            return RTCDtlsRole::Server;
        }

        DEFAULT_DTLS_ROLE_ANSWER
    }

    /// Build a DTLS HandshakeConfig from remote fingerprints, for the role already in
    /// `self.dtls_role`. Does not check or change transport state, so it serves both the
    /// initial start and a new association ([`update_remote`](Self::update_remote)).
    /// `resume`: the association resumes from, and makes, the connection's session
    /// ([`resumption`]); otherwise it neither offers nor accepts a resumption.
    /// (Brainwires fork; see FORK.md.)
    fn make_handshake_config(
        &self,
        remote_dtls_parameters: &RTCDtlsParameters,
        resume: bool,
    ) -> Result<Arc<::dtls::config::HandshakeConfig>> {
        let remote_fingerprints = remote_dtls_parameters.fingerprints.clone();
        // Leaving the callback out is what disables the check: `insecure_skip_verify` is
        // already true, so this comparison is the only thing standing between the peer's
        // certificate and acceptance. Dropping it does not accept a peer that presents no
        // certificate at all — `client_auth` is `RequireAnyClientCert`, which the DTLS layer
        // enforces on its own.
        //
        // Protocols where the answerer cannot know the offerer's fingerprint ahead of time
        // need this. libp2p's WebRTC-Direct is the canonical case: the server synthesizes the
        // client's offer locally with a placeholder fingerprint and authenticates the peer
        // afterwards with a Noise handshake over the data channel.
        let verify_peer_certificate: Option<VerifyPeerCertificateFn> = if !self
            .disable_certificate_fingerprint_verification
        {
            let fingerprint_crypto = self.crypto_provider.clone();
            let fingerprint_mismatch = self.fingerprint_mismatch.clone();
            Some(Arc::new(
                move |certs: &[Vec<u8>], _chains: &[CertificateDer<'static>]| -> Result<()> {
                    if certs.is_empty() {
                        return Err(Error::ErrNonCertificate);
                    }

                    // RFC 8122 section 5.1: the fingerprints of the most preferred hash
                    // function among those the peer offered, and the certificate must
                    // match one of that set. MD5, MD2 and unknown functions are never used.
                    let Some((algorithm, fingerprints)) =
                        preferred_fingerprints(&remote_fingerprints, fingerprint_crypto.crypto())
                    else {
                        return Err(Error::ErrUnsupportedFingerprintAlgorithm);
                    };
                    let hashed = fingerprint_crypto
                        .crypto()
                        .hash(algorithm, &certs[0])
                        .map_err(|error| Error::Crypto(error.to_string()))?;
                    let certificate_value = format_fingerprint(&hashed);
                    if fingerprints
                        .iter()
                        .any(|fp| fp.value.eq_ignore_ascii_case(&certificate_value))
                    {
                        return Ok(());
                    }

                    fingerprint_mismatch.store(true, std::sync::atomic::Ordering::Relaxed);
                    Err(Error::ErrNoMatchingCertificateFingerprint)
                },
            ))
        } else {
            None
        };

        let certificate = if let Some(cert) = self.certificates.first() {
            cert.dtls_certificate.clone()
        } else {
            return Err(Error::ErrNonCertificate);
        };

        // RFC 5764 section 4.1: `use_srtp` is for an association that carries RTP or RTCP.
        let profiles = if self.offers_use_srtp() {
            self.supported_srtp_protection_profiles()?
        } else {
            vec![]
        };

        let builder = ::dtls::config::ConfigBuilder::default()
            .with_crypto_provider(self.crypto_provider.clone())
            .with_certificates(vec![certificate])
            .with_srtp_protection_profiles(profiles)
            // A server that leaves `use_srtp` out is a data-channel-only peer, not a
            // failed handshake: whether the session can do without SRTP is decided when
            // the handshake completes (`DtlsHandler`), from the session's media sections.
            .with_use_srtp_optional(true)
            // As the server: with no shared profile the association falls back to DTLS
            // without SRTP (RFC 5764 section 4.1.1), unless the session has a media
            // section, for which that is not acceptable.
            .with_use_srtp_required(self.srtp_required)
            // Empty means the WebRTC default set (AEAD only); a non-empty list replaces it.
            .with_cipher_suites(if self.dtls_cipher_suites.is_empty() {
                webrtc_default_cipher_suites()
            } else {
                self.dtls_cipher_suites.clone()
            })
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            // RFC 8122 section 6.2: no client certificate ends the handshake with
            // bad_certificate.
            .with_bad_certificate_for_a_missing_client_certificate(true)
            .with_insecure_skip_verify(true)
            .with_insecure_verification(self.allow_insecure_verification_algorithm)
            .with_verify_peer_certificate(verify_peer_certificate)
            .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
            .with_replay_protection_window(self.replay_protection.dtls)
            // RFC 9147 section 5.8.2: 400 ms is the retransmission timer recommended
            // for DTLS-SRTP. A client that knows the round trip time of the selected
            // pair from ICE starts from 1.5 times that instead (`DtlsHandler`); the
            // libwebrtc rule (`DtlsFlightInterval`) from 50 ms, or twice the round trip.
            .with_flight_interval(self.flight_interval_rule.initial(None))
            .with_connection_id(self.connection_id_length.or(Some(0)))
            // RFC 8835 section 3.5 (RFC 8833 section 2): a client offers both WebRTC
            // identifiers, a server selects `webrtc`; it never promises the media
            // confidentiality of `c-webrtc`.
            .with_alpn_protocols(match (self.alpn, self.dtls_role) {
                (false, _) => vec![],
                (true, RTCDtlsRole::Client) => {
                    vec![ALPN_WEBRTC.to_owned(), ALPN_C_WEBRTC.to_owned()]
                }
                (true, _) => vec![ALPN_WEBRTC.to_owned()],
            })
            // No resumption but the connection's own session, in DTLS 1.3 (RFC 5764
            // section 3, RFC 8446 section 2.2): an association outside it issues no
            // tickets as a server (and so accepts no resumption: it has no key to open a
            // ticket with), and keeps nothing and offers no PSK as a client. DTLS 1.2
            // (RFC 5246 section 7.3, RFC 5077) takes no part in any association: no
            // session id or ticket is asked for, given or accepted. Every resumed
            // handshake has the stored peer certificates checked against this section's
            // fingerprints by `verify_peer_certificate`, as a full one has the
            // certificates it carries.
            .with_session_tickets(0)
            .with_session_cache(None)
            .with_session_store(None)
            .with_dtls12_resumption(false)
            .with_external_psks(vec![])
            .with_psk_without_key_exchange(false);
        let builder = match self.resumption.as_ref() {
            Some(group) if resume => group.configure(builder, self.dtls_role),
            _ => builder,
        };
        Ok(Arc::new(
            builder.build(self.dtls_role == RTCDtlsRole::Client, None)?,
        ))
    }

    pub(crate) fn prepare_transport(
        &mut self,
        ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<Arc<::dtls::config::HandshakeConfig>> {
        if self.state != RTCDtlsTransportState::New {
            return Err(Error::ErrInvalidDTLSStart);
        }

        self.dtls_role = self.derive_role(ice_role, remote_dtls_parameters.role);
        // Without the connection's session: it is given it once the negotiation is over, if
        // it takes part (`engage_session`).
        let dtls_handshake_config = self.make_handshake_config(&remote_dtls_parameters, false)?;
        // RFC 5764 section 3: the first association of a transport may resume the
        // connection's session, when it is for the same remote certificates and can run DTLS
        // 1.3 (the only version the peer connection resumes).
        self.resumption_candidate = dtls_handshake_config.supports_dtls13()
            && self.resumption.as_ref().is_some_and(|group| {
                group.admit(
                    &self.resumption_token,
                    self.dtls_role,
                    &remote_dtls_parameters.fingerprints,
                )
            });
        self.resumption_member = false;
        self.srtp_configured = self.offers_use_srtp();
        self.state_change(RTCDtlsTransportState::Connecting);
        self.remote_dtls_parameters = Some(remote_dtls_parameters);
        Ok(dtls_handshake_config)
    }

    /// Re-initialise the DTLS transport for re-handshake after an ICE restart, when one is needed.
    ///
    /// An ICE restart alone does not need a new DTLS session (RFC 8842 section 6: DTLS is
    /// bound to the ICE transport, not to a 5-tuple), and browsers do not start one, so a
    /// `Connected` or `Connecting` session whose remote fingerprints, `tls-id` and roles are
    /// unchanged is kept. See [`update_remote`](Self::update_remote).
    ///
    /// Brainwires fork feature; see FORK.md.
    #[cfg(test)]
    pub(crate) fn restart(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        self.update_remote(
            local_ice_role,
            remote_dtls_parameters,
            None,
            DtlsRemoteUpdate {
                ice_restart: true,
                ..Default::default()
            },
        )
        .map(|_| ())
    }

    /// Re-initialise the DTLS transport for a new association whatever its state: the transport
    /// it ran on was closed. No-ops if state is `New`.
    #[cfg(test)]
    pub(crate) fn restart_new_association(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        self.update_remote(
            local_ice_role,
            remote_dtls_parameters,
            None,
            DtlsRemoteUpdate {
                ice_restart: true,
                transport_closed: true,
                ..Default::default()
            },
        )
        .map(|_| ())
    }

    /// Applies the DTLS parameters of a remote description to a started transport: keeps the
    /// association, or replaces it with a new one when RFC 8842 section 3.1 says so. A no-op
    /// while the state is `New` (the first description starts the transport).
    ///
    /// A new association is established when
    ///
    /// - the description changes the DTLS roles: its `a=setup` takes the role this endpoint
    ///   has (`actpass` takes none, so it never changes them: the roles of an association are
    ///   fixed for its life, whichever side offers and whatever the ICE roles become);
    /// - its fingerprint set differs from the one the association was built for;
    /// - its `a=tls-id` differs from the association's (when both descriptions have one);
    /// - the transport was closed and is set up again;
    /// - the session has a media section and the association cannot key SRTP (it was set up
    ///   for data channels only, without `use_srtp`); or
    /// - ICE restarts and the association had failed or was closed.
    ///
    /// Otherwise the association goes on, across ICE restarts too (RFC 8842 section 6).
    ///
    /// For a new association the endpoint is replaced and the state goes back to
    /// `Connecting`: a server accepts the peer's ClientHello from then on, a client starts
    /// its handshake at the next `ICESelectedCandidatePairChange`, or at once when the caller
    /// asks the handler to (`DtlsHandlerContext::connect_requested`). The roles are the
    /// inverse of an explicit remote role; with `actpass` they stay as they were, and after a
    /// closed transport they are chosen anew (the configured answering role, else from the ICE
    /// role). The answerer takes a new local `tls-id` (RFC 8842 section 5.3); the
    /// offerer's is the one its offer carried.
    ///
    /// **Note on identity**: the local certificate and its fingerprint are *not*
    /// regenerated: the same identity is used by every association of the connection.
    pub(crate) fn update_remote(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
        remote_tls_id: Option<String>,
        update: DtlsRemoteUpdate,
    ) -> Result<DtlsAssociationUpdate> {
        let Some(new_role) = self.planned_association(
            local_ice_role,
            &remote_dtls_parameters,
            remote_tls_id.as_deref(),
            update,
            self.srtp_required,
        ) else {
            // Nothing DTLS depends on changed (or the transport is not started yet: the
            // initial start_transports handles that path): keep the association (over the
            // restarted ICE path, if ICE restarts).
            if self.state != RTCDtlsTransportState::New && remote_tls_id.is_some() {
                self.remote_tls_id = remote_tls_id;
            }
            return Ok(DtlsAssociationUpdate::Kept);
        };

        // The roles of the new association, committed only once its handshake config has been
        // built.
        let previous_role = self.dtls_role;
        self.dtls_role = new_role;
        // A later association is a full handshake, with a fresh key exchange: never a
        // resumption (SRTP re-keying, RFC 5764 section 4.4, needs new keys).
        let dtls_handshake_config = match self.make_handshake_config(&remote_dtls_parameters, false)
        {
            Ok(config) => config,
            Err(err) => {
                self.dtls_role = previous_role;
                return Err(err);
            }
        };
        // The offerer's `tls-id` is the one its offer carried; the answerer's is new (RFC 8842
        // section 5.3), the one its answer carried when `create_answer` staged it.
        let local_tls_id = if update.we_offer {
            self.staged_local_tls_id.take()
        } else if let Some(staged) = self.staged_local_tls_id.take() {
            Some(staged)
        } else {
            match generate_tls_id(&self.crypto_provider) {
                Ok(tls_id) => Some(tls_id),
                Err(err) => {
                    self.dtls_role = previous_role;
                    return Err(err);
                }
            }
        };
        if let Some(local_tls_id) = local_tls_id {
            self.local_tls_id = local_tls_id;
        }
        self.staged_tls_id_offered = false;
        self.replaced_offer_tls_id = None;

        if let Some(group) = self.session_group() {
            group.ended(&self.resumption_token, None);
        }
        self.resumption_candidate = false;
        self.resumption_member = false;
        self.state_change(RTCDtlsTransportState::Connecting);
        self.install_endpoint(dtls_handshake_config);
        self.remote_dtls_parameters = Some(remote_dtls_parameters);
        self.remote_tls_id = remote_tls_id;
        self.remote_certificates.clear();
        self.srtp_negotiated = None;
        self.srtp_configured = self.offers_use_srtp();
        self.renewal_requested = false;
        self.renewal_for_srtp_rekeying = false;
        // The new association brings new keys.
        self.srtp_rekeying = SrtpRekeying::Idle;
        self.srtp_rekeying_deferred_until = None;
        Ok(DtlsAssociationUpdate::New)
    }

    /// What [`Self::update_remote`] decides for these parameters, without doing it: `None`
    /// keeps the association (or leaves a transport that is not started to `start`),
    /// `Some(role)` is the DTLS role of the new association that replaces it. `srtp_required`
    /// is whether the session the description sets up has a media section.
    ///
    /// The answerer decides this when it applies the remote offer, so that its answer states
    /// the new association's role and `tls-id`, and makes the change when it applies that
    /// answer (a rolled-back offer changes nothing, RFC 9429 section 5.7).
    pub(crate) fn planned_association(
        &self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: &RTCDtlsParameters,
        remote_tls_id: Option<&str>,
        update: DtlsRemoteUpdate,
        srtp_required: bool,
    ) -> Option<RTCDtlsRole> {
        if self.state == RTCDtlsTransportState::New {
            return None;
        }
        let healthy = matches!(
            self.state,
            RTCDtlsTransportState::Connected | RTCDtlsTransportState::Connecting
        );
        let same_fingerprints = self
            .remote_dtls_parameters
            .as_ref()
            .is_some_and(|previous| {
                same_fingerprints(&previous.fingerprints, &remote_dtls_parameters.fingerprints)
            });
        // A peer that sends no `tls-id` (now, or before) signals nothing with it (RFC 8842
        // section 4).
        let same_tls_id = match (self.remote_tls_id.as_deref(), remote_tls_id) {
            (Some(previous), Some(new)) => previous == new,
            _ => true,
        };
        let same_roles = match remote_dtls_parameters.role {
            RTCDtlsRole::Client => self.dtls_role == RTCDtlsRole::Server,
            RTCDtlsRole::Server => self.dtls_role == RTCDtlsRole::Client,
            _ => matches!(self.dtls_role, RTCDtlsRole::Client | RTCDtlsRole::Server),
        };
        // A session that gained a media section on an association without SRTP keys needs
        // one that has them.
        let needs_srtp = srtp_required && !self.can_key_srtp();
        if !update.transport_closed
            && !needs_srtp
            && same_fingerprints
            && same_tls_id
            && same_roles
            && (healthy || !update.ice_restart)
        {
            return None;
        }
        // An `actpass` description leaves the choice here: the roles the endpoints have are
        // kept, so what runs over DTLS (SCTP takes its role from it) is not turned around.
        // Only a transport that was closed chooses anew.
        let previous_role = self.dtls_role;
        Some(
            if update.transport_closed
                || remote_dtls_parameters.role != RTCDtlsRole::Auto
                || !matches!(previous_role, RTCDtlsRole::Client | RTCDtlsRole::Server)
            {
                self.derive_role(local_ice_role, remote_dtls_parameters.role)
            } else {
                previous_role
            },
        )
    }

    /// Stages the `tls-id` the answer to an offer that asks for a new association carries
    /// (RFC 8842 section 5.3), the one [`Self::update_remote`] then takes. `false` when one was
    /// already staged (it is kept).
    ///
    /// A value an offer of this side staged is not the answer's: RFC 8842 section 5.3 has the
    /// answerer insert "a new unique attribute value", and an offer this side created (and
    /// perhaps sent, then rolled back) is another transaction's (RFC 9429 section 5.7). It is
    /// put aside (`replaced_offer_tls_id`) and a new one staged.
    pub(crate) fn stage_answer_tls_id(&mut self) -> Result<bool> {
        if self.staged_local_tls_id.is_some() && !self.staged_tls_id_offered {
            return Ok(false);
        }
        let fresh = generate_tls_id(&self.crypto_provider)?;
        if self.staged_tls_id_offered {
            self.replaced_offer_tls_id = self.staged_local_tls_id.take();
            self.staged_tls_id_offered = false;
        }
        self.staged_local_tls_id = Some(fresh);
        Ok(true)
    }

    /// The remote offer whose answer `tls-id` was staged is abandoned (rolled back, refused,
    /// replaced): the staged value goes, and the one of this side's own offer it replaced, if
    /// any, is back in place.
    pub(crate) fn drop_answer_tls_id(&mut self) {
        self.staged_local_tls_id = self.replaced_offer_tls_id.take();
        self.staged_tls_id_offered = self.staged_local_tls_id.is_some();
    }

    /// This side's offer is rolled back (RFC 9429 section 5.7: "Any resources or candidates
    /// that were allocated by the abandoned local description are discarded"): the `tls-id` it
    /// staged for a new association goes, so that neither the answer to the peer's offer nor
    /// a later offer of this side reuses a value that was signalled for an abandoned
    /// transaction (RFC 8842 section 4: a new association has a new value). The renewal it
    /// was made for stays asked for (`renewal_requested`): the next offer stages a new one.
    pub(crate) fn discard_offer_tls_id(&mut self) {
        if self.staged_tls_id_offered {
            self.staged_local_tls_id = None;
            self.staged_tls_id_offered = false;
        }
    }

    /// The `tls-id` an offer carries (RFC 8842 section 5.5): the association's, or, when the
    /// offer asks for a new association (`new_association`: the transport was closed and the
    /// offer sets one up again), a new value, the same for every such offer until an answer
    /// starts that association.
    pub(crate) fn offer_tls_id(&mut self, new_association: bool) -> Result<String> {
        let new_association = new_association || self.renewal_requested;
        if !new_association || self.state == RTCDtlsTransportState::New {
            return Ok(self.local_tls_id.clone());
        }
        if self.staged_local_tls_id.is_none() {
            self.staged_local_tls_id = Some(generate_tls_id(&self.crypto_provider)?);
            self.staged_tls_id_offered = true;
        }
        Ok(self.staged_local_tls_id.clone().unwrap_or_default())
    }

    /// Installs a fresh endpoint for `self.dtls_role`: a client keeps the config until the
    /// selected pair is known and it can `connect()`, a server accepts with it at once.
    fn install_endpoint(&mut self, dtls_handshake_config: Arc<::dtls::config::HandshakeConfig>) {
        if self.dtls_role == RTCDtlsRole::Client {
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                None,
            ));
            self.dtls_handshake_config = Some(dtls_handshake_config);
        } else {
            // Clear any stale client handshake config from a previous role.
            self.dtls_handshake_config = None;
            self.dtls_endpoint = Some(::dtls::endpoint::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                Some(dtls_handshake_config),
            ));
        }
    }

    /// Whether the handshake config for the role and session at hand takes part in `use_srtp`
    /// (RFC 5764 section 4.1: "only when the data being transported is RTP or RTCP"). A client
    /// offers it when the session has a media section, or on every association when the
    /// application asked for that; a server takes a profile whenever the client offers one
    /// (section 4.1.1 leaves that to the server), which costs nothing and lets a peer that
    /// always offers it add media later without a new association.
    fn offers_use_srtp(&self) -> bool {
        self.use_srtp_always || self.srtp_required || self.dtls_role == RTCDtlsRole::Server
    }

    /// Whether the current association has, or once its handshake completes can have, SRTP
    /// keys.
    pub(crate) fn can_key_srtp(&self) -> bool {
        self.srtp_negotiated.unwrap_or(self.srtp_configured)
    }

    fn supported_srtp_protection_profiles(&self) -> Result<Vec<SrtpProtectionProfile>> {
        let configured = if self.srtp_protection_profiles.is_empty() {
            default_srtp_protection_profiles()
        } else {
            self.srtp_protection_profiles.clone()
        };
        let supported: Vec<_> = configured
            .into_iter()
            .filter(|profile| {
                srtp_profile(*profile).is_some_and(|profile| {
                    profile
                        .ensure_crypto_supported(self.crypto_provider.crypto())
                        .is_ok()
                })
            })
            .collect();
        if supported.is_empty() {
            return Err(Error::Crypto(format!(
                "crypto provider {} supports none of the configured SRTP protection profiles",
                self.crypto_provider.name()
            )));
        }
        Ok(supported)
    }

    pub(crate) fn role(&self) -> RTCDtlsRole {
        self.dtls_role
    }

    /// The negotiation that set up the transports is over (RFC 5764 section 3): an admitted
    /// first association whose role has another transport admitted takes part in the
    /// connection's session. Its handshake config is made again with the session, and the
    /// group counts it. Any other stays out of it.
    ///
    /// A client's handshake has not started by then: its config waits for the selected
    /// pair, which only a handler event brings. Nothing enforces the same for a server: a
    /// ClientHello held from before the answer is released when the transport starts
    /// (`release_early_dtls`, inside `start_transports`), which is before this call. It is
    /// released only onto an ICE path that carries media, which a transport started in the
    /// same call does not have yet; and if one were read, that handshake would run on the
    /// config made without the session (a full handshake with the section's certificate
    /// check, no ticket issued or accepted), because `set_server_config` here changes the
    /// config of associations made after it only. Safe either way.
    pub(crate) fn engage_session(&mut self) -> Result<()> {
        if !std::mem::take(&mut self.resumption_candidate)
            || self.state != RTCDtlsTransportState::Connecting
        {
            return Ok(());
        }
        let Some(group) = self.resumption.clone() else {
            return Ok(());
        };
        if !group.engages(self.dtls_role) {
            return Ok(());
        }
        let Some(remote_dtls_parameters) = self.remote_dtls_parameters.clone() else {
            return Ok(());
        };
        let config = self.make_handshake_config(&remote_dtls_parameters, true)?;
        match self.dtls_role {
            RTCDtlsRole::Client if self.dtls_handshake_config.is_some() => {
                self.dtls_handshake_config = Some(config);
            }
            RTCDtlsRole::Server => match self.dtls_endpoint.as_mut() {
                Some(endpoint) => endpoint.set_server_config(Some(config)),
                None => return Ok(()),
            },
            _ => return Ok(()),
        }
        group.join(&self.resumption_token, self.dtls_role);
        self.resumption_member = true;
        Ok(())
    }

    /// A server transport's first handshake in the connection's session is complete: its
    /// endpoint takes any later handshake (a peer re-handshaking in place, RFC 6347 section
    /// 4.2.8) without the session's ticket keys, so that it is a full one. The association
    /// that completed keeps its own config, and sends its tickets.
    pub(crate) fn leave_session_after_handshake(&mut self) -> Result<()> {
        if self.dtls_role != RTCDtlsRole::Server || !self.resumption_member {
            return Ok(());
        }
        self.resumption_member = false;
        let Some(remote_dtls_parameters) = self.remote_dtls_parameters.clone() else {
            return Ok(());
        };
        let config = self.make_handshake_config(&remote_dtls_parameters, false)?;
        if let Some(endpoint) = self.dtls_endpoint.as_mut() {
            endpoint.set_server_config(Some(config));
        }
        Ok(())
    }

    pub(crate) fn start(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        let dtls_handshake_config =
            self.prepare_transport(local_ice_role, remote_dtls_parameters)?;
        self.install_endpoint(dtls_handshake_config);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        self.state_change(RTCDtlsTransportState::Closed);
        Ok(())
    }
}

fn srtp_profile(
    profile: SrtpProtectionProfile,
) -> Option<srtp::protection_profile::ProtectionProfile> {
    use srtp::protection_profile::ProtectionProfile;
    match profile {
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => Some(ProtectionProfile::AeadAes128Gcm),
        SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => Some(ProtectionProfile::AeadAes256Gcm),
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
            Some(ProtectionProfile::Aes128CmHmacSha1_80)
        }
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => {
            Some(ProtectionProfile::Aes128CmHmacSha1_32)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Cipher-suite plumbing for issue #808.
    //!
    //! `HandshakeConfig::local_cipher_suites` is `pub(crate)` to `rtci-dtls`, so these assert
    //! the setting reached the config *behaviourally*: a list that cannot be satisfied is
    //! rejected, which can only happen if it was applied rather than ignored.

    use super::*;
    use crate::peer_connection::configuration::setting_engine::ReplayProtection;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }

    use crypto::{AeadAlgorithm, CryptoAlgorithm, HashAlgorithm, RTCCrypto, RTCRandom};

    struct MissingAes128Gcm;

    impl RTCCrypto for MissingAes128Gcm {
        fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
            algorithm != CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Gcm)
        }
    }

    struct ProfileFilteringProvider {
        random_provider: Arc<dyn RTCCryptoProvider>,
        crypto: MissingAes128Gcm,
    }

    impl RTCCryptoProvider for ProfileFilteringProvider {
        fn name(&self) -> &'static str {
            "missing-aes-128-gcm"
        }

        fn crypto(&self) -> &dyn RTCCrypto {
            &self.crypto
        }

        fn random(&self) -> &dyn RTCRandom {
            self.random_provider.random()
        }
    }

    /// RFC 3711 sections 5.2 and 9.5: the 32-bit SRTP tag is not offered by default, only
    /// when the application configures it.
    #[test]
    fn the_32_bit_srtp_tag_is_offered_only_when_configured() {
        let default = transport(vec![]);
        let offered = default
            .supported_srtp_protection_profiles()
            .expect("profiles");
        assert!(!offered.contains(&SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32));
        assert!(offered.contains(&SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80));
        let mut configured = transport(vec![]);
        configured.srtp_protection_profiles = vec![
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
        ];
        assert!(
            configured
                .supported_srtp_protection_profiles()
                .expect("profiles")
                .contains(&SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32)
        );
    }

    fn transport(dtls_cipher_suites: Vec<CipherSuiteId>) -> DtlsTransport {
        DtlsTransport::new(RTCDtlsTransportConfig {
            id: test_transport_id(TransportKind::Dtls),
            ice_transport_id: test_transport_id(TransportKind::Ice),
            certificates: vec![],
            answering_dtls_role: DEFAULT_DTLS_ROLE_ANSWER,
            srtp_protection_profiles: vec![],
            use_srtp_always: true,
            dtls_cipher_suites,
            allow_insecure_verification_algorithm: false,
            disable_certificate_fingerprint_verification: false,
            replay_protection: ReplayProtection::default(),
            crypto_provider: crypto::default_provider().expect("test crypto provider"),
        })
        .expect("a self-signed ECDSA certificate is generated when none is supplied")
    }

    fn remote_params() -> RTCDtlsParameters {
        RTCDtlsParameters {
            role: RTCDtlsRole::Client,
            fingerprints: vec![],
        }
    }

    // W3C `DtlsTransport.state`. Only the setter existed before; the field it writes was
    // never readable from outside the crate's internals.
    #[test]
    fn state_reports_what_state_change_wrote() {
        let mut transport = transport(vec![]);
        assert_eq!(RTCDtlsTransportState::New, transport.state());

        transport.state_change(RTCDtlsTransportState::Connecting);
        assert_eq!(RTCDtlsTransportState::Connecting, transport.state());

        transport.state_change(RTCDtlsTransportState::Connected);
        assert_eq!(RTCDtlsTransportState::Connected, transport.state());
    }

    // W3C `DtlsTransport.getRemoteCertificates()`. The handshake path hands the peer's DER
    // chain to `update_dtls_stats_from_profile`, which hex-encodes it into `RTCCertificateStats`
    // and keeps only a fingerprint-derived id; the bytes themselves now have somewhere to live.
    #[test]
    fn remote_certificates_are_empty_until_the_handshake_supplies_them() {
        let mut transport = transport(vec![]);
        assert!(
            transport.get_remote_certificates().is_empty(),
            "nothing has been negotiated yet"
        );

        // What the handshake path assigns.
        let peer_chain = vec![vec![0x30, 0x82, 0x01, 0x0a], vec![0x30, 0x82, 0x02, 0x0b]];
        transport.remote_certificates = peer_chain.clone();

        assert_eq!(peer_chain, transport.get_remote_certificates());
    }

    #[test]
    fn empty_cipher_suites_keeps_the_dtls_defaults() {
        // The pre-#808 behaviour, and what every existing caller gets.
        assert!(
            transport(vec![])
                .prepare_transport(RTCIceRole::Controlling, remote_params())
                .is_ok()
        );
    }

    #[test]
    fn ecdsa_only_cipher_suites_are_accepted() {
        // The fix for #808: pin the suites an ECDSA certificate can actually satisfy, so a
        // peer cannot select an ECDHE_RSA suite and stall the handshake.
        assert!(
            transport(vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
            ])
            .prepare_transport(RTCIceRole::Controlling, remote_params())
            .is_ok()
        );
    }

    #[test]
    fn unsatisfiable_cipher_suites_are_rejected_rather_than_ignored() {
        // This is the assertion that proves plumbing. PSK suites are filtered out when no
        // PSK is configured, leaving nothing usable. If `set_dtls_cipher_suites` were
        // dropped on the floor, the default set would be used and this would succeed.
        let err = transport(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm])
            .prepare_transport(RTCIceRole::Controlling, remote_params())
            .expect_err("a PSK-only list with no PSK leaves no usable suite");
        assert!(
            err.to_string().contains("CipherSuite"),
            "expected a cipher-suite error, got: {err}"
        );
    }

    #[test]
    fn filters_srtp_profiles_by_provider_capabilities() -> Result<()> {
        let default_provider = crypto::default_provider().expect("test crypto provider");
        let certificate = RTCCertificate::generate(
            default_provider.crypto(),
            crypto::SignatureScheme::EcdsaP256Sha256,
            rcgen::CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(ProfileFilteringProvider {
            random_provider: default_provider,
            crypto: MissingAes128Gcm,
        });

        let build = |profiles| {
            DtlsTransport::new(RTCDtlsTransportConfig {
                id: test_transport_id(TransportKind::Dtls),
                ice_transport_id: test_transport_id(TransportKind::Ice),
                certificates: vec![certificate.clone()],
                answering_dtls_role: DEFAULT_DTLS_ROLE_ANSWER,
                srtp_protection_profiles: profiles,
                use_srtp_always: true,
                dtls_cipher_suites: vec![],
                allow_insecure_verification_algorithm: false,
                disable_certificate_fingerprint_verification: false,
                replay_protection: ReplayProtection::default(),
                crypto_provider: provider.clone(),
            })
        };

        let error = build(vec![SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm])?
            .prepare_transport(RTCIceRole::Controlling, remote_params())
            .expect_err("the provider's unsupported profile must not be advertised");
        assert!(error.to_string().contains("supports none"));

        assert!(
            build(vec![
                SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ])?
            .prepare_transport(RTCIceRole::Controlling, remote_params())
            .is_ok()
        );
        Ok(())
    }

    /// `RTCDtlsParameters` with a dummy sha-256 fingerprint: enough to build a config (the
    /// value only matters during handshake verification). (Brainwires fork restart tests.)
    fn dummy_params(role: RTCDtlsRole) -> RTCDtlsParameters {
        RTCDtlsParameters {
            role,
            fingerprints: vec![
                crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint {
                    algorithm: "sha-256".to_owned(),
                    value: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:\
                        00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
                        .to_owned(),
                },
            ],
        }
    }

    /// A transport whose answering role is `Auto`, so `derive_role` falls through to the ICE
    /// role (the fork's restart tests were written against that configuration).
    fn auto_role_transport() -> DtlsTransport {
        let mut t = transport(vec![]);
        t.answering_dtls_role = RTCDtlsRole::Auto;
        t
    }

    // ── prepare_transport ────────────────────────────────────────────

    #[test]
    fn prepare_transport_transitions_to_connecting_after_config() {
        let mut t = auto_role_transport();
        assert_eq!(t.state, RTCDtlsTransportState::New);

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    #[test]
    fn prepare_transport_rejects_non_new_state() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Connecting);

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err());
        // State must remain unchanged on error.
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    /// RFC 8122 section 6.2: the peer connection's DTLS server ends a handshake whose client
    /// sends no certificate with bad_certificate (the DTLS option, tested in
    /// `conn_conformance_test.rs::client_without_a_certificate_for_the_requested_algorithms_sends_none`).
    #[test]
    fn the_handshake_config_ends_a_missing_client_certificate_with_bad_certificate() {
        let t = auto_role_transport();
        let config = t
            .make_handshake_config(&dummy_params(RTCDtlsRole::Auto), false)
            .unwrap();
        assert!(config.bad_certificate_for_a_missing_client_certificate());
    }

    #[test]
    fn prepare_transport_stays_new_on_config_failure() {
        let mut t = auto_role_transport();
        // Empty fingerprints → make_handshake_config succeeds but verification
        // closure is built; however, an empty params with *no* fingerprints at
        // all still builds a config (the closure checks at handshake time).
        // Instead, force a failure by removing certificates.
        t.certificates.clear();

        let result = t.prepare_transport(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "should fail without certificates");
        // State must NOT have moved to Connecting.
        assert_eq!(t.state, RTCDtlsTransportState::New);
    }

    // ── restart ──────────────────────────────────────────────────────

    #[test]
    fn restart_noop_when_new() {
        let mut t = auto_role_transport();
        assert_eq!(t.state, RTCDtlsTransportState::New);

        let result = t.restart(RTCIceRole::Controlling, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        // Must still be New — restart is a no-op in this state.
        assert_eq!(t.state, RTCDtlsTransportState::New);
        assert!(t.dtls_endpoint.is_none());
    }

    #[test]
    fn restart_from_connected_as_client() {
        let mut t = auto_role_transport();
        // Simulate a fully-connected transport.
        t.state_change(RTCDtlsTransportState::Connected);

        let result = t.restart(
            RTCIceRole::Controlled, // controlled → DTLS client
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Client);
        assert!(t.dtls_endpoint.is_some(), "endpoint must be replaced");
        assert!(
            t.dtls_handshake_config.is_some(),
            "client must store handshake config"
        );
    }

    #[test]
    fn restart_from_connected_as_server() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Connected);

        let result = t.restart(
            RTCIceRole::Controlling, // controlling → DTLS server
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        assert!(t.dtls_endpoint.is_some(), "endpoint must be replaced");
        assert!(
            t.dtls_handshake_config.is_none(),
            "server must clear stale client handshake config"
        );
    }

    #[test]
    fn restart_from_failed() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Failed);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_from_closed() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Closed);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_from_connecting() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Connecting);

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn restart_clears_stale_client_config_when_switching_to_server() {
        let mut t = auto_role_transport();
        // First start as client: a stand-in for the client config the transport makes, which
        // verifies the peer by fingerprint, not by name (`insecure_skip_verify`).
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = Some(Arc::new(
            ::dtls::config::ConfigBuilder::default()
                .with_crypto_provider(crypto::default_provider().unwrap())
                .with_insecure_skip_verify(true)
                .build(true, None)
                .unwrap(),
        ));

        // Now restart as server (remote says Client → we become Server).
        let result = t.restart(
            RTCIceRole::Controlling,
            dummy_params(RTCDtlsRole::Client), // remote=Client → local=Server
        );
        assert!(result.is_ok());
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        assert!(
            t.dtls_handshake_config.is_none(),
            "stale client config must be cleared in server branch"
        );
    }

    #[test]
    fn restart_preserves_certificates() {
        let mut t = auto_role_transport();
        let fingerprint_before: Vec<_> = t
            .certificates
            .first()
            .unwrap()
            .get_fingerprints(crypto::default_provider().unwrap().crypto())
            .unwrap()
            .iter()
            .map(|fp| fp.value.clone())
            .collect();

        t.state_change(RTCDtlsTransportState::Connected);
        t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();

        let fingerprint_after: Vec<_> = t
            .certificates
            .first()
            .unwrap()
            .get_fingerprints(crypto::default_provider().unwrap().crypto())
            .unwrap()
            .iter()
            .map(|fp| fp.value.clone())
            .collect();

        assert_eq!(
            fingerprint_before, fingerprint_after,
            "restart must NOT regenerate certificates — same identity, new handshake"
        );
    }

    #[test]
    fn restart_fails_without_certificates() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Connected);
        t.certificates.clear();

        let result = t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "restart without certs must fail");
        // State should NOT advance to Connecting on config build failure.
        assert_eq!(t.state, RTCDtlsTransportState::Connected);
    }

    // ── start ────────────────────────────────────────────────────────

    #[test]
    fn start_as_client_stores_config_and_endpoint() {
        let mut t = auto_role_transport();
        let result = t.start(
            RTCIceRole::Controlled, // controlled → client
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Client);
        assert!(t.dtls_handshake_config.is_some());
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn start_as_server_creates_endpoint_no_stored_config() {
        let mut t = auto_role_transport();
        let result = t.start(
            RTCIceRole::Controlling, // controlling → server
            dummy_params(RTCDtlsRole::Auto),
        );
        assert!(result.is_ok());
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);
        // Server passes config directly to endpoint, not stored separately.
        assert!(t.dtls_handshake_config.is_none());
        assert!(t.dtls_endpoint.is_some());
    }

    #[test]
    fn start_rejects_double_start() {
        let mut t = auto_role_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();

        let result = t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto));
        assert!(result.is_err(), "double-start must be rejected");
    }

    // ── stop ─────────────────────────────────────────────────────────

    #[test]
    fn stop_transitions_to_closed() {
        let mut t = auto_role_transport();
        t.state_change(RTCDtlsTransportState::Connected);
        t.stop().unwrap();
        assert_eq!(t.state, RTCDtlsTransportState::Closed);
    }

    // ── derive_role ──────────────────────────────────────────────────

    #[test]
    fn derive_role_from_remote_client() {
        let t = auto_role_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Client),
            RTCDtlsRole::Server
        );
    }

    #[test]
    fn derive_role_from_remote_server() {
        let t = auto_role_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Server),
            RTCDtlsRole::Client
        );
    }

    #[test]
    fn derive_role_auto_controlling_becomes_server() {
        let t = auto_role_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlling, RTCDtlsRole::Auto),
            RTCDtlsRole::Server
        );
    }

    #[test]
    fn derive_role_auto_controlled_becomes_client() {
        let t = auto_role_transport();
        assert_eq!(
            t.derive_role(RTCIceRole::Controlled, RTCDtlsRole::Auto),
            DEFAULT_DTLS_ROLE_ANSWER
        );
    }

    #[test]
    fn restart_keeps_a_connected_session_when_the_remote_is_unchanged() {
        let mut t = auto_role_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = None; // a completed client handshake has consumed it

        // An ICE restart with the same remote fingerprint and setup role.
        t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        assert_eq!(
            t.state,
            RTCDtlsTransportState::Connected,
            "the session must be kept"
        );
        assert!(
            t.dtls_handshake_config.is_none(),
            "no new handshake may be prepared"
        );
    }

    #[test]
    fn restart_rehandshakes_when_the_remote_fingerprint_changes() {
        let mut t = auto_role_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        t.state_change(RTCDtlsTransportState::Connected);

        let mut params = dummy_params(RTCDtlsRole::Auto);
        params.fingerprints[0].value = params.fingerprints[0].value.replace("00", "11");
        t.restart(RTCIceRole::Controlled, params).unwrap();
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert!(t.dtls_handshake_config.is_some());
    }

    /// After the transport was closed (every BUNDLE m-section rejected), a description that sets
    /// up a new one starts a new association even with the same fingerprint and role.
    #[test]
    fn restart_new_association_rehandshakes_an_unchanged_connected_session() {
        let mut t = auto_role_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = None; // a completed client handshake has consumed it

        t.restart_new_association(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.dtls_role, RTCDtlsRole::Client);
        assert!(
            t.dtls_handshake_config.is_some(),
            "the client must hold a config for the new handshake"
        );
        assert!(t.dtls_endpoint.is_some(), "endpoint must be replaced");
    }

    #[test]
    fn restart_rehandshakes_a_failed_session_even_when_unchanged() {
        let mut t = auto_role_transport();
        t.start(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        t.state_change(RTCDtlsTransportState::Failed);
        t.restart(RTCIceRole::Controlled, dummy_params(RTCDtlsRole::Auto))
            .unwrap();
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    // ── update_remote: RFC 8842 section 3.1 ──────────────────────────

    /// A transport connected as `role`, built for `dummy_params`' fingerprint.
    fn connected_as(role: RTCDtlsRole) -> DtlsTransport {
        let mut t = auto_role_transport();
        // The remote took the other role.
        let remote = if role == RTCDtlsRole::Client {
            RTCDtlsRole::Server
        } else {
            RTCDtlsRole::Client
        };
        t.start(RTCIceRole::Controlling, dummy_params(remote))
            .unwrap();
        assert_eq!(t.dtls_role, role);
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = None; // a completed client handshake has consumed it
        t.remote_certificates = vec![vec![0x30]];
        t.srtp_negotiated = Some(true);
        t
    }

    fn update(we_offer: bool, ice_restart: bool) -> DtlsRemoteUpdate {
        DtlsRemoteUpdate {
            we_offer,
            ice_restart,
            transport_closed: false,
        }
    }

    /// RFC 8842 section 5.3: the roles of an association are fixed. An `actpass` offer takes
    /// no role, so it changes none, whatever this endpoint's ICE role and configured
    /// answering role would give a new association: the server that answers a later offer
    /// (now ICE-controlled, default answering role client) stays the server, with or without
    /// an ICE restart.
    #[test]
    fn an_actpass_offer_keeps_the_roles_of_the_association() {
        for role in [RTCDtlsRole::Server, RTCDtlsRole::Client] {
            for ice_role in [RTCIceRole::Controlling, RTCIceRole::Controlled] {
                for ice_restart in [false, true] {
                    for answering in [RTCDtlsRole::Auto, RTCDtlsRole::Client, RTCDtlsRole::Server] {
                        let mut t = connected_as(role);
                        t.answering_dtls_role = answering;
                        let local_tls_id = t.local_tls_id.clone();
                        let kept = t
                            .update_remote(
                                ice_role,
                                dummy_params(RTCDtlsRole::Auto),
                                None,
                                update(false, ice_restart),
                            )
                            .unwrap();
                        assert_eq!(kept, DtlsAssociationUpdate::Kept);
                        assert_eq!(t.dtls_role, role);
                        assert_eq!(t.state, RTCDtlsTransportState::Connected);
                        assert_eq!(t.local_tls_id, local_tls_id);
                        assert_eq!(t.remote_certificates.len(), 1);
                        assert!(t.dtls_handshake_config.is_none());
                    }
                }
            }
        }
    }

    /// An answer (or a legacy offer) that repeats the negotiated roles keeps the association;
    /// one that takes the role this endpoint has changes the roles, which establishes a new
    /// association (RFC 8842 section 3.1), with the roles the description gives.
    #[test]
    fn an_explicit_remote_role_keeps_or_replaces_the_association() {
        for role in [RTCDtlsRole::Server, RTCDtlsRole::Client] {
            let other = if role == RTCDtlsRole::Client {
                RTCDtlsRole::Server
            } else {
                RTCDtlsRole::Client
            };
            let mut t = connected_as(role);
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlling,
                    dummy_params(other),
                    None,
                    update(true, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::Kept
            );
            assert_eq!(t.dtls_role, role);

            // The remote now takes this endpoint's role.
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlling,
                    dummy_params(role),
                    None,
                    update(true, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::New
            );
            assert_eq!(t.dtls_role, other);
            assert_eq!(t.state, RTCDtlsTransportState::Connecting);
            assert_eq!(
                t.dtls_handshake_config.is_some(),
                other == RTCDtlsRole::Client,
                "a client holds the config of the handshake it will start"
            );
            assert!(t.remote_certificates.is_empty());
            assert_eq!(t.srtp_negotiated, None);
        }
    }

    /// A changed fingerprint set establishes a new association without an ICE restart too
    /// (RFC 8842 section 3.1); the new fingerprints are the ones in force.
    #[test]
    fn a_changed_fingerprint_replaces_the_association_without_an_ice_restart() {
        let mut t = connected_as(RTCDtlsRole::Server);
        let mut params = dummy_params(RTCDtlsRole::Auto);
        params.fingerprints[0].value = params.fingerprints[0].value.replace("00", "11");
        assert_eq!(
            t.update_remote(
                RTCIceRole::Controlled,
                params.clone(),
                None,
                update(false, false)
            )
            .unwrap(),
            DtlsAssociationUpdate::New
        );
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        assert_eq!(t.remote_dtls_parameters, Some(params.clone()));
        // An `actpass` description leaves the roles as they were.
        assert_eq!(t.dtls_role, RTCDtlsRole::Server);

        // An added fingerprint is a changed set as well; hex case and order are not.
        let mut t = connected_as(RTCDtlsRole::Server);
        let mut added = dummy_params(RTCDtlsRole::Auto);
        added.fingerprints.push(params.fingerprints[0].clone());
        assert_eq!(
            t.update_remote(RTCIceRole::Controlled, added, None, update(false, false))
                .unwrap(),
            DtlsAssociationUpdate::New
        );
        let mut t = connected_as(RTCDtlsRole::Server);
        let mut same = dummy_params(RTCDtlsRole::Auto);
        same.fingerprints[0].algorithm = "SHA-256".to_owned();
        assert_eq!(
            t.update_remote(RTCIceRole::Controlled, same, None, update(false, false))
                .unwrap(),
            DtlsAssociationUpdate::Kept
        );
    }

    /// RFC 8842 sections 3.1 and 4: a changed remote `tls-id` asks for a new association; the
    /// same value, a first value from a peer that sent none, or no value does not.
    #[test]
    fn a_changed_remote_tls_id_replaces_the_association() {
        let first = Some("abc3de65cddef001be82".to_owned());
        let second = Some("abc3de65cddef001be83".to_owned());
        let apply = |t: &mut DtlsTransport, tls_id: &Option<String>| {
            t.update_remote(
                RTCIceRole::Controlled,
                dummy_params(RTCDtlsRole::Auto),
                tls_id.clone(),
                update(false, false),
            )
            .unwrap()
        };
        let mut t = connected_as(RTCDtlsRole::Server);
        assert_eq!(t.remote_tls_id, None);
        // The peer starts to send one: nothing to compare it with.
        assert_eq!(apply(&mut t, &first), DtlsAssociationUpdate::Kept);
        assert_eq!(t.remote_tls_id, first);
        assert_eq!(apply(&mut t, &first), DtlsAssociationUpdate::Kept);
        // A description without one says nothing about the association.
        assert_eq!(apply(&mut t, &None), DtlsAssociationUpdate::Kept);
        assert_eq!(t.remote_tls_id, first);
        assert_eq!(apply(&mut t, &second), DtlsAssociationUpdate::New);
        assert_eq!(t.remote_tls_id, second);
        assert_eq!(t.state, RTCDtlsTransportState::Connecting);
    }

    /// RFC 8842 sections 4 and 5.3: the local `tls-id` is 20 to 255 characters of the
    /// attribute's alphabet with at least 120 random bits; the answerer that establishes a new
    /// association takes a new one; the offerer keeps the one its offer carried, a staged one
    /// if the offer asked for the new association.
    #[test]
    fn the_local_tls_id_changes_with_the_association() {
        let mut t = connected_as(RTCDtlsRole::Server);
        let first = t.local_tls_id.clone();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, connected_as(RTCDtlsRole::Server).local_tls_id);
        assert_eq!(t.offer_tls_id(false).unwrap(), first);

        // As the answerer.
        let mut changed = dummy_params(RTCDtlsRole::Auto);
        changed.fingerprints[0].value = changed.fingerprints[0].value.replace("00", "11");
        assert_eq!(
            t.update_remote(RTCIceRole::Controlled, changed, None, update(false, false))
                .unwrap(),
            DtlsAssociationUpdate::New
        );
        let second = t.local_tls_id.clone();
        assert_ne!(second, first);
        assert_eq!(second.len(), 32);

        // As the offerer of an offer that asks for a new association: the staged value is
        // the offer's, every time it is created, and the association's once the answer starts
        // it.
        t.state_change(RTCDtlsTransportState::Connected);
        let staged = t.offer_tls_id(true).unwrap();
        assert_ne!(staged, second);
        assert_eq!(t.offer_tls_id(true).unwrap(), staged);
        assert_eq!(t.local_tls_id, second, "creating an offer changes nothing");
        assert_eq!(
            t.update_remote(
                RTCIceRole::Controlling,
                dummy_params(RTCDtlsRole::Client),
                None,
                DtlsRemoteUpdate {
                    we_offer: true,
                    ice_restart: true,
                    transport_closed: true,
                },
            )
            .unwrap(),
            DtlsAssociationUpdate::New
        );
        assert_eq!(t.local_tls_id, staged);
        assert_eq!(t.staged_local_tls_id, None);

        // As the offerer whose answer changes the association: the offer's value stays.
        t.state_change(RTCDtlsTransportState::Connected);
        let mut changed = dummy_params(RTCDtlsRole::Client);
        changed.fingerprints[0].value = changed.fingerprints[0].value.replace("00", "22");
        assert_eq!(
            t.update_remote(RTCIceRole::Controlling, changed, None, update(true, false))
                .unwrap(),
            DtlsAssociationUpdate::New
        );
        assert_eq!(t.local_tls_id, staged);
    }

    /// RFC 9429 section 5.7 ("any resources or candidates that were allocated by the
    /// abandoned local description are discarded") with RFC 8842 section 5.3 (the answer to an
    /// offer that asks for a new association carries "a new unique attribute value"): a
    /// rolled-back offer's `tls-id` is unstaged, and neither the answer to the peer's offer
    /// nor the next offer of this side carries it; a remote offer's answer `tls-id` is never
    /// an offer's, and the offer's comes back if that remote offer is rolled back.
    #[test]
    fn a_rolled_back_offer_takes_its_tls_id_back() {
        let mut t = connected_as(RTCDtlsRole::Server);
        let current = t.local_tls_id.clone();
        t.renewal_requested = true;
        let rolled_back = t.offer_tls_id(false).unwrap();
        assert_ne!(rolled_back, current);

        // The offer is rolled back: nothing of it stays staged.
        t.discard_offer_tls_id();
        assert_eq!(t.staged_local_tls_id, None);
        assert_eq!(t.local_tls_id, current, "the association's value is kept");

        // The peer's offer asks for a new association: its answer has a value of its own.
        assert!(t.stage_answer_tls_id().unwrap());
        let answered = t.staged_local_tls_id.clone().unwrap();
        assert_ne!(answered, rolled_back);
        assert_ne!(answered, current);
        t.drop_answer_tls_id();
        assert_eq!(t.staged_local_tls_id, None);

        // The renewal is still wanted: the next offer has a new value too.
        let next = t.offer_tls_id(false).unwrap();
        assert!(
            ![rolled_back.as_str(), answered.as_str(), current.as_str()].contains(&next.as_str())
        );

        // An offer created and not applied when the peer's offer arrives: the answer does not
        // take its value, and it is back once the peer's offer is rolled back.
        assert!(t.stage_answer_tls_id().unwrap());
        let answered = t.staged_local_tls_id.clone().unwrap();
        assert_ne!(answered, next);
        t.drop_answer_tls_id();
        assert_eq!(t.staged_local_tls_id.as_deref(), Some(next.as_str()));
        assert_eq!(t.offer_tls_id(false).unwrap(), next);
    }

    /// RFC 5764 section 4.1: `use_srtp` only when the association carries RTP. A client offers
    /// it for a session with a media section (or always, on request); an association set up
    /// without it is replaced when the session gains one, with the roles kept.
    #[test]
    fn use_srtp_follows_the_sessions_media() {
        // (always, media at start, role) -> configured
        for (always, media, role, configured) in [
            (false, false, RTCDtlsRole::Client, false),
            (false, true, RTCDtlsRole::Client, true),
            (true, false, RTCDtlsRole::Client, true),
            (false, false, RTCDtlsRole::Server, true),
        ] {
            let mut t = auto_role_transport();
            t.use_srtp_always = always;
            t.srtp_required = media;
            let remote = if role == RTCDtlsRole::Client {
                RTCDtlsRole::Server
            } else {
                RTCDtlsRole::Client
            };
            t.start(RTCIceRole::Controlling, dummy_params(remote))
                .unwrap();
            assert_eq!(t.srtp_configured, configured, "{always} {media} {role}");
            assert_eq!(t.can_key_srtp(), configured);
        }

        for role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            let mut t = connected_as(role);
            t.srtp_negotiated = Some(false);
            // Still no media: kept.
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlled,
                    dummy_params(RTCDtlsRole::Auto),
                    None,
                    update(false, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::Kept
            );
            // A media section arrives.
            t.srtp_required = true;
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlled,
                    dummy_params(RTCDtlsRole::Auto),
                    None,
                    update(false, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::New
            );
            assert_eq!(t.dtls_role, role, "the roles are kept");
            assert!(t.srtp_configured && t.can_key_srtp());
            // With keys, the next description keeps it.
            t.state_change(RTCDtlsTransportState::Connected);
            t.srtp_negotiated = Some(true);
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlled,
                    dummy_params(RTCDtlsRole::Auto),
                    None,
                    update(false, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::Kept
            );
        }
    }

    /// A transport that failed or was closed is not brought back by a description that
    /// changes nothing and restarts nothing; an ICE restart, or a description that asks for a
    /// new association, does.
    #[test]
    fn a_failed_association_is_replaced_only_when_asked() {
        for state in [RTCDtlsTransportState::Failed, RTCDtlsTransportState::Closed] {
            let mut t = connected_as(RTCDtlsRole::Client);
            t.state_change(state);
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlled,
                    dummy_params(RTCDtlsRole::Auto),
                    None,
                    update(false, false)
                )
                .unwrap(),
                DtlsAssociationUpdate::Kept
            );
            assert_eq!(t.state, state);
            assert_eq!(
                t.update_remote(
                    RTCIceRole::Controlled,
                    dummy_params(RTCDtlsRole::Auto),
                    None,
                    update(false, true)
                )
                .unwrap(),
                DtlsAssociationUpdate::New
            );
            assert_eq!(t.state, RTCDtlsTransportState::Connecting);
        }
    }

    /// The certificate check uses the peer's fingerprints of the most preferred hash function
    /// offered (RFC 8122 section 5.1), and the verification callback is what the handshake
    /// config carries: a handshake against a peer whose description gave only a sha-512
    /// fingerprint completes, and one whose sha-512 fingerprint is of another certificate does
    /// not.
    #[test]
    fn the_handshake_verifies_a_sha512_fingerprint() -> Result<()> {
        use ::dtls::config::ConfigBuilder;
        use ::dtls::endpoint::{Endpoint, EndpointEvent};
        use std::net::SocketAddr;

        let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
        let handshake = |fingerprint_of_presented: bool| -> Result<bool> {
            let client_certificate = ::dtls::crypto::Certificate::generate_self_signed(
                vec!["localhost".into()],
                provider.crypto(),
            )?;
            let other_certificate = ::dtls::crypto::Certificate::generate_self_signed(
                vec!["localhost".into()],
                provider.crypto(),
            )?;
            let fingerprinted = if fingerprint_of_presented {
                &client_certificate
            } else {
                &other_certificate
            };
            let hashed = provider
                .crypto()
                .hash(HashAlgorithm::Sha512, &fingerprinted.certificate[0])
                .map_err(|e| Error::Other(e.to_string()))?;
            let mut transport = transport(vec![]);
            let server_config = transport.prepare_transport(
                RTCIceRole::Controlling,
                RTCDtlsParameters {
                    role: RTCDtlsRole::Client,
                    fingerprints: vec![RTCDtlsFingerprint {
                        algorithm: "sha-512".to_owned(),
                        value: format_fingerprint(&hashed).to_uppercase(),
                    }],
                },
            )?;
            let client_config = ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![client_certificate])
                .with_srtp_protection_profiles(default_srtp_protection_profiles())
                .with_insecure_skip_verify(true)
                .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
                .build(true, None)?;

            let client_addr: SocketAddr = "127.0.0.1:45001".parse().unwrap();
            let server_addr: SocketAddr = "127.0.0.1:45002".parse().unwrap();
            let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
            let mut server =
                Endpoint::new(server_addr, TransportProtocol::UDP, Some(server_config));
            let now = std::time::Instant::now();
            client.connect(now, server_addr, Arc::new(client_config), None)?;
            let mut completed = false;
            for _ in 0..6 {
                while let Some(packet) = client.poll_transmit() {
                    if let Ok(events) =
                        server.read(now, client_addr, packet.transport.ecn, packet.message)
                    {
                        completed |= events
                            .iter()
                            .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                    }
                }
                while let Some(packet) = server.poll_transmit() {
                    let _ = client.read(now, server_addr, packet.transport.ecn, packet.message);
                }
            }
            Ok(completed)
        };
        assert!(
            handshake(true)?,
            "the certificate matches its sha-512 fingerprint"
        );
        assert!(!handshake(false)?, "another certificate's fingerprint");
        Ok(())
    }

    /// RFC 5246 section 7.3 is not used by the engine (WebRTC authenticates each association by
    /// its SDP fingerprints, RFC 8827 section 6.5): as a DTLS 1.2 client its ClientHello offers
    /// no session id and asks for no ticket (RFC 5077); as a server it gives no session id and
    /// no ticket, and a client that offers a session it holds from another server (by id and
    /// by ticket) gets a full handshake.
    #[test]
    fn the_engine_neither_offers_nor_accepts_a_dtls12_resumption() -> Result<()> {
        engine_dtls12_resumption(false)
    }

    /// The same with the connection's DTLS session on
    /// (`SettingEngineBuilder::with_dtls_session_resumption(true)`) and the transports taking
    /// part in it (two of each role): the peer connection resumes in DTLS 1.3 only, so a DTLS
    /// 1.2 handshake neither asks for, gives nor accepts a session id or ticket.
    #[test]
    fn with_the_connections_session_a_dtls12_handshake_neither_asks_for_nor_accepts_a_ticket()
    -> Result<()> {
        engine_dtls12_resumption(true)
    }

    /// `transport`, its first association started for `params` by the negotiation, beside
    /// another transport of the same role, taking part in a new connection session when
    /// `session`. Returns its handshake config.
    fn negotiated_config(
        transport: &mut DtlsTransport,
        ice_role: RTCIceRole,
        params: RTCDtlsParameters,
        session: bool,
    ) -> Result<Arc<::dtls::config::HandshakeConfig>> {
        if !session {
            return transport.prepare_transport(ice_role, params);
        }
        let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
        let group = Arc::new(resumption::DtlsSessionGroup::new(provider.as_ref())?);
        let mut sibling = super::tests::transport(vec![]);
        sibling.resumption = Some(group.clone());
        transport.resumption = Some(group.clone());
        sibling.start(ice_role, params.clone())?;
        transport.start(ice_role, params.clone())?;
        group.close_admission();
        transport.engage_session()?;
        assert!(transport.resumption_member, "it takes part");
        if transport.dtls_role == RTCDtlsRole::Client {
            Ok(transport
                .dtls_handshake_config
                .clone()
                .expect("a client config"))
        } else {
            transport.make_handshake_config(&params, true)
        }
    }

    fn engine_dtls12_resumption(session: bool) -> Result<()> {
        use ::dtls::config::{ConfigBuilder, DtlsVersion};
        use ::dtls::endpoint::{Endpoint, EndpointEvent};
        use ::dtls::session::{MemorySessionCache, MemorySessionStore, SessionCache};
        use std::net::SocketAddr;

        let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
        let client_addr: SocketAddr = "127.0.0.1:45011".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:45012".parse().unwrap();

        // The engine as the client: its first ClientHello.
        let mut transport_client = transport(vec![]);
        let engine_client = negotiated_config(
            &mut transport_client,
            RTCIceRole::Controlled,
            dummy_params(RTCDtlsRole::Server),
            session,
        )?;
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        client.connect(std::time::Instant::now(), server_addr, engine_client, None)?;
        // With a provider that has the hybrid post-quantum key share (aws-lc-rs) the
        // ClientHello is larger than one record: its fragments are put back together. Each
        // record: header (13); each fragment: handshake header (12: type, length (3),
        // message_seq (2), fragment_offset (3), fragment_length (3)) and its bytes.
        let mut hello_body: Vec<u8> = vec![];
        while let Some(transmit) = client.poll_transmit() {
            let datagram = transmit.message;
            let mut record = 0;
            while record + 13 <= datagram.len() {
                let length =
                    u16::from_be_bytes([datagram[record + 11], datagram[record + 12]]) as usize;
                let fragment = &datagram[record + 13..record + 13 + length];
                if datagram[record] == 22 && fragment[0] == 1 {
                    let total =
                        u32::from_be_bytes([0, fragment[1], fragment[2], fragment[3]]) as usize;
                    let offset =
                        u32::from_be_bytes([0, fragment[6], fragment[7], fragment[8]]) as usize;
                    let size =
                        u32::from_be_bytes([0, fragment[9], fragment[10], fragment[11]]) as usize;
                    hello_body.resize(total, 0);
                    hello_body[offset..offset + size].copy_from_slice(&fragment[12..12 + size]);
                }
                record += 13 + length;
            }
        }
        assert!(!hello_body.is_empty(), "a ClientHello");
        // Version (2), random (32).
        let body = &hello_body[..];
        let session_id_length = body[34] as usize;
        assert_eq!(session_id_length, 0, "no session id offered");
        let mut at = 35;
        at += 1 + body[at] as usize; // cookie
        at += 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize; // cipher suites
        at += 1 + body[at] as usize; // compression methods
        let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let mut extension_types = vec![];
        while at < end {
            extension_types.push(u16::from_be_bytes([body[at], body[at + 1]]));
            at += 4 + u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        }
        assert!(!extension_types.is_empty());
        assert!(
            !extension_types.contains(&35),
            "no SessionTicket extension: {extension_types:?}"
        );
        // RFC 6066 section 3: the HostName is the server's DNS name "as understood by the
        // client"; a peer connection knows none (the peer is identified by its fingerprint)
        // and sends no server_name extension, as libwebrtc's DTLS does not.
        assert!(
            !extension_types.contains(&0),
            "no server_name extension: {extension_types:?}"
        );

        // The engine as the server, against a DTLS 1.2 client that resumes where it can.
        let client_certificate = ::dtls::crypto::Certificate::generate_self_signed(
            vec!["localhost".into()],
            provider.crypto(),
        )?;
        let hashed = provider
            .crypto()
            .hash(HashAlgorithm::Sha256, &client_certificate.certificate[0])
            .map_err(|e| Error::Other(e.to_string()))?;
        let fingerprint: Vec<String> = hashed.iter().map(|b| format!("{b:02x}")).collect();
        let mut transport_server = transport(vec![]);
        let engine_server = negotiated_config(
            &mut transport_server,
            RTCIceRole::Controlling,
            RTCDtlsParameters {
                role: RTCDtlsRole::Client,
                fingerprints: vec![RTCDtlsFingerprint {
                    algorithm: "sha-256".to_owned(),
                    value: fingerprint.join(":"),
                }],
            },
            session,
        )?;
        let store = Arc::new(MemorySessionStore::new());
        let client_config = Arc::new(
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![client_certificate.clone()])
                .with_srtp_protection_profiles(default_srtp_protection_profiles())
                .with_insecure_skip_verify(true)
                .with_server_name("localhost".to_owned())
                .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
                .with_session_store(Some(store.clone()))
                .build(true, None)?,
        );
        let handshake = |server_config: Arc<::dtls::config::HandshakeConfig>| -> Result<bool> {
            let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
            let mut server =
                Endpoint::new(server_addr, TransportProtocol::UDP, Some(server_config));
            let now = std::time::Instant::now();
            client.connect(now, server_addr, client_config.clone(), None)?;
            let mut completed = false;
            for _ in 0..8 {
                while let Some(packet) = client.poll_transmit() {
                    if let Ok(events) =
                        server.read(now, client_addr, packet.transport.ecn, packet.message)
                    {
                        completed |= events
                            .iter()
                            .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                    }
                }
                while let Some(packet) = server.poll_transmit() {
                    let _ = client.read(now, server_addr, packet.transport.ecn, packet.message);
                }
            }
            assert!(completed, "the handshake completes");
            Ok(server
                .get_connection_state(client_addr)
                .is_some_and(|state| state.resumed()))
        };

        // Nothing to resume from the engine.
        assert!(!handshake(engine_server.clone())?);
        assert_eq!(store.len_dtls12("localhost"), 0, "no session id, no ticket");

        // A session from a server that keeps one, offered to the engine: a full handshake.
        let resuming_server = Arc::new(
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![client_certificate])
                .with_srtp_protection_profiles(default_srtp_protection_profiles())
                .with_insecure_skip_verify(true)
                .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
                .with_session_cache(Some(
                    Arc::new(MemorySessionCache::default()) as Arc<dyn SessionCache>
                ))
                .with_session_tickets(1)
                .build(false, None)?,
        );
        assert!(!handshake(resuming_server.clone())?);
        assert_eq!(store.len_dtls12("localhost"), 1);
        assert!(
            handshake(resuming_server.clone())?,
            "that server resumes it"
        );
        assert!(!handshake(engine_server)?, "the engine does not");
        Ok(())
    }

    /// A peer that offers only AES-256-CBC-SHA must not get a session with the default
    /// configuration: the WebRTC defaults are AEAD only.
    #[test]
    fn default_cipher_suites_do_not_negotiate_cbc() -> Result<()> {
        use ::dtls::config::ConfigBuilder;
        use ::dtls::endpoint::{Endpoint, EndpointEvent};
        use std::net::SocketAddr;

        let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
        let client_certificate = ::dtls::crypto::Certificate::generate_self_signed(
            vec!["localhost".into()],
            provider.crypto(),
        )?;
        let hashed = provider
            .crypto()
            .hash(HashAlgorithm::Sha256, &client_certificate.certificate[0])
            .map_err(|e| Error::Other(e.to_string()))?;
        let client_fingerprint: Vec<String> = hashed.iter().map(|b| format!("{b:02x}")).collect();

        // Our side: a default-configured transport, answering as the DTLS server.
        let mut transport = transport(vec![]);
        let server_config = transport.prepare_transport(
            RTCIceRole::Controlling,
            RTCDtlsParameters {
                role: RTCDtlsRole::Client,
                fingerprints: vec![RTCDtlsFingerprint {
                    algorithm: "sha-256".to_owned(),
                    value: client_fingerprint.join(":"),
                }],
            },
        )?;

        let client_config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![client_certificate])
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha])
            .with_srtp_protection_profiles(default_srtp_protection_profiles())
            .with_insecure_skip_verify(true)
            .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
            .build(true, None)?;

        let client_addr: SocketAddr = "127.0.0.1:45001".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:45002".parse().unwrap();
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        let mut server = Endpoint::new(server_addr, TransportProtocol::UDP, Some(server_config));
        let now = std::time::Instant::now();
        client.connect(now, server_addr, Arc::new(client_config), None)?;

        let mut completed = false;
        for _ in 0..6 {
            while let Some(packet) = client.poll_transmit() {
                if let Ok(events) =
                    server.read(now, client_addr, packet.transport.ecn, packet.message)
                {
                    completed |= events
                        .iter()
                        .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                }
            }
            while let Some(packet) = server.poll_transmit() {
                if let Ok(events) =
                    client.read(now, server_addr, packet.transport.ecn, packet.message)
                {
                    completed |= events
                        .iter()
                        .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                }
            }
        }
        assert!(
            !completed,
            "a CBC-only peer completed a handshake against the default WebRTC configuration"
        );
        Ok(())
    }
}

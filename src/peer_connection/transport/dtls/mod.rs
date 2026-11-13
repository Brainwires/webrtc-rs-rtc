use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
use crate::peer_connection::transport::dtls::role::{DEFAULT_DTLS_ROLE_ANSWER, RTCDtlsRole};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crypto::{HashAlgorithm, RTCCryptoProvider};
use dtls::cipher_suite::CipherSuiteId;
use dtls::config::{ClientAuthType, VerifyPeerCertificateFn};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rcgen::CertificateParams;
use rustls::pki_types::CertificateDer;
use shared::error::{Error, Result};
use shared::{TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::SystemTime;

pub(crate) mod fingerprint;
pub(crate) mod parameters;
pub(crate) mod role;
pub(crate) mod state;

/// Whether two remote fingerprint lists name the same certificates (order and hex case aside).
fn same_fingerprints(a: &[RTCDtlsFingerprint], b: &[RTCDtlsFingerprint]) -> bool {
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

pub(crate) fn default_srtp_protection_profiles() -> Vec<SrtpProtectionProfile> {
    vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
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

    // The peer's certificate chain in DER form, retained at handshake completion so
    // `get_remote_certificates()` has something to return. Previously the bytes reached
    // `update_dtls_stats_from_profile`, were hex-encoded into `RTCCertificateStats`, and then
    // dropped; only the derived fingerprint id survived, which cannot be turned back into a
    // certificate.
    pub(crate) remote_certificates: Vec<Vec<u8>>,

    // The remote DTLS parameters (fingerprints, `setup` role) the current session was built
    // for, so an ICE restart that leaves them unchanged keeps the session (Brainwires fork).
    pub(crate) remote_dtls_parameters: Option<RTCDtlsParameters>,

    // From SettingEngine
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    /// Empty means "use the `dtls` crate's default set" (see
    /// [`SettingEngineBuilder::with_dtls_cipher_suites`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_dtls_cipher_suites)).
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) replay_protection: ReplayProtection,
}

pub(crate) struct RTCDtlsTransportConfig {
    pub(crate) id: RTCTransportId,
    pub(crate) ice_transport_id: RTCTransportId,
    pub(crate) certificates: Vec<RTCCertificate>,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) replay_protection: ReplayProtection,
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
}

impl DtlsTransport {
    pub(crate) fn new(config: RTCDtlsTransportConfig) -> Result<Self> {
        let RTCDtlsTransportConfig {
            id,
            ice_transport_id,
            mut certificates,
            answering_dtls_role,
            srtp_protection_profiles,
            dtls_cipher_suites,
            allow_insecure_verification_algorithm,
            disable_certificate_fingerprint_verification,
            replay_protection,
            crypto_provider,
        } = config;
        if !certificates.is_empty() {
            let now = SystemTime::now(); // Exemption: wall-clock is correct here to check X.509 certificate expiry
            for cert in &certificates {
                cert.expires
                    .duration_since(now)
                    .map_err(|_| Error::ErrCertificateExpired)?;
            }
        } else {
            let params = CertificateParams::new(vec![shared::util::math_rand_alpha(16)])
                .map_err(|error| Error::Other(error.to_string()))?;
            let cert = RTCCertificate::generate(
                crypto_provider.crypto(),
                crypto::SignatureScheme::EcdsaP256Sha256,
                params,
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
            remote_certificates: vec![],
            remote_dtls_parameters: None,

            answering_dtls_role,
            srtp_protection_profiles,
            dtls_cipher_suites,
            allow_insecure_verification_algorithm,
            disable_certificate_fingerprint_verification,
            replay_protection,
            crypto_provider,
        })
    }

    pub(crate) fn state_change(&mut self, state: RTCDtlsTransportState) {
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
    /// initial start and [`restart`](Self::restart). (Brainwires fork; see FORK.md.)
    fn make_handshake_config(
        &self,
        remote_dtls_parameters: &RTCDtlsParameters,
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
        let verify_peer_certificate: Option<VerifyPeerCertificateFn> =
            if !self.disable_certificate_fingerprint_verification {
                let fingerprint_crypto = self.crypto_provider.clone();
                Some(Arc::new(
                    move |certs: &[Vec<u8>], _chains: &[CertificateDer<'static>]| -> Result<()> {
                        if certs.is_empty() {
                            return Err(Error::ErrNonCertificate);
                        }

                        for fp in &remote_fingerprints {
                            if fp.algorithm != "sha-256" {
                                return Err(Error::ErrUnsupportedFingerprintAlgorithm);
                            }

                            let hashed = fingerprint_crypto
                                .crypto()
                                .hash(HashAlgorithm::Sha256, &certs[0])
                                .map_err(|error| Error::Crypto(error.to_string()))?;
                            let values: Vec<String> =
                                hashed.iter().map(|x| format! {"{x:02x}"}).collect();
                            let remote_value = values.join(":").to_lowercase();

                            if remote_value == fp.value.to_lowercase() {
                                return Ok(());
                            }
                        }

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

        let profiles = self.supported_srtp_protection_profiles()?;

        Ok(Arc::new(
            ::dtls::config::ConfigBuilder::default()
                .with_crypto_provider(self.crypto_provider.clone())
                .with_certificates(vec![certificate])
                .with_srtp_protection_profiles(profiles)
                // Empty leaves `dtls`'s default set in place; a non-empty list replaces it.
                .with_cipher_suites(self.dtls_cipher_suites.clone())
                .with_client_auth(ClientAuthType::RequireAnyClientCert)
                .with_insecure_skip_verify(true)
                .with_insecure_verification(self.allow_insecure_verification_algorithm)
                .with_verify_peer_certificate(verify_peer_certificate)
                .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
                .with_replay_protection_window(self.replay_protection.dtls)
                .build(self.dtls_role == RTCDtlsRole::Client, None)?,
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
        let dtls_handshake_config = self.make_handshake_config(&remote_dtls_parameters)?;
        self.state_change(RTCDtlsTransportState::Connecting);
        self.remote_dtls_parameters = Some(remote_dtls_parameters);
        Ok(dtls_handshake_config)
    }

    /// Re-initialise the DTLS transport for re-handshake after an ICE restart, when one is needed.
    ///
    /// An ICE restart alone does not need a new DTLS session (RFC 8842 §5 / RFC 8445: DTLS is
    /// bound to the ICE transport, not to a 5-tuple), and browsers do not start one, so a
    /// `Connected` or `Connecting` session whose remote fingerprints and derived role are
    /// unchanged is kept. The session is replaced when those change (a new remote identity or
    /// `setup` role), or when it is `Failed` or `Closed`; the next
    /// `ICESelectedCandidatePairChange` event then starts a fresh handshake.
    /// No-ops if state is `New` (initial `start_transports` handles it).
    ///
    /// **Note on identity**: the local certificate and its fingerprint are *not*
    /// regenerated — the same identity is reused across ICE restarts.  Only the
    /// DTLS endpoint and handshake state are reset, which is sufficient for a new
    /// handshake over the refreshed ICE transport.
    ///
    /// Brainwires fork feature; see FORK.md.
    pub(crate) fn restart(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        if self.state == RTCDtlsTransportState::New {
            // Not started yet — initial start_transports handles this path.
            return Ok(());
        }

        let new_role = self.derive_role(local_ice_role, remote_dtls_parameters.role);
        let healthy = matches!(
            self.state,
            RTCDtlsTransportState::Connected | RTCDtlsTransportState::Connecting
        );
        let same_remote = self.remote_dtls_parameters.as_ref().is_some_and(|previous| {
            same_fingerprints(&previous.fingerprints, &remote_dtls_parameters.fingerprints)
        });
        if healthy && same_remote && new_role == self.dtls_role {
            // Nothing DTLS depends on changed: keep the session over the restarted ICE path.
            return Ok(());
        }

        // Derive the role (it may differ if the ICE role swapped during restart), but only
        // commit it once the new handshake config has been built.
        let previous_role = self.dtls_role;
        self.dtls_role = new_role;
        let dtls_handshake_config = match self.make_handshake_config(&remote_dtls_parameters) {
            Ok(config) => config,
            Err(err) => {
                self.dtls_role = previous_role;
                return Err(err);
            }
        };

        self.state_change(RTCDtlsTransportState::Connecting);
        self.install_endpoint(dtls_handshake_config);
        self.remote_dtls_parameters = Some(remote_dtls_parameters);
        Ok(())
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
    //! `HandshakeConfig::local_cipher_suites` is `pub(crate)` to `rtc-dtls`, so these assert
    //! the setting reached the config *behaviourally*: a list that cannot be satisfied is
    //! rejected, which can only happen if it was applied rather than ignored.

    use super::*;
    use crate::peer_connection::configuration::setting_engine::ReplayProtection;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }

    use crypto::{AeadAlgorithm, CryptoAlgorithm, RTCCrypto, RTCRandom};

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

    fn transport(dtls_cipher_suites: Vec<CipherSuiteId>) -> DtlsTransport {
        DtlsTransport::new(RTCDtlsTransportConfig {
            id: test_transport_id(TransportKind::Dtls),
            ice_transport_id: test_transport_id(TransportKind::Ice),
            certificates: vec![],
            answering_dtls_role: DEFAULT_DTLS_ROLE_ANSWER,
            srtp_protection_profiles: vec![],
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
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
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
            fingerprints: vec![crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:\
                        00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
                    .to_owned(),
            }],
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
        // First start as client.
        t.state_change(RTCDtlsTransportState::Connected);
        t.dtls_handshake_config = Some(Arc::new(
            ::dtls::config::ConfigBuilder::default()
                .with_crypto_provider(crypto::default_provider().unwrap())
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
        assert_eq!(t.state, RTCDtlsTransportState::Connected, "the session must be kept");
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
}

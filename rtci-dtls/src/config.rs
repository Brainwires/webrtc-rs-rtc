//! Handshake configuration.
//!
//! [`ConfigBuilder`] is what a caller supplies: certificates, the client/server role, which cipher
//! suites and curves to offer, the SRTP protection profiles to negotiate through `use_srtp`,
//! and how strictly to require the extended master secret
//! ([`ExtendedMasterSecretType`]).
//!
//! WebRTC authenticates peers by comparing the certificate fingerprint against the one
//! signalled in SDP, not against a CA chain — so certificates here are normally self-signed
//! (see [`gen_self_signed_root_cert`]) and the check is implemented by supplying a
//! [`VerifyPeerCertificateFn`].
//!
//! [`HandshakeConfig`] is the resolved form the handshake
//! actually runs with, produced by [`ConfigBuilder::build`](crate::config::ConfigBuilder::build).

#[cfg(test)]
mod config_test;

use crate::cipher_suite::*;
use crate::conn::{
    DEFAULT_MAXIMUM_RETRANSMIT_NUMBER, DEFAULT_REPLAY_PROTECTION_WINDOW, INITIAL_TICKER_INTERVAL,
    MAXIMUM_RETRANSMIT_INTERVAL, MINIMUM_MTU, MINIMUM_REPLAY_PROTECTION_WINDOW,
};
use crate::crypto::*;
use crate::curve::named_curve::NamedCurve;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::record_layer::record_layer_header::{
    PROTOCOL_VERSION1_0, PROTOCOL_VERSION1_2, ProtocolVersion,
};
use crate::signature_hash_algorithm::{
    SignatureHashAlgorithm, SignatureScheme, parse_signature_schemes,
};
use crypto::RTCCryptoProvider;
use log::warn;
use shared::error::*;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::ClientCertVerifier;

/// Explicit rustls/webpki backend used only for CA-chain and hostname verification.
///
/// This policy adapter is separate from [`RTCCryptoProvider`]. Applications authenticating with
/// SDP fingerprints do not need it, while applications enabling WebPKI validation can select its
/// backend without changing their primitive RTC provider.
#[derive(Clone)]
pub struct RustlsVerifierAdapter {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RustlsVerifierAdapter {
    /// Wraps a rustls crypto provider for WebPKI verification.
    #[must_use]
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }

    /// Uses rustls's ring verification backend.
    #[cfg(feature = "crypto-ring")]
    #[must_use]
    pub fn ring() -> Self {
        Self::new(Arc::new(rustls::crypto::ring::default_provider()))
    }

    /// Uses rustls's AWS-LC-RS verification backend.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[must_use]
    pub fn aws_lc_rs() -> Self {
        Self::new(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }
}

fn default_verifier_adapter() -> Option<RustlsVerifierAdapter> {
    #[cfg(feature = "crypto-ring")]
    {
        Some(RustlsVerifierAdapter::ring())
    }
    #[cfg(all(not(feature = "crypto-ring"), feature = "crypto-aws-lc-rs"))]
    {
        Some(RustlsVerifierAdapter::aws_lc_rs())
    }
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
    {
        None
    }
}

/// Builds the default server-certificate verifier, with an explicit provider where we have one.
///
/// # Errors
///
/// Fails if the root store holds no usable trust anchors.
fn server_cert_verifier(
    roots: std::sync::Arc<rustls::RootCertStore>,
    adapter: &RustlsVerifierAdapter,
) -> Result<std::sync::Arc<dyn ServerCertVerifier>> {
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        roots,
        adapter.provider.clone(),
    )
    .build()
    .map_err(|err| Error::Other(format!("rustls server cert verifier: {err}")))?;
    Ok(verifier)
}

/// Config is used to configure a DTLS client or server.
/// After a Config is passed to a DTLS function it must not be modified.
///
/// # Session resumption and forward secrecy
///
/// Nothing is resumed unless the application configures it: a server issues tickets with
/// [`Self::with_session_tickets`] (or shared keys, [`Self::with_session_ticket_issuer`]) and
/// keeps DTLS 1.2 sessions with [`Self::with_session_cache`]; a client keeps what it is given
/// with [`Self::with_session_store`]. Once any of these is set, **both** protocol versions
/// resume by default, and they do not cost the same:
///
/// - **DTLS 1.3** resumes with `psk_dhe_ke` (RFC 8446 section 4.2.9): the ticket's PSK is
///   combined with a new (EC)DHE exchange, so every association still has keys of its own
///   and forward secrecy is kept. (`psk_ke`, which gives that up, is a separate opt-in:
///   [`Self::with_psk_without_key_exchange`].)
/// - **DTLS 1.2** resumes with the abbreviated handshake (RFC 5246 section 7.3, RFC 5077):
///   **no key exchange is run**. The resumed association's keys come from the master secret
///   of the association the session was made in and two public randoms. So there is **no
///   forward secrecy against whatever holds that master secret**: the server's session
///   cache, the client's store, and, with tickets, the server's ticket key, because an RFC
///   5077 ticket is the master secret sealed under that key and it crosses the network in
///   the clear part of the handshake. Whoever later obtains the ticket key (it lives as long
///   as the configuration; a key is replaced every ticket lifetime and kept one lifetime
///   more) and has recorded the traffic decrypts the association that got the ticket and
///   every association resumed from it. Without resumption each DTLS 1.2 certificate
///   handshake of this crate runs its own ephemeral ECDHE exchange and has none of this.
///
/// [`Self::with_dtls12_resumption`]`(false)` keeps DTLS 1.3 resumption and takes DTLS 1.2
/// out of it; an application that turns tickets or a store on for DTLS 1.3 and does not need
/// DTLS 1.2 resumption should set it. It is `true` by default for the applications that
/// configured resumption before the switch existed. (The peer connection of the `rtci` crate
/// sets it to `false` in every configuration.)
#[derive(Clone)]
pub struct ConfigBuilder {
    crypto_provider: Option<Arc<dyn RTCCryptoProvider>>,
    certificates: Vec<Certificate>,
    cipher_suites: Vec<CipherSuiteId>,
    signature_schemes: Vec<SignatureScheme>,
    srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    use_srtp_optional: bool,
    alpn_protocols: Vec<String>,
    use_srtp_required: bool,
    client_auth: ClientAuthType,
    bad_certificate_for_a_missing_client_certificate: bool,
    extended_master_secret: ExtendedMasterSecretType,
    flight_interval: Duration,
    maximum_flight_interval: Duration,
    handshake_timeout: Option<Duration>,
    cookie_exchange: bool,
    hello_verify_request_version: ProtocolVersion,
    early_data_retransmit: bool,
    min_version: DtlsVersion,
    max_version: DtlsVersion,
    connection_id: Option<usize>,
    connection_id_migration: bool,
    invalid_record_limit: Option<u64>,
    post_quantum_key_share: bool,
    psk: Option<PskCallback>,
    psk_identity_hint: Option<Vec<u8>>,
    session_tickets: u8,
    session_ticket_issuer: Option<crate::session::SessionTicketIssuer>,
    session_ticket_lifetime: Duration,
    session_store: Option<Arc<dyn crate::session::SessionStore>>,
    session_cache: Option<Arc<dyn crate::session::SessionCache>>,
    dtls12_resumption: bool,
    external_psks: Vec<crate::session::ExternalPsk>,
    psk_without_key_exchange: bool,
    post_handshake_auth: bool,
    max_early_data: u32,
    insecure_skip_verify: bool,
    insecure_hashes: bool,
    insecure_verification: bool,
    verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    roots_cas: rustls::RootCertStore,
    client_cas: rustls::RootCertStore,
    verifier_adapter: Option<RustlsVerifierAdapter>,
    /// A client's verifier of the server's chain and name, used instead of `roots_cas`.
    server_cert_verifier: Option<Arc<dyn ServerCertVerifier>>,
    server_name: String,
    mtu: usize,
    replay_protection_window: usize,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            crypto_provider: None,
            certificates: vec![],
            cipher_suites: vec![],
            signature_schemes: vec![],
            srtp_protection_profiles: vec![],
            use_srtp_optional: false,
            alpn_protocols: vec![],
            use_srtp_required: false,
            client_auth: ClientAuthType::default(),
            bad_certificate_for_a_missing_client_certificate: false,
            extended_master_secret: ExtendedMasterSecretType::default(),
            flight_interval: Duration::default(),
            maximum_flight_interval: MAXIMUM_RETRANSMIT_INTERVAL,
            handshake_timeout: None,
            cookie_exchange: true,
            hello_verify_request_version: PROTOCOL_VERSION1_0,
            early_data_retransmit: true,
            min_version: DtlsVersion::Dtls1_2,
            max_version: DtlsVersion::Dtls1_3,
            connection_id: Some(0),
            connection_id_migration: false,
            invalid_record_limit: None,
            post_quantum_key_share: true,
            psk: None,
            psk_identity_hint: None,
            session_tickets: 0,
            session_ticket_issuer: None,
            session_ticket_lifetime: crate::dtls13::psk::DEFAULT_TICKET_LIFETIME,
            session_store: None,
            session_cache: None,
            dtls12_resumption: true,
            external_psks: vec![],
            psk_without_key_exchange: false,
            post_handshake_auth: false,
            max_early_data: 0,
            insecure_skip_verify: false,
            insecure_hashes: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            roots_cas: rustls::RootCertStore::empty(),
            client_cas: rustls::RootCertStore::empty(),
            verifier_adapter: default_verifier_adapter(),
            server_cert_verifier: None,
            server_name: String::default(),
            mtu: 0,
            replay_protection_window: 0,
        }
    }
}

impl ConfigBuilder {
    /// Selects the cryptography and CSPRNG implementation for this DTLS association.
    ///
    /// The provider is resolved while building the handshake configuration and is reused for the
    /// entire handshake and record lifetime. No global registration is required.
    pub fn with_crypto_provider(mut self, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// certificates contains certificate chain to present to the other side of the connection.
    /// Server MUST set this if psk is nil, and MAY set it alongside a psk to serve both families
    /// Client SHOULD set this so CertificateRequests can be handled, and MUST NOT set it with a psk
    pub fn with_certificates(mut self, certificates: Vec<Certificate>) -> Self {
        self.certificates = certificates;
        self
    }

    /// cipher_suites is a list of supported cipher suites.
    /// If cipher_suites is nil, a default list is used
    ///
    /// The list is exact, and with it the versions: the TLS 1.3 suites in it
    /// (`Tls_Aes_128_Gcm_Sha256` and the others of that family) are what DTLS 1.3 is
    /// negotiated with, the rest what DTLS 1.2 is. A list without a TLS 1.3 suite therefore
    /// negotiates DTLS 1.2 only, and one with nothing else DTLS 1.3 only. The default list
    /// has both.
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<CipherSuiteId>) -> Self {
        self.cipher_suites = cipher_suites;
        self
    }

    /// signature_schemes contains the signature and hash schemes that the peer requests to verify.
    pub fn with_signature_schemes(mut self, signature_schemes: Vec<SignatureScheme>) -> Self {
        self.signature_schemes = signature_schemes;
        self
    }

    /// srtp_protection_profiles are the supported protection profiles
    /// Clients will send this via use_srtp and assert that the server properly responds
    /// Servers will assert that clients send one of these profiles and will respond as needed
    pub fn with_srtp_protection_profiles(
        mut self,
        srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    ) -> Self {
        self.srtp_protection_profiles = srtp_protection_profiles;
        self
    }

    /// Lets a client that offers `use_srtp` go on when the server's ServerHello carries no
    /// `use_srtp` extension (RFC 5764 section 4.1.1: a server that does not take the extension
    /// leaves it out). The association then has no SRTP profile
    /// ([`SrtpProtectionProfile::Unsupported`]) and carries DTLS application data only: the
    /// caller decides whether that is enough. `false` (the default) aborts such a handshake with
    /// a fatal alert.
    pub fn with_use_srtp_optional(mut self, use_srtp_optional: bool) -> Self {
        self.use_srtp_optional = use_srtp_optional;
        self
    }

    /// The application protocols of Application-Layer Protocol Negotiation (RFC 7301), most
    /// preferred first; empty (the default) uses no ALPN. A client offers them in its
    /// ClientHello and takes the one the server selects, which must be one of them; a server
    /// selects the first of its own that the client offered, refuses a client that offered
    /// ALPN but none of them (`no_application_protocol`), and answers a client without the
    /// extension without it. DTLS 1.2 (ServerHello) and DTLS 1.3 (EncryptedExtensions).
    /// [`State::application_protocol`](crate::state::State::application_protocol) gives the
    /// result. Each name is 1 to 255 bytes.
    pub fn with_alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Makes a server refuse a client whose `use_srtp` shares no profile with it, with a fatal
    /// insufficient_security alert. RFC 5764 section 4.1.1: with no shared profile "the server
    /// SHOULD NOT return the use_srtp extension at which point the connection falls back to
    /// the negotiated DTLS cipher suite. If that is not acceptable, the server SHOULD return
    /// an appropriate DTLS alert". `false` (the default) falls back; set `true` when the
    /// association is of no use without SRTP.
    pub fn with_use_srtp_required(mut self, use_srtp_required: bool) -> Self {
        self.use_srtp_required = use_srtp_required;
        self
    }

    /// client_auth determines the server's policy for
    /// TLS Client Authentication. The default is NoClientCert.
    pub fn with_client_auth(mut self, client_auth: ClientAuthType) -> Self {
        self.client_auth = client_auth;
        self
    }

    /// The alert a server that requires a client certificate
    /// ([`ClientAuthType::RequireAnyClientCert`], [`ClientAuthType::RequireAndVerifyClientCert`])
    /// ends the handshake with when the client sends none. `false` (the default):
    /// `handshake_failure` (RFC 5246 section 7.4.6), `certificate_required` under DTLS 1.3 (RFC
    /// 8446 section 4.4.2.4). `true`: `bad_certificate`, which RFC 8122 section 6.2 requires of
    /// an endpoint of the SDP offer/answer model ("if the client does not provide one ... the
    /// server endpoint MUST terminate the media connection with a bad_certificate error");
    /// the WebRTC peer connection sets it.
    pub fn with_bad_certificate_for_a_missing_client_certificate(mut self, bad: bool) -> Self {
        self.bad_certificate_for_a_missing_client_certificate = bad;
        self
    }

    /// extended_master_secret determines if the "Extended Master Secret" extension
    /// should be disabled, requested, or required (default requested).
    pub fn with_extended_master_secret(
        mut self,
        extended_master_secret: ExtendedMasterSecretType,
    ) -> Self {
        self.extended_master_secret = extended_master_secret;
        self
    }

    /// The initial value of the handshake retransmission timer: how long a flight waits for
    /// its answer before it is sent again. The timer doubles at each retransmission, up to
    /// [`Self::with_maximum_flight_interval`], and keeps its value until a flight is answered
    /// without loss (RFC 6347 4.2.4.1). Defaults to one second.
    pub fn with_flight_interval(mut self, flight_interval: Duration) -> Self {
        self.flight_interval = flight_interval;
        self
    }

    /// The value the handshake retransmission timer doubles up to. Defaults to 60 seconds, the
    /// least RFC 6347 4.2.4.1 allows as a maximum; a value below the initial interval is
    /// raised to it.
    pub fn with_maximum_flight_interval(mut self, maximum_flight_interval: Duration) -> Self {
        self.maximum_flight_interval = maximum_flight_interval;
        self
    }

    /// How long a handshake may take, from the first flight sent or received, before the
    /// association fails with `ErrHandshakeTimeout`. `None`, the default, never gives up:
    /// the flight is retransmitted, at the timer that doubles up to
    /// [`Self::with_maximum_flight_interval`], for as long as the association exists.
    ///
    /// RFC 6347 section 4.2.4 and RFC 9147 section 5.8 define the retransmission timer and
    /// set no total limit, so by default none is set here either: what ends a handshake is
    /// the transport under it (in a peer connection, ICE: consent expiry or the failure of
    /// every candidate pair, RFC 7675), a fatal alert, or the application closing the
    /// association. An application that runs DTLS over a transport that cannot tell it that
    /// the peer is gone sets a limit here. A server endpoint drops an association it made
    /// for an address the client has not verified after a fixed time whatever this says
    /// (the cookie exchange of a fragmented DTLS 1.3 ClientHello).
    pub fn with_handshake_timeout(mut self, handshake_timeout: Option<Duration>) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// Whether a server [`Endpoint`](crate::endpoint::Endpoint) answers a ClientHello that
    /// carries no valid cookie with a HelloVerifyRequest (RFC 6347 4.2.1). On by default, as
    /// the RFC asks: until a client echoes the cookie the server keeps no state for it and
    /// sends it nothing larger than what it received.
    ///
    /// Off, the first ClientHello gets an association and the server's whole first flight. That
    /// saves a round trip where something else has already shown that the client receives at
    /// its address (ICE connectivity checks do, for WebRTC), and makes the server an
    /// amplifier and a holder of state for spoofed addresses where nothing has.
    pub fn with_cookie_exchange(mut self, cookie_exchange: bool) -> Self {
        self.cookie_exchange = cookie_exchange;
        self
    }

    /// The server_version a server writes into its HelloVerifyRequest. The default is DTLS 1.0
    /// ([`PROTOCOL_VERSION1_0`]): RFC 6347 4.2.1 says a server should use it there whatever
    /// version it goes on to negotiate, so that a client of any version takes the message.
    /// [`PROTOCOL_VERSION1_2`] writes the version the ServerHello will carry instead, which is
    /// what this stack sent before and what some stacks do. A client is required to ignore the
    /// field, and this one does, so the setting changes nothing but that field.
    ///
    /// [`Self::build`] refuses any other version.
    pub fn with_hello_verify_request_version(mut self, version: ProtocolVersion) -> Self {
        self.hello_verify_request_version = version;
        self
    }

    /// Whether a client that receives protected application data while it still waits for the
    /// server's Finished sends its final flight again at once, instead of when its timer fires
    /// (RFC 6347 4.2.4, a MAY: such data means the server has its keys and its Finished was
    /// lost or is late). On by default. Only a record that authenticates under the negotiated
    /// keys counts, and a flight is sent again for this reason once at most.
    pub fn with_early_data_retransmit(mut self, early_data_retransmit: bool) -> Self {
        self.early_data_retransmit = early_data_retransmit;
        self
    }

    /// The DTLS versions to negotiate: the lowest and the highest, both included. The default
    /// is DTLS 1.2 to DTLS 1.3, with 1.3 preferred: a client offers both in
    /// `supported_versions`, a server takes 1.3 from a client that offers it and 1.2 from one
    /// that does not (RFC 9147 section 5.3, RFC 8446 section 4.2.1), and each end checks the
    /// downgrade sentinel of RFC 8446 section 4.1.3.
    ///
    /// DTLS 1.3 authenticates with certificates here; a configuration with a pre-shared key
    /// negotiates DTLS 1.2 (its PSK cipher suites), and [`Self::build`] refuses one that asks
    /// for DTLS 1.3 as the minimum. It also refuses a minimum above the maximum.
    pub fn with_protocol_versions(mut self, min: DtlsVersion, max: DtlsVersion) -> Self {
        self.min_version = min;
        self.max_version = max;
        self
    }

    /// Whether, and how, this side uses connection ids (RFC 9147 section 9, on RFC 9146's
    /// `connection_id` extension): `Some(n)` sends the extension and asks the peer to put a
    /// connection id of `n` random bytes in every protected record it sends, `Some(0)` sends
    /// it and asks for none (the peer may still ask for one in the other direction), `None`
    /// does not use the extension. Negotiated when both sides send it. The default is
    /// `Some(0)`, as RFC 9147 section 5.1 asks of a client that wants no connection id.
    ///
    /// Both versions: DTLS 1.2 uses RFC 9146 (`tls12_cid` records), DTLS 1.3 its own record
    /// header. A ClientHello that offers both carries the extension once, for both (RFC 9147
    /// section 5.1).
    pub fn with_connection_id(mut self, length: Option<usize>) -> Self {
        self.connection_id = length;
        self
    }

    /// Whether a server [`Endpoint`](crate::endpoint::Endpoint) follows an association to a
    /// new address when a record under one of its connection ids arrives from there, is
    /// authentic and is newer than any before it (RFC 9146 section 6). Off by default: the
    /// RFC also requires a strategy that shows the new address receives, and none is run
    /// here. An application that has one (ICE has: consent and connectivity checks on the
    /// new pair) turns this on; under ICE the engine addresses an association by the
    /// selected pair anyway.
    pub fn with_connection_id_migration(mut self, migration: bool) -> Self {
        self.connection_id_migration = migration;
        self
    }

    /// Whether DTLS 1.3 offers and accepts the hybrid post-quantum group X25519MLKEM768
    /// (draft-ietf-tls-ecdhe-mlkem, code point 0x11EC), preferred over the curves. On by
    /// default; it takes effect only with a crypto provider that has ML-KEM (the built-in
    /// aws-lc-rs one; ring has none). Its key share is 1216 bytes, so a ClientHello that
    /// carries it does not fit one datagram and is sent as two fragments.
    pub fn with_post_quantum_key_share(mut self, post_quantum_key_share: bool) -> Self {
        self.post_quantum_key_share = post_quantum_key_share;
        self
    }

    /// How many invalid records (malformed, or failing authentication) an association takes
    /// before it gives its peer up as persistently misbehaving and fails, without an alert
    /// (RFC 9147 section 5.10 for DTLS 1.3; RFC 6347 section 4.2.7 for DTLS 1.2, which counts
    /// the protected records that fail authentication). `None`, the default, never does: over UDP
    /// anyone who knows the addresses can send such records, and a limit lets them end the
    /// association. A limit suits a transport where only the peer can send (under ICE, a
    /// selected pair with consent checks narrows it to on-path senders).
    pub fn with_invalid_record_limit(mut self, limit: Option<u64>) -> Self {
        self.invalid_record_limit = limit;
        self
    }

    /// Server: how many tickets (NewSessionTicket messages, RFC 8446 section 4.6.1) a DTLS 1.3
    /// server sends after each handshake, for the client to resume with. 0, the default, sends
    /// none and accepts none. Tickets are sealed under a key the configuration makes at
    /// random when it is built, and each is accepted once: see [`crate::session`].
    ///
    /// Any count above 0 also makes a DTLS 1.2 server issue and accept RFC 5077 session
    /// tickets, one per handshake to a client that asks for one, for sessions made with the
    /// extended master secret. That costs forward secrecy, which DTLS 1.3 tickets do not: a
    /// DTLS 1.2 ticket is the association's master secret sealed under this server's ticket
    /// key and sent in the clear part of the handshake, and a resumed DTLS 1.2 association
    /// runs no key exchange, so whoever later obtains the ticket key decrypts the recorded
    /// association the ticket came from and every one resumed from it (see
    /// [the type's notes](Self#session-resumption-and-forward-secrecy)).
    /// [`Self::with_dtls12_resumption`]`(false)` issues DTLS 1.3 tickets only.
    ///
    /// A server that also has a [peer-certificate check](Self::with_verify_peer_certificate)
    /// runs it again on the client certificates a ticket carries. A ticket that carries none
    /// is resumed only when the server asks its clients for no certificate
    /// ([`ClientAuthType::NoClientCert`]: the first handshake had none to check either); a
    /// server that asks for one runs a full handshake instead, and asks again.
    pub fn with_session_tickets(mut self, count: u8) -> Self {
        self.session_tickets = count;
        self
    }

    /// Server: the keys to seal and open tickets with, shared with other configurations: a
    /// ticket one of them issued is accepted (once) by any other. It takes the place of
    /// [`Self::with_session_tickets`] and [`Self::with_session_ticket_lifetime`], whose count
    /// and lifetime are the issuer's own. `None`, the default, has the configuration make keys
    /// of its own when tickets are on. A client ignores it.
    pub fn with_session_ticket_issuer(
        mut self,
        issuer: Option<crate::session::SessionTicketIssuer>,
    ) -> Self {
        self.session_ticket_issuer = issuer;
        self
    }

    /// Server: how long a ticket it issues may be used for (`ticket_lifetime`), and how long a
    /// DTLS 1.2 session it keeps in its session cache may be resumed. Two hours by default; at
    /// most seven days (RFC 8446 section 4.6.1).
    pub fn with_session_ticket_lifetime(mut self, lifetime: Duration) -> Self {
        self.session_ticket_lifetime = lifetime;
        self
    }

    /// Client: where to keep the tickets servers send, and take one from for the next
    /// handshake with the same server name. Without a store (the default) a client offers no
    /// PSK and drops the tickets it is sent.
    ///
    /// A DTLS 1.2 client keeps its sessions there too (RFC 5246 section 7.3: by session id,
    /// or RFC 5077: by ticket, and it asks for a ticket in every ClientHello), when they were
    /// made with the extended master secret (RFC 7627 section 5.3), and offers the most recent
    /// one again. A resumed DTLS 1.2 association runs no key exchange: its keys come from
    /// the stored master secret, so what is in the store (and, for a ticket, the server's
    /// ticket key) opens every association of that session, recorded ones included (see
    /// [the type's notes](Self#session-resumption-and-forward-secrecy)).
    /// [`Self::with_dtls12_resumption`]`(false)` keeps DTLS 1.3 tickets only.
    pub fn with_session_store(
        mut self,
        store: Option<Arc<dyn crate::session::SessionStore>>,
    ) -> Self {
        self.session_store = store;
        self
    }

    /// DTLS 1.2 server: where to keep the sessions it may resume by session id (RFC 5246
    /// sections 7.3 and 7.4.1.3). With one, each full handshake that used the extended master
    /// secret makes a session with a new 32-byte session id, valid for
    /// [`Self::with_session_ticket_lifetime`]; a ClientHello that offers it gets the
    /// abbreviated handshake. `None`, the default, gives no session id and resumes by
    /// session id nothing. The cache holds master secrets, and a resumed association runs no
    /// key exchange: there is no forward secrecy against the cache's contents for the
    /// associations of a cached session (see
    /// [the type's notes](Self#session-resumption-and-forward-secrecy)).
    pub fn with_session_cache(
        mut self,
        cache: Option<Arc<dyn crate::session::SessionCache>>,
    ) -> Self {
        self.session_cache = cache;
        self
    }

    /// Whether DTLS 1.2 associations resume sessions at all (RFC 5246 section 7.3 by session
    /// id, RFC 5077 by ticket). `true`, the default, has a client with a
    /// [session store](Self::with_session_store) ask for a ticket and offer its sessions, and
    /// a server with a [session cache](Self::with_session_cache) or
    /// [tickets](Self::with_session_tickets) give session ids and tickets and resume them.
    /// `false` leaves DTLS 1.3 resumption as configured and takes DTLS 1.2 out of it: a
    /// client asks for no ticket, offers no session id or ticket and keeps no DTLS 1.2
    /// session; a server gives no session id, issues no ticket and resumes nothing, so every
    /// DTLS 1.2 handshake is a full one with its own (EC)DHE exchange.
    ///
    /// What `true` costs, once tickets, a cache or a store are configured: a resumed DTLS
    /// 1.2 association runs no key exchange, and a DTLS 1.2 ticket is the master secret of
    /// the association it came from, sealed under the server's ticket key and sent in the
    /// clear part of the handshake. There is then no forward secrecy against the ticket key,
    /// the session cache or the client's store: any of them, obtained later, decrypts the
    /// recorded associations of the session. DTLS 1.3 resumption (`psk_dhe_ke`) has no such
    /// cost. The default is `true` only so that configurations made before this switch
    /// existed behave as they did; set `false` unless DTLS 1.2 resumption is wanted (see
    /// [the type's notes](Self#session-resumption-and-forward-secrecy)).
    pub fn with_dtls12_resumption(mut self, resumption: bool) -> Self {
        self.dtls12_resumption = resumption;
        self
    }

    /// DTLS 1.3: external pre-shared keys (RFC 8446 section 2.2). A client offers each of
    /// them; a server accepts one whose identity it has in place of a certificate exchange.
    /// The DTLS 1.2 PSK suites are configured with [`Self::with_psk`] instead.
    ///
    /// An external PSK authenticates both sides by possession of the key (RFC 8446 sections
    /// 2.2 and 4.2.11): no certificate is sent in either direction, the association reports
    /// no peer certificates, and a [peer-certificate check](Self::with_verify_peer_certificate)
    /// is **not called** for that handshake, on a client or on a server, whatever the
    /// server's [`Self::with_client_auth`] says. A configuration may have both: the check
    /// then covers the handshakes that carry certificates (and resumptions of them), and the
    /// PSK the ones made with it. An application that identifies its peer by certificate
    /// alone must not configure an external PSK for that peer.
    pub fn with_external_psks(mut self, psks: Vec<crate::session::ExternalPsk>) -> Self {
        self.external_psks = psks;
        self
    }

    /// DTLS 1.3: whether a PSK may also be used alone, without an (EC)DHE exchange (the
    /// `psk_ke` mode of RFC 8446 section 4.2.9). Off by default: `psk_dhe_ke` only, which
    /// keeps forward secrecy (RFC 8446 section E.1).
    pub fn with_psk_without_key_exchange(mut self, allowed: bool) -> Self {
        self.psk_without_key_exchange = allowed;
        self
    }

    /// DTLS 1.3 client: offer post-handshake authentication (the `post_handshake_auth`
    /// extension, RFC 8446 section 4.2.6), so that the server may ask for this client's
    /// certificate at any time after the handshake ([`DTLSConn::request_client_certificate`](crate::conn::DTLSConn::request_client_certificate)).
    /// It is answered at once, with the configured certificate if the request allows it and
    /// with an empty Certificate otherwise. Off by default.
    pub fn with_post_handshake_auth(mut self, offer: bool) -> Self {
        self.post_handshake_auth = offer;
        self
    }

    /// DTLS 1.3 server: take up to `size` bytes of 0-RTT data (RFC 8446 section 4.2.10)
    /// with the tickets it issues ([`Self::with_session_tickets`]). 0, the default, takes
    /// none. 0-RTT data can be replayed by anyone who saw it: each ticket is accepted once
    /// (RFC 8446 section 8.1), and the ticket's age has to agree with the server's within ten
    /// seconds (section 8.3), but the application decides what is safe to do before the
    /// handshake is complete ([`EndpointEvent::EarlyData`](crate::endpoint::EndpointEvent::EarlyData)).
    /// A ClientHello answered with a HelloRetryRequest has no 0-RTT, so this takes effect
    /// only with the cookie exchange off ([`Self::with_cookie_exchange`]).
    pub fn with_max_early_data(mut self, size: u32) -> Self {
        self.max_early_data = size;
        self
    }

    /// psk sets the pre-shared key used by this DTLS connection
    /// A client with a psk offers only psk cipher_suites; a server that also holds certificates
    /// offers both families and lets the negotiated suite decide which credential it uses
    pub fn with_psk(mut self, psk: Option<PskCallback>) -> Self {
        self.psk = psk;
        self
    }

    /// psk_identity_hint sets the pre-shared key hint
    pub fn with_psk_identity_hint(mut self, psk_identity_hint: Option<Vec<u8>>) -> Self {
        self.psk_identity_hint = psk_identity_hint;
        self
    }

    /// insecure_skip_verify controls whether a client verifies the
    /// server's certificate chain and host name.
    /// If insecure_skip_verify is true, TLS accepts any certificate
    /// presented by the server and any host name in that certificate.
    /// In this mode, TLS is susceptible to man-in-the-middle attacks.
    /// This should be used only for testing.
    pub fn with_insecure_skip_verify(mut self, insecure_skip_verify: bool) -> Self {
        self.insecure_skip_verify = insecure_skip_verify;
        self
    }

    /// insecure_hashes allows the use of hashing algorithms that are known
    /// to be vulnerable.
    pub fn with_insecure_hashes(mut self, insecure_hashes: bool) -> Self {
        self.insecure_hashes = insecure_hashes;
        self
    }

    /// insecure_verification allows the use of verification algorithms that are
    /// known to be vulnerable or deprecated
    pub fn with_insecure_verification(mut self, insecure_verification: bool) -> Self {
        self.insecure_verification = insecure_verification;
        self
    }

    /// VerifyPeerCertificate, if not nil, is called after normal
    /// certificate verification by either a client or server. It
    /// receives the certificate provided by the peer and also a flag
    /// that tells if normal verification has succeeded. If it returns a
    /// non-nil error, the handshake is aborted and that error results.
    ///
    /// If normal verification fails then the handshake will abort before
    /// considering this callback. If normal verification is disabled by
    /// setting insecure_skip_verify, or (for a server) when client_auth is
    /// RequestClientCert or RequireAnyClientCert, then this callback will
    /// be considered but the verifiedChains will always be nil.
    ///
    /// What it covers. The check is called with the certificates the peer presents in a
    /// handshake, and it is called only when there are certificates:
    ///
    /// - A full handshake: on the server's chain (a client), on the client's chain (a
    ///   server). A server is not called for a client that sends no certificate: one it
    ///   never asks ([`ClientAuthType::NoClientCert`]) or one that answers a request with
    ///   none where that is allowed (`RequestClientCert`, `VerifyClientCertIfGiven`).
    /// - A resumption (a DTLS 1.3 ticket, a DTLS 1.2 session id or ticket): no certificate
    ///   is sent, and the check runs again on the certificates stored with the ticket or
    ///   session, those of the handshake that made it (with no verified chains). It fails
    ///   closed where a certificate should be there: a client fails a resumption whose
    ///   ticket or session carries none (`bad_certificate`), and a server that asks its
    ///   clients for a certificate resumes no ticket or session without one (a full
    ///   handshake runs instead). A server that asks for none resumes, without the check:
    ///   the first handshake had no client certificate either.
    /// - An external PSK handshake ([`Self::with_external_psks`], RFC 8446 sections 2.2 and
    ///   4.2.11): **not called**. No certificate exists; the peer is authenticated by
    ///   possession of the key, and by nothing this check sees.
    pub fn with_verify_peer_certificate(
        mut self,
        verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    ) -> Self {
        self.verify_peer_certificate = verify_peer_certificate;
        self
    }

    /// roots_cas defines the set of root certificate authorities
    /// that one peer uses when verifying the other peer's certificates.
    /// If RootCAs is nil, TLS uses the host's root CA set.
    /// Used by Client to verify server's certificate
    pub fn with_roots_cas(mut self, roots_cas: rustls::RootCertStore) -> Self {
        self.roots_cas = roots_cas;
        self
    }

    /// client_cas defines the set of root certificate authorities
    /// that servers use if required to verify a client certificate
    /// by the policy in client_auth.
    /// Used by Server to verify client's certificate
    pub fn with_client_cas(mut self, client_cas: rustls::RootCertStore) -> Self {
        self.client_cas = client_cas;
        self
    }

    /// Selects the rustls/webpki adapter used for optional CA-chain and hostname verification.
    pub fn with_rustls_verifier_adapter(mut self, adapter: RustlsVerifierAdapter) -> Self {
        self.verifier_adapter = Some(adapter);
        self
    }

    /// A client verifies the server's certificate chain and name with `verifier` (a rustls
    /// [`ServerCertVerifier`] of the application's) instead of the roots of
    /// [`Self::with_roots_cas`]. As with the roots, the handshake's CertificateVerify is still
    /// checked by the DTLS layer itself; `insecure_skip_verify` skips this verifier too.
    pub fn with_server_cert_verifier(mut self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
        self.server_cert_verifier = Some(verifier);
        self
    }

    /// server_name is used to verify the hostname on the returned
    /// certificates unless insecure_skip_verify is given, and a client sends it as SNI
    /// (RFC 6066 section 3) unless it is an IP address.
    ///
    /// A client with no server name takes the remote address `build` is given. With neither,
    /// a client that verifies nothing by name (`with_insecure_skip_verify(true)` or a PSK)
    /// sends no server_name extension (in 0.2.0 it sent "localhost"); for one that verifies
    /// the certificate by name `build` returns an error, as there is no name to verify against
    /// (in 0.2.0 it verified against "localhost", with a warning). A WebRTC peer connection
    /// verifies the certificate by its fingerprint in the session description (RFC 8122,
    /// RFC 8827) and sends none.
    pub fn with_server_name(mut self, server_name: String) -> Self {
        self.server_name = server_name;
        self
    }

    /// mtu is the length at which handshake messages will be fragmented to
    /// fit within the maximum transmission unit (default is 1200 bytes)
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// replay_protection_window is the size of the replay attack protection window.
    /// Duplication of the sequence number is checked in this window size.
    /// Packet with sequence number older than this value compared to the latest
    /// accepted packet will be discarded. (default is 64)
    ///
    /// RFC 6347 4.1.2.6 requires a window of at least 32: a smaller value is raised to 32.
    pub fn with_replay_protection_window(mut self, replay_protection_window: usize) -> Self {
        self.replay_protection_window = replay_protection_window;
        self
    }
}

pub(crate) const DEFAULT_MTU: usize = 1200; // bytes

/// A version of DTLS this crate negotiates.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DtlsVersion {
    /// DTLS 1.2 (RFC 6347), `{254, 253}` on the wire.
    Dtls1_2,
    /// DTLS 1.3 (RFC 9147), `{254, 252}` on the wire.
    Dtls1_3,
}

impl DtlsVersion {
    /// The version as a [`ProtocolVersion`]: what `supported_versions` carries, and the two
    /// bytes webrtc-stats' `tlsVersion` is the hex of (`FEFD`, `FEFC`).
    pub fn protocol_version(self) -> ProtocolVersion {
        match self {
            DtlsVersion::Dtls1_2 => PROTOCOL_VERSION1_2,
            DtlsVersion::Dtls1_3 => ProtocolVersion {
                major: 254,
                minor: 252,
            },
        }
    }
}

/// PSKCallback is called once we have the remote's psk_identity_hint.
/// If the remote provided none it will be nil
pub(crate) type PskCallback = Arc<dyn (Fn(&[u8]) -> Result<Vec<u8>>) + Send + Sync>;

/// ClientAuthType declares the policy the server will follow for
/// TLS Client Authentication.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientAuthType {
    #[default]
    /// `NO_CLIENT_CERT` (`0`).
    NoClientCert = 0,
    /// `REQUEST_CLIENT_CERT` (`1`).
    RequestClientCert = 1,
    /// `REQUIRE_ANY_CLIENT_CERT` (`2`).
    RequireAnyClientCert = 2,
    /// `VERIFY_CLIENT_CERT_IF_GIVEN` (`3`).
    VerifyClientCertIfGiven = 3,
    /// `REQUIRE_AND_VERIFY_CLIENT_CERT` (`4`).
    RequireAndVerifyClientCert = 4,
}

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
/// How strictly to require the extended master secret extension ([RFC 7627]).
pub enum ExtendedMasterSecretType {
    #[default]
    /// `REQUEST` (`0`).
    Request = 0,
    /// `REQUIRE` (`1`).
    Require = 1,
    /// `DISABLE` (`2`).
    Disable = 2,
}

impl ConfigBuilder {
    fn offered_cipher_suites(&self, is_client: bool) -> Result<Vec<Box<dyn CipherSuite>>> {
        let legacy_suites = self.configured_suites(false);
        // a client offers one family or the other, while a server can only offer them if
        // it actually holds a certificate.
        let exclude_certificate = if is_client {
            self.psk.is_some()
        } else {
            self.certificates.is_empty()
        };

        parse_cipher_suites(&legacy_suites, self.psk.is_none(), exclude_certificate)
    }

    /// The cipher suites of the configured list that belong to one family: the TLS 1.3
    /// suites, or the others.
    fn configured_suites(&self, tls13: bool) -> Vec<CipherSuiteId> {
        self.cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.is_tls13() == tls13)
            .collect()
    }

    fn validate(&self, is_client: bool) -> Result<()> {
        if self.min_version > self.max_version {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }
        // A pre-shared key means the DTLS 1.2 PSK suites: a client with one offers nothing
        // else, and a server with nothing else has no certificate for DTLS 1.3.
        let psk_only = self.psk.is_some() && (is_client || self.certificates.is_empty());
        if psk_only && self.min_version == DtlsVersion::Dtls1_3 {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }

        if is_client && self.psk.is_some() && self.psk_identity_hint.is_none() {
            return Err(Error::ErrPskAndIdentityMustBeSetForClient);
        }

        if !is_client && self.psk.is_none() && self.certificates.is_empty() {
            return Err(Error::ErrServerMustHaveCertificate);
        }

        // A server may hold both and let each handshake pick
        if is_client && !self.certificates.is_empty() && self.psk.is_some() {
            return Err(Error::ErrPskAndCertificate);
        }

        if self.psk_identity_hint.is_some() && self.psk.is_none() {
            return Err(Error::ErrIdentityNoPsk);
        }

        self.offered_cipher_suites(is_client)?;

        Ok(())
    }

    /// build handshake config
    pub fn build(
        mut self,
        is_client: bool,
        remote_addr: Option<SocketAddr>,
    ) -> Result<HandshakeConfig> {
        // The caller supplies the provider; this crate never resolves a default. An application
        // that wants the feature-selected built-in passes `crypto::default_provider()?`.
        let crypto_provider = self.crypto_provider.take().ok_or_else(|| {
            Error::Crypto(
                "no crypto provider configured: call ConfigBuilder::with_crypto_provider"
                    .to_owned(),
            )
        })?;
        self.validate(is_client)?;

        // Each id is paired with the suite's own `is_psk`, so the checks below can tell the two
        // families apart without a second definition of which suites are psk.
        let mut local_cipher_suites: Vec<(CipherSuiteId, bool)> = self
            .offered_cipher_suites(is_client)?
            .iter()
            .map(|cs| (cs.id(), cs.is_psk()))
            .filter(|(id, _)| id.supported_by(crypto_provider.crypto()))
            .collect();
        if local_cipher_suites.is_empty() {
            return Err(Error::ErrNoAvailableCipherSuites);
        }

        let sigs: Vec<u16> = self.signature_schemes.iter().map(|x| *x as u16).collect();
        let local_signature_schemes: Vec<_> = parse_signature_schemes(&sigs, self.insecure_hashes)?
            .into_iter()
            .filter(|algorithm| {
                algorithm.crypto_scheme().is_ok_and(|scheme| {
                    crypto_provider
                        .crypto()
                        .supports(crypto::CryptoAlgorithm::Signature(scheme))
                })
            })
            .collect();

        let has_non_psk_suites = local_cipher_suites.iter().any(|(_, is_psk)| !is_psk);
        if has_non_psk_suites && local_signature_schemes.is_empty() {
            return Err(Error::ErrNoAvailableSignatureSchemes);
        }

        let local_named_curves: Vec<_> = [NamedCurve::P256, NamedCurve::X25519, NamedCurve::P384]
            .into_iter()
            .filter(|curve| {
                curve.crypto_algorithm().is_ok_and(|algorithm| {
                    crypto_provider
                        .crypto()
                        .supports(crypto::CryptoAlgorithm::KeyExchange(algorithm))
                })
            })
            .collect();
        if has_non_psk_suites && local_named_curves.is_empty() {
            return Err(Error::ErrNoAvailableCipherSuites);
        }

        if !is_client && has_non_psk_suites {
            let signing_key = &self.certificates[0].private_key.signing_key;
            local_cipher_suites.retain(|(id, is_psk)| {
                *is_psk
                    || local_signature_schemes.iter().any(|algorithm| {
                        let signature_family_matches = match id {
                            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256
                            | CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha
                            | CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 => {
                                algorithm.signature.is_rsa()
                            }
                            // RFC 8422 5.1.1, 5.2: an ECDHE_ECDSA suite takes a
                            // certificate with an ECDSA- or EdDSA-capable key.
                            _ => matches!(
                                algorithm.signature,
                                crate::signature_hash_algorithm::SignatureAlgorithm::Ecdsa
                                    | crate::signature_hash_algorithm::SignatureAlgorithm::Ed25519
                            ),
                        };
                        signature_family_matches
                            && algorithm
                                .crypto_scheme()
                                .is_ok_and(|scheme| signing_key.supports(scheme))
                    })
            });
            // A mixed config keeps its psk suites either way, so being left with only those
            // means the certificate can sign none of the suites offered alongside them.
            let only_psk_suites_left = local_cipher_suites.iter().all(|(_, is_psk)| *is_psk);
            if only_psk_suites_left {
                return Err(Error::ErrNoAvailableCipherSuites);
            }
        }

        let local_cipher_suites: Vec<CipherSuiteId> =
            local_cipher_suites.into_iter().map(|(id, _)| id).collect();

        // DTLS 1.3: its own suites (the configured ones of that family, or the defaults),
        // certificates only. Without a usable suite, group or signature scheme the highest
        // version is DTLS 1.2.
        let psk_only = self.psk.is_some() && (is_client || self.certificates.is_empty());
        let mut max_version = self.max_version;
        let mut local_tls13_cipher_suites = vec![];
        if max_version == DtlsVersion::Dtls1_3 && !psk_only {
            // A configured list is exact: without a TLS 1.3 suite in it there is no
            // DTLS 1.3.
            local_tls13_cipher_suites = if self.cipher_suites.is_empty() {
                crate::dtls13::suite::DEFAULT_SUITES.to_vec()
            } else {
                self.configured_suites(true)
            };
            local_tls13_cipher_suites.retain(|suite| suite.supported_by(crypto_provider.crypto()));
            let signs = local_signature_schemes.iter().any(|scheme| {
                scheme.is_tls13_signature()
                    && (is_client
                        || self
                            .certificates
                            .first()
                            .is_some_and(|c| scheme.is_compatible(&c.private_key)))
            });
            if local_tls13_cipher_suites.is_empty() || local_named_curves.is_empty() || !signs {
                local_tls13_cipher_suites.clear();
            }
        }
        if local_tls13_cipher_suites.is_empty() {
            if self.min_version == DtlsVersion::Dtls1_3 {
                return Err(Error::ErrNoAvailableCipherSuites);
            }
            max_version = DtlsVersion::Dtls1_2;
        }
        // The groups of DTLS 1.3: the hybrid with ML-KEM first where the provider has it
        // (and the configuration does not switch it off), then the curves.
        let mut local_tls13_groups = vec![];
        if self.post_quantum_key_share && hybrid_key_share_works(crypto_provider.crypto()) {
            local_tls13_groups.push(NamedCurve::X25519MlKem768);
        }
        local_tls13_groups.extend_from_slice(&local_named_curves);

        // A list with TLS 1.3 suites only leaves nothing to negotiate DTLS 1.2 with.
        let min_version = if max_version == DtlsVersion::Dtls1_3
            && !self.cipher_suites.is_empty()
            && self.configured_suites(false).is_empty()
        {
            DtlsVersion::Dtls1_3
        } else {
            self.min_version
        };

        let retransmit_interval = if self.flight_interval != Duration::from_secs(0) {
            self.flight_interval
        } else {
            INITIAL_TICKER_INTERVAL
        };

        let maximum_transmission_unit = if self.mtu == 0 { DEFAULT_MTU } else { self.mtu };
        if self
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > 255)
        {
            return Err(Error::Other(
                "an ALPN protocol name is 1 to 255 bytes".to_owned(),
            ));
        }
        if self.connection_id.is_some_and(|length| length > 255) {
            return Err(Error::Other(
                "a connection id is at most 255 bytes".to_owned(),
            ));
        }
        if maximum_transmission_unit < MINIMUM_MTU {
            return Err(Error::Other(format!(
                "mtu {maximum_transmission_unit} is below the minimum of {MINIMUM_MTU}"
            )));
        }
        let maximum_retransmit_interval = self.maximum_flight_interval.max(retransmit_interval);
        if self.hello_verify_request_version != PROTOCOL_VERSION1_0
            && self.hello_verify_request_version != PROTOCOL_VERSION1_2
        {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }

        // `..Default::default()` used to supply this; when P7 replaced that with an explicit
        // field list it wrote `0`, which means *no retransmits are permitted at all*. The very
        // first firing of the retransmit timer then takes the handshake straight to `Errored`
        // (see `handshaker::handshake_timeout`), so a single reply arriving later than one
        // `retransmit_interval` kills the handshake instead of being retried.
        //
        // That is exactly what a loaded CI machine produces: under `-Cinstrument-coverage` on a
        // two-vCPU runner, a round trip between two in-process peers can easily exceed the 1 s
        // interval, and the connection dies with the misleading `ErrInvalidFsmTransition`.
        let maximum_retransmit_number = DEFAULT_MAXIMUM_RETRANSMIT_NUMBER;

        let replay_protection_window = if self.replay_protection_window == 0 {
            DEFAULT_REPLAY_PROTECTION_WINDOW
        } else if self.replay_protection_window < MINIMUM_REPLAY_PROTECTION_WINDOW {
            warn!(
                "replay protection window {} raised to the minimum of {}",
                self.replay_protection_window, MINIMUM_REPLAY_PROTECTION_WINDOW
            );
            MINIMUM_REPLAY_PROTECTION_WINDOW
        } else {
            self.replay_protection_window
        };

        let mut server_name = self.server_name.clone();

        // A client given no server name takes the remote address's (an address is used to
        // verify the certificate and never sent as SNI, RFC 6066 section 3). A client that
        // verifies nothing by name (insecure_skip_verify, or a PSK) and has neither keeps no
        // name: it sends no server_name extension (the extension is a MAY, and its HostName
        // is "the fully qualified DNS hostname of the server, as understood by the client",
        // which this client does not know). A WebRTC peer connection is such a client: it
        // checks the certificate by its fingerprint. A client that verifies by name and has
        // neither has nothing to verify against and is refused (0.2.0 used "localhost").
        if is_client && server_name.is_empty() {
            if let Some(remote_addr) = remote_addr {
                server_name = remote_addr.ip().to_string();
            } else if !self.insecure_skip_verify && self.psk.is_none() {
                return Err(Error::Other(
                    "a client that verifies the server's certificate needs a server name \
                     (with_server_name) or a remote address"
                        .to_owned(),
                ));
            }
        }

        let server_cert_verifier = if self.insecure_skip_verify {
            None
        } else if let Some(verifier) = self.server_cert_verifier.take() {
            Some(verifier)
        } else {
            let adapter = self.verifier_adapter.as_ref().ok_or_else(|| {
                Error::Crypto("CA-chain verification requires a RustlsVerifierAdapter".to_owned())
            })?;
            let roots = if self.roots_cas.is_empty() {
                gen_self_signed_root_cert()
            } else {
                self.roots_cas.clone()
            };
            Some(server_cert_verifier(Arc::new(roots), adapter)?)
        };

        let client_cert_verifier = if self.client_auth as u8
            >= ClientAuthType::VerifyClientCertIfGiven as u8
        {
            let adapter = self.verifier_adapter.as_ref().ok_or_else(|| {
                Error::Crypto(
                    "client-certificate verification requires a RustlsVerifierAdapter".to_owned(),
                )
            })?;
            Some(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(self.client_cas.clone()),
                    adapter.provider.clone(),
                )
                .build()
                .map_err(|err| Error::Other(format!("rustls client cert verifier: {err}")))?
                    as Arc<dyn ClientCertVerifier>,
            )
        } else {
            None
        };

        // DTLS 1.3 pre-shared keys: a server's tickets, and the external PSKs (RFC 8446
        // section 4.2.11: an identity of at least one byte).
        let ticket_issuer = if is_client {
            None
        } else if let Some(shared) = self.session_ticket_issuer.take() {
            Some(shared.0)
        } else if self.session_tickets > 0 {
            Some(Arc::new(crate::dtls13::psk::TicketIssuer::new(
                crypto_provider.as_ref(),
                self.session_tickets,
                self.session_ticket_lifetime,
            )?))
        } else {
            None
        };
        let external_psks = std::mem::take(&mut self.external_psks);
        if external_psks.iter().any(|psk| {
            psk.identity.is_empty() || psk.identity.len() > 0xffff || psk.secret.is_empty()
        }) {
            return Err(Error::Other(
                "an external PSK has an identity of 1 to 65535 bytes and a secret".to_owned(),
            ));
        }

        // Fields not derived from the builder come from `HandshakeConfig::new`, which also
        // supplies `crypto_provider`.
        Ok(HandshakeConfig {
            crypto_provider,
            local_psk_callback: self.psk.take(),
            local_psk_identity_hint: self.psk_identity_hint.take(),
            local_cipher_suites,
            local_named_curves,
            local_signature_schemes,
            extended_master_secret: self.extended_master_secret,
            local_srtp_protection_profiles: self.srtp_protection_profiles,
            use_srtp_optional: self.use_srtp_optional,
            alpn_protocols: self.alpn_protocols.clone(),
            use_srtp_required: self.use_srtp_required,
            server_name,
            client_auth: self.client_auth,
            bad_certificate_for_a_missing_client_certificate: self
                .bad_certificate_for_a_missing_client_certificate,
            local_certificates: self.certificates,
            name_to_certificate: Default::default(),
            insecure_skip_verify: self.insecure_skip_verify,
            insecure_verification: self.insecure_verification,
            verify_peer_certificate: self.verify_peer_certificate.take(),
            roots_cas: self.roots_cas,
            server_cert_verifier,
            client_cert_verifier,
            retransmit_interval,
            maximum_retransmit_interval,
            handshake_timeout: self.handshake_timeout,
            cookie_exchange: self.cookie_exchange,
            hello_verify_request_version: self.hello_verify_request_version,
            early_data_retransmit: self.early_data_retransmit,
            min_version,
            max_version,
            local_tls13_cipher_suites,
            local_tls13_groups,
            // The extension belongs to both versions (RFC 9146 for DTLS 1.2, RFC 9147
            // section 9 for 1.3). A hello carries it even when no connection id is asked for
            // (RFC 9147 section 5.1: so that the peer can ask for one), unless that is
            // switched off.
            connection_id: self.connection_id,
            connection_id_migration: self.connection_id_migration,
            invalid_record_limit: self.invalid_record_limit,
            ticket_issuer,
            session_store: if is_client {
                self.session_store.take()
            } else {
                None
            },
            session_cache: if is_client {
                None
            } else {
                self.session_cache.take()
            },
            session_lifetime: self
                .session_ticket_lifetime
                .min(crate::session::MAX_TICKET_LIFETIME),
            dtls12_resumption: self.dtls12_resumption,
            external_psks,
            psk_without_key_exchange: self.psk_without_key_exchange,
            post_handshake_auth: is_client && self.post_handshake_auth,
            max_early_data: if is_client { 0 } else { self.max_early_data },
            #[cfg(test)]
            psk_modes_for_test: None,
            initial_epoch: 0,
            maximum_transmission_unit,
            maximum_retransmit_number,
            replay_protection_window,
        })
    }
}

/// A callback that decides whether a peer's certificate chain is acceptable.
///
/// WebRTC verifies the fingerprint from SDP instead of a CA chain, so this is where that check
/// goes.
pub type VerifyPeerCertificateFn =
    Arc<dyn (Fn(&[Vec<u8>], &[CertificateDer<'static>]) -> Result<()>) + Send + Sync>;

/// Generates a self-signed certificate, as WebRTC endpoints use.
pub fn gen_self_signed_root_cert() -> rustls::RootCertStore {
    #[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    {
        let mut certs = rustls::RootCertStore::empty();
        certs
            .add(
                rcgen::generate_simple_self_signed(vec![])
                    .unwrap()
                    .cert
                    .der()
                    .to_owned(),
            )
            .unwrap();
        certs
    }
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
    {
        rustls::RootCertStore::empty()
    }
}

#[derive(Clone)]
/// The resolved configuration a handshake runs with, produced by [`ConfigBuilder::build`].
pub struct HandshakeConfig {
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) local_psk_callback: Option<PskCallback>,
    pub(crate) local_psk_identity_hint: Option<Vec<u8>>,
    pub(crate) local_cipher_suites: Vec<CipherSuiteId>, // Available CipherSuites
    pub(crate) local_named_curves: Vec<NamedCurve>,
    pub(crate) local_signature_schemes: Vec<SignatureHashAlgorithm>, // Available signature schemes
    pub(crate) extended_master_secret: ExtendedMasterSecretType, // Policy for the Extended Master Support extension
    pub(crate) local_srtp_protection_profiles: Vec<SrtpProtectionProfile>, // Available SRTPProtectionProfiles, if empty no SRTP support
    pub(crate) use_srtp_optional: bool, // A client goes on when the server leaves use_srtp out
    /// The ALPN protocols (RFC 7301), most preferred first; empty without ALPN.
    pub(crate) alpn_protocols: Vec<String>,
    pub(crate) use_srtp_required: bool, // A server refuses a client it shares no SRTP profile with
    pub(crate) server_name: String,
    pub(crate) client_auth: ClientAuthType, // If we are a client should we request a client certificate
    /// RFC 8122 section 6.2: bad_certificate for a missing required client certificate.
    pub(crate) bad_certificate_for_a_missing_client_certificate: bool,
    pub(crate) local_certificates: Vec<Certificate>,
    pub(crate) name_to_certificate: HashMap<String, Certificate>,
    pub(crate) insecure_skip_verify: bool,
    pub(crate) insecure_verification: bool,
    pub(crate) verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    pub(crate) roots_cas: rustls::RootCertStore,
    pub(crate) server_cert_verifier: Option<Arc<dyn ServerCertVerifier>>,
    pub(crate) client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
    pub(crate) retransmit_interval: Duration,
    pub(crate) maximum_retransmit_interval: Duration,
    pub(crate) handshake_timeout: Option<Duration>,
    pub(crate) cookie_exchange: bool,
    pub(crate) hello_verify_request_version: ProtocolVersion,
    pub(crate) early_data_retransmit: bool,
    /// The lowest version negotiated.
    pub(crate) min_version: DtlsVersion,
    /// The highest version negotiated: DTLS 1.3 only when there is something to negotiate it
    /// with (`local_tls13_cipher_suites`).
    pub(crate) max_version: DtlsVersion,
    /// The TLS 1.3 cipher suites, for DTLS 1.3. Empty when DTLS 1.3 is not negotiated.
    pub(crate) local_tls13_cipher_suites: Vec<CipherSuiteId>,
    /// The key exchange groups of DTLS 1.3, most preferred first: `local_named_curves`,
    /// with X25519MLKEM768 in front where the provider has it.
    pub(crate) local_tls13_groups: Vec<NamedCurve>,
    /// The length of the connection ids this side asks its peer to send, if it uses the
    /// connection_id extension at all.
    pub(crate) connection_id: Option<usize>,
    pub(crate) connection_id_migration: bool,
    pub(crate) invalid_record_limit: Option<u64>,
    /// DTLS 1.3 server: the tickets it issues and has accepted, if it issues any.
    pub(crate) ticket_issuer: Option<Arc<crate::dtls13::psk::TicketIssuer>>,
    /// Client: where it keeps tickets and DTLS 1.2 sessions, if it resumes.
    pub(crate) session_store: Option<Arc<dyn crate::session::SessionStore>>,
    /// DTLS 1.2 server: the sessions it resumes by session id, if it keeps any.
    pub(crate) session_cache: Option<Arc<dyn crate::session::SessionCache>>,
    /// How long a DTLS 1.2 session in `session_cache` may be resumed.
    pub(crate) session_lifetime: Duration,
    /// DTLS 1.2 sessions are resumed (`ConfigBuilder::with_dtls12_resumption`).
    pub(crate) dtls12_resumption: bool,
    pub(crate) external_psks: Vec<crate::session::ExternalPsk>,
    pub(crate) psk_without_key_exchange: bool,
    /// DTLS 1.3 client: it offers post-handshake authentication.
    pub(crate) post_handshake_auth: bool,
    /// DTLS 1.3 server: the most 0-RTT data it takes with a ticket.
    pub(crate) max_early_data: u32,
    /// The PSK key exchange modes a client offers, in place of the configured ones: for the
    /// tests of a peer that offers psk_ke alone.
    #[cfg(test)]
    pub(crate) psk_modes_for_test: Option<Vec<u8>>,
    pub(crate) initial_epoch: u16,
    pub(crate) maximum_transmission_unit: usize,
    pub(crate) maximum_retransmit_number: usize,
    pub(crate) replay_protection_window: usize,
}

impl fmt::Debug for HandshakeConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HandshakeConfig<T>")
            .field("crypto_provider", &self.crypto_provider.name())
            .field("local_psk_identity_hint", &self.local_psk_identity_hint)
            .field("local_cipher_suites", &self.local_cipher_suites)
            .field("local_named_curves", &self.local_named_curves)
            .field("local_signature_schemes", &self.local_signature_schemes)
            .field("extended_master_secret", &self.extended_master_secret)
            .field(
                "local_srtp_protection_profiles",
                &self.local_srtp_protection_profiles,
            )
            .field("server_name", &self.server_name)
            .field("client_auth", &self.client_auth)
            .field("local_certificates", &self.local_certificates)
            .field("name_to_certificate", &self.name_to_certificate)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("insecure_verification", &self.insecure_verification)
            .field("roots_cas", &self.roots_cas)
            .field("retransmit_interval", &self.retransmit_interval)
            .field("initial_epoch", &self.initial_epoch)
            .field("maximum_transmission_unit", &self.maximum_transmission_unit)
            .field("maximum_retransmit_number", &self.maximum_retransmit_number)
            .field("replay_protection_window", &self.replay_protection_window)
            .finish()
    }
}

impl HandshakeConfig {
    /// Whether a missing required client certificate ends the handshake with
    /// `bad_certificate` (RFC 8122 section 6.2); see
    /// [`ConfigBuilder::with_bad_certificate_for_a_missing_client_certificate`].
    pub fn bad_certificate_for_a_missing_client_certificate(&self) -> bool {
        self.bad_certificate_for_a_missing_client_certificate
    }

    pub(crate) fn new(crypto_provider: Arc<dyn RTCCryptoProvider>) -> Self {
        Self {
            crypto_provider,
            local_psk_callback: None,
            local_psk_identity_hint: None,
            local_cipher_suites: vec![],
            local_named_curves: vec![],
            local_signature_schemes: vec![],
            extended_master_secret: ExtendedMasterSecretType::Disable,
            local_srtp_protection_profiles: vec![],
            use_srtp_optional: false,
            alpn_protocols: vec![],
            use_srtp_required: false,
            server_name: String::new(),
            client_auth: ClientAuthType::NoClientCert,
            bad_certificate_for_a_missing_client_certificate: false,
            local_certificates: vec![],
            name_to_certificate: HashMap::new(),
            insecure_skip_verify: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            roots_cas: rustls::RootCertStore::empty(),
            server_cert_verifier: default_verifier_adapter().and_then(|adapter| {
                server_cert_verifier(Arc::new(gen_self_signed_root_cert()), &adapter).ok()
            }),
            client_cert_verifier: None,
            retransmit_interval: std::time::Duration::from_secs(0),
            maximum_retransmit_interval: MAXIMUM_RETRANSMIT_INTERVAL,
            handshake_timeout: None,
            cookie_exchange: true,
            hello_verify_request_version: PROTOCOL_VERSION1_0,
            early_data_retransmit: true,
            min_version: DtlsVersion::Dtls1_2,
            max_version: DtlsVersion::Dtls1_2,
            local_tls13_cipher_suites: vec![],
            local_tls13_groups: vec![],
            connection_id: None,
            connection_id_migration: false,
            invalid_record_limit: None,
            ticket_issuer: None,
            session_store: None,
            session_cache: None,
            session_lifetime: crate::dtls13::psk::DEFAULT_TICKET_LIFETIME,
            dtls12_resumption: true,
            external_psks: vec![],
            psk_without_key_exchange: false,
            post_handshake_auth: false,
            max_early_data: 0,
            #[cfg(test)]
            psk_modes_for_test: None,
            initial_epoch: 0,
            maximum_transmission_unit: DEFAULT_MTU,
            maximum_retransmit_number: DEFAULT_MAXIMUM_RETRANSMIT_NUMBER,
            replay_protection_window: DEFAULT_REPLAY_PROTECTION_WINDOW,
        }
    }

    /// This configuration with another initial value for the handshake retransmission
    /// timer: for a caller that learns the round trip time of the path after the
    /// configuration was built (ICE does), and sets the timer to 1.5 times it as RFC 9147
    /// section 5.8.2 asks. The maximum the timer doubles to is raised to it if need be.
    pub fn with_flight_interval(&self, flight_interval: std::time::Duration) -> Self {
        let mut config = self.clone();
        if !flight_interval.is_zero() {
            config.retransmit_interval = flight_interval;
            config.maximum_retransmit_interval =
                config.maximum_retransmit_interval.max(flight_interval);
        }
        config
    }

    /// The initial value of the handshake retransmission timer.
    pub fn flight_interval(&self) -> std::time::Duration {
        self.retransmit_interval
    }

    pub(crate) fn provider(&self) -> &Arc<dyn RTCCryptoProvider> {
        &self.crypto_provider
    }

    /// Whether DTLS 1.3 is negotiated at all: the configuration allows it and has a DTLS 1.3
    /// cipher suite, group and signature scheme to run it with.
    pub fn supports_dtls13(&self) -> bool {
        self.max_version == DtlsVersion::Dtls1_3
    }

    /// Whether DTLS 1.2 is negotiated at all.
    pub(crate) fn supports_dtls12(&self) -> bool {
        self.min_version == DtlsVersion::Dtls1_2
    }

    /// A server's answer to a ClientHello's ALPN extension offering `offered` (RFC 7301
    /// section 3.2): `None` when this server uses no ALPN (the extension is ignored), the
    /// first of its protocols the client offered, or an error when there is none, which is
    /// a `no_application_protocol` alert.
    pub(crate) fn select_alpn(&self, offered: &[String]) -> Option<Result<String>> {
        if self.alpn_protocols.is_empty() {
            return None;
        }
        Some(
            self.alpn_protocols
                .iter()
                .find(|protocol| offered.contains(protocol))
                .cloned()
                .ok_or_else(|| {
                    Error::Other("no application protocol in common (RFC 7301)".to_owned())
                }),
        )
    }

    /// The connection id a hello of this side carries, if it uses the extension: random
    /// bytes of the configured length, none for a length of zero.
    pub(crate) fn connection_id_offer(&self) -> Option<Vec<u8>> {
        let length = self.connection_id?;
        let mut connection_id = vec![0u8; length];
        self.crypto_provider
            .random()
            .fill(&mut connection_id)
            .ok()?;
        Some(connection_id)
    }

    pub(crate) fn get_certificate(&self, server_name: &str) -> Result<Certificate> {
        if self.local_certificates.is_empty() {
            return Err(Error::ErrNoCertificates);
        }

        if self.local_certificates.len() == 1 {
            // There's only one choice, so no point doing any work.
            return Ok(self.local_certificates[0].clone());
        }

        if server_name.is_empty() {
            return Ok(self.local_certificates[0].clone());
        }

        let lower = server_name.to_lowercase();
        let name = lower.trim_end_matches('.');

        if let Some(cert) = self.name_to_certificate.get(name) {
            return Ok(cert.clone());
        }

        // try replacing labels in the name with wildcards until we get a
        // match.
        let mut labels: Vec<&str> = name.split_terminator('.').collect();
        for i in 0..labels.len() {
            labels[i] = "*";
            let candidate = labels.join(".");
            if let Some(cert) = self.name_to_certificate.get(&candidate) {
                return Ok(cert.clone());
            }
        }

        // If nothing matches, return the first certificate.
        Ok(self.local_certificates[0].clone())
    }
}

/// Whether `crypto` can do both ends of the X25519MLKEM768 exchange: it says so, and one
/// exchange made at once with it (a client share, the server's answer by encapsulation, the
/// client's decapsulation) gives both sides the same secret. A provider that wraps another
/// and passes `supports` through while leaving `key_exchange_respond` at its Diffie-Hellman
/// default says yes and cannot answer a hybrid share; such a provider is not offered the
/// group, rather than failing every handshake that picks it.
fn hybrid_key_share_works(crypto: &dyn crypto::RTCCrypto) -> bool {
    let algorithm = crypto::KeyExchangeAlgorithm::X25519MlKem768;
    if !crypto.supports(crypto::CryptoAlgorithm::KeyExchange(algorithm)) {
        return false;
    }
    let Ok(client) = crypto.start_key_exchange(algorithm) else {
        return false;
    };
    let Ok((share, server_secret)) = crypto.key_exchange_respond(algorithm, client.public_key())
    else {
        return false;
    };
    client
        .complete(&share)
        .is_ok_and(|client_secret| client_secret.as_ref() == server_secret.as_ref())
}

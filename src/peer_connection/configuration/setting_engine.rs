//! Advanced configuration engine for WebRTC peer connections.
//!
//! The `SettingEngine` provides low-level control over WebRTC transport behavior,
//! timeouts, security settings, and network configuration. Unlike the standard
//! `RTCConfiguration` which focuses on standards-compliant WebRTC settings, the
//! `SettingEngine` allows for advanced customization and optimization for specific
//! deployment scenarios.
//!
//! # Key Configuration Areas
//!
//! - **ICE Timeouts**: Configure connection health monitoring and keepalive intervals
//! - **NAT Traversal**: Set up 1:1 NAT mappings for cloud deployments (e.g., AWS EC2)
//! - **DTLS Security**: Control certificate verification and DTLS role behavior
//! - **Replay Protection**: Configure anti-replay windows for DTLS, SRTP, and SRTCP
//! - **Network Types**: Restrict candidate gathering to specific network types
//!
//! # Examples
//!
//! ## Configuring ICE timeouts for unstable networks
//!
//! ```
//! use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use std::time::Duration;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase timeouts for mobile or unstable networks
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_ice_timeouts(
//!         Some(Duration::from_secs(10)),  // disconnected_timeout (default: 5s)
//!         Some(Duration::from_secs(30)),  // failed_timeout (default: 25s)
//!         Some(Duration::from_secs(3)),   // keep_alive_interval (default: 2s)
//!     )
//!     .build();
//!
//! // Use with RTCConfiguration
//! // let mut config = RTCConfiguration::default();
//! // config.setting_engine = Some(setting_engine);
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting up 1:1 NAT for cloud deployments
//!
//! ```
//! use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use rtci::peer_connection::transport::RTCIceCandidateType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure for AWS EC2 instance with Elastic IP
//! // Private IP: 10.0.1.5, Public IP: 54.123.45.67
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_nat_1to1_ips(
//!         vec!["54.123.45.67".to_string()],
//!         RTCIceCandidateType::Host, // Use public IP for host candidates
//!     )
//!     .build();
//!
//! // This tells ICE to advertise the public IP instead of the private one
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring replay protection for security-critical applications
//!
//! ```
//! use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase replay protection window sizes
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_dtls_replay_protection_window(128)  // DTLS anti-replay
//!     .with_srtp_replay_protection_window(256)  // SRTP anti-replay
//!     .with_srtcp_replay_protection_window(128) // SRTCP anti-replay
//!     .build();
//!
//! // Larger windows protect against more packet reordering but use more memory
//! # Ok(())
//! # }
//! ```
//!
//! ## Restricting network types for controlled environments
//!
//! ```
//! use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use ice::network_type::NetworkType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Only gather IPv4 UDP candidates (no IPv6, no TCP)
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_network_types(vec![NetworkType::Udp4])
//!     .build();
//!
//! // This reduces candidate gathering time and SDP size
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`RTCConfiguration`](crate::peer_connection::configuration::RTCConfiguration) - Standard WebRTC configuration
//! - [`MediaEngine`](crate::peer_connection::configuration::media_engine::MediaEngine) - Codec registration
//! - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
//! - [RFC 8446 - TLS 1.3 (DTLS basis)](https://datatracker.ietf.org/doc/html/rfc8446)

#[cfg(test)]
mod setting_engine_test;

use std::net::IpAddr;
use std::sync::Arc;

use crypto::RTCCryptoProvider;
use dtls::cipher_suite::CipherSuiteId;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
//TODO: use ice::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
use ice::agent::remote_policy::{IceAddressPolicy, RemoteAddressFilter};
use ice::mdns::MulticastDnsMode;
use ice::network_type::NetworkType;
use ice::{ConsentResponseWait, FailedNomination, NominationAcceptance, UnauthenticatedRequests};
//TODO: use ice::udp_network::UDPNetwork;
use crate::peer_connection::configuration::behaviour_profile::BehaviourProfile;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use std::time::Duration;

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

/// ICE timeout configuration for connection health monitoring.
///
/// These timeouts control how ICE determines connection state transitions
/// and when to send keepalive packets. Adjust these for different network
/// conditions (mobile, satellite, etc.).
#[derive(Default, Clone)]
pub struct Timeout {
    /// Duration without network activity before ICE is considered disconnected.
    /// Default: 5 seconds.
    pub ice_disconnected_timeout: Option<Duration>,

    /// Duration without network activity before ICE is considered failed after disconnected.
    /// Default: 25 seconds.
    pub ice_failed_timeout: Option<Duration>,

    /// How often ICE sends keepalive packets when there's no media flow.
    /// Default: 2 seconds. If media is flowing, no keepalives are sent.
    pub ice_keepalive_interval: Option<Duration>,

    /// Controls how often ICE sends binding requests for a candidate pair.
    /// When combined with `ice_max_binding_requests`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_check_interval: Option<Duration>,

    /// The max amount of binding requests ICE will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    /// When combined with `ice_check_interval`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_max_binding_requests: Option<u16>,

    /// Minimum wait time before accepting host candidates.
    pub ice_host_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting server reflexive candidates.
    pub ice_srflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting peer reflexive candidates.
    pub ice_prflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting relay candidates.
    pub ice_relay_acceptance_min_wait: Option<Duration>,
}

/// Data-channel configuration for in-band channels.
#[derive(Clone, Default)]
pub struct DataChannel {
    /// Maximum time to wait for a peer's `DATA_CHANNEL_ACK` before failing an
    /// in-band data channel, counted from the moment the association came up on this side.
    /// `None` (the default) disables the timeout.
    ///
    /// RFC 8832 has none: the `DATA_CHANNEL_OPEN` and the `DATA_CHANNEL_ACK` are sent on a
    /// reliable, ordered stream, so they arrive while the association lives, and a channel
    /// whose association fails gets an error with it. A fixed timeout instead closed channels
    /// on a lossy path that was still up, where SCTP's retransmissions (which back off) or
    /// the peer's half of the SCTP handshake (a lost COOKIE ACK) took longer than it.
    pub dcep_handshake_timeout: Option<Duration>,
}

/// MulticastDNS configuration for mDNS.
#[derive(Clone)]
pub struct MulticastDNS {
    /// Duration without network activity before mDNS query is considered failed.
    /// Default: 10 seconds.
    pub timeout: Option<Duration>,
    /// Represents the different Multicast modes that ICE can run.
    pub mode: MulticastDnsMode,
    /// Controls the local name for this agent. If none is specified a random one will be generated.
    pub local_name: String,
    /// Control mDNS local IP address
    pub local_ip: Option<IpAddr>,
    /// See [`SettingEngineBuilder::with_multicast_dns_first_query_delay`]. `None`: on.
    pub first_query_delay: Option<bool>,
    /// See [`SettingEngineBuilder::with_multicast_dns_multi_question_delay`]. `None`: on.
    pub multi_question_delay: Option<bool>,
    /// See [`SettingEngineBuilder::with_multicast_dns_destination_reported`].
    pub destination_reported: bool,
    /// See [`SettingEngineBuilder::with_multicast_dns_unicast_response`].
    pub unicast_response: bool,
    /// See [`SettingEngineBuilder::with_multicast_dns_rate_limit`].
    pub rate_limit: Option<ice::mdns::MdnsRateLimit>,
    /// See [`SettingEngineBuilder::with_multicast_dns_fail_closed`].
    pub fail_closed: bool,
    /// See [`SettingEngineBuilder::with_multicast_dns_expose_known_public_addresses`].
    pub expose_known_public_addresses: bool,
    /// See [`SettingEngineBuilder::with_multicast_dns_expose_temporary_ipv6_addresses`].
    pub expose_temporary_ipv6_addresses: bool,
}

impl Default for MulticastDNS {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
            // Safari and Chrome emit only mDNS ("<uuid>.local") host candidates
            // by default (to avoid leaking private IPs). With Disabled those are
            // silently dropped, leaving no usable remote candidates from such an
            // offer; QueryOnly resolves them via mDNS without publishing our own
            // host IPs as mDNS names. This matches the MulticastDnsMode enum's
            // own #[default].
            mode: MulticastDnsMode::QueryOnly,
            local_name: "".to_string(),
            local_ip: None,
            first_query_delay: None,
            multi_question_delay: None,
            destination_reported: false,
            unicast_response: false,
            rate_limit: None,
            fail_closed: false,
            expose_known_public_addresses: false,
            expose_temporary_ipv6_addresses: false,
        }
    }
}

/// ICE candidate gathering and filtering configuration.
///
/// Controls which types of candidates are gathered, NAT mappings,
/// and custom network filtering.
#[derive(Default, Clone)]
pub struct Candidates {
    /// Enable ICE Lite mode (only respond to connectivity checks, don't initiate).
    pub ice_lite: bool,

    /// webrtc-extensions 7: propose each nomination to the application first
    /// (`OnIceCandidatePairNominate`, answered with
    /// `RTCPeerConnection::resolve_candidate_pair_nomination`), the cancelable
    /// `icecandidatepairnominate`. Off by default: the agent nominates at once.
    pub candidate_pair_proposals: bool,

    /// Restrict candidate gathering to specific network types (e.g., UDP4, UDP6, TCP4).
    pub ice_network_types: Vec<NetworkType>,
    //TODO: pub interface_filter: Arc<Option<InterfaceFilterFn>>,
    //TODO: pub ip_filter: Arc<Option<IpFilterFn>>,
    /// External IP addresses for 1:1 NAT mappings (e.g., AWS Elastic IP).
    pub nat_1to1_ips: Vec<String>,

    /// Candidate type to use for NAT 1:1 IPs (Host or Srflx).
    pub nat_1to1_ip_candidate_type: RTCIceCandidateType,
    /// Static ICE username fragment (ufrag) for reproducible sessions.
    pub username_fragment: String,

    /// Static ICE password for reproducible sessions.
    pub password: String,

    /// Whether to discard local candidates during ICE restart.
    pub discard_local_candidates_during_ice_restart: bool,

    /// Allow gathering loopback candidates (useful for some VM configurations).
    /// Note: This is non-standard per RFC 8445.
    ///
    /// Not read by this engine, which gathers no candidates (see the deprecated
    /// `SettingEngineBuilder::with_include_loopback_candidate`).
    pub include_loopback_candidate: bool,

    /// Lets connectivity checks go to loopback / link-local remote addresses from local
    /// candidates outside that scope. See
    /// `SettingEngineBuilder::with_remote_candidate_scopes`.
    pub allow_loopback_remote_candidates: bool,
    /// See `SettingEngineBuilder::with_remote_candidate_scopes`.
    pub allow_link_local_remote_candidates: bool,
    /// See `SettingEngineBuilder::with_remote_address_filter`.
    pub remote_address_filter: Option<RemoteAddressFilter>,
    /// See `SettingEngineBuilder::with_ice_address_policy`. The default allows everything.
    pub address_policy: IceAddressPolicy,
}

/// Where the ICE agent follows RFC 8445 / RFC 8489 by default and a browser (libwebrtc)
/// behaviour, or one of this fork's hardenings, can be chosen instead. Every default is the
/// RFC's.
#[derive(Default, Clone)]
pub struct IceBehaviour {
    /// See [`SettingEngineBuilder::with_ice_tie_breaker`].
    pub tie_breaker: Option<u64>,
    /// See [`SettingEngineBuilder::with_ice_new_tie_breaker_on_restart`].
    pub new_tie_breaker_on_restart: bool,
    /// See [`SettingEngineBuilder::with_ice_nomination_acceptance`].
    pub nomination_acceptance: NominationAcceptance,
    /// See [`SettingEngineBuilder::with_ice_failed_nomination`].
    pub failed_nomination: FailedNomination,
    /// See [`SettingEngineBuilder::with_ice_nomination_on_consent_checks`].
    pub nominate_on_consent_checks: bool,
    /// See [`SettingEngineBuilder::with_ice_consent_response_wait`].
    pub consent_response_wait: ConsentResponseWait,
    /// See [`SettingEngineBuilder::with_ice_pacing`].
    pub pacing: Option<Duration>,
    /// See [`SettingEngineBuilder::with_ice_pacing_group`].
    pub pacing_group: Option<std::sync::Arc<ice::PacingGroup>>,
    /// See [`SettingEngineBuilder::with_ice_unauthenticated_requests`].
    pub unauthenticated_requests: UnauthenticatedRequests,
    /// See [`SettingEngineBuilder::with_ice_data_from_selected_pair_only`].
    pub data_from_selected_pair_only: bool,
    /// See [`SettingEngineBuilder::with_ice_data_before_nomination`].
    pub send_data_before_nomination: bool,
    /// See [`SettingEngineBuilder::with_ice_pairing_before_candidates_are_conveyed`].
    pub pair_before_conveyed: bool,
    /// See [`SettingEngineBuilder::with_ice_software`]: `None` until it is called (each
    /// stack's own SOFTWARE), then the value it was given.
    pub software: Option<Option<String>>,
}

/// Replay attack protection window sizes.
///
/// Larger windows provide better protection against packet reordering
/// but consume more memory. Set to 0 to disable replay protection (not recommended).
#[derive(Default, Copy, Clone)]
pub struct ReplayProtection {
    /// DTLS replay protection window size (in packets).
    pub dtls: usize,

    /// SRTP replay protection window size (in packets).
    pub srtp: usize,

    /// SRTCP replay protection window size (in packets).
    pub srtcp: usize,
}

/// Maximum message size for SCTP data channels.
///
/// Controls the maximum size of messages that can be sent through data channels.
/// Per [RFC 8841](https://datatracker.ietf.org/doc/html/rfc8841), the default is 64KB.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SctpMaxMessageSize {
    /// Fixed maximum message size in bytes.
    Bounded(u32),

    /// No practical limit (uses MAX_MESSAGE_SIZE internally).
    Unbounded,
}

impl SctpMaxMessageSize {
    /// Default message size per RFC 8841 (64KB).
    pub const DEFAULT_MESSAGE_SIZE: u32 = 65536;

    /// Maximum message size (256KB).
    pub const MAX_MESSAGE_SIZE: u32 = 262144;

    /// Returns the message size as `usize`.
    pub fn as_usize(&self) -> usize {
        match self {
            Self::Bounded(result) => (*result).min(Self::MAX_MESSAGE_SIZE) as usize,
            Self::Unbounded => Self::MAX_MESSAGE_SIZE as usize,
        }
    }
}

impl Default for SctpMaxMessageSize {
    fn default() -> Self {
        // https://datatracker.ietf.org/doc/html/rfc8841#section-6.1-4
        // > If the SDP "max-message-size" attribute is not present, the default value is 64K.
        Self::Bounded(Self::DEFAULT_MESSAGE_SIZE)
    }
}

/// Advanced configuration engine for fine-tuning WebRTC behavior.
///
/// `SettingEngine` provides granular control over transport-level settings that
/// are not exposed through the standard WebRTC API. Use this to optimize for
/// specific deployment scenarios, network conditions, or security requirements.
///
/// # Configuration Categories
///
/// - **Timeout**: ICE connection health monitoring and keepalive
/// - **TURN**: Allocation maintenance behavior
/// - **Candidates**: NAT traversal, network filtering, ICE credentials
/// - **Replay Protection**: Anti-replay window sizes for DTLS/SRTP/SRTCP
/// - **DTLS**: Certificate verification and role selection
/// - **Media Engine**: Codec registration behavior
/// - **SCTP**: Data channel message size limits
///
/// # Examples
///
/// ## Basic usage with RTCConfiguration
///
/// ```
/// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let setting_engine = SettingEngineBuilder::new()
///     // Configure timeouts
///     .with_ice_timeouts(
///         Some(Duration::from_secs(10)),
///         Some(Duration::from_secs(30)),
///         Some(Duration::from_secs(3)),
///     )
///     .build();
///
/// // Use with peer connection configuration
/// // let api = APIBuilder::new().with_setting_engine(setting_engine).build();
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [W3C WebRTC Spec](https://www.w3.org/TR/webrtc/)
/// - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
#[derive(Clone)]
pub struct SettingEngine {
    /// The profile the settings were last set to ([`SettingEngineBuilder::with_behaviour_profile`]);
    /// settings changed after it keep their own values.
    pub(crate) behaviour_profile: BehaviourProfile,
    pub(crate) crypto_provider: Option<Arc<dyn RTCCryptoProvider>>,
    /// The wall clock paired with the engine's clock ([`SettingEngineBuilder::with_wall_clock`]);
    /// `None`: read once when the peer connection is built.
    pub(crate) wall_clock: Option<shared::time::SystemInstant>,
    pub(crate) timeout: Timeout,
    pub(crate) data_channel: DataChannel,
    pub(crate) turn_allocation_refresh_interval_cap: Option<Duration>,
    pub(crate) turn_reallocation_delay: Duration,
    pub(crate) candidates: Candidates,
    pub(crate) ice: IceBehaviour,
    pub(crate) multicast_dns: MulticastDNS,
    pub(crate) replay_protection: ReplayProtection,
    /// Fingerprints at session level (`with_sdp_media_level_fingerprints(false)`); inverted
    /// so that the derived `Default` is media level.
    pub(crate) sdp_session_level_fingerprints: bool,
    pub(crate) disable_sdp_tls_id: bool,
    /// A remote description may ask for a new DTLS association without an ICE restart (RFC
    /// 8842 section 3.1 read without its section 6); off by default (RFC 9429 sections 5.8.3
    /// and 5.11).
    pub(crate) dtls_new_association_without_ice_restart: bool,
    /// A new DTLS association keeps the local candidates and may use the transport addresses
    /// of the one it replaces (`with_dtls_new_association_on_previous_addresses`); off by
    /// default (RFC 8842 sections 5.1 and 6).
    pub(crate) dtls_new_association_on_previous_addresses: bool,
    /// RFC 8830 section 3: a section that lists no `a=msid` any more ends its track.
    pub(crate) msid_removal_ends_track: bool,
    /// [`SettingEngineBuilder::with_unoffered_feedback_refused`]: RFC 9429 section 5.11, an
    /// answer with `a=rtcp-fb` the offer did not have is an error.
    pub(crate) unoffered_feedback_refused: bool,
    /// RFC 8830 section 3: a new msid-appdata in a section is a new track: the receiver's
    /// track ends and a new one takes its place.
    pub(crate) msid_appdata_change_renews_track: bool,
    /// RFC 8830 section 3: a remote track whose SSRCs have all left (BYE, timeout) ends.
    pub(crate) source_departure_ends_track: bool,
    /// [`SettingEngineBuilder::with_rtp_timeout_mutes_track`].
    pub(crate) rtp_timeout_mutes_track: bool,
    /// RFC 9429 section 5.3.1: an answer rejects the section of a transceiver stopped after
    /// the offer arrived.
    pub(crate) stopping_transceiver_rejected_in_answer: bool,
    /// `use_srtp` only on an association that carries SRTP media (RFC 5764 section 4.1);
    /// inverted so that the derived `Default` is the browsers' form, the default.
    pub(crate) dtls_use_srtp_only_with_media: bool,
    pub(crate) accept_lowercase_fingerprints: bool,
    /// [`SettingEngineBuilder::with_bundled_fingerprints_agreeing`]: a remote description whose
    /// bundled sections carry fingerprints other than the tagged section's is refused.
    pub(crate) bundled_fingerprints_agree: bool,
    /// [`SettingEngineBuilder::with_cryptex_required_on_every_bundled_section`]: `a=cryptex`
    /// counts only at the session level or on every RTP section, the tagged one not standing
    /// for its group.
    pub(crate) cryptex_required_on_every_bundled_section: bool,
    /// Answers and subsequent offers repeat the BUNDLE attributes in every bundled m=
    /// section instead of carrying them in the tagged one only (RFC 9143 section 7.1.3); see
    /// [`SettingEngineBuilder::with_bundle_attributes_repeated`].
    /// Inverted so that the derived default is "repeated".
    pub(crate) bundle_attributes_tagged_only: bool,
    /// [`SettingEngineBuilder::with_max_bundle_as_must_bundle`].
    /// Inverted so that the derived default is "honoured".
    pub(crate) max_bundle_ignored: bool,
    /// `with_rtcp_mux_only_in_subsequent_offers`.
    pub(crate) rtcp_mux_only_in_subsequent_offers: bool,
    /// [`SettingEngineBuilder::with_bundle_only_sections_in_browser_form`].
    pub(crate) bundle_only_sections_in_browser_form: bool,
    /// [`SettingEngineBuilder::with_answer_offered_formats_only`].
    pub(crate) answer_offered_formats_only: bool,
    /// [`SettingEngineBuilder::with_answer_ice_options`].
    pub(crate) answer_ice_options: AnswerIceOptions,
    /// [`SettingEngineBuilder::with_unique_transport_credentials`]: every transport of the
    /// connection gets ICE credentials of its own. The derived default `false` shares the first
    /// transport's.
    pub(crate) unique_transport_credentials: bool,
    /// [`SettingEngineBuilder::with_separate_fec_sessions`]: an offered FEC session of its
    /// own (RFC 5109 section 14.1) is accepted.
    pub(crate) separate_fec_sessions: bool,
    /// [`SettingEngineBuilder::with_implicit_rollback`].
    /// Inverted so that the derived default is "implicit rollback on".
    pub(crate) explicit_rollback_only: bool,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_media_engine_copy: bool,
    pub(crate) disable_media_engine_multiple_codecs: bool,
    /// [`SettingEngineBuilder::with_own_payload_types_in_answers`].
    pub(crate) own_payload_types_in_answers: bool,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) receive_mtu: usize,
    pub(crate) mid_generator: Option<Arc<dyn Fn(isize) -> String + Send + Sync>>,
    /// Determines the max size of any message that may be sent through an SCTP transport.
    pub(crate) sctp_max_message_size: SctpMaxMessageSize,
    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    /// `None` uses the rtci-sctp default (`INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub(crate) sctp_max_receive_buffer_size: Option<u32>,
    /// Overrides the outbound SCTP DATA-packet budget, converted to a payload
    /// budget via rtci-sctp's `max_payload_size_for_mtu`. `None` uses the rtci-sctp
    /// default (`INITIAL_MTU`, 1191 — the TURN-relayed IPv6 minimum-MTU budget).
    pub(crate) sctp_mtu: Option<u32>,
    /// SCTP path MTU discovery (RFC 8899 section 6.2.3): `Some` with the largest IP packet to
    /// probe for, `None` off. Unset is the default, on up to 1500 bytes.
    pub(crate) sctp_path_mtu_discovery: Option<Option<u32>>,
    /// SCTP streams share the bytes sent by weight (RFC 8260 section 3.6, RFC 8831 section
    /// 6.4). `None` is the default, on.
    pub(crate) sctp_weighted_fair_queueing: Option<bool>,
    /// SCTP user message interleaving (RFC 8260) is announced. `None` is the default, on.
    pub(crate) sctp_message_interleaving: Option<bool>,
    /// The SCTP zero checksum (RFC 9653) is announced as acceptable. `None` is the default,
    /// on.
    pub(crate) sctp_zero_checksum: Option<bool>,
    /// [`SettingEngineBuilder::with_sctp_max_streams`]. `None` is the default, 65535.
    pub(crate) sctp_max_streams: Option<u16>,
    /// [`SettingEngineBuilder::with_sctp_inbound_reassembly_limit`]. `None` is the default,
    /// 64 MiB.
    pub(crate) sctp_inbound_reassembly_limit: Option<usize>,
    /// [`SettingEngineBuilder::with_sctp_rto`]. `None` is RFC 9260's 1 / 1 / 60 seconds.
    pub(crate) sctp_rto: Option<sctp::RtoConfig>,
    /// [`SettingEngineBuilder::with_sctp_max_retransmissions`]. `None` is RFC 9260's 10.
    pub(crate) sctp_max_retransmissions: Option<usize>,
    /// [`SettingEngineBuilder::with_sctp_handshake_timers_back_off_rto`]. `true` (the
    /// default) is RFC 9260 5.1's.
    pub(crate) sctp_handshake_timers_back_off_rto: bool,
    /// [`SettingEngineBuilder::with_ice_failed_without_end_of_candidates`]. `false` (the
    /// default) is W3C webrtc-pc 5.6.4's "failed".
    pub(crate) ice_failed_without_end_of_candidates: bool,
    /// A message over 16 KB is refused on an association without message interleaving
    /// (RFC 8831 section 6.6). `None` is the default, on.
    pub(crate) sctp_message_size_limit_without_interleaving: Option<bool>,
    /// [`SettingEngineBuilder::with_data_channel_max_buffer_size`].
    pub(crate) data_channel_max_buffer_size: Option<u32>,
    /// [`SettingEngineBuilder::with_data_channel_send_before_ack`].
    pub(crate) data_channel_send_before_ack: bool,
    /// [`SettingEngineBuilder::with_non_interactive_video`].
    pub(crate) non_interactive_video: bool,
    /// [`SettingEngineBuilder::with_dscp_marking`].
    pub(crate) dscp_marking: crate::peer_connection::priority::RTCDscpMarking,
    /// [`SettingEngineBuilder::with_srtp_key_lifetime`].
    pub(crate) srtp_key_lifetime: Option<srtp::keying::KeyLifetime>,
    /// [`SettingEngineBuilder::with_dtls_connection_id`].
    pub(crate) dtls_connection_id_length: Option<usize>,
    /// [`SettingEngineBuilder::with_dtls_alpn`]: `true` when it is turned off.
    pub(crate) dtls_alpn_off: bool,
    /// [`SettingEngineBuilder::with_dtls_session_resumption`]: `true` when it is turned on.
    pub(crate) dtls_session_resumption: bool,
    /// [`SettingEngineBuilder::with_srtp_automatic_rekeying`]: `true` when it is turned off.
    pub(crate) srtp_automatic_rekeying_off: bool,
    /// [`SettingEngineBuilder::with_srtp_rekeying_dtls_client_first`]: `true` when it is
    /// turned off (both sides ask at the lifetime warning).
    pub(crate) srtp_rekeying_both_at_warning: bool,
    pub(crate) ignore_rid_pause_for_recv: bool,
    /// [`SettingEngineBuilder::with_rid_pause_marks`].
    pub(crate) rid_pause_marks: bool,
    /// [`SettingEngineBuilder::with_published_rid_id_grammar`].
    pub(crate) published_rid_id_grammar: bool,
    /// [`SettingEngineBuilder::with_rollback_content_ignored`].
    pub(crate) rollback_content_ignored: bool,
    /// [`SettingEngineBuilder::with_rollback_resets_offer_created_senders`].
    pub(crate) rollback_resets_offer_created_senders: bool,
    /// [`SettingEngineBuilder::with_rejected_rids_kept_in_offers`].
    pub(crate) rejected_rids_kept_in_offers: bool,
    /// [`SettingEngineBuilder::with_remote_rid_renegotiation_refused`].
    pub(crate) remote_rid_renegotiation_refused: bool,
    /// [`SettingEngineBuilder::with_strict_sdp_attribute_grammar`].
    pub(crate) strict_sdp_attribute_grammar: bool,
    /// [`SettingEngineBuilder::with_w3c_simulcast_answer`].
    pub(crate) w3c_simulcast_answer: bool,
    /// [`SettingEngineBuilder::with_nominated_candidates_only`].
    pub(crate) nominated_candidates_only: bool,
    /// [`SettingEngineBuilder::with_msid_appdata`]`(false)`: `a=msid` lines without the
    /// track id (inverted so that the derived default writes it).
    pub(crate) msid_appdata_omitted: bool,
    /// [`SettingEngineBuilder::with_video_receive_limits`].
    pub(crate) video_receive_limits: Option<crate::peer_connection::sdp::RTCVideoResolutionRange>,
    /// [`SettingEngineBuilder::with_codec_video_receive_limits`], by MIME type.
    pub(crate) codec_video_receive_limits:
        Vec<(String, crate::peer_connection::sdp::RTCVideoResolutionRange)>,
    /// Whether `write_rtp` sends header extension elements whose id is not negotiated; see
    /// [`SettingEngineBuilder::with_unnegotiated_header_extensions`].
    pub(crate) unnegotiated_header_extensions: bool,
    /// [`SettingEngineBuilder::with_ssrc_per_clock_rate`]: a codec of another clock rate moves
    /// the stream to a new SSRC (RFC 7160 section 4.1). Off by default: one SSRC across clock
    /// rates, which every browser receiver follows.
    pub(crate) ssrc_per_clock_rate: bool,
    /// [`SettingEngineBuilder::with_audio_redundancy`]: when an audio stream that negotiated
    /// RED (RFC 2198) is sent in it.
    pub(crate) audio_redundancy: interceptor::AudioRedundancy,
    pub(crate) write_ssrc_attributes_for_simulcast: bool,
    /// The application's socket layer reports each received datagram's ECN codepoint and
    /// applies the one each sent datagram carries ([`SettingEngineBuilder::with_ecn`]).
    pub(crate) ecn: bool,
    /// How a stream starts marking ([`SettingEngineBuilder::with_ecn_initiation`]).
    pub(crate) ecn_initiation: interceptor::EcnInitiation,
    /// ECN is used on `ack ccfb` alone, without `a=ecn-capable-rtp`
    /// ([`SettingEngineBuilder::with_ecn_without_signalling`]).
    pub(crate) ecn_without_signalling: bool,
    /// The engine's own stream transports ([`SettingEngineBuilder::with_tcp_candidate_gathering`]
    /// and the methods after it).
    pub(crate) streams: crate::peer_connection::streams::StreamSettings,
    /// How the engine's TURN-over-TLS connections verify their server
    /// ([`SettingEngineBuilder::with_turn_tls`]).
    pub(crate) turn_tls: crate::peer_connection::turn_tls::TurnTlsConfig,
    /// Which ECT codepoint marked packets carry ([`SettingEngineBuilder::with_ecn_marking`]).
    pub(crate) ecn_marking: interceptor::EcnMarking,
    /// The connection runs without the RTCP session the builder otherwise installs
    /// ([`SettingEngineBuilder::with_rtcp_session_omitted`]); a departure from RFC 8834 4.1.
    pub(crate) rtcp_session_omitted: bool,
    /// Received RTCP is held to RFC 3550 Appendix A.2 and section 6.4.1
    /// ([`SettingEngineBuilder::with_strict_rtcp_validity`]).
    pub(crate) strict_rtcp_validity: bool,
    /// RTCP feedback the application writes is sent whether or not its section negotiated
    /// it ([`SettingEngineBuilder::with_unnegotiated_rtcp_feedback`]).
    pub(crate) unnegotiated_rtcp_feedback: bool,
    /// `a=ice-options` in each media section instead of once at session level
    /// ([`SettingEngineBuilder::with_ice_options_in_media_sections`]).
    pub(crate) ice_options_in_media_sections: bool,
    /// [`SettingEngineBuilder::with_default_ice_pacing_stated`]`(false)`: no `a=ice-pacing`
    /// line while Ta is the default (inverted so that the derived default states it).
    pub(crate) default_ice_pacing_omitted: bool,
    /// How the DTLS client's retransmission timer starts
    /// ([`SettingEngineBuilder::with_dtls_flight_interval`]).
    pub(crate) dtls_flight_interval: DtlsFlightInterval,
}

/// What an answer's `a=ice-options` line says of the `trickle` and `ice2` options
/// ([`SettingEngineBuilder::with_answer_ice_options`]). RFC 9429 section 5.3.1 and RFC 8840
/// section 4.1.3, RFC 8445 section 10 and RFC 8839 section 4.3.2 disagree
/// (`docs/conformance/spec-issues.md` row 28). Offers always say `trickle ice2` (RFC 9429
/// sections 5.2.1 and 5.2.2); other options of the offer are never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AnswerIceOptions {
    /// RFC 9429 section 5.3.1: the line, "with the "trickle" option as specified in
    /// [RFC8840], Section 4.1.3 and the "ice2" option as specified in [RFC8445], Section 10,
    /// is only included if such an option was present in the offer". An offer with neither
    /// gets no `a=ice-options` line (the attribute has at least one option, RFC 8839 section
    /// 5.6); a browser's offer (`trickle`) gets `trickle`. The default: RFC 9429 governs a JSEP
    /// endpoint, and its working group made the condition on `trickle` deliberate
    /// (`rtcweb-wg/jsep#23`).
    #[default]
    AsOffered,
    /// libwebrtc's answer: `trickle` whatever the offer had
    /// (`p2p/base/transport_description_factory.cc`, `TransportDescriptionFactory::CreateAnswer`,
    /// `desc->AddOption(ICE_OPTION_TRICKLE)`). libwebrtc never writes `ice2`; this engine is
    /// RFC 8445 compliant and keeps saying so where the offer did (`ice2` as offered).
    TrickleAlways,
    /// RFC 8840 section 4.1.3 ("In any case, the Answerer MUST include the
    /// "ice-options:trickle" attribute"), RFC 8445 section 10 ("An agent compliant to this
    /// specification MUST inform the peer about the compliance using the 'ice2' option") and
    /// RFC 8839 section 4.3.2: every answer says `trickle ice2`. The `StrictRfc` profile's
    /// value (the RFC form of the `conflict` rows RFC8839-4.3.2-3, RFC8839-4.2.1.5-1 and
    /// RFC8445-10-1).
    Always,
}

/// How the first DTLS retransmission timer of a peer connection's handshake is chosen
/// ([`SettingEngineBuilder::with_dtls_flight_interval`]). The timer doubles on each
/// retransmission either way (RFC 9147 section 5.8.2, RFC 6347 section 4.2.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DtlsFlightInterval {
    /// RFC 9147 section 5.8.2 for DTLS-SRTP (the default): 400 ms, or, once ICE has measured
    /// the round trip time of the selected pair, 1.5 times that and never under 100 ms.
    #[default]
    Rfc9147,
    /// libwebrtc's `DtlsTransportInternalImpl::ConfigureHandshakeTimeout`
    /// (`p2p/dtls/dtls_transport.cc`, `ComputeRetransmissionTimeout`): twice ICE's round
    /// trip time, held between 50 ms and 3 s; 50 ms without a measured round trip time (the
    /// initial value `OpenSSLStreamAdapter` gives BoringSSL).
    Libwebrtc,
}

impl DtlsFlightInterval {
    /// The first retransmission timer for a handshake started with `round_trip_time`, ICE's
    /// measurement of the selected pair, if any.
    pub fn initial(self, round_trip_time: Option<Duration>) -> Duration {
        match (self, round_trip_time) {
            (Self::Rfc9147, None) => {
                crate::peer_connection::transport::dtls::DTLS_SRTP_FLIGHT_INTERVAL
            }
            (Self::Rfc9147, Some(rtt)) => (rtt + rtt / 2)
                .max(crate::peer_connection::transport::dtls::MINIMUM_FLIGHT_INTERVAL),
            (Self::Libwebrtc, None) => Duration::from_millis(50),
            (Self::Libwebrtc, Some(rtt)) => {
                (rtt * 2).clamp(Duration::from_millis(50), Duration::from_secs(3))
            }
        }
    }
}

/// The engine's own defaults, [`BehaviourProfile::Rfc`], whatever the build's default profile.
impl SettingEngine {
    pub(crate) fn rfc_base() -> Self {
        Self {
            behaviour_profile: BehaviourProfile::Rfc,
            crypto_provider: Default::default(),
            wall_clock: None,
            timeout: Default::default(),
            data_channel: Default::default(),
            turn_allocation_refresh_interval_cap: Default::default(),
            turn_reallocation_delay: Duration::ZERO,
            candidates: Default::default(),
            ice: Default::default(),
            multicast_dns: Default::default(),
            replay_protection: Default::default(),
            sdp_session_level_fingerprints: Default::default(),
            disable_sdp_tls_id: Default::default(),
            dtls_new_association_without_ice_restart: Default::default(),
            msid_removal_ends_track: Default::default(),
            // RFC 9429 section 5.11: such an answer "MUST result in an error".
            unoffered_feedback_refused: true,
            stopping_transceiver_rejected_in_answer: Default::default(),
            dtls_use_srtp_only_with_media: Default::default(),
            accept_lowercase_fingerprints: Default::default(),
            bundle_attributes_tagged_only: Default::default(),
            max_bundle_ignored: Default::default(),
            rtcp_mux_only_in_subsequent_offers: false,
            bundle_only_sections_in_browser_form: false,
            answer_offered_formats_only: true,
            answer_ice_options: AnswerIceOptions::default(),
            unique_transport_credentials: Default::default(),
            separate_fec_sessions: false,
            explicit_rollback_only: Default::default(),
            answering_dtls_role: Default::default(),
            disable_certificate_fingerprint_verification: Default::default(),
            allow_insecure_verification_algorithm: Default::default(),
            disable_media_engine_copy: Default::default(),
            disable_media_engine_multiple_codecs: Default::default(),
            srtp_protection_profiles: Default::default(),
            dtls_cipher_suites: Default::default(),
            receive_mtu: Default::default(),
            mid_generator: Default::default(),
            sctp_max_message_size: Default::default(),
            sctp_max_receive_buffer_size: Default::default(),
            sctp_mtu: Default::default(),
            sctp_path_mtu_discovery: Default::default(),
            sctp_weighted_fair_queueing: Default::default(),
            sctp_message_interleaving: Default::default(),
            sctp_zero_checksum: Default::default(),
            sctp_max_streams: Default::default(),
            sctp_rto: Default::default(),
            sctp_max_retransmissions: Default::default(),
            sctp_handshake_timers_back_off_rto: true,
            ice_failed_without_end_of_candidates: false,
            sctp_message_size_limit_without_interleaving: Default::default(),
            data_channel_max_buffer_size: Default::default(),
            data_channel_send_before_ack: Default::default(),
            non_interactive_video: Default::default(),
            dscp_marking: Default::default(),
            srtp_key_lifetime: Default::default(),
            srtp_automatic_rekeying_off: Default::default(),
            srtp_rekeying_both_at_warning: Default::default(),
            ignore_rid_pause_for_recv: Default::default(),
            rid_pause_marks: Default::default(),
            published_rid_id_grammar: Default::default(),
            rollback_content_ignored: Default::default(),
            rollback_resets_offer_created_senders: Default::default(),
            rejected_rids_kept_in_offers: Default::default(),
            remote_rid_renegotiation_refused: Default::default(),
            strict_sdp_attribute_grammar: Default::default(),
            w3c_simulcast_answer: Default::default(),
            nominated_candidates_only: Default::default(),
            msid_appdata_omitted: Default::default(),
            video_receive_limits: Default::default(),
            codec_video_receive_limits: Default::default(),
            unnegotiated_header_extensions: Default::default(),
            ssrc_per_clock_rate: Default::default(),
            // Train 11's fields, at the value the derive gave them.
            msid_appdata_change_renews_track: Default::default(),
            source_departure_ends_track: Default::default(),
            rtp_timeout_mutes_track: Default::default(),
            bundled_fingerprints_agree: Default::default(),
            cryptex_required_on_every_bundled_section: Default::default(),
            dtls_connection_id_length: Default::default(),
            dtls_alpn_off: Default::default(),
            dtls_session_resumption: Default::default(),
            write_ssrc_attributes_for_simulcast: Default::default(),
            ecn: Default::default(),
            ecn_initiation: Default::default(),
            ecn_without_signalling: Default::default(),
            streams: Default::default(),
            turn_tls: Default::default(),
            ecn_marking: Default::default(),
            rtcp_session_omitted: Default::default(),
            strict_rtcp_validity: Default::default(),
            unnegotiated_rtcp_feedback: Default::default(),
            ice_options_in_media_sections: Default::default(),
            default_ice_pacing_omitted: Default::default(),
            dtls_flight_interval: Default::default(),
            // Master's fields of the train-12 merge, at the value the derive gave them.
            own_payload_types_in_answers: Default::default(),
            audio_redundancy: Default::default(),
            // Train 13's field (sctp-15), at the value the derive gave it.
            sctp_inbound_reassembly_limit: Default::default(),
            // Train 13's field (mt-9), at the value the derive gave it.
            dtls_new_association_on_previous_addresses: Default::default(),
        }
    }

    /// The behaviour profile the settings were last set to: the build's default profile
    /// ([`BehaviourProfile::compiled_default`]) unless
    /// [`SettingEngineBuilder::with_behaviour_profile`] named another. Settings changed after it
    /// keep their own values.
    pub fn behaviour_profile(&self) -> BehaviourProfile {
        self.behaviour_profile
    }
}

/// Every setting at the default of [`BehaviourProfile::default()`]: the RFC defaults, or
/// Chrome's with the `chrome-defaults` cargo feature (see [`BehaviourProfile`]).
impl Default for SettingEngine {
    fn default() -> Self {
        SettingEngineBuilder(Self::rfc_base())
            .with_behaviour_profile(BehaviourProfile::default())
            .build()
    }
}

impl SettingEngine {
    /// The crypto provider configured on this engine, if any.
    ///
    /// `None` means no provider has been set, so building a peer connection will resolve the
    /// feature-selected built-in.
    ///
    /// Callers assembling additional components around a peer connection — an async wrapper's
    /// TURN client, for instance — read the provider from here and pass it to
    /// [`with_crypto_provider`](SettingEngineBuilder::with_crypto_provider) before building, so the whole
    /// connection provably shares one provider instead of resolving a second.
    pub fn crypto_provider(&self) -> Option<&Arc<dyn RTCCryptoProvider>> {
        self.crypto_provider.as_ref()
    }

    /// Set crypto provider on this engine.
    #[doc(hidden)]
    pub fn set_crypto_provider(&mut self, crypto_provider: Arc<dyn RTCCryptoProvider>) {
        self.crypto_provider = Some(crypto_provider);
    }

    /// Returns the multicast DNS configuration.
    pub fn multicast_dns(&self) -> &MulticastDNS {
        &self.multicast_dns
    }

    /// Returns the configured maximum interval between TURN allocation Refresh requests.
    ///
    /// `None` preserves the TURN client's default cadence of half the lifetime advertised by
    /// the server.
    pub fn turn_allocation_refresh_interval_cap(&self) -> Option<Duration> {
        self.turn_allocation_refresh_interval_cap
    }

    /// The `rid-id` grammar received lines are read with
    /// ([`SettingEngineBuilder::with_published_rid_id_grammar`]).
    pub(crate) fn rid_id_grammar(&self) -> sdp::attribute::RidIdGrammar {
        if self.published_rid_id_grammar {
            sdp::attribute::RidIdGrammar::Published
        } else {
            sdp::attribute::RidIdGrammar::Corrected
        }
    }

    /// How long after the release of one of its TURN allocations over UDP the engine waits
    /// before it allocates again from the same local address to the same server
    /// ([`SettingEngineBuilder::with_turn_reallocation_delay`]; zero by default).
    pub fn turn_reallocation_delay(&self) -> Duration {
        self.turn_reallocation_delay
    }

    /// The SOFTWARE of the ICE agent's STUN messages, in the form of
    /// [`ice::agent::agent_config::AgentConfig::software`] (`None`: its default, empty: none);
    /// see [`SettingEngineBuilder::with_ice_software`].
    pub(crate) fn ice_agent_software(&self) -> Option<String> {
        self.ice
            .software
            .as_ref()
            .map(|software| software.clone().unwrap_or_default())
    }

    /// The SOFTWARE of the server-reflexive Binding requests the engine's gatherer sends (RFC
    /// 8489 section 14.14: a request SHOULD carry it), resolved: the ICE agent's default
    /// ([`ice::agent::DEFAULT_SOFTWARE`]) unless [`SettingEngineBuilder::with_ice_software`]
    /// says otherwise, and `None` (no attribute) for `with_ice_software(None)` or an empty text.
    pub(crate) fn srflx_software(&self) -> Option<String> {
        match &self.ice.software {
            None => Some(ice::agent::DEFAULT_SOFTWARE.to_owned()),
            Some(Some(software)) if !software.is_empty() => Some(software.clone()),
            Some(_) => None,
        }
    }

    /// The SOFTWARE of the requests of the TURN clients the engine runs, in the form of
    /// [`turn::client::ClientConfig::software`] (empty: none); see
    /// [`SettingEngineBuilder::with_ice_software`].
    pub(crate) fn turn_software(&self) -> String {
        match &self.ice.software {
            None => turn::client::DEFAULT_SOFTWARE.to_owned(),
            Some(software) => software.clone().unwrap_or_default(),
        }
    }

    /// Whether an ICE restart discards the local candidates gathered by the previous generation.
    ///
    /// Set through
    /// [`with_discard_local_candidates_during_ice_restart`](SettingEngineBuilder::with_discard_local_candidates_during_ice_restart),
    /// where the reasoning lives.
    ///
    /// Read by the layer that owns the sockets, because the two decisions are one decision.
    /// Discarding the old candidates is only necessary when the transport under them is being
    /// replaced, and replacing that transport is only safe when the candidates naming it are
    /// discarded — so an async wrapper treats this as "the sockets are replaced on restart" and
    /// rebinds them, rather than exposing a second switch the two halves could disagree on.
    pub fn discard_local_candidates_during_ice_restart(&self) -> bool {
        self.candidates.discard_local_candidates_during_ice_restart
    }

    /// The ICE credentials configured on this engine.
    ///
    /// Both empty (the default) means every peer connection generates fresh random
    /// credentials when its ICE agent is created.
    pub fn ice_credentials(&self) -> (&str, &str) {
        (
            self.candidates.username_fragment.as_str(),
            self.candidates.password.as_str(),
        )
    }

    /// Set ICE credentials on this engine.
    #[doc(hidden)]
    pub fn set_ice_credentials(&mut self, username_fragment: String, password: String) {
        self.candidates.username_fragment = username_fragment;
        self.candidates.password = password;
    }
}

/// Fluent registry for [`SettingEngine`].
///
/// Mirrors [`RTCConfigurationBuilder`](crate::peer_connection::configuration::RTCConfigurationBuilder),
/// so a peer connection is configured in one style throughout rather than switching between a
/// fluent registry and a sequence of `&mut self` setters.
///
/// [`build`](Self::build) is infallible: every setting is either always valid or normalised on
/// the way in, so there is no failure mode to report.
#[derive(Default)]
pub struct SettingEngineBuilder(SettingEngine);

impl SettingEngineBuilder {
    /// A registry with every setting at its default: that of [`BehaviourProfile::default()`],
    /// the RFC defaults unless the `chrome-defaults` cargo feature is on in the build.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets every setting a [`BehaviourProfile`] governs to the profile's value, as the table
    /// `docs/behaviour-profiles.md` lists them; settings the profile does not govern keep
    /// theirs. A setting changed after this call keeps the value it is given.
    ///
    /// The same profile goes to [`MediaEngine::for_profile`](crate::peer_connection::configuration::media_engine::MediaEngine::for_profile),
    /// from which
    /// [`register_default_interceptors`](crate::peer_connection::configuration::interceptor_registry::register_default_interceptors)
    /// takes it, so that the whole peer connection follows one profile.
    ///
    /// ```
    /// use rtci::peer_connection::configuration::BehaviourProfile;
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_behaviour_profile(BehaviourProfile::Chrome)
    ///     .build();
    /// assert_eq!(setting_engine.behaviour_profile(), BehaviourProfile::Chrome);
    /// ```
    pub fn with_behaviour_profile(self, profile: BehaviourProfile) -> Self {
        let mut builder =
            crate::peer_connection::configuration::behaviour_profile::apply_to_setting_engine(
                self, profile,
            );
        builder.0.behaviour_profile = profile;
        builder
    }

    /// Selects the cryptographic provider used by peer connections built with this setting engine.
    ///
    /// The provider is resolved once at peer-connection construction and shared with ICE, DTLS,
    /// SRTP, certificate, and fingerprint operations. Different peer connections may select
    /// different providers in the same process.
    pub fn with_crypto_provider(mut self, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        self.0.crypto_provider = Some(provider);
        self
    }

    /// The wall-clock time the peer connection pairs with the instant it is built at, for the
    /// wall-clock values it writes itself: the `o=` session version of its descriptions (RFC
    /// 8866 section 5.2: "it is RECOMMENDED that a timestamp be used", seconds since 1900),
    /// the timestamps of its receivers' synchronization and contributing sources, and the NTP
    /// times of the RTCP session the peer connection installs when its interceptor registry
    /// has none.
    ///
    /// Without it the system clock is read: once when the peer connection is built (for the
    /// session version), at the first packet received (for the source timestamps), and the
    /// RTCP session takes the process-wide anchor
    /// ([`SystemInstant::shared`](shared::time::SystemInstant::shared)). Give one
    /// for a run under virtual time that is the same every time; with a seeded crypto provider
    /// ([`with_crypto_provider`](Self::with_crypto_provider), whose `random()` gives the
    /// `o=` session id) the `o=` line is then the same in every run.
    pub fn with_wall_clock(mut self, wall_clock: shared::time::SystemInstant) -> Self {
        self.0.wall_clock = Some(wall_clock);
        self
    }

    /// Overrides the default SRTP protection profiles.
    ///
    /// SRTP profiles define the encryption algorithms used for media streams.
    /// Only override this if you need specific security requirements or
    /// compatibility with non-standard implementations.
    ///
    /// # Parameters
    ///
    /// * `profiles` - List of SRTP protection profiles to use
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use specific SRTP profile
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_protection_profiles(vec![
    ///         SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ///     ])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtp_protection_profiles(mut self, profiles: Vec<SrtpProtectionProfile>) -> Self {
        self.0.srtp_protection_profiles = profiles;
        self
    }

    /// Restricts the DTLS cipher suites offered during the handshake.
    ///
    /// An empty list (the default) uses the WebRTC default set: the `dtls` crate's built-in
    /// suites without AES-256-CBC-SHA (AES-128-GCM and ChaCha20-Poly1305; browsers negotiate
    /// GCM). List a CBC suite here to offer it. The default offers **both** ECDHE_ECDSA and
    /// ECDHE_RSA suites. That is deliberate — the local
    /// certificate is not known when the list is compiled — but it means a remote peer may
    /// select an ECDHE_RSA suite that an ECDSA certificate cannot satisfy, and the
    /// handshake then stalls with the connection stuck in `Connecting`.
    ///
    /// Certificates generated by this crate are ECDSA (P-256), so an application that does
    /// not supply its own RSA certificate can pin the ECDSA suites and remove that
    /// possibility:
    ///
    /// ```
    /// use dtls::cipher_suite::CipherSuiteId;
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_cipher_suites(vec![
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    ///     ])
    ///     .build();
    /// ```
    ///
    /// The order is a preference order. Every suite named must be one the `dtls` crate
    /// implements, or building the transport fails with `ErrInvalidCipherSuite`; a list
    /// that filters down to nothing usable fails with `ErrNoAvailableCipherSuites`.
    pub fn with_dtls_cipher_suites(mut self, cipher_suites: Vec<CipherSuiteId>) -> Self {
        self.0.dtls_cipher_suites = cipher_suites;
        self
    }

    /// Caps the interval between TURN allocation Refresh requests.
    ///
    /// By default, TURN allocations are refreshed at half the lifetime advertised by the server.
    /// A shorter cap can keep an otherwise idle client-to-server NAT mapping active. Values below
    /// one second are rounded up by the TURN client.
    pub fn with_turn_allocation_refresh_interval_cap(mut self, cap: Duration) -> Self {
        self.0.turn_allocation_refresh_interval_cap = Some(cap);
        self
    }

    /// Waits `delay` after the release of one of the engine's TURN allocations over UDP has
    /// ended before allocating again on the same 5-tuple (the same local address to the same
    /// server address), e.g. a restart with new TURN credentials and one UDP socket.
    ///
    /// The engine always waits for the server's answer to the release (its Refresh of
    /// LIFETIME 0) before it allocates on that 5-tuple again: until then the allocation is
    /// the 5-tuple's and an Allocate is refused with 437 (RFC 8656 section 7.2), after which
    /// the client leaves the server alone for two minutes (section 7.4). RFC 8656 section 8.2
    /// has the server delete the allocation at once, so zero (the default) is the RFC's
    /// behaviour. Some servers keep the 5-tuple a little longer after answering: coturn turns
    /// a requested lifetime of zero into a one-second timer (`refresh_relay_connection`) and
    /// answers 437 until it fires; two seconds is enough there. It does not cover a new peer
    /// connection on the socket of one that was closed: the new one does not know of the
    /// old one's release (see the README, "re-allocating on the same socket after a release").
    pub fn with_turn_reallocation_delay(mut self, delay: Duration) -> Self {
        self.0.turn_reallocation_delay = delay;
        self
    }

    /// Configures ICE timeout behavior for connection health monitoring.
    ///
    /// These timeouts control when ICE transitions between connection states
    /// and when keepalive packets are sent. Adjust these for different network
    /// conditions:
    /// - Increase for unstable networks (mobile, satellite)
    /// - Decrease for low-latency applications
    ///
    /// # Parameters
    ///
    /// * `disconnected_timeout` - Duration without activity before considered disconnected (default: 5s)
    /// * `failed_timeout` - Duration after disconnected before considered failed (default: 25s)
    /// * `keep_alive_interval` - How often to send keepalives when idle (default: 2s)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Conservative settings for mobile networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_timeouts(
    ///         Some(Duration::from_secs(10)),  // Longer before disconnected
    ///         Some(Duration::from_secs(40)),  // Longer before failed
    ///         Some(Duration::from_secs(5)),   // Less frequent keepalives
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §16 - Timers](https://datatracker.ietf.org/doc/html/rfc8445#section-16)
    pub fn with_ice_timeouts(
        mut self,
        disconnected_timeout: Option<Duration>,
        failed_timeout: Option<Duration>,
        keep_alive_interval: Option<Duration>,
    ) -> Self {
        self.0.timeout.ice_disconnected_timeout = disconnected_timeout;
        self.0.timeout.ice_failed_timeout = failed_timeout;
        self.0.timeout.ice_keepalive_interval = keep_alive_interval;
        self
    }

    /// Configures the DCEP handshake timeout for in-band data channels.
    ///
    /// Off by default (RFC 8832 has no such timeout; see [`DataChannel::dcep_handshake_timeout`]).
    /// A channel whose `DATA_CHANNEL_ACK` has not arrived in time gets an error and is closed.
    ///
    /// # Parameters
    ///
    /// * `timeout` - Maximum time to wait for the peer's `DATA_CHANNEL_ACK`,
    ///   or `None` to disable the timeout.
    pub fn with_dcep_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.data_channel.dcep_handshake_timeout = timeout;
        self
    }

    /// Configures ICE connection attempt behavior, including number of connection attempts
    /// per candidate, and the amount of time between connection attempts.
    ///
    /// The default settings configure ICE to attempt to connect a candidate for up to 1.4 seconds.
    ///
    /// # Parameters
    ///
    /// * `check_interval` - The delay between each connection attempt (default: 200 ms)
    /// * `max_binding_requests` - Maximum number of connection attempts per candidate (default: 7)
    pub fn with_ice_connection_attempts(
        mut self,
        check_interval: Option<Duration>,
        max_binding_requests: Option<u16>,
    ) -> Self {
        self.0.timeout.ice_check_interval = check_interval;
        self.0.timeout.ice_max_binding_requests = max_binding_requests;
        self
    }

    /// Sets minimum wait time before accepting host candidates.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_host_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_host_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting server reflexive candidates.
    ///
    /// Server reflexive candidates are discovered through STUN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_srflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_srflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting peer reflexive candidates.
    ///
    /// Peer reflexive candidates are discovered during connectivity checks.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_prflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_prflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting relay candidates.
    ///
    /// Relay candidates are provided by TURN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_relay_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_relay_acceptance_min_wait = t;
        self
    }

    /*todo:
    /// set_udp_network allows ICE traffic to come through Ephemeral or UDPMux.
    /// UDPMux drastically simplifying deployments where ports will need to be opened/forwarded.
    /// UDPMux should be started prior to creating PeerConnections.
    pub fn with_udp_network(mut self, udp_network: UDPNetwork) -> Self {
        self.0.udp_network = udp_network;
    }*/

    /// webrtc-extensions 7 `icecandidatepairnominate`, cancelable: with `true`, the
    /// controlling agent proposes the pair it picked to nominate
    /// (`RTCPeerConnectionEvent::OnIceCandidatePairNominate`) and nominates it only when the
    /// application accepts (`RTCPeerConnection::resolve_candidate_pair_nomination`); a
    /// declined pair is not nominated and checks go on. Off by default (an event nobody
    /// cancels).
    pub fn with_candidate_pair_proposals(mut self, proposals: bool) -> Self {
        self.0.candidates.candidate_pair_proposals = proposals;
        self
    }

    /// Configures ICE Lite mode.
    ///
    /// In ICE Lite mode, the agent only responds to connectivity checks
    /// but does not initiate them. This is typically used by servers that
    /// have public IP addresses and don't need full ICE functionality.
    ///
    /// # Parameters
    ///
    /// * `lite` - `true` to enable ICE Lite, `false` for full ICE
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable ICE Lite for a publicly accessible server
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_lite(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §2.7 - Lite Implementation](https://datatracker.ietf.org/doc/html/rfc8445#section-2.7)
    pub fn with_lite(mut self, lite: bool) -> Self {
        self.0.candidates.ice_lite = lite;
        self
    }

    /// Restricts candidate gathering to specific network types.
    ///
    /// This reduces the number of candidates gathered, which can speed up
    /// connection establishment and reduce SDP size. Useful when you know
    /// certain network types won't work in your deployment.
    ///
    /// # Parameters
    ///
    /// * `candidate_types` - List of allowed network types (e.g., UDP4, UDP6, TCP4)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use ice::network_type::NetworkType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only use IPv4 UDP (most common case)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4])
    ///     .build();
    ///
    /// // Or allow both IPv4 and IPv6 UDP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4, NetworkType::Udp6])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_network_types(mut self, candidate_types: Vec<NetworkType>) -> Self {
        self.0.candidates.ice_network_types = candidate_types;
        self
    }

    /*todo:
    /// set_interface_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain network interfaces from ICE. Which may be
    /// useful if you know a certain interface will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_interface_filter(mut self, filter: InterfaceFilterFn) -> Self {
        self.0.candidates.interface_filter = Arc::new(Some(filter));
        self
    }


    /// set_ip_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain ip from ICE. Which may be
    /// useful if you know a certain ip will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_ip_filter(mut self, filter: IpFilterFn) -> Self {
        self.0.candidates.ip_filter = Arc::new(Some(filter));
    }*/

    /// Configures 1:1 NAT IP mapping for cloud deployments.
    ///
    /// This is essential for WebRTC servers running on cloud instances (e.g., AWS EC2)
    /// that have a private IP address but are accessible via a public IP through 1:1 NAT.
    ///
    /// # Parameters
    ///
    /// * `ips` - List of external/public IP addresses
    /// * `candidate_type` - How to advertise the public IPs:
    ///   - `RTCIceCandidateType::Host`: Replace private IP with public IP (mDNS disabled)
    ///   - `RTCIceCandidateType::Srflx`: Add public IP as server reflexive candidate
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtci::peer_connection::transport::RTCIceCandidateType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // AWS EC2: Private IP 10.0.1.5, Elastic IP 54.123.45.67
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Host,
    ///     )
    ///     .build();
    ///
    /// // Or use Srflx to keep private IP available
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Srflx,
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// - With `Host` type, the private IP is not advertised to the peer
    /// - With `Srflx` type, both private and public IPs are available
    /// - Cannot use STUN servers when using `Srflx` type
    /// - Cannot use with mDNS when using `Host` type
    ///
    /// # How it applies
    ///
    /// The sans-I/O engine gathers no candidates: the mapping is applied to the host
    /// candidates the application adds with `add_local_candidate`. With `Host` a mapped host
    /// candidate is announced on the public address (it stays bound to the local one); with
    /// `Srflx` a server-reflexive candidate on the public address is announced beside it. Each
    /// entry is `"<public ip>"` or `"<public ip>/<local ip>"`. An invalid list, `Host` with
    /// mDNS `QueryAndGather`, or a type the candidate policy excludes fails peer connection
    /// creation.
    pub fn with_nat_1to1_ips(
        mut self,
        ips: Vec<String>,
        candidate_type: RTCIceCandidateType,
    ) -> Self {
        self.0.candidates.nat_1to1_ips = ips;
        self.0.candidates.nat_1to1_ip_candidate_type = candidate_type;
        self
    }

    /// Sets the DTLS role to use when answering an offer.
    ///
    /// The DTLS role determines whether this peer acts as a DTLS client
    /// (initiating the handshake) or server (waiting for handshake). Normally
    /// this is negotiated automatically, but you can override it for debugging
    /// or compatibility with non-compliant implementations.
    ///
    /// # Parameters
    ///
    /// * `role` - DTLS role to use:
    ///   - `DTLSRole::Client`: Act as DTLS client, send ClientHello
    ///   - `DTLSRole::Server`: Act as DTLS server, wait for ClientHello
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(Error)` if role is not Client or Server
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtci::peer_connection::transport::RTCDtlsRole;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force this peer to always act as DTLS client when answering
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_answering_dtls_role(RTCDtlsRole::Client)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8842 - DTLS for WebRTC](https://datatracker.ietf.org/doc/html/rfc8842)
    pub fn with_answering_dtls_role(mut self, role: RTCDtlsRole) -> Self {
        // Deliberately unvalidated. `Unspecified` and `Auto` are not errors here: both
        // consumers already handle them — `to_connection_role()` maps `Unspecified` to
        // `ConnectionRole::Unspecified`, which the answer path detects and replaces with
        // `DEFAULT_DTLS_ROLE_ANSWER`, and the role-selection `match` falls through to the
        // ICE-derived default. Rejecting them contradicted behaviour that already worked.
        self.0.answering_dtls_role = role;
        self
    }

    /// Sets the timeout for multicast DNS resolution.
    pub fn with_multicast_dns_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.multicast_dns.timeout = timeout;
        self
    }

    /// set_ice_multicast_dns_mode controls if ice queries and generates mDNS ICE Candidates
    ///
    /// The default is [`MulticastDnsMode::QueryOnly`]: a remote host candidate with a
    /// `<uuid>.local` name (as browsers send) is resolved with an mDNS query, and the
    /// connection's own host candidates go out with their addresses
    /// (draft-ietf-mmusic-mdns-ice-candidates section 3.2.1, step 3: "Otherwise, resolve the
    /// candidate using mDNS"). The query datagrams leave through `poll_write` to
    /// 224.0.0.251:5353; a name that gets no answer is ignored when the query ends (step 5),
    /// logged at debug. To turn resolution off, so that no query is made and remote `.local`
    /// candidates are ignored at once, pass [`MulticastDnsMode::Disabled`]; the peer's checks
    /// from behind such a name can still connect as a peer-reflexive candidate (section 5.3).
    pub fn with_multicast_dns_mode(mut self, multicast_dns_mode: MulticastDnsMode) -> Self {
        self.0.multicast_dns.mode = multicast_dns_mode;
        self
    }

    /// set_ice_multicast_dns_host_name sets a static HostName to be used by ice instead of generating one on startup
    /// This should only be used for a single PeerConnection. Having multiple PeerConnections with the same HostName will cause
    /// undefined behavior
    pub fn with_multicast_dns_local_name(mut self, local_name: String) -> Self {
        self.0.multicast_dns.local_name = local_name;
        self
    }

    /// Sets the local IP address to use for multicast DNS.
    pub fn with_multicast_dns_local_ip(mut self, local_ip: Option<IpAddr>) -> Self {
        self.0.multicast_dns.local_ip = local_ip;
        self
    }

    /// Sets static ICE credentials for reproducible sessions.
    ///
    /// By default, ICE generates random credentials (ufrag/password) for each
    /// session. Setting static credentials allows for signalless WebRTC or
    /// reproducible testing environments.
    ///
    /// # Parameters
    ///
    /// * `username_fragment` - ICE username fragment (ufrag)
    /// * `password` - ICE password
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set static credentials for reproducible testing
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_credentials(
    ///         "test_ufrag".to_string(),
    ///         "test_password".to_string(),
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Only use static credentials in controlled environments. Random credentials
    /// provide better security for production deployments.
    pub fn with_ice_credentials(mut self, username_fragment: String, password: String) -> Self {
        self.0.candidates.username_fragment = username_fragment;
        self.0.candidates.password = password;
        self
    }

    /// Disables DTLS certificate fingerprint verification.
    ///
    /// **Warning**: Disabling fingerprint verification removes a critical
    /// security check and should only be used for testing or debugging.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to disable verification, `false` to enable
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only for testing/debugging!
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_certificate_fingerprint_verification(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_disable_certificate_fingerprint_verification(mut self, is_disabled: bool) -> Self {
        self.0.disable_certificate_fingerprint_verification = is_disabled;
        self
    }

    /// Allows insecure signature verification algorithms.
    ///
    /// Some signature algorithms are known to be vulnerable or deprecated.
    /// This setting allows their use for compatibility with legacy systems.
    ///
    /// **Warning**: Only enable this if absolutely necessary for compatibility.
    ///
    /// # Parameters
    ///
    /// * `is_allowed` - `true` to allow insecure algorithms, `false` to disallow
    pub fn with_allow_insecure_verification_algorithm(mut self, is_allowed: bool) -> Self {
        self.0.allow_insecure_verification_algorithm = is_allowed;
        self
    }

    /// Sets the DTLS replay protection window size.
    ///
    /// The replay protection window prevents attackers from re-sending captured
    /// packets. Larger windows protect against more packet reordering but use
    /// more memory. Set to 0 to disable (not recommended).
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Increase window for high-latency or reordering networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_replay_protection_window(128)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 6347 §4.1.2.6 - Anti-Replay](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6)
    pub fn with_dtls_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.dtls = n;
        self
    }

    /// Sets the SRTP replay protection window size.
    ///
    /// SRTP replay protection prevents replay attacks on encrypted media packets.
    /// Adjust the window size based on expected packet reordering in your network.
    ///
    /// The default is 1024 packets. A NACK retransmission sent without RTX reuses the lost
    /// packet's sequence number and arrives after every packet sent since, so a window smaller
    /// than the packets sent during a few NACK rounds refuses late repairs as too old.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // A wider window for a high packet rate
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_replay_protection_window(4096)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 3711 §3.3.2 - Replay Protection](https://datatracker.ietf.org/doc/html/rfc3711#section-3.3.2)
    pub fn with_srtp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtp = n;
        self
    }

    /// Sets the SRTCP replay protection window size.
    ///
    /// SRTCP replay protection applies to RTCP control packets. Usually
    /// a smaller window is sufficient since RTCP packets are less frequent.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Smaller window sufficient for RTCP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtcp_replay_protection_window(64)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtcp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtcp = n;
        self
    }

    /// Allows gathering of loopback candidates.
    ///
    /// By default, loopback candidates (127.x.x.x, ::1) are not gathered per
    /// RFC 8445. However, some VM configurations map public IPs to the loopback
    /// interface, making this necessary.
    ///
    /// # Parameters
    ///
    /// * `allow_loopback` - `true` to gather loopback candidates, `false` to skip
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable for certain VM configurations
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_include_loopback_candidate(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// This is non-standard behavior per [RFC 8445 §5.1.1.1](https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.1).
    /// Use with caution.
    ///
    /// # Not read by this engine
    ///
    /// The sans-I/O engine gathers no candidates (the application adds them), so this value is
    /// stored for API compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: the sans-I/O engine gathers no candidates; add a loopback candidate \
                with `add_local_candidate` instead"
    )]
    pub fn with_include_loopback_candidate(mut self, allow_loopback: bool) -> Self {
        self.0.candidates.include_loopback_candidate = allow_loopback;
        self
    }

    /// Discards previously gathered local candidates when an ICE restart is applied.
    ///
    /// By default the restarted generation keeps its local candidates, which avoids re-gathering
    /// addresses that are usually still valid. [RFC 8445 §9] describes a restart as flushing all
    /// state except the roles and gathering anew, so keeping them is an optimisation rather than
    /// the specified behaviour — it is sound only while the underlying sockets outlive the
    /// restart.
    ///
    /// Set this when they do not. If the transport rebinds its sockets as part of recovery — for
    /// example an application that replaces its UDP sockets after the platform invalidated them —
    /// the retained candidates name addresses nothing is bound to any more. Connectivity checks
    /// are then written for a local address with no socket behind it and silently go nowhere, so
    /// the restarted generation exchanges credentials successfully and never leaves `Checking`.
    ///
    /// Only the previous generation's candidates are discarded. Those added while the restart
    /// is staged (an answerer's between `set_remote_description` of the restart offer and
    /// `set_local_description` of its answer, an offerer's between `create_offer` and its
    /// `set_local_description`) are the new generation's: the restart keeps them and the
    /// answer lists them (see [`RTCPeerConnection::add_local_candidate`](crate::peer_connection::RTCPeerConnection::add_local_candidate)).
    ///
    /// # Parameters
    ///
    /// * `discard` - `true` to drop local candidates on restart, `false` (default) to keep them
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Pairs with a transport that rebinds its sockets during ICE restart.
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_discard_local_candidates_during_ice_restart(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §9 - ICE Restarts](https://datatracker.ietf.org/doc/html/rfc8445#section-9)
    ///
    /// [RFC 8445 §9]: https://datatracker.ietf.org/doc/html/rfc8445#section-9
    pub fn with_discard_local_candidates_during_ice_restart(mut self, discard: bool) -> Self {
        self.0
            .candidates
            .discard_local_candidates_during_ice_restart = discard;
        self
    }

    /// Allows connectivity checks to loopback and / or link-local remote addresses.
    ///
    /// Remote candidates are chosen by the peer. By default a loopback remote candidate
    /// (`127.0.0.0/8`, `::1`) is paired only with a loopback local candidate, and a link-local
    /// one (`169.254.0.0/16`, `fe80::/10`, which includes cloud metadata services) only with a
    /// link-local local candidate, so a remote peer cannot make this host send checks to its
    /// own services or its link's metadata address. Candidates that are never a unicast
    /// destination (unspecified, multicast, broadcast, port 0) are dropped regardless
    /// ([RFC 8445 §5.1.1.1]).
    ///
    /// [RFC 8445 §5.1.1.1]: https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.1
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// // Pair loopback remote candidates with any local candidate; keep link-local ones scoped.
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_remote_candidate_scopes(true, false)
    ///     .build();
    /// ```
    pub fn with_remote_candidate_scopes(mut self, loopback: bool, link_local: bool) -> Self {
        self.0.candidates.allow_loopback_remote_candidates = loopback;
        self.0.candidates.allow_link_local_remote_candidates = link_local;
        self
    }

    /// Whether the first mDNS query for a remote `.local` candidate waits a random 20 to 120
    /// ms (RFC 6762 section 5.2). On by default; `false` sends it at once.
    pub fn with_multicast_dns_first_query_delay(mut self, delay: bool) -> Self {
        self.0.multicast_dns.first_query_delay = Some(delay);
        self
    }

    /// Whether the mDNS answers to a query of more than one question (an A and an AAAA
    /// question for a published name, as browsers ask) wait a random 20 to 120 ms (RFC 6762
    /// section 6.3). On by default; `false` answers a query about the engine's own names only
    /// at once.
    pub fn with_multicast_dns_multi_question_delay(mut self, delay: bool) -> Self {
        self.0.multicast_dns.multi_question_delay = Some(delay);
        self
    }

    /// Declares that the application hands every datagram of its mDNS socket to `handle_read`
    /// with the datagram's destination address in `local_addr` (`IP_PKTINFO` /
    /// `IPV6_PKTINFO`): the mDNS group's (`224.0.0.251:5353`, `[ff02::fb]:5353`) for one that
    /// arrived by multicast, the host's own for one sent to it by unicast. A unicast arrival
    /// is then held to RFC 6762's rules for it (a query is answered by unicast and only to an
    /// on-link sender, section 5.5; a response is taken only when a recent question asked for
    /// a unicast response, section 6). Off by default.
    pub fn with_multicast_dns_destination_reported(mut self, reported: bool) -> Self {
        self.0.multicast_dns.destination_reported = reported;
        self
    }

    /// Makes the first mDNS query for a name ask for a unicast response (the QU bit, RFC 6762
    /// section 5.4; draft-ietf-mmusic-mdns-ice-candidates section 3.2.1). Off by default: a
    /// unicast response reaches only one of the sockets bound to port 5353 on a host (RFC 6762
    /// section 15.1). Use it with
    /// [`with_multicast_dns_destination_reported`](Self::with_multicast_dns_destination_reported)
    /// when the application's socket is the only one.
    pub fn with_multicast_dns_unicast_response(mut self, unicast: bool) -> Self {
        self.0.multicast_dns.unicast_response = unicast;
        self
    }

    /// Shares one limit on mDNS messages between peer connections
    /// (draft-ietf-mmusic-mdns-ice-candidates section 7.1: the limit is the implementation's).
    /// Give every peer connection of the process a clone of one `MdnsRateLimit`. Without it
    /// each peer connection has a limit of its own.
    pub fn with_multicast_dns_rate_limit(mut self, limit: ice::mdns::MdnsRateLimit) -> Self {
        self.0.multicast_dns.rate_limit = Some(limit);
        self
    }

    /// With mDNS `QueryAndGather`: what a host candidate becomes when the name of its address
    /// cannot be registered, because the application can send no mDNS for the address's
    /// family (`RTCPeerConnection::set_multicast_dns_publishing`) or the agent holds the most
    /// names it can (64).
    ///
    /// Off, the default, is draft-ietf-mmusic-mdns-ice-candidates section 3.1.1: "the ICE
    /// agent SHOULD still provide mDNS candidates in step 6 even if the local network does not
    /// support mDNS or mDNS registration fails in step 4". The candidate goes out under a
    /// `<uuid>.local` name that is never published: its address is not written, and a page
    /// cannot tell from the candidates whether mDNS works on the host.
    ///
    /// On, the connection fails closed: no host candidate for that address at all (UDP or
    /// TCP), so nothing the peer cannot resolve is offered; the server-reflexive and relayed
    /// candidates of the address are still gathered. The literal address is written in
    /// neither case.
    pub fn with_multicast_dns_fail_closed(mut self, fail_closed: bool) -> Self {
        self.0.multicast_dns.fail_closed = fail_closed;
        self
    }

    /// With mDNS `QueryAndGather`: leave unwrapped a host address that the gathering before
    /// the current ICE generation showed to be public. Off by default, in every behaviour
    /// profile; in the other mDNS modes it changes nothing.
    ///
    /// draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.2: "If the STUN response returns
    /// the same value as the local IP address, this indicates the address is in fact public
    /// [...] once an address has been identified as public, the ICE agent MAY cache this
    /// information and skip mDNS protection for that address in future ICE gathering phases.
    /// Note that if the set of STUN servers changes, any cached information SHOULD be
    /// discarded". The address is shown public when a server-reflexive candidate (the
    /// engine's or the application's) has its base's address, that base is a host candidate
    /// of the transport (an interface address: a STUN server cannot name another), and the
    /// address is a global unicast one (`ice::mdns::is_global_unicast`: never a private,
    /// loopback, link-local, unique-local or CGNAT address, whatever the server said). The
    /// gathering that shows it is not changed (its `.local` candidate went out first, the
    /// server-reflexive candidate follows with raddr `0.0.0.0` / `::` rport 9); from the next
    /// ICE restart, host candidates on the address carry it, as long as each restart's
    /// gathering shows it again. Per transport, never shared between connections; a change of
    /// the ICE servers (`set_configuration`) forgets it.
    ///
    /// What it exposes, and to whom: an address the remote peer and the application (a web
    /// page, in a browser) already received as the server-reflexive candidate; the later host
    /// candidates add that it is the host's own interface address. Chrome's own form (it
    /// writes host addresses for a page with media permission) is a browser consent policy,
    /// not the engine's: the `Chrome` behaviour profile leaves this off.
    pub fn with_multicast_dns_expose_known_public_addresses(mut self, expose: bool) -> Self {
        self.0.multicast_dns.expose_known_public_addresses = expose;
        self
    }

    /// With mDNS `QueryAndGather`: leave unwrapped the host addresses the application marked
    /// as RFC 4941 temporary IPv6 addresses (`RTCPeerConnection::set_temporary_ipv6_addresses`;
    /// `rtci-stream-driver`'s `PeerDriver` marks them from the operating system's interface
    /// list where it reports the flag). Off by default, in every behaviour profile; in the
    /// other mDNS modes it changes nothing.
    ///
    /// Through `PeerDriver` it has an effect on Linux / Android (`IFA_F_TEMPORARY`, shown on
    /// a runner) and macOS / iOS (`IN6_IFF_TEMPORARY`; the kernel request is shown to work, a
    /// temporary address was not observed on a runner). **On Windows it has no effect**: no
    /// address flag there has been shown to tell a temporary address from the stable one, so
    /// the driver marks nothing and every address stays hidden.
    ///
    /// draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.3: "the [RFC4941] IPv6 addresses
    /// recommended for WebRTC have inherent privacy protections, namely a short lifetime and
    /// the lack of any stateful information. Accordingly, implementations MAY choose to not
    /// conceal [RFC4941] addresses with mDNS names as a tradeoff for improved peer-to-peer
    /// connectivity." The engine cannot tell a temporary address by its bits: an address not
    /// marked stays hidden, and a marked one is unwrapped only if it is a global unicast
    /// address (`ice::mdns::is_global_unicast`).
    ///
    /// What it exposes, and to whom: the temporary address, to the remote peer and the
    /// application (a web page, in a browser), for the address's lifetime; not the stable
    /// IPv6 address, nor any IPv4 one. The `Chrome` behaviour profile leaves this off (a
    /// browser's choice of what to write is its consent policy, not the engine's).
    pub fn with_multicast_dns_expose_temporary_ipv6_addresses(mut self, expose: bool) -> Self {
        self.0.multicast_dns.expose_temporary_ipv6_addresses = expose;
        self
    }

    /// Fixes the ICE tiebreaker (RFC 8445 section 5.2), which is random otherwise. It decides
    /// who keeps the controlling role when both agents claim it (section 7.3.1.1): the larger
    /// one. For reproducible sessions and tests.
    pub fn with_ice_tie_breaker(mut self, tie_breaker: u64) -> Self {
        self.0.ice.tie_breaker = Some(tie_breaker);
        self
    }

    /// Draws a new ICE tiebreaker at every ICE restart (RFC 8445 section 16.1: "The agent MAY
    /// change the number when an ICE restart occurs"). Off by default: the tiebreaker stays
    /// for the peer connection's life, as in libwebrtc. A restart that is rolled back
    /// (RFC 9429 section 5.7) gives back the tiebreaker it replaced.
    pub fn with_ice_new_tie_breaker_on_restart(mut self, new_tie_breaker: bool) -> Self {
        self.0.ice.new_tie_breaker_on_restart = new_tie_breaker;
        self
    }

    /// Which pair a controlled ICE agent uses when the controlling agent nominates more than
    /// one.
    ///
    /// The default, [`NominationAcceptance::HighestPriority`], is RFC 8445 section 8.1.1: the
    /// nominated pair with the highest priority (a nominated pair of lower priority takes over
    /// when consent is lost on the selected one). [`NominationAcceptance::Latest`] is
    /// libwebrtc's rule: the latest nomination wins (with its `NOMINATION` attribute, the
    /// highest value), whatever the pair's priority; the session then follows a browser that
    /// moves to another pair and stops answering on the one it left.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtci::ice::NominationAcceptance;
    ///
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_nomination_acceptance(NominationAcceptance::Latest)
    ///     .build();
    /// ```
    pub fn with_ice_nomination_acceptance(mut self, acceptance: NominationAcceptance) -> Self {
        self.0.ice.nomination_acceptance = acceptance;
        self
    }

    /// What the controlling ICE agent does when its nomination fails (RFC 8445 section
    /// 7.2.5.2: the transaction times out after `Rc` requests, 39.5 s at an RTO of 500 ms, or
    /// is answered with an error or from another address).
    ///
    /// The default, [`FailedNomination::FailChecklist`], is RFC 8445 section 7.2.5.3.4: the
    /// pair and the checklist fail, and with them the ICE transport. Under heavy loss a whole
    /// transaction's requests or responses can be lost while the peer has accepted the
    /// nomination; the peer then stays connected until its consent expires.
    /// [`FailedNomination::Retry`] keeps the pair (it has received a success response) and
    /// nominates it again while the peer is heard from on it, for up to the consent expiry of
    /// 30 seconds of silence; then the next valid pair is nominated.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtci::ice::FailedNomination;
    ///
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_failed_nomination(FailedNomination::Retry)
    ///     .build();
    /// ```
    pub fn with_ice_failed_nomination(mut self, failed_nomination: FailedNomination) -> Self {
        self.0.ice.failed_nomination = failed_nomination;
        self
    }

    /// Whether an ICE transport whose checks have failed, or whose consent has expired, is
    /// "failed" without the indications W3C webrtc-pc 5.6.4 makes "failed" wait for, once the
    /// PAC timer (RFC 8863) has expired. `false` by default.
    ///
    /// The default is W3C webrtc-pc 5.6.4: "failed" is a transport that "has finished
    /// gathering, received an indication that there are no more remote candidates, finished
    /// checking all candidate pairs, and all pairs have either failed connectivity checks or
    /// lost consent"; the indication is an end-of-candidates candidate
    /// (`add_remote_candidate` with an empty `candidate`), `a=end-of-candidates` in the remote
    /// description, or a remote description without `a=ice-options:trickle`, and gathering
    /// is finished when the application has added its end-of-candidates local candidate.
    /// Without them the transport is "disconnected" ("it is still gathering and/or waiting
    /// for additional remote candidates") and becomes "failed" as soon as they are in, or
    /// "checking" when a new candidate comes; `restart_ice` starts it over. An application
    /// that never relays the peer's end-of-candidates sees "disconnected", never "failed".
    ///
    /// `true` is libwebrtc's behaviour (the `Chrome` behaviour profile, row
    /// `ice.failed-without-end-of-candidates`) and the end-of-candidates fallback RFC 8863
    /// section 5 allows ("ICE agents MAY use the PAC timer to also serve as an
    /// end-of-candidates fallback"): once the PAC timer has expired (39.5 s after the checks
    /// began, with the defaults) the transport fails by the checking timeout
    /// (`with_ice_timeouts`), a failed nomination or consent expiry without them.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_failed_without_end_of_candidates(true)
    ///     .build();
    /// ```
    pub fn with_ice_failed_without_end_of_candidates(mut self, enabled: bool) -> Self {
        self.0.ice_failed_without_end_of_candidates = enabled;
        self
    }

    /// Ta, the pacing of connectivity checks (RFC 8445 section 14.2), `None` for the default
    /// of 50 ms (never under 5 ms). A value other than the default is proposed to the peer as
    /// `a=ice-pacing` (RFC 8839 section 5.5) in every description, and both agents use the
    /// higher of the two proposals.
    pub fn with_ice_pacing(mut self, ta: Option<Duration>) -> Self {
        self.0.ice.pacing = ta;
        self
    }

    /// A pacing budget this peer connection's ICE agent shares with others' (RFC 8445 section
    /// 14.2: "all agents together send no more than one transaction per 5 ms"). An application
    /// that runs several peer connections gives each the same [`ice::PacingGroup`]; without one
    /// (the default) each agent paces by its own Ta only.
    pub fn with_ice_pacing_group(
        mut self,
        group: Option<std::sync::Arc<ice::PacingGroup>>,
    ) -> Self {
        self.0.ice.pacing_group = group;
        self
    }

    /// Makes the controlling ICE agent's consent checks carry USE-CANDIDATE, as libwebrtc's
    /// do. Off by default: RFC 8445 section 7.1.2 has the attribute sent "in order to nominate
    /// a candidate pair", once (section 8.1.1), and a consent check is a plain Binding request
    /// (RFC 7675 section 5.1). Without it the agent repeats its nomination only when the peer
    /// shows it lost it (a role conflict after the nomination).
    pub fn with_ice_nomination_on_consent_checks(mut self, enabled: bool) -> Self {
        self.0.ice.nominate_on_consent_checks = enabled;
        self
    }

    /// How long an ICE consent request (RFC 7675) waits for its response, that is, how long a
    /// matching, authenticated Binding success response still renews consent.
    ///
    /// The default, [`ConsentResponseWait::Rto`], is RFC 7675 section 5.1: "a time based on
    /// the estimated round-trip time (RTT) [...] with an allowance for variation in network
    /// delay", here `Rm` (16) times the candidate pair's RTO (RFC 8489 section 6.2.1, RFC
    /// 6298), which is 8 seconds at least and grows with the round-trip time the responses
    /// show, and never longer than the consent expiry (30 seconds). A path whose round trip
    /// rises, even from milliseconds to seconds at once, keeps its consent: a response that
    /// takes long is still taken, and makes the next requests wait longer.
    ///
    /// [`ConsentResponseWait::Fixed`] is a fixed wait; libwebrtc's is 60 seconds
    /// (`kConnectionResponseTimeout`), which takes a response whatever the round trip was.
    ///
    /// Either way consent expires 30 seconds after the last response that renewed it.
    ///
    /// ```
    /// use std::time::Duration;
    /// use rtci::ice::ConsentResponseWait;
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_consent_response_wait(ConsentResponseWait::Fixed(Duration::from_secs(60)))
    ///     .build();
    /// ```
    pub fn with_ice_consent_response_wait(mut self, wait: ConsentResponseWait) -> Self {
        self.0.ice.consent_response_wait = wait;
        self
    }

    /// What a STUN Binding request that fails the ICE short-term credential check gets.
    ///
    /// The default, [`UnauthenticatedRequests::Reject`], is RFC 8489 section 9.1.3: 400 (Bad
    /// Request) without MESSAGE-INTEGRITY or USERNAME, 401 (Unauthenticated) for an unknown
    /// username or a MESSAGE-INTEGRITY that does not match. The responses are rate limited,
    /// never longer than the request, and unsigned. [`UnauthenticatedRequests::Drop`] answers
    /// nothing (what this crate did before).
    pub fn with_ice_unauthenticated_requests(mut self, requests: UnauthenticatedRequests) -> Self {
        self.0.ice.unauthenticated_requests = requests;
        self
    }

    /// Accepts data (DTLS, SRTP) only from the selected candidate pair's remote address.
    ///
    /// Off by default: RFC 8445 section 12.2 has an agent "prepared to receive data on any of
    /// the candidates provided in the most recent candidate exchange", and data is accepted
    /// from the remote candidate of any valid pair (one a connectivity check of this agent
    /// succeeded on). A peer that sends before it nominates, or from a pair it moved to, is
    /// then heard. Turning this on restores the fork's hardening: everything from another
    /// address is dropped before DTLS sees it.
    pub fn with_ice_data_from_selected_pair_only(mut self, enabled: bool) -> Self {
        self.0.ice.data_from_selected_pair_only = enabled;
        self
    }

    /// Lets data be sent on the best valid candidate pair before a pair is selected (RFC 8445
    /// section 12.1: "An ICE agent MAY send data on any valid pair before selected pairs have
    /// been produced"). Off by default. With it a DTLS server answers a ClientHello that
    /// arrives before the nomination does.
    pub fn with_ice_data_before_nomination(mut self, enabled: bool) -> Self {
        self.0.ice.send_data_before_nomination = enabled;
        self
    }

    /// Pairs a local candidate as soon as it is added, before the application has it to
    /// trickle. Off by default: RFC 8838 section 10 ("A Trickle ICE agent MUST NOT pair a local
    /// candidate until it has been trickled to the remote party"), so a local candidate is
    /// paired once the application has taken its `OnIceCandidateEvent` from
    /// [`poll_event`](crate::sansio::Protocol::poll_event), or once a local description is
    /// set (it lists the candidates gathered so far), whichever comes first. Turning this on
    /// restores the earlier behaviour: checks may leave on a candidate the peer has not
    /// heard of yet, which it then learns as peer-reflexive.
    pub fn with_ice_pairing_before_candidates_are_conveyed(mut self, enabled: bool) -> Self {
        self.0.ice.pair_before_conveyed = enabled;
        self
    }

    /// The SOFTWARE attribute (RFC 8489 section 14.14) of the STUN messages the peer
    /// connection sends: the ICE agent's connectivity checks (consent checks and nominations
    /// included) and its success responses to the peer's, the server-reflexive Binding
    /// requests the engine's gatherer sends to the configuration's `stun:` / `stuns:` servers,
    /// and the requests of the TURN clients the engine runs for its `turn:` / `turns:`
    /// servers, over UDP, TCP, TLS and DTLS (Allocate, Refresh, CreatePermission, ChannelBind,
    /// ConnectionBind).
    ///
    /// Without this call the ICE agent sends `rtci-ice` and its version
    /// ([`ice::agent::DEFAULT_SOFTWARE`]) and the TURN clients `rtci-turn` and its version
    /// ([`turn::client::DEFAULT_SOFTWARE`]): RFC 8489 sections 6.1 and 6.3.1.1, requests and
    /// responses "SHOULD" carry one. `Some(text)` sends `text` in all of them. `None` (or an
    /// empty text) sends no SOFTWARE attribute at all, for an application that must not put
    /// an implementation fingerprint on the wire (section 16.1.2: "Implementers SHOULD
    /// make usage of the SOFTWARE attribute a configurable option"). The gatherer's Binding
    /// requests carry the ICE agent's text. The agent's error responses, the consent checks it keeps up on the previous generation's path during a
    /// restart, keepalive indications and TURN Send indications carry none in any case.
    ///
    /// `text` is fewer than 128 characters and at most 509 bytes (section 14.14); building the
    /// peer connection with a longer one fails with `ErrAttributeSizeOverflow`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// // No SOFTWARE attribute in any STUN message of the peer connection.
    /// let _setting_engine = SettingEngineBuilder::new().with_ice_software(None).build();
    /// ```
    pub fn with_ice_software(mut self, software: Option<String>) -> Self {
        self.0.ice.software = Some(software);
        self
    }

    /// [`Self::with_ice_software`] with "never called" expressible: `None` restores each
    /// stack's own SOFTWARE text, `Some(software)` is `with_ice_software(software)`. For the
    /// behaviour profiles, whose `Rfc` value is the uncalled state.
    pub(crate) fn ice_software_choice(mut self, software: Option<Option<String>>) -> Self {
        self.0.ice.software = software;
        self
    }

    /// Sets a filter asked about every remote candidate's address (an mDNS candidate's once it
    /// resolves) before the ICE agent holds it; `false` drops the candidate, so no check is ever
    /// sent there. Use it to apply the host's own network policy to peer-chosen destinations.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::sync::Arc;
    ///
    /// // Drop every remote candidate on a loopback address.
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_remote_address_filter(Arc::new(|addr: std::net::SocketAddr| {
    ///         !addr.ip().is_loopback()
    ///     }))
    ///     .build();
    /// ```
    pub fn with_remote_address_filter(mut self, filter: RemoteAddressFilter) -> Self {
        self.0.candidates.remote_address_filter = Some(filter);
        self
    }

    /// Sets the embedder's address policy for ICE, one predicate over a socket address, the
    /// direction it would be used in and the purpose ([`ice::AddressPurpose`]), asked at every
    /// point where an address enters the ICE agent or the peer connection:
    ///
    /// - the source of every datagram, of ICE-TCP stream data and of an ICE-TCP connection
    ///   (inbound): what comes from a refused source is dropped before the ICE agent, DTLS or
    ///   the media see it (no STUN response, no peer-reflexive candidate, no consent, no pair,
    ///   no DTLS record or packet taken); a connection the driver accepted from it is refused;
    /// - remote candidates, signalled or resolved from mDNS (outbound): one on a refused
    ///   address is never held or paired; `add_remote_candidate` treats it as W3C webrtc-pc
    ///   4.4.2 "administratively prohibited" (it succeeds, nothing is sent there);
    /// - peer-reflexive sources (inbound): a refused one is not learned and not answered;
    /// - STUN and TURN server addresses after resolution (outbound): a refused one is skipped,
    ///   as if it had failed, and is sent nothing.
    ///
    /// The default allows everything and changes nothing. It composes with
    /// [`Self::with_remote_address_filter`] (outbound remote candidates only, kept as it was)
    /// and with the "relay" ICE transport policy: under "relay" plus a policy that refuses
    /// private or host addresses, no datagram leaves from or goes to such an address.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::ice::{AddressPurpose, IceAddressPolicy};
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::net::IpAddr;
    ///
    /// // Nothing to or from private, loopback or link-local addresses; servers anywhere.
    /// let policy = IceAddressPolicy::new(|addr, _direction, purpose| {
    ///     let private = match addr.ip() {
    ///         IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
    ///         IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
    ///     };
    ///     purpose == AddressPurpose::StunTurnServer || !private
    /// });
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_address_policy(policy)
    ///     .build();
    /// ```
    pub fn with_ice_address_policy(mut self, policy: IceAddressPolicy) -> Self {
        self.0.candidates.address_policy = policy;
        self
    }

    /// Controls where DTLS fingerprints are placed in SDP.
    ///
    /// By default (`true`) they are in every media section, as RFC 9429 section 5.2.1 has it:
    /// "Attributes that SDP permits to be at either the session level or the media level
    /// SHOULD generally be at the media level even if they are identical" (browsers write
    /// them there too). `false` puts one at session level, which the same section allows
    /// ("implementations MAY choose to aggregate attributes at the session level").
    ///
    /// # Parameters
    ///
    /// * `sdp_media_level_fingerprints` - `true` for media-level, `false` for session-level
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // One fingerprint at session level
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sdp_media_level_fingerprints(false)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sdp_media_level_fingerprints(mut self, sdp_media_level_fingerprints: bool) -> Self {
        self.0.sdp_session_level_fingerprints = !sdp_media_level_fingerprints;
        self
    }

    /// Leaves the `a=tls-id` attribute (RFC 8842 section 4) out of offers and answers.
    ///
    /// By default every offer carries the DTLS association's `tls-id` on its first m-section
    /// (the BUNDLE tag), and an answer carries one when the offer did: the value stays the same
    /// while the association is kept and changes when a new one is asked for. Peers that do not
    /// know the attribute ignore it. Set `true` only for a peer that cannot take an unknown
    /// attribute. A received `a=tls-id` is read either way.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_sdp_tls_id(true)
    ///     .build();
    /// ```
    pub fn with_disable_sdp_tls_id(mut self, is_disabled: bool) -> Self {
        self.0.disable_sdp_tls_id = is_disabled;
        self
    }

    /// Accepts a remote description that asks for a new DTLS association without an ICE
    /// restart.
    ///
    /// By default (`false`) a peer connection follows RFC 9429: a re-offer, or the answer to
    /// one, whose `a=tls-id` differs from the one in use "MUST be part of an ICE restart"
    /// (section 5.8.3), and an answer that changes the remote fingerprint or `tls-id`
    /// without an ICE restart is an error (section 5.11); `set_remote_description` refuses
    /// it. RFC 8842 section 6 asks the same over ICE ("at least one of the endpoints MUST
    /// allocate a completely new set of ICE candidates"). With `true` such a description
    /// establishes a new association on the ICE session it has (RFC 8842 section 3.1 alone),
    /// for a peer that replaces its DTLS identity on the same ICE session.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_new_association_without_ice_restart(true)
    ///     .build();
    /// ```
    pub fn with_dtls_new_association_without_ice_restart(mut self, allowed: bool) -> Self {
        self.0.dtls_new_association_without_ice_restart = allowed;
        self
    }

    /// Lets a new DTLS association run on the local transport addresses of the one it
    /// replaces.
    ///
    /// By default (`false`) this side allocates a new 3-tuple for every new DTLS association
    /// over UDP, as RFC 8842 section 5.1 asks of an offerer that needs one ("the offerer MUST
    /// allocate a new 3-tuple for the offer in such a way that the offerer can disambiguate
    /// any packets associated with the new DTLS association from any packets associated with
    /// any other DTLS association") and of an answerer when the offerer did not (section 6:
    /// "a completely new set of ICE candidates that were not recently used for any other DTLS
    /// association"). The ICE restart that comes with the new association
    /// (`renew_dtls_association`, a data-only association replaced for SRTP, or the answer to
    /// a remote offer that asks for one) discards the local
    /// candidates, even without
    /// [`with_discard_local_candidates_during_ice_restart`](Self::with_discard_local_candidates_during_ice_restart),
    /// and `add_local_candidate` refuses a UDP candidate on a transport address one of them
    /// had, with `ErrICECandidateAddressOfPreviousDtlsAssociation`: the application gathers on
    /// new ports. The engine-run TURN clients delete their allocations and allocate again.
    /// The addresses stay refused until the next ICE restart that is not for a new
    /// association.
    ///
    /// The answerer allocates whether or not the offerer did: with trickle ICE it cannot know
    /// when it answers.
    ///
    /// `true` keeps the candidates (unless
    /// `with_discard_local_candidates_during_ice_restart` is set) and accepts the previous
    /// addresses, for an application with one fixed socket whose peer allocates the new
    /// 3-tuple; packets of the previous association that arrive late then reach the new one,
    /// which drops them as records it cannot decrypt.
    ///
    /// A new association without an ICE restart
    /// ([`with_dtls_new_association_without_ice_restart`](Self::with_dtls_new_association_without_ice_restart))
    /// runs on the ICE session it has, whatever this setting says.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_new_association_on_previous_addresses(true)
    ///     .build();
    /// ```
    pub fn with_dtls_new_association_on_previous_addresses(mut self, allowed: bool) -> Self {
        self.0.dtls_new_association_on_previous_addresses = allowed;
        self
    }

    /// Ends a remote track when a later remote description lists no `a=msid` on its media
    /// section any more, while the section still sends.
    ///
    /// RFC 8830 section 3: "When a session description is updated to no longer list any
    /// 'msid' attribute on a specific media description, the recipient can signal to its
    /// application that the corresponding MediaStreamTrack has ended." Section 3.2.5 states
    /// the procedure: "If no such attribute is found, stop the MediaStreamTrack. This will set
    /// its state to 'ended'." In this API the W3C webrtc-pc object model governs the track's state (RFC 9429 defers to it), and its
    /// "process remote tracks" keeps the track, moved to the session's default stream; it is
    /// muted when the section stops sending. That is the default (`false`). With `true` the
    /// receiver's track ends ([`RTCTrackEvent::OnClose`](crate::peer_connection::event::RTCTrackEvent::OnClose)).
    /// A direction change never ends the track (RFC 8830 section 3).
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_msid_removal_ends_track(true)
    ///     .build();
    /// ```
    pub fn with_msid_removal_ends_track(mut self, ends: bool) -> Self {
        self.0.msid_removal_ends_track = ends;
        self
    }

    /// Refuses a remote answer whose media section has an `a=rtcp-fb` line its offer did not
    /// have. The default is `true` (the `Rfc`, `StrictRfc` and `Performance` behaviour
    /// profiles); the `Chrome` profile sets `false`.
    ///
    /// RFC 9429 section 5.11: "If the 'm=' section references RTCP feedback mechanisms that
    /// were not present in the corresponding 'm=' section in the offer, this indicates a
    /// negotiation problem and MUST result in an error" (RFC 4585 section 4.2: "The answerer
    /// MUST NOT add feedback parameters"). With `true`, `set_remote_description` returns
    /// [`Error::ErrAnswerDoesNotMatchOffer`](shared::error::Error::ErrAnswerDoesNotMatchOffer)
    /// for such an answer and leaves the offer pending.
    ///
    /// With `false` the answer is applied, the extra feedback is logged and never enabled,
    /// since what is negotiated is the intersection with this endpoint's own feedback for the
    /// format. That is libwebrtc's form: it raises no error for such an answer and intersects.
    /// No recorded answer of a browser or of the interop peers (Pion, aiortc, str0m,
    /// webrtc-rs 0.17) carries such a line.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// // Apply such answers as libwebrtc does.
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_unoffered_feedback_refused(false)
    ///     .build();
    /// ```
    pub fn with_unoffered_feedback_refused(mut self, refused: bool) -> Self {
        self.0.unoffered_feedback_refused = refused;
        self
    }

    /// RFC 8830 section 3: "if the application ... receives an msid with a new msid-appdata
    /// value, it SHOULD \[learn\] that a new MediaStreamTrack has been added" (section 3, the
    /// recipient "MUST" learn of a new track for new appdata in the RFC's model). In this API
    /// the W3C webrtc-pc object model governs: a receiver has one track for its lifetime
    /// (webrtc-pc 5.3), with an id the engine generates, and RFC 9429 section 5.2.1 has
    /// senders leave the appdata out. That is the default (`false`): a changed appdata changes
    /// nothing the application sees. With `true`, a remote description whose section names
    /// another appdata than the one before ends the receiver's track
    /// ([`RTCTrackEvent::OnClose`](crate::peer_connection::event::RTCTrackEvent::OnClose)) and
    /// gives the receiver a new track, announced with a track event
    /// ([`RTCTrackEvent::OnRemoteTrack`](crate::peer_connection::event::RTCTrackEvent::OnRemoteTrack)).
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_msid_appdata_change_renews_track(true)
    ///     .build();
    /// ```
    pub fn with_msid_appdata_change_renews_track(mut self, renews: bool) -> Self {
        self.0.msid_appdata_change_renews_track = renews;
        self
    }

    /// Ends a remote track when all of its SSRCs have left: an RTCP BYE for each, or each
    /// timed out (RFC 3550 section 6.3.5, the RTCP session's `SourceTimedOut`).
    ///
    /// RFC 8830 section 3: "a MediaStreamTrack ... has ended when all of its SSRCs have ended
    /// (BYE, timeout)". In this API W3C webrtc section 9.3 governs the track's state: the
    /// track is muted when its source leaves and unmuted when media arrives again, and it ends
    /// only when its transceiver stops (a port of zero included). That is the default
    /// (`false`). With `true` the receiver's track ends
    /// ([`RTCTrackEvent::OnClose`](crate::peer_connection::event::RTCTrackEvent::OnClose))
    /// once every SSRC it receives has left; one that is heard again before then has not.
    pub fn with_source_departure_ends_track(mut self, ends: bool) -> Self {
        self.0.source_departure_ends_track = ends;
        self
    }

    /// Mutes a remote track when one of its SSRCs times out (RFC 3550 section 6.3.5: nothing
    /// heard from it for five report intervals), as a BYE does. The default is `false`.
    ///
    /// W3C webrtc-pc Candidate Correction 57 (w3c/webrtc-pc PR #3082, 2025-10-23, "RTCP
    /// timeout is not a reason to mute a remote track", fixing #3077) took "or via timeout"
    /// out of section 9.3: the track is muted when an SSRC "is removed due to reception of a
    /// BYE". By default a timed-out source is forgotten (no receiver lists it) and its track
    /// stays as it is. `true` takes the form of the Recommendation of 13 March 2025 without
    /// its candidate corrections ("removed either due to reception of a BYE or via timeout").
    /// [`SettingEngineBuilder::with_source_departure_ends_track`] ends the track when all its
    /// SSRCs have left, by BYE or timeout, whatever this says.
    pub fn with_rtp_timeout_mutes_track(mut self, mutes: bool) -> Self {
        self.0.rtp_timeout_mutes_track = mutes;
        self
    }

    /// Rejects, in an answer, the m= section of a transceiver that was stopped after the
    /// offer arrived.
    ///
    /// RFC 9429 section 5.3.1: an m= section "MUST be rejected ... if the associated
    /// RtpTransceiver has been stopped". W3C webrtc-pc 5.4 `stop()` puts such a transceiver
    /// in the "stopping" state, which "will not affect createAnswer" ("to avoid problems with
    /// RFC 8843"): the section is answered `a=inactive` and rejected by the next offer. That is
    /// the default (`false`), what browsers do. With `true` the answer rejects it (port 0)
    /// and the offerer stops its transceiver when it applies the answer; the offerer's
    /// BUNDLE-tagged section keeps the W3C form, since rejecting it would take the group's
    /// transport with it.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_stopping_transceiver_rejected_in_answer(true)
    ///     .build();
    /// ```
    pub fn with_stopping_transceiver_rejected_in_answer(mut self, rejected: bool) -> Self {
        self.0.stopping_transceiver_rejected_in_answer = rejected;
        self
    }

    /// Offers the DTLS `use_srtp` extension on every association, as browsers do (the
    /// default), or, with `false`, only on one that carries SRTP media.
    ///
    /// RFC 5764 section 4.1: "The use_srtp extension MUST only be used when the data being
    /// transported is RTP or RTCP". With `false` the engine follows it: as the DTLS client it
    /// offers `use_srtp` when the session has an audio or video section, and a
    /// data-channel-only session is set up without it; when such a session gains a media
    /// section later, a new DTLS association is established for it (the offer carries a new
    /// `a=tls-id`, RFC 8842). No browser acts on that `tls-id`: Chromium, Firefox and WebKit
    /// keep the first association, so the engine's new handshake never completes and neither
    /// the media nor the data channels flow afterwards (the browser matrix's "Rust offers
    /// media", "rollback" and "glare" cells, train round 8). The browsers' form is therefore
    /// the default, and the RFC form the setting, for peers that handle `tls-id` (this engine
    /// does). (As the DTLS server the engine takes a profile whenever the client offers one.)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_use_srtp_on_every_association(true)
    ///     .build();
    /// ```
    pub fn with_dtls_use_srtp_on_every_association(mut self, on_every_association: bool) -> Self {
        self.0.dtls_use_srtp_only_with_media = !on_every_association;
        self
    }

    /// Reads lower-case hex digits in a remote `a=fingerprint`, as browsers do.
    ///
    /// RFC 8122 section 5 defines the fingerprint as upper-case hex (`2UHEX *(":" 2UHEX)`), and
    /// by default a description with anything else is refused as malformed. Set `true` for a
    /// peer that writes lower-case digits.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_lowercase_fingerprints_accepted(true)
    ///     .build();
    /// ```
    pub fn with_lowercase_fingerprints_accepted(mut self, is_accepted: bool) -> Self {
        self.0.accept_lowercase_fingerprints = is_accepted;
        self
    }

    /// Whether a remote description is refused when a bundled m= section carries
    /// `a=fingerprint` values other than its BUNDLE group's tagged section. The default is
    /// `false`.
    ///
    /// `a=fingerprint` is of the TRANSPORT multiplexing category (RFC 8859 section 4.5 and
    /// appendix A): "the attribute value MUST be taken from the m= line whose information is
    /// used to set up the underlying transport", the tagged section's (RFC 9143 section
    /// 7.1.3). By default the tagged section's fingerprints are the group's and the other
    /// bundled sections' are not used, whatever they say. `true` is a hardening beyond the
    /// RFC: every bundled section must agree with the tagged one (in the sha-256 values when
    /// there are any), as the sections outside a BUNDLE group, which share the transport,
    /// always must; otherwise the description is
    /// [`Error::ErrSessionDescriptionConflictingFingerprints`](shared::error::Error::ErrSessionDescriptionConflictingFingerprints).
    pub fn with_bundled_fingerprints_agreeing(mut self, agreeing: bool) -> Self {
        self.0.bundled_fingerprints_agree = agreeing;
        self
    }

    /// Whether a description has Cryptex for a BUNDLE group only when `a=cryptex` is at the
    /// session level or on every RTP-based m= section of the group. The default is `false`.
    ///
    /// RFC 9335 section 4 binds the writer: "If BUNDLE is in use ... and the 'a=cryptex'
    /// attribute is present for a media line, it MUST be present for all RTP-based 'm='
    /// sections belonging to the same bundle group", and this engine writes it so (at the
    /// session level). The same paragraph assigns the attribute to the TRANSPORT category
    /// (RFC 8859 section 4.5: "the software MUST pick the one that's associated with the 'm='
    /// line whose information is used for setting up the underlying transport"), and RFC 9143
    /// section 7.1.3 has an answerer and a later offerer write such attributes "only in the
    /// tagged 'm=' section". By default the reader therefore takes the group's Cryptex from
    /// its BUNDLE-tagged section, so a peer that follows RFC 9143 keeps Cryptex; a section
    /// outside any group decides by its own attribute.
    ///
    /// `true` reads strictly (the JSEP stack's earlier form): `a=cryptex` on some but not all
    /// RTP-based sections of a group, the tagged one alone included, does not negotiate
    /// Cryptex, and a `Require` policy refuses such a description.
    pub fn with_cryptex_required_on_every_bundled_section(mut self, required: bool) -> Self {
        self.0.cryptex_required_on_every_bundled_section = required;
        self
    }

    /// Whether answers and subsequent offers repeat the BUNDLE attributes (the IDENTICAL and
    /// TRANSPORT categories of RFC 8859: `a=ice-ufrag`, `a=ice-pwd`, `a=setup`, media-level
    /// `a=fingerprint`, `a=rtcp-mux`, `a=rtcp-mux-only`, `a=rtcp-rsize`, candidates) in every
    /// bundled m= section. The default is `true`.
    ///
    /// RFC 9143 section 7.1.3 (and RFC 9429 sections 5.2.2 and 5.3.1): "In a subsequent offer
    /// or in an answer ... the offerer and answerer MUST include IDENTICAL and TRANSPORT
    /// multiplexing category SDP attributes (BUNDLE attributes) only in the tagged 'm='
    /// section" and "MUST NOT include such attributes in any other bundled 'm=' section".
    /// `false` writes that form.
    ///
    /// It is not the default because no browser takes it: given an answer or a subsequent
    /// offer whose second bundled section has no `a=rtcp-mux` of its own, Chromium and WebKit
    /// refuse the description with "rtcp-mux must be enabled when BUNDLE is enabled" and
    /// Firefox with "m-section at level 1 is missing a=rtcp-mux, which is required by
    /// rtcpMuxPolicy" (browser matrix, 2026-11-22). Browsers themselves repeat the
    /// attributes.
    ///
    /// Either form is accepted from the remote side whatever this is set to: the tagged
    /// section's attributes apply to every bundled section.
    pub fn with_bundle_attributes_repeated(mut self, repeated: bool) -> Self {
        self.0.bundle_attributes_tagged_only = !repeated;
        self
    }

    /// Whether a remote offer that arrives while a local offer is pending rolls the local
    /// offer back and is applied, in one `set_remote_description` call. The default is `true`.
    ///
    /// W3C webrtc-pc section 4.4.2, the `setRemoteDescription` steps: a description of type
    /// "offer" that "is invalid for the current connection.\[\[SignalingState\]\] as described in
    /// \[RFC9429\]" has the local description set to `{type: "rollback"}` first, and is then
    /// set. This engine's
    /// `set_remote_description` is that operation, browsers perform it and "perfect
    /// negotiation" relies on it. RFC 9429 does not forbid it: its state machine (section
    /// 3.2) is kept, because the rollback is applied first (section 5.7) and the offer is
    /// then applied in `stable` (section 5.6).
    ///
    /// With `false` the layer above does the rollback: a remote offer in `have-local-offer`
    /// is refused, as RFC 9429 section 5.6 has it for a description whose type is not valid
    /// in the current state.
    ///
    /// An offer that is refused after the implicit rollback leaves the local offer pending,
    /// as if nothing had been called; one that is applied emits the `stable` and then the
    /// `have-remote-offer` signaling state.
    pub fn with_implicit_rollback(mut self, implicit_rollback: bool) -> Self {
        self.0.explicit_rollback_only = !implicit_rollback;
        self
    }

    /// Whether the bundle policy `max-bundle` is honoured as the policy RFC 9429 names
    /// `must-bundle`. The default is `true`.
    ///
    /// W3C webrtc-pc section 4.2.5 (`RTCBundlePolicy`) defines `max-bundle` ("Gather ICE
    /// candidates for only one track. If the remote endpoint is not bundle-aware, negotiate
    /// only one media track") and has no `must-bundle`; RFC 9429 section 4.1.1 introduces
    /// "an identically defined 'must-bundle' policy". So both names select the one policy:
    /// every m= section of an initial offer but the first is bundle-only.
    ///
    /// RFC 9429 section 4.1.1 also says "'max-bundle' is considered deprecated, and
    /// implementations compliant with this specification SHOULD ignore attempts by the
    /// application to select this bundle policy (although some phase-out period may be
    /// necessary to avoid application breakage)". `false` does that: a configuration with
    /// `RTCBundlePolicy::MaxBundle` then behaves as the default policy, `balanced`.
    pub fn with_max_bundle_as_must_bundle(mut self, honoured: bool) -> Self {
        self.0.max_bundle_ignored = !honoured;
        self
    }

    /// Whether a subsequent offer says `a=rtcp-mux-only` again in the m= sections it carries
    /// over from the last exchange, under the RTCP mux policy `require`. The default is
    /// `false`.
    ///
    /// Two specifications disagree here. RFC 9429 section 5.2.2, which governs a JSEP
    /// endpoint, says of such a section "The 'a=rtcp-mux-only' line MUST NOT be added", and
    /// that is the default. RFC 8858 section 4.5 says "if the offerer and answerer have
    /// previously negotiated usage of exclusive RTP/RTCP multiplexing ... the offerer SHOULD
    /// associate an SDP 'rtcp-mux-only' with the corresponding SDP media description"; `true`
    /// does that. In a BUNDLE group the attribute (IDENTICAL category, RFC 8858 section 6)
    /// is then in the tagged section, and in every bundled one when the bundle attributes
    /// are repeated ([`with_bundle_attributes_repeated`](Self::with_bundle_attributes_repeated)).
    /// New sections of an offer say it either way (RFC 9429 section 4.1.1).
    pub fn with_rtcp_mux_only_in_subsequent_offers(mut self, repeated: bool) -> Self {
        self.0.rtcp_mux_only_in_subsequent_offers = repeated;
        self
    }

    /// Whether an initial offer writes its bundle-only m= sections in the form browsers
    /// accept: each bundle-only RTP section says `a=rtcp-mux`, each bundle-only section says
    /// its BUNDLE group's ICE credentials (the tagged section's `a=ice-ufrag` and `a=ice-pwd`),
    /// and the offer, when it has a bundle-only section, carries its `a=fingerprint` lines at
    /// session level as well as in the sections with a transport. The default is `false`; the
    /// `Chrome` behaviour profile sets `true`. Later offers and answers are not affected: they
    /// have no bundle-only sections (RFC 9429 section 5.2.2).
    ///
    /// The default is the RFC form. RFC 9143 section 7.1.3: "In the initial BUNDLE offer, the
    /// offerer MUST NOT include IDENTICAL and TRANSPORT multiplexing category SDP attributes
    /// (BUNDLE attributes) in bundle-only "m=" sections", and section 9.3.1.1: "the offerer
    /// MUST include an SDP 'rtcp-mux' attribute [RFC5761] in each bundled "m=" section
    /// (excluding any bundle-only "m=" sections)" (`rtcp-mux` is IDENTICAL, RFC 8859). Chromium,
    /// WebKit and Firefox refuse that form (browser matrix, test-env run 45900172027):
    /// Chromium and WebKit with "Failed to set local answer sdp: rtcp-mux must be enabled when
    /// BUNDLE is enabled.", Firefox with "m-section at level 1 is missing a=rtcp-mux, which is
    /// required by rtcpMuxPolicy"; with `a=rtcp-mux` alone Chromium and WebKit answer a
    /// bundle-only data section with port zero (no fingerprint applies to it) and Firefox
    /// stops (run 45902077847). With `a=rtcp-mux` and the session-level fingerprints all three
    /// take the offer (45903674595), but Firefox then refuses the engine's answer to its own
    /// next offer, "Remote description indicates ICE restart but offer did not request ICE
    /// restart" (45905096237): it compares each section's credentials with the ones the section
    /// had in the current remote description, and a bundle-only section had none. Writing the
    /// later descriptions with the credentials in the tagged section only does not help:
    /// "Invalid description, no ice-ufrag attribute at level 1" (45908363443). So the
    /// credentials go into the bundle-only sections, against RFC 9429 section 5.2.1:
    /// "Bundle-only "m=" sections MUST NOT contain any ICE credentials". The `a=rtcp-mux` and
    /// ICE credential lines are the departure; the session-level
    /// fingerprints are RFC form (RFC 8122 section 5: "either a session-level or a media-level
    /// SDP attribute"; RFC 9429 section 5.2.1: the m= sections "MUST all have the same
    /// fingerprint value or values [RFC8122], or these values MUST be session-level
    /// attributes"). With the default, a browser takes no initial offer of this engine that
    /// has a bundle-only section: `max-bundle` with more than one m= section, or `balanced`
    /// with two sections of one media type.
    pub fn with_bundle_only_sections_in_browser_form(mut self, browser_form: bool) -> Self {
        self.0.bundle_only_sections_in_browser_form = browser_form;
        self
    }

    /// Whether an answer lists only formats the offer has. The default is `true` (0.3.0; it
    /// was `false` up to 0.2.x), in the `Rfc`, `Chrome` and `Performance` behaviour profiles;
    /// the `StrictRfc` profile sets `false`.
    ///
    /// With `true` (the default), an answer lists only the offered formats this endpoint
    /// supports, matched by the engine's codec-matching rules, in the offer's order, each repair
    /// format (RTX, RED, FEC) only with the primary format it repairs: the intersection, as
    /// libwebrtc (Chrome), Firefox and WebKit answer. RFC 9429 section 5.3.1: "the media formats
    /// in the answer MUST include at least one format that is present in the offer but MAY
    /// include formats that are locally supported but not present in the offer". The
    /// web-platform-tests assume it (`webrtc/protocol/h265-level-id.https.html` asserts that
    /// the offerer's sender has exactly one codec).
    ///
    /// With `false`, an answer to a section the transceiver has no codec preferences for lists
    /// those formats and then every other media format this endpoint has registered for the
    /// kind, the literal reading of the bullet before (RFC 9429 section 5.3.1: "Any currently
    /// available media formats that are not present in the current remote description MUST
    /// be added after all existing formats"; RFC 3264 section 6.1: the answer "MAY indicate
    /// additional media formats, not listed in the corresponding stream in the offer, that
    /// the answerer is willing to send or receive"). The added formats carry no repair format
    /// and no feedback, and this endpoint receives on them (RFC 3264 section 6.1: "The
    /// answerer MUST be prepared to receive media for recvonly or sendrecv streams using any
    /// media formats listed for those streams in the answer"). They are live: the offerer may
    /// switch to one (WebKit did), and they are among the offerer's send codecs (W3C
    /// [[SendCodecs]]). `docs/conformance.md` lists this default as a standing departure from
    /// that MUST sentence, with the reasons.
    ///
    /// An answer with codec preferences is not affected: it lists the preferences that were
    /// offered whatever this setting says (RFC 9429 section 5.3.1, "MUST exclude any codecs not
    /// present in the codec preferences").
    pub fn with_answer_offered_formats_only(mut self, offered_only: bool) -> Self {
        self.0.answer_offered_formats_only = offered_only;
        self
    }

    /// What an answer's `a=ice-options` line says ([`AnswerIceOptions`]). The default is
    /// [`AnswerIceOptions::AsOffered`], RFC 9429 section 5.3.1 (`Rfc` and `Performance`
    /// profiles): an answer to a browser's offer says `trickle` alone, one to an offer
    /// without the line has none. The `Chrome` profile sets
    /// [`AnswerIceOptions::TrickleAlways`], the `StrictRfc` profile
    /// [`AnswerIceOptions::Always`] (`docs/conformance/spec-issues.md` row 28).
    pub fn with_answer_ice_options(mut self, options: AnswerIceOptions) -> Self {
        self.0.answer_ice_options = options;
        self
    }

    /// Whether each transport of the connection has ICE credentials of its own (RFC 9429
    /// section 5.2.1: "Each "m=" section, provided it is not marked as bundle-only, MUST
    /// contain a unique set of ICE credentials"). The default is `false`: the transports an
    /// offer or answer adds beside the first one (the first section of each media type in a
    /// `balanced` initial offer, every section under `max-compat`, every section answered
    /// outside a BUNDLE group) take the first transport's `ice-ufrag` and `ice-pwd`, and an ICE
    /// restart gives them all one new pair. Each transport keeps its own candidates, DTLS
    /// association and SRTP keys.
    ///
    /// The default is what Pion and webrtc-rs 0.17 can take, and RFC 8839 section 5.4 allows
    /// it ("If two data streams have identical "ice-ufrag"s, they MUST have identical
    /// "ice-pwd"s"): they refuse a description whose sections carry different credentials
    /// (`ErrSessionDescriptionConflictingIceUfrag`), bundled or not, so with `true` an initial
    /// `balanced` offer with audio and video, or media and a data channel, is refused by them.
    ///
    /// Chromium takes the RFC 9429 form, `true` (the `Chrome` behaviour profile's value):
    /// libwebrtc makes a transport description with credentials of its own for each m= section
    /// of an offer and of an answer (`TransportDescriptionFactory::CreateOffer` /
    /// `CreateAnswer`, `p2p/base/transport_description_factory.cc`) and makes the sections of a
    /// BUNDLE group share the first one's (`UpdateTransportInfoForBundle`,
    /// `pc/media_session.cc`). Its offers bundle every section whatever the bundle policy
    /// (`max-compat` included: `bundle_enabled` follows `use_rtp_mux`, `pc/sdp_offer_answer.cc`),
    /// so they show one pair; its answer to an offer without BUNDLE gives each section its own
    /// (fixture `chromium--balanced-rust-s-offer-has-a-transport-per-media-type-answered-without-bundle--1-answer.sdp`).
    ///
    /// With shared credentials the transports are told apart by their local addresses only:
    /// several transports on one local socket need `true`, since the ICE username of a STUN
    /// request is then the same for each.
    pub fn with_unique_transport_credentials(mut self, unique: bool) -> Self {
        self.0.unique_transport_credentials = unique;
        self
    }

    /// Whether an offered FEC session of its own is accepted: an m= section that lists only
    /// `ulpfec`, grouped with a media section by `a=group:FEC-FR` (RFC 5956 section 4.1) or
    /// `a=group:FEC` (RFC 4756), outside the BUNDLE group, which is how RFC 5109 section 14.1
    /// sends FEC "as a separate stream": in an RTP session of its own, on a transport of its
    /// own, where the FEC stream has the SSRC of the media stream it protects (section 7.2).
    ///
    /// `false`, the default, refuses it as RFC 5109 section 14.3 lets an answerer do (the FEC
    /// section answered with port 0, the group left out), which is what RFC 8854 section 5.2
    /// asks of a WebRTC endpoint: "Answerers SHOULD reject any FEC-only "m=" lines, unless they
    /// specifically know how to handle such a thing in a WebRTC context". `true` accepts it:
    /// the answer keeps the section and repeats the group (RFC 5109 section 14.3: "the
    /// answerer simply accepts the FEC RTP session and the grouping in the offer by including
    /// the same grouping in the answer"), with the direction of the transceiver it protects.
    ///
    /// Offering one is the application's call,
    /// [`RTCPeerConnection::add_fec_session`](crate::peer_connection::RTCPeerConnection::add_fec_session),
    /// whatever this says (RFC 8854 section 5.2: such sections "SHOULD NOT be offered", so
    /// nothing offers one by itself). Both need the ULPFEC interceptors in the chain
    /// ([`configure_ulpfec_sessions`](crate::peer_connection::configuration::interceptor_registry::configure_ulpfec_sessions)).
    /// No browser understands such a section: this is for peers that implement RFC 5109 as
    /// written.
    pub fn with_separate_fec_sessions(mut self, accept: bool) -> Self {
        self.0.separate_fec_sessions = accept;
        self
    }

    /// Where `a=ice-options` (RFC 8839 section 5.6) is written: once at session level (the
    /// default, `false`), or in each m= section that carries ICE credentials (`true`), after
    /// its `a=ice-pwd`. Section 5.6 allows either ("session-level or media-level"); the options
    /// are the same (`trickle ice2`, or `ice2` for a lite agent). Chromium writes them in every
    /// section (`BuildIceOptions` from `BuildMediaDescription`, `api/webrtc_sdp.cc`), the
    /// `Chrome` behaviour profile's value. Bundled sections that leave the BUNDLE attributes to
    /// the tagged one ([`Self::with_bundle_attributes_repeated`]`(false)`) leave this one too.
    pub fn with_ice_options_in_media_sections(mut self, in_media_sections: bool) -> Self {
        self.0.ice_options_in_media_sections = in_media_sections;
        self
    }

    /// Whether `a=ice-pacing` is written while Ta is the default 50 ms. The default is `true`:
    /// RFC 8839 section 4.3.1 says a full agent "SHOULD include an 'ice-pacing' attribute" in
    /// its offers and answers. With `false` no line is written for the default, which RFC 8445
    /// section 14.2 lets a peer read as the default ("If an agent does not ... indicate a
    /// value, the default value is used"); a Ta other than the default
    /// ([`Self::with_ice_pacing`]) is written either way ("MUST indicate the proposed value").
    /// libwebrtc writes no `a=ice-pacing` (`api/webrtc_sdp.cc` has none), the `Chrome`
    /// behaviour profile's value.
    pub fn with_default_ice_pacing_stated(mut self, stated: bool) -> Self {
        self.0.default_ice_pacing_omitted = !stated;
        self
    }

    /// How the first retransmission timer of the DTLS handshake is chosen; see
    /// [`DtlsFlightInterval`]. The default is [`DtlsFlightInterval::Rfc9147`]; the `Chrome`
    /// behaviour profile takes [`DtlsFlightInterval::Libwebrtc`]. RFC 9147 section 5.8.2's
    /// 1000 ms is a SHOULD "unless implementations have deployment-specific and/or external
    /// information about the round trip time", which ICE's measurement is.
    pub fn with_dtls_flight_interval(mut self, interval: DtlsFlightInterval) -> Self {
        self.0.dtls_flight_interval = interval;
        self
    }

    // SetICETCPMux enables ICE-TCP when set to a non-nil value. Make sure that
    // NetworkTypeTCP4 or NetworkTypeTCP6 is enabled as well.
    //pub fn SetICETCPMux(&mut self, tcpMux ice.TCPMux) {
    //    self.0.iceTCPMux = tcpMux
    //}

    // SetICEProxyDialer sets the proxy dialer interface based on golang.org/x/net/proxy.
    //pub fn SetICEProxyDialer(&mut self, d proxy.Dialer) {
    //    self.0.iceProxyDialer = d
    //}

    /// Prevents the MediaEngine from being copied for each PeerConnection.
    ///
    /// By default, each PeerConnection gets a copy of the MediaEngine, allowing
    /// independent codec configurations. Disabling this allows sharing a single
    /// MediaEngine and modifying it after PeerConnection creation.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to share MediaEngine, `false` to copy (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Share MediaEngine across connections
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_copy(true)
    ///     .build();
    ///
    /// // Warning: Don't share MediaEngine between multiple PeerConnections
    /// // unless you understand the implications
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Warning
    ///
    /// When disabled, ensure you don't share the same MediaEngine between
    /// multiple PeerConnections unless you specifically intend to do so.
    ///
    /// # Not read by this engine
    ///
    /// A PeerConnection takes its `MediaEngine` by value from the builder, so it always has
    /// its own; there is no shared engine to copy or not. This value is stored for API
    /// compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: a peer connection always owns its MediaEngine (the builder takes it \
                by value), so there is no copy to disable"
    )]
    pub fn with_disable_media_engine_copy(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_copy = is_disabled;
        self
    }

    /// Disables negotiating different codecs for different media sections.
    ///
    /// By default, each media section in the SDP can negotiate different codecs,
    /// which is the spec-compliant behavior. This setting forces all media
    /// sections to use the same codecs.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to use single codec set, `false` for per-section (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force same codecs for all media sections
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_multiple_codecs(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Deprecation Note
    ///
    /// This setting is targeted for removal in a future release (4.2.0 or later).
    ///
    /// # What it changes
    ///
    /// By default every remote description adds the formats of each of its audio and video
    /// sections to the codecs the connection has negotiated, so a second video section that
    /// offers only H.264 is answered with H.264 even when the first one negotiated VP8
    /// (RFC 9429, Section 5.10). A format is kept once, under the first payload type that
    /// named it. With `true`, only the first section of each kind (in the first remote
    /// description that has one) decides the codecs, and later sections are answered from
    /// that set.
    pub fn with_disable_media_engine_multiple_codecs(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_multiple_codecs = is_disabled;
        self
    }

    /// Whether an answer numbers the formats with this endpoint's own payload types (the ones
    /// the [`MediaEngine`](crate::peer_connection::configuration::media_engine::MediaEngine)
    /// registered them with) instead of the offer's. `false` by default.
    ///
    /// RFC 3264 section 6.1: "if a particular codec was referenced with a specific payload
    /// type number in the offer, that same payload type number SHOULD be used for that codec
    /// in the answer", which is the default. An answerer may number the formats otherwise
    /// (section 5.1: "the answer might indicate different payload type numbers for the same
    /// codecs, in which case, the offerer MUST send with the payload type numbers from the
    /// answer"; a gateway to a system with fixed numbers does), and that is `true`: each
    /// format of an offer this endpoint negotiates is answered under its registered payload
    /// type (the one a description of this endpoint already gave it, once it has one), RTX
    /// (`apt`) and RED (the encodings of its fmtp) following their primaries. The endpoint
    /// then receives with its own numbers and sends with the offer's (section 6.1: the
    /// answerer "MUST use the payload type numbers from the offer, even if they differ from
    /// those in the answer").
    ///
    /// Either way each direction of a media section follows the description that governs it:
    /// what is sent carries the remote description's payload types and what is received is
    /// read with the local description's (RFC 9429 sections 5.9 to 5.11).
    pub fn with_own_payload_types_in_answers(mut self, own: bool) -> Self {
        self.0.own_payload_types_in_answers = own;
        self
    }

    /// Sets the MTU size for the receive buffer.
    ///
    /// This controls the maximum size of packets that can be received. Leave
    /// at 0 to use the default MTU (1460 bytes, equal to UDP MTU).
    ///
    /// # Parameters
    ///
    /// * `receive_mtu` - MTU size in bytes, or 0 for default
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use larger MTU for jumbo frames
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(9000)
    ///     .build();
    ///
    /// // Or use default
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(0)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Not read by this engine
    ///
    /// The sans-I/O engine reads no sockets: the application receives each datagram into its
    /// own buffer and hands it over whole, so there is no receive buffer to size. This value
    /// is stored for API compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: the sans-I/O engine reads no sockets; size the application's own \
                receive buffer instead"
    )]
    pub fn with_receive_mtu(mut self, receive_mtu: usize) -> Self {
        self.0.receive_mtu = receive_mtu;
        self
    }

    /// Sets a custom MID (media stream ID) generator function.
    ///
    /// By default, MIDs are generated automatically. This allows you to provide
    /// a custom generation scheme, useful for reducing complexity when handling
    /// SDP offer/answer collisions.
    ///
    /// # Parameters
    ///
    /// * `f` - Function that takes the highest seen numeric MID and returns a new MID string
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate MIDs with a custom prefix
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_mid_generator(|max_mid| format!("custom_{}", max_mid + 1))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// - MIDs should be generated without leaking user information (e.g., randomly)
    /// - MIDs should be 3 bytes or less for efficient RTP header extension encoding
    /// - The `isize` argument is the greatest seen _numeric_ MID (doesn't include non-numeric MIDs)
    ///
    /// # See Also
    ///
    /// - [RFC 8843 - MID](https://datatracker.ietf.org/doc/html/rfc8843)
    ///
    /// `create_offer` calls it for each transceiver that has no mid yet, then moves the
    /// argument on (to the generated mid when it is a greater number, else by one), so two
    /// new transceivers of one offer get different arguments.
    pub fn with_mid_generator(
        mut self,
        f: impl Fn(isize) -> String + Send + Sync + 'static,
    ) -> Self {
        self.0.mid_generator = Some(Arc::new(f));
        self
    }

    /// Sets the maximum message size for SCTP data channels.
    ///
    /// This controls the largest message that can be sent through a data channel.
    /// Larger messages will be fragmented or rejected depending on the configuration.
    ///
    /// # Parameters
    ///
    /// * `max_message_size` - Maximum size (Bounded or Unbounded)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtci::peer_connection::configuration::setting_engine::{
    ///     SctpMaxMessageSize, SettingEngineBuilder,
    /// };
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use default 64KB
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
    ///         SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE,
    ///     ))
    ///     .build();
    ///
    /// // Or allow larger messages
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(256 * 1024)) // 256KB
    ///     .build();
    ///
    /// // Or unbounded (uses MAX_MESSAGE_SIZE internally)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8841 §6.1 - max-message-size](https://datatracker.ietf.org/doc/html/rfc8841#section-6.1)
    pub fn with_sctp_max_message_size(mut self, max_message_size: SctpMaxMessageSize) -> Self {
        self.0.sctp_max_message_size = max_message_size;
        self
    }

    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    ///
    /// This bounds how much unacknowledged data a peer may have in flight toward this
    /// endpoint — a bandwidth-delay-product ceiling. Lowering it reduces per-connection
    /// memory (the buffer fills only under load), which matters for servers holding many
    /// connections; but a smaller window can throttle throughput on high-latency,
    /// high-bandwidth paths, where more data must be in flight to keep the pipe full.
    ///
    /// **Bounds.** RFC 9260 §3.3.2 requires an advertised initial a_rwnd of at least **1500
    /// bytes**; smaller values (including `0`) are raised to that floor here, because a
    /// sub-1500 window makes the peer reject this endpoint's INIT/INIT-ACK and the SCTP
    /// association never establishes. The window should also be **≥ the largest SCTP
    /// message this endpoint will receive** ([`SettingEngineBuilder::with_sctp_max_message_size`], default
    /// 64 KiB): a buffer smaller than one message cannot hold it for reassembly, so a
    /// full-size inbound message would stall that receive direction. `0` here is *not*
    /// "unbounded" (unlike some other knobs) — to keep the default window, leave this
    /// unset (the default is `INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub fn with_sctp_max_receive_buffer_size(mut self, size: u32) -> Self {
        // RFC 9260 §3.3.2 (INIT) and §3.3.3 (INIT ACK) forbid advertising an initial a_rwnd
        // below 1500 bytes ("The Advertised Receiver Window Credit MUST NOT be smaller than
        // 1500. A receiver of an INIT chunk with the a_rwnd value set to a value smaller than
        // 1500 MUST discard the packet [and] SHOULD send [...] an ABORT chunk."). This crate
        // enforces it in `ChunkInit::check()` (ErrInitAdvertisedReceiver1500), so a
        // sub-1500 (or 0) value would silently break the handshake. Clamp up to that floor.
        const MIN_SCTP_RECEIVE_BUFFER_SIZE: u32 = 1500;
        if size < MIN_SCTP_RECEIVE_BUFFER_SIZE {
            log::warn!(
                "sctp receive buffer size {size} is below the RFC 9260 minimum; raising to \
                 {MIN_SCTP_RECEIVE_BUFFER_SIZE} bytes"
            );
        }

        self.0.sctp_max_receive_buffer_size = Some(size.max(MIN_SCTP_RECEIVE_BUFFER_SIZE));
        self
    }

    /// Overrides the SCTP MTU: the size budget, in bytes, for each outbound DATA packet
    /// (common header plus bundled DATA chunks) this endpoint emits. A SACK keeps within it
    /// too, carrying the gap blocks and duplicate TSNs that fit. Other control packets
    /// (INIT, INIT ACK, RECONFIG, FORWARD TSN, shutdown) marshal without consulting this value.
    ///
    /// Each SCTP packet becomes one DTLS record carried in one UDP datagram, so the wire
    /// size is this value plus the DTLS record overhead (13 bytes of header and what the
    /// cipher suite adds: 24 bytes with AES-GCM, 16 with ChaCha20-Poly1305), the UDP and IP
    /// headers, and 4 bytes of TURN ChannelData framing when relayed.
    ///
    /// Left unset, the budget follows the path: RFC 8831 section 5 says the initial path MTU
    /// at the IP layer "SHOULD NOT exceed 1200 bytes for IPv4 and 1280 bytes for IPv6", so an
    /// SCTP packet starts as what is left of that under the headers of the selected candidate pair and the negotiated DTLS cipher suite
    /// (1135 bytes over IPv4 and UDP with AES-GCM, 1195 over IPv6), recomputed when ICE
    /// selects another pair. Until a pair is selected it is 1191 (the TURN-relayed IPv6
    /// budget, webrtc-rs/rtc#178). Set this only for paths with a known different budget:
    /// raise it where the path genuinely carries more (fewer, larger packets cut per-packet
    /// overhead), lower it for tunnels with an even smaller MTU. A value set here is used as
    /// it is on every path, and path MTU discovery
    /// ([`with_sctp_path_mtu_discovery`](Self::with_sctp_path_mtu_discovery)), which grows the
    /// packets from the initial size otherwise, is off.
    ///
    /// The per-chunk payload budget is derived from this value by the inverse of the
    /// default derivation (minus the 12-byte common header and 16-byte DATA chunk header,
    /// rounded down to the SCTP 4-byte chunk-padding boundary), so a single maximum-size
    /// DATA chunk always marshals within this budget. Values below 32 — the smallest
    /// representable padded DATA packet — are raised to 32 with a warning.
    pub fn with_sctp_mtu(mut self, mtu: u32) -> Self {
        self.0.sctp_mtu = Some(mtu);
        self
    }

    /// SCTP path MTU discovery (RFC 8261 section 4, RFC 8831 section 5: SCTP over DTLS
    /// "MUST" discover the path MTU without ICMP; RFC 8899 section 6.2.3 is the method).
    /// Once the association is established it confirms the initial packet size (RFC 8831
    /// section 5's 1200 / 1280-byte IP packet under the headers of the selected pair and
    /// the DTLS record) with a probe, a HEARTBEAT and a PAD chunk (RFC 4820) of exactly the
    /// size tried, then searches for larger packets up to `max_ip_packet` bytes at the IP
    /// layer (the local interface MTU; 1500, Ethernet's, by default), comes back to the
    /// initial size when the path stops carrying the larger one, and searches again every
    /// 600 seconds and after ICE selects another pair. Probes carry no data and are lost
    /// without consequence where the path is smaller. `None` turns it off: the packet size
    /// then stays the initial one. A fixed [`with_sctp_mtu`](Self::with_sctp_mtu) turns it
    /// off too.
    pub fn with_sctp_path_mtu_discovery(mut self, max_ip_packet: Option<u32>) -> Self {
        self.0.sctp_path_mtu_discovery = Some(max_ip_packet);
        self
    }

    /// Whether SCTP sends from its data channels by weighted fair queueing (RFC 8260 section
    /// 3.6), each channel's share of the bytes in proportion to its priority. On by default:
    /// RFC 8831 section 6.4 says the priorities of data channels "MUST be interpreted as
    /// weighted-fair-queuing scheduling priorities per the definition of the corresponding
    /// stream scheduler supporting interleaving in \[RFC8260\]". `false` sends the messages in
    /// the order they were written, whatever their channel, and the priority of a channel is
    /// then carried to the peer and not otherwise used.
    pub fn with_sctp_weighted_fair_queueing(mut self, enabled: bool) -> Self {
        self.0.sctp_weighted_fair_queueing = Some(enabled);
        self
    }

    /// Whether SCTP announces user message interleaving (RFC 8260). On by default: RFC 8831
    /// sections 6.1 and 6.6 say it "SHOULD be used", so that a large message on one data
    /// channel does not hold up the others. It is used when the peer announces it too;
    /// otherwise the association sends DATA chunks, and nothing else changes. `false` does
    /// not announce it, which is what a browser that has not turned it on does.
    pub fn with_sctp_message_interleaving(mut self, enabled: bool) -> Self {
        self.0.sctp_message_interleaving = Some(enabled);
        self
    }

    /// Whether SCTP announces that it accepts packets with a zero checksum (RFC 9653) and
    /// sends them to a peer that announces the same. On by default: the association runs over
    /// DTLS, whose record protection detects errors better than the CRC32c (RFC 9653 section
    /// 6, "SCTP over DTLS"), and section 5.2 says an endpoint "SHOULD use zero as the checksum"
    /// then. A peer that does not announce it gets a CRC32c on every packet, and must send
    /// one. `false` does not announce it.
    pub fn with_sctp_zero_checksum(mut self, enabled: bool) -> Self {
        self.0.sctp_zero_checksum = Some(enabled);
        self
    }

    /// The number of SCTP streams this endpoint asks for and accepts in each direction
    /// (the OS and MIS of its INIT or INIT ACK, RFC 9260 section 3.3.2). The association has
    /// the smaller of both sides' counts, which is W3C `RTCSctpTransport.maxChannels`
    /// (webrtc-pc 6.1.1): a data channel id at or above it cannot be used. Unset, the default,
    /// is 65535, as browsers ask for; a value of 0 is raised to 1.
    pub fn with_sctp_max_streams(mut self, streams: u16) -> Self {
        self.0.sctp_max_streams = Some(streams.max(1));
        self
    }

    /// The most bytes of incomplete inbound messages a data channel association holds above
    /// SCTP. SCTP gives a message it cannot hold whole out in parts (RFC 9260 section 6.9),
    /// so its receive window reopens while the message is still arriving; the data channel
    /// layer joins the parts, because a data channel delivers whole messages only.
    ///
    /// What a conforming peer can have in progress is bounded by the negotiated parameters:
    /// at most one message per stream (RFC 8260 section 2.2.2, RFC 6458 section 3.1.4), each
    /// at most the `max-message-size` this side advertised (RFC 8841 section 6.1; a larger one
    /// is dropped, as before). The handler holds at most one incomplete message per stream,
    /// so what it holds never exceeds (streams with a message in progress) ×
    /// `max-message-size`. This setting is the ceiling over that product: a peer that would
    /// take the association past it loses the data channel whose part would go over (W3C
    /// `OnError` with `data-channel-failure`, the message naming this limit; RFC 8831
    /// section 6.6: "the receiver SHOULD close the corresponding data channel"). The rest of
    /// that message is read and dropped, then the channel's stream is reset; the other
    /// channels go on.
    ///
    /// Unset, the default, is 64 MiB: 1024 concurrent messages of the default 64 KiB
    /// `max-message-size`, or 256 of the largest this engine accepts (256 KiB), far more
    /// than ordinary use keeps in flight at once, and a quarter of what a peer could pin
    /// with 65535 streams of 1 KiB each. The worst case one association holds for inbound
    /// data is then its SCTP receive buffer
    /// ([`with_sctp_max_receive_buffer_size`](Self::with_sctp_max_receive_buffer_size), 1 MiB
    /// by default) plus this limit: 65 MiB with the defaults. A value below the advertised
    /// `max-message-size` is raised to it, so that a single message that size always fits.
    pub fn with_sctp_inbound_reassembly_limit(mut self, bytes: usize) -> Self {
        self.0.sctp_inbound_reassembly_limit = Some(bytes);
        self
    }

    /// RTO.Initial, RTO.Min and RTO.Max of the SCTP association (RFC 9260 sections 6.3.1 and
    /// 16): the retransmission timeout before a round trip is measured, and its bounds. Unset,
    /// the default, is the RFC's recommendation: 1, 1 and 60 seconds. A minimum or maximum of
    /// zero is raised to a millisecond, a maximum below the minimum to the minimum.
    ///
    /// With [`Self::with_sctp_max_retransmissions`] this bounds how long the association keeps
    /// retransmitting to a peer that does not answer before it fails (W3C webrtc-pc 6.2: the
    /// data channels then fail with `sctp-failure`). At the defaults that is minutes, longer
    /// than ICE consent (30 seconds) takes to fail the path: an application that wants SCTP
    /// itself to report an unreachable peer sooner (a path ICE still thinks alive) lowers it.
    pub fn with_sctp_rto(mut self, initial: Duration, min: Duration, max: Duration) -> Self {
        self.0.sctp_rto = Some(sctp::RtoConfig { initial, min, max });
        self
    }

    /// Back to RFC 9260's RTO.Initial, RTO.Min and RTO.Max (1, 1 and 60 seconds), undoing
    /// [`Self::with_sctp_rto`] (or a profile that set them).
    pub fn without_sctp_rto(mut self) -> Self {
        self.0.sctp_rto = None;
        self
    }

    /// Association.Max.Retrans (RFC 9260 sections 8.1 and 16): how many consecutive
    /// retransmission timeouts (an unanswered HEARTBEAT counts as one) the SCTP association
    /// takes before it declares the peer unreachable and fails. Unset, the default, is the
    /// RFC's 10. See [`Self::with_sctp_rto`]. `usize::MAX` never gives up, which leaves the
    /// failure of an unreachable peer to ICE consent (RFC 7675): what libwebrtc does
    /// (`DcSctpTransport::CreateDcSctpOptions` sets `max_retransmissions` to none,
    /// `media/sctp/dcsctp_transport.cc`), the `Chrome` behaviour profile's value.
    pub fn with_sctp_max_retransmissions(mut self, limit: usize) -> Self {
        self.0.sctp_max_retransmissions = Some(limit);
        self
    }

    /// Back to RFC 9260's Association.Max.Retrans of 10, undoing
    /// [`Self::with_sctp_max_retransmissions`] (or a profile that set it).
    pub fn without_sctp_max_retransmissions(mut self) -> Self {
        self.0.sctp_max_retransmissions = None;
        self
    }

    /// Whether an expiry of the SCTP handshake timers (T1-init, T1-cookie) backs off the
    /// association's RTO, as a retransmission timeout of DATA does. On by default: RFC 9260
    /// section 5.1, "The T1-init timer and T1-cookie timer SHOULD follow the same rules given
    /// in Section 6.3" (rule E2: "set RTO = RTO * 2"), so after a handshake that lost packets
    /// the first DATA waits the backed-off RTO until a round trip is measured.
    ///
    /// `false` is libwebrtc's (dcSCTP's `t1_init_` and `t1_cookie_` in
    /// `net/dcsctp/socket/dcsctp_socket.cc` double their own 1 s), the `Chrome` behaviour
    /// profile's value: each handshake timer starts at RTO.Initial and doubles by itself,
    /// and the RTO is left alone. See `sctp::TransportConfig::with_handshake_timers_back_off_rto`.
    pub fn with_sctp_handshake_timers_back_off_rto(mut self, enabled: bool) -> Self {
        self.0.sctp_handshake_timers_back_off_rto = enabled;
        self
    }

    /// Whether a message over 16 KB is refused when the SCTP association does not interleave
    /// user messages. On by default: RFC 8831 section 6.6 says "As long as message
    /// interleaving is not supported, the sender SHOULD limit the maximum message size to
    /// 16 KB to avoid monopolization", since such a message holds up every other data channel
    /// until all of it has been sent. With the limit,
    /// [`RTCSctpTransport::max_message_size`](crate::peer_connection::transport::RTCSctpTransport::max_message_size)
    /// reports at most 16384 once the association is up without interleaving, and `send`
    /// refuses a larger message. Between two endpoints that both interleave (two of this
    /// engine, by default) the limit does not apply.
    ///
    /// `false` is what browsers do: they send messages up to the peer's `max-message-size`
    /// whether or not the association interleaves, and current browsers do not announce
    /// interleaving. An application that sends more than 16 KB at a time to a browser sets
    /// this to `false`.
    pub fn with_sctp_message_size_limit_without_interleaving(mut self, enabled: bool) -> Self {
        self.0.sctp_message_size_limit_without_interleaving = Some(enabled);
        self
    }

    /// Replaces the SCTP transport's `[[MaxBufferSize]]` with a fixed limit: `send()` refuses
    /// data that would take a channel's `bufferedAmount` above `limit` bytes
    /// (`ErrDataChannelBufferFull`). `None`, the default, is the W3C rule (webrtc-pc 6.1.1.2):
    /// the larger of the peer's `max-message-size` and this side's send buffer, 16 MiB (the
    /// spec leaves the send buffer's size to the implementation; 16 MiB is Chromium's).
    ///
    /// A smaller limit makes `send()` refuse sooner; an application that keeps
    /// `bufferedAmount` low by `bufferedAmountLowThreshold` needs none.
    pub fn with_data_channel_max_buffer_size(mut self, limit: Option<u32>) -> Self {
        self.0.data_channel_max_buffer_size = limit;
        self
    }

    /// Whether `send()` accepts data on an in-band data channel that is still "connecting",
    /// waiting for the DATA_CHANNEL_ACK of the DATA_CHANNEL_OPEN this side sent. Off by
    /// default: W3C webrtc-pc 6.2 `send()` says "If channel.\[\[ReadyState\]\] is not "open",
    /// throw an InvalidStateError", and refuses with [`Error::ErrDataChannelNotOpen`].
    ///
    /// `true` is RFC 8832 section 6: "the peer that sent the DATA_CHANNEL_OPEN message MAY
    /// start sending messages containing user data without waiting for the reception of the
    /// corresponding DATA_CHANNEL_ACK message". The data goes out ordered behind the OPEN, and
    /// a peer that implements RFC 8832 (any browser, this engine) takes it as the ACK would.
    ///
    /// [`Error::ErrDataChannelNotOpen`]: shared::error::Error::ErrDataChannelNotOpen
    pub fn with_data_channel_send_before_ack(mut self, enabled: bool) -> Self {
        self.0.data_channel_send_before_ack = enabled;
        self
    }

    /// Marks video as non-interactive for [`RTCPeerConnection::dscp`]: the AF3x codepoints of
    /// RFC 8837 Table 1 instead of the AF4x ones. RFC 8837 section 5: "Non-browser
    /// implementations of WebRTC MAY use the AF3x DSCP values for video that is known not to
    /// be interactive, e.g., all video in a WebRTC video playback application". The default
    /// is `false`: all WebRTC video is interactive.
    ///
    /// [`RTCPeerConnection::dscp`]: crate::peer_connection::RTCPeerConnection::dscp
    pub fn with_non_interactive_video(mut self, non_interactive: bool) -> Self {
        self.0.non_interactive_video = non_interactive;
        self
    }

    /// How [`RTCPeerConnection::dscp`] and the codepoint of each stream transmit
    /// ([`StreamTransmit::dscp`](shared::stream::StreamTransmit::dscp)) mark what the
    /// connection sends.
    ///
    /// [`RTCDscpMarking::Rfc8837`], the default, marks by RFC 8837 Table 1 (RFC 8835 section
    /// 4.2: implementations "SHOULD attempt to set QoS on the packets sent") and turns a media
    /// flow whose marked packets the network blocks back to Default Forwarding (RFC 8835
    /// section 4.2: "MAY turn off use of DSCP markings if it detects symptoms of unexpected
    /// behavior such as ... blocking of packets with certain DSCP markings"; see the enum).
    /// [`RTCDscpMarking::WithoutFallback`] marks and never turns back; [`RTCDscpMarking::Off`]
    /// marks nothing (Default Forwarding, DSCP 0, for every datagram), for a platform where
    /// marking is not implemented or a network known to misbehave.
    ///
    /// [`RTCPeerConnection::dscp`]: crate::peer_connection::RTCPeerConnection::dscp
    /// [`RTCDscpMarking::Rfc8837`]: crate::peer_connection::priority::RTCDscpMarking::Rfc8837
    /// [`RTCDscpMarking::WithoutFallback`]: crate::peer_connection::priority::RTCDscpMarking::WithoutFallback
    /// [`RTCDscpMarking::Off`]: crate::peer_connection::priority::RTCDscpMarking::Off
    pub fn with_dscp_marking(
        mut self,
        marking: crate::peer_connection::priority::RTCDscpMarking,
    ) -> Self {
        self.0.dscp_marking = marking;
        self
    }

    /// Sets how many packets a DTLS-SRTP master key may protect. `None`, the default, is the
    /// profile's: 2^31 for the RFC 5764 profiles (section 4.1.2), 2^48 SRTP and 2^31 SRTCP
    /// packets for the AEAD ones (RFC 7714). When a key has a sixteenth of its lifetime left
    /// the connection raises `OnSrtpKeyLifetimeExpiring` and, unless
    /// [`Self::with_srtp_automatic_rekeying`] turned it off, asks for a new DTLS association
    /// (RFC 5764 section 4.4); at the limit nothing more is protected with the key and the
    /// DTLS transport fails (`dtls-failure`, RFC 3711 section 9.2: re-key, or end the session).
    ///
    /// The re-keying has to complete before the key runs out: an offer and its answer through
    /// the application's signalling, ICE checks on new candidates and a DTLS handshake, which
    /// takes seconds on a relayed path or with loss. Its margin is the larger of two: the last
    /// sixteenth of the lifetime, and the packets the key protects, at the rate it has been
    /// used since its first packet, in the time a re-keying needs as measured on the
    /// handshake that gave the key (twice its duration: the handshake and the ICE checks
    /// before it, which take no more round trips; and one DTLS retransmission timer for a
    /// lost flight). On a slow path the second is the larger and
    /// the re-keying starts earlier than the sixteenth (the lifetime event still comes at
    /// the sixteenth). The signalling's own delay is not measured: a lifetime so short that
    /// neither margin covers it ends the session instead (a 9600-packet lifetime at 188
    /// packets a second leaves 3.2 s at the sixteenth); the connection logs a warning when
    /// the time it has left is under 2 seconds. Lifetimes shorter than the profile's are for
    /// tests and constrained deployments; size them as `16 x packet rate x re-keying time`
    /// at least.
    ///
    /// A lifetime of zero, or above the RFC 3711 limits, makes building the peer connection
    /// fail.
    pub fn with_srtp_key_lifetime(mut self, lifetime: Option<srtp::keying::KeyLifetime>) -> Self {
        self.0.srtp_key_lifetime = lifetime;
        self
    }

    /// Asks the peer to put a connection id of `length` random bytes in every protected DTLS
    /// record it sends (RFC 9146 for DTLS 1.2, RFC 9147 section 9 for DTLS 1.3). `None`, the
    /// default, sends the `connection_id` extension asking for none (RFC 9147 section 5.1).
    ///
    /// With connection ids in use the engine follows RFC 9147 sections 9 and 11: when the ICE
    /// agent's selected pair changes (a new path), a DTLS 1.3 association switches to a fresh
    /// connection id the peer provided and asks for another, so records on the new path are
    /// not linked to the old ones by their id.
    pub fn with_dtls_connection_id(mut self, length: Option<usize>) -> Self {
        self.0.dtls_connection_id_length = length;
        self
    }

    /// Whether the DTLS handshake carries Application-Layer Protocol Negotiation with the
    /// WebRTC identifiers of RFC 8833 (RFC 8835 section 3.5). The default is `true`: as the
    /// DTLS client the engine offers `webrtc` and `c-webrtc` (section 2: "A peer in the client
    /// role MUST offer both identifiers if it is not aware of a need for confidentiality"),
    /// as the server it selects `webrtc`. A peer that sends or answers no ALPN connects all
    /// the same, taken as `webrtc` (section 2). The engine never selects `c-webrtc` as the
    /// server: it cannot promise the media confidentiality that identifier stands for (a
    /// client that requires it is refused with `no_application_protocol`, and section 2 has
    /// such a client abort anyway).
    /// [`RTCPeerConnection::dtls_application_protocol`](crate::peer_connection::RTCPeerConnection::dtls_application_protocol)
    /// gives what was selected. `false` leaves the extension out.
    pub fn with_dtls_alpn(mut self, alpn: bool) -> Self {
        self.0.dtls_alpn_off = !alpn;
        self
    }

    /// Whether the DTLS transports of a connection share one DTLS session (RFC 5764 section
    /// 3). The default is `false`.
    ///
    /// With sections that are not bundled a connection has a DTLS association per transport.
    /// RFC 5764 section 3: "As an optimization, the DTLS-SRTP implementation SHOULD use the
    /// following strategy: a single DTLS association is established, and all other DTLS
    /// associations wait until that connection is established before proceeding with their
    /// handshakes. This establishes a single session and all other associations can take
    /// advantage of TLS session resumption." With `true`, when the negotiation that sets up the
    /// transports sets up more than one in the same DTLS role, the first client transport to
    /// start runs a full handshake; every other one waits until it is complete, then resumes
    /// with one of the peer's DTLS 1.3 tickets (RFC 8446 section 4.6.1). As the server, every
    /// such transport accepts, for its first handshake, a ticket another transport of the
    /// connection issued.
    ///
    /// Off by default, a standing departure from that SHOULD, because where it does anything
    /// it makes the connection slower, and with most peers it cannot do anything:
    ///
    /// - **It costs connection time.** The other transports' handshakes run after the first
    ///   one instead of beside it. Measured with three unbundled transports on links with
    ///   latency (`tests/multi_transport_rtc2rtc.rs`,
    ///   `the_session_costs_the_other_transports_the_first_handshake_on_links_with_latency`),
    ///   the time until every DTLS transport is connected: at a 100 ms round trip 453 ms
    ///   with it off, 753 ms with it on against a peer that issues no ticket (+300 ms, about
    ///   3 round trips: the whole first handshake, and nothing is resumed) and 703 ms
    ///   between two peers that have it on (+250 ms, about 2.5 round trips); at a 300 ms
    ///   round trip 1.353 s, 2.253 s (+900 ms) and 2.103 s (+750 ms). What it saves is one
    ///   signature and one signature verification per other transport, and no round trip.
    /// - **One lost datagram delays every transport.** A datagram lost on the first
    ///   handshake holds all the others back, where without the session it delays that
    ///   transport alone
    ///   (`a_datagram_lost_on_the_first_handshake_delays_every_transport_with_the_session_on`).
    /// - **No browser can take part.** A browser issues no session ticket and offers none:
    ///   libwebrtc (Chromium, Safari) sets `SSL_OP_NO_TICKET` and makes an `SSL_CTX` per
    ///   transport; Firefox's `TransportLayerDtls::Setup()` turns session tickets off
    ///   (`SSL_ENABLE_SESSION_TICKETS`, `PR_FALSE`) and the session cache too
    ///   (`SSL_NO_CACHE`). Against a browser the setting only adds the wait.
    /// - **With BUNDLE it does nothing.** A bundled connection (every browser's, and any
    ///   connection whose answer bundles its sections) has one transport: nothing waits, no
    ///   ticket is asked for or issued, and the DTLS datagrams are the same as with the
    ///   setting off.
    ///
    /// So it is for an application whose both ends are this engine, whose sections are not
    /// bundled, and for which a signature per transport matters more than about 2.5 round
    /// trips of connection time.
    ///
    /// The wait is bounded. A first handshake that does not complete holds the others back
    /// at most three of their initial flight intervals (1.2 s at the RFC 9147 400 ms; 4.5
    /// round trips where ICE measured the round trip) and never more than 3 s, after which
    /// they run full handshakes; one that fails, is closed or cannot start holds them back
    /// no longer; and no time is spent waiting for a ticket that does not come. (Until 0.2,
    /// on by default, the wait had no bound, and a peer without tickets cost two flight
    /// intervals, 800 ms, on top of the first handshake.)
    ///
    /// The certificate check is not weakened: only the first association of each transport,
    /// set up by the negotiation that set up the transports, takes part, and only when its
    /// section names the same remote fingerprints as the transport that made the session; the
    /// section's own fingerprints are checked against the certificates stored with the
    /// ticket, so a resumption for a section that names another certificate fails with
    /// `fingerprint-failure`, as a full handshake does. Nothing is shared between connections.
    /// DTLS 1.3 only, with `psk_dhe_ke` only: the PSK is combined with a fresh (EC)DHE
    /// exchange; no DTLS 1.2 session id or ticket is asked for, issued or accepted, in any
    /// configuration. A later association (SRTP re-keying, RFC 5764 section 4.4; an ICE
    /// restart with new DTLS parameters; a transport added later) and a server's later
    /// handshake on the same transport are always full handshakes. The client keeps tickets
    /// at most five minutes and drops them all once every transport taking part has started;
    /// closing the connection wipes whatever tickets are left and the keys the server side
    /// seals its tickets under.
    ///
    /// `false`: every association runs a full handshake at once, and none offers or accepts
    /// a resumption. Bundled connections (one transport) are the same either way.
    pub fn with_dtls_session_resumption(mut self, resumption: bool) -> Self {
        self.0.dtls_session_resumption = resumption;
        self
    }

    /// Whether the connection re-keys SRTP by itself before a master key's lifetime ends. The
    /// default is `true`.
    ///
    /// RFC 5764 section 4.4: "Once the key lifetime has been reached, a new DTLS session SHOULD
    /// be established" (with section 4.1.2: the keys come from the association). When a key has
    /// a sixteenth of its lifetime left (`OnSrtpKeyLifetimeExpiring`, either direction), the
    /// connection does what [`RTCPeerConnection::renew_dtls_association`] does: the
    /// negotiation-needed flag is raised, and the next offer carries a new `a=tls-id` and new
    /// ICE credentials (RFC 9429 section 5.8.3: a new association is part of an ICE restart).
    /// Media goes on under the old keys until the new handshake hands over the new ones; the
    /// SCTP association and its data channels go on over the new association (RFC 8841
    /// section 10.5). The application only has to answer `negotiationneeded` as usual.
    ///
    /// `false` leaves it to the application: it gets the event only, and at the limit the
    /// DTLS transport fails. A browser peer ignores a new `tls-id` and keeps its association,
    /// so with one the renewal does not re-key and the transport fails at the limit either way;
    /// the default lifetimes (2^31 packets and more) are not reached by a call.
    ///
    /// [`RTCPeerConnection::renew_dtls_association`]: crate::peer_connection::RTCPeerConnection::renew_dtls_association
    pub fn with_srtp_automatic_rekeying(mut self, enabled: bool) -> Self {
        self.0.srtp_automatic_rekeying_off = !enabled;
        self
    }

    /// Which side starts the automatic SRTP re-keying ([`Self::with_srtp_automatic_rekeying`])
    /// when both could. The default is `true`: the DTLS client of the current association asks
    /// for the new association at the re-keying margin (a sixteenth of a key's lifetime left,
    /// or, when that is the larger, what a re-keying needs in time at the key's packet rate:
    /// [`Self::with_srtp_key_lifetime`]); the DTLS server waits a little first, for the
    /// client's offer: at most 500 ms, and at most an eighth of the time the keys have left at
    /// the rate they are used. If no new association has come by then (or a thirty-second of
    /// the lifetime is left, if that comes first), it asks itself. The client measures its
    /// handshake from its first flight, the server from the first datagram it reads, so with
    /// the same lifetime and rate the client's margin is never the smaller: it still asks
    /// first.
    ///
    /// Two peers with the same key lifetime reach the warning at about the same packet count:
    /// if both asked at once, their re-keying offers would cross (glare), which RFC 9429
    /// section 4.1.10 has resolved by a rollback (this engine does it), at the cost of an offer
    /// made for nothing. With the short wait the client's offer usually reaches the server
    /// first and the server answers it. Lifetimes are local: the server cannot know that the
    /// client re-keys at all (a browser does not, nor an engine with re-keying off or a longer
    /// lifetime), so the wait is bounded in time and never takes more than an eighth of the
    /// margin from a re-keying that has to cross a slow path. Without packets to measure the
    /// rate by, the server does not wait.
    ///
    /// `false`: both sides ask at the warning.
    pub fn with_srtp_rekeying_dtls_client_first(mut self, client_first: bool) -> Self {
        self.0.srtp_rekeying_both_at_warning = !client_first;
        self
    }

    /// Writes the pause mark `~` of `a=simulcast` (RFC 8853 section 5.2) although RTP stream
    /// pause and resume (RFC 7728) is not negotiated: for an inactive encoding of a sender,
    /// and for a stream the offer being answered marks. The default is `false`.
    ///
    /// RFC 8853 section 5.2: "The use of [the pause mark] MUST be accompanied by support
    /// for RTP stream pause/resume \[RFC7728\] ... signaled under the same 'm=' line", and
    /// section 5.3.2: an answerer "MUST NOT" mark a stream paused when the offer shows no
    /// such support. The engine does not implement RFC 7728 and never signals it, so by
    /// default it writes no `~`: an inactive encoding is listed and not sent, and an offered
    /// `~` is answered without the mark. `true` writes the mark all the same, as libwebrtc
    /// does for inactive layers.
    pub fn with_rid_pause_marks(mut self, rid_pause_marks: bool) -> Self {
        self.0.rid_pause_marks = rid_pause_marks;
        self
    }

    /// Reads the rid-ids of received `a=rid` and `a=simulcast` lines with the grammar of RFC
    /// 8851 section 10 as published, `rid-id = 1*(alpha-numeric / "-" / "_")` of any length,
    /// instead of the corrected one. The default is `false`.
    ///
    /// Erratum 7132 (Verified 2022-10-13) corrects the grammar to `rid-id =
    /// 1*255(alpha-numeric)`, "consistent with the rules for the RtpStreamId/RepairedRtpStreamId
    /// SDES from RFC 8852 section 3", the identifier a rid is sent as. By default a received
    /// `a=rid` line whose rid-id has `-` or `_` or more than 255 characters is discarded (RFC
    /// 8851 section 6.2.2 step 1: "In the case of a syntax error, the 'a=rid' line is
    /// discarded"), and a description whose `a=simulcast` line names one is refused (RFC 9429
    /// section 5.8). `true` takes them, for a peer that still writes the published form. Rids
    /// this endpoint writes are always in the corrected form (W3C webrtc-pc addTransceiver).
    pub fn with_published_rid_id_grammar(mut self, published: bool) -> Self {
        self.0.published_rid_id_grammar = published;
        self
    }

    /// Ignores the SDP of a `rollback` description instead of refusing one that has any. The
    /// default is `false`.
    ///
    /// RFC 9429 section 4.1.10: a rollback's "contents MUST be empty", so by default
    /// `set_local_description` / `set_remote_description` refuse a rollback whose SDP is not
    /// empty (whitespace aside) and change nothing. W3C webrtc-pc `RTCSessionDescriptionInit`
    /// says the `sdp` member "is unused" for a rollback: `true` takes that form and rolls back
    /// whatever the SDP holds.
    pub fn with_rollback_content_ignored(mut self, ignored: bool) -> Self {
        self.0.rollback_content_ignored = ignored;
        self
    }

    /// Returns, on a rollback of a remote offer to receive simulcast, the sender of a
    /// transceiver that offer created, kept because a track was added to it since
    /// (`add_track`), to one encoding without a rid: the track's. The default is `false`.
    ///
    /// W3C webrtc-pc: the sender of a transceiver a remote offer creates starts with
    /// `[[LastStableRidlessSendEncodings]]` "initialized to null" ("create an RTCRtpSender");
    /// the slot is set only when an offer is applied in stable, before that transceiver
    /// exists, and a rollback restores it only "If [[LastStableRidlessSendEncodings]] is not
    /// null". So by default the sender keeps the encodings the offer proposed. WPT
    /// `webrtc/simulcast/negotiation-encodings.https.html`, "sRD(simulcast offer), addTrack,
    /// then rollback brings us back to having a single encoding" (written for
    /// w3c/webrtc-pc#2764) expects one rid-less encoding: `true` takes that form, which
    /// Firefox 161 has and Chrome 158 and Safari 27.2 do not (wpt.fyi).
    pub fn with_rollback_resets_offer_created_senders(mut self, resets: bool) -> Self {
        self.0.rollback_resets_offer_created_senders = resets;
        self
    }

    /// Keeps offering, in later offers, the simulcast streams a remote answer rejected (left
    /// out of its `a=simulcast`), as RFC 9429 section 5.2.2 writes subsequent offers. The
    /// default is `false`.
    ///
    /// W3C webrtc-pc "set the RTCSessionDescription": "If description is missing any of the
    /// previously negotiated layers, then remove the dictionaries that correspond to the
    /// missing layers from transceiver.\[\[Sender\]\].\[\[SendEncodings\]\]", and its
    /// `createOffer` adds "an a=rid send line" "for each encoding given in
    /// \[\[SendEncodings\]\]": by default the sender drops the encodings of the rejected
    /// streams, and the next offer has neither their `a=rid` lines nor their place in
    /// `a=simulcast` (the W3C "simulcast envelope ... may be narrowed ... but cannot be
    /// reexpanded"). RFC 9429 section 5.2.2: "For RtpTransceivers that are still present, the
    /// "a=rid" lines MUST stay the same" and "any "a=simulcast" line MUST stay the same".
    ///
    /// With `true`, after a remote answer the sender still sends only the streams the answer
    /// kept (RFC 8853 section 5.3.3: the offerer "MUST NOT send any RTP packets corresponding
    /// to the removed rid-ids"), and `get_parameters` lists only those, but it keeps the
    /// rejected encodings: each later offer writes their `a=rid` lines as first offered and
    /// lists them in `a=simulcast` in their first place. A rejected stream counts as paused
    /// (RFC 8853 section 5.3.4: the `send` pause marks "SHALL reflect the offerer's opinion of
    /// the current pause state"), so it is written `~rid` only where the engine writes pause
    /// marks at all ([`Self::with_rid_pause_marks`], or RFC 7728 pause negotiated); otherwise
    /// the line is the first offer's. A later answer that accepts such a stream again brings
    /// its encoding back, and it is sent (RFC 8853 section 5.3.4: offers "inside an existing
    /// session follow the same rules as for initial SDP offer"; section 5.3.3: the offerer
    /// "MAY send any of the kept "receive"-direction rid-id alternatives"). Streams a local
    /// answer leaves out are not kept: section 5.2.2 is about the offers that follow this
    /// endpoint's own.
    pub fn with_rejected_rids_kept_in_offers(mut self, kept: bool) -> Self {
        self.0.rejected_rids_kept_in_offers = kept;
        self
    }

    /// Refuses, with `InvalidAccessError`, a remote offer that asks a sender with a simulcast
    /// envelope for a stream (an `a=simulcast` `recv` rid) outside its encodings. The default
    /// is `false`.
    ///
    /// W3C webrtc-pc Candidate Correction 37 (w3c/webrtc-pc PR #2794, 2022-12-08: "Don't fail
    /// sRD(offer) over rid mismatch, just answer with unicast") removed the step of "set a
    /// session description" that failed such an offer ("This specification does not allow
    /// remotely initiated RID renegotiation"). By default the offer is applied: the sender's
    /// encodings stay, the answer leaves out "any RID not found in the corresponding
    /// transceiver's [[Sender]].[[SendEncodings]]", and applying the answer removes the
    /// encodings it does not list (all but the first when it lists none). `true` takes the form
    /// of the Recommendation of 13 March 2025 without its candidate corrections, which refused
    /// the offer ("If the description attempted to renegotiate RIDs ... reject p with a newly
    /// created InvalidAccessError"). Browsers do not refuse it (w3c/webrtc-pc#2762). A remote
    /// answer is never refused for its rids: RFC 8851 section 6.4 ignores a rid the offer
    /// lacks.
    pub fn with_remote_rid_renegotiation_refused(mut self, refused: bool) -> Self {
        self.0.remote_rid_renegotiation_refused = refused;
        self
    }

    /// Checks each attribute value of a remote description against its grammar exactly,
    /// trailing whitespace included. The default is `false`.
    ///
    /// RFC 9429 section 5.8: a line that is not well formed rejects the description, even
    /// when its value is then ignored; every attribute is checked against its grammar either
    /// way. By default white space at the end of a value is not held against it: webrtc-rs
    /// 0.17.x writes a feedback without parameters as `a=rtcp-fb:96 goog-remb ` (a trailing
    /// space, which RFC 4585 section 4.2's `rtcp-fb-param` does not allow: a space must be
    /// followed by a token), and the strict reading refuses it
    /// (`tests/media_rejection_interop.rs::test_video_only_webrtc_offerer_rtc_answerer`:
    /// "a=rtcp-fb: `96 goog-remb `"), so an engine that reads them strictly cannot answer
    /// its offers. webrtc-rs fixed it on its default branch (`rtci` commit 718d405), as Pion
    /// did in v4.1.5 (pion/webrtc#3207, PR #3218); 0.17.x still writes it. `true` is the
    /// strict RFC form.
    pub fn with_strict_sdp_attribute_grammar(mut self, strict: bool) -> Self {
        self.0.strict_sdp_attribute_grammar = strict;
        self
    }

    /// Answers simulcast as W3C webrtc-pc `createAnswer` (section 4.4.2) does, instead of
    /// RFC 8853 / RFC 8851. The default is `false`.
    ///
    /// - A remote `a=simulcast` line that names a rid-id more than once is taken with each
    ///   rid-id at its first occurrence (W3C: "identically named rids are reduced to the
    ///   first"); by default it refuses the description (RFC 8853 section 5.2: "a single rid-id
    ///   MUST NOT occur more than once per 'a=simulcast' line"; RFC 9429 section 5.8).
    /// - The `a=rid` lines of an answer carry no restrictions (W3C sets none); by default they
    ///   keep the offered ones (RFC 8851 section 6.3).
    pub fn with_w3c_simulcast_answer(mut self, w3c: bool) -> Self {
        self.0.w3c_simulcast_answer = w3c;
        self
    }

    /// Whether each `a=msid` line carries the sender's track id as its `appdata`
    /// (`a=msid:<stream id> <track id>`, RFC 8830 section 2), as browsers write it. The
    /// default is `true`: webrtc-rs 0.17 (and Pion, whose track id it is) drops a simulcast
    /// (rid) section whose `a=msid` has no appdata, as that section has no `a=ssrc` lines to
    /// name the track (`simulcast_rtc_to_webrtc_interop`), so the interoperable form is the
    /// default. `false` is RFC 9429 section 5.2.1 ("an "a=msid" line ... but omitting the
    /// "appdata" field"). Either way a remote line's appdata is read when there is one, and
    /// the recipient names the track itself when there is none (RFC 8830 section 3). The
    /// source-level `a=ssrc:<ssrc> msid:` lines carry the track id in both forms.
    pub fn with_msid_appdata(mut self, appdata: bool) -> Self {
        self.0.msid_appdata_omitted = !appdata;
        self
    }

    /// Once ICE has selected a pair, later offers list the pair's local candidate alone (RFC
    /// 8839 section 4.4.1.2.2: "The offerer MUST NOT include any other SDP "candidate"
    /// attributes in the subsequent offer"). The default is `false`: every candidate of the
    /// most recent gathering, as RFC 9429 section 5.2.2 requires of a JSEP endpoint ("for
    /// each candidate that has been gathered during the most recent gathering phase ..., an
    /// "a=candidate" line MUST be added") and browsers do.
    pub fn with_nominated_candidates_only(mut self, only: bool) -> Self {
        self.0.nominated_candidates_only = only;
        self
    }

    /// The video frame sizes this endpoint can receive, with every video codec (its decoder's
    /// limits, or a policy): descriptions state them in `a=imageattr:* recv [x=...,y=...,q=1.0]`
    /// lines of their receiving video sections (RFC 9429 section 3.6.1, RFC 6236). A range
    /// that permits no size leaves the attribute out and makes those sections not receive
    /// (`sendonly` / `inactive`). The default is none: no `a=imageattr`.
    pub fn with_video_receive_limits(
        mut self,
        limits: crate::peer_connection::sdp::RTCVideoResolutionRange,
    ) -> Self {
        self.0.video_receive_limits = Some(limits);
        self
    }

    /// The video frame sizes this endpoint can receive with one codec (`mime_type`, such as
    /// `video/VP9`), instead of those of [`Self::with_video_receive_limits`]: codecs with
    /// different limits get one `a=imageattr` line per payload type (RFC 9429 section 3.6.1).
    pub fn with_codec_video_receive_limits(
        mut self,
        mime_type: &str,
        limits: crate::peer_connection::sdp::RTCVideoResolutionRange,
    ) -> Self {
        self.0
            .codec_video_receive_limits
            .retain(|(codec, _)| !codec.eq_ignore_ascii_case(mime_type));
        self.0
            .codec_video_receive_limits
            .push((mime_type.to_owned(), limits));
        self
    }

    /// Sends the header extension elements an application puts in a packet whose id is not
    /// negotiated for the sender, as the fork did before. The default is `false`.
    ///
    /// RFC 8285 section 4.1.2: "the local identifier ... MUST be one that has been negotiated"
    /// for an element that appears in a stream, so by default `RTCRtpSender::write_rtp` takes
    /// such an element out of the packet (with a trace log) and sends the rest. `true` passes
    /// them through.
    pub fn with_unnegotiated_header_extensions(mut self, pass_through: bool) -> Self {
        self.0.unnegotiated_header_extensions = pass_through;
        self
    }

    /// Whether a sender's stream moves to a new SSRC when the application writes a packet
    /// with a negotiated codec of another clock rate. The default is `false`: one SSRC for
    /// every clock rate.
    ///
    /// RFC 7160 section 4.1: "An RTP Sender with RTCP turned on MUST use a different SSRC for
    /// each different clock rate. An RTCP BYE MUST be sent and a new SSRC MUST be used if the
    /// clock rate switches back to a value already seen in the RTP stream." With `true`, a
    /// packet written with such a codec (Opus at 48 kHz, then PCMU at 8 kHz, on one audio
    /// sender) goes out as a new SSRC, the encoding's SSRC from then on; the stream it left
    /// stays in the RTCP session and its sender report follows the new one's in the next
    /// compound packet; a return to a rate used before sends a BYE for the SSRC that used it
    /// and takes another new one. Comfort noise and telephone events ride the stream as they
    /// are. `false` keeps one SSRC for every clock rate (RFC 7160 section 4.2 allows it only
    /// with RTCP off).
    ///
    /// `false` is the default because libwebrtc's receivers (Chromium, WebKit) do not follow
    /// the new SSRC: the browser interop matrix's RFC-form cells saw their track stay on the
    /// signalled SSRC and stop counting packets at the switch, in both offer directions, while
    /// Firefox followed. Turn it on for receivers known to follow (another `rtci` peer
    /// connection does).
    pub fn with_ssrc_per_clock_rate(mut self, ssrc_per_clock_rate: bool) -> Self {
        self.0.ssrc_per_clock_rate = ssrc_per_clock_rate;
        self
    }

    /// When a local audio stream whose section negotiated RED (RFC 2198) is sent in RED, each
    /// packet carrying a copy of the one before. The default is
    /// [`AudioRedundancy::WhenPreferred`](interceptor::AudioRedundancy::WhenPreferred): only
    /// when the remote description lists RED ahead of the stream's codec. Received RED is
    /// taken apart in every case.
    ///
    /// RFC 3264 sections 5.1 and 6.1: the formats of an m= line are "listed in order of
    /// preference", and the sender "SHOULD use the format with the highest preference". The
    /// default codecs offer RED after Opus, as Chromium and WebKit do, and those browsers
    /// answer it after Opus too; libwebrtc sends RED only when it precedes the codec it
    /// protects. So by default a call with them, or with another `rtci` peer connection,
    /// carries plain Opus: RED is negotiated, not used. RFC 8854 recommends Opus's in-band FEC
    /// for Opus (section 4.1) and FEC only for the loss observed or when the application asks
    /// (section 8).
    ///
    /// [`AudioRedundancy::Always`](interceptor::AudioRedundancy::Always) is that request: RED
    /// whenever negotiated, whatever the order. It about doubles the audio bitrate (a copy of
    /// the previous packet in each). [`AudioRedundancy::Never`](interceptor::AudioRedundancy::Never)
    /// sends the codec even to a peer that prefers RED.
    ///
    /// Applies to the RED interceptor the connection installs
    /// ([`configure_audio_redundancy_with`](crate::peer_connection::configuration::interceptor_registry::configure_audio_redundancy_with));
    /// a registry that fills [`Slot::Redundancy`](interceptor::Slot::Redundancy) itself
    /// decides with its own interceptor.
    pub fn with_audio_redundancy(mut self, audio_redundancy: interceptor::AudioRedundancy) -> Self {
        self.0.audio_redundancy = audio_redundancy;
        self
    }

    /// With [`Self::with_rid_pause_marks`], controls whether the `~` an offer puts on a
    /// stream it asks to receive is left out of the answer's `send` list.
    ///
    /// # Parameters
    ///
    /// * `ignore_rid_pause_for_recv` - `true` to leave the mark out, `false` to repeat it
    pub fn with_ignore_rid_pause_for_recv(mut self, ignore_rid_pause_for_recv: bool) -> Self {
        self.0.ignore_rid_pause_for_recv = ignore_rid_pause_for_recv;
        self
    }

    /// Controls whether to ignore SSRC attribute in SDP's sendonly or sendrecv for simulcast
    ///
    /// # Parameters
    ///
    /// * `write_ssrc_attributes_for_simulcast` - `true` to write, `false` to ignore
    pub fn with_write_ssrc_attributes_for_simulcast(
        mut self,
        write_ssrc_attributes_for_simulcast: bool,
    ) -> Self {
        self.0.write_ssrc_attributes_for_simulcast = write_ssrc_attributes_for_simulcast;
        self
    }

    /// Explicit Congestion Notification (RFC 3168) and L4S (RFC 9331) on RTP media.
    ///
    /// Turn this on when the application's socket layer carries ECN both ways:
    ///
    /// * **Receive**: each datagram handed to `handle_read` names the codepoint it arrived with
    ///   in [`TransportContext::ecn`](shared::TransportContext::ecn) (from the `IP_RECVTOS` /
    ///   `IPV6_RECVTCLASS` control message; `None` for Not-ECT).
    /// * **Send**: each datagram `poll_write` returns names the codepoint to set in
    ///   [`TransportContext::ecn`](shared::TransportContext::ecn) (`IP_TOS` / `IPV6_TCLASS`;
    ///   `None` for Not-ECT).
    ///
    /// With it on, the RTP packets of a stream whose codec negotiated RFC 8888 congestion
    /// control feedback (`a=rtcp-fb:<pt> ack ccfb`, see `configure_congestion_control_feedback`)
    /// and whose section negotiated ECN (`a=ecn-capable-rtp`, RFC 6679 section 6.1; see
    /// [`with_ecn_without_signalling`](Self::with_ecn_without_signalling)) are sent ECT: a
    /// sender marks only where the receiver reports the CE marks back. The codepoint is ECT(0)
    /// unless the receiver asks for ECT(1) (RFC 6679 section 7.3.1; see
    /// [`with_ecn_marking`](Self::with_ecn_marking) for L4S's ECT(1)). As RFC 8888 section 7
    /// requires, the stream first initiates ECN as RFC 6679
    /// section 7.2.1 has it (one packet in ten a probe, until the feedback shows the probes
    /// arrive ECT), then marks every packet (RTX included), and stops when the feedback shows
    /// the path clears the marking or drops marked packets (section 7.4); see
    /// [`with_ecn_initiation`](Self::with_ecn_initiation) and
    /// [`EcnValidation`](interceptor::EcnValidation). STUN, DTLS, SCTP and RTCP are never
    /// marked. Inbound RTP streams count their ECT(1) and CE receptions
    /// (`packetsReceivedWithEct1`, `packetsReceivedWithCe`) and outbound ones their ECT(1)
    /// packets (`packetsSentWithEct1`); with it off those members are left out of the stats,
    /// since the engine cannot see the IP header itself. Off by default.
    pub fn with_ecn(mut self, enabled: bool) -> Self {
        self.0.ecn = enabled;
        self
    }

    /// How a stream with ECN on ([`with_ecn`](Self::with_ecn)) starts marking:
    /// [`EcnInitiation::RtpAndRtcp`](interceptor::EcnInitiation::RtpAndRtcp), the default,
    /// probes first (RFC 6679 section 7.2.1, the method RFC 8888 section 7 requires);
    /// [`EcnInitiation::LeapOfFaith`](interceptor::EcnInitiation::LeapOfFaith) marks every
    /// packet from the first, as browsers that send L4S do (RFC 6679 section 7.2.3). Failure
    /// detection applies to both.
    pub fn with_ecn_initiation(mut self, initiation: interceptor::EcnInitiation) -> Self {
        self.0.ecn_initiation = initiation;
        self
    }

    /// The ECT codepoint a stream with ECN on ([`with_ecn`](Self::with_ecn)) marks its
    /// packets with: [`EcnMarking::Rfc6679`](interceptor::EcnMarking::Rfc6679), the default,
    /// sends ECT(0) unless the receiver's `a=ecn-capable-rtp` asks for ECT(1) or a random
    /// choice with `ect=` (RFC 6679 section 7.3.1: "SHOULD use ECT(0)");
    /// [`EcnMarking::L4s`](interceptor::EcnMarking::L4s) always sends ECT(1), the L4S
    /// identifier (RFC 9331), as browsers that send L4S do. `packetsSentWithEct1` counts the
    /// ECT(1) packets only.
    pub fn with_ecn_marking(mut self, marking: interceptor::EcnMarking) -> Self {
        self.0.ecn_marking = marking;
        self
    }

    /// With ECN on ([`with_ecn`](Self::with_ecn)), whether a stream marks on `ack ccfb` alone.
    ///
    /// By default ECN is negotiated as RFC 8888 section 7 and RFC 6679 section 6.1.1 have it:
    /// every RTP section of an offer carries `a=ecn-capable-rtp` with the initiation methods
    /// this endpoint implements (the one [`with_ecn_initiation`](Self::with_ecn_initiation)
    /// names first), an answer carries it with one method where the offer had it, and a
    /// stream marks only when both sides' sections carry it ("If the attribute is removed in
    /// the answer, then ECN MUST NOT be used in any direction") and the peer can read the
    /// field (its `mode` is not `setonly`); the answer's method is the initiation used.
    ///
    /// `true` is what browsers that send L4S do: no `a=ecn-capable-rtp` is written, and every
    /// stream with `ack ccfb` negotiated marks, initiating as `with_ecn_initiation` says.
    pub fn with_ecn_without_signalling(mut self, without_signalling: bool) -> Self {
        self.0.ecn_without_signalling = without_signalling;
        self
    }

    /// Whether the engine gathers TCP host candidates itself (RFC 6544 section 4.1 says it
    /// should be configurable; browsers gather them by default). On by default: for the
    /// address of each UDP host candidate the application adds, the engine asks its driver
    /// for listeners (`RTCPeerConnection::poll_stream_command`) and adds a passive and a
    /// simultaneous-open candidate on them and an active one (port 9), whose connections it
    /// opens itself. A driver that never serves the stream interface gets no TCP candidate.
    /// `false`: no TCP candidate but those the application adds.
    pub fn with_tcp_candidate_gathering(mut self, gather: bool) -> Self {
        self.0.streams.tcp_candidates = gather;
        self
    }

    /// Whether the gathered TCP candidates include a simultaneous-open one (RFC 6544 section
    /// 5.1: one passive and one S-O host candidate per interface). On by default; its
    /// listener and its connections bind with `reuse_address`. Browsers neither gather nor
    /// pair them (they connect to one as to a passive candidate, which works).
    pub fn with_tcp_simultaneous_open(mut self, simultaneous_open: bool) -> Self {
        self.0.streams.simultaneous_open = simultaneous_open;
        self
    }

    /// Whether the engine closes its ICE-TCP connections that carry no selected pair once ICE
    /// has completed (RFC 6544 section 8, SHOULD). On by default.
    pub fn with_tcp_close_unused_connections(mut self, close: bool) -> Self {
        self.0.streams.close_unused_connections = close;
        self
    }

    /// The limits of the engine's stream transports: the bytes of a connection the driver may
    /// hold unwritten, the bytes queued beyond which a packet is dropped whole, and the number
    /// of connections. See [`StreamConfig`](shared::stream::StreamConfig).
    pub fn with_stream_limits(mut self, limits: shared::stream::StreamConfig) -> Self {
        self.0.streams.limits = limits;
        self
    }

    /// Whether the engine runs the configuration's `turns:` and `turn:...?transport=tcp`
    /// servers itself, over its stream interface (RFC 8656 section 3.1): it resolves the
    /// name, connects (Happy Eyeballs, RFC 8305), runs TLS, allocates, announces the relayed
    /// candidate with its `relayProtocol` and relays. On by default; a driver that does not
    /// serve the stream interface sees nothing of it. `turn:` over UDP is
    /// [`with_relay_gathering`](Self::with_relay_gathering).
    pub fn with_turn_over_streams(mut self, run: bool) -> Self {
        self.0.streams.turn = run;
        self
    }

    /// Whether the engine also asks each of its `turn:...?transport=tcp` and `turns:` servers
    /// for a TCP allocation (RFC 6062, on a control connection of its own) and announces its
    /// relayed address as a passive TCP candidate and, on port 9, an active one (RFC 6544
    /// section 5.5): a peer that only reaches the relay over TCP connects through it. On by
    /// default.
    pub fn with_turn_tcp_relay(mut self, relay: bool) -> Self {
        self.0.streams.turn_tcp_relay = relay;
        self
    }

    /// Who gathers server-reflexive candidates (RFC 8445 section 5.1.1.2). By default
    /// ([`ReflexiveGathering::Engine`](crate::peer_connection::srflx::ReflexiveGathering)) the
    /// engine sends a Binding request to each `stun:` / `stuns:` server of the configuration:
    /// over UDP from each UDP host candidate the application adds (through `poll_write` /
    /// `handle_read`), and over TCP / TLS from its ICE-TCP listeners for a driver that serves
    /// the stream interface; a base for which the application adds a server-reflexive
    /// candidate itself is left to it. `Application` keeps the engine out of it.
    pub fn with_server_reflexive_gathering(
        mut self,
        who: crate::peer_connection::srflx::ReflexiveGathering,
    ) -> Self {
        self.0.streams.reflexive = who;
        self
    }

    /// Who gathers relayed candidates from the configuration's `turn:` servers over UDP (RFC
    /// 8656; RFC 8445 section 5.1.1.2). By default
    /// ([`RelayGathering::Engine`](crate::peer_connection::turn_streams::RelayGathering)) the
    /// engine allocates on each such server for each transport, from the transport's first UDP
    /// host candidate of the server's family, on the application's socket: the Allocate and
    /// everything after it leave through `poll_write`, the server's answers, Data indications
    /// and ChannelData are taken out of `handle_read` before ICE sees them (only those of the
    /// engine's own transactions and allocations: another TURN client on the socket is not
    /// disturbed). The server's addresses race as RFC 8656 section 3.9 asks for UDP. A server
    /// for which the application adds a relayed candidate itself (its `url`, or any relayed
    /// candidate over UDP without one) is left to it: the engine stops what it has not
    /// announced yet. An application that runs its own TURN client from a socket other than
    /// the one whose host candidate it gives the engine, and adds its relayed candidate late,
    /// would see both: it sets `Application`, and the engine sends nothing to those servers.
    pub fn with_relay_gathering(
        mut self,
        who: crate::peer_connection::turn_streams::RelayGathering,
    ) -> Self {
        self.0.streams.relay = who;
        self
    }

    /// How the engine's TURN-over-TLS connections verify their server: roots, a verifier,
    /// or (feature `turn-tls-webpki-roots`) the Mozilla roots. Without one no `turns:`
    /// server is used.
    pub fn with_turn_tls(mut self, tls: crate::peer_connection::turn_tls::TurnTlsConfig) -> Self {
        self.0.turn_tls = tls;
        self
    }

    /// Lets [`RTCRtpReceiver::write_rtcp`](crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver::write_rtcp)
    /// and [`RTCRtpSender::write_rtcp`](crate::rtp_transceiver::rtp_sender::RTCRtpSender::write_rtcp) send
    /// feedback the section did not negotiate: a departure from RFC 4585 section 4.2 ("no
    /// feedback messages other than those listed ... MUST be used") and RFC 5104 section 7.2.
    /// Off by default: such a write is refused with `ErrRTCPFeedbackNotNegotiated`.
    pub fn with_unnegotiated_rtcp_feedback(mut self, allowed: bool) -> Self {
        self.0.unnegotiated_rtcp_feedback = allowed;
        self
    }

    /// Builds the connection without an RTCP session: a departure from RFC 8834 section 4.1
    /// ("RTCP ... MUST be implemented and used by all WebRTC endpoints").
    ///
    /// Every peer connection sends RTCP: when the interceptor registry given to
    /// [`RTCPeerConnectionBuilder::with_interceptor_registry`](crate::peer_connection::RTCPeerConnectionBuilder::with_interceptor_registry)
    /// has nothing at [`Slot::RtcpSession`](interceptor::Slot::RtcpSession) and no
    /// `SenderReportInterceptor` / `ReceiverReportInterceptor` of its own,
    /// [`RTCPeerConnectionBuilder::build`](crate::peer_connection::RTCPeerConnectionBuilder::build)
    /// installs the session of
    /// [`configure_rtcp_reports`](crate::peer_connection::configuration::interceptor_registry::configure_rtcp_reports)
    /// (an empty registry included). With this on it does not, and a registry without an RTCP
    /// session sends only the RTCP the application writes. Off by default.
    pub fn with_rtcp_session_omitted(mut self, omitted: bool) -> Self {
        self.0.rtcp_session_omitted = omitted;
        self
    }

    /// Holds received RTCP to the validity checks of RFC 3550 Appendix A.2 and section 6.4.1:
    /// a datagram whose first packet is not an SR or RR (unless reduced-size RTCP, RFC 5506,
    /// was negotiated), whose first packet has its padding bit set, or with padding on a
    /// packet that is not the last, is discarded whole.
    ///
    /// Off by default: libwebrtc sends padding on a packet in the middle of a compound packet
    /// (its transport-wide congestion control feedback, padded to a multiple of four), so the
    /// default accepts any datagram whose version and lengths hold, and processes every packet
    /// in it that parses (RFC 8834 section 4.1).
    pub fn with_strict_rtcp_validity(mut self, strict: bool) -> Self {
        self.0.strict_rtcp_validity = strict;
        self
    }

    /// Finalises the settings.
    pub fn build(self) -> SettingEngine {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression guard for the Safari mDNS interop fix. Safari (and Chrome)
    // emit only mDNS "<uuid>.local" host candidates by default; a default
    // SettingEngine must accept and resolve them (QueryOnly), not silently
    // discard them (Disabled).
    #[test]
    fn test_default_multicast_dns_mode_is_query_only() {
        assert_eq!(MulticastDNS::default().mode, MulticastDnsMode::QueryOnly);
        assert_eq!(
            SettingEngine::default().multicast_dns.mode,
            MulticastDnsMode::QueryOnly
        );
    }

    #[test]
    fn test_turn_reallocation_delay() {
        assert_eq!(
            SettingEngine::default().turn_reallocation_delay(),
            Duration::ZERO
        );
        let delay = Duration::from_secs(2);
        let setting_engine = SettingEngineBuilder::new()
            .with_turn_reallocation_delay(delay)
            .build();
        assert_eq!(setting_engine.turn_reallocation_delay(), delay);
    }

    #[test]
    fn test_turn_allocation_refresh_interval_cap() {
        assert_eq!(
            SettingEngine::default().turn_allocation_refresh_interval_cap(),
            None
        );

        let cap = Duration::from_secs(30);
        let setting_engine = SettingEngineBuilder::new()
            .with_turn_allocation_refresh_interval_cap(cap)
            .build();

        assert_eq!(
            setting_engine.turn_allocation_refresh_interval_cap(),
            Some(cap)
        );
    }

    #[test]
    fn test_ice_credentials_roundtrip() {
        let setting_engine = SettingEngine::default();
        assert_eq!(setting_engine.ice_credentials(), ("", ""));

        let setting_engine = SettingEngineBuilder::new()
            .with_ice_credentials("ufrag".to_owned(), "password".to_owned())
            .build();
        assert_eq!(setting_engine.ice_credentials(), ("ufrag", "password"));

        let mut setting_engine = SettingEngine::default();
        setting_engine.set_ice_credentials("other_ufrag".to_owned(), "other_password".to_owned());
        assert_eq!(
            setting_engine.ice_credentials(),
            ("other_ufrag", "other_password")
        );
    }
}

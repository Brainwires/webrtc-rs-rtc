use super::*;
use crate::peer_connection::configuration::remote_bitrate_limit::RemoteBitrateLimit;
use crate::peer_connection::configuration::{RTCBundlePolicy, RTCRtcpMuxPolicy};
use crate::peer_connection::event::{
    RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent, RTCPeerConnectionIceEvent,
};
use crate::peer_connection::handler::datachannel::DataChannelHandlerContext;
use crate::peer_connection::handler::demuxer::DemuxerHandlerContext;
use crate::peer_connection::handler::endpoint::EndpointHandlerContext;
use crate::peer_connection::handler::interceptor::InterceptorHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
use crate::peer_connection::handler::transport_set::{
    TransportId, TransportSet, aggregate_connection_state,
};
use crate::peer_connection::sdp::answered_extension_directions;
use crate::peer_connection::sdp::ecn;
use crate::peer_connection::sdp::has_bundle_attribute;
use crate::peer_connection::sdp::section_multiplexes_rtcp;
use crate::peer_connection::sdp::{
    ATTR_KEY_RTCP_MUX_ONLY, BundleMode, MediaSection, PopulateSdpParams,
    add_candidates_to_media_descriptions, bundle_group_mids, bundle_groups, effective_direction,
    extmap_allow_mixed_in, get_application_media, get_application_media_section_sctp_port,
    get_by_mid, get_peer_direction, get_rids, have_data_channel, is_ext_map_allow_mixed_set,
    is_rejected_media, is_rtp_profile, is_unknown_media_protocol,
    rtp_extensions_from_media_description, superseded_clear_extensions, track_details_from_sdp,
    unknown_media_name,
};
use crate::peer_connection::sdp::{
    answer_ice_options, described_ssrcs, is_lite_set, ls_groups, media_packet_time, media_rtcp_xr,
    remote_candidates, share_bundle_destination,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use crate::peer_connection::transport::ice::candidate::RTCIceServerTransportProtocol;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceCandidate, rtc_ice_candidates_from_ice_candidates,
};
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use crate::peer_connection::transport::{RTCTransportId, TransportKind};
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::negotiates_ccfb;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    encoding_send_codec, is_repair_codec, is_rtx_mime_type, parse_rtx_apt, parse_rtx_time,
};
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::{
    PayloadType, RTCRemoteBandwidth, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
};
use crate::statistics::accumulator::{
    IceCandidateAccumulator, local_candidate_stats_id, remote_candidate_stats_id,
};
use ::sdp::description::common::Attribute;
use ::sdp::description::media::MediaDescription;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;
use rand::RngExt;
use std::collections::HashSet;
use std::collections::VecDeque;

/// What the last completed offer/answer exchange negotiated, remembered when an offer is
/// applied in the stable state and brought back by a rollback (W3C webrtc-pc "set a session
/// description": the `[[LastStableState...]]` slots; RFC 9429 section 5.7).
#[derive(Clone)]
pub(super) struct LastStableState {
    /// The negotiated codecs and header extensions (a remote offer replaces them).
    media_engine: MediaEngine,
    /// The transceivers as they were: their codecs and their senders' repair flows are what a
    /// rollback restores.
    rtp_transceivers: Vec<RTCRtpTransceiverInternal>,
    can_trickle_ice_candidates: Option<bool>,
}

/// The transport part of a remote offer, waiting for the local answer: the ICE and DTLS
/// transports take the offer's parameters (start, restart ICE, set up a new DTLS association,
/// take its candidates) when the answer is applied, so that a rollback of the offer has nothing
/// to undo (RFC 9429 section 5.7: "any media that is received is processed according to the
/// previous local and remote descriptions"). What the answer must already state is staged: the
/// local ICE credentials of a restart, and the role and `tls-id` of a new DTLS association.
#[derive(Clone, Debug)]
pub(super) struct PendingRemoteTransport {
    /// The offer's ICE username fragment: candidates of that generation reach the agent with
    /// the answer (they are kept in the remote description meanwhile).
    pub(super) ufrag: String,
    /// The offer restarts ICE (or sets a closed transport up again).
    pub(super) ice_restart: bool,
    /// The ICE gathering state before this offer staged the restart credentials its answer
    /// carries; `None` when it staged none.
    pub(super) staged_restart: Option<RTCIceGatheringState>,
    /// The DTLS role of the new association the offer asks for, which the answer states.
    pub(super) new_dtls_role: Option<RTCDtlsRole>,
    /// This offer staged the answer's new `tls-id`.
    pub(super) staged_tls_id: bool,
    /// The transports other than the default one the offer restarts ICE on or asks a new DTLS
    /// association of, each on its own (RFC 9429 section 5.3.1, RFC 8842 section 5.3, per
    /// transport): the gathering state it had before the restart credentials of the answer
    /// were staged on it (`None`: no restart), and whether the answer's `tls-id` was staged.
    pub(super) other_restarts: Vec<(TransportId, Option<RTCIceGatheringState>, bool)>,
}

/// See [`RTCPeerConnection::description_snapshot`].
pub(super) struct DescriptionSnapshot {
    signaling_state: RTCSignalingState,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,
    media_engine: MediaEngine,
    rtp_transceivers: Vec<RTCRtpTransceiverInternal>,
    removed_transceivers: usize,
    can_trickle_ice_candidates: Option<bool>,
    trickled_remote_candidates: usize,
    last_offer: String,
    last_answer: String,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_ongoing: bool,
    last_stable_state: Option<LastStableState>,
    pending_remote_transport: Option<PendingRemoteTransport>,
    events: usize,
    /// The remote description's declared CNAMEs and the declarations found contradicted
    /// (`InterceptorHandlerContext::declared_cnames`, `contradicted_declarations`).
    declared_cnames: (
        std::collections::HashMap<SSRC, String>,
        std::collections::HashMap<SSRC, String>,
    ),
}

/// The ICE agent configuration the connection's settings make, for each of its transports.
pub(crate) fn ice_agent_config(
    configuration: &RTCConfiguration,
    setting_engine: &SettingEngine,
) -> Result<AgentConfig> {
    let mut candidate_types = vec![];
    if setting_engine.candidates.ice_lite {
        candidate_types.push(ice::candidate::CandidateType::Host);
    } else if configuration.ice_transport_policy == RTCIceTransportPolicy::Relay {
        candidate_types.push(ice::candidate::CandidateType::Relay);
    }

    let mut validated_servers = vec![];
    if !configuration.ice_servers.is_empty() {
        for server in &configuration.ice_servers {
            let url = server.urls()?;
            validated_servers.extend(url);
        }
    }

    // RFC 8489 section 14.14: fewer than 128 characters, at most 509 bytes.
    if let Some(software) = setting_engine.ice_agent_software()
        && (software.len() > stun::textattrs::MAX_TEXT_B
            || software.chars().count() >= stun::textattrs::MAX_TEXT_CHARS)
    {
        return Err(Error::ErrAttributeSizeOverflow);
    }

    let network_types = if setting_engine.candidates.ice_network_types.is_empty() {
        ice::network_type::supported_network_types()
    } else {
        setting_engine.candidates.ice_network_types.clone()
    };

    Ok(AgentConfig {
        lite: setting_engine.candidates.ice_lite,
        candidate_pair_proposals: setting_engine.candidates.candidate_pair_proposals,
        urls: validated_servers,
        disconnected_timeout: setting_engine.timeout.ice_disconnected_timeout,
        failed_timeout: setting_engine.timeout.ice_failed_timeout,
        keepalive_interval: setting_engine.timeout.ice_keepalive_interval,
        candidate_types,
        network_types,
        check_interval: setting_engine
            .timeout
            .ice_check_interval
            .unwrap_or(std::time::Duration::from_millis(0)),
        max_binding_requests: setting_engine.timeout.ice_max_binding_requests,
        host_acceptance_min_wait: setting_engine.timeout.ice_host_acceptance_min_wait,
        srflx_acceptance_min_wait: setting_engine.timeout.ice_srflx_acceptance_min_wait,
        prflx_acceptance_min_wait: setting_engine.timeout.ice_prflx_acceptance_min_wait,
        relay_acceptance_min_wait: setting_engine.timeout.ice_relay_acceptance_min_wait,
        multicast_dns_mode: setting_engine.multicast_dns.mode,
        multicast_dns_local_name: setting_engine.multicast_dns.local_name.clone(),
        multicast_dns_local_ip: setting_engine.multicast_dns.local_ip,
        multicast_dns_query_timeout: setting_engine.multicast_dns.timeout,
        multicast_dns_first_query_delay: setting_engine.multicast_dns.first_query_delay,
        multicast_dns_multi_question_delay: setting_engine.multicast_dns.multi_question_delay,
        multicast_dns_destination_reported: setting_engine.multicast_dns.destination_reported,
        multicast_dns_unicast_response: setting_engine.multicast_dns.unicast_response,
        multicast_dns_rate_limit: setting_engine.multicast_dns.rate_limit.clone(),
        multicast_dns_fail_closed: setting_engine.multicast_dns.fail_closed,
        multicast_dns_expose_known_public_addresses: setting_engine
            .multicast_dns
            .expose_known_public_addresses,
        multicast_dns_expose_temporary_ipv6_addresses: setting_engine
            .multicast_dns
            .expose_temporary_ipv6_addresses,
        local_ufrag: setting_engine.candidates.username_fragment.clone(),
        local_pwd: setting_engine.candidates.password.clone(),
        allow_loopback_remote_candidates: setting_engine
            .candidates
            .allow_loopback_remote_candidates,
        allow_link_local_remote_candidates: setting_engine
            .candidates
            .allow_link_local_remote_candidates,
        remote_address_filter: setting_engine.candidates.remote_address_filter.clone(),
        address_policy: setting_engine.candidates.address_policy.clone(),
        tie_breaker: setting_engine.ice.tie_breaker,
        new_tie_breaker_on_restart: setting_engine.ice.new_tie_breaker_on_restart,
        nomination_acceptance: setting_engine.ice.nomination_acceptance,
        failed_nomination: setting_engine.ice.failed_nomination,
        nominate_on_consent_checks: setting_engine.ice.nominate_on_consent_checks,
        consent_response_wait: setting_engine.ice.consent_response_wait,
        ta: setting_engine.ice.pacing,
        pacing_group: setting_engine.ice.pacing_group.clone(),
        unauthenticated_requests: setting_engine.ice.unauthenticated_requests,
        data_from_selected_pair_only: setting_engine.ice.data_from_selected_pair_only,
        send_data_before_nomination: setting_engine.ice.send_data_before_nomination,
        hold_local_candidates_until_conveyed: !setting_engine.ice.pair_before_conveyed,
        software: setting_engine.ice_agent_software(),
        nat_1to1_ips: setting_engine.candidates.nat_1to1_ips.clone(),
        nat_1to1_ip_candidate_type: match setting_engine.candidates.nat_1to1_ip_candidate_type {
            RTCIceCandidateType::Srflx => ice::candidate::CandidateType::ServerReflexive,
            RTCIceCandidateType::Prflx => ice::candidate::CandidateType::PeerReflexive,
            RTCIceCandidateType::Relay => ice::candidate::CandidateType::Relay,
            RTCIceCandidateType::Host => ice::candidate::CandidateType::Host,
            _ => ice::candidate::CandidateType::Unspecified,
        },

        ..Default::default()
    })
}

/// A DTLS transport with the connection's settings and certificates.
pub(super) fn new_dtls_transport(
    setting_engine: &SettingEngine,
    certificates: Vec<crate::peer_connection::certificate::RTCCertificate>,
    dtls_transport_id: RTCTransportId,
    ice_transport_id: RTCTransportId,
    crypto_provider: std::sync::Arc<dyn crypto::RTCCryptoProvider>,
    resumption: Option<
        std::sync::Arc<crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup>,
    >,
) -> Result<DtlsTransport> {
    let mut dtls_transport = DtlsTransport::new(RTCDtlsTransportConfig {
        id: dtls_transport_id,
        ice_transport_id,
        certificates,
        answering_dtls_role: setting_engine.answering_dtls_role,
        srtp_protection_profiles: setting_engine.srtp_protection_profiles.clone(),
        use_srtp_always: !setting_engine.dtls_use_srtp_only_with_media,
        dtls_cipher_suites: setting_engine.dtls_cipher_suites.clone(),
        allow_insecure_verification_algorithm: setting_engine.allow_insecure_verification_algorithm,
        disable_certificate_fingerprint_verification: setting_engine
            .disable_certificate_fingerprint_verification,
        replay_protection: setting_engine.replay_protection,
        crypto_provider,
    })?;
    dtls_transport.srtp_key_lifetime = setting_engine.srtp_key_lifetime;
    dtls_transport.flight_interval_rule = setting_engine.dtls_flight_interval;
    dtls_transport.connection_id_length = setting_engine.dtls_connection_id_length;
    dtls_transport.alpn = !setting_engine.dtls_alpn_off;
    dtls_transport.resumption = resumption;
    Ok(dtls_transport)
}

impl RTCPeerConnection {
    pub(super) fn new(
        now: Instant,
        mut configuration: RTCConfiguration,
        mut media_engine: MediaEngine,
        mut setting_engine: SettingEngine,
        interceptor: Box<dyn Interceptor>,
    ) -> Result<Self> {
        configuration.validate()?;
        let streams_settings = setting_engine.streams;
        let turn_tls = setting_engine.turn_tls.clone();

        // Each media section negotiates its own codecs unless the application asked for one
        // codec set (RFC 9429 section 5.10 answers every m= section from its own formats).
        media_engine
            .set_multi_codec_negotiation(!setting_engine.disable_media_engine_multiple_codecs);
        media_engine.own_payload_types_in_answers = setting_engine.own_payload_types_in_answers;

        // The one place in `rtci` that resolves a default crypto provider. The application
        // either supplies one through `SettingEngineBuilder::with_crypto_provider` — which is also how
        // a wrapper crate injects a provider it resolved itself — or gets the feature-selected
        // built-in here, once, at construction. Everything downstream —
        // ICE, DTLS, SRTP, STUN, certificates — receives it explicitly, so no library code
        // reaches for a default behind the caller's back.
        let crypto_provider = match setting_engine.crypto_provider.take() {
            Some(crypto_provider) => crypto_provider,
            None => crypto::default_provider().map_err(|error| {
                Error::Crypto(format!(
                    "peer connection requires a crypto provider: {error}; configure one with SettingEngineBuilder::with_crypto_provider"
                ))
            })?,
        };
        // Record the resolution so `SettingEngine::crypto_provider` reports the provider this
        // connection actually uses, not merely what was requested.
        setting_engine.crypto_provider = Some(crypto_provider.clone());
        // The `o=` line of every description this peer connection generates (RFC 9429 section
        // 5.2.1): its version the time the peer connection is built, on the wall clock the
        // application gave or the system's, read here once.
        let built_at = setting_engine
            .wall_clock
            .unwrap_or_else(|| shared::time::SystemInstant::now(now))
            .unix(now);
        let sdp_origin = super::sdp::jsep_origin(crypto_provider.random(), built_at);

        let agent_config = ice_agent_config(&configuration, &setting_engine)?;
        let engine_srflx = super::srflx::EngineSrflx::new(
            &agent_config.urls,
            streams_settings.reflexive,
            turn_tls.client_config().ok().flatten(),
        );
        let mut engine_turn = super::turn_streams::EngineTurn::new(
            &agent_config.urls,
            streams_settings.turn,
            turn_tls,
        );
        engine_turn.tcp_relay = streams_settings.turn_tcp_relay;
        engine_turn.relay_gathering = streams_settings.relay;

        // One random nonce per peer connection, combined with a per-transport discriminator to
        // form the three `RTCTransportId`s. Drawn here rather than from a process-wide counter:
        // a counter is ambient state, and `rtci` may be used many times over in one process.
        // Randomness is what keeps two connections' transports from comparing equal — see
        // `RTCTransportId`.
        let transport_id_nonce: u64 = rand::rng().random();
        let ice_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Ice);
        let dtls_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Dtls);
        let sctp_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Sctp);

        // Create the ICE transport
        let mut ice_transport =
            IceTransport::new(now, agent_config, crypto_provider.clone(), ice_transport_id)?;
        ice_transport.agent.set_failed_without_end_of_candidates(
            setting_engine.ice_failed_without_end_of_candidates,
        );

        // Create the DTLS transport
        // The configuration keeps its certificates: `get_configuration` reports them and
        // `set_configuration` compares with them (W3C 4.4.1.5). With none configured the DTLS
        // transport generates its own, which the configuration does not list.
        let certificates = configuration.certificates.clone();
        // RFC 5764 section 3: one DTLS session for the connection's transports, never shared
        // with another connection.
        let resumption = if !setting_engine.dtls_session_resumption {
            None
        } else {
            Some(std::sync::Arc::new(
                crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup::new(
                    crypto_provider.as_ref(),
                )?,
            ))
        };
        let dtls_transport = new_dtls_transport(
            &setting_engine,
            certificates,
            dtls_transport_id,
            ice_transport_id,
            crypto_provider.clone(),
            resumption,
        )?;

        // Create the SCTP transport. The RFC behaviour is the default for each of these: the
        // weighted fair queueing scheduler (RFC 8831 section 6.4), message interleaving
        // (sections 6.1 and 6.6), the zero checksum over DTLS (RFC 9653) and State Cookies
        // with a MAC (RFC 9260 section 5.1.3).
        let sctp_transport = SctpTransport::new(
            setting_engine.sctp_max_message_size,
            setting_engine.sctp_max_receive_buffer_size,
            setting_engine.sctp_mtu,
            sctp_transport_id,
            dtls_transport_id,
        )
        .with_weighted_fair_queueing(setting_engine.sctp_weighted_fair_queueing.unwrap_or(true))
        .with_message_interleaving(setting_engine.sctp_message_interleaving.unwrap_or(true))
        .with_zero_checksum(setting_engine.sctp_zero_checksum.unwrap_or(true))
        .with_max_streams(setting_engine.sctp_max_streams)
        .with_inbound_reassembly_limit(setting_engine.sctp_inbound_reassembly_limit)
        .with_rto(setting_engine.sctp_rto)
        .with_max_retransmissions(setting_engine.sctp_max_retransmissions)
        .with_handshake_timers_back_off_rto(setting_engine.sctp_handshake_timers_back_off_rto)
        .with_path_mtu_discovery(setting_engine.sctp_path_mtu_discovery.unwrap_or(Some(
            crate::peer_connection::transport::sctp::SctpPath::DEFAULT_MAX_IP_PACKET,
        )))
        .with_message_size_limit_without_interleaving(
            setting_engine
                .sctp_message_size_limit_without_interleaving
                .unwrap_or(true),
        )
        .with_cookie_provider(crypto_provider)
        .with_max_buffer_size(setting_engine.data_channel_max_buffer_size);

        let always_negotiate = configuration.always_negotiate_data_channels;
        // Create Pipeline Context
        let ice_handler_context = IceHandlerContext::new(ice_transport);
        let dtls_handler_context = DtlsHandlerContext::new(dtls_transport);
        let sctp_handler_context = SctpHandlerContext::new(now, sctp_transport);

        // Listed in full rather than filled from `Default`: the ICE and DTLS handler contexts
        // own a crypto provider, and deriving `Default` for them would mean resolving one
        // implicitly. The provider is chosen once above and threaded from here.
        let pipeline_context = PipelineContext {
            demuxer_handler_context: DemuxerHandlerContext {
                mdns_legacy_unicast: setting_engine.multicast_dns.mode
                    == ice::mdns::MulticastDnsMode::QueryAndGather,
                ..Default::default()
            },
            transports: TransportSet::new(
                ice_handler_context,
                dtls_handler_context,
                SrtpHandlerContext {
                    rtp_header_encryption_policy: configuration.rtp_header_encryption_policy,
                    strict_rtcp_validity: setting_engine.strict_rtcp_validity,
                    ..Default::default()
                },
            ),
            sctp_handler_context,
            datachannel_handler_context: DataChannelHandlerContext::new(now),
            interceptor_handler_context: InterceptorHandlerContext::default()
                .with_source_departure_ending_tracks(setting_engine.source_departure_ends_track)
                .with_rtp_timeout_muting(setting_engine.rtp_timeout_mutes_track)
                .with_wall_clock(setting_engine.wall_clock),
            endpoint_handler_context: EndpointHandlerContext::default(),
            media_read_outs: VecDeque::new(),
            data_read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            // The salt of the report ids, drawn per connection so an application cannot
            // predict them (webrtc 8.4).
            stats: RTCStatsAccumulator::for_connection(
                setting_engine.ecn,
                setting_engine.ecn_initiation,
                rand::rng().random(),
            )
            .with_ecn_marking(setting_engine.ecn_marking),
            announced_ice_connection_state: RTCIceConnectionState::New,
            now,
        };

        // One CNAME for the connection (RFC 7022, RFC 8834 section 4.9): what RTCP says, what
        // the descriptions say (`a=ssrc:<ssrc> cname:`) and what the parameters report.
        media_engine.rtcp_cname = pipeline_context.interceptor_handler_context.cname.clone();

        // RFC 6679 section 7.1: with ECN signalled in SDP, "the "rtcp-xr" attribute with the
        // "ecn-sum" parameter MUST also be used", and `nack ecn` "MUST be used whenever the
        // initialisation method or a congestion control algorithm requires timely sender-side
        // knowledge of received CE markings" (every initiation method here reads the first
        // ECT packets back). Both go with every audio and video format; an answer keeps what
        // the offer had of them, and `ack ccfb` replaces `nack ecn` (RFC 8888 section 7).
        if setting_engine.ecn && !setting_engine.ecn_without_signalling {
            for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
                media_engine.register_feedback(
                    crate::rtp_transceiver::rtp_sender::RTCPFeedback {
                        typ: crate::rtp_transceiver::rtp_sender::TYPE_RTCP_FB_NACK.to_owned(),
                        parameter:
                            crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCP_FB_NACK_ECN
                                .to_owned(),
                    },
                    kind,
                );
                media_engine.register_feedback(
                    crate::rtp_transceiver::rtp_sender::RTCPFeedback {
                        typ: interceptor::RTCP_FB_XR.to_owned(),
                        parameter: interceptor::RTCP_XR_ECN_SUMMARY.to_owned(),
                    },
                    kind,
                );
            }
        }

        Ok(Self {
            configuration,
            media_engine,
            setting_engine,
            interceptor,
            local_description: None,
            current_local_description: None,
            pending_local_description: None,
            remote_description: None,
            current_remote_description: None,
            pending_remote_description: None,
            signaling_state: RTCSignalingState::Stable,
            peer_connection_state: RTCPeerConnectionState::New,
            can_trickle_ice_candidates: None,
            trickled_remote_candidates: 0,
            pipeline_context,
            data_channels: DataChannelRegistry::new(),
            rtp_transceivers: Vec::new(),
            removed_transceivers: Vec::new(),
            default_remote_stream_id: None,
            greater_mid: -1,
            sdp_origin,
            last_generated_sdp: String::new(),
            last_offer: String::new(),
            last_answer: String::new(),
            ice_credentials_to_replace: Vec::new(),
            mdns_publishing: Default::default(),
            mdns_destination_reported: None,
            temporary_ipv6_addresses: Vec::new(),
            ssrc_history: HashSet::new(),
            local_description_was_set: false,
            sctp_closed_by_answer: false,
            seen_selected_pair_changes: 0,
            identity_assertion: None,
            peer_identity: None,
            last_stable_state: None,
            pending_remote_transport: None,
            negotiation_needed_state: NegotiationNeededState::Empty,
            is_negotiation_ongoing: false,
            always_negotiate_data_channels: always_negotiate,
            announced: super::states_events::AnnouncedStates::new(),
            last_data_dscp: None,
            dscp_fallback: Default::default(),
            streams: super::streams::EngineStreams::new(
                streams_settings,
                engine_turn,
                engine_srflx,
            ),
        })
    }

    /// The bundle policy in effect: `max-bundle` (W3C webrtc-pc section 4.2.5) is the policy
    /// RFC 9429 section 4.1.1 names `must-bundle`, unless the application has it ignored as
    /// that section's SHOULD says, which leaves the default.
    pub(super) fn effective_bundle_policy(&self) -> RTCBundlePolicy {
        match self.configuration.bundle_policy {
            RTCBundlePolicy::MaxBundle if !self.setting_engine.max_bundle_ignored => {
                RTCBundlePolicy::MustBundle
            }
            RTCBundlePolicy::MaxBundle => RTCBundlePolicy::Unspecified,
            policy => policy,
        }
    }

    /// No offer/answer exchange has completed yet: an offer applied now is an initial offer
    /// (RFC 9143 section 2, "initial BUNDLE offer").
    pub(super) fn is_initial_exchange(&self) -> bool {
        self.current_local_description.is_none() && self.current_remote_description.is_none()
    }

    /// Whether the data section of an offer says `TCP/DTLS/SCTP` rather than `UDP/DTLS/SCTP`
    /// (RFC 8841 section 12.2), given the candidates the offer carries.
    ///
    /// "When a subsequent SDP offer or answer is sent after ICE nomination is complete, and it
    /// does not initiate ICE restart, ... the proto value MUST match the transport protocol
    /// associated with the nominated ICE candidate pair": the selected pair's, when there is
    /// one and no restart is staged. Otherwise "The proto value MUST match the transport
    /// protocol associated with the default candidate", which "SHOULD be chosen from one of
    /// those UDP candidates" when there are any: TCP only when every candidate gathered so
    /// far is a TCP one, and UDP while none is gathered (the dummy values of RFC 9429 section
    /// 5.2.1). An answer repeats the offer's proto instead (section 10.3).
    fn offers_sctp_over_tcp(&self, candidates: &[RTCIceCandidate]) -> bool {
        let ice_transport = self.ice_transport();
        if !ice_transport.has_pending_restart()
            && let Some((local, _)) = ice_transport.agent.get_selected_candidate_pair()
        {
            return local.network_type().is_tcp();
        }
        !candidates.is_empty()
            && candidates.iter().all(|candidate| {
                candidate.protocol == crate::peer_connection::transport::RTCIceProtocol::Tcp
            })
    }

    /// The local candidates an offer or answer this side makes carries for transport `id`
    /// while it has an ICE restart staged; `None` when it has none staged. The rule is the
    /// same for every transport (RFC 9429 section 5.2.1: each one that is not bundled has
    /// candidates of its own).
    ///
    /// An offer carries none: it advertises the new credentials and the candidates gathered
    /// so far belong to the old ones (RFC 8839 section 4.4.1.1.1: the agent "sets the rest of
    /// the ICE-related fields in the SDP for this data stream as it would in an initial
    /// offer", and a restart starts a new gathering phase whose candidates are signalled as
    /// they come). An answer to an offer that restarts ICE on the transport: the restart is
    /// applied with the answer (`defer_remote_transport`, `defer_other_remote_transports`),
    /// and keeps the local candidates unless they are to be discarded; they are the new
    /// generation's, so the answer lists them. Those gathered since the offer was applied are
    /// the new generation's in any case (the restart keeps them), and the answer lists them
    /// too (RFC 9429 section 5.3.1). A new DTLS association drops the previous generation's
    /// candidates (RFC 8842 section 5.1, `restart_needs_new_local_addresses_of`), and the
    /// answer lists only those given for the restart.
    pub(super) fn restart_offered_local_candidates(
        &self,
        id: TransportId,
        offer: bool,
    ) -> Result<Option<Vec<RTCIceCandidate>>> {
        let ice_transport = self.ice_transport_of(id);
        if !ice_transport.has_pending_restart() {
            return Ok(None);
        }
        let default = self.pipeline_context.transports.default_id();
        let answers_restart = !offer
            && self
                .pending_remote_transport
                .as_ref()
                .is_some_and(|pending| {
                    if id == default {
                        pending.ice_restart
                    } else {
                        pending
                            .other_restarts
                            .iter()
                            .any(|(other, gathering, _)| *other == id && gathering.is_some())
                    }
                });
        if !answers_restart {
            return Ok(Some(Vec::new()));
        }
        if !self
            .setting_engine
            .candidates
            .discard_local_candidates_during_ice_restart
            && !self.restart_needs_new_local_addresses_of(id, false)
        {
            return ice_transport.get_local_candidates().map(Some);
        }
        Ok(Some(
            ice_transport.get_restart_generation_local_candidates(),
        ))
    }

    /// The local candidates an offer or answer carries for the active transport; see
    /// [`Self::restart_offered_local_candidates`] while it has an ICE restart staged.
    fn offered_local_candidates(&self, offer: bool) -> Result<Vec<RTCIceCandidate>> {
        let active = self.pipeline_context.transports.active_id();
        if let Some(candidates) = self.restart_offered_local_candidates(active, offer)? {
            return Ok(candidates);
        }
        let candidates = self.ice_transport().get_local_candidates()?;
        // Two lite agents (RFC 8445 section 8.2, RFC 8839 sections 4.4.1.3 and 4.4.2.2): the
        // controlling agent's updated offer lists the local candidate of the pair it chose,
        // and the answer to it the local candidate its `a=remote-candidates` names.
        let only = if offer {
            self.pipeline_context
                .transports
                .default()
                .ice_handler_context
                .lite_candidate_update
                .as_ref()
                .map(|(local, _)| (local.address().to_owned(), local.port()))
        } else if self.setting_engine.candidates.ice_lite {
            self.remote_description()
                .and_then(|r| r.parsed.as_ref())
                .filter(|parsed| is_lite_set(parsed))
                .and_then(|parsed| remote_candidates(parsed).ok())
                .and_then(|named| named.into_iter().next())
        } else {
            None
        };
        // `with_nominated_candidates_only`: the RFC 8839 section 4.4.1.2.2 form of a later
        // offer, the selected pair's local candidate alone.
        let only = only.or_else(|| {
            (offer && self.setting_engine.nominated_candidates_only)
                .then(|| self.ice_transport().agent.get_selected_candidate_pair())
                .flatten()
                .map(|(local, _)| (local.address().to_owned(), local.port()))
        });
        Ok(match only {
            Some((address, port)) => candidates
                .into_iter()
                .filter(|c| c.address == address && c.port == port)
                .collect(),
            None => candidates,
        })
    }

    /// What a description this side makes says of the pair ICE selected (RFC 8839 sections
    /// 4.2.1.2, 4.3.4, 4.4.1.2.2 and 4.4.2): the `m=` / `c=` destination of the sections that
    /// carry the candidates, the selected pair's local candidate (in an answer to an offer
    /// with `a=remote-candidates`, the local candidate it names), and, in an offer of the
    /// controlling agent, the `a=remote-candidates` values: the pair's remote candidate.
    /// Nothing while no pair is selected, or while an ICE restart is staged (its description
    /// is an initial one again).
    fn selected_pair_in_sdp(&self, offer: bool) -> (Option<(std::net::IpAddr, u16)>, Vec<String>) {
        let ice = self.ice_transport();
        if ice.has_pending_restart() {
            return (None, vec![]);
        }
        if !offer
            && let Some((address, port)) = self
                .remote_description()
                .and_then(|r| r.parsed.as_ref())
                .and_then(|parsed| remote_candidates(parsed).ok())
                .and_then(|named| named.into_iter().next())
            && let Ok(ip) = address.parse::<std::net::IpAddr>()
            && ice
                .agent
                .get_local_candidates()
                .iter()
                .any(|c| c.address() == address && c.port() == port)
        {
            return (Some((ip, port)), vec![]);
        }
        let Some((local, remote)) = ice.agent.get_selected_candidate_pair() else {
            return (None, vec![]);
        };
        let destination = local
            .address()
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| (ip, local.port()));
        let remote_candidates = if offer && ice.role() == RTCIceRole::Controlling {
            vec![format!("1 {} {}", remote.address(), remote.port())]
        } else {
            vec![]
        };
        (destination, remote_candidates)
    }

    /// The controlling one of two lite agents chose a pair among several, or a sender moved to
    /// another SSRC after a collision: the negotiation-needed flag is updated, for the offer
    /// that conveys it.
    pub(crate) fn announce_lite_candidate_update(&mut self) {
        let lite = std::mem::take(
            &mut self
                .pipeline_context
                .transports
                .default_mut()
                .ice_handler_context
                .lite_candidate_update_raised,
        );
        let ssrcs = std::mem::take(
            &mut self
                .pipeline_context
                .interceptor_handler_context
                .ssrcs_replaced,
        );
        let pair_changes = self
            .pipeline_context
            .transports
            .default()
            .ice_handler_context
            .selected_pair_changes;
        let aligning = pair_changes != self.seen_selected_pair_changes && {
            self.seen_selected_pair_changes = pair_changes;
            self.needs_alignment_offer()
        };
        if lite || ssrcs || aligning {
            self.trigger_negotiation_needed();
        }
    }

    /// RFC 8839 section 4.3.4: "If there are one or more pairs that do not match, and the
    /// peer did not indicate support for the 'ice2' ice-option, the controlling agent MUST
    /// generate a subsequent offer in which the connection address, port, and transport
    /// protocol in the 'c=' and 'm=' lines ... match the corresponding local information of
    /// the nominated pair". True while this full, controlling agent's selected pair is not the
    /// default destination of its current local description (a real candidate, not the trickle
    /// placeholder) and the peer's description has no `ice2`; the next offer names the pair
    /// (`selected_pair_in_sdp`).
    pub(crate) fn needs_alignment_offer(&self) -> bool {
        let ice = self.ice_transport();
        if self.setting_engine.candidates.ice_lite
            || ice.role() != RTCIceRole::Controlling
            || ice.has_pending_restart()
        {
            return false;
        }
        let Some(remote) = self.remote_description().and_then(|r| r.parsed.as_ref()) else {
            return false;
        };
        if remote_ice_options(remote)
            .iter()
            .any(|option| option == "ice2")
        {
            return false;
        }
        let Some((local, _)) = ice.agent.get_selected_candidate_pair() else {
            return false;
        };
        let Some(section) = self
            .current_local_description
            .as_ref()
            .and_then(|d| d.parsed.as_ref())
            .and_then(|parsed| {
                parsed
                    .media_descriptions
                    .iter()
                    .find(|m| !is_rejected_media(m))
            })
        else {
            return false;
        };
        let port = section.media_name.port.value;
        let address = section
            .connection_information
            .first()
            .and_then(|c| c.address.as_ref())
            .map(|a| a.address.as_str());
        // A trickled description's placeholder (`9` and `0.0.0.0` / `::`, RFC 8838 section
        // 5.1, RFC 8839 section 4.2.5 item 2) names no default candidate: there is nothing
        // to align. Browsers trickle and write no `ice2`; they get no extra offer.
        if port == 9 && matches!(address, Some("0.0.0.0") | Some("::")) {
            return false;
        }
        !(port == local.port() as isize && address == Some(local.address()))
    }

    /// The fingerprints of every local certificate: W3C `RTCPeerConnection` writes an
    /// `a=fingerprint` line for each of its certificates (RFC 8829 §5.2.1), and the remote side
    /// accepts the one DTLS presents if it matches any of them (RFC 8122 §5).
    fn local_dtls_fingerprints(&self) -> Result<Vec<RTCDtlsFingerprint>> {
        let dtls_transport = self.dtls_transport();
        if dtls_transport.certificates.is_empty() {
            return Err(Error::ErrNonCertificate);
        }
        let mut fingerprints = vec![];
        for cert in &dtls_transport.certificates {
            for fingerprint in cert.get_fingerprints(dtls_transport.crypto_provider.crypto())? {
                if !fingerprints.contains(&fingerprint) {
                    fingerprints.push(fingerprint);
                }
            }
        }
        Ok(fingerprints)
    }

    /// generate_unmatched_sdp generates an SDP that doesn't take remote state into account
    /// This is used for the initial call for CreateOffer
    pub(super) fn generate_unmatched_sdp(&mut self) -> Result<SessionDescription> {
        let d =
            SessionDescription::new_jsep_session_description_with_origin(self.sdp_origin.clone());

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.offered_local_candidates(true)?;
        let (selected_destination, remote_candidates) = self.selected_pair_in_sdp(true);

        let local_mids = self.local_description_mids();
        let mut media_sections = vec![];
        let fec_sections = self.fec_sections();

        for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
            if t.stopped() {
                // RFC 9429 Section 5.2.2: a stopped transceiver has no m= section of its own; one
                // a local description already has stays, rejected, so the m= lines keep their
                // order.
                if let Some(mid) = t.mid().clone()
                    && local_mids.contains(&mid)
                {
                    media_sections.push(MediaSection {
                        mid,
                        transceiver_index: usize::MAX,
                        rejected: true,
                        rejected_kind: t.kind().to_string(),
                        stopped: true,
                        ..Default::default()
                    });
                }
                continue;
            }

            if let Some(sender) = t.sender_mut() {
                sender.set_negotiated();
            }

            if let Some(mid) = t.mid().clone() {
                media_sections.push(MediaSection {
                    mid,
                    transceiver_index: i,
                    fec: fec_sections[i].clone(),
                    ..Default::default()
                });
            }
        }
        // A FEC session is a second RTP session (RFC 5109 section 14.1): its section stays
        // outside the BUNDLE group and has a transport of its own.
        let fec_mids: Vec<String> = media_sections
            .iter()
            .filter(|section| section.fec.is_some())
            .map(|section| section.mid.clone())
            .collect();

        if self.always_negotiate_data_channels {
            // wpt100:hdrext — alwaysNegotiateDataChannels: the data section comes first.
            media_sections.insert(
                0,
                MediaSection {
                    mid: self.added_data_section_mid(),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                },
            );
        } else if !self.data_channels.is_empty() {
            media_sections.push(MediaSection {
                mid: free_data_mid(&media_sections, &self.rtp_transceivers),
                transceiver_index: usize::MAX,
                data: true,
                ..Default::default()
            });
        }

        let dtls_fingerprints = self.local_dtls_fingerprints()?;

        let params = PopulateSdpParams {
            media_description_fingerprint: !self.setting_engine.sdp_session_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed: true,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            bundle: BundleMode::initial_offer().with_requests(&fec_mids, &[]),
            offered_tag_rtcp_mux_only: false,
            rtcp_mux_only: self.configuration.rtcp_mux_policy != RTCRtcpMuxPolicy::Negotiate,
            rtcp_mux_only_renegotiated: self.setting_engine.rtcp_mux_only_in_subsequent_offers,
            bundle_policy: self.effective_bundle_policy(),
            initial_offer: true,
            bundle_attributes_in_tagged_section_only: self
                .setting_engine
                .bundle_attributes_tagged_only,
            bundle_only_browser_form: self.setting_engine.bundle_only_sections_in_browser_form,
            answer_offered_formats_only: false,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            sctp_port: self.sctp_transport().offer_port(),
            sctp_over_tcp: self.offers_sctp_over_tcp(&candidates),
            ignore_rid_pause_for_recv: false,
            rid_pause_marks: self.setting_engine.rid_pause_marks,
            video_receive_limits: self.setting_engine.video_receive_limits,
            codec_video_receive_limits: self.setting_engine.codec_video_receive_limits.clone(),
            w3c_simulcast_answer: self.setting_engine.w3c_simulcast_answer,
            msid_appdata: !self.setting_engine.msid_appdata_omitted,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
            ice_pacing: self.stated_ice_pacing(),
            ice_options_in_media_sections: self.setting_engine.ice_options_in_media_sections,
            ice_options: vec!["trickle", "ice2"],
            ls_groups: vec![],
            selected_destination,
            remote_candidates,
            ecn: self.signalled_ecn(),
        };
        let mut d = RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )?;
        // RFC 9429 section 4.1.1: under `max-compat` each section has a transport of its own.
        self.plan_offer_transports(&d)?;
        self.write_transport_attributes(&mut d, Some(true));
        Ok(d)
    }

    /// generate_matched_sdp generates a SDP and takes the remote state into account
    /// this is used everytime we have a remote_description
    pub(super) fn generate_matched_sdp(
        &mut self,
        include_unmatched: bool,
        connection_role: ConnectionRole,
        ignore_rid_pause_for_recv: bool,
    ) -> Result<SessionDescription> {
        let mut d =
            SessionDescription::new_jsep_session_description_with_origin(self.sdp_origin.clone());
        d = d.with_value_attribute(ATTR_KEY_MSID_SEMANTIC.to_owned(), "WMS *".to_owned());

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.offered_local_candidates(include_unmatched)?;
        let (selected_destination, remote_candidates) =
            self.selected_pair_in_sdp(include_unmatched);

        let mut media_sections = vec![];
        let fec_sections = self.fec_sections();
        let mut already_have_application_media_section = false;
        let is_extmap_allow_mixed = is_ext_map_allow_mixed_set(self.remote_description());
        let local_mids = self.local_description_mids();
        let initial_remote_offer = !include_unmatched && self.is_initial_exchange();

        // Extract the description to avoid borrowing conflicts
        let remote_parsed = self
            .remote_description()
            .and_then(|r| r.parsed.as_ref())
            .cloned();
        let media_descriptions = remote_parsed
            .as_ref()
            .map(|parsed| parsed.media_descriptions.clone());
        // An answer repeats each offered m= line's proto (RFC 9429 section 5.1.2); an offer
        // states this endpoint's own.
        let offered_protos = |media: &MediaDescription| {
            (!include_unmatched).then(|| media.media_name.protos.clone())
        };

        // The mids the remote description has: a transceiver whose mid isn't among them is new
        // to this negotiation, and may take a rejected m-line's place in an offer.
        let remote_mids: HashSet<String> = media_descriptions
            .iter()
            .flatten()
            .filter_map(|m| get_mid_value(m).cloned())
            .collect();
        let mut recycled: HashSet<usize> = HashSet::new();
        // The remote mids of the rejected m= lines a new transceiver took over: the stopped
        // transceiver that had one is done with it, and gets no rejected section of its own.
        let mut recycled_mids: HashSet<String> = HashSet::new();

        if let Some(media_descriptions) = media_descriptions {
            let transceiver_by_mid =
                RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
            for media in &media_descriptions {
                if let Some(mid_value) = get_mid_value(media) {
                    if mid_value.is_empty() {
                        return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                    }

                    // RFC 9429 Section 5.2.2: an offer may reuse a rejected m= section (whose
                    // transceiver, if any, is stopped) for a transceiver that has no m= section
                    // yet; it keeps its own new mid.
                    if include_unmatched && is_rejected_media(media) {
                        let free = match self
                            .rtp_transceivers
                            .iter()
                            .position(|t| t.mid().as_ref() == Some(mid_value))
                        {
                            Some(i) => self.rtp_transceivers[i].stopped(),
                            None => true,
                        };
                        let candidate = if free {
                            self.rtp_transceivers.iter().enumerate().position(|(j, t)| {
                                !t.stopped()
                                    && !recycled.contains(&j)
                                    && t.mid()
                                        .as_ref()
                                        .is_some_and(|m| !m.is_empty() && !remote_mids.contains(m))
                            })
                        } else {
                            None
                        };
                        if let Some(j) = candidate {
                            if let Some(sender) = self.rtp_transceivers[j].sender_mut() {
                                sender.set_negotiated();
                            }
                            recycled.insert(j);
                            recycled_mids.insert(mid_value.to_owned());
                            media_sections.push(MediaSection {
                                mid: self.rtp_transceivers[j].mid().clone().unwrap_or_default(),
                                transceiver_index: j,
                                fec: fec_sections[j].clone(),
                                ..Default::default()
                            });
                            continue;
                        }
                    }

                    // RFC 8829 §5.3.1: rejected m-lines (port=0) in the offer MUST be
                    // reflected as rejected in the answer to preserve m-line indexing.
                    if is_rejected_media(media) {
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: unknown_media_name(media),
                            offered_protos: offered_protos(media),
                            ..Default::default()
                        });
                        continue;
                    }

                    if media.is_webrtc_datachannel() {
                        // RFC 8841 section 10.5: the application asked for the SCTP
                        // association and the DTLS association under it to be closed, which
                        // is said by a zero port on the data section's m= line, in an offer
                        // as in an answer (`RTCPeerConnection::reject_data_section`).
                        if self.sctp_transport().staged == Some(SctpRenegotiation::Reject) {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rejected: true,
                                rejected_kind: media.media_name.media.clone(),
                                transceiver_index: usize::MAX,
                                offered_protos: offered_protos(media),
                                ..Default::default()
                            });
                            already_have_application_media_section = true;
                            continue;
                        }
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: usize::MAX,
                            data: true,
                            offered_protos: offered_protos(media),
                            ..Default::default()
                        });
                        already_have_application_media_section = true;
                        continue;
                    }

                    let kind = RtpCodecKind::from(media.media_name.media.as_str());
                    if kind == RtpCodecKind::Unspecified || is_unknown_media_protocol(media) {
                        // A media type this endpoint doesn't know (RFC 8866
                        // lets <media> be any token): rejected with port 0,
                        // its media type, protocol and formats kept, so the
                        // answer lines up with the offer and later offers
                        // carry it (RFC 9429 5.3.1, 5.2.2).
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: unknown_media_name(media),
                            ..Default::default()
                        });
                        continue;
                    }

                    // An audio or video section offered with a profile that is none of the
                    // RTP profiles of RFC 9429 section 5.1.2 is not RTP this endpoint can
                    // answer: rejected, its proto and formats kept. So is one offered without
                    // `a=rtcp-mux`: there is no RTCP component to answer it with (RFC 8858
                    // section 4.3: an answerer that only multiplexes "MUST reject the 'm='
                    // section"; RFC 9429 section 5.3.1). Under the mux policy "require" such
                    // an offer was refused when it was applied.
                    if !include_unmatched
                        && matches!(kind, RtpCodecKind::Audio | RtpCodecKind::Video)
                        && (!is_rtp_profile(media)
                            || !remote_parsed.as_ref().is_some_and(|parsed| {
                                section_multiplexes_rtcp(parsed, media, initial_remote_offer)
                            }))
                    {
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: Some(media.media_name.clone()),
                            ..Default::default()
                        });
                        continue;
                    }

                    if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                        // RFC 9429 Section 5.2.2: an offer rejects a stopped transceiver's m=
                        // section. An answer doesn't: a transceiver stopped after the offer
                        // arrived is W3C "stopping", which "will not affect createAnswer" (W3C
                        // webrtc-pc 5.4 `stop()`, "to avoid problems with RFC 8843": the section
                        // may be the BUNDLE-tagged one); it answers inactive, and is rejected by
                        // the next offer. With `with_stopping_transceiver_rejected_in_answer`
                        // the answer rejects it (RFC 9429 section 5.3.1), unless it is the
                        // offerer's BUNDLE tag, which keeps the W3C form.
                        let rejected_by_answer = !include_unmatched
                            && self.setting_engine.stopping_transceiver_rejected_in_answer
                            && remote_parsed.as_ref().is_some_and(|parsed| {
                                bundle_groups(parsed)
                                    .iter()
                                    .all(|group| group.first() != Some(&mid_value.as_str()))
                            });
                        if (include_unmatched || rejected_by_answer)
                            && self.rtp_transceivers[i].stopped()
                        {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rejected: true,
                                rejected_kind: media.media_name.media.clone(),
                                stopped: true,
                                transceiver_index: usize::MAX,
                                ..Default::default()
                            });
                            continue;
                        }
                        // draft-ietf-avtcore-rtp-sframe-03 section 6: "An answerer that
                        // requires SFrame MUST reject m-sections that do not have the
                        // "a=sframe" SDP attribute"; an offerer whose `a=sframe` an answer
                        // left out "SHOULD close it in subsequent offers".
                        let sframe_closed = if include_unmatched {
                            self.rtp_transceivers[i].sframe_refused()
                        } else {
                            self.rtp_transceivers[i].use_sframe() == Some(true)
                                && !media
                                    .has_attribute(crate::peer_connection::sdp::ATTR_KEY_SFRAME)
                        };
                        if sframe_closed {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rejected: true,
                                rejected_kind: media.media_name.media.clone(),
                                transceiver_index: usize::MAX,
                                offered_protos: offered_protos(media),
                                ..Default::default()
                            });
                            continue;
                        }
                        if let Some(sender) = self.rtp_transceivers[i].sender_mut() {
                            sender.set_negotiated();
                        }

                        let extensions = rtp_extensions_from_media_description(media)?;
                        // Answering, the section states [[Direction]] intersected with the
                        // reverse of the offered direction (RFC 9429 section 5.3.1): a sendonly
                        // offer is answered recvonly or inactive, never sendrecv (RFC 3264
                        // section 6.1). Applying the offer leaves [[Direction]] alone, so a later
                        // offer is answered from the application's direction again.
                        let answer_direction = (!include_unmatched).then(|| {
                            answered_direction(
                                self.rtp_transceivers[i].direction(),
                                remote_parsed.as_ref().map_or_else(
                                    || get_peer_direction(media),
                                    |parsed| effective_direction(parsed, media),
                                ),
                            )
                        });
                        // A FEC session's section (RFC 5109 section 14.1): one `ulpfec`
                        // format, no source, no header extension.
                        if let Some(mut fec) = fec_sections[i].clone() {
                            // An answer keeps the session only while the offer sets it up
                            // (RFC 5109 section 14.3: the answerer "accepts the FEC RTP
                            // session and the grouping in the offer"); else its section is
                            // refused, port 0.
                            if !include_unmatched
                                && self.rtp_transceivers[i]
                                    .fec_session()
                                    .is_some_and(|session| session.remote.is_none())
                            {
                                media_sections.push(MediaSection {
                                    mid: mid_value.to_owned(),
                                    rejected: true,
                                    rejected_kind: media.media_name.media.clone(),
                                    transceiver_index: usize::MAX,
                                    rejected_name: Some(media.media_name.clone()),
                                    ..Default::default()
                                });
                                continue;
                            }
                            if let Some(direction) = answer_direction {
                                fec.direction = direction;
                            }
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                transceiver_index: i,
                                answer_direction,
                                offered_protos: offered_protos(media),
                                renegotiated: include_unmatched,
                                fec: Some(fec),
                                ..Default::default()
                            });
                            continue;
                        }
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: i,
                            match_extensions: extensions,
                            match_extension_directions: if include_unmatched {
                                Default::default()
                            } else {
                                answered_extension_directions(media)
                            },
                            superseded_extensions: if include_unmatched {
                                vec![]
                            } else {
                                superseded_clear_extensions(media)?
                            },
                            rid_map: get_rids(media, self.setting_engine.rid_id_grammar()),
                            answer_direction,
                            offered_protos: offered_protos(media),
                            offered_rtcp_rsize: Some(if include_unmatched {
                                self.rtp_transceivers[i].rtcp_reduced_size()
                            } else {
                                remote_parsed.as_ref().is_some_and(|parsed| {
                                    has_bundle_attribute(parsed, media, ATTR_KEY_RTCPRSIZE)
                                })
                            }),
                            renegotiated: include_unmatched,
                            offered_codecs: (!include_unmatched)
                                .then(|| codecs_from_media_description(media).unwrap_or_default()),
                            offered_rtcp_xr: if include_unmatched {
                                None
                            } else {
                                media_rtcp_xr(media)
                            },
                            offered_ecn: if include_unmatched {
                                None
                            } else {
                                remote_parsed
                                    .as_ref()
                                    .and_then(|parsed| ecn::section_ecn_capability(parsed, media))
                            },
                            ..Default::default()
                        });
                    } else {
                        return Err(Error::ErrPeerConnTransceiverMidNil);
                    }
                }
            }
        }

        // If we are offering also include unmatched local transceivers
        let match_bundle_group = if include_unmatched {
            let already_matched: HashSet<String> = media_sections
                .iter()
                .map(|s| s.mid.clone())
                .chain(recycled_mids.iter().cloned())
                .collect();

            // wpt100:hdrext — alwaysNegotiateDataChannels: a data section the session doesn't
            // have yet goes after the negotiated sections, ahead of the new ones.
            if self.always_negotiate_data_channels && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    mid: self.added_data_section_mid(),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                });
                already_have_application_media_section = true;
            }

            for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
                if let Some(mid) = t.mid().clone() {
                    if already_matched.contains(&mid) {
                        continue;
                    }

                    // A stopped transceiver the remote side never saw: no m= section, unless a
                    // local description already has it (then rejected, keeping the order).
                    if t.stopped() {
                        if local_mids.contains(&mid) {
                            media_sections.push(MediaSection {
                                mid,
                                transceiver_index: usize::MAX,
                                rejected: true,
                                rejected_kind: t.kind().to_string(),
                                stopped: true,
                                ..Default::default()
                            });
                        }
                        continue;
                    }

                    if let Some(sender) = t.sender_mut() {
                        sender.set_negotiated();
                    }

                    media_sections.push(MediaSection {
                        mid,
                        transceiver_index: i,
                        fec: fec_sections[i].clone(),
                        ..Default::default()
                    });
                }
            }

            if !self.data_channels.is_empty() && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    mid: free_data_mid(&media_sections, &self.rtp_transceivers),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                });
            }
            // The BUNDLE groups of the most recent answer stay (RFC 9429 section 5.2.2).
            [
                &self.current_local_description,
                &self.current_remote_description,
            ]
            .into_iter()
            .flatten()
            .find(|d| d.sdp_type == RTCSdpType::Answer)
            .and_then(|d| d.parsed.as_ref())
            .map_or_else(
                || {
                    // No answer yet: as an initial offer, with the FEC sessions' sections
                    // outside the group (RFC 5109 section 14.1: a second RTP session).
                    let fec_mids: Vec<String> = media_sections
                        .iter()
                        .filter(|section| section.fec.is_some())
                        .map(|section| section.mid.clone())
                        .collect();
                    BundleMode::initial_offer().with_requests(&fec_mids, &[])
                },
                |answer| {
                    // The groups the application asked for (RFC 9143 sections 7.5.1, 7.5.2).
                    let requested = |want: bool| -> Vec<String> {
                        self.rtp_transceivers
                            .iter()
                            .filter(|t| !t.stopped() && t.bundle_request() == Some(want))
                            .filter_map(|t| t.mid().clone())
                            .collect()
                    };
                    BundleMode::following(answer).with_requests(&requested(false), &requested(true))
                },
            )
        } else {
            // The offered BUNDLE group, whatever other `a=group` lines the offer has
            // (RFC 9429 section 5.3.1); none when the offer has none.
            remote_parsed
                .as_ref()
                .map_or(BundleMode::Answer(vec![]), BundleMode::answering)
        };

        let dtls_fingerprints = self.local_dtls_fingerprints()?;

        // RFC 8841 section 10: an offer says which SCTP port this side wants next (section
        // 10.5); an answer follows the offer's data section, in its port (section 10.3: a new
        // port for a new port, zero for zero) and in its proto, which the answer repeats.
        let (sctp_port, sctp_over_tcp) = if include_unmatched {
            (
                self.sctp_transport().offer_port(),
                self.offers_sctp_over_tcp(&candidates),
            )
        } else {
            let offered = self
                .remote_description()
                .and_then(|d| d.parsed.as_ref())
                .and_then(get_application_media);
            let offered_port = offered
                .and_then(|media| {
                    get_application_media_section_sctp_port(media)
                        .ok()
                        .flatten()
                })
                .unwrap_or(0);
            (
                self.sctp_transport().answer_port(offered_port),
                offered.is_some_and(|media| {
                    media.media_name.protos.first().is_some_and(|p| p == "TCP")
                }),
            )
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: !self.setting_engine.sdp_session_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed,
            connection_role,
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            bundle_policy: self.effective_bundle_policy(),
            initial_offer: false,
            bundle_attributes_in_tagged_section_only: self
                .setting_engine
                .bundle_attributes_tagged_only,
            // Only an initial offer has bundle-only sections (RFC 9429 section 5.2.2).
            bundle_only_browser_form: false,
            answer_offered_formats_only: self.setting_engine.answer_offered_formats_only,
            rtcp_mux_only: self.configuration.rtcp_mux_policy != RTCRtcpMuxPolicy::Negotiate,
            rtcp_mux_only_renegotiated: self.setting_engine.rtcp_mux_only_in_subsequent_offers,
            offered_tag_rtcp_mux_only: !include_unmatched
                && remote_parsed
                    .as_ref()
                    .is_some_and(offerer_tagged_section_is_rtcp_mux_only),
            bundle: match_bundle_group,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            sctp_port,
            sctp_over_tcp,
            ignore_rid_pause_for_recv,
            rid_pause_marks: self.setting_engine.rid_pause_marks,
            video_receive_limits: self.setting_engine.video_receive_limits,
            codec_video_receive_limits: self.setting_engine.codec_video_receive_limits.clone(),
            w3c_simulcast_answer: self.setting_engine.w3c_simulcast_answer,
            msid_appdata: !self.setting_engine.msid_appdata_omitted,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
            ice_pacing: self.stated_ice_pacing(),
            ice_options_in_media_sections: self.setting_engine.ice_options_in_media_sections,
            ice_options: if include_unmatched {
                vec!["trickle", "ice2"]
            } else {
                answer_ice_options(
                    self.setting_engine.answer_ice_options,
                    &remote_parsed
                        .as_ref()
                        .map(remote_ice_options)
                        .unwrap_or_default(),
                )
            },
            ls_groups: if include_unmatched {
                [
                    &self.current_local_description,
                    &self.current_remote_description,
                ]
                .into_iter()
                .flatten()
                .find(|d| d.sdp_type == RTCSdpType::Answer)
                .and_then(|d| d.parsed.as_ref())
                .map(ls_groups)
                .unwrap_or_default()
            } else {
                remote_parsed.as_ref().map(ls_groups).unwrap_or_default()
            },
            selected_destination,
            remote_candidates,
            ecn: self.signalled_ecn(),
        };
        let mut d = RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )?;
        if include_unmatched {
            self.plan_offer_transports(&d)?;
        } else if let Some(offer) = self
            .remote_description()
            .and_then(|remote| remote.parsed.as_ref())
        {
            // RFC 5583 section 6.1: the offered decoding dependencies, kept for what the
            // answer accepts.
            crate::peer_connection::sdp::answer_decoding_dependencies(offer, &mut d);
            // RFC 5888 section 9.3: empty `a=group` lines of the offer are answered with this
            // endpoint's.
            crate::peer_connection::sdp::answer_group_capabilities(offer, &mut d);
            // RFC 3264 section 6: "The 't=' line in the answer MUST be equal to the ones in
            // the offer" (a WebRTC offer says `t=0 0`, which the answer has already).
            if !offer.time_descriptions.is_empty() {
                d.time_descriptions = offer.time_descriptions.clone();
            }
        }
        self.write_transport_attributes(&mut d, Some(include_unmatched));
        Ok(d)
    }

    pub(super) fn populate_local_candidates(
        &self,
        session_description: Option<&RTCSessionDescription>,
    ) -> Option<RTCSessionDescription> {
        if session_description.is_none() {
            return session_description.cloned();
        }

        if let Some(sd) = session_description {
            // The candidates to signal: not the peer-reflexive ones the agent learned from
            // its checks (RFC 8445 section 7.2.5.3.1).
            let candidates = rtc_ice_candidates_from_ice_candidates(
                &self.ice_transport().agent.get_local_candidates_to_signal(),
            );

            let mut parsed = match sd.unmarshal() {
                Ok(parsed) => parsed,
                Err(_) => return Some(sd.clone()),
            };

            if !parsed.media_descriptions.is_empty() {
                // The first section the description does not reject: a section with port
                // zero carries no candidates (RFC 8839 section 4.2.1.6). A bundle-only
                // section has port zero too and is never first (RFC 9143 section 7.2.1).
                let Some(at) = parsed
                    .media_descriptions
                    .iter()
                    .position(|m| m.media_name.port.value != 0)
                else {
                    return Some(sd.clone());
                };
                let mut m = parsed.media_descriptions.remove(at);
                m = match add_candidates_to_media_descriptions(
                    &candidates,
                    m,
                    self.ice_transport().ice_gathering_state,
                ) {
                    Ok(m) => m,
                    Err(_) => return Some(sd.clone()),
                };
                parsed.media_descriptions.insert(at, m);
                share_bundle_destination(&mut parsed);
                self.populate_other_transports_candidates(&mut parsed);
            }

            Some(RTCSessionDescription {
                sdp_type: sd.sdp_type,
                sdp: parsed.marshal(),
                parsed: Some(parsed),
            })
        } else {
            None
        }
    }

    /// The signaling state a description leads to (W3C webrtc-pc "set a session description",
    /// RFC 9429 sections 5.5 and 5.6), or the error that refuses it. Nothing is changed: both
    /// `set_local_description` and `set_remote_description` call this before they touch the
    /// connection, and [`Self::commit_description`] once every other check has passed.
    pub(super) fn check_description(
        &self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
    ) -> Result<RTCSignalingState> {
        let cur = self.signaling_state;
        let next = match (op, sd.sdp_type) {
            (_, RTCSdpType::Unspecified) => return Err(Error::ErrPeerConnSDPTypeInvalidValue),
            // stable->SetLocal(offer)->have-local-offer
            (StateChangeOp::SetLocal, RTCSdpType::Offer) => {
                if sd.sdp != self.last_offer {
                    return Err(Error::ErrSDPDoesNotMatchOffer);
                }
                RTCSignalingState::HaveLocalOffer
            }
            // have-remote-offer->SetLocal(answer)->stable
            // have-local-pranswer->SetLocal(answer)->stable
            (StateChangeOp::SetLocal, RTCSdpType::Answer) => {
                if sd.sdp != self.last_answer {
                    return Err(Error::ErrSDPDoesNotMatchAnswer);
                }
                RTCSignalingState::Stable
            }
            // have-remote-offer->SetLocal(pranswer)->have-local-pranswer
            (StateChangeOp::SetLocal, RTCSdpType::Pranswer) => {
                if sd.sdp != self.last_answer {
                    return Err(Error::ErrSDPDoesNotMatchAnswer);
                }
                RTCSignalingState::HaveLocalPranswer
            }
            // stable->SetRemote(offer)->have-remote-offer
            (StateChangeOp::SetRemote, RTCSdpType::Offer) => RTCSignalingState::HaveRemoteOffer,
            // have-local-offer->SetRemote(answer)->stable
            // have-remote-pranswer->SetRemote(answer)->stable
            (StateChangeOp::SetRemote, RTCSdpType::Answer) => RTCSignalingState::Stable,
            // have-local-offer->SetRemote(pranswer)->have-remote-pranswer
            (StateChangeOp::SetRemote, RTCSdpType::Pranswer) => {
                RTCSignalingState::HaveRemotePranswer
            }
            // have-local-offer or have-remote-offer->rollback->stable, through either method
            (_, RTCSdpType::Rollback) => RTCSignalingState::Stable,
        };
        check_next_signaling_state(cur, next, op, sd.sdp_type)
    }

    /// Records a description [`Self::check_description`] accepted: the pending and current
    /// descriptions, what a rollback has to restore, and the signaling state `next_state`
    /// (W3C webrtc-pc "set a session description").
    pub(super) fn commit_description(
        &mut self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
        next_state: RTCSignalingState,
        now: Instant,
    ) -> Result<()> {
        // A remote answer keeps the ICE restart of the local offer it answers; a rollback of
        // that offer takes it back (RFC 9429 section 5.7).
        if op == StateChangeOp::SetRemote
            && matches!(sd.sdp_type, RTCSdpType::Answer | RTCSdpType::Pranswer)
        {
            for id in self.pipeline_context.transports.ids() {
                self.with_transport(id, |pc| pc.commit_local_ice_restart());
            }
        }
        if sd.sdp_type == RTCSdpType::Rollback
            && self.signaling_state == RTCSignalingState::HaveLocalOffer
        {
            for id in self.pipeline_context.transports.ids() {
                self.with_transport(id, |pc| pc.revert_local_ice_restart(now));
            }
        }

        // A remote offer applied in the stable state: what the last completed exchange
        // negotiated is remembered, so that a rollback can bring it back (W3C: the
        // [[LastStableState...]] slots). An offer applied over a pending one keeps what was
        // remembered. A local offer changes none of it, so there is nothing to remember, and
        // what the application sets while its own offer is pending (codec preferences, say)
        // survives the rollback.
        if sd.sdp_type == RTCSdpType::Offer
            && op == StateChangeOp::SetRemote
            && self.signaling_state == RTCSignalingState::Stable
        {
            self.last_stable_state = Some(LastStableState {
                media_engine: self.media_engine.clone(),
                rtp_transceivers: self.rtp_transceivers.clone(),
                can_trickle_ice_candidates: self.can_trickle_ice_candidates,
            });
        }

        // RFC 3264 section 8.3.2: every payload type number the description gives a format keeps
        // meaning it for the rest of the session (`MediaEngine::payload_type_history`). A
        // rolled-back remote offer's go with the media engine the rollback restores.
        if sd.sdp_type != RTCSdpType::Rollback
            && let Some(parsed) = sd.parsed.as_ref()
        {
            self.media_engine.record_payload_types(parsed);
        }

        match (op, sd.sdp_type) {
            (StateChangeOp::SetLocal, RTCSdpType::Offer | RTCSdpType::Pranswer) => {
                self.pending_local_description = Some(sd.clone());
            }
            (StateChangeOp::SetRemote, RTCSdpType::Offer | RTCSdpType::Pranswer) => {
                self.pending_remote_description = Some(sd.clone());
            }
            (StateChangeOp::SetLocal, RTCSdpType::Answer) => {
                self.current_remote_description = self.pending_remote_description.take();
                self.pending_local_description = None;
                self.current_local_description = Some(sd.clone());
            }
            (StateChangeOp::SetRemote, RTCSdpType::Answer) => {
                self.current_local_description = self.pending_local_description.take();
                self.pending_remote_description = None;
                self.current_remote_description = Some(sd.clone());
            }
            (_, RTCSdpType::Rollback) => {
                self.pending_local_description = None;
                self.pending_remote_description = None;
                // What a local offer prepared the receivers for goes with it, before the
                // transceivers it associated lose their mids.
                self.roll_back_offered_receive();
                // Undo what the abandoned offer changed (RFC 9429, Section 5.7). Its transport
                // part was never applied: what it staged for the answer is dropped.
                self.drop_pending_remote_transport();
                // W3C: a rolled-back remote offer gives back the rid-less encoding it replaced
                // with proposed simulcast encodings.
                for transceiver in &mut self.rtp_transceivers {
                    if let Some(sender) = transceiver.sender_mut()
                        && sender.restore_ridless_send_encodings()
                        && !sender.bound_streams().is_empty()
                    {
                        sender.rebind_local_streams(&self.media_engine, self.interceptor.as_mut());
                    }
                }
                self.rollback_transceivers()?;
                self.restore_last_stable_state();
                // The transports the offer added go with it.
                self.restore_transport_layout();
            }
            (_, RTCSdpType::Unspecified) => return Err(Error::ErrPeerConnSDPTypeInvalidValue),
        }

        // W3C 4.4.1.6 [[SctpTransport]]: an offer that describes an SCTP association creates
        // the transport ("connecting") when there is none; an answer that closes the
        // association (a rejected data section, `a=sctp-port:0`) makes it null; a rollback
        // brings back [[LastStableStateSctpTransport]], which every stable state records.
        let (describes, closes) = describes_sctp_association(sd);
        match sd.sdp_type {
            RTCSdpType::Offer if describes => self.sctp_transport_mut().described = true,
            RTCSdpType::Answer if closes => {
                // W3C 6.1.2 "closed": the association is closed intentionally by "applying a
                // remote description that rejects data or changes the SCTP port", so the
                // transport the application holds goes to "closed" and fires statechange,
                // although `sctp()` is null from now on. The event is not one of the
                // description's own: it is queued after them, and after the `close` of the
                // channels the association carried (`announce_sctp_closed_by_answer`).
                let was = self.sctp().map(|sctp| sctp.state());
                self.sctp_transport_mut().described = false;
                if was.is_some_and(|state| {
                    state != crate::peer_connection::transport::RTCSctpTransportState::Closed
                }) {
                    self.announced.sctp = None;
                    self.sctp_closed_by_answer = true;
                }
            }
            RTCSdpType::Answer | RTCSdpType::Pranswer if describes => {
                self.sctp_transport_mut().described = true;
            }
            RTCSdpType::Rollback => {
                let last = self.sctp_transport().last_stable_described;
                self.sctp_transport_mut().described = last;
            }
            _ => {}
        }
        if next_state == RTCSignalingState::Stable {
            let described = self.sctp_transport().described;
            self.sctp_transport_mut().last_stable_described = described;
        }

        if matches!(sd.sdp_type, RTCSdpType::Answer) {
            // W3C "set a session description": an answer resets [[LastCreatedOffer]] and
            // [[LastCreatedAnswer]], so a description created for an exchange that is over
            // cannot be applied to the next one.
            self.last_offer.clear();
            self.last_answer.clear();
            self.last_stable_state = None;
            for transceiver in &mut self.rtp_transceivers {
                if let Some(sender) = transceiver.sender_mut() {
                    sender.forget_ridless_send_encodings();
                }
            }
        }

        let changed = self.signaling_state != next_state;
        self.signaling_state = next_state;
        let reached_stable = next_state == RTCSignalingState::Stable;
        if reached_stable {
            self.is_negotiation_ongoing = false;
            // Negotiation has committed: any transceiver that was created while applying
            // a remote offer is now part of the stable state, so clear the
            // created-by-remote flag. This keeps the flag meaning exactly "created by the
            // current pending (uncommitted) offer", which is what rollback relies on.
            for t in &mut self.rtp_transceivers {
                t.set_created_by_remote_description(false);
            }
        }
        // W3C "set a session description": "If connection.[[SignalingState]] changed above,
        // fire an event named signalingstatechange". An offer applied over a pending offer and
        // a repeated provisional answer change nothing.
        if changed {
            self.do_signaling_state_change(next_state);
        }
        if reached_stable {
            // A re-keying that waited for the renewal under way to end (one at a time): if
            // that one did not give this transport a new association (it was rolled back),
            // it is asked for now.
            self.request_wanted_srtp_rekeying();
            // W3C "update the negotiation-needed flag" is re-run each time the connection
            // returns to a stable signaling state. A transceiver added while the
            // connection was mid-negotiation (`negotiation_needed_op` step 2.3 bails out
            // when not stable) had its negotiation-needed check deferred; re-running it now
            // fires `OnNegotiationNeededEvent` if anything is still un-negotiated.
            self.trigger_negotiation_needed();
        }
        Ok(())
    }

    /// Brings back what the last completed exchange negotiated, after a rollback (W3C
    /// webrtc-pc "set a session description", the rollback steps; RFC 9429 section 5.7: "the
    /// state of the session is restored to the state it was in before the offer"): the
    /// negotiated codecs and header extensions, each transceiver's codecs, the repair (RTX /
    /// FEC) flows of its sender's encodings, and what the remote description said about
    /// trickling. The transceivers the offer created are already gone
    /// ([`Self::rollback_transceivers`]); one the offer stopped stays stopped, as the stop
    /// algorithm is not undone.
    fn restore_last_stable_state(&mut self) {
        let Some(saved) = self.last_stable_state.take() else {
            return;
        };
        self.media_engine = saved.media_engine;
        self.can_trickle_ice_candidates = saved.can_trickle_ice_candidates;
        // No transceiver is removed while an offer is pending, other than the ones the offer
        // created, which come after every transceiver that existed when it was applied: the
        // saved ones are the first of the list, in order.
        for (transceiver, saved) in self
            .rtp_transceivers
            .iter_mut()
            .zip(&saved.rtp_transceivers)
        {
            transceiver.restore_negotiated_state(saved);
        }
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
    }

    /// The part of the connection a description changes that is not a transport, copied so
    /// that a description which fails while it is applied leaves all of it as it was (RFC 9429
    /// sections 5.9 and 5.10: "the session state MUST be restored to its state before").
    pub(super) fn description_snapshot(&self) -> DescriptionSnapshot {
        DescriptionSnapshot {
            signaling_state: self.signaling_state,
            current_local_description: self.current_local_description.clone(),
            pending_local_description: self.pending_local_description.clone(),
            current_remote_description: self.current_remote_description.clone(),
            pending_remote_description: self.pending_remote_description.clone(),
            media_engine: self.media_engine.clone(),
            rtp_transceivers: self.rtp_transceivers.clone(),
            removed_transceivers: self.removed_transceivers.len(),
            can_trickle_ice_candidates: self.can_trickle_ice_candidates,
            trickled_remote_candidates: self.trickled_remote_candidates,
            last_offer: self.last_offer.clone(),
            last_answer: self.last_answer.clone(),
            negotiation_needed_state: self.negotiation_needed_state,
            is_negotiation_ongoing: self.is_negotiation_ongoing,
            last_stable_state: self.last_stable_state.clone(),
            pending_remote_transport: self.pending_remote_transport.clone(),
            events: self.pipeline_context.event_outs.len(),
            declared_cnames: {
                let ctx = &self.pipeline_context.interceptor_handler_context;
                (
                    ctx.declared_cnames.clone(),
                    ctx.contradicted_declarations.clone(),
                )
            },
        }
    }

    /// Puts back what [`Self::description_snapshot`] copied, dropping the events queued since.
    pub(super) fn restore_description_snapshot(&mut self, snapshot: DescriptionSnapshot) {
        self.sctp_closed_by_answer = false;
        self.signaling_state = snapshot.signaling_state;
        self.current_local_description = snapshot.current_local_description;
        self.pending_local_description = snapshot.pending_local_description;
        self.current_remote_description = snapshot.current_remote_description;
        self.pending_remote_description = snapshot.pending_remote_description;
        self.media_engine = snapshot.media_engine;
        self.rtp_transceivers = snapshot.rtp_transceivers;
        self.removed_transceivers
            .truncate(snapshot.removed_transceivers);
        self.can_trickle_ice_candidates = snapshot.can_trickle_ice_candidates;
        self.trickled_remote_candidates = snapshot.trickled_remote_candidates;
        self.last_offer = snapshot.last_offer;
        self.last_answer = snapshot.last_answer;
        self.negotiation_needed_state = snapshot.negotiation_needed_state;
        self.is_negotiation_ongoing = snapshot.is_negotiation_ongoing;
        self.last_stable_state = snapshot.last_stable_state;
        // What a refused description staged for its answer goes; what was pending before
        // stays pending.
        if self
            .pending_remote_transport
            .as_ref()
            .map(|p| (p.staged_restart.is_some(), p.staged_tls_id, &p.ufrag))
            != snapshot
                .pending_remote_transport
                .as_ref()
                .map(|p| (p.staged_restart.is_some(), p.staged_tls_id, &p.ufrag))
        {
            self.drop_pending_remote_transport();
        }
        self.pending_remote_transport = snapshot.pending_remote_transport;
        self.pipeline_context.event_outs.truncate(snapshot.events);
        let ctx = &mut self.pipeline_context.interceptor_handler_context;
        (ctx.declared_cnames, ctx.contradicted_declarations) = snapshot.declared_cnames;
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
        self.update_cryptex();
        self.update_encrypted_header_extensions();
    }

    pub(super) fn do_signaling_state_change(&mut self, new_state: RTCSignalingState) {
        log::info!("signaling state changed to {new_state}");
        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(new_state),
        );
    }

    /// The ICE transport of the active transport: the default one, except inside
    /// [`Self::with_transport`] and the pipeline's sweep of another transport.
    pub(crate) fn ice_transport(&self) -> &IceTransport {
        &self
            .pipeline_context
            .transports
            .active()
            .ice_handler_context
            .ice_transport
    }

    pub(crate) fn ice_transport_mut(&mut self) -> &mut IceTransport {
        &mut self
            .pipeline_context
            .transports
            .active_mut()
            .ice_handler_context
            .ice_transport
    }

    /// The DTLS transport of the active transport (see [`Self::ice_transport`]).
    pub(crate) fn dtls_transport(&self) -> &DtlsTransport {
        &self
            .pipeline_context
            .transports
            .active()
            .dtls_handler_context
            .dtls_transport
    }

    pub(crate) fn dtls_transport_mut(&mut self) -> &mut DtlsTransport {
        &mut self
            .pipeline_context
            .transports
            .active_mut()
            .dtls_handler_context
            .dtls_transport
    }

    /// Runs `f` with `id` the active transport, so that what `f` does through
    /// [`Self::ice_transport`] and [`Self::dtls_transport`] and the pipeline's handlers is
    /// done on that transport; the active transport is what it was before afterwards.
    pub(crate) fn with_transport<R>(
        &mut self,
        id: TransportId,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let previous = self.pipeline_context.transports.active_id();
        self.pipeline_context.activate_transport(id);
        let result = f(self);
        self.pipeline_context.activate_transport(previous);
        result
    }

    /// The ICE transport of the connection's transport `id`; the default one when `id` names
    /// none.
    pub(crate) fn ice_transport_of(&self, id: TransportId) -> &IceTransport {
        let transports = &self.pipeline_context.transports;
        &transports
            .transport(id)
            .unwrap_or_else(|| transports.default())
            .ice_handler_context
            .ice_transport
    }

    /// The DTLS transport of the connection's transport `id`; the default one when `id` names
    /// none.
    pub(crate) fn dtls_transport_of(&self, id: TransportId) -> &DtlsTransport {
        let transports = &self.pipeline_context.transports;
        &transports
            .transport(id)
            .unwrap_or_else(|| transports.default())
            .dtls_handler_context
            .dtls_transport
    }

    pub(crate) fn sctp_transport(&self) -> &SctpTransport {
        &self.pipeline_context.sctp_handler_context.sctp_transport
    }

    pub(crate) fn sctp_transport_mut(&mut self) -> &mut SctpTransport {
        &mut self.pipeline_context.sctp_handler_context.sctp_transport
    }

    /// add_rtp_transceiver appends t into rtp_transceivers
    /// and fires onNegotiationNeeded;
    /// caller of this method should hold `self.mu` lock
    pub(super) fn add_rtp_transceiver(
        &mut self,
        mut t: RTCRtpTransceiverInternal,
    ) -> RTCRtpTransceiverId {
        self.inherit_header_extensions_to_negotiate(&mut t);
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
        self.rtp_transceivers.len() - 1
    }

    /// Removes the transceiver at `i` from the set of transceivers. The ids of the transceivers
    /// after it move down by one, as the stats' references to them do; the removed id is
    /// recorded for [`RTCPeerConnection::take_removed_transceivers`].
    fn remove_rtp_transceiver(&mut self, i: RTCRtpTransceiverId) {
        let mut removed = self.rtp_transceivers.remove(i);
        self.end_removed_transceivers_track(&mut removed);
        self.removed_transceivers.push(i);
        self.pipeline_context.stats.transceiver_removed(i);
        // Cached SSRC owners are transceiver ids, now shifted.
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
    }

    /// Whether the m= section with `mid` is rejected (port 0) in the current local or the
    /// current remote description: the last completed offer/answer exchange rejected it (an
    /// answer rejects every section its offer rejected, and may reject more).
    pub(super) fn rejected_in_current_description(&self, mid: &str) -> bool {
        let rejected_in = |desc: Option<&RTCSessionDescription>| {
            desc.and_then(|d| d.parsed.as_ref()).is_some_and(|parsed| {
                parsed.media_descriptions.iter().any(|media| {
                    get_mid_value(media).is_some_and(|m| m == mid) && is_rejected_media(media)
                })
            })
        };
        rejected_in(self.current_local_description.as_ref())
            || rejected_in(self.current_remote_description.as_ref())
    }

    /// W3C webrtc-pc 4.4.1.6 (set the session description, once an answer is applied and the
    /// signaling state is stable): every stopped transceiver whose m= section is rejected in
    /// the current local or the current remote description is removed from the set of
    /// transceivers (RFC 9429 section 5.2.2: the m= section stays, rejected, and may be
    /// recycled). A stopped transceiver the exchange still answered (stopped after the offer
    /// arrived) stays until the next offer rejects its section.
    pub(super) fn remove_stopped_rejected_transceivers(&mut self) {
        if self.signaling_state != RTCSignalingState::Stable {
            return;
        }
        for i in (0..self.rtp_transceivers.len()).rev() {
            let t = &self.rtp_transceivers[i];
            if t.stopped()
                && let Some(mid) = t.mid().clone()
                && self.rejected_in_current_description(&mid)
            {
                self.remove_rtp_transceiver(i);
            }
        }
    }

    /// Undoes the transceiver changes made by an offer/answer transaction that is being rolled
    /// back, as required by RFC 9429, Section 5.7.
    ///
    /// - Transceivers that were implicitly created by applying the remote offer now being rolled
    ///   back are stopped and removed, unless a track has since been attached to them via
    ///   `add_track` (i.e. they have a sender). The latter are kept but disassociated so a
    ///   subsequent `create_offer` can re-add an "m=" section for the attached track.
    /// - Any remaining transceiver that was associated with an "m=" section solely by the
    ///   rolled-back description — i.e. its mid is not present in the current (last stable)
    ///   local or remote description — is disassociated: its mid is cleared and the "m=" section
    ///   index mapping is discarded. Transceivers associated by a prior, already-negotiated
    ///   exchange keep their mid.
    ///
    /// The effect is identical regardless of whether the rollback was applied via
    /// `set_local_description` or `set_remote_description`, as the spec requires.
    pub(super) fn rollback_transceivers(&mut self) -> Result<()> {
        // Mids that were associated by the last stable offer/answer exchange. A transceiver
        // whose mid appears here was not associated by the rolled-back description and must be
        // left untouched.
        let negotiated_mids = self.current_description_mids();

        // Stop and remove transceivers created by the rolled-back remote offer that `add_track`
        // never touched (it clears the flag; a sender made for `replaceTrack` or a sending
        // direction doesn't keep one, W3C 4.4.1.6 rollback). `created_by_remote_description` is
        // cleared once negotiation reaches stable, so a set flag denotes a transceiver created by
        // the pending, not-yet-committed offer. Iterate in reverse so index-based removal is
        // stable.
        for i in (0..self.rtp_transceivers.len()).rev() {
            let t = &self.rtp_transceivers[i];
            if t.created_by_remote_description() {
                self.rtp_transceivers[i].stop(&self.media_engine, &mut self.interceptor)?;
                self.remove_rtp_transceiver(i);
            }
        }

        // Disassociate any remaining transceiver that was associated with an "m=" section solely
        // by the rolled-back description.
        for t in &mut self.rtp_transceivers {
            let associated_by_rolled_back_desc = t
                .mid()
                .as_ref()
                .is_some_and(|mid| !negotiated_mids.contains(mid));
            if associated_by_rolled_back_desc {
                t.disassociate();
            }
        }

        // The created-by-remote flag on any survivors is cleared by the caller once the state
        // machine settles back to `stable` (see `set_description`).

        Ok(())
    }

    /// Gives each transceiver the `a=rtcp-xr` attribute (RFC 3611 section 5.1) and the `b=`
    /// lines of its section of a remote description (RFC 9429 section 5.10): `b=TIAS` (bits per second, RFC 3890), else `b=AS` (kilobits per second,
    /// RFC 8866 section 5.8), is the most this endpoint may send there; `b=RS` and `b=RR`
    /// (RFC 3556) are the RTCP bandwidth of senders and receivers. A session-level `b=` line
    /// and `b=CT` are ignored, as RFC 9429 section 5.10 says. A section without the lines
    /// clears what an earlier description set.
    pub(super) fn apply_remote_bandwidth(&mut self, remote: &SessionDescription) {
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for media in &remote.media_descriptions {
            let Some(&i) =
                get_mid_value(media).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            self.rtp_transceivers[i].note_remote_sframe(
                media.has_attribute(crate::peer_connection::sdp::ATTR_KEY_SFRAME),
            );
            let of = |bandwidth_type: &str| {
                media
                    .bandwidth
                    .iter()
                    .find(|b| !b.experimental && b.bandwidth_type == bandwidth_type)
                    .map(|b| b.bandwidth)
            };
            // RFC 3611 section 5.1: "a=rtcp-xr" at media level replaces the session's.
            let rtcp_xr = media_rtcp_xr(media).or_else(|| {
                remote
                    .attributes
                    .iter()
                    .find(|a| a.key == ATTR_KEY_RTCP_XR)
                    .map(|a| {
                        a.value
                            .as_deref()
                            .unwrap_or_default()
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect()
                    })
            });
            self.rtp_transceivers[i].set_remote_rtcp_xr(rtcp_xr);
            self.rtp_transceivers[i].set_remote_packet_time(media_packet_time(media));
            let application_specific = of("AS").map(|kbps| kbps.saturating_mul(1000));
            self.rtp_transceivers[i].set_remote_bandwidth(RTCRemoteBandwidth {
                // RFC 9429 section 5.10: "TIAS = AS * 1000 * 0.95 - (50 * 40 * 8)".
                max_bitrate: of("TIAS").or_else(|| {
                    application_specific
                        .map(|bps| (bps / 100).saturating_mul(95).saturating_sub(50 * 40 * 8))
                }),
                session_bitrate: of("TIAS").or(application_specific),
                rtcp_senders_bitrate: of("RS"),
                rtcp_receivers_bitrate: of("RR"),
            });
        }
    }

    /// What an applied answer negotiated for RTCP, section by section, given to the
    /// transceivers: reduced-size RTCP is used when both the offer and the answer carry
    /// `a=rtcp-rsize` (RFC 5506 section 5; RFC 9429 section 5.11: "If the answer does not
    /// contain 'a=rtcp-rsize', ... reduced-size RTCP MUST NOT be used"). The senders' and
    /// receivers' parameters report it (`rtcp.reduced_size`), which is what an RTCP session
    /// reads to choose between compound and reduced-size packets.
    pub(super) fn apply_negotiated_rtcp(
        &mut self,
        offer: &SessionDescription,
        answer: &SessionDescription,
        we_offered: bool,
    ) {
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for (offered, answered) in offer
            .media_descriptions
            .iter()
            .zip(&answer.media_descriptions)
        {
            let Some(&i) =
                get_mid_value(answered).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            // A bundled section takes the tagged section's when it has none of its own.
            // RFC 5506 section 4: reduced-size RTCP only "in sessions using the AVPF / SAVPF
            // early or immediate feedback mode" (and 4.1: never with RTP/AVP or RTP/SAVP).
            let reduced_size = !is_rejected_media(answered)
                && crate::peer_connection::sdp::is_avpf_section(offered)
                && crate::peer_connection::sdp::is_avpf_section(answered)
                && has_bundle_attribute(offer, offered, ATTR_KEY_RTCPRSIZE)
                && has_bundle_attribute(answer, answered, ATTR_KEY_RTCPRSIZE);
            self.rtp_transceivers[i].set_rtcp_reduced_size(reduced_size);
            // W3C 5.2.9: the send codecs' parameters are the remote description's, the
            // receive codecs' the local description's.
            if !is_rejected_media(answered) {
                let (local, remote) = if we_offered {
                    (offered, answered)
                } else {
                    (answered, offered)
                };
                self.rtp_transceivers[i].take_send_fmtp_from_remote(remote);
                self.rtp_transceivers[i].take_receive_fmtp_from_local(local);
            }
            // RFC 3264 sections 6.1 and 7: the formats this endpoint's answer added beyond the
            // offer's are received (the offerer may send with any format of the answer).
            self.rtp_transceivers[i].take_answered_formats(
                (!we_offered && !is_rejected_media(answered)).then_some((answered, offered)),
            );
            // RFC 8285 section 6: a stream mixes one- and two-byte header extensions only when
            // the offer and the answer both have `a=extmap-allow-mixed`.
            let mixed = !is_rejected_media(answered)
                && extmap_allow_mixed_in(offer, offered)
                && extmap_allow_mixed_in(answer, answered);
            self.rtp_transceivers[i].set_extmap_allow_mixed(mixed);
            self.rtp_transceivers[i].apply_sframe_answer(
                we_offered,
                offered.has_attribute(crate::peer_connection::sdp::ATTR_KEY_SFRAME),
                answered.has_attribute(crate::peer_connection::sdp::ATTR_KEY_SFRAME),
            );
        }
    }

    /// What an applied answer leaves of the simulcast encodings this endpoint offered or was
    /// asked for (RFC 8853 section 5.3.3, W3C webrtc-pc "set a session description": "If
    /// description is missing any of the previously negotiated layers, then remove the
    /// dictionaries that correspond to the missing layers from [[SendEncodings]]"; without
    /// simulcast, or without any of them, the first encoding stays).
    ///
    /// The encodings that stay take the restrictions of the answer's `a=rid` line. In a
    /// remote answer, a line that does not keep to what the offer said (RFC 8851 section 6.4)
    /// is discarded, so its stream goes.
    /// W3C webrtc-pc "set the RTCSessionDescription", a remote offer that asks to receive
    /// simulcast (`a=simulcast:recv`, the first alternative of each stream) on a section whose
    /// transceiver's sender has a lone encoding without a rid, or no encodings yet (the sender
    /// of a transceiver the offer created, "from the media description using
    /// proposedSendEncodings", or of one that has not sent): the sender is "promoted to
    /// simulcast" with `proposedSendEncodings`, one encoding per offered rid in the offer's
    /// order, duplicates removed, at most [`MAX_SEND_ENCODINGS`], the one at `index` of `n`
    /// scaled down by 2^(n - index - 1) (video). The lone encoding is kept as
    /// `[[LastStableRidlessSendEncodings]]` for a rollback; the answer then keeps the layers it
    /// answers (`apply_simulcast_answer`).
    ///
    /// [`MAX_SEND_ENCODINGS`]: crate::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS
    pub(super) fn propose_send_encodings(&mut self, offer: &SessionDescription) {
        use super::sdp::SimulcastDirection;
        use crate::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS;
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        let mut minted = vec![];
        for media in &offer.media_descriptions {
            if is_rejected_media(media) {
                continue;
            }
            let Some(&i) =
                get_mid_value(media).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            let mut rids: Vec<String> = vec![];
            for rid in get_rids(media, self.setting_engine.rid_id_grammar()) {
                if rid.direction == SimulcastDirection::Recv
                    && rid.simulcast
                    && !rids.contains(&rid.id)
                {
                    rids.push(rid.id);
                }
            }
            rids.truncate(MAX_SEND_ENCODINGS);
            if rids.is_empty() {
                continue;
            }
            let kind = self.rtp_transceivers[i].kind();
            let Some(encodings) = self.rtp_transceivers[i]
                .sender()
                .as_ref()
                .map(|sender| sender.send_encodings().to_vec())
            else {
                continue;
            };
            let base = match encodings.as_slice() {
                [lone] if lone.rtp_coding_parameters.rid.is_empty() => lone.clone(),
                // A sender without encodings yet: one made with its transceiver by this offer
                // ("Create an RTCRtpSender, sender, from the media description using
                // proposedSendEncodings"), or one of a transceiver that has not sent. The W3C
                // sender has its one default encoding from creation; the engine gives it when
                // first needed, here.
                [] => match self.new_send_encodings(kind, vec![]) {
                    Ok((mut defaults, _)) if !defaults.is_empty() => defaults.swap_remove(0),
                    Ok(_) => continue,
                    Err(err) => {
                        log::warn!("no encodings for the proposed simulcast envelope: {err}");
                        continue;
                    }
                },
                _ => continue,
            };
            minted.extend(base.rtp_coding_parameters.ssrc);
            minted.extend(base.rtp_coding_parameters.rtx.as_ref().map(|rtx| rtx.ssrc));
            minted.extend(base.rtp_coding_parameters.fec.as_ref().map(|fec| fec.ssrc));
            let n = rids.len();
            let mut proposed = Vec::with_capacity(n);
            for (index, rid) in rids.into_iter().enumerate() {
                let mut encoding = base.clone();
                let coding = &mut encoding.rtp_coding_parameters;
                coding.rid = rid;
                if index > 0 {
                    coding.ssrc = Some(self.unused_ssrc(&mut minted));
                    if let Some(rtx) = coding.rtx.as_mut() {
                        rtx.ssrc = self.unused_ssrc(&mut minted);
                    }
                    if let Some(fec) = coding.fec.as_mut() {
                        fec.ssrc = self.unused_ssrc(&mut minted);
                    }
                }
                if kind == RtpCodecKind::Video {
                    encoding.scale_resolution_down_by = Some(f64::from(1u32 << (n - index - 1)));
                }
                proposed.push(encoding);
            }
            minted.extend(proposed.iter().filter_map(|e| e.rtp_coding_parameters.ssrc));
            let Some(sender) = self.rtp_transceivers[i].sender_mut() else {
                continue;
            };
            sender.propose_send_encodings(proposed);
            if !sender.bound_streams().is_empty() {
                sender.rebind_local_streams(&self.media_engine, self.interceptor.as_mut());
            }
        }
    }

    pub(super) fn apply_negotiated_simulcast(
        &mut self,
        offer: &SessionDescription,
        answer: &SessionDescription,
        answer_is_local: bool,
    ) {
        use super::sdp::SimulcastDirection;
        use super::sdp::simulcast::{answered_rid_is_valid, same_format};
        use crate::rtp_transceiver::rtp_sender::RTCRtpRidRestrictions;
        // The direction this endpoint's streams have in the answer.
        let ours = if answer_is_local {
            SimulcastDirection::Send
        } else {
            SimulcastDirection::Recv
        };
        // RFC 9429 section 5.2.2 (`with_rejected_rids_kept_in_offers`): the streams a remote
        // answer rejects stay in this endpoint's later offers.
        let keep_rejected = !answer_is_local && self.setting_engine.rejected_rids_kept_in_offers;
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for (offered, answered) in offer
            .media_descriptions
            .iter()
            .zip(&answer.media_descriptions)
        {
            if is_rejected_media(answered) {
                continue;
            }
            let Some(&i) =
                get_mid_value(answered).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            let Some(sender) = self.rtp_transceivers[i].sender_mut() else {
                continue;
            };
            let offered_rids = get_rids(offered, self.setting_engine.rid_id_grammar());
            // RFC 8853 section 5.2 (a local answer: the offer's `recv` streams marked
            // paused) and section 5.3.3 (a remote answer: the answer's): the streams the
            // remote description marks `~` start paused.
            let remote_rids = if answer_is_local {
                offered_rids.clone()
            } else {
                get_rids(answered, self.setting_engine.rid_id_grammar())
            };
            sender.set_initially_paused_rids(
                remote_rids
                    .iter()
                    .filter(|rid| {
                        rid.direction == SimulcastDirection::Recv && rid.simulcast && rid.paused
                    })
                    .map(|rid| rid.id.clone())
                    .collect(),
            );
            let formats = same_format(offered, answered);
            // The connection's rid-id grammar, the one check_remote_description read this answer with:
            // a=simulcast is parsed whole, so another grammar here would drop every stream of a line
            // the checks let through (under with_published_rid_id_grammar), not only the odd rid.
            let accepted: Vec<(String, RTCRtpRidRestrictions)> =
                get_rids(answered, self.setting_engine.rid_id_grammar())
                    .into_iter()
                    .filter(|rid| rid.direction == ours && rid.simulcast)
                    .filter(|rid| {
                        answer_is_local
                            || offered_rids
                                .iter()
                                .find(|offered| {
                                    offered.id == rid.id
                                        && offered.direction == SimulcastDirection::Send
                                })
                                .is_some_and(|offered| {
                                    answered_rid_is_valid(offered, rid, &formats)
                                })
                    })
                    .map(|rid| {
                        let restrictions = rid.to_restrictions();
                        (rid.id, restrictions)
                    })
                    .collect();
            sender.apply_simulcast_answer(&accepted, keep_rejected);
        }
    }

    /// Hands what an applied answer negotiated to the parts of the interceptor chain that
    /// act on it. Each goes as a control message written into the chain; a chain without
    /// the interceptor a message is for drops it.
    ///
    /// - Reduced-size RTCP (`a=rtcp-rsize` in the offer and in the answer, RFC 5506 section
    ///   5), when every media section negotiated it:
    ///   [`RtcpSessionControl::ReducedSize`](interceptor::RtcpSessionControl).
    /// - The bandwidth of the remote description's `b=` lines, summed over the media sections
    ///   when each has the line (RFC 8859 section 6: `b=AS`, `b=RS` and `b=RR` are of the SUM
    ///   category, and the values of `b=TIAS` are added): the session bandwidth (RFC 3550
    ///   section 6.2) and
    ///   the RTCP bandwidth of senders and receivers (RFC 3556 section 2), as
    ///   [`RtcpSessionControl::Bandwidth`](interceptor::RtcpSessionControl).
    /// - `trr-int` of the local description (RFC 4585 section 4.2: this endpoint's minimum
    ///   interval between regular RTCP packets), the longest when sections differ:
    ///   [`RtcpSessionControl::TrrInt`](interceptor::RtcpSessionControl); without one,
    ///   `TrrIntCleared`, so that a value an earlier negotiation set does not stay.
    /// - The most the remote side accepts (`b=TIAS`, else `b=AS`; RFC 9429 section 5.10),
    ///   summed over the sections this endpoint sends in when each has a limit, as the upper
    ///   bound of the congestion controller's estimate ([`RemoteBitrateLimit`]).
    /// - `rtx-time` of the retransmission formats (RFC 4588 section 8.1): the local
    ///   description's is how long the NACK responder keeps a sent packet, the remote
    ///   description's how long the NACK generator asks for a missing one
    ///   ([`NackControl`](interceptor::NackControl)).
    /// - What identifies each stream this endpoint sends, for the SDES chunk of its SSRC: the
    ///   mid of its m= section (RFC 9143 section 15.1), the encoding's rid as RtpStreamId and,
    ///   on its RTX and FEC SSRCs, as RepairedRtpStreamId (RFC 8852 sections 3.1, 3.2):
    ///   [`RtcpSessionControl::StreamIdentifiers`](interceptor::RtcpSessionControl).
    pub(super) fn apply_negotiated_session(
        &mut self,
        now: Instant,
        local: &SessionDescription,
        remote: &SessionDescription,
    ) -> Result<()> {
        use interceptor::{NackControl, RtcpBandwidth, RtcpSessionControl};
        use std::time::Duration;

        let live = |t: &&RTCRtpTransceiverInternal| t.mid().is_some() && !t.stopped();
        let sum = |values: Vec<Option<u64>>| -> Option<u64> {
            if values.is_empty() {
                return None;
            }
            values
                .into_iter()
                .try_fold(0u64, |total, value| Some(total.saturating_add(value?)))
        };
        let of_live = |value: fn(&RTCRemoteBandwidth) -> Option<u64>| -> Vec<Option<u64>> {
            self.rtp_transceivers
                .iter()
                .filter(live)
                .map(|t| value(&t.remote_bandwidth()))
                .collect()
        };

        let reduced_size = self.rtp_transceivers.iter().any(|t| live(&t))
            && self
                .rtp_transceivers
                .iter()
                .filter(live)
                .all(|t| t.rtcp_reduced_size());
        let bandwidth = RtcpBandwidth {
            session: sum(of_live(|b| b.session_bitrate)),
            rs: sum(of_live(|b| b.rtcp_senders_bitrate)),
            rr: sum(of_live(|b| b.rtcp_receivers_bitrate)),
        };
        let send_limit = sum(self
            .rtp_transceivers
            .iter()
            .filter(live)
            .filter(|t| t.describes_sender() && t.current_direction().has_send())
            .map(|t| t.remote_bandwidth().max_bitrate)
            .collect());

        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        let negotiated_sections = |desc: &SessionDescription| -> Vec<Vec<RTCRtpCodecParameters>> {
            desc.media_descriptions
                .iter()
                .filter(|media| {
                    !is_rejected_media(media)
                        && get_mid_value(media)
                            .is_some_and(|mid| transceiver_by_mid.contains_key(mid.as_str()))
                })
                .filter_map(|media| codecs_from_media_description(media).ok())
                .collect()
        };
        let local_sections = negotiated_sections(local);
        let remote_sections = negotiated_sections(remote);
        let trr_int = local_sections
            .iter()
            .flatten()
            .flat_map(|codec| &codec.rtp_codec.rtcp_feedback)
            .filter(|feedback| feedback.typ == "trr-int")
            .filter_map(|feedback| feedback.parameter.trim().parse::<u64>().ok())
            .max();
        let rtx_times = |sections: &[Vec<RTCRtpCodecParameters>]| -> Vec<(u8, Option<Duration>)> {
            sections
                .iter()
                .flatten()
                .filter(|codec| is_rtx_mime_type(&codec.rtp_codec.mime_type))
                .map(|codec| {
                    (
                        codec.payload_type,
                        parse_rtx_time(&codec.rtp_codec.sdp_fmtp_line),
                    )
                })
                .collect()
        };

        // Each transport's SRTP context takes the flag of the sections it carries: reduced-size
        // RTCP on a transport only when every live section on it negotiated it.
        let mut per_transport: std::collections::HashMap<TransportId, bool> =
            std::collections::HashMap::new();
        for transceiver in self.rtp_transceivers.iter().filter(live) {
            let Some(mid) = transceiver.mid() else {
                continue;
            };
            let id = self.pipeline_context.transports.transport_id_for(mid);
            let entry = per_transport.entry(id).or_insert(true);
            *entry = *entry && transceiver.rtcp_reduced_size();
        }
        for bundle in self.pipeline_context.transports.iter_mut() {
            bundle.srtp_handler_context.rtcp_reduced_size =
                per_transport.get(&bundle.id).copied().unwrap_or(false);
        }
        let mut controls = vec![];
        // The SSRCs of each transport's sections: the RTP session each stream runs in
        // (RFC 8834 section 4.4: a transport per unbundled section, an RTCP session, a
        // congestion controller and a pacer each), told before what is per session.
        let mut assignments: std::collections::BTreeMap<usize, Vec<u32>> =
            std::collections::BTreeMap::new();
        for id in self.pipeline_context.transports.ids() {
            assignments.entry(id.0).or_default();
        }
        for transceiver in self.rtp_transceivers.iter().filter(live) {
            let Some(mid) = transceiver.mid() else {
                continue;
            };
            let id = self.pipeline_context.transports.transport_id_for(mid).0;
            let ssrcs = assignments.entry(id).or_default();
            let mut add = |coding: &crate::rtp_transceiver::rtp_sender::RTCRtpCodingParameters| {
                ssrcs.extend(coding.ssrc);
                ssrcs.extend(coding.rtx.as_ref().map(|rtx| rtx.ssrc));
                ssrcs.extend(coding.fec.as_ref().map(|fec| fec.ssrc));
            };
            if let Some(sender) = transceiver.sender() {
                for encoding in sender.send_encodings() {
                    add(&encoding.rtp_coding_parameters);
                }
            }
            if let Some(receiver) = transceiver.receiver() {
                for coding in receiver.get_coding_parameters() {
                    add(coding);
                }
            }
        }
        // A FEC session's streams run in its own RTP session (RFC 5109 section 14.1), under
        // the SSRCs the chain knows them by.
        for (index, transceiver) in self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, t)| live(t))
        {
            if transceiver.fec_session().is_none() {
                continue;
            }
            let Some(id) = transceiver
                .mid()
                .as_deref()
                .and_then(|mid| self.pipeline_context.transports.assignment(mid))
            else {
                continue;
            };
            assignments
                .entry(id.0)
                .or_default()
                .extend(self.fec_session_chain_ssrcs(index));
        }
        for (session, ssrcs) in &assignments {
            controls.push(
                interceptor::RtpSessionAssignment {
                    session: *session,
                    ssrcs: ssrcs.clone(),
                }
                .into_packet(now),
            );
        }
        // Reduced-size RTCP and the bandwidth are each RTCP session's: those of the sections
        // on its transport. With one transport that is every section.
        let single = self.pipeline_context.transports.len() == 1;
        let per_session: Vec<(usize, bool, RtcpBandwidth)> = if single {
            vec![(
                self.pipeline_context.transports.default_id().0,
                reduced_size,
                bandwidth,
            )]
        } else {
            self.pipeline_context
                .transports
                .ids()
                .into_iter()
                .map(|id| {
                    let on = |t: &&RTCRtpTransceiverInternal| {
                        live(t)
                            && t.mid().as_ref().is_some_and(|mid| {
                                self.pipeline_context.transports.transport_id_for(mid) == id
                            })
                    };
                    let of = |value: fn(&RTCRemoteBandwidth) -> Option<u64>| {
                        sum(self
                            .rtp_transceivers
                            .iter()
                            .filter(on)
                            .map(|t| value(&t.remote_bandwidth()))
                            .collect())
                    };
                    let reduced = self.rtp_transceivers.iter().any(|t| on(&t))
                        && self
                            .rtp_transceivers
                            .iter()
                            .filter(on)
                            .all(|t| t.rtcp_reduced_size());
                    (
                        id.0,
                        reduced,
                        RtcpBandwidth {
                            session: of(|b| b.session_bitrate),
                            rs: of(|b| b.rtcp_senders_bitrate),
                            rr: of(|b| b.rtcp_receivers_bitrate),
                        },
                    )
                })
                .collect()
        };
        for (session, reduced_size, bandwidth) in per_session {
            let tag = |mut packet: interceptor::TaggedPacket| {
                packet
                    .message
                    .add(interceptor::RtpSession(session).attribute());
                packet
            };
            controls.push(tag(
                RtcpSessionControl::ReducedSize(reduced_size).into_packet(now)
            ));
            controls.push(tag(
                RtcpSessionControl::Bandwidth(bandwidth).into_packet(now)
            ));
        }
        // A `trr-int` an earlier negotiation set and this one does not have is undone.
        controls.push(
            match trr_int {
                Some(trr_int) => RtcpSessionControl::TrrInt(Duration::from_millis(trr_int)),
                None => RtcpSessionControl::TrrIntCleared,
            }
            .into_packet(now),
        );
        controls.push(RemoteBitrateLimit(send_limit.map(|limit| limit as f64)).into_packet(now));
        // RFC 5104 section 4.2.1.2: a TMMBR "MUST NOT exceed the negotiated value": what this
        // endpoint's own description says it receives (`b=TIAS`, else `b=AS`).
        let receiving: HashSet<String> = self
            .rtp_transceivers
            .iter()
            .filter(live)
            .filter(|t| t.current_direction().has_recv())
            .filter_map(|t| t.mid().clone())
            .collect();
        controls.push(
            interceptor::TmmbrControl::NegotiatedMaximum(negotiated_receive_maximum(
                local, &receiving,
            ))
            .into_packet(now),
        );
        for (payload_type_rtx, rtx_time) in rtx_times(&local_sections) {
            controls.push(
                NackControl::LocalRtxTime {
                    payload_type_rtx,
                    rtx_time,
                }
                .into_packet(now),
            );
        }
        for (payload_type_rtx, rtx_time) in rtx_times(&remote_sections) {
            controls.push(
                NackControl::RemoteRtxTime {
                    payload_type_rtx,
                    rtx_time,
                }
                .into_packet(now),
            );
        }
        for transceiver in self.rtp_transceivers.iter().filter(live) {
            let (Some(mid), Some(sender)) = (transceiver.mid(), transceiver.sender()) else {
                continue;
            };
            if !sender.has_sent() {
                continue;
            }
            for encoding in sender.send_encodings() {
                controls.extend(
                    stream_identifiers(mid, &encoding.rtp_coding_parameters)
                        .into_iter()
                        .map(|control| control.into_packet(now)),
                );
            }
        }
        // The streams of the senders whose negotiated direction does not send, with their
        // RTX and FEC streams: what the pacer holds of them goes now, and nothing of them is
        // sent again (RFC 8866 sections 6.7.1 and 6.7.4: "No media is sent over an inactive
        // media stream"; RFC 3264 section 5.1; W3C webrtc-pc 4.4.1.6: the answer sets
        // `[[CurrentDirection]]`). RTCP goes on. Every answer says it again: a stream that
        // sends again is no longer named.
        let mut not_sending = Vec::new();
        for transceiver in self.rtp_transceivers.iter().filter(live) {
            let direction = transceiver.current_direction();
            if direction == RTCRtpTransceiverDirection::Unspecified || direction.has_send() {
                continue;
            }
            let Some(sender) = transceiver.sender() else {
                continue;
            };
            for encoding in sender.send_encodings() {
                let coding = &encoding.rtp_coding_parameters;
                not_sending.extend(coding.ssrc);
                not_sending.extend(coding.rtx.as_ref().map(|rtx| rtx.ssrc));
                not_sending.extend(coding.fec.as_ref().map(|fec| fec.ssrc));
            }
        }
        controls.push(interceptor::StreamsNotSending { ssrcs: not_sending }.into_packet(now));
        for control in controls {
            self.interceptor.handle_write(control)?;
        }
        Ok(())
    }

    /// Gives each m= section of a remote description that has no `a=mid` one (RFC 9429,
    /// Section 5.10 / 5.11: an endpoint that predates mids). In an answer it is the mid of our
    /// m= section at the same position; in an offer, the section's index (or the next number no
    /// other section has). Only the parsed description changes: the SDP text stays as given.
    pub(super) fn assign_missing_mids(&self, parsed: &mut SessionDescription, answers: bool) {
        let local: Vec<Option<String>> = if answers {
            self.pending_local_description
                .as_ref()
                .or(self.current_local_description.as_ref())
                .and_then(|d| d.parsed.as_ref())
                .map(|d| {
                    d.media_descriptions
                        .iter()
                        .map(|m| get_mid_value(m).filter(|mid| !mid.is_empty()).cloned())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        let mut taken: HashSet<String> = parsed
            .media_descriptions
            .iter()
            .filter_map(|m| get_mid_value(m).filter(|mid| !mid.is_empty()).cloned())
            .collect();
        let mut numbered = false;
        for (index, media) in parsed.media_descriptions.iter_mut().enumerate() {
            if get_mid_value(media).is_some_and(|mid| !mid.is_empty()) {
                continue;
            }
            numbered = true;
            let mid = match local.get(index).cloned().flatten() {
                Some(mid) if !taken.contains(&mid) => mid,
                _ => {
                    let mut n = index;
                    while taken.contains(&n.to_string()) {
                        n += 1;
                    }
                    n.to_string()
                }
            };
            taken.insert(mid.clone());
            media.attributes.retain(|a| a.key != ATTR_KEY_MID);
            media.attributes.push(Attribute {
                key: ATTR_KEY_MID.to_owned(),
                value: Some(mid),
            });
        }
        // RFC 5888 section 6: "If the identification-tag attribute is not present in each "m"
        // line of the session description, grouping of media lines MUST NOT be performed."
        if numbered {
            parsed.attributes.retain(|a| a.key != ATTR_KEY_GROUP);
        }
    }

    /// The mids of the pending and current local descriptions.
    /// Whether a local or remote description that is applied (pending or current) has a
    /// media section with `mid`: the transceiver's [[Mid]] is set then (W3C webrtc-pc 4.4.1.6).
    pub(crate) fn applied_description_has_mid(&self, mid: &str) -> bool {
        [
            &self.pending_local_description,
            &self.current_local_description,
            &self.pending_remote_description,
            &self.current_remote_description,
        ]
        .into_iter()
        .flatten()
        .filter_map(|d| d.parsed.as_ref())
        .any(|parsed| {
            parsed
                .media_descriptions
                .iter()
                .any(|m| get_mid_value(m).is_some_and(|value| value == mid))
        })
    }

    pub(super) fn local_description_mids(&self) -> HashSet<String> {
        let mut mids = HashSet::new();
        for desc in [
            self.pending_local_description.as_ref(),
            self.current_local_description.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(parsed) = desc.parsed.as_ref() {
                for media in &parsed.media_descriptions {
                    if let Some(mid) = get_mid_value(media)
                        && !mid.is_empty()
                    {
                        mids.insert(mid.clone());
                    }
                }
            }
        }
        mids
    }

    /// Collects the set of mids associated by the current (last stable) local and remote
    /// descriptions. Used by rollback to distinguish transceivers associated by a prior,
    /// already-negotiated exchange from those associated only by the description being rolled back.
    pub(super) fn current_description_mids(&self) -> HashSet<String> {
        let mut mids = HashSet::new();
        for desc in [
            self.current_local_description.as_ref(),
            self.current_remote_description.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(parsed) = desc.parsed.as_ref() {
                for media in &parsed.media_descriptions {
                    if let Some(mid) = get_mid_value(media)
                        && !mid.is_empty()
                    {
                        mids.insert(mid.clone());
                    }
                }
            }
        }
        mids
    }

    pub(super) fn start_rtp_senders(&mut self) -> Result<()> {
        // The FEC sessions as this negotiation left them (RFC 5109 section 14.1): the
        // protected senders' streams are bound, below, with where their FEC goes.
        self.sync_fec_sessions();
        // Collect SSRCs, kinds, mids, rids, encoding indices, rtx_ssrc, and transceiver_id for outbound stream accumulators
        // We do this in two phases to avoid borrow conflicts
        #[allow(clippy::type_complexity)]
        let mut outbound_streams_to_create: Vec<(
            u32,
            RtpCodecKind,
            String,
            String,
            u32,
            Option<u32>,
            RTCRtpTransceiverId,
        )> = Vec::new();

        // W3C webrtc-pc 4.4.1.6: once stable, an encoding's codec that the answer did not
        // negotiate for sending is removed.
        for transceiver in self.rtp_transceivers.iter_mut() {
            if let Some(sender) = transceiver.sender_mut() {
                sender.drop_unnegotiated_encoding_codecs();
            }
        }

        // RFC 9429 section 5.11 (RFC 7160 section 4.1): a started stream whose new codec has
        // another clock rate gets a new SSRC (and so does its RTX stream), moved as a collision
        // moves one: the old SSRC says BYE, what the application still writes with it goes out
        // with the new one, and later descriptions say `previous-ssrc`.
        let clock_rate_changes: Vec<(usize, Vec<SSRC>)> = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, t)| !t.stopped())
            .filter_map(|(i, t)| {
                let sender = t.sender().as_ref()?;
                (sender.is_negotiated() && sender.has_sent())
                    .then(|| (i, sender.clock_rate_changed_ssrcs(&self.media_engine)))
            })
            .filter(|(_, ssrcs)| !ssrcs.is_empty())
            .collect();
        let mut minted = vec![];
        for (i, ssrcs) in clock_rate_changes {
            for old in ssrcs {
                let new = self.unused_ssrc(&mut minted);
                let Some(sender) = self.rtp_transceivers[i].sender_mut() else {
                    continue;
                };
                if sender.replace_ssrc(old, new) == Some(old) {
                    self.stats_mut().replace_outbound_rtp_stream(old, new);
                }
            }
        }

        for (transceiver_id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            // Get kind and mid before mutable borrow of sender
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();
            let transceiver_stopped = transceiver.stopped();

            // A started sender's streams were bound with what an earlier negotiation decided;
            // one that changed the codec an encoding is sent with (or its RTX / FEC flow, or the
            // header extensions) re-binds them, keeping the SSRCs.
            if let Some(sender) = transceiver.sender_mut()
                && sender.is_negotiated()
                && sender.has_sent()
                && !transceiver_stopped
            {
                sender.rebind_local_streams(&self.media_engine, &mut self.interceptor);
                // A simulcast stream an earlier answer rejected and this one accepts again
                // (`with_rejected_rids_kept_in_offers`) is sent from now on: its outbound
                // statistics start (the streams that have them keep theirs).
                if self.setting_engine.rejected_rids_kept_in_offers {
                    for (encoding_index, coding) in sender.track().codings().iter().enumerate() {
                        if let Some(ssrc) = coding.rtp_coding_parameters.ssrc
                            && !sender.is_removed_ssrc(ssrc)
                        {
                            outbound_streams_to_create.push((
                                ssrc,
                                kind,
                                mid.clone(),
                                coding.rtp_coding_parameters.rid.clone(),
                                encoding_index as u32,
                                coding
                                    .rtp_coding_parameters
                                    .rtx
                                    .as_ref()
                                    .map(|rtx| rtx.ssrc),
                                transceiver_id,
                            ));
                        }
                    }
                }
                continue;
            }

            if let Some(sender) = transceiver.sender_mut()
                && sender.is_negotiated()
                && !sender.has_sent()
                && !sender.track().codings().is_empty()
            {
                // Collect SSRCs for stats accumulator creation
                for (encoding_index, coding) in sender.track().codings().iter().enumerate() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc
                        && !sender.is_removed_ssrc(ssrc)
                    {
                        let rid = coding.rtp_coding_parameters.rid.clone();
                        let rtx_ssrc = coding
                            .rtp_coding_parameters
                            .rtx
                            .as_ref()
                            .map(|rtx| rtx.ssrc);
                        outbound_streams_to_create.push((
                            ssrc,
                            kind,
                            mid.clone(),
                            rid,
                            encoding_index as u32,
                            rtx_ssrc,
                            transceiver_id,
                        ));
                    }
                }

                sender.bind_local_streams(&self.media_engine, &mut self.interceptor);

                sender.set_sent();
            }
        }

        // Create outbound stream accumulators
        for (ssrc, kind, mid, rid, encoding_index, rtx_ssrc, transceiver_id) in
            outbound_streams_to_create
        {
            self.pipeline_context
                .stats
                .get_or_create_outbound_rtp_streams(
                    ssrc,
                    kind,
                    &mid,
                    &rid,
                    encoding_index,
                    rtx_ssrc,
                    transceiver_id,
                );
        }

        // Whether each bound stream negotiated RFC 8888 feedback: its remote-inbound stats
        // have the RFC 8888 members, and with ECN on its packets go out ECT(1). Taken from what
        // the streams are bound with now, so a renegotiation that adds or drops `ack ccfb`
        // takes effect with it.
        for transceiver in &self.rtp_transceivers {
            let Some(sender) = transceiver.sender().as_ref() else {
                continue;
            };
            let ecn = self.negotiated_ecn(transceiver.mid().as_deref());
            for info in sender.bound_streams() {
                let ccfb = negotiates_ccfb(
                    info.rtcp_feedback
                        .iter()
                        .map(|f| (f.typ.as_str(), f.parameter.as_str())),
                );
                let rfc6679 = info.rtcp_feedback.iter().any(|f| {
                    f.typ == interceptor::RTCP_FB_XR
                        && f.parameter == interceptor::RTCP_XR_ECN_SUMMARY
                });
                self.pipeline_context
                    .stats
                    .set_outbound_rfc6679(info.ssrc, rfc6679);
                self.pipeline_context
                    .stats
                    .set_outbound_ccfb(info.ssrc, ccfb, ecn);
            }
        }

        Ok(())
    }

    /// The Ta a description states in `a=ice-pacing` (RFC 8839 sections 4.3.1, 4.3.2: a full
    /// implementation "SHOULD include an 'ice-pacing' attribute" in offers and answers, a lite
    /// one "MUST NOT"): the proposed one, else the default 50 ms (RFC 8445 section 14.2),
    /// unless `SettingEngineBuilder::with_default_ice_pacing_stated(false)` leaves the default
    /// unstated.
    pub(super) fn stated_ice_pacing(&self) -> Option<std::time::Duration> {
        if self.setting_engine.candidates.ice_lite {
            return None;
        }
        match self.ice_transport().agent.proposed_pacing() {
            Some(ta) => Some(ta),
            None if self.setting_engine.default_ice_pacing_omitted => None,
            None => Some(std::time::Duration::from_millis(50)),
        }
    }

    /// The initiation an offer or answer states in `a=ecn-capable-rtp` (RFC 6679 section 6.1):
    /// `None` when ECN is off, or used without signalling.
    pub(super) fn signalled_ecn(&self) -> Option<interceptor::EcnInitiation> {
        (self.setting_engine.ecn && !self.setting_engine.ecn_without_signalling)
            .then_some(self.setting_engine.ecn_initiation)
    }

    /// Whether the streams of the section `mid` may send ECT, and how they initiate it
    /// (RFC 6679 section 6.1.1): both current descriptions' sections carry
    /// `a=ecn-capable-rtp` with a method this endpoint implements, and the peer reads the
    /// marks. With `with_ecn_without_signalling` the configured initiation, whatever the
    /// descriptions say. `None` without ECN; the statistics also need `ack ccfb` to mark.
    pub(super) fn negotiated_ecn(&self, mid: Option<&str>) -> Option<ecn::NegotiatedEcn> {
        if !self.setting_engine.ecn {
            return None;
        }
        if self.setting_engine.ecn_without_signalling {
            // What browsers that send L4S do: ECT(1) on `ack ccfb` alone.
            return Some(ecn::NegotiatedEcn {
                initiation: self.setting_engine.ecn_initiation,
                preference: Some(interceptor::EctPreference::Ect1),
            });
        }
        let mid = mid?;
        let local = self.current_local_description.as_ref()?;
        let remote = self.current_remote_description.as_ref()?;
        fn section<'a>(
            d: &'a RTCSessionDescription,
            mid: &str,
        ) -> Option<(&'a SessionDescription, &'a MediaDescription)> {
            let parsed = d.parsed.as_ref()?;
            let media = parsed
                .media_descriptions
                .iter()
                .find(|m| get_mid_value(m).map(String::as_str) == Some(mid))?;
            Some((parsed, media))
        }
        ecn::negotiated_initiation(
            section(local, mid)?,
            section(remote, mid)?,
            local.sdp_type == RTCSdpType::Answer,
        )
    }

    pub(super) fn start_rtp(&mut self, remote_desc: RTCSessionDescription) -> Result<()> {
        self.start_rtp_senders()?;

        // The simulcast streams a local offer asked for and no media has claimed yet: the
        // answer says below which streams there are, if any.
        for transceiver in &mut self.rtp_transceivers {
            if let Some(receiver) = transceiver.receiver_mut() {
                receiver.drop_offered_layers();
            }
        }

        let incoming_tracks = if let Some(parsed) = &remote_desc.parsed {
            track_details_from_sdp(parsed, self.setting_engine.rid_id_grammar())
        } else {
            vec![]
        };
        let appdata_names_the_track = self.setting_engine.msid_appdata_change_renews_track;
        // RFC 5576 section 6.1: the CNAME each SSRC is declared with, against what its RTCP
        // SDES names (`handler/declared_cname.rs`).
        self.pipeline_context
            .interceptor_handler_context
            .set_declared_cnames(
                remote_desc
                    .parsed
                    .as_ref()
                    .map(sdp::declared_cnames)
                    .unwrap_or_default(),
            );

        for incoming_track in incoming_tracks.into_iter() {
            if let Some(transceiver) = self.rtp_transceivers.iter_mut().find(|transceiver| {
                transceiver.mid().as_ref() == Some(&incoming_track.mid)
                    && incoming_track.kind == transceiver.kind()
                    && transceiver.direction().has_recv()
                    // A FEC session's section describes no track (RFC 5109 section 14.1).
                    && transceiver.fec_session().is_none()
            }) && let Some(receiver) = transceiver.receiver_mut()
            {
                // The MediaStreams the track is in, one per `a=msid` line (RFC 8830 section 2).
                receiver.set_streams(incoming_track.stream_ids.clone());

                // RFC 5576 section 6.1: a declaration its source's SDES contradicted is not
                // applied again to the stream it established, which keeps flowing as it is.
                let ctx = &self.pipeline_context.interceptor_handler_context;
                if incoming_track.ssrc.is_some_and(|ssrc| {
                    ctx.declaration_contradicted(ssrc)
                        && receiver
                            .track()
                            .get_codec_by_ssrc(ssrc)
                            .is_some_and(|codec| !codec.mime_type.is_empty())
                }) {
                    continue;
                }

                if is_same_remote_track(receiver, &incoming_track, appdata_names_the_track) {
                    // Keep SSRCs and codecs learned from RTP; the sender may no longer attach
                    // the MID/RID header extension needed to learn them again.
                    continue;
                }

                // What media that arrived before this answer established (RFC 3264 section
                // 5.1), carried over into the track the answer describes.
                let early = receiver.early_codings();

                // An `a=msid` without appdata names no track: "the recipient can assign the
                // track ID itself" (RFC 8830 section 3; RFC 9429 section 5.2.1 has senders
                // write that form). The receiver's track keeps the id it was given before.
                let mut incoming_track = incoming_track;
                if incoming_track.track_id.is_empty() {
                    incoming_track.track_id = if receiver.track().track_id().is_empty() {
                        math_rand_alpha(16)
                    } else {
                        receiver.track().track_id().clone()
                    };
                }

                // RFC 9143 section 9.2: the SSRCs the section declares beside its rids, bound
                // when a packet of theirs that carries no RID arrives.
                receiver.set_declared_codings(
                    std::mem::take(&mut incoming_track.declared_ssrcs)
                        .into_iter()
                        .map(|declared| RTCRtpCodingParameters {
                            rid: String::new(),
                            ssrc: Some(declared.ssrc),
                            rtx: declared.rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                            fec: declared.fec_ssrc.map(|ssrc| RTCRtpFecParameters { ssrc }),
                            ..Default::default()
                        })
                        .collect(),
                );

                let mut receive_codings = vec![];
                if !incoming_track.rids.is_empty() {
                    // for incoming_track with rids, defer adding track until received the first RTP
                    // packet with rtp header extension with "urn:ietf:params:rtp-hdrext:sdes:mid" and
                    // "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", so that endpoint handler can
                    // map the unknown ssrc to m= line. Here, we should add a track but with 0 ssrc.
                    // The reason is to provide stream_id and track_id information for later usage
                    // when received the first RTP packet. So, it is placeholder here.
                    let mut codings = vec![];
                    let mut rid_restrictions = std::mem::take(&mut incoming_track.rid_restrictions);
                    for rid in std::mem::take(&mut incoming_track.rids) {
                        // RFC 8851 section 5: the restrictions the sender's `a=rid` line put on
                        // the stream, as the application reads them from the receiver.
                        let restrictions = rid_restrictions.remove(&rid).unwrap_or_default();
                        let rtp_coding_parameters = RTCRtpCodingParameters {
                            rid,
                            ssrc: None, // Defer receiver's track's ssrc until received the first RTP packet with mid/rid header extension in endpoint handler
                            rtx: None,
                            fec: None,
                            rid_restrictions: restrictions,
                        };
                        receive_codings.push(rtp_coding_parameters.clone());
                        codings.push(RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(),
                            ..Default::default()
                        })
                    }

                    receiver.set_remote_track(MediaStreamTrack::new(
                        incoming_track.stream_id.clone(),
                        incoming_track.track_id.clone(),
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        codings,
                    ));
                } else if let Some(ssrc) = incoming_track.ssrc {
                    // The declared stream, and (RFC 5576 `a=ssrc-group:SIM`) the further
                    // simulcast streams of the track, each a coding with its repair flows.
                    let layers = std::iter::once(sdp::SsrcLayer {
                        ssrc,
                        rtx_ssrc: incoming_track.rtx_ssrc,
                        fec_ssrc: incoming_track.fec_ssrc,
                    })
                    .chain(std::mem::take(&mut incoming_track.ssrc_layers));
                    let mut codings = vec![];
                    for layer in layers {
                        let rtp_coding_parameters = RTCRtpCodingParameters {
                            rid: "".to_string(),
                            ssrc: Some(layer.ssrc),
                            rtx: layer
                                .rtx_ssrc
                                .map(|rtx_ssrc| RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                            fec: layer
                                .fec_ssrc
                                .map(|fec_ssrc| RTCRtpFecParameters { ssrc: fec_ssrc }),
                            ..Default::default()
                        };
                        receive_codings.push(rtp_coding_parameters.clone());
                        codings.push(RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(), // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                            ..Default::default()
                        });
                    }

                    receiver.set_remote_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        codings,
                    ));

                    // Deliberately no `interceptor_remote_streams_op` here. It bound nothing: that
                    // walks the track's codings and skips any whose codec does not resolve, and the
                    // codec above is `Default::default()` — deferred until the first RTP packet
                    // names a payload type. So the call read as "bound", always did nothing, and
                    // the streams stayed unbound for the life of the connection.
                    //
                    // The bind happens once the codec is known, in the endpoint handler's
                    // `find_track_id_by_ssrc`.
                } else {
                    // No a=ssrc: the SSRC doesn't have to be declared (RFC 8843 §9.2). With one
                    // media section its packets are that section's; with several, the MID header
                    // extension says which. Add a track with no coding as a placeholder, carrying
                    // the stream and track ids, until the first RTP packet binds its SSRC in the
                    // interceptor handler (`bind_undeclared_ssrc`).
                    receiver.set_remote_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        vec![], // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                    ));
                }

                receiver.set_coding_parameters(receive_codings);
                if let Some(early) = early {
                    receiver.adopt_early_codings(early);
                }
            }
        }

        // RFC 5576 section 6.1: the declarations whose SSRC's SDES named another CNAME.
        let mid_negotiated = self
            .media_engine
            .receive_header_extension_id(::sdp::extmap::SDES_MID_URI)
            != 0;
        let contradicted = self
            .pipeline_context
            .interceptor_handler_context
            .withdraw_contradicted_declarations(&mut self.rtp_transceivers, mid_negotiated);
        for ssrc in contradicted {
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnRemoteCnameMismatch(ssrc));
        }

        Ok(())
    }

    /// Update the PeerConnectionState given the state of relevant transports
    /// <https://www.w3.org/TR/webrtc/#rtcpeerconnectionstate-enum>
    pub(crate) fn update_connection_state(&mut self, is_closed: bool) {
        // Once closed, the state is terminal — ignore any subsequent transport
        // state changes that would otherwise re-evaluate to e.g. `New`.
        if self.peer_connection_state == RTCPeerConnectionState::Closed && !is_closed {
            return;
        }

        // W3C 4.3.3, over every transport.
        let connection_state = if is_closed {
            RTCPeerConnectionState::Closed
        } else {
            let transports = &self.pipeline_context.transports;
            aggregate_connection_state(
                &transports.ice_connection_states(),
                &transports.dtls_states(),
            )
        };

        if self.peer_connection_state == connection_state {
            return;
        }

        log::info!("peer connection state changed: {connection_state}");
        self.peer_connection_state = connection_state;

        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(connection_state),
        );
    }

    /// Called by the public `RTCRtpTransceiver::set_direction` when a transceiver's preferred
    /// direction actually changes, to update the connection's negotiation-needed flag.
    ///
    /// This is a narrow, purpose-specific entry point so the general-purpose
    /// [`Self::trigger_negotiation_needed`] can stay `pub(super)`.
    ///
    /// See <https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction>.
    pub(crate) fn on_transceiver_direction_changed(&mut self) {
        self.trigger_negotiation_needed();
    }

    /// W3C `RTCRtpTransceiver.stop()` and `RTCRtpSender.setStreams()` end by updating the
    /// negotiation-needed flag (W3C webrtc 5.4, 5.2).
    pub(crate) fn on_transceiver_stopped_or_streams_changed(&mut self) {
        self.trigger_negotiation_needed();
    }

    /// Helper to trigger a negotiation needed.
    pub(super) fn trigger_negotiation_needed(&mut self) {
        if !self.do_negotiation_needed() {
            return;
        }
        let _ = self.negotiation_needed_op();
    }

    fn do_negotiation_needed(&mut self) -> bool {
        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // non-canon step 1
        if self.negotiation_needed_state == NegotiationNeededState::Run {
            self.negotiation_needed_state = NegotiationNeededState::Queue;
            false
        } else if self.negotiation_needed_state == NegotiationNeededState::Queue {
            false
        } else {
            self.negotiation_needed_state = NegotiationNeededState::Run;
            true
        }
    }

    fn negotiation_needed_op(&mut self) -> bool {
        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // Step 2.1
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return false;
        }
        // non-canon step 2.2
        // no need to check ops

        // non-canon, run again if there was a request
        // starting defer(after_do_negotiation_needed(params).await);

        // Step 2.3
        if self.signaling_state != RTCSignalingState::Stable {
            return self.after_negotiation_needed_op();
        }

        // Step 2.4
        if !self.check_negotiation_needed() {
            self.is_negotiation_ongoing = false;
            return self.after_negotiation_needed_op();
        }

        // Step 2.5
        if self.is_negotiation_ongoing {
            return self.after_negotiation_needed_op();
        }

        // Step 2.6
        // set negotiation is in middle of ongoing
        self.is_negotiation_ongoing = true;

        // Step 2.7
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnNegotiationNeededEvent);

        //TODO: do we need this call with new event-based handling?
        self.after_negotiation_needed_op()
    }

    fn after_negotiation_needed_op(&mut self) -> bool {
        let old_negotiation_needed_state = self.negotiation_needed_state;

        self.negotiation_needed_state = NegotiationNeededState::Empty;

        if old_negotiation_needed_state == NegotiationNeededState::Queue {
            self.do_negotiation_needed()
        } else {
            false
        }
    }

    fn check_negotiation_needed(&self) -> bool {
        // To check if negotiation is needed for connection, perform the following checks:
        // Skip 1, 2 steps
        // Step 4: "If connection.[[LocalIceCredentialsToReplace]] is not empty, return true."
        if self.ice_restart_pending() {
            return true;
        }
        // A sender moved to an SSRC after a collision that the current local description does
        // not have: the description that signals it (`previous-ssrc`, RFC 5576 section 5) is
        // an offer.
        if let Some(local) = self
            .current_local_description
            .as_ref()
            .and_then(|d| d.parsed.as_ref())
        {
            let described = described_ssrcs(local);
            if self.rtp_transceivers.iter().any(|transceiver| {
                transceiver.sender().as_ref().is_some_and(|sender| {
                    sender.replacement_ssrcs().any(|ssrc| {
                        !described.contains(&ssrc) && sender.track().ssrcs().any(|s| s == ssrc)
                    })
                })
            }) {
                return true;
            }
        }
        // A peer without `ice2`: the controlling agent's offer aligns the default destination
        // with the nominated pair (RFC 8839 section 4.3.4).
        if self.needs_alignment_offer() {
            return true;
        }
        // Two lite agents, this one controlling, chose a pair among several: the updated
        // candidate exchange of RFC 8445 section 8.2 is an offer.
        if self
            .pipeline_context
            .transports
            .default()
            .ice_handler_context
            .lite_candidate_update
            .is_some()
        {
            return true;
        }
        // Step 3: "Let description be connection.[[CurrentLocalDescription]]."
        let Some(local_desc) = &self.current_local_description else {
            // Without a current local description nothing has been negotiated yet: step 4
            // (data channels without a data section) and step 5.2 (a transceiver that is not
            // stopped and has no section) are the only checks that can hold, and when neither
            // does there is nothing to negotiate (step 6). A rollback to a stable state with
            // nothing in it fires no negotiationneeded.
            return !self.data_channels.is_empty()
                || self.rtp_transceivers.iter().any(|t| !t.stopped());
        };
        {
            let len_data_channel = self.data_channels.len();

            if len_data_channel != 0 && have_data_channel(local_desc).is_none() {
                return true;
            }

            for transceiver in &self.rtp_transceivers {
                // https://www.w3.org/TR/webrtc/#dfn-update-the-negotiation-needed-flag
                // Steps 5.1 and 5.4. This engine stops a transceiver at once (no separate
                // "stopping" state), so `stopped()` covers both: one that never had an m=
                // section needs none, and one that has needs negotiating until that section is
                // rejected in both current descriptions (or has gone to another transceiver).
                if transceiver.stopped() {
                    let Some(mid) = transceiver.mid().as_deref() else {
                        continue;
                    };
                    let rejected_in = |desc: Option<&RTCSessionDescription>| {
                        desc.and_then(|desc| get_by_mid(mid, desc))
                            .is_none_or(is_rejected_media)
                    };
                    if rejected_in(Some(local_desc))
                        && rejected_in(self.current_remote_description.as_ref())
                    {
                        continue;
                    }
                    return true;
                }
                let m = transceiver
                    .mid()
                    .as_ref()
                    .and_then(|mid| get_by_mid(mid.as_str(), local_desc));
                // Step 5.2
                if m.is_none() {
                    return true;
                }

                if let Some(m) = m {
                    // Step 5.3.1
                    // A transceiver can carry a send direction without a sender: answering a
                    // `recvonly` offer creates one implicitly, and `remove_track` leaves one
                    // behind. There is then no track, so no msid for this step to compare, and
                    // nothing a renegotiation could settle - claiming otherwise re-offers on
                    // every return to a stable signaling state, forever.
                    if transceiver.direction().has_send()
                        && transceiver.describes_sender()
                        && let Some(sender) = transceiver.sender()
                    {
                        // The stream ids of the section's a=msid lines (one per stream,
                        // RFC 8830 section 2) against the sender's associated streams:
                        // `setStreams` changes those without changing the track.
                        let mut described: Vec<&str> = m
                            .attributes
                            .iter()
                            .filter(|a| a.key == ATTR_KEY_MSID)
                            .filter_map(|a| a.value.as_deref())
                            .filter_map(|msid| msid.split_whitespace().next())
                            .collect();
                        if described.is_empty() {
                            return true; // doesn't contain a single a=msid line
                        }
                        described.sort_unstable();
                        described.dedup();
                        let mut associated: Vec<&str> =
                            sender.streams().iter().map(String::as_str).collect();
                        associated.sort_unstable();
                        associated.dedup();
                        if described != associated {
                            return true;
                        }
                    }
                    match local_desc.sdp_type {
                        RTCSdpType::Offer => {
                            // Step 5.3.2
                            if let Some(remote_desc) = &self.current_remote_description {
                                if let Some(rm) = transceiver
                                    .mid()
                                    .as_ref()
                                    .and_then(|mid| get_by_mid(mid.as_str(), remote_desc))
                                {
                                    if get_peer_direction(m) != transceiver.direction()
                                        && get_peer_direction(rm)
                                            != transceiver.direction().reverse()
                                    {
                                        return true;
                                    }
                                } else {
                                    return true;
                                }
                            }
                        }
                        RTCSdpType::Answer => {
                            // Step 5.3.3: the answer's direction against [[Direction]]
                            // intersected with the offered direction (RFC 9429 section 5.3.1),
                            // the direction an answer made now would state.
                            let offered = self
                                .current_remote_description
                                .as_ref()
                                .zip(transceiver.mid().as_ref())
                                .and_then(|(remote_desc, mid)| {
                                    get_by_mid(mid.as_str(), remote_desc)
                                })
                                .map(get_peer_direction);
                            let expected = match offered {
                                Some(offered) => {
                                    answered_direction(transceiver.direction(), offered)
                                }
                                None => transceiver.direction(),
                            };
                            if m.attribute(expected.to_string().as_str()).is_none() {
                                return true;
                            }
                        }
                        _ => {}
                    };
                }

                // Step 5.4
            }
            // Step 6
            false
        }
    }

    pub(super) fn new_transceiver_from_track(
        &self,
        track: MediaStreamTrack,
        mut init: RTCRtpTransceiverInit,
    ) -> Result<RTCRtpTransceiverInternal> {
        if init.direction == RTCRtpTransceiverDirection::Unspecified {
            Err(Error::ErrPeerConnAddTransceiverFromTrackSupport)
        } else {
            if init.send_encodings.is_empty() {
                init.send_encodings = self.send_encodings_from_track(&track);
            }
            Ok(RTCRtpTransceiverInternal::new(
                track.kind(),
                Some(track),
                init,
            ))
        }
    }

    /// A new random SSRC for a local stream that no other local stream has (the encodings of
    /// every sender, and `minted`, which it is added to) and that no remote description
    /// mentions: RFC 5576 section 5, "an endpoint MUST NOT use as its own any SSRC identifiers
    /// mentioned in media descriptions it has received", and section 8, the SSRCs of an answer
    /// and of an updated offer are new.
    /// RFC 5576 section 5: "collisions between two signalled sources MUST be resolved
    /// immediately". A remote description that describes one of this side's sender SSRCs moves
    /// that sender to a new one at once, as a collision the RTCP session detects does
    /// (`InterceptorHandler::process_session_event`): its streams are bound again if they were
    /// bound, its statistics start over, the application gets `OnSsrcCollision`, and the next
    /// description of this side signals the new SSRC with `previous-ssrc`.
    pub(super) fn resolve_signalled_ssrc_collisions(
        &mut self,
        parsed: &::sdp::description::session::SessionDescription,
    ) {
        let remote = described_ssrcs(parsed);
        let collided: Vec<(usize, SSRC)> = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter_map(|(i, transceiver)| Some((i, transceiver.sender().as_ref()?)))
            .flat_map(|(i, sender)| {
                sender
                    .track()
                    .ssrcs()
                    .filter(|ssrc| remote.contains(ssrc))
                    .map(move |ssrc| (i, ssrc))
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut minted = vec![];
        for (i, old) in collided {
            let new = self.unused_ssrc(&mut minted);
            let Some(sender) = self.rtp_transceivers[i].sender_mut() else {
                continue;
            };
            let Some(primary) = sender.replace_ssrc(old, new) else {
                continue;
            };
            log::warn!("ssrc collision: the remote description describes the local ssrc {old}");
            if !sender.bound_streams().is_empty() {
                sender.rebind_local_streams(&self.media_engine, self.interceptor.as_mut());
            }
            if primary == old {
                self.stats_mut().replace_outbound_rtp_stream(old, new);
            }
            self.pipeline_context
                .interceptor_handler_context
                .ssrcs_replaced = true;
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnSsrcCollision(old));
        }
    }

    /// RFC 7160 section 4.1: the stream `old` of transceiver `index`'s sender is written with
    /// `codec`, of another clock rate, from `now` on, so it moves to a new SSRC (its RTX stream
    /// too). The stream it leaves stays in its RTCP session; a return to a rate used before
    /// sends a BYE for the SSRC that used it. The RTCP session is told the new SSRC's RTP
    /// session, its SDES identifiers, and the switch (the next compound packet leads with the
    /// new SSRC's sender report, the other rates' behind it). The outbound statistics carry on
    /// under the new SSRC. Returns the new SSRC.
    pub(crate) fn move_sender_to_clock_rate(
        &mut self,
        index: usize,
        old: SSRC,
        codec: &RTCRtpCodecParameters,
        now: Instant,
    ) -> Option<SSRC> {
        let mut minted = vec![];
        let new = self.unused_ssrc(&mut minted);
        let (has_rtx, rid) = {
            let sender = self.rtp_transceivers.get(index)?.sender().as_ref()?;
            let coding = sender
                .send_encodings()
                .iter()
                .map(|encoding| &encoding.rtp_coding_parameters)
                .find(|coding| coding.ssrc == Some(old))?;
            (coding.rtx.is_some(), coding.rid.clone())
        };
        let new_rtx = has_rtx.then(|| self.unused_ssrc(&mut minted));
        let mid = self.rtp_transceivers[index].mid().clone();
        let sender = self.rtp_transceivers[index].sender_mut().as_mut()?;
        let (info, previous) = sender.move_to_clock_rate(
            old,
            new,
            new_rtx,
            codec,
            &self.media_engine,
            self.interceptor.as_mut(),
        );
        log::debug!(
            "rtp sender of transceiver {index}: ssrc {old} moves to {new} for clock rate {} (RFC 7160 4.1)",
            codec.rtp_codec.clock_rate
        );
        self.stats_mut().replace_outbound_rtp_stream(old, new);
        let repair = info.as_ref().and_then(|info| info.ssrc_rtx);
        let mut controls = vec![];
        if self.pipeline_context.transports.len() > 1
            && let Some(mid) = mid.as_deref()
        {
            let session = self.pipeline_context.transports.transport_id_for(mid).0;
            controls.push(
                interceptor::RtpSessionAssignment {
                    session,
                    ssrcs: std::iter::once(new).chain(repair).collect(),
                }
                .into_packet(now),
            );
        }
        let rid = (!rid.is_empty()).then_some(rid);
        controls.push(
            interceptor::RtcpSessionControl::StreamIdentifiers {
                ssrc: new,
                mid: mid.clone(),
                rid: rid.clone(),
                repaired_rid: None,
            }
            .into_packet(now),
        );
        if let Some(repair) = repair {
            controls.push(
                interceptor::RtcpSessionControl::StreamIdentifiers {
                    ssrc: repair,
                    mid,
                    rid: None,
                    repaired_rid: rid,
                }
                .into_packet(now),
            );
        }
        controls.push(
            interceptor::RtcpSessionControl::ClockRateSwitch {
                current: new,
                previous,
            }
            .into_packet(now),
        );
        for control in controls {
            if let Err(err) = self.interceptor.handle_write(control) {
                log::warn!("rtcp session control after a clock rate switch: {err}");
            }
        }
        Some(new)
    }

    pub(super) fn unused_ssrc(&self, minted: &mut Vec<SSRC>) -> SSRC {
        self.unused_ssrc_drawn(minted, &mut rand::random::<u32>)
    }

    /// Adds the SSRCs of every local stream (each sender's encodings with their RTX and FEC
    /// flows, and the streams it parked for other clock rates) to
    /// [`ssrc_history`](RTCPeerConnection::ssrc_history), which [`unused_ssrc`](Self::unused_ssrc)
    /// draws outside of. Called when a local description is applied: what it describes has
    /// been used. Past [`MAX_SSRC_HISTORY`] entries nothing more is kept (a draw then only
    /// avoids the SSRCs in use, as RFC 5576 section 8 requires at the least).
    pub(super) fn remember_local_ssrcs(&mut self) {
        let mut used: Vec<SSRC> = vec![];
        for transceiver in &self.rtp_transceivers {
            if let Some(sender) = transceiver.sender() {
                for encoding in sender.send_encodings() {
                    let coding = &encoding.rtp_coding_parameters;
                    used.extend(coding.ssrc);
                    used.extend(coding.rtx.as_ref().map(|rtx| rtx.ssrc));
                    used.extend(coding.fec.as_ref().map(|fec| fec.ssrc));
                }
                used.extend(sender.parked_ssrcs());
            }
        }
        for ssrc in used {
            if self.ssrc_history.len() >= MAX_SSRC_HISTORY {
                break;
            }
            self.ssrc_history.insert(ssrc);
        }
    }

    /// An unused SSRC for a stream's media (not a repair flow): the SSRC the RTCP sessions
    /// report from while the connection has never had a local stream, any other unused one
    /// after that.
    ///
    /// RFC 8108 section 6.1: "An endpoint that has never sent an RTP stream will have an SSRC
    /// that it uses for RTCP reporting. If that endpoint wants to start sending an RTP
    /// stream, it is RECOMMENDED that it use its existing SSRC for that stream, since
    /// otherwise the participant count in the RTP session will be unnecessarily increased".
    /// The session announces its reporting SSRC
    /// ([`RtcpSessionEvent::ReportingSsrc`](interceptor::RtcpSessionEvent)) when it draws it
    /// (with its own random source, which an application may seed). The second and later
    /// streams get new SSRCs ("it will need to generate a new SSRC for the second and any
    /// subsequent RTP streams"), and so does every stream once a local stream has been
    /// described (the SSRC may then have said BYE as the reporting SSRC).
    pub(super) fn unused_media_ssrc(&self, minted: &mut Vec<SSRC>) -> SSRC {
        let reporting = self
            .pipeline_context
            .interceptor_handler_context
            .reporting_ssrc;
        let never_sent = self.ssrc_history.is_empty()
            && self.rtp_transceivers.iter().all(|transceiver| {
                transceiver.sender().as_ref().is_none_or(|sender| {
                    sender
                        .send_encodings()
                        .iter()
                        .all(|encoding| encoding.rtp_coding_parameters.ssrc.is_none())
                        && sender.parked_ssrcs().next().is_none()
                })
            });
        if let Some(reporting) = reporting
            && never_sent
            && !self.taken_ssrcs(minted).contains(&reporting)
        {
            minted.push(reporting);
            return reporting;
        }
        self.unused_ssrc(minted)
    }

    /// The SSRCs a new local SSRC must differ from: `minted`, every local stream's (with
    /// their repair flows and the streams of other clock rates), the remote descriptions'
    /// and those local streams used before.
    fn taken_ssrcs(&self, minted: &[SSRC]) -> HashSet<SSRC> {
        let mut taken: HashSet<SSRC> = minted.iter().copied().collect();
        for transceiver in &self.rtp_transceivers {
            if let Some(sender) = transceiver.sender() {
                for encoding in sender.send_encodings() {
                    let coding = &encoding.rtp_coding_parameters;
                    taken.extend(coding.ssrc);
                    taken.extend(coding.rtx.as_ref().map(|rtx| rtx.ssrc));
                    taken.extend(coding.fec.as_ref().map(|fec| fec.ssrc));
                }
                // The streams of other clock rates are still in the session (RFC 7160 4.1).
                taken.extend(sender.parked_ssrcs());
            }
        }
        for description in [
            &self.current_remote_description,
            &self.pending_remote_description,
        ] {
            if let Some(parsed) = description.as_ref().and_then(|d| d.parsed.as_ref()) {
                taken.extend(described_ssrcs(parsed));
            }
        }
        // RFC 5576 sections 5 and 8: nor one a local stream used before.
        taken.extend(&self.ssrc_history);
        taken
    }

    /// [`unused_ssrc`](Self::unused_ssrc) with the candidates drawn from `draw`.
    fn unused_ssrc_drawn(&self, minted: &mut Vec<SSRC>, draw: &mut dyn FnMut() -> SSRC) -> SSRC {
        let taken = self.taken_ssrcs(minted);
        let ssrc = unused_ssrc_from(std::iter::repeat_with(draw), &taken);
        minted.push(ssrc);
        ssrc
    }

    pub(super) fn send_encodings_from_track(
        &self,
        track: &MediaStreamTrack,
    ) -> Vec<RTCRtpEncodingParameters> {
        self.send_encodings_from_track_drawn(track, &mut rand::random::<u32>)
    }

    /// [`send_encodings_from_track`](Self::send_encodings_from_track) with the SSRCs it mints
    /// drawn from `draw`.
    fn send_encodings_from_track_drawn(
        &self,
        track: &MediaStreamTrack,
        draw: &mut dyn FnMut() -> SSRC,
    ) -> Vec<RTCRtpEncodingParameters> {
        let (is_rtx_enabled, is_fec_enabled) = (
            self.media_engine
                .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
            self.media_engine
                .is_fec_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
        );

        // RFC 4588 section 4: a minted RTX (or FEC) SSRC differs from every SSRC the track's
        // own codings name, not only from those of other senders and remote descriptions.
        let mut minted: Vec<SSRC> = track
            .codings()
            .iter()
            .flat_map(|coding| {
                let coding = &coding.rtp_coding_parameters;
                [
                    coding.ssrc,
                    coding.rtx.as_ref().map(|rtx| rtx.ssrc),
                    coding.fec.as_ref().map(|fec| fec.ssrc),
                ]
            })
            .flatten()
            .collect();
        let mut new_ssrc = || self.unused_ssrc_drawn(&mut minted, draw);
        track
            .codings()
            .iter()
            .map(|coding| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: coding.rtp_coding_parameters.rid.to_owned(),
                    ssrc: coding.rtp_coding_parameters.ssrc.to_owned(),
                    // Whether there is a repair flow at all is the media engine's call: without a
                    // codec registered to carry it, an `a=ssrc-group` naming a repair SSRC has no
                    // `a=rtpmap` to give it a format, and that is an offer no peer can act on.
                    //
                    // Given one, the SSRC follows the same rule as the media SSRC on the line
                    // above: what the application named is what gets used, and one is minted only
                    // when the track left it unset.
                    rtx: is_rtx_enabled.then(|| {
                        coding
                            .rtp_coding_parameters
                            .rtx
                            .clone()
                            .unwrap_or_else(|| RTCRtpRtxParameters { ssrc: new_ssrc() })
                    }),
                    fec: is_fec_enabled.then(|| {
                        coding
                            .rtp_coding_parameters
                            .fec
                            .clone()
                            .unwrap_or_else(|| RTCRtpFecParameters { ssrc: new_ssrc() })
                    }),
                    rid_restrictions: coding.rtp_coding_parameters.rid_restrictions.clone(),
                },
                codec: coding.codec.clone(),
                ..Default::default()
            })
            .collect()
    }

    pub(crate) fn stats(&self) -> &RTCStatsAccumulator {
        &self.pipeline_context.stats
    }

    pub(crate) fn stats_mut(&mut self) -> &mut RTCStatsAccumulator {
        &mut self.pipeline_context.stats
    }

    /// Stages an ICE restart so the next offer advertises fresh credentials.
    ///
    /// The live session is untouched: inbound STUN keeps validating against the current ufrag/pwd
    /// until [`Self::apply_ice_restart`] runs at `set_local_description`. JSEP requires
    /// `createOffer` to be free of side effects, and an offer that is created and then discarded
    /// must leave a working connection working.
    ///
    /// The gathering state does move here, because SDP generation reads it and a restart offer
    /// must not claim end-of-candidates.
    pub(super) fn stage_ice_restart(&mut self) -> Result<()> {
        // Fixed credentials from the settings are the default transport's.
        let (local_ufrag, local_pwd) = if self.pipeline_context.transports.active_id()
            == self.pipeline_context.transports.default_id()
        {
            (
                self.setting_engine.candidates.username_fragment.clone(),
                self.setting_engine.candidates.password.clone(),
            )
        } else {
            self.restart_credentials_for_other_transport()
        };
        self.ice_transport_mut()
            .generate_restart_credentials(local_ufrag, local_pwd)?;
        self.ice_transport_mut().ice_gathering_state = RTCIceGatheringState::Gathering;

        Ok(())
    }

    /// The credentials a transport other than the default one restarts with: the ones the
    /// default transport has staged when the transports share theirs and it restarts too
    /// (`with_unique_transport_credentials` off), else new ones (empty: generated).
    fn restart_credentials_for_other_transport(&self) -> (String, String) {
        if self.setting_engine.unique_transport_credentials {
            return (String::new(), String::new());
        }
        let default = self.ice_transport_of(self.pipeline_context.transports.default_id());
        if !default.has_pending_restart() {
            return (String::new(), String::new());
        }
        let staged = default.agent.get_local_credentials();
        (staged.ufrag.clone(), staged.pwd.clone())
    }

    /// `restartIce` and an offer of this side that restarts ICE: every transport stages new
    /// credentials (W3C restartIce: "all ICE transports"), the default one first so that the
    /// others can take its credentials when they share them.
    pub(super) fn stage_ice_restart_on_every_transport(&mut self) -> Result<()> {
        let default = self.pipeline_context.transports.default_id();
        self.with_transport(default, |pc| pc.stage_ice_restart())?;
        for id in self.pipeline_context.transports.ids() {
            if id != default {
                self.with_transport(id, |pc| pc.stage_ice_restart())?;
            }
        }
        Ok(())
    }

    /// Applies the ICE restart every transport has staged (`set_local_description`); a
    /// transport with none staged is left alone. A local offer's (`revertible`) can be taken
    /// back by its rollback ([`Self::revert_local_ice_restart`]).
    pub(super) fn apply_staged_ice_restarts(
        &mut self,
        now: Instant,
        revertible: bool,
    ) -> Result<()> {
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| {
                if !pc.ice_transport().has_pending_restart() {
                    Ok(())
                } else if revertible {
                    pc.apply_local_offer_ice_restart(now)
                } else {
                    pc.apply_ice_restart(now)
                }
            })?;
        }
        Ok(())
    }

    /// Whether any transport has an ICE restart staged.
    pub(super) fn any_ice_restart_staged(&self) -> bool {
        self.pipeline_context
            .transports
            .ids()
            .into_iter()
            .any(|id| self.ice_transport_of(id).has_pending_restart())
    }

    /// Drops the transport part of the pending remote offer
    /// ([`PendingRemoteTransport`]) and what it staged for its answer: the offer was rolled
    /// back, refused or replaced by another one.
    pub(super) fn drop_pending_remote_transport(&mut self) {
        let Some(pending) = self.pending_remote_transport.take() else {
            return;
        };
        if let Some(gathering) = pending.staged_restart {
            self.ice_transport_mut().discard_restart_credentials();
            self.ice_transport_mut().ice_gathering_state = gathering;
        }
        if pending.staged_tls_id {
            self.dtls_transport_mut().drop_answer_tls_id();
        }
        for (id, gathering, staged_tls_id) in pending.other_restarts {
            if self.pipeline_context.transports.transport(id).is_none() {
                continue;
            }
            self.with_transport(id, |pc| {
                if let Some(gathering) = gathering {
                    pc.ice_transport_mut().discard_restart_credentials();
                    pc.ice_transport_mut().ice_gathering_state = gathering;
                }
                if staged_tls_id {
                    pc.dtls_transport_mut().drop_answer_tls_id();
                }
            });
        }
    }

    /// Applies the ICE restart a local offer staged (`create_offer`) so that a rollback of
    /// the offer can take it back ([`Self::revert_local_ice_restart`]; RFC 9429 section 5.7:
    /// "any resources allocated by the abandoned local description are discarded").
    pub(super) fn apply_local_offer_ice_restart(&mut self, now: Instant) -> Result<()> {
        let new_association = self.restart_needs_new_local_addresses(true);
        let keep_local_candidates = !new_association
            && !self
                .setting_engine
                .candidates
                .discard_local_candidates_during_ice_restart;
        let before = self
            .ice_transport_mut()
            .retire_local_addresses(new_association);
        self.ice_transport_mut()
            .previous_association_addresses_before_local_restart
            .get_or_insert(before);
        self.ice_transport_mut().candidates_needed =
            self.candidates_needed_reason(new_association, keep_local_candidates);
        if new_association {
            self.forget_srflx_of_refused_bases();
            self.reallocate_turn_links_of_active_transport(now);
        }
        if self
            .ice_transport()
            .gathering_before_local_restart
            .is_none()
        {
            let announced = self.announced_gathering();
            self.ice_transport_mut().gathering_before_local_restart = Some(announced);
        }
        self.ice_transport_mut()
            .agent
            .apply_restart_revertible(now, keep_local_candidates)
    }

    /// The answer to the local offer arrived: its ICE restart is kept.
    pub(super) fn commit_local_ice_restart(&mut self) {
        self.ice_transport_mut().agent.commit_restart();
        self.ice_transport_mut().gathering_before_local_restart = None;
        self.ice_transport_mut()
            .previous_association_addresses_before_local_restart = None;
    }

    /// Whether the ICE restart about to be applied on the active transport sets up a new DTLS
    /// association whose 3-tuple this side allocates (RFC 8842 section 5.1: an offerer that
    /// needs a new association, and an answerer when the offerer did not, "MUST allocate a new
    /// 3-tuple"; section 6: "a completely new set of ICE candidates that were not recently
    /// used for any other DTLS association"): its local candidates are discarded and their
    /// UDP addresses refused. `local_offer`: the restart is a local offer's; otherwise it is
    /// the answer's to a remote offer. The answerer allocates whether or not the offerer did,
    /// which it cannot know with trickle ICE when it answers. Off with
    /// `with_dtls_new_association_on_previous_addresses(true)`.
    pub(super) fn restart_needs_new_local_addresses(&self, local_offer: bool) -> bool {
        self.restart_needs_new_local_addresses_of(
            self.pipeline_context.transports.active_id(),
            local_offer,
        )
    }

    /// [`Self::restart_needs_new_local_addresses`] for transport `id`.
    pub(super) fn restart_needs_new_local_addresses_of(
        &self,
        id: TransportId,
        local_offer: bool,
    ) -> bool {
        if self
            .setting_engine
            .dtls_new_association_on_previous_addresses
        {
            return false;
        }
        let dtls = self.dtls_transport_of(id);
        // The `tls-id` of the new association: staged by the offer that asks for one
        // (`offer_tls_id`) or by the answer to an offer that does (`defer_remote_transport`).
        if dtls.staged_local_tls_id.is_some() {
            return true;
        }
        if !local_offer {
            return false;
        }
        // An offer that asks for a new association without `a=tls-id`
        // (`with_disable_sdp_tls_id`): it replaces a data-only association for SRTP (RFC 5764
        // section 4.1) or renews it (`renew_dtls_association`); `create_offer` restarts ICE
        // for each. A transport an answer closed (every m= section rejected, W3C 4.4.1.4) is
        // not set up again: a new one, not started, replaces it, with an ICE agent of its own
        // that holds no candidate of the closed one.
        dtls.is_started()
            && (dtls.renewal_requested
                || (self.rtp_transceivers.iter().any(|t| !t.stopped()) && !dtls.can_key_srtp()))
    }

    /// The local offer was rolled back: the ICE session goes on as before its restart, with
    /// its credentials, candidates and selected pair, and the gathering state it had (RFC 9429
    /// section 5.7). A no-op when the offer restarted nothing.
    pub(super) fn revert_local_ice_restart(&mut self, now: Instant) {
        // The `tls-id` of the new association the offer asked for goes with it.
        self.dtls_transport_mut().discard_offer_tls_id();
        let gathering = self
            .ice_transport_mut()
            .gathering_before_local_restart
            .take();
        self.ice_transport_mut().candidates_needed = None;
        if let Some(before) = self
            .ice_transport_mut()
            .previous_association_addresses_before_local_restart
            .take()
        {
            self.ice_transport_mut().previous_association_addresses = before;
        }
        if !self.ice_transport_mut().agent.revert_restart(now) {
            return;
        }
        if let Some(gathering) = gathering {
            self.restore_announced_gathering(gathering);
        }
    }

    /// Applies a staged ICE restart, restarting the agent's timers at `now`.
    ///
    /// A no-op when nothing is staged, so `set_local_description` can call it unconditionally
    /// without tearing down a session that was never asked to restart.
    pub(super) fn apply_ice_restart(&mut self, now: Instant) -> Result<()> {
        let new_association = self.restart_needs_new_local_addresses(false);
        let keep_local_candidates = !new_association
            && !self
                .setting_engine
                .candidates
                .discard_local_candidates_during_ice_restart;
        self.ice_transport_mut()
            .retire_local_addresses(new_association);
        self.ice_transport_mut().candidates_needed =
            self.candidates_needed_reason(new_association, keep_local_candidates);
        if new_association {
            self.forget_srflx_of_refused_bases();
            self.reallocate_turn_links_of_active_transport(now);
        }
        self.ice_transport_mut()
            .apply_restart(now, keep_local_candidates)
    }

    /// Why the active transport needs new local candidates after the ICE restart about to be
    /// applied, if it does (`OnLocalCandidatesNeeded`): it is for a new DTLS association
    /// (`new_association`, so the candidates are dropped and their addresses refused), or the
    /// restart drops the candidates without keeping any (`keep_local_candidates` false).
    fn candidates_needed_reason(
        &self,
        new_association: bool,
        keep_local_candidates: bool,
    ) -> Option<RTCLocalCandidatesNeededReason> {
        if new_association {
            let dtls = self.dtls_transport();
            Some(
                if dtls.renewal_requested && dtls.renewal_for_srtp_rekeying {
                    RTCLocalCandidatesNeededReason::SrtpRekeying
                } else {
                    RTCLocalCandidatesNeededReason::NewDtlsAssociation
                },
            )
        } else if !keep_local_candidates {
            Some(RTCLocalCandidatesNeededReason::DiscardedBySetting)
        } else {
            None
        }
    }

    pub(super) fn start_transports(
        &mut self,
        now: Instant,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        // Update ICE role (may change after ICE restart if peer roles swap)
        self.pipeline_context.stats.transport.ice_role = local_ice_role;

        // Start the ice transport
        self.ice_transport_mut()
            .start(now, local_ice_role, remote_ice_parameters)?;

        // Start the dtls transport
        self.dtls_transport_mut()
            .start(local_ice_role, remote_dtls_parameters)?;
        // A ClientHello that arrived before the answer (RFC 8842 section 5.2), now that DTLS
        // has an endpoint, if ICE has a path already.
        self.release_early_dtls();

        self.update_connection_state(false);

        Ok(())
    }

    /// Converts an RTCIceCandidate to an IceCandidateAccumulator for stats collection.
    ///
    /// # Parameters
    ///
    /// * `candidate` - The ICE candidate to convert.
    /// * `username_fragment` - The ICE username fragment.
    /// * `url` - Optional STUN/TURN server URL. Per W3C spec, this should only be
    ///   provided for local candidates of type "srflx" or "relay".
    pub(super) fn candidate_to_accumulator(
        &self,
        candidate: &RTCIceCandidate,
        username_fragment: &str,
        url: Option<&str>,
    ) -> IceCandidateAccumulator {
        // Per W3C spec, URL is only valid for local srflx/relay candidates
        let url_for_stats = match candidate.typ {
            RTCIceCandidateType::Srflx | RTCIceCandidateType::Relay => {
                url.map(|s| s.to_string()).unwrap_or_default()
            }
            _ => String::new(),
        };

        IceCandidateAccumulator {
            transport_id: self.pipeline_context.stats.transport.transport_id.clone(),
            address: if candidate.address.is_empty() {
                None
            } else {
                Some(candidate.address.clone())
            },
            port: candidate.port,
            protocol: candidate.protocol.to_string(),
            candidate_type: candidate.typ,
            priority: candidate.priority,
            // webrtc-stats `relayProtocol`: how the endpoint reaches the TURN server of a local
            // relay candidate. The application does that, so the candidate does not say; the
            // TURN URL it was gathered from does (RFC 7065).
            relay_protocol: match candidate.relay_protocol {
                RTCIceServerTransportProtocol::Unspecified
                    if candidate.typ == RTCIceCandidateType::Relay =>
                {
                    relay_protocol_of_turn_url(&url_for_stats)
                }
                protocol => protocol,
            },
            url: url_for_stats,
            foundation: candidate.foundation.clone(),
            related_address: candidate.related_address.clone(),
            related_port: candidate.related_port,
            username_fragment: username_fragment.to_string(),
            tcp_type: candidate.tcp_type,
            signalled: false,
        }
    }

    pub(super) fn add_ice_remote_candidate(&mut self, candidate_value: &str) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;
        self.add_signalled_remote_candidate(candidate)
    }

    /// Gives the ICE agent a remote candidate the application supplied, through
    /// `add_remote_candidate` or in a candidate line of a remote description, and registers
    /// its statistics.
    pub(super) fn add_signalled_remote_candidate(&mut self, candidate: Candidate) -> Result<()> {
        // Register remote candidate with stats accumulator, only once the agent keeps it (one
        // past its cap is dropped there and here).
        // Per W3C spec, URL must NOT be present for remote candidates
        let rtc_candidate: RTCIceCandidate = (&candidate).into();
        let candidate_id = remote_candidate_stats_id(&rtc_candidate.id);
        let (ufrag, _) = self.ice_transport().get_remote_user_credentials();
        let mut accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, None);
        // The application supplied this candidate, so its address may be shown in the stats.
        accumulator.signalled = true;

        // An mDNS candidate is held by the agent only once its name resolves, and not at all
        // when it is ignored. Its statistics object exists from the moment it is submitted
        // all the same, so that the report does not say whether the name resolved
        // (draft-ietf-mmusic-mdns-ice-candidates section 3.3.1).
        let is_mdns = candidate.address().ends_with(".local");
        // W3C 4.4.2: an administratively prohibited candidate behaves exactly as if it were
        // added, its statistics included, but the agent never checks connectivity to it.
        // So is one on an address the embedder's address policy refuses
        // (`SettingEngineBuilder::with_ice_address_policy`): that is the user agent's choice
        // "not to allow connection attempts to this address" of 4.4.2.
        let refused_by_policy = candidate.address().parse::<std::net::IpAddr>().is_ok()
            && !self.address_allowed(candidate.addr(), ice::AddressPurpose::RemoteCandidate);
        if refused_by_policy
            || super::prohibited::is_administratively_prohibited(
                &candidate,
                self.configuration.ice_transport_policy,
            )
        {
            self.stats_mut()
                .register_remote_candidate(candidate_id, accumulator);
            return Ok(());
        }
        let kept = self.ice_transport_mut().add_remote_candidate(candidate)?;
        if kept
            || (is_mdns
                && self.stats().remote_candidates.len() < MAX_UNRESOLVED_MDNS_CANDIDATE_STATS)
        {
            self.stats_mut()
                .register_remote_candidate(candidate_id, accumulator);
        }
        Ok(())
    }

    pub(super) fn add_ice_local_candidate(
        &mut self,
        candidate_value: &str,
        url: Option<&str>,
        relay_protocol: Option<RTCIceServerTransportProtocol>,
    ) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;
        // RFC 8842 sections 5.1 and 6: a new DTLS association over UDP runs on a new 3-tuple
        // (`restart_needs_new_local_addresses`).
        // While the restart of a new association is staged, the addresses of the generation
        // it replaces are refused already: a candidate given now is the next generation's.
        let staged_new_association = self.ice_transport().has_pending_restart()
            && self.restart_needs_new_local_addresses(self.pending_remote_transport.is_none());
        let refused = self
            .ice_transport()
            .on_previous_association_address(&candidate)
            .or_else(|| {
                (staged_new_association && candidate.network_type().is_udp())
                    .then(|| candidate.addr())
                    .filter(|addr| {
                        self.ice_transport()
                            .current_generation_udp_addresses()
                            .contains(addr)
                    })
            });
        if let Some(addr) = refused {
            return Err(Error::ErrICECandidateAddressOfPreviousDtlsAssociation(addr));
        }
        let known = self.ice_transport().agent.get_local_candidates().len();
        let ufrag = self
            .ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        let added: Vec<RTCIceCandidate> = if self
            .ice_transport_mut()
            .add_local_candidate(candidate.clone())?
        {
            // Usually one candidate is added; with a server-reflexive 1:1 NAT mapping
            // (`nat_1to1_ips`) the agent adds a second, on the external address. Each is
            // announced.
            let added: Vec<RTCIceCandidate> = self
                .ice_transport()
                .agent
                .get_local_candidates()
                .iter()
                .skip(known)
                .map(RTCIceCandidate::from)
                .collect();
            if added.is_empty() {
                return Err(Error::Other(
                    "local candidate missing after registration".to_owned(),
                ));
            }
            added
        } else {
            // An ICE restart keeps the local candidates by default
            // (`discard_local_candidates_during_ice_restart`), so the application's
            // gathering of the new generation re-adds candidates the agent already holds.
            // They belong to the new generation too (W3C 5.6, RFC 8838 section 9: the peer
            // discards the candidates of the old one), so one not yet announced for it is
            // announced now, once. Anything else the agent refused stays silent.
            let gathering = self.active_announced().gathering;
            let kept = self
                .ice_transport()
                .agent
                .get_local_candidates()
                .iter()
                .find(|kept| kept.equal(&candidate))
                .map(RTCIceCandidate::from);
            match kept {
                Some(kept)
                    if gathering == RTCIceGatheringState::Gathering
                        && !self.active_announced().announced_candidates.iter().any(
                            |(generation, announced)| {
                                *generation == ufrag && *announced == kept.to_string()
                            },
                        ) =>
                {
                    vec![kept]
                }
                _ => return Ok(()),
            }
        };

        for mut rtc_candidate in added {
            let announced = self.active_announced_mut();
            announced
                .announced_candidates
                .retain(|(generation, _)| *generation == ufrag);
            announced
                .announced_candidates
                .push((ufrag.clone(), rtc_candidate.to_string()));
            // Register local candidate with stats accumulator
            let candidate_id = local_candidate_stats_id(&rtc_candidate.id);
            // The candidate is of this ICE generation: `to_json` carries the fragment, and
            // the peer ignores it if it arrives after an ICE restart (RFC 8838 section 9). It
            // also names the media section of the transport (W3C "surface the candidate").
            self.ice_transport()
                .describe_local_candidate(&mut rtc_candidate);
            // W3C 4.8.1 `url` and `relayProtocol`: the server a local server-reflexive or
            // relay candidate was gathered from, and for a relay candidate the protocol to
            // the TURN server (RTCLocalIceCandidateInit; the application gathers, so it
            // supplies them). Null for every other candidate.
            match rtc_candidate.typ {
                RTCIceCandidateType::Srflx | RTCIceCandidateType::Relay => {
                    if rtc_candidate.url.is_none() {
                        rtc_candidate.url = url.map(str::to_owned);
                    }
                }
                _ => rtc_candidate.url = None,
            }
            if rtc_candidate.typ == RTCIceCandidateType::Relay {
                rtc_candidate.relay_protocol = relay_protocol
                    .filter(|protocol| *protocol != RTCIceServerTransportProtocol::Unspecified)
                    .unwrap_or_else(|| {
                        rtc_candidate
                            .url
                            .as_deref()
                            .map_or(RTCIceServerTransportProtocol::Unspecified, |u| {
                                relay_protocol_of_turn_url(u)
                            })
                    });
            }
            let (ufrag, _) = self.ice_transport().get_local_user_credentials();
            let accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, url);
            self.stats_mut()
                .register_local_candidate(candidate_id, accumulator);

            // Emit OnIceCandidateEvent
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: Some(rtc_candidate),
                    url: url.map(str::to_owned),
                    ice_transport: Some(self.ice_transport().id),
                }),
            );
        }

        Ok(())
    }

    /// Update the candidate pair stats from the ICE agent: every pair it holds, with its state,
    /// nomination and STUN transaction counters.
    ///
    /// This is called automatically by `get_stats()`. webrtc-stats reports a
    /// `RTCIceCandidatePairStats` for each pair of the ICE transport, not only the selected one,
    /// and every candidate a pair names has a candidate stats object of its own (every id a
    /// stats object names resolves in the same report). Pairs the agent no longer holds (an ICE
    /// restart drops them) are dropped from the stats too.
    pub(super) fn update_ice_agent_stats(&mut self, now: Instant) {
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.update_ice_agent_stats_on_active(now));
        }
    }

    /// `update_ice_agent_stats` for the active transport's agent.
    fn update_ice_agent_stats_on_active(&mut self, now: Instant) {
        let agent = &self
            .pipeline_context
            .transports
            .active()
            .ice_handler_context
            .ice_transport
            .agent;
        let pairs = agent.get_candidate_pairs_stats(now);

        // A local candidate is normally registered when gathered, a remote one when signalled;
        // one the agent learned from a connectivity check (peer-reflexive, RFC 8445 section
        // 7.3.1.3) was never signalled, so it has no stats object yet.
        let unregistered_local: Vec<RTCIceCandidate> = agent
            .get_local_candidates()
            .iter()
            .filter(|c| {
                pairs.iter().any(|p| p.local_candidate_id == c.id())
                    && !self
                        .pipeline_context
                        .stats
                        .local_candidates
                        .contains_key(&local_candidate_stats_id(c.id()))
            })
            .map(RTCIceCandidate::from)
            .collect();
        // A remote candidate also needs (new) statistics when it is no longer what its object
        // says: a peer-reflexive candidate that the signalled candidate with its address
        // replaced keeps its id, and so its pairs (RFC 8838 section 11), but is a signalled
        // host or server-reflexive candidate now, with the address that was signalled (the
        // name, for an mDNS candidate that resolved to it).
        let unregistered_remote: Vec<RTCIceCandidate> = agent
            .get_remote_candidates()
            .iter()
            .filter(|c| {
                pairs.iter().any(|p| p.remote_candidate_id == c.id())
                    && self
                        .pipeline_context
                        .stats
                        .remote_candidates
                        .get(&remote_candidate_stats_id(c.id()))
                        .is_none_or(|known| {
                            known.candidate_type != RTCIceCandidateType::from(c.candidate_type())
                        })
            })
            .map(|c| {
                let mut candidate = RTCIceCandidate::from(c);
                // draft-ietf-mmusic-mdns-ice-candidates section 3.3.1: a peer-reflexive
                // candidate's address is shown only when the peer signalled that address
                // itself; it may be the one an mDNS name hides.
                if c.candidate_type() == ::ice::candidate::CandidateType::PeerReflexive
                    && !agent.is_signalled_remote_ip(c.addr().ip())
                {
                    candidate.address.clear();
                }
                candidate
            })
            .collect();

        if !unregistered_local.is_empty() {
            let ufrag = self
                .ice_transport()
                .get_local_user_credentials()
                .0
                .to_owned();
            for candidate in unregistered_local {
                let accumulator = self.candidate_to_accumulator(&candidate, &ufrag, None);
                self.stats_mut()
                    .register_local_candidate(local_candidate_stats_id(&candidate.id), accumulator);
            }
        }
        if !unregistered_remote.is_empty() {
            let remote_ufrag = self
                .ice_transport()
                .get_remote_user_credentials()
                .0
                .to_owned();
            for candidate in unregistered_remote {
                let id = remote_candidate_stats_id(&candidate.id);
                let accumulator = if candidate.typ == RTCIceCandidateType::Prflx {
                    // Learned from a check, never signalled: no username fragment was given
                    // for it (webrtc-stats `usernameFragment`), and its address is not shown
                    // (`RTCStatsAccumulator::remote_candidate_entries`).
                    self.candidate_to_accumulator(&candidate, "", None)
                } else {
                    // Every other remote candidate the agent holds was signalled: one whose
                    // mDNS name resolved after it was submitted, or one that took the place
                    // of a learned candidate. The object made when it was submitted, under the
                    // id it had then, gives way to this one.
                    let mut accumulator =
                        self.candidate_to_accumulator(&candidate, &remote_ufrag, None);
                    accumulator.signalled = true;
                    let (address, port, protocol) = (
                        accumulator.address.clone(),
                        accumulator.port,
                        accumulator.protocol.clone(),
                    );
                    self.stats_mut().remote_candidates.retain(|other, known| {
                        *other == id
                            || !(known.signalled
                                && known.address == address
                                && known.port == port
                                && known.protocol == protocol)
                    });
                    accumulator
                };
                self.stats_mut().register_remote_candidate(id, accumulator);
            }
        }

        // Sync each pair's STUN stats, state and nomination from the agent, and drop the pairs
        // it no longer holds.
        self.pipeline_context.stats.sync_ice_candidate_pairs(&pairs);

        // And the candidates it no longer holds (an ICE restart lets go of them), unless a
        // pair that is still reported names them.
        let agent = &self
            .pipeline_context
            .transports
            .active()
            .ice_handler_context
            .ice_transport
            .agent;
        let local_held: HashSet<String> = agent
            .get_local_candidates()
            .iter()
            .map(|c| local_candidate_stats_id(c.id()))
            .collect();
        let mut remote_held: HashSet<String> = agent
            .get_remote_candidates()
            .iter()
            .map(|c| remote_candidate_stats_id(c.id()))
            .collect();
        // The mDNS candidates that were submitted for this ICE generation stay in the report
        // whether their name has resolved, has not yet, or never will (mDNS draft section
        // 3.3.1: the report does not leak whether resolution succeeded). So do those on a
        // bad port, which the agent never holds (W3C 4.4.2: an administratively prohibited
        // candidate behaves exactly as if it were added).
        let remote_ufrag = agent
            .get_remote_credentials()
            .map(|credentials| credentials.ufrag.as_str())
            .unwrap_or_default();
        remote_held.extend(
            self.pipeline_context
                .stats
                .remote_candidates
                .iter()
                .filter(|(_, known)| {
                    known.signalled
                        && known.username_fragment == remote_ufrag
                        && (known
                            .address
                            .as_deref()
                            .is_some_and(|address| address.ends_with(".local"))
                            || super::prohibited::BAD_PORTS.contains(&known.port))
                })
                .map(|(id, _)| id.clone()),
        );
        self.pipeline_context
            .stats
            .retain_candidates(&local_held, &remote_held);
    }

    /// Update the media source stats from the senders: the track each sender has attached has
    /// a `media-source` object, from the moment it is attached until no sender has it
    /// (webrtc-stats 8.11).
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn update_media_source_stats(&mut self) {
        let attached: Vec<(usize, String, RtpCodecKind)> = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter_map(|(transceiver_id, transceiver)| {
                let sender = transceiver.sender().as_ref()?;
                Some((
                    transceiver_id,
                    sender.attached_track()?.track_id().clone(),
                    sender.kind(),
                ))
            })
            .collect();
        self.pipeline_context.stats.sync_media_sources(&attached);
    }

    /// Whether `selector` names a sender or a receiver of this peer connection (or nothing).
    pub(super) fn stats_selector_is_ours(&self, selector: &StatsSelector) -> bool {
        match selector {
            StatsSelector::Sender(id) => self
                .rtp_transceivers
                .get(id.0)
                .is_some_and(|transceiver| transceiver.sender().is_some()),
            StatsSelector::Receiver(id) => self
                .rtp_transceivers
                .get(id.0)
                .is_some_and(|transceiver| transceiver.receiver().is_some()),
            _ => true,
        }
    }

    /// Update the transport stats from the DTLS transport itself: webrtc-stats
    /// `RTCTransportStats.dtlsState` is the `RTCDtlsTransport`'s state, which goes through
    /// `new`, `connecting`, `connected`, `closed` and `failed`, not only `connected`. (The ICE
    /// state follows the agent's events already.)
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn update_transport_stats(&mut self) {
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.update_transport_stats_on_active());
        }
        self.pipeline_context.stats.sync_outgoing_estimates();
    }

    /// `update_transport_stats` for the active transport.
    fn update_transport_stats_on_active(&mut self) {
        let dtls_state = self.dtls_transport().state();
        // webrtc-stats `iceLocalUsernameFragment`: the local username fragment in use for
        // message validation, which is the ICE agent's current one: the first description's,
        // then each applied restart's.
        let ufrag = self
            .ice_transport()
            .get_local_user_credentials()
            .0
            .to_owned();
        let transport = &mut self.pipeline_context.stats.transport;
        transport.on_dtls_state_changed(dtls_state);
        transport.ice_local_username_fragment = ufrag;
    }

    /// Update the data channel stats from the data channels themselves: every channel the peer
    /// connection holds has a stats object, from `connecting` (before it opens) through
    /// `closing` (once `close()` is called), not only from its open.
    ///
    /// This is called automatically by `get_stats()`. A channel that has gone from the registry
    /// keeps the stats object its close left (`closed`), as webrtc-stats keeps a closed channel's.
    pub(super) fn update_data_channel_stats(&mut self) {
        let channels: Vec<_> = self
            .data_channels
            .values()
            .map(|dc| {
                (
                    dc.id,
                    dc.label.clone(),
                    dc.protocol.clone(),
                    dc.ready_state,
                    dc.stream_id,
                )
            })
            .collect();
        for (id, label, protocol, state, stream_id) in channels {
            self.pipeline_context
                .stats
                .get_or_create_data_channel(id, &label, &protocol)
                .on_state_changed(state);
            if let Some(stream_id) = stream_id {
                self.pipeline_context
                    .stats
                    .set_data_channel_stream_id(id, stream_id);
            }
        }
    }

    /// Drops the stats of the RTP streams whose SSRC no longer belongs to a receiver's or a
    /// sender's track (a stopped transceiver, a removed track, a rebound simulcast layer), and
    /// with them their RTX / FEC reverse lookups. The outbound streams that stay take their
    /// encoding's `active` (webrtc-stats `RTCOutboundRtpStreamStats.active`: whether the stream
    /// is configured to be sent, which `set_parameters` changes).
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn retire_rtp_stream_stats(&mut self) {
        let mut inbound_live = HashSet::new();
        let mut outbound_live = HashSet::new();
        let mut outbound_active = Vec::new();
        for transceiver in &self.rtp_transceivers {
            if let Some(receiver) = transceiver.receiver() {
                inbound_live.extend(
                    receiver
                        .track()
                        .codings()
                        .iter()
                        .filter_map(|coding| coding.rtp_coding_parameters.ssrc),
                );
            }
            if let Some(sender) = transceiver.sender() {
                outbound_live.extend(
                    sender
                        .track()
                        .codings()
                        .iter()
                        .filter_map(|coding| coding.rtp_coding_parameters.ssrc),
                );
                outbound_active.extend(sender.send_encodings().iter().filter_map(|encoding| {
                    Some((encoding.rtp_coding_parameters.ssrc?, encoding.active))
                }));
            }
        }
        let stats = &mut self.pipeline_context.stats;
        stats.retire_rtp_streams(&inbound_live, &outbound_live);
        for (ssrc, active) in outbound_active {
            if let Some(stream) = stats.outbound_rtp_streams.get_mut(&ssrc) {
                stream.active = active;
            }
        }
    }

    /// The transceiver, id and kind of the track `sender` sends: what the stats of its media
    /// source are keyed and linked by. `None` for a sender that does not exist.
    pub(crate) fn sender_track_for_stats(
        &self,
        sender: crate::rtp_transceiver::RTCRtpSenderId,
    ) -> Option<(usize, String, RtpCodecKind)> {
        let transceiver_id = sender.0;
        let sender = self
            .rtp_transceivers
            .get(transceiver_id)?
            .sender()
            .as_ref()?;
        Some((
            transceiver_id,
            sender.attached_track()?.track_id().clone(),
            sender.kind(),
        ))
    }

    /// Update codec stats from transceivers to the stats accumulator.
    ///
    /// This is called automatically by `get_stats()` to ensure codec statistics
    /// are registered for all active RTP streams. Per W3C spec, codecs are only
    /// exposed when referenced by an RTP stream.
    pub(super) fn update_codec_stats(&mut self) {
        // Collect codec info from transceivers to avoid borrow conflicts
        let mut inbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();
        let mut outbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();

        for transceiver in &self.rtp_transceivers {
            // Process receivers (inbound streams)
            if let Some(receiver) = transceiver.receiver() {
                let codec_prefs = receiver.get_codec_preferences();
                let track = receiver.track();

                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        // Find the codec for this encoding
                        if let Some(codec) = track.get_codec_by_ssrc(ssrc)
                            && !codec.mime_type.is_empty()
                                // Find matching payload type from codec preferences
                                && let Some(codec_params) = codec_prefs.iter().find(|cp| {
                                    cp.rtp_codec.mime_type == codec.mime_type
                                        && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                            || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                                })
                        {
                            inbound_codecs.push((ssrc, codec.clone(), codec_params.payload_type));
                        }
                    }
                }
            }

            // Process senders (outbound streams)
            if let Some(sender) = transceiver.sender()
                && sender.has_sent()
            {
                let track = sender.track();
                let send_codecs = sender.get_send_codecs();
                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        let codec = &coding.codec;
                        if codec.mime_type.is_empty() {
                            // An encoding without a codec of its own is sent with the codec
                            // negotiation picked; its stream references that one (and takes its
                            // clock rate, which the remote-inbound jitter is converted with).
                            if let Some(codec_params) = encoding_send_codec(codec, send_codecs) {
                                outbound_codecs.push((
                                    ssrc,
                                    codec_params.rtp_codec,
                                    codec_params.payload_type,
                                ));
                            }
                        } else if let Some(codec_params) = send_codecs.iter().find(|cp| {
                            // Find matching payload type from send codecs
                            cp.rtp_codec.mime_type == codec.mime_type
                                && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                    || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                        }) {
                            outbound_codecs.push((ssrc, codec.clone(), codec_params.payload_type));
                        }
                    }
                }
            }
        }

        // Register inbound codecs
        for (ssrc, codec, payload_type) in inbound_codecs {
            self.pipeline_context
                .stats
                .register_inbound_codec(ssrc, &codec, payload_type);
        }

        // Register outbound codecs
        for (ssrc, codec, payload_type) in outbound_codecs {
            self.pipeline_context
                .stats
                .register_outbound_codec(ssrc, &codec, payload_type);
        }

        // Clean up unreferenced codecs
        self.pipeline_context.stats.cleanup_unreferenced_codecs();
    }

    pub(super) fn codec_preferences_from_encodings(
        &self,
        kind: RtpCodecKind,
        encodings: &[RTCRtpEncodingParameters],
    ) -> Result<Vec<RTCRtpCodecParameters>> {
        let media_engine_codecs = self.media_engine.get_codecs_by_kind(kind);
        let mut codec_preferences = vec![];

        for encoding in encodings {
            if encoding.codec.mime_type.is_empty() {
                continue;
            }

            let (codec, match_type) =
                codec_parameters_search(&encoding.codec, None, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }

            if !codec_preferences
                .iter()
                .any(|preference: &RTCRtpCodecParameters| {
                    preference.payload_type == codec.payload_type
                })
            {
                codec_preferences.push(codec);
            }
        }

        // The encodings name media codecs; the repair formats that accompany them (RTX for a
        // named primary, FEC, RED) stay offered, so they are listed too (a preference list
        // keeps only the repair kinds it lists, RTCRtpReceiverInternal::get_codecs). So do
        // the formats that run in the stream of an audio codec on its clock: telephone events
        // (RFC 4733 section 2.1, which RFC 7874 section 3 has every WebRTC endpoint support)
        // and comfort noise (RFC 3389 section 5, required with G.711 by RFC 7874 section 3).
        let named_clock_rates: Vec<u32> = codec_preferences
            .iter()
            .map(|c| c.rtp_codec.clock_rate)
            .collect();
        let rides_the_stream = |codec: &RTCRtpCodecParameters| {
            let mime_type = &codec.rtp_codec.mime_type;
            use crate::peer_connection::configuration::media_engine::{
                MIME_TYPE_CN, MIME_TYPE_TELEPHONE_EVENT,
            };
            (mime_type.eq_ignore_ascii_case(MIME_TYPE_TELEPHONE_EVENT)
                || mime_type.eq_ignore_ascii_case(MIME_TYPE_CN))
                && named_clock_rates.contains(&codec.rtp_codec.clock_rate)
        };
        if !codec_preferences.is_empty() {
            for codec in &media_engine_codecs {
                if rides_the_stream(codec)
                    && !codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == codec.payload_type)
                {
                    codec_preferences.push(codec.clone());
                    continue;
                }
                if !is_repair_codec(&codec.rtp_codec)
                    || codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == codec.payload_type)
                {
                    continue;
                }
                if let Some(apt) = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                    && !codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == apt)
                {
                    continue;
                }
                // RFC 2198 section 5: a RED format goes with the encodings its fmtp names, as
                // RTX with its `apt`.
                if !crate::peer_connection::configuration::media_engine::red_encodings_negotiated(
                    codec,
                    &codec_preferences,
                ) {
                    continue;
                }
                codec_preferences.push(codec.clone());
            }
            // So does telephone-event at a named codec's clock rate (RFC 4733, RFC 7874
            // section 5): naming the audio codec does not take DTMF away (W3C webrtc-pc 7.3:
            // DTMF needs telephone-event negotiated for sending).
            let named_rates: Vec<u32> = codec_preferences
                .iter()
                .map(|preference| preference.rtp_codec.clock_rate)
                .collect();
            for codec in &media_engine_codecs {
                if codec.rtp_codec.mime_type.eq_ignore_ascii_case(
                    crate::rtp_transceiver::rtp_sender::dtmf::MIME_TYPE_TELEPHONE_EVENT,
                ) && named_rates.contains(&codec.rtp_codec.clock_rate)
                    && !codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == codec.payload_type)
                {
                    codec_preferences.push(codec.clone());
                }
            }
        }

        Ok(codec_preferences)
    }

    /// RFC 3711 sections 8 and 9.1, RFC 5764 section 3: the local streams of a connection are
    /// all protected under one SRTP master key, so no two may have the same SSRC (a two-time
    /// pad). The SSRCs `encodings` name (media, RTX, FEC) are distinct, and no other sender
    /// has them; `replacing` is the transceiver whose sender's encodings they replace.
    pub(super) fn refuse_taken_ssrcs(
        &self,
        encodings: &[RTCRtpEncodingParameters],
        replacing: Option<crate::rtp_transceiver::RTCRtpTransceiverId>,
    ) -> Result<()> {
        let ssrcs = |encoding: &RTCRtpEncodingParameters| {
            let coding = &encoding.rtp_coding_parameters;
            [
                coding.ssrc,
                coding.rtx.as_ref().map(|rtx| rtx.ssrc),
                coding.fec.as_ref().map(|fec| fec.ssrc),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<SSRC>>()
        };
        let mut taken: HashSet<SSRC> = HashSet::new();
        for (id, transceiver) in self.rtp_transceivers.iter().enumerate() {
            if Some(id) == replacing || transceiver.stopped() {
                continue;
            }
            if let Some(sender) = transceiver.sender() {
                taken.extend(sender.send_encodings().iter().flat_map(ssrcs));
            }
        }
        let mut given = HashSet::new();
        for ssrc in encodings.iter().flat_map(ssrcs) {
            if taken.contains(&ssrc) || !given.insert(ssrc) {
                return Err(Error::ErrRTPSenderSsrcTaken(ssrc));
            }
        }
        Ok(())
    }

    pub(super) fn normalize_sender_track(
        &self,
        track: MediaStreamTrack,
        mut send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Result<(
        MediaStreamTrack,
        Vec<RTCRtpEncodingParameters>,
        Vec<RTCRtpCodecParameters>,
    )> {
        // RTX is the implementation's choice, not the application's (W3C webrtc-pc has no
        // `rtx` member in `sendEncodings`): encodings the application gave get a repair flow
        // whenever the media engine can carry one, as those `send_encodings_from_track` derives
        // from the track do. Without it, NACKed packets could only be resent on the media SSRC
        // and the outbound stream would have no `rtxSsrc`. A negotiation without RTX drops it
        // again (`configure_rtx_and_fec`).
        let is_rtx_enabled = self
            .media_engine
            .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly);
        // Likewise a FEC repair flow (RFC 5956 `FEC-FR`, flexfec-03 / RFC 8627) when a FEC
        // format is registered: the application names no FEC SSRC either.
        let is_fec_enabled = self
            .media_engine
            .is_fec_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly);
        let mut minted: Vec<SSRC> = send_encodings
            .iter()
            .flat_map(|encoding| {
                let coding = &encoding.rtp_coding_parameters;
                [
                    coding.ssrc,
                    coding.rtx.as_ref().map(|rtx| rtx.ssrc),
                    coding.fec.as_ref().map(|fec| fec.ssrc),
                ]
            })
            .flatten()
            .collect();
        // RFC 4588 section 4: the original and the retransmission stream have two different
        // SSRCs; nor may a FEC flow or another encoding share one (RFC 3550 section 8).
        let mut named = HashSet::new();
        if let Some(repeated) = minted.iter().find(|ssrc| !named.insert(**ssrc)) {
            return Err(Error::ErrRTPSenderSsrcCollision(*repeated));
        }
        for encoding in &mut send_encodings {
            if encoding.rtp_coding_parameters.ssrc.is_none() {
                encoding.rtp_coding_parameters.ssrc = Some(self.unused_media_ssrc(&mut minted));
            }
            if is_rtx_enabled && encoding.rtp_coding_parameters.rtx.is_none() {
                encoding.rtp_coding_parameters.rtx = Some(RTCRtpRtxParameters {
                    ssrc: self.unused_ssrc(&mut minted),
                });
            }
            if is_fec_enabled && encoding.rtp_coding_parameters.fec.is_none() {
                encoding.rtp_coding_parameters.fec = Some(RTCRtpFecParameters {
                    ssrc: self.unused_ssrc(&mut minted),
                });
            }
        }

        let codec_preferences =
            self.codec_preferences_from_encodings(track.kind(), &send_encodings)?;
        let has_rid = send_encodings
            .iter()
            .any(|encoding| !encoding.rtp_coding_parameters.rid.is_empty());
        let all_have_rid = send_encodings
            .iter()
            .all(|encoding| !encoding.rtp_coding_parameters.rid.is_empty());
        if send_encodings.len() > 1 && has_rid && !all_have_rid {
            return Err(Error::ErrRTPSenderRidNil);
        }
        // W3C webrtc-pc addTransceiver: a rid that "does not conform to the grammar
        // requirements specified in Section 10 of [RFC8851]" is a TypeError. The rid is sent as
        // the RtpStreamId of RFC 8852, whose section 3.1 narrows it to 1 to 255 alphanumeric
        // characters; a rid outside that could be signalled but never sent.
        if send_encodings.iter().any(|encoding| {
            let rid = &encoding.rtp_coding_parameters.rid;
            !rid.is_empty() && (rid.len() > 255 || !rid.bytes().all(|b| b.is_ascii_alphanumeric()))
        }) {
            return Err(Error::ErrRTPSenderRidInvalid);
        }

        let is_simulcast = send_encodings.len() > 1 && all_have_rid;
        // A rid names one encoding (RFC 8851 §4: rid-ids are unique within the m= section, and
        // W3C addTransceiver refuses a repeated rid); two alike would be written as duplicate
        // `a=rid` lines.
        if is_simulcast
            && send_encodings.iter().enumerate().any(|(i, encoding)| {
                send_encodings[..i].iter().any(|earlier| {
                    earlier.rtp_coding_parameters.rid == encoding.rtp_coding_parameters.rid
                })
            })
        {
            return Err(Error::ErrRTPSenderRIDCollision);
        }
        if !is_simulcast {
            send_encodings.truncate(1);
        }

        let track = MediaStreamTrack::new(
            track.stream_id().clone(),
            track.track_id().clone(),
            track.label().clone(),
            track.kind(),
            send_encodings.clone(),
        );

        Ok((track, send_encodings, codec_preferences))
    }
}

/// Whether `incoming_track` describes the track `receiver` already has, so that what RTP
/// taught the receiver (SSRCs bound by RID, their codecs) is kept. The msid-appdata counts
/// only when `appdata_names_the_track` (`with_msid_appdata_change_renews_track`, RFC 8830
/// section 3's model); by default it is ignored, as RFC 9429 section 5.8.2 reads `a=msid`
/// ("ignoring any "appdata" field").
fn is_same_remote_track(
    receiver: &RTCRtpReceiverInternal,
    incoming_track: &sdp::TrackDetails,
    appdata_names_the_track: bool,
) -> bool {
    let track = receiver.track();
    // A description without msid-appdata leaves the track id to this side: any id it gave
    // the track is the same track.
    if (appdata_names_the_track
        && !incoming_track.track_id.is_empty()
        && receiver.remote_track_id() != incoming_track.track_id)
        || track.track_id().is_empty()
        || track.stream_id() != &incoming_track.stream_id
    {
        return false;
    }

    let codings = receiver.get_coding_parameters();
    if !incoming_track.rids.is_empty() {
        // The rid codings; a declared stream bound without a rid is one of `declared_codings`.
        let mut current: Vec<&str> = codings
            .iter()
            .filter(|c| !c.rid.is_empty())
            .map(|c| c.rid.as_str())
            .collect();
        let mut remote: Vec<&str> = incoming_track.rids.iter().map(String::as_str).collect();
        current.sort_unstable();
        remote.sort_unstable();
        let declared = receiver.declared_codings();
        return current == remote
            && declared.len() == incoming_track.declared_ssrcs.len()
            && declared
                .iter()
                .zip(&incoming_track.declared_ssrcs)
                .all(|(coding, ssrcs)| {
                    coding.ssrc == Some(ssrcs.ssrc)
                        && coding.rtx.as_ref().map(|r| r.ssrc) == ssrcs.rtx_ssrc
                        && coding.fec.as_ref().map(|f| f.ssrc) == ssrcs.fec_ssrc
                });
    }

    match (codings, incoming_track.ssrc) {
        ([coding, ..], Some(ssrc)) if codings.len() == 1 + incoming_track.ssrc_layers.len() => {
            let layers = std::iter::once((ssrc, incoming_track.rtx_ssrc, incoming_track.fec_ssrc))
                .chain(
                    incoming_track
                        .ssrc_layers
                        .iter()
                        .map(|layer| (layer.ssrc, layer.rtx_ssrc, layer.fec_ssrc)),
                );
            coding.rid.is_empty()
                && codings
                    .iter()
                    .zip(layers)
                    .all(|(coding, (ssrc, rtx, fec))| {
                        coding.ssrc == Some(ssrc)
                            && coding.rtx.as_ref().map(|r| r.ssrc) == rtx
                            && coding.fec.as_ref().map(|f| f.ssrc) == fec
                    })
        }
        _ => false,
    }
}

/// A mid for a new data m= section: the number of m= sections so far, or the next number that
/// no m= section and no transceiver has (a stopped transceiver left out of the offer keeps its
/// mid, which must not come back on another section).
fn free_data_mid(
    media_sections: &[MediaSection],
    transceivers: &[RTCRtpTransceiverInternal],
) -> String {
    let mut n = media_sections.len();
    loop {
        let mid = n.to_string();
        if !media_sections.iter().any(|s| s.mid == mid)
            && !transceivers.iter().any(|t| t.mid().as_ref() == Some(&mid))
        {
            return mid;
        }
        n += 1;
    }
}

/// The direction an answer states for a media section offered with `offered`: `local` (the
/// transceiver's [[Direction]]) intersected with the reverse of the offered direction (RFC 9429
/// section 5.3.1, RFC 3264 section 6.1). A section with no direction attribute is sendrecv
/// (RFC 3264 section 5.1).
pub(crate) fn answered_direction(
    local: RTCRtpTransceiverDirection,
    offered: RTCRtpTransceiverDirection,
) -> RTCRtpTransceiverDirection {
    let offered = if offered == RTCRtpTransceiverDirection::Unspecified {
        RTCRtpTransceiverDirection::Sendrecv
    } else {
        offered
    };
    local.intersect(offered.reverse())
}

/// `a=rtcp-xr` (RFC 3611 section 5.1).
const ATTR_KEY_RTCP_XR: &str = "rtcp-xr";

/// Whether the offerer-tagged section of `offer` (the first tag of its BUNDLE group that is not
/// rejected, RFC 9143 section 7.2) carries `a=rtcp-mux-only`.
fn offerer_tagged_section_is_rtcp_mux_only(offer: &SessionDescription) -> bool {
    bundle_group_mids(offer)
        .into_iter()
        .find_map(|tag| {
            offer.media_descriptions.iter().find(|media| {
                get_mid_value(media).is_some_and(|mid| mid == tag) && !is_rejected_media(media)
            })
        })
        .is_some_and(|media| media.has_attribute(ATTR_KEY_RTCP_MUX_ONLY))
}

impl RTCPeerConnection {
    /// The `statechange` to "closed" of the SCTP transport an applied answer closed (W3C
    /// 6.1.2), queued once the description's own events and the `close` of its channels are.
    pub(super) fn announce_sctp_closed_by_answer(&mut self) {
        if std::mem::take(&mut self.sctp_closed_by_answer) {
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnSctpTransportStateChange(
                    crate::peer_connection::transport::RTCSctpTransportState::Closed,
                ),
            );
        }
    }

    /// W3C webrtc-pc "set a session description", once an answer made the state stable: "For
    /// any transceiver that was removed from the set of transceivers in a previous step, if
    /// any of its transports ... are still not closed and they're no longer referenced by a
    /// non-stopped transceiver, close the RTCDtlsTransports and their associated
    /// RTCIceTransports. This results in events firing on these objects in a queued task."
    ///
    /// With several transports, an answer's layout closes each transport it leaves without
    /// a section (`apply_transport_layout`). This is the case that layout does not see: the
    /// answer rejects every m= section, the data section included (RFC 9429 section 5.11:
    /// the ICE components of a rejected section are discarded "unless a non-rejected "m="
    /// section is bundled with" it), so no transport is in use. Each is closed; the next
    /// description that sets a section up finds a new one, not started
    /// (`close_transports_without_sections`). Called after the description's own events
    /// (signalingstatechange, channel errors, mutes, track events) are queued: the transport
    /// events are the queued task's.
    pub(super) fn close_unused_transports(&mut self) {
        let rejects_everything = [
            &self.current_local_description,
            &self.current_remote_description,
        ]
        .into_iter()
        .flatten()
        .any(|description| {
            description.sdp_type == RTCSdpType::Answer && rejects_every_media_section(description)
        });
        if !rejects_everything {
            return;
        }
        if let Err(err) = self.close_transports_without_sections() {
            log::warn!("closing the transports of a session without media sections: {err}");
        }
    }
}

/// Whether the description has m-sections and rejects every one (port 0): a completed
/// offer/answer like that leaves no transport (RFC 8843 §7.1.3, RFC 9429 §5.10).
fn rejects_every_media_section(desc: &RTCSessionDescription) -> bool {
    desc.parsed.as_ref().is_some_and(|parsed| {
        !parsed.media_descriptions.is_empty()
            && parsed.media_descriptions.iter().all(is_rejected_media)
    })
}

/// The transport a TURN URL (RFC 7065) says its server is reached over: for `turns:` TLS, or
/// DTLS with `transport=udp` (RFC 7350 section 4.1); else the `transport` parameter, UDP when
/// there is none. `Unspecified` for anything that is not a TURN URL.
pub(super) fn relay_protocol_of_turn_url(url: &str) -> RTCIceServerTransportProtocol {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("turns:") {
        return if lower.ends_with("?transport=udp") {
            RTCIceServerTransportProtocol::Dtls
        } else {
            RTCIceServerTransportProtocol::Tls
        };
    }
    if !lower.starts_with("turn:") {
        return RTCIceServerTransportProtocol::Unspecified;
    }
    match lower
        .split_once("?transport=")
        .map(|(_, transport)| transport)
    {
        Some("tcp") => RTCIceServerTransportProtocol::Tcp,
        _ => RTCIceServerTransportProtocol::Udp,
    }
}

#[cfg(test)]
mod transport_closed_tests {
    use super::*;
    use crate::peer_connection::sdp::session_description::RTCSessionDescription;

    fn offer(media: &str) -> RTCSessionDescription {
        let sdp =
            format!("v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 1\r\n{media}");
        RTCSessionDescription::offer(sdp).expect("offer")
    }

    /// A description whose every m-section is rejected closes the transport; one live section
    /// or none at all does not.
    #[test]
    fn rejects_every_media_section_only_when_all_are_rejected() {
        let rejected_video =
            "m=video 0 UDP/TLS/RTP/SAVPF 120\r\nc=IN IP4 0.0.0.0\r\na=inactive\r\na=mid:0\r\n";
        let live_audio = "m=audio 9 UDP/TLS/RTP/SAVPF 109\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\n\
                          a=ice-ufrag:abcd\r\na=ice-pwd:abcdefghijklmnopqrstuv\r\n\
                          a=rtpmap:109 opus/48000/2\r\n";
        assert!(rejects_every_media_section(&offer(rejected_video)));
        assert!(!rejects_every_media_section(&offer(&format!(
            "{rejected_video}{live_audio}"
        ))));
        assert!(!rejects_every_media_section(&offer("")));
    }
}

#[cfg(test)]
mod rejected_mline_generate_matched_sdp_tests {
    use super::*;
    use crate::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
    use crate::peer_connection::sdp::session_description::RTCSessionDescription;
    use crate::rtp_transceiver::rtp_sender::RTCRtpCodec;
    use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
    use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;

    /// Helper: build a peer connection with video-only codec support.
    fn build_video_only_pc() -> RTCPeerConnection {
        let mut me = MediaEngine::default();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )
        .unwrap();

        let se = crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .build();

        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_setting_engine(se)
            .build(std::time::Instant::now())
            .unwrap()
    }

    /// Offer with audio (port=0) rejected and video active.
    /// Exercises the `media.media_name.port.value == 0` branch for audio kind.
    #[test]
    fn test_generate_matched_sdp_rejected_audio_port_zero() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:11111 cname:test\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // Video should be accepted (non-zero port)
        let video = lines.iter().find(|l| l.starts_with("m=video")).unwrap();
        assert!(
            !video.starts_with("m=video 0"),
            "video must not be rejected"
        );

        // Audio should be rejected (port=0) in the answer
        let audio = lines.iter().find(|l| l.starts_with("m=audio")).unwrap();
        assert!(
            audio.starts_with("m=audio 0"),
            "rejected audio m-line must have port 0, got: {audio}"
        );

        // Must have exactly 2 m-lines
        let m_count = lines.iter().filter(|l| l.starts_with("m=")).count();
        assert_eq!(m_count, 2, "answer must preserve m-line count");
    }

    /// Offer with application/datachannel (port=0) rejected.
    /// Exercises the `media.media_name.port.value == 0` branch for application kind.
    #[test]
    fn test_generate_matched_sdp_rejected_application_port_zero() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:11111 cname:test\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // Application m-line must be rejected (port=0) with SCTP proto
        let app = lines
            .iter()
            .find(|l| l.starts_with("m=application"))
            .unwrap();
        assert!(
            app.starts_with("m=application 0"),
            "rejected application m-line must have port 0, got: {app}"
        );
    }

    /// First m-line is rejected (port=0), second is active video.
    /// Tests that ICE candidates are correctly added to the first *non-rejected* m-line.
    #[test]
    fn test_generate_matched_sdp_first_mline_rejected() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 1\r\n\
a=msid-semantic: WMS\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:22222 cname:test\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // First m-line (audio) must be rejected
        let audio = lines.iter().find(|l| l.starts_with("m=audio")).unwrap();
        assert!(audio.starts_with("m=audio 0"), "audio must be rejected");

        // Second m-line (video) must be accepted
        let video = lines.iter().find(|l| l.starts_with("m=video")).unwrap();
        assert!(!video.starts_with("m=video 0"), "video must be accepted");

        // The rejected audio m-line must NOT have ICE attributes
        // Find the audio section and check for ice-ufrag
        let mut in_audio = false;
        let mut audio_has_ice = false;
        for line in &lines {
            if line.starts_with("m=audio") {
                in_audio = true;
            } else if line.starts_with("m=") {
                in_audio = false;
            }
            if in_audio && line.starts_with("a=ice-ufrag") {
                audio_has_ice = true;
            }
        }
        assert!(
            !audio_has_ice,
            "rejected audio m-line must not contain ICE attributes"
        );
    }

    /// All m-lines rejected (port=0). Answer must preserve all with port=0.
    #[test]
    fn test_generate_matched_sdp_all_mlines_rejected() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=msid-semantic: WMS\r\n\
m=video 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:2\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // All 3 m-lines must be present and rejected
        let m_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("m=")).collect();
        assert_eq!(m_lines.len(), 3, "must have 3 m-lines");

        for m in &m_lines {
            // Extract the port (second space-separated token)
            let port: &str = m.split_whitespace().nth(1).unwrap();
            assert_eq!(port, "0", "all m-lines must have port=0, got: {m}");
        }
    }

    /// Mix of rejected and accepted m-lines in various positions.
    /// audio(rejected) -> video(accepted) -> application(rejected)
    #[test]
    fn test_generate_matched_sdp_mixed_rejected_accepted() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 1\r\n\
a=msid-semantic: WMS\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:33333 cname:test\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:2\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        let m_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("m=")).collect();
        assert_eq!(m_lines.len(), 3, "answer must have 3 m-lines");

        // audio rejected
        assert!(
            m_lines[0].starts_with("m=audio 0"),
            "audio must be rejected, got: {}",
            m_lines[0]
        );
        // video accepted
        assert!(
            m_lines[1].starts_with("m=video") && !m_lines[1].starts_with("m=video 0"),
            "video must be accepted, got: {}",
            m_lines[1]
        );
        // application rejected
        assert!(
            m_lines[2].starts_with("m=application 0"),
            "application must be rejected, got: {}",
            m_lines[2]
        );
    }
}

/// The most remote-candidate statistics objects held while an mDNS candidate that the agent
/// does not hold (unresolved, or ignored) is still given one: what a remote description can
/// make the report grow to.
const MAX_UNRESOLVED_MDNS_CANDIDATE_STATS: usize = 320;

/// The most this endpoint has said it receives in the sections `mids` of its description
/// `local`: per section `b=TIAS` (bits per second, RFC 3890), else `b=AS` times 1000 (RFC 8866
/// section 5.8), the smallest of the sections that state one, so that no TMMBR exceeds any of
/// them (RFC 5104 section 4.2.1.2). `None` when none does.
pub(crate) fn negotiated_receive_maximum(
    local: &SessionDescription,
    mids: &HashSet<String>,
) -> Option<u64> {
    local
        .media_descriptions
        .iter()
        .filter(|media| get_mid_value(media).is_some_and(|mid| mids.contains(mid)))
        .filter_map(|media| {
            let of = |bandwidth_type: &str| {
                media
                    .bandwidth
                    .iter()
                    .find(|b| !b.experimental && b.bandwidth_type == bandwidth_type)
                    .map(|b| b.bandwidth)
            };
            of("TIAS").or_else(|| of("AS").map(|kbps| kbps.saturating_mul(1000)))
        })
        .min()
}

/// The first of `draws` that is not in `taken` (and not 0, which some peers treat as unset).
/// The most SSRCs [`RTCPeerConnection::ssrc_history`] keeps: enough for any session's streams
/// and their renegotiations, small next to the 2^32 SSRC space.
pub(crate) const MAX_SSRC_HISTORY: usize = 4096;

pub(crate) fn unused_ssrc_from(
    draws: impl IntoIterator<Item = SSRC>,
    taken: &HashSet<SSRC>,
) -> SSRC {
    draws
        .into_iter()
        .find(|ssrc| *ssrc != 0 && !taken.contains(ssrc))
        .unwrap_or_default()
}

#[cfg(test)]
mod unused_ssrc_test {
    use super::*;
    use crate::peer_connection::configuration::media_engine::{
        MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
    };
    use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
    use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;

    /// A peer connection with VP8 and RTX, so a sender gets an RTX flow.
    fn vp8_with_rtx() -> RTCPeerConnection {
        let mut media_engine = MediaEngine::default();
        for (mime_type, payload_type, fmtp) in
            [(MIME_TYPE_VP8, 96, ""), (MIME_TYPE_RTX, 97, "apt=96")]
        {
            media_engine
                .register_codec(
                    RTCRtpCodecParameters {
                        rtp_codec: RTCRtpCodec {
                            mime_type: mime_type.to_owned(),
                            clock_rate: 90000,
                            channels: 0,
                            sdp_fmtp_line: fmtp.to_owned(),
                            rtcp_feedback: vec![],
                        },
                        payload_type,
                    },
                    RtpCodecKind::Video,
                )
                .unwrap();
        }
        RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())
            .unwrap()
    }

    fn track(coding: RTCRtpCodingParameters) -> MediaStreamTrack {
        MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: coding,
                ..Default::default()
            }],
        )
    }

    /// RFC 4588 section 4: the original and the retransmission stream "MUST use two different
    /// SSRC values". A minted RTX SSRC is drawn again when it is the SSRC the track names for
    /// its media.
    #[test]
    fn a_minted_rtx_ssrc_is_never_the_tracks_own_media_ssrc() {
        let pc = vp8_with_rtx();
        let track = track(RTCRtpCodingParameters {
            ssrc: Some(7),
            ..Default::default()
        });
        let mut draws = [7u32, 9].into_iter();
        let encodings = pc.send_encodings_from_track_drawn(&track, &mut || draws.next().unwrap());
        let coding = &encodings[0].rtp_coding_parameters;
        assert_eq!(Some(7), coding.ssrc);
        assert_eq!(Some(9), coding.rtx.as_ref().map(|rtx| rtx.ssrc));
    }

    /// RFC 4588 section 4: encodings the application gives that name one SSRC for the media
    /// and its retransmissions are refused.
    #[test]
    fn encodings_naming_one_ssrc_for_media_and_rtx_are_refused() {
        let pc = vp8_with_rtx();
        let coding = RTCRtpCodingParameters {
            ssrc: Some(5),
            rtx: Some(RTCRtpRtxParameters { ssrc: 5 }),
            ..Default::default()
        };
        let encodings = vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding.clone(),
            ..Default::default()
        }];
        assert!(matches!(
            pc.normalize_sender_track(track(coding), encodings),
            Err(Error::ErrRTPSenderSsrcCollision(5))
        ));
    }

    /// RFC 5104 section 4.2.1.2: the negotiated maximum is the local description's `b=TIAS`,
    /// else `b=AS` times 1000, of the receiving sections, the smallest when several state one.
    #[test]
    fn the_negotiated_receive_maximum_is_the_smallest_local_limit() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\nb=AS:800\r\na=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\nb=TIAS:500000\r\nb=AS:900\r\na=mid:1\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\n";
        let local = SessionDescription::unmarshal(&mut std::io::Cursor::new(sdp)).unwrap();
        let mids = |m: &[&str]| m.iter().map(|m| (*m).to_owned()).collect::<HashSet<_>>();
        assert_eq!(
            negotiated_receive_maximum(&local, &mids(&["0"])),
            Some(800_000)
        );
        assert_eq!(
            negotiated_receive_maximum(&local, &mids(&["0", "1", "2"])),
            Some(500_000)
        );
        assert_eq!(negotiated_receive_maximum(&local, &mids(&["2"])), None);
    }

    /// RFC 5576 section 5: an SSRC is not reused for another source within the participant
    /// timeout, and "SHOULD NOT" ever be; section 8: an updated offer's new SSRCs differ from
    /// "any previously used". A local description that is applied records the SSRCs of every
    /// local stream (the media and its RTX flow); a later draw of one of them, or of any other
    /// SSRC the history holds, is drawn again, also once no stream has it any more.
    #[test]
    fn an_ssrc_used_before_is_not_drawn_again() {
        let mut pc = vp8_with_rtx();
        pc.add_track(track(RTCRtpCodingParameters {
            ssrc: Some(7),
            rtx: Some(RTCRtpRtxParameters { ssrc: 8 }),
            ..Default::default()
        }))
        .unwrap();
        assert!(pc.ssrc_history.is_empty());
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), offer).unwrap();
        assert!(pc.ssrc_history.contains(&7), "{:?}", pc.ssrc_history);
        assert!(pc.ssrc_history.contains(&8), "{:?}", pc.ssrc_history);

        // An SSRC of an earlier stream that no sender has now.
        pc.ssrc_history.insert(33);
        let mut draws = [33u32, 7, 8, 41].into_iter();
        assert_eq!(
            41,
            pc.unused_ssrc_drawn(&mut vec![], &mut || draws.next().unwrap())
        );
    }

    /// RFC 5576 sections 5 and 8: a drawn SSRC that a remote description mentions or another
    /// local stream has is drawn again.
    #[test]
    fn a_taken_ssrc_is_drawn_again() {
        let taken: HashSet<SSRC> = [7, 9].into_iter().collect();
        assert_eq!(11, unused_ssrc_from([7, 0, 9, 11, 13], &taken));
        assert_eq!(7, unused_ssrc_from([7], &HashSet::new()));
    }
}

/// Whether `sd` describes an SCTP association (RFC 8841 section 10.2: a data section that is
/// not rejected, with a non-zero `a=sctp-port`), and whether it closes one (sections 10.3,
/// 10.4: its data section is rejected or has `a=sctp-port:0`). A bundle-only data section of
/// an offer (port zero with `a=bundle-only`, RFC 9143 section 7.2) is not rejected.
fn describes_sctp_association(sd: &RTCSessionDescription) -> (bool, bool) {
    let Some(section) = have_data_channel(sd) else {
        return (false, false);
    };
    let zero_port = section
        .attributes
        .iter()
        .any(|a| a.key == "sctp-port" && a.value.as_deref().map(str::trim) == Some("0"));
    let closed = is_rejected_media(section) || zero_port;
    (!closed, closed)
}

/// The SDES identifiers of an encoding's SSRCs (RFC 9143 section 15.1, RFC 8852 sections 3.1
/// and 3.2): the media SSRC's MID and RtpStreamId, its RTX SSRC's MID and RepairedRtpStreamId.
/// A FlexFEC SSRC has the MID only: RFC 8627 section 7.2, the RtpStreamId and
/// RepairedRtpStreamId items "SHOULD NOT be used" for FlexFEC streams (one FEC stream may
/// protect several).
pub(crate) fn stream_identifiers(
    mid: &str,
    coding: &crate::rtp_transceiver::rtp_sender::RTCRtpCodingParameters,
) -> Vec<interceptor::RtcpSessionControl> {
    let Some(ssrc) = coding.ssrc else {
        return vec![];
    };
    let rid = (!coding.rid.is_empty()).then(|| coding.rid.clone());
    let mut identifiers = vec![interceptor::RtcpSessionControl::StreamIdentifiers {
        ssrc,
        mid: Some(mid.to_owned()),
        rid: rid.clone(),
        repaired_rid: None,
    }];
    if let Some(rtx) = &coding.rtx {
        identifiers.push(interceptor::RtcpSessionControl::StreamIdentifiers {
            ssrc: rtx.ssrc,
            mid: Some(mid.to_owned()),
            rid: None,
            repaired_rid: rid,
        });
    }
    if let Some(fec) = &coding.fec {
        identifiers.push(interceptor::RtcpSessionControl::StreamIdentifiers {
            ssrc: fec.ssrc,
            mid: Some(mid.to_owned()),
            rid: None,
            repaired_rid: None,
        });
    }
    identifiers
}

#[cfg(test)]
mod stream_identifiers_test {
    use super::*;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
    };
    use interceptor::RtcpSessionControl;

    /// RFC 8852 sections 3.1 and 3.2 and RFC 9143 section 15.1: a simulcast layer's media SSRC
    /// carries its MID and RtpStreamId, its RTX SSRC the MID and the layer's RID as
    /// RepairedRtpStreamId. RFC 8627 section 7.2: "the RtpStreamId and RepairedRtpStreamId
    /// SDES items SHOULD NOT be used" for a FlexFEC stream: its SSRC carries the MID only.
    #[test]
    fn a_flexfec_ssrc_is_identified_by_its_mid_only() {
        let coding = RTCRtpCodingParameters {
            rid: "h".to_owned(),
            ssrc: Some(1),
            rtx: Some(RTCRtpRtxParameters { ssrc: 2 }),
            fec: Some(RTCRtpFecParameters { ssrc: 3 }),
            ..Default::default()
        };
        let items = |rid: Option<&str>, repaired: Option<&str>, ssrc: u32| {
            RtcpSessionControl::StreamIdentifiers {
                ssrc,
                mid: Some("1".to_owned()),
                rid: rid.map(str::to_owned),
                repaired_rid: repaired.map(str::to_owned),
            }
        };
        assert_eq!(
            stream_identifiers("1", &coding),
            vec![
                items(Some("h"), None, 1),
                items(None, Some("h"), 2),
                items(None, None, 3)
            ]
        );
    }
}

pub(crate) mod datachannel;
pub(crate) mod declared_cname;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod transport_set;

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEvent};
use crate::peer_connection::event::{
    RTCPeerConnectionEvent, RTCPeerConnectionIceEvent, RTCTransportEventKind,
};
use crate::peer_connection::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::peer_connection::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::peer_connection::handler::dtls::DtlsHandler;
use crate::peer_connection::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::peer_connection::handler::ice::IceHandler;
use crate::peer_connection::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::peer_connection::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::peer_connection::handler::srtp::SrtpHandler;
use crate::peer_connection::handler::transport_set::{TransportId, TransportSet};
use crate::peer_connection::message::{
    RTCMessage, TaggedRTCMessage,
    internal::{
        ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
        TaggedRTCMessageInternal,
    },
};
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::peer_connection::transport::dtls::SrtpRekeying;
use crate::peer_connection::transport::sctp::SctpPath;
use crate::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};
use crate::statistics::accumulator::RTCStatsAccumulator;
use ::interceptor::Packet;
use log::{debug, warn};
use shared::TaggedBytesMut;
use shared::error::{Error, flatten_errs};
use std::collections::VecDeque;
use std::time::Instant;

/// Forward handler list - invokes callback with handler list
macro_rules! forward_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_demuxer_handler,
                get_ice_handler,
                get_dtls_handler,
                get_sctp_handler,
                get_datachannel_handler,
                get_srtp_handler,
                get_interceptor_handler,
                get_endpoint_handler
            ]
        )
    };
}

/// Helper macro that processes a list of handlers with code blocks
macro_rules! process_handler_list {
    (call_macro: process_handler!($self:expr, $handler:ident, $code:block), [$($getter:ident),+]) => {{
        $(
            {
                let mut $handler = $self.$getter();
                $code
            }
        )+
    }};
}

/// Unified macro to iterate over handlers with code blocks
macro_rules! for_each_handler {
    // Forward order: execute code block for each handler
    (forward: $macro:ident!($($args:tt)*)) => {
        forward_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };
}

pub(crate) struct PipelineContext {
    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    /// The ICE, DTLS and SRTP contexts, one set per transport.
    pub(crate) transports: TransportSet,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline
    /// Media (RTP/RTCP) ready for the application.
    ///
    /// Split from data-channel output deliberately. Back-pressure is applied by *not draining
    /// a queue* — that is what grows [`Self::data_read_outs`], bounds the SCTP drain,
    /// lowers `a_rwnd` and throttles the peer. While both kinds shared one queue, a caller
    /// applying that back-pressure necessarily stopped draining media too, so a slow
    /// data-channel consumer froze video on the same connection for as long as it stalled —
    /// video that arrives over SRTP and is subject to none of SCTP's flow control.
    pub(crate) media_read_outs: VecDeque<TaggedRTCMessage>,
    /// Data-channel messages ready for the application.
    ///
    /// Its length *is* the back-pressure signal the SCTP handler bounds against, so a caller
    /// that declines to drain it throttles the peer — and nothing else. No counter to keep in
    /// step with it: the queue is the count.
    pub(crate) data_read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,

    // Statistics accumulator
    pub(crate) stats: RTCStatsAccumulator,

    /// The `iceConnectionState` last announced: the aggregate over the transports (W3C
    /// 4.3.4), told when it changes.
    pub(crate) announced_ice_connection_state:
        crate::peer_connection::state::ice_connection_state::RTCIceConnectionState,

    /// The newest instant the pipeline has been given, through a datagram, a write or a timeout.
    ///
    /// `close()` takes no time of its own, and this crate reads no clock, so the `close_notify`
    /// it sends is stamped with this.
    pub(crate) now: Instant,
}

impl PipelineContext {
    pub(crate) fn observe(&mut self, now: Instant) {
        self.now = self.now.max(now);
    }
}

/// The longest a DTLS server waits for the client's SRTP re-keying offer before asking itself
/// (`SettingEngineBuilder::with_srtp_rekeying_dtls_client_first`): long enough for an offer
/// made at the same packet count to reach it over a usual signalling path, short against the
/// time a re-keying takes on a slow one.
pub(crate) const SRTP_REKEYING_SERVER_WAIT: std::time::Duration =
    std::time::Duration::from_millis(500);

/// A re-keying margin under this, at the lifetime warning, is logged: an offer and answer, ICE
/// checks and a DTLS handshake may not fit (seconds through TURN or with loss).
const SRTP_REKEYING_TIGHT_MARGIN: std::time::Duration = std::time::Duration::from_secs(2);

impl RTCPeerConnection {
    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> Demuxer -> Raw Bytes
    */

    /// An event leaves for the application. A local candidate's `OnIceCandidateEvent` is the
    /// application's to trickle: from here on the candidate counts as conveyed and the agent
    /// pairs it (RFC 8838 section 10).
    /// W3C webrtc-pc "Updating the Negotiation-Needed flag": the event is fired by a queued
    /// task, which checks again when it runs: "If connection.[[IsClosed]] is true, abort these
    /// steps", "If connection.[[SignalingState]] is not "stable", abort these steps", and "If
    /// the result of checking if negotiation is needed is false, clear the negotiation-needed
    /// flag ... and abort these steps". The engine queues the event when the flag is set; the
    /// application reading it is when the task runs. One whose reason went in between (a
    /// rollback brought the connection back to stable with a renewal still wanted, and the
    /// answer to the peer's colliding offer gave the renewal before the application looked) is
    /// not handed out: an offer made for it would be a needless exchange. The flag
    /// (`is_negotiation_ongoing`) is cleared when the check finds nothing to negotiate, and set
    /// again, with a new event, when the connection is next stable with something to.
    fn negotiation_needed_withdrawn(&self, evt: &RTCPeerConnectionEvent) -> bool {
        matches!(evt, RTCPeerConnectionEvent::OnNegotiationNeededEvent)
            && (!self.is_negotiation_ongoing
                || self.signaling_state != RTCSignalingState::Stable
                || self.peer_connection_state == RTCPeerConnectionState::Closed)
    }

    fn hand_out_event(&mut self, evt: RTCPeerConnectionEvent) -> RTCPeerConnectionEvent {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
            candidate: Some(candidate),
            ice_transport,
            ..
        }) = &evt
        {
            // The candidate is of the transport the event names (each transport has its own
            // agent, RFC 9429 section 5.2.1), or else of the one whose ufrag it carries; the
            // transports share their ufrag unless `with_unique_transport_credentials`.
            let ufrag = candidate.username_fragment.clone();
            for bundle in self.pipeline_context.transports.iter_mut() {
                let ice = &mut bundle.ice_handler_context.ice_transport;
                let its = match ice_transport {
                    Some(id) => *id == ice.id,
                    None => ufrag
                        .as_ref()
                        .is_none_or(|u| *u == ice.agent.get_local_credentials().ufrag),
                };
                if its {
                    ice.agent.local_candidate_conveyed(&candidate.id);
                }
            }
        }
        evt
    }

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(
            &mut self.pipeline_context.demuxer_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_ice_handler(&mut self) -> IceHandler<'_> {
        IceHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .ice_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_dtls_handler(&mut self) -> DtlsHandler<'_> {
        DtlsHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .dtls_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    /// Next media (RTP/RTCP) message for the application, if any.
    ///
    /// Never affected by data-channel back-pressure. Media arrives over SRTP and is subject to
    /// none of SCTP's flow control, so a caller throttling a slow data-channel consumer must
    /// still be able to deliver video — draining this is how.
    ///
    /// Most callers should use [`poll_read`](sansio::Protocol::poll_read), which interleaves
    /// media and data-channel messages by the instant each was observed. Reach for this split
    /// pair only to drain one kind without the other.
    #[doc(hidden)]
    pub fn poll_media_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pipeline_context.media_read_outs.pop_front()
    }

    /// Next data-channel message for the application, if any.
    ///
    /// **Declining to call this is how back-pressure is applied.** Undrained messages leave
    /// bytes in SCTP's reassembly queue, which lowers the receiver-window credit advertised in
    /// every SACK, which tells the peer to slow down. Stop calling it while the application is
    /// behind, resume when it catches up.
    ///
    /// Most callers should use [`poll_read`](sansio::Protocol::poll_read), which interleaves
    /// media and data-channel messages by the instant each was observed; declining to call
    /// *that* applies the same back-pressure. Reach for this split pair only to drain one kind
    /// without the other.
    #[doc(hidden)]
    pub fn poll_data_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pipeline_context.data_read_outs.pop_front()
    }

    pub(crate) fn get_sctp_handler(&mut self) -> SctpHandler<'_> {
        // The SCTP handler bounds how much it pulls out of the reassembly queues against what
        // the application has not yet consumed. That backlog lives here, not in the handler's
        // own `read_outs` — the pipeline empties that within a single `handle_read` — and it
        // is data-channel output only, so unrelated media cannot throttle SCTP.
        let downstream_backlog = self.pipeline_context.data_read_outs.len();
        // The path under SCTP is looked at again only when ICE selected a pair or a DTLS
        // handshake completed since it was last looked at: a comparison, not work, per call.
        let selected_pair_changes = self
            .pipeline_context
            .transports
            .data_transport()
            .ice_handler_context
            .selected_pair_changes;
        let path = self
            .pipeline_context
            .sctp_handler_context
            .take_path_refresh(selected_pair_changes)
            .then(|| self.sctp_path());
        let mut handler = SctpHandler::new(
            &mut self.pipeline_context.sctp_handler_context,
            downstream_backlog,
        );
        if let Some(path) = path {
            handler.apply_path(path);
        }
        handler
    }

    /// What lies under the SCTP association: the selected candidate pair (its address
    /// family, its transport, whether this side's candidate is relayed) and what the DTLS
    /// version and cipher suite add to a record. `None` while no pair is selected.
    fn sctp_path(&self) -> Option<SctpPath> {
        let data = self.pipeline_context.transports.data_transport();
        let (local, remote) = data
            .ice_handler_context
            .ice_transport
            .agent
            .get_selected_candidate_pair()?;
        // The record overhead of the version and suite negotiated (a DTLS 1.3 record is
        // smaller than a DTLS 1.2 one).
        let dtls_record_overhead = data
            .dtls_handler_context
            .dtls_transport
            .dtls_endpoint
            .as_ref()
            .and_then(|endpoint| {
                endpoint.record_overhead(shared::TransportContext::default().peer_addr)
            })
            .unwrap_or(SctpPath::DEFAULT_DTLS_RECORD_OVERHEAD);
        Some(SctpPath {
            ipv6: remote.addr().is_ipv6(),
            tcp: local.network_type().is_tcp(),
            relayed: local.candidate_type() == ::ice::candidate::CandidateType::Relay,
            dtls_record_overhead,
        })
    }

    pub(crate) fn get_datachannel_handler(&mut self) -> DataChannelHandler<'_> {
        // Read the Copy values before `&mut self.data_channels` borrows self mutably. The
        // handler needs the DTLS role to give stream ids the parity RFC 8832 §6 requires, and
        // the negotiated stream count to bound them.
        let dtls_role = self
            .pipeline_context
            .transports
            .data_transport()
            .dtls_handler_context
            .dtls_transport
            .role();
        let max_channels = self.sctp_transport().max_channels();
        DataChannelHandler::new(
            &mut self.pipeline_context.datachannel_handler_context,
            &mut self.data_channels,
            &mut self.pipeline_context.stats,
            self.setting_engine.data_channel.dcep_handshake_timeout,
            dtls_role,
            max_channels,
        )
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .srtp_handler_context,
        )
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_> {
        let transports = &self.pipeline_context.transports;
        let rtp_session = (transports.len() > 1).then(|| transports.active_id().0);
        InterceptorHandler::new(
            &mut self.pipeline_context.interceptor_handler_context,
            &mut self.rtp_transceivers,
            &self.media_engine,
            &mut self.interceptor,
            &mut self.pipeline_context.stats,
            rtp_session,
        )
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(
            &mut self.pipeline_context.endpoint_handler_context,
            &mut self.rtp_transceivers,
            &mut self.pipeline_context.stats,
        )
    }

    /// Runs every handler's pending writes down the pipeline into `write_outs`, where
    /// [`poll_write`](sansio::Protocol::poll_write) hands them out.
    /// Queues a data channel's close behind the messages the application has already sent on
    /// it: they enter the pipeline at the endpoint too, and a close that went straight to the
    /// channel reset its SCTP stream ahead of them (RFC 8831 section 6.7: the reset follows the
    /// data), so the peer received none of it.
    pub(crate) fn write_data_channel_close(
        &mut self,
        data_channel_id: crate::data_channel::RTCDataChannelId,
    ) -> Result<(), Error> {
        use sansio::Protocol;

        let now = self.pipeline_context.now;
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id,
                data_channel_event: DataChannelEvent::Close,
            })),
        })
    }

    pub(crate) fn flush_writes(&mut self) {
        use sansio::Protocol;

        // The stages above SRTP are the connection's: they run once.
        let mut intermediate_wouts = VecDeque::new();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_wouts.pop_front() {
                if let Err(err) = handler.handle_write(msg) {
                    warn!("{}.handle_write got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_write() {
                intermediate_wouts.push_back(msg);
            }
        }), [get_endpoint_handler, get_interceptor_handler]);

        // SRTP and below are each transport's: a packet goes down the transport of the m=
        // section its SSRC belongs to, data channel messages down the one SCTP runs over
        // (RFC 9143 section 9; RFC 9429 section 5.2.1: a transport per unbundled section).
        let ids = self.pipeline_context.transports.ids();
        let data = self.pipeline_context.transports.data_transport_id();
        let mut per_transport: Vec<VecDeque<TaggedRTCMessageInternal>> =
            ids.iter().map(|_| VecDeque::new()).collect();
        while let Some(mut msg) = intermediate_wouts.pop_front() {
            // RTCP an RTP session's instance wrote goes down that session's transport.
            let mut named = None;
            if let RTCMessageInternal::Rtp(RTPMessage::SessionRtcp(session, packets)) = msg.message
            {
                named = ids.iter().copied().find(|id| id.0 == session);
                msg.message = RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets)));
            }
            let id = if ids.len() == 1 {
                ids[0]
            } else {
                named
                    .or_else(|| self.transport_of_write(&msg))
                    .unwrap_or(data)
            };
            // RFC 3550 section 6, RFC 8834 section 4.1: RTCP belongs to an RTP session, and a
            // transport without a negotiated RTP m= section (and SRTP keys) has none. Whatever
            // RTCP is written for it (an RTCP session the application built that joins by
            // itself) does not leave.
            if matches!(
                &msg.message,
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(_)))
            ) && !{
                let ctx = &self.pipeline_context.interceptor_handler_context;
                ctx.rtcp_joined.contains(&id.0) || ctx.rtcp_leaving.contains(&id.0)
            } {
                debug!("RTCP for a transport without an RTP session dropped");
                continue;
            }
            // A FEC session's transport (RFC 5109 section 14.1): the chain's SSRCs become the
            // wire's, where the FEC stream has the SSRC of the media stream it protects
            // (section 7.2), in RTP and in the session's RTCP.
            {
                let ctx = &self.pipeline_context.interceptor_handler_context;
                if let Some(map) = ctx.fec_session_map
                    && ctx.fec_session_transports.contains_key(&id.0)
                {
                    match &mut msg.message {
                        RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))) => {
                            map.map_rtp(packet);
                        }
                        RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) => {
                            let mapped = map.map_rtcp(packets);
                            if mapped.is_empty() {
                                continue;
                            }
                            *packets = mapped;
                        }
                        _ => {}
                    }
                }
            }
            let index = ids.iter().position(|t| *t == id).unwrap_or(0);
            per_transport[index].push_back(msg);
        }
        // What a session that left had to say (its BYE) has been handed on.
        self.pipeline_context
            .interceptor_handler_context
            .rtcp_leaving
            .clear();

        for (id, mut wouts) in ids.into_iter().zip(per_transport) {
            let previous = self.pipeline_context.transports.active_id();
            self.pipeline_context.activate_transport(id);
            process_handler_list!(call_macro: process_handler!(self, handler, {
                while let Some(msg) = wouts.pop_front() {
                    if let Err(err) = handler.handle_write(msg) {
                        warn!("{}.handle_write got error: {}", handler.name(), err);
                    }
                }
                while let Some(msg) = handler.poll_write() {
                    wouts.push_back(msg);
                }
            }), [get_srtp_handler]);
            if id == data {
                process_handler_list!(call_macro: process_handler!(self, handler, {
                    while let Some(msg) = wouts.pop_front() {
                        if let Err(err) = handler.handle_write(msg) {
                            warn!("{}.handle_write got error: {}", handler.name(), err);
                        }
                    }
                    while let Some(msg) = handler.poll_write() {
                        wouts.push_back(msg);
                    }
                }), [get_datachannel_handler, get_sctp_handler]);
            }
            process_handler_list!(call_macro: process_handler!(self, handler, {
                while let Some(msg) = wouts.pop_front() {
                    if let Err(err) = handler.handle_write(msg) {
                        warn!("{}.handle_write got error: {}", handler.name(), err);
                    }
                }
                while let Some(msg) = handler.poll_write() {
                    wouts.push_back(msg);
                }
            }), [get_dtls_handler, get_ice_handler, get_demuxer_handler]);
            self.pipeline_context.activate_transport(previous);

            // Final poll write out to pipeline's write out; what leaves from one of the
            // engine's ICE-TCP candidates goes onto that transport's connection instead.
            while let Some(msg) = wouts.pop_front() {
                // What this transport sends on a local address others share is how the
                // answers on that 5-tuple find it (`TransportSet::route`, rule 2).
                self.pipeline_context
                    .transports
                    .learn_path(id, &msg.transport);
                if let RTCMessageInternal::Raw(message) = msg.message
                    && let Some(out) = self.take_tcp_write(
                        id,
                        TaggedBytesMut {
                            now: msg.now,
                            transport: msg.transport,
                            message,
                        },
                    )
                {
                    self.pipeline_context.write_outs.push_back(out);
                }
            }
        }
    }

    /// The transport an RTP or RTCP packet on its way to SRTP goes down: that of the m=
    /// section of its SSRC (the sender's or receiver's whose stream it is, or that an RTCP
    /// packet reports on). `None` for anything else, and for an SSRC no section has.
    fn transport_of_write(&self, msg: &TaggedRTCMessageInternal) -> Option<TransportId> {
        let ssrcs: Vec<u32> = match &msg.message {
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))) => {
                vec![packet.header.ssrc]
            }
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) => packets
                .iter()
                .flat_map(|packet| packet.destination_ssrc())
                .collect(),
            _ => return None,
        };
        ssrcs
            .into_iter()
            .find_map(|ssrc| self.transport_of_ssrc(ssrc))
    }

    /// The transport of the m= section whose sender or receiver has `ssrc` (its media, RTX or
    /// FEC stream).
    pub(crate) fn transport_of_ssrc(&self, ssrc: u32) -> Option<TransportId> {
        let has = |coding: &crate::rtp_transceiver::rtp_sender::RTCRtpCodingParameters| {
            coding.ssrc == Some(ssrc)
                || coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc)
                || coding.fec.as_ref().is_some_and(|fec| fec.ssrc == ssrc)
        };
        self.rtp_transceivers
            .iter()
            .find_map(|transceiver| {
                let mid = transceiver.mid().as_ref()?;
                let sends = transceiver.sender().as_ref().is_some_and(|sender| {
                    sender
                        .send_encodings()
                        .iter()
                        .any(|encoding| has(&encoding.rtp_coding_parameters))
                });
                let receives = transceiver
                    .receiver()
                    .as_ref()
                    .is_some_and(|receiver| receiver.get_coding_parameters().iter().any(&has));
                (sends || receives).then(|| self.pipeline_context.transports.transport_id_for(mid))
            })
            // The stream of a FEC session (RFC 5109 section 14.1), which the chain knows by an
            // SSRC of its own: that session's transport.
            .or_else(|| self.fec_session_transport_of_ssrc(ssrc))
    }

    /// Starts and ends each transport's RTCP session. RFC 3550 section 6: RTCP is the control
    /// protocol of an RTP session, and a WebRTC endpoint has one per transport that carries
    /// RTP m= sections (RFC 8834 sections 4.1 and 4.4; RFC 9429 section 5.2.1). A transport's
    /// session joins once both hold: a negotiated RTP section uses it (not rejected, not
    /// stopped, with a current direction, `inactive` included: RFC 3264 section 5.1 keeps RTCP
    /// for every direction) and its DTLS association has given SRTP keys, so that nothing
    /// leaves unprotected (RFC 3711 section 3.4, RFC 5764 section 4.1). It leaves, saying BYE,
    /// when the transport's last such section is gone. A data-channel-only connection has no
    /// RTP session and sends no RTCP at all.
    pub(crate) fn sync_rtcp_sessions(&mut self, now: Instant) {
        let ids = self.pipeline_context.transports.ids();
        let ctx = &mut self.pipeline_context.interceptor_handler_context;
        ctx.srtp_keyed.retain(|id| ids.iter().any(|t| t.0 == *id));
        let mut wanted = std::collections::BTreeMap::new();
        for id in &ids {
            let Some(bundle) = self.pipeline_context.transports.transport(*id) else {
                continue;
            };
            let context = bundle.srtp_handler_context.local_srtp_context.as_ref();
            let ctx = &mut self.pipeline_context.interceptor_handler_context;
            if context.is_some() {
                ctx.srtp_keyed.insert(id.0);
            }
            if !ctx.srtp_keyed.contains(&id.0) {
                continue;
            }
            let carries_rtp = self.rtp_transceivers.iter().any(|transceiver| {
                !transceiver.stopped()
                    && transceiver.current_direction()
                        != crate::rtp_transceiver::RTCRtpTransceiverDirection::Unspecified
                    && transceiver.mid().as_ref().is_some_and(|mid| {
                        self.pipeline_context.transports.transport_id_for(mid) == *id
                    })
            });
            if carries_rtp {
                wanted.insert(id.0, self::interceptor::srtcp_overhead(context));
            }
        }
        let joined = std::mem::take(
            &mut self
                .pipeline_context
                .interceptor_handler_context
                .rtcp_joined,
        );
        let leaving: Vec<usize> = joined
            .iter()
            .copied()
            .filter(|session| !wanted.contains_key(session))
            .collect();
        let joining: Vec<(usize, usize)> = wanted
            .iter()
            .filter(|(session, _)| !joined.contains(session))
            .map(|(session, overhead)| (*session, *overhead))
            .collect();
        let mut handler = self.get_interceptor_handler();
        for session in leaving {
            // A transport that is gone takes its session with it: nothing would carry a BYE.
            if !ids.iter().any(|id| id.0 == session) {
                continue;
            }
            match handler.leave_rtcp_session(now, session) {
                Ok(()) => {
                    handler.ctx_mut().rtcp_leaving.insert(session);
                }
                Err(err) => {
                    warn!("the RTCP session of transport {session} could not leave: {err}")
                }
            }
        }
        for (session, overhead) in joining {
            if let Err(err) = handler.join_rtcp_session(now, session, overhead) {
                warn!("the RTCP session of transport {session} could not join: {err}");
            }
        }
        self.pipeline_context
            .interceptor_handler_context
            .rtcp_joined = wanted.into_keys().collect();
    }

    /// Takes the DTLS datagrams the active transport's ICE handler held from before it had a
    /// path, once it has one (RFC 8842 section 5.2: a ClientHello that overtook the answer),
    /// up the pipeline.
    pub(crate) fn release_early_dtls(&mut self) {
        let held = !self
            .pipeline_context
            .transports
            .active_mut()
            .ice_handler_context
            .early_dtls
            .is_empty();
        if held {
            self.get_ice_handler().release_early_dtls();
            self.pump_reads_on_active(None);
        }
    }

    /// Runs the pipeline's reads: `msg` up the active transport, or, without one, what every
    /// transport's handlers have queued.
    fn pump_reads(&mut self, msg: Option<TaggedRTCMessageInternal>) {
        if msg.is_some() || self.pipeline_context.transports.len() == 1 {
            self.pump_reads_on_active(msg);
            return;
        }
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.pump_reads_on_active(None));
        }
    }

    fn pump_reads_on_active(&mut self, msg: Option<TaggedRTCMessageInternal>) {
        // RFC 9143 section 9.2: an unknown SSRC is looked up in the tables of the transport
        // (the BUNDLE group, or the section) it arrived on.
        self.pipeline_context
            .interceptor_handler_context
            .arrival_mids = self.active_transport_mids();
        let mut intermediate_routs = VecDeque::<TaggedRTCMessageInternal>::new();

        if let Some(msg) = msg {
            intermediate_routs.push_back(msg);
        }

        use sansio::Protocol;
        // SCTP and the data channels are on the data transport only: another transport's
        // DTLS carries none of their packets, and its events are not theirs.
        let carries_data = self.active_carries_data();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_demuxer_handler, get_ice_handler, get_dtls_handler]);
        if carries_data {
            process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_sctp_handler, get_datachannel_handler]);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_srtp_handler, get_interceptor_handler, get_endpoint_handler]);

        // Finally, put intermediate_routs into RTCPeerConnection's routs
        while let Some(msg) = intermediate_routs.pop_front() {
            let rtc_message = match msg.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(application_message)) => {
                    if let DataChannelEvent::Message(data_channel_message) =
                        application_message.data_channel_event
                    {
                        Some(RTCMessage::DataChannelMessage(
                            application_message.data_channel_id,
                            data_channel_message,
                        ))
                    } else {
                        None
                    }
                }
                RTCMessageInternal::Rtp(RTPMessage::TrackPacket(track_packet)) => {
                    match track_packet.packet {
                        Packet::Rtp(packet) => {
                            Some(RTCMessage::RtpPacket(track_packet.track_id, packet))
                        }
                        Packet::Rtcp(packet) => {
                            Some(RTCMessage::RtcpPacket(track_packet.track_id, packet))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

            if let Some(rtc_message) = rtc_message {
                // The instant travels with the message: the application learns when the packet
                // was observed at the socket, not when it happened to drain it.
                let tagged = TaggedRTCMessage {
                    now: msg.now,
                    message: rtc_message,
                };
                // Routed by kind, so a caller can decline data-channel output — the only way
                // to apply SCTP back-pressure — without also declining media.
                match &tagged.message {
                    RTCMessage::DataChannelMessage(..) => {
                        self.pipeline_context.data_read_outs.push_back(tagged)
                    }
                    _ => self.pipeline_context.media_read_outs.push_back(tagged),
                }
            }
        }
    }

    /// RFC 5764 section 4.4: "Once the key lifetime has been reached, a new DTLS session SHOULD
    /// be established". A key of the active transport has reached the re-keying margin (a
    /// sixteenth of its lifetime left, or the packets a re-keying needs in time at its rate
    /// when that is more: `SrtpHandlerContext::rekeying_margin_reached`; `due` false) or a
    /// thirty-second of its lifetime is left (`due` true): unless the application turned it off, a
    /// new association is wanted, and asked for as `renew_dtls_association` does (new
    /// `tls-id`, ICE restart, negotiation-needed).
    ///
    /// At the sixteenth the DTLS server of the association waits a little
    /// (`SettingEngineBuilder::with_srtp_rekeying_dtls_client_first`): for at most
    /// [`SRTP_REKEYING_SERVER_WAIT`] and an eighth of the time the keys have left at the rate
    /// they are used, for the client's offer, so that two peers with the same lifetime do not
    /// both offer. Lifetimes are local, so the server cannot know the client re-keys at all:
    /// the wait is bounded in time, never a share of the margin a slow path needs (a
    /// handshake through TURN takes seconds, whatever the packet rate). Without an estimate of
    /// that time (no packet yet under these keys) the server does not wait. At the
    /// thirty-second either side asks at once.
    fn renew_before_the_key_lifetime_ends(&mut self, due: bool) {
        if self.setting_engine.srtp_automatic_rekeying_off || self.is_closed() {
            return;
        }
        let client_first = !self.setting_engine.srtp_rekeying_both_at_warning;
        let now = self.pipeline_context.now;
        let time_left = self
            .pipeline_context
            .transports
            .active()
            .srtp_handler_context
            .key_time_left(now);
        if let Some(left) = time_left.filter(|left| *left < SRTP_REKEYING_TIGHT_MARGIN) {
            log::warn!(
                "an SRTP key has {left:?} left at its packet rate: a re-keying may not complete \
                 in time (see SettingEngineBuilder::with_srtp_key_lifetime)"
            );
        }
        let dtls = self.dtls_transport_mut();
        let wait = time_left
            .map(|left| (left / 8).min(SRTP_REKEYING_SERVER_WAIT))
            .filter(|_| client_first && dtls.dtls_role == RTCDtlsRole::Server);
        dtls.srtp_rekeying = match (dtls.srtp_rekeying, wait) {
            (SrtpRekeying::Wanted, _) => SrtpRekeying::Wanted,
            _ if due => SrtpRekeying::Wanted,
            (SrtpRekeying::Deferred, _) => SrtpRekeying::Deferred,
            (_, Some(wait)) if !wait.is_zero() => {
                dtls.srtp_rekeying_deferred_until = Some(now + wait);
                SrtpRekeying::Deferred
            }
            _ => SrtpRekeying::Wanted,
        };
        self.request_wanted_srtp_rekeying();
    }

    /// A DTLS server that waited for the client's re-keying offer
    /// ([`SrtpRekeying::Deferred`]) and did not get it in time asks itself.
    pub(crate) fn end_srtp_rekeying_waits(&mut self, now: Instant) {
        let mut ended = false;
        for id in self.pipeline_context.transports.ids() {
            ended |= self.with_transport(id, |pc| {
                let dtls = pc.dtls_transport_mut();
                if dtls.srtp_rekeying == SrtpRekeying::Deferred
                    && dtls
                        .srtp_rekeying_deferred_until
                        .is_some_and(|until| until <= now)
                {
                    dtls.srtp_rekeying = SrtpRekeying::Wanted;
                    dtls.srtp_rekeying_deferred_until = None;
                    true
                } else {
                    false
                }
            });
        }
        if ended {
            self.request_wanted_srtp_rekeying();
        }
    }

    /// The earliest instant a server's wait for the client's re-keying offer ends.
    fn srtp_rekeying_wait_timeout(&self) -> Option<Instant> {
        self.pipeline_context
            .transports
            .ids()
            .into_iter()
            .filter_map(|id| {
                let dtls = self.dtls_transport_of(id);
                (dtls.srtp_rekeying == SrtpRekeying::Deferred)
                    .then_some(dtls.srtp_rekeying_deferred_until)
                    .flatten()
            })
            .min()
    }

    /// Asks for the new association the SRTP re-keying of a transport wants
    /// ([`SrtpRekeying::Wanted`]), unless one is already being negotiated or established, by
    /// either side, or the transport is not connected: one renewal at a time. What waits is
    /// asked for when the connection is back in the stable state with no new association
    /// under way (`commit_description`); a new association that comes meanwhile (the peer's
    /// renewal) brings new keys and nothing is asked for.
    pub(crate) fn request_wanted_srtp_rekeying(&mut self) {
        if self.setting_engine.srtp_automatic_rekeying_off || self.is_closed() {
            return;
        }
        let wanted = self
            .pipeline_context
            .transports
            .ids()
            .into_iter()
            .any(|id| {
                let dtls = self.dtls_transport_of(id);
                dtls.srtp_rekeying == SrtpRekeying::Wanted
                    && dtls.state() == RTCDtlsTransportState::Connected
            });
        if !wanted || self.dtls_renewal_under_way() {
            return;
        }
        log::debug!("an SRTP master key is near its lifetime: asking for a new DTLS association");
        self.request_dtls_renewal(true);
    }

    /// Whether a new DTLS association of some transport is asked for, being negotiated (an
    /// offer or the answer to the peer's offer carries a new `tls-id`, or the pending remote
    /// offer asks for one) or being established (its handshake has not completed).
    pub(crate) fn dtls_renewal_under_way(&self) -> bool {
        let pending_remote = self
            .pending_remote_transport
            .as_ref()
            .is_some_and(|pending| {
                pending.new_dtls_role.is_some()
                    || pending.staged_tls_id
                    || pending.other_restarts.iter().any(|(_, _, staged)| *staged)
            });
        pending_remote
            || self
                .pipeline_context
                .transports
                .ids()
                .into_iter()
                .any(|id| {
                    let dtls = self.dtls_transport_of(id);
                    dtls.renewal_requested
                        || dtls.staged_local_tls_id.is_some()
                        || (dtls.is_started() && dtls.state() == RTCDtlsTransportState::Connecting)
                })
    }

    /// Whether the active transport is the one the SCTP association runs over.
    fn active_carries_data(&self) -> bool {
        let transports = &self.pipeline_context.transports;
        transports.active_id() == transports.data_transport_id()
    }

    /// Has the handlers work off what applying a description left them, so that the events it
    /// causes are queued now, behind the description's own, and not at some later poll
    /// behind whatever the application did in between (W3C webrtc-pc: closing a channel's
    /// underlying data transport and closing a transport each "queue a task", in that order
    /// after the task that set the description). What `poll_event` does once its backlog is
    /// empty.
    pub(crate) fn settle_description_events(&mut self) {
        if self.pump_events() {
            self.pump_reads(None);
            self.pump_events();
        }
    }

    /// Returns whether any handler raised an event during the sweep, of any transport.
    fn pump_events(&mut self) -> bool {
        let mut raised = false;
        for id in self.pipeline_context.transports.ids() {
            raised |= self.with_transport(id, |pc| pc.pump_events_on_active());
        }
        // A handshake that completed may have keyed a transport that carries RTP sections.
        if raised {
            self.sync_rtcp_sessions(self.pipeline_context.now);
        }
        // A pair selected since: a comparison per transport, not work, when none was.
        self.tell_chain_of_path_changes(self.pipeline_context.now);
        // The SCTP transport's state follows its association, which any event may have moved;
        // the selected pair is the agent's, whose change event the DTLS handler consumes.
        self.announce_transport_states();
        if !self.is_closed() {
            self.announce_selected_candidate_pair();
        }

        raised
    }

    /// Tells the interceptor chain of each transport whose ICE agent selected another candidate
    /// pair after its first ([`::interceptor::PathChanged`], on the read leg, so the congestion
    /// controllers, which sit wire-most, see it first): a new path, on which the bandwidth
    /// estimate starts over and the packets sent into the old one are not counted as lost
    /// (RFC 8836 section 2, requirement 1; libwebrtc's
    /// `RtpTransportControllerSend::OnNetworkRouteChanged`, which leaves the first connection
    /// alone: "No need to reset BWE if this is the first time the network connects"). The
    /// controllers also follow the addresses inbound packets arrive between, but those do not
    /// change when a TURN relay keeps them or the application hands every datagram over with
    /// one placeholder pair. With several transports the carrier names the RTP session of the
    /// transport whose pair changed.
    fn tell_chain_of_path_changes(&mut self, now: Instant) {
        let several = self.pipeline_context.transports.len() > 1;
        let mut changed = Vec::new();
        for bundle in self.pipeline_context.transports.iter_mut() {
            let ice = &mut bundle.ice_handler_context;
            if ice.selected_pair_changes != ice.selected_pair_changes_told_chain {
                ice.selected_pair_changes_told_chain = ice.selected_pair_changes;
                if ice.selected_pair_changes > 1 {
                    changed.push(bundle.id.0);
                }
            }
        }
        use sansio::Protocol;
        for session in changed {
            let carrier = ::interceptor::PathChanged.into_packet(now, several.then_some(session));
            if let Err(err) = self.interceptor.handle_read(carrier) {
                warn!(
                    "the path change of transport {session} did not reach the interceptors: {err}"
                );
            }
        }
    }

    fn pump_events_on_active(&mut self) -> bool {
        let mut intermediate_eouts = VecDeque::new();
        let mut raised = false;

        use sansio::Protocol;

        let carries_data = self.active_carries_data();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_demuxer_handler, get_ice_handler, get_dtls_handler]);
        if carries_data {
            process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_sctp_handler, get_datachannel_handler]);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_srtp_handler, get_interceptor_handler, get_endpoint_handler]);

        // Finally, put intermediate_eouts into RTCPeerConnection's eouts, with the transport
        // and connection state events each causes, in the spec's order: the transport's own
        // event, then the connection's (W3C webrtc-pc 4.4.1.3, 5.5, 5.6).
        while let Some(evt_internal) = intermediate_eouts.pop_front() {
            match evt_internal.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state),
                ) => {
                    // `close()` sets the ICE connection state without an event; what the
                    // agent reports once it is closed is not told either.
                    if self.is_closed() {
                        continue;
                    }
                    // The transport's own event (`OnTransportEvent`, and the variant naming
                    // no transport for the default one); the connection's is the aggregate
                    // of every transport's state (W3C 4.3.4).
                    self.announce_ice_transport_state(state);
                    let aggregate = self.ice_connection_state();
                    if aggregate != self.pipeline_context.announced_ice_connection_state {
                        self.pipeline_context.announced_ice_connection_state = aggregate;
                        self.pipeline_context.event_outs.push_back(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(aggregate),
                        );
                    }
                    self.update_connection_state(false);
                }
                RTCEventInternal::DTLSHandshakeComplete(_, _) | RTCEventInternal::DTLSClosed => {
                    // The re-keying margin of the new keys is measured on the handshake that
                    // gave them (`SrtpHandlerContext::rekeying_margin_reached`).
                    for transport in self.pipeline_context.transports.iter_mut() {
                        transport.srtp_handler_context.rekeying_time = transport
                            .dtls_handler_context
                            .dtls_transport
                            .rekeying_handshake_time;
                    }
                    self.announce_transport_states();
                    self.update_connection_state(false);
                }
                RTCEventInternal::SrtpRekeyingDue => {
                    self.renew_before_the_key_lifetime_ends(true);
                }
                RTCEventInternal::SrtpRekeyingMarginReached => {
                    self.renew_before_the_key_lifetime_ends(false);
                }
                RTCEventInternal::SRTPKeyExhausted => {
                    // RFC 3711 section 9.2: re-key or end the session. A new DTLS association
                    // is not something a browser peer takes on a transport that has one, so
                    // the session ends: the transport fails with the reason.
                    use crate::peer_connection::rtc_error::{RTCError, RTCErrorDetailType};
                    let now = evt_internal.now;
                    self.get_dtls_handler().fail_with(
                        now,
                        RTCError::new(
                            RTCErrorDetailType::DtlsFailure,
                            "the SRTP master key reached its lifetime (RFC 3711 section 9.2)",
                        ),
                    );
                    self.announce_transport_states();
                }
                // webrtc-extensions 7: the candidate pair events are the active transport's.
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairAdd(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairAdd(pair.clone()),
                    RTCTransportEventKind::CandidatePairAdd(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairNominate(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairNominate(pair.clone()),
                    RTCTransportEventKind::CandidatePairNominate(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairRemove(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairRemove(pair.clone()),
                    RTCTransportEventKind::CandidatePairRemove(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(evt) => {
                    let expiring = matches!(
                        evt,
                        RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { .. }
                    );
                    self.pipeline_context.event_outs.push_back(evt);
                    if expiring {
                        self.renew_before_the_key_lifetime_ends(false);
                    }
                }
                _ => {}
            }
        }

        raised
    }
}

impl RTCPeerConnection {
    /// Whether the embedder's address policy lets `addr` be used for `purpose`
    /// (`SettingEngineBuilder::with_ice_address_policy`; the default allows everything).
    pub(crate) fn address_allowed(
        &self,
        addr: std::net::SocketAddr,
        purpose: ::ice::AddressPurpose,
    ) -> bool {
        self.setting_engine
            .candidates
            .address_policy
            .allows(addr, purpose)
    }

    /// Reads a datagram on the transport `id`, which the caller has already chosen (a stream
    /// the engine knows the transport of, a relayed candidate's link).
    pub(crate) fn read_on_transport(&mut self, id: TransportId, msg: TaggedBytesMut) {
        // Every datagram of the peer (direct, relayed by one of the engine's TURN allocations,
        // or read on an ICE-TCP connection) comes through here: one from a source the
        // embedder's address policy refuses reaches neither the ICE agent nor DTLS nor the
        // media (`SettingEngineBuilder::with_ice_address_policy`).
        if !self.address_allowed(
            msg.transport.peer_addr,
            ::ice::AddressPurpose::InboundDatagramSource,
        ) {
            log::debug!(
                "dropped a datagram from {}: the address policy refuses the source",
                msg.transport.peer_addr
            );
            return;
        }
        let msg = TaggedRTCMessageInternal {
            now: msg.now,
            transport: msg.transport,
            message: RTCMessageInternal::Raw(msg.message),
        };
        self.with_transport(id, |pc| pc.pump_reads(Some(msg)));
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedRTCMessage, TaggedRTCEvent> for RTCPeerConnection {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    /// Feeds one received datagram.
    ///
    /// `msg.transport.local_addr` is the address of the local candidate the datagram arrived
    /// on, and the ICE agent matches it exactly against its local candidates (RFC 8445 section
    /// 7.3.1.4); a datagram on any other address is discarded ("Discarded message, not a valid
    /// local candidate"). Two cases where that is not the socket's own address:
    ///
    /// - **A socket bound to the unspecified address** (`0.0.0.0:port`, `[::]:port`) passes
    ///   the concrete address the datagram was received on (its destination address, e.g.
    ///   `IP_PKTINFO` / `IPV6_RECVPKTINFO`; that is the host candidate's address), not
    ///   `socket.local_addr()`. Binding one socket per local address, as
    ///   `rtci-stream-driver`'s `PeerDriver` does, avoids the question.
    /// - **A datagram relayed by a TURN allocation the application runs**
    ///   ([`RelayGathering::Application`](crate::peer_connection::turn_streams::RelayGathering::Application)):
    ///   the payload of the Data indication or ChannelData, with `local_addr` = the relayed
    ///   address (the relay candidate's address) and `peer_addr` = the peer.
    ///
    /// ```text
    /// let (n, peer, destination_ip) = recv_with_pktinfo(&socket, &mut buf)?;  // wildcard-bound
    /// pc.handle_read(TaggedBytesMut { now, message: BytesMut::from(&buf[..n]),
    ///     transport: TransportContext {
    ///         local_addr: SocketAddr::new(destination_ip, socket_port),  // not 0.0.0.0:port
    ///         peer_addr: peer, transport_protocol: TransportProtocol::UDP, ecn: None } })?;
    /// ```
    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        self.pipeline_context.observe(msg.now);
        // Closed: only the answers to the TURN releases still under way are read (RFC 8656
        // section 8: the Refresh of LIFETIME 0 is a transaction like any other).
        if self.is_closed() {
            let _ = self.take_turn_release(msg);
            return Ok(());
        }
        // A record of one of the engine's DTLS associations to a TURN server (RFC 7350).
        let Some(msg) = self.take_turn_dtls(msg) else {
            return Ok(());
        };
        // The answer to one of the engine's own Binding requests to a STUN server.
        let Some(msg) = self.take_srflx_response(msg) else {
            return Ok(());
        };
        // An answer, Data indication or ChannelData of one of the engine's own TURN
        // allocations over UDP (RFC 8656).
        let Some(msg) = self.take_turn_udp(msg) else {
            return Ok(());
        };
        // The transport the datagram belongs to, by where it arrived (RFC 9143 section 9: a
        // transport per BUNDLE group or unbundled section) reads it. A Binding request on a
        // local address several transports share that names none of them is dropped
        // (`TransportSet::route`): the remote retransmits it.
        if let Some(transport) = self
            .pipeline_context
            .transports
            .route(&msg.transport, &msg.message)
        {
            self.read_on_transport(transport, msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.pump_reads(None);

        if let (Some(data), Some(media)) = (
            self.pipeline_context.data_read_outs.front(),
            self.pipeline_context.media_read_outs.front(),
        ) {
            if data.now <= media.now {
                self.pipeline_context.data_read_outs.pop_front()
            } else {
                self.pipeline_context.media_read_outs.pop_front()
            }
        } else if self.pipeline_context.data_read_outs.front().is_some() {
            self.pipeline_context.data_read_outs.pop_front()
        } else {
            self.pipeline_context.media_read_outs.pop_front()
        }
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        let now = msg.now;
        self.pipeline_context.observe(now);
        let rtc_message_internal = match msg.message {
            RTCMessage::DataChannelMessage(data_channel_id, data_channel_message) => {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id,
                    data_channel_event: DataChannelEvent::Message(data_channel_message),
                }))
            }
            RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp_packet)))
            }
            RTCMessage::RtcpPacket(_track_id, rtcp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(rtcp_packet)))
            }
        };

        // Only endpoint can handle user write message
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: rtc_message_internal,
        })
    }

    /// The next datagram to send; drain until `None`.
    ///
    /// Send it from `transport.local_addr` to `transport.peer_addr`: from the socket of that
    /// host address, or, when `local_addr` is the relayed address of a relay candidate the
    /// application added
    /// ([`RelayGathering::Application`](crate::peer_connection::turn_streams::RelayGathering::Application)),
    /// through that TURN allocation (a Send indication, or ChannelData on a bound channel;
    /// RFC 8656 sections 11 and 12), not directly. Datagrams of the engine's own allocations
    /// are already wrapped: they leave from a host address to the TURN server.
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.flush_writes();
        // A datagram for one of the engine's own TCP candidates goes on its connection
        // (`poll_stream_transmit`), not to the application.
        while let Some(msg) = self.pipeline_context.write_outs.pop_front() {
            if let Some(msg) = self.route_stream_write(msg) {
                return Some(msg);
            }
        }
        None
    }

    fn handle_event(&mut self, evt: TaggedRTCEvent) -> Result<(), Self::Error> {
        // `RTCEvent` is `pub enum RTCEvent {}` — uninhabited, reserved for future use — so no
        // caller can construct one and this arm is unreachable. Diverging on the empty match
        // keeps that fact in the type system, and avoids inventing an instant to wrap the
        // event with when there is none to be had. C3-03 replaces this with `evt.now` once
        // the public channel carries a timestamp.
        match evt.event {}
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        // A description or a timeout may have moved a transport's state (DTLS to "connecting"
        // when its handshake starts, say): announce it behind what is queued.
        self.announce_transport_states();
        self.announce_lite_candidate_update();
        // Drain the backlog before sweeping the pipeline again: anything a sweep adds lands
        // behind it anyway, and the sweep runs once the backlog is empty.
        while let Some(evt) = self.pipeline_context.event_outs.pop_front() {
            if self.negotiation_needed_withdrawn(&evt) {
                continue;
            }
            return Some(self.hand_out_event(evt));
        }

        // Handling an event can queue read messages, like the open of a negotiated data channel
        // on `SCTPHandshakeComplete`. Deliver them, and the events they raise, now rather than
        // on the next incoming packet.
        if self.pump_events() {
            self.pump_reads(None);
            self.pump_events();
        }

        while let Some(evt) = self.pipeline_context.event_outs.pop_front() {
            if self.negotiation_needed_withdrawn(&evt) {
                continue;
            }
            return Some(self.hand_out_event(evt));
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.pipeline_context.observe(now);
        // Closed: only the TURN releases still under way have timers.
        if self.is_closed() {
            self.turn_releases_handle_timeout(now);
            return Ok(());
        }
        // RFC 8837 section 5: the association's congestion control starts over when its
        // codepoint changed (a channel of another priority came or went).
        self.restart_sctp_congestion_control_on_dscp_change(now);
        // RFC 8835 section 4.2: a marked media flow the network blocks goes back to DSCP 0.
        self.detect_blocked_dscp(now);
        // The connection's handlers once, each transport's for every transport.
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_demuxer_handler]);
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| -> Result<(), Error> {
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    handler.handle_timeout(now)?;
                }), [get_ice_handler, get_dtls_handler]);
                Ok(())
            })?;
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_sctp_handler, get_datachannel_handler]);
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| -> Result<(), Error> {
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    handler.handle_timeout(now)?;
                }), [get_srtp_handler]);
                Ok(())
            })?;
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_interceptor_handler, get_endpoint_handler]);
        // The DTMF senders' playout (W3C webrtc-pc section 7).
        self.run_dtmf(now)?;
        // The engine's TURN-over-stream clients and connection races, and its Binding
        // requests to STUN servers.
        self.turn_handle_timeout(now);
        self.srflx_handle_timeout(now);
        self.end_srtp_rekeying_waits(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        // Closed: the TURN releases still under way are all that is left; `None` once they
        // are done (nothing more will be sent or read).
        if self.is_closed() {
            return self.turn_releases_poll_timeout();
        }
        let mut eto: Option<Instant> = None;
        for_each_handler!(forward: process_handler!(self, handler, {
            if let Some(next) = handler.poll_timeout() {
                eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
            }
        }));
        // The other transports' ICE, DTLS and SRTP timers.
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let next = self.with_transport(id, |pc| {
                let mut eto: Option<Instant> = None;
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Some(next) = handler.poll_timeout() {
                        eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
                    }
                }), [get_ice_handler, get_dtls_handler, get_srtp_handler]);
                eto
            });
            if let Some(next) = next {
                eto = Some(eto.map_or(next, |curr| curr.min(next)));
            }
        }
        if let Some(dtmf) = self.dtmf_timeout() {
            eto = Some(eto.map_or(dtmf, |curr| curr.min(dtmf)));
        }
        if let Some(turn) = self.turn_poll_timeout() {
            eto = Some(eto.map_or(turn, |curr| curr.min(turn)));
        }
        if let Some(srflx) = self.srflx_poll_timeout() {
            eto = Some(eto.map_or(srflx, |curr| curr.min(srflx)));
        }
        if let Some(wait) = self.srtp_rekeying_wait_timeout() {
            eto = Some(eto.map_or(wait, |curr| curr.min(wait)));
        }
        eto
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.signaling_state = RTCSignalingState::Closed;

        // Tell the peer before tearing anything down, so it can close at once instead of waiting
        // for its ICE consent checks to time out (rtc#255). During this flush the SCTP handler
        // sends the data it still holds and then an ABORT for each association (W3C close():
        // "tear down the underlying SCTP association by sending an SCTP ABORT chunk"), and the
        // DTLS handler queues a close_notify behind them, so nothing pending is dropped or sent
        // after it. They are routed now because closing the ICE handler below forgets the
        // selected candidate pair every outbound packet is addressed with; the packets wait in
        // `write_outs` for the caller's next `poll_write`.
        let now = self.pipeline_context.now;
        // RFC 3550 6.6: the SSRCs of a participant that leaves say BYE.
        self.get_interceptor_handler().request_goodbye(now);
        self.get_sctp_handler().request_abort();
        // Every transport's DTLS association says close_notify.
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.get_dtls_handler().request_close(now));
        }
        self.flush_writes();
        // The engine's TCP connections carry what was just queued, then close.
        self.close_streams();
        // Its DTLS associations to TURN servers say close_notify.
        self.close_turn_dtls();

        // Close handlers in reverse order (Endpoint→Interceptor→SRTP→DataChannel→SCTP→
        // DTLS→ICE→Demuxer) so that higher-level protocols (DataChannels, SCTP) shut down
        // before the transports they depend on (DTLS, ICE).
        // Collect all errors instead of short-circuiting so every handler gets a chance
        // to clean up even if an earlier one fails. (Brainwires fork; see FORK.md.)
        let mut close_errs: Vec<Error> = vec![];
        process_handler_list!(call_macro: process_handler!(self, handler, {
            if let Err(e) = handler.close() {
                close_errs.push(e);
            }
        }), [get_endpoint_handler, get_interceptor_handler]);
        // Each transport's SRTP, DTLS and ICE, the SCTP association's between them.
        for id in self.pipeline_context.transports.ids() {
            let carries_data = id == self.pipeline_context.transports.data_transport_id();
            let errs = self.with_transport(id, |pc| {
                let mut errs: Vec<Error> = vec![];
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Err(e) = handler.close() {
                        errs.push(e);
                    }
                }), [get_srtp_handler]);
                if carries_data {
                    process_handler_list!(call_macro: process_handler!(pc, handler, {
                        if let Err(e) = handler.close() {
                            errs.push(e);
                        }
                    }), [get_datachannel_handler, get_sctp_handler]);
                }
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Err(e) = handler.close() {
                        errs.push(e);
                    }
                }), [get_dtls_handler, get_ice_handler]);
                errs
            });
            close_errs.extend(errs);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            if let Err(e) = handler.close() {
                close_errs.push(e);
            }
        }), [get_demuxer_handler]);
        // The connection's DTLS session (RFC 5764 section 3), if it has one: the tickets its
        // client side holds and the keys its server side seals tickets under are wiped now,
        // not when the connection is dropped.
        if let Some(group) = self.dtls_transport().resumption.as_ref() {
            group.close();
        }

        // W3C WebRTC §close shutdown work is implemented in individual handler close() methods:
        //   InterceptorHandler::close() → interceptor.close()
        //   DataChannelHandler::close() → closes all RTCDataChannelInternal instances
        //   SctpHandler::close()        → closes all SCTP associations + endpoint
        //   DtlsHandler::close()        → dtls_transport.stop()
        //   IceHandler::close()         → ice_transport.agent.close()

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (steps #6 to #11): every
        // transceiver is stopped, and the transports' and the connection's states become
        // "closed", all without an event.
        for transceiver in &mut self.rtp_transceivers {
            if !transceiver.is_stopped()
                && let Err(err) = transceiver.stop(&self.media_engine, &mut *self.interceptor)
            {
                close_errs.push(err);
            }
        }
        // Step 7: every data channel's [[ReadyState]] becomes "closed", without the closing
        // procedure and without an event.
        for channel in self.data_channels.values_mut() {
            channel.ready_state = crate::data_channel::RTCDataChannelState::Closed;
        }
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| {
                pc.ice_transport_mut().ice_connection_state =
                    crate::peer_connection::state::ice_connection_state::RTCIceConnectionState::Closed;
            });
        }
        self.peer_connection_state = RTCPeerConnectionState::Closed;
        self.close_announced_states();

        flatten_errs(close_errs)
    }
}

#[cfg(test)]
mod handler_test {
    use super::*;
    use crate::data_channel::message::RTCDataChannelMessage;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::event::RTCDataChannelEvent;
    use bytes::BytesMut;
    use sansio::Protocol;
    use shared::{TransportContext, TransportProtocol};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// Media must be drainable while data-channel output is held back.
    ///
    /// That is the whole point of the split: back-pressure is applied by declining to drain
    /// the data-channel queue, and while both kinds shared one queue that also stopped media.
    /// A slow signalling channel froze video on the same connection for as long as it stalled.
    #[test]
    fn media_drains_while_data_channel_output_is_held_back() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        // Media outnumbering data, the shape of a real SFU connection.
        for i in 0..10 {
            let message = if i % 5 == 0 {
                RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default())
            } else {
                RTCMessage::RtpPacket(Default::default(), ::rtp::packet::Packet::default())
            };
            let tagged = TaggedRTCMessage { now: base, message };
            match tagged.message {
                RTCMessage::DataChannelMessage(..) => {
                    pc.pipeline_context.data_read_outs.push_back(tagged)
                }
                _ => pc.pipeline_context.media_read_outs.push_back(tagged),
            }
        }

        // Drain media only — as a caller applying data-channel back-pressure would.
        let mut media = 0;
        while let Some(msg) = pc.poll_media_read() {
            assert!(
                !matches!(msg.message, RTCMessage::DataChannelMessage(..)),
                "poll_media_read must never yield data-channel output"
            );
            media += 1;
        }

        assert_eq!(
            media, 8,
            "all media must be deliverable while data is held back"
        );
        assert_eq!(
            pc.pipeline_context.data_read_outs.len(),
            2,
            "held-back data-channel output must stay queued — its length is the signal the \
             SCTP drain is bounded against, so losing it would drop the back-pressure"
        );

        // And releasing it hands over exactly what was held.
        let mut data = 0;
        while let Some(msg) = pc.poll_data_read() {
            assert!(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
            data += 1;
        }
        assert_eq!(data, 2);
    }

    /// `poll_read` still yields both kinds, so the callers that predate the split — 58 files
    /// across tests and examples — behave exactly as before.
    #[test]
    fn poll_read_still_yields_both_kinds() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        pc.pipeline_context
            .data_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default()),
            });
        pc.pipeline_context
            .media_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::RtpPacket(
                    Default::default(),
                    ::rtp::packet::Packet::default(),
                ),
            });

        let mut kinds = vec![];
        while let Some(msg) = pc.poll_read() {
            kinds.push(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
        }
        assert_eq!(kinds.len(), 2, "poll_read must still drain everything");
        assert!(kinds.contains(&true) && kinds.contains(&false));
    }

    /// The instant the application supplies on `handle_write` is the one the core stamps the
    /// resulting internal message with — not a reading the core took for itself. Before C3-03
    /// the public `Win` was a bare `RTCMessage`, so this entry point had no time source and
    /// stamped `Instant::now()`.
    #[test]
    fn handle_write_stamps_from_the_caller_not_the_clock() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        pc.handle_write(TaggedRTCMessage {
            now: t(5),
            message: RTCMessage::DataChannelMessage(
                1,
                RTCDataChannelMessage {
                    is_string: true,
                    data: BytesMut::from(&b"hello"[..]),
                },
            ),
        })
        .expect("handle_write queues the message");

        let queued = pc
            .pipeline_context
            .endpoint_handler_context
            .write_outs
            .front()
            .expect("the message reaches the endpoint handler");

        assert_eq!(
            queued.now,
            t(5),
            "the internal message carries the caller's instant, not an ambient reading"
        );
        assert_ne!(queued.now, t(0), "and not the construction instant either");
    }

    /// The open of a negotiated data channel is queued as a read message while
    /// `SCTPHandshakeComplete` is being handled, i.e. inside `poll_event`. That same `poll_event`
    /// call must return the `OnOpen`: the async `webrtc` driver drains events until `poll_event`
    /// returns `None` and then waits for the next packet or timer.
    #[test]
    fn negotiated_channel_opens_within_the_same_poll_event() {
        use crate::data_channel::RTCDataChannelInit;
        use crate::peer_connection::event::TaggedRTCEventInternal;
        use crate::peer_connection::transport::RTCDtlsRole;

        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("a default peer connection builds");
        let id = pc
            .create_data_channel(
                "negotiated",
                Some(RTCDataChannelInit {
                    negotiated: Some(1),
                    ..Default::default()
                }),
            )
            .expect("a negotiated data channel is created")
            .id();

        // Drain what creating the channel raised (`OnNegotiationNeeded`): an unrelated event
        // returned alongside would keep the loop below polling and hide a stuck open.
        while pc.poll_event().is_some() {}

        // Resolved by the DTLS handshake, which precedes the association.
        pc.dtls_transport_mut().dtls_role = RTCDtlsRole::Client;

        // What the SCTP handler emits once the association is up.
        pc.pipeline_context
            .sctp_handler_context
            .event_outs
            .push_back(TaggedRTCEventInternal {
                now: base,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            });

        let mut opened = false;
        while let Some(event) = pc.poll_event() {
            if matches!(
                event,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(opened_id)) if opened_id == id
            ) {
                opened = true;
            }
        }
        assert!(
            opened,
            "the open must not wait for the next incoming packet"
        );
    }

    /// Check that messages in the `read_out` queues don't get stuck until the next incoming packet triggers `handle_read`.
    #[test]
    fn pump_read_outs() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        // drop a message into the data channel handler read outs, like DataChannel::emit_data_channel_opened() does
        pc.pipeline_context
            .datachannel_handler_context
            .read_outs
            .push_back(TaggedRTCMessageInternal {
                now: t(5),
                transport: TransportContext {
                    local_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    peer_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id: 42,
                    data_channel_event: DataChannelEvent::Open,
                })),
            });

        // call `poll_read` to pump the read outs
        let msg = pc.poll_read();
        assert!(
            msg.is_none(),
            "The message should be consumed by the enpoint handler"
        );

        // we should get a channel opened event
        let event = pc.poll_event().expect("should have an event");
        assert!(matches!(
            event,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(42))
        ));
    }
}

#[cfg(test)]
mod close_tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use sansio::Protocol;

    #[test]
    fn close_transitions_to_closed_state() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        assert_ne!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
        assert_ne!(pc.signaling_state, RTCSignalingState::Closed);

        pc.close().unwrap();

        assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
        assert_eq!(pc.signaling_state, RTCSignalingState::Closed);
    }

    #[test]
    fn close_is_idempotent() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        pc.close().unwrap();
        // Second close should be a no-op (early return for already-closed)
        pc.close().unwrap();
        assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
    }

    #[test]
    fn close_preserves_data_channels_in_map() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        // Create a data channel before closing
        let dc = pc.create_data_channel("test", None).unwrap();
        let dc_id = dc.id();
        assert!(pc.data_channels.contains(&dc_id));

        pc.close().unwrap();

        // Data channels must remain in the map so that public RTCDataChannel
        // methods (label(), ready_state(), etc.) which use unwrap() don't panic.
        assert!(
            pc.data_channels.contains(&dc_id),
            "data_channels map must not be cleared on close"
        );
    }

    #[test]
    fn close_with_data_channel_does_not_panic() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        let dc = pc.create_data_channel("my-dc", None).unwrap();
        let dc_id = dc.id();
        pc.close().unwrap();

        // After close, public accessors on the data channel must still work
        // (they unwrap() the map entry).
        let dc = pc.data_channel(dc_id).unwrap();
        assert_eq!(dc.label(), "my-dc");
        let _ = dc.ready_state();
    }
}

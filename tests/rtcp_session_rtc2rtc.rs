//! The RTCP session between two `rtci` peer connections, in virtual time: one CNAME per
//! connection for every SSRC it sends from (RFC 7022, RFC 8834 4.9, RFC 4588 5.2), feedback
//! from the connection's own SSRC in a compound packet (RFC 4585 3.1, RFC 8108 5.4.1), RTCP
//! kept to a few packets a second (RFC 3550 6.2), and BYE on close (RFC 3550 6.6).

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::{
    FlexFec03ReceiveBuilder, FlexFec03SendBuilder, Interceptor, Packet, Registry, Slot, StreamInfo,
    TaggedPacket,
};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, register_default_interceptors,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::event::RTCTrackEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::goodbye::Goodbye;
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtcp::receiver_report::ReceiverReport;
use rtci::rtcp::reception_report::ReceptionReport;
use rtci::rtcp::sender_report::SenderReport;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
    RTCRtpTransceiverInit,
};
use rtci::sansio::Protocol;
use rtci::shared::error::Error;
use rtci::shared::time::SystemInstant;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const FLEX_FEC_PT: u8 = 49;
const FIRST_SEQ: u16 = 4000;

fn codec(mime_type: &str, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

/// What a peer's RTCP session handed on towards the wire, in the order it left the session.
enum Left {
    /// An RTP packet, by its SSRC.
    Rtp(u32),
    /// The packets of one RTCP datagram, before SRTCP.
    Rtcp(Vec<Box<dyn rtci::rtcp::Packet>>),
}

type Tap = Arc<Mutex<Vec<Left>>>;

/// Wire-ward of the RTCP session ([`Slot::Custom`] below [`Slot::RtcpSession`]): it sees every
/// RTP packet after the session counted it and every compound packet the session wrote, whole.
/// On the wire SRTCP leaves only the first eight octets of a datagram in the clear, and a
/// compound packet carries the reports of several of the endpoint's SSRCs (RFC 8108 5.3.2).
struct TapInterceptor {
    tap: Tap,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TapInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        match &msg.message.packet {
            Packet::Rtp(packet) => self
                .tap
                .lock()
                .expect("tap")
                .push(Left::Rtp(packet.header.ssrc)),
            Packet::Rtcp(packets) if !packets.is_empty() => self
                .tap
                .lock()
                .expect("tap")
                .push(Left::Rtcp(packets.clone())),
            _ => {}
        }
        self.write_queue.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for TapInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// An SR or RR a peer's session wrote.
#[derive(Debug, Clone)]
struct Report {
    /// Where its datagram is in the tap.
    at: usize,
    ssrc: u32,
    /// A sender report (RFC 3550 6.4.1); a receiver report (6.4.2) otherwise.
    sender: bool,
    blocks: Vec<ReceptionReport>,
}

/// The SR and RR packets in what a peer's session wrote, in order.
fn reports(tap: &Tap) -> Vec<Report> {
    let tap = tap.lock().expect("tap");
    let mut reports = vec![];
    for (at, left) in tap.iter().enumerate() {
        let Left::Rtcp(packets) = left else {
            continue;
        };
        for packet in packets {
            let any = packet.as_any();
            if let Some(sr) = any.downcast_ref::<SenderReport>() {
                reports.push(Report {
                    at,
                    ssrc: sr.ssrc,
                    sender: true,
                    blocks: sr.reports.clone(),
                });
            } else if let Some(rr) = any.downcast_ref::<ReceiverReport>() {
                reports.push(Report {
                    at,
                    ssrc: rr.ssrc,
                    sender: false,
                    blocks: rr.reports.clone(),
                });
            }
        }
    }
    reports
}

/// The SSRCs that said BYE in what a peer's session wrote.
fn goodbyes(tap: &Tap) -> Vec<u32> {
    let tap = tap.lock().expect("tap");
    tap.iter()
        .filter_map(|left| match left {
            Left::Rtcp(packets) => Some(packets),
            Left::Rtp(_) => None,
        })
        .flatten()
        .filter_map(|packet| packet.as_any().downcast_ref::<Goodbye>())
        .flat_map(|goodbye| goodbye.sources.clone())
        .collect()
}

/// Where the first RTP packet with `ssrc` is in the tap, from `from` on.
fn first_rtp(tap: &Tap, ssrc: u32, from: usize) -> Option<usize> {
    let tap = tap.lock().expect("tap");
    (from..tap.len()).find(|&at| matches!(tap[at], Left::Rtp(sent) if sent == ssrc))
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The receivers of the tracks that opened.
    opened: Vec<RTCRtpReceiverId>,
    /// How many tracks closed.
    closed: usize,
    /// How many tracks were muted.
    muted: usize,
    /// The RTCP packets `poll_read` yielded.
    read_rtcp: Vec<Box<dyn rtci::rtcp::Packet>>,
    /// The (SSRC, sequence number) of the RTP packets `poll_read` yielded.
    read_rtp: Vec<(u32, u16)>,
    /// The RTCP datagrams this peer put on the wire.
    rtcp_datagrams: usize,
    /// The packet type and SSRC of the first packet of each of those datagrams (the SR or RR
    /// that heads a compound packet; SRTCP leaves the first eight octets in the clear).
    rtcp_leaders: Vec<(u8, u32)>,
    /// The `ssrcchange` / `csrcchange` events (webrtc-extensions 11), in order.
    source_changes: Vec<&'static str>,
    /// The SSRCs `OnSsrcCollision` named.
    collisions: Vec<u32>,
    /// The SSRCs `OnRemoteCnameMismatch` named (RFC 5576 section 6.1).
    cname_mismatches: Vec<u32>,
    /// How many times negotiation was asked for.
    negotiation_needed: usize,
    /// `OnSsrcCollision` and `OnNegotiationNeededEvent`, in the order they came.
    log: Vec<&'static str>,
}

impl Peer {
    /// A peer with VP8 and RTX in the default interceptor set; with `fec`, FlexFEC
    /// (`flexfec-03`) too, its encoder and decoder in the chain.
    fn new(addr: &str, fec: bool) -> Result<Self> {
        let mut media_engine = Self::media_engine(fec)?;
        let mut registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        if fec {
            // A fixed amount of repair: by default it follows the receiver's reported loss
            // (draft-03 section 8), and on a lossless path the first receiver report can stop
            // it before the first block is closed, so that the FEC SSRC never sends at all.
            registry = registry
                .with(
                    Slot::FecEncoder,
                    FlexFec03SendBuilder::new()
                        .with_adaptive_rate(false)
                        .build(),
                )
                .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build());
        }
        Self::built(
            addr,
            media_engine,
            registry,
            SettingEngineBuilder::new().build(),
        )
    }

    /// A peer as [`new`](Self::new) (no FEC) with a tap below its RTCP session, its report
    /// blocks carried by every SSRC when `every_ssrc`
    /// (`DefaultInterceptorOptions::rtcp_report_from_every_ssrc`, RFC 8108 5.1), and its NTP
    /// times on a wall clock of its own: RFC 7164 5.1 replaces a sender report by a receiver
    /// report in the two seconds around the end of a month, and the process's clock would
    /// make what the tap shows depend on when the test runs.
    fn tapped(addr: &str, every_ssrc: bool) -> Result<(Self, Tap)> {
        Self::tapped_with(addr, |options| {
            options.rtcp_report_from_every_ssrc = every_ssrc
        })
    }

    /// [`tapped`](Self::tapped), the default interceptor options changed by `edit`.
    fn tapped_with(
        addr: &str,
        edit: impl FnOnce(&mut DefaultInterceptorOptions),
    ) -> Result<(Self, Tap)> {
        let mut media_engine = Self::media_engine(false)?;
        let mut options = DefaultInterceptorOptions::for_profile(media_engine.behaviour_profile());
        edit(&mut options);
        options.wall_clock = Some(SystemInstant::at(
            Instant::now(),
            Duration::from_secs(1_700_000_000),
        ));
        let (registry, _handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            &options,
        )?;
        let tap = Tap::default();
        let registry = registry.with(
            Slot::Custom(100),
            TapInterceptor {
                tap: tap.clone(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
        );
        let peer = Self::built(
            addr,
            media_engine,
            registry,
            SettingEngineBuilder::new().build(),
        )?;
        Ok((peer, tap))
    }

    /// A peer with VP8 and RTX and an empty interceptor registry; with `omit_session`, the
    /// setting that leaves the RTCP session out.
    fn bare(addr: &str, omit_session: bool) -> Result<Self> {
        Self::built(
            addr,
            Self::media_engine(false)?,
            Registry::new(),
            SettingEngineBuilder::new()
                .with_rtcp_session_omitted(omit_session)
                .build(),
        )
    }

    fn media_engine(fec: bool) -> Result<MediaEngine> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    // RFC 5104 TMMBR negotiated for the stream.
                    rtcp_feedback: vec![rtci::rtp_transceiver::rtp_sender::RTCPFeedback {
                        typ: "ccm".to_owned(),
                        parameter: "tmmbr".to_owned(),
                    }],
                    ..codec(MIME_TYPE_VP8, "")
                },
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_RTX, &format!("apt={VP8_PT}")),
                payload_type: RTX_PT,
            },
            RtpCodecKind::Video,
        )?;
        if fec {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: codec(MIME_TYPE_FLEX_FEC03, "repair-window=10000000"),
                    payload_type: FLEX_FEC_PT,
                },
                RtpCodecKind::Video,
            )?;
        }
        Ok(media_engine)
    }

    fn built(
        addr: &str,
        media_engine: MediaEngine,
        registry: Registry,
        setting_engine: SettingEngine,
    ) -> Result<Self> {
        Self::built_from(
            addr,
            RTCPeerConnectionBuilder::new()
                .with_configuration(RTCConfigurationBuilder::new().build())
                .with_media_engine(media_engine)
                .with_setting_engine(setting_engine)
                .with_interceptor_registry(registry),
        )
    }

    /// A peer as [`new`](Self::new) (no FEC), created with the RTCP CNAME `cname`
    /// (`RTCPeerConnectionBuilder::with_rtcp_cname`).
    fn with_cname(addr: &str, cname: &str) -> Result<Self> {
        let mut media_engine = Self::media_engine(false)?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        Self::built_from(
            addr,
            RTCPeerConnectionBuilder::new()
                .with_configuration(RTCConfigurationBuilder::new().build())
                .with_media_engine(media_engine)
                .with_interceptor_registry(registry)
                .with_rtcp_cname(cname),
        )
    }

    fn built_from(addr: &str, builder: RTCPeerConnectionBuilder) -> Result<Self> {
        let pc = builder.build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            opened: Vec::new(),
            closed: 0,
            muted: 0,
            read_rtcp: Vec::new(),
            read_rtp: Vec::new(),
            rtcp_datagrams: 0,
            rtcp_leaders: Vec::new(),
            source_changes: Vec::new(),
            collisions: Vec::new(),
            cname_mismatches: Vec::new(),
            negotiation_needed: 0,
            log: Vec::new(),
        })
    }

    fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }
}

/// The SSRC and sequence number of an SRTP packet on the wire, or `None` for anything else.
fn wire_rtp(datagram: &[u8]) -> Option<(u32, u16)> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[2], datagram[3]]);
    let ssrc = u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]);
    Some((ssrc, seq))
}

/// Whether a datagram is SRTCP (RFC 5761: version 2 and a packet type of 192 to 223).
fn wire_rtcp(datagram: &[u8]) -> bool {
    datagram.len() >= 8 && datagram[0] >> 6 == 2 && (192..=223).contains(&datagram[1])
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Drop the sender's RTP packet with this SSRC and sequence number, once.
    drop_once: Option<(u32, u16)>,
    /// The sender's FEC SSRC, once a test has read it from the sender's parameters.
    fec_ssrc: Option<u32>,
    /// The sender's RTP packets with `fec_ssrc` put on the wire.
    fec_on_wire: usize,
    /// Drop every copy of the sender's RTP packet with this SSRC and sequence number: the
    /// original and any retransmission on the media SSRC.
    lose_for_good: Option<(u32, u16)>,
    /// How many copies of `lose_for_good` the link dropped.
    lost_copies: usize,
    /// Drop every sender RTP packet with one of these SSRCs (an RTX stream).
    blocked_ssrcs: Vec<u32>,
    /// Drop every RTCP datagram of the sender while set.
    hold_sender_rtcp: bool,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    if wire_rtcp(&msg.message) {
                        peer.rtcp_datagrams += 1;
                        let d = &msg.message;
                        peer.rtcp_leaders
                            .push((d[1], u32::from_be_bytes([d[4], d[5], d[6], d[7]])));
                    }
                    in_flight.push((
                        i,
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (i, from, to, data) in in_flight {
                if i == 0 && self.hold_sender_rtcp && wire_rtcp(&data) {
                    continue;
                }
                if i == 0
                    && let Some((ssrc, seq)) = wire_rtp(&data)
                {
                    if Some(ssrc) == self.fec_ssrc {
                        self.fec_on_wire += 1;
                    }
                    if self.lose_for_good == Some((ssrc, seq)) {
                        self.lost_copies += 1;
                        continue;
                    }
                    if self.blocked_ssrcs.contains(&ssrc) {
                        continue;
                    }
                }
                if i == 0
                    && let Some(rtp) = wire_rtp(&data)
                    && self.drop_once == Some(rtp)
                {
                    self.drop_once = None;
                    continue;
                }
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                    continue;
                };
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: data,
                });
            }
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed: {:?}", peer.states);
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                        peer.states.push(state);
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                        peer.opened.push(init.receiver_id);
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(_)) => {
                        peer.closed += 1;
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnMute(_)) => {
                        peer.muted += 1;
                    }
                    RTCPeerConnectionEvent::OnSsrcChange(_) => peer.source_changes.push("ssrc"),
                    RTCPeerConnectionEvent::OnCsrcChange(_) => peer.source_changes.push("csrc"),
                    RTCPeerConnectionEvent::OnSsrcCollision(ssrc) => {
                        peer.collisions.push(ssrc);
                        peer.log.push("collision");
                    }
                    RTCPeerConnectionEvent::OnRemoteCnameMismatch(ssrc) => {
                        peer.cname_mismatches.push(ssrc);
                    }
                    RTCPeerConnectionEvent::OnNegotiationNeededEvent => {
                        peer.negotiation_needed += 1;
                        peer.log.push("negotiation-needed");
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtcpPacket(_, packets) => peer.read_rtcp.extend(packets),
                    RTCMessage::RtpPacket(_, packet) => peer
                        .read_rtp
                        .push((packet.header.ssrc, packet.header.sequence_number)),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Moves virtual time to `until`, firing every deadline on the way.
    fn run_until(&mut self, until: Instant) -> Result<()> {
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// The offerer sends video; the answerer receives it. Connected over host candidates.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with(false)
    }

    /// [`connected`](Self::connected), with FlexFEC negotiated when `fec`.
    fn connected_with(fec: bool) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with_options(fec, None)
    }

    /// [`connected_with`](Self::connected_with), the receiver stating `receive_bandwidth`
    /// (`RTCRtpTransceiver::set_receive_bandwidth`) in its answer.
    fn connected_with_options(
        fec: bool,
        receive_bandwidth: Option<u64>,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_peers_with(
            [
                Peer::new("10.0.0.1:5000", fec)?,
                Peer::new("10.0.0.2:5000", fec)?,
            ],
            receive_bandwidth,
        )
    }

    /// [`connected`](Self::connected), between `peers` (offerer first).
    fn connected_peers(peers: [Peer; 2]) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_peers_with(peers, None)
    }

    /// [`connected_peers`](Self::connected_peers), the receiver stating `receive_bandwidth`.
    fn connected_peers_with(
        peers: [Peer; 2],
        receive_bandwidth: Option<u64>,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_peers_edited(peers, receive_bandwidth, str::to_owned, false)
    }

    /// [`connected_peers_with`](Self::connected_peers_with), the offer `edit`ed on its way to
    /// the answerer (the offerer sets the one it made), and the sender's RTCP held from the
    /// start when `hold_sender_rtcp`.
    fn connected_peers_edited(
        peers: [Peer; 2],
        receive_bandwidth: Option<u64>,
        edit: fn(&str) -> String,
        hold_sender_rtcp: bool,
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers,
            now: Instant::now(),
            drop_once: None,
            fec_ssrc: None,
            fec_on_wire: 0,
            lose_for_good: None,
            lost_copies: 0,
            blocked_ssrcs: Vec::new(),
            hold_sender_rtcp,
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    // An encoding the application gives gets its RTX and FEC SSRCs from the
                    // engine (`normalize_sender_track`): it names none.
                    ..Default::default()
                }],
            }),
        )?;
        let sender = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");

        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(
            now,
            rtci::peer_connection::sdp::RTCSessionDescription::offer(edit(&offer.sdp))?,
        )?;
        let receiving: Vec<_> = world.peers[1].pc.get_transceivers().collect();
        for id in receiving {
            world.peers[1]
                .pc
                .rtp_transceiver(id)
                .expect("a transceiver")
                .set_receive_bandwidth(receive_bandwidth);
        }
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }

        let start = world.now;
        loop {
            world.pump()?;
            if world.peers.iter().all(|p| p.connected) {
                break;
            }
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected after {CONNECT_WITHIN:?}: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            let next = world
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(world.now);
            world.run_until(next.max(world.now + Duration::from_millis(1)))?;
        }
        Ok((world, sender))
    }

    /// The sender's (media SSRC, RTX SSRC, negotiated payload type).
    fn sender_stream(&mut self, sender: RTCRtpSenderId) -> (u32, Option<u32>, u8) {
        let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let encoding = &parameters.encodings[0];
        let pt = parameters
            .rtp_parameters
            .codecs
            .first()
            .expect("a negotiated codec")
            .payload_type;
        (
            encoding.rtp_coding_parameters.ssrc.expect("an SSRC"),
            encoding
                .rtp_coding_parameters
                .rtx
                .as_ref()
                .map(|rtx| rtx.ssrc),
            pt,
        )
    }

    /// Writes `packets` RTP packets from sequence number `first`, 20 ms apart.
    fn send_media(&mut self, sender: RTCRtpSenderId, first: u16, packets: u16) -> Result<()> {
        let (ssrc, _, pt) = self.sender_stream(sender);
        for n in 0..packets {
            let now = self.now;
            let sequence_number = first.wrapping_add(n);
            self.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtci::rtp::Packet {
                        header: rtci::rtp::header::Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number,
                            timestamp: u32::from(sequence_number) * 1800,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 200]),
                    },
                )?;
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }

    /// The answerer's receiving transceiver is set to send as well: its sender.
    fn answerer_sender(&mut self) -> Result<RTCRtpSenderId> {
        let receiver = *self.peers[1].opened.first().expect("the track opened");
        let mut handle = self.peers[1]
            .pc
            .rtp_transceiver(RTCRtpTransceiverId::from(receiver))
            .expect("transceiver");
        handle.set_direction(RTCRtpTransceiverDirection::Sendrecv)?;
        Ok(handle.sender().expect("a sender"))
    }

    /// The answerer offers what [`answerer_sender`](Self::answerer_sender) set up, and the
    /// offerer, whose `sender`'s transceiver receives too from now on, answers.
    fn renegotiate_from_answerer(&mut self, sender: RTCRtpSenderId) -> Result<()> {
        let now = self.now;
        let offer = self.peers[1].pc.create_offer(None)?;
        self.peers[1].pc.set_local_description(now, offer.clone())?;
        self.peers[0].pc.set_remote_description(now, offer)?;
        self.peers[0]
            .pc
            .rtp_transceiver(RTCRtpTransceiverId::from(sender))
            .expect("transceiver")
            .set_direction(RTCRtpTransceiverDirection::Sendrecv)?;
        let answer = self.peers[0].pc.create_answer(None)?;
        self.peers[0]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[1].pc.set_remote_description(now, answer)?;
        self.pump()
    }

    /// Writes one RTP packet from the answerer's sender `back`, and 20 ms pass.
    fn send_back(&mut self, back: RTCRtpSenderId, sequence_number: u16) -> Result<()> {
        let now = self.now;
        let mut sender = self.peers[1].pc.rtp_sender(back).expect("sender");
        let parameters = sender.get_parameters();
        let payload_type = parameters
            .rtp_parameters
            .codecs
            .first()
            .expect("a negotiated codec")
            .payload_type;
        let ssrc = parameters.encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header: rtci::rtp::header::Header {
                    version: 2,
                    payload_type,
                    sequence_number,
                    timestamp: u32::from(sequence_number) * 1800,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from(vec![0x10u8; 200]),
            },
        )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

/// RFC 7022 4.2 / RFC 8834 4.9: each connection has one CNAME of 96 random bits; the receiver
/// learns it for the sender's media SSRC from its SDES, and, once a retransmission has been
/// sent, for the RTX SSRC too (RFC 4588 5.2: the same CNAME, and section 6.1: the RTX stream
/// sends its own sender reports).
#[test]
fn the_receiver_learns_one_cname_for_the_media_and_the_rtx_ssrc() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated");
    let cname = world.peers[0].pc.rtcp_cname().to_owned();
    assert_eq!(16, cname.len());
    assert_ne!(cname, world.peers[1].pc.rtcp_cname());

    // One packet is lost on the way: the receiver asks for it, the sender answers over RTX.
    world.drop_once = Some((ssrc, FIRST_SEQ + 20));
    world.send_media(sender, FIRST_SEQ, 150)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(ssrc)
    );
    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(rtx_ssrc),
        "the RTX SSRC is described with the same CNAME"
    );
    Ok(())
}

/// RFC 8834 4.9: "if explicitly requested at creation, an RTCPeerConnection MAY use the same
/// CNAME as an existing RTCPeerConnection". A connection built with another connection's
/// CNAME (`RTCPeerConnectionBuilder::with_rtcp_cname`) describes its SSRC with it in its
/// description (RFC 5576 `a=ssrc:<ssrc> cname:`) and in its RTCP SDES, so the receiver binds
/// the stream to that synchronisation context; a CNAME an SDES item cannot carry (empty, over
/// 255 octets) is refused when the connection is built.
#[test]
fn a_connection_created_with_an_existing_connections_cname_uses_it() -> Result<()> {
    let existing = Peer::new("10.0.0.3:5000", false)?;
    let cname = existing.pc.rtcp_cname().to_owned();
    let (mut world, sender) = World::connected_peers([
        Peer::with_cname("10.0.0.1:5000", &cname)?,
        Peer::new("10.0.0.2:5000", false)?,
    ])?;
    assert_eq!(cname, world.peers[0].pc.rtcp_cname());
    let (ssrc, _, _) = world.sender_stream(sender);
    let offer = world.peers[0]
        .pc
        .local_description()
        .expect("a local description")
        .sdp;
    assert!(
        offer.contains(&format!("a=ssrc:{ssrc} cname:{cname}")),
        "{offer}"
    );

    world.send_media(sender, FIRST_SEQ, 50)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(ssrc)
    );

    for refused in [String::new(), "x".repeat(256)] {
        assert!(
            RTCPeerConnectionBuilder::new()
                .with_rtcp_cname(refused)
                .build(Instant::now())
                .is_err()
        );
    }
    Ok(())
}

/// draft-ietf-payload-flexible-fec-scheme-03 section 4.2 ("the RTCP CNAME [...] to associate
/// [the repair flow] with the source flow") and RFC 8627 section 4.2.1 (the repair stream's
/// CNAME is the protected stream's): once the FEC SSRC has sent repair packets it is an RTCP
/// participant of its own, with sender reports and the connection's CNAME in its SDES (RFC
/// 3550 6.4, 6.5), and the receiver learns that CNAME for it.
#[test]
fn the_receiver_learns_the_cname_of_the_fec_ssrc_from_its_rtcp() -> Result<()> {
    let (mut world, sender) = World::connected_with(true)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    let fec_ssrc = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .fec
            .as_ref()
            .map(|fec| fec.ssrc)
            .expect("FlexFEC is negotiated: the encoding has a repair SSRC")
    };
    assert_ne!(fec_ssrc, ssrc);
    world.fec_ssrc = Some(fec_ssrc);
    let cname = world.peers[0].pc.rtcp_cname().to_owned();

    // Half a second of media: a repair block closes every five packets (100 ms).
    world.send_media(sender, FIRST_SEQ, 25)?;
    assert!(world.fec_on_wire > 0, "the FEC SSRC sent repair packets");

    // The sender's regular compound packets are spaced by the randomised interval of RFC 3550
    // 6.3.1 and, under RTP/AVPF, at least `T_rr_interval` (one second here) times a random
    // factor in [0.5, 1.5) (RFC 4585 3.5.3): the first one after the repair SSRC joined
    // carries its SR and SDES (RFC 8108 5.3.2), so the CNAME arrives within about 1.5 s.
    // Ten seconds of virtual time is a bound several intervals wide.
    let deadline = world.now + Duration::from_secs(10);
    let mut next_seq = FIRST_SEQ + 25;
    let learned = |world: &World| {
        [ssrc, fec_ssrc]
            .iter()
            .all(|&ssrc| world.peers[1].pc.remote_rtcp_cname(ssrc).is_some())
    };
    while world.now < deadline && !learned(&world) {
        world.send_media(sender, next_seq, 5)?;
        next_seq = next_seq.wrapping_add(5);
    }
    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(fec_ssrc),
        "the FEC SSRC is described with the source flow's CNAME"
    );
    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(ssrc)
    );
    Ok(())
}

/// RFC 4585 3.1, RFC 8108 5.4.1: a PLI the receiving application writes with no packet sender
/// reaches the sending application from the receiver's own SSRC, which is not zero.
#[test]
fn a_pli_arrives_from_the_receivers_own_ssrc() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, FIRST_SEQ, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");

    let now = world.now;
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .write_rtcp(
            now,
            vec![Box::new(PictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: ssrc,
            })],
        )?;
    world.pump()?;
    // RFC 4585 section 3.5.2: the PLI leaves as an Early packet, or, when an Early packet
    // (a NACK, say) already went out since the last Regular one (`allow_early` is false until
    // then, and that Regular packet is put off to `tp + 2 * T_rr`), with the next Regular
    // packet, a randomised interval away. Either way it arrives, once.
    let is_pli =
        |packet: &Box<dyn rtci::rtcp::Packet>| packet.as_any().is::<PictureLossIndication>();
    let deadline = now + Duration::from_secs(20);
    while world.now < deadline && !world.peers[0].read_rtcp.iter().any(is_pli) {
        let next = world.now + Duration::from_millis(100);
        world.run_until(next)?;
    }
    let settle = world.now + Duration::from_millis(500);
    world.run_until(settle)?;

    let plis: Vec<&PictureLossIndication> = world.peers[0]
        .read_rtcp
        .iter()
        .filter_map(|packet| packet.as_any().downcast_ref::<PictureLossIndication>())
        .collect();
    assert_eq!(1, plis.len(), "{:?}", world.peers[0].read_rtcp);
    assert_eq!(ssrc, plis[0].media_ssrc);
    assert_ne!(0, plis[0].sender_ssrc);
    assert_ne!(ssrc, plis[0].sender_ssrc);
    Ok(())
}

/// RFC 3550 6.2: RTCP stays a small share of the session: a few compound packets a second
/// from each side, with congestion control feedback at most every 50 ms from the receiver,
/// not one per stream per interceptor.
#[test]
fn rtcp_is_a_few_packets_a_second() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    for peer in world.peers.iter_mut() {
        peer.rtcp_datagrams = 0;
    }
    // Five seconds of media.
    world.send_media(sender, FIRST_SEQ, 250)?;

    for (name, peer) in ["sender", "receiver"].iter().zip(&world.peers) {
        println!(
            "the {name} sent {} RTCP datagrams in five seconds",
            peer.rtcp_datagrams
        );
        assert!(
            (3..=150).contains(&peer.rtcp_datagrams),
            "the {name} sent {} RTCP datagrams in five seconds",
            peer.rtcp_datagrams
        );
    }
    Ok(())
}

/// RFC 8834 4.1: "RTCP ... MUST be implemented and used by all WebRTC endpoints". Two
/// connections built with an empty interceptor registry still run the RTCP session: each
/// side sends its reports, and the sender's reach the receiver as SR for the media SSRC.
#[test]
fn a_connection_with_an_empty_interceptor_registry_still_sends_rtcp() -> Result<()> {
    let (mut world, sender) = World::connected_peers([
        Peer::bare("10.0.0.1:5000", false)?,
        Peer::bare("10.0.0.2:5000", false)?,
    ])?;
    for peer in world.peers.iter_mut() {
        peer.rtcp_datagrams = 0;
    }
    world.send_media(sender, FIRST_SEQ, 250)?;
    for (name, peer) in ["sender", "receiver"].iter().zip(&world.peers) {
        assert!(
            peer.rtcp_datagrams >= 3,
            "the {name} sent {} RTCP datagrams in five seconds",
            peer.rtcp_datagrams
        );
    }
    Ok(())
}

/// The departure from RFC 8834 4.1 the application can ask for: with
/// `with_rtcp_session_omitted`, a connection whose registry has no RTCP session sends none.
#[test]
fn the_rtcp_session_left_out_by_setting_sends_no_rtcp() -> Result<()> {
    let (mut world, sender) = World::connected_peers([
        Peer::bare("10.0.0.1:5000", true)?,
        Peer::bare("10.0.0.2:5000", true)?,
    ])?;
    for peer in world.peers.iter_mut() {
        peer.rtcp_datagrams = 0;
    }
    world.send_media(sender, FIRST_SEQ, 250)?;
    assert_eq!(
        [0, 0],
        [world.peers[0].rtcp_datagrams, world.peers[1].rtcp_datagrams]
    );
    Ok(())
}

/// RFC 3550 6.6: closing a connection says BYE for its SSRCs, and the peer's track is muted
/// (W3C webrtc 9.3); only negotiation ends a remote track.
#[test]
fn closing_the_sender_mutes_the_receivers_track() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 50)?;
    assert_eq!(1, world.peers[1].opened.len());
    assert_eq!(0, world.peers[1].muted);

    world.peers[0].pc.close()?;
    world.pump()?;

    assert_eq!(1, world.peers[1].muted, "the BYE muted the remote track");
    assert_eq!(0, world.peers[1].closed, "and did not end it");
    Ok(())
}

const SHARED: u32 = 0x5151_5151;

/// Two peers whose video senders both have the SSRC [`SHARED`]; `signal` is what the
/// signalling channel does to each description. Not connected yet.
fn shared_ssrc_world(signal: fn(&str) -> String) -> Result<(World, Vec<RTCRtpSenderId>, String)> {
    let mut world = World {
        peers: [
            Peer::new("10.0.0.1:5000", false)?,
            Peer::new("10.0.0.2:5000", false)?,
        ],
        now: Instant::now(),
        drop_once: None,
        fec_on_wire: 0,
        fec_ssrc: None,
        lose_for_good: None,
        lost_copies: 0,
        blocked_ssrcs: Vec::new(),
        hold_sender_rtcp: false,
    };
    let mut senders = vec![];
    for peer in world.peers.iter_mut() {
        let transceiver = peer.pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec!["shared".to_owned()],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(SHARED),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
            }),
        )?;
        senders.push(
            peer.pc
                .rtp_transceiver(transceiver)
                .and_then(|t| t.sender())
                .expect("a sender"),
        );
    }
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::offer(signal(&offer.sdp))?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::answer(signal(&answer.sdp))?,
    )?;
    Ok((world, senders, answer.sdp))
}

/// The SSRC of the first encoding of a sender, and its RTX SSRC.
fn encoding_ssrcs(world: &mut World, peer: usize, sender: RTCRtpSenderId) -> (u32, Option<u32>) {
    let mut sender = world.peers[peer].pc.rtp_sender(sender).expect("sender");
    let coding = &sender.get_parameters().encodings[0].rtp_coding_parameters;
    (
        coding.ssrc.expect("an SSRC"),
        coding.rtx.as_ref().map(|rtx| rtx.ssrc),
    )
}

/// RFC 3550 section 8.2, RFC 5576 sections 5 and 6.2, RFC 8834 section 4.8: two peers send
/// from one SSRC that no description names (the signalling channel takes the source lines out,
/// as for a peer that signals none). Each, hearing the other's packets on its own SSRC, moves
/// its sender to a new one: what the application still writes with the old SSRC goes out
/// with the new, the RTX flow stays, the statistics follow the new SSRC, negotiation is asked
/// for, and the next offer signals the new SSRC with `previous-ssrc`.
#[test]
fn a_sender_moves_to_a_new_ssrc_after_a_collision() -> Result<()> {
    fn without_sources(sdp: &str) -> String {
        sdp.split_inclusive("\r\n")
            .filter(|line| !line.starts_with("a=ssrc:") && !line.starts_with("a=ssrc-group:"))
            .collect()
    }
    let (mut world, senders, _) = shared_ssrc_world(without_sources)?;
    for i in 0..2 {
        let candidate = world.peers[i].candidate()?;
        world.peers[i].pc.add_local_candidate(candidate.clone())?;
        world.peers[1 - i].pc.add_remote_candidate(candidate)?;
    }
    let deadline = world.now + CONNECT_WITHIN;
    while !world.peers.iter().all(|p| p.connected) {
        if world.now >= deadline {
            bail!("not connected");
        }
        let step = world.now + Duration::from_millis(50);
        world.run_until(step)?;
    }
    let (_, rtx_before) = encoding_ssrcs(&mut world, 0, senders[0]);

    // Both write with the shared SSRC, as the application keeps doing.
    let mut wire_ssrcs = vec![];
    for n in 0..20u16 {
        for (i, sender) in senders.iter().enumerate() {
            let now = world.now;
            let mut rtp_sender = world.peers[i].pc.rtp_sender(*sender).expect("sender");
            let pt = rtp_sender.get_parameters().rtp_parameters.codecs[0].payload_type;
            rtp_sender.write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: FIRST_SEQ + n,
                        timestamp: u32::from(n) * 1800,
                        ssrc: SHARED,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 200]),
                },
            )?;
        }
        while let Some(msg) = world.peers[0].pc.poll_write() {
            if let Some((ssrc, _)) = wire_rtp(&msg.message) {
                wire_ssrcs.push(ssrc);
            }
            let _ = world.peers[1].pc.handle_read(TaggedBytesMut {
                now: world.now,
                transport: TransportContext {
                    local_addr: msg.transport.peer_addr,
                    peer_addr: msg.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: msg.message,
            });
        }
        world.pump()?;
        let step = world.now + Duration::from_millis(20);
        world.run_until(step)?;
    }
    assert_eq!(world.peers[0].collisions, vec![SHARED], "reported once");
    // Negotiation is asked for the new SSRC (each peer may hear the other's sender report on
    // the shared SSRC before any media). The event queued for the first exchange is not
    // handed out: that exchange was made before the events were read, and W3C's queued task
    // checks again whether negotiation is needed when it runs ("Updating the
    // Negotiation-Needed flag").
    assert_eq!(
        world.peers[0].negotiation_needed, 1,
        "the new SSRC is to be signalled: {:?}",
        world.peers[0].log
    );

    let (moved, rtx_after) = encoding_ssrcs(&mut world, 0, senders[0]);
    assert_ne!(moved, SHARED, "the sender has a new SSRC");
    assert_eq!(rtx_after, rtx_before, "the RTX flow keeps its own");
    assert_eq!(
        wire_ssrcs.last(),
        Some(&moved),
        "what is written with the old SSRC goes out with the new: {wire_ssrcs:?}"
    );

    let stats = world.peers[0]
        .pc
        .get_stats(world.now, rtci::statistics::StatsSelector::None);
    let outbound: Vec<u32> = stats
        .outbound_rtp_streams()
        .map(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc)
        .collect();
    assert!(outbound.contains(&moved), "{outbound:?}");
    assert!(!outbound.contains(&SHARED), "{outbound:?}");

    let offer = world.peers[0].pc.create_offer(None)?;
    assert!(
        offer
            .sdp
            .contains(&format!("a=ssrc:{moved} previous-ssrc:{SHARED}\r\n")),
        "{}",
        offer.sdp
    );
    assert!(
        !offer.sdp.contains(&format!("a=ssrc:{SHARED} ")),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// RFC 5576 section 5: "collisions between two signalled sources MUST be resolved
/// immediately". The answerer, whose sender has the SSRC the offer describes, moves before it
/// answers: the answer describes the new SSRC, with `previous-ssrc`.
#[test]
fn a_description_that_names_a_local_ssrc_moves_the_sender_at_once() -> Result<()> {
    let (mut world, senders, answer) = shared_ssrc_world(str::to_owned)?;
    let (moved, _) = encoding_ssrcs(&mut world, 1, senders[1]);
    assert_ne!(moved, SHARED, "the answerer's sender moved");
    assert!(
        answer.contains(&format!("a=ssrc:{moved} previous-ssrc:{SHARED}\r\n")),
        "{answer}"
    );
    assert!(!answer.contains(&format!("a=ssrc:{SHARED} ")), "{answer}");
    let (offerer, _) = encoding_ssrcs(&mut world, 0, senders[0]);
    assert_eq!(
        offerer, SHARED,
        "the offerer, whose SSRC no description took, keeps it"
    );
    world.pump()?;
    assert_eq!(world.peers[1].collisions, vec![SHARED]);
    Ok(())
}

/// The CNAME the sender of the RFC 5576 section 6.1 tests is created with: what its RTCP SDES
/// names for each of its SSRCs.
const SENT_CNAME: &str = "sent-cname";

/// RFC 5576 section 6.1: the offerer, created with [`SENT_CNAME`], sends video; its offer
/// reaches the answerer with each `a=ssrc:<ssrc> cname:` saying `declared` instead. The
/// sender's RTCP is held from the start when `hold_sender_rtcp`.
fn declared_cname_world(
    edit: fn(&str) -> String,
    hold_sender_rtcp: bool,
) -> Result<(World, RTCRtpSenderId)> {
    World::connected_peers_edited(
        [
            Peer::with_cname("10.0.0.1:5000", SENT_CNAME)?,
            Peer::new("10.0.0.2:5000", false)?,
        ],
        None,
        edit,
        hold_sender_rtcp,
    )
}

/// The offer as an answerer receives it when the description was written for another source:
/// every `cname` source attribute names `declared-elsewhere`.
fn declared_elsewhere(sdp: &str) -> String {
    sdp.replace(
        &format!(" cname:{SENT_CNAME}\r\n"),
        " cname:declared-elsewhere\r\n",
    )
}

impl World {
    /// Runs until the answerer has heard [`SENT_CNAME`] for `ssrc` in an RTCP SDES, and 100
    /// ms more.
    fn run_until_cname_heard(&mut self, ssrc: u32) -> Result<()> {
        let deadline = self.now + Duration::from_secs(10);
        while self.peers[1].pc.remote_rtcp_cname(ssrc) != Some(SENT_CNAME) {
            if self.now >= deadline {
                bail!("no SDES CNAME for ssrc {ssrc} within 10 s");
            }
            let until = self.now + Duration::from_millis(100);
            self.run_until(until)?;
        }
        let until = self.now + Duration::from_millis(100);
        self.run_until(until)
    }
}

/// The (SSRC, RTX SSRC) of each coding of the answerer's receiving track.
fn received_codings(world: &mut World) -> Vec<(Option<u32>, Option<u32>)> {
    let pc = &mut world.peers[1].pc;
    let id = pc.get_receivers().next().expect("a receiver");
    let receiver = pc.rtp_receiver(id).expect("the receiver");
    receiver
        .track()
        .codings()
        .iter()
        .map(|coding| {
            let coding = &coding.rtp_coding_parameters;
            (coding.ssrc, coding.rtx.as_ref().map(|rtx| rtx.ssrc))
        })
        .collect()
}

/// The offerer offers again, its offer `edit`ed on the way as the first one was, and the
/// answerer answers.
fn offer_again(world: &mut World, edit: fn(&str) -> String) -> Result<()> {
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::offer(edit(&offer.sdp))?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.pump()
}

/// RFC 5576 section 6.1: "If a session participant receives an RTCP SDES packet associating
/// this SSRC with a different CNAME, it SHOULD assume there has been an SSRC collision and
/// that the description of the source that was carried in the SDP description is not
/// applicable to the actual source being received"; section 5: packets of a source the
/// description does not describe "SHOULD be handled in the same manner as packets from
/// additional sources would be handled had the endpoint not received any a=ssrc: attributes".
/// The description declares the sender's SSRCs with another CNAME than its SDES names, and
/// the SDES (the sender reports from its media SSRC before it sends, RFC 8108 6.1) comes
/// before any media. The application is told, once per SSRC (the media SSRC, then the RTX
/// SSRC once it has sent); the declared stream is taken off the receiver, and the media that
/// follows opens the same track as a stream of an SSRC no description names: without the
/// declaration's `a=ssrc-group:FID` pairing, its retransmission associated by its `apt`
/// (RFC 4588 5.3), nothing lost. No local SSRC moves and nothing asks for negotiation (not an
/// RFC 3550 8.2 collision with this endpoint). An offer that declares the SSRC with the same
/// CNAME again is not applied to the stream again.
#[test]
fn an_sdes_cname_other_than_the_declared_one_leaves_the_ssrc_undeclared() -> Result<()> {
    let (mut world, sender) = declared_cname_world(declared_elsewhere, false)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated");
    let negotiation_needed = world.peers.each_ref().map(|peer| peer.negotiation_needed);

    world.run_until_cname_heard(ssrc)?;
    assert_eq!(world.peers[1].cname_mismatches, vec![ssrc]);
    assert_eq!(
        received_codings(&mut world),
        vec![],
        "the declared stream is taken off the receiver"
    );

    world.drop_once = Some((ssrc, FIRST_SEQ + 20));
    world.send_media(sender, FIRST_SEQ, 50)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    for seq in FIRST_SEQ..FIRST_SEQ + 50 {
        assert!(
            world.peers[1].read_rtp.contains(&(ssrc, seq)),
            "packet {seq} is received (the lost one by retransmission)"
        );
    }
    assert_eq!(world.peers[1].opened.len(), 1, "one track, opened once");
    assert_eq!((world.peers[1].closed, world.peers[1].muted), (0, 0));
    assert_eq!(
        received_codings(&mut world),
        vec![(Some(ssrc), None)],
        "the track's coding is the one an SSRC no description names gets: no declared RTX SSRC"
    );
    let mut mismatches = world.peers[1].cname_mismatches.clone();
    mismatches.sort_unstable();
    let mut both = vec![ssrc, rtx_ssrc];
    both.sort_unstable();
    assert_eq!(mismatches, both, "the RTX SSRC's SDES contradicts it too");

    assert_eq!(
        world.sender_stream(sender).0,
        ssrc,
        "the sender keeps its SSRC"
    );
    assert!(world.peers.iter().all(|peer| peer.collisions.is_empty()));
    assert_eq!(
        world.peers.each_ref().map(|peer| peer.negotiation_needed),
        negotiation_needed
    );

    // The same description again: the declaration stays not applicable.
    offer_again(&mut world, declared_elsewhere)?;
    world.send_media(sender, FIRST_SEQ + 50, 20)?;
    assert!(world.peers[1].read_rtp.contains(&(ssrc, FIRST_SEQ + 69)));
    assert_eq!(world.peers[1].opened.len(), 1, "still the one track");
    assert_eq!(received_codings(&mut world), vec![(Some(ssrc), None)]);
    assert_eq!(
        world.peers[1].cname_mismatches.len(),
        2,
        "told once per SSRC"
    );
    Ok(())
}

/// RFC 5576 section 6.1, the stream already flowing: the sender's RTCP is held until its
/// media has opened the track by the declared SSRC (with the declared RTX pairing), then the
/// SDES contradicting the declaration arrives (for the media SSRC, and its RTX SSRC when the
/// sender describes that too). The application is told; the stream is not
/// unbound, re-routed or ended: it keeps its track and its coding, and the media that follows
/// is received as before.
#[test]
fn a_flowing_stream_whose_sdes_contradicts_its_declared_cname_keeps_flowing() -> Result<()> {
    let (mut world, sender) = declared_cname_world(declared_elsewhere, true)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    world.send_media(sender, FIRST_SEQ, 30)?;
    assert_eq!(world.peers[1].opened.len(), 1);
    assert_eq!(received_codings(&mut world), vec![(Some(ssrc), rtx_ssrc)]);
    assert!(world.peers[1].cname_mismatches.is_empty());

    world.hold_sender_rtcp = false;
    world.run_until_cname_heard(ssrc)?;
    // The sender's first compound packet after the media describes its RTX SSRC as well
    // (declared too, with the same contradicted CNAME): each is reported once.
    let mismatches = world.peers[1].cname_mismatches.clone();
    let declared = [Some(ssrc), rtx_ssrc];
    assert!(mismatches.contains(&ssrc), "{mismatches:?}");
    assert!(
        mismatches.len() <= 2
            && (mismatches.len() < 2 || mismatches[0] != mismatches[1])
            && mismatches
                .iter()
                .all(|reported| declared.contains(&Some(*reported))),
        "only the declared SSRCs, once each: {mismatches:?}"
    );

    world.send_media(sender, FIRST_SEQ + 30, 30)?;
    for seq in FIRST_SEQ..FIRST_SEQ + 60 {
        assert!(
            world.peers[1].read_rtp.contains(&(ssrc, seq)),
            "packet {seq} is received"
        );
    }
    assert_eq!(world.peers[1].opened.len(), 1, "the same track");
    assert_eq!((world.peers[1].closed, world.peers[1].muted), (0, 0));
    assert_eq!(received_codings(&mut world), vec![(Some(ssrc), rtx_ssrc)]);
    assert!(world.peers.iter().all(|peer| peer.collisions.is_empty()));
    assert_eq!(world.sender_stream(sender).0, ssrc);
    Ok(())
}

/// RFC 5576 section 6.1, the CNAME the description declares being the one the SDES names
/// (as the engine writes it, `a_connection_created_with_an_existing_connections_cname_uses_it`):
/// nothing changes. The declared stream and its RTX pairing stay on the receiver before and
/// after the media, a lost packet comes back over the declared RTX flow, and nothing is
/// reported.
#[test]
fn an_sdes_cname_that_matches_the_declared_one_changes_nothing() -> Result<()> {
    let (mut world, sender) = declared_cname_world(str::to_owned, false)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    assert!(rtx_ssrc.is_some(), "RTX is negotiated");

    world.run_until_cname_heard(ssrc)?;
    assert_eq!(received_codings(&mut world), vec![(Some(ssrc), rtx_ssrc)]);

    world.drop_once = Some((ssrc, FIRST_SEQ + 20));
    world.send_media(sender, FIRST_SEQ, 50)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    for seq in FIRST_SEQ..FIRST_SEQ + 50 {
        assert!(
            world.peers[1].read_rtp.contains(&(ssrc, seq)),
            "packet {seq} is received"
        );
    }
    assert_eq!(world.peers[1].opened.len(), 1);
    assert_eq!(received_codings(&mut world), vec![(Some(ssrc), rtx_ssrc)]);
    assert!(world.peers[1].cname_mismatches.is_empty());
    assert!(world.peers.iter().all(|peer| peer.collisions.is_empty()));
    Ok(())
}

/// RFC 5956 / flexfec-03: with a FEC format registered, an encoding the application gives
/// without a FEC SSRC gets one, offered in an `a=ssrc-group:FEC-FR`, and its repair flow
/// recovers a media packet the link lost; the test names no FEC SSRC. NACK and RTX are
/// negotiated too, so the link drops every copy of the lost packet (the original and any
/// retransmission on the media SSRC) and the whole RTX stream: the packet can reach the
/// receiving application only through the FEC decoder.
#[test]
fn a_minted_fec_ssrc_carries_the_repair_flow_that_recovers_a_lost_packet() -> Result<()> {
    let (mut world, sender) = World::connected_with(true)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let fec_ssrc = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .fec
            .as_ref()
            .map(|fec| fec.ssrc)
            .expect("a FEC SSRC was minted")
    };
    let local = world.peers[0]
        .pc
        .current_local_description()
        .expect("negotiated")
        .sdp;
    assert!(
        local.contains(&format!("a=ssrc-group:FEC-FR {ssrc} {fec_ssrc}")),
        "{local}"
    );
    world.fec_ssrc = Some(fec_ssrc);
    world.blocked_ssrcs.extend(rtx_ssrc);
    let lost = FIRST_SEQ + 10;
    world.lose_for_good = Some((ssrc, lost));
    world.send_media(sender, FIRST_SEQ, 40)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    assert!(world.lost_copies >= 1, "the link lost the packet");
    assert!(world.fec_on_wire > 0, "the FEC SSRC sent repair packets");
    assert!(
        world.peers[1].read_rtp.contains(&(ssrc, lost)),
        "the lost packet was recovered"
    );
    Ok(())
}

/// RFC 5104 TMMBR from the receiving application: `RTCRtpReceiver::set_remote_bitrate_limit`
/// has the receiver's congestion control send a TMMBR for the sender's media SSRC, and the
/// sender, which negotiated `ccm tmmbr`, holds its estimate under it: its candidate pair's
/// `availableOutgoingBitrate` falls to the limit; `None` lifts it.
#[test]
fn a_receiver_asks_the_sender_to_limit_its_rate_with_tmmbr() -> Result<()> {
    use rtci::statistics::StatsSelector;
    use rtci::statistics::report::RTCStatsReportEntry;
    const LIMIT: u64 = 100_000;
    let outgoing = |pc: &mut RTCPeerConnection, now: Instant| -> Option<f64> {
        pc.get_stats(now, StatsSelector::None)
            .iter()
            .find_map(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) if pair.nominated => {
                    pair.available_outgoing_bitrate
                }
                _ => None,
            })
    };
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 25)?;
    let now = world.now;
    let before = outgoing(&mut world.peers[0].pc, now).expect("an estimate");
    assert!(before > LIMIT as f64, "{before}");
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .set_remote_bitrate_limit(now, Some(LIMIT))?;
    world.pump()?;
    world.send_media(sender, FIRST_SEQ + 25, 50)?;
    let now = world.now;
    let limited = outgoing(&mut world.peers[0].pc, now).expect("an estimate");
    assert!(limited <= LIMIT as f64, "{before} -> {limited}");
    Ok(())
}

/// A small deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`]: what the
/// engine draws through `RTCCryptoProvider::random()` and, through
/// `DefaultInterceptorOptions::rtcp_random`, the times of its RTCP packets (RFC 3550 6.3.1:
/// each interval is varied at random) are the same in every run of a seed.
struct SeededProvider {
    inner: std::sync::Arc<dyn rtci::crypto::RTCCryptoProvider>,
    rng: std::sync::Mutex<Rng>,
}

impl rtci::crypto::RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn rtci::crypto::RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn rtci::crypto::RTCRandom {
        self
    }
}

impl rtci::crypto::RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> std::result::Result<(), rtci::crypto::CryptoError> {
        let mut rng = self
            .rng
            .lock()
            .map_err(|_| rtci::crypto::CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl Peer {
    /// A peer as [`new`](Self::new) (no FEC) whose random numbers, the RTCP session's
    /// included, come from `seed`.
    fn seeded(addr: &str, seed: u64) -> Result<Self> {
        use rtci::peer_connection::configuration::interceptor_registry::{
            DefaultInterceptorOptions, register_default_interceptors_with_options,
        };
        let provider: std::sync::Arc<dyn rtci::crypto::RTCCryptoProvider> =
            std::sync::Arc::new(SeededProvider {
                inner: rtci::crypto::default_provider()?,
                rng: std::sync::Mutex::new(Rng(seed)),
            });
        let mut media_engine = Self::media_engine(false)?;
        let mut options = DefaultInterceptorOptions::default();
        options.rtcp_random = Some(provider.clone());
        let (registry, _handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            &options,
        )?;
        Self::built(
            addr,
            media_engine,
            registry,
            SettingEngineBuilder::new()
                .with_crypto_provider(provider)
                .build(),
        )
    }
}

/// RFC 4588 6.3 from the receiving application: `RTCRtpReceiver::set_nack_horizon` tells the
/// receiver which packets are no longer useful. A packet lost for good (its RTX copies too)
/// is asked for again and again; from the moment the horizon passes it no NACK leaves for it
/// (`nackCount` of its inbound stream stays put), and removing the horizon starts them again.
///
/// "From the moment" includes the NACK the RTCP session holds: early feedback is rate-limited
/// (RFC 4585 3.5.2), so a request made before the horizon usually still waits for the next
/// regular packet when the horizon is given, and that packet can be most of two seconds away
/// (the interval is varied at random, RFC 3550 6.3.1). Sent then, it would ask for a packet
/// the application has said it cannot use (RFC 4585 3.5.2, step 4a: stored feedback is sent
/// if it is still useful). The seeds are four of those on which, in a seeded scan of this
/// scenario under either crypto backend, that NACK left more than a second after the horizon
/// (about one seed in a hundred).
#[test]
fn a_receiver_stops_asking_for_packets_behind_its_nack_horizon() -> Result<()> {
    use rtci::statistics::StatsSelector;
    let nacks = |pc: &mut RTCPeerConnection, now: Instant, ssrc: u32| -> u32 {
        pc.get_stats(now, StatsSelector::None)
            .inbound_rtp_streams()
            .find(|s| s.received_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
            .map_or(0, |s| s.nack_count)
    };
    for seed in [25, 311, 349, 644] {
        let (mut world, sender) = World::connected_peers([
            Peer::seeded("10.0.0.1:5000", seed)?,
            Peer::seeded("10.0.0.2:5000", seed ^ 0xb0b)?,
        ])?;
        let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
        world.blocked_ssrcs.extend(rtx_ssrc);
        let lost = FIRST_SEQ + 10;
        world.lose_for_good = Some((ssrc, lost));
        world.send_media(sender, FIRST_SEQ, 30)?;
        let until = world.now + Duration::from_secs(1);
        world.run_until(until)?;
        let asked = nacks(&mut world.peers[1].pc, world.now, ssrc);
        assert!(asked > 0, "seed {seed}: the lost packet is asked for");
        let until = world.now + Duration::from_secs(1);
        world.run_until(until)?;
        let still_asked = nacks(&mut world.peers[1].pc, world.now, ssrc);
        assert!(
            still_asked > asked,
            "seed {seed}: and asked for again: {asked} -> {still_asked}"
        );

        let receiver = *world.peers[1].opened.first().expect("the track opened");
        let now = world.now;
        world.peers[1]
            .pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .set_nack_horizon(now, ssrc, Some(lost + 1))?;
        world.pump()?;
        let at_horizon = nacks(&mut world.peers[1].pc, world.now, ssrc);
        assert_eq!(
            at_horizon, still_asked,
            "seed {seed}: giving the horizon sends nothing"
        );
        // Several regular RTCP intervals: whatever was held has had its packet.
        let until = world.now + Duration::from_secs(6);
        world.run_until(until)?;
        assert_eq!(
            nacks(&mut world.peers[1].pc, world.now, ssrc),
            at_horizon,
            "seed {seed}: no NACK for a packet behind the horizon"
        );

        let now = world.now;
        world.peers[1]
            .pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .set_nack_horizon(now, ssrc, None)?;
        world.pump()?;
        // The request may have to wait for a regular RTCP packet.
        let until = world.now + Duration::from_secs(3);
        world.run_until(until)?;
        assert!(
            nacks(&mut world.peers[1].pc, world.now, ssrc) > at_horizon,
            "seed {seed}: asked for again without the horizon"
        );
    }
    Ok(())
}

/// The receive bandwidth API end to end: `RTCRtpTransceiver::set_receive_bandwidth` writes
/// `b=TIAS` and `b=AS` in the receiver's answer (RFC 3264 section 6: what the answerer "would
/// like the offerer to send"), the sender reads it as its maximum (RFC 9429 section 5.10), and
/// after the receiving application asks for more with a TMMBR (which RFC 5104 section 4.2.1.2
/// keeps at the negotiated value) the sender's estimate stays under it.
#[test]
fn the_receive_bandwidth_is_signalled_and_bounds_what_the_sender_sends() -> Result<()> {
    use rtci::statistics::StatsSelector;
    use rtci::statistics::report::RTCStatsReportEntry;
    const CAP: u64 = 80_000;
    let outgoing = |pc: &mut RTCPeerConnection, now: Instant| -> Option<f64> {
        pc.get_stats(now, StatsSelector::None)
            .iter()
            .find_map(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) if pair.nominated => {
                    pair.available_outgoing_bitrate
                }
                _ => None,
            })
    };
    let (mut world, sender) = World::connected_with_options(false, Some(CAP))?;
    let answer = world.peers[1]
        .pc
        .local_description()
        .expect("the answer")
        .sdp;
    // AS = ceil((80000 + 16000) / 950) = 102.
    assert!(answer.contains("b=TIAS:80000\r\nb=AS:102\r\n"), "{answer}");
    let transceiver = world.peers[0]
        .pc
        .get_transceivers()
        .next()
        .expect("the sender's transceiver");
    assert_eq!(
        world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .expect("transceiver")
            .remote_bandwidth()
            .max_bitrate,
        Some(CAP)
    );

    world.send_media(sender, FIRST_SEQ, 25)?;
    let now = world.now;
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .set_remote_bitrate_limit(now, Some(4 * CAP))?;
    world.pump()?;
    world.send_media(sender, FIRST_SEQ + 25, 50)?;
    let now = world.now;
    let estimate = outgoing(&mut world.peers[0].pc, now).expect("an estimate");
    assert!(estimate <= CAP as f64, "{estimate}");
    Ok(())
}

/// W3C webrtc 5.3: stopping the receiver's track does not stop the receiver: the media
/// still arrives and the receiver still sends its reception reports (RFC 3550 6.4.2).
#[test]
fn stopping_the_receivers_track_keeps_the_receiver_reporting() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .track_mut()
        .stop();
    let received = world.peers[1].read_rtp.len();
    let reports = world.peers[1].rtcp_datagrams;

    world.send_media(sender, FIRST_SEQ + 25, 150)?;
    assert!(
        world.peers[1].read_rtp.len() >= received + 100,
        "the media still arrives"
    );
    // The receiver sends no media: its RTCP is its receiver reports (and their SDES).
    assert!(
        world.peers[1].rtcp_datagrams > reports,
        "the receiver still reports"
    );
    Ok(())
}

/// W3C webrtc 5.4 "stop sending and receiving": `stop()` on the sending transceiver says
/// BYE for each RTP stream its sender sent (RFC 3550 6.6); on the receiving one, media that
/// still arrives is no longer received.
#[test]
fn stop_says_bye_for_the_senders_streams_and_stops_receiving() -> Result<()> {
    use rtci::rtp_transceiver::RTCRtpTransceiverId;
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 25)?;
    assert_eq!(0, world.peers[1].muted);

    world.peers[0]
        .pc
        .rtp_transceiver(RTCRtpTransceiverId::from(sender))
        .expect("transceiver")
        .stop()?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    // No description was exchanged: only the BYE for the sender's stream mutes the remote
    // track (W3C 9.3), which stays live.
    assert_eq!(1, world.peers[1].muted, "the BYE arrived");
    assert_eq!(0, world.peers[1].closed);

    // The receiving side stops: what the sender writes is not received any more.
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    world.peers[1]
        .pc
        .rtp_transceiver(RTCRtpTransceiverId::from(receiver))
        .expect("transceiver")
        .stop()?;
    world.pump()?;
    let received = world.peers[1].read_rtp.len();
    world.send_media(sender, FIRST_SEQ + 25, 50)?;
    assert_eq!(
        world.peers[1].read_rtp.len(),
        received,
        "nothing is received"
    );
    Ok(())
}

/// webrtc-extensions 11: the receiver fires `ssrcchange` when the synchronization source of
/// the last frame changes (the first frame's included) and `csrcchange` when its contributing
/// sources do, `ssrcchange` first, once both lists are updated; frames that change nothing
/// fire nothing.
#[test]
fn source_changes_fire_ssrcchange_and_csrcchange() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, pt) = world.sender_stream(sender);
    let send = |world: &mut World, seq: u16, csrc: Vec<u32>| -> Result<()> {
        let now = world.now;
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: seq,
                        timestamp: u32::from(seq) * 1800,
                        ssrc,
                        marker: true,
                        csrc,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 200]),
                },
            )?;
        world.pump()?;
        let until = now + Duration::from_millis(20);
        world.run_until(until)
    };
    send(&mut world, FIRST_SEQ, vec![])?;
    assert_eq!(
        world.peers[1].source_changes,
        ["ssrc"],
        "the first frame's source"
    );
    send(&mut world, FIRST_SEQ + 1, vec![])?;
    assert_eq!(world.peers[1].source_changes, ["ssrc"], "nothing changed");
    send(&mut world, FIRST_SEQ + 2, vec![11, 12])?;
    assert_eq!(world.peers[1].source_changes, ["ssrc", "csrc"]);
    send(&mut world, FIRST_SEQ + 3, vec![11, 12])?;
    send(&mut world, FIRST_SEQ + 4, vec![12])?;
    assert_eq!(world.peers[1].source_changes, ["ssrc", "csrc", "csrc"]);
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    let contributing: Vec<u32> = world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_contributing_sources()
        .map(|source| source.source)
        .collect();
    assert!(
        contributing.contains(&12),
        "the list was updated first: {contributing:?}"
    );
    Ok(())
}

/// RFC 5104 section 7.2 (a party that lists a codec control message "must" be able to receive
/// it and act on it) and RFC 4585 section 6.3.1: with an empty interceptor registry, a PLI
/// the remote receiver sends for a negotiated `nack pli` still reaches the sending
/// application, which owns the encoder.
#[test]
fn a_key_frame_request_reaches_an_application_with_an_empty_registry() -> Result<()> {
    let media_engine = || -> Result<MediaEngine> {
        let mut media_engine = Peer::media_engine(false)?;
        media_engine.register_feedback(
            rtci::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            },
            RtpCodecKind::Video,
        );
        Ok(media_engine)
    };
    let (mut world, sender) = World::connected_peers([
        Peer::built(
            "10.0.0.1:5000",
            media_engine()?,
            Registry::new(),
            SettingEngineBuilder::new().build(),
        )?,
        Peer::built(
            "10.0.0.2:5000",
            media_engine()?,
            Registry::new(),
            SettingEngineBuilder::new().build(),
        )?,
    ])?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, FIRST_SEQ, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    let now = world.now;
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .write_rtcp(
            now,
            vec![Box::new(PictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: ssrc,
            })],
        )?;
    let is_pli =
        |packet: &Box<dyn rtci::rtcp::Packet>| packet.as_any().is::<PictureLossIndication>();
    let deadline = now + Duration::from_secs(20);
    world.pump()?;
    while world.now < deadline && !world.peers[0].read_rtcp.iter().any(is_pli) {
        let next = world.now + Duration::from_millis(100);
        world.run_until(next)?;
    }
    assert!(
        world.peers[0].read_rtcp.iter().any(is_pli),
        "the PLI was delivered"
    );
    Ok(())
}

/// RFC 8108 section 6.1: "An endpoint that has never sent an RTP stream will have an SSRC
/// that it uses for RTCP reporting. If that endpoint wants to start sending an RTP stream, it
/// is RECOMMENDED that it use its existing SSRC for that stream, since otherwise the
/// participant count in the RTP session will be unnecessarily increased". The receiving peer
/// reports from one SSRC, with receiver reports; when its transceiver starts sending, the
/// stream is sent on that SSRC, which goes on as the same participant:
///
/// - from the stream's first packet on, and for as long as it sends, every report of that SSRC
///   is a sender report (RFC 3550 6.4: "The sender report is issued if a site has sent any
///   data packets during the interval since issuing the last report or the previous one,
///   otherwise the receiver report is issued");
/// - no SSRC says BYE, and none reports but that SSRC and the stream's RTX SSRC (a participant
///   of its own once it sends, RFC 4588 6.1: here the congestion controller's padding).
///
/// The reports are read below the session, whole: with the RTX SSRC in the session a compound
/// packet carries both SSRCs' reports, led by the one whose timer expired (RFC 8108 5.3.2),
/// so the first packet of a datagram, all SRTCP leaves readable on the wire, says nothing
/// about the other SSRC's report.
#[test]
fn a_receiver_that_starts_sending_sends_on_the_ssrc_it_reported_from() -> Result<()> {
    let (answerer, tap) = Peer::tapped("10.0.0.2:5000", false)?;
    let (mut world, sender) =
        World::connected_peers([Peer::new("10.0.0.1:5000", false)?, answerer])?;
    world.send_media(sender, FIRST_SEQ, 50)?;
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;
    let before = reports(&tap);
    assert!(!before.is_empty(), "the receiver reports");
    let reporting = before[0].ssrc;
    assert!(
        before
            .iter()
            .all(|report| report.ssrc == reporting && !report.sender),
        "the receiver sends receiver reports from one SSRC: {before:?}"
    );
    let leaders = world.peers[1].rtcp_leaders.clone();
    assert!(
        !leaders.is_empty() && leaders.iter().all(|&(_, leader)| leader == reporting),
        "that SSRC heads every datagram on the wire: {leaders:?}"
    );

    // The receiving transceiver starts sending, and the receiver offers it.
    let back = world.answerer_sender()?;
    assert_eq!(
        reporting,
        encoding_ssrcs(&mut world, 1, back).0,
        "the new stream's SSRC is the reporting SSRC"
    );
    world.renegotiate_from_answerer(sender)?;
    let (ssrc, rtx) = encoding_ssrcs(&mut world, 1, back);
    assert_eq!(reporting, ssrc);

    // The stream sends, a packet every 20 ms, until its SSRC has reported twice since its
    // first packet left: regular reports are a randomised interval apart (RFC 3550 6.3.1,
    // and at least half of `T_rr_interval`, RFC 4585 3.5.3), so a fixed number of packets
    // would hold a number of reports that varies from run to run. Twenty seconds is many
    // intervals.
    let renegotiated = tap.lock().expect("tap").len();
    let since_the_first_packet = |tap: &Tap| -> Vec<Report> {
        let Some(first) = first_rtp(tap, reporting, renegotiated) else {
            return vec![];
        };
        reports(tap)
            .into_iter()
            .filter(|report| report.at > first && report.ssrc == reporting)
            .collect()
    };
    let deadline = world.now + Duration::from_secs(20);
    let mut sequence_number = 100u16;
    while world.now < deadline && since_the_first_packet(&tap).len() < 2 {
        world.send_back(back, sequence_number)?;
        sequence_number += 1;
    }
    let while_sending = since_the_first_packet(&tap);
    assert!(
        while_sending.len() >= 2,
        "the stream's SSRC reports while it sends: {while_sending:?}"
    );
    assert!(
        while_sending.iter().all(|report| report.sender),
        "a report of the SSRC that is not a sender report while the stream sends: {while_sending:?}"
    );

    // The stream stops; the session runs on.
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;

    assert!(
        world.peers[0].read_rtp.iter().any(|(s, _)| *s == reporting),
        "the media arrives on the reporting SSRC"
    );
    assert_eq!(
        Vec::<u32>::new(),
        goodbyes(&tap),
        "the SSRC goes on as the same participant: nothing says BYE"
    );
    // The stream's RTX SSRC is a participant of its own once it sends (RFC 4588 6.1); no
    // other SSRC is.
    let all = reports(&tap);
    assert!(
        all.iter()
            .all(|report| report.ssrc == reporting || Some(report.ssrc) == rtx),
        "an SSRC reports that is neither the reporting SSRC nor the stream's RTX one ({rtx:?}): {all:?}"
    );
    let leaders = &world.peers[1].rtcp_leaders;
    assert!(
        leaders
            .iter()
            .all(|&(_, leader)| leader == reporting || Some(leader) == rtx),
        "one SSRC heads every compound packet but the stream's RTX one ({rtx:?}): {leaders:?}"
    );
    Ok(())
}

/// RFC 8108 section 5.1: "each SSRC will send RTCP reports for all other SSRCs, including
/// those co-located at the same endpoint". An endpoint sends a stream and its RTX stream (two
/// SSRCs) and receives one. With `DefaultInterceptorOptions::rtcp_report_from_every_ssrc` each
/// of its two SSRCs reports, in every regular compound packet, on the remote SSRC and on the
/// other of the two; without it (the default) the reception report blocks are carried once,
/// by the stream's SSRC, the RTX SSRC's report has none, and nothing reports on a co-located
/// SSRC.
#[test]
fn every_ssrc_reports_on_the_others_with_the_setting_and_the_blocks_go_once_without() -> Result<()>
{
    for every in [true, false] {
        let (offerer, tap) = Peer::tapped("10.0.0.1:5000", every)?;
        let (mut world, sender) =
            World::connected_peers([offerer, Peer::new("10.0.0.2:5000", false)?])?;
        let (media, rtx, _) = world.sender_stream(sender);
        let rtx = rtx.expect("RTX is negotiated");
        // The answerer's track opens with the first packets, and then the answerer sends
        // too: the offerer has a remote SSRC to report on.
        const OPENING: u16 = 10;
        world.send_media(sender, FIRST_SEQ, OPENING)?;
        let back = world.answerer_sender()?;
        world.renegotiate_from_answerer(sender)?;
        let remote = encoding_ssrcs(&mut world, 1, back).0;
        // One of the offerer's packets is lost and asked for again: its RTX SSRC sends.
        world.drop_once = Some((media, FIRST_SEQ + OPENING + 5));

        // The regular compound packets: those with a report of both of the offerer's SSRCs
        // (RFC 8108 5.3.2; a packet that only carries feedback has one report and no blocks,
        // RFC 4585 3.1), from the first one that reports on the remote SSRC.
        let regular = |tap: &Tap| -> Vec<Vec<Report>> {
            let all = reports(tap);
            let mut packets: Vec<Vec<Report>> = vec![];
            for report in all {
                match packets.last_mut() {
                    Some(packet) if packet[0].at == report.at => packet.push(report),
                    _ => packets.push(vec![report]),
                }
            }
            let names = |packet: &Vec<Report>, ssrc: u32| {
                packet
                    .iter()
                    .any(|report| report.blocks.iter().any(|block| block.ssrc == ssrc))
            };
            packets
                .into_iter()
                .skip_while(|packet| !names(packet, remote))
                .filter(|packet| {
                    [media, rtx]
                        .iter()
                        .all(|ssrc| packet.iter().any(|report| report.ssrc == *ssrc))
                })
                .collect()
        };
        // Both send until the offerer has made three such packets (a randomised interval
        // apart: thirty seconds is many intervals).
        let deadline = world.now + Duration::from_secs(30);
        let mut n = 0u16;
        while world.now < deadline && regular(&tap).len() < 3 {
            world.send_media(sender, FIRST_SEQ + OPENING + n, 1)?;
            world.send_back(back, 100 + n)?;
            n += 1;
        }
        assert!(
            first_rtp(&tap, rtx, 0).is_some(),
            "every {every}: the RTX SSRC sent"
        );
        let regular = regular(&tap);
        assert!(
            regular.len() >= 3,
            "every {every}: regular reports of both SSRCs ({media}, {rtx}): {:?}",
            reports(&tap)
        );
        for packet in &regular {
            let blocks_of = |ssrc: u32| -> Vec<u32> {
                packet
                    .iter()
                    .filter(|report| report.ssrc == ssrc)
                    .flat_map(|report| report.blocks.iter().map(|block| block.ssrc))
                    .collect()
            };
            let (of_media, of_rtx) = (blocks_of(media), blocks_of(rtx));
            if every {
                assert!(
                    of_media.contains(&remote) && of_media.contains(&rtx),
                    "the stream's SSRC {media} reports on the remote SSRC {remote} and on its RTX SSRC {rtx}: {packet:?}"
                );
                assert!(
                    of_rtx.contains(&remote) && of_rtx.contains(&media),
                    "the RTX SSRC {rtx} reports on the remote SSRC {remote} and on the stream's SSRC {media}: {packet:?}"
                );
                assert!(
                    !of_media.contains(&media) && !of_rtx.contains(&rtx),
                    "an SSRC reports on itself: {packet:?}"
                );
            } else {
                assert!(
                    of_media.contains(&remote),
                    "the stream's SSRC {media} reports on the remote SSRC {remote}: {packet:?}"
                );
                assert!(
                    of_rtx.is_empty(),
                    "the RTX SSRC {rtx} carries report blocks: {packet:?}"
                );
                assert!(
                    !of_media.contains(&media) && !of_media.contains(&rtx),
                    "a co-located SSRC is reported on: {packet:?}"
                );
            }
        }
    }
    Ok(())
}

/// RFC 8834 section 10 ("implementations are REQUIRED to ignore unknown RTCP packets and RTP
/// header extensions"), RFC 8285 section 4.1.2: what the interceptors read from a received
/// stream's header extensions is what its section signals. Transport-wide congestion control
/// (both sides `CongestionFeedback::Twcc`) is negotiated and the receiver reports on the
/// sender's transport-wide sequence numbers; a later offer leaves the extension out on its way
/// to the receiver, whose answer then has none, and the sender (whose copy of the answer
/// still lists it) keeps numbering its packets. The receiver no longer reads them: it sends no
/// transport-wide feedback.
#[test]
fn transport_wide_feedback_stops_when_the_section_no_longer_signals_its_extension() -> Result<()> {
    use rtci::peer_connection::configuration::interceptor_registry::CongestionFeedback;
    use rtci::rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    use rtci::sdp::extmap::TRANSPORT_CC_URI;

    let twcc = |options: &mut DefaultInterceptorOptions| {
        options.congestion_feedback = CongestionFeedback::Twcc;
    };
    let (offerer, _) = Peer::tapped_with("10.0.0.1:5000", twcc)?;
    let (answerer, tap) = Peer::tapped_with("10.0.0.2:5000", twcc)?;
    let (mut world, sender) = World::connected_peers([offerer, answerer])?;
    let feedback_since = |tap: &Tap, from: usize| -> usize {
        let tap = tap.lock().expect("tap");
        tap.iter()
            .skip(from)
            .filter_map(|left| match left {
                Left::Rtcp(packets) => Some(packets),
                Left::Rtp(_) => None,
            })
            .flatten()
            .filter(|packet| packet.as_any().is::<TransportLayerCc>())
            .count()
    };
    world.send_media(sender, FIRST_SEQ, 50)?;
    assert!(
        feedback_since(&tap, 0) > 0,
        "the receiver sends transport-wide feedback while the extension is negotiated"
    );
    let id = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == TRANSPORT_CC_URI)
        .map(|e| e.id)
        .expect("the transport-wide sequence number is negotiated");

    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    let without: String = offer
        .sdp
        .split("\r\n")
        .filter(|line| !(line.starts_with("a=extmap:") && line.contains(TRANSPORT_CC_URI)))
        .collect::<Vec<_>>()
        .join("\r\n");
    world.peers[1].pc.set_remote_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::offer(without)?,
    )?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert!(
        !answer.sdp.contains(TRANSPORT_CC_URI),
        "the receiver's answer leaves it out"
    );
    let with: String = answer
        .sdp
        .split("\r\n")
        .flat_map(|line| {
            let mut lines = vec![line.to_owned()];
            if line.starts_with("a=mid:") {
                lines.push(format!("a=extmap:{id} {TRANSPORT_CC_URI}"));
            }
            lines
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    world.peers[0].pc.set_remote_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::answer(with)?,
    )?;
    world.pump()?;
    // Feedback on what arrived before is let go.
    let settle = world.now + Duration::from_millis(500);
    world.run_until(settle)?;
    let mark = tap.lock().expect("tap").len();

    world.send_media(sender, FIRST_SEQ + 50, 100)?;
    assert!(
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .any(|e| e.uri == TRANSPORT_CC_URI),
        "the sender still numbers its packets"
    );
    assert_eq!(
        0,
        feedback_since(&tap, mark),
        "transport-wide feedback after the section stopped signalling the extension"
    );
    Ok(())
}

/// Whether `packets` form a full compound packet (RFC 3550 6.1): an SR or RR first and an
/// SDES with a CNAME for the leading SSRC.
fn full_compound(packets: &[Box<dyn rtci::rtcp::Packet>]) -> bool {
    use rtci::rtcp::source_description::{SdesType, SourceDescription};
    let Some(first) = packets.first().map(|packet| packet.as_any()) else {
        return false;
    };
    let leader = match (
        first.downcast_ref::<SenderReport>(),
        first.downcast_ref::<ReceiverReport>(),
    ) {
        (Some(sr), _) => sr.ssrc,
        (_, Some(rr)) => rr.ssrc,
        _ => return false,
    };
    packets
        .iter()
        .filter_map(|packet| packet.as_any().downcast_ref::<SourceDescription>())
        .flat_map(|sdes| &sdes.chunks)
        .any(|chunk| {
            chunk.source == leader
                && chunk
                    .items
                    .iter()
                    .any(|item| item.sdes_type == SdesType::SdesCname && !item.text.is_empty())
        })
}

/// RFC 5506 4.1 (reduced-size RTCP "MUST NOT be used for Regular (scheduled) RTCP report
/// purposes") and 4.2.3 ("all Regular RTCP MUST be full compound RTCP"), between two
/// connections that negotiated `a=rtcp-rsize`: of what each RTCP session writes, every
/// datagram that is not full compound (an SR or RR first, the SDES CNAME with it) holds
/// feedback messages only, and every report is in a full compound packet. Reduced-size is in
/// use: the receiver's congestion feedback and its key frame requests leave that way.
#[test]
fn with_reduced_size_negotiated_only_feedback_leaves_reduced_size() -> Result<()> {
    use rtci::rtcp::header::PacketType;

    let (offerer, offerer_tap) = Peer::tapped("10.0.0.1:5000", false)?;
    let (answerer, answerer_tap) = Peer::tapped("10.0.0.2:5000", false)?;
    let (mut world, sender) = World::connected_peers([offerer, answerer])?;
    let (ssrc, _, _) = world.sender_stream(sender);
    // The track opens with its first packet.
    world.send_media(sender, FIRST_SEQ - 25, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");
    assert!(
        world.peers[0]
            .pc
            .rtp_transceiver(RTCRtpTransceiverId::from(sender))
            .expect("transceiver")
            .rtcp_reduced_size(),
        "the offerer negotiated reduced-size RTCP"
    );
    assert!(
        world.peers[1]
            .pc
            .rtp_transceiver(RTCRtpTransceiverId::from(receiver))
            .expect("transceiver")
            .rtcp_reduced_size(),
        "the answerer negotiated reduced-size RTCP"
    );

    // Ten seconds of media; the receiving application asks for a key frame twice a second.
    for round in 0..20u16 {
        world.send_media(sender, FIRST_SEQ + round * 25, 25)?;
        let now = world.now;
        world.peers[1]
            .pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .write_rtcp(
                now,
                vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: ssrc,
                })],
            )?;
        world.pump()?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    for (name, tap) in [("offerer", &offerer_tap), ("answerer", &answerer_tap)] {
        let tap = tap.lock().expect("tap");
        let datagrams: Vec<&Vec<Box<dyn rtci::rtcp::Packet>>> = tap
            .iter()
            .filter_map(|left| match left {
                Left::Rtcp(packets) => Some(packets),
                Left::Rtp(_) => None,
            })
            .collect();
        let mut reports = 0;
        for packets in &datagrams {
            if packets.iter().any(|packet| {
                matches!(
                    packet.header().packet_type,
                    PacketType::SenderReport | PacketType::ReceiverReport
                )
            }) {
                reports += 1;
            }
            if full_compound(packets) {
                continue;
            }
            assert!(
                packets.iter().all(|packet| matches!(
                    packet.header().packet_type,
                    PacketType::TransportSpecificFeedback | PacketType::PayloadSpecificFeedback
                )),
                "the {name} sent a datagram that is neither full compound nor feedback only: \
                 {packets:?}"
            );
        }
        assert!(
            reports >= 5,
            "the {name} sent {reports} report packets in twelve seconds"
        );
        if name == "answerer" {
            let reduced = datagrams
                .iter()
                .filter(|packets| !full_compound(packets))
                .count();
            assert!(
                reduced > 0,
                "the receiver sent no reduced-size feedback: the test would not reach the rule"
            );
        }
    }
    Ok(())
}

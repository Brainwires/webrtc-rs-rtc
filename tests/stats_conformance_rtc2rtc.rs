//! W3C webrtc-stats members, checked against what two peers put on the wire.
//!
//! Two `rtci` peers talk over an in-memory network in virtual time. The network keeps a record
//! of every datagram (who sent it, when, what it was), so a counter in a report is compared
//! with the traffic itself, not only looked for. An SRTP packet's header travels in the clear:
//! the record has its SSRC, sequence number and header length; the payload sizes are the ones
//! the test wrote.
//!
//! No clock is read and no socket is opened.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::interceptor::{PacerBuilder, Registry, Slot};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_congestion_control_feedback, configure_nack, configure_rtcp_reports,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
    RTCRtpTransceiverInit,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext};
use rtci::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use rtci::statistics::stats::RTCQualityLimitationReason;
use rtci::statistics::{
    AudioPlayoutStatsUpdate, AudioReceiverStatsUpdate, AudioSourceStatsUpdate, DecoderStatsUpdate,
    EncoderStatsUpdate, PsnrSum, QualityLimitationDurations, StatsSelector, VideoSourceStatsUpdate,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const OPUS_PT: u8 = 111;
/// The payload every media packet of these tests carries.
const PAYLOAD: usize = 200;
/// The two bytes an RTX payload starts with: the original sequence number (RFC 4588 4).
const OSN: usize = 2;

/// How the two peers are configured.
#[derive(Clone, Copy)]
struct Setup {
    /// The offerer sends audio (Opus) instead of video (VP8).
    audio: bool,
    /// An RTX codec is negotiated for the video.
    rtx: bool,
    /// The NACK generator and responder are installed.
    nack: bool,
    /// The offerer opens a data channel before the offer.
    data_channel: bool,
    /// The offerer's candidate is signalled to the answerer. Without it the answerer learns
    /// the offerer's address from its connectivity checks: a peer-reflexive remote candidate.
    signal_offerer_candidate: bool,
    /// A pacer releasing at this many bits per second sits in the offerer's chain.
    pacer: Option<f64>,
    /// RFC 8888 congestion control feedback (`ack ccfb`) is negotiated.
    ccfb: bool,
    /// How long the network takes to deliver a datagram.
    delay: Duration,
}

const VIDEO: Setup = Setup {
    audio: false,
    rtx: true,
    nack: true,
    data_channel: false,
    signal_offerer_candidate: true,
    pacer: None,
    ccfb: false,
    delay: Duration::ZERO,
};

/// What a datagram on the wire is, by its first byte (RFC 7983) and, for the 128..=191 range,
/// its second (RFC 5761 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
    Other,
}

/// An SRTP packet's header, which travels in the clear.
#[derive(Debug, Clone, Copy)]
struct WireRtp {
    ssrc: u32,
    sequence_number: u16,
    /// The fixed header, the CSRC list and the header extension.
    header_len: usize,
}

/// One datagram a peer handed to the network.
#[derive(Debug, Clone, Copy)]
struct Datagram {
    /// The index of the peer that sent it.
    from: usize,
    at: Instant,
    len: usize,
    class: Class,
    rtp: Option<WireRtp>,
    /// For RTCP: the packet type and the sender SSRC of the first packet of the compound.
    rtcp: Option<(u8, u32)>,
    /// For STUN: the message type (0x0001 a Binding request, 0x0101 its success response).
    stun: Option<u16>,
    /// The network dropped it.
    dropped: bool,
    /// When the network handed it to the receiving peer (`handle_read`), if it did.
    delivered: Option<Instant>,
}

/// The STUN message type of a datagram that is STUN.
fn stun_type(datagram: &[u8]) -> Option<u16> {
    (datagram.len() >= 20 && datagram[0] <= 3)
        .then(|| u16::from_be_bytes([datagram[0], datagram[1]]))
}

fn classify(datagram: &[u8]) -> (Class, Option<WireRtp>, Option<(u8, u32)>) {
    let Some(&first) = datagram.first() else {
        return (Class::Other, None, None);
    };
    match first {
        0..=3 => (Class::Stun, None, None),
        20..=63 => (Class::Dtls, None, None),
        128..=191 if datagram.len() >= 12 => {
            if (192..=223).contains(&datagram[1]) {
                let ssrc = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
                (Class::Rtcp, None, Some((datagram[1], ssrc)))
            } else {
                let csrcs = usize::from(first & 0x0F);
                let mut header_len = 12 + 4 * csrcs;
                if first & 0x10 != 0 && datagram.len() >= header_len + 4 {
                    let words =
                        u16::from_be_bytes([datagram[header_len + 2], datagram[header_len + 3]]);
                    header_len += 4 + 4 * usize::from(words);
                }
                let rtp = WireRtp {
                    ssrc: u32::from_be_bytes([
                        datagram[8],
                        datagram[9],
                        datagram[10],
                        datagram[11],
                    ]),
                    sequence_number: u16::from_be_bytes([datagram[2], datagram[3]]),
                    header_len,
                };
                (Class::Rtp, Some(rtp), None)
            }
        }
        _ => (Class::Other, None, None),
    }
}

fn codec(mime_type: &str, clock_rate: u32, channels: u16, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        // The PLI and FIR the feedback-count test writes are negotiated (RFC 4585 section
        // 4.2, RFC 5104 section 7.2).
        rtcp_feedback: vec![
            rtci::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            },
            rtci::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "fir".to_owned(),
            },
        ],
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    /// The test closed the peer connection: it is no longer driven.
    closed: bool,
    states: Vec<RTCPeerConnectionState>,
    channel_events: Vec<RTCDataChannelEvent>,
    /// The (receiver, track id) of every track that opened.
    tracks: Vec<(RTCRtpReceiverId, String)>,
}

impl Peer {
    fn new(addr: &str, setup: Setup, offerer: bool) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        if setup.audio {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: codec(MIME_TYPE_OPUS, 48000, 2, "minptime=10;useinbandfec=1"),
                    payload_type: OPUS_PT,
                },
                RtpCodecKind::Audio,
            )?;
        } else {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: codec(MIME_TYPE_VP8, 90000, 0, ""),
                    payload_type: VP8_PT,
                },
                RtpCodecKind::Video,
            )?;
            if setup.rtx {
                media_engine.register_codec(
                    RTCRtpCodecParameters {
                        rtp_codec: codec(MIME_TYPE_RTX, 90000, 0, &format!("apt={VP8_PT}")),
                        payload_type: RTX_PT,
                    },
                    RtpCodecKind::Video,
                )?;
            }
        }
        let mut registry = configure_rtcp_reports(Registry::new());
        if setup.nack {
            registry = configure_nack(registry, &mut media_engine);
        }
        if setup.ccfb {
            registry = configure_congestion_control_feedback(registry, &mut media_engine);
        }
        if offerer && let Some(bits_per_second) = setup.pacer {
            registry = registry.with(
                Slot::Pacer,
                PacerBuilder::new()
                    .with_target_bitrate(bits_per_second)
                    .build(),
            );
        }
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(SettingEngineBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            closed: false,
            states: Vec::new(),
            channel_events: Vec::new(),
            tracks: Vec::new(),
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

    /// The report at `now`, as the JSON objects an application would read.
    fn stats(&mut self, now: Instant) -> Vec<Value> {
        objects(&self.pc.get_stats(now, StatsSelector::None))
    }
}

fn objects(report: &RTCStatsReport) -> Vec<Value> {
    report
        .iter()
        .map(|entry| {
            match entry {
                RTCStatsReportEntry::PeerConnection(s) => serde_json::to_value(s),
                RTCStatsReportEntry::Transport(s) => serde_json::to_value(s),
                RTCStatsReportEntry::IceCandidatePair(s) => serde_json::to_value(s),
                RTCStatsReportEntry::LocalCandidate(s) => serde_json::to_value(s),
                RTCStatsReportEntry::RemoteCandidate(s) => serde_json::to_value(s),
                RTCStatsReportEntry::Certificate(s) => serde_json::to_value(s),
                RTCStatsReportEntry::Codec(s) => serde_json::to_value(s),
                RTCStatsReportEntry::DataChannel(s) => serde_json::to_value(s),
                RTCStatsReportEntry::InboundRtp(s) => serde_json::to_value(s),
                RTCStatsReportEntry::OutboundRtp(s) => serde_json::to_value(s),
                RTCStatsReportEntry::RemoteInboundRtp(s) => serde_json::to_value(s),
                RTCStatsReportEntry::RemoteOutboundRtp(s) => serde_json::to_value(s),
                RTCStatsReportEntry::AudioSource(s) => serde_json::to_value(s),
                RTCStatsReportEntry::VideoSource(s) => serde_json::to_value(s),
                RTCStatsReportEntry::AudioPlayout(s) => serde_json::to_value(s),
                _ => unreachable!("a stats type this test does not know"),
            }
            .expect("a stats object serializes")
        })
        .collect()
}

/// The objects of type `typ`.
fn of_type<'a>(objects: &'a [Value], typ: &str) -> Vec<&'a Value> {
    objects.iter().filter(|o| o["type"] == typ).collect()
}

/// The one object of type `typ`.
fn one<'a>(objects: &'a [Value], typ: &str) -> &'a Value {
    let found = of_type(objects, typ);
    assert_eq!(found.len(), 1, "one {typ} object: {found:#?}");
    found[0]
}

/// The object of type `typ` for the stream `ssrc`.
fn stream<'a>(objects: &'a [Value], typ: &str, ssrc: u32) -> &'a Value {
    objects
        .iter()
        .find(|o| o["type"] == typ && o["ssrc"] == ssrc)
        .unwrap_or_else(|| panic!("no {typ} object for ssrc {ssrc}: {objects:#?}"))
}

fn u(object: &Value, member: &str) -> u64 {
    object[member]
        .as_u64()
        .unwrap_or_else(|| panic!("{member} is not an unsigned number in {object}"))
}

fn f(object: &Value, member: &str) -> f64 {
    object[member]
        .as_f64()
        .unwrap_or_else(|| panic!("{member} is not a number in {object}"))
}

fn has(object: &Value, member: &str) -> bool {
    object.as_object().expect("an object").contains_key(member)
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Every datagram a peer handed to the network, in the order it did.
    wire: Vec<Datagram>,
    /// RTP packets (SSRC, sequence number) the network drops, each once.
    drop_rtp: Vec<(u32, u16)>,
    /// The network drops everything.
    blackhole: bool,
    /// How long the network takes to deliver a datagram.
    delay: Duration,
    /// The datagrams on their way: when each arrives, at which peer, and the datagram.
    /// (arrival, receiving peer, transport, datagram, index in `wire`).
    in_transit: Vec<(Instant, usize, TransportContext, BytesMut, usize)>,
    /// A failed connection is an error (off for a test that makes one fail).
    fail_on_failed: bool,
    /// The offerer's transceiver.
    transceiver: RTCRtpTransceiverId,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut progressed = false;
            for from in 0..self.peers.len() {
                while let Some(msg) = self.peers[from].pc.poll_write() {
                    progressed = true;
                    let (transport, data) = (msg.transport, msg.message);
                    let (class, rtp, rtcp) = classify(&data);
                    let mut dropped = self.blackhole;
                    if let Some(rtp) = rtp
                        && let Some(at) = self
                            .drop_rtp
                            .iter()
                            .position(|d| *d == (rtp.ssrc, rtp.sequence_number))
                    {
                        self.drop_rtp.remove(at);
                        dropped = true;
                    }
                    let to = self
                        .peers
                        .iter()
                        .position(|p| p.addr == transport.peer_addr);
                    self.wire.push(Datagram {
                        from,
                        at: self.now,
                        len: data.len(),
                        class,
                        rtp,
                        rtcp,
                        stun: stun_type(&data),
                        dropped: dropped || to.is_none(),
                        delivered: None,
                    });
                    let index = self.wire.len() - 1;
                    if let Some(to) = to
                        && !dropped
                    {
                        self.in_transit
                            .push((self.now + self.delay, to, transport, data, index));
                    }
                }
            }
            // Delivered in the order they were sent.
            let mut waiting = Vec::new();
            for (arrives, to, transport, data, index) in std::mem::take(&mut self.in_transit) {
                if arrives > self.now {
                    waiting.push((arrives, to, transport, data, index));
                    continue;
                }
                progressed = true;
                self.wire[index].delivered = Some(self.now);
                let _ = self.peers[to].pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: transport.peer_addr,
                        peer_addr: transport.local_addr,
                        ecn: None,
                        transport_protocol: transport.transport_protocol,
                    },
                    message: data,
                });
            }
            self.in_transit = waiting;
            if !progressed {
                break;
            }
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed && self.fail_on_failed {
                            bail!("a peer's connection failed: {:?}", peer.states);
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                        peer.states.push(state);
                    }
                    RTCPeerConnectionEvent::OnDataChannel(event) => {
                        peer.channel_events.push(event);
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                        peer.tracks.push((init.receiver_id, init.track_id));
                    }
                    _ => {}
                }
            }
            while peer.pc.poll_read().is_some() {}
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
            for (arrives, ..) in &self.in_transit {
                next = next.min(*arrives);
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut().filter(|p| !p.closed) {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    fn run_for(&mut self, duration: Duration) -> Result<()> {
        self.run_until(self.now + duration)
    }

    /// Two peers set up with `setup`, connected over host candidates. The offerer (peer 0)
    /// sends one media stream; the answerer (peer 1) receives it.
    fn connected(setup: Setup) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with(setup, |_| Ok(()))
    }

    /// As [`World::connected`], with `before` run once the host candidates are exchanged and
    /// before the first check: what a peer gathers after a pair is nominated is not taken in
    /// that ICE session (RFC 8838 section 13).
    fn connected_with(
        setup: Setup,
        before: impl FnOnce(&mut World) -> Result<()>,
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", setup, true)?,
                Peer::new("10.0.0.2:5000", setup, false)?,
            ],
            now: Instant::now(),
            wire: Vec::new(),
            drop_rtp: Vec::new(),
            blackhole: false,
            delay: setup.delay,
            in_transit: Vec::new(),
            fail_on_failed: true,
            transceiver: 0,
        };
        let kind = if setup.audio {
            RtpCodecKind::Audio
        } else {
            RtpCodecKind::Video
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            kind,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        world.transceiver = transceiver;
        let sender = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");
        // A transceiver made from a kind has a sender without a track (W3C addTransceiver);
        // the stream objects name the track and its media source, so give it one. The track
        // has no codings of its own: the sender keeps the encoding (and SSRC) it has.
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .replace_track(Some(rtci::media_stream::MediaStreamTrack::new(
                "stats-stream".to_owned(),
                "stats-track".to_owned(),
                "stats-track".to_owned(),
                kind,
                vec![],
            )))?;
        if setup.data_channel {
            world.peers[0].pc.create_data_channel("first", None)?;
        }

        world.negotiate()?;
        world.trickle(setup.signal_offerer_candidate)?;
        before(&mut world)?;

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
                .chain(world.in_transit.iter().map(|(arrives, ..)| *arrives))
                .min()
                .unwrap_or(world.now);
            world.run_until(next.max(world.now + Duration::from_millis(1)))?;
        }
        Ok((world, sender))
    }

    /// One offer / answer exchange, the offerer offering.
    fn negotiate(&mut self) -> Result<()> {
        let now = self.now;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        Ok(())
    }

    /// Each peer gathers its host candidate and signals it; the offerer's only with
    /// `signal_offerer_candidate`.
    fn trickle(&mut self, signal_offerer_candidate: bool) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            if i == 1 || signal_offerer_candidate {
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    /// The sender's (media SSRC, RTX SSRC, payload type).
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

    /// Writes `count` media packets of `PAYLOAD` bytes (and `padding` padding bytes), 20 ms
    /// apart, with sequence numbers from `first_sequence_number`.
    fn send_media(
        &mut self,
        sender: RTCRtpSenderId,
        first_sequence_number: u16,
        count: u16,
        padding: u8,
    ) -> Result<()> {
        let (ssrc, _, pt) = self.sender_stream(sender);
        for n in 0..count {
            let now = self.now;
            let sequence_number = first_sequence_number.wrapping_add(n);
            self.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtci::rtp::Packet {
                        header: rtci::rtp::header::Header {
                            version: 2,
                            padding: padding > 0,
                            padding_size: padding,
                            payload_type: pt,
                            sequence_number,
                            timestamp: u32::from(sequence_number) * 960,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; PAYLOAD]),
                    },
                )?;
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }

    /// The RTP datagrams peer 0 sent on `ssrc`.
    fn rtp_sent(&self, ssrc: u32) -> Vec<Datagram> {
        self.wire
            .iter()
            .filter(|d| d.from == 0 && d.rtp.is_some_and(|rtp| rtp.ssrc == ssrc))
            .copied()
            .collect()
    }
}

/// webrtc-stats 8.10: a remote-outbound object's `remoteTimestamp` is the sender report's NTP
/// time, on the remote clock; webrtc 8.4: its `timestamp` is when that report arrived. Both
/// used to be the time of the `getStats` call.
#[test]
fn remote_outbound_times_are_the_sender_reports_ntp_time_and_its_arrival() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);

    // The latest sender report peer 0 sent for the stream: its place in the wire record.
    let latest_sr = |world: &World| {
        world
            .wire
            .iter()
            .rposition(|d| d.from == 0 && d.rtcp == Some((200, ssrc)))
            .expect("a sender report was sent")
    };

    world.send_media(sender, 1000, 150, 0)?;
    let first_sr = latest_sr(&world);
    let first_now = world.now;
    let first = world.peers[1].stats(first_now);

    world.send_media(sender, 1150, 200, 0)?;
    world.run_for(Duration::from_millis(300))?;
    let second_sr = latest_sr(&world);
    let second_now = world.now;
    let second = world.peers[1].stats(second_now);

    assert!(second_sr > first_sr, "more sender reports were sent");
    let between_reports = millis(world.wire[second_sr].at - world.wire[first_sr].at);
    assert!(
        between_reports >= 900.0,
        "the two reports are at least an RTCP interval apart: {between_reports} ms"
    );

    let (first_remote, second_remote) = (
        stream(&first, "remote-outbound-rtp", ssrc),
        stream(&second, "remote-outbound-rtp", ssrc),
    );
    // The remote clock moved by as much as the sender's did between its two reports.
    let remote_clock = f(second_remote, "remoteTimestamp") - f(first_remote, "remoteTimestamp");
    assert!(
        (remote_clock - between_reports).abs() < 1.0,
        "remoteTimestamp moved {remote_clock} ms between sender reports sent \
         {between_reports} ms apart"
    );
    // And the object is stamped with the report's arrival, not with the getStats call.
    let arrival = f(second_remote, "timestamp") - f(first_remote, "timestamp");
    assert!(
        (arrival - between_reports).abs() < 1.0,
        "timestamp moved {arrival} ms between sender reports that arrived \
         {between_reports} ms apart"
    );
    let inbound = stream(&second, "inbound-rtp", ssrc);
    let since_report = f(inbound, "timestamp") - f(second_remote, "timestamp");
    let expected = millis(second_now - world.wire[second_sr].at);
    assert!(
        (since_report - expected).abs() < 1.0,
        "the report arrived {expected} ms before getStats, the timestamps say {since_report}"
    );

    // What the report says the remote sent is what it had sent when it wrote the report.
    let sender_reports = world.wire[..=second_sr]
        .iter()
        .filter(|d| d.from == 0 && d.rtcp == Some((200, ssrc)))
        .count() as u64;
    assert_eq!(u(second_remote, "reportsSent"), sender_reports);
    let packets_before = world.wire[..second_sr]
        .iter()
        .filter(|d| d.from == 0 && d.rtp.is_some_and(|rtp| rtp.ssrc == ssrc))
        .count() as u64;
    assert_eq!(u(second_remote, "packetsSent"), packets_before);
    assert_eq!(
        u(second_remote, "bytesSent"),
        packets_before * PAYLOAD as u64
    );
    Ok(())
}

/// webrtc-stats 8.8 `active`: whether the stream is configured to be sent. It used to be
/// `true` whatever `set_parameters` said.
#[test]
fn active_follows_the_encoding() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 10, 0)?;
    let now = world.now;
    let before = world.peers[0].stats(now);
    let outbound = stream(&before, "outbound-rtp", ssrc);
    assert_eq!(outbound["active"], true);
    assert_eq!(u(outbound, "packetsSent"), 10);

    let set_active = |world: &mut World, active: bool| -> Result<()> {
        let mut rtp_sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let mut parameters = rtp_sender.get_parameters().clone();
        parameters.encodings[0].active = active;
        rtp_sender.set_parameters(parameters, None)?;
        Ok(())
    };

    set_active(&mut world, false)?;
    world.send_media(sender, 11, 10, 0)?;
    let now = world.now;
    let paused = world.peers[0].stats(now);
    let outbound = stream(&paused, "outbound-rtp", ssrc);
    assert_eq!(outbound["active"], false, "the encoding was made inactive");
    assert_eq!(
        u(outbound, "packetsSent"),
        10,
        "an inactive encoding sends nothing, and the stream object stays"
    );

    set_active(&mut world, true)?;
    world.send_media(sender, 21, 10, 0)?;
    let now = world.now;
    let resumed = world.peers[0].stats(now);
    let outbound = stream(&resumed, "outbound-rtp", ssrc);
    assert_eq!(outbound["active"], true);
    assert_eq!(u(outbound, "packetsSent"), 20);
    Ok(())
}

/// webrtc-stats 4.2: a member that does not apply to an object does not exist, and a member
/// nothing measures is left out. An audio stream has no `firCount` / `pliCount`, a stream
/// without RTX no `retransmitted*Received`, and nothing reported a socket error, so the pair
/// has no `packetsDiscardedOnSend` / `bytesDiscardedOnSend`. All were written as 0.
#[test]
fn audio_without_rtx_has_no_video_or_rtx_members_and_no_send_discards() -> Result<()> {
    let setup = Setup {
        audio: true,
        rtx: false,
        nack: false,
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    assert_eq!(rtx_ssrc, None);
    world.send_media(sender, 1, 100, 0)?;
    let now = world.now;

    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(outbound["kind"], "audio");
    assert_eq!(u(outbound, "packetsSent"), 100);
    for member in ["firCount", "pliCount", "rtxSsrc", "encodingIndex", "rid"] {
        assert!(!has(outbound, member), "audio outbound-rtp has {member}");
    }
    assert_eq!(u(outbound, "nackCount"), 0, "nackCount is for audio too");

    let answerer = world.peers[1].stats(now);
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    assert_eq!(inbound["kind"], "audio");
    assert_eq!(u(inbound, "packetsReceived"), 100);
    for member in [
        "firCount",
        "pliCount",
        "retransmittedPacketsReceived",
        "retransmittedBytesReceived",
        "rtxSsrc",
        "fecSsrc",
    ] {
        assert!(!has(inbound, member), "audio inbound-rtp has {member}");
    }

    for (side, report) in [("offerer", &offerer), ("answerer", &answerer)] {
        let pairs = of_type(report, "candidate-pair");
        assert!(!pairs.is_empty(), "{side} has a candidate pair");
        for pair in pairs {
            for member in ["packetsDiscardedOnSend", "bytesDiscardedOnSend"] {
                assert!(
                    !has(pair, member),
                    "{side}: {member} with no socket error reported"
                );
            }
        }
    }
    Ok(())
}

/// webrtc-stats 8.15 `dataChannelsClosed`: channels that left the `open` state. A channel
/// that goes while still `connecting` never was open; it used to be counted, so opened minus
/// closed (the number of open channels) could go below zero.
#[test]
fn a_channel_that_never_opened_is_not_counted_as_closed() -> Result<()> {
    let setup = Setup {
        data_channel: true,
        ..VIDEO
    };
    let (mut world, _) = World::connected(setup)?;
    let count = |peer: &Peer, wanted: fn(&RTCDataChannelEvent) -> bool| {
        peer.channel_events.iter().filter(|e| wanted(e)).count()
    };
    let is_open = |e: &RTCDataChannelEvent| matches!(e, RTCDataChannelEvent::OnOpen(_));
    let is_close = |e: &RTCDataChannelEvent| matches!(e, RTCDataChannelEvent::OnClose(_));
    let deadline = world.now + Duration::from_secs(5);
    while count(&world.peers[0], is_open) == 0 && world.now < deadline {
        world.run_for(Duration::from_millis(20))?;
    }
    assert_eq!(
        count(&world.peers[0], is_open),
        1,
        "the first channel opened"
    );

    // The network goes quiet: the second channel's DCEP OPEN reaches nobody, and the channel
    // stays `connecting`.
    world.blackhole = true;
    world.peers[0].pc.create_data_channel("second", None)?;
    world.run_for(Duration::from_millis(500))?;
    assert_eq!(
        count(&world.peers[0], is_open),
        1,
        "the second never opened"
    );
    let now = world.now;
    let report = world.peers[0].stats(now);
    assert_eq!(of_type(&report, "data-channel").len(), 2);
    let connection = one(&report, "peer-connection");
    assert_eq!(u(connection, "dataChannelsOpened"), 1);
    assert_eq!(u(connection, "dataChannelsClosed"), 0);

    // The remote closes its connection: both channels are closed with it.
    world.peers[1].pc.close()?;
    world.peers[1].closed = true;
    world.blackhole = false;
    world.run_for(Duration::from_secs(1))?;
    assert_eq!(
        count(&world.peers[0], is_close),
        2,
        "both channels closed: {:?}",
        world.peers[0].channel_events
    );

    let now = world.now;
    let report = world.peers[0].stats(now);
    let connection = one(&report, "peer-connection");
    assert_eq!(u(connection, "dataChannelsOpened"), 1);
    assert_eq!(
        u(connection, "dataChannelsClosed"),
        1,
        "one channel left the open state; the other never was in it"
    );
    Ok(())
}

/// webrtc-stats 8.19 `address`: a remote candidate's address is null unless the application
/// supplied it. A peer-reflexive remote candidate, learned from a connectivity check, used to
/// be reported with its address (and with a username fragment nobody signalled for it).
#[test]
fn a_peer_reflexive_remote_candidates_address_is_not_exposed() -> Result<()> {
    let setup = Setup {
        signal_offerer_candidate: false,
        ..VIDEO
    };
    let (mut world, _) = World::connected(setup)?;
    let now = world.now;

    // The answerer was never told the offerer's candidate.
    let answerer = world.peers[1].stats(now);
    let remote = of_type(&answerer, "remote-candidate");
    assert_eq!(remote.len(), 1, "{remote:#?}");
    let learned = remote[0];
    assert_eq!(learned["candidateType"], "prflx");
    assert!(
        learned["address"].is_null(),
        "an address the application never supplied: {learned}"
    );
    assert!(!has(learned, "usernameFragment"), "{learned}");
    assert_eq!(u(learned, "port"), 5000);
    // The pair in use names it, so it is the candidate the connection runs on.
    let transport = one(&answerer, "transport");
    let selected = answerer
        .iter()
        .find(|o| o["id"] == transport["selectedCandidatePairId"])
        .expect("the selected pair");
    assert_eq!(selected["remoteCandidateId"], learned["id"]);

    // The offerer was told the answerer's candidate: that address is the application's.
    let offerer = world.peers[0].stats(now);
    let signalled = of_type(&offerer, "remote-candidate");
    assert_eq!(signalled.len(), 1, "{signalled:#?}");
    assert_eq!(signalled[0]["candidateType"], "host");
    assert_eq!(signalled[0]["address"], "10.0.0.2");
    assert!(has(signalled[0], "usernameFragment"));
    Ok(())
}

/// The header length the wire shows for `datagrams`, summed.
fn header_bytes(datagrams: &[Datagram]) -> u64 {
    datagrams
        .iter()
        .map(|d| d.rtp.expect("an RTP datagram").header_len as u64)
        .sum()
}

/// webrtc-stats 7.1, 8.7, 8.8: an RTX stream is no object of its own; its packets count in
/// the stream's `packetsSent` / `bytesSent`, and `retransmitted*Sent` are subsets of those.
/// The receive side mirrors it. `packetsSent` used to leave the RTX packets out, and the
/// retransmitted bytes counted the two bytes of the original sequence number.
#[test]
fn retransmissions_over_rtx_are_counted_as_what_the_wire_carried() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated");
    world.drop_rtp = vec![(ssrc, 5040), (ssrc, 5041)];
    world.send_media(sender, 5000, 100, 0)?;
    world.run_for(Duration::from_secs(2))?;
    let now = world.now;

    let media = world.rtp_sent(ssrc);
    let repairs = world.rtp_sent(rtx_ssrc);
    assert_eq!(media.len(), 100);
    assert_eq!(
        repairs.len(),
        2,
        "each lost packet was sent again, over RTX"
    );
    assert_eq!(media.iter().filter(|d| d.dropped).count(), 2);
    assert!(repairs.iter().all(|d| !d.dropped));
    let (sent, lost, repaired) = (100u64, 2u64, 2u64);
    let payload = PAYLOAD as u64;

    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(u(outbound, "rtxSsrc"), u64::from(rtx_ssrc));
    assert_eq!(u(outbound, "packetsSent"), sent + repaired);
    assert_eq!(u(outbound, "bytesSent"), (sent + repaired) * payload);
    assert_eq!(u(outbound, "retransmittedPacketsSent"), repaired);
    assert_eq!(u(outbound, "retransmittedBytesSent"), repaired * payload);
    assert_eq!(
        u(outbound, "headerBytesSent"),
        header_bytes(&media) + header_bytes(&repairs) + repaired * OSN as u64,
        "every header on the wire, and an RTX packet's original sequence number"
    );
    assert_eq!(u(outbound, "nackCount"), 1, "one NACK named both packets");
    assert_eq!(u(outbound, "firCount"), 0, "a video stream has firCount");
    assert_eq!(u(outbound, "pliCount"), 0, "a video stream has pliCount");
    assert!(
        offerer.iter().all(|o| o["ssrc"] != rtx_ssrc),
        "the RTX stream is no object of its own"
    );

    let answerer = world.peers[1].stats(now);
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    let arrived: Vec<Datagram> = media.iter().filter(|d| !d.dropped).copied().collect();
    assert_eq!(u(inbound, "rtxSsrc"), u64::from(rtx_ssrc));
    assert_eq!(u(inbound, "packetsReceived"), sent - lost + repaired);
    assert_eq!(
        u(inbound, "bytesReceived"),
        (sent - lost + repaired) * payload
    );
    assert_eq!(u(inbound, "retransmittedPacketsReceived"), repaired);
    assert_eq!(u(inbound, "retransmittedBytesReceived"), repaired * payload);
    assert_eq!(
        u(inbound, "headerBytesReceived"),
        header_bytes(&arrived) + header_bytes(&repairs) + repaired * OSN as u64
    );
    assert_eq!(u(inbound, "nackCount"), 1);
    assert_eq!(u(inbound, "firCount"), 0);
    assert_eq!(u(inbound, "pliCount"), 0);
    assert!(answerer.iter().all(|o| o["ssrc"] != rtx_ssrc));
    Ok(())
}

/// webrtc-stats 8.8 `retransmittedPacketsSent`: retransmissions "on this SSRC or the RTX
/// SSRC". Without RTX a lost packet is sent again as it was, on the stream's own SSRC; that
/// was counted as a packet sent and never as a retransmitted one.
#[test]
fn retransmissions_without_rtx_are_counted_as_retransmitted() -> Result<()> {
    let setup = Setup {
        rtx: false,
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    assert_eq!(rtx_ssrc, None, "no RTX codec is negotiated");
    world.drop_rtp = vec![(ssrc, 7040)];
    world.send_media(sender, 7000, 100, 0)?;
    world.run_for(Duration::from_secs(2))?;
    let now = world.now;

    let media = world.rtp_sent(ssrc);
    assert_eq!(media.len(), 101, "the lost packet went out twice");
    assert_eq!(
        media
            .iter()
            .filter(|d| d.rtp.is_some_and(|rtp| rtp.sequence_number == 7040))
            .count(),
        2
    );
    let payload = PAYLOAD as u64;

    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(u(outbound, "packetsSent"), 101);
    assert_eq!(u(outbound, "bytesSent"), 101 * payload);
    assert_eq!(u(outbound, "retransmittedPacketsSent"), 1);
    assert_eq!(u(outbound, "retransmittedBytesSent"), payload);
    assert_eq!(u(outbound, "headerBytesSent"), header_bytes(&media));
    assert!(!has(outbound, "rtxSsrc"));

    let answerer = world.peers[1].stats(now);
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    assert_eq!(u(inbound, "packetsReceived"), 100);
    assert_eq!(u(inbound, "bytesReceived"), 100 * payload);
    for member in [
        "retransmittedPacketsReceived",
        "retransmittedBytesReceived",
        "rtxSsrc",
    ] {
        assert!(!has(inbound, member), "{member} without RTX: {inbound}");
    }
    Ok(())
}

/// webrtc-stats 8.5 `headerBytesReceived`, 8.8 `headerBytesSent`: "RTP header and padding
/// bytes". Padding was counted nowhere, so header plus payload bytes fell short of what was
/// sent.
#[test]
fn padding_is_counted_with_the_header_bytes() -> Result<()> {
    let setup = Setup {
        nack: false,
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    const PADDING: u8 = 12;
    world.send_media(sender, 100, 50, PADDING)?;
    let now = world.now;
    let media = world.rtp_sent(ssrc);
    assert_eq!(media.len(), 50);
    let expected_header = header_bytes(&media) + 50 * u64::from(PADDING);

    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(u(outbound, "bytesSent"), 50 * PAYLOAD as u64);
    assert_eq!(u(outbound, "headerBytesSent"), expected_header);

    let answerer = world.peers[1].stats(now);
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    assert_eq!(u(inbound, "bytesReceived"), 50 * PAYLOAD as u64);
    assert_eq!(u(inbound, "headerBytesReceived"), expected_header);
    Ok(())
}

/// webrtc-stats 8.17 `bytesSent` / `bytesReceived`: payload bytes, "not including headers,
/// padding or ICE connectivity checks". STUN datagrams were counted, so the transport's bytes
/// grew on an idle connection.
#[test]
fn transport_bytes_leave_out_ice_checks() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    world.send_media(sender, 1, 50, 0)?;
    // Idle: only consent checks cross the network.
    let idle_from = world.wire.len();
    world.run_for(Duration::from_secs(20))?;
    let idle: Vec<Datagram> = world.wire[idle_from..]
        .iter()
        .filter(|d| d.class != Class::Rtcp)
        .copied()
        .collect();
    assert!(
        idle.iter().any(|d| d.class == Class::Stun),
        "consent checks were sent"
    );
    assert!(
        idle.iter().all(|d| d.class == Class::Stun),
        "and, RTCP aside, nothing else: {idle:#?}"
    );
    let now = world.now;

    for (i, other) in [(0usize, 1usize), (1, 0)] {
        let report = world.peers[i].stats(now);
        let transport = one(&report, "transport");
        let sent: Vec<&Datagram> = world.wire.iter().filter(|d| d.from == i).collect();
        let received: Vec<&Datagram> = world
            .wire
            .iter()
            .filter(|d| d.from == other && !d.dropped)
            .collect();
        let payload_bytes = |datagrams: &[&Datagram]| -> u64 {
            datagrams
                .iter()
                .filter(|d| d.class != Class::Stun)
                .map(|d| d.len as u64)
                .sum()
        };
        assert_eq!(
            u(transport, "packetsSent"),
            sent.len() as u64,
            "peer {i}: every datagram is a packet sent"
        );
        assert_eq!(
            u(transport, "packetsReceived"),
            received.len() as u64,
            "peer {i}: every datagram is a packet received"
        );
        assert_eq!(
            u(transport, "bytesSent"),
            payload_bytes(&sent),
            "peer {i}: the bytes of everything sent but STUN"
        );
        assert_eq!(
            u(transport, "bytesReceived"),
            payload_bytes(&received),
            "peer {i}: the bytes of everything received but STUN"
        );
    }
    Ok(())
}

/// webrtc 8.4: an id is stable for an object across reports and "MUST NOT be predictable by
/// an application". Every id was a fixed string ("RTCPeerConnection", "RTCTransport",
/// "RTCOutboundRTPStream_video_<ssrc>"), the same on every connection.
#[test]
fn ids_are_stable_on_a_connection_and_not_the_same_on_another() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 60, 0)?;
    let now = world.now;
    let first = world.peers[0].stats(now);
    world.send_media(sender, 61, 60, 0)?;
    let now = world.now;
    let second = world.peers[0].stats(now);
    let other = world.peers[1].stats(now);

    let ids = |objects: &[Value]| -> Vec<String> {
        let mut ids: Vec<String> = objects
            .iter()
            .map(|o| o["id"].as_str().expect("an id").to_owned())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(
        ids(&first),
        ids(&second),
        "the same objects have the same ids in the next report"
    );
    for typ in ["peer-connection", "transport"] {
        assert_ne!(
            one(&second, typ)["id"],
            one(&other, typ)["id"],
            "the {typ} object has the same id on two connections"
        );
    }
    let outbound = stream(&second, "outbound-rtp", ssrc);
    let id = outbound["id"].as_str().expect("an id");
    assert!(
        !id.contains(&ssrc.to_string()) && !id.contains("RTC"),
        "an id an application could build from what it knows: {id}"
    );
    // Opaque as they are, the references still resolve.
    for report in [&second, &other] {
        for object in report.iter() {
            for (member, value) in object.as_object().expect("an object") {
                if member.ends_with("Id")
                    && let Some(target) = value.as_str()
                {
                    assert!(
                        report.iter().any(|o| o["id"] == target),
                        "{member} = {target} of {object} resolves to nothing"
                    );
                }
            }
        }
    }
    Ok(())
}

/// The object `id` names in a report.
fn by_id<'a>(objects: &'a [Value], id: &Value) -> &'a Value {
    objects
        .iter()
        .find(|o| o["id"] == *id)
        .unwrap_or_else(|| panic!("no object with id {id}: {objects:#?}"))
}

/// The value of the first `a=<name>:` line of an SDP.
fn sdp_attribute(sdp: &str, name: &str) -> String {
    let prefix = format!("a={name}:");
    sdp.lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no a={name} line in {sdp}"))
        .to_owned()
}

fn close_to(actual: f64, expected: f64, tolerance: f64) -> bool {
    (actual - expected).abs() <= tolerance
}

/// webrtc-stats 8.2, 8.5, 8.6, 8.8, 8.10, 8.11: a stream object names its transport, its
/// codec, its track, its mid, the object of the other end and, for a sender, the media source
/// of its track. Each is checked against the thing it names, not only resolved.
#[test]
fn a_stream_names_its_transport_codec_track_mid_and_source() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, pt) = world.sender_stream(sender);
    world.send_media(sender, 1, 100, 0)?;
    world.run_for(Duration::from_millis(1500))?;
    let now = world.now;
    let sender_track = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .track()
        .expect("the sender has a track")
        .track_id()
        .clone();
    let (receiver_id, receiver_track) = world.peers[1].tracks[0].clone();
    let mid = sdp_attribute(
        &world.peers[0].pc.local_description().expect("an offer").sdp,
        "mid",
    );

    let offerer = world.peers[0].stats(now);
    let transport = one(&offerer, "transport");
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(outbound["kind"], "video");
    assert_eq!(outbound["mid"], mid.as_str());
    assert_eq!(outbound["transportId"], transport["id"]);
    assert_eq!(u(outbound, "encodingIndex"), 0);
    assert!(!has(outbound, "rid"), "one encoding, no rid: {outbound}");
    let codec = by_id(&offerer, &outbound["codecId"]);
    assert_eq!(codec["type"], "codec");
    assert_eq!(u(codec, "payloadType"), u64::from(pt));
    assert_eq!(codec["mimeType"], MIME_TYPE_VP8);
    assert_eq!(u(codec, "clockRate"), 90000);
    assert_eq!(codec["transportId"], transport["id"]);
    assert!(!has(codec, "channels"), "a video codec has no channels");
    let source = by_id(&offerer, &outbound["mediaSourceId"]);
    assert_eq!(source["type"], "media-source");
    assert_eq!(source["kind"], "video");
    assert_eq!(source["trackIdentifier"], sender_track.as_str());
    let remote_inbound = by_id(&offerer, &outbound["remoteId"]);
    assert_eq!(remote_inbound["type"], "remote-inbound-rtp");
    assert_eq!(remote_inbound["localId"], outbound["id"]);
    assert_eq!(remote_inbound["ssrc"], ssrc);
    assert_eq!(remote_inbound["kind"], "video");
    assert_eq!(remote_inbound["transportId"], transport["id"]);
    assert_eq!(remote_inbound["codecId"], outbound["codecId"]);
    assert_eq!(
        u(remote_inbound, "packetsReceived"),
        100,
        "the receiver reported every packet"
    );
    assert_eq!(remote_inbound["packetsLost"], 0);
    assert_eq!(remote_inbound["fractionLost"], 0.0);

    let answerer = world.peers[1].stats(now);
    let transport = one(&answerer, "transport");
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    assert_eq!(inbound["kind"], "video");
    assert_eq!(inbound["mid"], mid.as_str());
    assert_eq!(inbound["trackIdentifier"], receiver_track.as_str());
    assert_eq!(inbound["transportId"], transport["id"]);
    let codec = by_id(&answerer, &inbound["codecId"]);
    assert_eq!(u(codec, "payloadType"), u64::from(pt));
    assert_eq!(codec["mimeType"], MIME_TYPE_VP8);
    assert_eq!(u(inbound, "packetsReceived"), 100);
    assert_eq!(u(inbound, "bytesReceived"), 100 * PAYLOAD as u64);
    assert_eq!(inbound["packetsLost"], 0);
    let remote_outbound = by_id(&answerer, &inbound["remoteId"]);
    assert_eq!(remote_outbound["type"], "remote-outbound-rtp");
    assert_eq!(remote_outbound["localId"], inbound["id"]);
    assert_eq!(remote_outbound["codecId"], inbound["codecId"]);

    // The last packet arrived when the wire says the last media datagram was sent (the
    // network takes no time here), and the report says how long ago that was.
    let last_media = world.rtp_sent(ssrc).last().expect("media was sent").at;
    let since_last = f(inbound, "timestamp") - f(inbound, "lastPacketReceivedTimestamp");
    assert!(
        close_to(since_last, millis(now - last_media), 0.5),
        "the last packet arrived {} ms ago, the report says {since_last}",
        millis(now - last_media)
    );

    // webrtc 8.5: a receiver selects its inbound streams and what they reference, directly
    // or not; the peer connection object is nobody's reference.
    let selected = objects(
        &world.peers[1]
            .pc
            .try_get_stats(now, StatsSelector::Receiver(receiver_id))?,
    );
    for typ in [
        "inbound-rtp",
        "remote-outbound-rtp",
        "codec",
        "transport",
        "candidate-pair",
        "local-candidate",
        "remote-candidate",
        "certificate",
    ] {
        assert!(!of_type(&selected, typ).is_empty(), "no {typ} selected");
    }
    assert!(of_type(&selected, "peer-connection").is_empty());
    let selected = objects(
        &world.peers[0]
            .pc
            .try_get_stats(now, StatsSelector::Sender(sender))?,
    );
    for typ in [
        "outbound-rtp",
        "remote-inbound-rtp",
        "media-source",
        "codec",
        "transport",
    ] {
        assert!(!of_type(&selected, typ).is_empty(), "no {typ} selected");
    }
    Ok(())
}

/// webrtc-stats 8.5 / 8.8 `nackCount`, `pliCount`, `firCount`: the feedback packets the
/// receiver sent are the ones the sender received.
#[test]
fn feedback_counts_are_the_feedback_packets_sent() -> Result<()> {
    use rtci::rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
    use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;

    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    // Three packets lost far enough apart for a NACK each.
    world.drop_rtp = vec![(ssrc, 3010), (ssrc, 3040), (ssrc, 3070)];
    world.send_media(sender, 3000, 100, 0)?;
    world.run_for(Duration::from_secs(1))?;
    let receiver_id = world.peers[1].tracks[0].0;
    for n in 0..5u8 {
        let now = world.now;
        let mut feedback: Vec<Box<dyn rtci::rtcp::Packet>> =
            vec![Box::new(PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: ssrc,
            })];
        if n < 2 {
            feedback.push(Box::new(FullIntraRequest {
                sender_ssrc: 1,
                media_ssrc: ssrc,
                fir: vec![FirEntry {
                    ssrc,
                    sequence_number: n,
                }],
            }));
        }
        world.peers[1]
            .pc
            .rtp_receiver(receiver_id)
            .expect("receiver")
            .write_rtcp(now, feedback)?;
        world.pump()?;
        world.run_for(Duration::from_millis(50))?;
    }
    let now = world.now;

    let answerer = world.peers[1].stats(now);
    let inbound = stream(&answerer, "inbound-rtp", ssrc);
    let nacks = u(inbound, "nackCount");
    assert!(
        (1..=3).contains(&nacks),
        "three losses, at most a NACK each: {nacks}"
    );
    // The counts are of the feedback packets that left. The RTCP session sends feedback on the
    // RFC 4585 section 3.5 schedule, so requests written within one interval leave as one: at
    // least one of each, at most what was written.
    let (plis, firs) = (u(inbound, "pliCount"), u(inbound, "firCount"));
    assert!((1..=5).contains(&plis), "five PLIs written: {plis}");
    assert!((1..=2).contains(&firs), "two FIRs written: {firs}");
    assert_eq!(u(inbound, "retransmittedPacketsReceived"), 3);

    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(u(outbound, "nackCount"), nacks, "every NACK sent arrived");
    assert_eq!(u(outbound, "pliCount"), plis, "every PLI sent arrived");
    assert_eq!(u(outbound, "firCount"), firs, "every FIR sent arrived");
    assert_eq!(u(outbound, "retransmittedPacketsSent"), 3);
    Ok(())
}

/// webrtc-stats 8.20: a candidate pair's STUN counters are the checks that crossed the
/// network, its round trip times what the network took, and its packet and byte counters
/// everything on the pair but those checks.
#[test]
fn a_candidate_pairs_counters_are_the_checks_and_the_payload_on_the_wire() -> Result<()> {
    const ONE_WAY: Duration = Duration::from_millis(15);
    let setup = Setup {
        delay: ONE_WAY,
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    world.send_media(sender, 1, 50, 0)?;
    world.run_for(Duration::from_secs(2))?;
    let settled = world.now;
    let before = [world.peers[0].stats(settled), world.peers[1].stats(settled)];
    let wire_before = world.wire.len();
    world.run_for(Duration::from_secs(20))?;
    let now = world.now;

    const REQUEST: u16 = 0x0001;
    const RESPONSE: u16 = 0x0101;
    for (i, other) in [(0usize, 1usize), (1, 0)] {
        let report = world.peers[i].stats(now);
        let transport = one(&report, "transport");
        let pairs = of_type(&report, "candidate-pair");
        assert_eq!(pairs.len(), 1, "one local and one remote candidate");
        let pair = pairs[0];
        assert_eq!(pair["id"], transport["selectedCandidatePairId"]);
        assert_eq!(pair["transportId"], transport["id"]);
        assert_eq!(pair["state"], "succeeded");
        assert_eq!(pair["nominated"], true);
        assert_eq!(
            by_id(&report, &pair["localCandidateId"])["type"],
            "local-candidate"
        );
        assert_eq!(
            by_id(&report, &pair["remoteCandidateId"])["type"],
            "remote-candidate"
        );

        // A datagram sent `ONE_WAY` ago or less has not arrived yet.
        let arrived = |d: &&Datagram| !d.dropped && d.at + ONE_WAY <= now;
        let count = |from: usize, stun: u16, only_arrived: bool| -> u64 {
            world
                .wire
                .iter()
                .filter(|d| d.from == from && d.stun == Some(stun))
                .filter(|d| !only_arrived || arrived(d))
                .count() as u64
        };
        let on_wire = (
            count(i, REQUEST, false),
            count(i, RESPONSE, false),
            count(other, REQUEST, true),
            count(other, RESPONSE, true),
        );
        assert_eq!(
            (
                u(pair, "requestsSent"),
                u(pair, "responsesSent"),
                u(pair, "requestsReceived"),
                u(pair, "responsesReceived"),
            ),
            on_wire,
            "peer {i}: requests sent, responses sent, requests received, responses received \
             against the wire; {pair}"
        );

        // Every answer took the network there and back.
        let round_trip = 2.0 * ONE_WAY.as_secs_f64();
        assert!(
            close_to(f(pair, "currentRoundTripTime"), round_trip, 0.002),
            "{pair}"
        );
        assert!(
            close_to(
                f(pair, "totalRoundTripTime"),
                round_trip * u(pair, "responsesReceived") as f64,
                0.002 * u(pair, "responsesReceived") as f64
            ),
            "{pair}"
        );

        // Idle, the only requests are the ones that keep the pair alive, and a consent request
        // goes out every 4 to 6 seconds (RFC 7675 section 5.1: 5 seconds, times 0.8 to 1.2).
        let earlier = one(&before[i], "candidate-pair");
        let idle_requests = world.wire[wire_before..]
            .iter()
            .filter(|d| d.from == i && d.stun == Some(REQUEST))
            .count() as u64;
        assert_eq!(
            u(pair, "requestsSent") - u(earlier, "requestsSent"),
            idle_requests,
            "peer {i}"
        );
        let consent_requests = u(pair, "consentRequestsSent") - u(earlier, "consentRequestsSent");
        assert!(
            (3..=5).contains(&consent_requests),
            "peer {i}: twenty seconds of consent requests: {consent_requests}; {pair}"
        );
        assert!(u(pair, "consentRequestsSent") <= u(pair, "requestsSent"));

        // Everything that is not STUN is the pair's payload.
        let sent: Vec<&Datagram> = world
            .wire
            .iter()
            .filter(|d| d.from == i && d.class != Class::Stun)
            .collect();
        let received: Vec<&Datagram> = world
            .wire
            .iter()
            .filter(|d| d.from == other && d.class != Class::Stun)
            .filter(|d| d.delivered.is_some())
            .collect();
        assert_eq!(
            u(pair, "packetsSent"),
            sent.len() as u64,
            "peer {i}: the payload datagrams it sent, as (ms after the first, kind, bytes): {:?}",
            sent.iter()
                .map(|d| (millis(d.at - sent[0].at) as u64, d.class, d.len))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            u(pair, "bytesSent"),
            sent.iter().map(|d| d.len as u64).sum::<u64>()
        );
        assert_eq!(u(pair, "packetsReceived"), received.len() as u64);
        assert_eq!(
            u(pair, "bytesReceived"),
            received.iter().map(|d| d.len as u64).sum::<u64>()
        );
        let last_sent = sent.last().expect("payload was sent").at;
        // The instant the network handed the datagram to the engine, which can be later than
        // `at + ONE_WAY` (the clock moves at least 1 ms a step): the engine stamps the pair
        // with the `now` of that `handle_read`, read from no clock.
        let last_received = received
            .last()
            .and_then(|d| d.delivered)
            .expect("payload was received");
        for (member, at) in [
            ("lastPacketSentTimestamp", last_sent),
            ("lastPacketReceivedTimestamp", last_received),
        ] {
            let ago = f(pair, "timestamp") - f(pair, member);
            // Exact up to the f64 rounding of epoch milliseconds (about 0.2 us here).
            assert!(
                close_to(ago, millis(now - at), 0.001),
                "{member} is {ago} ms before the report, the wire says {} ms",
                millis(now - at)
            );
        }
    }
    Ok(())
}

/// webrtc-stats 8.17, 8.18, 8.22: the transport's roles, states, ciphers, credentials and
/// certificates are those of the session, each side's local values being the other's remote.
#[test]
fn a_transport_reports_the_session_it_negotiated() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    world.send_media(sender, 1, 10, 0)?;
    let now = world.now;
    let reports = [world.peers[0].stats(now), world.peers[1].stats(now)];
    let sdp = [
        world.peers[0].pc.local_description().expect("offer").sdp,
        world.peers[1].pc.local_description().expect("answer").sdp,
    ];
    let transports = [one(&reports[0], "transport"), one(&reports[1], "transport")];

    assert_eq!(transports[0]["iceRole"], "controlling", "the offerer");
    assert_eq!(transports[1]["iceRole"], "controlled");
    let roles = [&transports[0]["dtlsRole"], &transports[1]["dtlsRole"]];
    assert!(
        (*roles[0] == "client" && *roles[1] == "server")
            || (*roles[0] == "server" && *roles[1] == "client"),
        "one DTLS client and one server: {roles:?}"
    );
    for (i, transport) in transports.iter().enumerate() {
        assert!(
            transport["iceState"] == "connected" || transport["iceState"] == "completed",
            "{transport}"
        );
        assert_eq!(transport["dtlsState"], "connected");
        // Two peers of this engine negotiate DTLS 1.3 ({254, 252}): the media counted
        // below went through SRTP keyed from its exporter.
        assert_eq!(transport["tlsVersion"], "FEFC", "DTLS 1.3");
        assert_eq!(
            transport["iceLocalUsernameFragment"],
            sdp_attribute(&sdp[i], "ice-ufrag").as_str()
        );
        assert_eq!(u(transport, "selectedCandidatePairChanges"), 1);
        assert_eq!(
            by_id(&reports[i], &transport["selectedCandidatePairId"])["type"],
            "candidate-pair"
        );
    }
    // Both ends negotiated the same suites, named as IANA names them.
    assert_eq!(transports[0]["dtlsCipher"], transports[1]["dtlsCipher"]);
    assert_eq!(transports[0]["srtpCipher"], transports[1]["srtpCipher"]);
    let dtls_cipher = transports[0]["dtlsCipher"].as_str().expect("dtlsCipher");
    assert!(
        dtls_cipher.starts_with("TLS_AES_") || dtls_cipher.starts_with("TLS_CHACHA20_"),
        "an IANA TLS 1.3 cipher suite name: {dtls_cipher}"
    );
    let srtp_cipher = transports[0]["srtpCipher"].as_str().expect("srtpCipher");
    assert!(
        [
            "SRTP_AEAD_AES_128_GCM",
            "SRTP_AEAD_AES_256_GCM",
            "SRTP_AES128_CM_HMAC_SHA1_80",
            "SRTP_AES128_CM_HMAC_SHA1_32"
        ]
        .contains(&srtp_cipher),
        "an IANA DTLS-SRTP protection profile name: {srtp_cipher}"
    );

    // A side's local certificate is the one its SDP fingerprint names, and the other side's
    // remote certificate.
    for (i, other) in [(0usize, 1usize), (1, 0)] {
        let local = by_id(&reports[i], &transports[i]["localCertificateId"]);
        let remote = by_id(&reports[other], &transports[other]["remoteCertificateId"]);
        assert_eq!(local["type"], "certificate");
        assert_eq!(remote["type"], "certificate");
        let fingerprint = sdp_attribute(&sdp[i], "fingerprint");
        let (algorithm, value) = fingerprint.split_once(' ').expect("algorithm and value");
        assert_eq!(local["fingerprintAlgorithm"], algorithm);
        assert!(
            local["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .eq_ignore_ascii_case(value),
            "{local} against a=fingerprint:{fingerprint}"
        );
        assert!(
            remote["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .eq_ignore_ascii_case(value)
        );
        assert_eq!(local["base64Certificate"], remote["base64Certificate"]);
        assert!(
            !has(local, "issuerCertificateId"),
            "a self-signed certificate"
        );
    }
    Ok(())
}

/// webrtc-stats 4.3 and 7.1: a transport whose consent expired has no selected pair any
/// more, which `selectedCandidatePairChanges` counts, while it is "disconnected" waiting for
/// the end of the candidates (W3C webrtc-pc 5.6.4) and once it is "failed"; and the report
/// stays available after `close()`.
#[test]
fn losing_the_selected_pair_is_a_change_and_stats_outlive_close() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 20, 0)?;
    let now = world.now;
    let alive = world.peers[0].stats(now);
    assert_eq!(
        u(one(&alive, "transport"), "selectedCandidatePairChanges"),
        1
    );

    // Nothing gets through any more: consent expires. No end of the candidates has been
    // signalled: "disconnected", and the pair is gone.
    world.blackhole = true;
    world.fail_on_failed = false;
    world.run_for(Duration::from_secs(60))?;
    assert!(
        !world.peers[0]
            .states
            .contains(&RTCPeerConnectionState::Failed),
        "{:?}",
        world.peers[0].states
    );
    let now = world.now;
    let lost = world.peers[0].stats(now);
    let transport = one(&lost, "transport");
    assert_eq!(transport["iceState"], "disconnected");
    assert!(!has(transport, "selectedCandidatePairId"), "{transport}");
    assert_eq!(u(transport, "selectedCandidatePairChanges"), 2);

    // The application ends its gathering and relays the peer's end-of-candidates: ICE fails.
    world.peers[0]
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    world.peers[0]
        .pc
        .add_remote_candidate(RTCIceCandidateInit {
            sdp_mline_index: Some(0),
            ..Default::default()
        })?;
    world.run_for(Duration::from_secs(1))?;
    assert!(
        world.peers[0]
            .states
            .contains(&RTCPeerConnectionState::Failed),
        "{:?}",
        world.peers[0].states
    );
    let now = world.now;
    let failed = world.peers[0].stats(now);
    let transport = one(&failed, "transport");
    assert_eq!(transport["iceState"], "failed");
    assert!(!has(transport, "selectedCandidatePairId"), "{transport}");
    assert_eq!(u(transport, "selectedCandidatePairChanges"), 2);

    world.peers[0].pc.close()?;
    world.peers[0].closed = true;
    let closed = world.peers[0].stats(now + Duration::from_secs(1));
    let outbound = stream(&closed, "outbound-rtp", ssrc);
    assert_eq!(
        outbound["id"],
        stream(&alive, "outbound-rtp", ssrc)["id"],
        "the same object after close"
    );
    assert_eq!(u(outbound, "packetsSent"), 20);
    assert_eq!(
        one(&closed, "peer-connection")["id"],
        one(&alive, "peer-connection")["id"]
    );
    assert_eq!(
        one(&closed, "transport")["id"],
        one(&alive, "transport")["id"]
    );
    Ok(())
}

/// webrtc-stats 8.16: a data channel's label, protocol, identifier, state and its message and
/// byte counters, against the channel and what was sent on it.
#[test]
fn a_data_channel_reports_what_it_is_and_what_crossed_it() -> Result<()> {
    let mut lone = Peer::new("10.0.0.9:5000", VIDEO, true)?;
    let unassigned: RTCDataChannelId = lone
        .pc
        .create_data_channel(
            "early",
            Some(RTCDataChannelInit {
                protocol: "chat.v1".to_owned(),
                ..Default::default()
            }),
        )?
        .id();
    let report = lone.stats(Instant::now());
    let channel = one(&report, "data-channel");
    assert_eq!(channel["label"], "early");
    assert_eq!(channel["protocol"], "chat.v1");
    assert_eq!(channel["state"], "connecting");
    assert!(
        !has(channel, "dataChannelIdentifier"),
        "channel {unassigned} has no id before the DTLS role is known: {channel}"
    );
    let connection = one(&report, "peer-connection");
    assert_eq!(u(connection, "dataChannelsOpened"), 0);
    assert_eq!(u(connection, "dataChannelsClosed"), 0);

    let setup = Setup {
        data_channel: true,
        ..VIDEO
    };
    let (mut world, _) = World::connected(setup)?;
    let opened = |peer: &Peer| {
        peer.channel_events.iter().find_map(|e| match e {
            RTCDataChannelEvent::OnOpen(id) => Some(*id),
            _ => None,
        })
    };
    let deadline = world.now + Duration::from_secs(5);
    while (opened(&world.peers[0]).is_none() || opened(&world.peers[1]).is_none())
        && world.now < deadline
    {
        world.run_for(Duration::from_millis(20))?;
    }
    let ids = [
        opened(&world.peers[0]).expect("open on the offerer"),
        opened(&world.peers[1]).expect("open on the answerer"),
    ];
    let messages: [&[u8]; 3] = [b"one", b"twenty bytes of data", b""];
    for message in messages {
        let now = world.now;
        world.peers[0]
            .pc
            .data_channel(ids[0])
            .expect("channel")
            .send(now, BytesMut::from(message))?;
        world.pump()?;
        world.run_for(Duration::from_millis(20))?;
    }
    world.run_for(Duration::from_millis(200))?;
    let now = world.now;
    let bytes: u64 = messages.iter().map(|m| m.len() as u64).sum();
    for (i, id) in ids.into_iter().enumerate() {
        let stream_id = world.peers[i]
            .pc
            .data_channel(id)
            .expect("channel")
            .stream_id()
            .expect("an open channel has a stream id");
        let report = world.peers[i].stats(now);
        let channel = one(&report, "data-channel");
        assert_eq!(channel["label"], "first");
        assert_eq!(channel["protocol"], "");
        assert_eq!(channel["state"], "open");
        assert_eq!(u(channel, "dataChannelIdentifier"), u64::from(stream_id));
        let (sent, received) = if i == 0 { (3, 0) } else { (0, 3) };
        assert_eq!(u(channel, "messagesSent"), sent);
        assert_eq!(u(channel, "bytesSent"), if i == 0 { bytes } else { 0 });
        assert_eq!(u(channel, "messagesReceived"), received);
        assert_eq!(u(channel, "bytesReceived"), if i == 0 { 0 } else { bytes });
        let connection = one(&report, "peer-connection");
        assert_eq!(u(connection, "dataChannelsOpened"), 1);
        assert_eq!(u(connection, "dataChannelsClosed"), 0);
    }
    Ok(())
}

/// webrtc-stats 8.8 `totalPacketSendDelay`: the time packets "have spent buffered locally
/// before being transmitted onto the network", from the packetizer to the socket. Here that
/// is the time the pacer held each packet; without one it is zero.
#[test]
fn total_packet_send_delay_is_the_time_the_pacer_held_the_packets() -> Result<()> {
    let setup = Setup {
        nack: false,
        // 100 kbit/s: a burst of sixty 230-byte packets takes about a second to leave.
        pacer: Some(100_000.0),
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    let (ssrc, _, pt) = world.sender_stream(sender);
    let written_at = world.now;
    for n in 0..60u16 {
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                written_at,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: 100 + n,
                        timestamp: 3000,
                        ssrc,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; PAYLOAD]),
                },
            )?;
    }
    world.pump()?;
    world.run_for(Duration::from_secs(5))?;
    let now = world.now;
    let media = world.rtp_sent(ssrc);
    assert_eq!(media.len(), 60, "the pacer let every packet out");
    let held: f64 = media
        .iter()
        .map(|d| (d.at - written_at).as_secs_f64())
        .sum();
    assert!(
        held > 1.0,
        "the pacer spread the burst out: {held} s in total"
    );
    let offerer = world.peers[0].stats(now);
    let outbound = stream(&offerer, "outbound-rtp", ssrc);
    assert_eq!(u(outbound, "packetsSent"), 60);
    assert!(
        close_to(f(outbound, "totalPacketSendDelay"), held, 1e-6),
        "the packets left {held} s after they were written, in total: {outbound}"
    );

    // Without a pacer a packet leaves when it is written.
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 20, 0)?;
    let now = world.now;
    let offerer = world.peers[0].stats(now);
    assert_eq!(
        stream(&offerer, "outbound-rtp", ssrc)["totalPacketSendDelay"],
        0.0
    );
    Ok(())
}

/// webrtc-stats 8.17 `ccfbMessagesSent` / `ccfbMessagesReceived`: the RFC 8888 feedback
/// packets one side sent are the ones the other received.
#[test]
fn ccfb_messages_sent_are_the_ones_received() -> Result<()> {
    let setup = Setup {
        ccfb: true,
        ..VIDEO
    };
    let (mut world, sender) = World::connected(setup)?;
    world.send_media(sender, 1, 100, 0)?;
    world.run_for(Duration::from_secs(1))?;
    let now = world.now;
    let offerer = world.peers[0].stats(now);
    let answerer = world.peers[1].stats(now);
    let (offerer, answerer) = (one(&offerer, "transport"), one(&answerer, "transport"));
    let sent = u(answerer, "ccfbMessagesSent");
    assert!(sent >= 5, "feedback for two seconds of media: {sent}");
    assert_eq!(u(offerer, "ccfbMessagesReceived"), sent);
    assert_eq!(
        u(offerer, "ccfbMessagesSent"),
        0,
        "the offerer receives no media"
    );
    assert_eq!(u(answerer, "ccfbMessagesReceived"), 0);
    Ok(())
}

/// The members the engine cannot measure, each supplied by the application with a value of
/// its own and read back from the report; and webrtc-stats 4.2 / 8.5: a member that does not
/// apply to a stream's kind does not exist, whatever was supplied.
///
/// The update structs are written out in full: a member added to one does not compile here
/// until it is supplied and checked.
#[test]
fn every_supplied_member_reaches_the_report_of_the_kind_it_applies_to() -> Result<()> {
    let decoder = DecoderStatsUpdate {
        frames_received: Some(101),
        frames_assembled_from_multiple_packets: Some(102),
        total_assembly_time: Some(1.03),
        frames_dropped: Some(104),
        frames_per_second: Some(29.5),
        frames_decoded: Some(106),
        key_frames_decoded: Some(107),
        frames_rendered: Some(108),
        frame_width: Some(1280),
        frame_height: Some(720),
        qp_sum: Some(111),
        total_decode_time: Some(1.12),
        total_inter_frame_delay: Some(1.13),
        total_squared_inter_frame_delay: Some(1.14),
        total_processing_delay: Some(1.15),
        pause_count: Some(116),
        total_pauses_duration: Some(1.17),
        freeze_count: Some(118),
        total_freezes_duration: Some(1.19),
        packets_discarded: Some(120),
        decoder_implementation: Some("a-decoder".to_owned()),
        power_efficient_decoder: Some(true),
        total_corruption_probability: Some(1.23),
        total_squared_corruption_probability: Some(1.24),
        corruption_measurements: Some(125),
        // Supplied here through the audio update (`receiver` below), whose values the report
        // shows only when the decoder update leaves these out; a decoder update's own values
        // and their precedence: `statistics::feed_test::
        // the_decoder_update_carries_the_jitter_buffer_members_of_a_video_stream`.
        jitter_buffer_delay: None,
        jitter_buffer_target_delay: None,
        jitter_buffer_minimum_delay: None,
        jitter_buffer_emitted_count: None,
    };
    let decoder_video_only: &[(&str, Value)] = &[
        ("framesReceived", 101.into()),
        ("framesAssembledFromMultiplePackets", 102.into()),
        ("totalAssemblyTime", 1.03.into()),
        ("framesDropped", 104.into()),
        ("framesPerSecond", 29.5.into()),
        ("framesDecoded", 106.into()),
        ("keyFramesDecoded", 107.into()),
        ("framesRendered", 108.into()),
        ("frameWidth", 1280.into()),
        ("frameHeight", 720.into()),
        ("qpSum", 111.into()),
        ("totalDecodeTime", 1.12.into()),
        ("totalInterFrameDelay", 1.13.into()),
        ("totalSquaredInterFrameDelay", 1.14.into()),
        ("pauseCount", 116.into()),
        ("totalPausesDuration", 1.17.into()),
        ("freezeCount", 118.into()),
        ("totalFreezesDuration", 1.19.into()),
        ("decoderImplementation", "a-decoder".into()),
        ("powerEfficientDecoder", true.into()),
        ("totalCorruptionProbability", 1.23.into()),
        ("totalSquaredCorruptionProbability", 1.24.into()),
        ("corruptionMeasurements", 125.into()),
    ];
    let decoder_any_kind: &[(&str, Value)] = &[
        ("totalProcessingDelay", 1.15.into()),
        ("packetsDiscarded", 120.into()),
    ];
    let receiver = AudioReceiverStatsUpdate {
        total_samples_received: Some(201),
        concealed_samples: Some(202),
        silent_concealed_samples: Some(203),
        concealment_events: Some(204),
        inserted_samples_for_deceleration: Some(205),
        removed_samples_for_acceleration: Some(206),
        audio_level: Some(0.207),
        total_audio_energy: Some(2.08),
        total_samples_duration: Some(2.09),
        jitter_buffer_delay: Some(2.10),
        jitter_buffer_target_delay: Some(2.11),
        jitter_buffer_minimum_delay: Some(2.12),
        jitter_buffer_emitted_count: Some(213),
        estimated_playout_timestamp: Some(Duration::from_millis(1_700_000_000_214)),
        fec_packets_discarded: Some(215),
        in_band_fec_packets_received: Some(216),
        in_band_fec_bytes_received: Some(217),
    };
    let receiver_audio_only: &[(&str, Value)] = &[
        ("totalSamplesReceived", 201.into()),
        ("concealedSamples", 202.into()),
        ("silentConcealedSamples", 203.into()),
        ("concealmentEvents", 204.into()),
        ("insertedSamplesForDeceleration", 205.into()),
        ("removedSamplesForAcceleration", 206.into()),
        ("audioLevel", 0.207.into()),
        ("totalAudioEnergy", 2.08.into()),
        ("totalSamplesDuration", 2.09.into()),
    ];
    let receiver_any_kind: &[(&str, Value)] = &[
        ("jitterBufferDelay", 2.10.into()),
        ("jitterBufferTargetDelay", 2.11.into()),
        ("jitterBufferMinimumDelay", 2.12.into()),
        ("jitterBufferEmittedCount", 213.into()),
        ("estimatedPlayoutTimestamp", 1_700_000_000_214.0.into()),
        ("fecPacketsDiscarded", 215.into()),
        // No FEC SSRC here: all the FEC there is, is what the decoder found in band.
        ("fecPacketsReceived", 216.into()),
        ("fecBytesReceived", 217.into()),
    ];
    let encoder = EncoderStatsUpdate {
        frame_width: Some(640),
        frame_height: Some(360),
        frames_per_second: Some(24.5),
        frames_sent: Some(304),
        huge_frames_sent: Some(305),
        frames_encoded: Some(306),
        key_frames_encoded: Some(307),
        qp_sum: Some(308),
        total_encode_time: Some(3.09),
        psnr_sum: Some(PsnrSum {
            y: 31.0,
            u: 32.0,
            v: 33.0,
        }),
        psnr_measurements: Some(311),
        target_bitrate: Some(312_000.0),
        quality_limitation_reason: Some(RTCQualityLimitationReason::Cpu),
        quality_limitation_durations: Some(QualityLimitationDurations {
            none: 3.21,
            cpu: 3.15,
            bandwidth: 3.16,
            other: 3.17,
        }),
        quality_limitation_resolution_changes: Some(318),
        encoder_implementation: Some("an-encoder".to_owned()),
        power_efficient_encoder: Some(false),
        scalability_mode: Some("L1T3".to_owned()),
    };
    let encoder_video_only: &[(&str, Value)] = &[
        ("frameWidth", 640.into()),
        ("frameHeight", 360.into()),
        ("framesPerSecond", 24.5.into()),
        ("framesSent", 304.into()),
        ("hugeFramesSent", 305.into()),
        ("framesEncoded", 306.into()),
        ("keyFramesEncoded", 307.into()),
        ("qpSum", 308.into()),
        ("totalEncodeTime", 3.09.into()),
        (
            "psnrSum",
            serde_json::json!({"y": 31.0, "u": 32.0, "v": 33.0}),
        ),
        ("psnrMeasurements", 311.into()),
        ("qualityLimitationReason", "cpu".into()),
        (
            "qualityLimitationDurations",
            serde_json::json!({"none": 3.21, "cpu": 3.15, "bandwidth": 3.16, "other": 3.17}),
        ),
        ("qualityLimitationResolutionChanges", 318.into()),
        ("encoderImplementation", "an-encoder".into()),
        ("powerEfficientEncoder", false.into()),
        ("scalabilityMode", "L1T3".into()),
    ];
    let encoder_any_kind: &[(&str, Value)] = &[("targetBitrate", 312_000.0.into())];

    let check = |object: &Value, expected: &[(&str, Value)], applies: bool| {
        for (member, value) in expected {
            if applies {
                assert_eq!(object[*member], *value, "{member} of {object}");
            } else {
                assert!(
                    !has(object, member),
                    "{member} does not apply to a {} stream: {object}",
                    object["kind"]
                );
            }
        }
    };

    for audio in [false, true] {
        let setup = Setup {
            audio,
            rtx: !audio,
            nack: !audio,
            ..VIDEO
        };
        let (mut world, sender) = World::connected(setup)?;
        let (ssrc, _, _) = world.sender_stream(sender);
        world.send_media(sender, 1, 20, 0)?;
        let now = world.now;

        // Before anything is supplied none of it is claimed.
        let before = world.peers[1].stats(now);
        let inbound = stream(&before, "inbound-rtp", ssrc);
        for expected in [
            decoder_video_only,
            decoder_any_kind,
            receiver_audio_only,
            &receiver_any_kind[..6],
        ] {
            check(inbound, expected, false);
        }
        assert_eq!(u(inbound, "fecPacketsReceived"), 0);
        let before = world.peers[0].stats(now);
        let outbound = stream(&before, "outbound-rtp", ssrc);
        check(outbound, encoder_video_only, false);
        check(outbound, encoder_any_kind, false);

        assert!(
            world.peers[1]
                .pc
                .update_decoder_stats(ssrc, decoder.clone())
        );
        assert!(
            world.peers[1]
                .pc
                .update_audio_receiver_stats(ssrc, receiver.clone())
        );
        assert!(
            !world.peers[1]
                .pc
                .update_decoder_stats(ssrc + 1, decoder.clone())
        );
        world.peers[1].pc.update_audio_playout_stats(
            "speaker",
            &[ssrc],
            AudioPlayoutStatsUpdate {
                synthesized_samples_duration: Some(4.01),
                synthesized_samples_events: Some(402),
                total_samples_duration: Some(4.03),
                total_playout_delay: Some(4.04),
                total_samples_count: Some(405),
            },
        );
        let answerer = world.peers[1].stats(now);
        let inbound = stream(&answerer, "inbound-rtp", ssrc);
        check(inbound, decoder_video_only, !audio);
        check(inbound, decoder_any_kind, true);
        check(inbound, receiver_audio_only, audio);
        check(inbound, receiver_any_kind, true);
        let playout = one(&answerer, "media-playout");
        assert_eq!(playout["kind"], "audio");
        assert_eq!(playout["synthesizedSamplesDuration"], 4.01);
        assert_eq!(playout["synthesizedSamplesEvents"], 402);
        assert_eq!(playout["totalSamplesDuration"], 4.03);
        assert_eq!(playout["totalPlayoutDelay"], 4.04);
        assert_eq!(playout["totalSamplesCount"], 405);
        if audio {
            assert_eq!(inbound["playoutId"], playout["id"]);
        } else {
            assert!(!has(inbound, "playoutId"), "playout is audio's: {inbound}");
        }

        assert!(
            world.peers[0]
                .pc
                .update_encoder_stats(ssrc, encoder.clone())
        );
        assert!(
            !world.peers[0]
                .pc
                .update_encoder_stats(ssrc + 1, encoder.clone())
        );
        let audio_source = AudioSourceStatsUpdate {
            audio_level: Some(0.501),
            total_audio_energy: Some(5.02),
            total_samples_duration: Some(5.03),
            echo_return_loss: Some(5.04),
            echo_return_loss_enhancement: Some(5.05),
        };
        let video_source = VideoSourceStatsUpdate {
            width: Some(1920),
            height: Some(1080),
            frames: Some(603),
            frames_per_second: Some(60.4),
        };
        // A source's update is taken by a sender of that kind only.
        assert_eq!(
            world.peers[0]
                .pc
                .update_audio_source_stats(sender, audio_source),
            audio
        );
        assert_eq!(
            world.peers[0]
                .pc
                .update_video_source_stats(sender, video_source),
            !audio
        );
        let offerer = world.peers[0].stats(now);
        let outbound = stream(&offerer, "outbound-rtp", ssrc);
        check(outbound, encoder_video_only, !audio);
        check(outbound, encoder_any_kind, true);
        let source = by_id(&offerer, &outbound["mediaSourceId"]);
        let audio_members: &[(&str, Value)] = &[
            ("audioLevel", 0.501.into()),
            ("totalAudioEnergy", 5.02.into()),
            ("totalSamplesDuration", 5.03.into()),
            ("echoReturnLoss", 5.04.into()),
            ("echoReturnLossEnhancement", 5.05.into()),
        ];
        let video_members: &[(&str, Value)] = &[
            ("width", 1920.into()),
            ("height", 1080.into()),
            ("frames", 603.into()),
            ("framesPerSecond", 60.4.into()),
        ];
        assert_eq!(source["kind"], if audio { "audio" } else { "video" });
        check(source, audio_members, audio);
        check(source, video_members, !audio);

        // What the candidate pair in use cannot know without the application.
        let pair = by_id(
            &offerer,
            &one(&offerer, "transport")["selectedCandidatePairId"],
        );
        for member in [
            "availableIncomingBitrate",
            "packetsDiscardedOnSend",
            "bytesDiscardedOnSend",
        ] {
            assert!(!has(pair, member), "{member} before anything said so");
        }
        assert!(
            world.peers[0]
                .pc
                .update_available_incoming_bitrate(1_250_000.0)
        );
        assert!(world.peers[0].pc.on_send_discarded(1200));
        assert!(world.peers[0].pc.on_send_discarded(300));
        let offerer = world.peers[0].stats(now);
        let pair = by_id(
            &offerer,
            &one(&offerer, "transport")["selectedCandidatePairId"],
        );
        assert_eq!(pair["availableIncomingBitrate"], 1_250_000.0);
        assert_eq!(u(pair, "packetsDiscardedOnSend"), 2);
        assert_eq!(u(pair, "bytesDiscardedOnSend"), 1500);
    }

    // The other values of RTCQualityLimitationReason.
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 5, 0)?;
    for (reason, name) in [
        (RTCQualityLimitationReason::None, "none"),
        (RTCQualityLimitationReason::Bandwidth, "bandwidth"),
        (RTCQualityLimitationReason::Other, "other"),
    ] {
        world.peers[0].pc.update_encoder_stats(
            ssrc,
            EncoderStatsUpdate {
                quality_limitation_reason: Some(reason),
                ..Default::default()
            },
        );
        let now = world.now;
        let offerer = world.peers[0].stats(now);
        assert_eq!(
            stream(&offerer, "outbound-rtp", ssrc)["qualityLimitationReason"],
            name
        );
    }
    Ok(())
}

/// webrtc-stats 8.19: a candidate's members are the candidate's, a local server-reflexive or
/// relay candidate names the server it came from (and a relay candidate how that server is
/// reached), and a remote candidate never does.
#[test]
fn a_candidate_reports_what_it_was_gathered_as() -> Result<()> {
    // (candidate, the server it was gathered from)
    let gathered = [
        (
            "candidate:842163049 1 udp 1694498815 203.0.113.5 6002 typ srflx raddr 10.0.0.1 rport 5000",
            Some("stun:stun.example.org:3478"),
        ),
        (
            "candidate:3745641921 1 udp 16777215 198.51.100.7 7000 typ relay raddr 203.0.113.5 rport 6002",
            Some("turn:turn.example.org:3478?transport=tcp"),
        ),
        (
            "candidate:3745641922 1 udp 16777214 198.51.100.7 7001 typ relay raddr 203.0.113.5 rport 6001",
            Some("turns:turn.example.org:5349"),
        ),
        (
            "candidate:1052947297 1 tcp 1518280447 10.0.0.1 9001 typ host tcptype passive",
            None,
        ),
    ];
    // Gathered before a pair is nominated: the agent takes no local candidate after that in
    // one ICE session (RFC 8838 section 13).
    let (mut world, _) = World::connected_with(VIDEO, |world| {
        for (candidate, url) in gathered {
            let init = RTCIceCandidateInit {
                sdp_mline_index: Some(0),
                candidate: candidate.to_owned(),
                url: url.map(str::to_owned),
                ..Default::default()
            };
            world.peers[0].pc.add_local_candidate(init.clone())?;
            world.peers[1]
                .pc
                .add_remote_candidate(RTCIceCandidateInit { url: None, ..init })?;
        }
        Ok(())
    })?;
    let ufrag = [
        sdp_attribute(
            &world.peers[0].pc.local_description().expect("offer").sdp,
            "ice-ufrag",
        ),
        sdp_attribute(
            &world.peers[1].pc.local_description().expect("answer").sdp,
            "ice-ufrag",
        ),
    ];
    world.run_for(Duration::from_secs(1))?;
    let now = world.now;
    let offerer = world.peers[0].stats(now);
    let answerer = world.peers[1].stats(now);
    let candidate = |objects: &[Value], typ: &str, port: u64| -> Value {
        objects
            .iter()
            .find(|o| o["type"] == typ && o["port"] == port)
            .unwrap_or_else(|| panic!("no {typ} on port {port}: {objects:#?}"))
            .clone()
    };

    // (port, type, protocol, priority, foundation, address, related address and port, url,
    //  relay protocol, tcp type)
    type Expected = (
        u64,
        &'static str,
        &'static str,
        u64,
        &'static str,
        &'static str,
        Option<(&'static str, u64)>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );
    let expected: [Expected; 5] = [
        (
            5000, "host", "udp", 0, "", "10.0.0.1", None, None, None, None,
        ),
        (
            6002,
            "srflx",
            "udp",
            1694498815,
            "842163049",
            "203.0.113.5",
            Some(("10.0.0.1", 5000)),
            Some("stun:stun.example.org:3478"),
            None,
            None,
        ),
        (
            7000,
            "relay",
            "udp",
            16777215,
            "3745641921",
            "198.51.100.7",
            Some(("203.0.113.5", 6002)),
            Some("turn:turn.example.org:3478?transport=tcp"),
            Some("tcp"),
            None,
        ),
        (
            7001,
            "relay",
            "udp",
            16777214,
            "3745641922",
            "198.51.100.7",
            Some(("203.0.113.5", 6001)),
            Some("turns:turn.example.org:5349"),
            Some("tls"),
            None,
        ),
        (
            9001,
            "host",
            "tcp",
            1518280447,
            "1052947297",
            "10.0.0.1",
            None,
            None,
            None,
            Some("passive"),
        ),
    ];
    for (port, typ, protocol, priority, foundation, address, related, url, relay, tcp) in expected {
        let local = candidate(&offerer, "local-candidate", port);
        let remote = candidate(&answerer, "remote-candidate", port);
        for (side, object, ufrag) in [("local", &local, &ufrag[0]), ("remote", &remote, &ufrag[0])]
        {
            assert_eq!(object["candidateType"], typ, "{side} {object}");
            assert_eq!(object["protocol"], protocol, "{side} {object}");
            assert_eq!(object["address"], address, "{side} {object}");
            if priority != 0 {
                assert_eq!(u(object, "priority"), priority, "{side} {object}");
                assert_eq!(object["foundation"], foundation, "{side} {object}");
            }
            match related {
                Some((related_address, related_port)) => {
                    assert_eq!(object["relatedAddress"], related_address, "{side} {object}");
                    assert_eq!(u(object, "relatedPort"), related_port, "{side} {object}");
                }
                None => {
                    assert!(!has(object, "relatedAddress"), "{side} {object}");
                    assert!(!has(object, "relatedPort"), "{side} {object}");
                }
            }
            match tcp {
                Some(tcp) => assert_eq!(object["tcpType"], tcp, "{side} {object}"),
                None => assert!(!has(object, "tcpType"), "{side} {object}"),
            }
            assert_eq!(
                object["usernameFragment"],
                ufrag.as_str(),
                "{side} {object}"
            );
            assert_eq!(
                by_id(
                    if side == "local" { &offerer } else { &answerer },
                    &object["transportId"]
                )["type"],
                "transport"
            );
        }
        match url {
            Some(url) => assert_eq!(local["url"], url, "{local}"),
            None => assert!(!has(&local, "url"), "{local}"),
        }
        match relay {
            Some(relay) => assert_eq!(local["relayProtocol"], relay, "{local}"),
            None => assert!(!has(&local, "relayProtocol"), "{local}"),
        }
        assert!(
            !has(&remote, "url"),
            "a remote candidate has no url: {remote}"
        );
        assert!(!has(&remote, "relayProtocol"), "{remote}");
    }
    assert_eq!(
        candidate(&answerer, "local-candidate", 5000)["usernameFragment"],
        ufrag[1].as_str()
    );

    // webrtc-stats 8.21: the pair in use succeeded and is the selected one; the pairs toward
    // the candidates nobody answers at did not, whichever check list state the agent left
    // them in when it stopped checking.
    world.run_for(Duration::from_secs(5))?;
    let now = world.now;
    let answerer = world.peers[1].stats(now);
    let pairs = of_type(&answerer, "candidate-pair");
    assert!(
        pairs.len() >= 4,
        "a pair for each remote candidate the local one can reach: {pairs:#?}"
    );
    let selected = &one(&answerer, "transport")["selectedCandidatePairId"];
    for pair in &pairs {
        let reachable = by_id(&answerer, &pair["remoteCandidateId"])["port"] == 5000;
        assert_eq!(pair["id"] == *selected, reachable, "{pair}");
        if reachable {
            assert_eq!(pair["state"], "succeeded", "{pair}");
            assert_eq!(pair["nominated"], true, "{pair}");
        } else {
            let state = pair["state"].as_str().expect("a state");
            assert!(
                ["frozen", "waiting", "in-progress", "failed"].contains(&state),
                "{pair}"
            );
            assert_eq!(pair["nominated"], false, "{pair}");
            assert_eq!(u(pair, "responsesReceived"), 0, "{pair}");
            assert_eq!(u(pair, "packetsSent"), 0, "{pair}");
            assert!(!has(pair, "currentRoundTripTime"), "{pair}");
        }
    }
    Ok(())
}

/// webrtc-stats 8.1: an RTP stream's objects are not deleted "when the transceiver goes
/// inactive"; the stream is still configured, it only stops sending.
#[test]
fn an_inactive_transceiver_keeps_its_stream_objects() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, 1, 60, 0)?;
    world.run_for(Duration::from_millis(1200))?;
    let now = world.now;
    let before = [world.peers[0].stats(now), world.peers[1].stats(now)];

    let transceiver = world.transceiver;
    world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)
        .expect("the change is accepted");
    world.negotiate()?;
    world.run_for(Duration::from_secs(3))?;
    let now = world.now;
    let after = [world.peers[0].stats(now), world.peers[1].stats(now)];

    for (typ, i) in [
        ("outbound-rtp", 0),
        ("remote-inbound-rtp", 0),
        ("inbound-rtp", 1),
        ("remote-outbound-rtp", 1),
    ] {
        assert_eq!(
            stream(&after[i], typ, ssrc)["id"],
            stream(&before[i], typ, ssrc)["id"],
            "the {typ} object is the one from before the transceiver went inactive"
        );
    }
    assert_eq!(
        u(stream(&after[0], "outbound-rtp", ssrc), "packetsSent"),
        60
    );
    assert_eq!(
        u(stream(&after[1], "inbound-rtp", ssrc), "packetsReceived"),
        60
    );
    Ok(())
}

/// webrtc-stats 7.1: at an ICE restart the candidate pairs of the old generation go, and
/// with them the candidates no pair names any more; 8.17: the transport reports the new
/// local username fragment, and the newly selected pair as one more change.
#[test]
fn an_ice_restart_replaces_the_pairs_the_candidates_and_the_username_fragment() -> Result<()> {
    let (mut world, sender) = World::connected(VIDEO)?;
    world.send_media(sender, 1, 20, 0)?;
    let now = world.now;
    let before = [world.peers[0].stats(now), world.peers[1].stats(now)];
    let ufrag = |world: &World, i: usize| {
        sdp_attribute(
            &world.peers[i]
                .pc
                .local_description()
                .expect("a description")
                .sdp,
            "ice-ufrag",
        )
    };
    let old_ufrag = [ufrag(&world, 0), ufrag(&world, 1)];

    world.peers[0].pc.restart_ice();
    world.negotiate()?;
    world.trickle(true)?;
    world.run_for(Duration::from_secs(5))?;
    world.send_media(sender, 21, 20, 0)?;
    let now = world.now;

    for i in 0..2 {
        let after = world.peers[i].stats(now);
        let new_ufrag = ufrag(&world, i);
        assert_ne!(new_ufrag, old_ufrag[i], "peer {i} restarted ICE");
        let transport = one(&after, "transport");
        assert_eq!(transport["iceLocalUsernameFragment"], new_ufrag.as_str());
        assert_eq!(
            transport["id"],
            one(&before[i], "transport")["id"],
            "the transport is the same object"
        );
        assert_eq!(u(transport, "selectedCandidatePairChanges"), 2);

        let old_pair = one(&before[i], "candidate-pair");
        let pairs = of_type(&after, "candidate-pair");
        assert_eq!(pairs.len(), 1, "peer {i}: {pairs:#?}");
        assert_ne!(
            pairs[0]["id"], old_pair["id"],
            "a pair of the new generation"
        );
        assert_eq!(pairs[0]["id"], transport["selectedCandidatePairId"]);
        assert_eq!(pairs[0]["state"], "succeeded");

        // The remote candidates of the old generation are in no pair any more: deleted.
        let remote = of_type(&after, "remote-candidate");
        assert_eq!(remote.len(), 1, "peer {i}: {remote:#?}");
        assert_ne!(remote[0]["id"], old_pair["remoteCandidateId"]);
        assert_eq!(remote[0]["id"], pairs[0]["remoteCandidateId"]);
        assert_eq!(
            remote[0]["usernameFragment"],
            ufrag(&world, 1 - i).as_str(),
            "the remote candidate is of the new generation: {}",
            remote[0]
        );
        // And every candidate still reported is one a pair names.
        for candidate in of_type(&after, "local-candidate") {
            assert_eq!(candidate["id"], pairs[0]["localCandidateId"], "peer {i}");
        }
    }
    Ok(())
}

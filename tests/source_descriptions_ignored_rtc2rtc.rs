//! RFC 5576 section 9 (backward compatibility): "endpoints MUST be prepared that recipients of
//! their RTP media session may not understand their explicit source descriptions", and "In
//! some cases (such as RTP Retransmission [RFC4588]), this may constrain some choices about the
//! bitstreams that are transmitted."
//!
//! Two `rtci` peer connections in virtual time. The sender has two video sections with the same
//! payload types (VP8 96, RTX 97), so nothing but the stream's own identifiers says which section
//! a packet belongs to: one track of one encoding with RTX, and one simulcast track of two
//! layers, each with RTX. It describes every SSRC (`a=ssrc` lines, `a=ssrc-group:FID`, also for
//! the simulcast layers). The receiver is handed the offer with every `a=ssrc` and
//! `a=ssrc-group` line removed, as a recipient that does not understand them reads it. It still
//! binds every stream to its section and its layer, and every RTX stream to the stream it
//! repairs: the sender's MID, RtpStreamId and RepairedRtpStreamId (RFC 9143 section 15, RFC
//! 8852), in its RTP and its RTCP SDES, are what the receiver goes by. One packet of every
//! stream is lost and comes back over its RTX stream.

use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_simulcast_extension_headers, register_default_interceptors,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const FIRST_SEQ: u16 = 7000;

/// The streams of the sender: (track, rid, media SSRC, RTX SSRC). The first track has one
/// encoding (no rid), the second two simulcast layers.
const STREAMS: [(usize, &str, u32, u32); 3] = [
    (0, "", 0x0576_0000, 0x0576_0100),
    (1, "lo", 0x0576_0010, 0x0576_0110),
    (1, "hi", 0x0576_0011, 0x0576_0111),
];

fn codec(mime_type: &str, sdp_fmtp_line: &str, rtcp_feedback: Vec<RTCPFeedback>) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback,
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The (SSRC, sequence number) of every RTP packet `poll_read` yielded.
    read_rtp: HashSet<(u32, u16)>,
    /// The SSRC, rid and receiver of every stream `OnTrack(OnOpen)` announced.
    opened: Vec<(u32, Option<String>, RTCRtpReceiverId)>,
    /// The SSRCs `OnUnassociatedRtpDiscarded` reported.
    discarded: Vec<u32>,
}

impl Peer {
    /// VP8 with RTX and NACK, the default interceptors and the simulcast header extensions
    /// (MID, RtpStreamId, RepairedRtpStreamId). The sender describes its simulcast layers'
    /// SSRCs too.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(
                    MIME_TYPE_VP8,
                    "",
                    vec![RTCPFeedback {
                        typ: "nack".to_owned(),
                        parameter: "".to_owned(),
                    }],
                ),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_RTX, &format!("apt={VP8_PT}"), vec![]),
                payload_type: RTX_PT,
            },
            RtpCodecKind::Video,
        )?;
        configure_simulcast_extension_headers(&mut media_engine)?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_write_ssrc_attributes_for_simulcast(true)
                    .build(),
            )
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read_rtp: HashSet::new(),
            opened: Vec::new(),
            discarded: Vec::new(),
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

/// The SSRC and sequence number of an SRTP packet on the wire, or `None` for anything else
/// (RFC 5761 section 4: RTCP packet types are 192 to 223).
fn wire_rtp(datagram: &[u8]) -> Option<(u32, u16)> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[2], datagram[3]]);
    let ssrc = u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]);
    Some((ssrc, seq))
}

/// `sdp` without its `a=ssrc` and `a=ssrc-group` lines: what a recipient that does not
/// understand source descriptions makes of it.
fn without_source_descriptions(sdp: &str) -> String {
    sdp.split_inclusive('\n')
        .filter(|line| !line.starts_with("a=ssrc:") && !line.starts_with("a=ssrc-group:"))
        .collect()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The sender's RTP packets (SSRC, sequence number) dropped once each.
    drop_once: HashSet<(u32, u16)>,
    /// The sender's RTP packets put on the wire, per SSRC.
    sent_by_ssrc: HashMap<u32, usize>,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
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
                if i == 0
                    && let Some(rtp) = wire_rtp(&data)
                {
                    *self.sent_by_ssrc.entry(rtp.0).or_default() += 1;
                    if self.drop_once.remove(&rtp) {
                        continue;
                    }
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
                        peer.opened.push((init.ssrc, init.rid, init.receiver_id));
                    }
                    RTCPeerConnectionEvent::OnUnassociatedRtpDiscarded(ssrc) => {
                        peer.discarded.push(ssrc);
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read_rtp
                        .insert((packet.header.ssrc, packet.header.sequence_number));
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

    /// The sender adds its two tracks and offers; the receiver is handed the offer without
    /// its source descriptions and answers; both connect. Returns the world, the sender's
    /// senders and the mids of the offer's two sections.
    fn connected() -> Result<(Self, Vec<RTCRtpSenderId>, Vec<String>)> {
        let mut world = World {
            peers: [Peer::new("10.0.5.1:5000")?, Peer::new("10.0.5.2:5000")?],
            now: Instant::now(),
            drop_once: HashSet::new(),
            sent_by_ssrc: HashMap::new(),
        };
        let mut senders = vec![];
        for track in 0..2 {
            let encodings = STREAMS
                .iter()
                .filter(|(t, ..)| *t == track)
                .map(|(_, rid, ssrc, rtx)| RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        rid: (*rid).to_owned(),
                        ssrc: Some(*ssrc),
                        rtx: Some(RTCRtpRtxParameters { ssrc: *rtx }),
                        ..Default::default()
                    },
                    active: true,
                    ..Default::default()
                })
                .collect();
            let track = MediaStreamTrack::new(
                "described".to_owned(),
                format!("video-{track}"),
                format!("video {track}"),
                RtpCodecKind::Video,
                encodings,
            );
            senders.push(world.peers[0].pc.add_track(track)?);
        }

        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        for (_, _, ssrc, rtx) in STREAMS {
            ensure!(
                offer.sdp.contains(&format!("a=ssrc:{ssrc} ")),
                "the offer describes ssrc {ssrc}: {}",
                offer.sdp
            );
            ensure!(
                offer
                    .sdp
                    .contains(&format!("a=ssrc-group:FID {ssrc} {rtx}")),
                "the offer pairs {ssrc} with its RTX ssrc {rtx}: {}",
                offer.sdp
            );
        }
        let mids: Vec<String> = offer
            .sdp
            .lines()
            .filter_map(|line| line.strip_prefix("a=mid:"))
            .map(|mid| mid.trim().to_owned())
            .collect();
        ensure!(mids.len() == 2, "two sections: {}", offer.sdp);
        let stripped = without_source_descriptions(&offer.sdp);
        ensure!(
            !stripped.contains("a=ssrc"),
            "nothing of the source descriptions is left: {stripped}"
        );
        world.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(stripped)?)?;
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
        Ok((world, senders, mids))
    }

    /// The negotiated VP8 payload type of `sender`.
    fn payload_type(&mut self, sender: RTCRtpSenderId) -> u8 {
        let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        sender
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
            .expect("VP8 is negotiated")
            .payload_type
    }

    /// Writes `packets` RTP packets on every stream from sequence number `first`, 20 ms apart.
    fn send_media(&mut self, senders: &[RTCRtpSenderId], first: u16, packets: u16) -> Result<()> {
        let pts: Vec<u8> = senders.iter().map(|s| self.payload_type(*s)).collect();
        for n in 0..packets {
            let now = self.now;
            let sequence_number = first.wrapping_add(n);
            for (track, _, ssrc, _) in STREAMS {
                self.peers[0]
                    .pc
                    .rtp_sender(senders[track])
                    .expect("sender")
                    .write_rtp(
                        now,
                        rtci::rtp::Packet {
                            header: rtci::rtp::header::Header {
                                version: 2,
                                payload_type: pts[track],
                                sequence_number,
                                timestamp: u32::from(sequence_number) * 1800,
                                ssrc,
                                marker: true,
                                ..Default::default()
                            },
                            payload: Bytes::from(vec![0x10u8; 200]),
                        },
                    )?;
            }
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }
}

/// RFC 5576 section 9: the receiver ignores the offer's source descriptions, and every stream
/// is received, bound to its own section (and layer), and repaired over its own RTX stream.
#[test]
fn streams_and_their_repairs_are_bound_when_the_source_descriptions_are_ignored() -> Result<()> {
    let (mut world, senders, mids) = World::connected()?;
    let lost: Vec<(u32, u16)> = STREAMS
        .iter()
        .enumerate()
        .map(|(i, (_, _, ssrc, _))| (*ssrc, FIRST_SEQ + 30 + 7 * i as u16))
        .collect();
    world.drop_once = lost.iter().copied().collect();

    world.send_media(&senders, FIRST_SEQ, 100)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert!(world.drop_once.is_empty(), "every loss happened");
    // The section each of the receiver's receivers is in.
    let mut section_of = HashMap::new();
    let transceivers: Vec<_> = world.peers[1].pc.get_transceivers().collect();
    for id in transceivers {
        let transceiver = world.peers[1].pc.rtp_transceiver(id).expect("transceiver");
        if let (Some(mid), Some(receiver)) = (transceiver.mid().clone(), transceiver.receiver()) {
            section_of.insert(receiver, mid);
        }
    }
    let receiver = &world.peers[1];
    for ((track, rid, ssrc, rtx), (_, seq)) in STREAMS.iter().zip(&lost) {
        assert!(
            receiver.read_rtp.contains(&(*ssrc, FIRST_SEQ + 50)),
            "ssrc {ssrc} (track {track}, rid {rid:?}) is received: {:?}",
            receiver
                .read_rtp
                .iter()
                .map(|(s, _)| *s)
                .collect::<HashSet<_>>()
        );
        let rid = (!rid.is_empty()).then(|| (*rid).to_owned());
        assert!(
            receiver.opened.iter().any(|(s, r, id)| *s == *ssrc
                && *r == rid
                && section_of.get(id) == Some(&mids[*track])),
            "ssrc {ssrc} opens in section {} with rid {rid:?}: {:?} (sections {section_of:?})",
            mids[*track],
            receiver.opened
        );
        assert!(
            world.sent_by_ssrc.get(rtx).copied().unwrap_or(0) > 0,
            "the loss on ssrc {ssrc} is retransmitted on its RTX ssrc {rtx}: {:?}",
            world.sent_by_ssrc
        );
        assert!(
            receiver.read_rtp.contains(&(*ssrc, *seq)),
            "the lost packet {seq} of ssrc {ssrc} comes back on its stream"
        );
    }
    assert_eq!(
        STREAMS.len(),
        receiver.opened.len(),
        "one stream opened per sent stream, none for an RTX ssrc: {:?}",
        receiver.opened
    );
    assert_eq!(
        Vec::<u32>::new(),
        receiver.discarded,
        "nothing is discarded"
    );
    Ok(())
}

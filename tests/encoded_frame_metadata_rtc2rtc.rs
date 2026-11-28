//! W3C webrtc-encoded-transform 4: the metadata of received encoded frames
//! (`RTCRtpReceiver::encoded_frame_metadata`), rtc to rtc: what the frame's packets say, and
//! what the receiver recorded as they arrived (receive time, capture time, the Dependency
//! Descriptor's frame ids).

#![allow(dead_code)]

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::codec::dependency_descriptor::{
    DEPENDENCY_DESCRIPTOR_URI, DecodeTargetIndication, DependencyDescriptorWriter,
    FrameDependencyStructure, FrameDependencyTemplate, RenderResolution,
};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_receiver::{RTCEncodedFrameMetadataKind, RTCEncodedVideoFrameType};
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::error::Error;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The RTP packets `poll_read` yielded.
    read_rtp: Vec<rtci::rtp::Packet>,
    /// The FIR entries (SSRC, sequence number) of the RTCP packets `poll_read` yielded.
    read_fir: Vec<(u32, u8)>,
    /// The events other than connection state changes.
    events: Vec<RTCPeerConnectionEvent>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        media_engine.register_header_extension(
            rtci::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability {
                uri: rtci::rtp::extension::ABS_CAPTURE_TIME_URI.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
        media_engine.register_header_extension(
            rtci::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability {
                uri: rtci::rtp::extension::CORRUPTION_DETECTION_URI.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read_rtp: Vec::new(),
            read_fir: Vec::new(),
            events: Vec::new(),
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

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear, RFC
/// 3711 section 3.1, apart from RFC 6904 elements), or `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The headers of the RTP packets the first peer put on the wire.
    wire: Vec<Header>,
    /// The SSRC `send` writes on.
    media_ssrc: Option<u32>,
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
                    && let Some(header) = wire_rtp_header(&data)
                {
                    self.wire.push(header);
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
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a peer's connection failed: {:?}", peer.states);
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                    peer.states.push(state);
                } else {
                    peer.events.push(event);
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtpPacket(_, packet) => peer.read_rtp.push(packet),
                    RTCMessage::RtcpPacket(_, packets) => {
                        for packet in packets {
                            if let Some(fir) = packet.as_any().downcast_ref::<
                                rtci::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest,
                            >() {
                                peer.read_fir
                                    .extend(fir.fir.iter().map(|e| (e.ssrc, e.sequence_number)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The headers on the wire of the stream `send` writes (not RTX, FEC or probes).
    fn media_wire(&self) -> Vec<&Header> {
        self.wire
            .iter()
            .filter(|h| Some(h.ssrc) == self.media_ssrc)
            .collect()
    }

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

    /// The first peer sends `kind`; the second answers, its answer passed through `edit`
    /// before the first applies it. Connected over host candidates.
    fn connected(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_edited(kind, |offer| offer, edit)
    }

    /// `connected`, the offer changed by `edit_offer` on its way to the receiver and the
    /// answer by `edit` on its way to the sender.
    fn connected_edited(
        kind: RtpCodecKind,
        edit_offer: impl Fn(String) -> String,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_prepared_edited(kind, edit_offer, edit, |_| {})
    }

    /// [`Self::connected`], each peer passed through `prepare` before the offer.
    fn connected_prepared(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
        prepare: impl Fn(&mut RTCPeerConnection),
    ) -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_prepared_edited(kind, |offer| offer, edit, prepare)
    }

    fn connected_prepared_edited(
        kind: RtpCodecKind,
        edit_offer: impl Fn(String) -> String,
        edit: impl Fn(String) -> String,
        prepare: impl Fn(&mut RTCPeerConnection),
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            wire: Vec::new(),
            media_ssrc: None,
        };
        for peer in world.peers.iter_mut() {
            // The tests read the header extensions on the wire: in the clear unless a test
            // asks for Cryptex (whose default policy, "negotiate", would encrypt them).
            peer.pc
                .set_rtp_header_encryption_policy(
                    rtci::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy::Disable,
                )
                .expect("before any description");
            prepare(&mut peer.pc);
        }
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
        world.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(edit_offer(offer.sdp))?)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(edit(answer.sdp))?)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// Writes a packet on the sender's stream with the given header extension elements.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16, elements: &[(u8, &[u8])]) -> Result<()> {
        let now = self.now;
        let (ssrc, pt) = {
            let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
            let parameters = sender.get_parameters();
            (
                parameters.encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
                parameters.rtp_parameters.codecs[0].payload_type,
            )
        };
        self.media_ssrc = Some(ssrc);
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        for (id, value) in elements {
            header.set_extension_upgrading(*id, Bytes::copy_from_slice(value))?;
        }
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

/// The sender's SSRC, payload type and the negotiated id of `uri`.
fn sender_stream(world: &mut World, sender: RTCRtpSenderId, uri: &str) -> (u32, u8, u8) {
    let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
    let parameters = sender.get_parameters();
    let id = parameters
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == uri)
        .map(|e| e.id as u8)
        .unwrap_or_else(|| panic!("{uri} is negotiated"));
    (
        parameters.encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC"),
        parameters.rtp_parameters.codecs[0].payload_type,
        id,
    )
}

fn receiver_metadata(
    world: &mut World,
    packets: &[rtci::rtp::Packet],
) -> Result<RTCEncodedFrameMetadataKind, Error> {
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .encoded_frame_metadata(packets)
}

/// The packets the second peer read with RTP timestamp `timestamp`.
fn read_frame(world: &World, timestamp: u32) -> Vec<rtci::rtp::Packet> {
    world.peers[1]
        .read_rtp
        .iter()
        .filter(|p| p.header.timestamp == timestamp)
        .cloned()
        .collect()
}

fn l1t3() -> FrameDependencyStructure {
    let template = |temporal_id, fdiffs: &[u16], chain: u8, dtis: &str| FrameDependencyTemplate {
        spatial_id: 0,
        temporal_id,
        dtis: DecodeTargetIndication::from_symbols(dtis).expect("indications"),
        fdiffs: fdiffs.to_vec(),
        chain_fdiffs: vec![chain],
    };
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 3,
        num_chains: 1,
        decode_target_protected_by: vec![0, 0, 0],
        resolutions: vec![RenderResolution {
            width: 640,
            height: 360,
        }],
        templates: vec![
            template(0, &[], 0, "SSS"),
            template(0, &[4], 4, "SSS"),
            template(1, &[2], 2, "SD-"),
            template(2, &[1], 1, "D--"),
            template(2, &[1], 3, "D--"),
        ],
    }
}

/// A VP8 payload: descriptor (S at the start of the frame), then a key frame header of
/// `size` or a delta frame tag.
fn vp8_payload(start: bool, key: Option<(u16, u16)>) -> Bytes {
    let mut payload = vec![if start { 0x10 } else { 0x00 }];
    match key {
        Some((width, height)) if start => {
            payload.extend([0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a]);
            payload.extend(width.to_le_bytes());
            payload.extend(height.to_le_bytes());
        }
        _ if start => payload.extend([0x11, 0x02, 0x00]),
        _ => {}
    }
    payload.extend([0x55u8; 60]);
    Bytes::from(payload)
}

/// webrtc-encoded-transform 4.1, 4.2, 4.3 over a connection: a VP8 key frame in two packets
/// and a delta frame, with the Dependency Descriptor and `abs-capture-time`. The key frame's
/// metadata has the SSRC, payload type, RTP timestamp, `video/VP8`, its receive time (its
/// last packet's arrival), the capture time and offset, frame id = the descriptor's frame
/// number, no dependencies, the descriptor's layers and resolution and type key; the delta
/// frame (with CSRCs) refers to the key frame's id, keeps the stream's size, reads its CSRCs,
/// an interpolated capture time, and is a delta frame.
#[test]
fn received_video_frames_carry_their_metadata() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, dd_id) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let structure = l1t3();
    let mut writer = DependencyDescriptorWriter::new(structure.clone(), 41)?;
    let key = writer.next_frame(&structure.templates[0], true)?;
    let delta = writer.next_frame(&structure.templates[3], false)?;

    let capture_ntp: u64 = (1000u64 << 32) | (1u64 << 30);
    let offset: i64 = -(1 << 31);
    let packet = |seq: u16, timestamp: u32, marker: bool, dd: Bytes, payload: Bytes| {
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp,
            ssrc,
            marker,
            ..Default::default()
        };
        header
            .set_extension_upgrading(dd_id, dd)
            .expect("an element");
        rtci::rtp::Packet { header, payload }
    };

    let sent_at = world.now;
    let first = packet(
        1,
        90_000,
        false,
        key.packet(true, false)?,
        vp8_payload(true, Some((320, 180))),
    );
    let second = packet(
        2,
        90_000,
        true,
        key.packet(false, true)?,
        vp8_payload(false, None),
    );
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_capture_time(sent_at, first, capture_ntp, Some(offset))?;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(sent_at, second)?;
    world.pump()?;
    world.run_until(sent_at + Duration::from_millis(50))?;

    let mut third = packet(
        3,
        93_000,
        true,
        delta.packet(true, true)?,
        vp8_payload(true, None),
    );
    third.header.csrc = vec![11, 12];
    let delta_sent_at = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(delta_sent_at, third)?;
    world.pump()?;
    world.run_until(delta_sent_at + Duration::from_millis(100))?;

    let key_packets = read_frame(&world, 90_000);
    assert_eq!(key_packets.len(), 2, "the key frame's packets were read");
    let RTCEncodedFrameMetadataKind::Video(key_meta) = receiver_metadata(&mut world, &key_packets)?
    else {
        bail!("a video frame");
    };
    assert_eq!(key_meta.frame.synchronization_source, ssrc);
    assert_eq!(key_meta.frame.payload_type, pt);
    assert_eq!(key_meta.frame.rtp_timestamp, 90_000);
    assert_eq!(key_meta.frame.mime_type.to_ascii_lowercase(), "video/vp8");
    assert!(key_meta.frame.contributing_sources.is_empty());
    let received = key_meta.frame.receive_time.expect("a receive time");
    assert!(received >= sent_at && received <= delta_sent_at);
    assert_eq!(key_meta.frame.capture_time, Some(1_000_250.0));
    assert_eq!(key_meta.frame.sender_capture_time_offset, Some(-500.0));
    assert_eq!(key_meta.frame_type, RTCEncodedVideoFrameType::Key);
    assert_eq!(key_meta.frame_id, Some(41));
    assert!(key_meta.dependencies.is_empty());
    assert_eq!(
        (key_meta.width, key_meta.height),
        (Some(640), Some(360)),
        "the descriptor's resolution"
    );
    assert_eq!(
        (key_meta.spatial_index, key_meta.temporal_index),
        (Some(0), Some(0))
    );

    let delta_packets = read_frame(&world, 93_000);
    let RTCEncodedFrameMetadataKind::Video(delta_meta) =
        receiver_metadata(&mut world, &delta_packets)?
    else {
        bail!("a video frame");
    };
    assert_eq!(delta_meta.frame_type, RTCEncodedVideoFrameType::Delta);
    assert_eq!(delta_meta.frame_id, Some(42));
    assert_eq!(delta_meta.dependencies, vec![41]);
    assert_eq!(delta_meta.temporal_index, Some(2));
    assert_eq!(
        (delta_meta.width, delta_meta.height),
        (Some(640), Some(360))
    );
    assert_eq!(delta_meta.frame.contributing_sources, vec![11, 12]);
    // 3000 ticks at 90 kHz after the stamped frame, the offset kept.
    let interpolated = delta_meta.frame.capture_time.expect("a capture time");
    assert!((interpolated - (1_000_250.0 + 3000.0 / 90.0)).abs() < 1e-6);
    assert_eq!(delta_meta.frame.sender_capture_time_offset, Some(-500.0));
    assert!(delta_meta.frame.receive_time.expect("a receive time") >= delta_sent_at);

    // Not one frame: refused.
    let mixed = [key_packets[0].clone(), delta_packets[0].clone()];
    assert!(matches!(
        receiver_metadata(&mut world, &mixed),
        Err(Error::TypeError(_))
    ));
    assert!(matches!(
        receiver_metadata(&mut world, &[]),
        Err(Error::TypeError(_))
    ));
    Ok(())
}

/// webrtc-encoded-transform 4.4: an audio frame's `sequenceNumber`, and its `audioLevel`
/// converted from the RFC 6464 level of its packet (10^(-level/20), 127 is 0); absent when
/// the packet has no level.
#[test]
fn received_audio_frames_carry_their_sequence_number_and_level() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let (ssrc, pt, level_id) = sender_stream(&mut world, sender, AUDIO_LEVEL);
    let packet = |seq: u16, level: Option<u8>| {
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        if let Some(level) = level {
            header
                .set_extension_upgrading(level_id, Bytes::from(vec![0x80 | level]))
                .expect("an element");
        }
        rtci::rtp::Packet {
            header,
            payload: Bytes::from(vec![0x10u8; 80]),
        }
    };
    for (seq, level) in [(10u16, Some(20u8)), (11, Some(127)), (12, None)] {
        let now = world.now;
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(now, packet(seq, level))?;
        world.pump()?;
        world.run_until(now + Duration::from_millis(30))?;
    }
    let mut levels = Vec::new();
    for seq in [10u32, 11, 12] {
        let frame = read_frame(&world, seq * 960);
        assert_eq!(frame.len(), 1, "packet {seq} was read");
        let RTCEncodedFrameMetadataKind::Audio(meta) = receiver_metadata(&mut world, &frame)?
        else {
            bail!("an audio frame");
        };
        assert_eq!(meta.sequence_number, Some(seq as u16));
        assert_eq!(meta.frame.synchronization_source, ssrc);
        assert!(
            meta.frame
                .mime_type
                .to_ascii_lowercase()
                .starts_with("audio/")
        );
        assert!(meta.frame.receive_time.is_some());
        levels.push(meta.audio_level);
    }
    assert!(
        (levels[0].expect("a level") - 0.1).abs() < 1e-12,
        "10^(-20/20)"
    );
    assert_eq!(levels[1], Some(0.0), "127 is silence");
    assert_eq!(levels[2], None, "no extension, no level");

    // 4.4.1, a locally sourced frame: its source's level, written as the RFC 6464 element
    // (0.5 is 6 dBov), reaches the peer's metadata and its synchronization source with the
    // voice activity flag.
    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp_with_audio_level(now, packet(13, None), 0.5, Some(true))?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(30))?;
    let frame = read_frame(&world, 13 * 960);
    let RTCEncodedFrameMetadataKind::Audio(meta) = receiver_metadata(&mut world, &frame)? else {
        bail!("an audio frame");
    };
    let expected = 10f64.powf(-6.0 / 20.0);
    assert!((meta.audio_level.expect("a level") - expected).abs() < 1e-12);
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    let source = world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .get_synchronization_sources()
        .find(|s| s.source == ssrc)
        .map(|s| s.voice_activity_flag);
    assert_eq!(source, Some(Some(true)));
    Ok(())
}

fn key_frame_requests(peer: &mut Peer) -> Vec<(RTCRtpSenderId, Option<String>)> {
    std::mem::take(&mut peer.events)
        .into_iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnKeyFrameRequest { sender, rid } => Some((sender, rid)),
            _ => None,
        })
        .collect()
}

fn request_key_frame(world: &mut World) -> Result<bool, Error> {
    let now = world.now;
    let receiver = world.peers[1]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .send_key_frame_request(now)
}

/// webrtc-encoded-transform 6.5 "send request key frame" and 6.4 `keyframerequest`: a video
/// receiver that does not receive sends nothing; one that does, a Full Intra Request for the
/// stream,
/// with a sequence number one more per request (RFC 5104 4.3.1.2), which reaches the sender's
/// peer as the FIR and as a key frame request for its sender (no RID: not simulcast).
#[test]
fn a_key_frame_request_reaches_the_sender_as_a_fir_and_an_event() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    // The sending peer's own receiver does not receive (its transceiver is sendonly): the
    // request resolves with nothing sent.
    let now = world.now;
    let own_receiver = world.peers[0]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    assert!(
        !world.peers[0]
            .pc
            .rtp_receiver(own_receiver)
            .expect("receiver")
            .send_key_frame_request(now)?,
        "not receiving"
    );
    world.run_until(world.now + Duration::from_millis(50))?;
    assert!(world.peers[1].read_fir.is_empty());

    let (ssrc, pt, _) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: pt,
                    sequence_number: 1,
                    timestamp: 1,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: vp8_payload(true, Some((320, 180))),
            },
        )?;
    world.pump()?;
    world.run_until(now + Duration::from_millis(50))?;
    let _ = key_frame_requests(&mut world.peers[0]);

    // RFC 4585 section 3.5.2: after an early RTCP packet the next one waits for the regular
    // RTCP interval, so each request is given time to go out.
    assert!(request_key_frame(&mut world)?);
    world.pump()?;
    world.run_until(world.now + Duration::from_secs(3))?;
    assert!(request_key_frame(&mut world)?);
    world.pump()?;
    world.run_until(world.now + Duration::from_secs(3))?;
    let firs: Vec<(u32, u8)> = world.peers[0]
        .read_fir
        .iter()
        .copied()
        .filter(|(s, _)| *s == ssrc)
        .collect();
    assert_eq!(firs.len(), 2, "two requests: {:?}", world.peers[0].read_fir);
    assert_eq!(
        firs[1].1,
        firs[0].1.wrapping_add(1),
        "a new request, a new number"
    );
    assert_eq!(
        key_frame_requests(&mut world.peers[0]),
        vec![(sender, None), (sender, None)]
    );
    Ok(())
}

/// webrtc-encoded-transform 6.5: on an audio receiver the request is an InvalidStateError.
#[test]
fn an_audio_receiver_cannot_request_a_key_frame() -> Result<()> {
    let (mut world, _) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    assert!(matches!(
        request_key_frame(&mut world),
        Err(Error::InvalidStateError)
    ));
    Ok(())
}

/// webrtc-encoded-transform 4.3.2: "For SVC, each spatial layer is transformed separately".
/// The sender payloads each spatial layer's frame of a VP9 picture on its own
/// (`Vp9Payloader::payload_layer_frame`); the receiver gives each layer's packets their own
/// metadata: the layer's spatial index and the scalability structure's size for that layer,
/// one RTP timestamp for the picture.
#[test]
fn each_spatial_layer_of_an_svc_picture_is_its_own_frame() -> Result<()> {
    use rtci::rtp::codec::vp9::{Vp9FrameInfo, Vp9Packet, Vp9Payloader, Vp9ScalabilityStructure};
    use rtci::rtp::packetizer::Depacketizer;
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, _, _) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let vp9_pt = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        sender
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("video/VP9"))
            .map(|c| c.payload_type)
            .expect("VP9 is negotiated")
    };
    let mut payloader = Vp9Payloader::default();
    payloader.set_scalability_structure(Some(Vp9ScalabilityStructure {
        spatial_layers: 2,
        resolutions: vec![(320, 180), (640, 360)],
        picture_group: vec![],
    }))?;
    let mut payloads = Vec::new();
    for layer in 0..2u8 {
        let info = Vp9FrameInfo {
            spatial_id: layer,
            inter_layer_dependency: layer == 1,
            end_of_picture: layer == 1,
            key_frame: Some(layer == 0),
            inter_picture_predicted: Some(false),
            ..Default::default()
        };
        let frame = Bytes::from(vec![0x80 | layer; 300]);
        for payload in payloader.payload_layer_frame(1200, &frame, &info)? {
            payloads.push(payload);
        }
    }
    let now = world.now;
    let count = payloads.len();
    for (i, payload) in payloads.into_iter().enumerate() {
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: vp9_pt,
                        sequence_number: 100 + i as u16,
                        timestamp: 45_000,
                        ssrc,
                        marker: i + 1 == count,
                        ..Default::default()
                    },
                    payload,
                },
            )?;
    }
    world.pump()?;
    world.run_until(now + Duration::from_millis(50))?;

    let picture = read_frame(&world, 45_000);
    assert_eq!(picture.len(), count, "the picture's packets were read");
    let layer_of = |packet: &rtci::rtp::Packet| {
        let mut descriptor = Vp9Packet::default();
        descriptor
            .depacketize(&packet.payload)
            .expect("a VP9 payload");
        descriptor.sid
    };
    let mut seen = Vec::new();
    for layer in 0..2u8 {
        let packets: Vec<_> = picture
            .iter()
            .filter(|p| layer_of(p) == layer)
            .cloned()
            .collect();
        assert!(!packets.is_empty(), "layer {layer} has packets");
        let RTCEncodedFrameMetadataKind::Video(meta) = receiver_metadata(&mut world, &packets)?
        else {
            bail!("a video frame");
        };
        seen.push((
            meta.spatial_index,
            meta.width,
            meta.height,
            meta.frame.rtp_timestamp,
        ));
    }
    assert_eq!(
        seen,
        vec![
            (Some(0), Some(320), Some(180), 45_000),
            (Some(1), Some(640), Some(360), 45_000),
        ]
    );
    Ok(())
}

/// webrtc-extensions 15 "remote capture timestamp": a received frame's capture time
/// translated to the receiver's clock by the stream's RTCP sender reports (RFC 3550 section
/// 6.4.1). Frames the sender wrote at 30 frame/s for three seconds, with RTP timestamps on
/// the 90 kHz clock that run with the sender's clock: once a sender report has arrived, each
/// frame's remote capture time is the instant it was written (the link has no delay), within
/// a few milliseconds; before the first report there is none.
#[test]
fn a_frames_remote_capture_time_is_on_the_receivers_clock() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, _) = sender_stream(&mut world, sender, rtci::rtp::extension::SDES_MID_URI);
    let start = world.now;
    let base = 90_000u32;
    let mut written = vec![];
    for frame in 0..90u32 {
        let now = world.now;
        let timestamp =
            base.wrapping_add((now.duration_since(start).as_secs_f64() * 90_000.0) as u32);
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: 500 + frame as u16,
                        timestamp,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: vp8_payload(true, None),
                },
            )?;
        written.push((timestamp, now));
        world.pump()?;
        world.run_until(now + Duration::from_micros(33_333))?;
    }
    let mut before_report = 0;
    let mut placed = 0;
    for (timestamp, at) in written {
        let packets = read_frame(&world, timestamp);
        if packets.is_empty() {
            continue;
        }
        let RTCEncodedFrameMetadataKind::Video(video) = receiver_metadata(&mut world, &packets)?
        else {
            panic!("a video frame");
        };
        match video.frame.remote_capture_time {
            None => before_report += 1,
            Some(remote) => {
                let error = if remote > at {
                    remote - at
                } else {
                    at - remote
                };
                assert!(
                    error < Duration::from_millis(5),
                    "frame {timestamp}: {error:?} off"
                );
                placed += 1;
            }
        }
    }
    assert!(
        placed > 30,
        "{placed} frames placed, {before_report} before a report"
    );
    Ok(())
}

/// W3C webrtc-stats 8.5 `corruptionMeasurements`: "If the corruption-detection header
/// extension is present in the RTP packets, corruption probability measurements MUST be
/// present." Before a packet carries it the corruption members do not exist; from the first
/// that does they exist (0 until the application's decoder measures), the frame's metadata
/// carries the parsed message the decoder compares with its frame, and what the application
/// then measures is what the report shows.
#[test]
fn the_corruption_detection_extension_makes_the_corruption_measurements_present() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, _, id) = sender_stream(
        &mut world,
        sender,
        rtci::rtp::extension::CORRUPTION_DETECTION_URI,
    );
    let inbound = |world: &mut World| {
        let now = world.now;
        world.peers[1]
            .pc
            .get_stats(now, rtci::statistics::StatsSelector::None)
            .inbound_rtp_streams()
            .find(|s| s.received_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
            .map(|s| {
                (
                    s.corruption_measurements,
                    s.total_corruption_probability,
                    s.total_squared_corruption_probability,
                )
            })
    };

    world.send(sender, 1, &[])?;
    assert_eq!(
        inbound(&mut world),
        Some((None, None, None)),
        "no extension yet: the members do not exist"
    );

    // B set, sequence index 3, std dev 128, Y err 2, UV err 1, three samples.
    let element = [0x80 | 3, 128, 0x21, 40, 50, 60];
    world.send(sender, 2, &[(id, &element)])?;
    // The pacer may hold the packet past `send`'s own 20 ms: until it was read.
    let deadline = world.now + Duration::from_secs(2);
    while !world.peers[1]
        .read_rtp
        .iter()
        .any(|p| p.header.sequence_number == 2)
        && world.now < deadline
    {
        let next = world.now + Duration::from_millis(10);
        world.run_until(next)?;
    }
    assert_eq!(inbound(&mut world), Some((Some(0), Some(0.0), Some(0.0))));

    let frame = read_frame(&world, 2 * 960);
    let RTCEncodedFrameMetadataKind::Video(metadata) = receiver_metadata(&mut world, &frame)?
    else {
        bail!("a video frame");
    };
    let message = metadata.corruption_detection.expect("the frame's message");
    assert!(message.interpret_sequence_index_as_most_significant_bits);
    assert_eq!(message.sequence_index, 3);
    assert_eq!(message.std_dev, 128);
    assert_eq!(
        (message.luma_error_threshold, message.chroma_error_threshold),
        (2, 1)
    );
    assert_eq!(message.sample_values, vec![40, 50, 60]);

    assert!(world.peers[1].pc.update_decoder_stats(
        ssrc,
        rtci::statistics::DecoderStatsUpdate {
            corruption_measurements: Some(1),
            total_corruption_probability: Some(0.25),
            total_squared_corruption_probability: Some(0.0625),
            ..Default::default()
        }
    ));
    assert_eq!(
        inbound(&mut world),
        Some((Some(1), Some(0.25), Some(0.0625)))
    );
    Ok(())
}

/// The answer with `params` on the fmtp line of every format of `codec` (`"vp8"`), one added
/// where a format has none.
fn with_codec_fmtp(sdp: String, codec: &str, params: &str) -> String {
    let pts: Vec<String> = sdp
        .lines()
        .filter_map(|l| {
            l.strip_prefix("a=rtpmap:")
                .and_then(|r| r.split_once(' '))
                .filter(|(_, enc)| enc.to_ascii_lowercase().starts_with(&format!("{codec}/")))
                .map(|(pt, _)| pt.to_owned())
        })
        .collect();
    assert!(!pts.is_empty(), "a {codec} format");
    let mut out = String::new();
    for line in sdp.split_inclusive("\r\n") {
        let pt = pts.iter().find(|pt| {
            line.starts_with(&format!("a=fmtp:{pt} "))
                || line
                    .to_ascii_lowercase()
                    .starts_with(&format!("a=rtpmap:{pt} {codec}/"))
        });
        match pt {
            Some(pt) if line.starts_with("a=fmtp:") => {
                out.push_str(&line.replacen(
                    &format!("a=fmtp:{pt} "),
                    &format!("a=fmtp:{pt} {params};"),
                    1,
                ));
            }
            Some(pt) => {
                out.push_str(line);
                if !sdp.contains(&format!("a=fmtp:{pt} ")) {
                    out.push_str(&format!("a=fmtp:{pt} {params}\r\n"));
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

fn with_vp8_fmtp(sdp: String, params: &str) -> String {
    with_codec_fmtp(sdp, "vp8", params)
}

/// Writes one VP8 frame of two packets at `timestamp` (a key frame of `key` size, or a delta
/// frame) on the sender's stream, sequence numbers from `seq`.
fn send_vp8_frame(
    world: &mut World,
    sender: RTCRtpSenderId,
    seq: u16,
    timestamp: u32,
    key: Option<(u16, u16)>,
) -> Result<()> {
    let (ssrc, pt, _) = sender_stream(world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let now = world.now;
    for (i, payload) in [vp8_payload(true, key), vp8_payload(false, None)]
        .into_iter()
        .enumerate()
    {
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: seq + i as u16,
                        timestamp,
                        ssrc,
                        marker: i == 1,
                        ..Default::default()
                    },
                    payload: payload.clone(),
                },
            )?;
    }
    world.media_ssrc = Some(ssrc);
    world.pump()?;
    Ok(())
}

/// RFC 7741 section 6.1: `max-fs` is the largest frame (in 16 by 16 macroblocks) the receiver
/// can decode, and "a sender MUST NOT send ... frames of a larger size". With `max-fs=300` in
/// the answer, a 640x480 key frame (1200 macroblocks) and the delta frame after it stay off
/// the wire; the 320x180 key frame (240) that follows, and its delta frame, go.
#[test]
fn frames_larger_than_the_receivers_max_fs_are_not_sent() -> Result<()> {
    let (mut world, sender) =
        World::connected(RtpCodecKind::Video, |sdp| with_vp8_fmtp(sdp, "max-fs=300"))?;
    send_vp8_frame(&mut world, sender, 1, 3000, Some((640, 480)))?;
    send_vp8_frame(&mut world, sender, 3, 6000, None)?;
    send_vp8_frame(&mut world, sender, 5, 9000, Some((320, 180)))?;
    send_vp8_frame(&mut world, sender, 7, 12000, None)?;
    world.run_until(world.now + Duration::from_millis(200))?;
    let timestamps: Vec<u32> = world.media_wire().iter().map(|h| h.timestamp).collect();
    assert_eq!(timestamps, vec![9000, 9000, 12000, 12000], "{timestamps:?}");
    Ok(())
}

/// RFC 7741 section 6.1: `max-fr` is the highest frame rate the receiver can decode, and "a
/// sender MUST NOT send frames at a higher rate". Thirty frames a second written for one
/// second against `max-fr=10`: ten frames go, a third of the frames written.
#[test]
fn frames_above_the_receivers_max_fr_are_not_sent() -> Result<()> {
    let (mut world, sender) =
        World::connected(RtpCodecKind::Video, |sdp| with_vp8_fmtp(sdp, "max-fr=10"))?;
    for frame in 0..30u32 {
        let key = (frame == 0).then_some((320, 180));
        send_vp8_frame(
            &mut world,
            sender,
            1 + 2 * frame as u16,
            3000 * (frame + 1),
            key,
        )?;
        world.run_until(world.now + Duration::from_millis(33))?;
    }
    world.run_until(world.now + Duration::from_millis(200))?;
    let mut frames: Vec<u32> = world.media_wire().iter().map(|h| h.timestamp).collect();
    frames.dedup();
    assert_eq!(frames.len(), 10, "{frames:?}");
    Ok(())
}

/// The capture time a receiver gives the first frame of a stream, written as soon as the
/// connection is up: (`Some` and its error against the instant it was written) or `None`.
fn first_frame_capture_time(edit: impl Fn(String) -> String) -> Result<Option<Duration>> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, edit)?;
    let (ssrc, pt, _) = sender_stream(&mut world, sender, rtci::rtp::extension::SDES_MID_URI);
    let now = world.now;
    world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .write_rtp(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: pt,
                    sequence_number: 1,
                    timestamp: 90_000,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: vp8_payload(true, Some((320, 180))),
            },
        )?;
    world.pump()?;
    let packets = read_frame(&world, 90_000);
    assert!(!packets.is_empty(), "the frame arrived");
    let RTCEncodedFrameMetadataKind::Video(video) = receiver_metadata(&mut world, &packets)? else {
        panic!("a video frame");
    };
    Ok(video.frame.remote_capture_time.map(|remote| {
        if remote > now {
            remote - now
        } else {
            now - remote
        }
    }))
}

/// RFC 6051 section 3.3 (RFC 8834 section 5.2.1 recommends it): with `ntp-64` negotiated, the
/// default, the first packets of a stream carry the sender's NTP timestamp, and the receiver
/// takes it "in exactly the same way as if an additional RTCP SR packet had been received":
/// the very first frame, which no sender report can have described yet, has its capture time
/// on the receiver's clock. With the extension left out of the answer it has none.
#[test]
fn the_first_frame_is_placed_by_its_in_band_ntp_timestamp_before_any_sender_report() -> Result<()> {
    let error = first_frame_capture_time(|sdp| sdp)?.expect("placed by ntp-64");
    assert!(error < Duration::from_millis(5), "{error:?} off");
    let without = first_frame_capture_time(|sdp| {
        sdp.lines()
            .filter(|line| !line.contains(rtci::rtp::extension::NTP_64_URI))
            .map(|line| format!("{line}\r\n"))
            .collect()
    })?;
    assert_eq!(None, without, "nothing places it without the extension");
    Ok(())
}

/// A VP9 packet that is a whole frame: the descriptor (B, E; P on a delta frame), and on a
/// key picture the scalability structure with one spatial layer of `key` size (RFC 9628
/// sections 4.2, 4.2.1).
fn vp9_payload(key: Option<(u16, u16)>) -> Bytes {
    let mut payload = match key {
        Some((width, height)) => {
            let mut p = vec![0x0E, 0x10];
            p.extend(width.to_be_bytes());
            p.extend(height.to_be_bytes());
            p
        }
        None => vec![0x4C],
    };
    payload.extend([0x55u8; 60]);
    Bytes::from(payload)
}

/// RFC 9628 section 6: a sender "SHOULD NOT" send VP9 frames larger than the receiver's
/// `max-fs`. With `max-fs=300` in the answer, a key picture whose scalability structure says
/// 640x480 (1200 macroblocks) and the delta frame after it stay off the wire; the 320x180 key
/// picture (240) and its delta frame go.
#[test]
fn vp9_frames_larger_than_the_receivers_max_fs_are_not_sent() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| {
        with_codec_fmtp(sdp, "vp9", "max-fs=300")
    })?;
    let (ssrc, pt) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let pt = parameters
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("video/VP9"))
            .map(|c| c.payload_type)
            .expect("VP9 negotiated");
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            pt,
        )
    };
    world.media_ssrc = Some(ssrc);
    for (i, key) in [Some((640, 480)), None, Some((320, 180)), None]
        .into_iter()
        .enumerate()
    {
        let now = world.now;
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: 1 + i as u16,
                        timestamp: 3000 * (i as u32 + 1),
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: vp9_payload(key),
                },
            )?;
        world.pump()?;
    }
    world.run_until(world.now + Duration::from_millis(200))?;
    let timestamps: Vec<u32> = world.media_wire().iter().map(|h| h.timestamp).collect();
    assert_eq!(timestamps, vec![9000, 12000], "{timestamps:?}");
    Ok(())
}

/// RFC 7160 section 3.2 / 4.2 with one SSRC across clock rates (the default, as browsers
/// need): the sender writes Opus (48 kHz) for 2.6 seconds, PCMU (8 kHz) for 3.1, then Opus
/// again, its RTP timestamps going on at each change from where the old rate had reached
/// (section 4.2's `start_offset`). Read as each frame arrives, every frame's remote capture
/// time (webrtc-extensions 15, by the sender reports) is the instant it was written, within a
/// few milliseconds, in all three stretches: the sender report extrapolates its RTP timestamp
/// at the rate being sent, and the receiver places a timestamp of one rate against a report
/// taken at another across the change.
#[test]
fn the_remote_capture_time_holds_across_clock_rate_changes_on_one_ssrc() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let (ssrc, opus, pcmu) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let pt = |mime: &str| {
            parameters
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime))
                .map(|c| c.payload_type)
                .unwrap_or_else(|| panic!("{mime} negotiated"))
        };
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            pt("audio/opus"),
            pt("audio/PCMU"),
        )
    };
    let start = world.now;
    // RFC 7160 4.2: timestamp = (capture_time - capture_start) * clock_rate + start_offset.
    let mut start_offset = 1_000_000u32;
    let mut capture_start = start;
    let mut rate = 48_000u32;
    let mut placed = [0usize; 3];
    for frame in 0..450u32 {
        let now = world.now;
        // The changes fall between the once-a-second in-band NTP timestamps (RFC 6051), so
        // frames after each are placed by a mapping taken at the other rate.
        let stretch = match frame {
            0..130 => 0,
            130..285 => 1,
            _ => 2,
        };
        let (pt, new_rate) = if stretch == 1 {
            (pcmu, 8_000)
        } else {
            (opus, 48_000)
        };
        if new_rate != rate {
            start_offset = start_offset.wrapping_add(
                (now.duration_since(capture_start).as_secs_f64() * f64::from(rate)).round() as u32,
            );
            capture_start = now;
            rate = new_rate;
        }
        let timestamp = start_offset.wrapping_add(
            (now.duration_since(capture_start).as_secs_f64() * f64::from(rate)).round() as u32,
        );
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: 100 + frame as u16,
                        timestamp,
                        ssrc,
                        marker: frame == 0,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x55u8; 80]),
                },
            )?;
        world.pump()?;
        let packets = read_frame(&world, timestamp);
        if let Some(packet) = packets.last() {
            let RTCEncodedFrameMetadataKind::Audio(audio) =
                receiver_metadata(&mut world, std::slice::from_ref(packet))?
            else {
                panic!("an audio frame");
            };
            if let Some(remote) = audio.frame.remote_capture_time {
                let error = if remote > now {
                    remote - now
                } else {
                    now - remote
                };
                assert!(
                    error < Duration::from_millis(5),
                    "frame {frame} (stretch {stretch}, timestamp {timestamp}): {error:?} off"
                );
                placed[stretch] += 1;
            }
        }
        world.run_until(now + Duration::from_millis(20))?;
    }
    assert!(
        placed.iter().all(|count| *count > 100),
        "frames placed in each stretch: {placed:?}"
    );
    Ok(())
}

/// RFC 9605 sections 4.4.3 and 6.1 (the engine row RFC9605-X-6): with SFrame applied per
/// frame the payload is opaque to a forwarder, and "the necessary media metadata will be
/// moved out of the encoded frame buffer to be sent in some channel visible to the SFU (e.g.,
/// an RTP header extension)", so that the SFU can "select which ones should be forwarded".
/// The sender's application encrypts each of 13 L1T3 frames (a key frame, then T2, T1, T2,
/// T0 three times) into one SFrame ciphertext, splits it with the format-agnostic payloader
/// into two packets, and gives each packet the Dependency Descriptor. The second peer, as a
/// forwarder that holds no key, reads only the headers: a `DecodeTargetSelector` for T0
/// forwards the four T0 frames, one for T2 all 13, each frame whole; what it forwards is
/// the ciphertext as sent, which the end receiver reassembles and decrypts.
#[test]
fn a_forwarder_routes_sframe_frames_by_the_dependency_descriptor_alone() -> Result<()> {
    use rtci::rtp::codec::dependency_descriptor::{
        DecodeTargetSelector, DependencyDescriptorReader,
    };
    use rtci::rtp::codec::opaque::{OpaqueDepacketizer, OpaquePayloader};
    use rtci::rtp::packetizer::{Depacketizer, Payloader};
    use rtci::sframe::{CipherSuite, SFrameContext};

    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, dd_id) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let structure = l1t3();
    let mut writer = DependencyDescriptorWriter::new(structure.clone(), 7)?;
    let key = [9u8; 16];
    let mut encryptor = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
    encryptor.add_send_key(4, &key)?;

    // The templates of the 13 frames, and the plaintext of frame n.
    let mut templates = vec![0usize];
    for _ in 0..3 {
        templates.extend([3, 2, 4, 1]);
    }
    let plaintext = |n: usize| -> Vec<u8> {
        (0..1500usize)
            .map(|i| ((i * 7 + n * 13) % 251) as u8)
            .collect()
    };
    let mut sent_payloads: Vec<Bytes> = vec![];
    let mut seq = 500u16;
    for (n, &template) in templates.iter().enumerate() {
        let frame = writer.next_frame(&structure.templates[template], n == 0)?;
        let ciphertext: Bytes = encryptor.encrypt(4, b"", &plaintext(n))?.into();
        let payloads = OpaquePayloader.payload(1000, &ciphertext)?;
        assert_eq!(payloads.len(), 2);
        let now = world.now;
        for (i, payload) in payloads.iter().enumerate() {
            let last = i + 1 == payloads.len();
            let mut header = Header {
                version: 2,
                payload_type: pt,
                sequence_number: seq,
                timestamp: 3000 * n as u32,
                ssrc,
                marker: last,
                ..Default::default()
            };
            header.set_extension_upgrading(dd_id, frame.packet(i == 0, last)?)?;
            seq = seq.wrapping_add(1);
            sent_payloads.push(payload.clone());
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtci::rtp::Packet {
                        header,
                        payload: payload.clone(),
                    },
                )?;
        }
        world.pump()?;
        let next = world.now + Duration::from_millis(33);
        world.run_until(next)?;
    }

    let mut received: Vec<rtci::rtp::Packet> = world.peers[1]
        .read_rtp
        .iter()
        .filter(|p| p.header.ssrc == ssrc)
        .cloned()
        .collect();
    received.sort_by_key(|p| p.header.sequence_number);
    received.dedup_by_key(|p| p.header.sequence_number);
    assert_eq!(received.len(), sent_payloads.len());
    for (packet, sent) in received.iter().zip(&sent_payloads) {
        assert_eq!(
            &packet.payload, sent,
            "the ciphertext arrives as it was sent"
        );
    }

    // The forwarder: headers only, no key. Returns the frames (by RTP timestamp) whose
    // packets it forwards, and the forwarded packets' payloads.
    let forward = |target: (u8, u8)| -> Result<(Vec<u32>, Vec<Bytes>)> {
        let mut reader = DependencyDescriptorReader::new();
        let mut selector = DecodeTargetSelector::new(target.0, target.1);
        let mut frames: Vec<u32> = vec![];
        let mut payloads = vec![];
        for packet in &received {
            let element = packet
                .header
                .get_extension(dd_id)
                .expect("every packet carries the descriptor");
            let descriptor = reader
                .read(&element)?
                .expect("the structure came with the key frame");
            if selector.forward(&descriptor, &reader) {
                if frames.last() != Some(&packet.header.timestamp) {
                    frames.push(packet.header.timestamp);
                }
                payloads.push(packet.payload.clone());
            }
        }
        Ok((frames, payloads))
    };
    // The end receiver, with the key (each pass a receiver of its own: the replay window).
    let decrypt = |payloads: &[Bytes]| -> Result<Vec<Vec<u8>>> {
        let mut decryptor = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
        decryptor.add_recv_key(4, &key)?;
        let mut depacketizer = OpaqueDepacketizer::default();
        let mut frames = vec![];
        for payload in payloads {
            let unit = depacketizer.depacketize(payload)?;
            if !unit.is_empty() {
                frames.push(decryptor.decrypt(b"", &unit)?);
            }
        }
        Ok(frames)
    };

    let base_layer: Vec<usize> = (0..templates.len())
        .filter(|&n| structure.templates[templates[n]].temporal_id == 0)
        .collect();
    assert_eq!(base_layer, vec![0, 4, 8, 12]);
    let (frames, payloads) = forward((0, 0))?;
    assert_eq!(
        frames,
        base_layer
            .iter()
            .map(|&n| 3000 * n as u32)
            .collect::<Vec<_>>(),
        "a receiver of T0 is sent the T0 frames"
    );
    assert_eq!(payloads.len(), 2 * base_layer.len(), "each frame whole");
    assert_eq!(
        decrypt(&payloads)?,
        base_layer.iter().map(|&n| plaintext(n)).collect::<Vec<_>>()
    );

    let (frames, payloads) = forward((0, 2))?;
    assert_eq!(
        frames.len(),
        templates.len(),
        "a receiver of T2 is sent every frame"
    );
    assert_eq!(
        decrypt(&payloads)?,
        (0..templates.len()).map(plaintext).collect::<Vec<_>>()
    );
    Ok(())
}

/// RFC 8834 section 10 ("implementations are REQUIRED to ignore unknown RTCP packets and RTP
/// header extensions"), RFC 8285 section 4.1.2: the audio level of a received frame's
/// metadata (webrtc-encoded-transform `audioLevel`) is read only from an element the
/// receiving section signals. The audio level is negotiated and read; a later offer leaves it
/// out on its way to the receiver, whose answer then has none, and the sender (whose copy of
/// the answer still lists it) keeps sending the element: the frame's metadata has no level.
#[test]
fn a_frames_audio_level_is_not_read_from_an_element_the_section_no_longer_signals() -> Result<()> {
    let without = |sdp: &str| -> String {
        sdp.split("\r\n")
            .filter(|line| !(line.starts_with("a=extmap:") && line.contains(AUDIO_LEVEL)))
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    let with = |sdp: &str, id: u8| -> String {
        sdp.split("\r\n")
            .flat_map(|line| {
                let mut lines = vec![line.to_owned()];
                if line.starts_with("a=mid:") {
                    lines.push(format!("a=extmap:{id} {AUDIO_LEVEL}"));
                }
                lines
            })
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let (_, _, id) = sender_stream(&mut world, sender, AUDIO_LEVEL);
    let level: &[u8] = &[0x80 | 20];
    let metadata_level = |world: &mut World, seq: u16| -> Result<Option<f64>> {
        let frame = read_frame(world, u32::from(seq) * 960);
        assert_eq!(frame.len(), 1, "packet {seq} was read");
        let RTCEncodedFrameMetadataKind::Audio(meta) = receiver_metadata(world, &frame)? else {
            bail!("an audio frame");
        };
        Ok(meta.audio_level)
    };
    world.send(sender, 700, &[(id, level)])?;
    assert!(
        metadata_level(&mut world, 700)?.is_some(),
        "negotiated, the level is read"
    );

    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(without(&offer.sdp))?)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert!(
        !answer.sdp.contains(AUDIO_LEVEL),
        "the receiver's answer leaves it out"
    );
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(with(&answer.sdp, id))?)?;
    world.pump()?;
    world.send(sender, 701, &[(id, level)])?;
    assert_eq!(
        None,
        metadata_level(&mut world, 701)?,
        "no longer signalled: the element is ignored"
    );
    Ok(())
}

/// One spatial layer's frame of picture `picture`: VP9 a frame (its first byte the frame
/// marker, its last not a superframe marker); AV1 the layer's OBUs (a temporal delimiter in
/// front of layer 0) with extension headers naming the layer.
fn svc_layer_frame(mime: &str, picture: usize, spatial_id: u8, temporal_id: u8) -> Bytes {
    let body: Vec<u8> = (0..1200usize)
        .map(|i| ((i * 7 + picture * 13 + spatial_id as usize * 29) % 251) as u8)
        .collect();
    if mime == "video/VP9" {
        let mut frame = vec![0x80 | spatial_id];
        frame.extend_from_slice(&body);
        frame.push(0);
        return Bytes::from(frame);
    }
    let mut obus = vec![];
    if spatial_id == 0 {
        obus.extend([2 << 3 | 0b010, 0]);
    }
    // OBU_FRAME with an extension header and a two-byte leb128 size.
    obus.extend([6 << 3 | 0b110, temporal_id << 5 | spatial_id << 3]);
    obus.extend([0x80 | (body.len() & 0x7f) as u8, (body.len() >> 7) as u8]);
    obus.extend_from_slice(&body);
    Bytes::from(obus)
}

const SVC_PICTURES: usize = 8;
const SVC_SUITE: rtci::sframe::CipherSuite = rtci::sframe::CipherSuite::Aes128GcmSha256_128;
const SVC_KEY: [u8; 16] = [3u8; 16];
const SVC_KEY_ID: u64 = 2;

/// One picture as the encoder gave it: its access unit (a VP9 superframe, an AV1 temporal
/// unit) and its layer frames, lowest first, each with its `(spatial_id, temporal_id)`.
struct SvcPicture {
    unit: Bytes,
    layers: Vec<((u8, u8), Bytes)>,
}

/// What a sender sent of an SVC stream (by RTP timestamp) and the packets the receiving peer
/// read, in sequence order.
struct SvcRun {
    dd_id: u8,
    pictures: std::collections::BTreeMap<u32, SvcPicture>,
    received: Vec<rtci::rtp::Packet>,
}

/// Sends `SVC_PICTURES` pictures of `mode` over a connection, rtc to rtc. `payloads` gets each
/// picture's access unit, layer frames (the `ScalabilityPattern`'s) and their data, and gives
/// the payload of each layer frame's SFrame RTP frame; each is split by the opaque payloader
/// and every packet carries that layer frame's Dependency Descriptor (its own frame number
/// and template).
fn send_svc_pictures(
    mime: &str,
    mode: rtci::rtp::codec::svc::ScalabilityMode,
    mut payloads: impl FnMut(
        &Bytes,
        &[rtci::rtp::codec::svc::LayerFrame],
        &[Bytes],
    ) -> Result<Vec<Vec<u8>>>,
) -> Result<SvcRun> {
    use rtci::rtp::codec::opaque::OpaquePayloader;
    use rtci::rtp::codec::svc::ScalabilityPattern;
    use rtci::rtp::packetizer::Payloader;

    let (mut world, sender) = World::connected(RtpCodecKind::Video, |sdp| sdp)?;
    let (ssrc, pt, dd_id) = sender_stream(&mut world, sender, DEPENDENCY_DESCRIPTOR_URI);
    let structure = ScalabilityPattern::dependency_structure(mode, Some((640, 360)));
    let mut writer = DependencyDescriptorWriter::new(structure, 9)?;
    let mut pattern = ScalabilityPattern::new(mode);
    let mut pictures = std::collections::BTreeMap::new();
    let mut seq = 700u16;
    for n in 0..SVC_PICTURES {
        let frames = pattern.next_picture(n == 0);
        let layers: Vec<Bytes> = frames
            .iter()
            .map(|f| svc_layer_frame(mime, n, f.spatial_id, f.temporal_id))
            .collect();
        let unit = if mime == "video/VP9" {
            rtci::rtp::codec::vp9::join_superframe(&layers)?
        } else {
            Bytes::from(layers.concat())
        };
        let sent = payloads(&unit, &frames, &layers)?;
        assert_eq!(
            sent.len(),
            frames.len(),
            "an SFrame RTP frame per layer frame"
        );
        let timestamp = 3000 * n as u32;
        let now = world.now;
        for (payload, frame) in sent.into_iter().zip(&frames) {
            let descriptor =
                writer.next_frame(&frame.dependencies(), frame.starts_coded_video_sequence())?;
            let packets = OpaquePayloader.payload(1000, &Bytes::from(payload))?;
            for (i, packet) in packets.iter().enumerate() {
                let last = i + 1 == packets.len();
                let mut header = Header {
                    version: 2,
                    payload_type: pt,
                    sequence_number: seq,
                    timestamp,
                    ssrc,
                    marker: last && frame.end_of_picture,
                    ..Default::default()
                };
                header.set_extension_upgrading(dd_id, descriptor.packet(i == 0, last)?)?;
                seq = seq.wrapping_add(1);
                world.peers[0]
                    .pc
                    .rtp_sender(sender)
                    .expect("sender")
                    .write_rtp(
                        now,
                        rtci::rtp::Packet {
                            header,
                            payload: packet.clone(),
                        },
                    )?;
            }
        }
        pictures.insert(
            timestamp,
            SvcPicture {
                unit,
                layers: frames
                    .iter()
                    .map(|f| (f.spatial_id, f.temporal_id))
                    .zip(layers)
                    .collect(),
            },
        );
        world.pump()?;
        let next = world.now + Duration::from_millis(33);
        world.run_until(next)?;
    }
    // The default pacer starts at the estimator's initial target (300 kbit/s) and the test
    // writes ~620 kbit/s: run 45871901329 had 25-26 of the 32 packets on the wire after the
    // last frame interval and all 32 after this drain.
    let drained = world.now + Duration::from_secs(2);
    world.run_until(drained)?;

    let mut received: Vec<rtci::rtp::Packet> = world.peers[1]
        .read_rtp
        .iter()
        .filter(|p| p.header.ssrc == ssrc)
        .cloned()
        .collect();
    received.sort_by_key(|p| p.header.sequence_number);
    received.dedup_by_key(|p| p.header.sequence_number);
    let mut on_wire: Vec<u16> = world
        .wire
        .iter()
        .filter(|h| h.ssrc == ssrc)
        .map(|h| h.sequence_number)
        .collect();
    on_wire.sort_unstable();
    on_wire.dedup();
    assert_eq!(
        received.len(),
        seq.wrapping_sub(700) as usize,
        "every packet arrived (received {:?}, on the wire {:?})",
        received
            .iter()
            .map(|p| p.header.sequence_number)
            .collect::<Vec<_>>(),
        on_wire
    );
    Ok(SvcRun {
        dd_id,
        pictures,
        received,
    })
}

/// An SFrame RTP frame a forwarder passed on: its picture's RTP timestamp, the layer its
/// Dependency Descriptor names, its reassembled payload, and what the end receiver's
/// decryption of that payload gave.
struct ForwardedFrame {
    timestamp: u32,
    layer: (u8, u8),
    payload: Bytes,
    decrypted: std::result::Result<
        Vec<u8>,
        Option<rtci::rtp_transceiver::sframe_transform::RTCSFrameTransformErrorType>,
    >,
}

/// The receiving peer as a forwarder with no key (it reads the headers only:
/// a `DecodeTargetSelector` for `target`, spatial and temporal), then the end receiver (the
/// key, and a replay window of its own per call): the number of packets forwarded and each
/// forwarded frame, decrypted on its own.
fn forward_svc_run(run: &SvcRun, target: (u8, u8)) -> Result<(usize, Vec<ForwardedFrame>)> {
    use rtci::rtp::codec::dependency_descriptor::{
        DecodeTargetSelector, DependencyDescriptorReader,
    };
    use rtci::rtp::codec::opaque::OpaqueDepacketizer;
    use rtci::rtp::packetizer::Depacketizer;
    use rtci::rtp_transceiver::sframe_transform::RTCRtpSFrameDecryptor;

    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(target.0, target.1);
    let mut decryptor = RTCRtpSFrameDecryptor::new(SVC_SUITE)?;
    decryptor.add_decryption_key(&SVC_KEY, SVC_KEY_ID)?;
    let mut depacketizer = OpaqueDepacketizer::default();
    let mut forwarded = 0;
    let mut frames = vec![];
    for packet in &run.received {
        let element = packet
            .header
            .get_extension(run.dd_id)
            .expect("every packet carries the descriptor");
        let descriptor = reader
            .read(&element)?
            .expect("the structure came with the key frame");
        if !selector.forward(&descriptor, &reader) {
            continue;
        }
        forwarded += 1;
        let payload = depacketizer.depacketize(&packet.payload)?;
        if !payload.is_empty() {
            frames.push(ForwardedFrame {
                timestamp: packet.header.timestamp,
                layer: (descriptor.spatial_id, descriptor.temporal_id),
                decrypted: decryptor
                    .transform(&payload)
                    .map_err(|e| e.map(|e| e.error_type)),
                payload,
            });
        }
    }
    Ok((forwarded, frames))
}

/// RFC 9605 section 6.1.3: "In both temporal and spatial scalability, the SFU may choose to
/// drop layers [...]. In order to support the SFU selectively removing layers, the sender MUST
/// encapsulate each layer in a different SFrame ciphertext." Eight pictures of `mode_name`
/// (two spatial layers) come out of the encoder as access units (a VP9 superframe, an AV1
/// temporal unit); `transform` refuses them whole, `transform_access_unit` gives one
/// ciphertext per layer (each with the sender's key id and a counter of its own), each sent as
/// its own frame with its own Dependency Descriptor. For each `targets` entry the receiving
/// peer, as a forwarder with no key, forwards what that decode target needs; the end receiver
/// decrypts every forwarded frame, each is exactly the layer frame its descriptor names, the
/// frames per picture are exactly those of layers up to the target, and `join_layer_frames`
/// gives the encoder's access unit byte for byte (spatial target 1) or the layer-0 unit alone
/// (spatial target 0, a decodable lower layer).
fn a_forwarder_drops_layers_of_sframe_encrypted_svc(
    mime: &str,
    mode_name: &str,
    targets: &[(u8, u8)],
) -> Result<()> {
    use rtci::rtp::codec::svc::ScalabilityMode;
    use rtci::rtp_transceiver::sframe_transform::{
        RTCRtpSFrameEncryptor, RTCSFrameType, join_layer_frames,
    };
    use std::collections::BTreeMap;

    let mode: ScalabilityMode = mode_name.parse()?;
    assert_eq!(mode.spatial_layers(), 2);
    let mut encryptor = RTCRtpSFrameEncryptor::new(SVC_SUITE, RTCSFrameType::PerFrame)?;
    encryptor.set_encryption_key(&SVC_KEY, SVC_KEY_ID)?;
    encryptor.set_scalability(mime, Some(mode))?;
    let mut headers = vec![];
    let run = send_svc_pictures(mime, mode, |unit, frames, _| {
        assert!(
            matches!(encryptor.transform(unit), Err(Error::TypeError(_))),
            "a unit of two layers is not one ciphertext"
        );
        let encrypted = encryptor.transform_access_unit(unit)?;
        assert_eq!(encrypted.len(), frames.len(), "one ciphertext per layer");
        let mut payloads = vec![];
        for (layer, frame) in encrypted.into_iter().zip(frames) {
            assert_eq!(layer.spatial_id, frame.spatial_id);
            let (header, _) = rtci::sframe::Header::decode(&layer.ciphertext)
                .map_err(|e| anyhow::anyhow!("an SFrame header: {e}"))?;
            headers.push(header);
            payloads.push(layer.ciphertext);
        }
        Ok(payloads)
    })?;
    // Distinct ciphertexts: the sender's key id on each, one counter after another.
    assert_eq!(
        headers.len(),
        run.pictures.values().map(|p| p.layers.len()).sum::<usize>()
    );
    assert!(headers.iter().all(|h| h.kid == SVC_KEY_ID), "{headers:?}");
    assert!(
        headers.windows(2).all(|w| w[1].ctr == w[0].ctr + 1),
        "a counter per layer ciphertext: {headers:?}"
    );

    let top = (1, mode.temporal_layers() - 1);
    for &(spatial, temporal) in targets {
        let (forwarded, frames) = forward_svc_run(&run, (spatial, temporal))?;
        assert_eq!(
            forwarded == run.received.len(),
            (spatial, temporal) == top,
            "S{spatial}T{temporal}: only the top target gets every packet ({forwarded} of {})",
            run.received.len()
        );
        let mut kept: BTreeMap<u32, Vec<Bytes>> = BTreeMap::new();
        for frame in frames {
            let plaintext = frame.decrypted.map_err(|e| {
                anyhow::anyhow!(
                    "S{spatial}T{temporal}: layer {:?} at {} does not decrypt: {e:?}",
                    frame.layer,
                    frame.timestamp
                )
            })?;
            let (_, sent) = run.pictures[&frame.timestamp]
                .layers
                .iter()
                .find(|(ids, _)| *ids == frame.layer)
                .expect("the descriptor names a layer frame of the picture");
            assert_eq!(
                &plaintext[..],
                &sent[..],
                "S{spatial}T{temporal}: the frame under the descriptor of layer {:?} at {} is \
                 that layer's",
                frame.layer,
                frame.timestamp
            );
            kept.entry(frame.timestamp)
                .or_default()
                .push(Bytes::from(plaintext));
        }
        let expected: BTreeMap<u32, Vec<Bytes>> = run
            .pictures
            .iter()
            .filter_map(|(timestamp, picture)| {
                let layers: Vec<Bytes> = picture
                    .layers
                    .iter()
                    .filter(|((s, t), _)| *s <= spatial && *t <= temporal)
                    .map(|(_, data)| data.clone())
                    .collect();
                (!layers.is_empty()).then_some((*timestamp, layers))
            })
            .collect();
        assert_eq!(
            kept, expected,
            "S{spatial}T{temporal}: exactly the layer frames of the decode target"
        );
        for (timestamp, layers) in &kept {
            let unit = join_layer_frames(mime, layers)?;
            if spatial == 1 {
                assert_eq!(
                    unit, run.pictures[timestamp].unit,
                    "S{spatial}T{temporal}: the encoder's access unit at {timestamp}, byte for byte"
                );
                continue;
            }
            assert_eq!(unit, layers[0], "the lower layer alone, at {timestamp}");
            // A decodable lower layer: one VP9 frame, or a temporal unit of layer 0's OBUs only.
            if mime == "video/VP9" {
                assert_eq!(rtci::rtp::codec::vp9::split_superframe(&unit)?.len(), 1);
            } else {
                let split = rtci::rtp::codec::av1::split_temporal_unit(&unit)?;
                assert_eq!(split.len(), 1);
                assert_eq!(split[0].spatial_id, 0);
            }
        }
    }
    Ok(())
}

#[test]
fn a_forwarder_drops_spatial_layer_1_of_sframe_encrypted_vp9_l2t1() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc("video/VP9", "L2T1", &[(0, 0), (1, 0)])
}

#[test]
fn a_forwarder_drops_spatial_layer_1_of_sframe_encrypted_vp9_l2t3() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc("video/VP9", "L2T3", &[(0, 2), (1, 2)])
}

#[test]
fn a_forwarder_drops_spatial_layer_1_of_sframe_encrypted_av1_l2t1() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc("video/AV1", "L2T1", &[(0, 0), (1, 0)])
}

#[test]
fn a_forwarder_drops_spatial_layer_1_of_sframe_encrypted_av1_l2t3() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc("video/AV1", "L2T3", &[(0, 2), (1, 2)])
}

/// The temporal half of RFC 9605 section 6.1.3 in a stream that also has spatial layers: a
/// forwarder that drops the top temporal layer (T2) and the two top ones (T1, T2), for a
/// receiver of either spatial layer, leaves ciphertexts that all decrypt, to exactly the
/// pictures of the temporal layers kept.
#[test]
fn a_forwarder_drops_temporal_layers_of_sframe_encrypted_vp9_l2t3() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc(
        "video/VP9",
        "L2T3",
        &[(0, 0), (0, 1), (1, 0), (1, 1)],
    )
}

/// As [`a_forwarder_drops_temporal_layers_of_sframe_encrypted_vp9_l2t3`], for AV1.
#[test]
fn a_forwarder_drops_temporal_layers_of_sframe_encrypted_av1_l2t3() -> Result<()> {
    a_forwarder_drops_layers_of_sframe_encrypted_svc(
        "video/AV1",
        "L2T3",
        &[(0, 0), (0, 1), (1, 0), (1, 1)],
    )
}

/// Why RFC 9605 section 6.1.3 asks for a ciphertext per layer (section 4.2: a per-frame
/// ciphertext "will span several packets, with the header appearing in the first packet and
/// the authentication tag in the last packet"). The access unit of two spatial layers
/// encrypted as one ciphertext (what the encryptor gives when no mode is declared, and what
/// it gave for every unit before the check), its bytes split at the end of layer 0's between
/// the two layers' Dependency Descriptor frames: a forwarder that drops spatial layer 1 leaves
/// the receiver layer 0's part, which does not authenticate, for every picture; with both
/// layers forwarded the two parts together decrypt to the unit.
fn one_ciphertext_over_the_access_unit_does_not_survive_a_layer_drop(mime: &str) -> Result<()> {
    use rtci::rtp_transceiver::sframe_transform::{
        RTCRtpSFrameDecryptor, RTCRtpSFrameEncryptor, RTCSFrameTransformErrorType, RTCSFrameType,
    };

    let mut encryptor = RTCRtpSFrameEncryptor::new(SVC_SUITE, RTCSFrameType::PerFrame)?;
    encryptor.set_encryption_key(&SVC_KEY, SVC_KEY_ID)?;
    let run = send_svc_pictures(mime, "L2T1".parse()?, |unit, frames, layers| {
        assert_eq!(frames.len(), 2);
        let encrypted = encryptor.transform_access_unit(unit)?;
        assert_eq!(
            encrypted.len(),
            1,
            "no declared mode: the unit is one ciphertext"
        );
        let ciphertext = &encrypted[0].ciphertext;
        let (_, header_len) = rtci::sframe::Header::decode(ciphertext)
            .map_err(|e| anyhow::anyhow!("an SFrame header: {e}"))?;
        // The AEAD output is as long as its input: layer 0's bytes come first.
        let split = header_len + layers[0].len();
        Ok(vec![
            ciphertext[..split].to_vec(),
            ciphertext[split..].to_vec(),
        ])
    })?;

    let (_, dropped) = forward_svc_run(&run, (0, 0))?;
    assert_eq!(
        dropped.len(),
        SVC_PICTURES,
        "layer 0's part of every picture"
    );
    for frame in &dropped {
        assert_eq!(frame.layer.0, 0);
        assert_eq!(
            frame.decrypted,
            Err(Some(RTCSFrameTransformErrorType::Authentication)),
            "layer 0 alone of one ciphertext over two layers, at {}",
            frame.timestamp
        );
    }

    let (_, both) = forward_svc_run(&run, (1, 0))?;
    assert_eq!(both.len(), 2 * SVC_PICTURES);
    let mut decryptor = RTCRtpSFrameDecryptor::new(SVC_SUITE)?;
    decryptor.add_decryption_key(&SVC_KEY, SVC_KEY_ID)?;
    for pair in both.chunks(2) {
        assert_eq!((pair[0].layer.0, pair[1].layer.0), (0, 1));
        assert_eq!(pair[0].timestamp, pair[1].timestamp);
        let whole = [&pair[0].payload[..], &pair[1].payload[..]].concat();
        assert_eq!(
            decryptor.transform(&whole).ok().map(Bytes::from),
            Some(run.pictures[&pair[0].timestamp].unit.clone()),
            "both parts together are the unit's ciphertext"
        );
    }
    Ok(())
}

#[test]
fn one_ciphertext_over_a_vp9_superframe_does_not_survive_a_layer_drop() -> Result<()> {
    one_ciphertext_over_the_access_unit_does_not_survive_a_layer_drop("video/VP9")
}

#[test]
fn one_ciphertext_over_an_av1_temporal_unit_does_not_survive_a_layer_drop() -> Result<()> {
    one_ciphertext_over_the_access_unit_does_not_survive_a_layer_drop("video/AV1")
}

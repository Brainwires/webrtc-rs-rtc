//! `RTCRtpSender::write_rtp` rewrites a payload type that is not negotiated for the sender to
//! the one negotiated for its encoding's codec, changing the number and never the payload. The
//! rewrites are counted, between two `rtci` peer connections in virtual time:
//! `rewritten_payload_type_rtp_packets` (every rewrite) and
//! `rewritten_from_another_codec_rtp_packets` (the written number names a different format, so
//! the bytes went out labelled as a codec they are not in), per sender and summed on the
//! connection.
//!
//! RFC 3264 section 5.1: "the answer might indicate different payload type numbers for the
//! same codecs, in which case, the offerer MUST send with the payload type numbers from the
//! answer"; section 7: the offerer "MUST send using a media format listed in the answer". An
//! application whose encoder keeps the codec or the number of its own offer after the answer
//! relies on the rewrite; the counters make that visible.
//!
//! The offerer registers VP8 on 96 with RTX on 97, and VP9 on 98. The answerer registers VP8
//! on 100 with RTX on 101 only, and numbers its answer with its own payload types
//! (`SettingEngineBuilder::with_own_payload_types_in_answers`): the answer negotiates VP8 on
//! 100 (and its RTX on 101), so the offerer sends VP8 with 100. VP9 is not in the answer.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

/// The offerer's numbers.
const OFFERER_VP8: u8 = 96;
const OFFERER_RTX: u8 = 97;
const OFFERER_VP9: u8 = 98;
/// The answerer's, which its answer gives VP8 and VP8's RTX.
const ANSWERER_VP8: u8 = 100;
const ANSWERER_RTX: u8 = 101;
/// A number neither endpoint gives any format.
const NO_FORMAT: u8 = 120;

fn codec(mime_type: &str, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    fn new(addr: &str, codecs: &[(RTCRtpCodec, u8)], own_payload_types: bool) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        for (rtp_codec, payload_type) in codecs {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: rtp_codec.clone(),
                    payload_type: *payload_type,
                },
                RtpCodecKind::Video,
            )?;
        }
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_own_payload_types_in_answers(own_payload_types)
                    .build(),
            )
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read_rtp: Vec::new(),
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

struct World {
    peers: [Peer; 2],
    now: Instant,
    sender: RTCRtpSenderId,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (from, to, data) in in_flight {
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
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read_rtp.push(packet.header);
                }
            }
        }
        Ok(())
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

    /// The offerer sends video; the answerer numbers its answer its own way. Connected.
    fn connected() -> Result<Self> {
        let offerer = Peer::new(
            "10.0.0.1:5000",
            &[
                (codec(MIME_TYPE_VP8, ""), OFFERER_VP8),
                (
                    codec(MIME_TYPE_RTX, &format!("apt={OFFERER_VP8}")),
                    OFFERER_RTX,
                ),
                (codec(MIME_TYPE_VP9, "profile-id=0"), OFFERER_VP9),
            ],
            false,
        )?;
        let answerer = Peer::new(
            "10.0.0.2:5000",
            &[
                (codec(MIME_TYPE_VP8, ""), ANSWERER_VP8),
                (
                    codec(MIME_TYPE_RTX, &format!("apt={ANSWERER_VP8}")),
                    ANSWERER_RTX,
                ),
            ],
            true,
        )?;
        let mut peers = [offerer, answerer];
        let transceiver = peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        let sender = peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");
        let mut world = World {
            peers,
            now: Instant::now(),
            sender,
        };
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(now, offer)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(answer.sdp.clone())?)?;
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
        // The premise: the answer renumbered VP8, and left VP9 out.
        let codecs: Vec<(String, u8)> = world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .map(|c| (c.rtp_codec.mime_type.to_ascii_lowercase(), c.payload_type))
            .collect();
        assert_eq!(
            codecs.first(),
            Some(&(MIME_TYPE_VP8.to_ascii_lowercase(), ANSWERER_VP8)),
            "the offerer sends VP8 with the answer's number ({})",
            answer.sdp
        );
        assert!(
            !codecs
                .iter()
                .any(|(_, pt)| [OFFERER_VP8, OFFERER_RTX, OFFERER_VP9].contains(pt)),
            "none of the offerer's numbers is negotiated for sending: {codecs:?}"
        );
        Ok(world)
    }

    /// Writes a packet with payload type `pt` on the sender's stream, then lets 33 ms pass.
    fn send(&mut self, seq: u16, pt: u8) -> Result<()> {
        let now = self.now;
        let ssrc = self.peers[0]
            .pc
            .rtp_sender(self.sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        let header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 3000,
            ssrc,
            marker: true,
            ..Default::default()
        };
        self.peers[0]
            .pc
            .rtp_sender(self.sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(33))
    }

    /// The offerer's sender's counters: (every rewrite, rewrites from another codec).
    fn sender_counts(&mut self) -> (u64, u64) {
        let sender = self.peers[0].pc.rtp_sender(self.sender).expect("sender");
        (
            sender.rewritten_payload_type_rtp_packets(),
            sender.rewritten_from_another_codec_rtp_packets(),
        )
    }

    /// The offerer's connection's sums, which equal the one sender's counters.
    fn connection_counts(&self) -> (u64, u64) {
        (
            self.peers[0].pc.rewritten_payload_type_rtp_packets(),
            self.peers[0].pc.rewritten_from_another_codec_rtp_packets(),
        )
    }

    /// The payload types of the packets the answerer's application got.
    fn received(&self) -> Vec<u8> {
        self.peers[1]
            .read_rtp
            .iter()
            .map(|h| h.payload_type)
            .collect()
    }
}

/// Packets written with the negotiated payload type are not rewritten: both counters stay 0,
/// on the sender and on the connection.
#[test]
fn packets_written_with_the_negotiated_payload_type_are_not_counted() -> Result<()> {
    let mut world = World::connected()?;
    for seq in 1..=5 {
        world.send(seq, ANSWERER_VP8)?;
    }
    assert_eq!(world.received(), vec![ANSWERER_VP8; 5]);
    assert_eq!(world.sender_counts(), (0, 0));
    assert_eq!(world.connection_counts(), (0, 0));
    assert_eq!(world.peers[1].pc.rewritten_payload_type_rtp_packets(), 0);
    Ok(())
}

/// RFC 3264 section 5.1: VP8 written with the offerer's own number after the answer
/// renumbered it is sent with the answer's number. It is a rewrite, counted, but not one from
/// another codec: the bytes are VP8 and leave labelled VP8.
#[test]
fn the_same_codec_renumbered_by_the_answer_counts_as_a_rewrite_only() -> Result<()> {
    let mut world = World::connected()?;
    world.send(1, ANSWERER_VP8)?;
    for seq in 2..=4 {
        world.send(seq, OFFERER_VP8)?;
    }
    world.send(5, ANSWERER_VP8)?;
    assert_eq!(
        world.received(),
        vec![ANSWERER_VP8; 5],
        "the renumbered packets arrive with the answer's number"
    );
    assert_eq!(world.sender_counts(), (3, 0));
    assert_eq!(world.connection_counts(), (3, 0));
    assert_eq!(world.peers[1].pc.unnegotiated_payload_type_rtp_packets(), 0);
    Ok(())
}

/// RFC 3264 section 7: VP9 is not in the answer. VP9 written with the offerer's VP9 number,
/// and a packet written with the offerer's RTX number that the answer did not keep, leave
/// labelled as VP8 (the payload is not touched): both counters count them.
#[test]
fn a_number_naming_another_registered_codec_counts_as_a_rewrite_from_another_codec() -> Result<()> {
    let mut world = World::connected()?;
    world.send(1, ANSWERER_VP8)?;
    world.send(2, OFFERER_VP9)?;
    world.send(3, OFFERER_VP9)?;
    world.send(4, OFFERER_RTX)?;
    assert_eq!(
        world.received(),
        vec![ANSWERER_VP8; 4],
        "the receiver cannot tell: every packet arrived as VP8"
    );
    assert_eq!(world.sender_counts(), (3, 3));
    assert_eq!(world.connection_counts(), (3, 3));

    // Renumbered VP8 adds to the rewrites, not to those from another codec.
    world.send(5, OFFERER_VP8)?;
    assert_eq!(world.sender_counts(), (4, 3));
    assert_eq!(world.connection_counts(), (4, 3));
    Ok(())
}

/// A number that names no format of the sender's kind is rewritten and counted, but not as
/// another codec: nothing says what its bytes are.
#[test]
fn a_number_naming_no_format_counts_as_a_rewrite_only() -> Result<()> {
    let mut world = World::connected()?;
    world.send(1, NO_FORMAT)?;
    world.send(2, NO_FORMAT)?;
    assert_eq!(world.received(), vec![ANSWERER_VP8; 2]);
    assert_eq!(world.sender_counts(), (2, 0));
    assert_eq!(world.connection_counts(), (2, 0));
    Ok(())
}

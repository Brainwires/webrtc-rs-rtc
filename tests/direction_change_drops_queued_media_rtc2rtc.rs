//! Media the pacer holds for a stream whose negotiated direction stops it sending does not
//! leave once that direction takes effect, between two `rtci` peer connections with the default
//! interceptors (the pacer among them) in virtual time.
//!
//! RFC 8866 section 6.7.4: "No media is sent over an inactive media stream"; section 6.7.1: a
//! receive-only stream is started "in receive-only mode" (RTCP goes on); RFC 3264 section 5.1:
//! an endpoint that "wishes to neither send nor receive media at this time" marks the stream
//! inactive. W3C webrtc-pc 4.4.1.6: the answer sets `[[CurrentDirection]]`, and a sender sends
//! only while it is "sendrecv" or "sendonly" (5.2 `replaceTrack`'s "sending"). The engine
//! refuses what the application writes from then on, but the packets the pacer had queued
//! before left afterwards, over the following second: a receiver saw media of a stream it had
//! been told was inactive (the WPT case "unmuted when setting direction to sendrecv after
//! inactive", reported by a consumer, deno_webrtc).

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
/// The packets of the burst written just before the direction changes.
const BURST: u16 = 120;
const VP8_PT: u8 = 96;
const MEDIA_SSRC: u32 = 0x4e4f_5258;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The RTP packets handed to the application: sequence number and payload.
    read: Vec<(u16, Bytes)>,
}

impl Peer {
    /// VP8 and nothing else for video (no `rtx` format), and the default interceptors: NACK,
    /// congestion control feedback, the abs-send-time stamp, the pacer.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
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
            read: Vec::new(),
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

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear), or
/// `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// When each datagram of the first peer's media stream crossed the wire, by sequence
    /// number.
    wire: BTreeMap<u16, Vec<Instant>>,
    /// The first peer's RTCP datagrams.
    rtcp_sent: usize,
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
                if i == 0 && data.len() >= 8 && data[0] >> 6 == 2 && (192..=223).contains(&data[1])
                {
                    self.rtcp_sent += 1;
                }
                if i == 0
                    && let Some(header) = wire_rtp_header(&data)
                    && header.ssrc == MEDIA_SSRC
                {
                    self.wire
                        .entry(header.sequence_number)
                        .or_default()
                        .push(self.now);
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
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read
                        .push((packet.header.sequence_number, packet.payload));
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

    /// Two connected peers; the first sends one VP8 stream.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            wire: BTreeMap::new(),
            rtcp_sent: 0,
        };
        let sender = world.peers[0].pc.add_track(MediaStreamTrack::new(
            "call".to_owned(),
            "video".to_owned(),
            "video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(MEDIA_SSRC),
                    ..Default::default()
                },
                codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                ..Default::default()
            }],
        ))?;
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
        world.peers[0].pc.set_remote_description(now, answer)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected: {:?}", world.peers[0].states);
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// The payload of the one-packet VP8 frame with sequence number `seq`: 1 000 octets.
    fn payload(seq: u16) -> Bytes {
        let mut payload = vec![0x10u8];
        payload.extend((0..999u16).map(|i| (i as u8) ^ (seq as u8)));
        Bytes::from(payload)
    }

    /// Writes a one-packet VP8 frame with sequence number `seq` now, and hands what leaves at
    /// once to the network.
    fn write(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        rtp_sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: VP8_PT,
                    sequence_number: seq,
                    timestamp: u32::from(seq) * 3000,
                    ssrc: MEDIA_SSRC,
                    marker: true,
                    ..Default::default()
                },
                payload: Self::payload(seq),
            },
        )?;
        self.pump()
    }

    /// Offers from the first peer with its transceiver's direction `direction`, and applies
    /// the answer, at the current instant.
    fn renegotiate(&mut self, direction: RTCRtpTransceiverDirection) -> Result<()> {
        let now = self.now;
        let transceiver = self.peers[0]
            .pc
            .get_transceivers()
            .next()
            .expect("the transceiver");
        self.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .expect("the transceiver")
            .set_direction(direction)?;
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
}

/// A burst queued at the pacer, then the stream made inactive (and, in a second round,
/// receive-only) in the same instant: from the moment the answer is applied no packet of the
/// stream leaves, though the pacer still held most of the burst; RTCP goes on. Made `sendrecv`
/// again, what is written from then on is sent and arrives, and none of the burst comes back.
#[test]
fn queued_media_of_a_stream_that_stops_sending_does_not_leave() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let mut seq = 1000u16;
    for direction in [
        RTCRtpTransceiverDirection::Inactive,
        RTCRtpTransceiverDirection::Recvonly,
    ] {
        // Sending: 1 000 octets every 20 ms, well inside the target.
        for _ in 0..25 {
            world.write(sender, seq)?;
            seq += 1;
            let next = world.now + Duration::from_millis(20);
            world.run_until(next)?;
        }
        // A burst the target cannot carry at once: the pacer queues it.
        let burst = seq..seq + BURST;
        for _ in 0..BURST {
            world.write(sender, seq)?;
            seq += 1;
        }
        let left_at_once = burst.clone().filter(|s| world.wire.contains_key(s)).count();
        assert!(
            left_at_once < usize::from(BURST) / 2,
            "{direction}: the pacer queued the burst ({left_at_once} of {BURST} left at once)"
        );

        world.renegotiate(direction)?;
        let changed_at = world.now;
        let rtcp_before = world.rtcp_sent;
        let until = world.now + Duration::from_secs(6);
        world.run_until(until)?;
        let after: Vec<u16> = world
            .wire
            .iter()
            .filter(|(_, at)| at.iter().any(|at| *at > changed_at))
            .map(|(seq, _)| *seq)
            .collect();
        assert!(
            after.is_empty(),
            "{direction}: media left after the direction took effect: {} packets, {:?}..",
            after.len(),
            after.iter().take(5).collect::<Vec<_>>()
        );
        assert!(
            world.rtcp_sent > rtcp_before,
            "{direction}: RTCP goes on (RFC 8866 section 6.7)"
        );

        // Sending again: what is written now is sent, and the queued burst stays gone.
        world.renegotiate(RTCRtpTransceiverDirection::Sendrecv)?;
        let resumed_at = world.now;
        let fresh = seq..seq + 10;
        for _ in 0..10 {
            world.write(sender, seq)?;
            seq += 1;
            let next = world.now + Duration::from_millis(20);
            world.run_until(next)?;
        }
        let until = world.now + Duration::from_secs(1);
        world.run_until(until)?;
        for s in fresh {
            assert!(
                world.wire.contains_key(&s),
                "{direction}: the packet {s} written after sendrecv was sent"
            );
            assert!(
                world.peers[1].read.iter().any(|(read, _)| *read == s),
                "{direction}: the packet {s} written after sendrecv arrived"
            );
        }
        let stale: Vec<u16> = burst
            .filter(|s| {
                world
                    .wire
                    .get(s)
                    .is_some_and(|at| at.iter().any(|at| *at > changed_at || *at >= resumed_at))
            })
            .collect();
        assert!(
            stale.is_empty(),
            "{direction}: stale burst packets {stale:?}"
        );
    }
    Ok(())
}

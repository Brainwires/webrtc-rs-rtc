//! The formats an answer adds beyond the offer's are received, between two `rtci` peer
//! connections in virtual time. The answerer lists them with
//! `SettingEngineBuilder::with_answer_offered_formats_only(false)` (the default before 0.3.0).
//!
//! RFC 9429 section 5.3.1 (no codec preferences): "Any currently available media formats that
//! are not present in the current remote description MUST be added after all existing
//! formats". RFC 3264 section 6.1: such a stream "MAY indicate additional media formats, not
//! listed in the corresponding stream in the offer, that the answerer is willing to send or
//! receive", and section 7, the offerer: "It MUST send using a media format listed in the
//! answer". So a format the answerer added is one the offerer may switch to, and the answerer
//! must not ignore it as a payload type it does not understand (RFC 3550 section 5.1).
//!
//! This is what a WebKit sender did in the browser interop cells: its offer, limited by
//! `setCodecPreferences` to VP8 and RTX, was answered with VP9 (payload type 98) added; after
//! some 35 VP8 packets it sent on 98, and the engine dropped the rest of the call.
//!
//! The offerer here sends video; its offer reaches the answerer with VP8 and its RTX only.

use anyhow::{Context, Result, bail};
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
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        // The answer lists the formats the offer lacks (the setting; the default answers with
        // the offered formats only since 0.3.0).
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                    .with_answer_offered_formats_only(false)
                    .build(),
            )
            .with_media_engine(media_engine)
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

    /// The first peer sends video; the second receives the offer with `edit_offer` applied
    /// and answers. Returns the world, the sender and the answer's SDP.
    fn connected(edit_offer: impl Fn(&str) -> String) -> Result<(Self, RTCRtpSenderId, String)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
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
            .set_remote_description(now, RTCSessionDescription::offer(edit_offer(&offer.sdp))?)?;
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
        Ok((world, sender, answer.sdp))
    }

    /// Writes a packet with payload type `pt` on the sender's stream, then lets 33 ms pass.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16, pt: u8) -> Result<()> {
        let now = self.now;
        let ssrc = self.peers[0]
            .pc
            .rtp_sender(sender)
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
        self.run_until(now + Duration::from_millis(33))
    }
}

/// The payload type `rtpmap` gives `encoding` (e.g. "VP8/90000") in `sdp`'s video section.
fn payload_type_of(sdp: &str, encoding: &str) -> Option<u8> {
    sdp.lines().find_map(|line| {
        let rest = line.strip_prefix("a=rtpmap:")?;
        let (pt, name) = rest.split_once(' ')?;
        name.trim()
            .eq_ignore_ascii_case(encoding)
            .then(|| pt.parse().ok())?
    })
}

/// The offer with its video section cut to VP8 and VP8's RTX, as a browser's offer after
/// `setCodecPreferences([VP8, RTX])` is.
fn vp8_and_rtx_only(sdp: &str) -> String {
    let vp8 = payload_type_of(sdp, "VP8/90000").expect("the offer has VP8");
    let rtx = sdp
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("a=fmtp:")?;
            let (pt, params) = rest.split_once(' ')?;
            (params.trim() == format!("apt={vp8}")).then(|| pt.parse::<u8>().ok())?
        })
        .expect("the offer has VP8's RTX");
    let keep = [vp8, rtx];
    let kept = |line: &str| -> bool {
        for prefix in ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"] {
            if let Some(rest) = line.strip_prefix(prefix) {
                let pt = rest.split([' ', '\t']).next().unwrap_or("");
                return pt == "*" || pt.parse::<u8>().is_ok_and(|pt| keep.contains(&pt));
            }
        }
        true
    };
    let mut out = String::new();
    for line in sdp.split("\r\n").filter(|l| !l.is_empty()) {
        if line.starts_with("m=video ") {
            let fields: Vec<&str> = line.split(' ').collect();
            out.push_str(&format!(
                "{} {} {} {vp8} {rtx}\r\n",
                fields[0], fields[1], fields[2]
            ));
        } else if kept(line) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out
}

/// RFC 9429 section 5.3.1 adds VP9 to the answer of a VP8-only offer; the offerer switches to
/// it (RFC 3264 section 7: any format of the answer) and every packet reaches the answerer's
/// application, none counted as ignored for its payload type (a payload type in neither
/// description is still ignored: `endpoint.rs` `rtx_test`).
#[test]
fn a_format_the_answer_added_is_received_when_the_offerer_switches_to_it() -> Result<()> {
    let (mut world, sender, answer) = World::connected(vp8_and_rtx_only)?;
    let vp8 = payload_type_of(&answer, "VP8/90000").context("the answer keeps VP8")?;
    let vp9 = payload_type_of(&answer, "VP9/90000")
        .context("RFC 9429 5.3.1: the answer adds the VP9 the offer lacked")?;
    let sent = [vp8, vp8, vp8, vp9, vp9, vp9, vp8];
    for (seq, pt) in sent.iter().enumerate() {
        world.send(sender, seq as u16 + 1, *pt)?;
    }
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    assert_eq!(received, sent, "the answer's VP9 is received ({answer})");
    assert_eq!(world.peers[1].pc.unnegotiated_payload_type_rtp_packets(), 0);
    Ok(())
}

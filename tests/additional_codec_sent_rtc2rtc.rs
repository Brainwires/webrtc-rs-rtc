//! WPT `webrtc/protocol/additional-codecs.html`, "Listing an additional codec in the answer
//! causes it to be sent", between two `rtci` peer connections in virtual time: what goes on
//! the wire, not only the sender's parameters.
//!
//! pc1 restricts its transceiver to VP8 (`setCodecPreferences([vp8])`) and sets its offer;
//! pc2 receives that offer with "H264" added on 63 and VP8 renamed `no-such-codec`, and
//! answers (the engine's default form: H.264 on 63 first, then the engine's other formats that
//! still have a number). RFC 9429 section 5.11: the offerer sends "the most preferred media
//! format from the remote description that is also locally supported"; RFC 3264 section
//! 8.3.2: it "MUST NOT send using any formats that are not in the answer".
//!
//! The application chooses the payload type of what it writes (the engine is sans-I/O and
//! does not encode): `write_rtp` with the payload type the sender's parameters name sends
//! that format; a packet written with the offer's VP8 number, which the answer does not have,
//! must not leave with it.

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
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
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
    /// `minimal`: VP8 and one H.264 format only (as a binding that registers few codecs), so
    /// the dynamic payload types are not all taken.
    /// `adds_formats`: the answer also lists the formats the offer lacks
    /// (`with_answer_offered_formats_only(false)`, the default before 0.3.0).
    fn with_codecs(addr: &str, minimal: bool, adds_formats: bool) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        if minimal {
            for (mime, pt, fmtp) in [
                ("video/VP8", 96u8, ""),
                (
                    "video/H264",
                    102u8,
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
                ),
            ] {
                media_engine.register_codec(
                    RTCRtpCodecParameters {
                        rtp_codec: rtci::rtp_transceiver::rtp_sender::RTCRtpCodec {
                            mime_type: mime.to_owned(),
                            clock_rate: 90000,
                            channels: 0,
                            sdp_fmtp_line: fmtp.to_owned(),
                            rtcp_feedback: vec![],
                        },
                        payload_type: pt,
                    },
                    RtpCodecKind::Video,
                )?;
            }
        } else {
            media_engine.register_default_codecs()?;
        }
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        // `adds_formats` false: no setting call at all, so the default is what is tested.
        let mut builder = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build());
        if adds_formats {
            builder = builder.with_setting_engine(
                rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                    .with_answer_offered_formats_only(false)
                    .build(),
            );
        }
        let pc = builder
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

    /// pc1 offers VP8 only; pc2 answers the WPT's edit of that offer. Returns the world, pc1's
    /// sender and the answer's SDP.
    /// The default codecs, the answer in the setting's form (formats added): the scenario the
    /// tests below were proven with (runs 45990202513, 45991341490).
    fn connected() -> Result<(Self, RTCRtpSenderId, String)> {
        Self::connected_with(false, true)
    }

    fn connected_with(minimal: bool, adds_formats: bool) -> Result<(Self, RTCRtpSenderId, String)> {
        let mut world = World {
            peers: [
                Peer::with_codecs("10.0.0.1:5000", minimal, adds_formats)?,
                Peer::with_codecs("10.0.0.2:5000", minimal, adds_formats)?,
            ],
            now: Instant::now(),
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
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
            .expect("a transceiver has a sender");
        let capabilities = world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video")
            .codecs;
        let find = |mime: &str| {
            capabilities
                .iter()
                .find(|c| c.mime_type.eq_ignore_ascii_case(mime))
                .cloned()
                .expect("a capability")
        };
        let (vp8, h264) = (find("video/VP8"), find("video/H264"));
        world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .expect("t")
            .set_codec_preferences(vec![RTCRtpCodecParameters {
                rtp_codec: vp8,
                payload_type: 0,
            }])?;
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        // The WPT's edit: " 63" on the m= line, H.264 on 63, VP8 renamed.
        let mut sdp = offer
            .sdp
            .split('\n')
            .map(|l| {
                let l = l.trim();
                if l.starts_with("m=") {
                    format!("{l} 63")
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        if !sdp.ends_with("\r\n") {
            sdp.push_str("\r\n");
        }
        sdp.push_str("a=rtpmap:63 H264/90000\r\n");
        sdp.push_str(&format!("a=fmtp:63 {}\r\n", h264.sdp_fmtp_line));
        let sdp = sdp.replace("VP8", "no-such-codec");
        world.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(sdp)?)?;
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

    /// The codec pc1's outbound-rtp for `ssrc` references (W3C webrtc-stats codecId).
    fn outbound_codec(&mut self, ssrc: u32) -> Option<String> {
        let report = self.peers[0].pc.get_stats(self.now, StatsSelector::None);
        let codec_id = report
            .outbound_rtp_streams()
            .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
            .map(|s| s.sent_rtp_stream_stats.rtp_stream_stats.codec_id.clone())?;
        report.iter().find_map(|entry| match entry {
            RTCStatsReportEntry::Codec(c) if c.stats.id == codec_id => Some(c.mime_type.clone()),
            _ => None,
        })
    }

    fn ssrc(&mut self, sender: RTCRtpSenderId) -> u32 {
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC")
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

/// The format the sender's parameters name first (what a codec-less encoding is sent with).
fn named_send_format(world: &mut World, sender: RTCRtpSenderId) -> (u8, String) {
    let codecs = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    let first = codecs.first().expect("a send codec");
    (
        first.payload_type,
        first.rtp_codec.mime_type.to_ascii_lowercase(),
    )
}

/// The WPT: the answer leads with H.264 on 63; the sender names it, media written with it
/// reaches pc2 on 63, and pc1's outbound-rtp references H.264.
#[test]
fn the_offerer_sends_h264_on_63_which_the_answer_leads_with() -> Result<()> {
    let (mut world, sender, answer) = World::connected()?;
    // Diagnostic (run with --nocapture): the answer's video section as pc2 wrote it.
    let video: Vec<&str> = answer
        .lines()
        .skip_while(|l| !l.starts_with("m=video"))
        .take_while(|l| !l.starts_with("m=") || l.starts_with("m=video"))
        .filter(|l| {
            l.starts_with("m=video") || l.starts_with("a=rtpmap:") || l.starts_with("a=fmtp:")
        })
        .collect();
    println!("ANSWER VIDEO SECTION:\n{}", video.join("\n"));
    let pc1_send_codecs: Vec<(u8, String)> = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .map(|c| (c.payload_type, c.rtp_codec.mime_type.clone()))
        .collect();
    println!("PC1 SEND CODECS AFTER THE ANSWER: {pc1_send_codecs:?}");
    // What I believe: the answer cannot add VP8 (its registered 96 is the offer's
    // no-such-codec and `answer_payload_types` finds no free number in 96-127).
    assert!(
        !video
            .iter()
            .any(|l| l.starts_with("a=rtpmap:") && l.contains(" VP8/")),
        "the answer contains VP8: {video:?}"
    );
    let first_answered = answer
        .lines()
        .find(|l| l.starts_with("m=video"))
        .and_then(|m| m.split(' ').nth(3))
        .map(str::to_owned);
    assert_eq!(first_answered.as_deref(), Some("63"), "{answer}");
    let (pt, mime) = named_send_format(&mut world, sender);
    assert_eq!((pt, mime.as_str()), (63, "video/h264"), "{answer}");
    for seq in 1..=5u16 {
        world.send(sender, seq, pt)?;
    }
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    println!("PC2 RECEIVED PAYLOAD TYPES: {received:?}");
    assert!(
        received.len() >= 4 && received.iter().all(|p| *p == 63),
        "pc2 receives H.264 on 63: {received:?}\n{answer}"
    );
    let ssrc = world.ssrc(sender);
    assert_eq!(
        world
            .outbound_codec(ssrc)
            .map(|m| m.to_ascii_lowercase())
            .as_deref(),
        Some("video/h264"),
        "W3C stats: outbound-rtp codecId names H.264"
    );
    Ok(())
}

/// A sender application that writes with the VP8 number of its own offer (an encoder fixed
/// on VP8): the answer has no such format (it renamed VP8), so nothing may leave on that number
/// (RFC 3264 section 8.3.2). Records what pc2 receives and what pc1's stats say.
#[test]
fn a_packet_written_with_the_offers_vp8_number_does_not_leave_with_it() -> Result<()> {
    let (mut world, sender, answer) = World::connected()?;
    // pc1's own offer numbered VP8 96 (the engine's registered number).
    for seq in 1..=5u16 {
        world.send(sender, seq, 96)?;
    }
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    let ssrc = world.ssrc(sender);
    let stats_codec = world.outbound_codec(ssrc);
    println!(
        "WRITTEN WITH 96: pc2 received {received:?}, pc2 unnegotiated {}, pc1 outbound codec \
         {stats_codec:?}",
        world.peers[1].pc.unnegotiated_payload_type_rtp_packets()
    );
    // On the wire: pc2 counts what arrives with a payload type its answer does not have
    // (RFC 3550 section 5.1, dropped).
    let unnegotiated = world.peers[1].pc.unnegotiated_payload_type_rtp_packets();
    assert!(
        received.iter().all(|p| *p != 96) && unnegotiated == 0,
        "the offer's VP8 number left pc1: received {received:?}, {unnegotiated} unnegotiated at \
         pc2, outbound codec {stats_codec:?}\n{answer}"
    );
    Ok(())
}

/// Regression test of jsep-91 (failing first on master, agent-test run 45990202513: the answer
/// was `63 99`, H.264 and VP8, and the sender's codecs were `[(99, "video/VP8")]`). The same
/// scenario with a media engine of VP8 and one H.264 format at both ends: dynamic numbers are
/// free, so the answer adds VP8 on one of them after H.264 on 63. RFC 9429
/// section 5.11 still has the offerer send "the most preferred media format from the remote
/// description that is also locally supported": H.264 on 63. (Diagnostic: prints the answer's
/// video section and pc1's send codecs.)
#[test]
fn with_free_payload_types_the_offerer_still_sends_the_answers_first_format() -> Result<()> {
    // The answer adds VP8 on a free number (the setting): the jsep-91 case.
    let (mut world, sender, answer) = World::connected_with(true, true)?;
    let video: Vec<&str> = answer
        .lines()
        .skip_while(|l| !l.starts_with("m=video"))
        .take_while(|l| !l.starts_with("m=") || l.starts_with("m=video"))
        .filter(|l| {
            l.starts_with("m=video") || l.starts_with("a=rtpmap:") || l.starts_with("a=fmtp:")
        })
        .collect();
    println!(
        "MINIMAL ENGINE, ANSWER VIDEO SECTION:\n{}",
        video.join("\n")
    );
    let pc1_send_codecs: Vec<(u8, String)> = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .map(|c| (c.payload_type, c.rtp_codec.mime_type.clone()))
        .collect();
    println!("MINIMAL ENGINE, PC1 SEND CODECS AFTER THE ANSWER: {pc1_send_codecs:?}");
    let (pt, mime) = named_send_format(&mut world, sender);
    assert_eq!(
        (pt, mime.as_str()),
        (63, "video/h264"),
        "RFC 9429 5.11: the answer's first format it can send; send codecs {pc1_send_codecs:?}\n{}",
        video.join("\n")
    );
    for seq in 1..=5u16 {
        world.send(sender, seq, pt)?;
    }
    let received: Vec<u8> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.payload_type)
        .collect();
    println!("MINIMAL ENGINE, PC2 RECEIVED PAYLOAD TYPES: {received:?}");
    assert!(
        received.len() >= 4 && received.iter().all(|p| *p == 63),
        "pc2 receives H.264 on 63: {received:?}"
    );
    Ok(())
}

/// The default answer (0.3.0: the offered formats only) to the WPT's edited offer is H.264 on 63
/// alone, with either codec set; the offerer sends H.264 on 63.
#[test]
fn by_default_the_answer_is_h264_on_63_alone_and_it_is_sent() -> Result<()> {
    for minimal in [false, true] {
        let (mut world, sender, answer) = World::connected_with(minimal, false)?;
        let m_line = answer
            .lines()
            .find(|l| l.starts_with("m=video"))
            .expect("a video section")
            .to_owned();
        assert!(
            m_line.ends_with(" 63"),
            "minimal {minimal}: {m_line}\n{answer}"
        );
        let (pt, mime) = named_send_format(&mut world, sender);
        assert_eq!((pt, mime.as_str()), (63, "video/h264"), "minimal {minimal}");
        for seq in 1..=5u16 {
            world.send(sender, seq, pt)?;
        }
        let received: Vec<u8> = world.peers[1]
            .read_rtp
            .iter()
            .map(|h| h.payload_type)
            .collect();
        assert!(
            received.len() >= 4 && received.iter().all(|p| *p == 63),
            "minimal {minimal}: {received:?}"
        );
    }
    Ok(())
}

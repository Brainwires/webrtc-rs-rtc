//! `PeerDriver` against itself over loopback UDP, with the application doing only what the
//! signalling is: descriptions and candidates carried to the other side, negotiation-needed
//! answered, media written and counted. No test code gathers or binds a socket: the driver
//! gathers when gathering begins, and again by itself when a transport needs new local
//! candidates (`OnLocalCandidatesNeeded`; a new DTLS association over UDP runs on a new
//! 3-tuple, RFC 8842 section 5.1).

use bytes::Bytes;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent,
};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::{RTCPeerConnectionState, RTCSignalingState};
use rtci::peer_connection::transport::{RTCDtlsTransportState, RTCIceCandidateInit};
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{
    RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// How long a previous socket stays open after a pair on a new one is selected.
const LINGER: Duration = Duration::from_secs(2);

/// One side: the driver, and what the application saw.
struct Side {
    driver: PeerDriver,
    /// Candidates to carry to the other side.
    outgoing: Vec<RTCIceCandidateInit>,
    negotiation_needed: bool,
    needed: Vec<RTCLocalCandidatesNeededEvent>,
    /// The sequence numbers of the RTP packets read.
    rtp: Vec<u16>,
    /// SRTP packets discarded: (sequence number, replay), with when.
    discarded: Vec<(u64, bool, Instant)>,
    /// When each new association's DTLS transport connected.
    dtls_connected: Vec<Instant>,
    /// Only TCP candidates of this type are carried to the other side (all candidates when
    /// `None`).
    carry: Option<&'static str>,
}

impl Side {
    fn new(settings: SettingEngineBuilder) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(settings.build())
            .build(Instant::now())?;
        Ok(Self {
            driver: PeerDriver::new(
                pc,
                PeerDriverConfig {
                    retired_socket_linger: LINGER,
                    ..PeerDriverConfig::on(vec![LOOPBACK])
                },
            ),
            outgoing: vec![],
            negotiation_needed: false,
            needed: vec![],
            rtp: vec![],
            discarded: vec![],
            dtls_connected: vec![],
            carry: None,
        })
    }

    /// What the application does with the events and reads.
    fn collect(&mut self) {
        while let Some(event) = self.driver.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(event) => {
                    if let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                        && let Ok(init) = candidate.to_json()
                        && self.carry.is_none_or(|tcptype| {
                            init.candidate.contains(" tcp ")
                                && init.candidate.contains(&format!("tcptype {tcptype}"))
                        })
                    {
                        self.outgoing.push(init);
                    }
                }
                RTCPeerConnectionEvent::OnNegotiationNeededEvent => self.negotiation_needed = true,
                RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => self.needed.push(needed),
                RTCPeerConnectionEvent::OnSrtpPacketDiscarded {
                    rtcp: false,
                    index,
                    replay,
                    ..
                } => self.discarded.push((index, replay, Instant::now())),
                RTCPeerConnectionEvent::OnDtlsTransportStateChange(
                    RTCDtlsTransportState::Connected,
                ) => self.dtls_connected.push(Instant::now()),
                _ => {}
            }
        }
        while let Some(read) = self.driver.pc_mut().poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = read.message {
                self.rtp.push(packet.header.sequence_number);
            }
        }
    }

    fn connected(&self) -> bool {
        self.driver.pc().connection_state() == RTCPeerConnectionState::Connected
    }
}

/// Both sides, one round each, the candidates carried across.
async fn round(a: &mut Side, b: &mut Side) -> Result<()> {
    a.driver.step(Duration::from_millis(1)).await?;
    b.driver.step(Duration::from_millis(1)).await?;
    a.collect();
    b.collect();
    for candidate in std::mem::take(&mut a.outgoing) {
        b.driver.pc_mut().add_remote_candidate(candidate)?;
    }
    for candidate in std::mem::take(&mut b.outgoing) {
        a.driver.pc_mut().add_remote_candidate(candidate)?;
    }
    Ok(())
}

/// Rounds until `done`, at most `limit` of wall time.
async fn run_until(
    a: &mut Side,
    b: &mut Side,
    limit: Duration,
    done: impl Fn(&Side, &Side) -> bool,
) -> Result<bool> {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        round(a, b).await?;
        if done(a, b) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Rounds for `duration` of wall time.
async fn run_for(a: &mut Side, b: &mut Side, duration: Duration) -> Result<()> {
    run_until(a, b, duration, |_, _| false).await.map(|_| ())
}

/// `a` offers, `b` answers. Returns the answer.
fn exchange(a: &mut Side, b: &mut Side) -> Result<String> {
    let now = Instant::now();
    let offer = a.driver.pc_mut().create_offer(None)?;
    a.driver
        .pc_mut()
        .set_local_description(now, offer.clone())?;
    b.driver.pc_mut().set_remote_description(now, offer)?;
    let answer = b.driver.pc_mut().create_answer(None)?;
    b.driver
        .pc_mut()
        .set_local_description(now, answer.clone())?;
    a.driver
        .pc_mut()
        .set_remote_description(now, answer.clone())?;
    a.driver.flush()?;
    b.driver.flush()?;
    a.negotiation_needed = false;
    Ok(answer.sdp)
}

fn sendrecv() -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Sendrecv,
        streams: vec![],
        send_encodings: vec![RTCRtpEncodingParameters {
            active: true,
            ..Default::default()
        }],
    })
}

/// Writes one Opus packet on the transceiver's sender.
fn write_audio(side: &mut Side, transceiver: RTCRtpTransceiverId, seq: u16) -> Result<()> {
    let pc = side.driver.pc_mut();
    let sender = pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .ok_or("a sender")?;
    let mut sender = pc.rtp_sender(sender).ok_or("the sender")?;
    let parameters = sender.get_parameters();
    let ssrc = parameters.encodings[0]
        .rtp_coding_parameters
        .ssrc
        .ok_or("an SSRC")?;
    let payload_type = parameters
        .rtp_parameters
        .codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("audio/opus"))
        .ok_or("opus")?
        .payload_type;
    sender.write_rtp(
        Instant::now(),
        rtci::rtp::Packet {
            header: rtci::rtp::header::Header {
                version: 2,
                payload_type,
                sequence_number: seq,
                timestamp: u32::from(seq) * 960,
                ssrc,
                marker: true,
                ..Default::default()
            },
            payload: Bytes::from(vec![0x10u8; 60]),
        },
    )?;
    side.driver.flush()?;
    Ok(())
}

/// Two sides connected over an audio transceiver of `a`. Returns the transceiver.
async fn connected(a: &mut Side, b: &mut Side) -> Result<RTCRtpTransceiverId> {
    let audio = a
        .driver
        .pc_mut()
        .add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    exchange(a, b)?;
    let up = run_until(a, b, Duration::from_secs(20), |a, b| {
        a.connected() && b.connected()
    })
    .await?;
    assert!(up, "connected");
    Ok(audio)
}

fn disjoint(before: &[SocketAddr], after: &[SocketAddr]) -> bool {
    !after.iter().any(|addr| before.contains(addr))
}

/// Stop the only transceiver, then add one: the answer that rejects every m= section closes
/// the transport, and the next exchange sets up a new one on which the previous UDP addresses
/// are refused. The driver gathers for it on new ports by itself and media flows; the
/// previous sockets are closed (the transport they served is gone).
#[tokio::test]
async fn stop_all_then_add_carries_media_on_new_sockets() -> Result<()> {
    let mut a = Side::new(SettingEngineBuilder::new())?;
    let mut b = Side::new(SettingEngineBuilder::new())?;
    let audio = connected(&mut a, &mut b).await?;
    let before = (a.driver.local_addresses(), b.driver.local_addresses());
    assert_eq!((before.0.len(), before.1.len()), (1, 1), "a socket each");

    a.driver
        .pc_mut()
        .rtp_transceiver(audio)
        .ok_or("the transceiver")?
        .stop()?;
    let answer = exchange(&mut a, &mut b)?;
    let ports: Vec<&str> = answer
        .lines()
        .filter(|l| l.starts_with("m="))
        .filter_map(|l| l.split(' ').nth(1))
        .collect();
    assert_eq!(ports, vec!["0"], "every section is rejected:\n{answer}");
    run_for(&mut a, &mut b, Duration::from_millis(200)).await?;

    let audio = a
        .driver
        .pc_mut()
        .add_transceiver_from_kind(RtpCodecKind::Audio, sendrecv())?;
    exchange(&mut a, &mut b)?;
    let up = run_until(&mut a, &mut b, Duration::from_secs(20), |a, b| {
        a.connected() && b.connected()
    })
    .await?;
    assert!(up, "connected on the new transport");
    for (who, side) in [("a", &a), ("b", &b)] {
        let reasons: Vec<_> = side.needed.iter().map(|n| n.reason).collect();
        assert_eq!(
            reasons,
            vec![RTCLocalCandidatesNeededReason::TransportReplaced],
            "{who}"
        );
    }
    b.rtp.clear();
    for seq in 1..=50u16 {
        write_audio(&mut a, audio, seq)?;
        run_for(&mut a, &mut b, Duration::from_millis(5)).await?;
    }
    run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
        b.rtp.len() >= 50
    })
    .await?;
    let received: HashSet<u16> = b.rtp.iter().copied().collect();
    let missing: Vec<u16> = (1..=50).filter(|s| !received.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "media on the new transport: missing {missing:?}"
    );
    for (who, side, before) in [("a", &a, &before.0), ("b", &b, &before.1)] {
        let after = side.driver.local_addresses();
        assert_eq!(
            after.len(),
            1,
            "{who}: the previous socket is closed: {after:?}"
        );
        assert!(
            disjoint(before, &after),
            "{who}: a new port: {before:?} -> {after:?}"
        );
    }
    Ok(())
}

/// Automatic SRTP re-keying (RFC 5764 section 4.4) with a short key lifetime: before `a`'s
/// key runs out the engine asks for a new DTLS association, the application only answers
/// negotiation-needed, and the driver moves both sides to new ports by itself (reason
/// `SrtpRekeying` on `a`, `NewDtlsAssociation` on `b`). Every packet written across the renewal
/// arrives; the previous sockets close once a pair on the new ones is selected.
#[tokio::test]
async fn automatic_srtp_re_keying_carries_every_packet_onto_new_sockets() -> Result<()> {
    const PACKETS: u16 = 1100;
    let lifetime = Some(rtci::srtp::keying::KeyLifetime {
        srtp_packets: 960,
        srtcp_packets: 1 << 31,
    });
    let mut a = Side::new(SettingEngineBuilder::new().with_srtp_key_lifetime(lifetime))?;
    let mut b = Side::new(SettingEngineBuilder::new())?;
    let audio = connected(&mut a, &mut b).await?;
    let before = (a.driver.local_addresses(), b.driver.local_addresses());
    b.rtp.clear();
    let mut renewals = 0;
    for seq in 1..=PACKETS {
        write_audio(&mut a, audio, seq)?;
        run_for(&mut a, &mut b, Duration::from_millis(10)).await?;
        if a.negotiation_needed
            && [&a, &b]
                .iter()
                .all(|s| s.driver.pc().signaling_state() == RTCSignalingState::Stable)
        {
            exchange(&mut a, &mut b)?;
            renewals += 1;
        }
    }
    run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
        b.rtp.len() >= usize::from(PACKETS)
    })
    .await?;
    assert!(renewals >= 1, "the engine asked for a new association");
    let received: HashSet<u16> = b.rtp.iter().copied().collect();
    let missing: Vec<u16> = (1..=PACKETS).filter(|s| !received.contains(s)).collect();
    let start = b
        .dtls_connected
        .first()
        .copied()
        .unwrap_or_else(Instant::now);
    let at = |t: &Instant| t.saturating_duration_since(start);
    assert!(
        missing.is_empty(),
        "{} packets lost across {renewals} renewals: {missing:?}; discarded by SRTP at b \
         (index, replay, at): {:?}; b's DTLS connected at {:?}",
        missing.len(),
        b.discarded
            .iter()
            .map(|(i, r, t)| (*i, *r, at(t)))
            .collect::<Vec<_>>(),
        b.dtls_connected.iter().map(at).collect::<Vec<_>>()
    );
    for (who, side, reason) in [
        ("a", &a, RTCLocalCandidatesNeededReason::SrtpRekeying),
        ("b", &b, RTCLocalCandidatesNeededReason::NewDtlsAssociation),
    ] {
        assert!(!side.needed.is_empty(), "{who}: told to gather");
        assert!(
            side.needed.iter().all(|n| n.reason == reason),
            "{who}: {:?}",
            side.needed
        );
    }
    run_for(&mut a, &mut b, LINGER * 3).await?;
    for (who, side, before) in [("a", &a, &before.0), ("b", &b, &before.1)] {
        let after = side.driver.local_addresses();
        assert_eq!(
            after.len(),
            1,
            "{who}: the previous sockets are closed once the new pair is selected (after the \
             linger): {after:?}"
        );
        assert!(
            disjoint(before, &after),
            "{who}: a new port: {before:?} -> {after:?}"
        );
    }
    Ok(())
}

/// `with_dtls_new_association_on_previous_addresses(true)`: a new DTLS association keeps the
/// candidates, no `OnLocalCandidatesNeeded` is fired, and the driver keeps its sockets; media
/// flows on them over the new association once it is up.
#[tokio::test]
async fn with_the_opt_out_the_driver_keeps_its_sockets() -> Result<()> {
    let settings =
        || SettingEngineBuilder::new().with_dtls_new_association_on_previous_addresses(true);
    let mut a = Side::new(settings())?;
    let mut b = Side::new(settings())?;
    let audio = connected(&mut a, &mut b).await?;
    let before = (a.driver.local_addresses(), b.driver.local_addresses());
    let tls_id = |side: &Side| {
        side.driver
            .pc()
            .local_description()
            .map(|d| d.sdp)
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix("a=tls-id:").map(str::to_owned))
    };
    let first = tls_id(&a);
    a.driver.pc_mut().renew_dtls_association();
    exchange(&mut a, &mut b)?;
    assert_ne!(tls_id(&a), first, "a new association");
    // On the same 3-tuple the two associations' packets cannot be told apart (what RFC 8842
    // section 5.1 avoids with a new one), so a packet sent across the switch may be lost: the
    // media is sent once the new association is up.
    run_for(&mut a, &mut b, Duration::from_secs(1)).await?;
    assert!(
        a.connected() && b.connected(),
        "connected over the new association"
    );
    b.rtp.clear();
    for seq in 1..=100u16 {
        write_audio(&mut a, audio, seq)?;
        run_for(&mut a, &mut b, Duration::from_millis(5)).await?;
    }
    run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
        b.rtp.len() >= 100
    })
    .await?;
    let received: HashSet<u16> = b.rtp.iter().copied().collect();
    let missing: Vec<u16> = (1..=100).filter(|s| !received.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "media over the new association: missing {missing:?}"
    );
    for (who, side, before) in [("a", &a, &before.0), ("b", &b, &before.1)] {
        assert!(side.needed.is_empty(), "{who}: {:?}", side.needed);
        assert_eq!(
            &side.driver.local_addresses(),
            before,
            "{who}: the same sockets"
        );
    }
    Ok(())
}

/// Both sides with the same key lifetime and each asking at the lifetime warning
/// (`with_srtp_rekeying_dtls_client_first(false)`): `a`'s outbound key and `b`'s inbound key
/// near their end on the same packet, both raise negotiation-needed and both offer a new
/// association (glare). The application does what W3C "perfect negotiation" does: `a`, the
/// polite side, rolls its offer back and answers `b`'s; `b` ignores `a`'s offer, and the
/// candidates `a` gathered for it, which `b` refuses. The rollback takes back `a`'s restart
/// (RFC 9429 section 5.7) after its driver already bound a socket for it: the driver closes
/// that socket and keeps the previous one carrying the media; the answer's new association
/// moves both sides to new sockets. Every packet arrives, and each side ends on one socket,
/// a new one.
#[tokio::test]
async fn crossing_re_keying_offers_are_rolled_back_and_carry_every_packet() -> Result<()> {
    const PACKETS: u16 = 1100;
    let settings = || {
        SettingEngineBuilder::new()
            .with_srtp_key_lifetime(Some(rtci::srtp::keying::KeyLifetime {
                srtp_packets: 960,
                srtcp_packets: 1 << 31,
            }))
            .with_srtp_rekeying_dtls_client_first(false)
    };
    let mut a = Side::new(settings())?;
    let mut b = Side::new(settings())?;
    let audio = connected(&mut a, &mut b).await?;
    let before = (a.driver.local_addresses(), b.driver.local_addresses());
    a.negotiation_needed = false;
    b.negotiation_needed = false;
    b.rtp.clear();
    let mut collisions = 0;
    let mut exchanges = 0;
    let stable = |a: &Side, b: &Side| {
        [a, b]
            .iter()
            .all(|s| s.driver.pc().signaling_state() == RTCSignalingState::Stable)
    };
    for seq in 1..=PACKETS {
        write_audio(&mut a, audio, seq)?;
        run_for(&mut a, &mut b, Duration::from_millis(10)).await?;
        if !stable(&a, &b) {
            continue;
        }
        match (a.negotiation_needed, b.negotiation_needed) {
            (true, true) => {
                collide(&mut a, &mut b)?;
                collisions += 1;
            }
            (true, false) => {
                exchange(&mut a, &mut b)?;
                exchanges += 1;
            }
            (false, true) => {
                exchange(&mut b, &mut a)?;
                b.negotiation_needed = false;
                exchanges += 1;
            }
            (false, false) => {}
        }
    }
    run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
        b.rtp.len() >= usize::from(PACKETS)
    })
    .await?;
    assert!(
        collisions >= 1,
        "the offers crossed ({exchanges} plain exchanges)"
    );
    let received: HashSet<u16> = b.rtp.iter().copied().collect();
    let missing: Vec<u16> = (1..=PACKETS).filter(|s| !received.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "{} packets lost across {collisions} collisions and {exchanges} exchanges: {missing:?}",
        missing.len()
    );
    run_for(&mut a, &mut b, LINGER * 3).await?;
    for (who, side, before) in [("a", &a, &before.0), ("b", &b, &before.1)] {
        let after = side.driver.local_addresses();
        assert_eq!(
            after.len(),
            1,
            "{who}: one socket left, the rolled-back offer's and the previous ones closed: \
             {after:?}"
        );
        assert!(
            disjoint(before, &after),
            "{who}: a new port: {before:?} -> {after:?}"
        );
    }
    Ok(())
}

/// Both sides offer; `polite` rolls its offer back and answers the other's, which ignores the
/// polite side's offer and its candidates (W3C webrtc-pc "perfect negotiation").
fn collide(polite: &mut Side, impolite: &mut Side) -> Result<()> {
    let now = Instant::now();
    let abandoned = polite.driver.pc_mut().create_offer(None)?;
    polite
        .driver
        .pc_mut()
        .set_local_description(now, abandoned)?;
    let offer = impolite.driver.pc_mut().create_offer(None)?;
    impolite
        .driver
        .pc_mut()
        .set_local_description(now, offer.clone())?;
    polite.driver.flush()?;
    impolite.driver.flush()?;
    polite.collect();
    impolite.collect();
    // The candidates of the abandoned offer's generation: the impolite side refuses them (it
    // never applied that offer), and ignores the error, as perfect negotiation does.
    for candidate in std::mem::take(&mut polite.outgoing) {
        let _ = impolite.driver.pc_mut().add_remote_candidate(candidate);
    }
    let pc = polite.driver.pc_mut();
    pc.set_local_description(
        now,
        rtci::peer_connection::sdp::RTCSessionDescription::rollback(None)?,
    )?;
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    impolite
        .driver
        .pc_mut()
        .set_remote_description(now, answer)?;
    polite.driver.flush()?;
    impolite.driver.flush()?;
    polite.negotiation_needed = false;
    impolite.negotiation_needed = false;
    Ok(())
}

/// RFC 8837 / RFC 8835 section 4.2 through the driver: each datagram leaves its UDP socket
/// with the DSCP (and ECN bits) the engine gives it (`RTCPeerConnection::traffic_class`), set
/// with `IP_TOS` before the datagram when it differs from the socket's. Audio at `high` is EF
/// (46): its packets leave a socket set to TOS 184, while STUN and RTCP leave it at 0; the
/// operating system reports the byte set (`getsockopt`, `sockets.rs`). Under
/// `RTCDscpMarking::Off` the socket is never marked. The audio arrives either way. On Windows,
/// where `IP_TOS` does not mark (see `sockets::set_traffic_class`), what happened is printed,
/// not asserted.
#[tokio::test]
async fn the_driver_marks_each_datagram_with_its_flows_codepoint() -> Result<()> {
    use rtci::peer_connection::priority::{RTCDscpMarking, RTCPriorityType};
    for marking in [RTCDscpMarking::Rfc8837, RTCDscpMarking::Off] {
        // UDP only: on loopback the engine's ICE-TCP pair would otherwise carry the call (its
        // connections are marked by `StreamDriver`, `loopback.rs`).
        let mut a = Side::new(
            SettingEngineBuilder::new()
                .with_dscp_marking(marking)
                .with_tcp_candidate_gathering(false),
        )?;
        let mut b = Side::new(SettingEngineBuilder::new().with_tcp_candidate_gathering(false))?;
        let audio = connected(&mut a, &mut b).await?;
        {
            let pc = a.driver.pc_mut();
            let sender = pc
                .rtp_transceiver(audio)
                .and_then(|t| t.sender())
                .ok_or("a sender")?;
            let mut sender = pc.rtp_sender(sender).ok_or("the sender")?;
            let mut parameters = sender.get_parameters().clone();
            parameters.encodings[0].priority = RTCPriorityType::High;
            sender.set_parameters(parameters, None)?;
        }
        for seq in 1..=20 {
            write_audio(&mut a, audio, seq)?;
            round(&mut a, &mut b).await?;
        }
        run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
            !b.rtp.is_empty()
        })
        .await?;
        assert!(!b.rtp.is_empty(), "{marking:?}: audio arrives");
        let sent = a.driver.sent_by_traffic_class().clone();
        let locals = a.driver.local_addresses();
        println!(
            "{marking:?}: sent by traffic class {sent:?}, unmarked sockets {}, socket now {:?}",
            a.driver.unmarked_sockets(),
            locals
                .first()
                .and_then(|l| a.driver.socket_traffic_class(*l))
                .map(|r| r.ok()),
        );
        #[cfg(not(windows))]
        {
            assert_eq!(a.driver.unmarked_sockets(), 0);
            match marking {
                RTCDscpMarking::Off => {
                    assert_eq!(sent.keys().copied().collect::<Vec<u8>>(), vec![0])
                }
                _ => {
                    assert!(sent.get(&(46 << 2)).is_some_and(|n| *n >= 20), "{sent:?}");
                    assert!(
                        sent.get(&0).is_some_and(|n| *n > 0),
                        "STUN and RTCP: {sent:?}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// RFC 6544 section 6.1 over real sockets: two lite peers (both descriptions `a=ice-lite`, no
/// connectivity check from either), the offerer's active TCP candidate and the answerer's
/// passive one the only candidates carried. The offerer opens the connection of the pair it
/// selects, the answerer carries its side of the DTLS handshake on the connection it
/// accepted, and the offerer's media arrives.
#[tokio::test]
async fn two_lite_peers_connect_over_tcp_and_carry_media() -> Result<()> {
    let lite = || SettingEngineBuilder::new().with_lite(true);
    let mut a = Side::new(lite())?;
    let mut b = Side::new(lite())?;
    a.carry = Some("active");
    b.carry = Some("passive");
    let audio = connected(&mut a, &mut b).await?;
    for seq in 1..=50u16 {
        write_audio(&mut a, audio, seq)?;
        run_for(&mut a, &mut b, Duration::from_millis(5)).await?;
    }
    let all = run_until(&mut a, &mut b, Duration::from_secs(5), |_, b| {
        b.rtp.len() >= 50
    })
    .await?;
    let received: HashSet<u16> = b.rtp.iter().copied().collect();
    let missing: Vec<u16> = (1..=50).filter(|s| !received.contains(s)).collect();
    assert!(
        all && missing.is_empty(),
        "media over TCP: missing {missing:?}"
    );
    Ok(())
}

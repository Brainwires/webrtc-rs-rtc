//! W3C webrtc 5.5.1: a DTLS transport whose handshake fails — here because the certificate the
//! peer presents does not match the `a=fingerprint` signalled for it — goes to "failed", and the
//! peer connection follows (W3C webrtc 4.3.3, "failed" when any DTLS transport is). Before, no
//! code set `RTCDtlsTransportState::Failed`: the handshake error was logged and dropped, and both
//! connections sat in "connecting" for as long as ICE held.
//!
//! The peers exchange datagrams in memory, on a virtual clock, as
//! `data_channels_negotiated_first_message_rtc2rtc.rs` does.

use anyhow::Result;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// A fingerprint that matches no certificate.
const WRONG_FINGERPRINT: &str = "a=fingerprint:sha-256 \
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:\
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF";

/// How far the virtual clock may run before the test gives up.
const DEADLINE: Duration = Duration::from_secs(30);

/// A bound on the turns, should a timer keep firing without the clock moving.
const MAX_TURNS: usize = 10_000;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    /// Datagrams that reached this peer and that it has not read yet.
    inbox: Vec<TaggedBytesMut>,
    /// Every peer connection state it reported, in order.
    states: Vec<RTCPeerConnectionState>,
    /// Every DTLS transport state change it reported, in order.
    dtls_states: Vec<RTCDtlsTransportState>,
    /// How many DTLS transport `error` events it reported.
    dtls_errors: usize,
}

impl Peer {
    fn new(addr: SocketAddr, answering_dtls_role: RTCDtlsRole, now: Instant) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(answering_dtls_role)
                    .build(),
            )
            .build(now)?;
        let host = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            states: Vec::new(),
            dtls_states: Vec::new(),
            dtls_errors: 0,
        })
    }

    /// One turn: everything that reached this peer, then its events and reads. Returns the
    /// datagrams it wrote.
    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    self.states.push(state);
                }
                RTCPeerConnectionEvent::OnDtlsTransportStateChange(state) => {
                    self.dtls_states.push(state);
                }
                RTCPeerConnectionEvent::OnDtlsTransportError(_) => self.dtls_errors += 1,
                _ => {}
            }
        }
        while self.pc.poll_read().is_some() {}
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    /// Hands this peer the datagrams `from` wrote to it, as its socket would.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }

    fn reported_failed(&self) -> bool {
        self.states.contains(&RTCPeerConnectionState::Failed)
    }

    fn dtls_state(&self) -> Option<RTCDtlsTransportState> {
        self.pc.sctp().map(|sctp| sctp.transport().state())
    }
}

/// Replaces the `a=fingerprint` line, so the answerer expects a certificate the offerer will
/// never present.
fn with_wrong_fingerprint(sdp: &str) -> String {
    sdp.lines()
        .map(|line| {
            if line.starts_with("a=fingerprint:") {
                WRONG_FINGERPRINT
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

/// The answerer (the DTLS server) is told a fingerprint the offerer's certificate cannot match.
/// It rejects the certificate with a fatal alert and fails; the offerer, receiving that alert,
/// fails too. Both DTLS transports end in "failed", and both peer connections report "failed"
/// without ever reporting "connected".
#[test]
fn a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection() -> Result<()> {
    let start = Instant::now();
    let mut now = start;
    let mut offerer = Peer::new("127.0.0.1:50020".parse()?, RTCDtlsRole::Client, now)?;
    let mut answerer = Peer::new("127.0.0.1:50021".parse()?, RTCDtlsRole::Server, now)?;

    // A data channel, for the m-line that carries the DTLS parameters.
    offerer.pc.create_data_channel("probe", None)?;

    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    let mut tampered = offer;
    tampered.sdp = with_wrong_fingerprint(&tampered.sdp);
    answerer.pc.set_remote_description(now, tampered)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;

    let mut turns = 0;
    while !(offerer.reported_failed() && answerer.reported_failed())
        && now.duration_since(start) < DEADLINE
        && turns < MAX_TURNS
    {
        turns += 1;
        let written = offerer.turn()?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        offerer.deliver(answerer.addr, written, now);

        // Nothing in flight: move the clock to the next timer.
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }

    assert_eq!(
        answerer.dtls_state(),
        Some(RTCDtlsTransportState::Failed),
        "the answerer's DTLS transport, which rejected the certificate, is failed"
    );
    assert_eq!(
        offerer.dtls_state(),
        Some(RTCDtlsTransportState::Failed),
        "the offerer's DTLS transport, which received the fatal alert, is failed"
    );
    assert!(
        answerer.reported_failed(),
        "the answerer reported the connection failed: {:?}",
        answerer.states
    );
    assert!(
        offerer.reported_failed(),
        "the offerer reported the connection failed: {:?}",
        offerer.states
    );
    assert!(
        !answerer.states.contains(&RTCPeerConnectionState::Connected)
            && !offerer.states.contains(&RTCPeerConnectionState::Connected),
        "a connection whose DTLS handshake failed never reports connected"
    );

    offerer.pc.close()?;
    answerer.pc.close()?;
    Ok(())
}

/// A copy of a datagram.
fn copy(datagram: &TaggedBytesMut) -> TaggedBytesMut {
    TaggedBytesMut {
        now: datagram.now,
        transport: datagram.transport,
        message: datagram.message.clone(),
    }
}

/// W3C webrtc-pc 5.5: on a DTLS error "If the state of transport is already "failed", abort
/// these steps": a transport fails once. After both transports failed over the fingerprint
/// mismatch, every datagram of the handshake, the fatal alert among them, reaches each peer
/// again and the clocks run on: neither transport reports a second `error` or `statechange`,
/// nor its connection a second "failed".
#[test]
fn a_failed_dtls_transport_fails_once() -> Result<()> {
    let start = Instant::now();
    let mut now = start;
    let mut offerer = Peer::new("127.0.0.1:50022".parse()?, RTCDtlsRole::Client, now)?;
    let mut answerer = Peer::new("127.0.0.1:50023".parse()?, RTCDtlsRole::Server, now)?;
    offerer.pc.create_data_channel("probe", None)?;
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    let mut tampered = offer;
    tampered.sdp = with_wrong_fingerprint(&tampered.sdp);
    answerer.pc.set_remote_description(now, tampered)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;

    // Everything each peer wrote, to hand to the other again once both failed.
    let mut from_offerer = vec![];
    let mut from_answerer = vec![];
    let mut turns = 0;
    let mut replayed = false;
    let mut after_failure = Duration::ZERO;
    while now.duration_since(start) < DEADLINE && turns < MAX_TURNS {
        turns += 1;
        let written = offerer.turn()?;
        from_offerer.extend(written.iter().map(copy));
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        from_answerer.extend(written.iter().map(copy));
        offerer.deliver(answerer.addr, written, now);

        if !replayed && offerer.reported_failed() && answerer.reported_failed() {
            replayed = true;
            answerer.deliver(offerer.addr, from_offerer.iter().map(copy).collect(), now);
            offerer.deliver(answerer.addr, from_answerer.iter().map(copy).collect(), now);
            continue;
        }
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            if replayed && after_failure >= Duration::from_secs(10) {
                break;
            }
            let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + Duration::from_secs(1));
            let next = next.max(now + Duration::from_millis(10));
            if replayed {
                after_failure += next - now;
            }
            now = next;
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }
    assert!(replayed, "both transports failed before the deadline");

    for (who, peer) in [("offerer", &offerer), ("answerer", &answerer)] {
        assert_eq!(peer.dtls_errors, 1, "{who}: one error event");
        assert_eq!(
            peer.dtls_states
                .iter()
                .filter(|s| **s == RTCDtlsTransportState::Failed)
                .count(),
            1,
            "{who}: one statechange to failed: {:?}",
            peer.dtls_states
        );
        assert_eq!(
            peer.states
                .iter()
                .filter(|s| **s == RTCPeerConnectionState::Failed)
                .count(),
            1,
            "{who}: the connection failed once: {:?}",
            peer.states
        );
        assert_eq!(peer.dtls_state(), Some(RTCDtlsTransportState::Failed));
    }
    offerer.pc.close()?;
    answerer.pc.close()?;
    Ok(())
}

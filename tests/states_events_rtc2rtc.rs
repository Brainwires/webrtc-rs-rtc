//! W3C webrtc-pc states and events an API layer needs (sections 4.3, 4.4.1.3, 4.4.2, 4.8,
//! 5.5, 5.6, 11, 12): the state getters, the transports' `statechange`, `gatheringstatechange`,
//! `selectedcandidatepairchange` and `error` events in the spec's order, the end-of-candidates
//! indications, `close()` without events, and the `RTCError` details.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{
    ICE_SERVER_UNREACHABLE, RTCDataChannelEvent, RTCPeerConnectionEvent,
    RTCPeerConnectionIceErrorEvent,
};
use rtci::peer_connection::rtc_error::{RTCError, RTCErrorDetailType};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::{
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState, RTCSignalingState,
};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit, RTCIceTransportState, RTCSctpTransportState,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::sansio::Protocol;
use rtci::shared::error::Error;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(120);
const MAX_TURNS: usize = 50_000;

/// A fingerprint that matches no certificate.
const WRONG_FINGERPRINT: &str = "a=fingerprint:sha-256 \
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:\
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF";

fn host(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
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
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    inbox: Vec<TaggedBytesMut>,
    /// Every event, in order.
    events: Vec<RTCPeerConnectionEvent>,
    /// Whether the link to this peer is cut: what is sent to it is lost.
    cut: bool,
}

impl Peer {
    fn new(addr: SocketAddr, role: RTCDtlsRole, now: Instant) -> Result<Self> {
        Self::with_settings(addr, role, now, |s| s)
    }

    /// [`Peer::new`] with `settings` applied to its setting engine.
    fn with_settings(
        addr: SocketAddr,
        role: RTCDtlsRole,
        now: Instant,
        settings: impl FnOnce(SettingEngineBuilder) -> SettingEngineBuilder,
    ) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(
                settings(SettingEngineBuilder::new().with_answering_dtls_role(role)).build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            events: Vec::new(),
            cut: false,
        })
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.pc.poll_event() {
            self.events.push(event);
        }
    }

    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        self.drain_events();
        while self.pc.poll_read().is_some() {}
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        if self.cut {
            return;
        }
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

    /// The state events, as labels, in order.
    fn state_labels(&self) -> Vec<String> {
        self.events.iter().filter_map(label).collect()
    }
}

fn label(event: &RTCPeerConnectionEvent) -> Option<String> {
    Some(match event {
        RTCPeerConnectionEvent::OnIceTransportStateChange(s) => format!("ice-transport:{s}"),
        RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(s) => format!("ice:{s}"),
        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => format!("connection:{s}"),
        RTCPeerConnectionEvent::OnDtlsTransportStateChange(s) => format!("dtls:{s}"),
        RTCPeerConnectionEvent::OnDtlsTransportError(e) => format!("dtls-error:{}", e.error_detail),
        RTCPeerConnectionEvent::OnSctpTransportStateChange(s) => format!("sctp:{s}"),
        RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_) => "pair".to_owned(),
        RTCPeerConnectionEvent::OnIceGathererStateChange(s) => format!("gatherer:{s}"),
        RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(s) => format!("gathering:{s}"),
        _ => return None,
    })
}

fn position(labels: &[String], wanted: &str) -> usize {
    labels
        .iter()
        .position(|l| l == wanted)
        .unwrap_or_else(|| panic!("no {wanted} in {labels:?}"))
}

/// Offer, answer and both candidates; `tamper` may change the offer the answerer sees.
fn negotiate(
    offerer: &mut Peer,
    answerer: &mut Peer,
    now: Instant,
    tamper: impl Fn(String) -> String,
) -> Result<()> {
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(tamper(offer.sdp))?)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;
    let (offerer_addr, answerer_addr) = (offerer.addr, answerer.addr);
    offerer.pc.add_local_candidate(host(offerer_addr)?)?;
    answerer.pc.add_local_candidate(host(answerer_addr)?)?;
    offerer.pc.add_remote_candidate(host(answerer_addr)?)?;
    answerer.pc.add_remote_candidate(host(offerer_addr)?)?;
    Ok(())
}

/// Runs both peers until `done` holds or the deadline passes. Returns the virtual time.
fn run(
    offerer: &mut Peer,
    answerer: &mut Peer,
    mut now: Instant,
    start: Instant,
    done: impl Fn(&Peer, &Peer) -> bool,
) -> Result<Instant> {
    let mut turns = 0;
    while !done(offerer, answerer) && now.duration_since(start) < DEADLINE && turns < MAX_TURNS {
        turns += 1;
        let written = offerer.turn()?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        offerer.deliver(answerer.addr, written, now);
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
    Ok(now)
}

fn with_wrong_fingerprint(sdp: String) -> String {
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

/// W3C 4.3, 4.4.2-7 to -10: the getters start at their initial values and follow the
/// connection.
#[test]
fn the_state_getters_report_the_initial_states_and_follow_negotiation() -> Result<()> {
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    assert_eq!(pc.signaling_state(), RTCSignalingState::Stable);
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::New);
    assert_eq!(pc.ice_connection_state(), RTCIceConnectionState::New);
    assert_eq!(pc.connection_state(), RTCPeerConnectionState::New);

    pc.create_data_channel("d", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    assert_eq!(pc.signaling_state(), RTCSignalingState::HaveLocalOffer);
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::Gathering);
    Ok(())
}

/// W3C 4.4.1.3, 5.5, 5.6 and 6.1.4: as two peers connect, each transport announces its own
/// state change before the connection-level event it causes, the selected pair is announced,
/// and the SCTP transport reports "connected". Then the link is cut: "disconnected" and
/// "failed" come in the same order.
#[test]
fn transport_state_events_come_before_the_connection_events_they_cause() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51020".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51021".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;

    let sctp_connected = |p: &Peer| {
        p.pc.sctp()
            .is_some_and(|s| s.state() == RTCSctpTransportState::Connected)
    };
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        sctp_connected(a) && sctp_connected(b)
    })?;
    offerer.drain_events();
    answerer.drain_events();

    for peer in [&offerer, &answerer] {
        let labels = peer.state_labels();
        assert!(
            position(&labels, "ice-transport:checking") < position(&labels, "ice:checking"),
            "{labels:?}"
        );
        assert!(
            position(&labels, "ice-transport:connected") < position(&labels, "ice:connected"),
            "{labels:?}"
        );
        assert!(
            position(&labels, "dtls:connecting") < position(&labels, "dtls:connected"),
            "{labels:?}"
        );
        assert!(
            position(&labels, "dtls:connected") < position(&labels, "connection:connected"),
            "{labels:?}"
        );
        assert!(labels.contains(&"sctp:connected".to_owned()), "{labels:?}");
        assert!(
            !labels.iter().any(|l| l.starts_with("sctp:connecting")),
            "the SCTP transport is created connecting, without an event: {labels:?}"
        );
        let announced: Vec<_> = peer
            .events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnSelectedCandidatePairChange(pair) => Some(pair.clone()),
                _ => None,
            })
            .collect();
        let selected = peer
            .pc
            .sctp()
            .expect("sctp")
            .transport()
            .ice_transport()
            .get_selected_candidate_pair();
        assert_eq!(
            announced.last().cloned(),
            selected,
            "the selected pair is announced"
        );
        assert_eq!(
            peer.pc.ice_connection_state(),
            RTCIceConnectionState::Connected
        );
        assert_eq!(
            peer.pc.connection_state(),
            RTCPeerConnectionState::Connected
        );
    }

    // The link goes: consent lapses (RFC 7675), the transport is disconnected. With no
    // end-of-candidates on either side it stays so (W3C 5.6.4: "failed" needs the transport to
    // have "finished gathering, received an indication that there are no more remote
    // candidates"; until then "disconnected"), past the consent expiry and the checking
    // timeout: the run ends at its deadline, 120 s on.
    let before = offerer.events.len();
    offerer.cut = true;
    answerer.cut = true;
    let now = run(&mut offerer, &mut answerer, now, now, |a, _| {
        a.pc.ice_connection_state() == RTCIceConnectionState::Failed
    })?;
    offerer.drain_events();
    let labels: Vec<String> = offerer.events[before..].iter().filter_map(label).collect();
    assert!(
        position(&labels, "ice-transport:disconnected") < position(&labels, "ice:disconnected")
            && position(&labels, "ice:disconnected") < position(&labels, "connection:disconnected"),
        "{labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l.ends_with(":failed")),
        "failed without the end of the candidates: {labels:?}"
    );
    assert_eq!(
        offerer.pc.ice_connection_state(),
        RTCIceConnectionState::Disconnected
    );

    // The application ends its gathering and relays the peer's end-of-candidates: "failed"
    // comes, in the same order.
    let before = offerer.events.len();
    offerer
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    offerer.pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    })?;
    run(&mut offerer, &mut answerer, now, now, |a, _| {
        a.pc.ice_connection_state() == RTCIceConnectionState::Failed
    })?;
    offerer.drain_events();
    let labels: Vec<String> = offerer.events[before..].iter().filter_map(label).collect();
    assert!(
        position(&labels, "ice-transport:failed") < position(&labels, "ice:failed")
            && position(&labels, "ice:failed") < position(&labels, "connection:failed"),
        "{labels:?}"
    );
    Ok(())
}

/// W3C 5.6.4: "The failed and completed states require an indication that there are no
/// additional remote candidates. This can be indicated by calling addIceCandidate with a
/// candidate value whose candidate property is set to an empty string or by
/// canTrickleIceCandidates being set to false." The answerer receives an offer without
/// `a=ice-options:trickle` (`canTrickleIceCandidates` false) and ends its own gathering; the
/// offerer does not end its gathering (its answer, which repeats only the options the offer
/// had, RFC 9429 section 5.3.1, says no `trickle` either, so the offerer has the remote
/// indication but not its own). The link is cut: the answerer's transport fails, the
/// offerer's stays "disconnected".
#[test]
fn a_peer_that_cannot_trickle_is_the_indication_that_no_candidate_is_to_come() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51120".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51121".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    let without_trickle = |sdp: String| {
        sdp.lines()
            .filter(|line| !line.starts_with("a=ice-options:"))
            .collect::<Vec<_>>()
            .join("\r\n")
            + "\r\n"
    };
    negotiate(&mut offerer, &mut answerer, start, without_trickle)?;
    assert_eq!(answerer.pc.can_trickle_ice_candidates(), Some(false));
    answerer
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    let connected = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Connected;
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        connected(a) && connected(b)
    })?;
    assert_eq!(
        answerer.pc.ice_connection_state(),
        RTCIceConnectionState::Completed,
        "nothing to come on either side for the answerer"
    );

    offerer.cut = true;
    answerer.cut = true;
    run(&mut offerer, &mut answerer, now, now, |_, b| {
        b.pc.ice_connection_state() == RTCIceConnectionState::Failed
    })?;
    assert_eq!(
        answerer.pc.ice_connection_state(),
        RTCIceConnectionState::Failed
    );
    assert_eq!(
        offerer.pc.ice_connection_state(),
        RTCIceConnectionState::Disconnected
    );
    Ok(())
}

/// `SettingEngineBuilder::with_ice_failed_without_end_of_candidates(true)` (the `Chrome`
/// profile, libwebrtc's form; RFC 8863 section 5: the PAC timer as the end-of-candidates
/// fallback): with nothing signalled, a cut link fails both transports once consent has
/// lapsed and the PAC timer (39.5 s) has expired.
#[test]
fn a_cut_link_fails_without_the_end_of_candidates_when_set_to() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::with_settings(
        "127.0.0.1:51130".parse()?,
        RTCDtlsRole::Client,
        start,
        |s| s.with_ice_failed_without_end_of_candidates(true),
    )?;
    let mut answerer = Peer::with_settings(
        "127.0.0.1:51131".parse()?,
        RTCDtlsRole::Server,
        start,
        |s| s.with_ice_failed_without_end_of_candidates(true),
    )?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let connected = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Connected;
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        connected(a) && connected(b)
    })?;
    offerer.cut = true;
    answerer.cut = true;
    let failed = |p: &Peer| p.pc.ice_connection_state() == RTCIceConnectionState::Failed;
    let at = run(&mut offerer, &mut answerer, now, now, |a, b| {
        failed(a) && failed(b)
    })?;
    assert!(failed(&offerer) && failed(&answerer));
    assert!(
        at.duration_since(start) >= Duration::from_millis(39_500),
        "not before the PAC timer: {:?}",
        at.duration_since(start)
    );
    Ok(())
}

/// W3C 5.5 and 11.2: a certificate that matches no fingerprint fails the DTLS transport with
/// `fingerprint-failure` on the side that checked it, and with `dtls-failure` and the alert it
/// received on the other; the `error` event comes before the `statechange` to "failed", which
/// comes before the connection's.
#[test]
fn a_dtls_failure_is_announced_with_its_error_detail_before_the_state_change() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51030".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51031".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, with_wrong_fingerprint)?;
    let failed = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Failed;
    run(&mut offerer, &mut answerer, start, start, |a, b| {
        failed(a) && failed(b)
    })?;
    offerer.drain_events();
    answerer.drain_events();

    let error_of = |peer: &Peer| -> RTCError {
        peer.events
            .iter()
            .find_map(|e| match e {
                RTCPeerConnectionEvent::OnDtlsTransportError(error) => Some(error.clone()),
                _ => None,
            })
            .expect("an error event")
    };
    let answerer_error = error_of(&answerer);
    assert_eq!(
        answerer_error.error_detail,
        RTCErrorDetailType::FingerprintFailure
    );
    let offerer_error = error_of(&offerer);
    assert_eq!(offerer_error.error_detail, RTCErrorDetailType::DtlsFailure);
    assert!(
        offerer_error.received_alert.is_some(),
        "the offerer received the answerer's fatal alert: {offerer_error:?}"
    );
    for peer in [&offerer, &answerer] {
        let labels = peer.state_labels();
        let error = labels
            .iter()
            .position(|l| l.starts_with("dtls-error:"))
            .expect("error");
        assert!(error < position(&labels, "dtls:failed"), "{labels:?}");
        assert!(
            position(&labels, "dtls:failed") < position(&labels, "connection:failed"),
            "{labels:?}"
        );
    }
    Ok(())
}

/// W3C close(): the transceivers are stopped and every state becomes "closed" without an
/// event (4.4.2-78 to -85); the getters say so.
#[test]
fn close_sets_every_state_to_closed_without_an_event() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51040".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51041".parse()?, RTCDtlsRole::Server, start)?;
    let channel = offerer.pc.create_data_channel("probe", None)?.id();
    let transceiver = offerer
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let connected = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Connected;
    run(&mut offerer, &mut answerer, start, start, |a, b| {
        connected(a) && connected(b)
    })?;
    offerer.drain_events();
    assert!(
        offerer
            .pc
            .sctp()
            .expect("sctp")
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .is_some()
    );

    let before = offerer.events.len();
    offerer.pc.close()?;
    offerer.drain_events();
    let labels: Vec<String> = offerer.events[before..].iter().filter_map(label).collect();
    assert!(
        labels.is_empty(),
        "close() fires no state event: {labels:?}"
    );
    assert_eq!(
        offerer.pc.connection_state(),
        RTCPeerConnectionState::Closed
    );
    assert_eq!(
        offerer.pc.ice_connection_state(),
        RTCIceConnectionState::Closed
    );
    assert_eq!(offerer.pc.signaling_state(), RTCSignalingState::Closed);
    let sctp = offerer.pc.sctp().expect("sctp");
    assert_eq!(sctp.transport().state(), RTCDtlsTransportState::Closed);
    assert_eq!(
        sctp.transport().ice_transport().state(),
        RTCIceTransportState::Closed
    );
    assert_eq!(
        sctp.transport()
            .ice_transport()
            .get_selected_candidate_pair(),
        None,
        "no selected pair in the closed state"
    );
    assert_eq!(sctp.state(), RTCSctpTransportState::Closed);
    assert_eq!(
        offerer
            .pc
            .data_channel(channel)
            .expect("the channel")
            .ready_state(),
        rtci::data_channel::RTCDataChannelState::Closed,
        "close() closes every data channel"
    );
    assert!(
        offerer
            .pc
            .rtp_transceiver(transceiver)
            .expect("transceiver")
            .is_stopped(),
        "close() stops every transceiver"
    );
    Ok(())
}

/// W3C 11.2 `sctp-failure`: the peer's close() aborts the association with a User-Initiated
/// Abort (RFC 9260 cause 12); the channels here fail with that cause code.
#[test]
fn a_data_channel_failed_by_an_abort_reports_the_sctp_cause_code() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51050".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51051".parse()?, RTCDtlsRole::Server, start)?;
    let channel = offerer.pc.create_data_channel("probe", None)?.id();
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let open = |p: &Peer| {
        p.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
            )
        })
    };
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        open(a) && open(b)
    })?;

    answerer.pc.close()?;
    let failed = |p: &Peer| {
        p.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnError(_))
            )
        })
    };
    run(&mut offerer, &mut answerer, now, now, |a, _| failed(a))?;
    let error = offerer
        .pc
        .data_channel_error(channel)
        .expect("the channel's error is kept");
    assert_eq!(error.error_detail, RTCErrorDetailType::SctpFailure);
    assert_eq!(error.sctp_cause_code, Some(12), "User-Initiated Abort");
    Ok(())
}

/// W3C 5.6: gathering begins at the first local description, with the transport's and the
/// connection's events; each candidate names its section and generation; the end of gathering
/// is an empty candidate, the state "complete" and then a null candidate, once only. A later
/// description of the same generation does not gather again (the audit's bug: it reset the
/// state, and the end was announced again on every empty candidate); an ICE restart does.
#[test]
fn gathering_is_announced_once_per_ice_generation() -> Result<()> {
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    let mut events = Vec::new();
    let drain = |pc: &mut RTCPeerConnection, events: &mut Vec<RTCPeerConnectionEvent>| {
        events.clear();
        while let Some(event) = pc.poll_event() {
            events.push(event);
        }
    };
    pc.create_data_channel("d", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    drain(&mut pc, &mut events);
    let labels: Vec<String> = events.iter().filter_map(label).collect();
    assert_eq!(labels, ["gatherer:gathering", "gathering:gathering"]);
    let ufrag = pc
        .local_description()
        .expect("local description")
        .sdp
        .lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .map(str::to_owned)
        .expect("ufrag");

    pc.add_local_candidate(host("10.0.0.1:5000".parse()?)?)?;
    drain(&mut pc, &mut events);
    let candidate = events
        .iter()
        .find_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(e) => e.candidate.clone(),
            _ => None,
        })
        .expect("a candidate event");
    assert_eq!(candidate.sdp_mid.as_deref(), Some("0"));
    assert_eq!(candidate.sdp_mline_index, Some(0));
    assert_eq!(candidate.username_fragment.as_deref(), Some(ufrag.as_str()));
    let init = candidate.to_json()?;
    assert_eq!(init.sdp_mid.as_deref(), Some("0"));
    assert!(init.candidate.starts_with("candidate:"));

    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    drain(&mut pc, &mut events);
    let sequence: Vec<String> = events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(e) => Some(match &e.candidate {
                // RFC 9429 section 4.1.20: the end event's section fields "MAY be specified
                // to indicate that the event applies to a specific "m=" section": this
                // engine names the section of the transport whose gathering ended.
                Some(c) if c.end_of_candidates => format!(
                    "end:{}:{}:{:?}:{:?}",
                    c.to_json().expect("json").candidate.is_empty(),
                    c.username_fragment.as_deref() == Some(ufrag.as_str()),
                    c.sdp_mid.as_deref(),
                    c.sdp_mline_index
                ),
                Some(_) => "candidate".to_owned(),
                None => "null".to_owned(),
            }),
            other => label(other),
        })
        .collect();
    assert_eq!(
        sequence,
        [
            "end:true:true:Some(\"0\"):Some(0)",
            "gatherer:complete",
            "gathering:complete",
            "null"
        ]
    );
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    let local = pc.local_description().expect("local description").sdp;
    assert!(local.contains("a=end-of-candidates"), "{local}");
    assert!(local.contains("a=candidate:"), "{local}");

    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    drain(&mut pc, &mut events);
    assert!(
        events
            .iter()
            .all(|e| label(e).is_none()
                && !matches!(e, RTCPeerConnectionEvent::OnIceCandidateEvent(_))),
        "the end is announced once: {events:?}"
    );

    // Back to stable and a new offer of the same generation: still complete, no event.
    pc.set_local_description(now, RTCSessionDescription::rollback(None)?)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    drain(&mut pc, &mut events);
    assert!(
        events.iter().filter_map(label).next().is_none(),
        "{events:?}"
    );
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    Ok(())
}

/// W3C 5.6 and restartIce: every ICE generation gathers anew and ends anew. Two restarts in a
/// row (each completed by an answer) give three generations, and each announces "gathering",
/// its own candidates with its own ufrag, then the empty candidate, "complete" and the null
/// candidate. A candidate the agent kept across the restart and the application gathers
/// again is announced for the new generation (it was dropped silently as a duplicate, so the
/// peer, which discards the old generation's candidates, never learned it).
#[test]
fn each_ice_restart_gathers_and_ends_its_own_generation() -> Result<()> {
    let now = Instant::now();
    let mut offerer = RTCPeerConnectionBuilder::new().build(now)?;
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    offerer.create_data_channel("d", None)?;
    let drain = |pc: &mut RTCPeerConnection| {
        let mut sequence = Vec::new();
        while let Some(event) = pc.poll_event() {
            match &event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(e) => {
                    sequence.push(match &e.candidate {
                        Some(c) if c.end_of_candidates => {
                            format!("end:{}", c.username_fragment.clone().unwrap_or_default())
                        }
                        Some(c) => format!(
                            "candidate:{}",
                            c.username_fragment.clone().unwrap_or_default()
                        ),
                        None => "null".to_owned(),
                    })
                }
                other => {
                    if let Some(l) = label(other).filter(|l| l.starts_with("gathering:")) {
                        sequence.push(l);
                    }
                }
            }
        }
        sequence
    };
    let mut ufrags = Vec::new();
    for generation in 0..3 {
        if generation > 0 {
            offerer.restart_ice();
        }
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(now, offer.clone())?;
        let ufrag = offer
            .sdp
            .lines()
            .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
            .map(str::to_owned)
            .expect("ufrag");
        assert!(
            !ufrags.contains(&ufrag),
            "generation {generation} reuses {ufrag}"
        );
        ufrags.push(ufrag.clone());
        assert_eq!(
            drain(&mut offerer),
            ["gathering:gathering"],
            "generation {generation}"
        );
        // The same host candidate every generation (the agent keeps it across a restart): it
        // is announced once per generation, a second add in the same one is silent.
        offerer.add_local_candidate(host("10.0.0.1:5000".parse()?)?)?;
        offerer.add_local_candidate(host("10.0.0.1:5000".parse()?)?)?;
        offerer.add_local_candidate(RTCIceCandidateInit::default())?;
        assert_eq!(
            drain(&mut offerer),
            [
                format!("candidate:{ufrag}"),
                format!("end:{ufrag}"),
                "gathering:complete".to_owned(),
                "null".to_owned()
            ],
            "generation {generation}"
        );
        answerer.set_remote_description(now, offer)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        offerer.set_remote_description(now, answer)?;
        drain(&mut offerer);
    }
    Ok(())
}

/// W3C restartIce (4.4.2-69 to -71) and the negotiation-needed check's credentials step: the
/// call raises negotiation-needed, and every offer restarts ICE until an answer has replaced
/// the credentials, even after an offer was discarded. The new generation gathers anew.
#[test]
fn restart_ice_restarts_every_offer_until_an_answer_replaces_the_credentials() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51060".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51061".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let connected = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Connected;
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        connected(a) && connected(b)
    })?;
    offerer
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    offerer.drain_events();
    let ufrag = |sdp: &str| {
        sdp.lines()
            .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
            .map(str::to_owned)
            .expect("ufrag")
    };
    let current = ufrag(&offerer.pc.current_local_description().expect("current").sdp);

    let before = offerer.events.len();
    offerer.pc.restart_ice();
    offerer.drain_events();
    assert!(
        offerer.events[before..]
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent)),
        "restartIce updates the negotiation-needed flag"
    );

    let discarded = offerer.pc.create_offer(None)?;
    assert_ne!(
        ufrag(&discarded.sdp),
        current,
        "the first offer restarts ICE"
    );
    let offer = offerer.pc.create_offer(None)?;
    assert_ne!(
        ufrag(&offer.sdp),
        current,
        "an offer after a discarded one still restarts ICE"
    );

    let before = offerer.events.len();
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp)?)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;
    offerer.drain_events();
    let labels: Vec<String> = offerer.events[before..].iter().filter_map(label).collect();
    assert!(
        labels.contains(&"gathering:gathering".to_owned()),
        "the new generation gathers: {labels:?}"
    );
    let replaced = ufrag(&offerer.pc.create_offer(None)?.sdp);
    assert_eq!(
        replaced,
        ufrag(&offerer.pc.current_local_description().expect("current").sdp),
        "once the answer replaced the credentials, offers keep them"
    );
    Ok(())
}

/// W3C 11.1 / 11.2 `sdp-syntax-error`: a description that does not parse is refused with the
/// number of the offending line.
#[test]
fn an_sdp_syntax_error_carries_its_line_number() {
    let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nbogus line\r\nt=0 0\r\n";
    let err = RTCSessionDescription::offer(sdp.to_owned()).expect_err("does not parse");
    assert!(matches!(err, Error::SdpSyntaxError { .. }), "{err:?}");
    let detail = RTCError::from_error(&err).expect("an RTCError");
    assert_eq!(detail.error_detail, RTCErrorDetailType::SdpSyntaxError);
    assert_eq!(detail.sdp_line_number, Some(4));
}

/// W3C 4.8.3 `icecandidateerror`: reported by the application that gathers; 701 once per
/// server URL while gathering; the address is withheld unless a local candidate exposed it;
/// a code that is neither STUN's nor 701 is refused.
#[test]
fn ice_candidate_errors_follow_the_spec_rules() -> Result<()> {
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    pc.create_data_channel("d", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    pc.add_local_candidate(host("10.0.0.1:5000".parse()?)?)?;
    while pc.poll_event().is_some() {}

    let unreachable = |address: &str| RTCPeerConnectionIceErrorEvent {
        address: address.to_owned(),
        port: 5000,
        url: "stun:stun.example.org".to_owned(),
        error_code: ICE_SERVER_UNREACHABLE,
        error_text: "unreachable".to_owned(),
        ..Default::default()
    };
    pc.report_ice_candidate_error(unreachable("10.0.0.1"))?;
    pc.report_ice_candidate_error(unreachable("10.0.0.1"))?;
    pc.report_ice_candidate_error(RTCPeerConnectionIceErrorEvent {
        address: "192.0.2.9".to_owned(),
        port: 6000,
        url: "turn:turn.example.org".to_owned(),
        error_code: 401,
        error_text: "Unauthorized".to_owned(),
        ..Default::default()
    })?;
    let errors: Vec<RTCPeerConnectionIceErrorEvent> = std::iter::from_fn(|| pc.poll_event())
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateErrorEvent(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(errors.len(), 2, "701 once per URL: {errors:?}");
    // 4.8.3 url: "the STUN or TURN URL that identifies the STUN or TURN server for which the
    // failure occurred", each event its own.
    assert_eq!(errors[0].url, "stun:stun.example.org");
    assert_eq!(errors[1].url, "turn:turn.example.org");
    assert_eq!(errors[0].address, "10.0.0.1", "an exposed address is given");
    assert_eq!(
        (errors[1].address.as_str(), errors[1].port),
        ("", 0),
        "an address no candidate exposed is withheld"
    );
    assert!(matches!(
        pc.report_ice_candidate_error(RTCPeerConnectionIceErrorEvent {
            error_code: 200,
            ..unreachable("")
        }),
        Err(Error::RangeError(_))
    ));
    Ok(())
}

/// The application may finish gathering before it sets a local description: the description
/// of that generation set afterwards does not start gathering again.
#[test]
fn gathering_finished_before_the_local_description_stays_complete() -> Result<()> {
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new().build(now)?;
    pc.create_data_channel("d", None)?;
    pc.add_local_candidate(host("10.0.0.1:5000".parse()?)?)?;
    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    assert_eq!(pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    Ok(())
}

/// W3C 4.3.4 / 5.6.4 "completed": the ICE transport finished gathering, received the remote
/// end-of-candidates and found a connection. Before both indications it stays "connected";
/// after them both sides complete. Each state is announced once (4.4.1.3: no event when the
/// derived state equals the current one). The ICE transport reports its local candidates and
/// the selected pair names this side's candidate as `local` and the peer's as `remote` (5.6,
/// 5.6.2).
#[test]
fn ice_completes_only_after_both_ends_of_candidates() -> Result<()> {
    let start = Instant::now();
    let (offerer_addr, answerer_addr): (SocketAddr, SocketAddr) =
        ("127.0.0.1:51110".parse()?, "127.0.0.1:51111".parse()?);
    let mut offerer = Peer::new(offerer_addr, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new(answerer_addr, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let connected = |p: &Peer| p.pc.connection_state() == RTCPeerConnectionState::Connected;
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        connected(a) && connected(b)
    })?;
    for peer in [&offerer, &answerer] {
        assert_eq!(
            peer.pc.ice_connection_state(),
            RTCIceConnectionState::Connected,
            "no end-of-candidates yet"
        );
    }

    for peer in [&mut offerer, &mut answerer] {
        peer.pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        peer.pc.add_remote_candidate(RTCIceCandidateInit {
            sdp_mid: Some("0".to_owned()),
            ..Default::default()
        })?;
    }
    let completed = |p: &Peer| p.pc.ice_connection_state() == RTCIceConnectionState::Completed;
    run(&mut offerer, &mut answerer, now, now, |a, b| {
        completed(a) && completed(b)
    })?;
    for (peer, own, other) in [
        (&mut offerer, offerer_addr, answerer_addr),
        (&mut answerer, answerer_addr, offerer_addr),
    ] {
        peer.drain_events();
        assert_eq!(
            peer.pc.ice_connection_state(),
            RTCIceConnectionState::Completed
        );
        let labels = peer.state_labels();
        for once in ["ice:connected", "ice:completed", "connection:connected"] {
            assert_eq!(
                labels.iter().filter(|l| *l == once).count(),
                1,
                "{once} once: {labels:?}"
            );
        }
        let ice = peer.pc.sctp().expect("sctp").transport().ice_transport();
        assert_eq!(ice.state(), RTCIceTransportState::Completed);
        let local = ice.get_local_candidates();
        assert!(
            local
                .iter()
                .any(|c| c.address == own.ip().to_string() && c.port == own.port()),
            "{local:?}"
        );
        let pair = ice.get_selected_candidate_pair().expect("a selected pair");
        assert_eq!(
            (pair.local().address.as_str(), pair.local().port),
            (own.ip().to_string().as_str(), own.port())
        );
        assert_eq!(
            (pair.remote().address.as_str(), pair.remote().port),
            (other.ip().to_string().as_str(), other.port())
        );
    }
    Ok(())
}

/// W3C 6.1.1.3 SCTP connected procedure: the transport's `statechange` to "connected" fires
/// before the `open` events of the channels it carries.
#[test]
fn the_sctp_transport_connects_before_its_channels_open() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51120".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51121".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("first", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let opened = |p: &Peer| {
        p.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
            )
        })
    };
    run(&mut offerer, &mut answerer, start, start, |a, b| {
        opened(a) && opened(b)
    })?;
    for peer in [&offerer, &answerer] {
        let sctp = peer
            .events
            .iter()
            .position(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnSctpTransportStateChange(
                        RTCSctpTransportState::Connected
                    )
                )
            })
            .expect("sctp connected");
        let open = peer
            .events
            .iter()
            .position(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
                )
            })
            .expect("open");
        assert!(sctp < open, "{:?}", peer.events);
    }
    Ok(())
}

/// W3C 6.1.2 "closed": the SCTP transport is closed when its DTLS transport goes to "closed",
/// here because the peer closed its connection (close_notify).
#[test]
fn the_sctp_transport_closes_with_its_dtls_transport() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51130".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51131".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    negotiate(&mut offerer, &mut answerer, start, |sdp| sdp)?;
    let sctp_connected = |p: &Peer| {
        p.pc.sctp()
            .is_some_and(|s| s.state() == RTCSctpTransportState::Connected)
    };
    let now = run(&mut offerer, &mut answerer, start, start, |a, b| {
        sctp_connected(a) && sctp_connected(b)
    })?;
    offerer.pc.close()?;
    let dtls_closed = |p: &Peer| {
        p.pc.sctp()
            .is_some_and(|s| s.transport().state() == RTCDtlsTransportState::Closed)
    };
    run(&mut offerer, &mut answerer, now, now, |_, b| dtls_closed(b))?;
    let sctp = answerer.pc.sctp().expect("sctp");
    assert_eq!(sctp.transport().state(), RTCDtlsTransportState::Closed);
    assert_eq!(sctp.state(), RTCSctpTransportState::Closed);
    Ok(())
}

/// W3C 5.6 `getRemoteCandidates()` and `getLocalParameters()`: the remote candidates are those
/// of the remote description, never a peer-reflexive one the agent learned from a check; the
/// local parameters are the local description's, and null while there is none. The answerer
/// is never told the offerer's candidate: it learns it as peer-reflexive from the offerer's
/// connectivity checks, and the pair still connects.
#[test]
fn remote_candidates_leave_out_the_peer_reflexive_ones_the_checks_found() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51090".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51091".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;

    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(start, offer.clone())?;
    answerer.pc.set_remote_description(start, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(start, answer.clone())?;
    offerer.pc.set_remote_description(start, answer.clone())?;
    let (offerer_addr, answerer_addr) = (offerer.addr, answerer.addr);
    offerer.pc.add_local_candidate(host(offerer_addr)?)?;
    answerer.pc.add_local_candidate(host(answerer_addr)?)?;
    offerer.pc.add_remote_candidate(host(answerer_addr)?)?;

    let sctp_connected = |p: &Peer| {
        p.pc.sctp()
            .is_some_and(|s| s.state() == RTCSctpTransportState::Connected)
    };
    run(&mut offerer, &mut answerer, start, start, |a, b| {
        sctp_connected(a) && sctp_connected(b)
    })?;

    let now = start + Duration::from_secs(1);
    let learned: Vec<_> = answerer
        .pc
        .get_stats(now, rtci::statistics::StatsSelector::None)
        .iter()
        .filter_map(|entry| match entry {
            rtci::statistics::report::RTCStatsReportEntry::RemoteCandidate(c) => {
                Some(c.candidate_type)
            }
            _ => None,
        })
        .collect();
    assert!(
        learned.contains(&rtci::peer_connection::transport::RTCIceCandidateType::Prflx),
        "the answerer's agent learned the offerer as peer-reflexive: {learned:?}"
    );
    let answerer_ice = answerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .ice_transport();
    assert_eq!(
        answerer_ice.get_remote_candidates(),
        vec![],
        "the remote description holds no candidate"
    );

    let offerer_ice = offerer.pc.sctp().expect("sctp").transport().ice_transport();
    let remote = offerer_ice.get_remote_candidates();
    assert_eq!(remote.len(), 1, "{remote:?}");
    assert_eq!(remote[0].port, answerer_addr.port());
    assert_eq!(remote[0].sdp_mline_index, Some(0));
    assert_eq!(remote[0].sdp_mid.as_deref(), Some("0"));

    let local = offerer_ice
        .get_local_parameters()
        .expect("a local description");
    let offer_ufrag = offerer
        .pc
        .local_description()
        .expect("offer")
        .sdp
        .lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:").map(str::to_owned))
        .expect("an ice-ufrag");
    assert_eq!(local.username_fragment, offer_ufrag);
    let remote_parameters = answerer_ice.get_remote_parameters().expect("an offer");
    assert_eq!(remote_parameters.username_fragment, offer_ufrag);
    Ok(())
}

/// W3C 5.6 `getLocalParameters()`: null while the local description is null. `createOffer`
/// alone associates the transceiver (its sender names the transport) but sets no description:
/// the parameters appear with `setLocalDescription`, as the offer states them.
#[test]
fn local_parameters_are_null_until_a_local_description_is_set() -> Result<()> {
    let now = Instant::now();
    let mut pc = Peer::new("127.0.0.1:51092".parse()?, RTCDtlsRole::Client, now)?.pc;
    let transceiver =
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    let offer = pc.create_offer(None)?;
    let sender = pc.rtp_sender(transceiver.into()).expect("sender");
    let ice = sender
        .transport()
        .expect("createOffer associated the transceiver")
        .ice_transport();
    assert_eq!(ice.get_local_parameters(), None);
    assert_eq!(ice.get_remote_parameters(), None);
    assert_eq!(ice.get_remote_candidates(), vec![]);

    pc.set_local_description(now, offer.clone())?;
    let sender = pc.rtp_sender(transceiver.into()).expect("sender");
    let local = sender
        .transport()
        .expect("transport")
        .ice_transport()
        .get_local_parameters()
        .expect("the offer's parameters");
    assert!(
        offer
            .sdp
            .contains(&format!("a=ice-ufrag:{}", local.username_fragment)),
        "{}",
        offer.sdp
    );
    assert!(
        offer.sdp.contains(&format!("a=ice-pwd:{}", local.password)),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// The datagrams `pc` sends in `span` of virtual time, as their destination addresses.
fn destinations(
    pc: &mut RTCPeerConnection,
    start: Instant,
    span: Duration,
) -> Result<Vec<SocketAddr>> {
    let mut now = start;
    let mut sent = vec![];
    while now < start + span {
        // The application reads its events: a local candidate's `icecandidate` is what
        // conveys it, and the agent pairs it from then on (RFC 8838 section 10).
        while pc.poll_event().is_some() {}
        while let Some(datagram) = pc.poll_write() {
            sent.push(datagram.transport.peer_addr);
        }
        let Some(next) = pc.poll_timeout() else { break };
        now = next.max(now + Duration::from_millis(1));
        pc.handle_timeout(now)?;
    }
    Ok(sent)
}

/// W3C 4.8.1.1: the candidate-attribute grammar "MAY be extended" (RFC 8839 section 5.1:
/// extension attributes are name / value pairs, and an unknown one is ignored). A remote
/// candidate with the extensions browsers send (`generation`, `network-id`,
/// `network-cost`) and one no specification defines is added and checked like the bare one.
#[test]
fn a_remote_candidate_with_grammar_extensions_is_added_and_checked() -> Result<()> {
    let start = Instant::now();
    let mut offerer = Peer::new("127.0.0.1:51099".parse()?, RTCDtlsRole::Client, start)?;
    let mut answerer = Peer::new("127.0.0.1:51100".parse()?, RTCDtlsRole::Server, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(start, offer.clone())?;
    answerer.pc.set_remote_description(start, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(start, answer)?;
    answerer.pc.add_local_candidate(host(answerer.addr)?)?;
    // The application takes the candidate's event to trickle it: only then is it paired (RFC
    // 8838 section 10).
    while answerer.pc.poll_event().is_some() {}
    let mut extended = host("127.0.0.1:6004".parse()?)?;
    extended.username_fragment = None;
    extended.candidate = format!(
        "{} generation 0 network-id 1 network-cost 10 x-unknown-extension yes",
        extended.candidate
    );
    answerer.pc.add_remote_candidate(extended)?;

    let remote: SocketAddr = "127.0.0.1:6004".parse()?;
    let sent = destinations(&mut answerer.pc, start, Duration::from_secs(5))?;
    assert!(
        sent.contains(&remote),
        "the extended candidate is checked: {sent:?}"
    );
    Ok(())
}

/// W3C 4.4.2: "The user agent MAY also choose to prohibit connections to other addresses".
/// The application's policy (`SettingEngineBuilder::with_remote_address_filter`) is that
/// choice: a remote candidate whose address it refuses is never checked, one it accepts is.
#[test]
fn a_remote_address_the_filter_refuses_is_never_checked() -> Result<()> {
    let start = Instant::now();
    for (port, refused) in [(6002u16, true), (6003, false)] {
        let mut offerer = Peer::new("127.0.0.1:51097".parse()?, RTCDtlsRole::Client, start)?;
        let mut answerer = Peer::new("127.0.0.1:51098".parse()?, RTCDtlsRole::Server, start)?;
        answerer.pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(RTCDtlsRole::Server)
                    .with_remote_address_filter(std::sync::Arc::new(|addr: SocketAddr| {
                        addr.port() != 6002
                    }))
                    .build(),
            )
            .build(start)?;
        offerer.pc.create_data_channel("probe", None)?;
        let offer = offerer.pc.create_offer(None)?;
        offerer.pc.set_local_description(start, offer.clone())?;
        answerer.pc.set_remote_description(start, offer)?;
        let answer = answerer.pc.create_answer(None)?;
        answerer.pc.set_local_description(start, answer)?;
        answerer.pc.add_local_candidate(host(answerer.addr)?)?;
        // The application takes the candidate's event to trickle it: only then is it paired
        // (RFC 8838 section 10).
        while answerer.pc.poll_event().is_some() {}
        let remote: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let _ = answerer.pc.add_remote_candidate(host(remote)?);

        let sent = destinations(&mut answerer.pc, start, Duration::from_secs(5))?;
        let to_candidate = sent.iter().filter(|a| **a == remote).count();
        if refused {
            assert_eq!(
                to_candidate, 0,
                "nothing is sent where the filter refuses: {sent:?}"
            );
        } else {
            assert!(to_candidate > 0, "the candidate is checked: {sent:?}");
        }
    }
    Ok(())
}

/// W3C 4.4.2 "administratively prohibited": the ICE agent never connects to a remote
/// candidate on a port of the Fetch bad-port list, nor, under the "relay" policy, to one that
/// needs name resolution; `addIceCandidate` still succeeds and the candidate is in the remote
/// description and `getRemoteCandidates()`, as if added. A candidate on another port is
/// checked.
#[test]
fn prohibited_remote_candidates_are_added_but_never_checked() -> Result<()> {
    let start = Instant::now();
    for (port, prohibited) in [(6000u16, true), (6001, false)] {
        let mut offerer = Peer::new("127.0.0.1:51093".parse()?, RTCDtlsRole::Client, start)?;
        let mut answerer = Peer::new("127.0.0.1:51094".parse()?, RTCDtlsRole::Server, start)?;
        offerer.pc.create_data_channel("probe", None)?;
        let offer = offerer.pc.create_offer(None)?;
        offerer.pc.set_local_description(start, offer.clone())?;
        answerer.pc.set_remote_description(start, offer)?;
        let answer = answerer.pc.create_answer(None)?;
        answerer.pc.set_local_description(start, answer)?;
        answerer.pc.add_local_candidate(host(answerer.addr)?)?;
        // The application takes the candidate's event to trickle it: only then is it paired
        // (RFC 8838 section 10).
        while answerer.pc.poll_event().is_some() {}
        let remote: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        answerer.pc.add_remote_candidate(host(remote)?)?;
        assert!(
            answerer
                .pc
                .remote_description()
                .expect("offer")
                .sdp
                .contains(&format!("127.0.0.1 {port} typ host")),
            "the candidate is in the remote description"
        );

        let sent = destinations(&mut answerer.pc, start, Duration::from_secs(5))?;
        let to_candidate = sent.iter().filter(|a| **a == remote).count();
        if prohibited {
            assert_eq!(to_candidate, 0, "nothing is sent to a bad port: {sent:?}");
        } else {
            assert!(to_candidate > 0, "the candidate is checked: {sent:?}");
        }
    }

    // Under the "relay" policy a name to resolve is prohibited the same way.
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(
                    rtci::peer_connection::configuration::RTCIceTransportPolicy::Relay,
                )
                .build(),
        )
        .build(start)?;
    let mut offerer = Peer::new("127.0.0.1:51095".parse()?, RTCDtlsRole::Client, start)?;
    offerer.pc.create_data_channel("probe", None)?;
    let offer = offerer.pc.create_offer(None)?;
    pc.set_remote_description(start, offer)?;
    pc.add_remote_candidate(RTCIceCandidateInit {
        candidate:
            "candidate:1 1 udp 2130706431 0f0e0d0c-0b0a-0908-0706-050403020100.local 51096 typ host"
                .to_owned(),
        sdp_mline_index: Some(0),
        ..Default::default()
    })?;
    assert!(
        pc.remote_description()
            .expect("offer")
            .sdp
            .contains(".local 51096 typ host")
    );
    Ok(())
}

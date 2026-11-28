//! A session that is set up and used over a lossy, reordering link reaches `connected` and stays
//! there.
//!
//! The real-network impairment test (`tests/testenv_impairment.rs`, netem) once saw a peer
//! connection go `failed` on a link with 5 % loss and reordering before its data channel opened.
//! Loss is no reason to fail: every connectivity check is a STUN transaction retransmitted
//! `Rc` times (RFC 8445 section 14.3, RFC 8489 section 6.2.1), consent expires only after 30 s
//! without a response (RFC 7675 section 5.1), DTLS retransmits its flights (RFC 6347
//! section 4.2.4) and SCTP its chunks (RFC 9260 section 6.3). These tests run the whole stack
//! (ICE, DTLS, SCTP, the data channel) between two `rtci` peers on a simulated network in
//! virtual time, dropping a fixed share of datagrams in each direction and delaying each one by
//! a random amount (so datagrams also overtake each other), with fixed seeds: the same run
//! every time, on every platform.
//!
//! At 5 % and 10 % loss nothing may fail. At 30 % loss each way a consent check and its
//! response both arrive only about half the time, and RFC 7675 sends each consent request once,
//! at most one every 4 seconds: consent can lapse, and then the peer MUST stop sending. What
//! may not happen is a failure before it lapsed, so there a failure counts only when no Binding
//! success response has reached that peer for 30 seconds.
//!
//! Nor may the data channel be closed before it opened without an error: its DATA_CHANNEL_OPEN
//! and DATA_CHANNEL_ACK travel on a reliable stream (RFC 8832 section 6), so the channel opens
//! while the association lives, and fails with it, with an error. At 30 % loss the association
//! can give up: the handshake after Max.Init.Retransmits (8) expiries of T1-init or T1-cookie,
//! or the side that came up first after Association.Max.Retrans (10) expiries of T3-rtx while
//! its peer, its COOKIE ACK lost, still discards DATA in COOKIE-ECHOED (RFC 9260 sections 5.1,
//! 6 and 8.1); all of it within about 320 seconds, at RTOs doubling to 60 seconds. There a
//! channel failed with an error is a valid end, a close without one is not, and neither is a
//! channel that has not opened, failed or lapsed after 400 seconds. Every message still
//! arrives exactly once, but not within any fixed time: a DATA
//! chunk and its SACK both arrive about half the time, each retransmission timeout doubles the
//! RTO up to RTO.Max, 60 seconds (RFC 9260 section 6.3.3 E2, and rule C7 allows no lower
//! ceiling), and Karn's algorithm (C5) takes no RTT sample from a retransmitted chunk, so once
//! every message is out the RTO stays backed off until the last is acknowledged.
//!
//! A seed fixes the link, and as much of the engine as a test can reach: each peer draws its
//! randomness from a generator seeded from the test's seed (its crypto provider's `random()`:
//! ICE credentials, the tie-breaker and the 4 to 6 second consent intervals, DTLS randoms and
//! cookies, SCTP's verification tags, initial TSNs, cookie key, HEARTBEAT nonces and jitter),
//! and both are built at the virtual start time, so ICE takes the same course under every
//! crypto provider and a failing seed fails the same way every time. Not everything is
//! seeded: the provider's own key generation and signatures and STUN transaction IDs draw
//! from the OS; they change bytes, not the course of a run (the link's losses and delays are
//! drawn per datagram, whatever it holds).
//!
//! Nor may DTLS give a handshake up on its own clock while the path is alive: RFC 6347
//! section 4.2.4 and RFC 9147 section 5.8 set no total limit on a handshake, and a peer
//! connection's handshake ends on ICE failure (consent expiry), a fatal alert or a close.
//!
//! At 30 % and 40 % loss every response to a nomination's requests can be lost while the peer
//! has accepted it: RFC 8445 section 7.2.5.3.4 then fails the pair and the checklist when the
//! nomination's transaction ends (`Rc` requests, 39.5 seconds, section 14.3), and that is a
//! valid end there, as long as the controlling peer reports it as an ICE failure
//! (`NominationFailed`) and no earlier.
//!
//! At every loss rate the consent rule is judged on every datagram, whatever the number of
//! datagrams a run takes: a peer sends no application data (anything but STUN, RFC 7983)
//! before a Binding success response has reached it or more than 30 seconds after the last
//! one (RFC 7675 Section 5.1: no data "until consent is obtained", and "the endpoint MUST cease
//! transmission" when it expires).

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::ice::FailedNomination;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A small deterministic generator (SplitMix64): the tests need reproducible loss, not quality.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`], so what
/// the engine draws through `RTCCryptoProvider::random()` is the same in every run and under
/// every provider. Not secure; a test of loss handling needs no secrecy.
struct SeededProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    rng: Mutex<Rng>,
}

impl RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut rng = self.rng.lock().map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// The link both directions share.
#[derive(Clone, Copy, Debug)]
struct Link {
    /// Share of datagrams dropped, each direction, independently.
    loss: f64,
    /// One-way delay.
    delay: Duration,
    /// Each datagram's delay is `delay` plus or minus up to this much, uniformly, so datagrams
    /// sent close together arrive out of order.
    jitter: Duration,
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    states: Vec<RTCPeerConnectionState>,
    ice_states: Vec<RTCIceConnectionState>,
    open: Option<RTCDataChannelId>,
    /// Errors and closes of a data channel announced before any channel opened here.
    closed_before_open: Vec<RTCDataChannelEvent>,
    received: Vec<u32>,
    /// When a Binding success response last reached this peer (RFC 7675: only such a response
    /// refreshes consent).
    last_binding_success: Option<Instant>,
    /// The first application datagram (not STUN) this peer sent without consent: when, and
    /// how long it had been since the last Binding success response reached it.
    sent_without_consent: Option<(Instant, Option<Duration>)>,
    /// The nomination (a Binding request with USE-CANDIDATE) this peer started or, controlled,
    /// received last: when, and its transaction id.
    nomination: Option<(Instant, [u8; 12])>,
}

impl Peer {
    fn new(
        addr: &str,
        now: Instant,
        seed: u64,
        failed_nomination: FailedNomination,
    ) -> Result<Self> {
        let provider = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(Rng(seed)),
        });
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_crypto_provider(provider)
                    .with_ice_failed_nomination(failed_nomination)
                    .build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            states: Vec::new(),
            ice_states: Vec::new(),
            open: None,
            closed_before_open: Vec::new(),
            received: Vec::new(),
            last_binding_success: None,
            sent_without_consent: None,
            nomination: None,
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

    fn failed(&self) -> bool {
        self.states.contains(&RTCPeerConnectionState::Failed)
            || self.ice_states.contains(&RTCIceConnectionState::Failed)
    }

    /// Whether this peer's ICE failed while it was still checking, at the end of the
    /// transaction of its last nomination (the controlled peer's: of the check the last one it
    /// received triggered) or later: RFC 8445 section 7.2.5.3.4.
    fn nomination_failed(&self, now: Instant) -> bool {
        self.ice_states.contains(&RTCIceConnectionState::Failed)
            && !self.ice_states.contains(&RTCIceConnectionState::Connected)
            && self
                .nomination
                .is_some_and(|(at, _)| now - at >= NOMINATION_TRANSACTION)
    }
}

/// The transaction id of a Binding request (STUN type 0x0001) with USE-CANDIDATE (0x0025).
fn nomination_id(data: &[u8]) -> Option<[u8; 12]> {
    if data.len() < 20 || data[0] != 0x00 || data[1] != 0x01 {
        return None;
    }
    let mut at = 20;
    while at + 4 <= data.len() {
        let typ = u16::from_be_bytes([data[at], data[at + 1]]);
        let len = usize::from(u16::from_be_bytes([data[at + 2], data[at + 3]]));
        if typ == 0x0025 {
            return data[8..20].try_into().ok();
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    None
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    link: Link,
    rng: Rng,
    /// Datagrams in flight, by arrival time (and a sequence number for ties): destination
    /// index, source address, payload.
    in_flight: BTreeMap<(Instant, u64), (usize, SocketAddr, BytesMut)>,
    seq: u64,
    sent: u64,
    dropped: u64,
    /// When the run started, and what happened in it since: every datagram a peer sent (its
    /// length, whether the link dropped it) and every state change, in order. A seed must give
    /// the same trace every time.
    start: Instant,
    trace: Vec<(Duration, Traced)>,
    /// `LOSSY_LINK_TRACE=live`: the virtual time is printed as it advances.
    live_trace: bool,
}

/// One entry of [`World::trace`].
#[derive(Clone, Debug, PartialEq)]
enum Traced {
    Datagram {
        from: usize,
        /// The first byte: STUN (0 to 3) or the DTLS record's content type (RFC 7983).
        kind: u8,
        len: usize,
        dropped: bool,
    },
    State(usize, RTCPeerConnectionState),
    Ice(usize, RTCIceConnectionState),
}

impl World {
    /// `salt` changes what the peers draw (and so the course of ICE, DTLS and SCTP) and not
    /// the link's losses and delays.
    fn new(link: Link, seed: u64, salt: u64, failed_nomination: FailedNomination) -> Result<Self> {
        let now = Instant::now();
        // Each peer its own stream, apart from each other and from the link's.
        let peer_seed = |i: u64| Rng(seed ^ (0x5eed_0000 + i) ^ (salt << 32)).next_u64();
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1:5000", now, peer_seed(1), failed_nomination)?,
                Peer::new("10.0.0.2:5000", now, peer_seed(2), failed_nomination)?,
            ],
            now,
            link,
            rng: Rng(seed),
            in_flight: BTreeMap::new(),
            seq: 0,
            sent: 0,
            dropped: 0,
            start: now,
            trace: Vec::new(),
            live_trace: std::env::var("LOSSY_LINK_TRACE").is_ok_and(|v| v == "live"),
        })
    }

    /// Takes what both peers want to send onto the link (dropping and delaying it), delivers
    /// what is due, and collects events and messages; repeated until nothing is due now.
    fn pump(&mut self) {
        loop {
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    let to = msg.transport.peer_addr;
                    let Some(dest) = self.peers.iter().position(|p| p.addr == to) else {
                        continue;
                    };
                    // RFC 7983: a first byte of 0 to 3 is STUN; anything else (DTLS here) is
                    // application data, which needs consent (RFC 7675 Section 5.1).
                    let peer = &mut self.peers[i];
                    let is_stun = msg.message.first().is_some_and(|b| *b <= 3);
                    let silent_for = peer.last_binding_success.map(|at| self.now - at);
                    if !is_stun
                        && peer.sent_without_consent.is_none()
                        && silent_for.is_none_or(|s| s > CONSENT_EXPIRY + VIRTUAL_TICK)
                    {
                        peer.sent_without_consent = Some((self.now, silent_for));
                    }
                    if let Some(id) = nomination_id(&msg.message)
                        && peer.nomination.is_none_or(|(_, last)| last != id)
                    {
                        peer.nomination = Some((self.now, id));
                    }
                    self.sent += 1;
                    let dropped = self.rng.unit() < self.link.loss;
                    self.trace.push((
                        self.now - self.start,
                        Traced::Datagram {
                            from: i,
                            kind: msg.message.first().copied().unwrap_or(0),
                            len: msg.message.len(),
                            dropped,
                        },
                    ));
                    if dropped {
                        self.dropped += 1;
                        continue;
                    }
                    let jitter = self.link.jitter.as_secs_f64() * (2.0 * self.rng.unit() - 1.0);
                    let delay = (self.link.delay.as_secs_f64() + jitter).max(0.0);
                    let at = self.now + Duration::from_secs_f64(delay);
                    self.seq += 1;
                    self.in_flight.insert(
                        (at, self.seq),
                        (dest, msg.transport.local_addr, msg.message),
                    );
                }
            }
            let mut delivered = false;
            while let Some(entry) = self.in_flight.first_entry() {
                if entry.key().0 > self.now {
                    break;
                }
                let (dest, from, data) = entry.remove();
                let peer = &mut self.peers[dest];
                if let Some(id) = nomination_id(&data)
                    && peer.nomination.is_none_or(|(_, last)| last != id)
                {
                    peer.nomination = Some((self.now, id));
                }
                // STUN message type 0x0101: Binding success response.
                if data.len() >= 20 && data[0] == 0x01 && data[1] == 0x01 {
                    peer.last_binding_success = Some(self.now);
                }
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: peer.addr,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: data,
                });
                delivered = true;
            }
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(event) = peer.pc.poll_event() {
                    match event {
                        RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                            self.trace
                                .push((self.now - self.start, Traced::State(i, state)));
                            peer.states.push(state)
                        }
                        RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                            self.trace
                                .push((self.now - self.start, Traced::Ice(i, state)));
                            peer.ice_states.push(state)
                        }
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                            peer.open = Some(id)
                        }
                        RTCPeerConnectionEvent::OnDataChannel(
                            event @ (RTCDataChannelEvent::OnError(_)
                            | RTCDataChannelEvent::OnClose(_)),
                        ) if peer.open.is_none() => peer.closed_before_open.push(event),
                        _ => {}
                    }
                }
                while let Some(message) = peer.pc.poll_read() {
                    if let RTCMessage::DataChannelMessage(_, msg) = message.message
                        && msg.data.len() >= 4
                    {
                        peer.received
                            .push(u32::from_be_bytes(msg.data[..4].try_into().unwrap()));
                    }
                }
            }
            if !delivered {
                break;
            }
        }
    }

    /// Moves virtual time to the earliest of both peers' deadlines, the next arrival and
    /// `wake` (when the test wants to act), and fires the timers that are due.
    fn advance(&mut self, wake: Option<Instant>) -> Result<()> {
        let mut next = self.in_flight.first_key_value().map(|(k, _)| k.0);
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let Some(deadline) = peer.pc.poll_timeout() else {
                bail!("peer {i} reports no deadline, so it would never make progress");
            };
            next = Some(next.map_or(deadline, |n: Instant| n.min(deadline)));
        }
        if let Some(wake) = wake {
            next = Some(next.map_or(wake, |n| n.min(wake)));
        }
        let next = next.expect("two peers");
        self.now = next.max(self.now + VIRTUAL_TICK);
        if self.live_trace {
            // Anchors the engine's logs (`RUST_LOG`) in virtual time.
            println!("NOW {:?}", self.now - self.start);
        }
        for peer in self.peers.iter_mut() {
            peer.pc.handle_timeout(self.now)?;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!(
            "a: {:?} / ice {:?}; b: {:?} / ice {:?}; {} of {} datagrams dropped",
            self.peers[0].states,
            self.peers[0].ice_states,
            self.peers[1].states,
            self.peers[1].ice_states,
            self.dropped,
            self.sent
        )
    }
}

/// How a session over a lossy link ended.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Every message arrived, exactly once.
    Delivered,
    /// The time was up with the channel open and messages still on their way, each that
    /// arrived having arrived once (only where `lapse_allowed`: RFC 9260 bounds no delivery
    /// time at that loss rate, see the module docs).
    Delivering,
    /// A peer failed after its consent had lapsed: no Binding success response had reached it
    /// for 30 seconds (RFC 7675 Section 5.1).
    ConsentLapsed,
    /// The SCTP association gave up by its retransmission limits before the channel opened,
    /// and the channel failed with an error (only where `lapse_allowed`, see the module docs).
    AssociationFailed,
    /// A peer's ICE failed while checking, at the end of its nomination's transaction (the
    /// controlled peer's: of the check the nomination triggered), every response to it lost
    /// (RFC 8445 section 7.2.5.3.4; only where `lapse_allowed`, see the module docs).
    NominationFailed,
}

/// How long a nomination's transaction lasts unanswered: `Rc` (7) requests, RTO, 2 RTO, ...
/// apart, the last given `Rm` (16) RTOs, at an RTO of at least 500 ms (RFC 8445 section 14.3,
/// RFC 8489 section 6.2.1).
const NOMINATION_TRANSACTION: Duration = Duration::from_millis(39_500);

/// RFC 7675 Section 5.1: "Consent expires after 30 seconds."
const CONSENT_EXPIRY: Duration = Duration::from_secs(30);

/// The smallest step [`World::advance`] takes; a deadline that close to the current instant
/// fires up to this much late.
const VIRTUAL_TICK: Duration = Duration::from_micros(100);

/// Sets up a session over `link` (seeded with `seed`), opens a reliable unordered data channel
/// and sends `count` numbered messages over it. An error if either peer reports `failed`
/// (unless `lapse_allowed` and its consent had lapsed); if a data channel is closed before it
/// opened (unless `lapse_allowed` and it failed with an error first); if the channel does not
/// open within `open_within`;
/// or if not every message arrives (exactly once) within `deliver_within` (where
/// `lapse_allowed`, the messages that arrived must have arrived once); all in virtual time.
fn session_over(
    link: Link,
    seed: u64,
    count: u32,
    open_within: Duration,
    deliver_within: Duration,
    lapse_allowed: bool,
) -> Result<Outcome> {
    session_over_salted(
        link,
        seed,
        0,
        FailedNomination::default(),
        count,
        open_within,
        deliver_within,
        lapse_allowed,
    )
}

/// [`session_over`], with the peers' randomness salted (see [`World::new`]).
#[allow(clippy::too_many_arguments)]
fn session_over_salted(
    link: Link,
    seed: u64,
    salt: u64,
    failed_nomination: FailedNomination,
    count: u32,
    open_within: Duration,
    deliver_within: Duration,
    lapse_allowed: bool,
) -> Result<Outcome> {
    let mut world = World::new(link, seed, salt, failed_nomination)?;
    drive(
        &mut world,
        seed,
        count,
        open_within,
        deliver_within,
        lapse_allowed,
    )
}

/// The body of [`session_over_salted`], on a world made for it.
fn drive(
    world: &mut World,
    seed: u64,
    count: u32,
    open_within: Duration,
    deliver_within: Duration,
    lapse_allowed: bool,
) -> Result<Outcome> {
    let link = world.link;
    world.peers[0].pc.create_data_channel(
        "lossy-link",
        Some(RTCDataChannelInit {
            ordered: false,
            ..Default::default()
        }),
    )?;
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
    // Each side ends its gathering and is told the other's end-of-candidates: a session whose
    // checks or consent fail is "failed" (W3C webrtc-pc 5.6.4), not left "disconnected".
    for i in 0..2 {
        world.peers[i]
            .pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        world.peers[1 - i]
            .pc
            .add_remote_candidate(RTCIceCandidateInit {
                sdp_mid: Some("0".to_owned()),
                ..Default::default()
            })?;
    }

    let start = world.now;
    let interval = Duration::from_millis(2);
    let mut next = 0u32;
    let mut next_send = start;
    loop {
        world.pump();
        if let Some((i, (at, silent_for))) = world
            .peers
            .iter()
            .enumerate()
            .find_map(|(i, p)| p.sent_without_consent.map(|v| (i, v)))
        {
            bail!(
                "seed {seed}, {link:?}: peer {i} sent application data {:?} into the session \
                 without consent ({}): {}",
                at - start,
                match silent_for {
                    Some(silent_for) =>
                        format!("{silent_for:?} after the last Binding success response reached it"),
                    None => "no Binding success response had reached it".to_owned(),
                },
                world.describe()
            );
        }
        if let Some(failed) = world.peers.iter().find(|p| p.failed()) {
            if lapse_allowed && failed.nomination_failed(world.now) {
                return Ok(Outcome::NominationFailed);
            }
            let silent_for = world.now - failed.last_binding_success.unwrap_or(start).max(start);
            if lapse_allowed && silent_for >= CONSENT_EXPIRY {
                return Ok(Outcome::ConsentLapsed);
            }
            bail!(
                "seed {seed}, {link:?}: a peer failed after {:?}, {silent_for:?} after the last \
                 Binding success response reached it (channel open: {}, {next} of {count} \
                 sent): {}",
                world.now - start,
                world.peers[0].open.is_some(),
                world.describe()
            );
        }
        if let Some(peer) = world
            .peers
            .iter()
            .find(|p| !p.closed_before_open.is_empty())
        {
            let failed = peer
                .closed_before_open
                .iter()
                .any(|event| matches!(event, RTCDataChannelEvent::OnError(_)));
            if lapse_allowed && failed {
                return Ok(Outcome::AssociationFailed);
            }
            bail!(
                "seed {seed}, {link:?}: {:?} before the channel opened, after {:?}, with the path \
                 up: {}",
                peer.closed_before_open,
                world.now - start,
                world.describe()
            );
        }
        let Some(id) = world.peers[0].open else {
            if world.now - start > open_within {
                bail!(
                    "seed {seed}, {link:?}: the channel did not open within {open_within:?}: {}",
                    world.describe()
                );
            }
            world.advance(None)?;
            continue;
        };
        if next < count && world.now >= next_send {
            let mut payload = next.to_be_bytes().to_vec();
            payload.resize(1024, 0xab);
            if let Some(mut dc) = world.peers[0].pc.data_channel(id)
                && dc.send(world.now, BytesMut::from(&payload[..])).is_ok()
            {
                next += 1;
            }
            next_send = world.now + interval;
            continue;
        }
        let received = &world.peers[1].received;
        if received.len() >= count as usize {
            let unique: HashSet<u32> = received.iter().copied().collect();
            assert_eq!(
                unique.len(),
                count as usize,
                "seed {seed}: every message arrives"
            );
            assert_eq!(received.len(), count as usize, "seed {seed}: and only once");
            return Ok(Outcome::Delivered);
        }
        if world.now - start > open_within + deliver_within {
            if lapse_allowed {
                let unique: HashSet<u32> = received.iter().copied().collect();
                assert_eq!(unique.len(), received.len(), "seed {seed}: only once");
                return Ok(Outcome::Delivering);
            }
            bail!(
                "seed {seed}, {link:?}: {} of {count} messages arrived ({next} sent) within \
                 {deliver_within:?} of opening: {}",
                received.len(),
                world.describe()
            );
        }
        world.advance((next < count).then_some(next_send))?;
    }
}

const SEEDS: [u64; 4] = [1, 2, 3, 0x5eed];

/// [`SEEDS`], or the seeds `LOSSY_LINK_SEEDS` names: a comma-separated list of numbers and
/// half-open ranges (`0..200`), each decimal or `0x` hex.
fn seeds() -> Vec<u64> {
    let Ok(list) = std::env::var("LOSSY_LINK_SEEDS") else {
        return SEEDS.to_vec();
    };
    let number = |s: &str| {
        let s = s.trim();
        match s.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => s.parse(),
        }
        .unwrap_or_else(|e| panic!("LOSSY_LINK_SEEDS: {s:?}: {e}"))
    };
    list.split(',')
        .flat_map(|part| match part.split_once("..") {
            Some((from, to)) => (number(from)..number(to)).collect::<Vec<_>>(),
            None => vec![number(part)],
        })
        .collect()
}

/// The netem link `tests/testenv_impairment.rs` ran the reliable unordered channel over: 5 %
/// loss, 30 ms plus or minus 15 ms, so datagrams sent within 30 ms of each other overtake each
/// other.
#[test]
fn a_session_over_a_link_with_loss_and_reordering_connects_and_delivers_everything() -> Result<()> {
    let link = Link {
        loss: 0.05,
        delay: Duration::from_millis(30),
        jitter: Duration::from_millis(15),
    };
    for seed in seeds() {
        session_over(
            link,
            seed,
            500,
            Duration::from_secs(30),
            Duration::from_secs(60),
            false,
        )?;
    }
    Ok(())
}

/// 10 % loss each way.
#[test]
fn a_session_over_a_link_with_ten_percent_loss_connects_and_delivers_everything() -> Result<()> {
    let link = Link {
        loss: 0.10,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(2),
    };
    for seed in seeds() {
        session_over(
            link,
            seed,
            300,
            Duration::from_secs(30),
            Duration::from_secs(90),
            false,
        )?;
    }
    Ok(())
}

/// Seeds of a 2000-seed sweep at 10 % loss where the data channel had not opened after 30
/// seconds (760, 1629 and 1963 with the aws-lc-rs provider, 992 with ring). The controlled
/// peer, the DTLS client, selected the pair when the first nomination request reached it and
/// started its handshake; the responses to the nomination were lost twice, and for those 3.5
/// seconds the controlling peer, with no pair selected, dropped every datagram that was not
/// STUN and could send none. Its four ClientHellos lost, the client's retransmission timer
/// had backed off to 6.4 seconds by the time the controlling peer selected the pair, and two
/// ordinary losses after that (12.8 seconds more) took the handshake past 30 seconds. The
/// controlling agent now sends and receives data on the pair it is nominating (RFC 8445
/// sections 12.1 and 12.2).
#[test]
fn the_handshake_is_answered_while_the_nominations_responses_are_lost() -> Result<()> {
    let link = Link {
        loss: 0.10,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(2),
    };
    for seed in [760, 992, 1629, 1963] {
        session_over(
            link,
            seed,
            300,
            Duration::from_secs(30),
            Duration::from_secs(90),
            false,
        )?;
    }
    Ok(())
}

/// Seed 715 with the peers' randomness salted 2, at 10 % loss (with ring; a sweep of 1000
/// seeds by two salts): 124 of 300 messages had arrived 90 seconds after the channel opened,
/// with ICE and DTLS up. A DATA chunk was lost in the window of a Fast Recovery that had
/// begun before it; the SACKs that reported it missing did not advance the Cumulative TSN
/// Ack Point, and the sender counted no miss indications from such SACKs, so it was never
/// retransmitted on gap reports. It waited for T3-rtx: one packet in flight at an RTO
/// doubling to 60 seconds, and a few lost SACKs held everything behind it. RFC 9260 section
/// 7.2.4 counts miss indications below the HTNA of every SACK. The train 8 CI failure (seed
/// 2, 205 of 300 delivered, ICE flapping only because consent checks went unanswered) had
/// this shape, in a run whose RTCP timing was not yet seeded and so cannot be replayed.
#[test]
fn a_loss_during_fast_recovery_is_retransmitted_on_gap_reports() -> Result<()> {
    let link = Link {
        loss: 0.10,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(2),
    };
    session_over_salted(
        link,
        715,
        2,
        FailedNomination::default(),
        300,
        Duration::from_secs(30),
        Duration::from_secs(90),
        false,
    )?;
    Ok(())
}

/// 30 % loss each way: about half of all check transactions lose the request or the
/// response. The session fails only when consent has lapsed, its channel opens or fails with
/// an error (never closes silently), and what arrives arrives once.
#[test]
fn a_session_over_a_link_with_thirty_percent_loss_fails_only_when_consent_lapses() -> Result<()> {
    for seed in seeds() {
        session_over(
            THIRTY_PERCENT,
            seed,
            50,
            Duration::from_secs(400),
            // At 30 % loss SCTP's retransmission timer backs off (RFC 9260 section 6.3.3), so
            // delivery is slow; the bound is about the session not ending, not about speed.
            Duration::from_secs(900),
            true,
        )?;
    }
    Ok(())
}

const THIRTY_PERCENT: Link = Link {
    loss: 0.30,
    delay: Duration::from_millis(20),
    jitter: Duration::from_millis(5),
};

/// The run that found it: at 30 % loss with seed 0x5eed, ICE and DTLS stayed connected and
/// the channel did not open within 300 s. The SCTP handshake had completed on the offerer
/// and not yet on the answerer (its COOKIE ACK lost, the OPEN discarded in COOKIE-ECHOED until
/// a retransmitted COOKIE ECHO was answered), and a DCEP handshake timeout of 30 s closed the
/// channel, with no error, before the ACK could come. RFC 8832 has no such timeout: the
/// channel opens while the association lives, or fails with an error when it gives up, or
/// consent lapses first.
#[test]
fn the_channel_opens_over_thirty_percent_loss_while_the_path_stays_up() -> Result<()> {
    session_over(
        THIRTY_PERCENT,
        0x5eed,
        50,
        Duration::from_secs(400),
        Duration::from_secs(900),
        true,
    )?;
    Ok(())
}

/// Seeds of a 41-seed sweep at 30 % loss where the session went `failed` at about 30 seconds
/// while a Binding success response had reached the peer less than 30 seconds before. ICE was
/// not what failed there: it stayed connected (a connected pair fails only when its consent
/// expires, RFC 7675 Section 5.1, and the consent rule is judged on every datagram); the peer
/// connection failed because the DTLS handshake was given up at a 30 second deadline of its
/// own. RFC 6347 section 4.2.4 and RFC 9147 section 5.8 set no such limit, and the engine no
/// longer has one by default: on these seeds the session fails only when consent lapses.
#[test]
fn ice_does_not_fail_while_consent_is_fresh_over_thirty_percent_loss() -> Result<()> {
    let mut outcomes = Vec::new();
    for seed in [0xa, 0x1c, 0x21, 0x24] {
        outcomes.push((
            seed,
            session_over(
                THIRTY_PERCENT,
                seed,
                50,
                Duration::from_secs(400),
                Duration::from_secs(900),
                true,
            )?,
        ));
    }
    println!("30 % loss, outcome by seed: {outcomes:?}");
    Ok(())
}

/// Seeds of a 400-seed sweep at 30 % loss on which, with the aws-lc-rs provider, the DTLS
/// handshake did not complete in 400 seconds with ICE up and nothing failing. The hybrid
/// X25519MLKEM768 key share makes the ClientHello two datagrams, and after unanswered
/// retransmissions the client cuts it into up to eight (RFC 9147 section 4.4); the server
/// endpoint dropped the association putting it together 60 seconds after it was made, which at
/// a backed-off timer of 60 seconds is about when the next transmission comes, so fragments of
/// different transmissions never added up, and the ones that came before the first fragment
/// of a transmission were dropped. The association now lives on for two minutes after each
/// datagram. Under ring the ClientHello is one datagram and these seeds take other courses.
#[test]
fn a_fragmented_client_hello_is_put_together_over_thirty_percent_loss() -> Result<()> {
    for seed in [0x49, 0x5b, 0x81] {
        session_over(
            THIRTY_PERCENT,
            seed,
            50,
            Duration::from_secs(400),
            Duration::from_secs(900),
            true,
        )?;
    }
    Ok(())
}

/// Seed 0x5eed with the peers' randomness salted 12, 157 and 280 (a sweep of 300 salts under
/// ring): the channel neither opened nor failed within 400 seconds, with ICE and DTLS up. The
/// INITs crossed; one side, its COOKIE ACKs all lost, was established and sent its
/// DATA_CHANNEL_OPEN, which the other discarded in COOKIE-ECHOED until its T1-cookie ran out
/// after Max.Init.Retransmits (RFC 9260 section 5.1) and its association ended. The
/// established side never heard of it: its DATA and HEARTBEATs now reached no association,
/// carried a zero checksum (RFC 9653) and were dropped unanswered, so it went on until its
/// own Association.Max.Retrans, well after 400 seconds. An out-of-the-blue packet with a zero
/// checksum is now answered with an ABORT under DTLS (RFC 9653 section 5.3 allows it), and
/// the channel fails with an error when the association does: `AssociationFailed`.
#[test]
fn a_channel_whose_association_ends_on_one_side_fails_on_the_other() -> Result<()> {
    for salt in [12, 157, 280] {
        session_over_salted(
            THIRTY_PERCENT,
            0x5eed,
            salt,
            FailedNomination::default(),
            50,
            Duration::from_secs(400),
            Duration::from_secs(900),
            true,
        )?;
    }
    Ok(())
}

/// 40 % loss each way, delays as [`THIRTY_PERCENT`].
const FORTY_PERCENT: Link = Link {
    loss: 0.40,
    delay: Duration::from_millis(20),
    jitter: Duration::from_millis(5),
};

/// Seeds on which the controlling peer went `failed` about 30 seconds in, still checking,
/// 29.5 seconds after the Binding success response that validated its pair reached it (30 %
/// loss: 0x4a, 0xff and 0x127 with the aws-lc-rs provider; 40 % loss: 0x1c and 0x21 with
/// both). The other peer had accepted the nomination and was connected; every response to the
/// nomination's requests had been lost, its transaction (seven requests over 39.5 seconds,
/// RFC 8445 section 14.3) still open. ICE's inherited checking timer (`disconnected_timeout +
/// failed_timeout`, 30 s from entering checking) failed the agent anyway; RFC 8445 sections
/// 6.1.4.2 and 8.1.2 fail a checklist only when every pair has failed. The agent now fails by
/// that timer only with nothing left in progress.
const HEAVY_LOSS_NOMINATION_SEEDS: [(Link, u64); 5] = [
    (THIRTY_PERCENT, 0x4a),
    (THIRTY_PERCENT, 0xff),
    (THIRTY_PERCENT, 0x127),
    (FORTY_PERCENT, 0x1c),
    (FORTY_PERCENT, 0x21),
];

fn heavy_loss_outcomes(failed_nomination: FailedNomination) -> Result<Vec<(f64, u64, Outcome)>> {
    let mut outcomes = Vec::new();
    for (link, seed) in HEAVY_LOSS_NOMINATION_SEEDS {
        outcomes.push((
            link.loss,
            seed,
            session_over_salted(
                link,
                seed,
                0,
                failed_nomination,
                50,
                Duration::from_secs(400),
                Duration::from_secs(900),
                true,
            )?,
        ));
    }
    println!("{failed_nomination:?}: outcome by loss and seed: {outcomes:?}");
    Ok(outcomes)
}

/// [`HEAVY_LOSS_NOMINATION_SEEDS`] by default (RFC 8445 section 7.2.5.3.4): no peer fails
/// while the nomination's transaction is open; when it ends unanswered, the controlling peer
/// reports an ICE failure (`NominationFailed`), and otherwise the session fails only when
/// consent lapses.
#[test]
fn ice_does_not_fail_while_a_nomination_is_in_progress_over_heavy_loss() -> Result<()> {
    heavy_loss_outcomes(FailedNomination::default())?;
    Ok(())
}

/// [`HEAVY_LOSS_NOMINATION_SEEDS`] with `FailedNomination::Retry`: a nomination whose
/// transaction times out is sent again while the peer is heard from, so the controlling peer
/// never fails by its nomination; the session fails only when consent lapses.
#[test]
fn a_retried_nomination_keeps_the_session_over_heavy_loss() -> Result<()> {
    for (loss, seed, outcome) in heavy_loss_outcomes(FailedNomination::Retry)? {
        assert_ne!(
            outcome,
            Outcome::NominationFailed,
            "{loss} loss, seed {seed:#x}: the nomination failed with Retry"
        );
    }
    Ok(())
}

/// A sweep for investigating, not part of the suite: runs a session on each seed of
/// [`seeds`] (`LOSSY_LINK_SEEDS`), the peers salted with `LOSSY_LINK_SALT` (default 0, see
/// [`World::new`]), `LOSSY_LINK_REPEAT` times each (default 1), at the loss
/// `LOSSY_LINK_LOSS` (default 0.10), and prints one line per run: the outcome, or the error,
/// and a fingerprint of the run's trace, so a seed that does not give the same run every
/// time shows. At 10 % loss nothing may fail (the parameters of
/// [`a_session_over_a_link_with_ten_percent_loss_connects_and_delivers_everything`]); from
/// 20 % on, those of the 30 % test.
/// `LOSSY_LINK_TRACE` prints each run's trace (`live`: also the virtual time as it advances,
/// between the engine's `RUST_LOG` lines).
/// `cargo test --test lossy_link_rtc2rtc sweep -- --ignored --nocapture`
#[test]
#[ignore = "an investigation tool: set LOSSY_LINK_SEEDS, LOSSY_LINK_LOSS, LOSSY_LINK_SALT, LOSSY_LINK_REPEAT"]
fn sweep() -> Result<()> {
    use std::hash::{DefaultHasher, Hash, Hasher};
    // `RUST_LOG` shows the engine's own logs.
    let _ = env_logger::builder().is_test(true).try_init();
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or(default.to_owned());
    let loss: f64 = env("LOSSY_LINK_LOSS", "0.10").parse()?;
    let repeat: u32 = env("LOSSY_LINK_REPEAT", "1").parse()?;
    let salt: u64 = env("LOSSY_LINK_SALT", "0").parse()?;
    let heavy = loss >= 0.2;
    let link = Link {
        loss,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(if heavy { 5 } else { 2 }),
    };
    let (count, open_within, deliver_within) = if heavy {
        (50, Duration::from_secs(400), Duration::from_secs(900))
    } else {
        (300, Duration::from_secs(30), Duration::from_secs(90))
    };
    let mut tally: BTreeMap<String, u32> = BTreeMap::new();
    for seed in seeds() {
        let mut fingerprints = HashSet::new();
        for rep in 0..repeat {
            let mut world = World::new(link, seed, salt, FailedNomination::default())?;
            let outcome = drive(&mut world, seed, count, open_within, deliver_within, heavy);
            let mut hasher = DefaultHasher::new();
            // The course: what the link saw, lengths aside (see
            // `the_same_seed_gives_the_same_run`).
            for (at, entry) in &world.trace {
                at.hash(&mut hasher);
                match entry {
                    Traced::Datagram {
                        from,
                        kind,
                        dropped,
                        ..
                    } => (from, kind, dropped).hash(&mut hasher),
                    other => format!("{other:?}").hash(&mut hasher),
                }
            }
            let fingerprint = hasher.finish();
            if std::env::var_os("LOSSY_LINK_TRACE").is_some() {
                for (at, entry) in &world.trace {
                    println!("TRACE seed={seed} {at:?} {entry:?}");
                }
            }
            fingerprints.insert(fingerprint);
            let summary = match &outcome {
                Ok(outcome) => format!("{outcome:?}"),
                Err(_) => "Error".to_owned(),
            };
            *tally.entry(summary.clone()).or_default() += 1;
            println!(
                "SWEEP loss={loss} seed={seed} rep={rep} outcome={summary} trace={} \
                 fingerprint={fingerprint:016x} received={} {}",
                world.trace.len(),
                world.peers[1].received.len(),
                match outcome {
                    Ok(_) => world.describe(),
                    Err(e) => e.to_string(),
                }
            );
        }
        if fingerprints.len() > 1 {
            println!(
                "SWEEP-NONDETERMINISTIC seed={seed}: {} traces in {repeat} runs",
                fingerprints.len()
            );
        }
    }
    println!("SWEEP-TALLY loss={loss}: {tally:?}");
    Ok(())
}

/// A seed fixes a run: the same seed twice gives the same course (every datagram each peer
/// sent, what kind it was and whether the link dropped it, and every state change, at the same
/// virtual instants), on every crypto provider. The lengths of the DTLS handshake datagrams
/// may differ by a byte or two: the provider's own key generation and ECDSA signatures (DER,
/// 70 to 72 bytes) draw from the OS, out of reach of `random()`; the link's draws are per
/// datagram, so they do not change the course. A run whose course something unseeded
/// decides (the OS's randomness, a hash map's iteration order, the wall clock) makes the
/// seeded tests here samples rather than cases: a seed that passes once can fail the next
/// time, as seed 2 of the 10 % test did once in CI.
#[test]
fn the_same_seed_gives_the_same_run() -> Result<()> {
    let link = Link {
        loss: 0.10,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(2),
    };
    for seed in seeds() {
        let mut traces = Vec::new();
        for _ in 0..2 {
            let mut world = World::new(link, seed, 0, FailedNomination::default())?;
            let outcome = drive(
                &mut world,
                seed,
                300,
                Duration::from_secs(30),
                Duration::from_secs(90),
                false,
            );
            traces.push((outcome.map_err(|e| e.to_string()), world.trace));
        }
        // First the course (what was sent when, and what was dropped), then the lengths.
        let course = |trace: &[(Duration, Traced)]| {
            trace
                .iter()
                .map(|(at, entry)| match entry {
                    Traced::Datagram {
                        from,
                        kind,
                        dropped,
                        ..
                    } => (
                        *at,
                        Traced::Datagram {
                            from: *from,
                            kind: *kind,
                            len: 0,
                            dropped: *dropped,
                        },
                    ),
                    other => (*at, other.clone()),
                })
                .collect::<Vec<_>>()
        };
        let (first, second) = (course(&traces[0].1), course(&traces[1].1));
        if let Some(at) =
            (0..first.len().max(second.len())).find(|&i| first.get(i) != second.get(i))
        {
            let (first, second) = (&traces[0].1, &traces[1].1);
            let around = |trace: &[(Duration, Traced)]| {
                trace[at.saturating_sub(4)..(at + 12).min(trace.len())].to_vec()
            };
            bail!(
                "seed {seed}: two runs part at entry {at} of {} / {}:\n  first:  {:?}\n  \
                 second: {:?}\n  outcomes: {:?} / {:?}",
                first.len(),
                second.len(),
                around(first),
                around(second),
                traces[0].0,
                traces[1].0
            );
        }
    }
    Ok(())
}

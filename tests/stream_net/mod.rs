//! An in-memory network for `rtci` peers that drive their TCP through the stream interface
//! (`poll_stream_command` / `poll_stream_transmit` / `handle_stream_*`), on a virtual clock.
//!
//! It plays the driver of every peer: listeners bind (port 0 gets a port from 5000 up),
//! connections connect after `connect_delay` to a listener on the address (or fail), and each
//! byte written arrives `latency` later at the other end, cut into pieces of random size up to
//! `max_segment` (several writes can also arrive in one piece). Written bytes are reported
//! `written_delay` after they were taken. A connection can be broken from the test (both ends
//! see a reset), and UDP between the peers can be turned off.

#![allow(dead_code)]

use bytes::BytesMut;
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::sansio::Protocol;
use rtci::shared::stream::{ListenerId, StreamCommand, StreamEvent, StreamId};
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// A small deterministic generator for segment sizes.
pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub ip: IpAddr,
    pub udp: SocketAddr,
    pub events: Vec<RTCPeerConnectionEvent>,
    pub received: Vec<Vec<u8>>,
    /// The SSRC of each RTP packet read.
    pub rtp_ssrcs: Vec<u32>,
    pub channel_open: Option<RTCDataChannelId>,
    /// Candidates to trickle to the other peer.
    pub outbox: Vec<RTCIceCandidateInit>,
    pub commands: Vec<StreamCommand>,
    /// Whether this peer's stream interface is served at all.
    pub driven: bool,
}

impl Peer {
    pub fn new(pc: RTCPeerConnection, index: usize) -> Self {
        let ip: IpAddr = format!("10.0.0.{}", index + 1).parse().unwrap();
        Self {
            pc,
            ip,
            udp: SocketAddr::new(ip, 4000),
            events: vec![],
            received: vec![],
            rtp_ssrcs: vec![],
            channel_open: None,
            outbox: vec![],
            commands: vec![],
            driven: true,
        }
    }

    pub fn connected(&self) -> bool {
        self.events.iter().rev().find_map(|e| match e {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => Some(*s),
            _ => None,
        }) == Some(RTCPeerConnectionState::Connected)
    }

    pub fn failed(&self) -> bool {
        self.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Failed
                )
            )
        })
    }

    /// The local candidates this peer announced, as candidate lines.
    pub fn announced(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev
                    .candidate
                    .as_ref()
                    .filter(|c| !c.end_of_candidates)
                    .and_then(|c| c.to_json().ok())
                    .map(|init| init.candidate),
                _ => None,
            })
            .collect()
    }
}

/// One end of a simulated connection.
#[derive(Clone, Copy, Debug)]
pub struct End {
    pub peer: usize,
    pub id: StreamId,
    pub local: SocketAddr,
}

#[derive(Debug)]
pub struct Conn {
    pub a: End,
    pub b: Option<End>,
    pub open: bool,
}

enum Delivery {
    Event(usize, StreamEvent),
    Read(usize, StreamId, Vec<u8>),
    /// A connection request reaching its destination.
    Syn {
        conn: usize,
        remote: SocketAddr,
    },
    Udp(usize, SocketAddr, SocketAddr, Vec<u8>),
}

pub struct Net {
    pub now: Instant,
    pub start: Instant,
    pub latency: Duration,
    pub connect_delay: Duration,
    pub written_delay: Duration,
    pub max_segment: usize,
    pub udp: bool,
    /// Connection requests to these addresses are refused.
    pub refused: Vec<SocketAddr>,
    /// Connection requests to a listener that is not bound with reuse (a passive one) are
    /// refused.
    pub refuse_plain_listeners: bool,
    /// Every passive listener asked for on port 0 gets this port, as `rtci-stream-driver`'s
    /// shared passive port: the last one asked for is the listener accepts are reported on.
    pub shared_passive_port: Option<u16>,
    /// Which trickled candidates of a peer reach the other one (all when `None`).
    pub carry: Option<fn(usize, &RTCIceCandidateInit) -> bool>,
    pub rng: XorShift,
    pub listeners: BTreeMap<SocketAddr, (usize, ListenerId, bool)>,
    pub conns: Vec<Conn>,
    pending: Vec<(Instant, u64, Delivery)>,
    seq: u64,
    next_port: BTreeMap<IpAddr, u16>,
    next_ephemeral: u16,
    /// Bytes in flight per (peer, stream id) toward the other end, waiting to be cut.
    pub tcp_writes_via_poll_write: u64,
    pub bytes_carried: u64,
    pub resets_seen: Vec<(usize, StreamId)>,
    pub closes_seen: Vec<(usize, StreamId)>,
    /// The DSCP of each stream transmit, with the peer that wrote it.
    pub transmit_dscps: Vec<(usize, u8)>,
}

impl Net {
    pub fn new() -> Self {
        let start = Instant::now();
        Self {
            now: start,
            start,
            latency: Duration::from_millis(10),
            connect_delay: Duration::from_millis(15),
            written_delay: Duration::from_millis(1),
            max_segment: 1400,
            udp: false,
            refused: vec![],
            refuse_plain_listeners: false,
            shared_passive_port: None,
            carry: None,
            rng: XorShift(0x9e37_79b9_7f4a_7c15),
            listeners: BTreeMap::new(),
            conns: vec![],
            pending: vec![],
            seq: 0,
            next_port: BTreeMap::new(),
            next_ephemeral: 40000,
            tcp_writes_via_poll_write: 0,
            bytes_carried: 0,
            resets_seen: vec![],
            closes_seen: vec![],
            transmit_dscps: Vec::new(),
        }
    }

    fn at(&mut self, delay: Duration, d: Delivery) {
        self.seq += 1;
        self.pending.push((self.now + delay, self.seq, d));
    }

    fn end_of(&self, peer: usize, id: StreamId) -> Option<(usize, bool)> {
        self.conns
            .iter()
            .position(|c| {
                (c.a.peer == peer && c.a.id == id)
                    || c.b.is_some_and(|b| b.peer == peer && b.id == id)
            })
            .map(|i| (i, self.conns[i].a.peer == peer && self.conns[i].a.id == id))
    }

    /// The other end of `peer`'s connection `id`.
    fn other(&self, peer: usize, id: StreamId) -> Option<(usize, End)> {
        let (i, is_a) = self.end_of(peer, id)?;
        let c = &self.conns[i];
        let other = if is_a { c.b? } else { c.a };
        Some((i, other))
    }

    /// Breaks connection `index`: both ends see a reset.
    pub fn break_connection(&mut self, index: usize) {
        let c = &mut self.conns[index];
        if !c.open {
            return;
        }
        c.open = false;
        let (a, b) = (c.a, c.b);
        self.at(
            Duration::ZERO,
            Delivery::Event(a.peer, StreamEvent::Reset { id: a.id }),
        );
        if let Some(b) = b {
            self.at(
                Duration::ZERO,
                Delivery::Event(b.peer, StreamEvent::Reset { id: b.id }),
            );
        }
    }

    fn command(&mut self, peer: usize, cmd: StreamCommand) {
        match cmd {
            StreamCommand::Listen {
                listener,
                local,
                reuse_address,
            } => {
                let port = if local.port() == 0
                    && !reuse_address
                    && let Some(shared) = self.shared_passive_port
                {
                    shared
                } else if local.port() == 0 {
                    let p = self.next_port.entry(local.ip()).or_insert(5000);
                    *p += 1;
                    *p
                } else {
                    local.port()
                };
                let bound = SocketAddr::new(local.ip(), port);
                self.listeners
                    .insert(bound, (peer, listener, reuse_address));
                self.at(
                    Duration::from_millis(1),
                    Delivery::Event(
                        peer,
                        StreamEvent::Listening {
                            listener,
                            local: bound,
                        },
                    ),
                );
            }
            StreamCommand::StopListening { listener } => {
                self.listeners
                    .retain(|_, (p, l, _)| !(*p == peer && *l == listener));
            }
            StreamCommand::Connect {
                id, local, remote, ..
            } => {
                let local = if local.port() == 0 {
                    self.next_ephemeral += 1;
                    SocketAddr::new(local.ip(), self.next_ephemeral)
                } else {
                    local
                };
                self.conns.push(Conn {
                    a: End { peer, id, local },
                    b: None,
                    open: false,
                });
                let conn = self.conns.len() - 1;
                let delay = self.connect_delay;
                self.at(delay, Delivery::Syn { conn, remote });
            }
            StreamCommand::Close { id } => {
                self.closes_seen.push((peer, id));
                if let Some((i, other)) = self.other(peer, id)
                    && self.conns[i].open
                {
                    self.conns[i].open = false;
                    let l = self.latency;
                    self.at(
                        l,
                        Delivery::Event(other.peer, StreamEvent::Closed { id: other.id }),
                    );
                }
                self.at(
                    Duration::ZERO,
                    Delivery::Event(peer, StreamEvent::Closed { id }),
                );
            }
            StreamCommand::Reset { id } => {
                self.resets_seen.push((peer, id));
                if let Some((i, other)) = self.other(peer, id)
                    && self.conns[i].open
                {
                    self.conns[i].open = false;
                    let l = self.latency;
                    self.at(
                        l,
                        Delivery::Event(other.peer, StreamEvent::Reset { id: other.id }),
                    );
                }
            }
            _ => {}
        }
    }

    fn transmit(&mut self, peer: usize, id: StreamId, data: Vec<u8>) {
        let wd = self.written_delay;
        self.at(
            wd,
            Delivery::Event(
                peer,
                StreamEvent::Written {
                    id,
                    bytes: data.len(),
                },
            ),
        );
        let Some((i, other)) = self.other(peer, id) else {
            return;
        };
        if !self.conns[i].open {
            return;
        }
        self.bytes_carried += data.len() as u64;
        let mut rest = &data[..];
        let latency = self.latency;
        while !rest.is_empty() {
            let n = (1 + (self.rng.next() as usize) % self.max_segment).min(rest.len());
            self.at(
                latency,
                Delivery::Read(other.peer, other.id, rest[..n].to_vec()),
            );
            rest = &rest[n..];
        }
    }

    /// One pass: every peer's output into the network, everything due delivered.
    pub fn step(&mut self, peers: &mut [Peer]) {
        for i in 0..peers.len() {
            if peers[i].driven {
                while let Some(cmd) = peers[i].pc.poll_stream_command() {
                    peers[i].commands.push(cmd.clone());
                    self.command(i, cmd);
                }
                while let Some(t) = peers[i].pc.poll_stream_transmit() {
                    self.transmit_dscps.push((i, t.dscp));
                    self.transmit(i, t.id, t.data);
                }
            }
            while let Some(m) = peers[i].pc.poll_write() {
                match m.transport.transport_protocol {
                    TransportProtocol::TCP => self.tcp_writes_via_poll_write += 1,
                    _ => {
                        if !self.udp {
                            continue;
                        }
                        if let Some(j) = peers.iter().position(|p| p.udp == m.transport.peer_addr) {
                            let l = self.latency;
                            self.at(
                                l,
                                Delivery::Udp(
                                    j,
                                    m.transport.peer_addr,
                                    m.transport.local_addr,
                                    m.message.to_vec(),
                                ),
                            );
                        }
                    }
                }
            }
        }
        // Deliver what is due, in time order.
        self.pending.sort_by_key(|(t, s, _)| (*t, *s));
        let due: Vec<_> = {
            let n = self
                .pending
                .iter()
                .take_while(|(t, _, _)| *t <= self.now)
                .count();
            self.pending.drain(..n).collect()
        };
        for (_, _, d) in due {
            self.deliver(peers, d);
        }
        for peer in peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match &event {
                    RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                        if let Some(c) = ev.candidate.as_ref().filter(|c| !c.end_of_candidates)
                            && let Ok(init) = c.to_json()
                        {
                            peer.outbox.push(init);
                        }
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        peer.channel_open = Some(*id)
                    }
                    _ => {}
                }
                peer.events.push(event);
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::DataChannelMessage(_, m) => peer.received.push(m.data.to_vec()),
                    RTCMessage::RtpPacket(_, packet) => peer.rtp_ssrcs.push(packet.header.ssrc),
                    _ => {}
                }
            }
        }
        // Trickle.
        for i in 0..peers.len() {
            let out = std::mem::take(&mut peers[i].outbox);
            for c in out {
                if self.carry.is_some_and(|carry| !carry(i, &c)) {
                    continue;
                }
                let _ = peers[1 - i].pc.add_remote_candidate(c);
            }
        }
    }

    fn deliver(&mut self, peers: &mut [Peer], d: Delivery) {
        let now = self.now;
        match d {
            Delivery::Event(peer, event) => {
                if peers[peer].driven {
                    let _ = peers[peer].pc.handle_stream_event(now, event);
                }
            }
            Delivery::Read(peer, id, data) => {
                let _ = peers[peer].pc.handle_stream_read(now, id, &data);
            }
            Delivery::Syn { conn, remote } => {
                let a = self.conns[conn].a;
                let target = self.listeners.get(&remote).copied();
                let refused = self.refused.contains(&remote)
                    || target.is_some_and(|(_, _, reuse)| self.refuse_plain_listeners && !reuse);
                match target {
                    Some((peer, listener, _)) if !refused && peers[peer].driven => {
                        match peers[peer]
                            .pc
                            .handle_stream_accepted(now, listener, remote, a.local)
                        {
                            Some(id) => {
                                self.conns[conn].b = Some(End {
                                    peer,
                                    id,
                                    local: remote,
                                });
                                self.conns[conn].open = true;
                                let _ = peers[a.peer].pc.handle_stream_event(
                                    now,
                                    StreamEvent::Connected {
                                        id: a.id,
                                        local: a.local,
                                    },
                                );
                            }
                            None => {
                                let _ = peers[a.peer].pc.handle_stream_event(
                                    now,
                                    StreamEvent::ConnectFailed { id: a.id },
                                );
                            }
                        }
                    }
                    _ => {
                        let _ = peers[a.peer]
                            .pc
                            .handle_stream_event(now, StreamEvent::ConnectFailed { id: a.id });
                    }
                }
            }
            Delivery::Udp(peer, local, from, data) => {
                let _ = peers[peer].pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: local,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&data[..]),
                });
            }
        }
    }

    /// Advances the clock to the next thing to happen (a timer or a delivery), by 50 ms at
    /// most, and fires the timers.
    pub fn advance(&mut self, peers: &mut [Peer]) {
        let mut next = self.now + Duration::from_millis(50);
        for p in peers.iter_mut() {
            if let Some(t) = p.pc.poll_timeout() {
                next = next.min(t);
            }
        }
        if let Some(t) = self.pending.iter().map(|(t, _, _)| *t).min() {
            next = next.min(t);
        }
        self.now = next.max(self.now + Duration::from_millis(1));
        for p in peers.iter_mut() {
            let _ = p.pc.handle_timeout(self.now);
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Connections still open.
    pub fn open_connections(&self) -> usize {
        self.conns.iter().filter(|c| c.open).count()
    }
}

/// A UDP host candidate line for `peer`.
pub fn udp_host(peer: &Peer) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            peer.udp.ip(),
            peer.udp.port()
        ),
        ..Default::default()
    }
}

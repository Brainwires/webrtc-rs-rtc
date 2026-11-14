//! ICE over TCP (RFC 6544) between two `rtc` peers, on a simulated network.
//!
//! One peer has a passive TCP host candidate (a listener), the other an active one (port 9 in
//! signalling; each connection it opens gets an ephemeral port). The test plays the network: a
//! datagram the active side sends to a passive address opens a "connection" with a fresh
//! ephemeral port, and every packet on it is framed with RFC 4571's two-byte length and
//! reassembled by a `TcpFrameDecoder` on the other end, as a real stream would be. No sockets
//! and no wall clock: time is virtual, so the run is deterministic.
//!
//! Both role assignments are covered. The one where the *passive* side is the controlling
//! agent (it offers) used to fail: the active peer's checks create a peer-reflexive candidate on
//! the passive side, which took no TCP type, so it paired with nothing and the controlling agent
//! never nominated the connection.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::ice::network_type::NetworkType;
use rtc::ice::tcp_type::TcpType;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time the connection gets before the test gives up. A healthy run takes well under
/// a second of it.
const DEADLINE: Duration = Duration::from_secs(30);

/// The port signalled for active candidates (RFC 6544 §4.5).
const ACTIVE_PORT: u16 = 9;

struct Peer {
    pc: RTCPeerConnection,
    ip: &'static str,
    tcp_type: TcpType,
    connected: bool,
    channel_open: Option<RTCDataChannelId>,
    received: Vec<Vec<u8>>,
}

impl Peer {
    fn new(ip: &'static str, tcp_type: TcpType) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_network_types(vec![NetworkType::Tcp4])
                    .build(),
            )
            .build(Instant::now())?;
        Ok(Self {
            pc,
            ip,
            tcp_type,
            connected: false,
            channel_open: None,
            received: Vec::new(),
        })
    }

    fn port(&self) -> u16 {
        if self.tcp_type == TcpType::Active {
            ACTIVE_PORT
        } else {
            5000
        }
    }

    fn listener(&self) -> Option<SocketAddr> {
        (self.tcp_type == TcpType::Passive).then(|| format!("{}:5000", self.ip).parse().unwrap())
    }

    fn candidate(&self) -> Result<rtc::peer_connection::transport::RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: self.ip.to_owned(),
                port: self.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: self.tcp_type,
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }
}

/// One simulated TCP connection: the active peer's ephemeral address and the passive peer's
/// listener, with a decoder per direction.
struct Connection {
    dialer: usize,
    dialer_addr: SocketAddr,
    listener: usize,
    listener_addr: SocketAddr,
    to_listener: TcpFrameDecoder,
    to_dialer: TcpFrameDecoder,
}

#[derive(Default)]
struct Network {
    connections: Vec<Connection>,
    next_port: u16,
    /// Packets in flight: (receiving peer, local address, peer address, payload).
    in_flight: Vec<(usize, SocketAddr, SocketAddr, BytesMut)>,
    /// Packets the network had nowhere to put.
    dropped: usize,
}

impl Network {
    /// Carries one packet a peer wrote. A passive peer can only answer on a connection that
    /// exists; an active one opens a connection to a listener the first time it writes to it.
    fn send(
        &mut self,
        peers: &[Peer],
        from: usize,
        local: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) {
        let framed = frame_packet(data);
        if let Some(c) = self
            .connections
            .iter_mut()
            .find(|c| c.listener == from && c.dialer_addr == to)
        {
            c.to_dialer.push(&framed).unwrap();
            while let Some(p) = c.to_dialer.next_packet() {
                self.in_flight.push((
                    c.dialer,
                    c.dialer_addr,
                    c.listener_addr,
                    BytesMut::from(&p[..]),
                ));
            }
            return;
        }
        if peers[from].tcp_type != TcpType::Active || local.port() != ACTIVE_PORT {
            self.dropped += 1;
            return;
        }
        let Some(listener) = peers.iter().position(|p| p.listener() == Some(to)) else {
            self.dropped += 1;
            return;
        };
        let index = match self
            .connections
            .iter()
            .position(|c| c.dialer == from && c.listener_addr == to)
        {
            Some(i) => i,
            None => {
                self.next_port += 1;
                self.connections.push(Connection {
                    dialer: from,
                    dialer_addr: SocketAddr::new(local.ip(), 40000 + self.next_port),
                    listener,
                    listener_addr: to,
                    to_listener: TcpFrameDecoder::new(),
                    to_dialer: TcpFrameDecoder::new(),
                });
                self.connections.len() - 1
            }
        };
        let c = &mut self.connections[index];
        c.to_listener.push(&framed).unwrap();
        while let Some(p) = c.to_listener.next_packet() {
            self.in_flight.push((
                c.listener,
                c.listener_addr,
                c.dialer_addr,
                BytesMut::from(&p[..]),
            ));
        }
    }
}

/// Offers from `peers[0]`, answers from `peers[1]`, trickles the candidates, opens a data
/// channel from the offerer and sends `messages` over it. Returns the peers once every message
/// arrived, or fails at the virtual deadline.
fn run(offerer: TcpType, answerer: TcpType, messages: &[Vec<u8>]) -> Result<(Vec<Peer>, Network)> {
    let mut peers = vec![
        Peer::new("10.0.0.1", offerer)?,
        Peer::new("10.0.0.2", answerer)?,
    ];
    let start = Instant::now();
    let mut now = start;

    let channel = peers[0].pc.create_data_channel("tcp", None)?.id();
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(now, offer.clone())?;
    peers[1].pc.set_remote_description(now, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(now, answer.clone())?;
    peers[0].pc.set_remote_description(now, answer)?;

    for i in 0..2 {
        let candidate = peers[i].candidate()?;
        peers[i].pc.add_local_candidate(candidate.clone())?;
        peers[1 - i].pc.add_remote_candidate(candidate)?;
    }

    let mut net = Network::default();
    let mut sent = false;
    while now.duration_since(start) < DEADLINE {
        for i in 0..2 {
            while let Some(msg) = peers[i].pc.poll_write() {
                assert_eq!(
                    msg.transport.transport_protocol,
                    TransportProtocol::TCP,
                    "a TCP-only agent writes TCP"
                );
                let (local, to) = (msg.transport.local_addr, msg.transport.peer_addr);
                net.send(&peers, i, local, to, &msg.message);
            }
        }
        for (i, local, from, data) in std::mem::take(&mut net.in_flight) {
            let _ = peers[i].pc.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: local,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::TCP,
                },
                message: data,
            });
        }
        for peer in peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected,
                    ) => peer.connected = true,
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Failed,
                    ) => bail!("a peer's connection failed"),
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        peer.channel_open = Some(id)
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::DataChannelMessage(_, m) = message.message {
                    peer.received.push(m.data.to_vec());
                }
            }
        }
        if !sent && peers[0].channel_open == Some(channel) {
            let mut dc = peers[0].pc.data_channel(channel).expect("open channel");
            for m in messages {
                dc.send(now, BytesMut::from(&m[..]))?;
            }
            sent = true;
        }
        if peers[1].received.len() == messages.len() && sent {
            return Ok((peers, net));
        }
        if !net.in_flight.is_empty() {
            continue;
        }
        let next = peers
            .iter_mut()
            .filter_map(|p| p.pc.poll_timeout())
            .min()
            .unwrap_or(now + Duration::from_millis(50));
        now = next.max(now + Duration::from_millis(1));
        for peer in peers.iter_mut() {
            let _ = peer.pc.handle_timeout(now);
        }
    }
    bail!(
        "not done after {DEADLINE:?} of virtual time: connected {}/{}, channel open {:?}, {} of {} \
         messages, {} packets dropped",
        peers[0].connected,
        peers[1].connected,
        peers[1].channel_open,
        peers[1].received.len(),
        messages.len(),
        net.dropped,
    )
}

fn messages() -> Vec<Vec<u8>> {
    // A small message, one larger than a UDP datagram could carry in one packet, and a run of
    // ordered ones.
    let mut out = vec![b"over tcp".to_vec(), vec![7u8; 60_000]];
    out.extend((0..50u8).map(|i| vec![i; 100]));
    out
}

fn check(offerer: TcpType, answerer: TcpType) -> Result<()> {
    let expected = messages();
    let (peers, net) = run(offerer, answerer, &expected)?;
    assert!(peers[0].connected && peers[1].connected);
    assert_eq!(peers[1].received, expected, "every message, in order");
    assert_eq!(
        net.connections.len(),
        1,
        "one TCP connection carries everything"
    );
    Ok(())
}

#[test]
fn ice_tcp_active_offerer_passive_answerer() -> Result<()> {
    check(TcpType::Active, TcpType::Passive)
}

#[test]
fn ice_tcp_passive_controlling_offerer_active_answerer() -> Result<()> {
    check(TcpType::Passive, TcpType::Active)
}

#[test]
fn ice_tcp_selected_pair_reports_tcp() -> Result<()> {
    use rtc::statistics::report::RTCStatsReportEntry;
    let (mut peers, _) = run(TcpType::Passive, TcpType::Active, &[b"x".to_vec()])?;
    for peer in peers.iter_mut() {
        let report = peer
            .pc
            .get_stats(Instant::now(), rtc::statistics::StatsSelector::None);
        let local: Vec<String> = report
            .iter()
            .filter_map(|entry| match entry {
                RTCStatsReportEntry::LocalCandidate(c) => Some(c.protocol.clone()),
                _ => None,
            })
            .collect();
        assert!(!local.is_empty());
        assert!(
            local.iter().all(|p| p == "tcp"),
            "only TCP candidates were gathered: {local:?}"
        );
        assert!(
            report.candidate_pairs().any(|p| p.nominated),
            "a TCP pair was nominated"
        );
    }
    Ok(())
}

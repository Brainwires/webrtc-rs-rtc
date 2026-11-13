//! Non-STUN traffic is accepted only from the selected candidate pair's remote address.

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const NEGOTIATED_ID: u16 = 1;
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

struct Peer {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    addr: SocketAddr,
    buf: Vec<u8>,
}

impl Peer {
    async fn new(role: RTCDtlsRole) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(role)
                    .build(),
            )
            .build(Instant::now())?;

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
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        Ok(Self {
            pc,
            socket,
            addr,
            buf: vec![0u8; 2048],
        })
    }

    fn handle_datagram(&mut self, n: usize, peer_addr: SocketAddr) {
        self.pc
            .handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&self.buf[..n]),
            })
            .ok();
    }
}

/// Flushes both peers, then waits for one datagram or the next timer. Returns the number of
/// datagrams peer `a` sent.
async fn pump(a: &mut Peer, b: &mut Peer) -> Result<usize> {
    let mut a_sent = 0;
    while let Some(msg) = a.pc.poll_write() {
        a.socket
            .send_to(&msg.message, msg.transport.peer_addr)
            .await?;
        a_sent += 1;
    }
    while let Some(msg) = b.pc.poll_write() {
        b.socket
            .send_to(&msg.message, msg.transport.peer_addr)
            .await?;
    }

    let fallback = Instant::now() + Duration::from_millis(50);
    let next =
        a.pc.poll_timeout()
            .unwrap_or(fallback)
            .min(b.pc.poll_timeout().unwrap_or(fallback));
    let delay = next
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(5));

    tokio::select! {
        _ = tokio::time::sleep(delay) => {
            a.pc.handle_timeout(Instant::now()).ok();
            b.pc.handle_timeout(Instant::now()).ok();
        }
        Ok((n, peer_addr)) = a.socket.recv_from(&mut a.buf) => a.handle_datagram(n, peer_addr),
        Ok((n, peer_addr)) = b.socket.recv_from(&mut b.buf) => b.handle_datagram(n, peer_addr),
    }
    Ok(a_sent)
}

fn selected_pair_packets_received(pc: &mut RTCPeerConnection) -> u64 {
    pc.get_stats(Instant::now(), StatsSelector::None)
        .candidate_pairs()
        .map(|pair| pair.packets_received)
        .max()
        .unwrap_or(0)
}

/// Once ICE has selected a pair, a non-STUN datagram from any other address is not part of the
/// connection and must be dropped before DTLS sees it.
#[tokio::test]
async fn non_stun_datagrams_from_other_addresses_are_dropped() -> Result<()> {
    let mut offer = Peer::new(RTCDtlsRole::Server).await?;
    let mut answer = Peer::new(RTCDtlsRole::Client).await?;
    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    let offer_dc = offer
        .pc
        .create_data_channel("strays", Some(init.clone()))?
        .id();
    let answer_dc = answer.pc.create_data_channel("strays", Some(init))?.id();

    let sdp = offer.pc.create_offer(None)?;
    offer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    answer.pc.set_remote_description(Instant::now(), sdp)?;
    let sdp = answer.pc.create_answer(None)?;
    answer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    offer.pc.set_remote_description(Instant::now(), sdp)?;

    let (mut offer_open, mut answer_open) = (false, false);
    let start = Instant::now();
    while start.elapsed() < TEST_TIMEOUT && !(offer_open && answer_open) {
        pump(&mut offer, &mut answer).await?;
        while let Some(event) = offer.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event
                && id == offer_dc
            {
                offer_open = true;
            }
        }
        while let Some(event) = answer.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event
                && id == answer_dc
            {
                answer_open = true;
            }
        }
        while offer.pc.poll_read().is_some() {}
        while answer.pc.poll_read().is_some() {}
    }
    assert!(offer_open && answer_open, "the peers never connected");

    let before = selected_pair_packets_received(&mut answer.pc);
    let stray: SocketAddr = "127.0.0.1:9".parse()?;
    assert_ne!(stray, offer.addr);
    for _ in 0..20 {
        // A DTLS application-data record header followed by junk.
        answer.buf[..32].copy_from_slice(&[0x17; 32]);
        answer.handle_datagram(32, stray);
    }
    let after = selected_pair_packets_received(&mut answer.pc);
    assert_eq!(
        before, after,
        "datagrams from an address that is not the selected pair's remote were accepted"
    );
    Ok(())
}

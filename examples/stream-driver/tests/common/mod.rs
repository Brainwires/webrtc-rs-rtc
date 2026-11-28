//! Two `PeerDriver`s with a data channel, on whatever runtime each is given: the harness of
//! the runtime tests (`runtimes.rs`, `virtual_time.rs`). Every time given to an engine is its
//! driver's runtime's clock.

#![allow(dead_code)]

use bytes::BytesMut;
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtci::peer_connection::transport::{RTCIceCandidateInit, RTCIceCandidateType};
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use rtci_stream_driver::runtime::Runtime;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One peer: its driver, and what the application saw.
pub struct Peer {
    pub driver: PeerDriver,
    /// Candidates to carry to the other peer.
    pub outgoing: Vec<RTCIceCandidateInit>,
    /// The data channel, once open.
    pub open: Option<RTCDataChannelId>,
    /// Data channel messages received.
    pub received: Vec<Vec<u8>>,
    /// Every peer connection state it went through, with the runtime's time.
    pub states: Vec<(RTCPeerConnectionState, Instant)>,
    /// Every ICE connection state it went through, with the runtime's time.
    pub ice_states: Vec<(RTCIceConnectionState, Instant)>,
    /// Whether the end-of-candidates candidate is carried to the other peer too (an
    /// application that relays it; W3C webrtc-pc 5.6.4: "failed" needs it). Off by default.
    pub relay_end_of_candidates: bool,
}

impl Peer {
    /// A peer on `runtime` with a host candidate on `ip`.
    pub fn new(runtime: Arc<dyn Runtime>, ip: IpAddr) -> Result<Self> {
        Self::with_settings(runtime, ip, SettingEngineBuilder::new())
    }

    /// As [`new`](Self::new), with `settings`.
    pub fn with_settings(
        runtime: Arc<dyn Runtime>,
        ip: IpAddr,
        settings: SettingEngineBuilder,
    ) -> Result<Self> {
        Self::with_config(runtime, settings, PeerDriverConfig::on(vec![ip]))
    }

    /// A peer on `runtime` with `settings`, its driver configured by `config`.
    pub fn with_config(
        runtime: Arc<dyn Runtime>,
        settings: SettingEngineBuilder,
        config: PeerDriverConfig,
    ) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(settings.build())
            .build(runtime.now())?;
        Ok(Self {
            driver: PeerDriver::with_runtime(runtime, pc, config),
            outgoing: vec![],
            open: None,
            received: vec![],
            states: vec![],
            ice_states: vec![],
            relay_end_of_candidates: false,
        })
    }

    pub fn now(&self) -> Instant {
        self.driver.runtime().now()
    }

    /// What the application does with the events and reads.
    pub fn collect(&mut self) {
        let now = self.now();
        while let Some(event) = self.driver.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(event) => {
                    if let Some(candidate) = event
                        .candidate
                        .filter(|c| self.relay_end_of_candidates || !c.end_of_candidates)
                        && let Ok(init) = candidate.to_json()
                    {
                        self.outgoing.push(init);
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    self.open = Some(id);
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    self.states.push((state, now));
                }
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    self.ice_states.push((state, now));
                }
                _ => {}
            }
        }
        while let Some(read) = self.driver.pc_mut().poll_read() {
            if let RTCMessage::DataChannelMessage(_, message) = read.message {
                self.received.push(message.data.to_vec());
            }
        }
    }

    /// The type of the remote candidate of the first transport's selected pair: `Host` once
    /// a `.local` candidate of the peer resolved and carries the pair, `Prflx` when the pair
    /// was learnt from the peer's checks instead.
    pub fn selected_remote_type(&self) -> Option<RTCIceCandidateType> {
        let transports = self.driver.pc().dtls_transports();
        let pair = transports
            .first()?
            .ice_transport()
            .get_selected_candidate_pair()?;
        Some(pair.remote().typ)
    }

    pub fn connected(&self) -> bool {
        self.driver.pc().connection_state() == RTCPeerConnectionState::Connected
    }

    /// Sends `data` on the open data channel.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let now = self.now();
        let id = self.open.ok_or("no open data channel")?;
        let mut channel = self.driver.pc_mut().data_channel(id).ok_or("the channel")?;
        channel.send(now, BytesMut::from(data))?;
        self.driver.flush()?;
        Ok(())
    }
}

/// `a` creates a data channel and offers, `b` answers.
pub fn negotiate(a: &mut Peer, b: &mut Peer) -> Result<RTCDataChannelId> {
    let channel = a.driver.pc_mut().create_data_channel("runtime", None)?.id();
    let offer = a.driver.pc_mut().create_offer(None)?;
    let now = a.now();
    a.driver
        .pc_mut()
        .set_local_description(now, offer.clone())?;
    let now = b.now();
    b.driver.pc_mut().set_remote_description(now, offer)?;
    let answer = b.driver.pc_mut().create_answer(None)?;
    b.driver
        .pc_mut()
        .set_local_description(now, answer.clone())?;
    let now = a.now();
    a.driver.pc_mut().set_remote_description(now, answer)?;
    a.driver.flush()?;
    b.driver.flush()?;
    Ok(channel)
}

/// Both peers, one step each (waiting at most `wait`), the candidates carried across.
pub async fn round(a: &mut Peer, b: &mut Peer, wait: Duration) -> Result<()> {
    a.driver.step(wait).await?;
    b.driver.step(wait).await?;
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

/// Rounds until `done`, at most `rounds` of them.
pub async fn run_until(
    a: &mut Peer,
    b: &mut Peer,
    wait: Duration,
    rounds: usize,
    mut done: impl FnMut(&Peer, &Peer) -> bool,
) -> Result<bool> {
    for _ in 0..rounds {
        round(a, b, wait).await?;
        if done(a, b) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Connects `a` and `b` and carries one message each way on the data channel.
pub async fn connect_and_exchange(
    a: &mut Peer,
    b: &mut Peer,
    wait: Duration,
    rounds: usize,
) -> Result<()> {
    negotiate(a, b)?;
    let open = run_until(a, b, wait, rounds, |a, b| {
        a.open.is_some() && b.open.is_some()
    })
    .await?;
    assert!(
        open,
        "the data channel opens: a {:?} b {:?}",
        a.driver.pc().connection_state(),
        b.driver.pc().connection_state()
    );
    a.send(b"from a")?;
    b.send(b"from b")?;
    let delivered = run_until(a, b, wait, rounds, |a, b| {
        !a.received.is_empty() && !b.received.is_empty()
    })
    .await?;
    assert!(delivered, "a message each way");
    assert_eq!(a.received, vec![b"from b".to_vec()]);
    assert_eq!(b.received, vec![b"from a".to_vec()]);
    Ok(())
}

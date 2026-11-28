//! `PeerDriver`'s mDNS over the host's real mDNS group: the smoke tests of the driver's real
//! mDNS sockets. Two driven connections publish their host addresses behind `.local` names
//! (draft-ietf-mmusic-mdns-ice-candidates section 3.1) and resolve each other's through the
//! driver's mDNS sockets, on the host's egress interface and on loopback.
//!
//! What they prove beyond the virtual-time tests (`tests/mdns_virtual_time.rs`: the same
//! exchange, the interface rules of RFC 6762 section 14 and the shared budget of section 7.1,
//! on the mock network, on every platform) is that the driver's sockets work with the
//! operating system's: bound, joined and sent on the right interface. They also need the
//! host to deliver multicast between two sockets of this process on that interface, which is
//! not the driver's to give: a CI virtual machine whose network does not loop multicast back
//! (seen on a self-hosted Windows VM, NAT address 10.0.2.15: no mDNS datagram arrived, on its
//! interface nor on loopback) made all of them fail. So each test first probes the host
//! ([`host_loops_multicast`], with the driver's own socket options: joined on the address's
//! interface, sent with `IP_MULTICAST_IF` set to it): when the host does not deliver, the test
//! is skipped with the reason printed, except where the job says multicast works
//! ([`host_multicast_expected`]: `cargo.yml` on Linux, macOS and GitHub-hosted Windows), where
//! a failing probe fails the test (the skip cannot become universal).
//!
//! Linux and Windows. Multicast needs a route that carries it back to this host: GitHub's macOS
//! image has none (an mDNS send fails with "No route to host"; `cargo.yml` reroutes it for the
//! root crate's interop tests only), and on a desktop Mac a multicast socket raises the Local
//! Network privacy prompt. The budget's own rules are unit tests of the crate (`mdns_io.rs`).
#![cfg(any(target_os = "linux", target_os = "windows"))]

use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::MdnsRateLimit;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The tests share the host's mDNS group: one at a time, so that what a test counts is its own.
static MDNS_GROUP_IN_USE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The address of the host's default-route interface (a UDP socket connected to a
/// documentation address sends nothing): the drivers' candidates are gathered there, and the
/// driver sends and joins mDNS on that address's interface. (Asking which interface a socket
/// connected to the mDNS group would use gave loopback on Windows once a test of this binary had
/// joined the group on loopback.)
fn mdns_egress_ip() -> Option<IpAddr> {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("192.0.2.1:9")?;
            socket.local_addr()
        })
        .ok()
        .map(|addr| addr.ip())
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

/// The address the system answers for the mDNS group: a UDP socket connected to
/// 224.0.0.251:5353 and its local address. On Windows a process that joined the group on
/// loopback and sent to it there leaves this answer at 127.0.0.1 for every process after it has
/// exited (hosted Windows, agent-test run 46049295359; the `netsh` joins table entry alone does
/// not move it): the Windows pre- and post-condition of
/// `by_default_drivers_on_loopback_leave_the_group_route_off_loopback`.
fn group_answer() -> Option<IpAddr> {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect((rtci::mdns::MDNS_MULTICAST_IPV4, rtci::mdns::MDNS_PORT))?;
            socket.local_addr()
        })
        .ok()
        .map(|addr| addr.ip())
}

/// The address the test runs on ([`mdns_egress_ip`]), or `None` when this host has no
/// interface that carries multicast to the mDNS group (some GitHub-hosted Windows images have
/// none) or does not deliver it back to this process on it ([`multicast_or_skip`]); the test is
/// then skipped with the reason printed (the same connection runs on virtual time on every
/// platform, `tests/mdns_virtual_time.rs`). On Linux the hosted runners always have one that
/// delivers, so its absence fails the test there rather than hiding a regression.
fn mdns_egress_or_skip(test: &str) -> Option<IpAddr> {
    let ip = mdns_egress_ip();
    if ip.is_none() {
        assert!(
            !cfg!(target_os = "linux"),
            "{test} needs an interface that carries multicast to the mDNS group"
        );
        println!("SKIPPED {test}: no interface on this host carries multicast to the mDNS group");
        return None;
    }
    ip.filter(|ip| multicast_or_skip(test, *ip))
}

/// Whether the host delivers a datagram sent to the mDNS group (224.0.0.251:5353, the group and
/// port the drivers use) from `ip`'s interface back to a socket of this process joined to the
/// group on that interface, within two seconds. The probe is a DNS response with no records
/// and a random ID (what other responders on the link ignore, and only this probe sends); it
/// is sent up to ten times, 200 ms apart. Not a retry of the test: it asks the host one
/// question, before the test, and the test runs once.
fn host_loops_multicast(ip: IpAddr) -> bool {
    let IpAddr::V4(interface) = ip else {
        return false;
    };
    let probe = || -> std::io::Result<bool> {
        let group = SocketAddr::from((rtci::mdns::MDNS_MULTICAST_IPV4, rtci::mdns::MDNS_PORT));
        let receiver: std::net::UdpSocket = rtci::mdns::MulticastSocket::new()
            .with_interface(interface)
            .into_std()?;
        receiver.set_nonblocking(false)?;
        receiver.set_read_timeout(Some(Duration::from_millis(200)))?;
        let sender = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sender.set_multicast_if_v4(&interface)?;
        sender.set_multicast_loop_v4(true)?;
        sender.bind(&SocketAddr::new(ip, 0).into())?;
        let sender: std::net::UdpSocket = sender.into();
        let nonce = std::process::id()
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or_default();
        let [id0, id1, ..] = nonce.to_be_bytes();
        let message = [id0, id1, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = [0u8; 1500];
        for _ in 0..10 {
            sender.send_to(&message, group)?;
            let until = Instant::now() + Duration::from_millis(200);
            while Instant::now() < until {
                match receiver.recv_from(&mut buf) {
                    Ok((n, _)) if buf[..n] == message => return Ok(true),
                    Ok(_) => continue,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(false)
    };
    probe().unwrap_or_else(|e| {
        println!("multicast probe on {ip}: {e}");
        false
    })
}

/// Whether this job says the host delivers multicast to itself: `RTCI_EXPECT_HOST_MULTICAST`, a
/// comma-separated list of operating system names (`std::env::consts::OS`: `linux`, `macos`,
/// `windows`), which `cargo.yml` sets on the jobs where these tests run today (Linux, macOS
/// with its multicast route over loopback, GitHub-hosted Windows). There a failing probe fails
/// the test instead of skipping it, so the skip cannot quietly remove coverage; elsewhere
/// (a self-hosted VM that does not loop multicast, an `agent-test` run without the variable) it
/// skips with the reason printed.
fn host_multicast_expected() -> bool {
    std::env::var("RTCI_EXPECT_HOST_MULTICAST")
        .is_ok_and(|v| v.split(',').any(|os| os.trim() == std::env::consts::OS))
}

/// [`host_loops_multicast`] on `ip`'s interface, or the test is skipped with the reason
/// printed; where [`host_multicast_expected`], a host that does not deliver fails the test.
fn multicast_or_skip(test: &str, ip: IpAddr) -> bool {
    if host_loops_multicast(ip) {
        return true;
    }
    if host_multicast_expected() {
        panic!(
            "{test}: this host does not deliver multicast to itself on {ip}, and the job says it \
             does (RTCI_EXPECT_HOST_MULTICAST): the real-socket mDNS tests must run here"
        );
    }
    println!("SKIPPED {test}: the host does not loop multicast on {ip} back to this process");
    false
}

struct Side {
    driver: PeerDriver,
    outgoing: Vec<RTCIceCandidateInit>,
    signalled: Vec<String>,
}

impl Side {
    /// A driver on `ip` with `PeerDriverConfig::on`'s defaults (the rate limit aside).
    fn new(ip: IpAddr, limit: Option<MdnsRateLimit>) -> Result<Self> {
        Self::with_config(PeerDriverConfig {
            mdns_rate_limit: limit,
            ..PeerDriverConfig::on(vec![ip])
        })
    }

    /// As [`new`](Self::new), asking for mDNS on loopback on Windows
    /// (`PeerDriverConfig::mdns_on_loopback_on_windows`).
    fn asking_for_loopback_mdns(ip: IpAddr, limit: Option<MdnsRateLimit>) -> Result<Self> {
        Self::with_config(PeerDriverConfig {
            mdns_rate_limit: limit,
            mdns_on_loopback_on_windows: true,
            ..PeerDriverConfig::on(vec![ip])
        })
    }

    fn with_config(config: PeerDriverConfig) -> Result<Self> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let settings =
            SettingEngineBuilder::new().with_multicast_dns_mode(MulticastDnsMode::QueryAndGather);
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(settings.build())
            .build(Instant::now())?;
        Ok(Self {
            driver: PeerDriver::new(pc, config),
            outgoing: vec![],
            signalled: vec![],
        })
    }

    fn collect(&mut self) {
        while let Some(event) = self.driver.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
                && let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                && let Ok(init) = candidate.to_json()
            {
                self.signalled.push(init.candidate.clone());
                self.outgoing.push(init);
            }
        }
        while self.driver.pc_mut().poll_read().is_some() {}
    }

    fn connected(&self) -> bool {
        self.driver.pc().connection_state() == RTCPeerConnectionState::Connected
    }
}

async fn round(a: &mut Side, b: &mut Side) -> Result<()> {
    a.driver.step(Duration::from_millis(5)).await?;
    b.driver.step(Duration::from_millis(5)).await?;
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

/// `a` offers an audio transceiver, `b` answers; rounds until both are connected or `limit`.
async fn connect(a: &mut Side, b: &mut Side, limit: Duration) -> Result<bool> {
    a.driver.pc_mut().add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
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
    a.driver.pc_mut().set_remote_description(now, answer)?;
    let until = Instant::now() + limit;
    while Instant::now() < until {
        round(a, b).await?;
        if a.connected() && b.connected() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn assert_only_local_names(who: &str, side: &Side, ip: IpAddr) {
    assert!(!side.signalled.is_empty(), "{who}: candidates signalled");
    for candidate in &side.signalled {
        assert!(
            candidate.contains(".local ") && !candidate.contains(&ip.to_string()),
            "{who}: the host address is hidden behind a .local name: {candidate}"
        );
    }
}

/// Both connections publish `.local` names only; each resolves the other's through its
/// driver's mDNS sockets (nothing else carries an mDNS datagram), and they connect.
#[tokio::test]
async fn driven_connections_resolve_each_others_mdns_candidates_and_connect() -> Result<()> {
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let Some(ip) =
        mdns_egress_or_skip("driven_connections_resolve_each_others_mdns_candidates_and_connect")
    else {
        return Ok(());
    };
    let limit = MdnsRateLimit::default();
    let mut a = Side::new(ip, Some(limit.clone()))?;
    let mut b = Side::new(ip, Some(limit))?;
    let up = connect(&mut a, &mut b, Duration::from_secs(30)).await?;
    assert_only_local_names("a", &a, ip);
    assert_only_local_names("b", &b, ip);
    assert!(
        a.driver.mdns_datagrams_sent() > 0 && b.driver.mdns_datagrams_sent() > 0,
        "both drivers sent mDNS: {} and {}",
        a.driver.mdns_datagrams_sent(),
        b.driver.mdns_datagrams_sent()
    );
    for (who, side) in [("a", &a), ("b", &b)] {
        assert!(
            side.driver.mdns_datagrams_received() > 0,
            "{who}: the driver's mDNS sockets received the group's datagrams"
        );
    }
    assert!(
        up,
        "connected over the resolved .local candidates: a {:?} / b {:?}",
        a.driver.pc().connection_state(),
        b.driver.pc().connection_state()
    );
    Ok(())
}

/// RFC 6762 section 14: the driver sends each mDNS message on the interface of the address it
/// is about and joins the group there, not only on the system's default multicast interface.
/// Two drivers whose only address is loopback publish names of 127.0.0.1, announce and answer
/// them on the loopback interface, resolve each other's, and connect. (Sent on the default
/// interface, as 0.2.0-dev did before, the answers came from another address and were
/// refused: the names never resolved.)
///
/// On Windows the drivers send no mDNS on loopback unless asked
/// (`PeerDriverConfig::mdns_on_loopback_on_windows`, set here), and what they then send leaves the
/// group's destination-cache route on loopback for the whole host after this process (`netsh
/// interface ipv4 show destinationcache address=224.0.0.251`; agent-test runs 46045692164,
/// 46049295359): on a runner that lives on (a self-hosted Windows VM) the next job's mDNS would
/// leave by loopback. So it is ignored there, and `scripts/windows-poisoned-mdns-route.sh` runs it
/// on GitHub-hosted Windows, whose runner is thrown away, and deletes the entry afterwards.
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Windows: mDNS on loopback leaves the group's destination-cache route on loopback for the whole host; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows), which deletes the entry"
)]
async fn drivers_on_loopback_resolve_each_other_on_the_loopback_interface() -> Result<()> {
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let ip = IpAddr::from(Ipv4Addr::LOCALHOST);
    if !multicast_or_skip(
        "drivers_on_loopback_resolve_each_other_on_the_loopback_interface",
        ip,
    ) {
        return Ok(());
    }
    let limit = MdnsRateLimit::default();
    let mut a = Side::asking_for_loopback_mdns(ip, Some(limit.clone()))?;
    let mut b = Side::asking_for_loopback_mdns(ip, Some(limit))?;
    let up = connect(&mut a, &mut b, Duration::from_secs(30)).await?;
    assert_only_local_names("a", &a, ip);
    assert_only_local_names("b", &b, ip);
    assert!(
        up,
        "connected over the resolved .local candidates on loopback: a {:?} (mDNS sent {}, received {}) / b {:?} (sent {}, received {})",
        a.driver.pc().connection_state(),
        a.driver.mdns_datagrams_sent(),
        a.driver.mdns_datagrams_received(),
        b.driver.pc().connection_state(),
        b.driver.mdns_datagrams_sent(),
        b.driver.mdns_datagrams_received()
    );
    Ok(())
}

/// The 0.3.0 default on Windows: drivers given only 127.0.0.1 send no mDNS on loopback, so once
/// they are gone the host's answer for the group ([`group_answer`]) is where it was, not
/// 127.0.0.1. The precondition is asserted: the answer must not be loopback before (a host left
/// in that state proves nothing), and the drivers must have had mDNS to send (the engine's
/// probes and announcements of their names, dropped by the driver: unsent). Needs a host whose
/// route for the group is not on loopback, so it is ignored and
/// `scripts/windows-poisoned-mdns-route.sh` runs it on GitHub-hosted Windows before it changes
/// the route.
#[cfg(windows)]
#[tokio::test]
#[ignore = "needs a Windows host whose route for 224.0.0.251 is not on loopback; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows) before it moves the route"]
async fn by_default_drivers_on_loopback_leave_the_group_route_off_loopback() -> Result<()> {
    let _group = MDNS_GROUP_IN_USE.lock().await;
    let ip = IpAddr::from(Ipv4Addr::LOCALHOST);
    let before = group_answer();
    assert!(
        before.is_some_and(|ip| !ip.is_loopback()),
        "PRECONDITION: the host's answer for the group is {before:?} before the test; it must not \
         be loopback, or the test proves nothing"
    );
    // `PeerDriverConfig::on`'s default, not set here: what is tested is the default itself.
    let mut a = Side::new(ip, Some(MdnsRateLimit::default()))?;
    let mut b = Side::new(ip, Some(MdnsRateLimit::default()))?;
    let _ = connect(&mut a, &mut b, Duration::from_secs(5)).await?;
    let seen = [("a", &a), ("b", &b)].map(|(who, side)| {
        (
            who,
            side.driver.unsent_datagrams(),
            side.driver.mdns_available(false),
        )
    });
    drop((a, b));
    let after = group_answer();
    println!("### group answer before {before:?}, after the default drivers on loopback {after:?}");
    assert!(
        after.is_some_and(|ip| !ip.is_loopback()),
        "the default drivers on loopback left the group's answer at {after:?} (was {before:?})"
    );
    for (who, unsent, available) in seen {
        assert!(
            unsent > 0,
            "{who}: the connection had mDNS for its loopback name to send"
        );
        assert!(!available, "{who}: no IPv4 mDNS socket for loopback only");
    }
    Ok(())
}

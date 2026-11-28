//! `PeerDriver`'s mDNS on virtual time: two drivers whose connections publish their host
//! addresses behind `.local` names (draft-ietf-mmusic-mdns-ice-candidates section 3.1), on one
//! `MockRuntime`'s in-memory network. Their mDNS sockets meet on the mock network's multicast
//! group, so the whole path (the driver's mDNS sockets, its socket bookkeeping for `.local`
//! candidates, the engine's resolver) runs on every platform without a multicast route and
//! without a privacy prompt. The real-multicast tests are `tests/mdns.rs`.
#![cfg(feature = "runtime-mock")]

mod common;

use common::{Peer, Result, negotiate, run_until};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, MdnsRateLimit};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::transport::RTCIceCandidateType;
use rtci_stream_driver::peer::PeerDriverConfig;
use rtci_stream_driver::runtime::mock::LinkConfig;
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// The longest a driver waits in one step.
const STEP: Duration = Duration::from_millis(10);

/// `QueryAndGather` over UDP only: an ICE-TCP pair would connect without the UDP sockets whose
/// bookkeeping this test is about (0.1.0 closed every UDP socket of a `.local` candidate when
/// the signalling state returned to stable, and a TCP pair hid it).
fn publishing() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
        .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
        .with_tcp_candidate_gathering(false)
}

/// Both connections offer only `.local` names; each driver's mDNS socket carries the other's
/// queries and answers, the names resolve, and the connections connect over UDP on the sockets
/// the drivers keep for their `.local` candidates.
#[test]
fn two_publishing_drivers_resolve_each_other_and_connect_on_virtual_time() -> Result<()> {
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(shared.clone(), A, publishing())?;
    let mut b = Peer::with_settings(shared, B, publishing())?;
    let mut up = false;
    runtime.run(async {
        negotiate(&mut a, &mut b)?;
        up = run_until(&mut a, &mut b, STEP, 2_000, |a, b| {
            a.connected() && b.connected()
        })
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let mdns: Vec<_> = runtime
        .net()
        .log()
        .into_iter()
        .filter(|d| d.to.port() == MDNS_PORT)
        .collect();
    let state = |p: &Peer| {
        format!(
            "{:?}, mDNS sent {} received {}, unsent {}",
            p.driver.pc().connection_state(),
            p.driver.mdns_datagrams_sent(),
            p.driver.mdns_datagrams_received(),
            p.driver.unsent_datagrams()
        )
    };
    assert!(
        up,
        "connected over the resolved .local candidates: a {} / b {}",
        state(&a),
        state(&b)
    );
    assert!(
        mdns.iter().any(|d| d.from.ip() == A) && mdns.iter().any(|d| d.from.ip() == B),
        "each driver's mDNS answers left from the address of their record: {mdns:?}"
    );
    assert_eq!(
        (
            a.driver.local_addresses().len(),
            b.driver.local_addresses().len()
        ),
        (1, 1),
        "each driver still holds the UDP socket of its .local candidate"
    );
    Ok(())
}

/// Both ways blocked between `a` and `b`.
fn cut(runtime: &MockRuntime, a: IpAddr, b: IpAddr) {
    runtime.net().set_links(
        a,
        b,
        LinkConfig {
            blocked: true,
            ..Default::default()
        },
    );
}

/// Runs `a` and `b` (negotiated) until both are connected and each selected pair's remote
/// candidate is the peer's resolved `.local` one, at most 2000 rounds.
fn resolve_and_connect(runtime: &MockRuntime, a: &mut Peer, b: &mut Peer) -> Result<bool> {
    runtime.run(async {
        negotiate(a, b)?;
        run_until(a, b, STEP, 2_000, |a, b| {
            a.connected()
                && b.connected()
                && a.selected_remote_type() == Some(RTCIceCandidateType::Host)
                && b.selected_remote_type() == Some(RTCIceCandidateType::Host)
        })
        .await
    })
}

/// RFC 6762 section 14: a driver takes part in mDNS on the link of its candidates' addresses,
/// not only on the host's default multicast interface. Here the default interface (10.9.9.9)
/// is on another link than both drivers' addresses: each driver joins the group on its own
/// address's interface and sends there, and the names resolve. (A driver that joined on the
/// default interface only heard nothing from the peer's link.)
#[test]
fn drivers_whose_link_is_not_the_default_multicast_interface_resolve_each_other() -> Result<()> {
    const DEFAULT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    const A1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const B1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let runtime = MockRuntime::new();
    runtime.net().set_default_multicast_interface(DEFAULT);
    cut(&runtime, DEFAULT, A1);
    cut(&runtime, DEFAULT, B1);
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(shared.clone(), A1, publishing())?;
    let mut b = Peer::with_settings(shared, B1, publishing())?;
    let up = resolve_and_connect(&runtime, &mut a, &mut b)?;
    assert!(
        up,
        "both resolved the other's name and connected over it: a {:?} {:?}, b {:?} {:?}",
        a.driver.pc().connection_state(),
        a.selected_remote_type(),
        b.driver.pc().connection_state(),
        b.selected_remote_type()
    );
    Ok(())
}

/// RFC 6762 section 14 on a multi-homed host: `a` has an address on the host's default
/// interface (10.0.0.1) and one on the link it shares with `b` (192.168.1.1), and the two
/// links do not reach each other. Each mDNS message about a name leaves from that name's
/// address, on its interface: the answer for `a`'s 192.168.1.1 name reaches `b`, and `b`
/// resolves it. (Sent from the default interface it never arrives, and `b` connects only
/// through a peer-reflexive candidate learnt from `a`'s checks.)
#[test]
fn a_multi_homed_driver_answers_for_each_name_on_the_interface_of_its_address() -> Result<()> {
    const A0: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const A1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const B1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let runtime = MockRuntime::new();
    runtime.net().set_default_multicast_interface(A0);
    cut(&runtime, A0, B1);
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_config(
        shared.clone(),
        publishing(),
        PeerDriverConfig::on(vec![A0, A1]),
    )?;
    let mut b = Peer::with_settings(shared, B1, publishing())?;
    let up = resolve_and_connect(&runtime, &mut a, &mut b)?;
    let answers_from_a1 = runtime
        .net()
        .log()
        .iter()
        .filter(|d| d.to.port() == MDNS_PORT && d.from.ip() == A1)
        .count();
    assert!(
        up,
        "b resolved a's name on their shared link: a {:?} {:?}, b {:?} {:?}",
        a.driver.pc().connection_state(),
        a.selected_remote_type(),
        b.driver.pc().connection_state(),
        b.selected_remote_type()
    );
    assert!(
        answers_from_a1 > 0,
        "a's mDNS for its 192.168.1.1 name left from it"
    );
    Ok(())
}

/// With `.local` candidates the driver can tell its sockets apart only by port (the engine
/// signals a name, not the address), so a publishing driver keeps the ports of its sockets
/// unique across its addresses, though each address has its own ports (the mock network gives
/// each address the same first ephemeral port, as two interfaces of a host can).
#[test]
fn a_publishing_driver_gives_each_of_its_sockets_a_port_of_its_own() -> Result<()> {
    const A0: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const A1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_config(
        shared.clone(),
        publishing(),
        PeerDriverConfig::on(vec![A0, A1]),
    )?;
    let mut b = Peer::with_settings(shared, B, publishing())?;
    let up = resolve_and_connect(&runtime, &mut a, &mut b)?;
    let ports: Vec<u16> = a
        .driver
        .local_addresses()
        .iter()
        .map(|l| l.port())
        .collect();
    assert_eq!(ports.len(), 2, "{ports:?}");
    assert_ne!(ports[0], ports[1], "one port per socket: {ports:?}");
    assert!(up, "connected over the resolved names");
    Ok(())
}

/// RFC 6762 section 11: a response that arrived at the mDNS group is on the link "regardless
/// of source IP address". On a LAN of public addresses the drivers' answers come from public
/// sources; the driver reports that they arrived at the group (the mock reports each
/// datagram's destination as `IP_PKTINFO` would), so the names resolve. (Judged by the scope of
/// the source alone, every answer was refused and nothing resolved.)
#[test]
fn drivers_on_a_lan_of_public_addresses_resolve_each_other() -> Result<()> {
    const A1: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    const B1: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_settings(shared.clone(), A1, publishing())?;
    let mut b = Peer::with_settings(shared, B1, publishing())?;
    let up = resolve_and_connect(&runtime, &mut a, &mut b)?;
    assert!(
        up,
        "resolved over the group from public sources: a {:?} {:?}, b {:?} {:?}",
        a.driver.pc().connection_state(),
        a.selected_remote_type(),
        b.driver.pc().connection_state(),
        b.selected_remote_type()
    );
    Ok(())
}

/// draft-ietf-mmusic-mdns-ice-candidates section 7.1: one rate limit over all mDNS queries and
/// responses. Two connections whose drivers share a small budget (1 at once, then 1 a second)
/// send together no more than it allows over the whole exchange (probes, announcements,
/// queries and answers of both), and still connect: what the budget refused waited, and
/// leaves later at the budget's rate. (On the mock network and clock: it was a test of
/// `tests/mdns.rs` on the host's mDNS group, where it failed whenever the host did not
/// deliver multicast to itself, which says nothing of the budget.)
#[test]
fn two_drivers_send_their_mdns_within_one_shared_budget_on_virtual_time() -> Result<()> {
    const BURST: u32 = 1;
    const PER_SECOND: u32 = 1;
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let limit = MdnsRateLimit::new(BURST, PER_SECOND);
    let config = |ip: IpAddr| PeerDriverConfig {
        mdns_rate_limit: Some(limit.clone()),
        ..PeerDriverConfig::on(vec![ip])
    };
    let mut a = Peer::with_config(shared.clone(), publishing(), config(A))?;
    let mut b = Peer::with_config(shared, publishing(), config(B))?;
    let start = runtime.now();
    let up = runtime.run(async {
        negotiate(&mut a, &mut b)?;
        let up = run_until(&mut a, &mut b, STEP, 10_000, |a, b| {
            a.connected() && b.connected()
        })
        .await?;
        // The exchange goes on for a while, and what the budget held leaves at its rate.
        run_until(&mut a, &mut b, STEP, 10_000, |a, _| {
            a.now().duration_since(start) >= Duration::from_secs(4)
        })
        .await?;
        Ok::<bool, Box<dyn std::error::Error>>(up)
    })?;
    let elapsed = runtime.now().duration_since(start);
    let sent = a.driver.mdns_datagrams_sent() + b.driver.mdns_datagrams_sent();
    let allowed = u64::from(BURST) + (elapsed.as_secs_f64() * f64::from(PER_SECOND)).ceil() as u64;
    assert!(
        elapsed >= Duration::from_secs(4),
        "the exchange ran {elapsed:?} of virtual time"
    );
    assert!(
        sent <= allowed,
        "{sent} mDNS datagrams in {elapsed:?}: the shared budget allows {allowed}"
    );
    assert!(
        sent > u64::from(BURST),
        "the held mDNS left after the burst: {sent}"
    );
    assert!(
        up,
        "connected, the held mDNS sent as the budget allowed: a {:?} / b {:?}",
        a.driver.pc().connection_state(),
        b.driver.pc().connection_state()
    );
    Ok(())
}

/// What two publishing drivers whose only address is 127.0.0.1 did on the mock network.
struct OnLoopback {
    /// Datagrams sent to the IPv4 mDNS group from 127.0.0.1.
    group_from_loopback: usize,
    /// Whether the IPv4 mDNS socket of each was bound and usable.
    available: (bool, bool),
    /// Both connected over the peer's resolved name.
    up: bool,
}

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Two drivers on 127.0.0.1 configured by `config` (one each), run to a connection over each
/// other's resolved `.local` name (at most 2000 rounds).
fn drivers_on_loopback(config: impl Fn() -> PeerDriverConfig) -> Result<OnLoopback> {
    let runtime = MockRuntime::new();
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    let mut a = Peer::with_config(shared.clone(), publishing(), config())?;
    let mut b = Peer::with_config(shared, publishing(), config())?;
    let up = resolve_and_connect(&runtime, &mut a, &mut b)?;
    let group_from_loopback = runtime
        .net()
        .log()
        .iter()
        .filter(|d| d.to == SocketAddr::from((MDNS_MULTICAST_IPV4, MDNS_PORT)))
        .filter(|d| d.from.ip() == LOOPBACK)
        .count();
    Ok(OnLoopback {
        group_from_loopback,
        available: (
            a.driver.mdns_available(false),
            b.driver.mdns_available(false),
        ),
        up,
    })
}

/// With `PeerDriverConfig::mdns_on_loopback_on_windows` (and on every system other than
/// Windows whatever it says), drivers on loopback announce and answer their names on the IPv4
/// group from 127.0.0.1, resolve each other's and connect: the baseline of the next test, which
/// varies only the setting.
#[test]
fn drivers_asked_for_mdns_on_loopback_send_it_there_and_connect() -> Result<()> {
    let run = drivers_on_loopback(|| PeerDriverConfig {
        mdns_on_loopback_on_windows: true,
        ..PeerDriverConfig::on(vec![LOOPBACK])
    })?;
    assert!(
        run.group_from_loopback > 0,
        "mDNS went to the group from 127.0.0.1"
    );
    assert_eq!(run.available, (true, true), "both IPv4 mDNS sockets bound");
    assert!(run.up, "connected over the resolved loopback names");
    Ok(())
}

/// The 0.3.0 default on Windows: a driver sends no mDNS to the IPv4 group from a loopback
/// address and binds no IPv4 mDNS socket for loopback-only addresses, since on Windows that
/// traffic leaves the group's destination-cache route on loopback for the whole host
/// (`peer` module documentation). On other systems the default changes nothing: the same
/// exchange as the test above.
#[test]
fn by_default_drivers_on_loopback_send_no_mdns_there_on_windows_only() -> Result<()> {
    // `PeerDriverConfig::on`'s default, not set here: what is tested is the default itself.
    let run = drivers_on_loopback(|| PeerDriverConfig::on(vec![LOOPBACK]))?;
    if cfg!(windows) {
        assert_eq!(
            run.group_from_loopback, 0,
            "no mDNS to the group from 127.0.0.1"
        );
        assert_eq!(run.available, (false, false), "no IPv4 mDNS socket");
    } else {
        assert!(run.group_from_loopback > 0, "unchanged off Windows");
        assert_eq!(run.available, (true, true));
        assert!(run.up);
    }
    Ok(())
}

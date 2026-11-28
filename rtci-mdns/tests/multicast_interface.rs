//! `MulticastSocket::with_interface`: what the socket sends leaves by that interface (RFC 6762
//! section 14), not by the system's route for the group; and on Windows `MulticastSocket::new()`
//! without an interface joins and sends on the default route's interface. Real multicast: ignored by
//! default, run by `scripts/windows-poisoned-mdns-route.sh` on a Windows host whose route for
//! 224.0.0.251 has been left on loopback (the destination-cache entry a process that sent to
//! the group from 127.0.0.1 leaves behind), where a socket that followed the route sent with
//! source 127.0.0.1.
//!
//! The Windows tests of `new()` first check their own precondition on the host they run on: a
//! socket made as 0.2's `new()` made it (joined on `INADDR_ANY`, no `IP_MULTICAST_IF`) must NOT
//! get the datagram through. The listening case asserts it (a 0.2-style receiver must not hear a
//! sender on the network interface; it held on every host shape measured). The sends case does
//! not: on hosts whose group answer before the poisoning was "vEthernet (nat)" an unconnected
//! send escaped the poisoned route (agent-test run 46124346568), so there it prints the fixed
//! line `### CANNOT PROVE HERE: an unconnected send escapes the poisoned route on this host`
//! (which `scripts/windows-poisoned-mdns-route.sh` raises as a warning) and still asserts that
//! `new()` sends by the default route, which must hold on every host. The tests of this file run
//! one at a time (they share the group).

use rtci_mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, MulticastSocket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The default route's address (a socket connected to a documentation address sends nothing).
fn default_route_v4() -> Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    match socket.local_addr().unwrap().ip() {
        IpAddr::V4(ip) => ip,
        other => panic!("no IPv4 default route: {other}"),
    }
}

/// One test at a time on the group: a test's sockets must not see another's sends.
static GROUP: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    GROUP.lock().unwrap_or_else(|e| e.into_inner())
}

/// A socket made as 0.2's `MulticastSocket::new()` made it on Windows: port 5353 shared, bound to
/// 0.0.0.0, joined on `INADDR_ANY`, TTL 255, no `IP_MULTICAST_IF` (it follows the group's route).
#[cfg(windows)]
fn as_0_2_new() -> std::net::UdpSocket {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.set_multicast_ttl_v4(255).unwrap();
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
        .unwrap();
    socket
        .join_multicast_v4(&MDNS_MULTICAST_IPV4, &Ipv4Addr::UNSPECIFIED)
        .unwrap();
    socket.into()
}

/// Sends a datagram of this process from `sender` to the mDNS group until `receiver` gets it, at
/// most 3 s, and returns the source it came from.
fn source_seen(sender: &std::net::UdpSocket, receiver: &std::net::UdpSocket) -> IpAddr {
    source_seen_within(sender, receiver, Duration::from_secs(3))
        .expect("the datagram came back to the receiver")
}

/// As [`source_seen`], `None` when nothing arrived `within`.
fn source_seen_within(
    sender: &std::net::UdpSocket,
    receiver: &std::net::UdpSocket,
    within: Duration,
) -> Option<IpAddr> {
    receiver.set_nonblocking(false).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let group = SocketAddr::from((MDNS_MULTICAST_IPV4, MDNS_PORT));
    let nonce = (std::process::id()
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default())
    .to_be_bytes();
    let message = [nonce[2], nonce[3], 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut buf = [0u8; 1500];
    let until = Instant::now() + within;
    let mut from = None;
    while Instant::now() < until && from.is_none() {
        sender.send_to(&message, group).unwrap();
        while let Ok((n, source)) = receiver.recv_from(&mut buf) {
            if buf[..n] == message {
                from = Some(source.ip());
                break;
            }
        }
    }
    from
}

#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn a_socket_given_an_interface_sends_from_it_whatever_the_group_route() {
    let _group = one_at_a_time();
    let interface = default_route_v4();
    let sender: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let receiver: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let from = source_seen(&sender, &receiver);
    println!("### sent by {interface}, received from {from}");
    assert_eq!(
        from,
        IpAddr::V4(interface),
        "the datagram left by the system's route for the group, not by the socket's interface"
    );
}

/// On Windows a socket built without an interface sends by the default route's interface, not
/// by the group's route (on loopback on the host the script prepared). The receiver is joined on
/// the default route's interface, as a peer on the network is. Windows only: elsewhere `new()`
/// follows the group's route on purpose.
#[cfg(windows)]
#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn on_windows_a_socket_without_an_interface_sends_by_the_default_route() {
    let _group = one_at_a_time();
    let interface = default_route_v4();
    let receiver: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let control = source_seen_within(&as_0_2_new(), &receiver, Duration::from_secs(2));
    println!(
        "### precondition: a 0.2-style sender reached the receiver on {interface}: {control:?}"
    );
    if control.is_some() {
        // Not a pass of the fix and not a failure of it: on this host (seen on the "vEthernet
        // (nat)" image shape, agent-test run 46124346568) an unconnected send escapes the
        // poisoned route, so 0.2's new() would have passed too. The fixed line below is the
        // marker the script turns into a warning; the real check still runs.
        let before = std::env::var("RTCI_GROUP_ANSWER_BEFORE").unwrap_or_else(|_| "unknown".into());
        let interface_before =
            std::env::var("RTCI_GROUP_INTERFACE_BEFORE").unwrap_or_else(|_| "unknown".into());
        println!(
            "### CANNOT PROVE HERE: an unconnected send escapes the poisoned route on this host \
             ({before} on {interface_before}, default route {interface})"
        );
    }
    let sender: std::net::UdpSocket = MulticastSocket::new().into_std().unwrap();
    let from = source_seen(&sender, &receiver);
    println!("### new() sent, default route {interface}, received from {from}");
    assert_eq!(
        from,
        IpAddr::V4(interface),
        "MulticastSocket::new() sent by the system's route for the group, not by the default route"
    );
}

/// On Windows a socket built without an interface also listens on the default route's
/// interface: a datagram sent there (by a socket given that interface, as a peer on the network
/// sends) reaches it. On the host the script prepared a join on `INADDR_ANY` lands on loopback
/// and hears nothing from the network (agent-test run 46123619860: the interop probe, a `new()`
/// socket that sent by the network interface, never heard itself). Windows only, as above.
#[cfg(windows)]
#[test]
#[ignore = "real multicast on the host's mDNS group; run by scripts/windows-poisoned-mdns-route.sh (cargo.yml, GitHub-hosted Windows)"]
fn on_windows_a_socket_without_an_interface_hears_the_default_route() {
    let _group = one_at_a_time();
    let interface = default_route_v4();
    let sender: std::net::UdpSocket = MulticastSocket::new()
        .with_interface(interface)
        .into_std()
        .unwrap();
    let control = source_seen_within(&sender, &as_0_2_new(), Duration::from_secs(2));
    println!("### precondition: a 0.2-style receiver heard the sender on {interface}: {control:?}");
    assert!(
        control.is_none(),
        "PRECONDITION: on this host a receiver made as 0.2's new() (joined on INADDR_ANY) heard the \
         sender on {interface} from {control:?}: its join is not on the poisoned route, so this \
         test cannot tell the fix apart"
    );
    let receiver: std::net::UdpSocket = MulticastSocket::new().into_std().unwrap();
    let from = source_seen(&sender, &receiver);
    println!("### new() received from {from}, default route {interface}");
    assert_eq!(from, IpAddr::V4(interface));
}

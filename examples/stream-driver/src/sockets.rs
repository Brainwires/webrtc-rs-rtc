//! Server-side socket choices, which belong to the driver and not to the engine: port ranges,
//! which local addresses get candidates, and one UDP port or one ICE-TCP listening port shared
//! by many peer connections.
//!
//! A shared port works because every ICE connectivity check names its recipient: the USERNAME
//! of a Binding request is `<receiver's ufrag>:<sender's ufrag>` (RFC 8445 section 7.2.2). The
//! first request from a remote address says which peer connection it is for
//! ([`UfragMux::route`]); everything else from that address follows it. Each peer connection
//! registers its local ufrags (`RTCPeerConnection::ice_username_fragments`: one per transport,
//! several when sections are not bundled) after each local description, an ICE restart's new
//! ones included. Inside the peer connection the engine does the same between its transports:
//! what the shared port brings goes to the transport whose ufrag the first check names.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::runtime::{AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, Runtime};

/// An inclusive range of ports for the sockets a peer connection gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// The lowest port.
    pub min: u16,
    /// The highest port.
    pub max: u16,
}

impl PortRange {
    /// `min..=max`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `min` is 0 or above `max`.
    pub fn new(min: u16, max: u16) -> io::Result<Self> {
        if min == 0 || min > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not a port range: {min}..={max}"),
            ));
        }
        Ok(Self { min, max })
    }

    fn len(self) -> u32 {
        u32::from(self.max - self.min) + 1
    }

    /// The ports of the range, starting at a rotating offset so that successive sockets spread
    /// over it rather than all trying the first free port.
    fn ports(self) -> impl Iterator<Item = u16> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let len = self.len();
        let start = NEXT.fetch_add(1, Ordering::Relaxed) % len;
        (0..len).map(move |i| self.min + ((start + i) % len) as u16)
    }
}

fn exhausted(range: PortRange) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("no free port in {}..={}", range.min, range.max),
    )
}

/// The first of `ports` that `bind` succeeds on. A port in use is skipped, and so is a port the
/// host refuses to applications (`PermissionDenied`): on Windows a port inside an excluded port
/// range (Hyper-V, WinNAT and other reservations; `netsh interface ipv4 show
/// excludedportrange`) fails with WSAEACCES, and elsewhere a privileged port does; the next
/// port of the range can still be free. Any other error is the same for every port of the range
/// (an address that is not local, ...) and comes back at once.
///
/// When no port could be bound: `AddrInUse` if some port was in use (the range is full), else
/// the refusal (no port of the range is usable on this host).
fn bind_first<T>(
    range: PortRange,
    ports: impl Iterator<Item = u16>,
    mut bind: impl FnMut(u16) -> io::Result<T>,
) -> io::Result<T> {
    let mut in_use = false;
    let mut refused = None;
    for port in ports {
        match bind(port) {
            Ok(socket) => return Ok(socket),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => in_use = true,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refused = Some(e),
            Err(e) => return Err(e),
        }
    }
    match refused {
        Some(e) if !in_use => Err(e),
        _ => Err(exhausted(range)),
    }
}

/// A UDP socket on `ip`, on a free port of `range`. Ports the host refuses (an excluded port
/// range on Windows, a privileged port) are skipped like ports in use.
///
/// # Errors
///
/// `AddrInUse` when every usable port of the range is taken; `PermissionDenied` when the host
/// refuses every port of it; another bind error as it came.
pub fn bind_udp_in_range(ip: IpAddr, range: PortRange) -> io::Result<std::net::UdpSocket> {
    bind_first(range, range.ports(), |port| {
        std::net::UdpSocket::bind(SocketAddr::new(ip, port))
    })
}

/// A UDP socket of `runtime` on `ip`, on a free port of `range`, skipping refused ports as
/// [`bind_udp_in_range`] does.
///
/// # Errors
///
/// As [`bind_udp_in_range`].
pub fn bind_runtime_udp_in_range(
    runtime: &dyn Runtime,
    ip: IpAddr,
    range: PortRange,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    bind_first(range, range.ports(), |port| {
        runtime.bind_udp(SocketAddr::new(ip, port))
    })
}

/// A TCP listener of `runtime` on `ip`, on a free port of `range`.
///
/// # Errors
///
/// As [`bind_udp_in_range`].
pub fn bind_tcp_listener_in_range(
    runtime: &dyn Runtime,
    ip: IpAddr,
    range: PortRange,
    reuse_address: bool,
) -> io::Result<Arc<dyn AsyncTcpListener>> {
    bind_first(range, range.ports(), |port| {
        runtime.listen_tcp(SocketAddr::new(ip, port), reuse_address)
    })
}

/// Keeps an interface by name.
pub type InterfaceFilter = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// Keeps an address.
pub type IpFilter = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Which local addresses get host candidates.
#[derive(Clone, Default)]
pub struct AddressFilter {
    /// Only these addresses (bind addresses); empty: every address of every interface.
    pub bind_addresses: Vec<IpAddr>,
    /// Loopback addresses too (off by default: RFC 8445 section 5.1.1.1: "Addresses from a
    /// loopback interface MUST NOT be included in the candidate addresses"; turning this on
    /// departs from that rule, for local use and tests only). On Windows a driver with mDNS on a loopback address leaves a
    /// destination-cache route for 224.0.0.251 via loopback after the process exits, and the
    /// system then routes the group by loopback for other processes until the entry is deleted
    /// (`peer` module documentation), so on Windows a `PeerDriver` sends no mDNS on loopback
    /// unless `PeerDriverConfig::mdns_on_loopback_on_windows` asks.
    pub include_loopback: bool,
    /// IPv6 link-local addresses too (off by default).
    pub include_link_local: bool,
    /// Keep an interface by name (`eth0`, `en0`, ...).
    pub interface_filter: Option<InterfaceFilter>,
    /// Keep an address.
    pub ip_filter: Option<IpFilter>,
}

impl std::fmt::Debug for AddressFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressFilter")
            .field("bind_addresses", &self.bind_addresses)
            .field("include_loopback", &self.include_loopback)
            .field("include_link_local", &self.include_link_local)
            .field("interface_filter", &self.interface_filter.is_some())
            .field("ip_filter", &self.ip_filter.is_some())
            .finish()
    }
}

impl AddressFilter {
    /// Whether `ip`, on the interface named `interface` (when known), passes.
    pub fn keeps(&self, interface: Option<&str>, ip: IpAddr) -> bool {
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }
        if ip.is_loopback() && !self.include_loopback {
            return false;
        }
        if let IpAddr::V6(v6) = ip
            && v6.is_unicast_link_local()
            && !self.include_link_local
        {
            return false;
        }
        if let (Some(filter), Some(name)) = (&self.interface_filter, interface)
            && !filter(name)
        {
            return false;
        }
        self.ip_filter.as_ref().is_none_or(|filter| filter(ip))
    }

    /// The addresses to gather on: the bind addresses that pass, or every interface address
    /// that passes.
    ///
    /// # Errors
    ///
    /// The interfaces could not be listed.
    pub fn local_addresses(&self) -> io::Result<Vec<IpAddr>> {
        if !self.bind_addresses.is_empty() {
            return Ok(self
                .bind_addresses
                .iter()
                .copied()
                .filter(|ip| self.keeps(None, *ip))
                .collect());
        }
        let mut out = Vec::new();
        for interface in shared::ifaces::ifaces()? {
            let Some(addr) = interface.addr else {
                continue;
            };
            let ip = addr.ip();
            if self.keeps(Some(&interface.name), ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
        Ok(out)
    }
}

/// The ufrags of a STUN Binding request: `(receiver, sender)` from its USERNAME (RFC 8445
/// section 7.2.2). `None` for anything else.
pub fn binding_request_ufrags(datagram: &[u8]) -> Option<(&str, &str)> {
    const BINDING_REQUEST: u16 = 0x0001;
    const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
    const USERNAME: u16 = 0x0006;
    if datagram.len() < 20 || datagram[4..8] != MAGIC_COOKIE {
        return None;
    }
    if u16::from_be_bytes([datagram[0], datagram[1]]) != BINDING_REQUEST {
        return None;
    }
    let length = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let attributes = datagram.get(20..20 + length)?;
    let mut at = 0;
    while at + 4 <= attributes.len() {
        let kind = u16::from_be_bytes([attributes[at], attributes[at + 1]]);
        let len = u16::from_be_bytes([attributes[at + 2], attributes[at + 3]]) as usize;
        let value = attributes.get(at + 4..at + 4 + len)?;
        if kind == USERNAME {
            let username = std::str::from_utf8(value).ok()?;
            return username.split_once(':');
        }
        at += 4 + len.next_multiple_of(4);
    }
    None
}

/// Routes what arrives on a shared port to the peer connection it is for: by the receiver's
/// ufrag of the first Binding request from an address, then by that address.
#[derive(Debug)]
pub struct UfragMux<K> {
    by_ufrag: HashMap<String, K>,
    by_address: HashMap<SocketAddr, K>,
}

impl<K> Default for UfragMux<K> {
    fn default() -> Self {
        Self {
            by_ufrag: HashMap::new(),
            by_address: HashMap::new(),
        }
    }
}

impl<K: Clone + Eq + Hash> UfragMux<K> {
    /// An empty mux.
    pub fn new() -> Self {
        Self::default()
    }

    /// `key`'s peer connection answers to `ufrag` (its local ICE username fragment).
    pub fn register(&mut self, ufrag: &str, key: K) {
        self.by_ufrag.insert(ufrag.to_owned(), key);
    }

    /// Forgets `key`: its ufrags and its remote addresses.
    pub fn unregister(&mut self, key: &K) {
        self.by_ufrag.retain(|_, k| k != key);
        self.by_address.retain(|_, k| k != key);
    }

    /// The peer connection that registered `ufrag`.
    pub fn lookup_ufrag(&self, ufrag: &str) -> Option<&K> {
        self.by_ufrag.get(ufrag)
    }

    /// The peer connection a datagram from `from` is for: the one this address was routed to
    /// before, or the one the datagram (a Binding request) names. `None`: no one's; drop it.
    pub fn route(&mut self, from: SocketAddr, datagram: &[u8]) -> Option<K> {
        if let Some(key) = self.by_address.get(&from) {
            // A request naming another registered ufrag moves the address (a peer that
            // restarted ICE with the same address talks to another connection now).
            if let Some((receiver, _)) = binding_request_ufrags(datagram)
                && let Some(other) = self.by_ufrag.get(receiver)
                && other != key
            {
                let other = other.clone();
                self.by_address.insert(from, other.clone());
                return Some(other);
            }
            return Some(key.clone());
        }
        let (receiver, _) = binding_request_ufrags(datagram)?;
        let key = self.by_ufrag.get(receiver)?.clone();
        self.by_address.insert(from, key.clone());
        Some(key)
    }
}

/// A connection accepted on an ICE-TCP listening port shared by many peer connections, with
/// the ufrag its first check names.
#[derive(Debug)]
pub struct SharedAccept {
    /// The connection.
    pub stream: Arc<dyn AsyncTcpStream>,
    /// Its local address (the shared port).
    pub local: SocketAddr,
    /// The peer's address.
    pub remote: SocketAddr,
    /// The receiver's ufrag of its first Binding request.
    pub ufrag: String,
    /// What was read to find it, to hand to the engine first
    /// ([`StreamDriver::adopt_shared`](crate::StreamDriver::adopt_shared)).
    pub read: Vec<u8>,
}

/// Accepts the next connection on a shared ICE-TCP port and reads its first RFC 4571 frame
/// (for `timeout` at most) to learn which peer connection it is for. Connections whose first
/// frame is not a Binding request with a USERNAME are dropped and the next one is awaited.
///
/// # Errors
///
/// An accept error.
pub async fn accept_by_ufrag(
    runtime: &dyn Runtime,
    listener: &dyn AsyncTcpListener,
    timeout: Duration,
) -> io::Result<SharedAccept> {
    loop {
        let (stream, remote) = listener.accept().await?;
        let local = stream.local_addr()?;
        let mut read = Vec::new();
        let first = crate::runtime::timeout(runtime, timeout, async {
            let mut buf = [0u8; 4096];
            loop {
                if read.len() >= 2 {
                    let len = u16::from_be_bytes([read[0], read[1]]) as usize;
                    if read.len() >= 2 + len {
                        return Some(read[2..2 + len].to_vec());
                    }
                }
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => read.extend_from_slice(&buf[..n]),
                }
                if read.len() > 2 + 65535 {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten();
        let Some(frame) = first else {
            continue;
        };
        let Some((ufrag, _)) = binding_request_ufrags(&frame) else {
            continue;
        };
        let ufrag = ufrag.to_owned();
        return Ok(SharedAccept {
            stream,
            local,
            remote,
            ufrag,
            read,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Binding request with USERNAME `username` (no integrity: the mux reads, never trusts).
    pub(crate) fn binding_request(username: &str) -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x0006u16.to_be_bytes());
        attrs.extend_from_slice(&(username.len() as u16).to_be_bytes());
        attrs.extend_from_slice(username.as_bytes());
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }
        let mut m = vec![0x00, 0x01];
        m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        m.extend_from_slice(&[9; 12]);
        m.extend(attrs);
        m
    }

    #[test]
    fn the_ufrags_of_a_binding_request_are_read_and_nothing_else_is_taken_for_one() {
        assert_eq!(
            binding_request_ufrags(&binding_request("abcd:wxyz")),
            Some(("abcd", "wxyz"))
        );
        // A Binding response, a DTLS record, a short datagram.
        let mut response = binding_request("abcd:wxyz");
        response[1] = 0x01;
        response[0] = 0x01;
        assert_eq!(binding_request_ufrags(&response), None);
        assert_eq!(binding_request_ufrags(&[22, 254, 253, 0, 0]), None);
        assert_eq!(binding_request_ufrags(&[0; 10]), None);
        // An attribute running past the message.
        let mut cut = binding_request("abcd:wxyz");
        cut.truncate(26);
        assert_eq!(binding_request_ufrags(&cut), None);
    }

    #[test]
    fn a_mux_routes_by_the_first_request_then_by_the_address() {
        let mut mux = UfragMux::new();
        mux.register("aaaa", 1);
        mux.register("bbbb", 2);
        let x: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let y: SocketAddr = "198.51.100.2:5000".parse().unwrap();
        // DTLS from an address no request came from: nobody's.
        assert_eq!(mux.route(x, &[22, 254, 253]), None);
        assert_eq!(mux.route(x, &binding_request("bbbb:peer")), Some(2));
        assert_eq!(mux.route(x, &[22, 254, 253]), Some(2), "then by address");
        assert_eq!(mux.route(y, &binding_request("aaaa:peer")), Some(1));
        assert_eq!(mux.route(y, &binding_request("zzzz:peer")), Some(1));
        // A request for an unknown ufrag from a new address is dropped.
        let z: SocketAddr = "198.51.100.3:5000".parse().unwrap();
        assert_eq!(mux.route(z, &binding_request("zzzz:peer")), None);
        // A known address naming another connection moves to it.
        assert_eq!(mux.route(y, &binding_request("bbbb:peer")), Some(2));
        mux.unregister(&2);
        assert_eq!(mux.route(x, &[22]), None);
        assert_eq!(mux.lookup_ufrag("aaaa"), Some(&1));
    }

    #[test]
    fn port_ranges_are_checked_and_cover_every_port() {
        assert!(PortRange::new(0, 10).is_err());
        assert!(PortRange::new(20, 10).is_err());
        let range = PortRange::new(40000, 40003).unwrap();
        let mut ports: Vec<u16> = range.ports().collect();
        ports.sort();
        assert_eq!(ports, vec![40000, 40001, 40002, 40003]);
    }

    /// A stand-in for the host: ports in use, and ports it refuses (Windows' excluded port
    /// ranges answer WSAEACCES, which std reports as `PermissionDenied`).
    struct Host {
        in_use: Vec<u16>,
        refused: Vec<u16>,
    }

    impl Host {
        fn bind(&mut self, port: u16) -> io::Result<u16> {
            if self.refused.contains(&port) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else if self.in_use.contains(&port) {
                Err(io::Error::from(io::ErrorKind::AddrInUse))
            } else {
                self.in_use.push(port);
                Ok(port)
            }
        }
    }

    #[test]
    fn a_port_the_host_refuses_inside_the_range_is_skipped_like_one_in_use() {
        let range = PortRange::new(40000, 40003).unwrap();
        let mut host = Host {
            in_use: vec![],
            refused: vec![40000, 40001],
        };
        // Starting at a refused port, then another: the free ports after them are used.
        let order = || [40000, 40001, 40002, 40003].into_iter();
        assert_eq!(bind_first(range, order(), |p| host.bind(p)).unwrap(), 40002);
        assert_eq!(bind_first(range, order(), |p| host.bind(p)).unwrap(), 40003);
        // Every usable port taken: the range is full.
        let full = bind_first(range, order(), |p| host.bind(p)).unwrap_err();
        assert_eq!(full.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn a_range_the_host_refuses_entirely_says_so_rather_than_full() {
        let range = PortRange::new(40000, 40001).unwrap();
        let mut host = Host {
            in_use: vec![],
            refused: vec![40000, 40001],
        };
        let err = bind_first(range, range.ports(), |p| host.bind(p)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // Another error is the same for every port and is not retried.
        let mut tried = 0;
        let err = bind_first(range, range.ports(), |_| -> io::Result<()> {
            tried += 1;
            Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
        })
        .unwrap_err();
        assert_eq!((err.kind(), tried), (io::ErrorKind::AddrNotAvailable, 1));
    }

    #[test]
    fn the_address_filter_drops_loopback_link_local_and_what_the_filters_refuse() {
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let ll: IpAddr = "fe80::1".parse().unwrap();
        let filter = AddressFilter {
            bind_addresses: vec![v4, lo, ll],
            ..Default::default()
        };
        assert_eq!(filter.local_addresses().unwrap(), vec![v4]);
        let all = AddressFilter {
            include_loopback: true,
            include_link_local: true,
            ..filter.clone()
        };
        assert_eq!(all.local_addresses().unwrap(), vec![v4, lo, ll]);
        let only_v6 = AddressFilter {
            ip_filter: Some(Arc::new(|ip: IpAddr| ip.is_ipv6())),
            ..all.clone()
        };
        assert_eq!(only_v6.local_addresses().unwrap(), vec![ll]);
        let no_eth = AddressFilter {
            interface_filter: Some(Arc::new(|name: &str| !name.starts_with("eth"))),
            ..Default::default()
        };
        assert!(!no_eth.keeps(Some("eth0"), v4));
        assert!(no_eth.keeps(Some("wlan0"), v4));
    }
}

/// `IPV6_TCLASS`, on the targets where `socket2` has it.
#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
))]
fn set_tclass(socket: &socket2::SockRef<'_>, value: u32) -> io::Result<()> {
    socket.set_tclass_v6(value)
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
))]
fn tclass(socket: &socket2::SockRef<'_>) -> io::Result<u32> {
    socket.tclass_v6()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
)))]
fn set_tclass(_: &socket2::SockRef<'_>, _: u32) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
)))]
fn tclass(_: &socket2::SockRef<'_>) -> io::Result<u32> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Sets the byte the socket's packets carry in the IPv4 TOS / IPv6 Traffic Class field: the
/// DSCP in its upper six bits (RFC 2474 section 3), the ECN codepoint in the lower two (RFC
/// 3168 section 5). `ipv6` says which option (`IPV6_TCLASS` or `IP_TOS`) the socket's family
/// takes.
///
/// What each platform does:
/// - **Linux, Android, the BSDs, macOS**: `IP_TOS` / `IPV6_TCLASS` set what every later
///   packet carries, with no privilege. (Linux keeps the ECN bits of a TCP socket to itself.)
/// - **Windows**: `IP_TOS` is accepted, and `getsockopt` reads the value back (hosted
///   `windows-latest`), but Microsoft documents the option as not to be used and the stack as
///   not applying it unless the host's policy allows applications to set it (it does not by
///   default): the packets are not known to carry it. Marking needs the qWAVE
///   API (`QOSAddSocketToFlow`, and `QOSSetFlow` with `QOSSetOutgoingDSCPValue`, which only an
///   administrator or a member of Network Configuration Operators may call) or a Group Policy
///   QoS rule. The driver does neither: on Windows its packets leave unmarked whatever the
///   engine asks, and RFC 8835 section 4.2 allows that ("It is appropriate to depart from this
///   recommendation when running on platforms where QoS marking is not implemented").
///   `IPV6_TCLASS` is not offered there (`socket2` has none): `Unsupported`, and the driver
///   counts the socket in `PeerDriver::unmarked_sockets`.
/// - Other targets without `IPV6_TCLASS` in `socket2`: an error for IPv6.
///
/// # Errors
///
/// The option is refused or not offered on this platform.
pub fn set_traffic_class(socket: socket2::SockRef<'_>, ipv6: bool, value: u8) -> io::Result<()> {
    if ipv6 {
        set_tclass(&socket, u32::from(value))
    } else {
        socket.set_tos_v4(u32::from(value))
    }
}

/// The byte the socket's packets carry in the IPv4 TOS / IPv6 Traffic Class field, as the
/// operating system reports it (`getsockopt` of `IP_TOS` / `IPV6_TCLASS`).
///
/// # Errors
///
/// The option is not offered on this platform.
pub fn traffic_class(socket: socket2::SockRef<'_>, ipv6: bool) -> io::Result<u32> {
    if ipv6 {
        tclass(&socket)
    } else {
        socket.tos_v4()
    }
}

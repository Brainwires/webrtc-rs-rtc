//! Socket utilities for mDNS.
//!
//! This module provides [`MulticastSocket`], a builder for creating properly
//! configured UDP sockets for mDNS communication.
//!
//! # Example
//!
//! ```rust,ignore
//! use rtci_mdns::MulticastSocket;
//! use std::net::SocketAddr;
//!
//! let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
//! let std_socket = MulticastSocket::new(bind_addr).into_std()?;
//!
//! // For tokio:
//! let socket = tokio::net::UdpSocket::from_std(std_socket)?;
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use crate::MDNS_PORT;
use crate::proto::MDNS_MULTICAST_IPV4;
use socket2::{Domain, Protocol, Socket, Type};

/// The IP TTL mDNS packets are sent with (RFC 6762 section 11): older queriers take any
/// other value for a packet from off the link and drop it.
const MDNS_IP_TTL: u32 = 255;

/// Sets the TTL of what `socket` sends, multicast and unicast, to [`MDNS_IP_TTL`]. The
/// operating system's default for multicast is 1.
fn set_mdns_ttl(socket: &Socket) -> io::Result<()> {
    socket.set_multicast_ttl_v4(MDNS_IP_TTL)?;
    socket.set_ttl_v4(MDNS_IP_TTL)
}

/// A builder for creating multicast UDP sockets suitable for mDNS.
///
/// `MulticastSocket` provides a convenient way to create properly configured
/// UDP sockets for mDNS communication. The resulting socket will be:
///
/// - Bound to the specified address (typically `0.0.0.0:5353`)
/// - Configured with `SO_REUSEADDR` enabled
/// - Configured with `SO_REUSEPORT` enabled (on supported platforms)
/// - Set to non-blocking mode for async compatibility
/// - Joined to the mDNS multicast group (224.0.0.251)
/// - Sending with IP TTL 255, multicast and unicast (RFC 6762 section 11)
///
/// # Examples
///
/// Basic usage with tokio:
///
/// ```rust,ignore
/// use rtci_mdns::MulticastSocket;
/// use std::net::SocketAddr;
///
/// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
/// let std_socket = MulticastSocket::new(bind_addr).into_std()?;
/// let socket = tokio::net::UdpSocket::from_std(std_socket)?;
/// ```
///
/// With a specific network interface:
///
/// ```rust,ignore
/// use rtci_mdns::MulticastSocket;
/// use std::net::{Ipv4Addr, SocketAddr};
///
/// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
/// let interface = Ipv4Addr::new(192, 168, 1, 100);
/// let std_socket = MulticastSocket::new(bind_addr)
///     .with_interface(interface)
///     .into_std()?;
/// ```
#[derive(Debug, Clone)]
pub struct MulticastSocket {
    multicast_local_ipv4: Option<Ipv4Addr>,
    multicast_local_port: Option<u16>,
    interface: Option<Ipv4Addr>,
}

impl Default for MulticastSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastSocket {
    /// Creates a new `MulticastSocket` builder with the specified bind address.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The local address to bind to. Use `0.0.0.0:5353` to listen
    ///   on all interfaces on the standard mDNS port.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MulticastSocket;
    ///
    /// let builder = MulticastSocket::new();
    /// ```
    pub fn new() -> Self {
        Self {
            multicast_local_ipv4: None,
            multicast_local_port: None,
            interface: None,
        }
    }

    /// Sets the local IPv4 address to bind the multicast socket to.
    ///
    /// Defaults to unspecified (`0.0.0.0`), letting the OS choose.
    pub fn with_multicast_local_ipv4(mut self, multicast_local_ipv4: Ipv4Addr) -> Self {
        self.multicast_local_ipv4 = Some(multicast_local_ipv4);
        self
    }

    /// Sets the local port to bind the multicast socket to.
    ///
    /// Defaults to the mDNS port (5353), which is required to receive multicast queries
    /// from other hosts; a different port is only useful for testing.
    pub fn with_multicast_local_port(mut self, multicast_local_port: u16) -> Self {
        self.multicast_local_port = Some(multicast_local_port);
        self
    }

    /// Sets a specific network interface for multicast operations.
    ///
    /// If not set, the socket joins the multicast group on all interfaces
    /// (`INADDR_ANY`).
    ///
    /// With an interface the socket also sends by it (`IP_MULTICAST_IF`, RFC 6762 section 14).
    /// Without one, on Linux, macOS and other systems, it sends by the system's route for
    /// 224.0.0.251. On Windows that route comes from the destination cache, and a process that
    /// sent to the group from 127.0.0.1 leaves it on loopback after it exits, so on Windows a
    /// socket built without an interface (and without a local address of its own,
    /// [`with_multicast_local_ipv4`](Self::with_multicast_local_ipv4)) joins and sends on the
    /// interface of the default route instead (see [`into_std`](Self::into_std)). On a Windows host with
    /// several interfaces whose mDNS link is not the default route's, pass the interface of
    /// the address the application publishes.
    ///
    /// # Arguments
    ///
    /// * `interface` - The IPv4 address of the network interface to use.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MulticastSocket;
    /// use std::net::Ipv4Addr;
    ///
    /// let builder = MulticastSocket::new()
    ///     .with_interface(Ipv4Addr::new(192, 168, 1, 100));
    /// ```
    pub fn with_interface(mut self, interface: Ipv4Addr) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Converts this builder into a configured `std::net::UdpSocket`.
    ///
    /// This method creates the socket with the following configuration:
    /// - `SO_REUSEADDR` enabled (allows multiple processes to bind)
    /// - `SO_REUSEPORT` enabled on Unix platforms (except Solaris/illumos)
    /// - Non-blocking mode enabled (for async compatibility)
    /// - Joined to the mDNS multicast group (224.0.0.251), on [`with_interface`]'s interface when
    ///   one is given, and sending by that interface (`IP_MULTICAST_IF`), whatever the system's
    ///   route for the group says
    /// - Without an interface: on Windows, unless [`with_multicast_local_ipv4`] names a local
    ///   address, joined and sending on the interface of the default route (the address a UDP
    ///   socket connected to 192.0.2.1, a documentation address, takes; nothing is sent there),
    ///   as if [`with_interface`] had named it: the system's route for the group, which both a
    ///   join on `INADDR_ANY` and a send without `IP_MULTICAST_IF` follow there, is left on
    ///   loopback for the whole host by any process that sent to the group from 127.0.0.1.
    ///   Where the default route's address is unspecified or loopback, or there is none, and on
    ///   other systems: joined on the default interface (`INADDR_ANY`), sending by the system's
    ///   route for the group
    /// - IP TTL 255 on what it sends (RFC 6762 section 11)
    ///
    /// [`with_interface`]: Self::with_interface
    /// [`with_multicast_local_ipv4`]: Self::with_multicast_local_ipv4
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Setting socket options fails
    /// - Binding to the address fails
    /// - Joining the multicast group fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rtci_mdns::MulticastSocket;
    /// use std::net::SocketAddr;
    ///
    /// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    /// let std_socket = MulticastSocket::new(bind_addr).into_std()?;
    ///
    /// // Use with tokio:
    /// let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    /// ```
    ///
    /// # Platform Notes
    ///
    /// - On Unix-like systems (except Solaris/illumos), `SO_REUSEPORT` is enabled
    ///   to allow multiple processes to bind to the same port.
    pub fn into_std(self) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Enable address reuse for multiple processes
        socket.set_reuse_address(true)?;

        // Enable port reuse on supported platforms
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;

        // Set non-blocking mode for async compatibility
        socket.set_nonblocking(true)?;

        // RFC 6762 section 11: responses leave with IP TTL 255
        set_mdns_ttl(&socket)?;

        let multicast_local_ip = if let Some(multicast_local_ipv4) = self.multicast_local_ipv4 {
            IpAddr::V4(multicast_local_ipv4)
        } else if cfg!(target_os = "linux") {
            IpAddr::V4(MDNS_MULTICAST_IPV4)
        } else {
            // DNS_MULTICAST_IPV4 doesn't work on Mac/Win,
            // only 0.0.0.0 works fine, even 127.0.0.1 doesn't work
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        };

        let multicast_local_port = if let Some(multicast_local_port) = self.multicast_local_port {
            multicast_local_port
        } else {
            MDNS_PORT
        };

        let multicast_local_addr = SocketAddr::new(multicast_local_ip, multicast_local_port);

        // Bind to the specified address
        socket.bind(&multicast_local_addr.into())?;

        // RFC 6762 section 14: the socket joins the group on the interface it sends by, and what
        // it sends leaves by that interface (`IP_MULTICAST_IF`), not by the system's route for
        // the group. On Windows that route comes from the destination cache, which a process
        // that sent to the group from loopback leaves on loopback after it has exited (source
        // 127.0.0.1, `netsh interface ipv4 show destinationcache`): a socket without
        // `IP_MULTICAST_IF` then sends by loopback with source 127.0.0.1, and a join on
        // `INADDR_ANY` lands on loopback too (agent-test run 46123619860: a socket joined on
        // `INADDR_ANY` and sending by the network interface no longer heard its own datagrams).
        // So without an interface, on Windows, the socket joins and sends on the default route's
        // interface (`multicast_if`). Elsewhere it keeps `INADDR_ANY` and the system's route
        // (GitHub's macOS image routes the group to lo0 on purpose).
        let bound_unspecified = self
            .multicast_local_ipv4
            .is_none_or(|ip| ip.is_unspecified());
        let iface = multicast_if(
            self.interface,
            cfg!(windows) && bound_unspecified,
            default_route_v4,
        );
        socket.join_multicast_v4(
            &MDNS_MULTICAST_IPV4,
            &iface.unwrap_or(Ipv4Addr::UNSPECIFIED),
        )?;
        if let Some(iface) = iface {
            socket.set_multicast_if_v4(&iface)?;
        }

        Ok(socket.into())
    }
}

/// The interface a socket joins the group on and its multicast leaves by (`IP_MULTICAST_IF`), or
/// `None` for `INADDR_ANY` and the system's route for the group: the interface given; without one, where `default_route_instead` (on
/// Windows, a socket bound to the unspecified address), the default route's
/// ([`default_route_v4`]) unless that is unspecified or loopback.
fn multicast_if(
    interface: Option<Ipv4Addr>,
    default_route_instead: bool,
    default_route: impl FnOnce() -> Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    match interface {
        Some(interface) if !interface.is_unspecified() => Some(interface),
        _ if default_route_instead => {
            default_route().filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
        }
        _ => None,
    }
}

/// The address of the host's default-route IPv4 interface: the local address a UDP socket
/// connected to 192.0.2.1:9 (TEST-NET-1, RFC 5737) takes. Connecting a UDP socket sends nothing.
/// `None` without an IPv4 default route. Not the route for 224.0.0.251, which is what a stale
/// destination-cache entry moves on Windows.
fn default_route_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::MDNS_PORT;
    use std::str::FromStr;

    #[test]
    fn test_multicast_constants() {
        assert_eq!(MDNS_MULTICAST_IPV4, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(MDNS_PORT, 5353);
    }

    #[test]
    fn test_multicast_socket_builder() {
        let builder = MulticastSocket::new()
            .with_multicast_local_ipv4(Ipv4Addr::from_str("0.0.0.0").unwrap())
            .with_multicast_local_port(5353);
        assert!(builder.multicast_local_ipv4.is_some());
        assert!(builder.multicast_local_port.is_some());
        assert!(builder.interface.is_none());
    }

    #[test]
    fn test_multicast_socket_with_interface() {
        let interface = Ipv4Addr::new(192, 168, 1, 100);
        let builder = MulticastSocket::new()
            .with_multicast_local_ipv4(Ipv4Addr::from_str("0.0.0.0").unwrap())
            .with_multicast_local_port(5353)
            .with_interface(interface);
        assert_eq!(builder.interface, Some(interface));
    }

    // RFC 6762 section 11. The socket is neither bound nor used: only its options are read.
    #[test]
    fn test_mdns_socket_sends_with_ip_ttl_255() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        assert_ne!(socket.multicast_ttl_v4().unwrap(), 255, "not the default");
        set_mdns_ttl(&socket).unwrap();
        assert_eq!(socket.multicast_ttl_v4().unwrap(), 255);
        assert_eq!(socket.ttl_v4().unwrap(), 255);
    }

    const NIC: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 49);

    // RFC 6762 section 14: an interface given is the one sent by, on every platform; the default
    // route is not even asked.
    #[test]
    fn an_interface_given_is_the_one_multicast_leaves_by() {
        let given = Ipv4Addr::new(192, 168, 1, 100);
        for default_route_instead in [false, true] {
            assert_eq!(
                multicast_if(Some(given), default_route_instead, || panic!("not asked")),
                Some(given)
            );
        }
    }

    // On Windows (`default_route_instead`) a socket without an interface sends by the default
    // route's interface, not by the group's route that a stale destination-cache entry leaves on
    // loopback; elsewhere it follows the system's route (`None`).
    #[test]
    fn without_an_interface_windows_sends_by_the_default_route_and_others_by_the_group_route() {
        assert_eq!(multicast_if(None, true, || Some(NIC)), Some(NIC));
        assert_eq!(
            multicast_if(Some(Ipv4Addr::UNSPECIFIED), true, || Some(NIC)),
            Some(NIC)
        );
        assert_eq!(multicast_if(None, false, || panic!("not asked")), None);
    }

    // A default route that is loopback or unspecified, or none, leaves the system's route.
    #[test]
    fn a_default_route_on_loopback_or_none_leaves_the_system_route() {
        assert_eq!(multicast_if(None, true, || Some(Ipv4Addr::LOCALHOST)), None);
        assert_eq!(
            multicast_if(None, true, || Some(Ipv4Addr::UNSPECIFIED)),
            None
        );
        assert_eq!(multicast_if(None, true, || None), None);
    }

    // Note: Socket creation tests would require actual network access
    // and might conflict with other mDNS services, so we keep them minimal
}

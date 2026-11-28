//! The async runtime a driver runs on, injected per driver.
//!
//! The engine is sans-I/O; the driver owns sockets, tasks and timers. Everything of those that
//! touches a reactor or a clock goes through one object-safe trait, [`Runtime`], given to each
//! driver as an `Arc<dyn Runtime>` ([`StreamDriver::with_runtime`](crate::StreamDriver::with_runtime),
//! [`PeerDriver::with_runtime`](crate::peer::PeerDriver::with_runtime)):
//!
//! | Injected (reactor or clock) | Not injected (executor-agnostic, one implementation) |
//! | --- | --- |
//! | spawning a task ([`Runtime::spawn`]) | channels and wake-ups between the driver's tasks |
//! | the clock and timers ([`Runtime::now`], [`Runtime::sleep_until`]) | [`sleep`], [`timeout`], [`yield_now`]: free functions on top |
//! | UDP sockets, multicast included ([`Runtime::bind_udp`], [`Runtime::bind_udp_multicast`]) | |
//! | TCP listeners and connections ([`Runtime::listen_tcp`], [`Runtime::connect_tcp`]) | |
//! | name resolution ([`Runtime::resolve_host`] and the optional record lookups) | |
//! | running a future to completion ([`Runtime::block_on`]) | |
//!
//! There is no global or default runtime in the library, and none can be set: each driver is
//! given its own. Cargo features only decide which built-in runtime *types* exist
//! (`runtime-tokio`, on by default: `TokioRuntime`; `runtime-smol`: `SmolRuntime`;
//! `runtime-mock`: `MockRuntime`, virtual time and an in-memory network); they never
//! decide what the driver uses, and several can be on at once.
//! With `default-features = false` and no built-in runtime the crate builds without any of them,
//! and an application implements [`Runtime`] for its own executor (the `custom-runtime`
//! example).
//!
//! The design follows the upstream project's "Bring Your Own Async Runtime"
//! (webrtc.rs, 2026-07-30), with one addition: the clock ([`Runtime::now`]) is the runtime's,
//! because the driver stamps every engine input with a time and a virtual clock must be the
//! one both the engine and the timers see.

#[cfg(feature = "runtime-mock")]
pub mod mock;
#[cfg(feature = "runtime-smol")]
mod smol_runtime;
#[cfg(feature = "runtime-tokio")]
mod tokio_runtime;
#[cfg(feature = "runtime-mock")]
pub use mock::{MockClock, MockNet, MockRuntime};
#[cfg(feature = "runtime-smol")]
pub use smol_runtime::SmolRuntime;
#[cfg(feature = "runtime-tokio")]
pub use tokio_runtime::TokioRuntime;

use shared::stream::{DnsRecord, RecordKind};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::fmt::Debug;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// A boxed future that can move between threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a driver needs from an async runtime: the primitives that touch a reactor or a clock.
///
/// Object safe (`&self` receivers, no generic methods): drivers hold an `Arc<dyn Runtime>`.
/// See the [module documentation](self) for what is and is not here.
pub trait Runtime: Send + Sync + Debug + 'static {
    /// Runs `future` as a task of its own. Dropping the handle detaches the task (it runs on);
    /// [`JoinHandle::abort`] cancels it.
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Box<dyn JoinHandle>;

    /// The runtime's clock. Every time the driver gives the engine comes from here, so a
    /// virtual clock drives the engine's timers too.
    fn now(&self) -> Instant;

    /// A future that completes once [`now`](Self::now) has reached `deadline` (at once when it
    /// has already).
    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()>;

    /// A UDP socket bound to `local` (port 0: any free port).
    ///
    /// # Errors
    ///
    /// The bind failed: `AddrInUse` for a port in use, `PermissionDenied` for one the host
    /// refuses (both are skipped inside a port range).
    fn bind_udp(&self, local: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>>;

    /// A UDP socket joined to a multicast group (mDNS: 224.0.0.251 or ff02::fb on 5353).
    ///
    /// # Errors
    ///
    /// The bind or the join failed (a host without IPv6, say).
    fn bind_udp_multicast(&self, config: &MulticastConfig) -> io::Result<Arc<dyn AsyncUdpSocket>>;

    /// A TCP listener on `local` (backlog 128). `reuse_address` sets `SO_REUSEADDR` (and
    /// `SO_REUSEPORT` where the platform has it).
    ///
    /// # Errors
    ///
    /// As [`bind_udp`](Self::bind_udp).
    fn listen_tcp(
        &self,
        local: SocketAddr,
        reuse_address: bool,
    ) -> io::Result<Arc<dyn AsyncTcpListener>>;

    /// A TCP connection from `local` (bound first: an ICE-TCP active candidate's address) to
    /// `remote`, with `TCP_NODELAY` set. The driver bounds it with its connect timeout.
    fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        reuse_address: bool,
    ) -> BoxFuture<'static, io::Result<Arc<dyn AsyncTcpStream>>>;

    /// The addresses of `host` with `port`, both families together (the system resolver asks
    /// for AAAA and A at once, RFC 8305 section 3).
    fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>>;

    /// The addresses of one family of `host`, when the runtime can ask for AAAA and A apart
    /// (RFC 8305 section 3: the engine starts on the first answer). `None`, the default: it
    /// cannot, and the driver uses [`resolve_host`](Self::resolve_host).
    fn resolve_family(
        &self,
        host: &str,
        port: u16,
        ipv6: bool,
    ) -> Option<BoxFuture<'static, Vec<SocketAddr>>> {
        let _ = (host, port, ipv6);
        None
    }

    /// The SRV or NAPTR records of `name` (RFC 5928, RFC 8489 section 8). The default answers
    /// none, and the engine then uses the host and the scheme's default port.
    fn resolve_records(&self, name: &str, kind: RecordKind) -> BoxFuture<'static, Vec<DnsRecord>> {
        let _ = (name, kind);
        Box::pin(std::future::ready(Vec::new()))
    }

    /// Runs `future` to completion on the calling thread. The future need not be `Send`.
    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>);

    /// Whether [`now`](Self::now) is a virtual clock (a mock's) rather than the wall clock.
    /// What is kept per process on the wall clock (the mDNS budget,
    /// [`process_mdns_rate_limit`](crate::peer::process_mdns_rate_limit)) is not shared with a
    /// driver on a virtual clock, whose times run elsewhere. `false` by default.
    fn virtual_clock(&self) -> bool {
        false
    }
}

/// A task spawned with [`Runtime::spawn`]. Dropping it detaches the task.
pub trait JoinHandle: Send + Debug {
    /// Cancels the task (it is dropped at its next await point, or before it starts).
    fn abort(&self);

    /// Whether the task has ended (finished or cancelled).
    fn is_finished(&self) -> bool;

    /// Ready once the task has ended.
    fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

impl<'a> dyn JoinHandle + 'a {
    /// Waits for the task to end.
    pub fn join(&mut self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| self.poll_join(cx))
    }
}

/// One datagram (or, with `segment_size`, several of one size back to back) to send.
#[derive(Debug, Clone, Copy)]
pub struct Transmit<'a> {
    /// Where to.
    pub destination: SocketAddr,
    /// The bytes.
    pub contents: &'a [u8],
    /// The byte for the IPv4 TOS / IPv6 Traffic Class field: the DSCP in the upper six bits
    /// (RFC 2474), the ECN codepoint in the lower two (RFC 3168). The engine gives one per
    /// datagram (`RTCPeerConnection::traffic_class`, RFC 8837).
    pub traffic_class: u8,
    /// `Some(n)`: `contents` is several datagrams of `n` bytes (the last may be shorter), for a
    /// socket that sends them in one call (GSO). The driver sends one datagram per transmit.
    pub segment_size: Option<usize>,
    /// The address the datagram is to leave from, for a socket bound to the unspecified
    /// address: the engine names one for each mDNS datagram (an answer leaves from the address
    /// of its record, on that address's interface, RFC 6762 section 14). `None`: the socket's
    /// own address, or the system's choice.
    pub source: Option<IpAddr>,
}

/// What [`AsyncUdpSocket::poll_recv`] says about one buffer it filled.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    /// The sender.
    pub addr: SocketAddr,
    /// How many bytes of the buffer were filled.
    pub len: usize,
    /// The size of each datagram in the buffer (`len` when it holds one; less when the socket
    /// coalesced several of one sender, GRO).
    pub stride: usize,
    /// The ECN codepoint the datagram arrived with, when the socket reports it.
    pub ecn: Option<u8>,
    /// The local address it was sent to, when the socket reports it.
    pub dst_ip: Option<IpAddr>,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }
    }
}

/// A UDP socket of a runtime, in the poll form of quinn-udp's so that batched send and receive
/// (`sendmmsg`, `recvmmsg`, GSO, GRO) fit.
pub trait AsyncUdpSocket: Send + Sync + Debug {
    /// Sends `transmit`, marked with its `traffic_class`. `Pending` when the socket cannot take
    /// it now (the driver then counts it lost, as UDP would).
    fn poll_send(&self, cx: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>>;

    /// Receives up to `bufs.len()` datagrams (at most [`max_receive_batch`](Self::max_receive_batch)),
    /// filling `meta` alongside; how many.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>>;

    /// The address it is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// How many buffers one [`poll_recv`](Self::poll_recv) can fill. 1 by default.
    fn max_receive_batch(&self) -> usize {
        1
    }

    /// The TOS / Traffic Class byte the operating system reports for the socket (`getsockopt`
    /// of `IP_TOS` / `IPV6_TCLASS`): what its next datagram carries.
    ///
    /// # Errors
    ///
    /// The option is not offered on this platform.
    fn traffic_class(&self) -> io::Result<u32>;

    /// Whether the platform refused to mark this socket: its datagrams leave with traffic
    /// class 0 whatever the transmit asks (see [`crate::sockets::set_traffic_class`]).
    fn unmarked(&self) -> bool {
        false
    }
}

/// A TCP connection of a runtime. `&self` methods: the driver's reader and writer tasks share
/// one `Arc`.
pub trait AsyncTcpStream: Send + Sync + Debug {
    /// Reads into `buf`; 0 at the peer's end of stream.
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>;

    /// Writes some of `buf`; how much.
    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;

    /// Ends the sending direction (FIN).
    ///
    /// # Errors
    ///
    /// The socket refused.
    fn shutdown_write(&self) -> io::Result<()>;

    /// Makes the close abortive (`SO_LINGER` 0): when the last reference is dropped the
    /// connection is reset (RST) instead of closed with FIN.
    ///
    /// # Errors
    ///
    /// The socket refused.
    fn reset_on_close(&self) -> io::Result<()>;

    /// Sets the socket's TOS / Traffic Class byte and returns what the operating system reports
    /// for it afterwards.
    ///
    /// # Errors
    ///
    /// The platform refused the option or does not offer it.
    fn set_traffic_class(&self, value: u8) -> io::Result<u32>;

    /// Its local address.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// The peer's address.
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

/// A TCP listener of a runtime.
pub trait AsyncTcpListener: Send + Sync + Debug {
    /// The next connection, with `TCP_NODELAY` set, and its peer's address.
    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Arc<dyn AsyncTcpStream>, SocketAddr)>>;

    /// The address it listens on.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl<'a> dyn AsyncTcpListener + 'a {
    /// Waits for the next connection.
    pub async fn accept(&self) -> io::Result<(Arc<dyn AsyncTcpStream>, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }
}

impl<'a> dyn AsyncTcpStream + 'a {
    /// Reads into `buf`; 0 at the peer's end of stream.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_read(cx, buf)).await
    }

    /// Writes all of `buf`.
    pub async fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = std::future::poll_fn(|cx| self.poll_write(cx, buf)).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}

impl<'a> dyn AsyncUdpSocket + 'a {
    /// Waits for one datagram: its length and sender.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut meta = [RecvMeta::default()];
            let mut bufs = [IoSliceMut::new(&mut *buf)];
            match self.poll_recv(cx, &mut bufs, &mut meta) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok((meta[0].len, meta[0].addr))),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    /// Sends one datagram, unmarked, waiting for room.
    pub async fn send_to(&self, buf: &[u8], destination: SocketAddr) -> io::Result<usize> {
        let transmit = Transmit {
            destination,
            contents: buf,
            traffic_class: 0,
            segment_size: None,
            source: None,
        };
        std::future::poll_fn(|cx| self.poll_send(cx, &transmit)).await
    }

    /// Sends `transmit` if the socket can take it now: how many bytes, or the system's error
    /// (`WouldBlock` when the socket cannot take it now).
    ///
    /// # Errors
    ///
    /// The send failed, or would block.
    pub fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<usize> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match self.poll_send(&mut cx, transmit) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// What a multicast socket is bound and joined to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastConfig {
    /// The group (224.0.0.251 or ff02::fb for mDNS).
    pub group: IpAddr,
    /// The port (5353 for mDNS).
    pub port: u16,
    /// The addresses of the interfaces to join the group on: one membership per interface
    /// that has one of them (the addresses of the group's family; an IPv6 address names its
    /// interface by index, [`interface_index`]). Empty: the system's default interface only.
    /// RFC 6762 section 14: a host on several links takes part in mDNS on each of them.
    pub interfaces: Vec<IpAddr>,
    /// TTL / hop limit of what it sends, multicast and unicast (255 for mDNS, RFC 6762
    /// section 11).
    pub hop_limit: u32,
    /// Shares the port with other processes (`SO_REUSEADDR`, and `SO_REUSEPORT` where the
    /// platform has it).
    pub reuse_address: bool,
}

impl MulticastConfig {
    /// mDNS on `group` (224.0.0.251 or ff02::fb): port 5353, joined on the interfaces of
    /// `interfaces` (the default interface when empty), hop limit 255, the port shared with
    /// the host's other responders.
    pub fn mdns(group: IpAddr, interfaces: Vec<IpAddr>) -> Self {
        Self {
            group,
            port: 5353,
            interfaces,
            hop_limit: 255,
            reuse_address: true,
        }
    }

    /// The addresses of [`interfaces`](Self::interfaces) of the group's family.
    pub fn interfaces_of_family(&self) -> impl Iterator<Item = IpAddr> + '_ {
        let v4 = self.group.is_ipv4();
        self.interfaces
            .iter()
            .copied()
            .filter(move |ip| ip.is_ipv4() == v4 && !ip.is_unspecified())
    }
}

/// The index of the interface that holds the IPv6 address `ip` (what `IPV6_MULTICAST_IF` and
/// an IPv6 group membership name an interface by), `None` when no interface of the host holds
/// it.
pub fn interface_index(ip: Ipv6Addr) -> Option<u32> {
    let interfaces = shared::ifaces::ifaces().ok()?;
    let entry = interfaces
        .iter()
        .find(|i| matches!(i.addr, Some(SocketAddr::V6(a)) if *a.ip() == ip))?;
    if let Some(SocketAddr::V6(a)) = entry.addr
        && a.scope_id() != 0
    {
        return Some(a.scope_id());
    }
    name_to_index(&entry.name)
}

#[cfg(unix)]
fn name_to_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(not(unix))]
fn name_to_index(_: &str) -> Option<u32> {
    None
}

/// The name of the interface that holds `ip`, `None` when no interface of the host holds it.
pub fn interface_name(ip: IpAddr) -> Option<String> {
    shared::ifaces::ifaces()
        .ok()?
        .into_iter()
        .find(|i| i.addr.is_some_and(|a| a.ip() == ip))
        .map(|i| i.name)
}

/// Applies a [`Transmit::source`] to a real multicast socket bound to the unspecified address:
/// before a datagram to a multicast group, it sets the interface the datagram leaves by
/// (`IP_MULTICAST_IF` to the source address, `IPV6_MULTICAST_IF` to the index of the interface
/// that holds it) when it differs from the last one set. The system then sends from that
/// interface's address: on Linux exactly the address given (`IP_MULTICAST_IF` with an address
/// sets the source), on macOS and Windows the interface's address, the same one where the
/// interface has one address of the family. For built-in and third-party runtimes whose sockets
/// have a file descriptor.
#[derive(Debug, Default)]
pub struct MulticastInterfaceSelector {
    last: std::sync::Mutex<Option<IpAddr>>,
}

impl MulticastInterfaceSelector {
    /// Sets the interface of `transmit` on `socket`. A transmit to a unicast destination, or
    /// without a source of the destination's family, changes nothing.
    ///
    /// # Errors
    ///
    /// The source is on no interface of the host, or the system refused the option: the
    /// datagram is not to be sent from another interface instead.
    pub fn apply(&self, socket: SockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        let destination = transmit.destination.ip();
        let Some(source) = transmit.source.filter(|source| {
            destination.is_multicast()
                && !source.is_unspecified()
                && source.is_ipv4() == destination.is_ipv4()
        }) else {
            return Ok(());
        };
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *last == Some(source) {
            return Ok(());
        }
        match source {
            IpAddr::V4(source) => socket.set_multicast_if_v4(&source)?,
            IpAddr::V6(source) => {
                let index = interface_index(source).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("no interface holds {source}"),
                    )
                })?;
                socket.set_multicast_if_v6(index)?;
            }
        }
        *last = Some(source);
        Ok(())
    }
}

/// Waits `duration` on `runtime`'s clock.
pub fn sleep(runtime: &dyn Runtime, duration: Duration) -> BoxFuture<'static, ()> {
    runtime.sleep_until(runtime.now() + duration)
}

/// [`timeout`] ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// `future`'s output, or [`Elapsed`] if `duration` of `runtime`'s clock passes first.
pub async fn timeout<T>(
    runtime: &dyn Runtime,
    duration: Duration,
    future: impl Future<Output = T>,
) -> Result<T, Elapsed> {
    timeout_at(runtime, runtime.now() + duration, future).await
}

/// `future`'s output, or [`Elapsed`] if `runtime`'s clock reaches `deadline` first.
pub async fn timeout_at<T>(
    runtime: &dyn Runtime,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, Elapsed> {
    let mut future = std::pin::pin!(future);
    let mut sleep = runtime.sleep_until(deadline);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = future.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        sleep.as_mut().poll(cx).map(|()| Err(Elapsed))
    })
    .await
}

/// Gives other tasks a turn: pending once, with the task woken at once.
pub async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

/// Applies a [`Transmit::traffic_class`] to a real socket: sets `IP_TOS` / `IPV6_TCLASS` when
/// the value differs from the last one set, and stops asking once the platform refused (its
/// datagrams then leave unmarked, [`AsyncUdpSocket::unmarked`]). For built-in and third-party
/// runtimes whose sockets have a file descriptor.
#[derive(Debug)]
pub struct TrafficClassMarker {
    /// The byte last set (a new socket's is 0), or [`Self::REFUSED`].
    state: AtomicU16,
}

impl Default for TrafficClassMarker {
    fn default() -> Self {
        Self {
            state: AtomicU16::new(0),
        }
    }
}

impl TrafficClassMarker {
    const REFUSED: u16 = 0x100;

    /// Marks `socket` (IPv6 when `ipv6`) with `value` before a datagram: what the datagram
    /// carries (0 once the platform refused).
    pub fn apply(&self, socket: SockRef<'_>, ipv6: bool, value: u8) -> u8 {
        let current = self.state.load(Ordering::Relaxed);
        if current == Self::REFUSED {
            return 0;
        }
        if current == u16::from(value) {
            return value;
        }
        match crate::sockets::set_traffic_class(socket, ipv6, value) {
            Ok(()) => {
                self.state.store(u16::from(value), Ordering::Relaxed);
                value
            }
            // The platform does not mark (RFC 8835 4.2: "appropriate to depart ... on platforms
            // where QoS marking is not implemented"): the socket is not asked again.
            Err(_) => {
                self.state.store(Self::REFUSED, Ordering::Relaxed);
                0
            }
        }
    }

    /// Whether the platform refused.
    pub fn refused(&self) -> bool {
        self.state.load(Ordering::Relaxed) == Self::REFUSED
    }
}

/// A non-blocking std UDP socket on `local`: what the built-in runtimes wrap.
///
/// # Errors
///
/// The bind failed.
pub fn std_udp(local: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(local)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// A non-blocking std UDP socket joined as `config` says: for IPv4 what rtci-mdns'
/// `MulticastSocket` builds (bound to the group on Linux, to 0.0.0.0 elsewhere), for IPv6
/// `[::]:port`, IPv6 only; a membership of the group on every interface of
/// [`MulticastConfig::interfaces`] (the default interface when there is none).
///
/// # Errors
///
/// The bind failed, or no membership could be joined (an interface that refuses one is
/// skipped while another joins).
pub fn std_multicast(config: &MulticastConfig) -> io::Result<std::net::UdpSocket> {
    let domain = match config.group {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if config.group.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if config.reuse_address {
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    let interfaces: Vec<IpAddr> = config.interfaces_of_family().collect();
    match config.group {
        IpAddr::V4(group) => {
            socket.set_multicast_ttl_v4(config.hop_limit)?;
            socket.set_ttl_v4(config.hop_limit)?;
            // The group itself does not bind on macOS and Windows; 0.0.0.0 does.
            let local = if cfg!(target_os = "linux") {
                group
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            socket.bind(&SocketAddr::new(local.into(), config.port).into())?;
            join_each(&interfaces, |interface| match interface {
                Some(IpAddr::V4(interface)) => {
                    if cfg!(windows) && interface.is_loopback() {
                        warn_loopback_join_on_windows(group);
                    }
                    socket.join_multicast_v4(&group, &interface)
                }
                _ => socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED),
            })?;
        }
        IpAddr::V6(group) => {
            socket.set_multicast_hops_v6(config.hop_limit)?;
            socket.set_unicast_hops_v6(config.hop_limit)?;
            socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), config.port).into())?;
            join_each(&interfaces, |interface| {
                let index = match interface {
                    Some(IpAddr::V6(ip)) => interface_index(ip).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!("no interface holds {ip}"),
                        )
                    })?,
                    _ => 0,
                };
                socket.join_multicast_v6(&group, index)
            })?;
        }
    }
    Ok(socket.into())
}

/// On Windows a socket joined on the loopback interface that sends to the group leaves the
/// group's destination-cache entry on loopback after the process has exited, and the system
/// then answers 127.0.0.1 for the group to every process that asks which address reaches it,
/// until the entry is deleted (`peer` module documentation). Said once per process.
fn warn_loopback_join_on_windows(group: Ipv4Addr) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        log::warn!(
            "joining {group} on the loopback interface: on Windows mDNS sent there leaves the \
             group's destination-cache route on loopback after this process, for other \
             processes too (netsh interface ipv4 delete destinationcache, as administrator)"
        );
    });
}

/// Joins once per interface (`None`: the default one, when there is no interface): an error
/// only when no membership was made. A second address of an interface already joined is
/// refused by the system (`EADDRINUSE`) and changes nothing.
fn join_each(
    interfaces: &[IpAddr],
    mut join: impl FnMut(Option<IpAddr>) -> io::Result<()>,
) -> io::Result<()> {
    if interfaces.is_empty() {
        return join(None);
    }
    let mut first_error = None;
    let mut joined = false;
    for interface in interfaces {
        match join(Some(*interface)) {
            Ok(()) => joined = true,
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => joined = true,
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match (joined, first_error) {
        (false, Some(e)) => Err(e),
        _ => Ok(()),
    }
}

fn tcp_socket(addr: SocketAddr, reuse_address: bool) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if reuse_address {
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// A non-blocking std TCP listener on `local`, backlog 128.
///
/// # Errors
///
/// The bind failed.
pub fn std_tcp_listener(
    local: SocketAddr,
    reuse_address: bool,
) -> io::Result<std::net::TcpListener> {
    let socket = tcp_socket(local, reuse_address)?;
    socket.bind(&local.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

/// A non-blocking TCP socket bound to `local`, for a runtime to connect to a peer.
///
/// # Errors
///
/// The bind failed.
pub fn std_tcp_bound(local: SocketAddr, reuse_address: bool) -> io::Result<Socket> {
    let socket = tcp_socket(local, reuse_address)?;
    socket.bind(&local.into())?;
    Ok(socket)
}

/// Starts a non-blocking TCP connection from `local` to `remote`: the socket is bound, and the
/// handshake runs. A runtime waits for it to become writable, then reads `take_error` and
/// `peer_addr` (what async-io's own `connect` does), for runtimes whose connect cannot bind a
/// local address first.
///
/// # Errors
///
/// The bind failed, or the connection failed at once.
pub fn std_tcp_connect_start(
    local: SocketAddr,
    remote: SocketAddr,
    reuse_address: bool,
) -> io::Result<std::net::TcpStream> {
    let socket = std_tcp_bound(local, reuse_address)?;
    match socket.connect(&remote.into()) {
        Ok(()) => {}
        Err(e) if connect_in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(socket.into())
}

/// Whether a non-blocking connect's error only says the handshake is under way.
fn connect_in_progress(e: &io::Error) -> bool {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    // Windows: WSAEWOULDBLOCK.
    e.kind() == io::ErrorKind::WouldBlock
}

/// Makes `socket`'s close abortive (`SO_LINGER` 0: RST instead of FIN), for
/// [`AsyncTcpStream::reset_on_close`].
///
/// # Errors
///
/// The socket refused.
pub fn reset_on_close(socket: SockRef<'_>) -> io::Result<()> {
    socket.set_linger(Some(Duration::ZERO))
}

/// Sets `socket`'s TOS / Traffic Class and reads it back (for [`AsyncTcpStream::set_traffic_class`]).
///
/// # Errors
///
/// The platform refused the option or does not offer it.
pub fn set_and_read_traffic_class(socket: SockRef<'_>, ipv6: bool, value: u8) -> io::Result<u32> {
    crate::sockets::set_traffic_class(SockRef::from(&*socket), ipv6, value)?;
    crate::sockets::traffic_class(socket, ipv6)
}

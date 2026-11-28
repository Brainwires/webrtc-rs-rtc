# `rtci`

<p align="center">
 <strong>Sans-I/O WebRTC implementation in Rust</strong>
</p>

<!-- rtci-lineage:start -->
**rtci** (an RTC implementation) descends from webrtc-rs [`rtc`](https://github.com/webrtc-rs/rtc) as of upstream commit `0fbcaa74` and is developed independently; [FORK.md](FORK.md) lists what it carries over upstream. Its crates were renamed from `rtc` / `rtc-*` to `rtci` / `rtci-*` at 0.1.0. Upstream's licence and copyright notices are retained.
<!-- rtci-lineage:end -->

- [Overview](#overview)
- [Status](#status)
- [Installation](#installation)
- [Sans-I/O Event Loop Pattern](#sans-io-event-loop-pattern)
- [Driving the Engine](#driving-the-engine)
- [Feeding ICE Candidates](#feeding-ice-candidates)
- [Back-Pressure](#back-pressure)
- [Features](#features)
- [Examples](#examples)
- [Crates](#crates)
- [Common Use Cases](#common-use-cases)
- [Specification Compliance](#specification-compliance)
- [Documentation](#documentation)
- [Building and Testing](#building-and-testing)
- [Semantic Versioning](#semantic-versioning)
- [Contributing](#contributing)
- [License](#license)

## Overview

`rtci` is a Rust implementation of [WebRTC](https://www.w3.org/TR/webrtc/) with a **sans-I/O architecture**: the
protocol logic is separate from all I/O, so the application controls networking, threading and the async runtime.

### What is Sans-I/O?

Sans-I/O (without I/O) is a design pattern where the library handles protocol logic but **you** control all I/O
operations. Instead of the library performing network reads and writes directly, you feed it network data and it tells
you what to send.

**Benefits:**

- **Runtime independent**: works with tokio, async-std, smol or blocking I/O
- **Control**: the application decides threading, scheduling and I/O multiplexing
- **Testable**: the protocol logic runs in tests without a network
- **Embeddable**: it fits into existing networking code

There is no ambient clock, either: every method that needs the time takes an `Instant` from you. That is what makes a
whole session reproducible in a test without a socket or a sleep.

## Status

As of 2026-11-26 the workspace is audited clause by clause against 113 specifications (the W3C WebRTC
API, statistics, extensions, encoded transform and SVC specifications, and the IETF RFCs and drafts
WebRTC uses); every row names the code and the test that proves it. From
[docs/conformance/audit/COUNTS.md](docs/conformance/audit/COUNTS.md), of the rows that bind this engine:

| Level | Rows that apply | RFC behaviour tested | Tested as the default |
| --- | ---: | ---: | ---: |
| MUST | 5098 | 5095 (99.9 %) | 5057 (99.2 %) |
| SHOULD | 988 | 925 (93.6 %) | 919 (93.0 %) |
| MAY | 605 | 503 (83.1 %) | 501 (82.8 %) |

"RFC behaviour tested" includes the clauses whose RFC behaviour is selected by a named setting because a
browser or a deployed peer cannot interoperate with it by default. 3 MUST rows are open (0 untested,
3 partial, 0 missing, none violated); each, with its class and reason, is in [docs/conformance/audit/OPEN-MUST.md](docs/conformance/audit/OPEN-MUST.md); what
is not implemented on purpose is in [docs/conformance.md](docs/conformance.md). Three defaults depart from a MUST by
the owner's decision, not for interoperability, and are listed in docs/conformance.md ("Standing departures from a
MUST"), each with the setting that gives the RFC form (the `StrictRfc` profile sets all three): the H.264
de-interleaving order (**this default does not follow RFC 6184 section 7.2**: PDON does not start at 0, which would
deliver a stream's DON 0 last; `MediaEngine::set_h264_literal_pdon(true)`), the formats of an answer (RFC 9429
section 5.3.1, whose "MUST be added after all existing formats" the next bullet's "MAY include formats that are
locally supported but not present in the offer" contradicts: answers list only the offered formats;
`SettingEngineBuilder::with_answer_offered_formats_only(false)`) and the RTP circuit breaker's packet size (RFC 8083
section 3; `DefaultInterceptorOptions::circuit_breaker_packet_size`, the `LastFrames` form). Known issues are tracked
in the repository's [issues](https://github.com/Brainwires/rtci/issues), security problems as
[SECURITY.md](SECURITY.md) describes.

## Installation

```toml
[dependencies]
rtci = "0.2"
```

The crates use Rust edition 2024; the minimum supported Rust version is 1.89 (`rust-version` in the manifests,
checked by CI's MSRV job).

### Crypto Providers

All cryptography goes through a pluggable [`RTCCryptoProvider`]. Two built-in providers ship with the crate and the
Cargo features are **additive**: enabling both builds, and `ring` is preferred when both are on:

```toml
# Default: the ring provider, no C toolchain required.
rtci = "0.2"

# aws-lc-rs instead (pulls in the aws-lc-sys C toolchain).
rtci = { version = "0.2", default-features = false, features = ["crypto-aws-lc-rs"] }
```

There is **no process-global provider to install**. The provider is selected per peer connection through
`SettingEngine::set_crypto_provider`, so two peer connections in one process may use different ones. Applications
needing OpenSSL, a FIPS-validated module, an HSM, or a platform backend can implement the public traits themselves and
validate the result against the bundled conformance suite (`rtci_crypto::conformance::assert_provider`, behind the
`test-support` feature). The other features: `pem` (PEM certificate import in DTLS), `turn-tls-webpki-roots` (the Mozilla
roots for TURN over TLS) and `openssl` / `vendored-openssl` (an OpenSSL AES-CTR cipher for SRTP).

[`RTCCryptoProvider`]: rtci-crypto/README.md

## Sans-I/O Event Loop Pattern

The event loop is the [`sansio::Protocol`] trait implemented by `RTCPeerConnection`: **bring the trait into scope with
`use rtci::sansio::Protocol;` or none of these methods will resolve.**

| Method | Direction | What it does |
| --- | --- | --- |
| `handle_read(TaggedBytesMut)` | in | Feed one received UDP/TCP datagram, tagged with its 5-tuple and arrival instant |
| `poll_write() -> Option<TaggedBytesMut>` | out | Take the next packet to put on the wire; drain until `None` |
| `poll_read() -> Option<TaggedRTCMessage>` | out | Take the next inbound RTP/RTCP/data-channel message for the application |
| `poll_event() -> Option<RTCPeerConnectionEvent>` | out | Take the next state change or notification |
| `poll_timeout() -> Option<Instant>` | out | Next deadline for retransmissions, keepalives and ICE checks |
| `handle_timeout(Instant)` | in | Tell the connection a deadline has passed |
| `handle_write(TaggedRTCMessage)` | in | Queue an outbound RTP/RTCP/data-channel message |
| `close()` | in | Shut the connection down |

After `close()` keep the loop running for the connection until `poll_timeout()` returns `None`:
drain `poll_write` onto the socket, feed what arrives with `handle_read`, call `handle_timeout`
at `poll_timeout`. A closed connection does nothing else, but the engine's TURN allocations over
UDP are deleted with a Refresh of LIFETIME 0 that is an ordinary STUN transaction (RFC 8656
section 8, RFC 8489 section 6.2.1): it is retransmitted, a 438 is answered with the new nonce,
and an Allocate still under way is followed and its allocation deleted. Each one done raises
`OnTurnAllocationReleased` with the local address it used; when `poll_timeout()` is `None` the
socket is free for another connection, whose Allocate on the same 5-tuple would otherwise be
refused with 437 while the old allocation lives (up to its lifetime, 10 minutes by default).
Dropping a connection without `close()` sends nothing.

TURN credentials that expire (a TURN REST API username, `<expiry>:<id>`) are rotated on a live
connection with `rotate_ice_servers(now, servers)` and one offer / answer round: the peer sees an
ICE restart (same connection, new ice-ufrag, same DTLS fingerprint). For no gap, bind a second
UDP socket and add its host candidate after `create_offer` and before `set_local_description`
of the restart offer: the new allocation is made from it, the old one relays until the new pair
carries the data and is then deleted, and `OnTurnAllocationReleased` names the old socket, which
the application may then close. With one socket the old allocation is released first
(`OnTurnAllocationReplacedInPlace`). After the restart, re-send your host candidates to the peer
(a candidate kept across the restart is not announced again).

**Re-allocating on the same socket after a release.** A TURN allocation is its 5-tuple's (RFC
8656 section 2.2), and an Allocate on a 5-tuple that still has one is refused with 437 (section
7.2). On a 437 the client "SHOULD pick another client transport address", tries three, and then
"SHOULD NOT try to create another allocation on the server for 2 minutes" (section 7.4), so no
client retries on the refused 5-tuple. RFC 8656 section 8.2 has the server delete an allocation
as soon as it answers the Refresh of LIFETIME 0; coturn does not: it answers, keeps the
allocation for one more second (`refresh_relay_connection` floors the lifetime at 1 s) and
answers an Allocate on that 5-tuple meanwhile with 437. Observed live (a consumer, 2026-11-27,
production coturn): on two back-to-back restarts an Allocate about 140 ms after a confirmed
release got 437 and one 3.0 s later succeeded, both times.
- *Engine-run TURN* (`RelayGathering::Engine`, the default): within one peer connection (an ICE
  restart with new TURN credentials and one UDP socket) the engine allocates again on a released
  5-tuple only once the server has answered the release, and
  `SettingEngineBuilder::with_turn_reallocation_delay` makes it wait longer after that answer
  (2 s covers coturn; the default, zero, is RFC 8656's). On a 437 it raises
  `OnTurnRequestRejected { method: "Allocate", error_code: 437, .. }`, moves the Allocate to
  another UDP host candidate's base of the transport if there is one (up to three), and
  otherwise leaves that server alone for two minutes: that ICE generation has no relayed
  candidate from it, and an ICE restart after the two minutes allocates again. A *new* peer
  connection on the socket of one that was closed does not know of the old one's release:
  after `OnTurnAllocationReleased` wait for the server's hold (2 s for coturn) before it
  gathers, or give it another UDP socket (a second host candidate) as well.
- *Application-run TURN* (`RelayGathering::Application`, your own `rtci::turn::client::Client`):
  the same rules are yours. Delete with `Relay::close` and wait for
  `Event::AllocationReleased`, then for the server's hold, before an `allocate` from the same
  local address to the same server; on an `AllocateError` with code 437, allocate from another
  socket, or leave the server for two minutes.

`handle_event` is also part of the trait, but `RTCEvent` is currently uninhabited: no value of it can be constructed,
so there is nothing to call it with. It exists so the signature is already right when the first inbound event variant
is added.

Order matters only in that `poll_write` should be drained after anything that could have produced output:
`handle_read`, `handle_timeout`, `handle_write`, and the negotiation calls all queue packets rather than sending them.

[`sansio::Protocol`]: https://docs.rs/sansio/latest/sansio/trait.Protocol.html

### Event Loop Example

```rust,no_run
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::RTCIceServer;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::sansio::Protocol;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use bytes::BytesMut;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build the peer connection. `build` takes the instant the session starts.
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_string()],
                    ..Default::default()
                }])
                .build(),
        )
        .build(Instant::now())?;

    // 2. Signaling: every description call also takes the current instant.
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer.clone())?;
    // send `offer.sdp` over your signaling channel, then:
    //   let answer = RTCSessionDescription::answer(answer_sdp)?;
    //   pc.set_remote_description(Instant::now(), answer)?;

    // 3. You own the socket. Bind a concrete local address, the one you add as a host
    //    candidate ("Feeding ICE Candidates"): `local_addr` below must be a local candidate's
    //    address, and a socket bound to 0.0.0.0 reports 0.0.0.0:port, which none is.
    let socket = UdpSocket::bind("192.168.1.100:0").await?;
    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; 2000];
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86400);

    loop {
        // Drain everything the connection wants to send.
        while let Some(msg) = pc.poll_write() {
            socket.send_to(&msg.message, msg.transport.peer_addr).await?;
        }

        // Drain state changes and notifications.
        while let Some(event) = pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("connection state: {state}");
                    if state == RTCPeerConnectionState::Failed {
                        return Ok(());
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!("new track: {}", init.track_id);
                }
                // RTCPeerConnectionEvent is #[non_exhaustive].
                _ => {}
            }
        }

        // Drain inbound application messages. `poll_read` yields a *tagged* message:
        // `now` is when the packet was observed at the socket, not when you drained it.
        while let Some(TaggedRTCMessage { now, message }) = pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, _packet) => {
                    println!("RTP on track {track_id} at {now:?}");
                }
                RTCMessage::RtcpPacket(receiver_id, _packets) => {
                    println!("RTCP for receiver {receiver_id:?}");
                }
                RTCMessage::DataChannelMessage(channel_id, _msg) => {
                    println!("data-channel message on {channel_id:?}");
                }
                // RTCMessage is #[non_exhaustive].
                _ => {}
            }
        }

        // Wait for whichever comes first: a packet or the next protocol deadline.
        let timeout = pc.poll_timeout().unwrap_or(Instant::now() + DEFAULT_TIMEOUT);
        let delay = timeout.saturating_duration_since(Instant::now());
        if delay.is_zero() {
            pc.handle_timeout(Instant::now())?;
            continue;
        }

        tokio::select! {
            biased;

            _ = tokio::time::sleep(delay) => {
                pc.handle_timeout(Instant::now())?;
            }
            Ok((n, peer_addr)) = socket.recv_from(&mut buf) => {
                pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&buf[..n]),
                })?;
            }
        }
    }
}
```

## Driving the Engine

An application author writes one loop around the connection. It has two halves; the second is
needed only when the engine is to run TCP (ICE-TCP candidates, TURN over TCP or TLS) itself.

**Datagrams** (the loop above): every UDP datagram read goes to `handle_read`, everything from
`poll_write` goes out, deadlines go through `poll_timeout` / `handle_timeout`. A datagram
tagged `TransportProtocol::TCP` there is one the application framed itself, for a TCP candidate
it added on its own.

**The local address of a datagram.** The `local_addr` of a datagram given to `handle_read` is
the address of the local *candidate* it arrived on, not necessarily the socket's own address:
the ICE agent matches it exactly against its local candidates (RFC 8445 section 7.3.1.4) and
discards anything else with "Discarded message, not a valid local candidate". Two cases trip
ported code:

- **A socket bound to the unspecified address** (`0.0.0.0:port`, `[::]:port`) must report the
  concrete local address each datagram was received on (its destination address, from
  `IP_PKTINFO` / `IPV6_RECVPKTINFO` or the platform's equivalent), which is the host
  candidate's address; `socket.local_addr()` matches no host candidate. Or bind one socket per
  local address, as `rtci-stream-driver`'s `PeerDriver` does (`PeerDriverConfig::addresses`).
  A datagram that only "works" on `0.0.0.0:port` does so by accident: a server-reflexive
  candidate whose related address is `0.0.0.0:port` matches it.
- **A datagram relayed by a TURN allocation the application runs**
  (`with_relay_gathering(RelayGathering::Application)`, relay candidate added with
  `add_local_candidate`) carries `local_addr` = the relayed address (the relay candidate's
  address), `peer_addr` = the peer from the Data indication or the channel. In the other
  direction, a datagram from `poll_write` whose `transport.local_addr` is the relayed address
  goes through the allocation (Send indication or ChannelData to `transport.peer_addr`), not
  out of a socket. This is what the engine does for the allocations it runs itself.

```text
// wildcard-bound socket: the destination address of the datagram, not 0.0.0.0:port
let local_addr = SocketAddr::new(destination_ip /* IP_PKTINFO */, socket.local_addr()?.port());
// relayed by the application's TURN client
pc.handle_read(TaggedBytesMut { now, message: payload, transport: TransportContext {
    local_addr: relayed_addr, peer_addr: peer, transport_protocol: TransportProtocol::UDP, ecn: None } })?;
// and out
while let Some(msg) = pc.poll_write() {
    if msg.transport.local_addr == relayed_addr { turn.send_to(&msg.message, msg.transport.peer_addr)?; }
    else { socket_of(msg.transport.local_addr).send_to(&msg.message, msg.transport.peer_addr)?; }
}
```

**Streams** (`rtci::shared::stream`): the engine names its TCP connections and listeners by id
and the application only owns the sockets. After each input:

```text
while let Some(command) = pc.poll_stream_command()  { /* Listen, Connect, Close, Reset, Resolve */ }
while let Some(transmit) = pc.poll_stream_transmit() { /* write transmit.data on transmit.id */ }
// what the sockets did:
pc.handle_stream_event(now, event)?;   // Listening, Connected, Written, Closed, Reset, Resolved, ...
pc.handle_stream_accepted(now, listener, local, remote)   // Some(id), or None: close the socket
pc.handle_stream_read(now, id, &bytes)?;                  // any piece size; the engine reassembles
```

Once the application serves this interface, the engine gathers a passive, a simultaneous-open
and an active TCP candidate for each UDP host address it is given (RFC 6544; per transport when
sections are not bundled), frames with RFC 4571, connects to `turn:...?transport=tcp` and
`turns:` servers (names resolved through `StreamCommand::Resolve`, Happy Eyeballs across the
addresses) and closes the connections ICE no longer needs. For each TCP / TLS server it also makes a TCP allocation
(RFC 6062): a passive and an active relayed TCP candidate, each peer's connection on a data
connection to the server (`with_turn_tcp_relay(false)` turns this off). Once ICE has completed
it closes the TURN connections whose relayed candidate is not selected, and reconnects and
restarts ICE when the selected one's is lost (RFC 6544 section 11.2). A `turns:...?transport=udp` server is reached over DTLS
(RFC 7350) from a UDP host candidate's base without the stream interface: its records go out
through `poll_write` and come back through `handle_read` like any datagram (a name still needs
`Resolve`). A plain `turn:` server over UDP is allocated on the same way, from each transport's
UDP host candidate's base: an unauthenticated Allocate to each of the server's addresses (RFC
8656 section 3.9), the first answered kept; the engine takes out of `handle_read` only the
answers to its own transactions and the Data indications and ChannelData of its own
allocations. An application that runs its own TURN client sets
`with_relay_gathering(RelayGathering::Application)`; one that adds a relayed candidate for a
server (its `url`) has that server left to it. With `stun:` / `stuns:` servers
configured it also gathers the server-reflexive candidates: a Binding request from each UDP host
candidate (out of `poll_write`, the answer taken out of `handle_read`; this needs no stream
interface for a server given by address) and over TCP / TLS from its ICE-TCP listeners
(`ReflexiveGathering::Application` leaves it to the application). A driver may answer a
`Resolve` per family (`StreamEvent::ResolvedFamily`, AAAA and A as each arrives) so the race
starts on the first answer (RFC 8305 section 3), or once with `StreamEvent::Resolved`. For a
server URI without a port the engine first asks for its NAPTR and SRV records
(`StreamCommand::ResolveRecords`, answered with `StreamEvent::ResolvedRecords`; RFC 5928, RFC
8489 section 8); a driver that cannot look records up answers with none. `StreamEvent::Written` is the
back-pressure signal: the engine holds a window of unacknowledged bytes per connection.
`SettingEngineBuilder::with_tcp_candidate_gathering(false)` keeps the engine's TCP off; an
application that never polls the stream interface gets no TCP candidate and nothing changes.
Poll it before adding the end of candidates: the end of gathering waits for the listeners only
of an application that has served the interface; one that ends its candidates first gets no TCP
candidate (none may follow the end of candidates, RFC 8838 section 13), a warning in the log,
and a `StopListening` after each `Listen` once it does poll.

**What is engine and what is driver.** The engine (`rtci`) decides and runs every protocol:
which TCP candidates exist, which connections to open and when to close them, RFC 4571 and
TURN framing, TLS and DTLS to TURN servers, the TURN client (UDP and TCP allocations), STUN
Binding requests, the Happy Eyeballs race, NAPTR / SRV resolution order, ICE, DTLS, SCTP and
SRTP. It names listeners and connections by id and never touches a socket or a clock. The
driver owns the sockets and nothing else: it binds, connects, accepts, reads, writes, closes
and resolves names when the engine says so, and reports what happened. The application owns
its UDP sockets, signalling and the loop.

**The reference driver** (crate `rtci-stream-driver`, in `examples/stream-driver`, published beside the
engine) implements the stream half on tokio; its crate documentation has the command table and the
loop. `cargo run --example stream-driver-loopback` runs two peer connections over loopback TCP
through it with a data channel, the smallest complete program (the test environment runs it).
The driver also has the socket choices a server makes:

| Need | Where |
| --- | --- |
| Ports from a range (firewall rules) | `DriverConfig::tcp_port_range`, `sockets::bind_udp_in_range` / `bind_tcp_listener_in_range` with `PortRange::new(min, max)` |
| One UDP port for many peer connections | `sockets::UfragMux`: register every `pc.ice_username_fragments()` entry after each local description; `route(from, datagram)` picks the connection |
| One passive ICE-TCP port for many peer connections | `DriverConfig::shared_passive`, `sockets::accept_by_ufrag`, then `StreamDriver::adopt_shared` on the connection the first check names |
| Which local addresses get candidates | `sockets::AddressFilter` (`bind_addresses`, `include_loopback`, `include_link_local`, `interface_filter`, `ip_filter`) and `local_addresses()` |
| mDNS on loopback on Windows (off by default: it leaves the group's route on loopback for the whole host) | `PeerDriverConfig::mdns_on_loopback_on_windows` |
| SRV / NAPTR lookups and per-family answers | feature `dns-records` (hickory-resolver) |
| A server behind a 1:1 NAT | `SettingEngineBuilder::with_nat_1to1_ips(vec![external_ip], RTCIceCandidateType::Host)` (or `Srflx` to add a server-reflexive candidate beside each host one); it applies to the engine's TCP candidates too |

Inside one peer connection the engine routes between its transports the same way a shared port
routes between connections: by the ufrag the first Binding request names (RFC 8445 section
7.2.2), so a shared port also works when sections are not bundled.

## Feeding ICE Candidates

Because RTC does no I/O, it also does no candidate gathering: **you** bind the sockets, so **you** tell the connection
which local candidates exist. Build them with the `rtci-ice` candidate constructors and hand each one to
`add_local_candidate`. A host candidate's address is a concrete local address, and it is the `local_addr` of every
datagram you then feed for it (see "The local address of a datagram" above: not `0.0.0.0:port` for a wildcard-bound
socket; the relayed address for a datagram relayed by your own TURN client):

```rust,no_run
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use std::time::Instant;

fn gather(pc: &mut rtci::peer_connection::RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.100".to_string(),
            port: 8080,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    // An EMPTY candidate string is the end-of-gathering sentinel: it moves the ICE gathering
    // state to `Complete` and emits `OnIceGatheringStateChangeEvent(Complete)`. Nothing else
    // reaches that state, so send it once you have added every local candidate.
    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    Ok(())
}
```

Remote candidates arrive over your signaling channel and go in through `add_remote_candidate`, which requires a remote
description to have been set first. For `srflx` and `relay` candidates, set `RTCIceCandidateInit::url` to the
STUN/TURN server the candidate was gathered from so it is attributed correctly in `getStats`.

After an ICE restart, send your local candidates to the peer again: a candidate the engine kept across the restart is
not announced again, and without them a peer reached only through a relay never selects a pair in the new generation.
(The restarted generation keeps its local candidates by default;
`SettingEngineBuilder::with_discard_local_candidates_during_ice_restart(true)` drops them instead.)

Browsers often send their host candidates under `<uuid>.local` names
(draft-ietf-mmusic-mdns-ice-candidates). By default (`MulticastDnsMode::QueryOnly`) the connection resolves such a
name with an mDNS query, which leaves through `poll_write` to `224.0.0.251:5353`, as the draft's processing procedure
says (section 3.2.1, step 3). A name that does not resolve, the usual case when the peer is not on your link, is
ignored when its query ends (10 s by default, `SettingEngineBuilder::with_multicast_dns_timeout`) and logged at debug
level only; the peer's checks can still reach you as a peer-reflexive candidate. To send no mDNS at all and ignore
remote `.local` candidates at once, set `SettingEngineBuilder::with_multicast_dns_mode(MulticastDnsMode::Disabled)`.

## Back-Pressure

`poll_read` is the throttle. Undrained data-channel messages leave bytes in SCTP's reassembly queue, which lowers the
receiver-window credit advertised in every SACK, which tells the peer to slow down. **Declining to call `poll_read` is
how you apply back-pressure**; resume when the application catches up. Media is never throttled this way: RTP arrives
over SRTP and is subject to none of SCTP's flow control.

## Porting from webrtc-rs `rtc` / older forks

Behaviour that differs from webrtc-rs `rtc` (and from this fork before the `rtci` names) and
that ported code trips over first:

- **`add_remote_candidate` needs `sdp_mid` or `sdp_mline_index`.** A non-empty candidate with
  neither is refused with `Error::TypeError` (W3C webrtc-pc `addIceCandidate`). If your
  signalling carries bare `candidate:` lines, set `sdp_mline_index` (under BUNDLE the index of
  the group's tagged m= section, usually 0: the transport's candidates name it) or `sdp_mid`.
- **The bare builder has no congestion control.** `RTCPeerConnectionBuilder::new()` without
  `with_interceptor_registry` runs the RTCP session and key-frame requests only: no NACK, no
  transport-wide feedback, no GCC, no pacer, no circuit breaker. Build the registry with
  `register_default_interceptors_with_handles` (or `register_default_interceptors_with_options`)
  and keep its `DefaultInterceptorHandles`: the encoder's target is
  `handles.congestion_control.target_bitrate()`, per encoding `RTCRtpSender::target_bitrates()`.
  `GccInterceptorBuilder` / `GccHandle` are for a chain assembled by hand.
- **The target before feedback is a seed.** Until the first congestion feedback,
  `CongestionControlHandle::target_bitrate()` returns the estimator's start (300 kbit/s by
  default), never zero, and `stats().delay_based_bitrate` / `loss_based_bitrate` are already
  `Some`; `stats().packet_loss` is `None` until feedback was folded in.
- **Data channel messages to browsers are capped at 16 KiB under the `Rfc` profile.** Toward
  a peer that does not announce interleaving (I-DATA, RFC 8260; no browser does) `send` of a
  larger message returns `Error::ErrMessageTooLargeWithoutInterleaving` (RFC 8831 section 6.6,
  a SHOULD). `with_sctp_message_size_limit_without_interleaving(false)` lifts it; see "Read
  this first" in FORK.md.
- **After `close()`, keep draining `poll_write`.** `close()` queues the last datagrams (DTLS
  `close_notify`, a TURN Refresh of lifetime 0 that releases the allocation); call
  `poll_write` until it returns `None` and send them. Dropping the connection sends nothing.
- **The engine gathers server-reflexive and relay candidates itself by default.**
  `ReflexiveGathering::Engine` and `RelayGathering::Engine` are the defaults: with `stun:` /
  `turn:` servers configured the engine sends the Binding and Allocate requests through
  `poll_write` from the UDP host candidates you add. Code that ran its own STUN / TURN
  client sets `SettingEngineBuilder::with_server_reflexive_gathering(ReflexiveGathering::
  Application)` and `with_relay_gathering(RelayGathering::Application)`, or the engine
  gathers too.
- **Two ways to restart ICE.** `RTCOfferOptions { ice_restart: true, .. }` restarts ICE in the
  one offer `create_offer` is called with; `restart_ice()` (W3C `restartIce`) marks the
  restart until an offer carries it and fires negotiation-needed. Both stage the same restart.

## Features

- **ICE** (Interactive Connectivity Establishment) - NAT traversal with STUN/TURN, plus mDNS candidates
- **DTLS** (Datagram Transport Layer Security) - Encryption for media and data
- **SCTP** (Stream Control Transmission Protocol) - Reliable data channels
- **RTP/RTCP** - Real-time media transport and control
- **SDP** (Session Description Protocol) - Offer/answer negotiation, Unified Plan
- **Data Channels** - Bidirectional peer-to-peer data transfer, in-band (DCEP) and out-of-band
- **Media Tracks** - Audio/video RTP transport (encoding, decoding, capture and playout are the application's)
- **Video pipeline** (`rtci-video`, in development, not published) - the receive side beside the engine: frame
  assembly for VP8, VP9, AV1, H.264 and H.265, the frame reference finder, a jitter buffer with libwebrtc's playout
  timing, key-frame requests (PLI) and the W3C video statistics; decoders behind a trait. See
  [docs/video-pipeline.md](docs/video-pipeline.md)
- **Trickle ICE** - Progressive candidate gathering, and ICE restart
- **ICE over TCP** - Active, passive and simultaneous-open, built into the engine (it gathers the TCP candidates,
  opens, frames, reuses and closes the connections; the application's driver owns the sockets only)
- **Stream transports without sockets** - `rtci_shared::stream`: connection ids, listen / connect / close / reset
  commands for the driver, RFC 4571 and TURN framing of arbitrarily segmented reads, an optional TLS layer and
  back-pressure; `examples/stream-driver` is a tokio driver for it
- **TURN over TCP and TLS built in** - the engine runs `turn:?transport=tcp` and `turns:` servers through its stream
  interface: resolution by the driver, Happy Eyeballs (RFC 8305), TLS with rustls sans-I/O (ALPN `stun.turn`; roots or a
  verifier from the application, Mozilla roots with feature `turn-tls-webpki-roots`), relayed candidates with
  `relayProtocol`; TURN over DTLS (RFC 7350) and over plain UDP on the application's socket as well (who gathers
  from `turn:` servers over UDP: `with_relay_gathering`)
- **NAT-assisted candidates in the reference driver** - `rtci_stream_driver::nat_mapping` (opt-in, no dependency): a
  PCP (RFC 6887) MAP request with a NAT-PMP (RFC 6886) fallback to the gateway the application names; the mapping is
  added as a server-reflexive candidate with type preference 105 (RFC 6544 section 5.3)
- **Server-side sockets in the reference driver** - `rtci_stream_driver::sockets`: port ranges for UDP sockets and
  ICE-TCP listeners, the local address list (bind addresses, interface and IP filters, loopback and link-local opt-in),
  one UDP port and one passive ICE-TCP port shared by many peer connections (routed by the ICE ufrag of the first
  check, `UfragMux`, `accept_by_ufrag`, `RTCPeerConnection::ice_username_fragment`); 1:1 NAT addresses
  (`with_nat_1to1_ips`) apply to every host candidate, the engine's TCP ones included
- **Simulcast** - RID-based simulcast, sending and receiving
- **SVC signalling in `rtci-rtp`** - the W3C scalability modes and their layer structures, VP8 / VP9 layer descriptors, the AV1 Dependency Descriptor, and forwarder-side layer selectors (`scalabilityMode` on an encoding, `RTCRtpSender::set_configured_scalability_mode`)
- **RTX & FEC** - RFC 4588 retransmission; FlexFEC through opt-in interceptors, both as browsers send it
  (draft-ietf-payload-flexible-fec-scheme-03, `video/flexfec-03`) and as published (RFC 8627, `video/flexfec`: masks,
  row / column / 2-D protection, retransmission); ULPFEC (RFC 5109) in RED, as browsers send it for video, through
  `configure_ulpfec` (opt-in, not in the default codecs)
- **Statistics** - `getStats` per the W3C WebRTC Statistics API, for what a transport measures (members that need an
  encoder, decoder or playout are left out, not reported as 0)
- **Interceptors** - Composable RTP/RTCP pipeline: the RTCP session (reports, CNAME, BYE, RFC 3550 / RFC 4585 timing, compound packets), NACK, TWCC and RFC 8888 feedback,
  bandwidth estimation (GCC) with a pacer, the RTP circuit breaker and key-frame requests by default; the jitter buffer, FlexFEC and ULPFEC are opt-in.
  The encoder's target: `register_default_interceptors_with_handles` (`DefaultInterceptorHandles::congestion_control`) or `RTCRtpSender::target_bitrates`
- **Pluggable crypto** - `ring` or `aws-lc-rs` built in, or bring your own provider

Each claim above, with its specification section, where it is implemented and the test that proves it, is in
[docs/conformance.md](docs/conformance.md), which also lists what is not implemented on purpose (media coding, DTLS 1.3 resumption and 0-RTT,
I-DATA, a TURN server and others).

## Behaviour profiles

The defaults follow the RFCs, MUST and SHOULD alike, except where a named browser or deployed peer cannot
interoperate with the RFC form, and the standing departures listed in [docs/conformance.md](docs/conformance.md)
(for example, the H.264 de-interleaving default does not follow RFC 6184 section 7.2). Every place where the engine and an RFC, or the engine and libwebrtc (Chrome), choose
differently is a setting, and a `BehaviourProfile` sets all of them in one call:

```rust,no_run
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Chosen at run time, here by name ("rfc", "chrome", "strict-rfc", "performance"), or
    // written as BehaviourProfile::Chrome.
    let profile = BehaviourProfile::from_name("chrome").unwrap_or_default();
    let setting_engine = SettingEngineBuilder::new()
        .with_behaviour_profile(profile)
        // A setting given after the profile overrides it.
        .with_sctp_message_size_limit_without_interleaving(true)
        .build();
    let mut media_engine = MediaEngine::for_profile(profile);
    media_engine.register_default_codecs()?;
    // The interceptors take the media engine's profile.
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let _ = (setting_engine, registry);
    Ok(())
}
```

- `Rfc`: the engine's defaults, unchanged: the RFC form, and the interoperable one only where a named browser or
  deployed peer cannot take the RFC's.
- `Chrome`: libwebrtc's choice wherever both do a thing and choose differently (a timer, an order, a form on the wire,
  a lenient or strict acceptance rule). Capabilities the engine has and Chrome lacks stay on (SCTP interleaving,
  RFC 8888 feedback, FlexFEC, ...), so its offers are a superset of Chrome's.
- `StrictRfc`: the RFC form even where the default is the interoperable one or a standing departure; for conformance
  testing, it **does not interoperate with browsers**.
- `Performance`: the defaults, with each behaviour where an RFC permits a cheaper form that does the same thing set to
  it (RTCP `T_rr_interval` 1 s, congestion control feedback and reports inside RFC 3550's 5%), each value with its
  measured saving and cost. It never turns a capability off or leaves what the RFCs permit.

**Known limit of the default profile: bundle-only sections and browsers.** An initial offer's bundle-only m= sections
are written in the RFC 9143 / RFC 9429 form (RFC 9143 7.1.3 and 9.3.1.1, RFC 9429 5.2.1: no `a=rtcp-mux`, no ICE
credentials, no other BUNDLE attribute), which
Chromium, WebKit and Firefox refuse. With the default profile no browser accepts an rtci offer under `max-bundle` with
more than one m= section (nor, by the same rule, a `balanced` offer with two sections of one media type). Use the
`Chrome` profile, or
`SettingEngineBuilder::with_bundle_only_sections_in_browser_form(true)` alone, or `balanced`
with one section of each type. Offers from browsers and answers are not affected.

**Answers list the offered formats only (since 0.3.0).** Without codec preferences, an answer lists the offered
formats this endpoint supports, in the offer's order, as every browser answers (RFC 9429 5.3.1: the answer "MAY include
formats that are locally supported but not present in the offer"). Up to 0.2.x it also listed every other media format
registered for the kind after them, the literal reading of the bullet before ("MUST be added after all existing
formats"), and received on them; `SettingEngineBuilder::with_answer_offered_formats_only(false)`, or the `StrictRfc`
profile, still answers that way. The two bullets of RFC 9429 5.3.1 contradict each other; the choice and its reasons
are a standing departure in [docs/conformance.md](docs/conformance.md).

**At run time**, `SettingEngineBuilder::with_behaviour_profile`, `MediaEngine::for_profile` and
`DefaultInterceptorOptions::for_profile` select a profile for one peer connection; `BehaviourProfile::from_name` reads
one from configuration. **At build time**, two cargo features of `rtci` change `BehaviourProfile::default()`, and with it
every `Default` / `new()` of those objects: `chrome-defaults` makes it `Chrome`, `performance-defaults` makes it
`Performance`. With both on, `chrome-defaults` wins and the build prints a deprecation warning naming both.
**Cargo unifies features: one crate of a build that turns a feature on changes the defaults of every user of `rtci` in
that build.** Prefer the explicit call; `BehaviourProfile::compiled_default()` says which default a build has.

[docs/behaviour-profiles.md](docs/behaviour-profiles.md), generated from the table in the code and checked by CI, lists
every governed behaviour: the setting, the clause, its value in each profile and the source of each Chrome value
(observed in the recorded Chromium descriptions and the browser matrix, or read in libwebrtc's source at a pinned
revision, with the file and line); the settings no profile changes, with the reason; and what Chrome does that the
engine cannot express.

## Examples

The repository has examples for the common cases (they are not part of the published crate):

- [data-channels-offer-answer](examples/data-channels-offer-answer/) -
  Complete data channel setup with signaling
- [data-channels-flow-control](examples/data-channels-flow-control/) -
  Applying back-pressure to a fast sender
- [trickle-ice](examples/trickle-ice/) - Progressive candidate exchange
- [ice-restart](examples/ice-restart/) - Recovering a connection after a
  network change
- [perfect-negotiation](examples/perfect-negotiation/) - Glare-free
  renegotiation with rollback
- [reflect](examples/reflect/) - Echo server that reflects media back to
  the sender
- [save-to-disk-vpx](examples/save-to-disk-vpx/) - Receive and save VP8/VP9
  video
- [play-from-disk-vpx](examples/play-from-disk-vpx/) - Send VP8/VP9 video
  from disk
- [simulcast](examples/simulcast) - Receive 3 simulcast encodings in one
  track
- [broadcast](examples/broadcast) - Broadcast a video to multiple peers
- [stats](examples/stats) - Statistical information about a
  PeerConnection

Run one with its registered example name:

```bash
cargo run --example data-channels-offer
cargo run --example data-channels-answer
```

## Crates

The engine is the root crate, `rtci`; each protocol is a crate of its own, usable alone and re-exported by
`rtci` (`rtci::ice`, `rtci::dtls`, ...). Each crate's README lists the specifications it implements.

| Crate | What it is |
| --- | --- |
| `rtci` | The peer connection: JSEP negotiation, transports, media and data channels, statistics |
| [`rtci-crypto`](rtci-crypto/README.md) | The provider-neutral cryptography interface, with the ring and aws-lc-rs providers |
| [`rtci-shared`](rtci-shared/README.md) | Marshalling traits, transport context, replay detection, the stream transport interface |
| [`rtci-ice`](rtci-ice/README.md) | The ICE agent (RFC 8445), trickle ICE, ICE-TCP, consent freshness |
| [`rtci-stun`](rtci-stun/README.md) | STUN messages, integrity and a client (RFC 8489) |
| [`rtci-turn`](rtci-turn/README.md) | The TURN client (RFC 8656, RFC 6062) |
| [`rtci-mdns`](rtci-mdns/README.md) | mDNS querier and responder (RFC 6762) |
| [`rtci-dtls`](rtci-dtls/README.md) | DTLS 1.2 and 1.3, DTLS-SRTP key export |
| [`rtci-srtp`](rtci-srtp/README.md) | SRTP and SRTCP, AES-GCM, Cryptex |
| [`rtci-sctp`](rtci-sctp/README.md) | SCTP (RFC 9260) for data channels |
| [`rtci-datachannel`](rtci-datachannel/README.md) | Data channels and DCEP (RFC 8831, RFC 8832) |
| [`rtci-rtp`](rtci-rtp/README.md) | RTP, header extensions, payload formats, SVC structures |
| [`rtci-rtcp`](rtci-rtcp/README.md) | RTCP packets and feedback messages |
| [`rtci-interceptor`](rtci-interceptor/README.md) | The RTP / RTCP pipeline: RTCP session, NACK, TWCC, GCC, pacing, FEC |
| [`rtci-interceptor-derive`](rtci-interceptor-derive/README.md) | Macros for writing interceptors |
| [`rtci-sdp`](rtci-sdp/README.md) | SDP parsing and serialization |
| [`rtci-media`](rtci-media/README.md) | Media samples and container readers and writers |
| [`rtci-sframe`](rtci-sframe/README.md) | SFrame end-to-end media encryption (RFC 9605) |
| [`rtci-stream-driver`](examples/stream-driver/README.md) | The tokio driver for the engine's stream transports (it does I/O) |

These are the crates published to crates.io ([docs/releasing.md](docs/releasing.md) has the order). Not published:
`rtci-signal`, the examples' signalling helper; `rtci-video`, the video pipeline (in development, not part of
the 0.2.1 release); the fuzz crates, the benchmark and the test environment's peers.

## Common Use Cases

### Data Channels

```rust,no_run
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::sansio::Protocol;
use std::time::Instant;

fn open(pc: &mut RTCPeerConnection) -> Result<RTCDataChannelId, Box<dyn std::error::Error>> {
    let init = RTCDataChannelInit {
        ordered: true,
        max_retransmits: None,
        ..Default::default()
    };
    // The handle borrows `pc`, so keep the id to reach the channel again later.
    let id = pc.create_data_channel("my-channel", Some(init))?.id();
    Ok(id)
}

fn on_open(pc: &mut RTCPeerConnection, id: RTCDataChannelId) -> Result<(), Box<dyn std::error::Error>> {
    // Only send once the channel is open: an in-band channel's SCTP stream is
    // established by the DCEP handshake, and sending before then is rejected.
    if let Some(mut dc) = pc.data_channel(id) {
        dc.send_text(Instant::now(), "Hello, WebRTC!")?;
    }
    Ok(())
}

fn drive(pc: &mut RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
            on_open(pc, id)?;
        }
    }
    Ok(())
}
```

### Media Tracks

```rust,no_run
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::RTCPeerConnection;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

fn add_video(
    pc: &mut RTCPeerConnection,
    ssrc: u32,
) -> Result<RTCRtpSenderId, Box<dyn std::error::Error>> {
    let track = MediaStreamTrack::new(
        "stream-id".to_string(),
        "track-id".to_string(),
        "Camera".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec::default(),
            ..Default::default()
        }],
    );

    Ok(pc.add_track(track)?)
}
```

The engine does not encode: the application writes RTP with `RTCRtpSender::write_rtp`. What it
sends is the codec negotiated for the sender, the first media codec of
`RTCRtpSender::get_parameters().rtp_parameters.codecs`, with that codec's payload type (the
remote description's number, RFC 3264 section 5.1). A remote description changes it, so after
applying an answer (or, when answering, an offer) the application reads it again and encodes
that codec, rather than keeping the encoder it chose from `setCodecPreferences` or its own
offer. A packet written with a payload type that is not negotiated is sent with the negotiated
one: `write_rtp` rewrites the number, never the payload, so bytes of another codec would go out
labelled as the negotiated one. Each rewrite is counted:
`RTCRtpSender::rewritten_payload_type_rtp_packets()` (every rewrite, the same codec renumbered
included) and `RTCRtpSender::rewritten_from_another_codec_rtp_packets()` (the written number
names a different format), summed on the connection by the `RTCPeerConnection` methods of the
same names. An application's tests can assert the second stays 0.

### Statistics

```rust,no_run
use rtci::peer_connection::RTCPeerConnection;
use rtci::statistics::StatsSelector;
use std::time::Instant;

fn report(pc: &mut RTCPeerConnection) {
    // The instant is passed in rather than read from the clock, so a stats
    // snapshot is as reproducible as the rest of the session.
    let report = pc.get_stats(Instant::now(), StatsSelector::None);

    if let Some(stats) = report.peer_connection() {
        println!("data channels opened: {}", stats.data_channels_opened);
    }
    for stream in report.inbound_rtp_streams() {
        println!(
            "ssrc {}: {} packets received",
            stream.received_rtp_stream_stats.rtp_stream_stats.ssrc,
            stream.received_rtp_stream_stats.packets_received
        );
    }
}
```

### Signaling

WebRTC requires an external signaling channel (e.g. WebSocket, HTTP) to exchange offers and answers. Note that every
description call takes the current instant:

```rust,no_run
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use std::time::Instant;

fn negotiate(
    pc: &mut RTCPeerConnection,
    answer_sdp: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer.clone())?;
    // send `offer.sdp` over your signaling channel, receive the answer, then:
    let answer = RTCSessionDescription::answer(answer_sdp)?;
    pc.set_remote_description(Instant::now(), answer)?;
    Ok(())
}
```

## Specification Compliance

This implementation follows these specifications:

| Layer | Specification |
| --- | --- |
| API | [W3C WebRTC 1.0](https://www.w3.org/TR/webrtc/), [W3C WebRTC Statistics](https://www.w3.org/TR/webrtc-stats/) |
| Signaling | [RFC 9429](https://datatracker.ietf.org/doc/html/rfc9429) (JSEP), [RFC 8866](https://datatracker.ietf.org/doc/html/rfc8866) (SDP), [RFC 8843](https://datatracker.ietf.org/doc/html/rfc8843) (BUNDLE), [RFC 8853](https://datatracker.ietf.org/doc/html/rfc8853) (Simulcast) |
| Connectivity | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) (ICE), [RFC 8838](https://datatracker.ietf.org/doc/html/rfc8838) (Trickle ICE), [RFC 8839](https://datatracker.ietf.org/doc/html/rfc8839) (SDP for ICE), [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) (STUN), [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) (TURN) |
| Security | [RFC 9147](https://datatracker.ietf.org/doc/html/rfc9147) (DTLS 1.3), [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347) (DTLS 1.2), [RFC 5764](https://datatracker.ietf.org/doc/html/rfc5764) (DTLS-SRTP), [RFC 3711](https://datatracker.ietf.org/doc/html/rfc3711) (SRTP) |
| Data | [RFC 9260](https://datatracker.ietf.org/doc/html/rfc9260) (SCTP), [RFC 8261](https://datatracker.ietf.org/doc/html/rfc8261) (SCTP over DTLS), [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831) (Data Channels), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832) (DCEP) |
| Media | [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) (RTP/RTCP), [RFC 4588](https://datatracker.ietf.org/doc/html/rfc4588) (RTX), [RFC 8285](https://datatracker.ietf.org/doc/html/rfc8285) (Header Extensions), [RFC 5761](https://datatracker.ietf.org/doc/html/rfc5761) (RTP/RTCP Mux) |

Which sections of each are implemented, and which are not, is in [docs/conformance.md](docs/conformance.md).

## Documentation

- API documentation: the crate documentation (`cargo doc --open`; docs.rs once published)
- [Conformance](docs/conformance.md) - Every claim with its spec section and test, and what is not implemented
- [Test exclusions](docs/test-exclusions.md) and [upstream test parity](docs/upstream-test-parity.md) - Every test runs,
  and every upstream test is accounted for
- [Examples](examples/) - Working code examples
- [Sans-I/O Pattern](https://sans-io.readthedocs.io/) - The sans-I/O design
- [FORK.md](FORK.md) - What this code base carries over upstream, and why
- [CHANGELOG.md](CHANGELOG.md) - Every change, by release
- [docs/releasing.md](docs/releasing.md) - How a release is published

## Building and Testing

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build with the aws-lc-rs crypto provider instead of ring
cargo build --no-default-features --features crypto-aws-lc-rs

# Build documentation
cargo doc --open

# Run an example
cargo run --example data-channels-answer

# The repository's own checks (no build needed)
python3 scripts/check-test-inventory.py   # no ignored, commented-out, orphaned or platform-gated test
python3 scripts/check-test-parity.py      # every upstream test has a fork test, a mapping or a reason
python3 scripts/check-fuzz-registry.py    # every fuzz target is listed for OSS-Fuzz and run by CI
python3 scripts/check-workflow-pins.py    # actions pinned by SHA, no self-hosted runner for a fork PR

# Fuzz one target (nightly toolchain and cargo-fuzz; each crate's fuzz/ directory, ./fuzz for `rtci`)
cd rtci-sctp/fuzz && cargo fuzz run --debug-assertions endpoint_handle_datagrams
```

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **Patch** (`0.x.Y`): Bug fixes and internal improvements with no public API changes.
- **Minor** (`0.X.0`): Backwards-compatible additions or deprecations to the public API.
- **Major** (`X.0.0`): Breaking changes to the public API.

While the version is `0.x`, the minor version acts as the major: a minor bump may include breaking changes. Once
`1.0.0` is released, full semver stability guarantees apply.

Pre-release versions are published with the following suffixes, in order of increasing stability:

- **`-alpha.N`**: Early preview. API is unstable and may change significantly.
- **`-beta.N`**: Feature-complete for the release. API may still have minor changes.
- **`-rc.N`**: Release candidate. No further API changes are expected unless critical issues are found.

For example: `1.0.0-alpha.1`, then `1.0.0-beta.1`, `1.0.0-rc.1` and `1.0.0`.

## Contributing

Issues and pull requests go to the repository. Report security problems privately, as [SECURITY.md](SECURITY.md)
describes.

## License

This project is licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

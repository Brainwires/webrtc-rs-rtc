# rtci-mdns

Multicast DNS for WebRTC: a querier that resolves `.local` names (the mDNS host candidates
browsers send) and a responder that publishes local names, with probing, announcing,
answering, defending a name and goodbyes, a cache bounded by TTL, and one rate limit over
everything sent.

## Specifications

- RFC 6762, Multicast DNS
- draft-ietf-mmusic-mdns-ice-candidates, mDNS names for ICE host candidates

Clause-by-clause status, with the test that proves each clause: [rfc6762](../docs/conformance/audit/rfc6762.md), [draft-ietf-mmusic-mdns-ice-candidates](../docs/conformance/audit/draft-ietf-mmusic-mdns-ice-candidates.md).

## Use

`Mdns::new(now, MdnsConfig)` creates the state machine; `query_now` starts a query and
`poll_event` reports the answer (`MdnsEvent`). `MulticastSocket` builds a UDP socket joined to
the mDNS group for applications that want one. The root crate (`rtci`) uses it for mDNS
candidates. The crate documentation has query and responder examples.

`MulticastSocket::with_interface` joins and sends on that interface (`IP_MULTICAST_IF`, RFC
6762 section 14). Without one the socket joins on `INADDR_ANY` and sends by the system's route
for 224.0.0.251, except on Windows, where it joins and sends on the default route's interface:
there the group's route comes
from a destination cache that any process which sent to the group from 127.0.0.1 leaves on
loopback for the whole host. A Windows host whose mDNS link is not the default route's should
pass the interface.

## Sans-I/O

The protocol is a `sansio::Protocol`: datagrams in through `handle_read`, out through `poll_write`, deadlines through `poll_timeout` / `handle_timeout`. Only `MulticastSocket`, an optional helper, touches the operating system. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

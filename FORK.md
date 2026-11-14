# Brainwires fork of webrtc-rs/rtc

This repository is [webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) plus the changes listed
below. It is what ReachMyDevice pins, and what the Deno WebRTC extension (Brainwires/deno
`ext/webrtc`) builds on.

## Sync point

| | |
|---|---|
| Upstream | `webrtc-rs/rtc` `master` |
| Last upstream commit merged | `0fbcaa74` (after v0.21.1, 2026-11-12) |
| Previous sync point (original fork point) | `bf30a00c` (2026-04-06) |
| Fork master before this sync | `81bc7c6b` |
| Fork release | `0.21.1+brainwires.2` (build metadata marks the fork; it orders with upstream 0.21.1) |

The fork is kept in sync by **merging** upstream into a branch (never rebasing), so the fork's
history stays intact.

## Standing rules for syncing

1. **Never take an upstream change that removes, deprecates or disables a feature, API, flag or
   platform, or narrows behaviour by default.** If such a commit bundles a fix, port only the fix
   and revert the removal inside the merge resolution. Record it in the table below.
2. Every fork feature is kept unless upstream's version is a strict superset; when one is dropped
   for that reason, say so here.
3. Security fixes are always taken.

## What the fork carries over upstream

### Fork features

| Feature | Where | Notes |
|---|---|---|
| TWCC-driven GCC interceptor with a shared bitrate handle | `rtc-interceptor/src/gcc/twcc_gcc/` | `GccInterceptorBuilder`, `GccHandle`, `GccInterceptor`, `GccShared`. Trendline filter + AIMD (draft-ietf-rmcat-gcc-02). Lives beside upstream's GCC (`Gcc`, `configure_congestion_control`), which is the more complete estimator; the fork's keeps its pull-style `GccHandle` API, which ReachMyDevice uses. Place it in `Slot::CongestionControl`, below `Slot::TwccSender`. |
| Adaptive jitter buffer | `rtc-interceptor/src/adaptive_jitter_buffer/` | Exported as `AdaptiveJitterBufferBuilder` / `AdaptiveJitterBufferInterceptor` (renamed because upstream now owns `JitterBufferBuilder`). Delay adapts to RFC 3550 interarrival jitter and honours the `playout-delay` header extension; upstream's is fixed-depth. |
| `rtc-interceptor-derive` (`#[derive(Interceptor)]`, `#[interceptor]`) and `Interceptor::with` | `rtc-interceptor-derive/`, `rtc-interceptor/src/lib.rs` | Upstream deleted both with the list-based chain. A nested interceptor built with them is an ordinary interceptor and goes in a `Registry` slot: `NoopInterceptor::new().with(builder.build())`. |
| DTLS re-handshake on ICE restart | `src/peer_connection/transport/dtls/mod.rs` (`restart`), `src/peer_connection/mod.rs` | Only when the remote fingerprints or the derived DTLS role change, or the session is Failed/Closed; an ICE restart alone keeps the session (browsers do not re-handshake). Keeps the local certificate; replaces the DTLS endpoint so the next selected pair starts a fresh handshake. |
| RRID (RFC 8852 repaired-rtp-stream-id) association for RTX simulcast | `src/peer_connection/handler/interceptor.rs` (`bind_repair_by_rrid`) | Upstream still has this as TODO #12. |
| Repair codecs never establish a layer | `src/peer_connection/handler/endpoint.rs` (`is_repair_mime_type`) | RTX/FEC payload types are not used as a layer's primary codec. |
| Rejected m-lines reflected in answers (RFC 8829 §5.3.1) | `src/peer_connection/internal.rs`, `src/peer_connection/sdp/mod.rs` | Port 0 in the offer stays port 0 in the answer. |
| `RTCConfiguration` Serialize/Deserialize | `src/peer_connection/configuration/mod.rs` | W3C camelCase; certificates are skipped. |
| PeerConnection close collects every handler's error and closes in reverse order | `src/peer_connection/handler/mod.rs` | On top of upstream's ABORT + close_notify. The fork's per-channel closing procedure and SCTP state release were dropped: upstream aborts the association (W3C `close()`) and derives `SctpTransport.state` from the aborted association. |
| Duplicate negotiated DATA_CHANNEL_OPEN is not fatal | `src/peer_connection/handler/sctp.rs` | Both peers may open the same pre-negotiated stream. |
| RTP marshal bounds checks | `rtc-rtp/src/header/mod.rs`, `codec/h264`, `codec/h265` | CSRC count, one/two-byte extension lengths, total extension length, NALU sizes. |
| `DataChannelMessage::new` | `rtc-datachannel` | |
| TURN client `turn_server_addr()` / `local_addr()` accessors, TCP TURN example | `rtc-turn` | The example now uses upstream's TURN stream framing (RFC 8656 §12.5); the fork's original example used RFC 4571 framing, which TURN does not use. |
| `RTCCertificate::from_key_pair` | `src/peer_connection/certificate/mod.rs` | Kept (upstream removed it); wraps `generate_from_signing_key` with the built-in provider. |
| Inbound key-frame requests reach the application | `rtc-interceptor/src/keyframe.rs` (`KeyFrameRequestInterceptor`, `Slot::KeyFrameRequests`), `src/peer_connection/configuration/interceptor_registry.rs` (`configure_key_frame_requests`, in `register_default_interceptors`) | Upstream's terminus ends every inbound RTCP packet no interceptor vouches for, PLI and FIR included, though only the application (the encoder) can answer them. The fork marks them `DeliverToApplication` by default. |
| ICE over TCP between `rtc` peers in both role assignments | `rtc-ice/src/agent/mod.rs` (`handle_inbound`, `add_remote_candidate`, `find_local_candidate`), `rtc-ice/src/tcp_type` (`complement`) | A peer-reflexive candidate learned over TCP takes the complementary TCP type, so a controlling agent with a passive candidate pairs with (and nominates) the peer that dialled it; exact local address matches win over an active candidate's IP-only match. `tests/ice_tcp_rtc2rtc.rs`. |
| mDNS host candidates per address | `rtc-ice/src/agent/mod.rs` (`mdns_name_for`), `rtc-ice/src/mdns`, `rtc-mdns/src/proto` (`add_local_name`, AAAA) | `QueryAndGather` without a fixed IP publishes each local address (IPv4 and IPv6, UDP and TCP) under its own `<uuid>.local` name, as browsers do; queries ask for A and AAAA. The fixed-IP form also hides that address's TCP candidates. |
| mDNS datagrams reach ICE whatever their first byte | `src/peer_connection/handler/demuxer.rs` | Port 5353 on both ends goes to the agent before RFC 7983 demultiplexing. |
| Bounded RFC 4571 decoding | `rtc-shared/src/tcp_framing.rs` (`TcpFrameDecoder::push`, `try_frame_packet`) | `push` refuses data past two frames' worth; packets are taken without shifting the buffer each time. |
| CI: benchmarks, fuzzing, OSS-Fuzz, git-cliff release notes | `.github/workflows/{bench,fuzz,release}.yml`, `oss-fuzz/`, `cliff.toml` | |

### Hardening (fork only)

Peer-input hardening upstream does not have: bounded DTLS fragment reassembly, early-record queue
and handshake cache; AEAD-only default DTLS suites; ChangeCipherSpec honoured only for the
handshake's one epoch transition; SRTP state only after authentication, and SRTCP authenticated
whatever its E flag; ICE source filtering, authenticated role conflicts and consent, candidate
caps (mDNS-resolved ones included), mDNS answers only from the mDNS socket, at most 64 published
mDNS names (a host candidate past them is dropped, not sent with its address); bounded RFC 4571
frame decoding; bounded SCTP
FORWARD-TSN/SACK/receive window and stream-id checks; DCEP stream-id parity and internal message
types refused from the wire; TURN client server-address filtering and response MESSAGE-INTEGRITY
checks; errors instead of panics on malformed DTLS/SCTP/DCEP/ICE/SDP/RTCP input; NACK
retransmission de-duplication and rate limit; bounded H.264 FU-A and AV1 reassembly, AV1 OBU
checks, VP9 per-picture state; RTP extension blocks consumed whole; SLI on PT 206; bounded IVF and
H.265 writer buffers; sha-256 fingerprint selection; fuzzing CI fixes and stateful SCTP targets.
See CHANGELOG.md.

Left as the RFCs require: the TURN client accepts 401 (Unauthorized) and 438 (Stale Nonce) error
responses without MESSAGE-INTEGRITY (RFC 8489 §9.2.4; a server cannot sign a reply about the
credential or nonce it would sign with). So a forged 438 can still end the request it answers
with a stale-nonce error and replace the allocation's nonce; the server's own 438 on the next
request restores it. Only a sender that passes the server-address filter can do this, and it
cannot release the allocation or forge any other response.

### Dependency audit (fork only)

`.github/workflows/audit.yml` resolves dependencies afresh and runs `cargo deny check advisories`
on every PR: first on the library's own graph with `.github/deny-library.toml` (normal and build
dependencies, all features, no ignores), then on the whole workspace with `deny.toml`. Ignores are
allowed only in `deny.toml`, only for advisories that cannot reach the library, each with its
reason. Today there is one:

| Advisory | Crate | Why it is ignored |
| --- | --- | --- |
| RUSTSEC-2026-0441 (unmaintained, no vulnerability) | `pin-utils` 0.1.1 | Dev-dependency only, interop tests: `webrtc` 0.17.3 -> `webrtc-util` -> `nix` 0.26. `webrtc` 0.17.3 is the last release of the independent implementation the interop tests exercise; 0.20+ is built on the upstream `rtc` crates. |

### Defaults the fork widens

- `register_default_interceptors` includes `KeyFrameRequestInterceptor`: an application on the
  defaults now receives the compound RTCP packets that carry a PLI or FIR as
  `RTCMessage::RtcpPacket` (upstream delivers no RTCP by default). Build the chain without it to
  keep upstream's behaviour.
- `MulticastDnsMode::QueryAndGather` without `multicast_dns_local_ip` hides every host candidate
  (upstream's points one name at 127.0.0.1 and hides none).

### Defaults the fork narrows on purpose

- DTLS: the default WebRTC cipher suites are AEAD only (AES-128-GCM, ChaCha20-Poly1305); the
  AES-256-CBC-SHA suites are opt-in. This is the one deliberate exception to rule 1, decided by
  the maintainer for security. To offer CBC again, list the suites with
  `SettingEngineBuilder::with_dtls_cipher_suites` (for example
  `CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha`).

### Upstream API replacements taken

Removed upstream APIs with a replacement that covers them are taken as breaking changes, without
shims: `CryptoPrivateKeyKind`, `KeyingMaterialExporter`, `extract_session_keys_from_dtls`,
`MessageIntegrity::default`, `FnTimeGen`, the old `Packet` message type and the
`SettingEngine::set_*` setters. CHANGELOG.md lists the new API for each.

### Upstream changes not taken (reverted inside the merge)

| Upstream commit | What it removed or narrowed | What the fork does instead |
|---|---|---|
| `14d89bb2` interceptor redesign | Deleted `rtc-interceptor-derive` and `Interceptor::with` | Takes the redesign, keeps the crate and `with` (see above). |
| `4d0c5070` (#837) | Stopped advertising ULPFEC (PT 116) by default | ULPFEC stays in `register_default_codecs`. |
| `8080cef3` | `write_rtp` stopped rewriting an un-negotiated payload type to the encoding's codec | The fuzzy-match fallback stays; only a packet with no matching codec at all is an error. |
| `1f1b0874` (#123) | `write_rtp` errors on header extension ids not negotiated on the sender | They are passed through (with a trace log), as before. |
| `702ffbc0` | `RTCConfiguration::validate` rejects a Relay policy without a TURN URL | Warns instead; an application may add its own relay candidates. |
| `fd81f68f` (crypto P4) | Removed the `openssl` / `vendored-openssl` features (rtc, rtc-srtp) | Features kept: the AES-CM SRTP keystream comes from OpenSSL when enabled (`rtc-crypto/src/openssl_ctr.rs`, reached through `rtc-srtp`'s `openssl` feature so `rtc-crypto` stays the only crate naming a crypto implementation). |
| crypto P5/P6 | Removed the `pem` feature name (rtc, rtc-dtls) | Kept as a no-op feature (PEM is always built now), so dependents that enable it still build. |

### Fork features dropped because upstream's is a strict superset

| Fork change | Upstream replacement |
|---|---|
| `check_partial_reliability_status` `>=` → `>` fix (PR-SCTP max_retransmits) | Upstream's message-based reliability (`retransmission_policy_exhausted`, #242) uses `nsent > max_retransmits` and also defers abandonment to retransmission. |
| DTLS `CryptoPrivateKey` private fields + panic-free `Clone` | Upstream's provider-neutral `SigningKey` (no DER re-parse, no panic). |
| `HandshakeConfig::default()` placeholder verifier | Upstream has no `Default`; the verifier is an `Option` built by `ConfigBuilder`. |
| Negotiated data channels (#61) and `set_direction` renegotiation (#51) | Upstream #101 and #102 implement the same behaviour; the fork's integration tests are kept. |
| RTX/FEC SSRC routing to the primary track | Upstream de-encapsulates RTX onto the primary (#120) and binds declared repair SSRCs (#197); the fork's RRID part is kept. |
| `total_lost` clamp | Merged cleanly with upstream; the fork's clamp to the signed 24-bit maximum stays. |

## How to sync with upstream

```sh
git clone https://github.com/Brainwires/webrtc-rs-rtc.git && cd webrtc-rs-rtc
git remote add upstream https://github.com/webrtc-rs/rtc.git
git fetch upstream
git switch -c sync/upstream-<version> master
git log --oneline "$(git merge-base master upstream/master)"..upstream/master   # audit these
git merge --no-ff upstream/master
```

1. Audit every new upstream commit against the standing rules above, before resolving. For
   each removal or narrowed default, plan how the resolution keeps the old behaviour.
2. Resolve the conflicts. Keep fork features, port bundled fixes from commits you leave out, and
   add a row to the tables above for each.
3. Build and test with the pinned toolchain:
   `RUSTUP_TOOLCHAIN=1.92.0 cargo build --workspace && cargo test --workspace --no-fail-fast`.
4. Update the sync point at the top of this file, then open a PR into `master`.

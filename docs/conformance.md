# Conformance

The engine does everything it claims, and claims nothing it doesn't do. A claim is a row of the
README's feature list, a row of `FORK.md`, the documentation of a public option, a codec or
attribute the default SDP offers, or a member the statistics report emits. This document holds
one row per claim: the specification section, where it is implemented, and the test that proves
it. What is deliberately not implemented is listed at the end, so nothing is implied that is not
there.

## How it is checked

Each area's rows live in a fragment under [`conformance/`](conformance/), written with the code
that makes the claim true. In every table with a **Test** column, each backticked name is a test
(`name`, `file.rs::name`) or a test file (`tests/x.rs`); `scripts/check-test-inventory.py` (the
`Test inventory` job in `cargo.yml`) fails when one does not exist, so a claim cannot outlive the
test behind it. Tables whose proof is an environment test or a browser-interop cell say
**Proved by** instead; `scripts/test-env/interop/gate.mjs` checks those (criterion C3).

The rest of the evidence that the claims hold:

- [Test exclusions](test-exclusions.md): every test runs on every platform CI tests, except the
  ones listed there with a reason and a covering test.
- [Upstream test parity](upstream-test-parity.md): every test of upstream `webrtc-rs/rtc` and
  `webrtc-rs/webrtc` v0.17.1 has a fork test, a mapped equivalent, or the reason it cannot exist.
- [Performance ledger](performance.md): every measured performance cost or gain that was
  accepted (and every measured alternative that was refused), with its figures, its guard and
  its evidence. A branch that moves a measured figure adds its ledger row in the same branch and
  tags its CHANGELOG entry `Performance: <id>`; `scripts/check-performance-ledger.py` (the
  `Test inventory` job) fails on a tag without a row or a row naming a file or test that does not
  exist, and the pull-request job of `bench.yml` fails on a micro-benchmark regression that has
  no allowlist entry naming a row.
- Fuzzing: every parser a peer, a server or an untrusted file reaches has a fuzz target, run by
  `fuzz.yml` and built by OSS-Fuzz ([fuzzing and gates](conformance/w7.md)).

## Claims, by area

| Area | Fragment |
|---|---|
| Data channels, SCTP | [conformance/w1.md](conformance/w1.md) |
| JSEP negotiation, codecs, transceivers, API state rules; SDP syntax and typed attributes (rtci-sdp) | [conformance/w2.md](conformance/w2.md) |
| ICE, TURN, STUN, DTLS, mDNS, SRTP | [conformance/w3.md](conformance/w3.md) |
| JSEP negotiation, codecs, transceivers, API state rules | [conformance/w2.md](conformance/w2.md) |
| ICE, TURN, STUN, DTLS, mDNS, SRTP, SFrame | [conformance/w3.md](conformance/w3.md) |
| RTP, RTCP, interceptors, payloaders, FEC | [conformance/w4.md](conformance/w4.md) |
| Statistics | [conformance/w5.md](conformance/w5.md) |
| The real-network environment and the browser matrix | [conformance/w6.md](conformance/w6.md) |
| Fuzzing and the repository's gates | [conformance/w7.md](conformance/w7.md) |

## Decisions that change a claim

| # | Claim | What the engine does |
|---|---|---|
| D1 | ULPFEC (RFC 5109) | Implemented, opt-in, and not offered by default. `configure_ulpfec` adds the encoder and decoder for ULPFEC carried in RED (RFC 2198), the form browsers negotiate for video; the application registers `video/red` and `MIME_TYPE_ULP_FEC` and passes their payload types. The RED payload format (RFC 2198) is in `rtci-rtp` (`codec::red`); the engine uses it for that carriage only: it neither offers `red` for audio nor wraps or unwraps audio in it. A separate FEC RTP session (RFC 5109 14.1: an m= section of `ulpfec` alone on a transport of its own, grouped with the media section, the FEC stream under the media stream's SSRC) is implemented and opt-in on both sides: `RTCPeerConnection::add_fec_session` offers one, `SettingEngineBuilder::with_separate_fec_sessions(true)` accepts one, `configure_ulpfec_sessions` adds the interceptors. RFC 8854 section 5.2 has a WebRTC endpoint not offer FEC-only m= sections and refuse them unless it knows how, so the default does neither. |
| D1 | ULPFEC (RFC 5109) | Not offered by default: nothing encodes or decodes it. `MIME_TYPE_ULP_FEC` stays, and an application with its own coder registers it explicitly. RED is not implemented. |
| D2 | `bundle_policy` | A section outside a BUNDLE group has a transport of its own (mt-2): a remote offer without a group, or with sections outside it, is answered with a transport per such section, and `max-compat` offers a transport per section; an answer that bundles them closes all but the tagged section's. The policy decides what an initial offer marks `a=bundle-only` and which sections of an offer without a BUNDLE group are answered (RFC 9429 4.1.1; `balanced` is the default; `must-bundle` is a policy; `max-bundle`, which W3C webrtc-pc 4.2.5 still defines, is that policy too, unless `with_max_bundle_as_must_bundle(false)` has it ignored as the RFC's SHOULD says). A `balanced` initial offer gives the first section of each media type a transport (mt-5), each BUNDLE group is one (mt-6); the transports share the first one's ICE credentials unless `with_unique_transport_credentials(true)` (mt-7), also on one shared local socket (mt-9). |
| D2b | Bundle-only sections of an initial offer | The default writes them in the RFC 9143 7.1.3 / 9.3.1.1 form: port zero, `a=bundle-only`, no IDENTICAL or TRANSPORT attribute (no `a=rtcp-mux`, no ICE credentials, no `a=fingerprint`, no `a=setup`). Chromium, WebKit and Firefox refuse an offer with such an RTP section (browser matrix, test-env run 45900172027): Chromium and WebKit "Failed to set local answer sdp: rtcp-mux must be enabled when BUNDLE is enabled.", Firefox "m-section at level 1 is missing a=rtcp-mux, which is required by rtcpMuxPolicy". `SettingEngineBuilder::with_bundle_only_sections_in_browser_form(true)`, on in the `Chrome` profile, writes `a=rtcp-mux` in each bundle-only RTP section and the group's ICE credentials in each bundle-only section (the departures: RFC 9143 7.1.3 / 9.3.1.1, RFC 9429 5.2.1 "Bundle-only "m=" sections MUST NOT contain any ICE credentials") and the fingerprints at session level as well (RFC form: RFC 8122 5, RFC 9429 5.2.1). `a=rtcp-mux` alone is not enough (Chromium and WebKit answer the data section with port zero, run 45902077847); with the session-level fingerprints all three take the offer (45903674595), and without the ICE credentials Firefox refuses the engine's answer to its next offer as an unrequested ICE restart (45905096237; later descriptions in the tagged-only form are refused too, "no ice-ufrag attribute at level 1", 45908363443). With the default profile no browser accepts an offer under `max-bundle` with more than one m= section. Cells: `max-bundle: Rust offers *` (`scenarios.spec.mjs`); test: `tests/jsep_bundle_only_browser_form.rs`. |
| D3 | `SettingEngine` options with no effect in a sans-I/O engine (`receive_mtu`, `include_loopback_candidate`, `disable_media_engine_copy`) | `#[deprecated]` with the reason; no option is silently a no-op. `nat_1to1_ips` and `disable_media_engine_multiple_codecs` are implemented. |
| D4 | FlexFEC draft-03 (`video/flexfec-03`) where libwebrtc departs from the draft's letter | The engine follows libwebrtc, the only draft-03 peer: mask bit j names the packet SN base + j (the draft's text says SN base + j + 1; RFC 8627 4.2.2.1 later wrote down what libwebrtc does), and the coder answers to the subtype `flexfec-03` only (the draft registers `flexfec`, which now means RFC 8627 and selects that coder). Both are pinned by tests (`mask_bit_j_names_sn_base_plus_j_as_libwebrtc_sends_it`, `the_mime_type_match_is_exact`). |

## Standing departures from a MUST

A default follows the RFC, its MUSTs first (`docs/conformance/audit/RULES.md`). Where the
owner has decided that a default departs from a MUST for a reason other than a browser or
deployed peer that cannot interoperate with the RFC form, the departure is listed here with
its reason and the test behind it, and the audit row says the same. In each, the RFC form is
an explicit setting and the `StrictRfc` behaviour profile selects it
([behaviour-profiles.md](behaviour-profiles.md), section 1). The defaults that depart from a
MUST because a named peer cannot take the RFC form are the audit's `setting` rows, also in
behaviour-profiles.md. A clause that another specification governing this API contradicts (the
audit's `conflict` rows, such as RFC8830-3.2.5-1, whose W3C form is the default) is not a
departure by decision and is not listed here; `StrictRfc` selects those RFC forms too. Two
entries are of another kind, and say so: a clause the RFC contradicts in the same paragraph
(RFC 6347 section 4.2.1), where `StrictRfc` keeps the default because neither sentence is the
RFC form over the other, and an opt-in setting that permits what a MUST NOT forbids (RFC 8446
section 4.2.3), off by default and in no profile.

What the maintainers' current draft work says of each contradiction and departure below (W3C
candidate corrections and issues, IETF errata and bis drafts, with dates), and whether the
default matches it, is in the register [conformance/draft-work.md](conformance/draft-work.md).
Defects found in the specifications themselves, and their upstream state, are listed in [conformance/spec-issues.md](conformance/spec-issues.md).

| Clause | The MUST | The default | The RFC form | Why the default departs | Test |
|---|---|---|---|---|---|
| RFC 6184 section 7.2.2 (audit row RFC6184-7.2.2-1) | "Let PDON be a variable that is initialized to 0 at the beginning of the RTP session. [...] If the value of DON of the NAL unit is larger than the value of PDON, the DON distance is equal to DON - PDON. Otherwise, the DON distance is equal to 65535 - PDON + DON + 1. NAL units are delivered to the decoder in ascending order of DON distance" | **This default does not follow RFC 6184 section 7.2.** Until the first NAL unit has been passed on, the H.264 de-interleaving buffer takes PDON as the DON just before the earliest NAL unit it holds, not 0; after that PDON is the DON of the last NAL unit passed on, as the RFC says | `MediaEngine::set_h264_literal_pdon(true)` (`h264.literal-pdon`, set by `StrictRfc`), read by `MediaEngine::h264_depacketizer` and `RTCRtpReceiver::h264_depacketizer`; in `rtci-rtp`, `H264DeinterleavingBuffer::with_literal_pdon(true)` | Owner decision, 2026-11-26. With PDON = 0, a NAL unit whose DON is 0 is not "larger than PDON", so its distance is 65535 - 0 + 0 + 1 = 65536, the largest there is: a stream numbered from DON 0 (section 5.5 lets the first DON be any value), or one whose first DONs wrap through 0, has its first NAL unit delivered last, after NAL units that follow it in decoding order. For a stream that starts at any other DON the default gives the RFC's order. No erratum to RFC 6184 touches section 7.2 as of 2026-11-26 (errata 3318, 4713 and 4714 are on sections 8.1 and 8.2.2) | `rtci-rtp/src/codec/h264/interleaved_test.rs::a_stream_numbered_from_don_0_leaves_in_decoding_order`, `rtci-rtp/src/codec/h264/interleaved_test.rs::nal_units_leave_in_the_order_of_the_rfc_procedure_from_pdon_0`, `rtci-rtp/src/codec/h264/interleaved_test.rs::with_the_literal_pdon_the_order_is_the_rfc_procedures_from_don_0`, `tests/h264_deinterleaving_profile.rs` |
| RFC 9429 section 5.3.1 (audit rows RFC9429-5.3.1-16 and RFC3264-6.1-7, verdict `setting`; the section contradicts itself) | "Any currently available media formats that are not present in the current remote description MUST be added after all existing formats", while the next bullet reads "the media formats in the answer MUST include at least one format that is present in the offer but MAY include formats that are locally supported but not present in the offer" (and RFC 3264 section 6.1: the answer "MAY indicate additional media formats") | Since 0.3.0 (jsep-95, owner decision 2026-11-27) an answer lists only the offered formats this endpoint supports, in the offer's order, each repair format with its primary (`SettingEngineBuilder::with_answer_offered_formats_only`, default `true`) | `with_answer_offered_formats_only(false)`, the default up to 0.2.x: every other registered media format is added after the offered ones; `BehaviourProfile::StrictRfc` selects it (`jsep.answer-offered-formats-only`) | (1) The browsers answer with the offered formats only: libwebrtc (Chrome; WebKit's WebRTC is libwebrtc) `pc/codec_vendor.cc` @ a222406d: `CodecVendor::GetNegotiatedCodecsForAnswer` (line 1415) calls `NegotiateCodecs` (line 1566), which keeps each local codec that `FindMatchingCodec` finds in the offer (line 813) and sorts them into the offer's order (`keep_offer_order`, line 876); nothing the offer lacks is answered. The web-platform-tests assume it: `webrtc/protocol/h265-level-id.https.html` asserts the offerer's sender has one codec, and an `rtci` answerer in the 0.2.x form gave 14. (2) The added formats are live: WebKit switched its sender to the VP9 an answer added on 98 (test-env run 45878070327, job 140110123339, cell 'chrome profile: simulcast, three RIDs reach Rust' [webkit]: 693 packets on 98 against 13 VP8; 0.2.0 dropped them, 0.2.1 receives them), and they are the offerer's send codecs (jsep-91, W3C [[SendCodecs]]). (3) They spend dynamic payload type numbers in the peer's session: a browser's later offer that gives one of them another format meets RFC 3264 section 8.3.2 ("MUST NOT change for the duration of a session"). `StrictRfc` and the setting give the MUST sentence's form | `tests/jsep_answer_offered_formats_only.rs::by_default_an_answer_lists_the_offered_formats_only`, `tests/jsep_answer_offered_formats_only.rs::every_profile_but_strict_rfc_answers_the_offered_formats_only`, `tests/jsep_answer_offered_formats_only.rs::without_the_setting_an_answer_adds_the_other_formats_after_the_offered_ones` |
| RFC 8083 section 3 (audit row RFC8083-3-3, verdict `setting`) | "If the RTP packets being sent vary in size, then the average size over the packet comprising the last 4 * G frames MUST be used" (s, in the TCP throughput the circuit breaker compares with) | The packet size s is the average over the packets of the window the sending rate is measured over, the last CB_INTERVAL reporting intervals (`PacketSize::SendingWindow`) | `DefaultInterceptorOptions::circuit_breaker_packet_size` / `CircuitBreakerBuilder::with_packet_size(PacketSize::LastFrames)` (`cb.packet-size`, set by `StrictRfc`) | Measured: a talking call (talkspurts of 750-byte frames, silences of 11-byte frames) over a lossy, jittery path is ceased for congestion with section 3's s, because the last four frames are often silence and s then is a few tens of bytes against the talkspurts' rate; the default keeps it running. 60 s calls at 5 % loss, 40 and 100 ms of jitter: section 3's s ceased 5 of 6 runs, the default none (hosted run 45521916073). Constant-size flows are the same under both forms | `tests/circuit_breaker_reordering_rtc2rtc.rs::the_last_frames_packet_size_ceases_a_talking_call_the_default_keeps`, `rtci-interceptor/tests/circuit_breaker.rs::the_packet_size_is_that_of_the_window_the_rate_is_measured_over` |
| RFC 6347 section 4.2.1 (audit row RFC6347-4.2.1-8, `partial`; an internal conflict of the RFC) | "The server MUST use the same version number in the HelloVerifyRequest that it would use when sending a ServerHello", in the paragraph after "DTLS 1.2 server implementations SHOULD use DTLS version 1.0 regardless of the version of TLS that is expected to be negotiated" | A DTLS 1.2 server's HelloVerifyRequest says DTLS 1.0 (fe ff), its ServerHello DTLS 1.2 (fe fd): the SHOULD | `rtci-dtls` `ConfigBuilder::with_hello_verify_request_version(PROTOCOL_VERSION1_2)` writes the ServerHello's version (the MUST); the peer connection does not expose it, and `StrictRfc` does not select it | Coordinator ruling, 2026-11-26. The two sentences cannot both be met by a DTLS 1.2 server, and neither is "the RFC form" over the other, so the default follows what deployed stacks do: OpenSSL 3.6.3 (`ssl/statem/statem_srvr.c`, `dtls_raw_hello_verify_request`: "Always use DTLS 1.0 version: see RFC 6347") writes DTLS 1.0; BoringSSL (boring-sys 4.15.15) sends no HelloVerifyRequest as a server, and its client does not check the version. Erratum 4103 to RFC 6347 (status Reported) proposes "MAY use DTLS version 1.0 [...] or the version that is expected to be negotiated" and deleting the MUST. Clients ignore the field either way (RFC 6347 4.2.1: "solely to indicate packet formatting") | `rtci-dtls/src/endpoint/endpoint_test.rs::hello_verify_request_says_dtls_1_0_unless_configured_to_say_1_2` |
| RFC 8446 section 4.2.3 (audit row RFC8446-4.2.3-21, `tested` for the default; an opt-in) | For TLS 1.2 negotiated by a TLS 1.3 implementation, the legacy hash/signature pairs "MUST NOT be offered or negotiated by any implementation. In particular, MD5 [SLOTH], SHA-224, and DSA MUST NOT be used." | MD5 (and SHA-1) schemes in a configured signature scheme list are dropped; SHA-224 and DSA have no scheme in this crate | The default is the RFC form; the opt-in `rtci-dtls` `ConfigBuilder::with_insecure_hashes(true)` keeps an MD5 scheme the application lists, which a DTLS 1.2 handshake would then offer: it permits the MUST NOT. Not in any profile, not exposed by the peer connection | Kept from the upstream API for applications that must reach legacy peers; its rustdoc says the hashes are "known to be vulnerable". Named here so the opt-in is not mistaken for a conformant setting | `rtci-dtls/src/signature_hash_algorithm/signature_hash_algorithm_test.rs::test_parse_signature_schemes` (cases "Md5DeniedByDefault" and "Md5KeptWithInsecureHashes") |

## Standing departures from a SHOULD

A default follows the RFC, its SHOULDs included (`docs/conformance/audit/RULES.md`). Where a
default departs from a SHOULD for a reason the behaviour profiles do not carry (the RFC form
is in no profile, `StrictRfc` included, and stays an explicit setting), the departure is listed
here with its reason and the test behind the reason, and the audit row says the same. The
SHOULDs whose RFC form `StrictRfc` selects are in
[behaviour-profiles.md](behaviour-profiles.md), section 1.

| Clause | The SHOULD | The default | The RFC form | Why the default departs | Test |
|---|---|---|---|---|---|
| RFC 5764 section 3 (audit row RFC5764-3-4) | "As an optimization, the DTLS-SRTP implementation SHOULD use the following strategy: a single DTLS association is established, and all other DTLS associations wait until that connection is established before proceeding with their handshakes", then resume its session | Every DTLS transport of a connection starts its handshake as soon as its ICE path is there, and none resumes | `SettingEngineBuilder::with_dtls_session_resumption(true)` (DTLS 1.3 tickets with `psk_dhe_ke`; the wait bounded by three flight intervals and 3 s); `BehaviourProfile::StrictRfc` turns it on (`dtls.session-resumption`) | The strategy trades connection time for signatures. The other transports start one handshake later: with three unbundled transports every transport is connected about 3 round trips later against a peer that issues no ticket and about 2.5 later between two engines that resume (round trip 100 ms: 453 ms off, 753 ms, 703 ms; 300 ms: 1.353 s, 2.253 s, 2.103 s), and one datagram lost on the first handshake delays every transport. It saves one signature and one verification per other transport. No browser can take part (libwebrtc sets `SSL_OP_NO_TICKET`; Firefox's `TransportLayerDtls::Setup()` turns session tickets and the session cache off), so against a browser only the wait is left; with BUNDLE there is one transport and nothing to share. Two security reviews found no authentication bypass: it is safe, and not cheap | `multi_transport_rtc2rtc.rs::the_session_costs_the_other_transports_the_first_handshake_on_links_with_latency`, `multi_transport_rtc2rtc.rs::a_datagram_lost_on_the_first_handshake_delays_every_transport_with_the_session_on`, `multi_transport_rtc2rtc.rs::unbundled_transports_wait_for_the_first_and_resume_its_dtls_session`, `multi_transport_rtc2rtc.rs::without_dtls_session_resumption_every_transport_runs_a_full_handshake` |

## Not implemented, on purpose

These are outside what the engine claims. None is offered in the default SDP or implied by the
README.

| Area | Not implemented | Why |
|---|---|---|
| Media | Encoding, decoding, capture, playout | The engine is a transport. Statistics members that need them are left out of the report, not reported as 0. |
| DTLS | In the peer connection: DTLS 1.3 session resumption other than between the transports of one connection (that one is an opt-in, see "Standing departures from a SHOULD"), external PSKs, 0-RTT and post-handshake authentication, and DTLS 1.2 session resumption by session id and RFC 5077 ticket (implemented in `rtci-dtls`, off in the engine) | DTLS 1.3 itself, RSASSA-PSS, the hybrid ML-KEM group, connection ids for both versions and DTLS 1.3 pre-shared keys (tickets, resumption, external PSKs) are implemented (`conformance/w3.md`). WebRTC authenticates each association by the fingerprints of its SDP and makes a new one per session, so by default the engine issues no ticket, keeps no session cache or store and offers no PSK, session id or ticket, and with `with_dtls_session_resumption(true)` only DTLS 1.3 tickets of the same connection, never a DTLS 1.2 session id or ticket (`the_engine_neither_offers_nor_accepts_a_dtls12_resumption`); a configuration with a DTLS 1.2 pre-shared key negotiates DTLS 1.2. 0-RTT, off by default in `rtci-dtls` too, needs the cookie exchange off. |
| DTLS | Renegotiation | RFC 8827 section 6.5 forbids renegotiation in WebRTC and DTLS 1.3 removed it: a request is refused with the no_renegotiation warning (RFC 5746). |
| DTLS in SDP | Listening for a ClientHello before the answer (RFC 8842 5.2); a new 3-tuple for a new association (RFC 8842 5.1, 6); the old association kept while a new one forms (RFC 8842 5.5) | Transports start with the remote description, and the answerer's retransmitted ClientHello is what the offerer takes. The engine has no sockets: the application decides which candidates a new association runs on. |
| STUN | NAT behaviour discovery (RFC 5780): the discovery procedures, CHANGE-REQUEST / RESPONSE-PORT / PADDING as typed attributes; backwards compatibility with RFC 3489 (no magic cookie); resending a request after a 5xx; resolving a server name (SRV, A / AAAA) and (D)TLS to a STUN server | RFC 5780 is experimental and outside the WebRTC specification set; RESPONSE-ORIGIN and OTHER-ADDRESS are encoded and decoded, the rest are code points. RFC 3489 compatibility and the 5xx resend are optional in RFC 8489 (§11, §6.3.4). `rtci-stun` performs no I/O: the application resolves names (`Uri::srv_query_name`, `Uri::port_or_default`) and owns the connection. |
| TURN | A TURN server; relay candidates with transport TCP | Never claimed. The TURN client is implemented, TCP allocations (RFC 6062) included, but ICE gathers no relayed TCP candidate from one. |
| SRTP | AEAD double (RFC 8723), EKT, the SEED and ARIA transforms | Never claimed. |
| SRTP | AES-f8 (RFC 3711 4.1.2) | Optional in RFC 3711 (section 5 makes AES-CM, the NULL cipher and HMAC-SHA1 mandatory), with no DTLS-SRTP code point in the IANA registry. To add it: `k_e`, `k_s`, `k_a` as for AES-CM; `IV' = E(k_e XOR m, IV)` with `m = k_s \|\| 0x555..5`; `S(j) = E(k_e, IV' XOR j XOR S(j-1))`, `S(-1) = 0`; the SRTP IV is `0x00 \|\| M \|\| PT \|\| SEQ \|\| TS \|\| SSRC \|\| ROC` and the SRTCP IV `0..0 \|\| E \|\| SRTCP index \|\| V \|\| P \|\| RC \|\| PT \|\| length \|\| SSRC` (4.1.2.2, 4.1.2.3); at most 2^32 blocks per IV; test vectors in Appendix B.1. It needs only `RTCCrypto::block_encrypt` and a third `Cipher` implementation beside the two in `rtci-srtp/src/cipher/`. |
| SRTP | `<From, To>` master key lifetimes (RFC 3711 8.1.1) | Optional. Re-keying is by MKI (`Context::add_master_key`) or a new DTLS-SRTP handshake. |
| SRTP | Negotiation of an MKI (`use_srtp` `srtp_mki`), of RFC 6904 (`urn:ietf:params:rtp-hdrext:encrypt`), and of the NULL-cipher and RFC 6188 counter-mode profiles by a peer connection | `rtci-srtp` implements all of them ([SRTP claims](conformance/w3.md)); a peer connection negotiates none. The NULL cipher is forbidden in WebRTC (RFC 8827 6.5), the RFC 6188 suites have no DTLS-SRTP code point, and browsers use Cryptex (RFC 9335), not RFC 6904. |
| SFrame | An SFrame RTP payload format (draft-ietf-avtcore-rtp-sframe), its SDP signalling, a transceiver switch | `rtci-sframe` encrypts and decrypts; the application packetizes the ciphertext and signals its use. |
| FEC | For RFC 8627 FlexFEC: answering FlexFEC only when offered with RTX (1.1.7), refusing an offer over its `repair-window` (5.2.1), adapting the amount of FEC to loss (8) | The RFC 8627 coder itself is implemented (opt-in, `video/flexfec`; [conformance/w4.md](conformance/w4.md)). libwebrtc answers both FlexFEC and RTX, and the engine does the same. |
| Identity | `peer_identity`, identity providers, making and verifying assertions | Applications (Deno, for one) implement webrtc-identity above the engine, which carries the `a=identity` attribute for them (`set_identity_assertion`, `remote_identity_assertion`). |
| RTP | H.264 interleaved mode in negotiation (`rtci-rtp` packetizes and depacketizes STAP-B / MTAP / FU-B and de-interleaves; no codec the engine registers offers `packetization-mode=2`); `scalabilityMode` on an encoding | Simulcast is implemented. The SVC modes, their layer structures and their signalling (VP8 / VP9 payload descriptors, AV1 with the Dependency Descriptor) are in `rtci-rtp` for an application to use ([conformance/w4.md](conformance/w4.md)); the encoding parameter, its validation and offering the Dependency Descriptor by default are not. |
| W3C API | `RTCDTMFSender` | Applications implement DTMF above the engine, with `rtci-rtp`'s telephone-event packets and sender state machine (`codec::telephone_event`); the engine sends the packets it is given. |
| TURN | A TURN server; relay candidates with transport TCP | Never claimed. The TURN client is implemented, TCP allocations (RFC 6062) included, but ICE gathers no relayed TCP candidate from one. |
| STUN | NAT behaviour discovery (RFC 5780): the discovery procedures, CHANGE-REQUEST / RESPONSE-PORT / PADDING as typed attributes; backwards compatibility with RFC 3489 (no magic cookie); resending a request after a 5xx; resolving a server name (SRV, A / AAAA) and (D)TLS to a STUN server | RFC 5780 is experimental and outside the WebRTC specification set; RESPONSE-ORIGIN and OTHER-ADDRESS are encoded and decoded, the rest are code points. RFC 3489 compatibility and the 5xx resend are optional in RFC 8489 (§11, §6.3.4). `rtci-stun` performs no I/O: the application resolves names (`Uri::srv_query_name`, `Uri::port_or_default`) and owns the connection. |
| SCTP | RACK-TLP | Never claimed; none is needed for a browser data channel. |
| TURN | TCP allocations (RFC 6062), a TURN server | Never claimed. The TURN client is implemented. |
| SRTP | AEAD double (RFC 8723), MKI, EKT | Never claimed. |
| FEC | FlexFEC as RFC 8627 | Only draft-ietf-payload-flexible-fec-scheme-03 is implemented, and the codec name is matched exactly so RFC 8627 `flexfec` is never fed to it. |
| RTP | H.264 STAP-B / MTAP / FU-B (interleaved mode, never offered); SVC layer packetization for VP9 and AV1 | Simulcast is implemented; SVC is not claimed. |
| Identity | `peer_identity`, identity providers | Applications (Deno, for one) implement webrtc-identity above the engine. |
| W3C API | `RTCDTMFSender` | Applications implement DTMF above the engine; the engine sends the telephone-event packets it is given. |
| Test platforms | The real-network environment and browser interop run on Linux only | They need network namespaces. Unit and integration tests run on Linux, macOS and Windows. |
| Web platform tests | WPT | They test a browser API, not this crate; the Deno integration runs them. |

## Specified, not started

Two pieces of the BUNDLE / JSEP model were written down here as the work they were, with the
audit rows they would close. Both are now implemented (mt-1 to mt-6); the "Done" paragraphs
below say what each step did and the last one what is left.

### Several BUNDLE groups (size M)

RFC 9143 section 5 lets a description carry more than one `a=group:BUNDLE` line, each m=
section in at most one of them. Today `bundle_groups` (`src/peer_connection/sdp/mod.rs`) reads
every group line, but the answer (`BundleMode::Answer(Some(group))`) and the transport
attributes (`tagged_section`, `extract_ice_details`) use the first group only: sections of a
second group are treated as outside any group and answered with port zero.

A group is a transport, so the whole of this piece depends on the next one. The part that is
its own:

1. Parsing. `bundle_groups` already returns every group. Done: a description in which a mid
   is in two BUNDLE groups is refused (`apply_set_remote_description`, `SdpInvalidValue`):
   RFC9143-5-1 (`a_mid_in_two_bundle_groups_refuses_the_description`).
2. Offers. Keep generating one group: nothing in RFC 9429 has a JSEP endpoint offer several
   (sections 5.2.1 and 5.2.2 speak of "the" BUNDLE group). A subsequent offer after a remote
   offer with several groups repeats the groups of the most recent answer
   (`MediaSection` gains the index of its group; `populate_sdp` writes one `a=group:BUNDLE`
   line per index, the tagged section first): RFC9429-5.2.2-28 for the multi-group case.
3. Answers. `BundleMode::Answer` carries `Vec<Vec<String>>`. Each offered group is answered
   on its own: its first accepted tag is the answerer-tagged section, only that section
   carries the BUNDLE attributes (RFC 9143 section 7.1.3), a section is never moved between
   groups (section 7.3): RFC9143-5-2, RFC9143-7.3-1 (multi-group part), RFC9429-5.3.1-31.
4. Receiving an answer. `check_answer_against_offer` already compares the groups of the two
   descriptions as sets per group; add the rule that the answer's group *i* is a subset of
   the offer's group *i* and not of another: RFC9143-7.4-1, RFC9143-7.3.2-2.
5. Transport selection. Every lookup of "the transport of this m= section" (ICE credentials,
   DTLS fingerprint and role, candidates by `sdpMid`, the SRTP context, the RTP stream
   tables of RFC 9143 section 9.2) goes through the section's group, which is the
   multi-transport piece below.
6. Tests: an offer with two groups is answered with two groups, each with its own
   credentials; a mid in two groups is refused; a subsequent offer keeps the two groups; a
   packet is delivered through the transport of its group and an SSRC is looked up in that
   group's table only.

Rows: RFC9143-5-1, RFC9143-5-2, RFC9143-7.3-1, RFC9143-7.3.2-2, RFC9143-9.2-2 (per group),
RFC9429-5.2.2-28, RFC9429-5.3.1-31.

### Several transports (size L)

A peer connection here has one ICE agent, one DTLS endpoint and association, one SRTP context
pair and one SCTP association (`PipelineContext` in `src/peer_connection/handler/mod.rs`).
RFC 9429 has an m= section that is not bundled into another one own a transport: its own ICE
credentials and candidates, DTLS association and SRTP keys. That is what an initial offer
means for each section that is not bundle-only, what an answerer has to give a section
offered outside a BUNDLE group or moved out of one, and what an offerer falls back to when
the answer has no BUNDLE group.

Done (mt-1): the indirection. The ICE, DTLS and SRTP contexts are a `TransportSet`
(`src/peer_connection/handler/transport_set.rs`) of transport bundles keyed by a transport id,
reached through `default()`, `transport(id)`, `transport_for(mid)` and the data transport the
SCTP association runs over; `handle_read` routes a datagram to a transport before the pipeline
reads it; the sender's, receiver's and SCTP transport's `transport()` name their section's
transport. The set holds one transport, so no row changes with it; the items below fill it.

Done (mt-2): items 1 to 6 and 9 for sections outside a BUNDLE group, in
`src/peer_connection/transport_layout.rs`. A remote offer's sections outside its group get a
transport each, started with the answer from their own part of the offer; a `max-compat` offer
gives every section one; an answer settles the layout (bundled sections move to the tagged
section's transport, the others close). The default transport keeps the single-transport
description handling (deferral to the answer, rollback, ICE restart); the others are set up
through the same `apply_remote_transport` on their part of the description. Datagrams go to
the transport that gathered on their local address (a transport needs local addresses of its
own), outgoing RTP and RTCP to the transport of their SSRC's section, SCTP to the data
section's; the SCTP and data channel handlers see only the data transport's DTLS. The
application learns what to gather for from `ice_transport_sections()`. Tests:
`tests/multi_transport_rtc2rtc.rs` (audio, video and data on three transports; a bundling
answer leaving one), `set_description_atomic_test.rs`, the aggregation tests in
`transport_set.rs`, and the browser scenario "unbundled: max-compat without a BUNDLE group".
Done (mt-4): transport identity. Every transport fires its own events
(`RTCPeerConnectionEvent::OnTransportEvent`, naming its ICE and DTLS transports; the variants
that name no transport are the default transport's), local candidates name their transport and
go through one path whatever the transport, the gathering state aggregates every transport (W3C
4.3.2), `dtls_transports()` / `dtls_transport_by_id` give the handles, and the statistics have
a `transport` object per transport (`src/statistics/accumulator/transports.rs`: the handlers
update the active transport's, the others are parked).
Done (mt-5): `balanced` initial offers give the first section of each media type a transport
(`plan_offer_transports`). Done (mt-6): several BUNDLE groups, each a transport
(`transport_groups`, `BundleMode` with the groups, `arrival_mids` for the per-group payload
type and MID tables); a later offer keeps the groups of the most recent answer.
Done (mt-7): the transports share the first transport's ICE credentials by default (browser
form; Pion and webrtc-rs 0.17 refuse a description whose sections differ, so the `balanced`
default offer of mt-5 did not reach them); `with_unique_transport_credentials(true)` is RFC
9429 5.2.1's unique credentials, and the multi-transport tests run both. An end-of-candidates
that names no section ends every transport's gathering, so a single-socket application
completes. (Routing on a shared port then needed the unique credentials; mt-9 below.)
Done (mt-8): ICE restart and DTLS per transport (`stage_ice_restart_on_every_transport`,
`apply_staged_ice_restarts`, `defer_other_remote_transports`, `PendingRemoteTransport::
other_restarts`): `restart_ice` restarts all, a remote offer restarts the transports whose
credentials it changes, each transport writes and checks its own `a=tls-id`, a rollback undoes
each; the connection state follows W3C 4.3.3 over the aggregate ICE state (exhaustive unit
tables in `transport_set.rs`), consent per transport shown rtc-to-rtc. Sections moving into a
group (the transport discarded) and out of one (a transport of its own) by a remote offer, a
rejected section's transport released at once, and three transports on one local socket (with
unique credentials) are tested; transport counters are per transport.
Done (mt-9): several transports on one local socket with the default (shared) credentials.
The receiver's ufrag of a Binding request names every transport then, so a datagram that
arrives on a local address several transports gathered on goes to the first of these rules
that leaves one transport (`TransportSet::route`, `src/peer_connection/handler/transport_set.rs`):

1. a Binding request: the transports whose local ufrag is the receiver's part of the USERNAME
   and whose remote ufrag, once known, is the sender's part (RFC 8445 section 7.2.2; a peer
   with credentials of its own per transport is told apart here, as is any peer by unique
   local credentials);
2. the transport that sent on this 5-tuple, or read a request on it that a rule settled
   (every datagram a transport writes on a shared address is recorded,
   `TransportSet::learn_path`; a 5-tuple two transports claim decides nothing);
3. the transport that knows the sender as a remote candidate (signalled with its section's
   `sdpMid`, or peer-reflexive from a check it answered);
4. a Binding request: the transport an earlier request with the same tie-breaker
   (ICE-CONTROLLING / ICE-CONTROLLED) was routed to, when the remote's agents have one each
   (an `rtci` peer; a browser has one per connection, and a tie-breaker two transports saw
   decides nothing).

A Binding request none of these settles (shared credentials, from an address no transport has
signalled, sent to or answered) goes to no transport: answered by the wrong one it would give
that transport a peer-reflexive candidate on another transport's path, and the two would
connect crossed. It is dropped, and the remote's retransmission (RFC 8445 section 14.3) is
routed once a candidate has been signalled or a check sent on the path. Anything else none of
the rules settles goes to the default transport, as before. A remote that sends every check
from addresses it never signals (all of them peer-reflexive, behind an address-dependent NAT)
to transports that share credentials and one local socket cannot be told apart by anything a
datagram carries: with such a peer, use `with_unique_transport_credentials(true)` or a socket
per transport. Tests: `transport_set.rs`
(`a_port_shared_with_shared_credentials_is_routed_by_username_path_candidate_and_tie_breaker`)
and `tests/multi_transport_rtc2rtc.rs::three_transports_share_one_port_with_shared_credentials_through_the_drivers_mux`
(three transports on one port behind the reference driver's `UfragMux`, the remote's
candidates arriving late, no transport on another's path).
Done (mt-9) too: this side moving a section out of a BUNDLE group and back
(`RTCRtpTransceiver::set_bundle_request`, RFC 9143 sections 7.5.1 and 7.5.2: the next offer
leaves the tag out of the group, without `a=bundle-only`, and gives the section a transport of
its own; `plan_offer_transports` keeps the group's transport for the group); bandwidth probing
per transport (`each_transport_probes_its_own_path`, which found the NACK responder filling
every transport's probe clusters on one transport's RTX stream, fixed); `renew_dtls_association`,
which the security stack's automatic re-keying calls, renews every transport's association,
each writing its own new `a=tls-id` and running its own handshake; the transports an answer leaves unused fire "closed" at their DTLS and
ICE transports (W3C 4.4.1.6).
Left: several transports on one 5-tuple (impossible once DTLS runs), the remote of the
paragraph above, an ICE-TCP connection accepted on a passive port several transports share
when both sides share their credentials and the remote's tie-breakers have not been seen on a
datagram path (only a check whose full USERNAME, or whose tie-breaker, names one transport ties
a connection to it, `route_named`: such a port needs `with_unique_transport_credentials(true)`
on one side; `a_shared_passive_port_with_shared_credentials_is_tied_by_the_full_username_or_tie_breaker`), moving the data section out of a group (the API is per transceiver), and the
"closed" events of a connection all of whose sections are rejected (one transport, which the
engine keeps for the next offer). With the security stack's renewal (`conf/sec-11-auto-rekey`, which also restarts ICE) RTP of
every transport flows under the new keys (`renewing_the_dtls_association_renews_every_transport`,
mt-10); without it, media after a renewal was lost when this side offered as DTLS server. The RTCP session, transport-wide numbering, congestion
controller and pacer are per transport since the media stack's `PerRtpSession`
(`conf/media-11-train-fixes`, merged at mt-8).

1. The transport as a value. `Transport { id, ice: IceTransport, dtls: DtlsTransport, srtp
   contexts, selected pair, stats }` replaces the single fields of the handler contexts
   (`IceHandlerContext`, `DtlsHandlerContext`, `SrtpHandlerContext`); `PipelineContext` holds
   `Vec<Transport>` and a map from mid to transport index. SCTP stays one association, on
   the transport of the data section. `RTCDtlsTransport` and `RTCIceTransport` handles become
   per transceiver, as W3C webrtc-pc has them (`sender.transport`, `receiver.transport`,
   `sctp.transport`), and several distinct ones can exist.
2. Demultiplexing. The first stage of the read path (`handler/demuxer.rs`, RFC 7983) is per
   transport; which transport a datagram belongs to is decided before it, by the local
   candidate it arrived on, and for a datagram on a shared socket by the ICE username of its
   STUN binding request (`<remote ufrag>:<local ufrag>`), then by the 5-tuple that request
   validated. `handle_read` takes the datagram's local address, as it does today.
3. Gathering. The application adds local candidates per transport: `add_local_candidate`
   takes the mid (or m= line index) the candidate belongs to, and the candidate events name
   it. With the bundle policy the count of transports to gather for is known before the offer
   (RFC 9429 section 4.1.1): `balanced` one per media type, `max-compat` one per m= section,
   `must-bundle` one. Bundle-only sections get none.
4. Offers. An initial offer writes each transport's own ufrag, pwd, fingerprint, setup and
   candidates in the sections that own one (the BUNDLE attributes of RFC 9143 section 7.1.3,
   "each bundled 'm=' line can contain a different set"), and the default candidate of that
   transport in `m=` / `c=`: RFC9143-7.2-1, RFC9429-5.2.1-13, 5.2.1-14, 5.2.1-40, 5.2.2-7.
5. Answers received. When the answer bundles, the transports of the sections bundled into
   the tagged one are closed (their candidates released, an event per closed transport) and
   their transceivers point at the tagged section's transport. When it does not, or moves a
   section out, each keeps its own: RFC9143-7.4-3, RFC9143-7.3.2-1, RFC9429-5.11 (transport
   steps).
6. Answers generated. A section offered outside any BUNDLE group, or with a transport the
   answerer keeps separate, is answered with its own credentials and candidates instead of
   being rejected by the policy (`populate_sdp`, the `BundleMode::Answer(None)` arm):
   RFC9429-5.3.1-8, 5.3.1-9, 5.3.1-19, RFC9143-7.3.2-1.
7. RTCP without multiplexing stays out: every transport multiplexes (`a=rtcp-mux-only`), so
   the component-2 rows (RFC9429-5.2.2-11, 5.3.2-9, RFC9143-9.3.1.1-3) stay `n/a`.
8. Rollback. A transport created by an offer that is rolled back is closed and its
   candidates released (W3C "set a session description", rollback steps; RFC 9429 section
   5.7). With one transport this is done: a remote offer's transport part waits for the
   answer, and a local offer's ICE restart is taken back by its rollback
   (`Agent::apply_restart_revertible`), so RFC9429-5.7-7 is tested; a second transport adds
   "close the transports the offer created".
9. Connection state. `RTCPeerConnectionState` and `RTCIceConnectionState` aggregate over the
   transports as W3C webrtc-pc sections 4.3.2 and 4.3.3 define (any failed: failed; all
   connected or completed: connected). Statistics get one `transport` and its candidate
   pairs per transport.
10. Tests, in the simulated network of the rtc2rtc tests: `max-compat` with audio and video
    to an answerer that does not bundle (two transports, both carry media); the same offer to
    one that bundles (the second transport closes, media moves to the first); a section moved
    out in the answer; an answer without a BUNDLE group; rollback of an offer that added a
    transport; a datagram for transport B arriving on A's candidate is dropped; and against
    the webrtc 0.17 test peer with `balanced`.

What blocks it, measured on the code (jsep7, 2026-11-22): the single transport is not one
field but the shape of the read and write paths. `PipelineContext` holds one
`IceHandlerContext`, `DtlsHandlerContext`, `SrtpHandlerContext` and SCTP context; the
handlers in `src/peer_connection/handler/` (18 k lines with their tests) take those contexts
directly; `RTCPeerConnection` reaches the transport through `ice_transport()` /
`dtls_transport()` and their `_mut` forms at 184 call sites in `src/`. Items 1, 2 and 9 change every one of them, and
item 2 adds a routing step in front of the demuxer. That is the transport-layer rewrite the
task excludes; its size is L (about 3 to 5 k lines of change, plus the tests of item 10). The
pieces that do not need it are done (several BUNDLE groups, item 1; rollback, item 8).

Rows: RFC9143-7.2-1, RFC9143-7.3.2-1, RFC9143-7.4-3, RFC9143-9.3.1.2-3 (moved-out part),
RFC9429-5.2.1-13, 5.2.1-14, 5.2.1-40, 5.2.2-7, 5.2.2-10, 5.3.1-8, 5.3.1-9, 5.3.1-19, 5.3.2-5,
5.7-7, RFC9429-4.1.1-3 (the "one transport all the same" note), RFC8839 rows on the default
candidate in `m=` / `c=`, and the W3C webrtc-pc rows on `RTCDtlsTransport` per transceiver.
What it does not close: a separate RTCP component (item 7).

### Execution order (one branch per step)

The two pieces above as a sequence of branches, each of which leaves master correct (one
transport still works at every step) and closes rows of its own. Owner: the multi-transport
work (`conf/mt-*`); T1 is done by `conf/mt-1-transport-set` (`TransportSet` in
`src/peer_connection/handler/transport_set.rs`), and that work may reorder the rest. Run every step through the
train's browser matrix before the next; steps 4 to 9 change what is on the wire.

| Step | Branch content | Files touched | Rows it closes |
|---|---|---|---|
| T1 | `Transport` value: move the ICE / DTLS / SRTP state of `IceHandlerContext`, `DtlsHandlerContext`, `SrtpHandlerContext` into `struct Transport` held as `Vec<Transport>` (length 1) plus `mid -> index` in `PipelineContext`; `ice_transport()` / `dtls_transport()` take the index of transport 0. No behaviour change | `src/peer_connection/handler/{mod,ice,dtls,srtp}.rs`, `src/peer_connection/mod.rs`, `internal.rs`, `dtls_sdp.rs` (the 184 call sites) | none (refactor; the whole suite is the test) |
| T2 | Per-transport read routing: a datagram is given to a transport by its local candidate, then by the STUN USERNAME (`<remote ufrag>:<local ufrag>`) and the validated 5-tuple, before the RFC 7983 demuxer | `handler/demuxer.rs`, `handler/ice.rs`, `handler/mod.rs` (`handle_read`) | none yet; unit tests for the routing (a datagram for B on A's candidate is dropped) |
| T3 | Gathering per transport: `add_local_candidate` and the candidate events carry the mid; `bundle_policy` decides the number of transports before the offer (RFC 9429 4.1.1) | `src/peer_connection/mod.rs` (`add_local_candidate`, events), `transport/ice/mod.rs`, `configuration/mod.rs` | WEBRTC-4.2.4-1, WEBRTC-4.2.4-2 (gathering part), RFC9429-4.1.1-3 |
| T4 | Initial offers with one transport per non-bundle-only section: own ufrag / pwd / fingerprint / setup / tls-id / candidates and default destination per section | `sdp/mod.rs` (`populate_sdp`, `add_transceiver_sdp`, `default_candidate`), `dtls_sdp.rs`, `internal.rs` (`offered_local_candidates`) | RFC9143-7.2-1, RFC9429-5.2.1-13, 5.2.1-14, 5.2.1-40, 5.2.2-7 |
| T5 | Received answers: bundled sections' extra transports close (candidates released, event), transceivers point at the tagged transport; an answer without BUNDLE or with a section moved out keeps each transport | `src/peer_connection/mod.rs` (`apply_remote_transport`, `apply_remote_description`), `transport/` | RFC9143-7.4-3, RFC9143-7.3.2-1, RFC9143-9.3.1.2-3, RFC9429-5.11 transport steps, 5.2.2-10 |
| T6 | Generated answers: a section offered outside any group (or kept separate) is answered with its own transport instead of rejected | `sdp/mod.rs` (`BundleMode::Answer(None)`), `internal.rs` (`generate_matched_sdp`), `mod.rs` (`defer_remote_transport` per transport) | RFC9429-5.3.1-8, 5.3.1-9, 5.3.1-19, 5.3.2-5, RFC9143-7.3.2-1 (answerer part) |
| T7 | Several BUNDLE groups: `MediaSection` carries its group index, `BundleMode::Answer(Vec<Vec<String>>)`, one `a=group:BUNDLE` per group in answers and later offers, answer group *i* a subset of offer group *i* | `sdp/mod.rs` (`bundle_groups`, `tagged_section`, `populate_sdp`), `internal.rs` (`check_answer_against_offer`) | RFC9143-5-2, 7.3-1, 7.3.2-2, 7.4-1, 9.2-2 (per group), RFC9429-5.2.2-28, 5.3.1-31 |
| T8 | Rollback closes the transports the rolled-back offer created; connection and ICE connection states aggregate over transports (W3C 4.3.2, 4.3.3); one `transport` stats object and its pairs per transport | `internal.rs` (rollback, `update_connection_state`), `src/statistics/` | RFC9429-5.7-7 (several-transport part), W3C 4.3.2 / 4.3.3 aggregation rows, W3C RTCDtlsTransport-per-transceiver rows |
| T9 | Interop: rtc2rtc tests of section 10 above, the webrtc 0.17 peer with `balanced`, and the browser matrix with `max-compat` | `tests/` | the `partial` notes "one transport" in rfc9143.md, rfc9429.md, rfc8839.md (default candidate per section) |

## Known bugs

None open is the bar for calling a release conformant: each bug found is either fixed, with a test
and a row in its area's fragment, or its claim is withdrawn and the feature moves to the table
above. An open bug is listed here, with its spec section and the issue that tracks it, until then.

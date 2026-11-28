# Key erasure in rtci-dtls, rtci-srtp and rtci-crypto

The rule: memory a secret was in is overwritten before it is freed. Every struct holding secret
key material derives `Zeroize` and `ZeroizeOnDrop`, or holds each secret in a type that does
(`crypto::SecretVec`, `zeroize::Zeroizing`). Key material is never built in a buffer that
grows: a `Vec` that grows moves to a new allocation and frees the old one as it is. Clauses:
RFC 5246 section 8.1 (the premaster secret is deleted once the master secret exists), RFC 8446
section 7.1 (a secret is erased once what derives from it is computed), RFC 7714
section 13.1 (SRTP keys, and a secret master salt, erased when no longer needed; RFC 3711 itself
has no erasure clause: its section 3.2.1 has the master key "kept secret").

## What holds what

| Secret | Where it lives | Erased (0.1.0) | Erased now | Test |
|---|---|---|---|---|
| (EC)DHE private scalar | the provider's key-exchange object (`ring::agreement::EphemeralPrivateKey`, AWS-LC) | ring: no (the freed key-exchange object kept it: 1 block per exchange, X25519 and P-256, measured with the 0.1.0 code path as mutation m6) | ring: yes (`ErasedOnDrop`; `into_inner` overwrites the slot when `agree_ephemeral` consumes the key; the stack copy is scrubbed after key agreement); AWS-LC: its own, not measured | `ring_ecdhe_private_key_and_shared_secret_are_erased` (scalar drawn from a known seed through the test-support seam) |
| (EC)DHE shared secret / DTLS 1.2 premaster secret | `SecretVec` from the provider; `State.pre_master_secret` | no: `into_bytes` to a plain `Vec`, `State` field plain, flight 4's local plain on error paths | yes: `SecretVec` end to end, forgotten once the master secret exists; the stack scrubbed after the provider computes it | `tests/dtls_secret_erasure.rs` (all DTLS 1.2 tests, process test) |
| PSK from the application's callback, PSK premaster secret | flight 3/4 locals | no (plain `Vec`) | yes (`SecretVec` on receipt; premaster built at its size) | `dtls12_psk_and_its_premaster_secret_are_erased` |
| DTLS 1.2 master secret | `State.master_secret`, sessions, tickets | no: `State` field plain; replaced without erasure | yes (`SecretVec`) | `dtls12_secrets_are_erased_for_every_cipher_suite_family`, ticket and serialization tests |
| PRF output and its `A(i)` values (master secret, key block, exporter output) | `prf_p_hash` | no: plain vectors, growing output buffer, truncated copy | yes: zeroizing buffers sized up front, HMAC keyed once | `tests/dtls_srtp_keying_material_erasure.rs::dtls12_*`, `dtls12_secrets_*` |
| Key block: client/server write keys, MAC keys, write IVs | `EncryptionKeys`; the record ciphers' IVs | no; `EncryptionKeys` printed every key in `Display`/`Debug` | yes: `EncryptionKeys` and `CryptoGcm`/`CryptoCcm`/`CryptoChaCha20` derive `Zeroize`, `ZeroizeOnDrop`; `Debug` prints lengths; `Display` removed | `dtls12_secrets_*` (the 4-byte AES-GCM/CCM implicit nonces are too short to search for; ChaCha20's 12-byte IVs are searched) |
| Record cipher key schedules | AES-CBC, AES-CCM: RustCrypto `aes` in the crate's objects; AES-GCM, ChaCha20: the provider | CBC/CCM no (`aes` without `zeroize`) | CBC/CCM yes (`aes`, `ctr` with `zeroize`); stack scrubbed after each is built | `dtls12_secrets_*`, `dtls13_secrets_*` (CCM) |
| Finished verify data inputs | master secret / finished keys (above) | as above | as above | as above (verify_data itself is sent, not secret) |
| DTLS-SRTP exporter output | `export_keying_material` returns `SecretVec` | DTLS 1.2: no (PRF); DTLS 1.3: yes | yes | `dtls_srtp_keying_material_erasure.rs` |
| DTLS 1.3 key schedule secrets, traffic secrets, exporter/resumption secrets | `KeySchedule`, `ReadEpoch.secret`, sessions | yes (`SecretVec`) | yes | `dtls13_secrets_are_erased_across_key_updates` |
| DTLS 1.3 traffic keys, record-number keys | the provider's AEAD and header-mask objects | ring: no; AWS-LC: yes | yes: ring's objects in an `ErasedOnDrop` allocation, overwritten after the drop | as above (ring's objects no longer left out of the search); `rtci-crypto/tests/ring_key_object_erasure.rs` |
| DTLS record keys of the AES-GCM and ChaCha20-Poly1305 suites; PRF, HKDF and cookie HMAC keys (HMAC-SHA-256/384) | ring provider: `ring::aead::LessSafeKey`, `ring::hmac::Key`; AWS-LC: its own | ring: no | yes (`ErasedOnDrop`) | `dtls12_secrets_*`, `ring_key_objects_are_erased_when_dropped` (the HMAC states are searched for there) |
| DTLS 1.3 record IVs | `RecordKeys` | no: inline in epochs kept in vectors that grow (copies freed), plain store in `Drop` | yes: `SecretVec` in the heap | `dtls13_secrets_*` (found in 0.1.0 code by the scan) |
| Resumption PSK (1.3), ticket keys, ticket plaintexts | `TicketIssuer`, `seal`/`open` | keys yes; plaintexts grew while built (copies freed) | yes: plaintexts sized up front; keys drawn with `fill_secret` | `dtls12_ticket_keys_*`, `dtls13_resumption_*` |
| External PSK (1.3) | `ExternalPsk` (`SecretVec`) | yes | yes | `dtls13_resumption_and_external_psk_secrets_are_erased` |
| Cookie secrets (1.2 HelloVerifyRequest, 1.3 HelloRetryRequest) | `CookieSecrets` in the endpoint; the HRR secret | no: the previous secret (after a rotation) was never erased; drawn from the buffered generator, whose output buffer kept them (the current secret taken out with `take()` was not observed left behind) | yes: both overwritten in place; drawn with `RTCRandom::fill_secret` | `cookie_secrets_are_erased_with_the_endpoint` (rotates, looks for both) |
| Serialized `State` (`marshal_binary`) | the returned bytes; `SerializedState` | intermediate copies freed as they were | intermediate copies erased, output written once at its size | `dtls12_state_serialization_leaves_no_master_secret_behind` |
| Certificate private key (PKCS#8) and the provider's parsed key pair | provider `SigningKey` (`pkcs8_der: SecretVec`; ring's `Ed25519KeyPair` / `EcdsaKeyPair` / `RsaKeyPair`); PEM import copy | ring key pair: no (1 freed block per key, Ed25519 and P-256, measured with the 0.1.0 layout as mutation m7); import copy plain | ring Ed25519/P-256 key pairs: yes (`ErasedOnDrop`); `pkcs8_der` and the import copy `SecretVec`; ring's RSA key pair keeps its private limbs in heap allocations of ring's own, which the crate cannot reach (by reading ring 0.17.14; not measured); the application's own copies (`pem`/`rcgen` buffers, the PKCS#8 it supplies) are its to protect | `ring_signing_key_objects_are_erased_when_dropped` (Ed25519 secret prefix, P-256 scalar in ring's Montgomery form) |
| SRTP master keys and salts | `SessionKeys` | yes (manual `Drop`) | yes (`Zeroize`, `ZeroizeOnDrop`) | `rtci-srtp/tests/key_erasure.rs` |
| SRTP session keys, salts, KDF output | `SecretVec` | yes | yes | `rtci-srtp/tests/key_schedule_erasure.rs` |
| SRTP AES-CM key schedules (payload cipher of the AES-CM profiles; RFC 6904 header-extension keystream of every profile) | 0.2.0: the key in a `SecretVec`, expanded into both AES schedules on the stack for every packet. Now: the expanded schedule in the boxed cipher object (`AesCtr`), used through a reference | heap: yes; stack: no (never observed in 0.1.0 / 0.2.0; measured for this change: both schedules of the SRTCP and header-extension keys in dead stack frames after every packet) | yes: nothing is expanded per packet; the object is overwritten whole when dropped and built over overwritten stack | `rtci-srtp/tests/key_residue.rs`, `key_schedule_erasure.rs` |
| SRTP HMAC-SHA1 states (AES-CM, NULL profiles) | ring provider: RustCrypto `hmac` / `sha1` in a boxed object; AWS-LC: `HMAC_CTX` | ring: heap no in 0.1.0, yes in 0.2.0; stack no (each MAC was computed on a copy of the keyed object in a stack frame) | ring: yes (`hmac` 0.13, `sha1` 0.11 with `zeroize`; computed in the keyed object, in place). AWS-LC: heap yes, stack NO (its limit, below) | `with_ring_no_key_is_left_in_freed_rust_memory`, `key_residue.rs` |
| SRTP AES-GCM keys and round keys | the provider's AEAD object | ring: no; AWS-LC: yes | yes: ring's `LessSafeKey` in an `ErasedOnDrop` allocation, overwritten after the drop; what building it leaves on the stack is overwritten (`on_erased_stack`) | `with_ring_no_key_is_left_in_freed_rust_memory`, `key_residue.rs`, `aws_lc_*` |
| What building an SRTP context, re-deriving session keys and adding a master key leave on the stack (the master key and both of its AES schedules, session round keys, GHASH key, HMAC states) | dead stack frames of the calling thread | no | yes: run under `crypto::on_erased_stack` | `key_residue.rs` (build, rekey steps) |
| `Debug`/log output | `SecretVec`, sessions, `SessionKeys`, `CryptoPrivateKey`: redacted | `EncryptionKeys`, `SerializedState` printed keys | redacted / no `Debug` | review |

## The ring provider's key objects

ring does not erase its own key objects when they are dropped (its maintainer decided against
destructor-based zeroization, ring issue #15, closed 2025-02-25). Since 0.2 the ring provider
keeps each key object it makes in an allocation of its own, `ErasedOnDrop<T>`
(`rtci-crypto/src/providers/ring.rs`): a `Box<MaybeUninit<T>>` lent out only as `&T`; on drop
the value is dropped in place and then the `size_of::<T>()` bytes are overwritten with volatile
writes before the box is freed. After the drop in place the slot holds no value, so the overwrite
is a write to the crate's own memory and does not depend on ring's layout. It covers
`ring::aead::LessSafeKey` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), `aead::quic::HeaderProtectionKey`
(DTLS 1.3 record-number keys) and `hmac::Key` (HMAC-SHA-256/384/512: the PRF, HKDF and cookie
keys). In ring 0.17 these keep their whole key schedule inline (AES round keys, the GHASH table,
the ChaCha20 key, the two SHA-2 states), with no allocation of their own. Measured: every one is
found live and none is left in freed memory after the drop
(`rtci-crypto/tests/ring_key_object_erasure.rs`, Linux x86_64, macOS arm64, Windows x86_64); the
SRTP and DTLS scans find no key of either provider after the drop, in the heap on every platform
and in the whole process on Linux. Mutations caught: the overwrite removed; the value moved to
another heap block before the drop.

What remains with ring:

- The ECDHE private key (`agreement::EphemeralPrivateKey`) and the Ed25519 and ECDSA P-256
  signing key pairs are kept in `ErasedOnDrop` too (since the second zeroize round); the
  private key is consumed by value by `agree_ephemeral`, so `into_inner` reads it out and
  overwrites the slot. Measured: found live, left in no freed block (before: one freed block
  each). The shared secret is in no freed block either. An RSA signing key pair keeps its
  private limbs in heap allocations of ring's own, freed by ring without erasure: out of the
  crate's reach, the provider's limit (from ring 0.17.14's source; not measured).
- Stack copies in DTLS. Building a key object leaves copies in the dead stack frames of the
  functions that built it, and a value moved out of the wrapper would be a copy it cannot
  reach (the wrapper never moves its value out). The DTLS crate calls `crypto::scrub_stack()`
  after building keyed objects and after key agreement. What the tests show for DTLS: copies
  carried from dead frames into heap padding were found and the scrub removes them (its
  removal is caught, m13 of the first round); DTLS has no stack measurement of the kind SRTP
  has (next section), so for a copy that stays on the stack DTLS is "scrubbed, not measured".
  `scrub_stack` is one bulk zero fill of a buffer in a never-inlined frame (32 KiB in an
  optimised build, 128 KiB in an unoptimised one: `debug_assertions`), made
  observable to the optimiser (`black_box` and a compiler fence) so it is not dropped as a
  dead store; it reaches the stack below its caller only, never registers or the frames above.
  Tested (zeroize3, ubuntu): its body emptied, the DTLS erasure tests fail in debug and release
  builds (runs 45659948616, 45659954724); the fill left unobservable, they fail in a release
  build (45659972471) and pass in a debug build (45659963417: at opt-level 0 nothing is
  removed, so the two cannot be told apart there). Cost: about 0.5 to 0.7 µs per call in an
  optimised build.

## SRTP keys on the stack: what is guaranteed, and how it is known

RFC 7714 section 13.1: "If the master salt is to be kept secret, it MUST be properly erased when
no longer needed", and "The secret master key and all keys derived from it MUST be kept secret.
All keys MUST be properly erased when no longer needed."

**The measurement** (`rtci-srtp/tests/key_residue.rs`). Each step of a session's life runs on a
worker thread whose stack the test maps itself and fills with a known byte: building the
contexts, protecting and unprotecting RTP and RTCP (with RFC 6904 header-extension encryption),
re-keying (an MKI and a key derivation rate of two packets: session keys derived again on the
packet path, a second master key added and the first removed), tearing down. The contexts go
from one worker to the next as boxes, so what a worker's dead frames hold is what that step
left, and the test reads those bytes while the worker waits. Every key the session derives is
looked for in every form: the keys, the AES round keys of both schedules, the GHASH key (as
`H`, as two host-order words, and as the `H·x` table entry of carry-less-multiplication code),
the HMAC padded keys and both SHA-1 states in both word orders, the header-extension keys, each
key derivation epoch, the master key and the master salt. On Linux the whole process is searched
as well, while the contexts are alive (the search must find the keys where they are kept, and
must not find a master-key schedule in the heap) and after the teardown (nothing may be left
outside the workers' dead frames). A control leaves a key on a stack, in the heap, in a freed
block and in static data and finds each, and does not find an erased one. The inventories are
identical, digest for digest, in the test-environment image (glibc 2.39) and on GitHub's
runners (glibc 2.43) with one compiler.

**What 0.2.0 left** (ring provider, rustc 1.99.1, x86-64 Linux: 1943 key forms over the ten
profiles and both ways of keying, 2137 with rustc 1.100; 1995 on AArch64 macOS, the same
picture; the AWS-LC provider 1817):

| Step | `Context::new` | with an MKI and a key derivation rate |
|---|---|---|
| building | 298: the master key and both of its AES schedules (227), SRTCP HMAC-SHA1 states, SRTCP and SRTP round keys, for AES-GCM the GHASH key and table entry | the same |
| packets | 273: both AES schedules of the SRTCP and header-extension encryption keys, HMAC-SHA1 states | 537: the same and, from deriving again, the master key |
| re-keying | n/a | 537, for the new master key |
| tearing down | 0 | 0 |

Nothing outside dead stack frames, ever: no heap block, no other mapping. What a step leaves
is what the last calls at each depth wrote; later calls overwrite earlier residue, so the SRTP
keys are mostly hidden under the SRTCP ones in this table.

**What is done about it**

- Building a context, deriving session keys again and adding a master key run under
  `crypto::on_erased_stack`: the work runs in a frame of its own and the stack below it is
  overwritten afterwards (`scrub_stack`), 32 KiB of it in an optimised build and 128 KiB in an
  unoptimised one. The built-in providers use about 3 KiB there in an optimised build and 42 to
  47 KiB in an unoptimised one, where every temporary has a stack slot of its own: the deepest
  part is the AES key schedules of the key derivation (`common::block_encrypt` holds a cipher
  object of each AES key length in its frame, and `aes` builds the decryption schedule from the
  encryption one in frames below it). With one 32 KiB depth for every build, rustc 1.99.1's
  unoptimised build (the test environment's compiler) left the master key and its AES round
  keys 37.7 to 42.2 KB below the measurement's starting point, beyond the overwrite, in all 20
  measurements of the ring provider (run 45970063627); with rustc 1.100 nothing was left beyond it.
  The unoptimised depth is the deepest use measured (47 KiB) times 2.7. A measured depth (fill
  the stack below with a marker first, overwrite down to the lowest byte the work changed) was
  not taken: it writes the region, reads it back and writes it again instead of writing it once, and in an optimised build, where the
  work uses a tenth of the 32 KiB, it would only add cost to the set-up (row `zeroize-3` of
  docs/performance.md); the optimised depth and cost are unchanged.
- AES-CM: the expanded schedule lives in the boxed cipher object and a packet runs the counter
  mode over a reference to it; nothing is expanded per packet. `aes`'s cipher types are unions
  of a hardware and a larger portable schedule and the bytes of the variant not in use are
  never written by it (they are what the stack held where the value was built), so the object
  is overwritten whole when dropped, used bytes or not, and is built over stack that has just
  been overwritten.
- HMAC-SHA1 (ring provider): `hmac` 0.13 and `sha1` 0.11 with their `zeroize` features; the
  keyed object is boxed and a MAC is computed in it (`update`, `finalize_reset`). The one copy
  the crate makes per MAC (the outer state) is overwritten by the crate when dropped. With
  `hmac` 0.12, as in 0.2.0, each MAC was computed on a copy of the whole keyed object in a
  stack frame: with everything else of this change in place that alone left 42 key forms in an
  optimised build on x86-64 Linux and 36 on AArch64 macOS.
- ring's AES-GCM `seal` / `open` were measured to leave no form of the key in a stack frame
  (x86-64 with AES-NI, AArch64 with the ARMv8 extensions): nothing to do there.

**What is guaranteed, by which test**

| Claim | Where it is asserted |
|---|---|
| ring provider (the default), unoptimised and optimised builds, every profile, both ways of keying: no key the session derives is found in any form in the dead stack frames of the thread that built the contexts, protected and unprotected packets, re-keyed or tore down | `with_ring_key_handling_leaves_no_key_in_dead_stack_frames`, CI job `key_residue`: x86-64 Linux with the workspace's `rust-version` (the oldest supported compiler) and with stable, AArch64 macOS with stable |
| the same thread, the same build: nothing is left anywhere else in the process after the teardown, and no master-key schedule is in the heap while the contexts live | the same test, Linux (whole-process search) |
| either provider, unoptimised and optimised builds: building and tearing down leave nothing in dead stack frames | the same test and `with_aws_lc_building_and_tearing_down_leave_no_key_in_dead_stack_frames`: CI job `key_residue` (both builds, the same compilers and platforms), the ordinary test jobs (Linux, macOS, stable, unoptimised) and the test environment (rustc 1.99.1, unoptimised) |
| HMAC-SHA1 computed in the keyed object is correct and the object is reusable | `rtci-crypto/tests/hmac_sha1_vectors.rs` (RFC 2202 cases 1 to 7), and the SRTP, DTLS and STUN vectors of their crates |

Each part of the fix is held by the first test (mutations): without the overwrite in
`on_erased_stack`, building leaves 874 key forms (run 45886867130); with the overwrite 32 KiB
deep in an unoptimised build too, building leaves the master key and its round keys with rustc
1.99.1 (run 45970063627, where it was found; the mutation `mut/zeroize-4-scrub-32k-in-debug`
reproduces it, run 45983076469: 242 key forms after building, the same inventory digest as the
test environment's failure); with `hmac` and `sha1`
built without `zeroize`, 480 HMAC-SHA1 states are left in freed heap after the teardown
(45886871614); with the AES-CM cipher object built over stack that was not overwritten first,
round keys of the master key are in the heap while the contexts live (45886877182: the unused
bytes of `aes`'s union, carried from the stack). Cost: docs/performance.md, row `zeroize-3`.

**What is not guaranteed**

- **The AWS-LC provider's packet path.** AWS-LC computes each HMAC on a copy of the keyed
  context in a stack frame of its own, and its AES-GCM leaves a GHASH table entry in one: every
  protected or unprotected packet leaves the SRTP / SRTCP HMAC-SHA1 states (AES-CM and NULL
  profiles) or a form of the GCM key in dead stack frames, 78 key forms over the profiles in an
  optimised build and 24 in an unoptimised one (where the overwrite after each AES-CTR
  operation, below, also clears most of the HMAC states; 150 without it with rustc 1.89 and
  1.99.1, runs 46030856312, 46030861874). The engine does not overwrite the stack after every
  packet. `known_limit_with_aws_lc_the_packet_path_leaves_keys_in_dead_stack_frames` (ignored)
  is the limit as a test.
- **Unoptimised builds: what rtci-crypto's profile decides.** At opt-level 0 the AES-NI
  intrinsics of `aes` are calls whose vector arguments go through stack copies, so every block
  of the AES-CTR keystream leaves round keys and AES states in stack temporaries: before
  dtls-34, 72 and 84 to 108 round-key forms of the per-packet AES-CTR key with rustc 1.89 and
  1.99.1 on x86-64 Linux, 18 on AArch64 macOS, none with rustc 1.100 on Linux (runs 45983045311,
  46030856312, 46030861874). Since dtls-34 rtci-crypto overwrites 48 KiB of stack after each
  record operation of RustCrypto's AES in a build with `debug_assertions`
  (`scrub_record_stack`; the next section), and the ring provider's packet path leaves 0 forms
  there with every compiler measured, asserted in every build. The gap: `debug_assertions` is
  rtci-crypto's own profile setting; a custom profile that turns it off for rtci-crypto (or
  optimises rtci-crypto) while `aes` stays at opt-level 0 gets no overwrite and the residue
  above. The test's "stack used" includes the overwrites (about 142 KiB unoptimised, 37 KiB
  optimised).
- **CPU registers, and whatever stores them on a stack.** A provider's AES leaves round keys in
  vector registers when it returns. A signal delivered next puts them into the signal frame; on
  Apple systems the lazy set-up of a thread-local saves the vector registers on the caller's
  stack (seen once during this work: one AES-GCM round key of the ring provider, when a
  thread-local was first used in a thread right after a packet). The engine's packet path uses
  no thread-local and installs no signal handler; it cannot speak for the application's.
- **Windows; architectures other than x86-64 and AArch64.** The code is the same and the heap
  searches run on Windows, but the stack measurement needs a thread on a stack of the test's
  own (`pthread_attr_setstack`) and has run on x86-64 Linux and AArch64 macOS only. On
  processors without the AES and SHA instructions the portable routines of `aes`, `sha1` and
  ring run instead, which nothing here has measured.
- **Deeper than the overwrite.** `on_erased_stack` overwrites 32 KiB below its frame in an
  optimised build and 128 KiB in an unoptimised one (the depth follows `debug_assertions`: a
  build profile with opt-level 0 and `debug-assertions = false` gets 32 KiB, which rustc 1.99.1
  was measured to exceed). A provider supplied by the application that uses more stack than
  that to build a key object leaves what lies deeper.
- **DTLS.** Measured the same way since zeroize-5: the next section.

For an application: nothing is asked of it for SRTP with the default provider. With the AWS-LC
provider, the thread that protects and unprotects packets keeps HMAC-SHA1 states or a GCM key
form in its dead stack frames until later calls on that thread overwrite them; call
`crypto::scrub_stack()` from that thread when a session ends if that matters.

The AWS-LC provider (`crypto-aws-lc-rs`) cleanses its `EVP_AEAD_CTX` and `HMAC_CTX` itself: no
freed block and no other part of the process holds a key after the drop, for every SRTP profile
and the DTLS suites tested. What its packet path leaves in stack frames is in the next section.

## DTLS keys on the stack: what is guaranteed, and how it is known

RFC 5246 section 8.1 (the premaster secret deleted once the master secret exists), RFC 8446
section 7.1 (a secret erased once what derives from it is computed), RFC 7714 section 13.1 for
the SRTP keying material a DTLS-SRTP association exports (RFC 5764 section 4.2).

**Why it matters.** A key left in a dead stack frame does not stay there: the next value built
over that frame and moved into the heap carries it in bytes no field owns (padding, the
payload of a `None`, the unused arm of a union), and that heap block is later freed with the
key in it, which no `Zeroize` can prevent. The heap quarantine test (`tests/dtls_secret_erasure.rs`)
saw it twice on Windows before this work: the exporter output carried by an `Option<Instant>`,
and an AES-CCM write key in a freed 692-byte block (the worked example below). Fixing a carrier
moves the leak to the next one; the source is the dead frames.

**The measurement** (`rtci-dtls/tests/key_residue.rs`, unix; the `owned_stack` module of the
SRTP measurement). Each step of an association runs on a worker thread whose stack the test
maps itself: the configurations and endpoints, every one-way delivery of the handshake, the
DTLS-SRTP export (client and server), four application records each way, two DTLS 1.3 key
updates, the close_notify exchange, the teardown; for ticket resumption the first association's
teardown and the resumed association's steps too. Scenarios, with each provider: DTLS 1.2 with
AES-128-GCM, AES-128-CCM, ChaCha20-Poly1305, AES-256-CBC-SHA and PSK AES-128-GCM, DTLS 1.2 ticket
resumption, DTLS 1.3 with AES-128-GCM, AES-128-CCM and ChaCha20-Poly1305, DTLS 1.3 ticket
resumption. The secrets come from a provider wrapper that records, inverted, every key that
crosses the provider boundary and the first inputs of each HMAC; the test recomputes the PRF
outputs (master secret, `A(i)`, key block, exporter output) and every `HKDF-Expand-Label`
output with the provider's HMAC, and turns each secret into its forms (AES round keys of both
schedules, the GHASH key forms, HMAC padded keys and SHA-1 / SHA-256 states, raw bytes), on a
scratch worker whose stack is overwritten and unmapped, after every step's worker has been
parked. The needles are checked against what the association used (each record key in a
recomputed key block or equal to an HKDF "key" output; the recomputed exporter output equal to
what was exported), and a control step leaves the exported material on its stack and must be
found. Each form is classed:

- *secrets of key derivation*: (EC)DHE shared secret, premaster and master secret, PRF
  intermediates, HKDF secrets, Finished and binder keys, cookie secrets, the exported keying
  material;
- *record keys*: the AEAD, CBC and record-number keys with their schedules, the CBC suite's
  HMAC-SHA1 MAC key;
- *not keys*: IVs and key-block bytes outside every key. A DTLS 1.3 record's nonce is the IV
  XORed with the sequence number, and `RecordKeys::nonce` copies the whole IV into its frame
  before the XOR, so the nonce of a record with sequence number 0 is the IV itself. An AEAD does
  not need its nonce to be secret, and the IV is an independent HKDF output: knowing it gives
  neither the key nor the traffic secret. Counted and printed, not asserted.

**What was left before** (0.2.0 with the SRTP work of zeroize-3 and zeroize-4, whose DTLS
code is 0.2.0's; runs 46006489538, 46007195162, 46007201947; forms over all scenarios,
unoptimised / optimised):

| | ring | AWS-LC |
|---|---|---|
| x86-64 Linux, rustc 1.100 | 138 / 107 | 162 / 168 |
| x86-64 Linux, rustc 1.99.1 | 294 / 159 | 308 / 166 |
| x86-64 Linux, rustc 1.89 | 269 / 114 | 300 / 172 |
| AArch64 macOS, rustc 1.100 | 160 / 110 | 188 / 186 |

Almost all of it HMAC state of secrets of key derivation: the master secret's HMAC states after
every DTLS 1.2 delivery that runs the PRF (key block, Finished verify_data) and after the export
(ring copies the keyed HMAC context onto the stack for every MAC; AWS-LC both states, many
times); the exported keying material itself; the cookie secrets' states (HelloVerifyRequest,
HelloRetryRequest); in DTLS 1.3 the HMAC states and outputs of the key schedule's secrets
(traffic, exporter, resumption secrets, Finished and binder keys). No AES round key was found
in the set-up of any suite, no ticket key, no (EC)DHE shared secret. The deepest form lay 61.5
KB below the measurement's floor (unoptimised; DTLS 1.3, the first delivery to the server, an
HMAC-SHA-256 key's state), 30.4 KB optimised. Teardown left nothing.

**What is done about it.** Six places that derive keys run under `crypto::on_erased_stack`:
`prf_p_hash` (master secret, extended master secret, key block, verify_data, exporter), the
DTLS 1.2 cookie MAC, the DTLS 1.3 key schedule's `expand_label` (every secret but the extracted
ones) and its Finished HMAC (Finished and binder), the DTLS 1.3 exporter, and the DTLS 1.3
HelloRetryRequest cookie MAC. The record path is unchanged. Eight more wraps were tried and
removed: with each taken away alone, every inventory stayed the same byte for byte (run
46010716061): the five DTLS 1.2 suite set-ups (their PRF is `prf_p_hash`, and each cipher's
constructor already overwrites the stack after every provider call), `RecordKeys::new` (it
already overwrites before and after building its key objects) and the two HKDF-Extract steps
(each caller derives a secret through `expand_label` right after, whose overwrite reaches the
same frames). The overwrite depth is the SRTP one (32 KiB optimised, 128 KiB unoptimised); no
DTLS form of any class lay deeper than 38.2 KB below the floor afterwards.

**Cost.** The six wraps run once per derivation, never per record; the record path is
code-identical to zeroize-4. Measured twice against zeroize-4 (`30ea0f57`) on the same runner per
job with `scripts/bench-compare.sh rtci-dtls:record_protection` (ring): the first run (46014777435,
3 rounds) had every benchmark within the gate and one, `DTLS/Decrypt/AES-128-GCM/ring`, at
x1.127; the repeat (46018059811, 5 rounds, three heads with the same record-path code) gave that
benchmark x0.97 for this head, x1.01 for a head whose engine is zeroize-4's and x1.01 for the
14-wrap head: not a property of the change. `DTLS/Handshake/DTLS-1.2/ring` x1.004 and x1.011.
No ledger row and no allowlist entry.

**After** (head `98e3cbd7`; runs 46015289354, 46015302538, 46015308455): no secret of key
derivation in any form, after any step, in any scenario, with either provider, in either build,
with rustc 1.89, 1.99.1 and 1.100 on x86-64 Linux and 1.100 on AArch64 macOS; nothing at all
after the configurations, the connect, the export and the teardown. What is left is the record
path and IVs (forms, unoptimised / optimised):

| | ring | AWS-LC |
|---|---|---|
| x86-64 Linux, rustc 1.100 | 50 / 27 | 58 / 50 |
| x86-64 Linux, rustc 1.99.1 | 195 / 27 | 203 / 50 |
| x86-64 Linux, rustc 1.89 | 182 / 36 | 193 / 64 |
| AArch64 macOS, rustc 1.100 | 76 / 33 | 83 / 77 |

**What is guaranteed, by which test**

| Claim | Where it is asserted |
|---|---|
| either provider, every build: no secret of key derivation in a dead stack frame after any step; no key of any class after the steps that protect no record | `with_ring_dtls_key_handling_leaves_no_key_in_dead_stack_frames`, `with_aws_lc_dtls_key_handling_leaves_no_key_in_dead_stack_frames`: CI job `key_residue` (x86-64 Linux with `rust-version` and stable, AArch64 macOS with stable, unoptimised and optimised); the ordinary test jobs and the test environment unoptimised |
| ring, every build: no record key of an AES suite (AES-GCM, AES-CBC cipher and MAC keys, AES-CCM) after any step | the ring test; AES-CCM in an optimised build from rustc 1.99.1 on (below) |
| AWS-LC, every build: no AES-CBC cipher key and no AES-CCM key (the record path rtci-crypto composes from RustCrypto's AES) | the AWS-LC test; AES-CCM in an optimised build from rustc 1.99.1 on |

Each wrap is held by these tests: with any one of the six taken away alone, both tests fail in
both builds (run 46014737611, `mut/zeroize-5-gated-wraps-2`). The record-work overwrite of an
unoptimised build (below) is held by them too: with it switched off (`RTCI_MUT=M1`, a gate read
once per process, the frames otherwise the same) both tests fail unoptimised with rustc 1.89,
1.99.1 and AArch64 macOS 1.100: 452, 446 and 119 AES-CCM / AES-CBC forms come back (runs
46030856312, 46030861874; with rustc 1.100 on x86-64 Linux there were none to begin with).

**What is not guaranteed**

- **ring's ChaCha20-Poly1305 record path.** It copies the key to the stack for every record:
  DTLS 1.2 key-block bytes of the write keys after the deliveries that seal or open records, the
  records and the close (8 to 10 forms optimised, at most 17.8 KB deep; up to 25.8 KB
  unoptimised).
  Removing the suite set-up's wrap did not change them: they come from the records.
- **AWS-LC's record path.** A GHASH table entry of the AES-GCM key for every record (33 to 36
  forms optimised, DTLS 1.2 and 1.3), and the HMAC-SHA1 states of the AES-CBC suite's MAC key
  (10 forms, 22.7 KB deep optimised, 38.2 KB unoptimised), from AWS-LC's own frames.
  `known_limit_with_aws_lc_the_dtls_record_path_leaves_keys_in_dead_stack_frames` (ignored) is
  the limit as a test.
- **AES-CCM with rustc older than 1.99.1, optimised.** AES-CCM is RustCrypto's AES in
  rtci-crypto with either provider. With rustc 1.89 its record path left one to three round keys
  of a DTLS 1.3 AES-CCM record key in the delivery that opens the server's flight, 16.4 to 16.7
  KB below the floor (one, round key 4, with the 14-wrap build, run 46012389383; two with
  zeroize-5's final one, 46015302538; three with dtls-34, 46030485783: the number follows the
  layout; repeats within a run identical). None with 1.99.1 or 1.100. Not fixed in an
  optimised build: it would need an overwrite after every record there.
  `RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT=1` turns that assertion into a printed count;
  `scripts/key-residue-report.sh` and the `key_residue` CI job set it for any compiler older
  than 1.99.1 (the versions between 1.89 and 1.99.1 are unmeasured and treated as the limit).
- **Unoptimised builds: what rtci-crypto's profile decides.** At opt-level 0 the AES-NI
  intrinsics of `aes` are calls whose vector arguments go through stack copies: every block of
  the AES-CCM and AES-CBC record path left round keys and AES states in stack temporaries (97
  to 100 AES-CCM and 44 to 47 AES-CBC forms with rustc 1.89 and 1.99.1, 26 and 7 on AArch64
  macOS, none with 1.100 on Linux). Since dtls-34 rtci-crypto runs each record operation of
  RustCrypto's AES (AES-CCM, AES-CBC, AES-CTR) in a frame of its own and overwrites 48 KiB of
  stack below it afterwards, with `debug_assertions` only (`scrub_record_stack`); an optimised
  build compiles none of it. Depth: the deepest AES-CCM / AES-CBC form measured lay 31,288 bytes
  below the measurement's floor (rustc 1.89, the AES-CCM records step, run 46015302538), and the
  record call lies below that floor, so it lay less than that below the call; 48 KiB is that
  times 1.5. The forms 36.8 to 38.2 KB deep are AWS-LC's HMAC-SHA1 states of the AES-CBC MAC key,
  not RustCrypto's AES. The gap: `debug_assertions` is rtci-crypto's own profile setting; a
  custom profile that turns it off for rtci-crypto (or optimises rtci-crypto) while `aes` and
  `ccm` stay at opt-level 0 gets no overwrite and the residue above.
- **IVs** (above): 7 to 26 forms per provider and build.
- **Run-to-run variation.** Within a run the repeats agree digest for digest, except one form
  more or less in a few legs (AWS-LC optimised on Linux, 50 / 51; ring unoptimised on Linux,
  50 / 51; ring optimised on macOS, 33 / 35): all of them record-path or IV forms.
- **CPU registers, signal frames, Windows, other architectures**: as for SRTP above. On Windows
  the evidence is the heap side, the quarantine tests of `tests/dtls_secret_erasure.rs` and
  `tests/dtls_srtp_keying_material_erasure.rs`, and it is a detector, not a proof (the worked
  example below): whether a key in a dead frame reaches a freed block depends on where later
  values happen to lie.
- **What the measurement cannot see**: forms the test does not compute (AWS-LC's internal
  representations other than the ones above, SHA-384 / SHA-512 HMAC states: no measured suite
  uses them), and a provider wrapper is in the measured stack (it adds a frame to each provider
  call and handles keys only by reference and only inverted).

### A worked example: an AES-CCM key reaching the heap on Windows

The heap quarantine test failed on Windows only, with the DTLS 1.2 AES-128-CCM suite only, in
2 or 3 rounds of 3 (runs 46018046209, 46025525728; dtls-32 on its own showed the same,
45927483372): "block 1 of the PRF key expansion = an AEAD key (16 bytes)", the raw client write
key, "in a freed block of 692 bytes". What it took to find out what that was:

- **The block** (an allocation-site trace of every 692-byte block, run 46024198829): a hashbrown
  table of `(HandshakeType, HandshakeMessage)`, 4 buckets of 168 bytes and 20 control bytes,
  allocated by `HashMap::insert` in `HandshakeCache::full_pull_map`, called by `flight4::parse`.
  The one live bucket holds a `ClientKeyExchange` (its 65-byte public key at entry offsets 24 to
  63); the key lies at entry offset 72, past every field that variant writes. `full_pull_map`
  builds each message on the stack (`Handshake::unmarshal`) and moves it into the map whole:
  the bytes the smaller variant never writes are whatever the stack held there.
- **Around the key** (the same dump): round key 0 (the key), 16 other bytes, round key 1, 16
  other bytes, part of round key 2: round keys paired with AES states, the shape of per-block
  work, not of the key schedule's set-up. Wrapping the AES-CCM suite's set-up in
  `on_erased_stack` did not remove it (2 of 3 rounds still failed).
- **Where the bytes came from** (run 46026969169, three rounds each, an unoptimised control
  failing in 2 of 3 in the same job): absent in an optimised build, absent with the `aes` and
  `ccm` crates alone optimised, absent with the portable AES (`--cfg aes_force_soft`), and absent
  with the stack overwritten after each AES-CCM call (46026978042). So it is the unoptimised
  AES-NI code of `aes`, which passes its vector arguments through stack copies, during the
  CCM decryption of the client's Finished (with the client write key), which the server does
  between two parses of the client's flight: the second parse builds its messages over those
  frames. Not CPU registers: those would survive an optimised build.
- **Why Windows, why it came and went.** The carrier is wherever a later value's unwritten bytes
  fall, which moves with every layout change: zeroize-5 with dtls-31 alone was clean
  (46024205258), dtls-32's changes (a new `DTLSConn` field, the handshaker's code) made it appear, and with the record-work
  overwrite switched off but its wrapper in place the Windows test passes six rounds of six too
  (46030868260, where the gate reads its variable once and writes no frames of its own): the
  wrapper's own frame moved the carrier off the key. That is why the Windows heap test is no
  proof that the overwrite works, and is not cited as one: it cannot tell the overwrite from a
  layout change. The proof is the stack measurement, which reads the frames themselves: with
  the overwrite off the AES-CCM / AES-CBC forms are back in the dead frames (452 with rustc
  1.89), with it on there are none (46030856312, 46030861874).

## What the tests look at

`rtci-dtls/tests/key_residue.rs` is the DTLS stack measurement described above.
`tests/dtls_secret_erasure.rs` runs associations over a provider wrapper that records every
secret crossing the provider boundary (kept inverted) and derives what the association
computes from them; a test allocator keeps every block freed during the association (and
tracks those still allocated after it) and searches them all. On Linux the whole process is
searched after a worker thread has dropped the association. `rtci-srtp/tests/key_*` do the
same for SRTP contexts with keys they compute themselves; `rtci-srtp/tests/key_residue.rs` is
the stack measurement described above, with the whole-process search on Linux. It computes the
keys it looks for on a worker whose stack is overwritten and unmapped before anything is
searched, so no stack of a test thread ever holds one, and leaves nothing out of the search.
(The process search it replaced left out the whole mapping that held the searching thread's
stack, which with glibc 2.42 and later is also the mapping of the worker's stack; and the
stack of a thread that has ended is mostly given back to the kernel by glibc. It therefore saw
part of the residue in one environment and none in another:
`investigate_how_the_c_library_treats_thread_stacks` prints the facts.)

## Serialized state

`State::marshal_binary` returns the session's master secret in the clear inside its bytes, and
`unmarshal_binary` reads it from bytes the caller holds: protecting and erasing those bytes is
the application's responsibility. The format is unchanged.

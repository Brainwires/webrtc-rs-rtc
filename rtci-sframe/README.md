# rtci-sframe

SFrame ([RFC 9605](https://www.rfc-editor.org/rfc/rfc9605)) for the Sans-I/O WebRTC stack:
authenticated encryption of media that stays end-to-end when the transport is not. A selective
forwarding unit terminates SRTP and still cannot read or alter what SFrame protects.

The crate does no I/O, reads no clock and runs no key exchange. The application brings the keys
from its key management, and decides what a ciphertext covers (a whole encoded frame, or one
packet's payload) and how it is packetized.

```rust
use rtci_sframe::{CipherSuite, SFrameContext};

let suite = CipherSuite::Aes128GcmSha256_128;
let base_key = [0x2a; 16]; // from the application's key management

let mut sender = SFrameContext::with_default_provider(suite)?;
sender.add_send_key(7, &base_key)?;
let mut receiver = SFrameContext::with_default_provider(suite)?;
receiver.add_recv_key(7, &base_key)?;

let ciphertext = sender.encrypt(7, b"metadata", b"an encoded frame")?;
assert_eq!(receiver.decrypt(b"metadata", &ciphertext)?, b"an encoded frame");
```

## What is implemented

- The SFrame header (section 4.3), key derivation (4.4.2), encryption and decryption (4.4.3,
  4.4.4).
- Every registered cipher suite: `AES_128_CTR_HMAC_SHA256_80` / `_64` / `_32`,
  `AES_128_GCM_SHA256_128`, `AES_256_GCM_SHA512_128` (RFC 9605), and
  `AES_256_CTR_HMAC_SHA512_80` / `_64` / `_32` (RFC 10079, IANA values 0x0006 to 0x0008, listed
  by the W3C Encoded Transform API), checked against RFC 10079 Appendix A.2.
- A key store in which a key encrypts or decrypts, never both. A sending key owns its counter:
  a (key, nonce) pair is never used twice, and a key that has used every counter stops.
- Anti-replay per receiving key (section 9.3), on by default.
- The sender-keys scheme (section 5.1): KID layout, ratchet, and a receiver that follows the
  sender's ratchet only once a ciphertext has authenticated under the new key.
- MLS-keyed contexts (section 5.2): KID layout, keys derived on demand from the epoch secret the
  application exports, old epochs removed when their low bits are reused. No MLS here.
- A bounded store for ciphertexts whose key has not arrived yet.

Every test vector of RFC 9605 Appendix C is checked byte for byte.

## What stays with the application

That a base key has one sender and a (base key, KID) pair is installed for sending once; the key
exchange and when keys change; what goes into the metadata; packetizing a ciphertext and
reassembling it, unless it lets the engine do so: the SFrame RTP payload format
(draft-ietf-avtcore-rtp-sframe-03) is in `rtci-rtp` (`codec::sframe`), and the root crate (`rtci`)
negotiates it (`a=sframe`) and applies it to a transceiver's packets.

Scalable video: RFC 9605 section 6.1.3 makes the sender put each layer in its own ciphertext, so
that a forwarder can drop layers. This crate encrypts what it is given; the root crate's
`rtp_transceiver::sframe_transform` (`RTCRtpSFrameEncryptor::set_scalability`,
`transform_access_unit`, `transform_layer_frame`, `join_layer_frames`) splits VP9 superframes and
AV1 temporal units into their spatial layers, and its module documentation says how an
application hands layer frames.

## Specifications

RFC 9605 and the SFrame parts of draft-ietf-avtcore-rtp-sframe-03; clause-by-clause status in
[rfc9605](../docs/conformance/audit/rfc9605.md) and
[draft-ietf-avtcore-rtp-sframe](../docs/conformance/audit/draft-ietf-avtcore-rtp-sframe.md).

## Cryptography

All of it goes through `rtci-crypto`'s provider (`crypto-ring` by default, `crypto-aws-lc-rs`):
AES-CTR, AES-GCM and HMAC from the provider, HKDF built on its HMAC. Tags are compared in
constant time, and this crate's copies of base keys and derived key material are erased when
dropped.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

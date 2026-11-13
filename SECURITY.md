# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability** (https://github.com/Brainwires/webrtc-rs-rtc/security/advisories/new).
The report is visible only to the maintainers.

Include what you can of:

- the affected crate(s) and version or commit;
- the protocol layer (ICE, STUN/TURN, DTLS, SRTP/SRTCP, SCTP, data channels, RTP/RTCP, SDP, mDNS);
- what a remote peer or an on-path attacker can do (crash, memory or CPU exhaustion, authentication
  bypass, data disclosure) and whether it needs keys or a completed handshake;
- a proof of concept: a packet capture, a minimised fuzz input or a failing test.

## What to expect

- An acknowledgement within 3 working days.
- An assessment and a planned fix date within 10 working days.
- A fix released as a patch version, with a GitHub security advisory (and a CVE where it applies)
  that credits you unless you ask us not to.

Please give us time to release a fix before disclosing the issue publicly.

## Supported versions

| Version                      | Supported |
| ---------------------------- | --------- |
| 0.21.x (`+brainwires.N`)     | yes       |
| 0.20.x and older fork builds | no        |

## Upstream

This repository is a fork of [webrtc-rs/rtc](https://github.com/webrtc-rs/rtc). If an issue also
affects upstream, we will coordinate with the upstream maintainers before disclosure. You are welcome
to report it to both.

## Scope

In scope: every crate in this workspace, including how it handles untrusted network input from a
remote peer, a TURN server, an mDNS responder or a signalling channel. Out of scope: the example
programs (`examples/`) and test-only dependencies, which are not part of a released library.

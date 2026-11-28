//! W3C webrtc-pc section 4.4.1.5 ("set the session description"): which error a JavaScript
//! API over this engine raises when a description is refused. One that does not parse (RFC
//! 9429 sections 5.8.1 and 5.8.2) is an `RTCError` (`OperationError`) with `errorDetail`
//! `"sdp-syntax-error"`; one that fails the semantic checks of RFC 9429 section 5.8.3 is an
//! `InvalidAccessError`; one the signaling state does not take is an `InvalidStateError`.
//! `Error::dom_exception_name` and `Error::rtc_error_detail` give those names.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::sdp::RTCSessionDescription;

fn video(mid: &str, transport: &str) -> String {
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:{mid}\na=recvonly\na=rtpmap:96 VP8/90000\n"
    )
}

/// RFC 9429 section 5.8.3 refusals: each is an `InvalidAccessError`.
#[test]
fn a_description_that_fails_the_semantic_checks_is_an_invalid_access_error() -> TestResult {
    let without_ufrag = TRANSPORT.replace("a=ice-ufrag:4ZcD\n", "");
    let without_fingerprint = TRANSPORT
        .lines()
        .filter(|l| !l.starts_with("a=fingerprint:"))
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    let without_mux = TRANSPORT.replace("a=rtcp-mux\n", "");
    for (what, sdp) in [
        ("no a=ice-ufrag", video("0", &without_ufrag)),
        ("no a=fingerprint", video("0", &without_fingerprint)),
        (
            "no a=rtcp-mux under the require policy",
            video("0", &without_mux),
        ),
    ] {
        let mut offerer = default_peer()?;
        offerer.add_transceiver_from_kind(
            rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Video,
            None,
        )?;
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(Instant::now(), offer)?;
        let answer = RTCSessionDescription::answer(crlf(&format!(
            "{SESSION}{}",
            sdp.replace("a=recvonly", "a=sendrecv")
        )))?;
        let refused = offerer
            .set_remote_description(Instant::now(), answer)
            .expect_err(what);
        assert_eq!(
            refused.dom_exception_name(),
            Some("InvalidAccessError"),
            "{what}: {refused}"
        );
        assert_eq!(refused.rtc_error_detail(), None, "{what}");
    }
    Ok(())
}

/// A description that does not parse is an `RTCError` with `errorDetail` `sdp-syntax-error`.
#[test]
fn a_description_that_does_not_parse_is_an_sdp_syntax_error() -> TestResult {
    let refused = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}m=video nine UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\n"
    )))
    .expect_err("a port that is not a number");
    assert_eq!(
        refused.dom_exception_name(),
        Some("OperationError"),
        "{refused}"
    );
    assert_eq!(refused.rtc_error_detail(), Some("sdp-syntax-error"));
    Ok(())
}

/// An answer in the `stable` state is an `InvalidStateError`.
#[test]
fn an_answer_without_an_offer_is_an_invalid_state_error() -> TestResult {
    let mut pc = default_peer()?;
    // A well-formed answer (`a=setup:active`): only the state is wrong.
    let transport = TRANSPORT.replace("a=setup:actpass", "a=setup:active");
    let answer =
        RTCSessionDescription::answer(crlf(&format!("{SESSION}{}", video("0", &transport))))?;
    let refused = pc
        .set_remote_description(Instant::now(), answer)
        .expect_err("no offer");
    assert_eq!(
        refused.dom_exception_name(),
        Some("InvalidStateError"),
        "{refused}"
    );
    Ok(())
}

/// A signaling state a test puts `alice` in, by applying descriptions she created herself.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reach {
    Stable,
    HaveLocalOffer,
    HaveRemoteOffer,
    HaveLocalPranswer,
    HaveRemotePranswer,
}

/// A remote offer of one video section, mid `r0` (not one of the numeric mids alice gives her
/// own sections).
fn remote_offer() -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
    Ok(RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE r0\n{}",
        video("r0", TRANSPORT).replace("a=recvonly", "a=sendrecv")
    )))?)
}

/// A well-formed remote answer to that offer's section (`a=setup:active`).
fn remote_answer_sdp() -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE r0\n{}",
        video(
            "r0",
            &TRANSPORT.replace("a=setup:actpass", "a=setup:active")
        )
        .replace("a=recvonly", "a=sendrecv")
    ))
}

/// `alice` in `reach`, with the last offer and the last answer she created, neither of them
/// spent: each passes the "last created" check of RFC 9429 section 5.4 (W3C
/// `[[LastCreatedOffer]]` / `[[LastCreatedAnswer]]`), so applying it in a state that does not
/// take its type meets the state check of section 5.5 and nothing before it.
///
/// The answer is alice's answer to a remote offer. `HaveRemoteOffer` stops there and
/// `HaveLocalPranswer` applies the answer as a pranswer; both created the offer in stable
/// first (createOffer is refused while a remote offer is pending). The others roll the remote
/// offer back (an answer only resets the last created descriptions when it is applied) and
/// then create the offer; `HaveLocalOffer` and `HaveRemotePranswer` apply it, and the latter
/// takes bob's answer to it as a remote pranswer.
fn alice_in(
    reach: Reach,
) -> Result<
    (
        rtci::peer_connection::RTCPeerConnection,
        RTCSessionDescription,
        RTCSessionDescription,
    ),
    Box<dyn std::error::Error>,
> {
    use rtci::peer_connection::state::RTCSignalingState;
    use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

    let now = Instant::now();
    let mut alice = default_peer()?;
    alice.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let answering = matches!(reach, Reach::HaveRemoteOffer | Reach::HaveLocalPranswer);

    let early_offer = if answering {
        Some(alice.create_offer(None)?)
    } else {
        None
    };
    alice.set_remote_description(now, remote_offer()?)?;
    let answer = alice.create_answer(None)?;
    let offer = match early_offer {
        Some(offer) => {
            if reach == Reach::HaveLocalPranswer {
                alice.set_local_description(
                    now,
                    RTCSessionDescription::pranswer(answer.sdp.clone())?,
                )?;
            }
            offer
        }
        None => {
            alice.set_local_description(now, RTCSessionDescription::rollback(None)?)?;
            let offer = alice.create_offer(None)?;
            if reach != Reach::Stable {
                alice.set_local_description(now, offer.clone())?;
            }
            if reach == Reach::HaveRemotePranswer {
                let mut bob = default_peer()?;
                bob.set_remote_description(now, offer.clone())?;
                let bobs_answer = bob.create_answer(None)?;
                alice.set_remote_description(
                    now,
                    RTCSessionDescription::pranswer(bobs_answer.sdp)?,
                )?;
            }
            offer
        }
    };
    let expected = match reach {
        Reach::Stable => RTCSignalingState::Stable,
        Reach::HaveLocalOffer => RTCSignalingState::HaveLocalOffer,
        Reach::HaveRemoteOffer => RTCSignalingState::HaveRemoteOffer,
        Reach::HaveLocalPranswer => RTCSignalingState::HaveLocalPranswer,
        Reach::HaveRemotePranswer => RTCSignalingState::HaveRemotePranswer,
    };
    assert_eq!(alice.signaling_state(), expected, "{reach:?}");
    Ok((alice, offer, answer))
}

/// Which description a refusal case applies, and through which method.
#[derive(Clone, Copy, Debug)]
enum Apply {
    LocalOffer,
    LocalAnswer,
    LocalPranswer,
    RemoteAnswer,
    RemotePranswer,
}

/// Applies `apply` to a fresh `alice_in(reach)` and returns what went wrong, if anything: RFC
/// 9429 section 5.5 / 5.6 "If the type is not correct for the current state, processing MUST
/// stop and an error MUST be returned", the error being the state check's (W3C webrtc-pc
/// "set the session description": `InvalidStateError`), with the signaling state unchanged.
fn refused_for_its_state(
    reach: Reach,
    apply: Apply,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let (mut alice, offer, answer) = alice_in(reach)?;
    let before = alice.signaling_state();
    let now = Instant::now();
    let result =
        match apply {
            Apply::LocalOffer => alice.set_local_description(now, offer),
            Apply::LocalAnswer => alice.set_local_description(now, answer),
            Apply::LocalPranswer => {
                alice.set_local_description(now, RTCSessionDescription::pranswer(answer.sdp)?)
            }
            Apply::RemoteAnswer => alice
                .set_remote_description(now, RTCSessionDescription::answer(remote_answer_sdp())?),
            Apply::RemotePranswer => alice
                .set_remote_description(now, RTCSessionDescription::pranswer(remote_answer_sdp())?),
        };
    let after = alice.signaling_state();
    Ok(match result {
        Ok(()) => Some(format!("{apply:?} in {reach:?}: accepted, now {after}")),
        Err(error) => {
            let state_check = matches!(
                error,
                rtci::shared::error::Error::ErrSignalingStateProposedTransitionInvalid(_)
            ) && error.dom_exception_name() == Some("InvalidStateError");
            if !state_check {
                Some(format!(
                    "{apply:?} in {reach:?}: refused by another check: {error} ({:?})",
                    error.dom_exception_name()
                ))
            } else if after != before {
                Some(format!(
                    "{apply:?} in {reach:?}: refused, but the state went {before} -> {after}"
                ))
            } else {
                None
            }
        }
    })
}

/// Runs every case on its own peers and fails listing each one that was not refused by the
/// state check.
fn assert_refused_for_their_state(cases: &[(Reach, Apply)]) -> TestResult {
    let mut wrong = vec![];
    for &(reach, apply) in cases {
        if let Some(what) = refused_for_its_state(reach, apply)? {
            wrong.push(what);
        }
    }
    assert!(
        wrong.is_empty(),
        "not refused for their state:\n{}",
        wrong.join("\n")
    );
    Ok(())
}

/// RFC 9429 section 5.5: "If the type is "offer", the PeerConnection state MUST be either
/// "stable" or "have-local-offer"", and "If the type is not correct for the current state,
/// processing MUST stop and an error MUST be returned". The offer is the last one alice
/// created (stable and have-local-offer take it: `alice_in` applies it in both), so only the
/// state can refuse it.
#[test]
fn a_local_offer_outside_stable_and_have_local_offer_is_an_invalid_state_error() -> TestResult {
    assert_refused_for_their_state(&[
        (Reach::HaveRemoteOffer, Apply::LocalOffer),
        (Reach::HaveLocalPranswer, Apply::LocalOffer),
        (Reach::HaveRemotePranswer, Apply::LocalOffer),
    ])
}

/// RFC 9429 section 5.5: "If the type is "pranswer" or "answer", the PeerConnection state MUST
/// be either "have-remote-offer" or "have-local-pranswer"", and a type that is not correct for
/// the state stops with an error. The answer is the last one alice created, kept through the
/// rollback of the offer it answered (so the last-created check of section 5.4 passes; it is
/// taken as a pranswer in have-remote-offer by `alice_in`): only the state can refuse it.
#[test]
fn a_local_answer_or_pranswer_outside_the_answering_states_is_an_invalid_state_error() -> TestResult
{
    let mut cases = vec![];
    for reach in [
        Reach::Stable,
        Reach::HaveLocalOffer,
        Reach::HaveRemotePranswer,
    ] {
        cases.push((reach, Apply::LocalAnswer));
        cases.push((reach, Apply::LocalPranswer));
    }
    assert_refused_for_their_state(&cases)
}

/// RFC 9429 section 5.6: "If the type is "pranswer" or "answer", the PeerConnection state MUST
/// be either "have-local-offer" or "have-remote-pranswer"": a remote answer or pranswer while
/// alice is the answerer (have-remote-offer, have-local-pranswer) is refused for its state.
/// `an_answer_without_an_offer_is_an_invalid_state_error` has the stable case.
#[test]
fn a_remote_answer_while_answering_is_an_invalid_state_error() -> TestResult {
    let mut cases = vec![];
    for reach in [Reach::HaveRemoteOffer, Reach::HaveLocalPranswer] {
        cases.push((reach, Apply::RemoteAnswer));
        cases.push((reach, Apply::RemotePranswer));
    }
    assert_refused_for_their_state(&cases)
}

/// W3C webrtc-pc 4.6.1 (`RTCSdpType` "rollback"): "An "answer" or "pranswer" cannot be rolled
/// back." Once the answer is applied, on either side and through either method, a rollback is
/// an `InvalidStateError` (RFC 9429 section 5.7: "once the answerer has performed
/// setLocalDescription with its answer, this cannot be rolled back") and the descriptions the
/// answer completed stay current. The pranswer half is
/// `set_description_atomic_test.rs::a_rollback_is_refused_outside_the_offer_states`.
#[test]
fn an_applied_answer_cannot_be_rolled_back() -> TestResult {
    use jsep_common::exchange;
    use rtci::peer_connection::state::RTCSignalingState;
    use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

    let mut wrong = vec![];
    for (side, local) in [
        ("offerer", true),
        ("offerer", false),
        ("answerer", true),
        ("answerer", false),
    ] {
        let mut offerer = default_peer()?;
        offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
        let mut answerer = default_peer()?;
        exchange(&mut offerer, &mut answerer)?;
        let pc = if side == "offerer" {
            &mut offerer
        } else {
            &mut answerer
        };
        let before = (
            pc.current_local_description().map(|d| d.sdp),
            pc.current_remote_description().map(|d| d.sdp.clone()),
        );
        let rollback = RTCSessionDescription::rollback(None)?;
        let result = if local {
            pc.set_local_description(Instant::now(), rollback)
        } else {
            pc.set_remote_description(Instant::now(), rollback)
        };
        let after = (
            pc.current_local_description().map(|d| d.sdp),
            pc.current_remote_description().map(|d| d.sdp.clone()),
        );
        let how = if local { "local" } else { "remote" };
        match result {
            Ok(()) => wrong.push(format!("{side}, {how} rollback: accepted")),
            Err(error) if error.dom_exception_name() != Some("InvalidStateError") => {
                wrong.push(format!("{side}, {how} rollback: {error}"));
            }
            Err(_) => {}
        }
        if pc.signaling_state() != RTCSignalingState::Stable
            || after != before
            || before.0.is_none()
        {
            wrong.push(format!(
                "{side}, {how} rollback: state {} or the current descriptions changed",
                pc.signaling_state()
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    Ok(())
}

/// W3C webrtc-pc 4.5.1 ("the specified error name"), for the operations other than setting a
/// description: what each refusal of the constructor, `setConfiguration` ("set the
/// configuration", "validate an ICE server URL"), `createAnswer` and `addIceCandidate` is
/// named, by the step that raises it.
#[test]
fn every_refusal_of_the_configuration_and_the_candidates_has_its_w3c_name() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::certificate::RTCCertificate;
    use rtci::peer_connection::configuration::{
        RTCBundlePolicy, RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCRtcpMuxPolicy,
    };
    use rtci::peer_connection::transport::RTCIceCandidateInit;
    use std::time::{Duration, SystemTime};

    let now = Instant::now();
    let provider = rtci::crypto::default_provider()?;
    let certificate = |issued: SystemTime, lifetime: Option<Duration>| {
        RTCCertificate::generate_certificate(
            provider.crypto(),
            rtci::crypto::SignatureScheme::EcdsaP256Sha256,
            lifetime,
            issued,
        )
    };
    let mut named: Vec<(String, Option<&'static str>, &'static str)> = vec![];
    let mut expect = |what: &str, refused: rtci::shared::error::Error, name: &'static str| {
        named.push((
            format!("{what}: {refused:?}"),
            refused.dom_exception_name(),
            name,
        ));
    };

    // Constructor step 3: "If the value of certificate.expires is less than the current
    // time, throw an InvalidAccessError."
    let expired = certificate(
        SystemTime::now() - Duration::from_secs(60 * 24 * 3600),
        Some(Duration::from_secs(24 * 3600)),
    )?;
    let built = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_certificates(vec![expired])
                .build(),
        )
        .build(now);
    expect(
        "an expired certificate",
        built.err().expect("refused"),
        "InvalidAccessError",
    );

    // "Set the configuration": "If oldConfig is not null, run the following steps, and if
    // any of them fail, throw an InvalidModificationError".
    let original = certificate(SystemTime::now(), None)?;
    let base = || {
        RTCConfigurationBuilder::new()
            .with_certificates(vec![original.clone()])
            .with_bundle_policy(RTCBundlePolicy::Balanced)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
            .with_ice_candidate_pool_size(0)
    };
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(base().build())
        .build(now)?;
    pc.create_data_channel("errors", None)?;
    let offer = pc.create_offer(None)?;
    // setLocalDescription: an offer that is not [[LastCreatedOffer]] is an
    // InvalidModificationError (an answer that is not [[LastCreatedAnswer]] alike:
    // jsep_description_state.rs).
    expect(
        "an offer that is not the last created",
        pc.set_local_description(
            now,
            RTCSessionDescription::offer(offer.sdp.replace("s=-", "s=edited"))?,
        )
        .expect_err("edited"),
        "InvalidModificationError",
    );
    pc.set_local_description(now, offer.clone())?;
    let changes: Vec<(&str, RTCConfiguration)> = vec![
        (
            "other certificates",
            base()
                .with_certificates(vec![certificate(SystemTime::now(), None)?])
                .build(),
        ),
        (
            "another bundlePolicy",
            base()
                .with_bundle_policy(RTCBundlePolicy::MaxBundle)
                .build(),
        ),
        (
            "another rtcpMuxPolicy",
            base()
                .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate)
                .build(),
        ),
        (
            "another iceCandidatePoolSize after setLocalDescription",
            base().with_ice_candidate_pool_size(2).build(),
        ),
    ];
    for (what, changed) in changes {
        let refused = pc.set_configuration(changed).expect_err(what);
        expect(what, refused, "InvalidModificationError");
    }

    // "Validate an ICE server URL" and "set the configuration" step 11: SyntaxError, and
    // InvalidAccessError for the TURN credentials.
    let server = |url: &str| RTCIceServer {
        urls: vec![url.to_owned()],
        username: "user".to_owned(),
        credential: "secret".to_owned(),
    };
    for (what, server, name) in [
        (
            "no url",
            RTCIceServer {
                urls: vec![],
                ..server("stun:x")
            },
            "SyntaxError",
        ),
        ("another scheme", server("http:example.org"), "SyntaxError"),
        ("a fragment", server("stun:example.org#frag"), "SyntaxError"),
        (
            "an @ in the path",
            server("turn:user@example.org"),
            "SyntaxError",
        ),
        (
            "a / in the path",
            server("turn:example.org/path"),
            "SyntaxError",
        ),
        (
            "a query on a stun url",
            server("stun:example.org?transport=udp"),
            "SyntaxError",
        ),
        (
            "a query other than the transport",
            server("turn:example.org?transport=sctp"),
            "SyntaxError",
        ),
        (
            "a host that does not parse",
            server("turn:exa mple.org"),
            "SyntaxError",
        ),
        (
            "a port that does not parse",
            server("stun:example.org:99999"),
            "SyntaxError",
        ),
        (
            "a turn url without a credential",
            RTCIceServer {
                credential: String::new(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a turn url without a username",
            RTCIceServer {
                username: String::new(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a username of 509 bytes",
            RTCIceServer {
                username: "u".repeat(509),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a credential with a control character",
            RTCIceServer {
                credential: "sec\u{7}ret".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a credential with a default-ignorable code point (not an OpaqueString)",
            RTCIceServer {
                credential: "The\u{ad}Matrix".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a username that is not an OpaqueString (RFC 8489 section 14.3)",
            RTCIceServer {
                username: "us\u{0}er".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
    ] {
        let refused = pc
            .set_configuration(base().with_ice_servers(vec![server]).build())
            .expect_err(what);
        expect(what, refused, name);
    }

    // createAnswer: "If connection.[[RemoteDescription]] is null ... InvalidStateError".
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    expect(
        "createAnswer without a remote description",
        answerer
            .create_answer(None)
            .expect_err("no remote description"),
        "InvalidStateError",
    );

    // addIceCandidate (4.4.2).
    let host = |init: RTCIceCandidateInit| RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host".to_owned(),
        ..init
    };
    let mid = Some("0".to_owned());
    expect(
        "addIceCandidate without a remote description",
        answerer
            .add_remote_candidate(host(RTCIceCandidateInit {
                sdp_mid: mid.clone(),
                ..Default::default()
            }))
            .expect_err("no remote description"),
        "InvalidStateError",
    );
    answerer.set_remote_description(now, offer)?;
    for (what, init, name) in [
        (
            "neither sdpMid nor sdpMLineIndex",
            RTCIceCandidateInit::default(),
            "TypeError",
        ),
        (
            "an sdpMid of no media description",
            RTCIceCandidateInit {
                sdp_mid: Some("nope".to_owned()),
                ..Default::default()
            },
            "OperationError",
        ),
        (
            "an sdpMLineIndex past the media descriptions",
            RTCIceCandidateInit {
                sdp_mline_index: Some(5),
                ..Default::default()
            },
            "OperationError",
        ),
        (
            "a usernameFragment that is not the section's",
            RTCIceCandidateInit {
                sdp_mid: mid.clone(),
                username_fragment: Some("someoneelse".to_owned()),
                ..Default::default()
            },
            "OperationError",
        ),
    ] {
        let refused = answerer.add_remote_candidate(host(init)).expect_err(what);
        expect(what, refused, name);
    }

    let wrong: Vec<_> = named
        .iter()
        .filter(|(_, got, want)| *got != Some(*want))
        .collect();
    assert!(wrong.is_empty(), "named otherwise: {wrong:#?}");
    Ok(())
}

//! The state checks of `create_offer`, `create_answer`, `set_local_description` and
//! `set_remote_description` (W3C webrtc-pc 4.4.2; RFC 9429 sections 4.1.9, 5.5 and 5.6): each
//! refusal leaves the connection usable for the call that is valid.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCSignalingState;
use rtci::shared::error::Error;
use sansio::Protocol;

#[test]
fn create_answer_needs_a_remote_offer() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0101_0101))?;
    // No remote description at all (RFC 9429 section 4.1.9).
    assert!(matches!(
        offerer.create_answer(None),
        Err(Error::ErrNoRemoteDescription)
    ));
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    assert!(offerer.create_answer(None).is_err(), "have-local-offer");

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    // Stable, with a remote description: InvalidStateError (W3C createAnswer).
    for pc in [&mut offerer, &mut answerer] {
        assert!(matches!(
            pc.create_answer(None),
            Err(Error::ErrIncorrectSignalingState)
        ));
    }
    Ok(())
}

#[test]
fn a_closed_connection_refuses_offers_answers_and_descriptions() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0202_0202))?;
    let offer = offerer.create_offer(None)?;

    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0303_0303))?;
    let own_offer = pc.create_offer(None)?;
    pc.close()?;

    assert!(matches!(
        pc.create_offer(None),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(pc.create_answer(None).is_err());
    assert!(matches!(
        pc.set_local_description(Instant::now(), own_offer),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(matches!(
        pc.set_remote_description(Instant::now(), offer),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(pc.local_description().is_none() && pc.remote_description().is_none());
    Ok(())
}

/// W3C setLocalDescription: an offer that is not `[[LastCreatedOffer]]`, or an answer that is
/// not `[[LastCreatedAnswer]]`, is an InvalidModificationError; an empty SDP stands for the
/// last one created (RFC 9429 section 5.4: a local description is not modified).
#[test]
fn a_local_description_is_the_last_one_created() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0404_0404))?;
    let offer = offerer.create_offer(None)?;

    let edited = offer.sdp.replace("s=-", "s=edited");
    assert_ne!(edited, offer.sdp);
    assert!(matches!(
        offerer.set_local_description(Instant::now(), RTCSessionDescription::offer(edited)?),
        Err(Error::ErrSDPDoesNotMatchOffer)
    ));
    assert!(offerer.local_description().is_none());

    // An offer with no SDP is the offer last created.
    let mut implicit = offer.clone();
    implicit.sdp = String::new();
    offerer.set_local_description(Instant::now(), implicit)?;
    assert_eq!(
        offerer
            .pending_local_description()
            .expect("the offer is pending")
            .sdp
            .lines()
            .find(|l| l.starts_with("o=")),
        offer.sdp.lines().find(|l| l.starts_with("o="))
    );

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    let edited = answer.sdp.replace("s=-", "s=edited");
    assert!(matches!(
        answerer.set_local_description(Instant::now(), RTCSessionDescription::answer(edited)?),
        Err(Error::ErrSDPDoesNotMatchAnswer)
    ));
    assert!(answerer.local_description().is_none());

    let mut implicit = answer.clone();
    implicit.sdp = String::new();
    answerer.set_local_description(Instant::now(), implicit)?;
    assert!(answerer.current_local_description().is_some());
    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(())
}

/// W3C "set a session description": a description whose type "is invalid for the current
/// [[SignalingState]] as described in [RFC9429]" rejects with an InvalidStateError, for a
/// local description too (RFC 9429 section 5.5: an answer or pranswer only in
/// have-remote-offer / have-local-pranswer, an offer not in have-remote-offer). Each
/// description is the last one created, so setLocalDescription's InvalidModificationError
/// (another SDP) does not come first; the state is left as it was.
#[test]
fn a_local_description_of_a_type_the_state_does_not_take_is_an_invalid_state_error() -> TestResult {
    let now = Instant::now();
    let refused = |pc: &mut rtci::peer_connection::RTCPeerConnection,
                   description: RTCSessionDescription,
                   what: &str| {
        let state = pc.signaling_state();
        let err = pc.set_local_description(now, description).expect_err(what);
        assert_eq!(
            err.dom_exception_name(),
            Some("InvalidStateError"),
            "{what}: {err:?}"
        );
        assert_eq!(pc.signaling_state(), state, "{what}: the state changed");
    };

    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0505_0505))?;
    let offer = offerer.create_offer(None)?;

    // An answer and a pranswer in stable and in have-local-offer: the answerer creates an
    // answer to a remote offer, rolls the offer back ([[LastCreatedAnswer]] stays), and offers
    // itself.
    let mut answerer = default_peer()?;
    answerer.set_remote_description(now, offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(answerer.signaling_state(), RTCSignalingState::Stable);
    refused(
        &mut answerer,
        RTCSessionDescription::answer(answer.sdp.clone())?,
        "an answer in stable",
    );
    refused(
        &mut answerer,
        RTCSessionDescription::pranswer(answer.sdp.clone())?,
        "a pranswer in stable",
    );
    let own_offer = answerer.create_offer(None)?;
    answerer.set_local_description(now, own_offer)?;
    assert_eq!(
        answerer.signaling_state(),
        RTCSignalingState::HaveLocalOffer
    );
    refused(
        &mut answerer,
        RTCSessionDescription::answer(answer.sdp.clone())?,
        "an answer in have-local-offer",
    );
    refused(
        &mut answerer,
        RTCSessionDescription::pranswer(answer.sdp)?,
        "a pranswer in have-local-offer",
    );

    // An offer in have-remote-offer: one created in stable, before the remote offer came.
    let mut glare = default_peer()?;
    glare.add_track(video_track("glare", 0x0606_0606))?;
    let own_offer = glare.create_offer(None)?;
    glare.set_remote_description(now, offer)?;
    assert_eq!(glare.signaling_state(), RTCSignalingState::HaveRemoteOffer);
    refused(&mut glare, own_offer, "an offer in have-remote-offer");
    // The valid call still works.
    let answer = glare.create_answer(None)?;
    glare.set_local_description(now, answer)?;
    assert_eq!(glare.signaling_state(), RTCSignalingState::Stable);
    Ok(())
}

/// W3C setLocalDescription: "If type is "answer" or "pranswer", and sdp is not the empty string
/// and not equal to [[LastCreatedAnswer]]", InvalidModificationError: the pranswer branch. The
/// answer last created, applied as a pranswer, is taken (have-local-pranswer).
#[test]
fn a_local_pranswer_is_the_last_answer_created() -> TestResult {
    let now = Instant::now();
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0707_0707))?;
    let offer = offerer.create_offer(None)?;
    let mut answerer = default_peer()?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;

    let edited = answer.sdp.replace("s=-", "s=edited");
    assert_ne!(edited, answer.sdp);
    let err = answerer
        .set_local_description(now, RTCSessionDescription::pranswer(edited)?)
        .expect_err("a pranswer that is not the last answer created");
    assert!(matches!(err, Error::ErrSDPDoesNotMatchAnswer), "{err:?}");
    assert_eq!(err.dom_exception_name(), Some("InvalidModificationError"));
    assert_eq!(
        answerer.signaling_state(),
        RTCSignalingState::HaveRemoteOffer
    );
    assert!(answerer.pending_local_description().is_none());

    answerer.set_local_description(now, RTCSessionDescription::pranswer(answer.sdp)?)?;
    assert_eq!(
        answerer.signaling_state(),
        RTCSignalingState::HaveLocalPranswer
    );
    Ok(())
}

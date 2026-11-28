//! RFC 9429 section 5.11: "If the 'm=' section references RTCP feedback mechanisms that were
//! not present in the corresponding 'm=' section in the offer, this indicates a negotiation
//! problem and MUST result in an error." (RFC 4585 section 4.2: "The answerer MUST NOT add
//! feedback parameters to the media description".)
//!
//! That is the default (`SettingEngineBuilder::with_unoffered_feedback_refused(true)`, in the
//! `Rfc`, `StrictRfc` and `Performance` behaviour profiles): `set_remote_description` refuses
//! such an answer and the offer stays pending. The `Chrome` profile sets it `false`, libwebrtc's
//! form (pc/sdp_offer_answer.cc @ a222406d checks no feedback in a remote answer): the answer is
//! applied and the extra feedback is never enabled.

mod jsep_common;

use jsep_common::{TestResult, video_track};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCSignalingState;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use std::time::Instant;

fn peer(
    profile: BehaviourProfile,
    refused: Option<bool>,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::for_profile(profile);
    media_engine.register_default_codecs()?;
    let setting_engine = SettingEngineBuilder::new().with_behaviour_profile(profile);
    let setting_engine = match refused {
        Some(refused) => setting_engine.with_unoffered_feedback_refused(refused),
        None => setting_engine,
    };
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(setting_engine.build())
        .build(Instant::now())?)
}

/// The pending video offer of `offerer` and the answer of a peer of `profile`, with one
/// `a=rtcp-fb` line the offer did not have added to the answer's video section.
fn answer_with_extra_feedback(
    offerer: &mut RTCPeerConnection,
    profile: BehaviourProfile,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut answerer = peer(profile, None)?;
    offerer.add_track(video_track("v", 0x5e13_0201))?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    assert!(!offer.sdp.contains("made-up"));
    let payload_type = answer
        .sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .and_then(|l| l.split_whitespace().nth(3))
        .expect("the answer accepts a video format")
        .to_owned();
    let mut lines: Vec<String> = answer.sdp.lines().map(str::to_owned).collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(&format!("a=rtpmap:{payload_type} ")))
        .expect("the format's rtpmap");
    lines.insert(at + 1, format!("a=rtcp-fb:{payload_type} made-up"));
    Ok(lines.join("\r\n") + "\r\n")
}

/// [`answer_with_extra_feedback`] for an offerer of `profile` whose
/// `with_unoffered_feedback_refused` is `refused` after the profile, when given.
fn offer_and_answer_with_extra_feedback(
    profile: BehaviourProfile,
    refused: Option<bool>,
) -> Result<(RTCPeerConnection, String), Box<dyn std::error::Error>> {
    let mut offerer = peer(profile, refused)?;
    let answer = answer_with_extra_feedback(&mut offerer, profile)?;
    Ok((offerer, answer))
}

fn assert_refused(offerer: &mut RTCPeerConnection, answer: String, what: &str) -> TestResult {
    let refused =
        offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(answer)?);
    assert!(
        matches!(
            refused,
            Err(rtci::shared::error::Error::ErrAnswerDoesNotMatchOffer(ref reason))
                if reason.contains("made-up") && reason.contains("RFC 9429 section 5.11")
        ),
        "{what}: {refused:?}"
    );
    assert_eq!(
        offerer.signaling_state(),
        RTCSignalingState::HaveLocalOffer,
        "{what}"
    );
    Ok(())
}

/// The default: RFC 9429 section 5.11's error, the offer left pending. `Rfc`, `StrictRfc` and
/// `Performance` keep it, and so does a configuration that names no profile.
#[test]
fn by_default_an_answer_with_feedback_the_offer_lacked_is_refused() -> TestResult {
    for profile in [
        BehaviourProfile::Rfc,
        BehaviourProfile::StrictRfc,
        BehaviourProfile::Performance,
    ] {
        let (mut offerer, answer) = offer_and_answer_with_extra_feedback(profile, None)?;
        assert_refused(&mut offerer, answer, &format!("{profile:?}"))?;
    }
    // No profile named, in a build without `chrome-defaults` (whose default is `Chrome`).
    if BehaviourProfile::default() != BehaviourProfile::Chrome {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut offerer = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        let answer = answer_with_extra_feedback(&mut offerer, BehaviourProfile::Rfc)?;
        assert_refused(&mut offerer, answer, "no profile")?;
    }
    Ok(())
}

/// The `Chrome` profile (libwebrtc's form), or the setting turned off under any profile: the
/// answer is applied.
#[test]
fn the_chrome_profile_applies_an_answer_with_feedback_the_offer_lacked() -> TestResult {
    for (profile, refused) in [
        (BehaviourProfile::Chrome, None),
        (BehaviourProfile::Rfc, Some(false)),
        (BehaviourProfile::StrictRfc, Some(false)),
    ] {
        let (mut offerer, answer) = offer_and_answer_with_extra_feedback(profile, refused)?;
        offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(answer)?)?;
        assert_eq!(
            offerer.signaling_state(),
            RTCSignalingState::Stable,
            "{profile:?} {refused:?}"
        );
    }
    Ok(())
}

/// `with_unoffered_feedback_refused(true)` after the `Chrome` profile refuses again.
#[test]
fn the_setting_after_the_chrome_profile_refuses_the_answer() -> TestResult {
    let (mut offerer, answer) =
        offer_and_answer_with_extra_feedback(BehaviourProfile::Chrome, Some(true))?;
    assert_refused(&mut offerer, answer, "Chrome, then the setting")
}

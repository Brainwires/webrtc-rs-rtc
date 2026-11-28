//! The `a=ice-options` line of an answer (`docs/conformance/spec-issues.md` row 28).
//!
//! By default an answer follows RFC 9429 section 5.3.1: the line, with the "trickle" option and
//! the "ice2" option, "is only included if such an option was present in the offer" (the
//! condition on `trickle` was chosen on purpose, `rtcweb-wg/jsep#23`).
//! `SettingEngineBuilder::with_answer_ice_options(AnswerIceOptions::Always)` (the `StrictRfc`
//! profile: the `conflict` rows' RFC form) gives RFC 8840 section 4.1.3 ("In any case, the
//! Answerer MUST include the "ice-options:trickle" attribute"), RFC 8445 section 10 and RFC 8839
//! section 4.3.2: every answer says `trickle ice2`. `AnswerIceOptions::TrickleAlways` (the
//! `Chrome` profile) is libwebrtc's `trickle` whatever the offer had, `ice2` as offered.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::{
    AnswerIceOptions, SettingEngineBuilder,
};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fn build(settings: SettingEngineBuilder) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings.build())
        .build(Instant::now())?)
}

fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    build(SettingEngineBuilder::new())
}

fn peer(options: AnswerIceOptions) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    build(SettingEngineBuilder::new().with_answer_ice_options(options))
}

/// An audio offer whose session-level `a=ice-options` line is `options` (none for `None`).
fn offer(options: Option<&str>) -> String {
    let line = options.map_or(String::new(), |o| format!("a=ice-options:{o}\n"));
    crlf(&format!(
        "{SESSION}{line}a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
"
    ))
}

/// The answer `pc` makes to `sdp`, set as its local description.
fn answer_to(
    pc: &mut RTCPeerConnection,
    sdp: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(sdp)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    Ok(answer.sdp)
}

/// Every `a=ice-options` line of `sdp` (session or media level), as its value.
fn ice_options(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter(|l| l.starts_with("a=ice-options"))
        .map(|l| {
            l.trim_start_matches("a=ice-options")
                .trim_start_matches(':')
                .to_owned()
        })
        .collect()
}

/// The cases: (the offer's line, what each setting answers: AsOffered, TrickleAlways, Always).
type Case = (Option<&'static str>, [&'static [&'static str]; 3]);
const CASES: [Case; 6] = [
    (None, [&[], &["trickle"], &["trickle ice2"]]),
    // A browser's offer.
    (
        Some("trickle"),
        [&["trickle"], &["trickle"], &["trickle ice2"]],
    ),
    (
        Some("ice2"),
        [&["ice2"], &["trickle ice2"], &["trickle ice2"]],
    ),
    (
        Some("trickle ice2"),
        [&["trickle ice2"], &["trickle ice2"], &["trickle ice2"]],
    ),
    // Other options of the offer are not echoed.
    (
        Some("trickle renomination"),
        [&["trickle"], &["trickle"], &["trickle ice2"]],
    ),
    (
        Some("ice2 trickle"),
        [&["trickle ice2"], &["trickle ice2"], &["trickle ice2"]],
    ),
];

/// The default is RFC 9429 section 5.3.1: each option only when the offer has it, and no line
/// (never an empty one: RFC 8839 section 5.6, "ice-options" is one or more option tags) when it
/// has neither.
#[test]
fn by_default_an_answer_says_only_the_options_the_offer_has() -> TestResult {
    for (offered, answered) in CASES {
        let answer = answer_to(&mut default_peer()?, offer(offered))?;
        assert_eq!(
            ice_options(&answer),
            answered[0],
            "offer {offered:?}: {answer}"
        );
        assert!(!answer.contains("a=ice-options\r\n"), "{answer}");
        assert!(!answer.contains("a=ice-options:\r\n"), "{answer}");
    }
    Ok(())
}

/// Each value of the setting.
#[test]
fn each_setting_answers_its_form() -> TestResult {
    for (index, setting) in [
        AnswerIceOptions::AsOffered,
        AnswerIceOptions::TrickleAlways,
        AnswerIceOptions::Always,
    ]
    .into_iter()
    .enumerate()
    {
        for (offered, answered) in CASES {
            let answer = answer_to(&mut peer(setting)?, offer(offered))?;
            assert_eq!(
                ice_options(&answer),
                answered[index],
                "{setting:?}, offer {offered:?}: {answer}"
            );
        }
    }
    Ok(())
}

/// The options are read where the offer has them: at media level too.
#[test]
fn media_level_options_of_the_offer_count() -> TestResult {
    let sdp = offer(None).replace("a=mid:0\r\n", "a=mid:0\r\na=ice-options:trickle\r\n");
    let answer = answer_to(&mut default_peer()?, sdp)?;
    assert_eq!(ice_options(&answer), ["trickle"], "{answer}");
    Ok(())
}

/// A lite agent (whose offers say `trickle ice2`, ice-36) answers as any agent does; it still
/// says `a=ice-lite`.
#[test]
fn a_lite_agent_answers_the_offers_options() -> TestResult {
    for (setting, offered, answered) in [
        (None, None, vec![]),
        (None, Some("trickle"), vec!["trickle"]),
        (None, Some("trickle ice2"), vec!["trickle ice2"]),
        (Some(AnswerIceOptions::Always), None, vec!["trickle ice2"]),
        (
            Some(AnswerIceOptions::Always),
            Some("trickle"),
            vec!["trickle ice2"],
        ),
    ] {
        let mut builder = SettingEngineBuilder::new().with_lite(true);
        if let Some(setting) = setting {
            builder = builder.with_answer_ice_options(setting);
        }
        let answer = answer_to(&mut build(builder)?, offer(offered))?;
        assert!(answer.contains("a=ice-lite\r\n"), "{answer}");
        assert_eq!(
            ice_options(&answer),
            answered,
            "setting {setting:?}, offer {offered:?}: {answer}"
        );
    }
    Ok(())
}

/// Offers are not affected: an initial offer says `trickle ice2` (RFC 9429 section 5.2.1), and
/// so does the answerer's later offer after it answered a browser's offer with `trickle`
/// alone (section 5.2.2 follows 5.2.1). That later offer changes the options its answer
/// stated, which RFC 8839 section 4.4.1.1.1 forbids outside a restart ("The agent MUST NOT
/// modify the SDP "ice-options" ... attributes in a subsequent offer unless the offer is sent
/// in order to request an ICE restart"; spec-issues row 28). An `rtci` peer applies RFC 8839
/// section 4.4.2.1 to such an offer and refuses it; here the `rtci` offerer's own offer lost
/// its `ice2` on the way (as a browser's has none), so its current remote description is the
/// `trickle`-only answer. Browsers do not look (libwebrtc reads no `ice2` and compares no
/// `ice-options`; Firefox's `JsepSessionImpl` "TODO(bug 1095226): Check ice-options?").
#[test]
fn a_later_offer_says_trickle_and_ice2_again_and_an_rtci_peer_that_lost_ice2_refuses_it()
-> TestResult {
    let now = Instant::now();
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let initial = offerer.create_offer(None)?;
    assert_eq!(
        ice_options(&initial.sdp),
        ["trickle ice2"],
        "{}",
        initial.sdp
    );
    offerer.set_local_description(now, initial.clone())?;

    // The offer reaches the answerer in a browser's form: `trickle` only.
    let browser_form = initial.sdp.replace(
        "a=ice-options:trickle ice2\r\n",
        "a=ice-options:trickle\r\n",
    );
    let mut answerer = default_peer()?;
    let answer = answer_to(&mut answerer, browser_form)?;
    assert_eq!(ice_options(&answer), ["trickle"], "{answer}");
    offerer.set_remote_description(now, RTCSessionDescription::answer(answer)?)?;

    let later = answerer.create_offer(None)?;
    assert_eq!(ice_options(&later.sdp), ["trickle ice2"], "{}", later.sdp);
    answerer.set_local_description(now, later.clone())?;
    let refused = offerer
        .set_remote_description(now, later)
        .expect_err("an offer without a restart that changed ice-options");
    assert!(refused.to_string().contains("ice-options"), "{refused}");
    Ok(())
}

/// Two `rtci` peers: an `rtci` offer always has both options, so the answer has both under
/// every setting, and the offerer reads the same from it (`canTrickleIceCandidates`, W3C
/// webrtc-pc 4.4.1.6 / RFC 9429 5.10; the peer's `ice2`, RFC 8839 section 4.3.4).
#[test]
fn two_rtci_peers_read_both_options_from_the_answer_under_every_setting() -> TestResult {
    for setting in [
        AnswerIceOptions::AsOffered,
        AnswerIceOptions::TrickleAlways,
        AnswerIceOptions::Always,
    ] {
        let now = Instant::now();
        let mut offerer = peer(setting)?;
        let mut answerer = peer(setting)?;
        offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let o = offerer.create_offer(None)?;
        offerer.set_local_description(now, o.clone())?;
        answerer.set_remote_description(now, o)?;
        let a = answerer.create_answer(None)?;
        answerer.set_local_description(now, a.clone())?;
        offerer.set_remote_description(now, a.clone())?;
        assert_eq!(
            ice_options(&a.sdp),
            ["trickle ice2"],
            "{setting:?}: {}",
            a.sdp
        );
        assert_eq!(offerer.can_trickle_ice_candidates(), Some(true));
        assert_eq!(answerer.can_trickle_ice_candidates(), Some(true));
        let options = offerer.remote_ice_options();
        assert!(
            options.contains(&"trickle".to_owned()) && options.contains(&"ice2".to_owned()),
            "{setting:?}: {options:?}"
        );
    }
    Ok(())
}

/// The profiles: `Rfc` and `Performance` answer as offered, `Chrome` with libwebrtc's
/// `trickle` always, `StrictRfc` with the `conflict` rows' form, `trickle ice2` always.
#[test]
fn the_profiles_answer_a_browser_offer_each_in_its_form() -> TestResult {
    for (profile, answered) in [
        (BehaviourProfile::Rfc, vec!["trickle"]),
        (BehaviourProfile::Performance, vec!["trickle"]),
        (BehaviourProfile::Chrome, vec!["trickle"]),
        (BehaviourProfile::StrictRfc, vec!["trickle ice2"]),
    ] {
        let answer = answer_to(
            &mut build(SettingEngineBuilder::new().with_behaviour_profile(profile))?,
            offer(Some("trickle")),
        )?;
        assert_eq!(ice_options(&answer), answered, "{profile}: {answer}");
    }
    // An offer with neither option tells `Chrome` from `Rfc`.
    for (profile, answered) in [
        (BehaviourProfile::Rfc, vec![]),
        (BehaviourProfile::Chrome, vec!["trickle"]),
        (BehaviourProfile::StrictRfc, vec!["trickle ice2"]),
    ] {
        let answer = answer_to(
            &mut build(SettingEngineBuilder::new().with_behaviour_profile(profile))?,
            offer(None),
        )?;
        assert_eq!(ice_options(&answer), answered, "{profile}: {answer}");
    }
    Ok(())
}

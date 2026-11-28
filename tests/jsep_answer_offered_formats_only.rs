//! `SettingEngineBuilder::with_answer_offered_formats_only`, `true` by default since 0.3.0 (the
//! `Rfc`, `Chrome` and `Performance` profiles): an answer lists only the formats the offer has,
//! in the offer's order, each repair format only with the primary it repairs (RFC 9429 section
//! 5.3.1: the answer "MAY include formats that are locally supported but not present in the
//! offer"; libwebrtc `pc/codec_vendor.cc` `NegotiateCodecs`). With `false` (the `StrictRfc`
//! profile; the default up to 0.2.x) an answer adds every other registered media format after
//! the offered ones (RFC 9429 section 5.3.1: "Any currently available media formats that are
//! not present in the current remote description MUST be added after all existing formats";
//! `tests/jsep_answer_unoffered_formats.rs`).
//!
//! The web-platform-tests scenario `webrtc/protocol/h265-level-id.https.html`, "Offer to send
//! H265, answer to receive level-id=30 results in level-id=30", is reproduced here: a
//! `sendonly` transceiver whose codec preferences are the H.265 send capability offers, the
//! peer answers, the answer's `level-id` is rewritten to 30 and applied, and the offerer's
//! sender has one codec, at level-id 30.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, media_sections, port_of};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_HEVC, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpTransceiverId, RTCRtpTransceiverInit};

fn build(settings: SettingEngineBuilder) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings.build())
        .build(Instant::now())?)
}

/// A peer with the setting at `offered_only`.
fn peer(offered_only: bool) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    build(SettingEngineBuilder::new().with_answer_offered_formats_only(offered_only))
}

/// The formats of a section's m= line.
fn formats(section: &[String]) -> Vec<String> {
    section[0]
        .split_whitespace()
        .skip(3)
        .map(str::to_owned)
        .collect()
}

fn attribute<'a>(section: &'a [String], key: &str, pt: &str) -> Option<&'a str> {
    let prefix = format!("a={key}:{pt} ");
    section.iter().find_map(|l| l.strip_prefix(prefix.as_str()))
}

fn rtpmap<'a>(section: &'a [String], pt: &str) -> &'a str {
    attribute(section, "rtpmap", pt).unwrap_or_else(|| panic!("an rtpmap for {pt}: {section:?}"))
}

fn encoding_name(section: &[String], pt: &str) -> String {
    rtpmap(section, pt)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Every RTX format of `section` repairs a format the section lists (RFC 4588 section 8.1).
fn assert_rtx_repairs_a_listed_format(section: &[String]) {
    let listed = formats(section);
    for pt in &listed {
        if encoding_name(section, pt) != "rtx" {
            continue;
        }
        let apt = attribute(section, "fmtp", pt)
            .and_then(|line| {
                line.split(';')
                    .find_map(|p| p.trim().strip_prefix("apt=").map(str::to_owned))
            })
            .unwrap_or_else(|| panic!("rtx {pt} has an apt: {section:?}"));
        assert!(
            listed.contains(&apt) && encoding_name(section, &apt) != "rtx",
            "rtx {pt} repairs {apt}, which the section lists: {section:?}"
        );
    }
}

/// A video offer: VP9 profile 1, VP8 with its RTX, a format this endpoint does not have and an
/// RTX format for it, in that order.
fn video_offer() -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 100 96 97 45 46
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:100 VP9/90000
a=fmtp:100 profile-id=1
a=rtpmap:96 VP8/90000
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
a=rtpmap:45 foo/90000
a=rtpmap:46 rtx/90000
a=fmtp:46 apt=45
"
    ))
}

fn answer_to(
    pc: &mut RTCPeerConnection,
    offer: String,
) -> Result<String, Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

#[test]
fn with_the_setting_an_answer_lists_the_offered_formats_only_in_the_offers_order() -> TestResult {
    let answer = answer_to(&mut peer(true)?, video_offer())?;
    let section = &media_sections(&answer)[0];
    assert_ne!(port_of(section), 0, "{answer}");
    // VP9 profile 1 and VP8 in the offer's order, VP8's RTX; neither `foo` nor its RTX
    // (this endpoint does not have `foo`), and no format the offer lacks.
    assert_eq!(formats(section), vec!["100", "96", "97"], "{answer}");
    assert_eq!(encoding_name(section, "100"), "vp9", "{answer}");
    assert_eq!(encoding_name(section, "96"), "vp8", "{answer}");
    assert_eq!(attribute(section, "fmtp", "97"), Some("apt=96"), "{answer}");
    assert_rtx_repairs_a_listed_format(section);
    Ok(())
}

#[test]
fn without_the_setting_an_answer_adds_the_other_formats_after_the_offered_ones() -> TestResult {
    // The offered formats this endpoint has, in the offer's order (independent of the
    // setting's own code path).
    let offered_only = ["100", "96", "97"].map(str::to_owned);
    let answer = answer_to(&mut peer(false)?, video_offer())?;
    let section = &media_sections(&answer)[0];
    let answered = formats(section);
    assert!(
        answered.starts_with(&offered_only) && answered.len() > offered_only.len(),
        "the offered formats first, then the others: {answer}"
    );
    for pt in &answered[offered_only.len()..] {
        assert!(
            !["100", "96", "97", "45", "46"].contains(&pt.as_str()),
            "{pt} is not an offered payload type: {answer}"
        );
        assert_ne!(
            encoding_name(section, pt),
            "rtx",
            "no repair format is added: {answer}"
        );
    }
    assert_rtx_repairs_a_listed_format(section);
    Ok(())
}

/// A peer built without the call answers with the offered formats only (0.3.0 default: the
/// `Rfc` profile, and the `Chrome` one under the `chrome-defaults` feature, both say `true`).
#[test]
fn by_default_an_answer_lists_the_offered_formats_only() -> TestResult {
    let answer = answer_to(&mut build(SettingEngineBuilder::new())?, video_offer())?;
    let answered = formats(&media_sections(&answer)[0]);
    assert_eq!(answered, vec!["100", "96", "97"], "{answer}");
    Ok(())
}

#[test]
fn every_profile_but_strict_rfc_answers_the_offered_formats_only() -> TestResult {
    for (profile, offered_only) in [
        (BehaviourProfile::Chrome, true),
        (BehaviourProfile::Rfc, true),
        (BehaviourProfile::StrictRfc, false),
        (BehaviourProfile::Performance, true),
    ] {
        let answer = answer_to(
            &mut build(SettingEngineBuilder::new().with_behaviour_profile(profile))?,
            video_offer(),
        )?;
        let answered = formats(&media_sections(&answer)[0]);
        assert_eq!(
            answered == ["100", "96", "97"],
            offered_only,
            "{profile}: {answer}"
        );
    }
    Ok(())
}

/// An audio offer of Opus alone is answered with Opus alone.
#[test]
fn with_the_setting_an_opus_offer_is_answered_with_opus_alone() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
"
    ));
    let answer = answer_to(&mut peer(true)?, offer.clone())?;
    assert_eq!(
        formats(&media_sections(&answer)[0]),
        vec!["111"],
        "{answer}"
    );
    let answer = answer_to(&mut peer(false)?, offer)?;
    assert!(
        formats(&media_sections(&answer)[0]).len() > 1,
        "the default adds the other audio formats: {answer}"
    );
    Ok(())
}

/// Codec preferences that name a format the offer lacks: with the setting the answer still
/// lists only what was offered (libwebrtc negotiates the preferences against the offer).
///
/// The engine already answers so without the setting: on the mutation branch (the setting
/// read but not applied, agent-test run 45969404986) this test passed, so through the public
/// API preferences set after the offer never bring an unoffered format into the answer, and
/// the setting's filter over the preferred formats (`offered_formats_only`) is defensive. The
/// test pins the outcome, not the filter.
#[test]
fn with_the_setting_codec_preferences_add_no_format_the_offer_lacks() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 97
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
"
    ));
    let mut pc = peer(true)?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let id = pc.get_transceivers().next().expect("a transceiver");
    // The registered capabilities, read on a connection that negotiated nothing (the
    // answerer's own list narrows to what its offer had).
    let mut fresh = peer(true)?;
    let fresh_id = fresh.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let fresh_sender = fresh
        .rtp_transceiver(fresh_id)
        .expect("t")
        .sender()
        .expect("a sender");
    let capabilities = fresh
        .rtp_sender(fresh_sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs;
    let preferences: Vec<RTCRtpCodecParameters> = ["video/VP9", "video/VP8", "video/rtx"]
        .iter()
        .map(|mime| RTCRtpCodecParameters {
            rtp_codec: capabilities
                .iter()
                .find(|c| c.mime_type.eq_ignore_ascii_case(mime))
                .expect("a capability")
                .clone(),
            payload_type: 0,
        })
        .collect();
    pc.rtp_transceiver(id)
        .expect("t")
        .set_codec_preferences(preferences)?;
    let answer = pc.create_answer(None)?.sdp;
    let section = &media_sections(&answer)[0];
    let names: Vec<String> = formats(section)
        .iter()
        .map(|pt| encoding_name(section, pt))
        .collect();
    assert_eq!(names, vec!["vp8", "rtx"], "{answer}");
    assert_rtx_repairs_a_listed_format(section);
    Ok(())
}

/// The fmtp lines of `sdp` that have a `level-id`, with it set to `level` (the WPT's
/// `sdpModifyFmtpLevelId`).
fn with_level_id(sdp: &str, level: &str) -> String {
    sdp.split("\r\n")
        .map(|line| {
            let Some((head, parameters)) = line
                .strip_prefix("a=fmtp:")
                .and_then(|rest| rest.split_once(' '))
            else {
                return line.to_owned();
            };
            if !parameters
                .split(';')
                .any(|p| p.split_once('=').is_some_and(|(k, _)| k == "level-id"))
            {
                return line.to_owned();
            }
            let parameters: Vec<String> = parameters
                .split(';')
                .map(|p| match p.split_once('=') {
                    Some(("level-id", _)) => format!("level-id={level}"),
                    _ => p.to_owned(),
                })
                .collect();
            format!("a=fmtp:{head} {}", parameters.join(";"))
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The WPT scenario, up to the offerer's sender parameters: (the answer as the answerer
/// wrote it, the offerer's send codecs).
fn h265_level_id_scenario(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> Result<(String, Vec<RTCRtpCodecParameters>), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let id: RTCRtpTransceiverId = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit::with_direction(
            RTCRtpTransceiverDirection::Sendonly,
        )),
    )?;
    let sender = offerer
        .rtp_transceiver(id)
        .expect("t")
        .sender()
        .expect("a sender");
    let h265 = offerer
        .rtp_sender(sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs
        .into_iter()
        .find(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_HEVC))
        .expect("H.265 is a send capability");
    offerer
        .rtp_transceiver(id)
        .expect("t")
        .set_codec_preferences(vec![RTCRtpCodecParameters {
            rtp_codec: h265,
            payload_type: 0,
        }])?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    assert_eq!(
        formats(&media_sections(&offer.sdp)[0]).len(),
        1,
        "the offer has H.265 alone: {}",
        offer.sdp
    );
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    // "Modify SDP to tell `pc1` that `pc2` can only receive level-id=30."
    offerer.set_remote_description(
        now,
        RTCSessionDescription::answer(with_level_id(&answer.sdp, "30"))?,
    )?;
    let codecs = offerer
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    Ok((answer.sdp, codecs))
}

fn level_id(codec: &RTCRtpCodecParameters) -> Option<String> {
    codec
        .rtp_codec
        .sdp_fmtp_line
        .split(';')
        .find_map(|p| p.trim().strip_prefix("level-id=").map(str::to_owned))
}

/// WPT `webrtc/protocol/h265-level-id.https.html`, "Offer to send H265, answer to receive
/// level-id=30 results in level-id=30", with the answerer in the `Chrome` form: the answer
/// has one format, H.265, and the offerer's sender has exactly one codec, at level-id 30.
#[test]
fn with_the_setting_the_h265_level_id_scenario_answers_one_h265_format() -> TestResult {
    let (answer, codecs) = h265_level_id_scenario(&mut peer(false)?, &mut peer(true)?)?;
    let section = &media_sections(&answer)[0];
    let answered = formats(section);
    assert_eq!(answered.len(), 1, "{answer}");
    assert_eq!(encoding_name(section, &answered[0]), "h265", "{answer}");
    // assert_equals(params.codecs.length, 1); level-id 30.
    assert_eq!(codecs.len(), 1, "{codecs:?}");
    assert!(
        codecs[0]
            .rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_HEVC),
        "{codecs:?}"
    );
    assert_eq!(level_id(&codecs[0]).as_deref(), Some("30"), "{codecs:?}");
    Ok(())
}

/// The same scenario with an answerer in the setting's form (`peer(false)`, the default before
/// 0.3.0): the answer lists H.265 and then the other registered video formats (one of them
/// H.265 at most: the offered one). The offerer's send codecs are the answer's formats it can
/// send, the answer's first leading (RFC 9429 section 5.11, RFC 3264 section 7: conf/jsep-91):
/// H.265 at level-id 30 first, one codec per media format of the answer's m= line (its repair
/// formats, RTX / RED / FEC, are not send codecs).
#[test]
fn with_added_formats_the_h265_level_id_scenario_lists_the_answers_formats_h265_first() -> TestResult
{
    let (answer, codecs) = h265_level_id_scenario(&mut peer(false)?, &mut peer(false)?)?;
    let section = &media_sections(&answer)[0];
    let answered = formats(section);
    assert!(answered.len() > 1, "{answer}");
    assert_eq!(encoding_name(section, &answered[0]), "h265", "{answer}");
    assert_eq!(
        answered
            .iter()
            .filter(|pt| encoding_name(section, pt) == "h265")
            .count(),
        1,
        "{answer}"
    );
    let media_formats = answered
        .iter()
        .filter(|pt| {
            !matches!(
                encoding_name(section, pt).as_str(),
                "rtx" | "red" | "ulpfec" | "flexfec-03"
            )
        })
        .count();
    assert_eq!(codecs.len(), media_formats, "{answer}\n{codecs:?}");
    assert!(
        codecs[0]
            .rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_HEVC),
        "{codecs:?}"
    );
    assert_eq!(level_id(&codecs[0]).as_deref(), Some("30"), "{codecs:?}");
    Ok(())
}

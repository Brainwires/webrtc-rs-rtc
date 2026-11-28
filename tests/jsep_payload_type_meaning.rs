//! A dynamic payload type number keeps the format it was first given for the whole session
//! (RFC 3264 section 8.3.2: "the mapping from a particular dynamic payload type number to a
//! particular codec within that media stream MUST NOT change for the duration of a session";
//! RFC 9143 section 9.1.1: in a BUNDLE group "all codecs associated with the payload type
//! number MUST share an identical codec configuration"; W3C webrtc-pc `setCodecPreferences`: a
//! removed codec's "payload type is not to be reused in future offers or answers").
//!
//! The cases: a later offer drops a format, and the answer to it must not give that format's
//! number to one of this endpoint's formats the answer adds (RFC 9429 section 5.3.1); and a
//! later offer of this endpoint must not number one of its formats with a number an earlier
//! description gave another format, also one this endpoint never accepted.

mod jsep_common;

use std::collections::HashMap;
use std::time::Instant;

use jsep_common::{TRANSPORT, TestResult, crlf, default_peer, media_sections, peer_adding_formats};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;

/// A remote offer of one video section, `version` its `o=` session version (RFC 8866 section
/// 5.2: a later offer of the session increments it), `formats` the m= line's formats and
/// `lines` their attributes.
fn offer(version: u32, formats: &str, lines: &str) -> String {
    crlf(&format!(
        "v=0
o=- 4215775240449105457 {version} IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF {formats}
{TRANSPORT}a=mid:0
a=sendrecv
{lines}"
    ))
}

const VP8: &str = "a=rtpmap:96 VP8/90000\n";
/// H.264 Constrained Baseline on 98, the number the engine registers VP9 profile 0 under.
const H264_ON_98: &str = "a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
";
/// A format this endpoint does not have, on 98.
const FOO_ON_98: &str = "a=rtpmap:98 foo/90000\n";

/// Each payload type of each section (by its position) with its `a=rtpmap` encoding,
/// lower-cased (`vp8/90000`).
fn mappings(sdp: &str) -> Vec<HashMap<String, String>> {
    media_sections(sdp)
        .iter()
        .map(|section| {
            section
                .iter()
                .filter_map(|l| l.strip_prefix("a=rtpmap:"))
                .filter_map(|v| v.split_once(' '))
                .map(|(pt, encoding)| (pt.to_owned(), encoding.to_ascii_lowercase()))
                .collect()
        })
        .collect()
}

/// Every dynamic payload type `later` lists means what it meant in the first of `earlier`
/// that listed it, section by section.
fn assert_keeps_meanings(earlier: &[&str], later: &str, what: &str) {
    let later_maps = mappings(later);
    for (index, later_map) in later_maps.iter().enumerate() {
        for (pt, encoding) in later_map {
            let number: u8 = pt.parse().expect("a payload type");
            if !(96..=127).contains(&number) && !(35..=63).contains(&number) {
                continue;
            }
            let first = earlier
                .iter()
                .find_map(|sdp| mappings(sdp).get(index).and_then(|m| m.get(pt)).cloned());
            if let Some(first) = first {
                assert_eq!(
                    encoding,
                    &first,
                    "{what}: payload type {pt} of section {index} was {first} earlier in the \
                     session and is {encoding} now:\n{later}\n--- earlier ---\n{}",
                    earlier.join("\n---\n")
                );
            }
        }
    }
}

fn apply_offer(
    pc: &mut RTCPeerConnection,
    sdp: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(sdp.to_owned())?,
    )?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

/// Offer 1 gives 98 to H.264; offer 2 drops H.264. The answer to offer 2 adds the engine's
/// other formats (RFC 9429 section 5.3.1), VP9 among them, which the engine registers under
/// 98: it must take another number.
#[test]
fn an_answer_does_not_give_a_dropped_formats_number_to_a_format_it_adds() -> TestResult {
    let mut pc = peer_adding_formats()?; // the setting: the answer adds formats
    let offer1 = offer(2, "96 98", &format!("{VP8}{H264_ON_98}"));
    let answer1 = apply_offer(&mut pc, &offer1)?;
    assert_eq!(
        mappings(&answer1)[0].get("98").map(String::as_str),
        Some("h264/90000"),
        "the answer keeps the offer's number for H.264 (RFC 3264 6.1): {answer1}"
    );
    let offer2 = offer(3, "96", VP8);
    let answer2 = apply_offer(&mut pc, &offer2)?;
    assert_keeps_meanings(&[&offer1, &answer1, &offer2], &answer2, "answer 2");
    Ok(())
}

/// The same with a format this endpoint never accepted: offer 1 gave 98 to `foo`.
#[test]
fn an_answer_does_not_give_an_unaccepted_formats_number_to_a_format_it_adds() -> TestResult {
    let mut pc = peer_adding_formats()?; // the setting: the answer adds formats
    let offer1 = offer(2, "96 98", &format!("{VP8}{FOO_ON_98}"));
    let answer1 = apply_offer(&mut pc, &offer1)?;
    assert_keeps_meanings(&[&offer1], &answer1, "answer 1");
    let offer2 = offer(3, "96", VP8);
    let answer2 = apply_offer(&mut pc, &offer2)?;
    assert_keeps_meanings(&[&offer1, &answer1, &offer2], &answer2, "answer 2");
    Ok(())
}

/// The offer side: after the exchanges above, this endpoint's own offer (RFC 9429 section
/// 5.2.2: "all currently available formats") numbers VP9 too.
#[test]
fn a_later_offer_does_not_give_an_earlier_number_to_another_format() -> TestResult {
    for first_on_98 in [H264_ON_98, FOO_ON_98] {
        let mut pc = default_peer()?;
        let offer1 = offer(2, "96 98", &format!("{VP8}{first_on_98}"));
        let answer1 = apply_offer(&mut pc, &offer1)?;
        let offer2 = offer(3, "96", VP8);
        let answer2 = apply_offer(&mut pc, &offer2)?;
        let own = pc.create_offer(None)?.sdp;
        assert_keeps_meanings(
            &[&offer1, &answer1, &offer2, &answer2],
            &own,
            "this endpoint's offer",
        );
    }
    Ok(())
}

/// Directly after offer 1 too, before anything is dropped.
#[test]
fn an_offer_after_the_first_exchange_does_not_give_an_earlier_number_to_another_format()
-> TestResult {
    for first_on_98 in [H264_ON_98, FOO_ON_98] {
        let mut pc = default_peer()?;
        let offer1 = offer(2, "96 98", &format!("{VP8}{first_on_98}"));
        let answer1 = apply_offer(&mut pc, &offer1)?;
        let own = pc.create_offer(None)?.sdp;
        assert_keeps_meanings(&[&offer1, &answer1], &own, "this endpoint's offer");
    }
    Ok(())
}

/// A format that keeps its number: offer 2 still has H.264 on 98, and the answer keeps it
/// there (the history only ever avoids a number for another format).
#[test]
fn a_format_the_offer_keeps_keeps_its_number() -> TestResult {
    let mut pc = default_peer()?;
    let offer1 = offer(2, "96 98", &format!("{VP8}{H264_ON_98}"));
    let answer1 = apply_offer(&mut pc, &offer1)?;
    let offer2 = offer(3, "96 98", &format!("{VP8}{H264_ON_98}"));
    let answer2 = apply_offer(&mut pc, &offer2)?;
    assert_eq!(
        mappings(&answer2)[0].get("98").map(String::as_str),
        Some("h264/90000"),
        "{answer2}"
    );
    assert_keeps_meanings(&[&offer1, &answer1, &offer2], &answer2, "answer 2");
    Ok(())
}

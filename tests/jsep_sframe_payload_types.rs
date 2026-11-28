//! draft-ietf-avtcore-rtp-sframe-03 section 6 under BUNDLE: "If BUNDLE is in use and the
//! "a=sframe" attribute is present for a media section but not for another media section of
//! the same BUNDLE, payload types for media encodings that are relevant for SFrame MUST NOT be
//! reused between the two media sections." Each section keeps its own numbering through the
//! answer and later offers, its sender uses it, and a remote description that reuses a media
//! payload type across the two kinds of section is refused. RFC 9143 section 9.1.1 (one
//! payload type, one configuration in a group) still holds.

mod jsep_common;

use std::collections::HashMap;
use std::time::Instant;

use jsep_common::{
    TestResult, crlf, default_peer, exchange, media_sections, peer_adding_formats, video_track,
};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverId};

/// A section's formats: payload type -> (`a=rtpmap` encoding, `a=fmtp` parameters).
fn formats(section: &[String]) -> HashMap<u8, (String, String)> {
    let mut formats: HashMap<u8, (String, String)> = HashMap::new();
    for line in section {
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            let (pt, encoding) = rest.split_once(' ').expect("rtpmap");
            formats.entry(pt.parse().unwrap()).or_default().0 = encoding.to_ascii_lowercase();
        } else if let Some(rest) = line.strip_prefix("a=fmtp:") {
            let (pt, parameters) = rest.split_once(' ').expect("fmtp");
            formats.entry(pt.parse().unwrap()).or_default().1 = parameters.to_owned();
        }
    }
    formats
}

fn is_repair(encoding: &str) -> bool {
    let name = encoding.split('/').next().unwrap_or_default();
    name == "rtx" || name == "red" || name == "ulpfec" || name.starts_with("flexfec")
}

/// The media (not repair) payload types of a section.
fn media_payload_types(section: &[String]) -> Vec<u8> {
    let mut pts: Vec<u8> = formats(section)
        .into_iter()
        .filter(|(_, (encoding, _))| !is_repair(encoding))
        .map(|(pt, _)| pt)
        .collect();
    pts.sort();
    pts
}

/// Every RTX format of the section names a primary of the same section.
fn assert_rtx_in_section(section: &[String]) {
    let formats = formats(section);
    for (pt, (encoding, parameters)) in &formats {
        if encoding.starts_with("rtx/") {
            let apt: u8 = parameters
                .split(';')
                .find_map(|p| p.trim().strip_prefix("apt="))
                .expect("an apt")
                .parse()
                .unwrap();
            assert!(
                formats.get(&apt).is_some_and(|(e, _)| !is_repair(e)),
                "rtx {pt} repairs {apt}, not a media format of its section: {section:?}"
            );
        }
    }
}

/// An offerer with a plain video sender and one whose transform uses SFrame.
fn offerer()
-> Result<(RTCPeerConnection, RTCRtpSenderId, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    let plain = pc.add_track(video_track("plain", 0x5f01_0101))?;
    let sframe = pc.add_track(video_track("sframe", 0x5f02_0202))?;
    pc.rtp_transceiver(RTCRtpTransceiverId::from(sframe))
        .expect("transceiver")
        .set_transform_use_sframe(true)?;
    Ok((pc, plain, sframe))
}

fn bundled(sdp: &str) -> bool {
    sdp.lines().any(|l| l == "a=group:BUNDLE 0 1")
}

fn assert_disjoint(sdp: &str) {
    let sections = media_sections(sdp);
    let (plain, sframe) = (&sections[0], &sections[1]);
    assert!(sframe.iter().any(|l| l == "a=sframe"), "{sdp}");
    assert!(!plain.iter().any(|l| l == "a=sframe"), "{sdp}");
    let (a, b) = (media_payload_types(plain), media_payload_types(sframe));
    assert!(!a.is_empty() && !b.is_empty(), "{sdp}");
    assert!(
        a.iter().all(|pt| !b.contains(pt)),
        "plain {a:?} and SFrame {b:?} share a media payload type:\n{sdp}"
    );
    assert_rtx_in_section(plain);
    assert_rtx_in_section(sframe);
}

/// The offer, the answer and the next offer number the SFrame section's media formats apart
/// from the plain section's, RTX following its own section's primaries.
#[test]
fn an_sframe_section_numbers_its_formats_apart_from_a_plain_one_in_the_bundle() -> TestResult {
    let (mut offerer, _, _) = offerer()?;
    let mut answerer = default_peer()?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    assert!(bundled(&offer), "{offer}");
    assert_disjoint(&offer);
    assert_disjoint(&answer);
    let (reoffer, reanswer) = exchange(&mut offerer, &mut answerer)?;
    assert_disjoint(&reoffer);
    assert_disjoint(&reanswer);
    // The numbering does not move between exchanges (RFC 3264 section 8.3.2).
    for (first, second) in [(&offer, &reoffer), (&answer, &reanswer)] {
        let (a, b) = (media_sections(first), media_sections(second));
        for i in 0..2 {
            assert_eq!(media_payload_types(&a[i]), media_payload_types(&b[i]));
        }
    }
    // The answerer's own offer keeps each section's numbering too.
    let (third, _) = exchange(&mut answerer, &mut offerer)?;
    assert_disjoint(&third);
    Ok(())
}

/// Each sender sends with its own section's numbering: the SFrame sender's codecs are among
/// the SFrame section's payload types, the plain sender's among the plain section's (the two
/// are disjoint, so neither sends the other's).
#[test]
fn each_sender_uses_its_own_sections_payload_types() -> TestResult {
    let (mut offerer, plain, sframe) = offerer()?;
    let mut answerer = default_peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    let sections = media_sections(&answer);
    for (sender, section) in [(plain, &sections[0]), (sframe, &sections[1])] {
        let expected = media_payload_types(section);
        let mut sent: Vec<u8> = offerer
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .filter(|c| {
                !is_repair(
                    &c.rtp_codec
                        .mime_type
                        .to_ascii_lowercase()
                        .replace("video/", ""),
                )
            })
            .map(|c| c.payload_type)
            .collect();
        sent.sort();
        // The track asks for VP8 (`video_track`): the sender sends the section's VP8.
        assert!(!sent.is_empty(), "{answer}");
        assert!(
            sent.iter().all(|pt| expected.contains(pt)),
            "{sent:?} not all of {expected:?}: {answer}"
        );
    }
    Ok(())
}

const SESSION: &str = "v=0
o=- 1 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF
a=ice-ufrag:Ab1c
a=ice-pwd:9/9muCWoOi3uLifh0NuRHlkwz
";

fn section(mid: &str, pt: u8, sframe: bool) -> String {
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF {pt}
c=IN IP4 0.0.0.0
a=setup:actpass
a=mid:{mid}
a=sendrecv
a=rtcp-mux
a=rtpmap:{pt} VP8/90000
{}",
        if sframe { "a=sframe\n" } else { "" }
    )
}

/// A remote offer whose SFrame section and plain section of one BUNDLE group number VP8 with
/// the same payload type is refused; numbered apart, it is applied and answered with both
/// numbers.
#[test]
fn a_remote_offer_reusing_a_payload_type_across_sframe_and_plain_sections_is_refused() -> TestResult
{
    let mut pc = peer_adding_formats()?; // the answer adds formats: their numbering is checked
    let shared = crlf(&format!(
        "{SESSION}{}{}",
        section("0", 96, false),
        section("1", 96, true)
    ));
    assert!(
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(shared)?)
            .is_err()
    );

    let apart = crlf(&format!(
        "{SESSION}{}{}",
        section("0", 96, false),
        section("1", 120, true)
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(apart)?)?;
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    // The offered format first in each section; the formats the answer adds after it (RFC
    // 9429 section 5.3.1) keep the two numberings apart too.
    for (section, offered) in [(&sections[0], 96u8), (&sections[1], 120u8)] {
        let first: u8 = section[0]
            .split_whitespace()
            .nth(3)
            .and_then(|pt| pt.parse().ok())
            .expect("a format");
        assert_eq!(first, offered, "{}", answer.sdp);
    }
    assert_disjoint(&answer.sdp);
    Ok(())
}

/// With one section per kind negotiated (`with_disable_media_engine_multiple_codecs(true)`)
/// the SFrame section still keeps its own numbering: the offerer's SFrame sender sends among
/// the SFrame section's payload types of the answer, not the plain section's.
#[test]
fn the_sframe_numbering_survives_single_section_negotiation() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    let peer = || -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_disable_media_engine_multiple_codecs(true)
                    .build(),
            )
            .build(Instant::now())?)
    };
    let mut offerer = peer()?;
    offerer.add_track(video_track("plain", 0x5f03_0101))?;
    let sframe = offerer.add_track(video_track("sframe", 0x5f03_0202))?;
    offerer
        .rtp_transceiver(RTCRtpTransceiverId::from(sframe))
        .expect("transceiver")
        .set_transform_use_sframe(true)?;
    let mut answerer = peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_disjoint(&answer);
    let sections = media_sections(&answer);
    let (plain, expected) = (
        media_payload_types(&sections[0]),
        media_payload_types(&sections[1]),
    );
    let codecs: Vec<u8> = offerer
        .rtp_sender(sframe)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .map(|c| c.payload_type)
        .collect();
    assert!(
        codecs.iter().any(|pt| expected.contains(pt)),
        "the SFrame sender has the SFrame section's formats: {codecs:?}\n{answer}"
    );
    assert!(
        codecs.iter().all(|pt| !plain.contains(pt)),
        "and none of the plain section's: {codecs:?}\n{answer}"
    );
    Ok(())
}

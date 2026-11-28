//! `SettingEngineBuilder::with_answer_offered_formats_only(false)` (the `StrictRfc` profile;
//! the default before 0.3.0, which lists the offered formats only):
//! RFC 9429 section 5.3.1: without codec preferences, "Any currently available media formats
//! that are not present in the current remote description MUST be added after all existing
//! formats" of an answer (RFC 3264 section 6.1: the answerer "MAY" list formats the offer did
//! not have, which the offerer can use in a later offer). The offerer does not send them.

mod jsep_common;

use jsep_common::{
    TestResult, default_peer, exchange, media_sections, peer_adding_formats, video_track,
};
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MIME_TYPE_VP9};
use rtci::rtp_transceiver::RTCRtpTransceiverId;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};

fn formats(section: &[String]) -> Vec<String> {
    section[0]
        .split_whitespace()
        .skip(3)
        .map(str::to_owned)
        .collect()
}

fn rtpmap_of<'a>(section: &'a [String], pt: &str) -> &'a str {
    let prefix = format!("a=rtpmap:{pt} ");
    section
        .iter()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("an rtpmap for {pt}: {section:?}"))
}

#[test]
fn an_answer_lists_its_other_formats_after_the_offered_ones() -> TestResult {
    let mut offerer = default_peer()?;
    // The setting's form (the default before 0.3.0; `StrictRfc`).
    let mut answerer = peer_adding_formats()?;
    let sender = offerer.add_track(video_track("v", 0x0e11_0101))?;
    let vp8: Vec<RTCRtpCodecParameters> = offerer
        .rtp_sender(sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities")
        .codecs
        .into_iter()
        .filter(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
        .map(|rtp_codec| RTCRtpCodecParameters {
            rtp_codec,
            payload_type: 0,
        })
        .collect();
    offerer
        .rtp_transceiver(RTCRtpTransceiverId::from(sender))
        .expect("t")
        .set_codec_preferences(vp8)?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let offered = formats(&media_sections(&offer)[0]);
    assert_eq!(offered.len(), 1, "{offer}");
    let answered_section = &media_sections(&answer)[0];
    let answered = formats(answered_section);
    assert_eq!(
        answered[0], offered[0],
        "the offered format first: {answer}"
    );
    assert!(
        answered[1..]
            .iter()
            .any(|pt| rtpmap_of(answered_section, pt).starts_with("VP9/")),
        "VP9, which the offer did not have, is added after it: {answer}"
    );
    assert!(
        answered[1..]
            .iter()
            .all(|pt| !rtpmap_of(answered_section, pt).starts_with("rtx/")),
        "no repair format is added: {answer}"
    );
    assert!(
        !answered_section.iter().any(|l| answered[1..]
            .iter()
            .any(|pt| l.starts_with(&format!("a=rtcp-fb:{pt} ")))),
        "an added format has no feedback: {answer}"
    );

    // The offerer may send with every format of the answer it can send (W3C webrtc-pc
    // [[SendCodecs]]: "the codecs that description negotiates for sending and which the user
    // agent is currently capable of sending"; jsep-91), VP9 included, and sends with the
    // answer's first, VP8 (RFC 9429 section 5.11, RFC 3264 section 7). Before jsep-91 the
    // added format was left out of the send codecs.
    let parameters = offerer
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .clone();
    let codecs = &parameters.rtp_parameters.codecs;
    assert!(
        codecs
            .first()
            .is_some_and(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8)),
        "{codecs:?}"
    );
    assert!(
        codecs
            .iter()
            .any(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP9)),
        "{codecs:?}"
    );
    Ok(())
}

/// RFC 9429 section 5.3.1: "If codec preferences have been set for the associated
/// transceiver, media formats MUST be generated in the corresponding order, regardless of what
/// was offered, and MUST exclude any codecs not present in the codec preferences": nothing
/// the offer lacks is added then either.
#[test]
fn with_codec_preferences_an_answer_has_them_in_their_order_and_nothing_else() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    // Every registered video format is offered, VP8 ahead of VP9.
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(std::time::Instant::now(), offer.clone())?;
    answerer.set_remote_description(std::time::Instant::now(), offer)?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    // The registered capabilities (a connection's own narrow to what was negotiated).
    let mut fresh = default_peer()?;
    let fresh_sender = fresh.add_track(video_track("c", 0x0e11_0301))?;
    let capabilities = fresh
        .rtp_sender(fresh_sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs;
    let pick = |mime: &str, payload_type: u8| -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: capabilities
                .iter()
                .find(|c| c.mime_type.eq_ignore_ascii_case(mime))
                .expect("a capability")
                .clone(),
            payload_type,
        }
    };
    // The engine's default payload types: VP8 96, VP9 (profile 0) 98.
    let preferences = vec![pick(MIME_TYPE_VP9, 98), pick(MIME_TYPE_VP8, 96)];
    answerer
        .rtp_transceiver(id)
        .expect("t")
        .set_codec_preferences(preferences)?;
    let answer = answerer.create_answer(None)?.sdp;
    let section = &media_sections(&answer)[0];
    let names: Vec<String> = formats(section)
        .iter()
        .map(|pt| {
            rtpmap_of(section, pt)
                .split('/')
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    assert_eq!(names, vec!["VP9".to_owned(), "VP8".to_owned()], "{answer}");
    Ok(())
}

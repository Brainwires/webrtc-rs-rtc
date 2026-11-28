//! The simulcast streams a remote answer rejects, in the offers that follow (RFC 9429 section
//! 5.2.2 against W3C webrtc-pc "set the RTCSessionDescription" and `createOffer`).
//!
//! W3C, the default: "If description is missing any of the previously negotiated layers, then
//! remove the dictionaries that correspond to the missing layers from
//! transceiver.[[Sender]].[[SendEncodings]]", and `createOffer` writes "an a=rid send line" for
//! "each encoding given in [[SendEncodings]]": the next offer lists only the kept streams.
//! RFC 9429 section 5.2.2, with `SettingEngineBuilder::with_rejected_rids_kept_in_offers(true)`:
//! "For RtpTransceivers that are still present, the "a=rid" lines MUST stay the same" and "any
//! "a=simulcast" line MUST stay the same"; the sender still sends only what the answer kept
//! (RFC 8853 section 5.3.3), and a later answer may accept a stream again (section 5.3.4).
//!
//! Every peer states the settings these tests depend on, so they hold under every behaviour
//! profile (the `chrome-defaults` feature included).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, crlf, media_sections, mid_of, vp8};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRidRestrictions, RtpCodecKind,
};

const LAYERS: [(&str, u64); 3] = [("f", 1280), ("h", 640), ("q", 320)];

/// A peer of the RFC profile with the rejected streams kept in later offers (`kept`) and the
/// `~` pause marks written (`pause_marks`), or not.
fn peer(kept: bool, pause_marks: bool) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Rfc);
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_behaviour_profile(BehaviourProfile::Rfc)
                .with_rejected_rids_kept_in_offers(kept)
                .with_rid_pause_marks(pause_marks)
                .with_w3c_simulcast_answer(false)
                .build(),
        )
        .build(Instant::now())?)
}

/// A VP8 track with the encodings f, h, q (max-width 1280, 640, 320).
fn simulcast_track() -> MediaStreamTrack {
    let encodings = LAYERS
        .iter()
        .enumerate()
        .map(|(i, (rid, max_width))| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ssrc: Some(0x0593_0000 + i as u32),
                rid_restrictions: RTCRtpRidRestrictions {
                    max_width: Some(*max_width),
                    ..Default::default()
                },
                ..Default::default()
            },
            codec: vp8(),
            active: true,
            ..Default::default()
        })
        .collect();
    MediaStreamTrack::new(
        "simulcast-stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    )
}

/// The rids of the sender's encodings, as `getParameters` gives them.
fn sent_rids(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> Vec<String> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings
        .iter()
        .map(|e| e.rtp_coding_parameters.rid.clone())
        .collect()
}

/// The lines of the video section (mid 0) of `sdp` that start with `prefix`.
fn section_lines(sdp: &str, prefix: &str) -> Vec<String> {
    media_sections(sdp)
        .into_iter()
        .find(|section| mid_of(section) == Some("0"))
        .unwrap_or_default()
        .into_iter()
        .filter(|line| line.starts_with(prefix))
        .collect()
}

fn strings(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| (*line).to_owned()).collect()
}

/// `sdp` with each line of `drop` left out; each must be in it.
fn without_lines(sdp: &str, drop: &[&str]) -> String {
    let sdp = sdp.replace("\r\n", "\n");
    for line in drop {
        assert!(sdp.lines().any(|l| l == *line), "`{line}` is not in\n{sdp}");
    }
    sdp.lines()
        .filter(|line| !drop.contains(line))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// `sdp` with `from` replaced by `to`, which must occur in it.
fn edited(sdp: &str, from: &str, to: &str) -> String {
    assert!(sdp.contains(from), "`{from}` is not in\n{sdp}");
    sdp.replace(from, to)
}

/// How the remote answer to the first offer treats the stream q.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Leaves q out of `a=rid` and `a=simulcast` (RFC 8853 section 5.3.2: an answerer "MAY
    /// reduce the number of simulcast streams").
    RejectsQ,
    /// Has no `a=rid` and no `a=simulcast` at all: no simulcast, the first encoding stays.
    NoSimulcast,
}

/// Two peers after the first exchange, the offerer's sender and its first offer.
struct Negotiated {
    offerer: RTCPeerConnection,
    answerer: RTCPeerConnection,
    sender: RTCRtpSenderId,
    first_offer: String,
}

/// The first exchange: `offerer` sends f, h, q, and applies the answer of an RFC-profile
/// answerer edited as `answer` says (the answerer applied its own answer unedited).
fn negotiated(
    mut offerer: RTCPeerConnection,
    answer: Answer,
) -> Result<Negotiated, Box<dyn std::error::Error>> {
    let sender = offerer.add_track(simulcast_track())?;
    let mut answerer = peer(false, false)?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer.clone())?;
    let local_answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, local_answer.clone())?;
    let remote_answer = match answer {
        Answer::RejectsQ => edited(
            &without_lines(&local_answer.sdp, &["a=rid:q recv max-width=320"]),
            "a=simulcast:recv f;h;q",
            "a=simulcast:recv f;h",
        ),
        Answer::NoSimulcast => without_lines(
            &local_answer.sdp,
            &[
                "a=rid:f recv max-width=1280",
                "a=rid:h recv max-width=640",
                "a=rid:q recv max-width=320",
                "a=simulcast:recv f;h;q",
            ],
        ),
    };
    offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&remote_answer))?)?;
    Ok(Negotiated {
        offerer,
        answerer,
        sender,
        first_offer: offer.sdp,
    })
}

const FIRST_RID_LINES: [&str; 3] = [
    "a=rid:f send max-width=1280",
    "a=rid:h send max-width=640",
    "a=rid:q send max-width=320",
];

/// The default, W3C webrtc-pc 4.4.1.6 ("remove the dictionaries that correspond to the missing
/// layers") and `createOffer` ("for each encoding given in [[SendEncodings]] ... add an a=rid
/// send line ... and add an a=simulcast:send line giving the RIDs in the same order"): after an
/// answer that rejected q, the sender has f and h, and the next offer lists only them; after
/// an answer without simulcast, only f is left and the next offer has neither line (one
/// encoding: "If the length of the [[SendEncodings]] slot ... is larger than 1").
#[test]
fn by_default_a_later_offer_leaves_out_the_streams_an_answer_rejected() -> TestResult {
    let mut failures = vec![];
    for (answer, kept, rids, simulcast) in [
        (
            Answer::RejectsQ,
            vec!["f", "h"],
            vec!["a=rid:f send max-width=1280", "a=rid:h send max-width=640"],
            vec!["a=simulcast:send f;h"],
        ),
        (Answer::NoSimulcast, vec!["f"], vec![], vec![]),
    ] {
        let Negotiated {
            mut offerer,
            sender,
            first_offer,
            ..
        } = negotiated(peer(false, false)?, answer)?;
        assert_eq!(
            section_lines(&first_offer, "a=rid:"),
            strings(&FIRST_RID_LINES)
        );
        let sent = sent_rids(&mut offerer, sender);
        let next = offerer.create_offer(None)?.sdp;
        let seen = (
            sent,
            section_lines(&next, "a=rid:"),
            section_lines(&next, "a=simulcast:"),
        );
        let expected = (strings(&kept), strings(&rids), strings(&simulcast));
        if seen != expected {
            failures.push(format!(
                "{answer:?}: sender, a=rid, a=simulcast {seen:?}, expected {expected:?}\n{next}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// RFC 9429 section 5.2.2, with `with_rejected_rids_kept_in_offers(true)`: "For RtpTransceivers
/// that are still present, the "a=rid" lines MUST stay the same" and "any "a=simulcast" line
/// MUST stay the same", also after an answer rejected q (or all simulcast): the next offer's
/// lines are the first offer's, while the sender sends only what the answer kept (RFC 8853
/// section 5.3.3: "MUST NOT send any RTP packets corresponding to the removed rid-ids";
/// `getParameters` lists those). With pause marks written, the rejected stream is listed
/// paused (`~q`, RFC 8853 section 5.3.4: the offerer's "current pause state"), as libwebrtc
/// writes it; its a=rid line stays the same.
#[test]
fn with_the_setting_a_later_offer_keeps_the_streams_an_answer_rejected() -> TestResult {
    let mut failures = vec![];
    for (answer, pause_marks, kept, simulcast) in [
        (
            Answer::RejectsQ,
            false,
            vec!["f", "h"],
            "a=simulcast:send f;h;q",
        ),
        (
            Answer::NoSimulcast,
            false,
            vec!["f"],
            "a=simulcast:send f;h;q",
        ),
        (
            Answer::RejectsQ,
            true,
            vec!["f", "h"],
            "a=simulcast:send f;h;~q",
        ),
    ] {
        let Negotiated {
            mut offerer,
            sender,
            first_offer,
            ..
        } = negotiated(peer(true, pause_marks)?, answer)?;
        assert_eq!(
            section_lines(&first_offer, "a=rid:"),
            strings(&FIRST_RID_LINES)
        );
        assert_eq!(
            section_lines(&first_offer, "a=simulcast:"),
            strings(&["a=simulcast:send f;h;q"])
        );
        let sent = sent_rids(&mut offerer, sender);
        let next = offerer.create_offer(None)?.sdp;
        let seen = (
            sent,
            section_lines(&next, "a=rid:"),
            section_lines(&next, "a=simulcast:"),
        );
        let expected = (
            strings(&kept),
            strings(&FIRST_RID_LINES),
            strings(&[simulcast]),
        );
        if seen != expected {
            failures.push(format!(
                "{answer:?}, pause marks {pause_marks}: sender, a=rid, a=simulcast {seen:?}, \
                 expected {expected:?}\n{next}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// RFC 8853 section 5.3.4 ("Offers inside an existing session follow the same rules as for
/// initial SDP offer") and 5.3.3 (the offerer "MAY send any of the kept "receive"-direction
/// rid-id alternatives"), with `with_rejected_rids_kept_in_offers(true)`: the later offer
/// lists q again, an answer that accepts it is applied, and the sender has its three encodings
/// again, q in its first place; the offer after that still has the first offer's lines. By
/// default the later offer has no q to accept and the sender stays at f, h.
#[test]
fn a_later_answer_may_accept_a_rejected_stream_again() -> TestResult {
    let mut failures = vec![];
    for (kept, expected) in [(true, vec!["f", "h", "q"]), (false, vec!["f", "h"])] {
        let Negotiated {
            mut offerer,
            mut answerer,
            sender,
            first_offer,
        } = negotiated(peer(kept, false)?, Answer::RejectsQ)?;
        let now = Instant::now();
        let reoffer = offerer.create_offer(None)?;
        offerer.set_local_description(now, reoffer.clone())?;
        answerer.set_remote_description(now, reoffer)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        offerer.set_remote_description(now, answer.clone())?;
        let sent = sent_rids(&mut offerer, sender);
        if sent != strings(&expected) {
            failures.push(format!(
                "kept {kept}: sender {sent:?}, expected {expected:?}; the answer\n{}",
                answer.sdp
            ));
        }
        if kept {
            let after = offerer.create_offer(None)?.sdp;
            for prefix in ["a=rid:", "a=simulcast:"] {
                if section_lines(&after, prefix) != section_lines(&first_offer, prefix) {
                    failures.push(format!(
                        "kept: {prefix} of the offer after re-acceptance {:?}, first {:?}",
                        section_lines(&after, prefix),
                        section_lines(&first_offer, prefix)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// rid-1 (RFC 8851 section 10 as corrected by erratum 7132, `rid-id = 1*255(alpha-numeric)`)
/// together with `with_rejected_rids_kept_in_offers(true)`, through the statement that applies
/// a remote simulcast answer to the sender (`apply_negotiated_simulcast`: the rids of the
/// answer read with the connection's rid-id grammar, then `apply_simulcast_answer(&accepted,
/// keep_rejected)`).
///
/// A rid outside the grammar cannot be among that statement's accepted streams: an `a=rid`
/// line that `a=simulcast` does not name is no simulcast stream (nor one the offer sent), and
/// an `a=simulcast` that names it refuses the description before anything is applied (RFC 9429
/// section 5.8; RFC 8853 section 5.1 takes its rid-id from RFC 8851). So the answer that
/// accepts f and h, rejects q and names `a-b` is refused and changes nothing (signaling state,
/// encodings f h q); the same answer with `a=rid:a-b recv` left unnamed is applied (the line is
/// discarded, RFC 8851 section 6.2.2 step 1): the sender has f and h, and the next offer keeps
/// q's lines (RFC 9429 section 5.2.2) and has no `a-b`.
#[test]
fn a_rid_outside_the_grammar_never_reaches_the_simulcast_answer_and_the_rejected_rid_is_kept()
-> TestResult {
    let mut offerer = peer(true, false)?;
    let sender = offerer.add_track(simulcast_track())?;
    let mut answerer = peer(false, false)?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let local_answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, local_answer.clone())?;
    let rejects_q = edited(
        &without_lines(&local_answer.sdp, &["a=rid:q recv max-width=320"]),
        "a=simulcast:recv f;h;q",
        "a=simulcast:recv f;h",
    );
    let with_a_b_line = edited(
        &rejects_q,
        "a=rid:h recv max-width=640\n",
        "a=rid:h recv max-width=640\na=rid:a-b recv\n",
    );

    // Named by a=simulcast: the description is refused, nothing changes.
    let named = edited(
        &with_a_b_line,
        "a=simulcast:recv f;h\n",
        "a=simulcast:recv f;h;a-b\n",
    );
    let refused = offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&named))?);
    assert!(
        matches!(refused, Err(rtci::shared::error::Error::SdpInvalidValue(ref reason)) if reason.contains("a=simulcast")),
        "an a=simulcast naming a-b refuses the answer: {refused:?}"
    );
    assert_eq!(
        offerer.signaling_state(),
        rtci::peer_connection::state::RTCSignalingState::HaveLocalOffer
    );
    assert_eq!(sent_rids(&mut offerer, sender), strings(&["f", "h", "q"]));

    // Left unnamed: the answer applies, the a-b line is discarded, q is kept for the offers.
    offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&with_a_b_line))?)?;
    assert_eq!(sent_rids(&mut offerer, sender), strings(&["f", "h"]));
    let next = offerer.create_offer(None)?.sdp;
    assert_eq!(
        (
            section_lines(&next, "a=rid:"),
            section_lines(&next, "a=simulcast:")
        ),
        (
            strings(&FIRST_RID_LINES),
            strings(&["a=simulcast:send f;h;q"])
        ),
        "the next offer keeps q\n{next}"
    );
    assert!(!next.contains("a-b"), "no a-b in the next offer\n{next}");
    Ok(())
}

/// The other side of the test above, where the grammar argument of that statement decides the
/// outcome: with `with_published_rid_id_grammar(true)` (and the rejected rids kept), an answer
/// whose `a=simulcast` names f, h and `a-b` (and rejects q) passes the refusal checks, which read
/// the published grammar. The statement reads the same grammar, so the line parses: f and h are
/// accepted, `a-b` matches no rid this endpoint offered and is not taken, q stays in the next
/// offer. Read with the corrected grammar there instead, the whole `a=simulcast` line would fail
/// to parse and be ignored: an answer without simulcast, which leaves the sender its first
/// encoding only (h lost with the line).
#[test]
fn with_the_published_grammar_an_answer_naming_a_b_keeps_every_stream_it_accepts() -> TestResult {
    let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Rfc);
    media_engine.register_default_codecs()?;
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_behaviour_profile(BehaviourProfile::Rfc)
                .with_rejected_rids_kept_in_offers(true)
                .with_rid_pause_marks(false)
                .with_w3c_simulcast_answer(false)
                .with_published_rid_id_grammar(true)
                .build(),
        )
        .build(Instant::now())?;
    let sender = offerer.add_track(simulcast_track())?;
    let mut answerer = peer(false, false)?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let local_answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, local_answer.clone())?;
    let named = edited(
        &edited(
            &without_lines(&local_answer.sdp, &["a=rid:q recv max-width=320"]),
            "a=simulcast:recv f;h;q",
            "a=simulcast:recv f;h;a-b",
        ),
        "a=rid:h recv max-width=640\n",
        "a=rid:h recv max-width=640\na=rid:a-b recv\n",
    );
    offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&named))?)?;
    assert_eq!(
        sent_rids(&mut offerer, sender),
        strings(&["f", "h"]),
        "the sender keeps every stream the answer accepted"
    );
    let next = offerer.create_offer(None)?.sdp;
    assert_eq!(
        (
            section_lines(&next, "a=rid:"),
            section_lines(&next, "a=simulcast:")
        ),
        (
            strings(&FIRST_RID_LINES),
            strings(&["a=simulcast:send f;h;q"])
        ),
        "the next offer keeps q\n{next}"
    );
    assert!(!next.contains("a-b"), "no a-b in the next offer\n{next}");
    Ok(())
}

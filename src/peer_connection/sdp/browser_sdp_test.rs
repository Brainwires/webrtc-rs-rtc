//! Real descriptions, as browsers and deployed stacks wrote them, through the remote-description
//! checks: every file of `tests/fixtures/browser-sdp/` (named
//! `<writer>[-<version>]--<scenario>--<n>-<offer|answer>.sdp`; the browser files are recorded by the
//! interop harness, `scripts/test-env/interop/common.mjs` `recordDescriptions`, the webrtc-rs
//! ones by `tests/webrtc_0_17_descriptions_interop.rs`).
//!
//! What a writer really puts on the wire must not be refused with the default settings: a form
//! the strict reading of a grammar refuses is a documented tolerance
//! (`check_attribute_lines`), not a refusal.

use std::path::PathBuf;
use std::time::Instant;

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::media_engine::MediaEngine;

struct Fixture {
    name: String,
    answer: bool,
    sdp: String,
}

fn fixtures() -> Vec<Fixture> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/browser-sdp");
    let mut out: Vec<Fixture> = std::fs::read_dir(&dir)
        .expect("tests/fixtures/browser-sdp exists")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "sdp"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let answer = name.ends_with("-answer.sdp");
            assert!(
                answer || name.ends_with("-offer.sdp"),
                "{name}: a fixture's name ends with -offer.sdp or -answer.sdp"
            );
            // The files keep the line endings they were written with.
            let sdp = std::fs::read_to_string(&path).expect("a readable fixture");
            Fixture { name, answer, sdp }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn parsed(fixture: &Fixture) -> SessionDescription {
    RTCSessionDescription {
        sdp_type: if fixture.answer {
            RTCSdpType::Answer
        } else {
            RTCSdpType::Offer
        },
        sdp: fixture.sdp.clone(),
        parsed: None,
    }
    .unmarshal()
    .unwrap_or_else(|e| panic!("{}: does not parse: {e}", fixture.name))
}

#[test]
fn the_fixtures_cover_every_writer_the_interop_tests_meet() {
    let names: Vec<String> = fixtures().into_iter().map(|f| f.name).collect();
    for writer in ["chromium", "firefox", "webkit", "webrtc-rs-0.17"] {
        assert!(
            names.iter().any(|n| n.starts_with(writer)),
            "no fixture written by {writer}: {names:?}"
        );
    }
}

#[test]
fn every_attribute_real_writers_put_in_a_description_passes_the_grammar_check() {
    let mut refused = vec![];
    for fixture in fixtures() {
        let desc = parsed(&fixture);
        if let Err(e) = check_attribute_lines(&desc, false, RidIdGrammar::Corrected) {
            refused.push(format!("{}: {e}", fixture.name));
        }
    }
    assert!(refused.is_empty(), "refused: {refused:#?}");
}

#[test]
fn real_answers_take_a_dtls_role_and_bundled_payload_types_agree() {
    for fixture in fixtures() {
        let desc = parsed(&fixture);
        if fixture.answer {
            assert!(
                !crate::peer_connection::has_setup_value(&desc, "actpass"),
                "{}: an answer with a=setup:actpass",
                fixture.name
            );
        }
        crate::peer_connection::check_bundled_payload_types(&desc)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        crate::peer_connection::check_pause_lines(&desc)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
    }
}

/// An offer is applied whole, every check of `set_remote_description` included, by a peer with
/// the default codecs and settings.
#[test]
fn real_offers_are_accepted_as_remote_descriptions() {
    let mut refused = vec![];
    for fixture in fixtures().into_iter().filter(|f| !f.answer) {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("default codecs");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())
            .expect("a peer connection");
        if let Err(e) = pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(fixture.sdp.clone()).expect("an offer"),
        ) {
            refused.push(format!("{}: the offer is refused: {e}", fixture.name));
        }
    }
    assert!(refused.is_empty(), "{refused:#?}");
}

/// The tolerances the default reading has over the strict one
/// (`SettingEngineBuilder::with_strict_sdp_attribute_grammar(true)`), each with the writers
/// that need it: a fixture the strict reading refuses must be refused for one of these and
/// nothing else, so a new form a real writer uses is either tolerated and listed here or
/// fixed.
///
/// - white space at the end of an attribute value (in `a=rtcp-fb`, RFC 4585 section 4.2's
///   `rtcp-fb-param` allows none): webrtc-rs 0.17.x (and Pion before v4.1.5) writes a feedback
///   without parameters as `a=rtcp-fb:96 goog-remb ` in the text `create_offer` and
///   `create_answer` return (`format!("{} {} {}", pt, typ, parameter)`); the description it
///   re-writes once candidates are gathered has no such space.
fn needs_a_tolerance(desc: &SessionDescription) -> bool {
    desc.attributes
        .iter()
        .chain(
            desc.media_descriptions
                .iter()
                .flat_map(|m| m.attributes.iter()),
        )
        .filter_map(|a| a.value.as_deref())
        .any(|v| v.len() != v.trim_end().len())
}

#[test]
fn the_strict_grammar_refuses_real_descriptions_only_for_the_listed_tolerances() {
    let mut unexpected = vec![];
    for fixture in fixtures() {
        let desc = parsed(&fixture);
        let strict = check_attribute_lines(&desc, true, RidIdGrammar::Corrected);
        if strict.is_err() != needs_a_tolerance(&desc) {
            unexpected.push(format!("{}: strict reading {strict:?}", fixture.name));
        }
    }
    assert!(unexpected.is_empty(), "{unexpected:#?}");
}

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use interceptor::Registry;
use std::collections::BTreeSet;
use std::time::Instant;

fn read(
    row: &GovernedBehaviour,
    s: &SettingEngine,
    m: &MediaEngine,
    o: &DefaultInterceptorOptions,
) -> String {
    match row.hook {
        Hook::Setting { read, .. } => read(s),
        Hook::Media { read, .. } => read(m),
        Hook::Interceptors { read, .. } => read(o),
    }
}

/// Every governed value, as each profile sets it, is the value the table states.
#[test]
fn each_profile_sets_every_governed_value_the_table_states() {
    for profile in BehaviourProfile::ALL {
        let setting_engine = SettingEngineBuilder::new()
            .with_behaviour_profile(profile)
            .build();
        let media_engine = MediaEngine::for_profile(profile);
        let options = DefaultInterceptorOptions::for_profile(profile);
        assert_eq!(setting_engine.behaviour_profile(), profile);
        assert_eq!(media_engine.behaviour_profile(), profile);
        for row in GOVERNED {
            assert_eq!(
                read(row, &setting_engine, &media_engine, &options),
                row.value(profile),
                "{} under {profile}",
                row.id
            );
        }
    }
}

/// `Rfc` changes nothing: the table's `Rfc` column is what the engine's own defaults are,
/// before any profile is applied.
#[test]
fn the_rfc_profile_is_the_engines_defaults_unchanged() {
    let setting_engine = SettingEngine::rfc_base();
    let media_engine = MediaEngine::rfc_base();
    let options = DefaultInterceptorOptions::rfc_base();
    for row in GOVERNED {
        assert_eq!(
            read(row, &setting_engine, &media_engine, &options),
            row.rfc,
            "{}: the Rfc column is not the engine's default",
            row.id
        );
    }
}

/// `Default` everywhere is the build's default profile: `Rfc`, `Chrome` with the
/// `chrome-defaults` feature, `Performance` with `performance-defaults` alone (with both,
/// `Chrome`).
#[test]
fn the_defaults_follow_the_compiled_default_profile() {
    let expected = if cfg!(feature = "chrome-defaults") {
        BehaviourProfile::Chrome
    } else if cfg!(feature = "performance-defaults") {
        BehaviourProfile::Performance
    } else {
        BehaviourProfile::Rfc
    };
    assert_eq!(BehaviourProfile::compiled_default(), expected);
    assert_eq!(BehaviourProfile::default(), expected);
    let setting_engine = SettingEngine::default();
    let built = SettingEngineBuilder::new().build();
    let media_engine = MediaEngine::default();
    let options = DefaultInterceptorOptions::default();
    assert_eq!(setting_engine.behaviour_profile(), expected);
    assert_eq!(built.behaviour_profile(), expected);
    assert_eq!(media_engine.behaviour_profile(), expected);
    for row in GOVERNED {
        assert_eq!(
            read(row, &setting_engine, &media_engine, &options),
            row.value(expected),
            "{}",
            row.id
        );
        assert_eq!(
            read(row, &built, &media_engine, &options),
            row.value(expected),
            "{}",
            row.id
        );
    }
}

/// A setting given after the profile keeps its own value; one given before is replaced.
#[test]
fn a_setting_after_the_profile_overrides_it() {
    let after = SettingEngineBuilder::new()
        .with_behaviour_profile(BehaviourProfile::Chrome)
        .with_sctp_message_size_limit_without_interleaving(true)
        .with_ice_nomination_acceptance(NominationAcceptance::HighestPriority)
        .build();
    assert_eq!(
        after.sctp_message_size_limit_without_interleaving,
        Some(true)
    );
    assert_eq!(
        after.ice.nomination_acceptance,
        NominationAcceptance::HighestPriority
    );
    let before = SettingEngineBuilder::new()
        .with_ice_nomination_acceptance(NominationAcceptance::HighestPriority)
        .with_behaviour_profile(BehaviourProfile::Chrome)
        .build();
    assert_eq!(
        before.ice.nomination_acceptance,
        NominationAcceptance::Latest
    );
    // Back to Rfc gives the defaults again.
    let back = SettingEngineBuilder::new()
        .with_behaviour_profile(BehaviourProfile::StrictRfc)
        .with_behaviour_profile(BehaviourProfile::Rfc)
        .build();
    let base = SettingEngine::rfc_base();
    let media_engine = MediaEngine::rfc_base();
    let options = DefaultInterceptorOptions::rfc_base();
    for row in GOVERNED {
        assert_eq!(
            read(row, &back, &media_engine, &options),
            read(row, &base, &media_engine, &options),
            "{}",
            row.id
        );
    }
}

/// A peer connection built the default way under each profile (setting engine, media engine
/// with the default codecs, the default interceptors) carries every governed value, and its
/// ICE agent configuration the ICE ones.
#[test]
fn a_default_peer_connection_carries_its_profiles_values() -> shared::error::Result<()> {
    for profile in BehaviourProfile::ALL {
        let setting_engine = SettingEngineBuilder::new()
            .with_behaviour_profile(profile)
            .build();
        let mut media_engine = MediaEngine::for_profile(profile);
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        let options = DefaultInterceptorOptions::for_profile(pc.media_engine.behaviour_profile());
        for row in GOVERNED {
            assert_eq!(
                read(row, &pc.setting_engine, &pc.media_engine, &options),
                row.value(profile),
                "{} under {profile}",
                row.id
            );
        }
        if profile == BehaviourProfile::StrictRfc {
            // The default VP9 formats registered after the profile state the limits.
            assert!(
                pc.media_engine.video_codecs.iter().any(|codec| codec
                    .rtp_codec
                    .sdp_fmtp_line
                    .contains(
                        crate::peer_connection::configuration::media_engine::VP9_RECEIVER_LIMITS
                    )),
                "StrictRfc VP9 formats state max-fr / max-fs"
            );
        }
        let agent = crate::peer_connection::internal::ice_agent_config(
            &pc.configuration,
            &pc.setting_engine,
        )?;
        let ice = &pc.setting_engine.ice;
        assert_eq!(
            agent.nomination_acceptance, ice.nomination_acceptance,
            "{profile}"
        );
        assert_eq!(agent.failed_nomination, ice.failed_nomination, "{profile}");
        assert_eq!(
            agent.nominate_on_consent_checks, ice.nominate_on_consent_checks,
            "{profile}"
        );
        assert_eq!(
            agent.consent_response_wait, ice.consent_response_wait,
            "{profile}"
        );
        assert_eq!(
            agent.send_data_before_nomination, ice.send_data_before_nomination,
            "{profile}"
        );
        assert_eq!(
            agent.hold_local_candidates_until_conveyed, !ice.pair_before_conveyed,
            "{profile}"
        );
        // Set on the agent once it is made (not an `AgentConfig` field).
        assert_eq!(
            pc.ice_transport().agent.failed_without_end_of_candidates(),
            pc.setting_engine.ice_failed_without_end_of_candidates,
            "{profile}"
        );
        // SOFTWARE: the ICE agent's checks and responses and the TURN clients' requests.
        assert_eq!(
            agent.software,
            pc.setting_engine.ice_agent_software(),
            "{profile}"
        );
        if profile == BehaviourProfile::Chrome {
            assert_eq!(
                agent.software.as_deref(),
                Some(""),
                "{profile}: no SOFTWARE"
            );
            assert_eq!(
                pc.setting_engine.turn_software(),
                "",
                "{profile}: no SOFTWARE"
            );
        } else {
            assert_eq!(agent.software, None, "{profile}: the agent's own SOFTWARE");
            assert_eq!(
                pc.setting_engine.turn_software(),
                turn::client::DEFAULT_SOFTWARE,
                "{profile}"
            );
        }
        // The DTLS transport starts its handshake by the profile's rule.
        assert_eq!(
            pc.dtls_transport().flight_interval_rule,
            pc.setting_engine.dtls_flight_interval,
            "{profile}"
        );
    }
    Ok(())
}

/// The two rules of the first DTLS retransmission timer: RFC 9147's (400 ms, or 1.5 round
/// trips and at least 100 ms) and libwebrtc's `ComputeRetransmissionTimeout` (two round trips
/// within 50 ms and 3 s, 50 ms without one).
#[test]
fn the_dtls_flight_interval_rules_start_where_their_sources_say() {
    use crate::peer_connection::configuration::setting_engine::DtlsFlightInterval;
    let ms = Duration::from_millis;
    for (rule, round_trip_time, expected) in [
        (DtlsFlightInterval::Rfc9147, None, ms(400)),
        (DtlsFlightInterval::Rfc9147, Some(ms(200)), ms(300)),
        (DtlsFlightInterval::Rfc9147, Some(ms(20)), ms(100)),
        (DtlsFlightInterval::Rfc9147, Some(ms(4000)), ms(6000)),
        (DtlsFlightInterval::Libwebrtc, None, ms(50)),
        (DtlsFlightInterval::Libwebrtc, Some(ms(200)), ms(400)),
        (DtlsFlightInterval::Libwebrtc, Some(ms(10)), ms(50)),
        (DtlsFlightInterval::Libwebrtc, Some(ms(4000)), ms(3000)),
    ] {
        assert_eq!(
            rule.initial(round_trip_time),
            expected,
            "{rule:?} {round_trip_time:?}"
        );
    }
}

/// Removes `/* ... */` comments and `//` line comments (a commented-out setter is not one).
fn code_of(source: &str) -> String {
    let mut out = String::new();
    let mut rest = source;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        rest = match rest[start..].find("*/") {
            Some(end) => &rest[start + end + 2..],
            None => "",
        };
    }
    out.push_str(rest);
    out.lines()
        .map(|line| match line.trim_start().starts_with("//") {
            true => "",
            false => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The settings a source file declares: `pub fn <prefix>...` in an `impl` of `owner`, or the
/// `pub` fields of struct `owner`.
fn declared(source: &str, owner: &str, prefixes: &[&str]) -> BTreeSet<String> {
    let code = code_of(source);
    let mut names = BTreeSet::new();
    for line in code.lines() {
        let line = line.trim_start();
        for prefix in prefixes {
            if let Some(rest) = line.strip_prefix(&format!("pub fn {prefix}")) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                names.insert(format!("{owner}::{prefix}{name}"));
            }
        }
    }
    names
}

fn struct_fields(source: &str, owner: &str) -> BTreeSet<String> {
    let code = code_of(source);
    let start = code
        .find(&format!("pub struct {owner} {{"))
        .expect("the struct");
    let body = &code[start..];
    let body = &body[..body.find("\n}").expect("its end")];
    body.lines()
        .filter_map(|line| line.trim_start().strip_prefix("pub "))
        .filter_map(|rest| rest.split(':').next())
        .filter(|name| name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .map(|name| format!("{owner}::{name}"))
        .collect()
}

/// Every setting of the setting engine, the media engine and the interceptor options is in
/// the table or in the list of settings the profiles leave alone, and both name only settings
/// that exist: a setting added without a profile entry fails here.
#[test]
fn every_setting_is_governed_or_listed_as_left_alone() {
    let mut settings = declared(
        include_str!("setting_engine.rs"),
        "SettingEngineBuilder",
        &["with_", "without_"],
    );
    settings.extend(declared(
        include_str!("media_engine.rs"),
        "MediaEngine",
        &["set_"],
    ));
    settings.extend(struct_fields(
        include_str!("interceptor_registry.rs"),
        "DefaultInterceptorOptions",
    ));
    assert!(
        settings.len() > 100,
        "the scan found the settings: {settings:?}"
    );

    let governed: BTreeSet<String> = GOVERNED.iter().map(|row| row.setting.to_owned()).collect();
    let left_alone: BTreeSet<String> = NOT_GOVERNED
        .iter()
        .map(|row| row.setting.to_owned())
        .collect();
    assert_eq!(
        left_alone.len(),
        NOT_GOVERNED.len(),
        "a setting is listed twice as left alone"
    );
    let both: Vec<_> = governed.intersection(&left_alone).collect();
    assert!(both.is_empty(), "governed and left alone: {both:?}");

    let unclassified: Vec<_> = settings
        .iter()
        .filter(|name| !governed.contains(*name) && !left_alone.contains(*name))
        .collect();
    assert!(
        unclassified.is_empty(),
        "settings with no profile entry (add a row to GOVERNED or NOT_GOVERNED in \
         behaviour_profile.rs, then run scripts/behaviour-profiles.py): {unclassified:?}"
    );
    let stale: Vec<_> = governed
        .union(&left_alone)
        .filter(|name| !settings.contains(*name))
        .collect();
    assert!(
        stale.is_empty(),
        "table entries naming no setting: {stale:?}"
    );
}

/// The rendered table lists every governed behaviour (`scripts/behaviour-profiles.py --check`
/// checks the whole text).
#[test]
fn the_rendered_table_lists_every_governed_behaviour() {
    let doc = include_str!("../../../docs/behaviour-profiles.md");
    let ids: BTreeSet<&str> = GOVERNED.iter().map(|row| row.id).collect();
    assert_eq!(ids.len(), GOVERNED.len(), "an id is used twice");
    for row in GOVERNED {
        assert!(
            doc.contains(&format!("`{}`", row.id)),
            "{} is not in the doc",
            row.id
        );
    }
    for row in NOT_EXPRESSIBLE {
        assert!(
            doc.contains(row.behaviour),
            "{} is not in the doc",
            row.behaviour
        );
    }
}

/// Every row that differs between profiles differs in at least one column; a row the same in
/// every profile belongs to NOT_GOVERNED.
#[test]
fn every_governed_row_differs_somewhere() {
    for row in GOVERNED {
        assert!(
            row.rfc != row.chrome || row.rfc != row.strict_rfc || row.rfc != row.performance,
            "{} is the same in every profile",
            row.id
        );
        assert!(!row.chrome_source.is_empty(), "{} has no source", row.id);
    }
}

#[test]
fn profile_names_round_trip() {
    for profile in BehaviourProfile::ALL {
        assert_eq!(BehaviourProfile::from_name(profile.name()), Some(profile));
        assert_eq!(profile.to_string(), profile.name());
    }
    assert_eq!(
        BehaviourProfile::from_name("Strict_RFC"),
        Some(BehaviourProfile::StrictRfc)
    );
    assert_eq!(BehaviourProfile::from_name("firefox"), None);
}

/// The `Performance` profile changes only the rows that say what it saves: every other row
/// keeps the engine's (`Rfc`) value, so it never turns a capability off or takes a form
/// outside the RFCs that `Rfc` does not already take.
#[test]
fn the_performance_profile_differs_from_rfc_only_where_it_saves() {
    let changed: Vec<&str> = GOVERNED
        .iter()
        .filter(|row| row.performance != row.rfc)
        .map(|row| row.id)
        .collect();
    assert_eq!(
        changed,
        [
            "rtcp.t-rr-interval",
            "rtcp.congestion-feedback-in-budget",
            "rtcp.minimum-session-bandwidth",
            "cc.feedback-share",
            "cc.feedback-max-interval",
        ]
    );
}

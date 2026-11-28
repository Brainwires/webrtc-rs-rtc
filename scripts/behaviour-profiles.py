#!/usr/bin/env python3
"""Renders docs/behaviour-profiles.md from the tables of
src/peer_connection/configuration/behaviour_profile.rs.

    python3 scripts/behaviour-profiles.py          # write the doc
    python3 scripts/behaviour-profiles.py --check  # fail when the doc is not what the code says

Also checks that each standing departure from a MUST in docs/conformance.md (the rows other than
an internal conflict of the RFC and an opt-in) has a governed behaviour that the StrictRfc profile
turns to the RFC form, and that README's sentence "N defaults depart from a MUST by the owner's
decision" names each of them with the right count words.

Also checks, as the crate's `every_setting_is_governed_or_listed_as_left_alone` test does,
that every setting of the setting engine, the media engine and the default interceptor options
is either governed by the profiles or listed as left alone, and that both lists name only
settings that exist.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "src/peer_connection/configuration"
SOURCE = CONFIG / "behaviour_profile.rs"
DOC = ROOT / "docs/behaviour-profiles.md"
CONFORMANCE = ROOT / "docs/conformance.md"
README = ROOT / "README.md"

COUNT_WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six"}
SETS_WORDS = {1: "sets it", 2: "sets both", 3: "sets all three", 4: "sets all four",
              5: "sets all five", 6: "sets all six"}

STRING = r'"((?:[^"\\]|\\.)*)"'


def unescape(text):
    return re.sub(r"\\(.)", r"\1", text)


def field(block, key, value=STRING):
    match = re.search(r"^\s*" + key + r":\s*" + value + r",?\s*$", block, re.M)
    if not match:
        raise SystemExit(f"behaviour-profiles: no `{key}` in\n{block}")
    return unescape(match.group(1))


def optional(block, key, value=STRING):
    match = re.search(r"^\s*" + key + r":\s*" + value + r",?\s*$", block, re.M)
    return unescape(match.group(1)) if match else None


def strip_comments(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return "\n".join("" if line.lstrip().startswith("//") else line for line in code.split("\n"))


def governed(source):
    start = source.index("governed_behaviours! {\n")
    body = source[start:]
    body = body[: body.index("\n}\n")]
    rows = []
    for block in re.split(r"\n    \{\n", body)[1:]:
        hook = re.search(r"^\s*apply_(setting|media|interceptors):", block, re.M)
        if not hook:
            raise SystemExit(f"behaviour-profiles: no apply_* hook in\n{block}")
        rfc = field(block, "rfc", r".*?=>\s*" + STRING)
        performance = optional(block, "performance", r".*?=>\s*" + STRING)
        rows.append(
            {
                "performance": rfc if performance is None else performance,
                "performance_note": optional(block, "performance_note"),
                "id": field(block, "id"),
                "setting": field(block, "setting"),
                "clause": field(block, "clause"),
                "rfc": field(block, "rfc", r".*?=>\s*" + STRING),
                "chrome": field(block, "chrome", r".*?=>\s*" + STRING),
                "strict_rfc": field(block, "strict_rfc", r".*?=>\s*" + STRING),
                "source": field(block, "chrome_source"),
                "evidence": field(block, "evidence", r"(\w+)"),
                "target": hook.group(1),
            }
        )
    return rows


def entries(source, static, struct, keys):
    start = source.index(f"pub(crate) static {static}: &[{struct}] = &[")
    body = source[start:]
    body = body[: body.index("\n];\n")]
    out = []
    for block in body.split(f"{struct} {{")[1:]:
        entry = {}
        for key in keys:
            if key == "class":
                entry[key] = field(block, key, r"NotGovernedClass::(\w+)")
            else:
                entry[key] = field(block, key)
        out.append(entry)
    return out


def declared(path, owner, prefixes):
    code = strip_comments(path.read_text())
    names = set()
    for prefix in prefixes:
        for name in re.findall(r"^\s*pub fn (" + prefix + r"\w*)", code, re.M):
            names.add(f"{owner}::{name}")
    return names


def struct_fields(path, owner):
    code = strip_comments(path.read_text())
    start = code.index(f"pub struct {owner} {{")
    body = code[start:]
    body = body[: body.index("\n}")]
    return {f"{owner}::{name}" for name in re.findall(r"^\s*pub (\w+):", body, re.M)}


def standing_departures(rows):
    """The defaults that depart from a MUST by the owner's decision: the rows of
    docs/conformance.md "Standing departures from a MUST" except the two of another kind (an
    internal conflict of the RFC, an opt-in), each as (RFC number, section, governed row)."""
    text = CONFORMANCE.read_text()
    if "## Standing departures from a MUST" not in text:
        raise SystemExit("behaviour-profiles: docs/conformance.md has no standing departures table")
    section = text.split("## Standing departures from a MUST", 1)[1].split("\n## ", 1)[0]
    out, errors = [], []
    for line in section.splitlines():
        if not line.startswith("| RFC "):
            continue
        clause = line.split(" | ")[0].lstrip("| ")
        if "internal conflict" in clause or "an opt-in" in clause:
            continue
        m = re.match(r"RFC (\d+) section ([\d.]+)", clause)
        if not m:
            errors.append(f"conformance.md: a departure row without 'RFC <n> section <s>': {clause}")
            continue
        number, sec = m.group(1), m.group(2)
        # Several departures may share a clause (RFC 9429 5.3.1: jsep-95 and jsep-98): the
        # governed row is the one of that clause whose setting the departure names.
        candidates = [r for r in rows if r["clause"].startswith(f"RFC {number} {sec}")]
        row = next((r for r in candidates if r["setting"].rsplit("::", 1)[-1] in line),
                   candidates[0] if candidates else None)
        if row is None:
            errors.append(f"conformance.md: RFC {number} section {sec} is a standing departure "
                          "but no governed behaviour names that clause")
        elif row["strict_rfc"] == row["rfc"]:
            errors.append(f"{row['id']}: RFC {number} section {sec} is a standing departure, "
                          "but the StrictRfc profile does not select its RFC form")
        out.append((number, sec, row))
    return out, errors


def check_readme(departures):
    """README's sentence on the defaults that depart from a MUST names each departure of
    docs/conformance.md, with the right count words."""
    text = " ".join(README.read_text().split())
    m = re.search(r"(\w+) defaults? departs? from a MUST by the owner's decision(.*?)Known issues", text)
    if not m:
        return ["README.md: no sentence 'N defaults depart from a MUST by the owner's decision'"]
    n, errors = len(departures), []
    if m.group(1) != COUNT_WORDS.get(n):
        errors.append(f"README.md: '{m.group(1)} defaults depart from a MUST', docs/conformance.md "
                      f"lists {n} ({COUNT_WORDS.get(n)})")
    if SETS_WORDS.get(n) and f"the `StrictRfc` profile {SETS_WORDS[n]}" not in m.group(2):
        errors.append(f"README.md: the sentence should say 'the `StrictRfc` profile {SETS_WORDS.get(n)}'")
    for number, sec, _ in departures:
        if f"RFC {number} section {sec.split('.')[0]}" not in m.group(2):
            errors.append(f"README.md: the departure from RFC {number} section {sec} is not named")
    return errors


def check_completeness(rows, not_governed):
    settings = declared(CONFIG / "setting_engine.rs", "SettingEngineBuilder", ["with_", "without_"])
    settings |= declared(CONFIG / "media_engine.rs", "MediaEngine", ["set_"])
    settings |= struct_fields(CONFIG / "interceptor_registry.rs", "DefaultInterceptorOptions")
    governed_names = {row["setting"] for row in rows}
    left_alone = [entry["setting"] for entry in not_governed]
    errors = []
    if len(set(left_alone)) != len(left_alone):
        errors.append("a setting is listed twice in NOT_GOVERNED")
    both = governed_names & set(left_alone)
    if both:
        errors.append(f"governed and left alone: {sorted(both)}")
    missing = sorted(settings - governed_names - set(left_alone))
    if missing:
        errors.append(
            "settings with no profile entry (add a GOVERNED or NOT_GOVERNED entry to "
            f"behaviour_profile.rs): {missing}"
        )
    stale = sorted((governed_names | set(left_alone)) - settings)
    if stale:
        errors.append(f"profile entries naming no setting: {stale}")
    ids = [row["id"] for row in rows]
    if len(set(ids)) != len(ids):
        errors.append("an id is used twice")
    for row in rows:
        if (row["performance"] != row["rfc"]) != (row["performance_note"] is not None):
            errors.append(f"{row['id']}: a Performance value and its performance_note go together")
        if row["rfc"] == row["chrome"] == row["strict_rfc"] == row["performance"]:
            errors.append(f"{row['id']} is the same in every profile (move it to NOT_GOVERNED)")
        if row["evidence"] not in ("Observed", "Source", "Unverified"):
            errors.append(f"{row['id']}: evidence {row['evidence']}")
        if row["evidence"] == "Source" and "@ " not in row["source"]:
            errors.append(f"{row['id']}: a source row names the revision it read (@ <commit>)")
    return errors, len(settings)


def cell(text):
    return text.replace("|", "\\|").replace("\n", " ")


def code(text):
    return f"`{cell(text)}`"


# The revisions the `Source` rows were read at (the rows cite the first 8 hex digits).
LIBWEBRTC_REVISION = "a222406d49ecffb8e045d113e45f89f62b3819e8"
LIBWEBRTC_DATE = "2026-11-23"
CHROMIUM_REVISION = "8dafa8bce175adc309d5d4fc9cdde25e9e285d4a"
BORINGSSL_REVISION = "289645a450721a7210bf9c69d42bf40a0f1ee730"

EVIDENCE_PREFIX = {"Observed": "observed: ", "Source": "source: ", "Unverified": "**unverified**: "}


def counts(rows):
    return {kind: sum(1 for row in rows if row["evidence"] == kind) for kind in EVIDENCE_PREFIX}


CLASS_TITLES = {
    "EngineOnly": "Engine-only capabilities: the same in every profile",
    "Same": "Examined: the default is libwebrtc's too, or already the RFC's",
    "Input": "Application input: no default to choose",
    "Deprecated": "Deprecated, not read by the engine",
}


def render(rows, not_governed, not_expressible, departures):
    n = counts(rows)
    differs = sum(1 for row in rows if row["chrome"] != row["rfc"])
    strict = sum(1 for row in rows if row["strict_rfc"] != row["rfc"])
    perf = [row for row in rows if row["performance"] != row["rfc"]]
    out = []
    w = out.append
    w("# Behaviour profiles")
    w("")
    w("<!-- Generated by scripts/behaviour-profiles.py from")
    w("     src/peer_connection/configuration/behaviour_profile.rs. Do not edit by hand. -->")
    w("")
    w(f"**{len(rows)} governed behaviours.** Chrome values: **{n['Observed']} observed**, "
      f"**{n['Source']} from libwebrtc's source**, **{n['Unverified']} unverified**. "
      f"**{len(not_expressible)} not expressible.**")
    w("")
    w("A `BehaviourProfile` sets, in one call, every default where the engine and an RFC, or the")
    w("engine and libwebrtc (Chrome), choose differently:")
    w("")
    w("- **`Rfc`**: the engine's defaults, unchanged. The RFCs' behaviour, and the interoperable")
    w("  form where a named browser or deployed peer cannot take the RFC's (the audit's `setting`")
    w("  verdict, `docs/conformance/audit/RULES.md`), except the standing departures from the RFC")
    w("  text listed in `docs/conformance.md`, which the owner decided (" + "; ".join(
        f"`{row['id'] if row else '?'}`: " + ("this default does not follow" if i == 0 else "nor")
        + f" RFC {number} section {sec}" for i, (number, sec, row) in enumerate(departures)) + ").")
    w("- **`Chrome`**: libwebrtc's choice wherever the engine and libwebrtc both do a thing and")
    w("  choose differently (a timer, an order, a form on the wire, a lenient or strict acceptance")
    w("  rule). It never turns off a capability the engine has and Chrome lacks: those are the same")
    w("  in every profile (section 2), so the `Chrome` profile's offers are a **superset** of")
    w("  Chrome's (extra header extensions, `a=rtcp-fb` types, `a=tls-id`, formats).")
    w("- **`StrictRfc`**: the RFC form even where the default is the interoperable one, or a")
    w("  standing departure, or a `conflict` row's RFC form (RFC 8830 3.2.5,")
    w("  `track.msid-removal-ends-track`). For")
    w("  conformance testing only: **it does not interoperate with browsers** (Chromium, Firefox")
    w("  and WebKit refuse an answer whose bundled sections lack `a=rtcp-mux`; a data-only")
    w("  association without `use_srtp` cannot gain media with a browser).")
    w("- **`Performance`**: the engine's defaults, with each behaviour where an RFC offers a form")
    w("  that does the same thing at lower cost (a parameter, a MAY, a negotiated extension) set")
    w("  to it. It never turns a capability off and never leaves what the RFCs permit; a cheaper")
    w("  libwebrtc value that lies outside an RFC belongs to `Chrome`, not here. Each value is")
    w("  measured: section 1a.")
    w("")
    w("```rust")
    w("let profile = BehaviourProfile::Chrome;")
    w("let setting_engine = SettingEngineBuilder::new().with_behaviour_profile(profile).build();")
    w("let mut media_engine = MediaEngine::for_profile(profile);")
    w("media_engine.register_default_codecs()?;")
    w("// Reads the media engine's profile:")
    w("let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;")
    w("```")
    w("")
    w("A setting given after `with_behaviour_profile` keeps its own value. The connection's")
    w("automatic RTCP session (a registry without one) follows the setting engine's profile.")
    w("")
    w("## The `chrome-defaults` cargo feature")
    w("")
    w("With the `chrome-defaults` feature of the `rtci` crate, `BehaviourProfile::default()` is")
    w("`Chrome`, and so is every `SettingEngine::default()`, `SettingEngineBuilder::new()`,")
    w("`MediaEngine::default()` and `DefaultInterceptorOptions::default()`.")
    w("")
    w("**Cargo unifies features across a dependency graph: one crate of a build that enables")
    w("`chrome-defaults` changes the defaults of every user of `rtci` in that build**, libraries")
    w("that never asked for it included. Prefer the explicit `with_behaviour_profile` call;")
    w("`BehaviourProfile::compiled_default()` tells which default a build has.")
    w("")
    w("## The `performance-defaults` cargo feature")
    w("")
    w("The same for `Performance`: with the `performance-defaults` feature every default above")
    w("is `Performance`. With both features on, `chrome-defaults` wins (it is the one that")
    w("changes the wire to match a peer) and the build prints a deprecation warning naming the")
    w("two features, so the pick is never silent.")
    w("")
    w(f"## 1. Defaults that differ: governed by the profile ({len(rows)})")
    w("")
    w(f"{len(rows)} governed behaviours: the `Chrome` value differs from `Rfc` in {differs}, the")
    w(f"`StrictRfc` value in {strict}, the `Performance` value in {len(perf)}. Chrome values:")
    w(f"{n['Observed']} observed, {n['Source']} from")
    w(f"the source, {n['Unverified']} unverified.")
    w("")
    w("A value is what `{:?}` of the setting writes; the crate's tests compare each with the")
    w("setting a profile leaves, and the `Rfc` column with the engine's defaults before any")
    w("profile. **Observed** Chrome values come from the recorded Chromium descriptions")
    w("(`tests/fixtures/browser-sdp/chromium--*.sdp`, from the test environment of conformance")
    w("train 9, round 3: Playwright 1.64.1's Chromium) or a cell of the browser matrix.")
    w("**Source** values were read in libwebrtc's public source")
    w(f"(`https://webrtc.googlesource.com/src/`, `main` at `{LIBWEBRTC_REVISION}`,")
    w(f"{LIBWEBRTC_DATE}; the rows cite `@ {LIBWEBRTC_REVISION[:8]}`), the file, the symbol and")
    w("what it does; a value a field trial changes is the default with the trial named. Where")
    w("Chromium's glue sets a libwebrtc option the row cites")
    w(f"`chromium/src` `{CHROMIUM_REVISION[:8]}` (`{CHROMIUM_REVISION}`), and BoringSSL")
    w(f"`{BORINGSSL_REVISION[:8]}` (`{BORINGSSL_REVISION}`). **Unverified** values were")
    w("established neither way; each says why.")
    w("")
    w("| Behaviour | Setting | Clause | `Rfc` | `Chrome` | `StrictRfc` | `Performance` | Source of the Chrome value |")
    w("|---|---|---|---|---|---|---|---|")
    for row in rows:
        source = EVIDENCE_PREFIX[row["evidence"]] + row["source"]
        w(
            f"| {code(row['id'])} | {code(row['setting'])} | {cell(row['clause'])} | "
            f"{code(row['rfc'])} | {code(row['chrome'])} | {code(row['strict_rfc'])} | "
            f"{code(row['performance'])} | {cell(source)} |"
        )
    w("")
    w(f"## 1a. What `Performance` changes, and what it was measured to save ({len(perf)})")
    w("")
    w("Each row: the RFC clause that permits the value, the saving and the cost, measured by")
    w("`tests/rtcp_rate_trace_rtc2rtc.rs` (two `rtci` peer connections, virtual time, 20 ms")
    w("each way; run with `-- --ignored --nocapture`) and the interceptor tests named.")
    w("")
    w("| Behaviour | `Rfc` | `Performance` | Why it is within the RFCs, saving, cost |")
    w("|---|---|---|---|")
    for row in perf:
        w(
            f"| {code(row['id'])} | {code(row['rfc'])} | {code(row['performance'])} | "
            f"{cell(row['performance_note'])} |"
        )
    w("")
    w("Other overhead the trace showed, left as it is because `Performance` already covers it")
    w("or no RFC-permitted setting changes it:")
    w("")
    w("- The start-up value of the session bandwidth (1 Mbit/s with video, 64 kbit/s with audio,")
    w("  for the first two seconds of media): 13.5 to 14.5 regular packets/s in those two seconds")
    w("  against 2.5/s after them at 100 kbit/s. Under `Performance` `T_rr_interval` holds them")
    w("  to about one a second; no setting of its own.")
    w("- The peer's reduced-size feedback pulls `avg_rtcp_size` down (RFC 5506 3.4 expects it),")
    w("  so regular reports speed up: 19.4 regular packets/s each way at 1 Mbit/s both ways")
    w("  with `a=rtcp-rsize`, 15.9/s without. Under `Performance` 1.5 and 1.4/s.")
    w("- Not in `Performance` because they are outside an RFC: libwebrtc's 5 s audio report")
    w("  interval whatever the bandwidth (section 3) and congestion control feedback outside")
    w("  the RTCP bandwidth (`rtcp.immediate-congestion-feedback`, the engine's default too, an")
    w("  audit row for the owner).")
    w("")
    for klass in ["EngineOnly", "Same", "Input", "Deprecated"]:
        entries = [entry for entry in not_governed if entry["class"] == klass]
        number = "2. " if klass == "EngineOnly" else ""
        w(f"## {number}{CLASS_TITLES[klass]} ({len(entries)})")
        w("")
        if klass == "EngineOnly":
            w("A capability the engine has and Chrome lacks stays on under `Chrome`: it negotiates")
            w("down with a Chrome peer, or a Chrome peer does not notice it. Further engine-only")
            w("capabilities with no setting: RFC 7728 pause / resume, SFrame, Cryptex negotiation")
            w("(libwebrtc's `cryptex_policy` is `kDisabled` by default), receive simulcast with")
            w("`a=imageattr`, several transports and BUNDLE groups, RTCP extended reports, and the")
            w("statistics the engine reports beyond Chrome's. DTLS 1.3 with DTLS 1.2 fallback is")
            w("not engine-only: libwebrtc offers it too (`PeerConnectionFactoryInterface::Options`")
            w("`ssl_max_version = SSL_PROTOCOL_DTLS_13`, `api/peer_connection_interface.h`, which")
            w("Chromium leaves), and Chromium adds the X25519MLKEM768 key share under its")
            w("`kWebRtcPqcForDtls` feature, as the engine does where its crypto backend has it.")
            w("")
        w("| Setting | Note |")
        w("|---|---|")
        for entry in entries:
            w(f"| {code(entry['setting'])} | {cell(entry['note'])} |")
        w("")
    w(f"## 3. Not expressible ({len(not_expressible)})")
    w("")
    w("What Chrome does that no setting of the engine can express, and what it would take.")
    w("")
    w("| Behaviour | Chrome | What would be needed |")
    w("|---|---|---|")
    for entry in not_expressible:
        w(f"| {cell(entry['behaviour'])} | {cell(entry['chrome'])} | {cell(entry['needed'])} |")
    w("")
    w("## How it is checked")
    w("")
    w("- `src/peer_connection/configuration/behaviour_profile_test.rs`: every value of every")
    w("  profile, the `Rfc` column against the engine's own defaults, a peer connection built the")
    w("  default way under each profile (its ICE agent configuration included), and that every")
    w("  setting of `SettingEngineBuilder`, `MediaEngine` and `DefaultInterceptorOptions` is in")
    w("  this document (a new setting without a profile entry fails the test and this script).")
    w("- `tests/behaviour_profiles.rs`: under `Chrome`, an offer and an answer compared")
    w("  structurally with the committed Chromium descriptions (the engine's extra attributes are")
    w("  listed there as documented differences); rtc to rtc connections with data and media")
    w("  between profiles, and the `StrictRfc` refusals.")
    w("- `scripts/behaviour-profiles.py --check` (a Python gate of `cargo.yml`): this document is")
    w("  what the code says, every standing departure from a MUST of `docs/conformance.md` has a")
    w("  governed behaviour whose `StrictRfc` value differs from its `Rfc` one, and README's")
    w("  sentence on those departures names each of them with the right count.")
    w("- The browser matrix runs the core scenarios with the Rust peer under `Chrome`")
    w("  (`examples/interop-peer`, `profile=chrome`).")
    w("")
    return "\n".join(out)


def main():
    source = SOURCE.read_text()
    rows = governed(source)
    not_governed = entries(source, "NOT_GOVERNED", "NotGoverned", ["setting", "class", "note"])
    not_expressible = entries(
        source, "NOT_EXPRESSIBLE", "NotExpressible", ["behaviour", "chrome", "needed"]
    )
    errors, scanned = check_completeness(rows, not_governed)
    departures, departure_errors = standing_departures(rows)
    errors += departure_errors + check_readme(departures)
    if errors:
        for error in errors:
            print(f"behaviour-profiles: {error}", file=sys.stderr)
        return 1
    text = render(rows, not_governed, not_expressible, departures)
    if "--check" in sys.argv[1:]:
        if not DOC.exists() or DOC.read_text() != text:
            print(
                "behaviour-profiles: docs/behaviour-profiles.md is not what the code says; "
                "run python3 scripts/behaviour-profiles.py",
                file=sys.stderr,
            )
            return 1
    else:
        DOC.write_text(text)
    n = counts(rows)
    print(
        f"behaviour-profiles: {len(rows)} governed ({n['Observed']} observed, "
        f"{n['Source']} from source, {n['Unverified']} unverified), {len(not_governed)} left alone, "
        f"{len(not_expressible)} not expressible; {scanned} settings scanned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

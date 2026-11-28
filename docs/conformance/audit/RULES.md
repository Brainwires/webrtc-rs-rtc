# Clause audit: verdicts and classes

The rules every table in this directory follows. `scripts/audit-count.py` counts the tables
(`COUNTS.md`); `scripts/open-must.py` lists the open MUST rows with their class (`OPEN-MUST.md`).
Both run in CI with `--check`.

## Rows

One file per specification: title, version or date, a totals block, then one table

    | ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |

IDs are `<SPEC>-<§>-<n>` and stable. The level is the clause's RFC 2119 keyword (MUST counts MUST,
MUST NOT, SHALL, SHALL NOT, REQUIRED; SHOULD counts SHOULD, SHOULD NOT, (NOT) RECOMMENDED; MAY
counts MAY, OPTIONAL), or `proc` / `DESC` for a procedure step. Every normative clause that binds
an implementation of the kind this engine is (endpoint; client for TURN and STUN) is a row; for
W3C specifications, the algorithm steps and API-observable requirements that apply to the engine
under the JavaScript API.

A test named in the Test cell of a MUST or SHOULD row is backticked (`name`, `file.rs::name`), and
`scripts/check-test-inventory.py --check` (CI) fails when such a name is no `fn`, module, fuzz
target or field in the tree, or a `file.rs::name` is a `fn` only in files of another name: a
renamed or deleted test cannot stay cited. It checks that the name exists, not what the test
asserts.

## Verdicts

A verdict is decided by reading the code and the test, not names or comments. When unsure, the
lower verdict; never round up. A row is never relabelled to make a number look better: a verdict
states something true and checkable.

| Verdict | Meaning |
|---|---|
| `tested` | Implemented, and a test that would fail if the behaviour broke exercises production code. |
| `setting` | The clause's behaviour is implemented and has a test that fails without it; it is selected by the named setting; the default differs because the named browser cell or deployed peer cannot interoperate with it. |
| `conflict` | Two specifications conflict for this endpoint: the clause's behaviour is implemented and has a test that fails without it, selected by the named setting; the other specification's form, which governs this endpoint (a W3C specification of the JavaScript API the engine is under, or RFC 9429 for a JSEP endpoint), is the default and has a test of its own. |
| `setting` | The clause's behaviour is implemented and has a test that fails without it; it is selected by the named setting; the default differs because the named browser cell or deployed peer cannot interoperate with it, or because a named test of the repository measured it worse ("measured", below). |
| `untested` | Implemented, no such test (or the test is hollow: it asserts constants or mocks the unit). |
| `partial` | Some of it is implemented; the note says what is missing. |
| `missing` | Not implemented. A clause listed as "Not implemented, on purpose" is still `missing`. |
| `violated` | The code does the opposite. |
| `n/a` | Does not bind this engine; the note says why (sans-I/O, server role, the application's job, superseded for this kind of endpoint by a named clause, ...). |

A `setting` row's note starts in this form, which `audit-count.py` checks:

    Setting: `SettingEngineBuilder::with_x(true)`. RFC test: `tests/x.rs::the_rfc_form`.
    Default differs: <the cell or peer> cannot interoperate with it: <its error>. <rest>

The setting's last path segment must be a `fn` in the Rust sources and each test must exist (as
`scripts/check-test-inventory.py` finds tests). The test must run the RFC form (the setting
turned to it) and fail without it, which is checked by mutation before the verdict is given.

One more kind of evidence makes a `setting` (coordinator decision, audit-5): **measured**. The
RFC or draft form is implemented, has its own mutation-checked test and is selected by the named
setting, and it is not the default because a recorded measurement on the repository's own
congestion or impairment tests shows it performs worse. The note then reads

    Setting: `X::with_y(..)`. RFC test: `path.rs::the_rfc_form`.
    Default differs: measured by `path.rs::the_measurement`: <the numbers, both forms>. <rest>

and `audit-count.py --check` requires the word "measured", the setting, the RFC test and the
measurement test to exist, and numbers. A setting whose default differs for another reason (a
design rule, a specification conflict, performance that no repository test measures) is not
`setting`: the row stays `partial` until the default changes, or a failing cell or peer, or
such a measurement, is named.

A `conflict` row's note starts in this form, which `audit-count.py` checks the same way (the
setting is a `fn`, both tests exist):

    Setting: `SettingEngineBuilder::with_x(true)`. RFC test: `tests/x.rs::the_rfc_form`.
    Default test: `tests/x.rs::the_w3c_form`. Default differs: W3C <spec section> requires
    <what it requires>. <rest>

(or `Default differs: RFC 9429 <section> requires ...`). It is for a clause whose behaviour a
W3C specification (webrtc-pc, webrtc-extensions, ...) or, for a JSEP endpoint, RFC 9429
contradicts for the same observable state; both forms are tested by mutation before the verdict
is given. A row whose only
reason is interoperability is `setting`; one where the clause simply does not bind the engine is
`n/a`. A `conflict` row is listed in `OPEN-MUST.md` with class E.

`COUNTS.md` reports two figures per level, over the rows that apply (all but `n/a`): "RFC
behaviour tested" (`tested` + `setting` + `conflict`) and "tested as the default" (`tested`).

A `setting` row's setting is governed by the behaviour profiles (`docs/behaviour-profiles.md`):
`BehaviourProfile::StrictRfc` turns every such setting to the RFC form at once (with the RFC
SHOULDs the default departs from for the same reason), while `Rfc`, the default, keeps the
interoperable form. A new `setting` row's setting needs a `StrictRfc` value in
`src/peer_connection/configuration/behaviour_profile.rs`: the profile's completeness test fails a
setting that has no entry there. `StrictRfc` does not interoperate with browsers; it exists to run
the RFC forms together.

## Contradictions

Where a specification contradicts itself or another specification (a `conflict` row, a
standing departure in `docs/conformance.md`, or a note that records an ambiguity), the default
and the row's wording follow the current draft work of the people who maintain it, not our own
reading (owner rule, 2026-11-27): the W3C editor's draft with its merged pull requests, candidate
corrections and issue resolutions; the IETF working group's "bis" Internet-Draft and tracker;
the RFC's errata. A note cites it by correction number, PR, issue or draft version, with its
date ("Candidate Correction 37, w3c/webrtc-pc PR #2794, 2022-12-08"), and says so plainly when no
draft work exists. `docs/conformance/draft-work.md` is the register of these: each entry quotes
the clauses, the draft work and its date, and whether the default matches it. A row that moves
to or from `conflict`, or a new departure, gets an entry there. The register is re-checked before
each release (`docs/releasing.md`).

## Classes of the open MUST rows

Every MUST row that is `untested`, `partial`, `missing`, `violated`, `setting` or `conflict` has exactly one
class in `open-must.tsv`, with a size (S, M, L), an owner area and what would close it:

| Class | Meaning | Closes by |
|---|---|---|
| A | RFC behaviour implemented and tested, a named setting, not the default because a named browser cell or deployed peer cannot interoperate, or a named repository test measured it worse | Verdict `setting` (the setting, the RFC-form test and the cell or peer with its error, or the measurement test with its numbers, cited) |
| B | Implemented, lacking a test that fails without it | A test, checked by mutation |
| C | Partly implemented | The missing part, with tests |
| D | Not implemented | An implementation, with tests |
| E | Cannot be met or observed inside this engine for a stated reason (a crypto provider's interface, the application's or the operating system's responsibility, a clause that binds a different role, a specification that supersedes it for this kind of endpoint) | `n/a` with the reason when the clause does not bind the engine; otherwise a test of the engine-side guarantee, or it stays open as never testable, with the reason |
| F | The note is stale: the behaviour is already tested on this tree | The verdict, once the cited test is checked by mutation |

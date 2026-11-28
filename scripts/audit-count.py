#!/usr/bin/env python3
"""Exact counts of the clause audit (``docs/conformance/audit/*.md``).

Every audit file holds one or more clause tables with the header
``| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |`` and a totals
block, one line per level::

    - MUST: tested 3 / untested 0 / partial 1 / missing 0 / violated 0 / n-a 2

with ``setting N / `` and ``conflict N / `` before ``untested`` where the file has such rows
(they may be left out when there are none),

or all levels on one line, ``Totals (N rows): MUST: ...; SHOULD: ...; MAY: ...``
(``n/a`` for ``n-a``, a trailing ``(total N)`` / ``(rows: N)``, a parenthesised gloss after the
level and backticks around the line are all accepted). This script counts the table rows by level
and verdict and fails when:

* a row's verdict is not one of ``tested``, ``setting``, ``conflict``, ``untested``, ``partial``,
  ``missing``, ``violated``, ``n/a`` (``n-a`` and backticks accepted);
* a ``conflict`` row's note does not name, in this form, a setting that exists, a test of the
  RFC form and a test of the default (the other specification's form) that exist, and that
  specification (a W3C one, or RFC 9429 for a JSEP endpoint)::

      Setting: `SettingEngineBuilder::with_x(true)`. RFC test: `tests/x.rs::the_rfc_form`.
      Default test: `tests/x.rs::the_w3c_form`. Default differs: W3C <spec section> requires
      <what it requires>. <rest of the note>

* a ``setting`` row's note does not name, in this form, a setting that exists in the source and
  a test of the RFC form that exists, and the peer or browser cell the default is for::

      Setting: `SettingEngineBuilder::with_x(true)`. RFC test: `tests/x.rs::the_rfc_form`.
      Default differs: <the cell or peer> cannot interoperate: <its error>. <rest of the note>

  The setting's last path segment, without its arguments, must be a ``fn`` of a Rust source
  file; the test is found as ``scripts/check-test-inventory.py`` finds the tests the conformance
  tables name (``name``, ``path.rs::name``). Several of each may be given, comma-separated
  (``docs/conformance/audit/RULES.md`` defines the verdict). For the "measured" kind of
  evidence the reason reads ``Default differs: measured by `<test>`: <numbers> ...``: the
  measurement test must exist and the numbers be given;
* a row's level carries no RFC 2119 keyword and is not a procedure step (``proc``, ``DESC``);
* a ``Totals (N rows)`` heading's N is not the number of table rows;
* a file's totals line for a level disagrees with its table, a level that has rows has no totals
  line, or a ``(total N)`` / ``(rows: N)`` figure is not the sum of its line.

A file whose tables have rows but that has no totals block at all fails too. Summary files (no
clause table) are skipped.

Levels: MUST counts MUST, MUST NOT, SHALL, SHALL NOT and REQUIRED; SHOULD counts SHOULD, SHOULD
NOT, RECOMMENDED and NOT RECOMMENDED; MAY counts MAY and OPTIONAL. A cell naming two keywords
(``MAY/SHOULD``) counts under the first. ``proc`` and ``DESC`` rows are procedure steps
(``PROC``), checked against a ``Procedure steps`` totals line when the file has one.

It writes ``docs/conformance/audit/COUNTS.md``, which reports for each level both "RFC behaviour
tested" (``tested`` + ``setting`` + ``conflict``) and "tested as the default" (``tested``). ``--check`` writes nothing and fails when that
file is not what it would write (CI runs it that way).

``--check`` also compares README.md's status figures with what it computes (the status table's
MUST / SHOULD / MAY rows, "N MUST rows are open (...)", "audited ... against N specifications"),
naming the line and both figures; the train integrator's README updater writes the same patterns.
Self-test: ``python3 scripts/test_audit_count.py``.

Usage: ``python3 scripts/audit-count.py [--check]``. Standard library only.
"""

from __future__ import annotations

import glob
import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "docs", "conformance", "audit")
COUNTS = os.path.join(AUDIT, "COUNTS.md")

VERDICTS = ["tested", "setting", "conflict", "untested", "partial", "missing", "violated", "n/a"]
LEVELS = ["MUST", "SHOULD", "MAY", "PROC"]

HEADER = ["ID", "§", "Level", "Clause (short paraphrase)", "Verdict", "Code", "Test", "Note"]

KEYWORD = re.compile(
    r"\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED|SHOULD NOT|SHOULD|NOT RECOMMENDED|RECOMMENDED"
    r"|MAY|OPTIONAL)\b"
)
KEYWORD_LEVEL = {
    "MUST NOT": "MUST",
    "MUST": "MUST",
    "SHALL NOT": "MUST",
    "SHALL": "MUST",
    "REQUIRED": "MUST",
    "SHOULD NOT": "SHOULD",
    "SHOULD": "SHOULD",
    "NOT RECOMMENDED": "SHOULD",
    "RECOMMENDED": "SHOULD",
    "MAY": "MAY",
    "OPTIONAL": "MAY",
}
PROC = re.compile(r"^(proc|DESC)\b")

TOTALS = re.compile(
    r"^(?:-\s*)?`?(?P<level>MUST|SHOULD|MAY|Procedure steps)\b[^:]*:\s*"
    r"tested (?P<tested>\d+) / (?:setting (?P<setting>\d+) / )?(?:conflict (?P<conflict>\d+) / )?"
    r"untested (?P<untested>\d+) / "
    r"partial (?P<partial>\d+) / "
    r"missing (?P<missing>\d+) / violated (?P<violated>\d+) / n[-/]a (?P<na>\d+)"
    r"(?:\s*\((?:total|rows:)\s*(?P<total>\d+)\))?`?\s*$"
)


ONE_LINE = re.compile(r"^Totals \(\d+ rows\):\s*(?P<parts>.+)$")
ROWS = re.compile(r"^Totals \((?P<rows>\d+) rows\):")


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def level_of(cell: str) -> str | None:
    cell = cell.replace("`", "").strip()
    if PROC.match(cell):
        return "PROC"
    m = KEYWORD.search(cell)
    return KEYWORD_LEVEL[m.group(1)] if m else None


def verdict_of(cell: str) -> str | None:
    cell = cell.replace("`", "").strip()
    if cell == "n-a":
        cell = "n/a"
    return cell if cell in VERDICTS else None


def empty() -> dict[str, dict[str, int]]:
    return {lv: {v: 0 for v in VERDICTS} for lv in LEVELS}


SETTING_NOTE = re.compile(
    r"Setting: (?P<settings>`[^`]+`(?:, `[^`]+`)*)\. RFC test: (?P<tests>`[^`]+`(?:, `[^`]+`)*)\. "
    r"Default differs: (?P<why>\S.{11,})"
)


CONFLICT_NOTE = re.compile(
    r"Setting: (?P<settings>`[^`]+`(?:, `[^`]+`)*)\. RFC test: (?P<tests>`[^`]+`(?:, `[^`]+`)*)\. "
    r"Default test: (?P<defaults>`[^`]+`(?:, `[^`]+`)*)\. "
    r"Default differs: (?P<spec>(?:W3C|RFC \d+) [^:]{3,}?) (?:requires|governs)\b(?P<why>.{11,})"
)
MEASURED_NOTE = re.compile(
    r"measured by (?P<tests>`[^`]+`(?:, `[^`]+`)*): (?P<numbers>\S.{7,})"
)


class Source:
    """The Rust functions and the tests of the tree, read once, for the ``setting`` rows."""

    def __init__(self) -> None:
        self._fns: set[str] | None = None
        self._tests: dict[str, set[str]] | None = None
        spec = importlib.util.spec_from_file_location(
            "check_test_inventory", os.path.join(ROOT, "scripts", "check-test-inventory.py")
        )
        assert spec and spec.loader
        self.inventory = importlib.util.module_from_spec(spec)
        # Registered before it runs: a dataclass looks its module up in sys.modules
        # (Python 3.14 fails on a module loaded from a file without it).
        sys.modules[spec.name] = self.inventory
        spec.loader.exec_module(self.inventory)

    def _scan(self) -> None:
        fns: set[str] = set()
        tests: dict[str, set[str]] = {}
        findings: list = []
        fn = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
        for path in self.inventory.rust_files():
            fns.update(fn.findall(path.read_text(encoding="utf-8", errors="replace")))
            self.inventory.scan_file(path, findings, tests)
        self._fns, self._tests = fns, tests

    def has_fn(self, name: str) -> bool:
        if self._fns is None:
            self._scan()
        assert self._fns is not None
        return name in self._fns

    def has_test(self, ref: str) -> bool:
        if self._tests is None:
            self._scan()
        assert self._tests is not None
        return self.inventory.test_exists(ref, self._tests)


def check_setting(note: str, where: str, source: Source, errors: list[str]) -> None:
    """A ``setting`` row names an existing setting, an existing test of the RFC form, and why
    the default differs."""
    m = SETTING_NOTE.search(note)
    if not m:
        errors.append(
            f"{where}: a `setting` row's note needs 'Setting: `...`. RFC test: `...`. "
            "Default differs: <cell or peer> ...'"
        )
        return
    for setting in re.findall(r"`([^`]+)`", m.group("settings")):
        name = setting.split("(", 1)[0].rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()
        if not source.has_fn(name):
            errors.append(f"{where}: setting `{setting}`: no `fn {name}` in the source")
    for test in re.findall(r"`([^`]+)`", m.group("tests")):
        if not source.has_test(test):
            errors.append(f"{where}: RFC test `{test}` does not exist")
    # The "measured" kind of evidence (RULES.md): the default differs because the RFC form
    # measured worse on the repository's own congestion or impairment tests. The note gives
    # the numbers and names the test that produces them.
    why = m.group("why")
    if why.lower().startswith("measured"):
        measurement = MEASURED_NOTE.match(why)
        if not measurement:
            errors.append(
                f"{where}: a measured `setting` needs 'Default differs: measured by "
                "`<test>`: <numbers> ...'"
            )
            return
        for test in re.findall(r"`([^`]+)`", measurement.group("tests")):
            if not source.has_test(test):
                errors.append(f"{where}: measurement test `{test}` does not exist")
        if not re.search(r"\d", measurement.group("numbers")):
            errors.append(f"{where}: a measured `setting` gives the numbers it measured")


def check_conflict(note: str, where: str, source: Source, errors: list[str]) -> None:
    """A ``conflict`` row names an existing setting, an existing test of the RFC form, an
    existing test of the default (the other specification's form), and that specification."""
    m = CONFLICT_NOTE.search(note)
    if not m:
        errors.append(
            f"{where}: a `conflict` row's note needs 'Setting: `...`. RFC test: `...`. "
            "Default test: `...`. Default differs: <W3C spec or RFC 9429> <section> requires ...'"
        )
        return
    for setting in re.findall(r"`([^`]+)`", m.group("settings")):
        name = setting.split("(", 1)[0].rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()
        if not source.has_fn(name):
            errors.append(f"{where}: setting `{setting}`: no `fn {name}` in the source")
    for kind in ("tests", "defaults"):
        for test in re.findall(r"`([^`]+)`", m.group(kind)):
            if not source.has_test(test):
                label = "RFC test" if kind == "tests" else "default test"
                errors.append(f"{where}: {label} `{test}` does not exist")


def scan(
    path: str, errors: list[str], source: Source | None = None
) -> dict[str, dict[str, int]] | None:
    """Counts of one file's clause tables, or None when it has no clause table."""
    name = os.path.basename(path)
    counts = empty()
    totals: dict[str, tuple[int, dict[str, int]]] = {}
    in_table = False
    header: list[str] | None = None
    saw_table = False
    declared_rows: tuple[int, int] | None = None
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            if not line.startswith("|"):
                header = None
                in_table = False
                stripped = line.strip()
                one = ONE_LINE.match(stripped)
                parts = [p.strip() for p in one.group("parts").split(";")] if one else [stripped]
                for part in parts:
                    m = TOTALS.match(part)
                    if not m:
                        continue
                    lv = "PROC" if m.group("level") == "Procedure steps" else m.group("level")
                    got = {
                        v: int(m.group("na" if v == "n/a" else v) or 0) for v in VERDICTS
                    }
                    if lv in totals:
                        errors.append(f"{name}:{no}: a second {lv} totals line")
                    totals[lv] = (no, got)
                    total = m.group("total")
                    if total is not None and int(total) != sum(got.values()):
                        errors.append(
                            f"{name}:{no}: {lv} total {total} is not the sum "
                            f"{sum(got.values())}"
                        )
                declared = ROWS.match(stripped)
                if declared:
                    declared_rows = (no, int(declared.group("rows")))
                continue
            row = cells(line)
            if header is None:
                header = row
                in_table = row == HEADER
                saw_table = saw_table or in_table
                continue
            if not in_table or set("".join(row)) <= set("-: "):
                continue
            d = dict(zip(header, row))
            lv = level_of(d.get("Level", ""))
            vd = verdict_of(d.get("Verdict", ""))
            if lv is None:
                errors.append(f"{name}:{no}: unknown level {d.get('Level', '')!r} ({row[0]})")
            if vd is None:
                errors.append(f"{name}:{no}: unknown verdict {d.get('Verdict', '')!r} ({row[0]})")
            if lv and vd:
                counts[lv][vd] += 1
            if vd == "setting":
                if source is None:
                    source = Source()
                check_setting(d.get("Note", ""), f"{name}:{no} ({row[0]})", source, errors)
            if vd == "conflict":
                if source is None:
                    source = Source()
                check_conflict(d.get("Note", ""), f"{name}:{no} ({row[0]})", source, errors)
    if not saw_table:
        return None
    rows = sum(sum(c.values()) for c in counts.values())
    if declared_rows and declared_rows[1] != rows:
        errors.append(f"{name}:{declared_rows[0]}: Totals ({declared_rows[1]} rows), table has {rows}")
    if rows and not totals:
        errors.append(f"{name}: no totals lines")
    for lv in LEVELS:
        have = sum(counts[lv].values())
        if lv not in totals:
            if have and totals and lv != "PROC":
                errors.append(f"{name}: {have} {lv} rows but no {lv} totals line")
            continue
        no, got = totals[lv]
        if got != counts[lv]:
            diff = ", ".join(
                f"{v} {got[v]}->{counts[lv][v]}" for v in VERDICTS if got[v] != counts[lv][v]
            )
            errors.append(f"{name}:{no}: {lv} totals disagree with the table ({diff})")
    return counts


def fmt(c: dict[str, int]) -> str:
    return " | ".join(str(c[v]) for v in VERDICTS) + f" | {sum(c.values())}"


def pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}" if whole else "-"


def render(per_file: dict[str, dict[str, dict[str, int]]]) -> str:
    out = [
        "# Clause audit counts",
        "",
        "Generated by `scripts/audit-count.py` from the tables in this directory; do not edit by",
        "hand (CI runs the script with `--check`). Levels: MUST includes MUST NOT, SHALL and",
        "REQUIRED; SHOULD includes SHOULD NOT and (NOT) RECOMMENDED; MAY includes OPTIONAL; PROC",
        "is a procedure step without a keyword. `setting`: the RFC behaviour is implemented and",
        "tested, selected by a named setting; the default differs because a named browser cell or",
        "deployed peer cannot interoperate with it. `conflict`: two specifications conflict; the",
        "clause's form is implemented and tested as a named setting, the W3C form that governs the",
        "API is the default and tested too (`RULES.md`).",
        "",
        "## Total",
        "",
        "| Level | " + " | ".join(VERDICTS) + " | rows |",
        "|---" * (len(VERDICTS) + 2) + "|",
    ]
    total = empty()
    for c in per_file.values():
        for lv in LEVELS:
            for v in VERDICTS:
                total[lv][v] += c[lv][v]
    for lv in LEVELS:
        out.append(f"| {lv} | {fmt(total[lv])} |")
    all_levels = {v: sum(total[lv][v] for lv in LEVELS) for v in VERDICTS}
    out.append(f"| all | {fmt(all_levels)} |")
    out += [
        "",
        "## RFC behaviour tested",
        "",
        "Of the rows that bind the engine (all rows but `n/a`): \"RFC behaviour tested\" counts",
        "`tested` + `setting` + `conflict`, \"tested as the default\" counts `tested` alone.",
        "",
        "| Level | rows that apply | RFC behaviour tested | % | tested as the default | % |",
        "|---|---|---|---|---|---|",
    ]
    for lv in LEVELS:
        apply = sum(total[lv].values()) - total[lv]["n/a"]
        rfc = total[lv]["tested"] + total[lv]["setting"] + total[lv]["conflict"]
        default = total[lv]["tested"]
        out.append(
            f"| {lv} | {apply} | {rfc} | {pct(rfc, apply)} | {default} | {pct(default, apply)} |"
        )
    out += [
        "",
        "## Per file",
        "",
        "| File | Level | " + " | ".join(VERDICTS) + " | rows |",
        "|---" * (len(VERDICTS) + 3) + "|",
    ]
    for name, c in per_file.items():
        for lv in LEVELS:
            if sum(c[lv].values()):
                out.append(f"| `{name}` | {lv} | {fmt(c[lv])} |")
    return "\n".join(out) + "\n"


README = os.path.join(ROOT, "README.md")


def readme_count_errors(counts_text: str, specifications: int, readme_text: str) -> list[str]:
    """README.md's figures that come from the audit, against `counts_text` (COUNTS.md as this
    script renders it) and the number of audited specifications: the status table's MUST /
    SHOULD / MAY rows, the open-MUST sentence and "audited ... against N specifications". The
    patterns are the ones the train integrator's README updater (handoff/train36/tools/
    readme_counts.py) reads and writes, so the two agree. Each error names README's line and
    both figures."""
    errors: list[str] = []
    lines = readme_text.split("\n")

    def line_of(pattern: str) -> int | None:
        for no, line in enumerate(lines, 1):
            if re.search(pattern, line):
                return no
        return None

    tot = {
        m.group(1): list(map(int, m.groups()[1:]))
        for m in re.finditer(
            r"^\| (MUST|SHOULD|MAY|PROC|all) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$",
            counts_text,
            re.M,
        )
    }
    pct = {
        m.group(1): m.groups()[1:]
        for m in re.finditer(
            r"^\| (MUST|SHOULD|MAY|PROC) \| (\d+) \| (\d+) \| ([\d.]+) \| (\d+) \| ([\d.]+) \|$",
            counts_text,
            re.M,
        )
    }
    for lvl in ("MUST", "SHOULD", "MAY"):
        if lvl not in pct:
            continue
        a, b, bp, d, dp = pct[lvl]
        want = f"| {lvl} | {a} | {b} ({bp} %) | {d} ({dp} %) |"
        no = line_of(rf"^\| {lvl} \| \d+ \| \d+ \([\d.]+ %\) \| \d+ \([\d.]+ %\) \|$")
        if no is None:
            errors.append(f"README.md: no status table row for {lvl} (COUNTS.md: {want})")
        elif lines[no - 1] != want:
            errors.append(f"README.md:{no}: {lines[no - 1]!r}, COUNTS.md gives {want!r}")
    if "MUST" in tot:
        _tested, _setting, _conflict, untested, partial, missing, violated, _na, _rows = tot["MUST"]
        opn = untested + partial + missing + violated
        viol = "none violated" if violated == 0 else f"{violated} violated"
        want = f"{opn} MUST rows are open ({untested} untested, {partial} partial, {missing} missing, {viol})"
        flat = " ".join(readme_text.split())
        m = re.search(r"\d+ MUST rows are open \(\d+ untested, \d+ partial, \d+ missing, [^)]*\)", flat)
        no = line_of(r"\d+ MUST rows are open")
        if m is None:
            errors.append(f"README.md: no open-MUST sentence (COUNTS.md: {want})")
        elif m.group(0) != want:
            errors.append(f"README.md:{no}: {m.group(0)!r}, COUNTS.md gives {want!r}")
    m = re.search(r"audited clause by clause against (\d+) specifications", readme_text)
    no = line_of(r"audited clause by clause against \d+ specifications")
    if m is None:
        errors.append(f"README.md: no 'audited clause by clause against N specifications' ({specifications})")
    elif int(m.group(1)) != specifications:
        errors.append(
            f"README.md:{no}: {m.group(1)} specifications, the audit has {specifications} "
            "(the files of docs/conformance/audit/ with clause tables)"
        )
    return errors


def main() -> int:
    check = "--check" in sys.argv[1:]
    errors: list[str] = []
    source = Source()
    per_file: dict[str, dict[str, dict[str, int]]] = {}
    for path in sorted(glob.glob(os.path.join(AUDIT, "*.md"))):
        if os.path.abspath(path) == COUNTS:
            continue
        counts = scan(path, errors, source)
        if counts is not None:
            per_file[os.path.basename(path)] = counts
    text = render(per_file)
    for e in errors:
        print(f"audit-count: {e}", file=sys.stderr)
    if check:
        try:
            with open(COUNTS, encoding="utf-8") as f:
                current = f.read()
        except FileNotFoundError:
            current = ""
        if current != text:
            print(
                "audit-count: docs/conformance/audit/COUNTS.md is out of date; run "
                "python3 scripts/audit-count.py",
                file=sys.stderr,
            )
            errors.append("stale COUNTS.md")
        with open(README, encoding="utf-8") as f:
            for e in readme_count_errors(text, len(per_file), f.read()):
                print(f"audit-count: {e}", file=sys.stderr)
                errors.append(e)
    else:
        with open(COUNTS, "w", encoding="utf-8") as f:
            f.write(text)
    if errors:
        print(f"audit-count: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print(f"audit-count: {len(per_file)} files consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

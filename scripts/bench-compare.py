#!/usr/bin/env python3
"""Compare criterion micro-benchmarks of a pull request with its base, measured in one job.

`scripts/bench-compare.sh` builds the base and the head on the same runner and runs every
benchmark in rounds that alternate between the two trees (base, head, then head, base, ...). Each
round writes criterion's `--output-format bencher` lines to a file. This script reads those files
and decides, per benchmark:

* ``ratio``: the head's median over the rounds divided by the base's median;
* the spread: the lowest and highest per-round ratio (round i of the head over round i of the
  base), which is what the runner's noise did to this benchmark in this job;
* ``slower`` when EVERY round's ratio exceeds ``1 + threshold`` and the median difference exceeds
  ``floor_ns`` (an integer-nanosecond bench of a few ns moves by a whole step on noise alone);
* ``slower`` too when the two trees are SEPARATED over at least ``separation_rounds`` rounds of
  each: the head's fastest round is slower than the base's slowest by more than ``separation``
  (relative) and ``separation_floor_ns`` (the integer resolution of criterion's bencher lines).
  This one does not depend on how fast the runner is: the noise band is the base's own spread in
  the same job. With two rounds a separation is only a suspect (``--suspects`` lists them, and
  `scripts/bench-compare.sh` runs those benches for more rounds before the verdict);
* ``faster`` symmetrically; ``same`` otherwise; ``new`` when only the head has it and ``gone``
  when only the base does.

A ``slower`` benchmark fails the job unless `benches/accepted-regressions.toml` has an entry for
it whose ``max_ratio`` covers the measured ratio and whose ``ledger`` id is a row of
`docs/performance.md`: an accepted regression is a ledger decision, never a silent one. An entry
that no longer matches a slower benchmark is reported as stale (remove it: the baseline moved).

The threshold and floor are set from measured base==head runs (`docs/performance.md`, "How to
measure"). Usage::

    python3 scripts/bench-compare.py --base base-1.txt base-2.txt --head head-1.txt head-2.txt \\
        [--allowlist benches/accepted-regressions.toml] [--ledger docs/performance.md] \\
        [--threshold 0.25] [--floor-ns 25] [--summary "$GITHUB_STEP_SUMMARY"]

Exit status 1 when a benchmark is slower and not accepted, 2 on bad input, else 0.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import statistics
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Set from five base==head runs on hosted runners (docs/performance.md, "How to measure"):
# single rounds ranged 0.85 to 1.40, but the lowest round of a bench never exceeded 1.053.
DEFAULT_THRESHOLD = 0.20
DEFAULT_FLOOR_NS = 25.0
# The separation rule (docs/performance.md, row bench-2): set from train 36's 24 pull-request bench
# runs (two rounds each): at 5 % and 3 ns it marks `Interceptor/Pacer/write+poll` in 17 of the 18
# runs after the regression of round 7 and in none of the 6 before; on two rounds it also marks a
# few other benches in 8 of the 24 runs, hence the extra rounds before it decides.
DEFAULT_SEPARATION = 0.05
DEFAULT_SEPARATION_FLOOR_NS = 3.0
DEFAULT_SEPARATION_ROUNDS = 4


def ratio_of(head: float, base: float) -> float:
    """head / base; two zeros (a sub-nanosecond bench prints 0) are the same."""
    if base > 0:
        return head / base
    return 1.0 if head == 0 else float("inf")

START = re.compile(r"^test (?P<name>\S.*?) \.\.\. ")
RESULT = re.compile(r"bench:\s+(?P<ns>[\d,]+(?:\.\d+)?) ns/iter")


def parse_bencher(text: str) -> dict[str, float]:
    """Benchmark name -> nanoseconds per iteration, from criterion's bencher lines.

    Criterion prints the integer with thousands separators (``1,234``). A message criterion
    prints while a bench runs can split its line (``test X ... Criterion.rs ERROR: ...`` and
    ``bench: 297 ns/iter`` on the next line), so a result belongs to the last ``test X ...``
    seen. Other lines are ignored; a name seen twice keeps its last value.
    """
    out: dict[str, float] = {}
    pending: str | None = None
    for line in text.splitlines():
        line = line.strip()
        start = START.match(line)
        if start:
            pending = start["name"]
            line = line[start.end():]
        result = RESULT.search(line)
        if result and pending is not None:
            out[pending] = float(result["ns"].replace(",", ""))
            pending = None
    return out


@dataclass
class Allowed:
    """One accepted regression: a benchmark (or a glob over names) may be this much slower."""

    bench: str
    max_ratio: float
    ledger: str
    note: str = ""
    used: bool = False

    def matches(self, name: str) -> bool:
        return fnmatch.fnmatchcase(name, self.bench)


def load_allowlist(text: str) -> list[Allowed]:
    """Entries of `benches/accepted-regressions.toml`: ``[[accepted]]`` tables with ``bench``,
    ``max_ratio`` and ``ledger`` (and an optional ``note``)."""
    data = tomllib.loads(text)
    out = []
    for index, entry in enumerate(data.get("accepted", [])):
        missing = [key for key in ("bench", "max_ratio", "ledger") if key not in entry]
        if missing:
            raise ValueError(f"accepted entry {index + 1} lacks {', '.join(missing)}")
        max_ratio = float(entry["max_ratio"])
        if max_ratio <= 1.0:
            raise ValueError(f"accepted entry {index + 1} ({entry['bench']}): max_ratio must exceed 1")
        out.append(Allowed(str(entry["bench"]), max_ratio, str(entry["ledger"]), str(entry.get("note", ""))))
    return out


LEDGER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def ledger_ids(text: str) -> set[str]:
    """The row ids of the ledger tables in `docs/performance.md`: the first cell of every table
    row whose first header cell is ``id`` (the header and separator rows skipped)."""
    ids = set()
    in_ledger = False
    for line in text.splitlines():
        if not line.startswith("|"):
            in_ledger = False
            continue
        first = line.strip("|").split("|", 1)[0].strip().strip("`")
        if first == "id":
            in_ledger = True
            continue
        if in_ledger and LEDGER_ID.match(first):
            ids.add(first)
    return ids


@dataclass
class Result:
    name: str
    verdict: str  # slower | faster | same | new | gone
    base_ns: float | None = None
    head_ns: float | None = None
    ratio: float | None = None
    low: float | None = None
    high: float | None = None
    accepted_by: Allowed | None = None
    rounds: list[float] = field(default_factory=list)
    # The trees are separated (see the module docstring), however many rounds there were.
    separated: str | None = None  # "slower" | "faster" | None
    # Which rule decided a slower / faster verdict: "threshold" or "separation".
    by: str | None = None

    @property
    def fails(self) -> bool:
        return self.verdict == "slower" and self.accepted_by is None

    def change(self) -> str:
        if self.ratio is None:
            return ""
        return f"{(self.ratio - 1.0) * 100:+.1f} %"


def compare(
    base_rounds: list[dict[str, float]],
    head_rounds: list[dict[str, float]],
    threshold: float = DEFAULT_THRESHOLD,
    floor_ns: float = DEFAULT_FLOOR_NS,
    allowlist: list[Allowed] | None = None,
    separation: float = DEFAULT_SEPARATION,
    separation_floor_ns: float = DEFAULT_SEPARATION_FLOOR_NS,
    separation_rounds: int = DEFAULT_SEPARATION_ROUNDS,
) -> list[Result]:
    """One result per benchmark seen in either tree, slowest change first."""
    if not base_rounds or not head_rounds:
        raise ValueError("need at least one round of each tree")
    allowlist = allowlist or []
    names = set().union(*base_rounds, *head_rounds)
    results = []
    for name in sorted(names):
        base = [r[name] for r in base_rounds if name in r]
        head = [r[name] for r in head_rounds if name in r]
        if not base:
            results.append(Result(name, "new", head_ns=statistics.median(head)))
            continue
        if not head:
            results.append(Result(name, "gone", base_ns=statistics.median(base)))
            continue
        base_ns = statistics.median(base)
        head_ns = statistics.median(head)
        ratio = ratio_of(head_ns, base_ns)
        # Rounds paired by index; a round in which either tree lacks the bench is skipped.
        paired = [
            ratio_of(h[name], b[name])
            for b, h in zip(base_rounds, head_rounds)
            if name in b and name in h
        ] or [ratio]
        low, high = min(paired), max(paired)
        difference = head_ns - base_ns
        separated = None
        if min(head) > max(base) * (1.0 + separation) and min(head) - max(base) > separation_floor_ns:
            separated = "slower"
        elif max(head) * (1.0 + separation) < min(base) and min(base) - max(head) > separation_floor_ns:
            separated = "faster"
        enough = len(base) >= separation_rounds and len(head) >= separation_rounds
        by = None
        if low > 1.0 + threshold and difference > floor_ns:
            verdict, by = "slower", "threshold"
        elif high < 1.0 / (1.0 + threshold) and -difference > floor_ns:
            verdict, by = "faster", "threshold"
        elif enough and separated:
            verdict, by = separated, "separation"
        else:
            verdict = "same"
        result = Result(
            name, verdict, base_ns, head_ns, ratio, low, high, rounds=paired, separated=separated, by=by
        )
        if verdict == "slower":
            for entry in allowlist:
                if entry.matches(name):
                    entry.used = True
                    if ratio <= entry.max_ratio:
                        result.accepted_by = entry
                    break
        results.append(result)
    order = {"slower": 0, "faster": 1, "same": 2, "new": 3, "gone": 4}
    results.sort(key=lambda r: (order[r.verdict], -(r.ratio or 0.0), r.name))
    return results


def format_ns(value: float | None) -> str:
    if value is None:
        return ""
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} ms"
    if value >= 1_000:
        return f"{value / 1_000:.2f} µs"
    return f"{value:.0f} ns"


def suspects(results: list[Result]) -> list[str]:
    """Benchmarks whose trees are separated toward slower but that are not slower yet (too few
    rounds): the ones to measure again."""
    return [r.name for r in results if r.separated == "slower" and r.verdict != "slower"]


def report(
    results: list[Result],
    allowlist: list[Allowed],
    threshold: float,
    floor_ns: float,
    separation: float = DEFAULT_SEPARATION,
    separation_floor_ns: float = DEFAULT_SEPARATION_FLOOR_NS,
    separation_rounds: int = DEFAULT_SEPARATION_ROUNDS,
) -> tuple[str, list[str]]:
    """A markdown summary and the failure messages."""
    failures = []
    lines = [
        "## Benchmarks compared with the base (same runner, alternating rounds)",
        "",
        f"Slower or faster = every round beyond {threshold * 100:.0f} % and the median differs by "
        f"more than {floor_ns:.0f} ns; or, over at least {separation_rounds} rounds of each, the "
        f"head's fastest round beyond the base's slowest by more than {separation * 100:.0f} % and "
        f"{separation_floor_ns:.0f} ns (separated). Ratio = head median / base median; spread = "
        "lowest and highest per-round ratio.",
        "",
        "| benchmark | base | head | ratio | spread | verdict |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        if (
            r.verdict in ("same",)
            and r.separated is None
            and r.ratio is not None
            and abs(r.ratio - 1.0) < threshold / 2
        ):
            continue
        verdict = r.verdict
        if r.by == "separation":
            verdict += " (separated)"
        elif r.verdict == "same" and r.separated:
            verdict += f" (separated {r.separated}, too few rounds)"
        if r.verdict == "slower":
            how = " (separated)" if r.by == "separation" else ""
            if r.accepted_by:
                verdict = f"slower{how}, accepted ({r.accepted_by.ledger})"
            else:
                verdict = f"**SLOWER**{how}"
        spread = f"{r.low:.3f} to {r.high:.3f}" if r.low is not None else ""
        ratio = f"{r.ratio:.3f}" if r.ratio is not None else ""
        lines.append(f"| `{r.name}` | {format_ns(r.base_ns)} | {format_ns(r.head_ns)} | {ratio} | {spread} | {verdict} |")
    shown = len(lines) - 6
    same = sum(1 for r in results if r.verdict == "same")
    lines += ["", f"{len(results)} benchmarks: {shown} listed, the rest within {threshold * 50:.0f} % ({same} same in all)."]

    for r in results:
        if r.fails:
            entry = next((e for e in allowlist if e.matches(r.name)), None)
            beyond = f" (its allowlist entry accepts up to {entry.max_ratio:.2f}x)" if entry else ""
            how = ", every round of the head beyond every round of the base" if r.by == "separation" else ""
            failures.append(
                f"{r.name}: slower by {(r.ratio - 1.0) * 100:.1f} % (ratio {r.ratio:.3f}, rounds "
                f"{r.low:.3f} to {r.high:.3f}{how}){beyond}; if accepted, add a ledger row "
                "(docs/performance.md) and an allowlist entry "
                "(benches/accepted-regressions.toml) naming it"
            )
    stale = [e for e in allowlist if not e.used]
    if stale:
        lines += ["", "Allowlist entries that matched no slower benchmark (stale: the baseline moved, remove them):"]
        lines += [f"- `{e.bench}` ({e.ledger})" for e in stale]
    return "\n".join(lines) + "\n", failures


def machine_lines(results: list[Result]) -> list[str]:
    """One tab-separated line per benchmark, for collecting noise across runs."""
    out = []
    for r in results:
        rounds = ",".join(f"{x:.4f}" for x in r.rounds)
        out.append(
            "BENCH\t" + "\t".join(
                [
                    r.name,
                    r.verdict,
                    "" if r.base_ns is None else f"{r.base_ns:.1f}",
                    "" if r.head_ns is None else f"{r.head_ns:.1f}",
                    "" if r.ratio is None else f"{r.ratio:.4f}",
                    rounds,
                ]
            )
        )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", nargs="+", required=True, type=Path, help="bencher output per round, base tree")
    parser.add_argument("--head", nargs="+", required=True, type=Path, help="bencher output per round, head tree")
    parser.add_argument("--allowlist", type=Path, default=ROOT / "benches" / "accepted-regressions.toml")
    parser.add_argument("--ledger", type=Path, default=ROOT / "docs" / "performance.md")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--floor-ns", type=float, default=DEFAULT_FLOOR_NS)
    parser.add_argument("--separation", type=float, default=DEFAULT_SEPARATION)
    parser.add_argument("--separation-floor-ns", type=float, default=DEFAULT_SEPARATION_FLOOR_NS)
    parser.add_argument("--separation-rounds", type=int, default=DEFAULT_SEPARATION_ROUNDS)
    parser.add_argument(
        "--suspects",
        action="store_true",
        help="print only the benchmarks to measure again (separated, too few rounds), one per line",
    )
    parser.add_argument("--summary", type=Path, help="append the markdown summary here")
    args = parser.parse_args(argv)

    try:
        base_rounds = [parse_bencher(p.read_text()) for p in args.base]
        head_rounds = [parse_bencher(p.read_text()) for p in args.head]
        allowlist = load_allowlist(args.allowlist.read_text()) if args.allowlist.exists() else []
        known = ledger_ids(args.ledger.read_text()) if args.ledger.exists() else set()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"bench-compare: {error}", file=sys.stderr)
        return 2
    if not any(head_rounds):
        print("bench-compare: the head produced no benchmark lines", file=sys.stderr)
        return 2
    unknown = [e for e in allowlist if e.ledger not in known]
    if unknown:
        for e in unknown:
            print(f"bench-compare: allowlist entry {e.bench} names ledger id {e.ledger}, "
                  f"which is not a row of {args.ledger.name}", file=sys.stderr)
        return 2

    separation = (args.separation, args.separation_floor_ns, args.separation_rounds)
    results = compare(base_rounds, head_rounds, args.threshold, args.floor_ns, allowlist, *separation)
    if args.suspects:
        for name in suspects(results):
            print(name)
        return 0
    summary, failures = report(results, allowlist, args.threshold, args.floor_ns, *separation)
    print("\n".join(machine_lines(results)))
    print(summary)
    if args.summary:
        with args.summary.open("a") as handle:
            handle.write(summary)
    for message in failures:
        print(f"::error::{message}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

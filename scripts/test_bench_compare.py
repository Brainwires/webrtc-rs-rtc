#!/usr/bin/env python3
"""Unit tests for scripts/bench-compare.py: the bencher parser, ratios and spread, the verdict's
threshold and floor, the separation rule and its suspects, new and gone benchmarks, and the
accepted-regression allowlist.

    python3 scripts/test_bench_compare.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bench_compare", HERE / "bench-compare.py")
bc = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["bench_compare"] = bc
spec.loader.exec_module(bc)


def by_name(results):
    return {r.name: r for r in results}


class Parse(unittest.TestCase):
    def test_reads_bencher_lines_with_thousands_separators(self):
        text = "\n".join(
            [
                "   Compiling rtci-dtls v0.2.0-dev",
                "test DTLS/Setup/AES-128-GCM/ring ... bench:         327 ns/iter (+/- 12)",
                "test DTLS/Encrypt/AES-256-CBC/ring ... bench:       3,204 ns/iter (+/- 41)",
                "test DTLS/Handshake/DTLS-1.2/ring ... bench:   2,512,330 ns/iter (+/- 9,101)",
                "Warning: Unable to complete 100 samples in 2.0s.",
                "test result: ok. 0 passed; 0 failed",
            ]
        )
        self.assertEqual(
            {
                "DTLS/Setup/AES-128-GCM/ring": 327.0,
                "DTLS/Encrypt/AES-256-CBC/ring": 3204.0,
                "DTLS/Handshake/DTLS-1.2/ring": 2512330.0,
            },
            bc.parse_bencher(text),
        )

    def test_a_line_split_by_a_criterion_message(self):
        text = "\n".join(
            [
                'test DTLS/Setup/AES-128-GCM/ring ... Criterion.rs ERROR: error: Failed to access file "x/base/sample.json"',
                "bench:         297 ns/iter (+/- 8)",
                "test DTLS/Encrypt/AES-128-GCM/ring ... bench:         208 ns/iter (+/- 0)",
            ]
        )
        self.assertEqual(
            {"DTLS/Setup/AES-128-GCM/ring": 297.0, "DTLS/Encrypt/AES-128-GCM/ring": 208.0},
            bc.parse_bencher(text),
        )

    def test_a_name_with_spaces_and_no_deviation(self):
        self.assertEqual({"STUN/a b": 9.0}, bc.parse_bencher("test STUN/a b ... bench: 9 ns/iter"))


class Ratios(unittest.TestCase):
    def test_ratio_of_medians_and_spread_of_paired_rounds(self):
        base = [{"x": 100.0}, {"x": 110.0}, {"x": 90.0}]
        head = [{"x": 105.0}, {"x": 99.0}, {"x": 99.0}]
        r = bc.compare(base, head, threshold=0.25, floor_ns=0)[0]
        self.assertAlmostEqual(99.0 / 100.0, r.ratio)
        self.assertAlmostEqual(0.9, r.low)
        self.assertAlmostEqual(1.1, r.high)
        self.assertEqual("same", r.verdict)

    def test_a_sub_nanosecond_bench_printing_zero_is_the_same(self):
        r = bc.compare([{"z": 0.0}] * 2, [{"z": 0.0}] * 2)[0]
        self.assertEqual(1.0, r.ratio)
        self.assertEqual([1.0, 1.0], r.rounds)
        self.assertEqual("same", r.verdict)

    def test_identical_trees_are_the_same(self):
        rounds = [{"a": 10.0, "b": 2000.0}, {"a": 11.0, "b": 2100.0}]
        self.assertTrue(all(r.verdict == "same" for r in bc.compare(rounds, rounds)))


class Verdict(unittest.TestCase):
    def test_slower_needs_every_round_beyond_the_threshold(self):
        base = [{"x": 1000.0}, {"x": 1000.0}]
        caught = bc.compare(base, [{"x": 1300.0}, {"x": 1260.0}], threshold=0.25, floor_ns=0)[0]
        self.assertEqual("slower", caught.verdict)
        self.assertTrue(caught.fails)
        one_round = bc.compare(base, [{"x": 1600.0}, {"x": 1100.0}], threshold=0.25, floor_ns=0)[0]
        self.assertEqual("same", one_round.verdict, "one noisy round is not a regression")

    def test_the_floor_keeps_nanosecond_steps_out(self):
        base = [{"tiny": 4.0}, {"tiny": 4.0}]
        head = [{"tiny": 6.0}, {"tiny": 6.0}]
        self.assertEqual("same", bc.compare(base, head, threshold=0.25, floor_ns=25)[0].verdict)
        self.assertEqual("slower", bc.compare(base, head, threshold=0.25, floor_ns=1)[0].verdict)

    def test_a_forty_fold_setup_is_slower_by_a_wide_margin(self):
        base = [{"DTLS/Setup/AES-128-GCM/ring": 300.0}] * 2
        head = [{"DTLS/Setup/AES-128-GCM/ring": 12400.0}] * 2
        r = bc.compare(base, head)[0]
        self.assertEqual("slower", r.verdict)
        self.assertGreater(r.ratio, 40)

    def test_faster_is_reported_not_failed(self):
        r = bc.compare([{"x": 1000.0}] * 2, [{"x": 500.0}] * 2)[0]
        self.assertEqual("faster", r.verdict)
        self.assertFalse(r.fails)

    def test_new_and_gone_benchmarks_do_not_fail(self):
        results = by_name(bc.compare([{"old": 50.0}] * 2, [{"new": 70.0}] * 2))
        self.assertEqual("gone", results["old"].verdict)
        self.assertEqual("new", results["new"].verdict)
        self.assertFalse(any(r.fails for r in results.values()))

    def test_slower_first_in_the_order(self):
        base = [{"a": 100.0, "b": 100.0, "c": 100.0}] * 2
        head = [{"a": 100.0, "b": 400.0, "c": 200.0}] * 2
        self.assertEqual(["b", "c", "a"], [r.name for r in bc.compare(base, head, floor_ns=0)])


ALLOWLIST = """
[[accepted]]
bench = "DTLS/Setup/*"
max_ratio = 60.0
ledger = "zeroize-1"
note = "scrub_stack after building keyed objects"
"""


class Allowlist(unittest.TestCase):
    def test_an_entry_accepts_up_to_its_ratio(self):
        allow = bc.load_allowlist(ALLOWLIST)
        base = [{"DTLS/Setup/AES-128-GCM/ring": 300.0, "DTLS/Encrypt/AES-128-GCM/ring": 270.0}] * 2
        head = [{"DTLS/Setup/AES-128-GCM/ring": 12400.0, "DTLS/Encrypt/AES-128-GCM/ring": 900.0}] * 2
        results = by_name(bc.compare(base, head, allowlist=allow))
        setup = results["DTLS/Setup/AES-128-GCM/ring"]
        self.assertEqual("slower", setup.verdict)
        self.assertFalse(setup.fails)
        self.assertEqual("zeroize-1", setup.accepted_by.ledger)
        self.assertTrue(results["DTLS/Encrypt/AES-128-GCM/ring"].fails, "the entry names Setup only")

    def test_beyond_the_accepted_ratio_fails_again(self):
        allow = bc.load_allowlist(ALLOWLIST)
        r = bc.compare([{"DTLS/Setup/x": 100.0}] * 2, [{"DTLS/Setup/x": 7000.0}] * 2, allowlist=allow)[0]
        self.assertTrue(r.fails)
        _, failures = bc.report([r], allow, bc.DEFAULT_THRESHOLD, bc.DEFAULT_FLOOR_NS)
        self.assertIn("accepts up to 60.00x", failures[0])

    def test_an_unused_entry_is_stale(self):
        allow = bc.load_allowlist(ALLOWLIST)
        results = bc.compare([{"y": 100.0}] * 2, [{"y": 100.0}] * 2, allowlist=allow)
        summary, failures = bc.report(results, allow, bc.DEFAULT_THRESHOLD, bc.DEFAULT_FLOOR_NS)
        self.assertEqual([], failures)
        self.assertIn("stale", summary)
        self.assertIn("DTLS/Setup/*", summary)

    def test_an_entry_needs_its_fields_and_a_ratio_above_one(self):
        with self.assertRaises(ValueError):
            bc.load_allowlist('[[accepted]]\nbench = "x"\nmax_ratio = 2.0\n')
        with self.assertRaises(ValueError):
            bc.load_allowlist('[[accepted]]\nbench = "x"\nmax_ratio = 0.9\nledger = "a"\n')


class Ledger(unittest.TestCase):
    def test_ids_are_the_first_cells_of_tables_headed_id(self):
        text = "\n".join(
            [
                "| id | date | change |",
                "|---|---|---|",
                "| `gcc-9` | 2026-11-24 | x |",
                "| rtx-1r2 | 2026-11-24 | y |",
                "",
                "| profile | RTCP |",
                "|---|---|",
                "| default | 122 |",
            ]
        )
        self.assertEqual({"gcc-9", "rtx-1r2"}, bc.ledger_ids(text))


class Messages(unittest.TestCase):
    def test_the_failure_says_how_to_accept(self):
        results = bc.compare([{"x": 1000.0}] * 2, [{"x": 1500.0}] * 2)
        _, failures = bc.report(results, [], bc.DEFAULT_THRESHOLD, bc.DEFAULT_FLOOR_NS)
        self.assertEqual(1, len(failures))
        self.assertIn("slower by 50.0 %", failures[0])
        self.assertIn("if accepted, add a ledger row", failures[0])
        self.assertIn("an allowlist entry", failures[0])


class Separation(unittest.TestCase):
    """The second rule (row bench-2): every head round beyond every base round, over enough rounds."""

    def rounds(self, values):
        return [{"P": float(v)} for v in values]

    def test_train_36_pacer_two_rounds_is_a_suspect_not_a_verdict(self):
        # Train 36 round 11 (run 46081695614): x1.077, rounds 1.072 / 1.081, under the threshold.
        results = bc.compare(self.rounds([111, 111]), self.rounds([119, 120]))
        self.assertEqual("same", results[0].verdict)
        self.assertEqual("slower", results[0].separated)
        self.assertEqual(["P"], bc.suspects(results))

    def test_separated_over_enough_rounds_is_slower(self):
        r = bc.compare(self.rounds([111, 111, 112, 111, 110, 111]), self.rounds([119, 120, 119, 121, 120, 119]))[0]
        self.assertEqual(("slower", "separation"), (r.verdict, r.by))
        self.assertEqual([], bc.suspects([r]))

    def test_overlapping_rounds_are_the_same(self):
        r = bc.compare(self.rounds([100, 110, 100, 108]), self.rounds([109, 105, 112, 107]))[0]
        self.assertEqual("same", r.verdict)
        self.assertIsNone(r.separated)

    def test_a_gap_under_the_margin_is_the_same(self):
        # Separated but by 4 %: the rule wants more than 5 %.
        r = bc.compare(self.rounds([100] * 4), self.rounds([104] * 4))[0]
        self.assertEqual("same", r.verdict)

    def test_a_gap_under_the_resolution_floor_is_the_same(self):
        # 10 -> 12 ns is 20 %, but 2 ns is two steps of criterion's integer figures.
        r = bc.compare(self.rounds([10] * 4), self.rounds([12] * 4))[0]
        self.assertEqual("same", r.verdict)
        self.assertIsNone(r.separated)

    def test_faster_symmetrically(self):
        r = bc.compare(self.rounds([120, 119, 121, 120]), self.rounds([110, 111, 110, 111]))[0]
        self.assertEqual(("faster", "separation"), (r.verdict, r.by))

    def test_the_threshold_rule_still_decides_first(self):
        r = bc.compare(self.rounds([1000] * 4), self.rounds([2000] * 4))[0]
        self.assertEqual(("slower", "threshold"), (r.verdict, r.by))

    def test_a_separated_slower_bench_fails_the_job_and_an_entry_accepts_it(self):
        results = bc.compare(self.rounds([111] * 4), self.rounds([120] * 4))
        self.assertTrue(results[0].fails)
        entry = bc.Allowed("P", 1.2, "zeroize-1")
        results = bc.compare(self.rounds([111] * 4), self.rounds([120] * 4), allowlist=[entry])
        self.assertFalse(results[0].fails)


class Main(unittest.TestCase):
    def write(self, directory, name, text):
        path = Path(directory) / name
        path.write_text(text)
        return path

    def run_main(self, base_ns, head_ns, allowlist="", ledger="| id | date |\n|---|---|\n| zeroize-1 | 2026-11-25 |\n"):
        with tempfile.TemporaryDirectory() as d:
            base = [self.write(d, f"b{i}", f"test X/y ... bench: {n} ns/iter (+/- 1)\n") for i, n in enumerate(base_ns)]
            head = [self.write(d, f"h{i}", f"test X/y ... bench: {n} ns/iter (+/- 1)\n") for i, n in enumerate(head_ns)]
            allow = self.write(d, "allow.toml", allowlist)
            led = self.write(d, "ledger.md", ledger)
            args = ["--base", *map(str, base), "--head", *map(str, head), "--allowlist", str(allow), "--ledger", str(led)]
            return bc.main(args)

    def test_exit_status(self):
        self.assertEqual(0, self.run_main([1000, 1010], [1005, 1000]))
        self.assertEqual(1, self.run_main([1000, 1000], [2000, 2100]))
        accepted = '[[accepted]]\nbench = "X/y"\nmax_ratio = 3.0\nledger = "zeroize-1"\n'
        self.assertEqual(0, self.run_main([1000, 1000], [2000, 2100], accepted))

    def test_an_entry_without_a_ledger_row_is_refused(self):
        orphan = '[[accepted]]\nbench = "X/y"\nmax_ratio = 3.0\nledger = "no-such-row"\n'
        self.assertEqual(2, self.run_main([1000, 1000], [2000, 2100], orphan))

    def test_suspects_lists_the_benches_to_measure_again(self):
        with tempfile.TemporaryDirectory() as d:
            base = [self.write(d, f"b{i}", f"test X/y ... bench: {n} ns/iter (+/- 1)\n") for i, n in enumerate([111, 111])]
            head = [self.write(d, f"h{i}", f"test X/y ... bench: {n} ns/iter (+/- 1)\n") for i, n in enumerate([119, 120])]
            args = ["--base", *map(str, base), "--head", *map(str, head), "--allowlist", str(Path(d) / "none.toml"), "--suspects"]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(0, bc.main(args))
            self.assertEqual("X/y\n", out.getvalue())

    def test_no_head_lines_is_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            base = self.write(d, "b", "test X/y ... bench: 10 ns/iter (+/- 1)\n")
            head = self.write(d, "h", "error: could not compile\n")
            args = ["--base", str(base), "--head", str(head), "--allowlist", str(Path(d) / "none.toml")]
            self.assertEqual(2, bc.main(args))


if __name__ == "__main__":
    unittest.main(verbosity=2)

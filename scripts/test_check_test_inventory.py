#!/usr/bin/env python3
"""Unit tests for scripts/check-test-inventory.py: the clause-audit half (`--check`: every
backticked name in the Test cell of a MUST / SHOULD row names something in the tree), and the
feature-gated targets (a `[[test]]` with `required-features` that no `cargo test` of cargo.yml
runs, or a test file whose crate-level `#![cfg]` names a feature that no command turns on).
Small trees made for each case.

    python3 scripts/test_check_test_inventory.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_test_inventory", HERE / "check-test-inventory.py")
gate = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["check_test_inventory"] = gate
spec.loader.exec_module(gate)

HEADER = "| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |\n|---|---|---|---|---|---|---|---|\n"


class Tree:
    """A throwaway repository root with the files a case writes."""

    def __init__(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.write(
            "crate/src/thing_test.rs",
            "#[test]\nfn a_refused_packet_is_dropped() {}\n\nstruct S {\n    pub initial_value_fn: u8,\n}\n",
        )
        self.write("crate/src/lib.rs", "mod thing_test;\nmod wire_framing;\n")
        self.write("crate/src/wire_framing.rs", "fn helper() {}\n")
        self.write("crate/fuzz/fuzz_targets/packet_unmarshal.rs", "fuzz_target!(|d: &[u8]| {});\n")
        self.write("tests/testenv_network.rs", "#[test]\nfn reaches_the_lan() {}\n")

    def write(self, rel: str, text: str) -> "Tree":
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return self

    def row(self, level: str, test_cell: str) -> "Tree":
        line = f"| RFC1-1-1 | 1 | {level} | a clause | tested | `x.rs` | {test_cell} | |\n"
        return self.write("docs/conformance/audit/rfc1.md", "# RFC 1\n\n" + HEADER + line)

    def errors(self) -> list[str]:
        return gate.audit_dead_names(self.root)

    def close(self) -> None:
        self._dir.cleanup()


class AuditNamesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree()

    def tearDown(self) -> None:
        self.tree.close()

    def test_an_existing_test_passes(self) -> None:
        self.tree.row("MUST", "`a_refused_packet_is_dropped`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_renamed_test_fails(self) -> None:
        self.tree.row("MUST", "`thing_test.rs::a_refused_packet_is_discarded`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("RFC1-1-1", errors[0])
        self.assertIn("a_refused_packet_is_discarded", errors[0])
        self.assertIn("rfc1.md:5", errors[0])

    def test_a_should_row_is_checked_too(self) -> None:
        self.tree.row("SHOULD NOT", "`no_such_test_anywhere`")
        self.assertEqual(len(self.tree.errors()), 1)

    def test_a_may_row_is_not_checked(self) -> None:
        self.tree.row("MAY", "`no_such_test_anywhere`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_test_cited_under_another_file_fails(self) -> None:
        self.tree.row("MUST", "`other_test.rs::a_refused_packet_is_dropped`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("not in other_test.rs", errors[0])

    def test_the_directory_and_a_crate_prefix_are_not_compared(self) -> None:
        self.tree.row(
            "MUST",
            "`src/x/thing_test.rs::a_refused_packet_is_dropped`, `crate thing_test.rs::a_refused_packet_is_dropped`",
        )
        self.assertEqual(self.tree.errors(), [])

    def test_fuzz_targets_modules_test_files_and_fields_are_names(self) -> None:
        self.tree.row(
            "MUST",
            "`packet_unmarshal`, `wire_framing`, `thing_test::tests`, `testenv_network`, `initial_value_fn`",
        )
        self.assertEqual(self.tree.errors(), [])

    def test_text_that_is_not_a_test_name_is_not_checked(self) -> None:
        self.tree.row("MUST", "`hd` tests, `a=rtcp-mux`, `tests/x.rs`, `MAX_SIZE`, `foo(true)`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_trailing_call_is_dropped_before_the_lookup(self) -> None:
        self.tree.row("MUST", "`a_refused_packet_is_dropped()`, `gone_away_test(1)`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("gone_away_test", errors[0])


class ScanTest(unittest.TestCase):
    """The hidden-test half: what `scan_file` reports for one file."""

    def scan(self, text: str) -> list:
        tree = Tree()
        try:
            tree.write("crate/tests/t.rs", text)
            saved, gate.ROOT = gate.ROOT, tree.root
            try:
                findings: list = []
                gate.scan_file(tree.root / "crate/tests/t.rs", findings, {})
            finally:
                gate.ROOT = saved
            return [(f.kind, f.test) for f in findings]
        finally:
            tree.close()

    def test_a_test_ignored_on_one_platform_is_reported_as_ignored(self) -> None:
        text = (
            "#[test]\n#[cfg_attr(\n    windows,\n    ignore = \"a reason\"\n)]\nfn only_off_windows() {}\n\n"
            "#[test]\n#[cfg_attr(target_os = \"macos\", ignore)]\nfn not_on_macos() {}\n"
        )
        self.assertEqual(
            self.scan(text), [("ignored", "only_off_windows"), ("ignored", "not_on_macos")]
        )

    def test_other_cfg_attrs_are_not_ignores(self) -> None:
        text = "#[test]\n#[cfg_attr(windows, allow(unused))]\nfn runs_everywhere() {}\n"
        self.assertEqual(self.scan(text), [])


MANIFEST = """[package]
name = "video"

[features]
default = ["engine"]
engine = ["dep:rtci"]
vp8 = ["dep:vp8-decoder"]
everything = ["vp8", "other/feature"]

[[test]]
name = "send"
required-features = ["engine", "vp8"]

[[test]]
name = "plain"
path = "tests/plain_calls.rs"
"""


class FeatureGatedTest(unittest.TestCase):
    """`send` needs `engine` (a default) and `vp8`; `plain` needs nothing."""

    def setUp(self) -> None:
        self.tree = Tree()
        self.tree.write("video/Cargo.toml", MANIFEST)

    def tearDown(self) -> None:
        self.tree.close()

    def findings(self, *commands: str) -> list:
        steps = "".join(f"      - run: {c}\n" for c in commands)
        self.tree.write(".github/workflows/cargo.yml", "jobs:\n  a:\n    steps:\n" + steps)
        found: list = []
        gate.feature_gated_findings(self.tree.root, found)
        return found

    def assert_runs(self, *commands: str) -> None:
        self.assertEqual(self.findings(*commands), [], commands)

    def assert_unrun(self, *commands: str) -> None:
        found = self.findings(*commands)
        self.assertEqual([(f.kind, f.path, f.test) for f in found], [("feature-gated", "video/tests/send.rs", "*")])
        self.assertIn("engine, vp8", found[0].detail)

    def test_a_target_no_command_runs_is_a_finding(self) -> None:
        self.assert_unrun("cargo test --workspace --verbose", "cargo build -p video --features vp8")

    def test_the_package_with_the_feature_runs_it(self) -> None:
        self.assert_runs("cargo test --package video --features vp8 --no-fail-fast")
        self.assert_runs("cargo test -p video -F engine,vp8")
        self.assert_runs("cargo test --workspace --features video/vp8")

    def test_all_features_and_a_feature_that_implies_it_run_it(self) -> None:
        self.assert_runs("cargo test -p video --all-features")
        self.assert_runs("cargo test -p video --features everything")

    def test_without_the_default_features_a_default_one_is_missing(self) -> None:
        self.assert_unrun("cargo test -p video --no-default-features --features vp8")

    def test_another_package_does_not_run_it(self) -> None:
        self.assert_unrun("cargo test -p audio --features vp8", "cargo test --features vp8")

    def test_the_target_selection_must_include_it(self) -> None:
        self.assert_runs("cargo test -p video --features vp8 --test send --test other")
        self.assert_runs("cargo test -p video --features vp8 --tests")
        self.assert_unrun("cargo test -p video --features vp8 --test other")
        self.assert_unrun("cargo test -p video --features vp8 --lib")

    def test_a_name_filter_runs_only_part_of_it(self) -> None:
        self.assert_unrun("cargo test -p video --features vp8 -- --ignored measure_")
        self.assert_unrun("cargo test -p video --features vp8 some_test")
        self.assert_runs("cargo test -p video --features vp8 -- --nocapture")

    def test_continued_lines_and_chained_commands_are_read(self) -> None:
        self.assert_runs("cargo test -p video \\\n          --features vp8 --verbose")
        self.assert_runs("cargo check -p video && cargo test -p video --features vp8 | tee log")

    def test_a_matrix_expression_is_left_out(self) -> None:
        self.assert_runs("cargo test -p video --features vp8 ${{ matrix.args }}")


CRYPTO_MANIFEST = """[package]
name = "crypto"

[features]
default = ["ring"]
ring = []
aws = []
test-support = []
"""


class CrateCfgTest(unittest.TestCase):
    """Test files gated by a crate-level `#![cfg(...)]` on a feature: compiled without it, the
    target builds and runs 0 tests, so a command counts only if it turns the features on."""

    def setUp(self) -> None:
        self.tree = Tree()
        self.tree.write("crypto/Cargo.toml", CRYPTO_MANIFEST)
        self.tree.write("crypto/tests/plain.rs", "#[test]\nfn t() {}\n")
        self.tree.write("crypto/tests/both.rs", '//! Doc.\n\n#![cfg(all(feature = "ring", feature = "aws"))]\n#[test]\nfn t() {}\n')
        self.tree.write("crypto/tests/none.rs", '#![cfg(not(any(feature = "ring", feature = "aws")))]\n#[test]\nfn t() {}\n')
        self.tree.write("crypto/tests/support.rs", '#![cfg(feature = "test-support")]\n#![cfg(unix)]\n#[test]\nfn t() {}\n')

    def tearDown(self) -> None:
        self.tree.close()

    def unrun(self, workflow: str) -> list[str]:
        self.tree.write(".github/workflows/cargo.yml", workflow)
        found: list = []
        gate.feature_gated_findings(self.tree.root, found)
        self.assertTrue(all(f.kind == "feature-gated" for f in found))
        return sorted(f.path.rsplit("/", 1)[-1] for f in found)

    def test_default_features_leave_every_gated_file_unrun(self) -> None:
        # Fails with a gate that knows only `required-features`: it reports nothing here.
        self.assertEqual(
            self.unrun("jobs:\n  a:\n    steps:\n      - run: cargo test --workspace\n"),
            ["both.rs", "none.rs", "support.rs"],
        )

    def test_the_features_on_the_command_line_run_them(self) -> None:
        workflow = (
            "jobs:\n  a:\n    steps:\n"
            "      - run: cargo test -p crypto --features aws,test-support\n"
            "      - run: cargo test -p crypto --no-default-features --test none\n"
        )
        self.assertEqual(self.unrun(workflow), [])

    def test_a_feature_off_needs_the_package_by_name_not_the_workspace(self) -> None:
        workflow = "jobs:\n  a:\n    steps:\n      - run: cargo test --workspace --no-default-features --features aws\n"
        self.assertEqual(self.unrun(workflow), ["both.rs", "none.rs", "support.rs"])
        workflow = "jobs:\n  a:\n    steps:\n      - run: cargo test --workspace --no-default-features\n"
        self.assertIn("none.rs", self.unrun(workflow))

    def test_matrix_values_are_expanded(self) -> None:
        workflow = (
            "jobs:\n"
            "  lists:\n    strategy:\n      matrix:\n        backend: [ ring, aws ]\n"
            "    steps:\n      - run: cargo test -p crypto --features ${{ matrix.backend }},test-support\n"
            "  includes:\n    strategy:\n      matrix:\n        include:\n"
            "          - name: none\n            args: --no-default-features\n"
            "          - name: default\n            args: \"\"\n"
            "    steps:\n      - run: cargo test -p crypto ${{ matrix.args }} --test none\n"
        )
        self.assertEqual(self.unrun(workflow), [])

    def test_the_cfg_evaluator(self) -> None:
        holds = gate.cfg_holds
        self.assertTrue(holds('any(feature = "a", feature = "b")', {"b"}))
        self.assertFalse(holds('all(feature = "a", feature = "b")', {"b"}))
        self.assertTrue(holds('not(feature = "a")', set()))
        self.assertTrue(holds('all(unix, feature = "a")', {"a"}))
        self.assertTrue(holds('target_os = "linux"', set()))


if __name__ == "__main__":
    unittest.main()

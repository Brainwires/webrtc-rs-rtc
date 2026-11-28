#!/usr/bin/env python3
"""Unit tests for scripts/audit-count.py's README check (`readme_count_errors`): README.md's
status figures against COUNTS.md and the number of audited specifications.

    python3 scripts/test_audit_count.py

The tree's own README.md and COUNTS.md agree; the same README with one figure changed fails,
naming the line and both figures.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location("audit_count", HERE / "audit-count.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

COUNTS = (ROOT / "docs/conformance/audit/COUNTS.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def specifications() -> int:
    import re

    return len(set(re.findall(r"^\| `([^`]+\.md)` \|", COUNTS, re.M)))


class ReadmeCounts(unittest.TestCase):
    def errors(self, readme: str) -> list[str]:
        return gate.readme_count_errors(COUNTS, specifications(), readme)

    def test_the_tree_agrees(self):
        self.assertEqual(self.errors(README), [])

    def test_a_changed_open_must_count_is_named(self):
        import re

        m = re.search(r"(\d+) MUST rows are open", README)
        changed = README.replace(m.group(0), f"{int(m.group(1)) + 5} MUST rows are open", 1)
        errors = self.errors(changed)
        self.assertEqual(len(errors), 1, errors)
        self.assertRegex(errors[0], r"^README\.md:\d+: ")
        self.assertIn(f"{int(m.group(1)) + 5} MUST rows are open", errors[0])
        self.assertIn(f"{m.group(1)} MUST rows are open", errors[0])

    def test_a_changed_status_table_figure_is_named(self):
        import re

        m = re.search(r"^\| SHOULD \| (\d+) \|", README, re.M)
        changed = README.replace(m.group(0), f"| SHOULD | {int(m.group(1)) - 1} |", 1)
        errors = self.errors(changed)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("COUNTS.md gives", errors[0])
        self.assertIn(f"| SHOULD | {m.group(1)} |", errors[0])

    def test_a_changed_specification_count_is_named(self):
        import re

        m = re.search(r"against (\d+) specifications", README)
        changed = README.replace(m.group(0), f"against {int(m.group(1)) - 2} specifications", 1)
        errors = self.errors(changed)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(f"{int(m.group(1)) - 2} specifications, the audit has {specifications()}", errors[0])

    def test_a_missing_sentence_is_reported(self):
        changed = README.replace("MUST rows are open", "MUST rows remain")
        self.assertTrue(any("no open-MUST sentence" in e for e in self.errors(changed)))


if __name__ == "__main__":
    unittest.main()

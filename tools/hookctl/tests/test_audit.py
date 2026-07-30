"""Aggregation: how many checks ran, how many failed, and what the counts say.

`audit`'s value is its numbers, so the arithmetic behind them is worth pinning:
a report that says "13 passed, 0 failed" while a check inside it failed would be
worse than no report at all.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest

from ..spec import EX_FAIL, EX_OK, AuditCheck, AuditReport
from ..verbs import audit as audit_verb
from . import support


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out:
        yield out


class TestAuditReport(unittest.TestCase):
    def test_an_empty_report_is_passing_and_empty(self):
        report = AuditReport()
        self.assertTrue(report.ok)
        self.assertEqual(0, report.passed)
        self.assertEqual(0, report.failed)
        self.assertEqual(EX_OK, report.exit_code())

    def test_counts_and_exit_code(self):
        report = AuditReport().plus(
            AuditCheck("a", True),
            AuditCheck("b", False, "why"),
            AuditCheck("c", True),
        )
        self.assertEqual(3, len(report.checks))
        self.assertEqual(2, report.passed)
        self.assertEqual(1, report.failed)
        self.assertFalse(report.ok)
        self.assertEqual(EX_FAIL, report.exit_code())
        self.assertEqual(("b",), tuple(c.name for c in report.failures))

    def test_adding_never_mutates_what_was_already_reported(self):
        # Two halves of one report cannot disagree about what ran, because a
        # report is a value.
        first = AuditReport.of([AuditCheck("a", True)])
        second = first.extend([AuditCheck("b", False)])
        self.assertEqual(1, len(first.checks))
        self.assertTrue(first.ok)
        self.assertEqual(2, len(second.checks))
        self.assertFalse(second.ok)

    def test_a_single_failure_fails_the_whole_thing(self):
        report = AuditReport.of([AuditCheck(f"c{i}", True) for i in range(12)])
        self.assertEqual(EX_OK, report.exit_code())
        self.assertEqual(EX_FAIL, report.plus(AuditCheck("last", False)).exit_code())


class TestMatcherCounting(unittest.TestCase):
    """The drift signal: literal spellings versus references to a class."""

    def test_a_literal_leaf(self):
        self.assertEqual(
            (1, 0), audit_verb.count_matchers({"kind": "tokens", "value": "git add -A"})
        )

    def test_a_set_or_class_reference(self):
        self.assertEqual(
            (0, 1),
            audit_verb.count_matchers({"kind": "word", "value": "$class:shell_names"}),
        )
        self.assertEqual(
            (0, 1), audit_verb.count_matchers({"kind": "word", "value": "$set:mine"})
        )
        # A path_class names a class in its value; membership is decided by
        # normalizing rather than by comparing.
        self.assertEqual(
            (0, 1),
            audit_verb.count_matchers({"kind": "path_class", "value": "home_or_root"}),
        )

    def test_a_group_sums_its_children(self):
        entry = {
            "any": [
                {"kind": "tokens", "value": "a"},
                {"kind": "word", "value": "$class:shell_names"},
                {
                    "all": [
                        {"kind": "tokens", "value": "b"},
                        {"kind": "flag", "value": "$set:flags"},
                    ]
                },
            ]
        }
        self.assertEqual((2, 2), audit_verb.count_matchers(entry))

    def test_every_group_operator_is_descended_into(self):
        for key in audit_verb.GROUP_KEYS:
            entry = {key: [{"kind": "tokens", "value": "x"}]}
            self.assertEqual((1, 0), audit_verb.count_matchers(entry), key)

    def test_the_shipped_defaults_are_mostly_still_referencing(self):
        # Not a threshold to tune: it asserts the file this repository ships
        # actually inherits lists from the binary, which is the property the
        # per-rule table exists to protect.
        doc = json.loads(
            (support.project_root() / "src" / "default-rules.json").read_text(
                encoding="utf-8"
            )
        )
        refs = sum(
            audit_verb.count_matchers(entry)[1]
            for rule in doc["rules"]
            for field in ("match", "match_all", "match_none")
            for entry in rule.get(field, [])
        )
        self.assertGreater(refs, 0)


SELFTEST_JSON = json.dumps(
    {
        "ok": True,
        "literal": {"total": 10, "passed": 10},
        "generated": {"total": 3, "passed": 3},
        "lint": [{"level": "warning"}, {"level": "warning"}],
    }
)

FAILING_JSON = json.dumps(
    {
        "ok": False,
        "literal": {"total": 4, "passed": 3},
        "generated": {"total": 0, "passed": 0},
        "lint": [{"level": "error"}],
    }
)


class TestFixtureAggregation(unittest.TestCase):
    def fixtures(self, replies):
        process = support.FakeProcess(replies=replies)
        ctx = support.context("audit", process=process)
        with quiet():
            checks, totals = audit_verb.audit_fixtures(
                ctx, "zig-out/bin/claude-hooker-gate"
            )
        return checks, totals, process

    def test_every_rule_file_is_asked_and_its_counts_are_summed(self):
        checks, totals, process = self.fixtures(
            {"selftest": support.reply(stdout=SELFTEST_JSON)}
        )
        self.assertEqual(4, len(checks), "one check per shipped rule document")
        self.assertTrue(all(c.ok for c in checks))
        self.assertEqual(40, totals["literal"])
        self.assertEqual(12, totals["generated"])
        self.assertEqual(0, totals["errors"])
        self.assertEqual(8, totals["warnings"])
        # Asked with a scrubbed environment, so the answer cannot depend on the
        # operator's CLAUDE_HOOK_* overrides.
        self.assertEqual(4, len(process.calls))
        self.assertTrue(all("--json" in c for c in process.commands))

    def test_a_failing_fixture_is_reported_as_failing(self):
        checks, totals, _ = self.fixtures(
            {
                "structural-rules.json": support.reply(code=1, stdout=FAILING_JSON),
                "selftest": support.reply(stdout=SELFTEST_JSON),
            }
        )
        failed = [c for c in checks if c.failed]
        self.assertEqual(1, len(failed))
        self.assertIn("structural-rules.json", failed[0].name)
        self.assertEqual(1, totals["errors"])

    def test_output_that_is_not_json_is_a_failure_with_the_reason(self):
        checks, _, _ = self.fixtures(
            {
                "selftest": support.reply(
                    code=65, stderr='claude-hooker-gate: unknown key "reasn"\n'
                )
            }
        )
        self.assertTrue(all(c.failed for c in checks))
        self.assertIn("unknown key", checks[0].detail)


if __name__ == "__main__":
    unittest.main()

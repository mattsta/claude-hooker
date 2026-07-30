"""The verb table's own integrity, and its agreement with the README.

`help`, dispatch and the README's verb table all read one table. These tests are
what make "cannot drift" true rather than merely intended: they assert the table
is well-formed, that every verb in it is documented, and that the documented
`help` output is the rendered one, byte for byte — a check that needs no Zig
toolchain and no gate binary, so it fails the moment a verb is added and the
README is not.
"""

from __future__ import annotations

import unittest

from .. import docs, ui
from ..registry import GROUPS, VERBS, find, in_group
from ..spec import CROSS_TIMEOUT, DEFAULT_BUILD_TIMEOUT, MIN_TIMEOUT, ArgShape
from . import support


class TestTableIntegrity(unittest.TestCase):
    def test_names_are_unique(self):
        names = [v.name for v in VERBS]
        self.assertEqual(
            sorted(names), sorted(set(names)), "a duplicate verb name shadows a verb"
        )

    def test_every_verb_is_in_a_declared_group(self):
        declared = {g.name for g in GROUPS}
        for verb in VERBS:
            self.assertIn(verb.group, declared, verb.name)

    def test_every_group_has_verbs(self):
        for group in GROUPS:
            self.assertTrue(
                in_group(group.name), f"{group.name} is an empty section of help"
            )

    def test_every_verb_has_a_handler_and_a_summary(self):
        for verb in VERBS:
            self.assertTrue(callable(verb.handler), verb.name)
            self.assertTrue(verb.summary.strip(), verb.name)
            self.assertFalse(
                verb.summary.endswith("."),
                f"{verb.name}: summaries are phrases, not sentences",
            )

    def test_lookup(self):
        self.assertEqual("doctor", find("doctor").name)
        self.assertIsNone(find("doctorr"))
        self.assertIsNone(find(""))

    def test_passthrough_verbs_carry_gate_arguments_and_others_do_not(self):
        for verb in VERBS:
            self.assertEqual(verb.passthrough, bool(verb.gate_args), verb.name)
        self.assertEqual(("check", "--explain"), find("explain").gate_args)
        self.assertEqual(("check",), find("check").gate_args)

    def test_only_the_comparison_verbs_rebuild_first(self):
        # A rebuild is right for the verbs that compare an install against THIS
        # tree, and wrong for everything else: `check` must not recompile the
        # world to answer a question about one command.
        rebuilding = {v.name for v in VERBS if v.refresh_build}
        self.assertEqual({"doctor", "status", "diff-defaults"}, rebuilding)

    def test_the_verbs_that_take_nothing(self):
        strict = {v.name for v in VERBS if v.args is ArgShape.none}
        self.assertEqual({"verify", "audit", "selfcheck"}, strict)

    def test_verbs_that_cannot_work_without_a_compiler_say_so(self):
        needs = {v.name for v in VERBS if v.needs_toolchain}
        self.assertEqual(
            {
                "setup",
                "init",
                "upgrade",
                "build",
                "test",
                "verify",
                "parity",
                "cross",
                "fmt",
            },
            needs,
        )
        # `audit` degrades instead of refusing, `uninstall` needs the compiler
        # only when zig-out is empty, and the passthroughs need a binary rather
        # than a toolchain.
        for name in ("audit", "uninstall", "doctor", "selfcheck", "reap"):
            self.assertFalse(find(name).needs_toolchain, name)

    def test_every_verb_is_bounded_and_only_cross_is_bounded_generously(self):
        # No verb may carry an unbounded budget. An unbounded child is the whole
        # bug: a `zig build test` nothing was waiting on spun for eleven hours.
        for verb in VERBS:
            self.assertIsInstance(verb.timeout, float, verb.name)
            self.assertGreaterEqual(verb.timeout, MIN_TIMEOUT, verb.name)
        generous = {v.name for v in VERBS if v.timeout > DEFAULT_BUILD_TIMEOUT}
        self.assertEqual(
            {"cross"}, generous, "only `cross` honestly takes tens of minutes"
        )
        self.assertEqual(CROSS_TIMEOUT, find("cross").timeout)

    def test_the_verbs_that_clear_a_previous_runs_runaway_first(self):
        reaping = {v.name for v in VERBS if v.auto_reap}
        self.assertEqual(
            {
                "setup",
                "init",
                "upgrade",
                "check",
                "build",
                "test",
                "verify",
                "parity",
                "cross",
                "audit",
            },
            reaping,
        )
        # Every verb that compiles is in that set: a fresh build must never
        # share a core with something a dead run abandoned.
        for verb in VERBS:
            if verb.needs_toolchain and verb.name != "fmt":
                self.assertTrue(
                    verb.auto_reap, f"{verb.name} compiles but does not auto-reap"
                )
        # And `doctor` is deliberately NOT, because it is the verb whose job is
        # to show you the thing an auto-reap would have silently removed.
        self.assertFalse(find("doctor").auto_reap)
        self.assertFalse(
            find("reap").auto_reap,
            "`reap` is the reaper; it must not reap before reaping",
        )

    def test_only_doctor_adds_a_check_of_the_runners_own(self):
        self.assertEqual({"doctor"}, {v.name for v in VERBS if v.runner_checks})


class TestHelpRendering(unittest.TestCase):
    def test_every_verb_appears_once_under_its_own_heading(self):
        text = ui.help_text(VERBS, GROUPS)
        for group in GROUPS:
            self.assertIn(group.heading, text)
        for verb in VERBS:
            self.assertEqual(
                1, text.count(f"  {verb.name:<{ui.VERB_COLUMN}}"), verb.name
            )
            self.assertIn(verb.summary, text)

    def test_exactly_one_trailing_newline(self):
        # The README quotes this as an ordinary fenced block, and the comparison
        # against it is byte for byte.
        text = ui.help_text(VERBS, GROUPS)
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))

    def test_groups_are_printed_in_table_order(self):
        text = ui.help_text(VERBS, GROUPS)
        positions = [text.index(g.heading) for g in GROUPS]
        self.assertEqual(sorted(positions), positions)


class TestReadmeAgreement(unittest.TestCase):
    """The two documentation checks that need neither zig nor a gate binary."""

    def setUp(self):
        self.readme = support.project_root() / "README.md"

    def test_the_verb_table_lists_exactly_the_verbs_that_exist(self):
        check = docs.check_verb_table(self.readme, VERBS)
        self.assertTrue(check.ok, check.detail)
        self.assertEqual(f"{len(VERBS)} verbs", check.detail)

    def test_the_readme_quotes_help_verbatim(self):
        check = docs.check_help_block(self.readme, VERBS, GROUPS)
        self.assertTrue(check.ok, check.detail)

    def test_the_quickstart_leads_with_hookctl(self):
        self.assertTrue(docs.check_quickstart(self.readme).ok)

    def test_the_event_table_block_is_present_and_shaped_like_a_table(self):
        """The cell-for-cell comparison needs a gate binary, and `audit` does it.

        What is checkable without one is that the table exists at all and still
        has one row per event — which is what catches an editor deleting the
        anchor or reflowing the table into prose.
        """
        lines = docs.readme_table(self.readme, "events")
        self.assertIsNotNone(lines, "no <!-- hookctl:events --> table")
        # A header, a separator, then one row per event, every row starting with
        # a backticked event name.
        self.assertGreaterEqual(len(lines), 3)
        rows = [line for line in lines[2:] if line.strip()]
        self.assertEqual(30, len(rows), "expected 30 event rows")
        for row in rows:
            self.assertTrue(row.startswith("| `"), row)
            # Six columns between seven pipes, so a cell containing a stray pipe
            # is caught here rather than by a table that renders as one long line.
            self.assertEqual(8, len(row.split("|")), row)


if __name__ == "__main__":
    unittest.main()

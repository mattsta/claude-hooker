"""Argument parsing: the verb, the flags, and what is forwarded untouched."""

from __future__ import annotations

import unittest
from pathlib import Path

from .. import argv as argv_mod


class TestParse(unittest.TestCase):
    def test_verb_and_the_rest(self):
        inv = argv_mod.parse(["check", "git", "add", "-A"])
        self.assertEqual("check", inv.verb)
        self.assertEqual(("git", "add", "-A"), inv.args)
        self.assertFalse(inv.empty)
        self.assertFalse(inv.wants_help)

    def test_no_arguments_at_all_is_not_a_verb(self):
        inv = argv_mod.parse([])
        self.assertTrue(inv.empty)
        self.assertIsNone(inv.verb)

    def test_help_flags(self):
        for spelling in ("-h", "--help"):
            self.assertTrue(argv_mod.parse([spelling]).wants_help, spelling)
        self.assertFalse(argv_mod.parse(["help"]).wants_help)

    def test_arguments_are_forwarded_verbatim(self):
        # The runner is deliberately not a parser: a flag it has never heard of
        # belongs to the child and must arrive there unchanged, in order.
        raw = ["--tool", "Bash", "--", "-rf", "--json"]
        self.assertEqual(tuple(raw), argv_mod.parse(["check", *raw]).args)


class TestFlagValue(unittest.TestCase):
    def test_both_spellings(self):
        self.assertEqual("/sb", argv_mod.flag_value(["--claude-dir", "/sb"]))
        self.assertEqual("/sb", argv_mod.flag_value(["--claude-dir=/sb"]))

    def test_absent_and_valueless(self):
        self.assertIsNone(argv_mod.flag_value([]))
        self.assertIsNone(argv_mod.flag_value(["--json"]))
        # A trailing `--claude-dir` with nothing after it is not a value; the
        # child will reject it, and this must not invent one.
        self.assertIsNone(argv_mod.flag_value(["--claude-dir"]))

    def test_a_value_containing_an_equals_sign_survives(self):
        self.assertEqual("/a=b", argv_mod.flag_value(["--claude-dir=/a=b"]))

    def test_other_flags(self):
        self.assertTrue(argv_mod.has_flag(["--dry-run"], "--dry-run"))
        self.assertFalse(argv_mod.has_flag(["--dry-run=1"], "--dry-run"))


class TestFlagOnly(unittest.TestCase):
    def test_extracts_just_the_pair(self):
        args = ["--force-rules", "--claude-dir", "/sb", "--dry-run"]
        self.assertEqual(("--claude-dir", "/sb"), argv_mod.flag_only(args))

    def test_keeps_the_joined_spelling_joined(self):
        self.assertEqual(
            ("--claude-dir=/sb",), argv_mod.flag_only(["--claude-dir=/sb", "--dry-run"])
        )

    def test_nothing_when_absent(self):
        self.assertEqual((), argv_mod.flag_only(["--dry-run"]))


class TestAbsolutize(unittest.TestCase):
    def test_relative_becomes_absolute_against_the_callers_cwd(self):
        # Children run at the repository root, so a relative --claude-dir typed
        # in some other directory would otherwise silently mean a different
        # place.
        out = argv_mod.absolutize(["--claude-dir", "sandbox"], cwd="/tmp/here")
        self.assertEqual(("--claude-dir", "/tmp/here/sandbox"), out)

    def test_joined_spelling_too(self):
        out = argv_mod.absolutize(["--claude-dir=sandbox"], cwd="/tmp/here")
        self.assertEqual(("--claude-dir=/tmp/here/sandbox",), out)

    def test_an_absolute_path_is_left_alone(self):
        self.assertEqual(
            ("--claude-dir", "/sb"), argv_mod.absolutize(["--claude-dir", "/sb"])
        )

    def test_everything_else_is_untouched(self):
        args = ["--json", "--rules", "src/default-rules.json"]
        self.assertEqual(tuple(args), argv_mod.absolutize(args))

    def test_defaults_to_the_process_cwd(self):
        out = argv_mod.absolutize(["--claude-dir", "sandbox"])
        self.assertEqual(str(Path.cwd() / "sandbox"), out[1])


class TestRemovingTheRunnersOwnFlags(unittest.TestCase):
    """`--timeout` is the runner's, and no child understands it."""

    def test_both_spellings_go_and_take_their_value_with_them(self):
        self.assertEqual(
            ("test",),
            argv_mod.without_flag_value(["--timeout", "5", "test"], "--timeout"),
        )
        self.assertEqual(
            ("test",), argv_mod.without_flag_value(["--timeout=5", "test"], "--timeout")
        )

    def test_everything_else_survives_in_order(self):
        args = ["--claude-dir", "/sb", "--timeout", "30", "git", "add", "-A"]
        self.assertEqual(
            ("--claude-dir", "/sb", "git", "add", "-A"),
            argv_mod.without_flag_value(args, "--timeout"),
        )

    def test_a_trailing_flag_with_no_value_does_not_eat_the_next_thing(self):
        self.assertEqual((), argv_mod.without_flag_value(["--timeout"], "--timeout"))

    def test_a_valueless_flag_is_removed_on_its_own(self):
        self.assertEqual(
            ("--all",), argv_mod.without_flag(["--dry-run", "--all"], "--dry-run")
        )
        self.assertEqual(("--all",), argv_mod.without_flag(["--all"], "--dry-run"))


if __name__ == "__main__":
    unittest.main()

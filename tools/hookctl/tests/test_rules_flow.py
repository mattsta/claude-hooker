"""`init`, `rules` and the authoring wizard, run against a fake tree.

The fake tree carries real copies of the two catalog documents and a fake gate
binary, and every gate invocation is answered by `FakeProcess` — so what is
under test is the runner's half of the contract: which files it writes, what
lands in them, which argv it issues, and what it refuses to do. The gate's
half (does a composed document actually pass selftest) is covered by `audit`,
which composes every profile against the real binary.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from .. import rulecatalog
from ..interact import Aborted, Console
from ..spec import COOKBOOK_RULES_FILE, EX_FAIL, EX_USAGE, SHIPPED_RULES_FILE, Paths
from ..verbs import init as init_verb
from ..verbs import rules as rules_verb
from . import support


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


def fake_root(tmp: Path) -> Path:
    """A project root with the real catalog documents and a fake built gate."""
    root = tmp / "root"
    for rel in (SHIPPED_RULES_FILE, COOKBOOK_RULES_FILE):
        source = support.project_root() / rel
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    support.executable(root / "zig-out" / "bin" / "claude-hooker-gate")
    support.executable(root / "zig-out" / "bin" / "claude-hooker-install")
    return root


def context(tmp: Path, verb: str, args=(), process=None):
    root = fake_root(tmp)
    return support.context(
        verb,
        args,
        paths=Paths.of(root, tmp / "claude"),
        process=process or support.FakeProcess(),
    )


def scripted(*answers: str) -> Console:
    feed = list(answers)

    def read(prompt: str) -> str:
        if not feed:
            raise Aborted()
        return feed.pop(0)

    return Console(read=read)


def rules_file(tmp: Path) -> Path:
    return tmp / "claude" / "hook-rules.json"


def read_doc(tmp: Path) -> dict:
    return json.loads(rules_file(tmp).read_text(encoding="utf-8"))


class InitProfiles(unittest.TestCase):
    """Every test here runs `init` as a script would: no terminal, no console.
    Pinned rather than inherited, or the suite would hang at a confirm prompt
    when run from a real terminal."""

    def setUp(self):
        self._interactive = init_verb.stdin_is_interactive
        init_verb.stdin_is_interactive = lambda: False

    def tearDown(self):
        init_verb.stdin_is_interactive = self._interactive

    def test_recommended_writes_the_shipped_document_and_installs(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            process = support.FakeProcess()
            ctx = context(tmp, "init", ("--profile", "recommended"), process)
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            shipped = rulecatalog.load_doc(ctx.paths.project_root / SHIPPED_RULES_FILE)
            self.assertEqual(shipped, read_doc(tmp))
            self.assertTrue(process.ran("claude-hooker-install"))
            self.assertTrue(process.ran("selftest --rules"))

    def test_observe_writes_only_log_rules(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--profile", "observe", "--no-install"))
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            decisions = {r["decision"] for r in read_doc(tmp)["rules"]}
            self.assertEqual({"log"}, decisions)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--profile", "minimal", "--dry-run"))
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            self.assertFalse(rules_file(tmp).exists())

    def test_existing_file_needs_force_when_not_interactive(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            support.write(rules_file(tmp), '{"rules": []}')
            ctx = context(tmp, "init", ("--profile", "minimal", "--no-install"))
            with captured():
                self.assertEqual(EX_FAIL, init_verb.init(ctx))
            self.assertEqual('{"rules": []}', rules_file(tmp).read_text("utf-8"))

    def test_force_rules_replaces_with_a_backup(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            support.write(rules_file(tmp), '{"rules": []}')
            ctx = context(
                tmp,
                "init",
                ("--profile", "minimal", "--no-install", "--force-rules"),
            )
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            self.assertEqual(
                len(rulecatalog.MINIMAL_RULES), len(read_doc(tmp)["rules"])
            )
            backups = list(rules_file(tmp).parent.glob("hook-rules.json.bak-*"))
            self.assertEqual(1, len(backups))

    def test_not_a_terminal_and_no_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init")
            with captured():
                self.assertEqual(EX_USAGE, init_verb.init(ctx))
            self.assertFalse(rules_file(tmp).exists())

    def test_bad_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--profile", "everything"))
            with captured():
                self.assertEqual(EX_USAGE, init_verb.init(ctx))

    def test_unknown_flag_is_refused_before_any_work(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            process = support.FakeProcess()
            ctx = context(tmp, "init", ("--recommended",), process)
            with captured():
                self.assertEqual(EX_USAGE, init_verb.init(ctx))
            self.assertEqual([], process.calls)


class InitBundles(unittest.TestCase):
    """The non-interactive bundle spellings."""

    def setUp(self):
        self._interactive = init_verb.stdin_is_interactive
        init_verb.stdin_is_interactive = lambda: False

    def tearDown(self):
        init_verb.stdin_is_interactive = self._interactive

    def test_one_bundle_lands_exactly_its_rules(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--bundle", "git-discipline", "--no-install"))
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            bundle = rulecatalog.bundle_named("git-discipline")
            self.assertEqual(
                sorted(bundle.rules),
                sorted(r["name"] for r in read_doc(tmp)["rules"]),
            )

    def test_bundles_are_repeatable_and_shadowable(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(
                tmp,
                "init",
                (
                    "--bundle",
                    "agent-hygiene",
                    "--bundle",
                    "machine-guards",
                    "--shadow",
                    "--no-install",
                ),
            )
            with captured():
                self.assertEqual(0, init_verb.init(ctx))
            doc = read_doc(tmp)
            wanted = set(rulecatalog.bundle_named("agent-hygiene").rules) | set(
                rulecatalog.bundle_named("machine-guards").rules
            )
            self.assertEqual(wanted, {r["name"] for r in doc["rules"]})
            self.assertEqual({"log"}, {r["decision"] for r in doc["rules"]})

    def test_unknown_bundle_and_mixed_flags_are_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--bundle", "no-such", "--no-install"))
            with captured():
                self.assertEqual(EX_USAGE, init_verb.init(ctx))
            self.assertFalse(rules_file(tmp).exists())
            mixed = context(
                tmp,
                "init",
                ("--profile", "minimal", "--bundle", "git-discipline"),
            )
            with captured():
                self.assertEqual(EX_USAGE, init_verb.init(mixed))


class InitWalkthrough(unittest.TestCase):
    def test_enter_all_the_way_takes_every_bundle_enforced(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            # Enter through: method (bundles), one per bundle (take), the
            # unbundled extra (skip), and the mode question (enforce).
            answers = [""] * (
                1 + len(rulecatalog.BUNDLES) + len(rulecatalog.UNBUNDLED) + 1
            )
            with captured():
                self.assertEqual(0, init_verb.init(ctx, console=scripted(*answers)))
            doc = read_doc(tmp)
            bundled = {n for b in rulecatalog.BUNDLES for n in b.rules}
            self.assertEqual(bundled, {r["name"] for r in doc["rules"]})
            self.assertIn("deny", {r["decision"] for r in doc["rules"]})

    def test_a_shadowed_bundle_lands_as_log(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            # First bundle answered `s`, the rest taken, extra skipped, enforce.
            answers = (
                [""]
                + ["s"]
                + [""] * (len(rulecatalog.BUNDLES) - 1)
                + [""] * len(rulecatalog.UNBUNDLED)
                + [""]
            )
            with captured():
                self.assertEqual(0, init_verb.init(ctx, console=scripted(*answers)))
            doc = read_doc(tmp)
            first = rulecatalog.BUNDLES[0]
            for name in first.rules:
                self.assertEqual(
                    "log", rulecatalog.live_rule(doc, name)["decision"], name
                )

    def test_shadow_mode_demotes_the_whole_selection(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            # "2" = everything, then "shadow" at the mode question.
            with captured():
                self.assertEqual(
                    0, init_verb.init(ctx, console=scripted("2", "shadow"))
                )
            self.assertEqual({"log"}, {r["decision"] for r in read_doc(tmp)["rules"]})

    def test_cherry_picking_a_skipped_bundle(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            first = rulecatalog.BUNDLES[0]
            answers = (
                [""]  # method: bundles
                + ["n"]  # skip the first bundle
                + [""] * (len(rulecatalog.BUNDLES) - 1)  # take the rest
                + [""] * len(rulecatalog.UNBUNDLED)  # skip the extras
                + ["y"]  # yes, cherry-pick from the skipped bundle
                + ["y"]  # take its first rule
                + [""] * (len(first.rules) - 1)  # leave the rest
                + [""]  # mode: enforce
            )
            with captured():
                self.assertEqual(0, init_verb.init(ctx, console=scripted(*answers)))
            doc = read_doc(tmp)
            names = {r["name"] for r in doc["rules"]}
            self.assertIn(first.rules[0], names)
            for left_out in first.rules[1:]:
                self.assertNotIn(left_out, names)

    def test_rule_by_rule_defaults_take_the_bundled_rules(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            catalog = rulecatalog.load_catalog(ctx.paths.project_root)
            answers = ["4"] + [""] * len(catalog.entries)
            with captured():
                self.assertEqual(0, init_verb.init(ctx, console=scripted(*answers)))
            bundled = {n for b in rulecatalog.BUNDLES for n in b.rules}
            self.assertEqual(bundled, {r["name"] for r in read_doc(tmp)["rules"]})

    def test_aborting_mid_walkthrough_writes_nothing(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "init", ("--no-install",))
            with captured():
                self.assertEqual(EX_FAIL, init_verb.init(ctx, console=scripted("", "")))
            self.assertFalse(rules_file(tmp).exists())


class RulesVerb(unittest.TestCase):
    def seeded(self, tmp: Path, process=None):
        ctx = context(tmp, "rules", (), process)
        shipped = rulecatalog.load_doc(ctx.paths.project_root / SHIPPED_RULES_FILE)
        support.write(rules_file(tmp), json.dumps(shipped))
        return ctx

    def run_rules(self, ctx, *args: str) -> int:
        import dataclasses

        with captured():
            return rules_verb.rules(dataclasses.replace(ctx, args=tuple(args)))

    def test_list_and_show_need_no_gate(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(0, self.run_rules(ctx, "list"))
            self.assertEqual(0, self.run_rules(ctx, "show", "no-pkill"))

    def test_add_carries_rule_cases_and_sets(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(0, self.run_rules(ctx, "add", "deny-prompt-private-key"))
            doc = read_doc(tmp)
            self.assertIsNotNone(rulecatalog.live_rule(doc, "deny-prompt-private-key"))
            self.assertIn("private_key_headers", doc["sets"])

    def test_add_shadow_demotes(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(
                0, self.run_rules(ctx, "add", "no-rm-rf-home-or-root", "--shadow")
            )
            rule = rulecatalog.live_rule(read_doc(tmp), "no-rm-rf-home-or-root")
            self.assertEqual("log", rule["decision"])

    def test_add_a_whole_bundle(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(0, self.run_rules(ctx, "add", "database-safety"))
            doc = read_doc(tmp)
            for name in rulecatalog.bundle_named("database-safety").rules:
                self.assertIsNotNone(rulecatalog.live_rule(doc, name), name)

    def test_add_a_bundle_already_covered_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            # The shipped defaults already carry all of `observability`.
            self.assertEqual(EX_FAIL, self.run_rules(ctx, "add", "observability"))

    def test_add_refuses_a_duplicate_and_an_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(EX_FAIL, self.run_rules(ctx, "add", "no-pkill"))
            self.assertEqual(EX_USAGE, self.run_rules(ctx, "add", "no-such"))

    def test_remove_then_file_shrinks(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            before = len(read_doc(tmp)["rules"])
            self.assertEqual(0, self.run_rules(ctx, "remove", "no-pkill"))
            self.assertEqual(before - 1, len(read_doc(tmp)["rules"]))

    def test_promote_and_demote_are_guarded(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            # Not in shadow yet: nothing to promote.
            self.assertEqual(EX_FAIL, self.run_rules(ctx, "promote", "no-pkill"))
            self.assertEqual(0, self.run_rules(ctx, "demote", "no-pkill"))
            self.assertEqual(
                "log", rulecatalog.live_rule(read_doc(tmp), "no-pkill")["decision"]
            )
            self.assertEqual(0, self.run_rules(ctx, "promote", "no-pkill"))
            self.assertEqual(
                "deny", rulecatalog.live_rule(read_doc(tmp), "no-pkill")["decision"]
            )

    def test_a_watch_rule_promotes_only_with_a_stated_decision(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(0, self.run_rules(ctx, "add", "single-entrypoint-only"))
            # The catalog ships it as `log`: bare promote has no enforced form
            # to restore, so the decision has to be stated.
            self.assertEqual(
                EX_USAGE, self.run_rules(ctx, "promote", "single-entrypoint-only")
            )
            self.assertEqual(
                0,
                self.run_rules(
                    ctx, "promote", "single-entrypoint-only", "--to", "deny"
                ),
            )
            rule = rulecatalog.live_rule(read_doc(tmp), "single-entrypoint-only")
            self.assertEqual("deny", rule["decision"])
            self.assertFalse(rule["reason"].startswith("Observational"))
            # And demote returns it to the catalog's log form exactly.
            self.assertEqual(0, self.run_rules(ctx, "demote", "single-entrypoint-only"))
            rule = rulecatalog.live_rule(read_doc(tmp), "single-entrypoint-only")
            self.assertEqual(
                rulecatalog.load_catalog(ctx.paths.project_root)
                .find("single-entrypoint-only")
                .rule,
                rule,
            )

    def test_to_is_refused_where_the_catalog_knows_the_enforced_form(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(0, self.run_rules(ctx, "demote", "no-pkill"))
            self.assertEqual(
                EX_USAGE, self.run_rules(ctx, "promote", "no-pkill", "--to", "ask")
            )
            self.assertEqual(
                EX_USAGE,
                self.run_rules(ctx, "promote", "single-entrypoint-only", "--to", "log"),
            )

    def test_rejected_selftest_leaves_the_file_alone(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            process = support.FakeProcess(
                replies={"selftest --rules": support.reply(code=65, stderr="lint")}
            )
            ctx = self.seeded(tmp, process)
            before = rules_file(tmp).read_text("utf-8")
            self.assertEqual(EX_FAIL, self.run_rules(ctx, "add", "ask-sudo"))
            self.assertEqual(before, rules_file(tmp).read_text("utf-8"))
            draft = rules_file(tmp).with_name("hook-rules.json.draft")
            self.assertTrue(draft.exists())

    def test_usage_errors(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = self.seeded(tmp)
            self.assertEqual(EX_USAGE, self.run_rules(ctx, "frobnicate"))
            self.assertEqual(EX_USAGE, self.run_rules(ctx, "show"))
            self.assertEqual(EX_USAGE, self.run_rules(ctx, "list", "extra"))
            self.assertEqual(EX_USAGE, self.run_rules(ctx, "remove", "x", "--shadow"))


class AuthorWizard(unittest.TestCase):
    def test_a_command_rule_lands_with_its_cases(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            process = support.FakeProcess()
            ctx = context(tmp, "rules", ("new",), process)
            console = scripted(
                "",  # event: PreToolUse
                "",  # tool: Bash
                "deny",  # decision
                "",  # template: program
                "terraform",  # program name
                "",  # add another condition? no
                "no-terraform",  # name
                "Infra changes are the operator's. Ask them to run `terraform`.",
                "terraform apply",  # must catch
                "",  # done
                "echo terraform",  # must not catch
                "",  # done
                "",  # target: global
            )
            import dataclasses

            with captured():
                self.assertEqual(
                    0,
                    rules_verb.rules(
                        dataclasses.replace(ctx, args=("new",)), console=console
                    ),
                )
            doc = read_doc(tmp)
            rule = rulecatalog.live_rule(doc, "no-terraform")
            self.assertEqual("deny", rule["decision"])
            self.assertEqual(
                [{"kind": "command_word", "value": "terraform"}], rule["match"]
            )
            cases = [t for t in doc["tests"] if t.get("expect_rule") == "no-terraform"]
            self.assertEqual(1, len(cases))
            # The first must-catch case is replayed through `check`.
            self.assertTrue(process.ran("check --rules"))

    def test_a_shape_rule_via_the_structure_template(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "rules", ("new",))
            console = scripted(
                "",  # event: PreToolUse
                "",  # tool: Bash
                "log",  # decision: shadow-first, as the cookbook teaches
                "structure",  # template
                "pipes > 2",  # the comparison
                "",  # add another condition? no
                "watch-my-pipelines",  # name
                "Observational only — measuring pipeline length first.",
                "a | b | c | d",  # must catch (asserted `none`: log never blocks)
                "",  # done
                "a | b",  # must not catch
                "",  # done
                "",  # target: global
            )
            import dataclasses

            with captured():
                self.assertEqual(
                    0,
                    rules_verb.rules(
                        dataclasses.replace(ctx, args=("new",)), console=console
                    ),
                )
            rule = rulecatalog.live_rule(read_doc(tmp), "watch-my-pipelines")
            self.assertEqual([{"kind": "shape", "value": "pipes > 2"}], rule["match"])

    def test_aborting_the_interview_writes_nothing(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            ctx = context(tmp, "rules", ("new",))
            with captured():
                self.assertEqual(
                    EX_FAIL, rules_verb.rules(ctx, console=scripted("", ""))
                )
            self.assertFalse(rules_file(tmp).exists())

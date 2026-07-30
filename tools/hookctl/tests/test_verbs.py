"""What each verb actually runs.

Handlers are tested by reading back the argv they would have issued, which is
the whole surface that matters: `hookctl` is a runner, and a bug in it is a
wrong command line — a gate invoked without `--claude-dir` made absolute, an
installer pointed at the wrong binary, a passthrough that forgot its
subcommand.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from .. import discovery, registry
from ..spec import EX_UNAVAILABLE, DoctorCheck, Health
from ..verbs import operator, passthrough
from . import support

#: What the gate's `doctor --json` looks like, reduced to one check. The runner's
#: own row is merged INTO this document rather than printed after it, so that a
#: script parsing the output still gets one valid object.
GATE_JSON = (
    '{"version":"0.2.0","claude_dir":"/sb","diagnosing":"/sb/gate","ok":true,'
    '"pass":1,"warn":0,"fail":0,'
    '"checks":[{"id":"wiring","title":"hook entries","status":"pass","detail":"wired","remedy":null}]}'
)

CLEAN_CHECK = DoctorCheck(
    "processes", "build and test processes", Health.ok, "nothing running"
)

#: The incident, as `ps` showed it: an orphaned runner at 100% cpu for eleven
#: hours, with the build runner below it naming the project root. The uid is this
#: machine's, because a scan refuses another user's processes and a hardcoded one
#: would find nothing on a CI runner.
INCIDENT_TEMPLATE = (
    "  39262      1   {uid}  11:04:33  99.8    40832 zig build test\n"
    "  39267  39262   {uid}  11:04:33   0.1    10784 .zig-cache/o/235b31/build /opt/zig /opt/zig/lib "
    "{root} .zig-cache /home/.cache/zig test\n"
)

#: A process table with nothing of this toolchain's in it.
IDLE_TABLE = f"  7712   7711   {os.getuid()}     00:04   0.3     8000 /bin/zsh\n"


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


class VerbCase(unittest.TestCase):
    """A temp tree with a repo root and a sandbox claude dir."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hookctl-verbs-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.sandbox = Path(self.tmp.name) / "claude"
        self.paths = discovery.paths(
            ["--claude-dir", str(self.sandbox)], root=self.root
        )

    def ctx(self, verb, args=(), *, platform=support.DARWIN, replies=None):
        return support.context(
            verb,
            args,
            paths=self.paths,
            platform=platform,
            process=support.FakeProcess(replies=replies or {}),
        )

    def build_binaries(self):
        support.executable(self.paths.built_gate)
        support.executable(self.paths.built_installer)


class TestPassthrough(VerbCase):
    def test_the_gate_subcommand_comes_from_the_table(self):
        self.build_binaries()
        for name, expected in (
            ("doctor", ("doctor",)),
            ("status", ("status",)),
            ("explain", ("check", "--explain")),
            ("version", ("version",)),
        ):
            ctx = self.ctx(name)
            with captured():
                self.assertEqual(0, passthrough.run_gate(ctx))
            gate_call = ctx.process.calls[-1]
            self.assertEqual("zig-out/bin/claude-hooker-gate", gate_call[0], name)
            self.assertEqual(expected, gate_call[1 : 1 + len(expected)], name)

    def test_the_operators_arguments_follow_with_claude_dir_absolute(self):
        self.build_binaries()
        ctx = self.ctx("check", ["--claude-dir", "sandbox", "git", "add", "-A"])
        with captured():
            passthrough.run_gate(ctx)
        call = ctx.process.calls[-1]
        self.assertEqual("check", call[1])
        self.assertEqual("--claude-dir", call[2])
        self.assertTrue(Path(call[3]).is_absolute(), call[3])
        self.assertEqual(("git", "add", "-A"), call[4:])

    def test_the_comparison_verbs_rebuild_first_and_the_others_do_not(self):
        self.build_binaries()
        ctx = self.ctx("doctor")
        with captured():
            passthrough.run_gate(ctx)
        self.assertEqual(("zig", "build", "--release"), ctx.process.calls[0])

        ctx = self.ctx("check", ["ls"])
        with captured():
            passthrough.run_gate(ctx)
        self.assertFalse(
            ctx.process.ran("zig build"),
            "`check` must not recompile to answer a question",
        )

    def test_an_installed_gate_is_named_by_its_absolute_path(self):
        support.executable(self.paths.installed_gate)
        ctx = self.ctx("version")
        with captured() as (_, err):
            passthrough.run_gate(ctx)
        self.assertEqual(str(self.paths.installed_gate), ctx.process.calls[-1][0])
        self.assertIn("using the installed", err.getvalue())

    def test_a_differing_built_gate_is_announced_once(self):
        support.executable(self.paths.built_gate, "fresh")
        support.executable(self.paths.installed_gate, "stale")
        ctx = self.ctx("version")
        with captured() as (_, err):
            passthrough.run_gate(ctx)
        self.assertIn("NOT the same binary", err.getvalue())

    def test_no_gate_anywhere_is_unavailable_with_the_fix(self):
        ctx = self.ctx("doctor")
        with captured() as (out, err):
            code = passthrough.run_gate(ctx)
        self.assertEqual(EX_UNAVAILABLE, code)
        self.assertIn(
            "needs a claude-hooker-gate binary and there is none", err.getvalue()
        )
        self.assertIn("./hookctl build", err.getvalue())
        self.assertEqual("", out.getvalue())

    def test_a_tree_that_does_not_compile_is_said_out_loud_not_fatal(self):
        support.executable(self.paths.installed_gate)
        ctx = self.ctx("doctor", replies={"zig build --release": support.reply(code=1)})
        with captured() as (_, err):
            code = passthrough.run_gate(ctx)
        self.assertEqual(
            0, code, "an install can still be diagnosed against the last build"
        )
        self.assertIn("does not currently compile", err.getvalue())


class TestSetup(VerbCase):
    def test_build_then_install_then_ask_the_os_about_the_signature(self):
        ctx = self.ctx("setup", ["--claude-dir", str(self.sandbox)])
        with captured() as (out, _):
            self.assertEqual(0, operator.setup(ctx))
        commands = ctx.process.commands
        self.assertEqual("zig build --release", commands[0])
        self.assertIn(
            "zig-out/bin/claude-hooker-install --gate zig-out/bin/claude-hooker-gate",
            commands[1],
        )
        self.assertIn(str(self.sandbox), commands[1])
        # The signature is the last thing asked about, of the file that was just
        # installed — not of the one in zig-out.
        self.assertTrue(any("codesign --display" in c for c in commands))
        self.assertTrue(any("codesign --verify" in c for c in commands))
        self.assertTrue(
            all(
                str(self.paths.installed_gate) in c for c in commands if "codesign" in c
            )
        )
        printed = out.getvalue()
        self.assertIn("== build ==", printed)
        self.assertIn("== install ==", printed)
        self.assertIn("== signature ==", printed)

    def test_off_darwin_there_is_no_signature_section_at_all(self):
        ctx = self.ctx("setup", platform=support.LINUX)
        with captured() as (out, _):
            operator.setup(ctx)
        self.assertNotIn("signature", out.getvalue())
        self.assertFalse(ctx.process.ran("codesign"))

    def test_a_dry_run_asks_about_nothing(self):
        ctx = self.ctx("setup", ["--dry-run"])
        with captured() as (out, _):
            operator.setup(ctx)
        self.assertFalse(
            ctx.process.ran("codesign"), "there is nothing on disk to ask about"
        )
        self.assertNotIn("== signature ==", out.getvalue())

    def test_a_failed_build_stops_before_installing_anything(self):
        ctx = self.ctx("setup", replies={"zig build --release": support.reply(code=1)})
        with captured():
            self.assertEqual(1, operator.setup(ctx))
        self.assertEqual(1, len(ctx.process.calls))

    def test_a_failed_install_is_not_followed_by_a_signature_claim(self):
        ctx = self.ctx(
            "setup", replies={"claude-hooker-install": support.reply(code=70)}
        )
        with captured() as (out, _):
            self.assertEqual(70, operator.setup(ctx))
        self.assertFalse(ctx.process.ran("codesign"))
        self.assertNotIn("== signature ==", out.getvalue())


class TestUpgrade(VerbCase):
    def test_it_diffs_the_defaults_then_reinstalls_the_binary_only(self):
        ctx = self.ctx("upgrade", ["--claude-dir", str(self.sandbox)])
        with captured() as (out, _):
            self.assertEqual(0, operator.upgrade(ctx))
        commands = ctx.process.commands
        self.assertEqual("zig build --release", commands[0])
        self.assertIn("claude-hooker-gate diff-defaults --claude-dir", commands[1])
        self.assertIn("claude-hooker-install --gate", commands[2])
        printed = out.getvalue()
        self.assertIn("Your rule file is not touched", printed)
        self.assertIn("== reinstall the binary ==", printed)

    def test_force_rules_says_what_it_will_do_before_doing_it(self):
        ctx = self.ctx("upgrade", ["--force-rules"])
        with captured() as (out, _):
            operator.upgrade(ctx)
        self.assertIn(
            "--force-rules: your rule file WILL be overwritten", out.getvalue()
        )

    def test_diff_defaults_is_not_handed_the_installers_own_flags(self):
        ctx = self.ctx(
            "upgrade", ["--claude-dir", str(self.sandbox), "--force-rules", "--dry-run"]
        )
        with captured():
            operator.upgrade(ctx)
        diff = [c for c in ctx.process.commands if "diff-defaults" in c][0]
        self.assertNotIn("--force-rules", diff)
        self.assertNotIn("--dry-run", diff)


class TestUninstall(VerbCase):
    def test_it_builds_the_installer_when_zig_out_is_empty(self):
        ctx = self.ctx("uninstall", ["--purge"])
        with captured():
            self.assertEqual(0, operator.uninstall(ctx))
        self.assertEqual(("zig", "build", "--release"), ctx.process.calls[0])
        self.assertIn("--uninstall --purge", ctx.process.commands[-1])

    def test_with_the_installer_already_built_nothing_is_compiled(self):
        self.build_binaries()
        ctx = self.ctx("uninstall")
        with captured():
            operator.uninstall(ctx)
        self.assertFalse(ctx.process.ran("zig build"))

    def test_without_a_compiler_or_an_installer_it_degrades(self):
        ctx = support.context(
            "uninstall",
            paths=self.paths,
            toolchain=type(support.ZIG).absent(),
            process=support.FakeProcess(),
        )
        with captured() as (_, err):
            self.assertEqual(EX_UNAVAILABLE, operator.uninstall(ctx))
        self.assertIn("needs the Zig compiler", err.getvalue())
        self.assertEqual([], ctx.process.calls)


class TestDoctorGetsTheRunnersOwnCheck(VerbCase):
    """`doctor` = the gate's checks about an INSTALL, plus one about this TREE.

    The gate cannot make this one. An installed gate in a `~/.claude` with no
    clone beside it has no working tree to have stale build processes in.
    """

    def incident(self) -> str:
        """The incident, with the build runner naming THIS test's project root."""
        return INCIDENT_TEMPLATE.format(uid=os.getuid(), root=self.root)

    def doctor(self, args=(), *, listing: str | None = None):
        self.build_binaries()
        ctx = support.context(
            "doctor",
            args,
            paths=self.paths,
            process=support.FakeProcess(
                replies={
                    "ps ": support.reply(
                        stdout=listing if listing is not None else IDLE_TABLE
                    ),
                    "claude-hooker-gate doctor": support.reply(stdout=GATE_JSON),
                }
            ),
        )
        with captured() as (out, err):
            code = passthrough.run_gate(ctx)
        return code, out.getvalue(), err.getvalue(), ctx

    def test_the_check_is_printed_under_the_gates_own(self):
        code, out, _, _ = self.doctor()
        self.assertEqual(0, code)
        self.assertIn("this checkout's own build processes", out)
        self.assertIn("PASS  processes", out)
        self.assertIn("no build or test process from this checkout is running", out)

    def test_a_runaway_makes_doctor_exit_nonzero_even_when_the_install_is_fine(self):
        code, out, _, _ = self.doctor(listing=self.incident())
        self.assertEqual(
            1, code, "a FAIL from the runner's check must still fail the verb"
        )
        self.assertIn("FAIL  processes", out)
        self.assertIn("./hookctl reap", out)

    def test_json_gets_one_valid_document_with_the_extra_row_merged_in(self):
        code, out, _, _ = self.doctor(["--json"], listing=self.incident())
        self.assertEqual(1, code)
        parsed = json.loads(out)
        self.assertEqual(["wiring", "processes"], [c["id"] for c in parsed["checks"]])
        # The tallies are recomputed rather than incremented, so they cannot
        # drift from the rows.
        self.assertEqual(1, parsed["pass"])
        self.assertEqual(1, parsed["fail"])
        self.assertFalse(parsed["ok"])
        self.assertEqual(
            len(parsed["checks"]), parsed["pass"] + parsed["warn"] + parsed["fail"]
        )

    def test_a_json_document_it_does_not_understand_is_passed_through_untouched(self):
        self.assertIsNone(passthrough.merge_json("not json at all", CLEAN_CHECK))
        self.assertIsNone(passthrough.merge_json('{"no":"checks"}', CLEAN_CHECK))
        self.assertIsNone(passthrough.merge_json("[]", CLEAN_CHECK))

    def test_a_warn_is_merged_without_making_the_document_not_ok(self):
        merged = passthrough.merge_json(
            GATE_JSON, dataclasses.replace(CLEAN_CHECK, status=Health.warn)
        )
        parsed = json.loads(merged or "{}")
        self.assertEqual(1, parsed["warn"])
        self.assertEqual(0, parsed["fail"])
        self.assertTrue(
            parsed["ok"], "a WARN must not break a pipeline, on either side"
        )


class TestRegistryWiring(unittest.TestCase):
    def test_every_passthrough_verb_shares_one_handler(self):
        # What `doctor` adds is a FIELD, not a second handler: `help`, dispatch
        # and the doc check keep reading one table.
        handlers = {v.handler for v in registry.VERBS if v.passthrough}
        self.assertEqual({passthrough.run_gate}, handlers)


if __name__ == "__main__":
    unittest.main()

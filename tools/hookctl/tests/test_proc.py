"""The subprocess chokepoint: the failures that are not "exited nonzero".

These are the only tests here that really spawn something, and everything they
spawn is `/bin/echo`, `/bin/sh` or a `sleep` with a small self-terminating
bound. Nothing here is allowed to outlive its test: the incident this module was
rewritten for began with a test runner that outlived its invoker, and a suite
that manufactured long-lived children to prove it can kill them would be
reproducing the bug in order to test the fix.

The group-kill tests are the load-bearing ones. `zig build test` puts the work
in its GRANDchildren, so `sh -c 'sleep 60 & sleep 60'` is the shape that
matters: a direct child with children of its own, where killing only the direct
child leaves the rest running at PPID 1.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import time
import unittest
from pathlib import Path

from .. import proc
from ..spec import EX_TIMEOUT, EX_UNAVAILABLE, RunMode


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.runner = proc.Runner(cwd=Path("/"))

    def test_captured_output_comes_back_with_the_argv_that_produced_it(self):
        result = self.runner.run(("echo", "hello"), mode=RunMode.capture)
        self.assertTrue(result.ok)
        self.assertEqual("hello\n", result.stdout)
        self.assertEqual(("echo", "hello"), result.argv)
        self.assertEqual("echo hello", result.command)
        self.assertGreaterEqual(result.duration, 0.0)

    def test_a_nonzero_exit_is_reported_not_raised(self):
        result = self.runner.run(("sh", "-c", "exit 3"), mode=RunMode.capture)
        self.assertFalse(result.ok)
        self.assertEqual(3, result.code)

    def test_a_missing_program_is_a_result_not_an_exception(self):
        result = self.runner.run(("hookctl-no-such-program",), mode=RunMode.capture)
        self.assertEqual(EX_UNAVAILABLE, result.code)
        self.assertIn("not found on PATH", result.stderr)
        self.assertIn("hookctl-no-such-program", result.first_error_line())

    def test_a_hung_child_is_given_up_on(self):
        # 124 rather than 69: a step that was killed is a different fact from a
        # step that could not be run, and a script has to be able to tell them
        # apart. `timed_out` is the flag the verbs branch on.
        result = self.runner.run(("sleep", "30"), mode=RunMode.capture, timeout=0.2)
        self.assertEqual(EX_TIMEOUT, result.code)
        self.assertTrue(result.timed_out)
        self.assertIn("no answer after 0s", result.stderr)
        self.assertIn("no survivors", result.stderr)

    def test_quiet_hides_a_success_and_replays_a_failure(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.runner.run(("echo", "fine"), mode=RunMode.quiet)
            self.assertEqual("", out.getvalue())
            self.runner.run(
                ("sh", "-c", "echo trouble >&2; exit 1"), mode=RunMode.quiet
            )
        self.assertIn("trouble", err.getvalue())

    def test_the_environment_can_be_scrubbed_of_the_gates_overrides(self):
        # The checks that must give the same answer on every machine run this
        # way: CLAUDE_HOOK_* is exactly what would make them differ.
        script = "echo ${CLAUDE_HOOK_DISABLE-unset} ${CLAUDE_PROJECT_DIR-unset}"
        import os

        os.environ["CLAUDE_HOOK_DISABLE"] = "no-pkill"
        os.environ["CLAUDE_PROJECT_DIR"] = "/repo"
        self.addCleanup(os.environ.pop, "CLAUDE_HOOK_DISABLE", None)
        self.addCleanup(os.environ.pop, "CLAUDE_PROJECT_DIR", None)

        kept = self.runner.run(("sh", "-c", script), mode=RunMode.capture)
        self.assertEqual("no-pkill /repo\n", kept.stdout)
        scrubbed = self.runner.run(
            ("sh", "-c", script), mode=RunMode.capture, scrub_env=True
        )
        self.assertEqual("unset unset\n", scrubbed.stdout)

    def test_verbose_echoes_the_command_to_stderr_only(self):
        loud = proc.Runner(cwd=Path("/"), verbose=True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            loud.run(("echo", "hi"), mode=RunMode.capture)
        self.assertIn("+ echo hi", err.getvalue())
        self.assertEqual("", out.getvalue())

    def test_children_run_at_the_directory_they_were_given(self):
        result = proc.Runner(cwd=Path("/")).run(
            ("sh", "-c", "pwd"), mode=RunMode.capture
        )
        self.assertEqual("/\n", result.stdout)

    def test_first_error_line_prefers_stderr_and_falls_back_to_the_code(self):
        result = self.runner.run(("sh", "-c", "exit 7"), mode=RunMode.capture)
        self.assertEqual("exited 7", result.first_error_line())


class TestGroupKill(unittest.TestCase):
    """The bug, reduced: a child whose children do the work.

    Every process started here is a `sleep` with a small bound, so the worst
    case if an assertion is wrong is a handful of sleeps that exit by themselves
    within seconds. Nothing spins, and nothing loops without an upper bound.
    """

    #: Long enough that nothing can finish on its own and turn a real failure
    #: into a pass; short enough that a leak from a broken assertion is gone
    #: before anyone notices.
    CHILD_SECONDS = 30

    def setUp(self):
        self.runner = proc.Runner(cwd=Path("/"))

    def spawn_family(self):
        """A child with two children of its own, all in one new session."""
        child = subprocess.Popen(
            (
                "sh",
                "-c",
                f"sleep {self.CHILD_SECONDS} & sleep {self.CHILD_SECONDS} & wait",
            ),
            start_new_session=True,
        )
        self.addCleanup(self._make_sure_it_is_gone, child)
        # Wait for `sh` to fork the grandchildren rather than assuming it has:
        # an assertion about killing a group of three is worthless if the group
        # only ever had one member. Bounded, and each `ps` is itself slow enough
        # that the first look is normally the last.
        pgid = os.getpgid(child.pid)
        for _ in range(20):
            if len(self._members(pgid)) >= 3:
                break
            time.sleep(0.05)
        return child, pgid

    def _members(self, pgid: int) -> list[int]:
        # `-ax`, not the default: a child in its own session has no controlling
        # terminal, and a plain `ps` would not list the very processes under
        # test. This is the same reason `processes.PS_DARWIN` uses `-ax`.
        listed = subprocess.run(
            ("ps", "-axo", "pid=,pgid="),
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        found = []
        for line in listed.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit() and int(fields[1]) == pgid:
                found.append(int(fields[0]))
        return found

    def _make_sure_it_is_gone(self, child):
        """Belt to the braces: never leave a process behind, even on failure."""
        proc.terminate_group(child)

    def test_a_new_session_means_the_child_leads_its_own_group(self):
        # The property everything else here depends on. Without it there is no
        # handle on the grandchildren at all.
        child, pgid = self.spawn_family()
        self.assertEqual(child.pid, pgid)
        self.assertNotEqual(os.getpgid(0), pgid)
        self.assertGreaterEqual(
            len(self._members(pgid)), 3, "sh did not fork its two children"
        )

    def test_terminating_the_group_takes_the_grandchildren_with_it(self):
        child, pgid = self.spawn_family()
        self.assertGreaterEqual(len(self._members(pgid)), 3)
        survivors = proc.terminate_group(child)
        self.assertEqual((), survivors, "terminate_group reported survivors")
        self.assertEqual(
            [], self._members(pgid), "a grandchild outlived the group kill"
        )

    def test_a_timeout_kills_the_group_and_says_so(self):
        result = self.runner.run(
            (
                "sh",
                "-c",
                f"sleep {self.CHILD_SECONDS} & sleep {self.CHILD_SECONDS} & wait",
            ),
            mode=RunMode.capture,
            timeout=0.4,
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(EX_TIMEOUT, result.code)
        self.assertIn("no survivors", result.stderr)
        self.assertGreater(result.duration, 0.3)

    def test_a_group_this_runner_belongs_to_is_never_signalled(self):
        """The guard that stops a bug here from killing the operator's shell."""
        ours = subprocess.Popen(("sleep", "0.01"))  # no new session: our group
        self.addCleanup(ours.wait)
        self.assertIsNone(proc.group_of(ours))

    def test_the_timeout_message_names_the_command_the_budget_and_the_survivors(self):
        clean = proc.timeout_message(("zig", "build", "test"), 301.4, 300.0, 0)
        self.assertIn("zig build test", clean)
        self.assertIn("no answer after 300s", clean)
        self.assertIn("ran 301.4s", clean)
        self.assertIn("no survivors", clean)
        leaked = proc.timeout_message(("zig", "build", "test"), 301.4, 300.0, 1)
        self.assertIn("SURVIVED SIGKILL", leaked)
        self.assertIn("./hookctl reap", leaked)


class TestZigHelpers(unittest.TestCase):
    def test_zig_build_is_the_one_shape_this_project_compiles_in(self):
        from .support import FakeProcess

        process = FakeProcess()
        proc.zig_build(process, "--release", mode=RunMode.quiet)
        self.assertEqual(("zig", "build", "--release"), process.calls[0])
        self.assertEqual(RunMode.quiet, process.modes[0])

    def test_the_zig_version_is_read_or_absent(self):
        from .support import FakeProcess, reply

        answered = FakeProcess(replies={"zig version": reply(stdout="0.16.0\n")})
        self.assertEqual("0.16.0", proc.zig_version(answered))
        silent = FakeProcess(replies={"zig version": reply(code=1)})
        self.assertIsNone(proc.zig_version(silent))


if __name__ == "__main__":
    unittest.main()

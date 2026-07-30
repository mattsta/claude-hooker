"""The runaway-process hunt, driven entirely by fixture text.

**Nothing in this file spawns a long-running process, and nothing in it may.**
The incident this code exists for began with a test runner that outlived its
invoker; a suite that manufactured eleven-hour spinners to prove it can find
eleven-hour spinners would be reproducing the bug in order to test the fix. So
the process table is a string, the clock is a counter, the filesystem is a
predicate and the signals go into a list.

The centrepiece fixture is the incident itself, transcribed from the shape a real
`zig build test` leaves in `ps` — which is worth reading before the tests,
because three of its four lines are the reason attribution is not a substring
match:

  * the orphaned `zig build test` has **no path in its argv at all**;
  * the build runner between them is the only process that spells out the
    project root;
  * the test binaries that actually burn the CPU are spawned with a **relative**
    path.
"""

from __future__ import annotations

import ast
import contextlib
import io
import os
import unittest
from pathlib import Path

from .. import processes, ui
from ..spec import (
    EX_FAIL,
    EX_OK,
    EX_UNAVAILABLE,
    EX_USAGE,
    Attribution,
    Health,
    KillSignal,
    Platform,
    ProcessKind,
    ProcessTable,
    Scope,
    Thresholds,
)
from ..verbs import reap as reap_verb
from . import support

ROOT = "/Users/matt/repos/demo"

#: This machine's uid, substituted into every fixture. The uid column is not
#: decoration: `shortlist` refuses another user's processes, so a fixture that
#: hardcoded 501 would find five candidates on the author's laptop and none at
#: all on a CI runner. `OTHER_UID` is somebody else, for the row that must be
#: filtered out.
OURS = os.getuid()
OTHER_UID = 0 if OURS != 0 else 1

# ---------------------------------------------------------------------------
# fixtures: real `ps` output, one per platform
# ---------------------------------------------------------------------------

#: macOS: `ps -axww -o pid=,ppid=,uid=,etime=,pcpu=,rss=,command=`, eleven hours
#: into the incident.
DARWIN_INCIDENT = f"""\
  39262      1   {OURS}  11:04:33  99.8    40832 zig build test
  39267  39262   {OURS}  11:04:33   0.1    10784 .zig-cache/o/235b31/build \
/opt/homebrew/Cellar/zig/0.16.0/bin/zig /opt/homebrew/Cellar/zig/0.16.0/lib/zig \
/Users/matt/repos/demo .zig-cache /Users/matt/.cache/zig --seed 0xb5e4a51a test
  39271  39267   {OURS}  11:04:32   6.5    38800 (zig)
  39293  39267   {OURS}  11:04:31  99.4     6256 ./.zig-cache/o/99bca0/test \
--cache-dir=./.zig-cache --seed=0xb5e4a51a --listen=-
  39295  39267   {OURS}  11:04:31  98.7     6128 ./.zig-cache/o/541236/test \
--cache-dir=./.zig-cache --seed=0xb5e4a51a --listen=-
   1234      1   {OURS}  3-02:11:09   0.0     3200 /Users/matt/repos/other/.zig-cache/o/abc123/test --listen=-
    501      1   {OTHER_UID}  9-00:00:00  99.0    12000 /Users/matt/repos/demo/.zig-cache/o/deadbe/test --listen=-
   7712   7711   {OURS}     00:04   0.3     8000 /bin/zsh
"""

#: Linux: `ps -eww -o pid=,ppid=,uid=,etime=,pcpu=,rss=,args=`. Two differences
#: from the above that the parser has to survive: `%cpu` over 100 (procps counts
#: per-core, so a two-thread process reads 187.5) and the `DD-HH:MM:SS` elapsed
#: form for anything past a day.
LINUX_ROOT = "/srv/ci/demo"
LINUX_TABLE = f"""\
   4210      1  {OURS}    11:04:33  99.8    40832 zig build test
   4215   4210  {OURS}    11:04:33   0.1    10784 .zig-cache/o/235b31/build \
/usr/bin/zig /usr/lib/zig /srv/ci/demo .zig-cache /home/ci/.cache/zig --seed 0x1 test
   4260   4215  {OURS}  2-03:04:05 187.5     6256 /srv/ci/demo/.zig-cache/o/99bca0/test --listen=-
   4261   4215  {OURS}       05:23   4.0    38800 /usr/bin/zig build-exe -ODebug src/main.zig
      1      0  {OTHER_UID} 21-11:22:33   0.0     9000 /sbin/init
"""

#: A healthy build, thirty seconds in: nothing orphaned, nothing over the
#: elapsed threshold, and the compile pegging a core the way a compile does.
DARWIN_HEALTHY = f"""\
  50100  50099   {OURS}     00:31  95.0    40832 zig build test
  50101  50100   {OURS}     00:30   0.2    10784 .zig-cache/o/235b31/build /opt/zig /opt/zig/lib \
/Users/matt/repos/demo .zig-cache /Users/matt/.cache/zig test
"""

#: A build that has been going for twenty minutes and is doing nothing: past the
#: ten-minute threshold, parented, idle. A WARN, not a FAIL.
DARWIN_SLOW = f"""\
  50200  50199   {OURS}     20:14   1.0    40832 zig build test
  50201  50200   {OURS}     20:13   0.5    10784 .zig-cache/o/235b31/build /opt/zig /opt/zig/lib \
/Users/matt/repos/demo .zig-cache /Users/matt/.cache/zig test
"""

#: Nothing of ours at all.
IDLE = f"  7712   7711   {OURS}     00:04   0.3     8000 /bin/zsh\n"


def ours(pid: int, ppid: int, elapsed: str, cpu: str, command: str) -> str:
    """One `ps` row owned by this user, for the one-line fixtures."""
    return f"  {pid}  {ppid}  {OURS}  {elapsed}  {cpu}  3200 {command}\n"


def table(text: str) -> ProcessTable:
    return ProcessTable(records=processes.parse_table(text))


def scan_of(
    text: str,
    root: str = ROOT,
    *,
    uid: int = OURS,
    self_pid: int = 99999,
    thresholds: Thresholds = Thresholds(),
    cwds=(),
    exists=lambda _path: False,
):
    """`classify` with every impure input stated. No machine is consulted."""
    return processes.classify(
        table(text),
        root,
        uid=uid,
        self_pid=self_pid,
        cwds=cwds,
        thresholds=thresholds,
        exists=exists,
    )


class TestParsing(unittest.TestCase):
    def test_the_macos_table_parses_every_row(self):
        records = processes.parse_table(DARWIN_INCIDENT)
        self.assertEqual(8, len(records))
        runner = records[0]
        self.assertEqual(39262, runner.pid)
        self.assertEqual(1, runner.ppid)
        self.assertEqual(OURS, runner.uid)
        self.assertEqual("zig build test", runner.command)
        self.assertEqual("zig", runner.exe)
        self.assertAlmostEqual(99.8, runner.cpu)
        self.assertEqual(40832, runner.rss_kib)
        # Eleven hours, four minutes, thirty-three seconds. The whole point.
        self.assertAlmostEqual(11 * 3600 + 4 * 60 + 33, runner.elapsed)
        self.assertTrue(runner.orphaned)

    def test_the_linux_table_parses_including_the_two_things_that_differ(self):
        records = processes.parse_table(LINUX_TABLE)
        self.assertEqual(5, len(records))
        by_pid = {r.pid: r for r in records}
        # procps counts cpu per core, so a multi-threaded process is over 100.
        self.assertAlmostEqual(187.5, by_pid[4260].cpu)
        # `DD-HH:MM:SS` for anything past a day.
        self.assertAlmostEqual(2 * 86400 + 3 * 3600 + 4 * 60 + 5, by_pid[4260].elapsed)
        self.assertAlmostEqual(21 * 86400 + 11 * 3600 + 22 * 60 + 33, by_pid[1].elapsed)
        # `args=` keeps the whole command line, spaces and all.
        self.assertEqual(
            "/usr/bin/zig build-exe -ODebug src/main.zig", by_pid[4261].command
        )

    def test_the_elapsed_forms_both_platforms_print(self):
        for text, seconds in (
            ("00:04", 4),
            ("05:23", 5 * 60 + 23),
            ("11:04:33", 11 * 3600 + 4 * 60 + 33),
            ("3-02:11:09", 3 * 86400 + 2 * 3600 + 11 * 60 + 9),
            ("  21-11:22:33 ", 21 * 86400 + 11 * 3600 + 22 * 60 + 33),
        ):
            self.assertAlmostEqual(
                seconds, processes.parse_elapsed(text) or -1, msg=text
            )
        for junk in ("", "   ", "nonsense", "1:2:3:4", "x-01:00:00"):
            self.assertIsNone(processes.parse_elapsed(junk), junk)

    def test_a_line_that_cannot_be_parsed_is_skipped_not_guessed_at(self):
        mixed = "  1 2 3 00:01 0.0 100 fine\ngarbage\n  4 5 6 nope 0.0 100 bad-etime\n  7 8 9 00:02 0.0 100\n"
        records = processes.parse_table(mixed)
        self.assertEqual([1], [r.pid for r in records])

    def test_the_ps_command_line_differs_by_platform_and_why(self):
        darwin = processes.ps_argv(
            Platform(system="Darwin", arch="arm64", needs_signing=True)
        )
        linux = processes.ps_argv(
            Platform(system="Linux", arch="x86_64", needs_signing=False)
        )
        # `-e` on macOS means "show the environment", so it cannot be one command.
        self.assertIn("-axww", darwin)
        self.assertIn("-eww", linux)
        # An orphan has no controlling terminal; without `-x`/`-e` it is invisible.
        self.assertTrue(darwin[1].startswith("-ax"))
        # procps names the full command line `args`; BSD names it `command`.
        self.assertTrue(darwin[-1].endswith("command="))
        self.assertTrue(linux[-1].endswith("args="))

    def test_lsof_output_becomes_cwds(self):
        found = processes.parse_lsof(
            "p39262\nn/Users/matt/repos/demo\np1234\nn/elsewhere\n"
        )
        self.assertEqual(
            [(39262, "/Users/matt/repos/demo"), (1234, "/elsewhere")],
            [(c.pid, c.cwd) for c in found],
        )
        # A pid with no `n` line contributes nothing: not knowing is not a match.
        self.assertEqual((), processes.parse_lsof("p39262\np1234\n"))


class TestRecognition(unittest.TestCase):
    def test_the_four_shapes_a_zig_build_leaves_in_ps(self):
        kinds = {
            r.pid: processes.kind_of(r) for r in processes.parse_table(DARWIN_INCIDENT)
        }
        self.assertEqual(ProcessKind.build_step, kinds[39262])
        self.assertEqual(ProcessKind.build_runner, kinds[39267])
        # macOS shows a compiler process as a bare `(zig)` with no argv at all.
        self.assertEqual(ProcessKind.compiler, kinds[39271])
        self.assertEqual(ProcessKind.test_binary, kinds[39293])
        # A shell is not a build process, whoever owns it.
        self.assertIsNone(kinds[7712])

    def test_a_zig_that_is_not_building_is_a_compiler_not_a_build_step(self):
        kinds = {
            r.pid: processes.kind_of(r) for r in processes.parse_table(LINUX_TABLE)
        }
        self.assertEqual(ProcessKind.compiler, kinds[4261])
        self.assertIsNone(kinds[1])

    def test_the_shortlist_is_ours_and_only_ours(self):
        listed = processes.shortlist(table(DARWIN_INCIDENT), uid=OURS)
        self.assertEqual(
            [39262, 39267, 39271, 39293, 39295, 1234], [r.pid for r in listed]
        )
        # pid 501 in the fixture is a `zigd` owned by somebody else: it would be
        # shortlisted on its name alone, and is not, because another user's
        # processes are not ours to have an opinion about — nor, on a shared
        # machine, ours to signal.
        self.assertIsNotNone(processes.kind_of(table(DARWIN_INCIDENT).find(501)))
        self.assertNotIn(501, [r.pid for r in listed])

    def test_the_running_commands_own_lineage_is_never_a_candidate(self):
        """The guard that stops `hookctl build` reaping the build it is about to run."""
        # Standing where the build runner stands: its parent, its children and
        # itself all drop out, which is the whole tree in this fixture.
        scanned = scan_of(DARWIN_INCIDENT, self_pid=39267)
        self.assertEqual([1234], [c.pid for c in scanned.candidates])


class TestAttribution(unittest.TestCase):
    def test_the_pathless_parent_and_relative_children_inherit_from_the_build_runner(
        self,
    ):
        scanned = scan_of(DARWIN_INCIDENT)
        mine = {c.pid: c.attribution for c in scanned.candidates}
        # 39267 is the only process naming the root. Everything joined to it by
        # a parent edge is placed by it.
        for pid in (39262, 39267, 39271, 39293, 39295):
            self.assertEqual(Attribution.this_project, mine[pid], pid)

    def test_another_checkouts_build_is_recognised_and_kept_out_of_scope(self):
        scanned = scan_of(DARWIN_INCIDENT)
        mine = {c.pid: c.attribution for c in scanned.candidates}
        self.assertEqual(Attribution.other_project, mine[1234])
        self.assertNotIn(1234, [c.pid for c in scanned.in_scope(Scope.project)])
        self.assertIn(1234, [c.pid for c in scanned.in_scope(Scope.everything)])

    def test_all_widens_to_every_checkout_and_marks_the_ones_that_are_not_ours(self):
        scanned = scan_of(DARWIN_INCIDENT)
        self.assertEqual(5, len(scanned.in_scope(Scope.project)))
        self.assertEqual(6, len(scanned.in_scope(Scope.everything)))
        with captured() as (out, _):
            ui.process_table(scanned.in_scope(Scope.everything), marking_scope=True)
        printed = out.getvalue()
        self.assertIn("other project", printed, "an out-of-project pid must be marked")
        self.assertEqual(1, printed.count("other project"))

    def test_an_orphan_with_only_a_relative_cache_path_is_placed_by_the_file_existing(
        self,
    ):
        """The harder half of the incident: the anchor is gone too.

        If the build runner dies and only the test binaries survive, nothing in
        their argv is absolute — but `.zig-cache/o/<hash>/test` is content
        addressed, so its presence in THIS root's cache is a strong match.
        """
        orphaned_binaries = ours(
            39293,
            1,
            "11:04:31",
            "99.4",
            "./.zig-cache/o/99bca0/test --cache-dir=./.zig-cache --listen=-",
        )
        # Nothing on disk: unplaceable, and therefore out of project scope.
        blind = scan_of(orphaned_binaries)
        self.assertEqual(Attribution.unknown, blind.candidates[0].attribution)
        self.assertEqual((), blind.in_scope(Scope.project))
        # That object is in our cache: ours.
        found = scan_of(
            orphaned_binaries,
            exists=lambda path: path.endswith("/.zig-cache/o/99bca0/test"),
        )
        self.assertEqual(Attribution.this_project, found.candidates[0].attribution)

    def test_a_working_directory_places_a_process_with_no_paths_at_all(self):
        """The last resort, and the only thing that can place a bare `zig build`."""
        alone = ours(39262, 1, "11:04:33", "99.8", "zig build test")
        self.assertEqual(Attribution.unknown, scan_of(alone).candidates[0].attribution)
        inside = scan_of(
            alone, cwds=(processes.CwdRecord(pid=39262, cwd=ROOT + "/src"),)
        )
        self.assertEqual(Attribution.this_project, inside.candidates[0].attribution)
        outside = scan_of(
            alone, cwds=(processes.CwdRecord(pid=39262, cwd="/somewhere/else"),)
        )
        self.assertEqual(Attribution.other_project, outside.candidates[0].attribution)

    def test_an_installed_toolchain_path_is_not_another_project(self):
        # `/opt/homebrew/.../bin/zig` is a compiler, not somebody's checkout, and
        # calling it `other_project` would be a wrong answer rather than a
        # cautious one.
        scanned = scan_of(LINUX_TABLE, LINUX_ROOT)
        mine = {c.pid: c.attribution for c in scanned.candidates}
        self.assertEqual(Attribution.this_project, mine[4261])


class TestClassification(unittest.TestCase):
    def test_the_incident_is_flagged_orphaned_and_pegged(self):
        scanned = scan_of(DARWIN_INCIDENT)
        by_pid = {c.pid: c for c in scanned.candidates}
        # The runner: reparented to init AND burning a core AND eleven hours old.
        self.assertTrue(by_pid[39262].orphaned)
        self.assertTrue(by_pid[39262].pegged)
        self.assertTrue(by_pid[39262].long_running)
        self.assertEqual("orphaned, pegged, long-running", by_pid[39262].why())
        # The test binaries: not orphaned (their parent survived) but pegged.
        self.assertFalse(by_pid[39293].orphaned)
        self.assertTrue(by_pid[39293].pegged)
        self.assertTrue(by_pid[39293].fatal)

    def test_a_thirty_second_old_compile_is_pegged_but_not_a_runaway(self):
        """The asymmetry that keeps auto-reap from killing honest work.

        A compile at 95% cpu looks exactly like a runaway on the cpu axis alone.
        `doctor` says so, because reporting is cheap; auto-reap does not act,
        because being wrong there costs somebody their build.
        """
        scanned = scan_of(DARWIN_HEALTHY)
        pegged = [c for c in scanned.candidates if c.pegged]
        self.assertEqual([50100], [c.pid for c in pegged])
        self.assertEqual((), scanned.runaway())
        self.assertEqual([50100], [c.pid for c in scanned.fatal()])

    def test_long_running_alone_is_neither_fatal_nor_a_runaway(self):
        scanned = scan_of(DARWIN_SLOW)
        self.assertEqual([50200, 50201], [c.pid for c in scanned.long_running()])
        self.assertEqual((), scanned.fatal())
        self.assertEqual((), scanned.runaway())

    def test_the_thresholds_are_values_not_constants_in_the_code(self):
        # The same table, judged by a machine with a different idea of "long".
        strict = scan_of(
            DARWIN_SLOW, thresholds=Thresholds(long_running=60.0, pegged=80.0)
        )
        self.assertEqual(2, len(strict.long_running()))
        patient = scan_of(
            DARWIN_SLOW, thresholds=Thresholds(long_running=86400.0, pegged=80.0)
        )
        self.assertEqual((), patient.long_running())

    def test_an_orphan_is_a_runaway_however_idle_it_is(self):
        idle_orphan = ours(
            40000, 1, "11:00:00", "0.0", ROOT + "/.zig-cache/o/ab/test --listen=-"
        )
        scanned = scan_of(idle_orphan)
        self.assertEqual([40000], [c.pid for c in scanned.runaway()])

    def test_a_machine_that_will_not_list_processes_is_not_reported_as_clean(self):
        scanned = processes.classify(
            ProcessTable(available=False, note="ps: not found on PATH"),
            ROOT,
            uid=OURS,
            self_pid=1,
        )
        self.assertFalse(scanned.available)
        self.assertEqual((), scanned.candidates)
        self.assertIn("not found on PATH", scanned.note)


class TestKilling(unittest.TestCase):
    def test_sigterm_to_every_pid_first_then_sigkill_to_what_is_left(self):
        signals = support.FakeSignals(
            living={10, 20, 30}, dies_on={20: KillSignal.kill}
        )
        clock = support.FakeClock()
        outcome = processes.kill((10, 20, 30), signals, clock, grace=2.0, poll=0.5)
        # Every TERM is sent before any KILL: a reaper that escalated pid by pid
        # would SIGKILL a process that was about to exit cleanly.
        self.assertEqual(
            [(10, "SIGTERM"), (20, "SIGTERM"), (30, "SIGTERM"), (20, "SIGKILL")],
            signals.order,
        )
        self.assertEqual((10, 20, 30), outcome.killed)
        self.assertEqual((), outcome.survivors)
        self.assertEqual((KillSignal.term, KillSignal.kill), outcome.signals_to(20))

    def test_a_survivor_of_sigkill_is_reported_rather_than_claimed_dead(self):
        immortal = support.FakeSignals(living={10})
        immortal.dies_on[10] = KillSignal.term

        class Unkillable(support.FakeSignals):
            def send(self, pid, which):
                self.sent.append((pid, which))
                return processes.KillAttempt(pid=pid, signal=which, delivered=True)

        signals = Unkillable(living={10})
        outcome = processes.kill(
            (10,), signals, support.FakeClock(), grace=0.2, poll=0.1
        )
        self.assertEqual((10,), outcome.survivors)
        self.assertEqual((), outcome.killed)
        self.assertIn((10, KillSignal.kill), signals.sent)

    def test_a_pid_that_exited_between_the_scan_and_the_signal_is_a_success(self):
        signals = support.FakeSignals(living=set())
        outcome = processes.kill((10,), signals, support.FakeClock())
        self.assertEqual((10,), outcome.killed)
        self.assertFalse(outcome.attempts[0].delivered)
        self.assertEqual("already gone", outcome.attempts[0].note)

    def test_nothing_is_signalled_when_there_is_nothing_to_signal(self):
        signals = support.FakeSignals()
        outcome = processes.kill((), signals, support.FakeClock())
        self.assertEqual([], signals.sent)
        self.assertFalse(outcome.acted)

    def test_ancestors_are_asked_to_stop_before_their_children(self):
        # A build runner that is still alive can start another compile, so it
        # goes first. Within a generation, by pid, so a transcript is stable.
        scanned = scan_of(DARWIN_INCIDENT)
        order = processes.kill_order(scanned.in_scope(Scope.project))
        self.assertEqual((39262, 39267, 39271, 39293, 39295), order)

    def test_the_kill_path_names_pids_and_never_a_pattern(self):
        """A mechanical guard, because this is the one rule with teeth.

        The shipped policy denies `pkill`, and a reaper is the strongest case FOR
        that rule: any pattern broad enough to match "the runaway zig build"
        matches this Python process, whose own argv contains the words it would
        be matching on.

        The guard reads the syntax tree rather than the text, so that prose
        explaining why `pkill` is forbidden does not trip a check on `pkill`
        being CALLED. Docstrings are excluded; every other string literal is
        searched, because a real pattern-killer would be one.
        """
        for module in (processes, reap_verb):
            tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
            # `clean=False`: the cleaned form is not the literal that is in the
            # tree, so the comparison below would never match without it.
            documented = {
                ast.get_docstring(node, clean=False)
                for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef))
            }
            literals = [
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value not in documented
            ]
            for text in literals:
                for forbidden in ("pkill", "killall", "kill -"):
                    self.assertNotIn(
                        forbidden, text, f"{module.__name__} names {forbidden} in code"
                    )
            called = {
                f"{node.value.id}.{node.attr}"
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            }
            for forbidden in (
                "os.system",
                "os.popen",
                "subprocess.run",
                "subprocess.Popen",
                # A pgid read out of `ps` is not this module's to signal: the
                # group could hold processes no scan ever looked at. Group kills
                # belong to `proc`, which owns the child whose group it is.
                "os.killpg",
            ):
                self.assertNotIn(
                    forbidden, called, f"{module.__name__} reaches for {forbidden}"
                )
            keywords = {
                kw.arg
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                for kw in node.keywords
            }
            self.assertNotIn("shell", keywords, f"{module.__name__} passes shell=")
            if module is processes:
                # `os.kill` takes a number and a signal and nothing else. It is
                # the only kill primitive in the package's scanning half, and
                # `reap` reaches it only through this module.
                self.assertIn("os.kill", called)
        # And the only two argvs this module ever issues are reads.
        self.assertEqual(("ps", "lsof"), (processes.PS_DARWIN[0], processes.LSOF[0]))
        self.assertEqual(("ps", "lsof"), (processes.PS_LINUX[0], processes.LSOF[0]))


class TestDoctorCheck(unittest.TestCase):
    def test_fail_on_the_incident_naming_the_pids_and_the_reason(self):
        check = processes.doctor_check(scan_of(DARWIN_INCIDENT))
        self.assertEqual("processes", check.id)
        self.assertEqual(Health.fail, check.status)
        self.assertEqual(EX_FAIL, check.exit_code())
        self.assertIn("pid 39262", check.detail)
        self.assertIn("orphaned", check.detail)
        self.assertIn("11h04m", check.detail)
        # The sentence that explains why no other gate saw this.
        self.assertIn("COMPILED", check.detail)
        self.assertIn("./hookctl reap", check.remedy or "")

    def test_warn_on_long_running(self):
        check = processes.doctor_check(scan_of(DARWIN_SLOW))
        self.assertEqual(Health.warn, check.status)
        # A WARN must not break a pipeline, exactly as on the gate's side.
        self.assertEqual(EX_OK, check.exit_code())
        self.assertIn("longer than 10m00s", check.detail)
        self.assertIn("pid 50200", check.detail)

    def test_pass_when_there_is_nothing_running(self):
        check = processes.doctor_check(scan_of(IDLE))
        self.assertEqual(Health.ok, check.status)
        self.assertIn("no build or test process", check.detail)
        self.assertIsNone(check.remedy)

    def test_a_healthy_live_build_passes_and_says_what_it_saw(self):
        # `doctor` run during an honest compile must not invent a problem, but
        # must not pretend the machine is idle either.
        check = processes.doctor_check(
            scan_of(
                DARWIN_HEALTHY, thresholds=Thresholds(long_running=600.0, pegged=99.9)
            )
        )
        self.assertEqual(Health.ok, check.status)
        self.assertIn("2 build process(es)", check.detail)

    def test_not_applicable_rather_than_absent_when_ps_cannot_be_asked(self):
        check = processes.doctor_check(
            processes.classify(
                ProcessTable(available=False, note="ps: not found on PATH"),
                ROOT,
                uid=OURS,
                self_pid=1,
            )
        )
        # Emitted, and PASS — the same treatment the gate gives the signature
        # check off macOS. Silence would read as "checked, and clean".
        self.assertEqual(Health.ok, check.status)
        self.assertIn("not applicable", check.detail)
        self.assertIn("not found on PATH", check.detail)

    def test_a_long_detail_summarises_rather_than_scrolling(self):
        many = "".join(
            ours(
                40000 + i,
                1,
                "11:00:00",
                "99.0",
                f"{ROOT}/.zig-cache/o/h{i}/test --listen=-",
            )
            for i in range(9)
        )
        check = processes.doctor_check(scan_of(many))
        self.assertEqual(Health.fail, check.status)
        self.assertIn("and 6 more", check.detail)


class TestScanOrchestration(unittest.TestCase):
    """The one impure step: what `scan` asks the machine, and when."""

    def test_it_reads_ps_and_nothing_else_when_everything_is_placeable(self):
        process = support.FakeProcess(
            replies={"ps ": support.reply(stdout=DARWIN_INCIDENT)}
        )
        scanned = processes.scan(
            process, support.DARWIN, Path(ROOT), uid=OURS, self_pid=99999
        )
        self.assertEqual(1, len(process.calls))
        self.assertFalse(
            process.ran("lsof"),
            "no cwd probe is needed when the argv places everything",
        )
        self.assertEqual(6, len(scanned.candidates))

    def test_the_cwd_probe_happens_only_for_what_nothing_else_could_place(self):
        alone = ours(39262, 1, "11:04:33", "99.8", "zig build test")
        process = support.FakeProcess(
            replies={
                "ps ": support.reply(stdout=alone),
                "lsof": support.reply(stdout=f"p39262\nn{ROOT}\n"),
            }
        )
        scanned = processes.scan(
            process, support.DARWIN, Path(ROOT), uid=OURS, self_pid=99999
        )
        self.assertTrue(process.ran("lsof"))
        # And the probe is what placed it.
        self.assertEqual(Attribution.this_project, scanned.candidates[0].attribution)

    def test_a_ps_that_fails_is_unavailable_not_empty(self):
        process = support.FakeProcess(
            replies={"ps ": support.reply(code=69, stderr="ps: not found on PATH\n")}
        )
        scanned = processes.scan(
            process, support.DARWIN, Path(ROOT), uid=OURS, self_pid=1
        )
        self.assertFalse(scanned.available)
        self.assertIn("not found", scanned.note)


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


class TestReapVerb(unittest.TestCase):
    """The verb, driven by fixture `ps` output and fake signals."""

    def ctx(self, args=(), *, listing: str = DARWIN_INCIDENT):
        return support.context(
            "reap",
            args,
            paths=support.Paths.of(Path(ROOT), Path(ROOT) / "sandbox"),
            process=support.FakeProcess(replies={"ps ": support.reply(stdout=listing)}),
        )

    def run_reap(self, args=(), *, listing=DARWIN_INCIDENT, signals=None):
        if signals is None:
            signals = support.FakeSignals(living={39262, 39267, 39271, 39293, 39295})
        with captured() as (out, err):
            code = reap_verb.reap(
                self.ctx(args, listing=listing),
                signals=signals,
                clock=support.FakeClock(),
            )
        return code, out.getvalue(), err.getvalue(), signals

    def test_a_clean_checkout_exits_zero_and_signals_nothing(self):
        code, out, _, signals = self.run_reap(listing=IDLE)
        self.assertEqual(EX_OK, code, "clean must be scriptable as success")
        self.assertIn("nothing to reap", out)
        self.assertEqual([], signals.sent)

    def test_finding_something_exits_nonzero_so_a_script_can_gate_on_it(self):
        code, out, _, _ = self.run_reap()
        self.assertEqual(EX_FAIL, code)
        self.assertIn("5 process(es) found", out)
        # Every candidate is printed, pid first, before anything is signalled.
        for pid in (39262, 39267, 39271, 39293, 39295):
            self.assertIn(str(pid), out)
        self.assertIn("orphaned, pegged", out)

    def test_dry_run_lists_and_signals_nothing_and_still_exits_nonzero(self):
        code, out, _, signals = self.run_reap(["--dry-run"])
        self.assertEqual(EX_FAIL, code)
        self.assertEqual([], signals.sent, "--dry-run must not signal anything")
        self.assertIn("--dry-run: nothing was signalled", out)
        self.assertIn("39262", out)

    def test_the_default_scope_is_this_checkout_and_all_widens_it(self):
        _, narrow, _, _ = self.run_reap(["--dry-run"])
        self.assertNotIn("1234", narrow)
        _, wide, _, _ = self.run_reap(["--dry-run", "--all"])
        self.assertIn("1234", wide)
        self.assertIn("other project", wide)
        self.assertIn("(all checkouts)", wide)

    def test_it_kills_by_pid_ancestors_first_and_reports_each_signal(self):
        code, out, _, signals = self.run_reap()
        self.assertEqual(EX_FAIL, code)
        self.assertEqual(
            [(pid, "SIGTERM") for pid in (39262, 39267, 39271, 39293, 39295)],
            signals.order,
        )
        self.assertIn("SIGTERM  pid 39262", out)
        self.assertIn("none of those pids is alive now", out)

    def test_a_flag_it_does_not_know_is_refused_rather_than_ignored(self):
        """`reap` forwards to no child, so nobody downstream would catch a typo.

        And the consequence of ignoring one is specific: `--dry-runn` would kill
        the processes the operator asked to merely look at.
        """
        for typo in (["--dry-runn"], ["--all", "--force"], ["39262"]):
            with captured() as (out, err):
                code = reap_verb.reap(
                    self.ctx(typo),
                    signals=support.FakeSignals(),
                    clock=support.FakeClock(),
                )
            self.assertEqual(EX_USAGE, code, typo)
            self.assertIn(
                f"does not understand {typo[-1] if len(typo) > 1 else typo[0]}",
                err.getvalue(),
            )
            self.assertIn("--dry-run and --all", err.getvalue())
            self.assertEqual(
                "", out.getvalue(), "nothing may be listed, let alone killed"
            )
        # And the two it does know are accepted together.
        self.assertEqual((), reap_verb.unknown_flags(("--dry-run", "--all")))

    def test_a_machine_that_cannot_list_processes_refuses_rather_than_reporting_clean(
        self,
    ):
        ctx = support.context(
            "reap",
            paths=support.Paths.of(Path(ROOT), Path(ROOT) / "sandbox"),
            process=support.FakeProcess(
                replies={"ps ": support.reply(code=69, stderr="ps: not found\n")}
            ),
        )
        with captured() as (out, err):
            code = reap_verb.reap(
                ctx, signals=support.FakeSignals(), clock=support.FakeClock()
            )
        self.assertEqual(EX_UNAVAILABLE, code)
        self.assertIn("cannot list processes", err.getvalue())
        self.assertIn("nothing can be concluded", err.getvalue())
        self.assertEqual("", out.getvalue())


class TestAutoReap(unittest.TestCase):
    def auto(self, verb: str, listing: str, living=None):
        living = living if living is not None else {39262, 39267, 39271, 39293, 39295}
        signals = support.FakeSignals(living=set(living))
        ctx = support.context(
            verb,
            paths=support.Paths.of(Path(ROOT), Path(ROOT) / "sandbox"),
            process=support.FakeProcess(replies={"ps ": support.reply(stdout=listing)}),
        )
        with captured() as (out, err):
            reap_verb.auto_reap(ctx, signals=signals, clock=support.FakeClock())
        return out.getvalue(), err.getvalue(), signals

    def test_it_kills_a_previous_runs_orphan_before_a_build_starts(self):
        out, err, signals = self.auto("test", DARWIN_INCIDENT)
        # Only the runaways: the orphan, and what is both pegged and long-running.
        self.assertEqual({39262, 39293, 39295}, {pid for pid, _ in signals.sent})
        self.assertIn("a previous run left 3 process(es)", err)
        self.assertIn("reaped", err)
        # stdout is somebody's answer and stays clean.
        self.assertEqual("", out)

    def test_it_says_nothing_at_all_when_there_is_nothing_to_kill(self):
        out, err, signals = self.auto("test", DARWIN_HEALTHY, living={50100, 50101})
        self.assertEqual([], signals.sent)
        self.assertEqual("", out)
        self.assertEqual("", err, "a line printed on every run is a line nobody reads")

    def test_a_verb_that_does_not_declare_it_never_looks(self):
        out, err, signals = self.auto("doctor", DARWIN_INCIDENT)
        self.assertEqual([], signals.sent)
        self.assertEqual("", err)

    def test_doctor_deliberately_does_not_auto_reap(self):
        """A diagnosis that tidied up first could never show you the problem."""
        from ..registry import find

        self.assertFalse(find("doctor").auto_reap)
        self.assertTrue(find("doctor").runner_checks)


class TestHumanNumbers(unittest.TestCase):
    def test_durations_read_at_the_granularity_that_makes_the_size_obvious(self):
        self.assertEqual("0s", ui.human_elapsed(0.4))
        self.assertEqual("59s", ui.human_elapsed(59.9))
        self.assertEqual("1m00s", ui.human_elapsed(60))
        self.assertEqual("10m00s", ui.human_elapsed(600))
        self.assertEqual("11h04m", ui.human_elapsed(11 * 3600 + 4 * 60 + 33))
        self.assertEqual("3d02h", ui.human_elapsed(3 * 86400 + 2 * 3600))

    def test_memory_reads_in_the_unit_it_is_in(self):
        self.assertEqual("512.0 KiB", ui.human_bytes(512))
        self.assertEqual("39.9 MiB", ui.human_bytes(40832))
        self.assertEqual("2.0 GiB", ui.human_bytes(2 * 1024 * 1024))


if __name__ == "__main__":
    unittest.main()

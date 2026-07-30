"""The one place this package spawns a process.

Every external command — `zig`, `zig build`, the gate, the installer,
`python3`, `codesign` — goes through `Runner.run`. That is worth a module of its
own for four reasons, each of which was previously a thing every call site had
to remember:

  * **cwd.** Children run at the repository root. `zig build` has to run where
    `build.zig` is, and the binaries are addressed by repo-relative path so
    nothing prints a machine-specific absolute path that was not the operator's
    own argument.
  * **timeouts, and what a timeout has to kill.** See below. This is the reason
    this module is worth reading.
  * **verbose echo.** `HOOKCTL_VERBOSE=1` prints each argv before it runs. When
    a doc check disagrees with a transcript, the first question is always "what
    command produced that", and it should not require reading this source.
  * **error formatting.** A missing binary, a timeout and a non-zero exit are
    three different facts. They all come back as a `RunResult` with a code and
    a message rather than as an exception one caller handles and another does
    not.

`Runner` satisfies `spec.Process`, which is what the verbs actually depend on,
so a test can pass a recorder and assert on the argv without spawning anything.

## Why every child gets its own session, and why a timeout kills a GROUP

`zig build test` is not one process. It is a `zig` front end, which spawns a
compiled build runner, which spawns compiler processes and then the compiled
test binaries — and it is the grandchildren that do the work and burn the CPU.
Killing the direct child leaves them running, reparented to init, executing
whatever was compiled at that instant. That is not a hypothetical: it is the
incident this module was rewritten for. A `zig build test` whose invoker died
was left at PPID 1 with two of its test binaries still spinning an infinite
loop from a half-finished refactor, for eleven hours, at 100% CPU each. Every
gate stayed green throughout, because the binaries that were spinning had been
built from source that no longer existed.

So:

  * children are spawned with `start_new_session=True`, which makes each child
    the leader of its own process group. That is what makes a group-wide kill
    *possible*; without it there is no handle on the grandchildren.
  * a timeout sends SIGTERM to the whole group, waits, then SIGKILL to the whole
    group, and then checks whether anything survived and says so.
  * the direct child is always reaped, on every path out.
  * **Ctrl-C is handled here too.** A child in its own session is no longer in
    the terminal's foreground process group, so the SIGINT from a Ctrl-C reaches
    this runner and *not* the build. Without the `KeyboardInterrupt` handler
    below, `start_new_session=True` would itself have become a new way to
    manufacture the exact orphan it exists to prevent.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import ui
from .spec import ENCODING, EX_TIMEOUT, EX_UNAVAILABLE, FROZEN, RunMode, RunResult

#: Ceiling for a probe: asking a binary its version, or asking `codesign` what
#: it thinks of one. Long enough that a cold page-in is fine, short enough that
#: a wedged binary does not wedge the runner.
PROBE_TIMEOUT = 30.0

#: How long a process group is given to honour SIGTERM before SIGKILL, and how
#: often it is polled. A build runner that is being asked to stop has some
#: bookkeeping to do; a runaway has none, and two seconds is not a wait anyone
#: notices when the alternative was eleven hours.
GROUP_GRACE = 2.0
GROUP_POLL = 0.05

#: The environment prefix the gate reads. The checks that must give the same
#: answer on every machine scrub it, because these overrides are exactly the
#: thing that would make them differ.
GATE_ENV_PREFIX = "CLAUDE_HOOK_"


# ---------------------------------------------------------------------------
# killing a process group
# ---------------------------------------------------------------------------


def group_of(child: subprocess.Popen) -> int | None:
    """The child's process group, or None if it must not be signalled.

    Two refusals, both of which would be catastrophic rather than merely wrong:
    a pgid of 0 or 1 means "every process I am allowed to signal", and a pgid
    equal to this runner's own group means the runner would kill itself and its
    caller's shell. `start_new_session=True` makes both impossible; they are
    checked anyway, because the cost of being wrong here is somebody's session.
    """
    try:
        pgid = os.getpgid(child.pid)
    except (ProcessLookupError, PermissionError):
        return None
    if pgid <= 1 or pgid == os.getpgid(0):
        return None
    return pgid


def _signal_group(pgid: int, sig: int) -> bool:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def group_alive(pgid: int) -> bool:
    """Whether anything is left in the group.

    Only meaningful once the direct child has been REAPED: an unreaped zombie is
    still a member of its group, so asking before reaping always says yes.
    """
    return _signal_group(pgid, 0)


def _reap(child: subprocess.Popen, seconds: float) -> None:
    with contextlib.suppress(subprocess.TimeoutExpired):
        child.wait(timeout=seconds)


def terminate_group(
    child: subprocess.Popen,
    *,
    grace: float = GROUP_GRACE,
    poll: float = GROUP_POLL,
) -> tuple[int, ...]:
    """SIGTERM the child's whole group, then SIGKILL it. Returns survivors.

    The return value is the point: "I killed it" is a claim, and a claim about
    a runaway process is exactly the kind that should be checked before it is
    printed. An empty tuple means the group is genuinely empty afterwards.
    """
    pgid = group_of(child)
    if pgid is None:
        _reap(child, grace)
        return ()

    _signal_group(pgid, signal.SIGTERM)
    # Waiting on the direct child both gives the group its grace period and
    # reaps the child, which is what makes the `group_alive` below honest.
    _reap(child, grace)
    if group_alive(pgid):
        _signal_group(pgid, signal.SIGKILL)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and group_alive(pgid):
            time.sleep(poll)
    _reap(child, grace)
    return (pgid,) if group_alive(pgid) else ()


def _drain(child: subprocess.Popen, seconds: float) -> None:
    """Close the child's pipes without letting a survivor hold this runner open.

    `communicate()` reads to EOF, and EOF on the pipe needs every process
    holding the write end to be gone — including a grandchild that outlived a
    SIGKILL. So the read is bounded and the pipes are closed by hand if it does
    not finish.
    """
    try:
        child.communicate(timeout=seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    for pipe in (child.stdout, child.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


@dataclass(**FROZEN)
class Runner:
    cwd: Path
    verbose: bool = False

    def run(
        self,
        argv: Sequence[str],
        *,
        mode: RunMode = RunMode.inherit,
        timeout: float | None = None,
        scrub_env: bool = False,
    ) -> RunResult:
        args = tuple(str(a) for a in argv)
        if self.verbose:
            ui.note("+ " + " ".join(args))
        env = _scrubbed_env() if scrub_env else None
        capture = mode is not RunMode.inherit
        started = time.monotonic()

        try:
            child = subprocess.Popen(  # noqa: S603  (argv is a tuple, never a shell string)
                args,
                cwd=self.cwd,
                env=env,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                text=True if capture else None,
                # UTF-8 whatever the locale says, and `errors="replace"` on
                # child output only: a mangled byte in a diagnostic must not
                # lose the diagnostic.
                encoding=ENCODING if capture else None,
                errors="replace" if capture else None,
                # The whole reason a timeout here can be honoured. See the
                # module docstring.
                start_new_session=True,
            )
        except FileNotFoundError:
            # The honest report for "that program is not on this machine": the
            # command that was attempted, so the reader can see the typo or the
            # missing dependency for themselves.
            return _failed(args, started, f"{args[0]}: not found on PATH")
        except PermissionError as err:
            return _failed(args, started, f"{args[0]}: not executable ({err.strerror})")

        try:
            out, err = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            survivors = terminate_group(child)
            _drain(child, GROUP_GRACE)
            return _timed_out(args, started, timeout, survivors)
        except KeyboardInterrupt:
            # The child is in its own session, so the terminal's SIGINT did not
            # reach it. Leaving it running is how an orphan is made.
            terminate_group(child)
            _drain(child, GROUP_GRACE)
            raise

        result = RunResult(
            argv=args,
            code=child.returncode,
            stdout=out or "",
            stderr=err or "",
            duration=time.monotonic() - started,
        )
        # `quiet` is "capture, but do not hide a failure": a step whose success
        # is one tick in a report still has to be debuggable when it fails.
        if mode is RunMode.quiet and not result.ok:
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            sys.stdout.flush()
        return result


def _failed(argv: tuple[str, ...], started: float, message: str) -> RunResult:
    return RunResult(
        argv=argv,
        code=EX_UNAVAILABLE,
        stderr=message + "\n",
        duration=time.monotonic() - started,
    )


def timeout_message(
    argv: tuple[str, ...], elapsed: float, budget: float | None, survivors: int
) -> str:
    """What a timed-out step reports.

    It names the command, the budget it blew, how long it actually ran, and
    whether the process group is empty now — because "killed it" with nothing
    checking is the claim that let the original incident run for eleven hours.
    """
    limit = f"{budget:.0f}s" if budget is not None else "its budget"
    ending = (
        f"{survivors} process group(s) SURVIVED SIGKILL — run `./hookctl reap`"
        if survivors
        else "killed its process group; no survivors"
    )
    return f"{' '.join(argv)}: no answer after {limit} (ran {elapsed:.1f}s), {ending}"


def _timed_out(
    argv: tuple[str, ...],
    started: float,
    budget: float | None,
    survivors: tuple[int, ...],
) -> RunResult:
    elapsed = time.monotonic() - started
    return RunResult(
        argv=argv,
        code=EX_TIMEOUT,
        stderr=timeout_message(argv, elapsed, budget, len(survivors)) + "\n",
        duration=elapsed,
        timed_out=True,
    )


def _scrubbed_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(GATE_ENV_PREFIX)}
    env.pop("CLAUDE_PROJECT_DIR", None)
    return env


def zig_build(
    process,
    *args: str,
    mode: RunMode = RunMode.inherit,
    timeout: float | None = None,
) -> RunResult:
    """`zig build <args>`. The only shape in which this project is compiled.

    `timeout` is not optional in practice — every caller passes `ctx.timeout` —
    but it defaults to None here rather than to a number, so that a caller which
    forgot is visible as `None` in a test's recorded call rather than silently
    inheriting a plausible-looking default from this file.
    """
    return process.run(("zig", "build", *args), mode=mode, timeout=timeout)


def zig_version(process) -> str | None:
    """What `zig version` says, or None if it did not answer.

    Reported rather than enforced: the build itself is the authority on whether
    a toolchain is new enough, and it says so far better than a version
    comparison here would.
    """
    result = process.run(
        ("zig", "version"), mode=RunMode.capture, timeout=PROBE_TIMEOUT
    )
    if not result.ok:
        return None
    first = result.stdout.strip().splitlines()
    return first[0].strip() if first else None

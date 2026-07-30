"""`reap`, the auto-reap that runs before a build, and `doctor`'s ninth check.

Three entry points onto one scan, which is the point of the arrangement: the
verb an operator types, the thing that happens automatically before a compile,
and the line `doctor` prints all ask the same question of the same code. A
second implementation of "is this a runaway" would be a second thing to be
wrong about, and the whole reason this exists is that nothing was watching.

**They act on deliberately different bars, and that asymmetry is the design.**

  * `reap`, typed, kills every build process of this checkout it can find. You
    said so; a live build is included, because "stop what this checkout is
    doing" is what the word means.
  * `auto_reap`, which nobody asked for, kills only what is unambiguously a
    runaway: an orphan, or something both pegged and long-running. A pegged
    process that started ten seconds ago is a compile doing its job, and a
    silent reaper that killed a colleague's honest build would be a worse bug
    than the one being fixed here.
  * `processes_check` kills nothing at all and reports everything, because a
    diagnosis that quietly cleaned up first would be a diagnosis that can never
    show you the problem.

Nothing here kills by pattern. See `processes.kill`.
"""

from __future__ import annotations

from .. import argv as argv_mod
from .. import processes, ui
from ..spec import (
    EX_FAIL,
    EX_OK,
    EX_UNAVAILABLE,
    EX_USAGE,
    Candidate,
    Clock,
    Context,
    DoctorCheck,
    ProcessScan,
    ReapOutcome,
    Scope,
    Signals,
)

#: List, do not kill.
DRY_RUN = "--dry-run"
#: Widen from this checkout to every zig build process this user owns.
ALL = "--all"

#: Everything `reap` accepts, and nothing else. This verb forwards to no child,
#: so there is nobody downstream to reject a flag it does not know — and the
#: consequence of accepting one silently is specific and bad: `--dry-runn` would
#: kill the processes the operator asked to merely look at.
KNOWN_FLAGS = (DRY_RUN, ALL)


def unknown_flags(args: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(a for a in args if a not in KNOWN_FLAGS)


def scope_of(args: tuple[str, ...]) -> Scope:
    return Scope.everything if argv_mod.has_flag(args, ALL) else Scope.project


def scan(ctx: Context) -> ProcessScan:
    """The one scan. Everything in this module goes through here."""
    return processes.scan(ctx.process, ctx.platform, ctx.paths.project_root)


def processes_check(ctx: Context) -> DoctorCheck:
    """`doctor`'s check about this checkout rather than about an install."""
    return processes.doctor_check(scan(ctx))


def kill_found(
    found: tuple[Candidate, ...],
    *,
    signals: Signals | None = None,
    clock: Clock | None = None,
) -> ReapOutcome:
    """Kill what a scan found, ancestors first.

    The two collaborators are arguments with real-machine defaults rather than
    values constructed inside, so the kill sequence can be driven by a test
    without a test ever needing something real to kill. That is not a nicety
    here: manufacturing long-lived processes in a suite is how the incident this
    file exists for got started.
    """
    return processes.kill(
        processes.kill_order(found),
        signals if signals is not None else processes.OsSignals(),
        clock if clock is not None else processes.WallClock(),
    )


def auto_reap(
    ctx: Context, *, signals: Signals | None = None, clock: Clock | None = None
) -> None:
    """Clear a previous run's runaway before this run starts. Silent if clean.

    Announced on stderr rather than stdout, and only when it actually killed
    something: a line printed on every invocation is a line nobody reads, and
    `check`'s stdout is somebody's answer.
    """
    if not ctx.verb.auto_reap:
        return
    scanned = scan(ctx)
    if not scanned.available:
        return
    runaway = scanned.runaway()
    if not runaway:
        return
    ui.note(f"a previous run left {len(runaway)} process(es) of this checkout running:")
    for candidate in runaway:
        ui.note(f"  {processes.describe(candidate)} {candidate.record.command}")
    outcome = kill_found(runaway, signals=signals, clock=clock)
    if outcome.killed:
        ui.note("reaped " + ui.pids(outcome.killed) + " before starting")
    if outcome.survivors:
        ui.note(
            "could NOT kill "
            + ui.pids(outcome.survivors)
            + "; this run will compete with them"
        )


def reap(
    ctx: Context, *, signals: Signals | None = None, clock: Clock | None = None
) -> int:
    """`reap [--dry-run] [--all]`.

    Exits nonzero when anything was found, so `./hookctl reap --dry-run` is a
    usable condition in a script: zero means this checkout is not running
    anything, which is the only state in which a green gate means what it says.
    """
    stray = unknown_flags(ctx.args)
    if stray:
        ui.rejects_flag(ctx.verb.name, stray[0], KNOWN_FLAGS)
        ui.note(
            "  refusing rather than ignoring: a mistyped --dry-run is a kill you did not ask for"
        )
        return EX_USAGE
    scope = scope_of(ctx.args)
    scanned = scan(ctx)
    if not scanned.available:
        # Not "clean". A machine that will not list its processes is a machine
        # this cannot answer for, and saying so is the whole difference between
        # a diagnostic and a rubber stamp.
        ui.note(f"cannot list processes on this machine: {scanned.note}")
        ui.note(
            "  nothing was killed, and nothing can be concluded about what is running."
        )
        return EX_UNAVAILABLE

    found = scanned.in_scope(scope)
    if not found:
        where = "this checkout" if scope is Scope.project else "any checkout of yours"
        ui.out(f"nothing to reap: no zig build or test process of {where} is running.")
        return EX_OK

    ui.section(
        f"{len(found)} process(es) found"
        + (" (all checkouts)" if scope is Scope.everything else "")
    )
    ui.process_table(found, marking_scope=scope is Scope.everything)

    if argv_mod.has_flag(ctx.args, DRY_RUN):
        ui.out()
        ui.out(
            f"{DRY_RUN}: nothing was signalled. Without it, those {len(found)} pid(s) would be sent "
            "SIGTERM, given a moment, then SIGKILL."
        )
        return EX_FAIL

    ui.out()
    ui.section("kill (SIGTERM, then SIGKILL to whatever is left)")
    outcome = kill_found(found, signals=signals, clock=clock)
    ui.reaped(outcome)
    ui.out()
    if outcome.survivors:
        ui.out(
            f"killed {len(outcome.killed)}, and {len(outcome.survivors)} SURVIVED — see above."
        )
    else:
        ui.out(
            f"killed {len(outcome.killed)} process(es); none of those pids is alive now."
        )
    return EX_FAIL

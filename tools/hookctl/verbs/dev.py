"""The contributor's verbs: `build`, `test`, `parity`, `cross`, `fmt`,
`selfcheck`, `verify`.

Most of them are one toolchain invocation each, and exist so that nobody has to
remember which step is called what. `verify` is the one with a policy in it: it
is the pre-commit gate, and it is deliberately wider than `zig build check` —
`check` folds the shlex parity oracle in only when `zig build` itself finds a
`python3`, and since this runner IS Python, a skip there would be a lie. So
parity is run as its own step, and two more kinds of check that cannot live in
the Zig test suite are run after it:

  * this runner's own unit tests (`tools/hookctl/tests`), which are about the
    Python that decides which binary answers and what the README must say;
  * the documentation checks, which read README.md and compare it against the
    verb table and the gate's live output.

Both are folded in here rather than left to a separate command, because a gate
somebody has to remember to run twice is a gate that runs once.
"""

from __future__ import annotations

import re
import sys

from .. import discovery, docs, ui
from ..proc import zig_build
from ..spec import AuditCheck, AuditReport, Context, RunMode, RunResult

#: `Ran 27 tests in 0.031s`, which unittest writes to stderr.
RAN_TESTS = re.compile(r"^Ran (\d+) tests?", re.MULTILINE)


def timed_out(step: str, result: RunResult) -> int:
    """Report a step the runner gave up on, and its exit code.

    Kept separate from "the step failed" everywhere it is used, because the two
    mean opposite things: a failing step told you something, and a killed step
    told you nothing except that it was still going. `proc` has already killed
    the process group by the time this is called; this is the sentence that names
    which step it was and how long it ran.
    """
    ui.note(f"`{step}` was still running after {result.duration:.0f}s and was killed.")
    ui.note("  " + result.first_error_line())
    ui.note(
        "  raise the budget with `--timeout SECONDS` if this machine is honestly that slow."
    )
    return result.code


def unittest_argv(ctx: Context, *, quiet: bool) -> tuple[str, ...]:
    """`python3 -m unittest` over this package's tests.

    Discovery is rooted at `tools/` so the tests import as `hookctl.tests.*` —
    the same package path the runner itself uses, which means a test importing
    `hookctl.spec` gets the tree it is testing and not an installed copy.
    """
    tools = ctx.paths.project_root / "tools"
    argv = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "--start-directory",
        str(tools / "hookctl" / "tests"),
        "--top-level-directory",
        str(tools),
    ]
    if quiet:
        argv.append("--quiet")
    return tuple(argv)


def python_tests(ctx: Context) -> AuditCheck:
    """The runner's own tests as one line, with the count."""
    result = ctx.process.run(
        unittest_argv(ctx, quiet=True), mode=RunMode.quiet, timeout=ctx.timeout
    )
    # unittest reports on stderr; the count is the useful half of it.
    found = RAN_TESTS.search(result.stderr) or RAN_TESTS.search(result.stdout)
    count = found.group(1) if found else "?"
    return AuditCheck(
        "hookctl's own unit tests",
        result.ok,
        f"{count} tests" if result.ok else f"{count} tests, exit {result.code}",
    )


def _step(ctx: Context, name: str, *args: str) -> int:
    """One bounded `zig build` step, with a timeout reported as a timeout.

    Every zig invocation in this module goes through here, which is what makes
    "no unbounded child" a property of the file rather than of each function's
    author remembering.
    """
    result = zig_build(ctx.process, *args, timeout=ctx.timeout)
    if result.timed_out:
        return timed_out(name, result)
    return result.code


def build(ctx: Context) -> int:
    """Both binaries into zig-out/bin, in the same mode `setup` installs, so
    the two are never mysteriously different files."""
    return _step(ctx, "zig build --release", "--release", *ctx.args)


def test(ctx: Context) -> int:
    return _step(ctx, "zig build test", "test", *ctx.args)


def parity(ctx: Context) -> int:
    return _step(ctx, "zig build parity", "parity", *ctx.args)


def cross(ctx: Context) -> int:
    """Compile everything for Linux without running it.

    This code is POSIX-only and is mostly written on macOS while mostly running
    on Linux. Compiling for Linux is the half of that gap a laptop can close;
    running the suite there is CI's job.

    It is also the one step whose honest duration is tens of minutes — it
    compiles the binaries and every test module for three targets — so it
    carries its own, much larger, budget. See `spec.CROSS_TIMEOUT`.
    """
    return _step(ctx, "zig build cross", "cross", *ctx.args)


def fmt(ctx: Context) -> int:
    result = ctx.process.run(
        ("zig", "fmt", *ctx.args, "src", "build.zig"),
        mode=RunMode.inherit,
        timeout=ctx.timeout,
    )
    return timed_out("zig fmt", result) if result.timed_out else result.code


def selfcheck(ctx: Context) -> int:
    """This runner's own unit tests, verbosely, for working on the runner."""
    result = ctx.process.run(
        unittest_argv(ctx, quiet=False), mode=RunMode.inherit, timeout=ctx.timeout
    )
    return (
        timed_out("hookctl's own unit tests", result)
        if result.timed_out
        else result.code
    )


def verify(ctx: Context) -> int:
    """The pre-commit gate: everything `zig build check` runs, plus the
    runner's own tests and the documentation checks that live here because they
    are about this runner."""
    ui.section("zig build check (unit tests, both binaries)")
    result = zig_build(ctx.process, "check", mode=RunMode.inherit, timeout=ctx.timeout)
    if result.timed_out:
        return timed_out("zig build check", result)
    if not result.ok:
        return result.code
    ui.out("   ok   every test passed and both binaries compile")

    # `check` folds parity in only when `zig build` itself finds a python3 on
    # PATH, and is green without it otherwise. That concession is right for
    # `zig build` and wrong here: this runner IS Python, so an interpreter
    # demonstrably exists, and a gate that quietly stopped comparing against
    # the reference implementation would be worse than one that failed.
    ui.out()
    ui.section("shlex parity oracle")
    result = zig_build(ctx.process, "parity", mode=RunMode.inherit, timeout=ctx.timeout)
    if result.timed_out:
        return timed_out("zig build parity", result)
    if not result.ok:
        return result.code
    ui.out("   ok   the checked-in oracle is what Python's shlex says today")

    ui.out()
    ui.section("hookctl's own unit tests")
    report = AuditReport().plus(python_tests(ctx))
    ui.report(report.checks)

    ui.out()
    ui.section("documentation checks")
    # Silently resolved: which binary answered is not interesting here (the
    # doc checks compare shapes, not versions), and a missing one is already
    # reported as the failing check it causes.
    gate = discovery.choose_gate(ctx.paths).gate
    doc_checks = docs.checks(
        ctx.process,
        ctx.paths.readme,
        ctx.verbs,
        ctx.groups,
        ctx.gate_argv(gate) if gate is not None else None,
    )
    ui.report(doc_checks)
    return report.extend(doc_checks).exit_code()

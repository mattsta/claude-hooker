"""The verbs that are a thin front for a gate subcommand.

`status`, `doctor`, `check`, `explain`, `stats`, `classes`, `selftest`,
`diff-defaults` and `version` are all one handler. What distinguishes them is
data in the registry — the arguments that go before the operator's own — not
code, because a per-verb wrapper is a place for a per-verb inconsistency to
live. There is exactly one policy about which binary answers, one about
`--claude-dir`, and one about rebuilding first, and they are all here.

`resolve_gate` and `refresh_build` are also used by `verify` and `audit`, which
ask the same gate the same way. That is deliberate: "which binary answered" must
have one answer per run, whoever is asking.

The one verb that gets more than the gate's answer is `doctor`, and it gets it
from a `Verb` field (`runner_checks`) rather than from its own handler — same
reason `gate_args` and `refresh_build` are fields. What it adds is the one check
the gate cannot make: the gate diagnoses an INSTALL, and "is a build process
from this CHECKOUT still spinning" is a question about a working tree, which an
installed gate in a `~/.claude` with no clone beside it has no way to answer.
"""

from __future__ import annotations

import json

from .. import argv as argv_mod
from .. import discovery, ui
from ..proc import zig_build
from ..spec import (
    EX_UNAVAILABLE,
    GATE_NAME,
    Context,
    DoctorCheck,
    GateBinary,
    Health,
    RunMode,
)
from .reap import processes_check

#: The gate's own machine-readable form. When it is asked for, the runner's extra
#: check is merged INTO that document rather than printed after it: a script
#: parsing `doctor --json` must get one valid object, and a check that is only
#: visible to human readers is a check scripts cannot gate on.
JSON_FLAG = "--json"


def refresh_build(ctx: Context) -> None:
    """Bring zig-out/bin up to date before a verb whose answer depends on it.

    `doctor`, `status` and `diff-defaults` all compare the installed gate
    against *this working tree*. A stale zig-out would make them compare
    against whatever was last built, which is precisely the confusion they
    exist to remove. A tree that does not compile is not fatal — an install can
    still be diagnosed — but it is said out loud, because the comparison is
    then against older source.
    """
    if not ctx.toolchain.present:
        return
    # `--release`, like every other build here: zig-out/bin must hold the same
    # bytes `setup` installs, or "the built gate differs from the installed one"
    # would fire on every run and mean nothing.
    if not zig_build(
        ctx.process, "--release", mode=RunMode.quiet, timeout=ctx.timeout
    ).ok:
        ui.stale_build(ctx.verb.name)


def resolve_gate(ctx: Context, *, announce: bool = True) -> GateBinary | None:
    """The gate binary to answer with, or None with the reason printed."""
    choice = discovery.choose_gate(ctx.paths)
    if announce:
        ui.announce_gate(choice, ctx.paths)
    if choice.gate is None:
        ui.no_gate(ctx.verb.name, GATE_NAME, toolchain_present=ctx.toolchain.present)
        return None
    return choice.gate


def merge_json(document: str, check: DoctorCheck) -> str | None:
    """The gate's `doctor --json`, with the runner's check appended.

    Pure, and returns None rather than raising if the document is not the shape
    it expects — a gate old enough not to know this format must degrade to
    "printed unchanged", not to a traceback in the middle of a diagnosis.

    The tallies are recomputed rather than incremented, so that `pass + warn +
    fail == len(checks)` cannot drift, and `ok` keeps the gate's meaning: a WARN
    is not a failure.
    """
    try:
        parsed = json.loads(document)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("checks"), list):
        return None
    rows = list(parsed["checks"])
    rows.append(
        {
            "id": check.id,
            "title": check.title,
            "status": check.status.value,
            "detail": check.detail,
            "remedy": check.remedy,
        }
    )
    counts = {level.value: 0 for level in Health}
    for row in rows:
        status = row.get("status") if isinstance(row, dict) else None
        if isinstance(status, str) and status in counts:
            counts[status] += 1
    merged = dict(parsed)
    merged["checks"] = rows
    merged["pass"] = counts[Health.ok.value]
    merged["warn"] = counts[Health.warn.value]
    merged["fail"] = counts[Health.fail.value]
    merged["ok"] = counts[Health.fail.value] == 0
    return json.dumps(merged)


def _with_runner_checks(ctx: Context, argv: tuple[str, ...]) -> int:
    """The gate's answer, plus the one check only the runner can make.

    The check is computed BEFORE the gate runs, so that what it reports is the
    process table as it was when the operator asked — `refresh_build` has already
    happened by now, and a scan taken afterwards would be reporting on a machine
    this command had just changed.
    """
    check = processes_check(ctx)
    if argv_mod.has_flag(ctx.args, JSON_FLAG):
        run = ctx.process.run(argv, mode=RunMode.capture, timeout=ctx.timeout)
        merged = merge_json(run.stdout, check)
        if merged is None:
            ui.out(run.stdout.rstrip("\n"))
            ui.note("the gate's --json output was not the expected shape, so the")
            ui.note(
                f"  `{check.id}` check is reported here instead: {check.status.word()} — {check.detail}"
            )
        else:
            ui.out(merged)
        return max(run.code, check.exit_code())

    code = ctx.process.run(argv, mode=RunMode.inherit, timeout=ctx.timeout).code
    ui.out()
    ui.section("this checkout's own build processes (not part of the install)")
    ui.doctor_check(check)
    return max(code, check.exit_code())


def run_gate(ctx: Context) -> int:
    """Hand the verb over to the gate, with `--claude-dir` made absolute."""
    if ctx.verb.refresh_build:
        refresh_build(ctx)
    gate = resolve_gate(ctx)
    if gate is None:
        return EX_UNAVAILABLE
    argv = (ctx.gate_argv(gate), *ctx.verb.gate_args, *argv_mod.absolutize(ctx.args))
    if ctx.verb.runner_checks:
        return _with_runner_checks(ctx, argv)
    return ctx.process.run(argv, mode=RunMode.inherit, timeout=ctx.timeout).code

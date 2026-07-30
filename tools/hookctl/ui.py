"""Everything this runner prints, and nothing else.

Two streams, used for two different things, on purpose:

  * **stdout** is the answer — the report, the transcript, the counts. It is
    what a `--json` verb's child writes and what a reader pastes into an issue.
  * **stderr** is how the answer was arrived at: which binary was chosen, why a
    verb cannot run, what to install. Every one of those lines is prefixed
    `hookctl:` so it is obvious which of the two programs in a piped run said
    it.

The `help` text is rendered from the verb table rather than written out, which
is the whole reason the README can quote it byte for byte and have that
comparison mean something.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from .spec import (
    MIN_TIMEOUT,
    MIN_ZIG,
    Attribution,
    AuditCheck,
    Candidate,
    DoctorCheck,
    GateChoice,
    GateNotice,
    Health,
    Paths,
    ReapOutcome,
    Verb,
    VerbGroup,
)

#: Where a verb's summary starts in `help`. Wide enough for the longest verb
#: name with a space after it.
VERB_COLUMN = 15

#: Width of the check-id column in a diagnosis. The same number the Zig side
#: uses (`cli.CHECK_ID_COLUMN`), because the runner's own check is printed under
#: the gate's and a different width would look like a different report.
CHECK_ID_COLUMN = 12


def out(msg: str = "") -> None:
    print(msg, flush=True)


def note(msg: str) -> None:
    """A line about how the work is being done, kept off stdout so that
    `--json` output stays machine-readable."""
    print(f"hookctl: {msg}", file=sys.stderr, flush=True)


def section(title: str) -> None:
    out(f"== {title} ==")


def report(checks: Iterable[AuditCheck]) -> None:
    for check in checks:
        mark = "ok  " if check.ok else "FAIL"
        out(f"   {mark} {check.name}" + (f" — {check.detail}" if check.detail else ""))


# ---------------------------------------------------------------------------
# numbers a person reads
# ---------------------------------------------------------------------------


def human_elapsed(seconds: float) -> str:
    """A duration, at the granularity that makes the size obvious.

    `11h02m` rather than `39754s`: the fact that mattered in the incident this
    exists for was "eleven HOURS", and a raw second count is a number a reader
    has to do arithmetic on before being alarmed by it.
    """
    total = int(seconds)
    if total >= 86400:
        return f"{total // 86400}d{(total % 86400) // 3600:02d}h"
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60:02d}m"
    if total >= 60:
        return f"{total // 60}m{total % 60:02d}s"
    return f"{total}s"


def human_bytes(kib: int) -> str:
    value = float(kib)
    for unit in ("KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


# ---------------------------------------------------------------------------
# a diagnosis, and the processes behind one
# ---------------------------------------------------------------------------


def doctor_check(check: DoctorCheck, width: int = 96) -> None:
    """One `DoctorCheck`, in the layout the gate's `doctor` uses.

    The runner's check is printed directly under the gate's eight, so it is laid
    out by the same rules: the verdict word, the id in a fixed column, the detail
    wrapped under it, and the remedy behind an arrow for anything not passing.
    """
    lead = " " * (6 + CHECK_ID_COLUMN)
    out(
        f"{check.status.word()}  {check.id:<{CHECK_ID_COLUMN}}"
        + _wrapped(check.detail, lead, width)
    )
    # The remediation line is the difference between a diagnosis and a
    # complaint, so it is printed for everything that is not passing — and a
    # check with nothing to do carries no remedy to print.
    if check.status is not Health.ok and check.remedy:
        out("      -> " + _wrapped(check.remedy, " " * 9, width))


def _wrapped(text: str, lead: str, width: int) -> str:
    """`text`, wrapped to `width`, with every line after the first indented to
    `lead`. Hand-rolled rather than `textwrap` so that the first line starts
    where the caller has already printed to."""
    budget = max(width - len(lead), 24)
    lines: list[str] = []
    current = ""
    for word in text.split():
        if current and len(current) + 1 + len(word) > budget:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return ("\n" + lead).join(lines)


#: The header of the candidate table. Written out rather than generated: it is
#: the one place the column widths below are stated, and it is easier to keep
#: two literals in step than to read a format string twice.
PROCESS_HEADER = "    pid   ppid  elapsed    %cpu       rss  state              command"


def process_table(
    candidates: Sequence[Candidate], *, marking_scope: bool = False
) -> None:
    """Every candidate, one line each, pid first.

    The pid is first because it is the only column an operator can act on, and
    because every kill this tool performs names one of these numbers. `--all`
    turns on the scope marker: an out-of-project process must be impossible to
    mistake for one of this checkout's.
    """
    out(PROCESS_HEADER)
    for candidate in candidates:
        record = candidate.record
        state = candidate.why()
        if marking_scope and candidate.attribution is not Attribution.this_project:
            state = f"{state} [{candidate.attribution.value.replace('_', ' ')}]"
        out(
            f"{record.pid:>7}{record.ppid:>7}  {human_elapsed(record.elapsed):<9}"
            f"{record.cpu:>5.1f}  {human_bytes(record.rss_kib):>9}  {state:<18} {record.command}"
        )


def reaped(outcome: ReapOutcome) -> None:
    """What the kill sequence did, per pid, in the order it happened."""
    for attempt in outcome.attempts:
        suffix = f" ({attempt.note})" if attempt.note else ""
        out(f"   {attempt.signal.value:<8} pid {attempt.pid}{suffix}")
    if outcome.survivors:
        note(
            "these pids survived SIGKILL and need a look by hand: "
            + pids(outcome.survivors)
        )


def pids(numbers: Sequence[int]) -> str:
    return ", ".join(str(n) for n in numbers)


# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------

HELP_PREAMBLE: tuple[str, ...] = (
    "hookctl — the one runner for claude-hooker.",
    "",
    "usage: ./hookctl <verb> [options]",
    "",
)

HELP_EPILOGUE: tuple[str, ...] = (
    "",
    "check vs verify",
    "  `check` is the GATE's verb: it asks what the gate would do about one",
    "  command (`./hookctl check 'git add -A'`). The repository's own gate — unit",
    "  tests, both binaries, the shlex parity oracle, the doc checks — is `verify`.",
    "  There is deliberately no `hookctl check` that means the second thing.",
    "",
    "paths and sandboxes",
    "  Every verb that touches an install accepts --claude-dir DIR, which moves the",
    "  whole install (binary, rules, settings.json, log) into DIR. Without it the",
    "  install is ~/.claude. Relative paths are resolved against your cwd.",
    "",
    "the underlying steps still work",
    "  This shells out to `zig build` — `zig build setup`, `zig build check` and",
    "  friends are unchanged and are exactly what these verbs run.",
)


def help_text(verbs: Sequence[Verb], groups: Sequence[VerbGroup]) -> str:
    lines = list(HELP_PREAMBLE)
    for index, group in enumerate(groups):
        if index:
            lines.append("")
        lines.append(group.heading)
        for verb in verbs:
            if verb.group == group.name:
                lines.append(f"  {verb.name:<{VERB_COLUMN}}{verb.summary}")
    lines += list(HELP_EPILOGUE)
    # Exactly one trailing newline, so the README can quote this as an ordinary
    # fenced block and the comparison in `docs.check_help_block` is byte-for-byte.
    return "\n".join(lines) + "\n"


def usage(verbs: Sequence[Verb], groups: Sequence[VerbGroup], stream=None) -> None:
    print(help_text(verbs, groups).rstrip("\n"), file=stream or sys.stderr)


# ---------------------------------------------------------------------------
# the two states worth explaining at length
# ---------------------------------------------------------------------------


def no_toolchain(
    verb_name: str, passthrough_names: Sequence[str], installed: Path | None
) -> None:
    """The whole no-toolchain story, in one message.

    This repository is built when it is cloned — there is no prebuilt binary to
    fall back to and no download to verify — so the honest answer is to name
    what to install and which verbs still work without it.
    """
    note(f"`{verb_name}` needs the Zig compiler, and `zig` is not on PATH.")
    note(
        f"  install Zig {MIN_ZIG} or newer: https://ziglang.org/download/  (or `brew install zig`)"
    )
    note("  this project is built from source; there are no prebuilt binaries.")
    if installed is not None:
        note(f"  an installed gate was found at {installed} — these verbs still work:")
        note("    " + " ".join(passthrough_names))
    else:
        note(
            "  no installed gate was found either, so no verb can run until Zig is available."
        )


def announce_gate(choice: GateChoice, paths: Paths) -> None:
    """Say which gate answered, when that could change the answer."""
    if choice.notice is GateNotice.built_differs and choice.gate is not None:
        note(
            f"using the freshly built {paths.display(choice.gate.path)}, which is NOT the same binary as the"
        )
        note(f"  installed {choice.installed}")
    elif choice.notice is GateNotice.installed_fallback:
        note(
            f"using the installed {choice.installed} — nothing is built in zig-out/bin yet"
        )


def no_gate(verb_name: str, gate_name: str, *, toolchain_present: bool) -> None:
    note(f"`{verb_name}` needs a {gate_name} binary and there is none.")
    if toolchain_present:
        note("  run `./hookctl build` (or `./hookctl setup` to install one).")
    else:
        note(f"  install Zig {MIN_ZIG} or newer and run `./hookctl build`.")


def stale_build(verb_name: str) -> None:
    note(
        f"the source tree does not currently compile, so `{verb_name}` is using the last"
    )
    note(
        "  binary built into zig-out/bin; the version it reports may be older than src/."
    )


def bad_timeout(stated: str, falling_back_to: float) -> None:
    """A `--timeout` that is not a positive number of seconds.

    Refused rather than obeyed, and said out loud rather than silently ignored:
    a run the operator believes is bounded and is not is worse than one they
    know is not.
    """
    note(
        f"--timeout {stated!r} is not a number of seconds of at least {MIN_TIMEOUT:.0f}"
    )
    note(f"  using this verb's default of {falling_back_to:.0f}s instead")


def rejects_arguments(verb_name: str, first: str) -> None:
    note(f"`{verb_name}` takes no arguments (got {first})")


def rejects_flag(verb_name: str, got: str, known: Sequence[str]) -> None:
    """A verb that takes SOME flags, refusing one it does not know.

    Distinct from `rejects_arguments` because the two are different facts, and
    for `reap` the difference is not cosmetic: it forwards to no child, so
    nothing downstream would catch the typo, and a mistyped `--dry-run` that was
    quietly ignored is a kill the operator did not ask for.
    """
    note(f"`{verb_name}` does not understand {got}")
    note(f"  it takes {' and '.join(known)}, and nothing else")


def unknown_verb(name: str) -> None:
    note(f"unknown verb {name!r}")

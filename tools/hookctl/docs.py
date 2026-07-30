"""The documentation checks: README.md as an assertion about the code.

These live in the runner rather than in the Zig test suite because they are
about the runner — `./hookctl help` is quoted in the README, and quoted
exactly, so a verb added here and not documented there is a failing check
rather than a thing somebody notices six months later.

Each check is anchored by an HTML comment (`<!-- hookctl:help -->`) rather than
by a heading or by searching for the command text. An anchor is a thing a writer
can see and keep, and these checks' job is to notice when the block below one
stops matching reality.

What is compared depends on what CAN be compared on every machine:

  * `help` has no paths in it, so it is compared **byte for byte**.
  * the per-event table is a **native markdown table**, which formatters re-pad
    at will, so its *cells* are compared — alignment is presentation, the cell
    text is the claim.
  * the `doctor` and `status` transcripts contain a claude-dir path, so their
    *shape* is compared: every check the binary emits must appear in the doctor
    block, and every label the status renderer prints must appear in the status
    block. That is the drift that actually happens — a check is added and the
    transcript silently stops being a full inventory.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import ui
from .proc import PROBE_TIMEOUT
from .spec import ENCODING, AuditCheck, Process, RunMode, Verb, VerbGroup


def readme_block(readme: Path, anchor: str) -> str | None:
    """The fenced block introduced by `<!-- hookctl:<anchor> -->`."""
    text = readme.read_text(encoding=ENCODING)
    marker = f"<!-- hookctl:{anchor} -->"
    at = text.find(marker)
    if at < 0:
        return None
    fence = text.find("```", at)
    if fence < 0:
        return None
    body_start = text.find("\n", fence)
    end = text.find("\n```", body_start)
    if body_start < 0 or end < 0:
        return None
    return text[body_start + 1 : end + 1]


def readme_table(readme: Path, anchor: str) -> list[str] | None:
    """The pipe-table rows introduced by `<!-- hookctl:<anchor> -->`.

    A native markdown table has no fence to find, so the block is the first
    contiguous run of `|`-led lines after the marker. A blank line between the
    marker and the table is normal markdown; the scan skips ahead to the first
    row rather than stopping at the first blank.
    """
    text = readme.read_text(encoding=ENCODING)
    marker = f"<!-- hookctl:{anchor} -->"
    at = text.find(marker)
    if at < 0:
        return None
    rows: list[str] = []
    for line in text[at + len(marker) :].splitlines():
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    return rows or None


def table_cells(lines: Sequence[str]) -> list[tuple[str, ...]]:
    """Each table row as a tuple of stripped cells, separator rows dropped.

    Column alignment is the formatter's business: padding inside a cell and the
    dash-count of the separator row change every time someone reflows the
    table, and change nothing about what the table claims. The cell text is the
    claim, so the cell text is what gets compared.
    """
    rows: list[tuple[str, ...]] = []
    for line in lines:
        stripped = line.strip().strip("|")
        cells = tuple(cell.strip() for cell in stripped.split("|"))
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def check_help_block(
    readme: Path, verbs: Sequence[Verb], groups: Sequence[VerbGroup]
) -> AuditCheck:
    """`./hookctl help` is quoted in the README, and quoted exactly.

    This block has no paths in it, so it is the one transcript that can be
    compared byte for byte on any machine — which makes it the check that
    actually catches a verb added here and not documented there.
    """
    block = readme_block(readme, "help")
    if block is None:
        return AuditCheck(
            "README quotes `./hookctl help`", False, "no <!-- hookctl:help --> block"
        )
    expected = "$ ./hookctl help\n" + ui.help_text(verbs, groups)
    name = "README quotes `./hookctl help` verbatim"
    if block == expected:
        return AuditCheck(name, True)
    for i, (a, b) in enumerate(zip(block.splitlines(), expected.splitlines())):
        if a != b:
            return AuditCheck(
                name,
                False,
                f"line {i + 1} differs: README has {a!r}, hookctl prints {b!r}",
            )
    return AuditCheck(
        name,
        False,
        f"length differs: README block has {len(block.splitlines())} lines, "
        f"hookctl prints {len(expected.splitlines())}",
    )


def check_verb_table(readme: Path, verbs: Sequence[Verb]) -> AuditCheck:
    """The verb reference table lists exactly the verbs that exist."""
    name = "README's verb table matches the implementation"
    rows = readme_table(readme, "verbs")
    if rows is None:
        return AuditCheck(name, False, "no <!-- hookctl:verbs --> table")
    documented = set(re.findall(r"^\| `([a-z-]+)[^`]*`", "\n".join(rows), re.MULTILINE))
    implemented = {v.name for v in verbs}
    missing = implemented - documented
    extra = documented - implemented
    if missing or extra:
        parts = []
        if missing:
            parts.append("undocumented: " + ", ".join(sorted(missing)))
        if extra:
            parts.append("documented but not implemented: " + ", ".join(sorted(extra)))
        return AuditCheck(name, False, "; ".join(parts))
    return AuditCheck(name, True, f"{len(implemented)} verbs")


def check_event_table(process: Process, readme: Path, gate_argv: str) -> AuditCheck:
    """The per-event reference table is quoted from the binary, cell for cell.

    Thirty rows of event-specific protocol facts — which response field carries a
    refusal, which decisions that field can hold, what the matcher means, which
    payload keys are readable — is precisely the documentation that rots: every
    cell is a claim about the code, a stale one is not obviously wrong, and the
    cost of a stale one is an operator writing a rule that cannot fire.

    So the gate renders the table (`events --markdown`) and this compares the
    README's copy against it. The README carries the table as native markdown —
    the point of the reformat was that it renders — and formatters re-pad the
    columns, so the comparison strips alignment and compares cell text. Every
    fact still comes from the binary; only the whitespace belongs to the editor.
    """
    name = "README quotes the per-event table cell for cell"
    lines = readme_table(readme, "events")
    if lines is None:
        return AuditCheck(name, False, "no <!-- hookctl:events --> table")
    run = process.run(
        (gate_argv, "events", "--markdown"),
        mode=RunMode.capture,
        scrub_env=True,
        timeout=PROBE_TIMEOUT,
    )
    if not run.ok or not run.stdout.strip():
        return AuditCheck(
            name, False, (run.stderr or "events --markdown printed nothing").strip()
        )
    documented = table_cells(lines)
    rendered = table_cells(run.stdout.splitlines())
    if documented == rendered:
        return AuditCheck(name, True, f"{len(rendered) - 1} events")
    for i, (a, b) in enumerate(zip(documented, rendered)):
        if a != b:
            readme_row = " | ".join(a)
            gate_row = " | ".join(b)
            return AuditCheck(
                name,
                False,
                f"row {i + 1} differs: README has {readme_row!r}, "
                f"the gate renders {gate_row!r}",
            )
    return AuditCheck(
        name,
        False,
        f"length differs: README table has {len(documented)} rows, "
        f"the gate renders {len(rendered)}",
    )


def check_quickstart(readme: Path) -> AuditCheck:
    """The quickstart leads with hookctl, not with a zig invocation."""
    name = "README's quickstart leads with ./hookctl"
    block = readme_block(readme, "quickstart")
    if block is None:
        return AuditCheck(name, False, "no <!-- hookctl:quickstart --> block")
    first = next((line for line in block.splitlines() if line.strip()), "")
    if "./hookctl setup" not in first:
        return AuditCheck(name, False, f"first line is {first!r}")
    return AuditCheck(name, True)


def check_transcripts(
    process: Process, readme: Path, gate_argv: str
) -> tuple[AuditCheck, ...]:
    """The doctor/status transcripts still describe the output they quote."""
    results: list[AuditCheck] = []
    with tempfile.TemporaryDirectory(prefix="hookctl-doccheck-") as tmp:
        empty = str(Path(tmp) / "claude")
        Path(empty).mkdir(parents=True)
        run = process.run(
            (gate_argv, "doctor", "--claude-dir", empty, "--json"),
            mode=RunMode.capture,
            scrub_env=True,
            timeout=PROBE_TIMEOUT,
        )
        block = readme_block(readme, "doctor")
        if block is None:
            results.append(
                AuditCheck(
                    "README's doctor transcript is a full inventory",
                    False,
                    "no <!-- hookctl:doctor --> block",
                )
            )
        elif not run.stdout.strip():
            results.append(
                AuditCheck(
                    "README's doctor transcript is a full inventory",
                    False,
                    (run.stderr or "doctor printed nothing").strip(),
                )
            )
        else:
            ids = [c["id"] for c in json.loads(run.stdout)["checks"]]
            missing = [i for i in ids if i not in block]
            results.append(
                AuditCheck(
                    "README's doctor transcript names every check",
                    not missing,
                    ", ".join(missing) + " missing"
                    if missing
                    else f"{len(ids)} checks",
                )
            )

        status = process.run(
            (gate_argv, "status", "--claude-dir", empty),
            mode=RunMode.capture,
            scrub_env=True,
            timeout=PROBE_TIMEOUT,
        )
        block = readme_block(readme, "status")
        labels = [
            m.group(1).strip()
            for m in re.finditer(r"^(\w[\w -]*?)\s+: ", status.stdout, re.MULTILINE)
        ]
        if block is None:
            results.append(
                AuditCheck(
                    "README's status transcript names every line",
                    False,
                    "no <!-- hookctl:status --> block",
                )
            )
        elif not labels:
            results.append(
                AuditCheck(
                    "README's status transcript names every line",
                    False,
                    "status printed no labelled lines",
                )
            )
        else:
            missing = [label for label in labels if label not in block]
            results.append(
                AuditCheck(
                    "README's status transcript names every line",
                    not missing,
                    ", ".join(missing) + " missing"
                    if missing
                    else f"{len(labels)} lines",
                )
            )
    return tuple(results)


def checks(
    process: Process,
    readme: Path,
    verbs: Sequence[Verb],
    groups: Sequence[VerbGroup],
    gate_argv: str | None,
) -> tuple[AuditCheck, ...]:
    """Every documentation check, in the order they are reported."""
    results = [
        check_help_block(readme, verbs, groups),
        check_verb_table(readme, verbs),
        check_quickstart(readme),
    ]
    if gate_argv is None:
        results.append(
            AuditCheck(
                "README transcripts name every check the binary emits",
                False,
                "no gate binary to ask",
            )
        )
        return tuple(results)
    results.append(check_event_table(process, readme, gate_argv))
    results += list(check_transcripts(process, readme, gate_argv))
    return tuple(results)

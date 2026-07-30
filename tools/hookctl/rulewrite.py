"""Writing an operator's rule file: one pipeline, gate-checked, reversible.

Every path that ends with bytes landing in a `hook-rules.json` — `init`'s
composition, `rules add/remove/promote/demote`, the authoring wizard — goes
through `validated_write`, and the order inside it is the point:

  1. the composed document is written to a sibling temp file;
  2. the GATE's own `selftest` is run against that temp file — the same parse,
     the same lint, the same cases the hook itself would apply. This runner
     never judges a rule document; the binary that will enforce it does;
  3. only on a pass is the existing file copied aside to a timestamped
     `.bak-<seconds>` sibling (the same naming the installer uses for
     `settings.json`) and the temp file swapped into place with `os.replace`,
     so the live file is never half-written even if the process dies mid-way;
  4. on a failure nothing of the operator's is touched: the rejected document
     is kept as a `.draft` sibling and reported, because the gate's complaint
     names the problem and the draft is where to fix it.

Rule edits are live on the gate's very next call — there is no reinstall and no
restart — which is exactly why nothing may land unvalidated.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

from .spec import ENCODING, Process, RuleWrite, RunMode, RunResult

#: The suffix chain for a rejected composition: `hook-rules.json.draft`.
DRAFT_SUFFIX = ".draft"


def render(doc: dict) -> str:
    """A rule document as the bytes that go on disk.

    Two-space indent and a trailing newline, matching the shipped documents, so
    a seeded-then-edited file and a composed file diff cleanly against each
    other and against `src/default-rules.json`.
    """
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def backup(target: Path) -> Path | None:
    """Copy `target` aside before it is rewritten; None when there is nothing.

    `.bak-<epoch seconds>` — the same shape the installer gives its
    `settings.json` backups, so an operator recovering by hand is looking for
    one pattern, not two.
    """
    if not target.exists():
        return None
    aside = target.with_name(f"{target.name}.bak-{int(time.time())}")
    shutil.copyfile(target, aside)
    return aside


def selftest(
    process: Process, gate_argv: str, rules_path: Path, timeout: float
) -> RunResult:
    """The gate's judgement of one rule document.

    Quiet on a pass — several hundred `PASS #...` lines would bury the line
    that matters — and replayed in full on a failure, because the failure
    output IS the diagnosis. `summary_line` recovers the one-line verdict for
    the caller to print on success.
    """
    return process.run(
        (gate_argv, "selftest", "--rules", str(rules_path)),
        mode=RunMode.quiet,
        timeout=timeout,
    )


def summary_line(result: RunResult) -> str:
    """The gate's own `result : ...` tally, for reporting a quiet pass."""
    for line in result.stdout.splitlines():
        if line.startswith("result"):
            return line.split(":", 1)[1].strip()
    return "passed"


def validated_write(
    process: Process,
    gate_argv: str,
    target: Path,
    doc: dict,
    timeout: float,
) -> RuleWrite:
    """Compose -> selftest -> backup -> swap; or keep a draft and touch nothing."""
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f"{target.name}.new-{os.getpid()}")
    temp.write_text(render(doc), encoding=ENCODING)
    result = selftest(process, gate_argv, temp, timeout)
    if not result.ok:
        draft = target.with_name(target.name + DRAFT_SUFFIX)
        temp.replace(draft)
        return RuleWrite(ok=False, target=target, draft=draft, selftest=result)
    aside = backup(target)
    temp.replace(target)
    return RuleWrite(ok=True, target=target, backup=aside, selftest=result)

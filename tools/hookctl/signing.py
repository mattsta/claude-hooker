"""What this runner knows about macOS code signatures.

Why a Python module for it at all, when the installer signs and the gate's
`doctor` diagnoses: because `setup` and `upgrade` are the two moments where an
operator is watching, and the signature is the one property of an install whose
failure mode is **silent**. macOS kills a Mach-O whose signature does not
validate — SIGKILL, no message — and a killed PreToolUse hook is a hook that
fails OPEN. Nothing is denied, nothing is logged, and the tool call proceeds.
There is no output to notice. So the status is printed even when it is fine.

Three things are deliberately NOT here:

  * **no Developer ID, ever.** This project is cloned and built; it ships no
    artifacts, so there is nothing to notarize and nobody to trust. The
    signature is ad-hoc (`codesign -s -`), which is exactly enough to satisfy
    the loader.
  * **no signing.** Signing the installed binary is the installer's job
    (`src/install.zig`), atomically, right after it copies the file. This module
    only asks and reports.
  * **no `-dv` shortcut for validity.** `codesign -dv` prints
    `Signature=adhoc` for a binary with a byte appended to it — the display flag
    reads what the signature *claims*, not whether it still covers the file.
    Only `codesign --verify` answers that, which is why both are run.
"""

from __future__ import annotations

import re
from pathlib import Path

from .proc import PROBE_TIMEOUT
from .spec import Platform, Process, RunMode, SignatureReport, SignatureState

CODESIGN = "codesign"

#: `CodeDirectory v=20400 size=7465 flags=0x20002(adhoc,linker-signed) hashes=…`
FLAGS_PATTERN = re.compile(r"^CodeDirectory .*?(flags=\S+)", re.MULTILINE)
#: `Signature=adhoc`
SIGNATURE_PATTERN = re.compile(r"^Signature=(\S+)", re.MULTILINE)

#: codesign's own words for "there is no signature here at all".
UNSIGNED_MARKER = "not signed at all"


def verify_command(path: Path) -> tuple[str, ...]:
    return (CODESIGN, "--verify", str(path))


def display_command(path: Path) -> tuple[str, ...]:
    return (CODESIGN, "--display", "--verbose=2", str(path))


def resign_command(path: Path) -> tuple[str, ...]:
    """The repair, in the form an operator can paste.

    `--force` is present because a file that already carries a real signature
    is refused otherwise, and the whole point of the repair is that it works on
    whatever is currently there.
    """
    return (CODESIGN, "--force", "--sign", "-", str(path))


def probe(process: Process, path: Path, platform: Platform) -> SignatureReport:
    """Ask the OS about one file. Two short spawns, or none.

    On a platform with no code-signature requirement this spawns nothing and
    says `not_applicable` — which is a different answer from "unsigned", and the
    difference is the whole reason the state is an enum.
    """
    if not platform.needs_signing:
        return SignatureReport(path=path, state=SignatureState.not_applicable)

    shown = process.run(
        display_command(path), mode=RunMode.capture, timeout=PROBE_TIMEOUT
    )
    # codesign writes its report to stderr; stdout is empty for --display.
    described = shown.stderr + shown.stdout
    flags = FLAGS_PATTERN.search(described)
    signature = SIGNATURE_PATTERN.search(described)
    form = flags.group(1) if flags else ""
    if signature:
        form = (
            f"{form}, Signature={signature.group(1)}"
            if form
            else f"Signature={signature.group(1)}"
        )

    verified = process.run(
        verify_command(path), mode=RunMode.capture, timeout=PROBE_TIMEOUT
    )
    if verified.ok:
        return SignatureReport(path=path, state=SignatureState.valid, form=form)

    note = verified.first_error_line()
    if UNSIGNED_MARKER in note:
        return SignatureReport(
            path=path, state=SignatureState.unsigned, form=form, note=note
        )
    # `codesign` itself is missing or unrunnable: reported as not knowing, never
    # as a pass.
    if (
        f"{CODESIGN}: not found" in note
        or "not executable" in note
        or "gave up" in note
    ):
        return SignatureReport(
            path=path, state=SignatureState.unavailable, form=form, note=note
        )
    return SignatureReport(
        path=path, state=SignatureState.invalid, form=form, note=note
    )


def summary_lines(report: SignatureReport) -> tuple[str, ...]:
    """The `setup`/`upgrade` report, as lines. Empty when there is nothing to
    say because this machine has no signature requirement."""
    if report.state is SignatureState.not_applicable:
        return ()
    path = report.path
    if report.state is SignatureState.valid:
        form = report.form or "no flags reported"
        expected = (
            "" if report.adhoc else " — NOT the ad-hoc signature this project installs"
        )
        return (
            f"   ok   {path}: {form}{expected}",
            "        `codesign --verify` accepts it; no Developer ID is involved or required.",
        )
    if report.state is SignatureState.unavailable:
        return (
            f"   warn {path}: cannot be checked — {report.note}",
            "        macOS may still refuse to run it; check by hand with "
            f"`{' '.join(verify_command(path))}`.",
        )
    return (
        f"   FAIL {path}: {report.note or report.state.value}",
        "        macOS may SIGKILL this binary, and a killed gate fails OPEN: the hook",
        "        produces no decision and no log line, so nothing is enforced.",
        f"        re-sign it with `{' '.join(resign_command(report.path))}`.",
    )

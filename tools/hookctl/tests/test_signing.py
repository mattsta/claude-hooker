"""macOS code signatures: the verdicts, and the two ways they are dangerous.

The whole reason this is checked and reported rather than assumed: macOS kills a
Mach-O whose signature does not validate, and a killed PreToolUse hook fails
OPEN — no decision, no log line, no output to notice. So "valid" is printed, and
"cannot tell" is never rounded up to "fine".

The not-applicable path — a machine with no signature requirement — is exercised
by constructing a `Platform` with `needs_signing=False` rather than by finding
another operating system. It must spawn nothing at all.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from .. import signing
from ..spec import SignatureState
from . import support

GATE = Path("/sb/hooks/claude-hooker-gate")

# What `codesign --display --verbose=2` prints for a binary as the Zig linker
# emits it, verbatim (it writes to stderr).
LINKER_SIGNED = """Executable=/sb/hooks/claude-hooker-gate
Identifier=claude-hooker-gate
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=7465 flags=0x20002(adhoc,linker-signed) hashes=230+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
"""

# And after `codesign --force --sign -`.
RESIGNED = """Executable=/sb/hooks/claude-hooker-gate
Identifier=claude-hooker-gate
CodeDirectory v=20400 size=29604 flags=0x2(adhoc) hashes=919+2 location=embedded
Signature=adhoc
"""

DEVELOPER_ID = """Executable=/sb/hooks/claude-hooker-gate
CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=40+2 location=embedded
Signature size=9000
Authority=Developer ID Application: Somebody (ABCDE12345)
"""


def probe(
    display: str, verify_code: int = 0, verify_err: str = "", *, platform=support.DARWIN
):
    process = support.FakeProcess(
        replies={
            "--display": support.reply(stderr=display),
            "--verify": support.reply(code=verify_code, stderr=verify_err),
        }
    )
    return signing.probe(process, GATE, platform), process


class TestProbe(unittest.TestCase):
    def test_a_linker_signed_binary_is_valid_and_adhoc(self):
        report, process = probe(LINKER_SIGNED)
        self.assertIs(SignatureState.valid, report.state)
        self.assertTrue(report.adhoc)
        self.assertIn("flags=0x20002(adhoc,linker-signed)", report.form)
        self.assertIn("Signature=adhoc", report.form)
        self.assertTrue(report.ok)
        # Both questions are asked, because neither answers the other.
        self.assertTrue(process.ran("--display"))
        self.assertTrue(process.ran("--verify"))

    def test_a_re_signed_binary_is_also_adhoc(self):
        report, _ = probe(RESIGNED)
        self.assertIs(SignatureState.valid, report.state)
        self.assertTrue(report.adhoc)
        self.assertIn("flags=0x2(adhoc)", report.form)

    def test_a_developer_id_signature_is_valid_but_not_what_we_install(self):
        report, _ = probe(DEVELOPER_ID)
        self.assertIs(SignatureState.valid, report.state)
        self.assertFalse(report.adhoc)
        # Reported, not corrected: nothing here requires or wants a Developer ID.
        self.assertIn(
            "NOT the ad-hoc signature", "\n".join(signing.summary_lines(report))
        )

    def test_an_appended_byte_still_claims_to_be_adhoc_and_is_invalid(self):
        # The exact reason `--display` alone is not enough: the flags say adhoc
        # for a file whose signature no longer covers its bytes.
        report, _ = probe(
            LINKER_SIGNED,
            verify_code=1,
            verify_err="/sb/hooks/claude-hooker-gate: main executable failed strict validation\n",
        )
        self.assertIs(SignatureState.invalid, report.state)
        self.assertIn("failed strict validation", report.note)
        self.assertFalse(report.ok)

    def test_an_unsigned_file(self):
        report, _ = probe(
            "/sb/hooks/claude-hooker-gate: code object is not signed at all\n",
            verify_code=1,
            verify_err="/sb/hooks/claude-hooker-gate: code object is not signed at all\n",
        )
        self.assertIs(SignatureState.unsigned, report.state)
        self.assertFalse(report.ok)

    def test_no_codesign_on_the_machine_is_not_knowing(self):
        report, _ = probe(
            "", verify_code=69, verify_err="codesign: not found on PATH\n"
        )
        self.assertIs(SignatureState.unavailable, report.state)
        self.assertFalse(report.ok, "not knowing must never be reported as fine")

    def test_a_wedged_codesign_is_also_not_knowing(self):
        report, _ = probe(
            "", verify_code=69, verify_err="codesign: no answer after 30s, gave up\n"
        )
        self.assertIs(SignatureState.unavailable, report.state)


class TestNotApplicable(unittest.TestCase):
    def test_off_darwin_nothing_is_asked_and_nothing_is_said(self):
        report, process = probe(LINKER_SIGNED, platform=support.LINUX)
        self.assertIs(SignatureState.not_applicable, report.state)
        self.assertTrue(report.ok)
        self.assertEqual([], process.calls, "a non-macOS run must not spawn codesign")
        self.assertEqual((), signing.summary_lines(report))


class TestReporting(unittest.TestCase):
    def test_a_valid_signature_is_still_printed(self):
        report, _ = probe(LINKER_SIGNED)
        lines = signing.summary_lines(report)
        self.assertTrue(lines[0].startswith("   ok   "))
        self.assertIn("adhoc", lines[0])
        self.assertIn("No developer id is involved".lower(), "\n".join(lines).lower())

    def test_a_broken_signature_names_the_danger_and_the_repair(self):
        report, _ = probe(
            LINKER_SIGNED,
            verify_code=1,
            verify_err="/sb/hooks/claude-hooker-gate: main executable failed strict validation\n",
        )
        text = "\n".join(signing.summary_lines(report))
        self.assertIn("FAIL", text)
        self.assertIn("SIGKILL", text)
        self.assertIn("fails OPEN", text)
        self.assertIn("codesign --force --sign - /sb/hooks/claude-hooker-gate", text)

    def test_the_repair_command_is_the_one_documented(self):
        self.assertEqual(
            ("codesign", "--force", "--sign", "-", str(GATE)),
            signing.resign_command(GATE),
        )


if __name__ == "__main__":
    unittest.main()

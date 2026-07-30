"""End to end: install into a sandbox, then ask the OS about what landed.

Everything else about signatures is tested against stated facts. This is the one
test that runs the real installer and the real `codesign`, because the property
being asserted is a claim about a file on disk: after `setup`, the gate in the
claude dir validates. A test that only ever saw canned output could not tell you
that.

It skips — rather than fails — when there is nothing to run it with: off macOS
there is no signature requirement (that path is covered by injection in
`test_signing.py`), and without `zig-out/bin` there is no installer. Under
`./hookctl verify` both are present, which is where it earns its keep.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from .. import discovery, signing
from ..proc import Runner
from ..spec import RunMode, SignatureState
from . import support

HERE = support.project_root()
GATE = HERE / "zig-out" / "bin" / "claude-hooker-gate"
INSTALLER = HERE / "zig-out" / "bin" / "claude-hooker-install"

PLATFORM = discovery.platform()


@unittest.skipUnless(PLATFORM.needs_signing, "code signatures are a macOS requirement")
@unittest.skipUnless(
    GATE.is_file() and INSTALLER.is_file(), "run `./hookctl build` first"
)
class TestInstalledSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hookctl-sig-e2e-")
        self.addCleanup(self.tmp.cleanup)
        self.sandbox = Path(self.tmp.name) / "claude"
        self.process = Runner(cwd=HERE)

    def install(self, gate: Path = GATE) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(INSTALLER), "--gate", str(gate), "--claude-dir", str(self.sandbox)],
            cwd=HERE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )

    @property
    def installed(self) -> Path:
        return self.sandbox / "hooks" / "claude-hooker-gate"

    def test_a_fresh_install_lands_signed_and_says_so(self):
        done = self.install()
        self.assertEqual(0, done.returncode, done.stdout + done.stderr)
        self.assertIn("ok   signature:", done.stdout)
        self.assertIn("adhoc", done.stdout)

        # And independently: the OS agrees.
        report = signing.probe(self.process, self.installed, PLATFORM)
        self.assertIs(SignatureState.valid, report.state, report.note)
        self.assertTrue(report.adhoc, report.form)

    def test_doctor_reports_the_signature_of_what_it_wired(self):
        self.assertEqual(0, self.install().returncode)
        done = self.process.run(
            (str(GATE), "doctor", "--claude-dir", str(self.sandbox), "--json"),
            mode=RunMode.capture,
            scrub_env=True,
            timeout=120,
        )
        import json

        checks = {c["id"]: c for c in json.loads(done.stdout)["checks"]}
        self.assertIn("signature", checks, "the check must be in the inventory")
        self.assertEqual(
            "pass", checks["signature"]["status"], checks["signature"]["detail"]
        )
        self.assertIn("adhoc", checks["signature"]["detail"])

    def test_a_tampered_gate_is_refused_by_the_install(self):
        # A byte appended to a COPY inside the sandbox: the cheapest real way to
        # break a signature, and one `codesign --display` alone would miss.
        tampered = Path(self.tmp.name) / "gate-tampered"
        tampered.write_bytes(GATE.read_bytes() + b"x")
        tampered.chmod(0o755)
        self.assertIs(
            SignatureState.invalid,
            signing.probe(self.process, tampered, PLATFORM).state,
            "the tampering itself did not take",
        )

        done = self.install(tampered)
        self.assertNotEqual(
            0, done.returncode, "an install must not ship a binary the OS may kill"
        )
        self.assertIn("FAIL signature:", done.stdout)
        self.assertIn("fails OPEN", done.stdout)
        # It tried to repair it first, and said so.
        self.assertIn("re-signing ad-hoc", done.stdout)

    def test_an_unsigned_gate_is_repaired_rather_than_refused(self):
        stripped = Path(self.tmp.name) / "gate-stripped"
        stripped.write_bytes(GATE.read_bytes())
        stripped.chmod(0o755)
        removed = self.process.run(
            ("codesign", "--remove-signature", str(stripped)),
            mode=RunMode.capture,
            timeout=60,
        )
        if not removed.ok:
            self.skipTest(
                f"could not strip a signature to test with: {removed.first_error_line()}"
            )
        self.assertIs(
            SignatureState.unsigned,
            signing.probe(self.process, stripped, PLATFORM).state,
        )

        done = self.install(stripped)
        self.assertEqual(0, done.returncode, done.stdout + done.stderr)
        self.assertIn("re-signing ad-hoc", done.stdout)
        self.assertIn("(re-signed by this install)", done.stdout)
        self.assertIs(
            SignatureState.valid,
            signing.probe(self.process, self.installed, PLATFORM).state,
        )


if __name__ == "__main__":
    unittest.main()

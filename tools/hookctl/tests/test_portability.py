"""The two promises that are about the runner as a *file*, not as a program.

**Any python3 gets an honest answer.** `./hookctl` is the first command a new
clone types, under whatever `python3` the machine provides. An interpreter at
or above `MIN_PYTHON` must run the real entry point; an older one must be
turned away by the entry point's own guard — one line naming the required
version, exit 69 — and never with a traceback from an import it cannot digest.
Both halves are proven against `/usr/bin/python3`, the interpreter the
platform ships, whichever side of the floor it falls on.

**Every value that crosses a boundary is immutable.** Asserted over the whole
module rather than per class, so a new type cannot join the package as a
mutable one by omission.
"""

from __future__ import annotations

import dataclasses
import subprocess
import unittest
from pathlib import Path

from .. import spec
from . import support

PLATFORM_PYTHON = Path("/usr/bin/python3")
ENTRY = support.project_root() / "hookctl"


def platform_version() -> tuple:
    done = subprocess.run(
        [str(PLATFORM_PYTHON), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    printed = (done.stdout + done.stderr).split()[-1]
    return tuple(int(part) for part in printed.split(".")[:2])


class TestFrozenTypes(unittest.TestCase):
    def test_every_dataclass_in_spec_is_frozen(self):
        found = 0
        for name, obj in vars(spec).items():
            if not (isinstance(obj, type) and dataclasses.is_dataclass(obj)):
                continue
            found += 1
            self.assertTrue(obj.__dataclass_params__.frozen, f"{name} is mutable")
        self.assertGreater(found, 8, "spec should hold the package's types")

    def test_a_frozen_value_cannot_be_reassigned(self):
        paths = spec.Paths.of(Path("/repo"), Path("/sb"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            paths.claude_dir = Path("/elsewhere")  # type: ignore[misc]

    def test_slots_everywhere(self):
        self.assertTrue(spec.FROZEN["frozen"])
        self.assertTrue(spec.FROZEN["slots"])

    def test_the_declared_minimum_is_the_one_the_entry_point_enforces(self):
        # Two files name it; a disagreement would either lock out a supported
        # interpreter or let an unsupported one reach an import error. The
        # ruff config's `target-version` is held to the same floor, so
        # modernization cannot outrun what the guard admits.
        text = ENTRY.read_text(encoding=spec.ENCODING)
        major, minor = spec.MIN_PYTHON
        self.assertIn(f"sys.version_info < ({major}, {minor})", text)
        self.assertIn(f"Python {major}.{minor} or newer", text)
        ruff = (support.project_root() / "ruff.toml").read_text(encoding=spec.ENCODING)
        self.assertIn(f'target-version = "py{major}{minor}"', ruff)


@unittest.skipUnless(PLATFORM_PYTHON.exists(), "no /usr/bin/python3 on this machine")
class TestPlatformInterpreter(unittest.TestCase):
    """Whichever side of the floor the platform python falls on, the answer is
    deliberate: the runner runs, or the guard speaks. Nothing tracebacks."""

    def run_entry(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(PLATFORM_PYTHON), str(ENTRY), *args],
            capture_output=True,
            text=True,
            encoding=spec.ENCODING,
            timeout=120,
        )

    def test_the_platform_interpreter_gets_a_deliberate_answer(self):
        done = self.run_entry("help")
        if platform_version() >= spec.MIN_PYTHON:
            self.assertEqual(0, done.returncode, done.stderr)
            self.assertIn("operator verbs", done.stdout)
        else:
            major, minor = spec.MIN_PYTHON
            self.assertEqual(spec.EX_UNAVAILABLE, done.returncode)
            self.assertIn(f"Python {major}.{minor} or newer", done.stderr)
            self.assertNotIn("Traceback", done.stderr)

    def test_a_usage_error_is_still_not_a_traceback(self):
        # On a supported interpreter this exercises dispatch, the registry and
        # the whole ui module; on an older one, the same guard answers.
        done = self.run_entry("docter")
        if platform_version() >= spec.MIN_PYTHON:
            self.assertEqual(spec.EX_USAGE, done.returncode)
            self.assertIn("unknown verb", done.stderr)
        else:
            self.assertEqual(spec.EX_UNAVAILABLE, done.returncode)
            self.assertNotIn("Traceback", done.stderr)


if __name__ == "__main__":
    unittest.main()

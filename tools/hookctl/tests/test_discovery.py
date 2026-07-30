"""Resolution: the layout, the toolchain, the platform, and WHICH gate answers.

The gate-precedence tests are the ones worth having. Two binaries can exist at
once — the one this tree just built and the one installed in the claude dir —
and which of them answered changes the answer. Every state of that pair is
pinned here.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from .. import discovery
from ..spec import GateNotice, GateSource, Toolchain
from . import support


class TestPaths(unittest.TestCase):
    def test_one_directory_moves_the_whole_install(self):
        paths = discovery.paths(["--claude-dir", "/sb"], root=Path("/repo"))
        self.assertEqual(Path("/sb"), paths.claude_dir)
        self.assertEqual(Path("/sb/hooks/claude-hooker-gate"), paths.installed_gate)
        self.assertEqual(Path("/sb/hook-rules.json"), paths.rules_path)
        self.assertEqual(Path("/sb/hook-gate-log.jsonl"), paths.log_path)
        self.assertEqual(Path("/sb/settings.json"), paths.settings_path)
        # The built binaries and the README belong to the tree, not the install.
        self.assertEqual(Path("/repo/zig-out/bin/claude-hooker-gate"), paths.built_gate)
        self.assertEqual(
            Path("/repo/zig-out/bin/claude-hooker-install"), paths.built_installer
        )
        self.assertEqual(Path("/repo/README.md"), paths.readme)

    def test_without_the_flag_the_install_is_under_home(self):
        paths = discovery.paths([], root=Path("/repo"), home="/home/op")
        self.assertEqual(Path("/home/op/.claude"), paths.claude_dir)
        self.assertEqual(
            Path("/home/op/.claude/hooks/claude-hooker-gate"), paths.installed_gate
        )

    def test_the_joined_spelling_is_honoured_too(self):
        paths = discovery.paths(["--claude-dir=/sb"], root=Path("/repo"))
        self.assertEqual(Path("/sb"), paths.claude_dir)

    def test_paths_inside_the_tree_are_printed_relative(self):
        paths = discovery.paths([], root=Path("/repo"), home="/home/op")
        self.assertEqual(
            "zig-out/bin/claude-hooker-gate", paths.display(paths.built_gate)
        )
        # An installed gate is outside the tree and keeps its absolute path.
        self.assertEqual(str(paths.installed_gate), paths.display(paths.installed_gate))

    def test_the_project_root_is_this_tree(self):
        root = discovery.project_root()
        self.assertTrue((root / "hookctl").is_file())
        self.assertTrue((root / "tools" / "hookctl" / "spec.py").is_file())


class TestToolchain(unittest.TestCase):
    def test_present(self):
        found = discovery.toolchain(which=support.which("/opt/zig"))
        self.assertTrue(found.present)
        self.assertEqual("/opt/zig", found.path)
        self.assertIn("/opt/zig", found.describe())

    def test_absent_is_a_state_not_an_error(self):
        missing = discovery.toolchain(which=support.which(None))
        self.assertFalse(missing.present)
        self.assertIsNone(missing.path)
        self.assertEqual(missing, Toolchain.absent())
        self.assertIn("install 0.16.0+", missing.describe())

    def test_the_version_is_added_later_without_mutating(self):
        found = discovery.toolchain(which=support.which("/opt/zig"))
        named = found.with_version("0.16.0")
        self.assertIsNone(found.version)
        self.assertEqual("zig 0.16.0 at /opt/zig", named.describe())


class TestPlatform(unittest.TestCase):
    def test_darwin_needs_signing_and_nothing_else_does(self):
        self.assertTrue(discovery.platform(system="Darwin", arch="arm64").needs_signing)
        self.assertFalse(
            discovery.platform(system="Linux", arch="x86_64").needs_signing
        )
        self.assertFalse(
            discovery.platform(system="FreeBSD", arch="amd64").needs_signing
        )

    def test_this_machine_is_reported_without_being_asked_twice(self):
        here = discovery.platform()
        self.assertEqual(here.needs_signing, here.system == "Darwin")


class TestChooseGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hookctl-gate-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.paths = discovery.paths(
            ["--claude-dir", str(Path(self.tmp.name) / "claude")], root=self.root
        )

    def test_nothing_built_and_nothing_installed(self):
        choice = discovery.choose_gate(self.paths)
        self.assertIsNone(choice.gate)
        self.assertFalse(choice.resolved)
        self.assertIs(GateNotice.quiet, choice.notice)

    def test_the_built_one_wins(self):
        support.executable(self.paths.built_gate, "fresh")
        support.executable(self.paths.installed_gate, "fresh")
        choice = discovery.choose_gate(self.paths)
        self.assertEqual(self.paths.built_gate, choice.gate.path)
        self.assertIs(GateSource.built, choice.gate.source)
        # Same bytes: saying so on every run would train the reader to skip the
        # line that matters.
        self.assertIs(GateNotice.quiet, choice.notice)

    def test_differing_bytes_are_announced(self):
        support.executable(self.paths.built_gate, "fresh")
        support.executable(self.paths.installed_gate, "older")
        choice = discovery.choose_gate(self.paths)
        self.assertEqual(self.paths.built_gate, choice.gate.path)
        self.assertIs(GateNotice.built_differs, choice.notice)
        self.assertEqual(self.paths.installed_gate, choice.installed)

    def test_a_same_size_difference_is_still_a_difference(self):
        # Size alone would miss this; the comparison hashes the contents.
        support.executable(self.paths.built_gate, "aaaa")
        support.executable(self.paths.installed_gate, "bbbb")
        self.assertIs(
            GateNotice.built_differs, discovery.choose_gate(self.paths).notice
        )

    def test_the_installed_one_stands_in(self):
        support.executable(self.paths.installed_gate, "older")
        choice = discovery.choose_gate(self.paths)
        self.assertEqual(self.paths.installed_gate, choice.gate.path)
        self.assertIs(GateSource.installed, choice.gate.source)
        self.assertIs(GateNotice.installed_fallback, choice.notice)

    def test_a_directory_where_the_gate_should_be_is_not_a_gate(self):
        self.paths.installed_gate.mkdir(parents=True)
        self.assertIsNone(discovery.installed_gate(self.paths))


if __name__ == "__main__":
    unittest.main()

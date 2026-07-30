"""Resolution: turning a command line and a filesystem into frozen facts.

Nothing in this module writes, prints, or spawns. It reads — `is_file`, a hash,
`shutil.which` — and returns a `Paths`, a `Toolchain`, a `Platform`, a
`GateChoice`. Keeping it that way is what makes the interesting decisions
testable without a machine that is in the interesting state: a test builds two
files in a temp directory and asserts which one a verb would have run, and the
no-toolchain path is reached by constructing `Toolchain.absent()` rather than by
moving `zig` out of the way.

The one decision worth reading twice is `choose_gate`. Two gate binaries can
exist at once — the one this tree just built and the one installed in the
claude dir — and which of them answered a question changes the answer. So the
choice is a value with a reason attached, not a path.
"""

from __future__ import annotations

import hashlib
import os
import platform as platform_module
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path

from . import argv as argv_mod
from .spec import (
    GateBinary,
    GateChoice,
    GateNotice,
    GateSource,
    Paths,
    Platform,
    Toolchain,
)

#: The directory the runner lives in: `<root>/tools/hookctl/discovery.py`.
_PACKAGE_DEPTH = 2


def project_root(module_file: str | None = None) -> Path:
    """The repository root, derived from this file's own location.

    Not from the cwd, and not from an environment variable: `./hookctl` must
    mean the same tree whichever directory it is typed in.
    """
    here = Path(module_file or __file__).resolve()
    return here.parents[_PACKAGE_DEPTH]


def platform(system: str | None = None, arch: str | None = None) -> Platform:
    """This machine, or a stated one.

    `needs_signing` is decided here, once. macOS SIGKILLs a Mach-O whose code
    signature does not validate, and a SIGKILLed gate is a gate that fails
    OPEN with no output at all — so on Darwin the signature is part of the
    install, not a detail of it.
    """
    name = system or platform_module.system()
    machine = arch or platform_module.machine()
    return Platform(system=name, arch=machine, needs_signing=name == "Darwin")


def toolchain(which: Callable[[str], str | None] = shutil.which) -> Toolchain:
    """Whether there is a Zig compiler, and where.

    The version is deliberately not probed here — that would need a subprocess,
    and this module does not spawn. `proc.zig_version` fills it in for the one
    verb that reports it.
    """
    found = which("zig")
    if found is None:
        return Toolchain.absent()
    return Toolchain(path=found, present=True)


def claude_dir(args: Sequence[str] = (), *, home: str | None = None) -> Path:
    """The install a verb is talking about: `--claude-dir`, else `~/.claude`.

    Resolved to an absolute path here so that everything derived from it is
    absolute too — the installed gate's path ends up inside `settings.json`,
    where a relative path would mean whatever directory the harness happened
    to start in.
    """
    explicit = argv_mod.flag_value(args)
    if explicit:
        # abspath, NOT Path.resolve(): a symlinked claude dir must keep the
        # spelling the operator gave it in every path derived from here.
        return Path(os.path.abspath(explicit))  # noqa: PTH100
    base = Path(home) if home is not None else Path("~").expanduser()
    return base / ".claude"


def paths(
    args: Sequence[str] = (), *, root: Path | None = None, home: str | None = None
) -> Paths:
    return Paths.of(root or project_root(), claude_dir(args, home=home))


def installed_gate(paths_: Paths) -> Path | None:
    """The installed gate, or None when this claude dir has no install."""
    return paths_.installed_gate if paths_.installed_gate.is_file() else None


def same_contents(a: Path, b: Path) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False
    return (
        hashlib.sha256(a.read_bytes()).digest()
        == hashlib.sha256(b.read_bytes()).digest()
    )


def choose_gate(paths_: Paths) -> GateChoice:
    """Which `claude-hooker-gate` a passthrough verb should run.

    The freshly built one wins: it is the tree the operator is looking at, and
    for `doctor` it is the only binary that can see version drift at all. The
    installed one stands in when nothing is built, which is the state a machine
    that only ever ran `./hookctl setup` is in.

    The reason travels with the choice so the caller can announce it — but only
    when it could change the answer. See `GateNotice`.
    """
    installed = installed_gate(paths_)
    if paths_.built_gate.is_file():
        notice = GateNotice.quiet
        if installed is not None and not same_contents(paths_.built_gate, installed):
            notice = GateNotice.built_differs
        return GateChoice(
            gate=GateBinary(path=paths_.built_gate, source=GateSource.built),
            notice=notice,
            installed=installed,
        )
    if installed is not None:
        return GateChoice(
            gate=GateBinary(path=installed, source=GateSource.installed),
            notice=GateNotice.installed_fallback,
            installed=installed,
        )
    return GateChoice(gate=None, notice=GateNotice.quiet, installed=None)

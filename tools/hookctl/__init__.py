"""hookctl — the single runner for claude-hooker.

Operating this tool should not require knowing that Zig exists. Everything an
operator or a contributor needs is a verb: `./hookctl setup` installs,
`./hookctl doctor` diagnoses, `./hookctl verify` is the pre-commit gate. Under
the hood this shells out to `zig build` and to the two binaries it produces; the
raw `zig build setup` / `zig build check` steps still work and are still what
this calls, so nobody's muscle memory breaks.

Why Python and not more Zig: two of these jobs cannot be done by the binaries.
Building them is one (a binary cannot compile itself into existence), and
running every mechanical consistency check the repository has — across four
rule fixtures, the class catalog, and the documentation — is the other. It is
stdlib-only and does no work at import time, so it needs no environment of its
own, and it will never grow a dependency.

This project ships as source: there are no prebuilt binaries and no release
artifacts to download. Without a Zig toolchain the build verbs cannot work, and
this says so in one line rather than failing somewhere deeper.

The layout, and why it is a package rather than one file:

    spec.py       every value that crosses a function boundary, as a frozen
                  dataclass. No strings threaded between functions.
    argv.py       the little argument parsing the runner itself does.
    discovery.py  pure resolution: project root, toolchain, claude dir, and
                  WHICH of the two gate binaries answers a question.
    proc.py       the single subprocess chokepoint. Every child gets its own
                  session and a wall-clock budget; a timeout kills the whole
                  process GROUP, because the grandchildren are the problem.
    processes.py  reading the process table: finding, judging and killing this
                  checkout's own stale build and test processes, by pid.
    signing.py    what `codesign` says about an installed gate (macOS).
    docs.py       README.md as an assertion about the code.
    rulecatalog.py  every rule the repository ships or documents, as one
                  adoptable catalog, with the pure transforms `init` and
                  `rules` are built from (compose, shadow, adopt, remove).
    rulewrite.py  the one pipeline every rule-file write goes through:
                  gate selftest first, timestamped backup, atomic swap.
    interact.py   the injectable console the wizards ask questions with.
    ui.py         everything printed, including the `help` text the README
                  quotes byte for byte.
    registry.py   the one verb table: help, dispatch and the doc check read it.
    main.py       argv -> Context -> verb handler -> exit code.
    verbs/        one module per family; handlers take a Context, return a code.
    tests/        stdlib unittest, run by `./hookctl selfcheck` and by `verify`.
"""

from __future__ import annotations

__all__ = ["run"]

# Only `run` is lifted out of `main.py`: importing `main` here as well would
# rebind the submodule name to the function and hide `hookctl.main` from
# anything that wants the module (its own tests, for one).
from .main import run

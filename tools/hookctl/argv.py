"""Argument parsing: the little of it this runner does, in one place.

`hookctl` is deliberately not an argument parser. Everything after the verb
belongs to a child — the gate, the installer, or `zig build` — and inventing a
second grammar for it would mean every flag the gate gains has to be taught to
this file too. So the only arguments read here are the ones the runner itself
has to act on, and there is exactly one: `--claude-dir`, which decides which
install a verb is talking about.

Both spellings are understood (`--claude-dir DIR` and `--claude-dir=DIR`)
because both are what people type, and the value is resolved against the
caller's working directory: children run with the repository root as their cwd,
so a relative `--claude-dir build/sandbox` typed somewhere else would otherwise
silently mean a different place.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass

from .spec import FROZEN

CLAUDE_DIR = "--claude-dir"

#: The spellings that mean "print the verb list and stop".
HELP_FLAGS = ("-h", "--help")


@dataclass(**FROZEN)
class Invocation:
    """One command line, split at the verb.

    `verb` is None for a bare `./hookctl`, which is a usage error rather than a
    default action: a tool that installs things must not do so because a
    command line was empty.
    """

    verb: str | None
    args: tuple[str, ...] = ()

    @property
    def wants_help(self) -> bool:
        return self.verb in HELP_FLAGS

    @property
    def empty(self) -> bool:
        return self.verb is None


def parse(argv: Sequence[str]) -> Invocation:
    if not argv:
        return Invocation(verb=None)
    return Invocation(verb=argv[0], args=tuple(argv[1:]))


def flag_value(args: Sequence[str], name: str = CLAUDE_DIR) -> str | None:
    """The value an operator passed for `name`, if any."""
    prefix = name + "="
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(prefix):
            return arg.split("=", 1)[1]
    return None


def flag_values(args: Sequence[str], name: str) -> tuple[str, ...]:
    """Every value an operator passed for a repeatable flag, in order.

    `--bundle a --bundle b` is how a script asks for two bundles; the
    single-value `flag_value` would silently drop the second, which for a
    policy tool is a rule set the operator believes is wider than it is.
    """
    prefix = name + "="
    found: list[str] = []
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            found.append(args[i + 1])
        elif arg.startswith(prefix):
            found.append(arg.split("=", 1)[1])
    return tuple(found)


def has_flag(args: Sequence[str], name: str) -> bool:
    """Whether a valueless flag is present, verbatim."""
    return name in args


def without_flag(args: Sequence[str], name: str) -> tuple[str, ...]:
    """`args` with a valueless flag removed.

    For the flags this runner acts on itself and must not forward: a child that
    is handed `--dry-run` because the runner also understood it is a child
    running the wrong command.
    """
    return tuple(arg for arg in args if arg != name)


def without_flag_value(args: Sequence[str], name: str) -> tuple[str, ...]:
    """`args` with `name` and its value removed, in both spellings.

    `--timeout` is the runner's own, and `zig build --timeout 30` is not a
    thing. Stripping happens before the `ArgShape.none` guard, so that
    `./hookctl verify --timeout 5` is a bounded verify rather than a usage
    error.
    """
    prefix = name + "="
    out: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg == name:
            skip = True
            continue
        if arg.startswith(prefix):
            continue
        out.append(arg)
    return tuple(out)


def flag_only(args: Sequence[str], name: str = CLAUDE_DIR) -> tuple[str, ...]:
    """Just the `name` flag and its value, for handing to a subcommand that
    takes it and nothing else the caller passed."""
    prefix = name + "="
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            return (arg, args[i + 1])
        if arg.startswith(prefix):
            return (arg,)
    return ()


def absolutize(
    args: Sequence[str], name: str = CLAUDE_DIR, *, cwd: str | None = None
) -> tuple[str, ...]:
    """`args` with `name`'s value resolved against the caller's cwd."""

    def absolute(value: str) -> str:
        # abspath, NOT Path.resolve(): the value ends up in settings.json and
        # in children's argv, and resolve() rewrites symlinks — an operator
        # who points --claude-dir at a symlink gets the spelling they typed.
        return os.path.abspath(  # noqa: PTH100
            value if cwd is None else os.path.join(cwd, value)  # noqa: PTH118
        )

    out = list(args)
    prefix = name + "="
    for i, arg in enumerate(out):
        if arg == name and i + 1 < len(out):
            out[i + 1] = absolute(out[i + 1])
        elif arg.startswith(prefix):
            out[i] = prefix + absolute(arg.split("=", 1)[1])
    return tuple(out)

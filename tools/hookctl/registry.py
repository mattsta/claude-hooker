"""The verb table. One table, read by everything.

`help` renders from it, dispatch looks up in it, and the README's verb-table
check compares against it. That is the whole reason it is a table of frozen
dataclasses in one module instead of a chain of `if verb == "..."`: those three
readers cannot drift apart if there is only one thing to read.

Adding a verb is therefore three lines and a handler — and if the README is not
updated to match, `./hookctl verify` fails, which is the intended amount of
friction for adding to an operator-facing surface.
"""

from __future__ import annotations

from . import ui
from .spec import CROSS_TIMEOUT, ArgShape, Context, Verb, VerbGroup
from .verbs import audit as audit_verb
from .verbs import dev, operator
from .verbs import init as init_verb
from .verbs import reap as reap_verb
from .verbs import rules as rules_verb
from .verbs.passthrough import run_gate

#: The sections of `help`, in the order they are printed. The heading is data
#: so that `help` and this table cannot disagree about which verbs are an
#: operator's business and which are a contributor's.
GROUPS: tuple[VerbGroup, ...] = (
    VerbGroup("operator", "operator verbs — installing and operating the gate"),
    VerbGroup(
        "dev", "dev verbs — working on this repository (these need `zig` on PATH)"
    ),
)


def _gate(
    name: str,
    summary: str,
    gate_args: tuple[str, ...],
    *,
    refresh_build: bool = False,
    auto_reap: bool = False,
    runner_checks: bool = False,
) -> Verb:
    """A verb that is a front for a gate subcommand."""
    return Verb(
        name=name,
        group="operator",
        summary=summary,
        handler=run_gate,
        gate_args=gate_args,
        refresh_build=refresh_build,
        auto_reap=auto_reap,
        runner_checks=runner_checks,
    )


def _help(ctx: Context) -> int:
    """`help` renders from the table it is itself an entry in — which is what
    makes the README's byte-for-byte comparison against it worth having."""
    ui.out(ui.help_text(ctx.verbs, ctx.groups).rstrip("\n"))
    return 0


VERBS: tuple[Verb, ...] = (
    Verb(
        "setup",
        "operator",
        "build, install and verify — the one command a new install needs",
        operator.setup,
        needs_toolchain=True,
        auto_reap=True,
    ),
    # `init` is `setup` with a conversation in front of it: choose a profile or
    # walk the catalog rule by rule, selftest the composition, then install.
    Verb(
        "init",
        "operator",
        "choose your rules, then install — the guided first run",
        init_verb.init,
        needs_toolchain=True,
        auto_reap=True,
    ),
    Verb(
        "upgrade",
        "operator",
        "rebuild, show what the defaults gained, reinstall (keeps your rules)",
        operator.upgrade,
        needs_toolchain=True,
        auto_reap=True,
    ),
    Verb(
        "uninstall",
        "operator",
        "remove every gate hook entry; --purge also drops binary and log",
        operator.uninstall,
    ),
    # `doctor`, `status` and `diff-defaults` compare an install against THIS
    # tree, so they rebuild zig-out first; the other passthroughs answer about
    # a command or a rule file and do not care.
    _gate(
        "status",
        "one screen: version, rules, overlay, log, what is switched off",
        ("status",),
        refresh_build=True,
    ),
    # `doctor` is the one verb that adds a check of its own, and the one
    # compiling verb that must NOT auto-reap: a diagnosis that tidied up first
    # could never show you the thing you ran it to find.
    _gate(
        "doctor",
        "diagnose the install, PASS/WARN/FAIL with a fix for each problem",
        ("doctor",),
        refresh_build=True,
        runner_checks=True,
    ),
    _gate(
        "diff-defaults",
        "what the shipped defaults gained since your rule file was seeded",
        ("diff-defaults",),
        refresh_build=True,
    ),
    # The rule file's lifecycle: the catalog against the live file, adoption
    # (with cases and sets, at the right first-match position), the shadow
    # promote/demote pair, and the authoring interview.
    Verb(
        "rules",
        "operator",
        "list, adopt, shadow, promote, remove or author rules",
        rules_verb.rules,
    ),
    _gate(
        "check",
        "ask the gate what it would do about one command",
        ("check",),
        auto_reap=True,
    ),
    _gate(
        "explain",
        "as `check`, plus the parsed and resolved command model",
        ("check", "--explain"),
    ),
    _gate("stats", "per-rule summary of the decision log", ("stats",)),
    _gate(
        "classes",
        "the built-in classes a rule may name, and their members",
        ("classes",),
    ),
    _gate(
        "events",
        "the 30 hook events: what each carries, and what it can refuse",
        ("events",),
    ),
    _gate("selftest", "run the rule file's own cases, then lint it", ("selftest",)),
    _gate("version", "the gate's version", ("version",)),
    Verb("help", "operator", "this message", _help),
    Verb(
        "build",
        "dev",
        "compile both binaries into zig-out/bin",
        dev.build,
        needs_toolchain=True,
        auto_reap=True,
    ),
    Verb(
        "test", "dev", "unit tests only", dev.test, needs_toolchain=True, auto_reap=True
    ),
    Verb(
        "selfcheck",
        "dev",
        "hookctl's own unit tests (no toolchain needed; folded into verify)",
        dev.selfcheck,
        args=ArgShape.none,
    ),
    Verb(
        "verify",
        "dev",
        "THE GATE: tests + both binaries + shlex parity + doc checks",
        dev.verify,
        args=ArgShape.none,
        needs_toolchain=True,
        auto_reap=True,
    ),
    Verb(
        "parity",
        "dev",
        "regenerate the shlex oracle and diff it against the checked-in copy",
        dev.parity,
        needs_toolchain=True,
        auto_reap=True,
    ),
    # The one verb whose honest duration is tens of minutes: it compiles the
    # binaries and every test module for three Linux targets.
    Verb(
        "cross",
        "dev",
        "compile the binaries and all tests for Linux (x86_64, aarch64) without running",
        dev.cross,
        needs_toolchain=True,
        timeout=CROSS_TIMEOUT,
        auto_reap=True,
    ),
    Verb(
        "fmt",
        "dev",
        "zig fmt over src/ and build.zig (add --check to only report)",
        dev.fmt,
        needs_toolchain=True,
    ),
    Verb(
        "audit",
        "dev",
        "every mechanical consistency check, with its counts",
        audit_verb.audit,
        args=ArgShape.none,
        auto_reap=True,
    ),
    Verb(
        "reap",
        "dev",
        "kill this checkout's stale build/test processes (--dry-run, --all)",
        reap_verb.reap,
    ),
)


def find(name: str) -> Verb | None:
    for verb in VERBS:
        if verb.name == name:
            return verb
    return None


def in_group(group: str) -> tuple[Verb, ...]:
    return tuple(v for v in VERBS if v.group == group)

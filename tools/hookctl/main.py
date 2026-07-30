"""Dispatch: argv in, exit code out.

This is the only module that reads the environment and the only one that builds
a `Context`. Everything a handler needs is resolved here, once, so that no verb
has to ask "am I on macOS", "is there a toolchain", "where is the claude dir"
for itself — and so that every one of those answers can be substituted in a
test by building a `Context` by hand.

Three guards live here rather than in the handlers, because they were previously
repeated in several of them and a verb that forgot one was a silent surprise:

  * a verb declared `ArgShape.none` refuses arguments *before* any work starts.
    `verify` and `audit` run the whole repository; a typo'd flag must not be
    ignored for two minutes and then reported as success.
  * a verb declared `needs_toolchain` explains the missing compiler in one
    place. There is no prebuilt binary to fall back on, so that message has to
    name what to install and which verbs still work without it.
  * a verb declared `auto_reap` gets a previous run's runaway cleared before it
    starts. Here rather than in the handlers for the strongest version of the
    usual reason: "the verbs that compile are bounded and do not compete with a
    stale spinner" has to be a property of dispatch, or it is a property of
    whichever handler was written most recently.

`--timeout` is resolved here too, and stripped from the arguments before
anything else looks at them — including the `ArgShape.none` guard, so that
`./hookctl verify --timeout 900` is a bounded verify and not a usage error, and
including the forwarding, because `zig build --timeout 900` is not a thing.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import argv as argv_mod
from . import discovery, proc, registry, ui
from .spec import (
    EX_INTERRUPTED,
    EX_UNAVAILABLE,
    EX_USAGE,
    MIN_TIMEOUT,
    TIMEOUT_ENV,
    TIMEOUT_FLAG,
    ArgShape,
    Context,
    Verb,
)
from .verbs.reap import auto_reap

#: Set to anything but empty or `0` to echo every child command line.
VERBOSE_ENV = "HOOKCTL_VERBOSE"


def verbose_from(environ) -> bool:
    return environ.get(VERBOSE_ENV, "") not in ("", "0")


def timeout_from(verb: Verb, args: Sequence[str], environ) -> float:
    """The wall-clock ceiling for this run: the flag, else the environment, else
    the verb's own default.

    A value that is not a positive number is refused rather than obeyed. In
    particular `--timeout 0` is refused: "unbounded" is spelled nowhere, because
    an unbounded child is the entire bug this budget exists for.
    """
    stated = argv_mod.flag_value(args, TIMEOUT_FLAG) or environ.get(TIMEOUT_ENV) or ""
    if not stated:
        return verb.timeout
    try:
        seconds = float(stated)
    except ValueError:
        ui.bad_timeout(stated, verb.timeout)
        return verb.timeout
    if seconds < MIN_TIMEOUT:
        ui.bad_timeout(stated, verb.timeout)
        return verb.timeout
    return seconds


def build_context(
    verb: Verb,
    args: Sequence[str] = (),
    *,
    root: Path | None = None,
    environ=None,
) -> Context:
    env = os.environ if environ is None else environ
    project_root = root or discovery.project_root()
    # The timeout is read from the arguments as typed and then removed from the
    # ones the handler sees: it is the runner's, and no child understands it.
    return Context(
        verb=verb,
        args=argv_mod.without_flag_value(args, TIMEOUT_FLAG),
        paths=discovery.paths(args, root=project_root, home=env.get("HOME")),
        toolchain=discovery.toolchain(),
        platform=discovery.platform(),
        process=proc.Runner(cwd=project_root, verbose=verbose_from(env)),
        verbs=registry.VERBS,
        groups=registry.GROUPS,
        timeout=timeout_from(verb, args, env),
    )


def blocked(ctx: Context) -> int | None:
    """Why this verb must not run, as its exit code — or None to go ahead.

    One function, so that "needs a compiler and there isn't one" is explained
    identically whichever verb hit it, and so the whole degradation path can be
    tested by handing this a context with `Toolchain.absent()`.
    """
    if ctx.verb.needs_toolchain and not ctx.toolchain.present:
        ui.no_toolchain(
            ctx.verb.name,
            tuple(v.name for v in ctx.verbs if v.passthrough),
            ctx.paths.installed_gate if ctx.paths.installed_gate.is_file() else None,
        )
        return EX_UNAVAILABLE
    return None


def main(argv: Sequence[str], *, environ=None, context=build_context) -> int:
    invocation = argv_mod.parse(argv)
    if invocation.empty:
        ui.usage(registry.VERBS, registry.GROUPS)
        return EX_USAGE
    if invocation.wants_help:
        ui.out(ui.help_text(registry.VERBS, registry.GROUPS).rstrip("\n"))
        return 0

    verb = registry.find(invocation.verb or "")
    if verb is None:
        ui.unknown_verb(invocation.verb or "")
        ui.usage(registry.VERBS, registry.GROUPS)
        return EX_USAGE

    # `--timeout` is the runner's own, so the guard is applied to what is LEFT
    # after it is taken out: `./hookctl verify --timeout 900` is a bounded verify
    # and not a usage error. `build_context` takes the arguments as typed and
    # does the same removal for what the handler sees.
    if verb.args is ArgShape.none and argv_mod.without_flag_value(
        invocation.args, TIMEOUT_FLAG
    ):
        ui.rejects_arguments(
            verb.name, argv_mod.without_flag_value(invocation.args, TIMEOUT_FLAG)[0]
        )
        return EX_USAGE

    ctx = context(verb, invocation.args, environ=environ)
    reason = blocked(ctx)
    if reason is not None:
        return reason
    # Before the handler, so that nothing this run compiles has to share a core
    # with something a previous run abandoned. Silent unless it killed something.
    auto_reap(ctx)
    # Through the context, so a test can substitute the whole world a handler
    # sees — including the handler.
    return ctx.verb.handler(ctx)


def run(argv: Sequence[str]) -> int:
    """`main`, with the two ways a runner is interrupted rather than wrong.

    Ctrl-C reports what a shell reports for a SIGINT'd child, and a closed pipe
    is not an error at all — `./hookctl audit | head` is a normal thing to do.
    """
    try:
        return main(argv)
    except KeyboardInterrupt:
        return EX_INTERRUPTED
    except BrokenPipeError:
        # Python would otherwise print "BrokenPipeError ignored" while flushing
        # at exit, so the interpreter is left no chance to flush.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        os._exit(0)

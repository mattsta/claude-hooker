"""Dispatch, and the two guards that used to be every handler's job.

The no-toolchain path is the interesting one. This project ships as source, so
"no compiler" is a state an operator can genuinely be in — and it is reached
here by handing dispatch a context built with `Toolchain.absent()`, not by
hiding `zig` from a subprocess.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import tempfile
import unittest

from .. import discovery, registry
from .. import main as main_mod
from ..spec import (
    CROSS_TIMEOUT,
    DEFAULT_BUILD_TIMEOUT,
    EX_UNAVAILABLE,
    EX_USAGE,
    ArgShape,
    Context,
    Toolchain,
)
from . import support


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


class Recorder:
    """A handler that remembers the context it was given, or was never called."""

    def __init__(self, code: int = 0):
        self.contexts: list[Context] = []
        self.code = code

    def __call__(self, ctx: Context) -> int:
        self.contexts.append(ctx)
        return self.code

    @property
    def ran(self) -> bool:
        return bool(self.contexts)


def dispatch(
    argv,
    *,
    toolchain: Toolchain = support.ZIG,
    handler: Recorder | None = None,
    paths=None,
):
    """`main`, with the world substituted: the handler records, and the
    toolchain is whatever the case under test needs it to be."""
    recorder = handler or Recorder()

    def factory(verb, args, *, environ=None):
        return support.context(
            dataclasses.replace(verb, handler=recorder),
            args,
            toolchain=toolchain,
            paths=paths,
        )

    with captured() as (out, err):
        code = main_mod.main(argv, context=factory)
    return code, out.getvalue(), err.getvalue(), recorder


class TestUsage(unittest.TestCase):
    def test_no_verb_at_all_is_a_usage_error(self):
        with captured() as (out, err):
            code = main_mod.main([])
        self.assertEqual(EX_USAGE, code)
        # The verb list goes to stderr for a usage error, so a piped run's
        # stdout stays the answer.
        self.assertIn("usage: ./hookctl <verb>", err.getvalue())
        self.assertEqual("", out.getvalue())

    def test_an_unknown_verb_is_named_and_exits_64(self):
        with captured() as (out, err):
            code = main_mod.main(["docter"])
        self.assertEqual(EX_USAGE, code)
        self.assertIn("unknown verb 'docter'", err.getvalue())
        self.assertIn("usage: ./hookctl <verb>", err.getvalue())
        self.assertEqual("", out.getvalue())

    def test_help_goes_to_stdout_and_exits_zero(self):
        for spelling in ("-h", "--help"):
            with captured() as (out, err):
                code = main_mod.main([spelling])
            self.assertEqual(0, code, spelling)
            self.assertIn("operator verbs", out.getvalue())
            self.assertEqual("", err.getvalue())

    def test_the_help_verb_prints_what_the_flag_prints(self):
        code, out, _, _ = dispatch(["--help"])
        self.assertEqual(0, code)
        with captured() as (verb_out, _):
            main_mod.main(["help"])
        self.assertEqual(out, verb_out.getvalue())


class TestArgumentGuard(unittest.TestCase):
    def test_a_verb_that_takes_nothing_refuses_arguments_before_working(self):
        for name in (v.name for v in registry.VERBS if v.args is ArgShape.none):
            code, out, err, recorder = dispatch([name, "--oops"])
            self.assertEqual(EX_USAGE, code, name)
            self.assertIn(f"`{name}` takes no arguments (got --oops)", err)
            self.assertFalse(
                recorder.ran, f"{name} started working before rejecting the argument"
            )
            self.assertEqual("", out, name)

    def test_a_forwarding_verb_passes_everything_through(self):
        code, _, _, recorder = dispatch(["check", "--tool", "Bash", "--", "-rf"])
        self.assertEqual(0, code)
        self.assertEqual(("--tool", "Bash", "--", "-rf"), recorder.contexts[0].args)


class TestToolchainGuard(unittest.TestCase):
    def test_a_build_verb_degrades_with_the_whole_story(self):
        code, out, err, recorder = dispatch(["build"], toolchain=Toolchain.absent())
        self.assertEqual(EX_UNAVAILABLE, code)
        self.assertFalse(recorder.ran, "the handler must not run without a compiler")
        self.assertIn("`build` needs the Zig compiler", err)
        self.assertIn("install Zig 0.16.0 or newer", err)
        self.assertIn("there are no prebuilt binaries", err)
        # With nothing installed either, it says so rather than listing verbs
        # that would also fail.
        self.assertIn("no installed gate was found either", err)
        self.assertEqual("", out)

    def test_with_a_gate_installed_it_names_the_verbs_that_still_work(self):
        with tempfile.TemporaryDirectory(prefix="hookctl-degrade-") as tmp:
            paths = discovery.paths(["--claude-dir", tmp], root=support.project_root())
            support.executable(paths.installed_gate)
            _, _, err, _ = dispatch(
                ["build"], toolchain=Toolchain.absent(), paths=paths
            )
        self.assertIn("an installed gate was found at", err)
        # Every passthrough verb, and nothing that needs a compiler.
        for name in ("doctor", "status", "check", "version"):
            self.assertIn(name, err)
        self.assertNotIn(" fmt", err)

    def test_every_toolchain_verb_degrades_the_same_way(self):
        for verb in (v for v in registry.VERBS if v.needs_toolchain):
            code, _, err, recorder = dispatch([verb.name], toolchain=Toolchain.absent())
            self.assertEqual(EX_UNAVAILABLE, code, verb.name)
            self.assertFalse(recorder.ran, verb.name)
            self.assertIn(f"`{verb.name}` needs the Zig compiler", err)

    def test_with_a_compiler_the_handler_runs_and_sees_it(self):
        code, _, err, recorder = dispatch(["build"])
        self.assertEqual(0, code)
        self.assertTrue(recorder.contexts[0].toolchain.present)
        self.assertNotIn("needs the Zig compiler", err)

    def test_a_verb_that_does_not_need_a_compiler_still_runs_without_one(self):
        # `audit` degrades instead of refusing: "what does this machine's policy
        # actually assert" is answerable on a machine that cannot compile.
        code, _, _, recorder = dispatch(["audit"], toolchain=Toolchain.absent())
        self.assertEqual(0, code)
        self.assertTrue(recorder.ran)
        self.assertFalse(recorder.contexts[0].toolchain.present)

    def test_the_exit_code_is_the_handlers(self):
        code, _, _, _ = dispatch(["doctor"], handler=Recorder(code=2))
        self.assertEqual(2, code)


class TestTimeoutResolution(unittest.TestCase):
    """`--timeout`, the environment variable, and the verb's own default.

    Resolved in one place so that no handler has to read the environment to find
    out how long it is allowed to take — and so that "every child is bounded" is
    a property of dispatch rather than of each handler's author.
    """

    def resolve(self, verb_name, args=(), environ=None):
        with captured():
            return main_mod.timeout_from(registry.find(verb_name), args, environ or {})

    def test_the_default_is_the_verbs_own(self):
        self.assertEqual(DEFAULT_BUILD_TIMEOUT, self.resolve("test"))
        self.assertEqual(CROSS_TIMEOUT, self.resolve("cross"))

    def test_the_flag_wins_in_both_spellings(self):
        self.assertEqual(5.0, self.resolve("test", ["--timeout", "5"]))
        self.assertEqual(5.5, self.resolve("test", ["--timeout=5.5"]))

    def test_the_environment_is_the_fallback_and_the_flag_beats_it(self):
        self.assertEqual(90.0, self.resolve("test", [], {"HOOKCTL_TIMEOUT": "90"}))
        self.assertEqual(
            5.0, self.resolve("test", ["--timeout", "5"], {"HOOKCTL_TIMEOUT": "90"})
        )

    def test_a_value_that_is_not_a_positive_number_is_refused_out_loud(self):
        for bad in ("nonsense", "0", "-1", "0.5"):
            with captured() as (_, err):
                seconds = main_mod.timeout_from(
                    registry.find("test"), ["--timeout", bad], {}
                )
            self.assertEqual(DEFAULT_BUILD_TIMEOUT, seconds, bad)
            # Said out loud: a run the operator believes is bounded and is not is
            # worse than one they know is not. `--timeout 0` in particular must
            # not be a spelling of "unbounded".
            self.assertIn("is not a number of seconds", err.getvalue(), bad)

    def test_the_flag_reaches_the_context_and_never_reaches_a_child(self):
        ctx = main_mod.build_context(
            registry.find("test"), ["--timeout", "5", "extra"], environ={}
        )
        self.assertEqual(5.0, ctx.timeout)
        self.assertEqual(("extra",), ctx.args, "`zig build --timeout 5` is not a thing")

    def test_a_verb_that_takes_no_arguments_can_still_be_bounded(self):
        # The guard runs on what is LEFT after `--timeout` is taken out, or
        # `./hookctl verify --timeout 900` would be a usage error.
        code, _, err, recorder = dispatch(["verify", "--timeout", "900"])
        self.assertEqual(0, code, err)
        self.assertTrue(recorder.ran)
        code, _, err, recorder = dispatch(["verify", "--timeout", "900", "--oops"])
        self.assertEqual(EX_USAGE, code)
        self.assertIn("takes no arguments (got --oops)", err)


class TestContext(unittest.TestCase):
    def test_the_handler_receives_the_resolved_world(self):
        verb = registry.find("doctor")
        ctx = main_mod.build_context(
            verb, ["--claude-dir", "/sb"], environ={"HOME": "/home/op"}
        )
        self.assertEqual(verb, ctx.verb)
        self.assertEqual(("--claude-dir", "/sb"), ctx.args)
        self.assertEqual("/sb", str(ctx.paths.claude_dir))
        self.assertEqual(registry.VERBS, ctx.verbs)
        self.assertEqual(registry.GROUPS, ctx.groups)

    def test_home_comes_from_the_environment_it_was_handed(self):
        ctx = main_mod.build_context(
            registry.find("status"), [], environ={"HOME": "/home/op"}
        )
        self.assertEqual("/home/op/.claude", str(ctx.paths.claude_dir))

    def test_verbose_is_off_unless_asked_for(self):
        self.assertFalse(main_mod.verbose_from({}))
        self.assertFalse(main_mod.verbose_from({"HOOKCTL_VERBOSE": ""}))
        self.assertFalse(main_mod.verbose_from({"HOOKCTL_VERBOSE": "0"}))
        self.assertTrue(main_mod.verbose_from({"HOOKCTL_VERBOSE": "1"}))
        self.assertTrue(main_mod.verbose_from({"HOOKCTL_VERBOSE": "yes"}))

    def test_blocked_is_the_only_gate_and_it_is_pure(self):
        self.assertIsNone(main_mod.blocked(support.context("build")))
        with captured():
            self.assertEqual(
                EX_UNAVAILABLE,
                main_mod.blocked(
                    support.context("build", toolchain=Toolchain.absent())
                ),
            )


if __name__ == "__main__":
    unittest.main()

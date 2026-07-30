"""The verbs that change a machine: `setup`, `upgrade`, `uninstall`.

These are the three that write, so they are the three that say what they are
about to do, in named sections, before and while they do it. The actual writing
is the installer's — `claude-hooker-install` runs its own selftest of the embedded
defaults, backs up `settings.json`, and verifies every artifact by reading it
back — so what these handlers own is the ORDER: build the binaries, then let the
installer place them, then report what the OS thinks of the result.

That last part is new and is the reason `setup` prints a signature section on
macOS. The installer signs and verifies; this reads the answer back out of
`codesign` independently and puts it where the operator is already looking. A
gate the loader kills fails OPEN and says nothing at all, so "fine" is worth a
line of output.
"""

from __future__ import annotations

from .. import argv as argv_mod
from .. import signing, ui
from ..proc import zig_build
from ..spec import EX_UNAVAILABLE, Context, RunMode

#: The build every verb here does. One mode, so zig-out/bin holds the same
#: bytes `setup` installs and "the built gate differs from the installed one"
#: means something when it is said.
RELEASE = "--release"


def build_release(ctx: Context) -> int:
    ui.section("build")
    result = zig_build(ctx.process, RELEASE, mode=RunMode.inherit, timeout=ctx.timeout)
    if result.timed_out:
        ui.note(
            f"the build was still running after {result.duration:.0f}s and its process group was killed."
        )
        ui.note("  " + result.first_error_line())
        return result.code
    if not result.ok:
        return result.code
    ui.out(
        f"{ctx.paths.display(ctx.paths.built_gate)}, {ctx.paths.display(ctx.paths.built_installer)} (release)"
    )
    return 0


def run_installer(ctx: Context, args: tuple[str, ...]) -> int:
    return ctx.process.run(
        (
            ctx.paths.display(ctx.paths.built_installer),
            "--gate",
            ctx.paths.display(ctx.paths.built_gate),
            *args,
        ),
        mode=RunMode.inherit,
        timeout=ctx.timeout,
    ).code


def report_signature(ctx: Context, args: tuple[str, ...]) -> None:
    """What `codesign` says about the gate that was just installed.

    Skipped for a dry run — there is nothing on disk to ask about — and a
    complete no-op off macOS, where `signing.probe` spawns nothing and reports
    `not_applicable`.
    """
    if argv_mod.has_flag(args, "--dry-run"):
        return
    # `ctx.paths` already reflects `--claude-dir`: the layout is resolved once,
    # in one place, rather than re-derived here from the same arguments.
    report = signing.probe(ctx.process, ctx.paths.installed_gate, ctx.platform)
    lines = signing.summary_lines(report)
    if not lines:
        return
    ui.out()
    ui.section("signature")
    for line in lines:
        ui.out(line)


def setup(ctx: Context) -> int:
    args = argv_mod.absolutize(ctx.args)
    code = build_release(ctx)
    if code:
        return code
    ui.out()
    ui.section("install")
    # The installer runs its own selftest of the embedded defaults first and
    # verifies every artifact by reading it back, so there is nothing for this
    # to re-check afterwards.
    code = run_installer(ctx, args)
    if code == 0:
        report_signature(ctx, args)
    return code


def upgrade(ctx: Context) -> int:
    args = argv_mod.absolutize(ctx.args)
    forcing = argv_mod.has_flag(args, "--force-rules")
    code = build_release(ctx)
    if code:
        return code

    ui.out()
    ui.section("what the shipped defaults gained")
    # `diff-defaults` takes the install and nothing else `upgrade` was given
    # (`--force-rules` and `--dry-run` are the installer's).
    ctx.process.run(
        (
            ctx.paths.display(ctx.paths.built_gate),
            "diff-defaults",
            *argv_mod.flag_only(args),
        ),
        mode=RunMode.inherit,
        timeout=ctx.timeout,
    )
    if forcing:
        ui.out(
            "\n--force-rules: your rule file WILL be overwritten with the shipped defaults."
        )
    else:
        ui.out(
            "\nYour rule file is not touched. Adopt anything above by editing it; rule"
        )
        ui.out("edits are live on the next tool call, with no reinstall.")

    ui.out()
    ui.section("reinstall the binary")
    code = run_installer(ctx, args)
    if code == 0:
        report_signature(ctx, args)
    return code


def uninstall(ctx: Context) -> int:
    args = argv_mod.absolutize(ctx.args)
    if not ctx.paths.built_installer.is_file():
        # The installer is not copied into the claude dir, so uninstalling
        # needs the one in zig-out — build it if it is not there.
        if not ctx.toolchain.present:
            ui.no_toolchain(
                ctx.verb.name,
                tuple(v.name for v in ctx.verbs if v.passthrough),
                ctx.paths.installed_gate
                if ctx.paths.installed_gate.is_file()
                else None,
            )
            return EX_UNAVAILABLE
        result = zig_build(
            ctx.process, RELEASE, mode=RunMode.quiet, timeout=ctx.timeout
        )
        if not result.ok:
            return result.code
    return ctx.process.run(
        (ctx.paths.display(ctx.paths.built_installer), "--uninstall", *args),
        mode=RunMode.inherit,
        timeout=ctx.timeout,
    ).code

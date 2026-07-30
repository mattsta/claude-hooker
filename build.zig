const std = @import("std");

/// Every module that carries tests. One list, used by `test` and by `cross`, so
/// a new module cannot be added to one and forgotten in the other.
const test_modules = .{ "shell", "classes", "resolve", "rules", "protocol", "decision_log", "cli", "install" };

/// The platforms `zig build cross` compiles for.
///
/// This code is POSIX-only and was written on macOS, while the machines it runs
/// on are mostly Linux. Nothing in `src/` is OS-conditional — no `@import
/// ("builtin")`, no libc — so a compile for these is cheap and catches the whole
/// class of "a std API that only exists on Darwin". It is not a substitute for
/// running the suite on Linux, which CI does; it is what makes a Linux break
/// findable from a laptop before the push.
const cross_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
    // musl as well as glibc: a static build is how this would land in a slim
    // image, and it exercises a different libc surface.
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    // The gate: minimal, fast-startup PreToolUse permission gate.
    const gate = b.addExecutable(.{
        .name = "claude-hooker-gate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(gate);

    // The installer: wires gate + rules + settings.json.
    const installer = b.addExecutable(.{
        .name = "claude-hooker-install",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/install.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(installer);

    // `zig build test` — unit tests for matching, protocol, log, CLI, and the
    // installer's settings surgery.
    const test_step = b.step("test", "Run unit tests");
    inline for (test_modules) |name| {
        const t = b.addTest(.{ .root_module = testModule(b, name, target, optimize) });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // `zig build cross` — compile everything for Linux without running it.
    //
    // Depending on a compile step rather than a run step is the whole point: a
    // Linux binary cannot execute on the machine that is most likely to be
    // writing this code, but it can be *compiled*, and a std API that does not
    // exist on Linux fails there. The test modules are compiled too, because
    // test-only code is only analyzed in a test build and is exactly where a
    // Darwin-only assumption hides.
    const cross_step = b.step("cross", "Compile the binaries and every test module for Linux (x86_64, aarch64) without running them");
    for (cross_targets) |query| {
        const cross_target = b.resolveTargetQuery(query);
        inline for (.{ "main", "install" }) |name| {
            const exe = b.addExecutable(.{
                .name = "claude-hook-" ++ name ++ "-cross",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/" ++ name ++ ".zig"),
                    .target = cross_target,
                    .optimize = optimize,
                }),
            });
            cross_step.dependOn(&exe.step);
        }
        inline for (test_modules) |name| {
            const t = b.addTest(.{ .root_module = testModule(b, name, cross_target, optimize) });
            cross_step.dependOn(&t.step);
        }
    }

    // `zig build parity` — regenerate the shell lexer's shlex oracle from the
    // corpus and prove the checked-in copy still matches.
    //
    // The Zig side of parity needs no Python: `src/shell.zig` asserts against
    // the checked-in `shell-oracle.jsonl`, and fails if the corpus grew
    // without it. This step is what proves the oracle itself is not stale —
    // that the numbers in it are still what Python's shlex actually says.
    // It joins `check` when a python3 is on PATH and is silently absent when
    // one is not, because a Zig project's one-command gate must not stop
    // working on a machine without an interpreter.
    //
    // That tolerance has a cost worth naming: on a machine with no `python3`,
    // `zig build check` is green having never run the oracle. `./hookctl verify`
    // therefore runs `parity` as its own step rather than relying on `check` to
    // include it — hookctl is itself Python, so an interpreter demonstrably
    // exists whenever it is the thing asking, and a skip there would be a lie
    // rather than a concession.
    const parity_step = b.step("parity", "Regenerate the shlex oracle and diff it against the checked-in copy");
    const python = b.findProgram(&.{"python3"}, &.{}) catch null;
    // `diff` is POSIX and present on both platforms this is tested on, but a
    // slim container image is a real place to run a build, and "cannot find
    // diff" beats an opaque spawn failure inside a step named "parity".
    const differ = b.findProgram(&.{"diff"}, &.{}) catch null;

    // `zig build check` — the one-command gate: every test passes AND both
    // binaries compile. Either half alone can be green while the other is
    // broken, which is exactly the state this step exists to make impossible
    // to miss.
    const check_step = b.step("check", "Run the unit tests, the shlex parity oracle, and build both binaries");
    check_step.dependOn(test_step);
    check_step.dependOn(&gate.step);
    check_step.dependOn(&installer.step);
    // ...and leaves them in zig-out/bin, not merely compiled into the cache.
    //
    // This is load-bearing for the documentation checks, which have to
    // interrogate a real binary — `doctor`'s check ids, `status`'s labels — and
    // pick one by looking for a built gate first and an INSTALLED gate second. In
    // a fresh clone nothing is built yet, so without this they would fall back to
    // whatever release happens to be installed on the machine and validate this
    // tree's README against a different binary. On a machine with an older gate
    // installed that is a confusing failure; on one with no gate at all it is a
    // failure with nothing to check. Either way the answer must come from the
    // tree being checked.
    check_step.dependOn(b.getInstallStep());

    if (python != null and differ != null) {
        const regen = b.addSystemCommand(&.{python.?});
        regen.addFileArg(b.path("tests/shlex_oracle.py"));
        regen.addFileArg(b.path("src/testdata/shell-corpus.txt"));
        // The oracle's own output is UTF-8 whatever the machine's locale says —
        // the corpus has Japanese and emoji in it, and `shlex` hands them back
        // unchanged. Without this, the script's stdout encoding is locale-derived
        // and the step dies on a `LC_ALL=C` runner instead of comparing anything.
        regen.setEnvironmentVariable("PYTHONUTF8", "1");
        const fresh = regen.captureStdOut(.{ .basename = "shell-oracle.jsonl" });

        const cmp = b.addSystemCommand(&.{ differ.?, "-u" });
        cmp.addFileArg(b.path("src/testdata/shell-oracle.jsonl"));
        cmp.addFileArg(fresh);
        cmp.expectExitCode(0);
        cmp.setName("diff checked-in oracle against a fresh shlex run");

        parity_step.dependOn(&cmp.step);
        check_step.dependOn(parity_step);
    } else {
        parity_step.dependOn(&b.addFail(b.fmt(
            "parity needs {s} on PATH: it regenerates src/testdata/shell-oracle.jsonl by running " ++
                "tests/shlex_oracle.py and diffing the result against the checked-in copy",
            .{if (python == null) "python3" else "diff"},
        )).step);
    }

    // `zig build setup [-- --dry-run ...]` — build everything, then run the
    // installer against the freshly built gate.
    const setup = b.addRunArtifact(installer);
    setup.addArg("--gate");
    setup.addFileArg(gate.getEmittedBin());
    if (b.args) |args| setup.addArgs(args);
    setup.has_side_effects = true;
    const setup_step = b.step("setup", "Install gate + rules + settings.json wiring (use -- --dry-run to preview)");
    setup_step.dependOn(&setup.step);
}

/// One module with tests in it, wired the same way for every target.
fn testModule(
    b: *std.Build,
    comptime name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/" ++ name ++ ".zig"),
        .target = target,
        .optimize = optimize,
    });
    // The documentation is test input. `RULES_COOKBOOK.md` claims that every
    // rule JSON on the page is byte-identical to the fixture, and a claim like
    // that is worth exactly as much as the check behind it — so the page itself
    // is embedded and compared. It lives outside `src/`, which is why it arrives
    // as a named import rather than a relative path.
    if (comptime std.mem.eql(u8, name, "cli") or std.mem.eql(u8, name, "install")) {
        mod.addAnonymousImport("cookbook_md", .{ .root_source_file = b.path("RULES_COOKBOOK.md") });
    }
    return mod;
}

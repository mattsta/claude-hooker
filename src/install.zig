//! claude-hooker-install — one-shot installer for the hook gate.
//!
//! What it does (idempotently):
//!   0. Runs the EMBEDDED default rules through the same selftest machinery
//!      the operator's `claude-hooker-gate selftest` uses, and refuses to
//!      install anything if they fail. A shipped default that does not pass
//!      its own cases is a bug that must never reach a machine.
//!   1. Copies the built `claude-hooker-gate` binary into <claude-dir>/hooks/,
//!      and on macOS makes sure the OS will actually run it: the copy's code
//!      signature is verified, and re-signed ad-hoc if it does not validate. A
//!      Mach-O the loader kills is a hook that fails OPEN and says nothing (see
//!      "the code signature" below). No-op on every other platform.
//!   2. Seeds <claude-dir>/hook-rules.json from the embedded default rules
//!      when absent (never overwrites without --force-rules).
//!   3. Merges a hook entry pointing at the installed gate into
//!      <claude-dir>/settings.json — one per hook event the live rules actually
//!      use, and only those — after writing a timestamped backup. Entries that
//!      are already correct are left untouched, and an entry for an event the
//!      rules no longer use is removed.
//!   4. Verifies what it just did — one line per artifact, the signature
//!      included — by reading the results back rather than trusting the writes.
//!
//! ## Why the wiring is derived from the rules
//!
//! The harness only invokes a hook for the events (and, within a tool event,
//! the tool names) that `settings.json` names. So the wiring is not a constant:
//! it is `cli.wiringPlan(rule_set)`, computed from the policy that will actually
//! be live. That closes a real gap and prevents its multi-event version:
//!
//!   - the single-event installer wired `PreToolUse` with `"matcher": "Bash"`,
//!     while the shipped defaults include a `Write` rule and an any-tool rule.
//!     Two shipped rules could never fire on a real install, and nothing said
//!     so.
//!   - a rule file with `Stop` rules and no `hooks.Stop` entry is the same fault
//!     one level up. `doctor` now WARNs about it, and this is what fixes it.
//!
//! `--uninstall` reverses step 3 only: our entries (matched by the installed
//! gate's command path, under every event key) are removed, again after a
//! backup. Rules, log, and binary stay. `--purge` additionally removes the
//! binary and the decision log — but NEVER the rule file, which is the
//! operator's own policy document and is theirs to delete or keep.
//!
//! <claude-dir> defaults to ~/.claude; override with --claude-dir for a
//! sandboxed test install. --dry-run prints the plan without writing.
//! Note: settings.json is rewritten via a JSON round-trip, so key order and
//! formatting may change (the backup preserves the original bytes).

const std = @import("std");
const rules = @import("rules.zig");
const cli = @import("cli.zig");

/// The rules to seed a fresh machine with. Owned by `cli` because
/// `diff-defaults` needs the very same bytes to say what an operator's edited
/// copy is missing; two embeds of one file is two things that can drift.
const default_rules_json = cli.DEFAULT_RULES_JSON;

const GATE_BINARY_NAME = cli.GATE_BINARY_NAME;

/// Where everything lives, derived once from <claude-dir>. Shared with the
/// operator CLI's `doctor`/`status`/`diff-defaults`, which have to look for an
/// install in exactly the places this one writes it.
const Layout = cli.Layout;

const Options = struct {
    dry_run: bool = false,
    force_rules: bool = false,
    uninstall: bool = false,
    purge: bool = false,
    gate_path: ?[]const u8 = null,
    claude_dir: ?[]const u8 = null,
};

const usage =
    \\usage: claude-hooker-install --gate <path-to-claude-hooker-gate>
    \\                           [--claude-dir <dir>] [--dry-run] [--force-rules]
    \\       claude-hooker-install --uninstall [--purge]
    \\                           [--claude-dir <dir>] [--dry-run]
    \\
    \\  --force-rules  overwrite an existing hook-rules.json with the default
    \\  --uninstall    remove our PreToolUse entry from settings.json
    \\  --purge        with --uninstall, also remove the gate binary and the
    \\                 decision log (the rule file is never removed)
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    // One-shot process: every allocation (including the parsed settings JSON
    // tree we mutate) comes from the process arena, so there is exactly one
    // allocator in play and cleanup is automatic at exit.
    const gpa = init.arena.allocator();

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buf);
    const stderr = &stderr_writer.interface;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var opts = Options{};
    var args_it = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_it.next(); // program name
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dry-run")) {
            opts.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--force-rules")) {
            opts.force_rules = true;
        } else if (std.mem.eql(u8, arg, "--uninstall")) {
            opts.uninstall = true;
        } else if (std.mem.eql(u8, arg, "--purge")) {
            // Purging is a stronger uninstall, never an install-time action.
            opts.purge = true;
            opts.uninstall = true;
        } else if (std.mem.eql(u8, arg, "--gate")) {
            opts.gate_path = args_it.next() orelse return failUsage(stderr, "--gate requires a path");
        } else if (std.mem.eql(u8, arg, "--claude-dir")) {
            opts.claude_dir = args_it.next() orelse return failUsage(stderr, "--claude-dir requires a path");
        } else {
            return failUsage(stderr, "unknown argument");
        }
    }

    const claude_dir = opts.claude_dir orelse blk: {
        const home = init.environ_map.get("HOME") orelse {
            return failUsage(stderr, "HOME is not set and --claude-dir was not given");
        };
        break :blk try std.fs.path.join(gpa, &.{ home, ".claude" });
    };
    const layout = try Layout.init(gpa, claude_dir);

    if (opts.uninstall) {
        try runUninstall(io, gpa, stdout, layout, opts);
    } else {
        try runInstall(io, gpa, stdout, stderr, layout, opts);
    }
    try stdout.flush();
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

fn runInstall(
    io: std.Io,
    gpa: std.mem.Allocator,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    layout: Layout,
    opts: Options,
) !void {
    const gate_source = opts.gate_path orelse return failUsage(stderr, "--gate is required");

    // ---- 0. the shipped default must pass its own tests ----
    // Before anything is read from disk and long before anything is written:
    // if the rules this binary carries are broken, there is no version of
    // "install" that is the right thing to do.
    const check = try checkConfig(gpa, default_rules_json);
    if (!check.ok) {
        try stderr.writeAll("claude-hooker-install: the EMBEDDED default rules fail their own selftest.\n");
        try stderr.writeAll("This binary is broken; nothing was installed.\n\n");
        try stderr.writeAll(check.report);
        try stderr.flush();
        return error.DefaultRulesSelftestFailed;
    }
    try stdout.print("selftest: embedded default rules OK ({d} cases, {d} lint warning(s))\n", .{
        check.cases,
        check.warnings,
    });

    const rules_exists = fileExists(io, layout.rules_dest);
    const settings = try loadSettings(io, gpa, layout.settings_path);

    // The rules that will be live once this install finishes — the existing
    // file when one is being kept, the embedded defaults when one is being
    // seeded or overwritten. The wiring plan is computed from THOSE, because
    // wiring an event the live policy has no rules for (or failing to wire one
    // it does) is the failure this derivation exists to prevent.
    const live_rules = try liveRules(io, gpa, layout.rules_dest, rules_exists and !opts.force_rules);
    const plan = try cli.wiringPlan(gpa, live_rules);
    const change = try planWiring(gpa, settings, layout.gate_dest, plan);

    // ---- report the plan ----
    try stdout.print("claude-hooker-install plan:\n", .{});
    try stdout.print("  gate    : {s} -> {s}\n", .{ gate_source, layout.gate_dest });
    try stdout.print("  rules   : {s} ({s})\n", .{
        layout.rules_dest,
        if (!rules_exists) "seed default" else if (opts.force_rules) "OVERWRITE with default" else "keep existing",
    });
    try stdout.print("  settings: {s} ({s})\n", .{
        layout.settings_path,
        if (change.isEmpty()) "already wired for every event the rules use, no change" else "rewrite hook entries (backup first)",
    });
    for (plan) |entry| {
        try stdout.print("    {s: <20} {s: <10} {d} rule(s){s}\n", .{
            entry.event.name(),
            entry.matcher orelse "(all)",
            entry.rules,
            if (cli.wiredExactly(change.existing, entry, layout.gate_dest))
                "  already wired"
            else if (cli.wiredFor(change.existing, entry.event, layout.gate_dest))
                "  REWIRE (matcher changed)"
            else
                "  ADD",
        });
    }
    // Only the events leaving the file entirely. An event being REWIRED is also
    // in `change.stale` — the removal is how the old entry makes way for the new
    // one — and listing it twice would read as a contradiction.
    for (change.stale) |event| {
        const rewired = for (plan) |p| {
            if (p.event == event) break true;
        } else false;
        if (rewired) continue;
        try stdout.print("    {s: <20} {s: <10} 0 rule(s)  REMOVE\n", .{ event.name(), "-" });
    }
    if (opts.dry_run) {
        try stdout.print("dry run: nothing written.\n", .{});
        return;
    }

    const cwd = std.Io.Dir.cwd();

    // ---- 1. install the gate binary (exec bit copied from the source) ----
    try cwd.copyFile(gate_source, cwd, layout.gate_dest, io, .{ .make_path = true });

    // ---- 1a. make sure the OS will actually run it ----
    const signature = try ensureSigned(io, gpa, stdout, layout.gate_dest);

    // ---- 2. seed rules ----
    if (!rules_exists or opts.force_rules) {
        try writeFileAtomic(io, gpa, layout.rules_dest, default_rules_json);
    }

    // ---- 3. wire settings.json ----
    if (!change.isEmpty()) {
        if (try backup(io, gpa, layout.settings_path)) |path| {
            try stdout.print("  backup  : {s}\n", .{path});
        }
        const merged = try wireHooks(gpa, settings, layout.gate_dest, plan);
        try writeFileAtomic(io, gpa, layout.settings_path, merged);
    }

    // ---- 4. verify, by reading back ----
    if (!try verify(io, gpa, stdout, layout, signature, plan)) {
        // The `verify:` block IS the diagnosis, and returning an error skips
        // the flush at the end of `main` — so it is flushed here. An install
        // that failed and said nothing about why would be the worst of both.
        try stdout.flush();
        return error.VerificationFailed;
    }

    try stdout.print("done. Hooks are snapshotted at session start — takes effect in NEW Claude Code sessions.\n", .{});
}

/// The rule set the install will leave behind: the file on disk when one is
/// being kept, else the embedded defaults.
///
/// Best-effort on the existing file, deliberately. A rule document that no
/// longer parses is a problem `doctor` and `selftest` report loudly, and this
/// step's job is only to decide which events to wire — falling back to the
/// defaults' plan there wires `PreToolUse` and nothing exotic, which is strictly
/// better than refusing to install.
fn liveRules(
    io: std.Io,
    gpa: std.mem.Allocator,
    rules_path: []const u8,
    keep_existing: bool,
) !rules.RuleSet {
    if (keep_existing) {
        if (std.Io.Dir.cwd().readFileAlloc(io, rules_path, gpa, .limited(rules.MAX_CONFIG_BYTES))) |bytes| {
            if (rules.parse(gpa, bytes)) |loaded| {
                return loaded.ruleSet();
            } else |_| {}
        } else |_| {}
    }
    // Parsed leaky into the process arena: everything here borrows from the
    // embedded document, which has program lifetime.
    var loaded = try rules.parse(gpa, default_rules_json);
    return loaded.ruleSet();
}

/// What wiring `settings.json` needs: which of our entries are already correct,
/// and which have to go.
const WiringChange = struct {
    /// Every hook command already in the file, across every event key.
    existing: []const cli.HookEntry,
    /// Events whose entry of ours must be REMOVED: either the plan no longer
    /// names the event at all, or it does and the entry's matcher is not the one
    /// the plan calls for.
    ///
    /// Both cases are removals for the same reason — there is one code path for
    /// "take our entry out" — and both matter. Dropping an event whose rules are
    /// gone is what makes "wired for the events that have rules, and only those"
    /// true after a rule is deleted rather than only on a fresh install; and
    /// replacing a stale MATCHER is what stops a rule file that grew a `Write`
    /// rule from sitting behind a `Bash` matcher forever.
    stale: []const rules.Event,
    /// Events in the plan that are not correctly wired yet.
    missing: usize,

    fn isEmpty(self: WiringChange) bool {
        return self.missing == 0 and self.stale.len == 0;
    }
};

fn planWiring(
    gpa: std.mem.Allocator,
    settings: Settings,
    gate_dest: []const u8,
    plan: []const cli.WireEntry,
) !WiringChange {
    const existing: []const cli.HookEntry = if (settings.root) |root|
        try cli.hookEntries(gpa, root)
    else
        &.{};

    var stale: std.ArrayList(rules.Event) = .empty;
    var missing: usize = 0;
    for (plan) |entry| {
        if (cli.wiredExactly(existing, entry, gate_dest)) continue;
        missing += 1;
        // Present but with the wrong matcher: the old entry has to come out
        // before the right one goes in, or the file ends up with both.
        if (cli.wiredFor(existing, entry.event, gate_dest)) try stale.append(gpa, entry.event);
    }

    for (existing) |entry| {
        const event = entry.event orelse continue;
        if (!std.mem.eql(u8, entry.command, gate_dest)) continue;
        const planned = for (plan) |p| {
            if (p.event == event) break true;
        } else false;
        if (planned) continue;
        const already = for (stale.items) |s| {
            if (s == event) break true;
        } else false;
        if (!already) try stale.append(gpa, event);
    }

    return .{ .existing = existing, .stale = stale.items, .missing = missing };
}

// ---------------------------------------------------------------------------
// the code signature (macOS)
// ---------------------------------------------------------------------------
//
// On macOS a Mach-O whose code signature does not validate is killed by the
// kernel. A killed PreToolUse hook writes no decision envelope, and the hooks
// contract reads a missing answer as "proceed" — so a broken signature does not
// make this gate strict, it makes it silently ABSENT on every tool call. That
// is the only failure in this system with no output at all, which is why an
// install ends by asking the OS rather than by assuming.
//
// The signing itself is CONDITIONAL, and that is deliberate. Zig's linker
// already emits an `adhoc,linker-signed` binary, and `copyFile` preserves it,
// so the copy normally validates as it lands: re-signing anyway would rewrite
// the file and make the installed gate differ byte-for-byte from the one in
// `zig-out/bin`, which is an invariant the runner relies on ("the built gate is
// NOT the same binary as the installed one" would then fire on every single
// `doctor` run and mean nothing). So the copy is verified first, and signed only
// when it does not validate — which is exactly the case that would otherwise
// ship a binary the OS may kill.
//
// Everything below is a comptime no-op off macOS.

/// What happened about the signature, for the `verify:` block to report.
const SignatureOutcome = struct {
    facts: cli.SignatureFacts,
    /// Null when the copy already validated and nothing was re-signed.
    resigned: ?cli.Resign = null,
};

fn ensureSigned(
    io: std.Io,
    gpa: std.mem.Allocator,
    stdout: *std.Io.Writer,
    path: []const u8,
) !SignatureOutcome {
    if (!cli.signing_required) return .{ .facts = .{} };

    const first = cli.inspectSignature(io, gpa, path);
    if (first.state == .valid) return .{ .facts = first };

    // Loud on the way in: a binary this installer just wrote does not validate,
    // and the repair attempt is part of the transcript whether or not it works.
    try stdout.print("signature: the installed gate does not validate ({s}); re-signing ad-hoc\n", .{
        if (first.note.len > 0) first.note else @tagName(first.state),
    });
    const attempt = cli.resignAdhoc(io, gpa, path);
    switch (attempt) {
        .signed => try stdout.print("  {s} --force --sign - {s}\n", .{ cli.CODESIGN, path }),
        .failed => |why| try stdout.print("  {s} FAILED: {s}\n", .{ cli.CODESIGN, why }),
        .skipped => {},
    }
    return .{ .facts = cli.inspectSignature(io, gpa, path), .resigned = attempt };
}

/// One `verify:` line about the signature. Prints nothing at all on a platform
/// that does not police signatures, and returns false only when the binary is
/// one the OS may refuse to run.
fn verifySignature(stdout: *std.Io.Writer, sig: SignatureOutcome) !bool {
    const s = sig.facts;
    if (!s.applicable) return true;
    const repaired = if (sig.resigned != null) " (re-signed by this install)" else "";
    switch (s.state) {
        .valid => {
            if (!s.adhoc) {
                try stdout.print("  warn signature: {s} validates but is not ad-hoc ({s})\n", .{ s.path, s.form });
                return true;
            }
            try stdout.print("  ok   signature: {s} ({s}){s}\n", .{ s.path, s.form, repaired });
            return true;
        },
        .unsigned, .invalid => {
            try stdout.print("  FAIL signature: {s} {s}\n", .{
                s.path,
                if (s.state == .unsigned) "carries no code signature" else s.note,
            });
            try stdout.print("       macOS may SIGKILL it, and a killed gate fails OPEN: no decision, no log\n", .{});
            try stdout.print("       line, nothing enforced. Re-sign with `{s} --force --sign - {s}`.\n", .{ cli.CODESIGN, s.path });
            return false;
        },
        .unavailable => {
            // Not knowing is a warning, not a pass and not a failure: the
            // linker's own signature is probably intact, and a machine without
            // the command line tools must still be able to install.
            try stdout.print("  warn signature: {s} could not be checked ({s} did not answer: {s})\n", .{
                s.path,
                cli.CODESIGN,
                s.note,
            });
            try stdout.print("       install the Xcode command line tools to have this verified.\n", .{});
            return true;
        },
    }
}

/// Read every artifact back and say, one line each, whether it is what the
/// install claimed to produce. Returns false if any check failed.
///
/// Deliberately re-reads from disk rather than reporting what was written: a
/// successful `write` is not evidence that the file the gate will later load
/// parses, and the whole point of this step is to catch the difference.
fn verify(
    io: std.Io,
    gpa: std.mem.Allocator,
    stdout: *std.Io.Writer,
    layout: Layout,
    signature: SignatureOutcome,
    plan: []const cli.WireEntry,
) !bool {
    var all_ok = true;
    try stdout.print("verify:\n", .{});

    // gate: present and non-empty.
    if (std.Io.Dir.cwd().statFile(io, layout.gate_dest, .{})) |stat| {
        if (stat.size > 0) {
            try stdout.print("  ok   gate    : {s} ({d} bytes)\n", .{ layout.gate_dest, stat.size });
        } else {
            all_ok = false;
            try stdout.print("  FAIL gate    : {s} (empty file)\n", .{layout.gate_dest});
        }
    } else |err| {
        all_ok = false;
        try stdout.print("  FAIL gate    : {s} ({s})\n", .{ layout.gate_dest, @errorName(err) });
    }

    // signature: the OS's own answer about the file just written, asked right
    // after the file itself because "present and executable" is not the same
    // question as "will be allowed to run". Silent off macOS.
    if (!try verifySignature(stdout, signature)) all_ok = false;

    // rules: readable AND parseable by the same parser the gate uses.
    if (std.Io.Dir.cwd().readFileAlloc(io, layout.rules_dest, gpa, .limited(rules.MAX_CONFIG_BYTES))) |bytes| {
        if (rules.parse(gpa, bytes)) |loaded| {
            const rule_set = loaded.ruleSet();
            try stdout.print("  ok   rules   : {s} ({d} rules, {d} cases)\n", .{
                layout.rules_dest,
                rule_set.rules.len,
                rule_set.tests.len,
            });
        } else |err| {
            all_ok = false;
            try stdout.print("  FAIL rules   : {s} (invalid: {s})\n", .{ layout.rules_dest, @errorName(err) });
        }
    } else |err| {
        all_ok = false;
        try stdout.print("  FAIL rules   : {s} ({s})\n", .{ layout.rules_dest, @errorName(err) });
    }

    // settings: every planned event actually has our entry in the file on disk.
    // Per event, not "an entry exists": wiring five of six events and reporting
    // one green line is the failure this whole derivation exists to avoid.
    if (loadSettings(io, gpa, layout.settings_path)) |settings| {
        const entries = if (settings.root) |root| try cli.hookEntries(gpa, root) else &.{};
        var wired: usize = 0;
        for (plan) |entry| {
            // The MATCHER is verified too, not just the presence of a command:
            // an entry under the right event with the wrong matcher is a hook the
            // harness never invokes for the rules that needed widening.
            if (cli.wiredExactly(entries, entry, layout.gate_dest)) {
                wired += 1;
            } else {
                all_ok = false;
                try stdout.print("  FAIL settings: {s} (no {s} entry for the gate with matcher {s})\n", .{
                    layout.settings_path,
                    entry.event.name(),
                    entry.matcher orelse "(none)",
                });
            }
        }
        if (wired == plan.len) {
            try stdout.print("  ok   settings: {s} ({d} event(s) wired:", .{ layout.settings_path, wired });
            for (plan) |entry| try stdout.print(" {s}", .{entry.event.name()});
            try stdout.print(")\n", .{});
        }
    } else |err| {
        all_ok = false;
        try stdout.print("  FAIL settings: {s} ({s})\n", .{ layout.settings_path, @errorName(err) });
    }

    return all_ok;
}

// ---------------------------------------------------------------------------
// the embedded-config gate
// ---------------------------------------------------------------------------

/// The verdict on a rule document, plus the report an operator would read.
pub const ConfigCheck = struct {
    ok: bool,
    /// Selftest output in the same shape `claude-hooker-gate selftest` prints.
    report: []const u8,
    cases: usize,
    warnings: usize,
};

/// Run a rule document through the operator-facing selftest: parse it, run
/// its own cases, lint it.
///
/// Takes bytes rather than reading a file so the shipped default and a
/// deliberately-broken document are the same kind of input, and the install
/// gate can be exercised without a filesystem.
pub fn checkConfig(gpa: std.mem.Allocator, bytes: []const u8) !ConfigCheck {
    var out: std.Io.Writer.Allocating = .init(gpa);

    var loaded = rules.parse(gpa, bytes) catch |err| {
        try out.writer.print("rule document does not parse: {s}\n", .{@errorName(err)});
        return .{ .ok = false, .report = out.written(), .cases = 0, .warnings = 0 };
    };
    const rule_set = loaded.ruleSet();

    var suite = try cli.runSuite(gpa, rule_set);
    // The report is already written into `out` by the time this releases the
    // generated commands, so nothing returned points into the suite's arena.
    defer suite.deinit();
    const findings = try cli.lintWith(gpa, rule_set, loaded.set_uses);
    const code = try cli.writeSelftestReport(&out.writer, null, &suite, findings);
    const case_count = suite.total();

    return .{
        .ok = code == 0,
        .report = out.written(),
        .cases = case_count,
        .warnings = findings.len - cli.countErrors(findings),
    };
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

fn runUninstall(
    io: std.Io,
    gpa: std.mem.Allocator,
    stdout: *std.Io.Writer,
    layout: Layout,
    opts: Options,
) !void {
    const settings = try loadSettings(io, gpa, layout.settings_path);
    // Null: every event key, not a plan's worth. An uninstall takes the gate out
    // of the file entirely, whatever the rules happen to say today.
    const removal = try removeHookEntry(gpa, settings, layout.gate_dest, null);
    const log_path = try resolveLogPath(io, gpa, layout);

    try stdout.print("claude-hook-uninstall plan:\n", .{});
    try stdout.print("  settings: {s} ({s})\n", .{
        layout.settings_path,
        if (removal.removed == 0) "no gate entry, nothing to remove" else "remove every gate entry (backup first)",
    });
    try stdout.print("  gate    : {s} ({s})\n", .{ layout.gate_dest, if (opts.purge) "REMOVE" else "keep" });
    try stdout.print("  log     : {s} ({s})\n", .{ log_path, if (opts.purge) "REMOVE" else "keep" });
    try stdout.print("  rules   : {s} (keep — operator property, never removed)\n", .{layout.rules_dest});
    if (opts.dry_run) {
        try stdout.print("dry run: nothing written.\n", .{});
        return;
    }

    if (removal.json) |json| {
        if (try backup(io, gpa, layout.settings_path)) |path| {
            try stdout.print("  backup  : {s}\n", .{path});
        }
        try writeFileAtomic(io, gpa, layout.settings_path, json);
        try stdout.print("removed {d} gate entry/entries from {s}\n", .{ removal.removed, layout.settings_path });
    }

    if (opts.purge) {
        try removeIfPresent(io, stdout, layout.gate_dest, "gate");
        try removeIfPresent(io, stdout, log_path, "log");
        // The rotated generation is part of the log, not a separate artifact.
        const rotated = try std.fmt.allocPrint(gpa, "{s}.1", .{log_path});
        try removeIfPresent(io, stdout, rotated, "log.1");
    }

    // Say what is still on disk, so nobody has to guess what "uninstalled"
    // left behind.
    try stdout.print("remaining:\n", .{});
    try stdout.print("  rules   : {s}{s}\n", .{ layout.rules_dest, presence(fileExists(io, layout.rules_dest)) });
    try stdout.print("  log     : {s}{s}\n", .{ log_path, presence(fileExists(io, log_path)) });
    try stdout.print("  gate    : {s}{s}\n", .{ layout.gate_dest, presence(fileExists(io, layout.gate_dest)) });
    try stdout.print("  settings: {s}{s}\n", .{ layout.settings_path, presence(fileExists(io, layout.settings_path)) });
    try stdout.print("done. Existing Claude Code sessions keep the snapshotted hook until they restart.\n", .{});
}

fn presence(exists: bool) []const u8 {
    return if (exists) "" else " (absent)";
}

fn removeIfPresent(io: std.Io, stdout: *std.Io.Writer, path: []const u8, label: []const u8) !void {
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            try stdout.print("  warn {s}: could not remove {s} ({s})\n", .{ label, path, @errorName(err) });
            return;
        },
    };
    try stdout.print("  removed {s}: {s}\n", .{ label, path });
}

/// Where the decision log would be for this install: the rule file's
/// `logging.path` when it names one, else the default name beside the rules.
/// Reading the rule file is best-effort — a missing or broken policy document
/// must not stop an uninstall.
fn resolveLogPath(io: std.Io, gpa: std.mem.Allocator, layout: Layout) ![]const u8 {
    const configured: ?[]const u8 = blk: {
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, layout.rules_dest, gpa, .limited(rules.MAX_CONFIG_BYTES)) catch break :blk null;
        const loaded = rules.parse(gpa, bytes) catch break :blk null;
        break :blk loaded.ruleSet().logging.path;
    };
    if (configured) |path| {
        if (path.len > 0) return path;
    }
    return layout.log_default;
}

/// The settings document with our PreToolUse entry taken out, or a null
/// document when there was nothing of ours in it.
const Removal = struct {
    removed: usize,
    /// The rewritten document; null means "leave the file alone".
    json: ?[]const u8,

    const none: Removal = .{ .removed = 0, .json = null };
};

/// Remove every hook whose command is exactly `gate_dest`, under every event
/// key, and then any container the removal left empty.
///
/// Matching on the command path is what makes this OUR entry rather than "the
/// first hook": an operator's other gates, linters, and loggers live in the same
/// arrays and must survive untouched. Emptied containers are dropped so an
/// install/uninstall round-trip returns the file to what it was, rather than
/// leaving `"hooks": {"PreToolUse": []}` behind as a scar.
///
/// `only` restricts the removal to one set of events — that is how an install
/// unwires an event whose rules are gone without touching the ones it is about
/// to (re)wire. Null means every event, which is what `--uninstall` wants.
fn removeHookEntry(
    gpa: std.mem.Allocator,
    settings: Settings,
    gate_dest: []const u8,
    only: ?[]const rules.Event,
) !Removal {
    var root = settings.root orelse return .none;
    if (root != .object) return .none;

    var hooks_val = root.object.get("hooks") orelse return .none;
    if (hooks_val != .object) return .none;

    var removed: usize = 0;
    // The key list is COPIED, and each event's array is edited THROUGH A
    // POINTER rather than re-`put`. Both matter: `put` runs `getOrPut`, which
    // reserves capacity for a new entry before it discovers the key already
    // exists, so it can reallocate the map's entry array mid-iteration and
    // leave the loop walking freed memory. That is not a hypothetical — it
    // silently removed the gate from the first event key and skipped the rest.
    // Emptied keys are collected and dropped afterwards for the same reason.
    const keys = try gpa.dupe([]const u8, hooks_val.object.keys());
    var emptied: std.ArrayList([]const u8) = .empty;

    for (keys) |key| {
        if (only) |wanted| {
            const event = rules.Event.from(key) orelse continue;
            const listed = for (wanted) |e| {
                if (e == event) break true;
            } else false;
            if (!listed) continue;
        }
        const slot = hooks_val.object.getPtr(key) orelse continue;
        var list_val = slot.*;
        if (list_val != .array) continue;

        var i: usize = 0;
        while (i < list_val.array.items.len) {
            var entry = list_val.array.items[i];
            if (entry == .object) {
                if (entry.object.get("hooks")) |inner_val| {
                    if (inner_val == .array) {
                        var inner = inner_val.array;
                        var j: usize = 0;
                        while (j < inner.items.len) {
                            if (isGateHook(inner.items[j], gate_dest)) {
                                _ = inner.orderedRemove(j);
                                removed += 1;
                            } else {
                                j += 1;
                            }
                        }
                        // The list is a value: write it back through its owner.
                        try entry.object.put(gpa, "hooks", .{ .array = inner });
                        list_val.array.items[i] = entry;
                        if (inner.items.len == 0) {
                            _ = list_val.array.orderedRemove(i);
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
        if (list_val.array.items.len == 0) {
            try emptied.append(gpa, key);
        } else {
            slot.* = list_val;
        }
    }
    if (removed == 0) return .none;

    for (emptied.items) |key| _ = hooks_val.object.orderedRemove(key);
    if (hooks_val.object.count() == 0) {
        _ = root.object.orderedRemove("hooks");
    } else {
        try root.object.put(gpa, "hooks", hooks_val);
    }

    return .{ .removed = removed, .json = try render(gpa, root) };
}

fn isGateHook(hook: std.json.Value, gate_dest: []const u8) bool {
    const obj = switch (hook) {
        .object => |o| o,
        else => return false,
    };
    const cmd = obj.get("command") orelse return false;
    return switch (cmd) {
        .string => |s| std.mem.eql(u8, s, gate_dest),
        else => false,
    };
}

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

fn failUsage(stderr: *std.Io.Writer, msg: []const u8) error{BadUsage} {
    stderr.print("claude-hooker-install: {s}\n{s}", .{ msg, usage }) catch {};
    stderr.flush() catch {};
    return error.BadUsage;
}

fn fileExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Copy `path` aside to a timestamped sibling before it is rewritten. Null
/// when there was no file to preserve.
fn backup(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !?[]const u8 {
    if (!fileExists(io, path)) return null;
    const now_ns = std.Io.Clock.real.now(io).nanoseconds;
    const backup_path = try std.fmt.allocPrint(gpa, "{s}.bak-{d}", .{ path, @divTrunc(now_ns, std.time.ns_per_s) });
    const cwd = std.Io.Dir.cwd();
    try cwd.copyFile(path, cwd, backup_path, io, .{});
    return backup_path;
}

/// Load settings.json as a dynamic JSON value; a missing file yields `null`
/// (caller treats it as an empty object). Invalid JSON is a hard error —
/// silently rewriting a corrupt settings file would destroy operator config.
/// Parsed leaky into the caller's arena so the tree can be mutated with the
/// same allocator it was built from.
const Settings = struct {
    root: ?std.json.Value,
};

fn loadSettings(io: std.Io, arena: std.mem.Allocator, path: []const u8) !Settings {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return .{ .root = null },
        else => return err,
    };
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    return .{ .root = root };
}

/// Is our gate wired under `event`? A thin wrapper so the tests and the
/// `verify:` block ask the same question the same way.
fn hookEntryPresent(
    gpa: std.mem.Allocator,
    settings: Settings,
    gate_dest: []const u8,
    event: rules.Event,
) !bool {
    const root = settings.root orelse return false;
    return cli.wiredFor(try cli.hookEntries(gpa, root), event, gate_dest);
}

/// Bring `settings.json` to exactly the wiring `plan` describes and return the
/// pretty-printed document.
///
/// Two halves, and both are needed for the promise to hold over an install's
/// lifetime rather than only on the first one: every planned event gains an
/// entry if it does not have ours, and every event wired to our gate that the
/// plan does NOT name loses it. Without the second half, deleting the last
/// `Stop` rule would leave the harness spawning this gate on every turn to
/// decide nothing.
///
/// Other tools' hooks are never touched, at either end: the removal matches our
/// gate's exact command path, and the addition appends rather than replacing.
fn wireHooks(
    gpa: std.mem.Allocator,
    settings: Settings,
    gate_dest: []const u8,
    plan: []const cli.WireEntry,
) ![]const u8 {
    // Unwire the stale events first, through the same removal `--uninstall`
    // uses, so there is one implementation of "take our entry out".
    var current = settings;
    const change = try planWiring(gpa, settings, gate_dest, plan);
    if (change.stale.len > 0) {
        const removal = try removeHookEntry(gpa, settings, gate_dest, change.stale);
        if (removal.json) |json| {
            current = .{ .root = try std.json.parseFromSliceLeaky(std.json.Value, gpa, json, .{}) };
        }
    }

    var root: std.json.Value = current.root orelse .{ .object = .empty };
    if (root != .object) return error.SettingsNotAnObject;

    var hooks_val = root.object.get("hooks") orelse std.json.Value{ .object = .empty };
    if (hooks_val != .object) return error.HooksNotAnObject;

    // Re-read AFTER the stale removal above, so an entry that was taken out for
    // carrying the wrong matcher is correctly seen as absent now.
    const existing: []const cli.HookEntry = try cli.hookEntries(gpa, root);
    for (plan) |entry| {
        if (cli.wiredExactly(existing, entry, gate_dest)) continue;
        const key = entry.event.name();
        var list_val = hooks_val.object.get(key) orelse std.json.Value{ .array = std.json.Array.init(gpa) };
        if (list_val != .array) return error.HookListNotAnArray;

        // {"matcher":<m>,"hooks":[{"type":"command","command":<gate>}]}
        var cmd_obj: std.json.ObjectMap = .empty;
        try cmd_obj.put(gpa, "type", .{ .string = "command" });
        try cmd_obj.put(gpa, "command", .{ .string = gate_dest });
        var inner_arr = std.json.Array.init(gpa);
        try inner_arr.append(.{ .object = cmd_obj });
        var entry_obj: std.json.ObjectMap = .empty;
        // The matcher key is OMITTED where the event's matcher is not a tool
        // name: on those events the harness would compare the string against a
        // session source, a notification type or a literal filename, and any
        // value we invented would silently narrow the hook to nothing.
        if (entry.matcher) |matcher| try entry_obj.put(gpa, "matcher", .{ .string = matcher });
        try entry_obj.put(gpa, "hooks", .{ .array = inner_arr });

        try list_val.array.append(.{ .object = entry_obj });
        try hooks_val.object.put(gpa, key, list_val);
    }
    try root.object.put(gpa, "hooks", hooks_val);

    return render(gpa, root);
}

fn render(gpa: std.mem.Allocator, root: std.json.Value) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try std.json.Stringify.value(root, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    return try gpa.dupe(u8, out.written());
}

/// Write via a temp sibling + rename so a crash never leaves a torn file.
fn writeFileAtomic(io: std.Io, gpa: std.mem.Allocator, path: []const u8, contents: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(gpa, "{s}.tmp", .{path});
    defer gpa.free(tmp_path);
    const cwd = std.Io.Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = tmp_path, .data = contents });
    try cwd.rename(tmp_path, cwd, path, io);
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "the embedded default rules pass the install gate" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const check = try checkConfig(arena.allocator(), default_rules_json);
    try testing.expect(check.ok);
    try testing.expect(check.cases >= 6);
    try testing.expect(std.mem.indexOf(u8, check.report, "-> OK") != null);
}

test "a default whose own case fails is refused, with the failure in the report" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The rule denies `git add -A`; the case claims `ls` is denied too.
    const broken =
        \\{ "rules": [ { "name": "no-git-add-all", "reason": "stage explicitly",
        \\               "match": [ { "kind": "tokens", "value": "git add -A" } ] } ],
        \\  "tests": [ { "command": "ls", "expect": "deny" } ] }
    ;
    const check = try checkConfig(arena.allocator(), broken);
    try testing.expect(!check.ok);
    try testing.expect(std.mem.indexOf(u8, check.report, "FAIL") != null);
    try testing.expect(std.mem.indexOf(u8, check.report, "expected deny, got none") != null);
}

test "a default with a rule that can never fire is refused by lint" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const broken =
        \\{ "rules": [ { "name": "dead", "reason": "no matchers at all" } ],
        \\  "tests": [ { "command": "ls", "expect": "none" } ] }
    ;
    const check = try checkConfig(arena.allocator(), broken);
    try testing.expect(!check.ok);
    try testing.expect(std.mem.indexOf(u8, check.report, "can never fire") != null);
}

test "a default that does not parse is refused before anything is run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const check = try checkConfig(arena.allocator(), "{ not json");
    try testing.expect(!check.ok);
    try testing.expectEqual(@as(usize, 0), check.cases);
    try testing.expect(std.mem.indexOf(u8, check.report, "does not parse") != null);
}

// ---- the signature line ---------------------------------------------------

/// A writer over an arena, for asserting on what a report actually said.
fn captureInto(gpa: std.mem.Allocator) std.Io.Writer.Allocating {
    return .init(gpa);
}

test "install verify: a valid ad-hoc signature is one ok line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var out = captureInto(arena.allocator());
    const ok = try verifySignature(&out.writer, .{ .facts = .{
        .applicable = true,
        .system = "macos",
        .path = "/sb/hooks/claude-hooker-gate",
        .state = .valid,
        .form = "flags=0x20002(adhoc,linker-signed), Signature=adhoc",
        .adhoc = true,
    } });
    try testing.expect(ok);
    try testing.expect(std.mem.indexOf(u8, out.written(), "ok   signature: /sb/hooks/claude-hooker-gate") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "adhoc,linker-signed") != null);
    // Nothing was re-signed, so nothing claims it was.
    try testing.expect(std.mem.indexOf(u8, out.written(), "re-signed") == null);
}

test "install verify: a broken signature fails the install and says why it matters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var out = captureInto(arena.allocator());
    const ok = try verifySignature(&out.writer, .{
        .facts = .{
            .applicable = true,
            .system = "macos",
            .path = "/sb/hooks/claude-hooker-gate",
            .state = .invalid,
            .note = "main executable failed strict validation",
        },
        .resigned = .{ .failed = "main executable failed strict validation" },
    });
    try testing.expect(!ok);
    const text = out.written();
    try testing.expect(std.mem.indexOf(u8, text, "FAIL signature:") != null);
    try testing.expect(std.mem.indexOf(u8, text, "failed strict validation") != null);
    // The two facts that make this worth failing an install over.
    try testing.expect(std.mem.indexOf(u8, text, "SIGKILL") != null);
    try testing.expect(std.mem.indexOf(u8, text, "fails OPEN") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--force --sign -") != null);
}

test "install verify: an unsigned binary is refused, and no codesign is not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var unsigned = captureInto(gpa);
    try testing.expect(!try verifySignature(&unsigned.writer, .{ .facts = .{
        .applicable = true,
        .path = "/sb/hooks/claude-hooker-gate",
        .state = .unsigned,
    } }));
    try testing.expect(std.mem.indexOf(u8, unsigned.written(), "carries no code signature") != null);

    // A machine without the command line tools still gets an install — but it
    // is told the signature is unknown rather than fine.
    var unknown = captureInto(gpa);
    try testing.expect(try verifySignature(&unknown.writer, .{ .facts = .{
        .applicable = true,
        .path = "/sb/hooks/claude-hooker-gate",
        .state = .unavailable,
        .note = "FileNotFound",
    } }));
    try testing.expect(std.mem.indexOf(u8, unknown.written(), "could not be checked") != null);
    try testing.expect(std.mem.indexOf(u8, unknown.written(), "warn signature:") != null);
}

test "install verify: a repaired signature says so" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var out = captureInto(arena.allocator());
    try testing.expect(try verifySignature(&out.writer, .{
        .facts = .{
            .applicable = true,
            .path = "/sb/hooks/claude-hooker-gate",
            .state = .valid,
            .form = "flags=0x2(adhoc), Signature=adhoc",
            .adhoc = true,
        },
        .resigned = .signed,
    }));
    try testing.expect(std.mem.indexOf(u8, out.written(), "(re-signed by this install)") != null);
}

test "install verify: off macOS the signature is not mentioned at all" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The non-Darwin path, exercised by stating the platform rather than by
    // needing one: no line, no warning, no invented problem.
    var out = captureInto(arena.allocator());
    try testing.expect(try verifySignature(&out.writer, .{ .facts = .{ .applicable = false, .system = "linux" } }));
    try testing.expectEqualStrings("", out.written());
}

// ---- settings round-trip --------------------------------------------------

const GATE = "/sandbox/.claude/hooks/claude-hooker-gate";

fn parseSettings(arena: std.mem.Allocator, bytes: []const u8) !Settings {
    return .{ .root = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) };
}

/// Compare two documents by structure rather than by bytes: the installer
/// rewrites through a JSON round-trip, so key order and whitespace are not
/// the promise — content is.
fn expectSameJson(arena: std.mem.Allocator, a: []const u8, b: []const u8) !void {
    const va = try std.json.parseFromSliceLeaky(std.json.Value, arena, a, .{});
    const vb = try std.json.parseFromSliceLeaky(std.json.Value, arena, b, .{});
    const ra = try render(arena, va);
    const rb = try render(arena, vb);
    try testing.expectEqualStrings(ra, rb);
}

/// One shadow rule per event, so a test can say "a policy that uses these
/// events" and get the plan the installer would compute for it.
///
/// Held at container scope rather than built in a helper: a `RuleSet` borrows
/// its rule slice, and a slice of a function-local array is exactly the dangling
/// pointer std.json's borrowing already trains this codebase to watch for.
const rule_for: [rules.Events.COUNT]rules.Rule = blk: {
    var built: [rules.Events.COUNT]rules.Rule = undefined;
    for (rules.Events.all(), 0..) |*d, i| {
        built[i] = .{
            .name = d.name(),
            .event = d.event,
            .decision = .log,
            .reason = "a test rule",
            .match = &.{.{ .kind = .substring, .field = .trigger, .value = "x" }},
        };
    }
    break :blk built;
};

fn planOver(arena: std.mem.Allocator, comptime events_: []const rules.Event) ![]const cli.WireEntry {
    const chosen = comptime blk: {
        var built: [events_.len]rules.Rule = undefined;
        for (events_, 0..) |e, i| built[i] = rule_for[@intFromEnum(e)];
        break :blk built;
    };
    return cli.wiringPlan(arena, .{ .rules = &chosen });
}

test "install then uninstall returns settings.json to what it was" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const original =
        \\{ "model": "opus", "env": { "FOO": "bar" } }
    ;
    const plan = try planOver(arena, &.{ .PreToolUse, .Stop });
    const wired = try wireHooks(arena, try parseSettings(arena, original), GATE, plan);
    try testing.expect(try hookEntryPresent(arena, try parseSettings(arena, wired), GATE, .PreToolUse));
    try testing.expect(try hookEntryPresent(arena, try parseSettings(arena, wired), GATE, .Stop));

    const removal = try removeHookEntry(arena, try parseSettings(arena, wired), GATE, null);
    try testing.expectEqual(@as(usize, 2), removal.removed);
    try expectSameJson(arena, original, removal.json.?);
}

test "wiring is idempotent across every event in the plan" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plan = try planOver(arena, &.{ .PreToolUse, .PostToolUse, .Stop, .SessionStart });
    const once = try wireHooks(arena, .{ .root = null }, GATE, plan);
    const twice = try wireHooks(arena, try parseSettings(arena, once), GATE, plan);
    try expectSameJson(arena, once, twice);

    // Four keys, one entry each, and the tool events carry a matcher while the
    // others deliberately do not.
    const root = (try parseSettings(arena, once)).root.?;
    const entries = try cli.hookEntries(arena, root);
    try testing.expectEqual(@as(usize, 4), entries.len);
    for (entries) |entry| {
        const d = entry.event.?.descriptor();
        try testing.expectEqual(d.matcher == .tool_name, entry.matcher.len > 0);
    }
}

test "an event whose rules are gone is UNWIRED by the next install" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Wired for two events, then the Stop rules are deleted from the policy.
    const wide = try wireHooks(arena, .{ .root = null }, GATE, try planOver(arena, &.{ .PreToolUse, .Stop }));
    try testing.expect(try hookEntryPresent(arena, try parseSettings(arena, wide), GATE, .Stop));

    const narrowed = try planOver(arena, &.{.PreToolUse});
    const change = try planWiring(arena, try parseSettings(arena, wide), GATE, narrowed);
    try testing.expectEqual(@as(usize, 1), change.stale.len);
    try testing.expectEqual(rules.Event.Stop, change.stale[0]);
    try testing.expect(!change.isEmpty());

    const rewired = try wireHooks(arena, try parseSettings(arena, wide), GATE, narrowed);
    try testing.expect(try hookEntryPresent(arena, try parseSettings(arena, rewired), GATE, .PreToolUse));
    // The whole point: the harness stops spawning the gate on every turn to
    // decide nothing.
    try testing.expect(!try hookEntryPresent(arena, try parseSettings(arena, rewired), GATE, .Stop));
    // And no husk is left behind.
    try testing.expect(std.mem.indexOf(u8, rewired, "Stop") == null);
}

test "a stale MATCHER is rewired, not left in place" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The original single-event bug, arriving by the upgrade path: an install
    // wired `PreToolUse` for `Bash`, then the rule file grew a `Write` rule. An
    // installer that saw "our command is already under PreToolUse" and stopped
    // would leave the new rule permanently unreachable — and report the install
    // as verified.
    const narrow = rules.RuleSet{ .rules = &.{
        .{ .name = "a", .tool = "Bash", .reason = "r", .match = &.{.{ .value = "x" }} },
    } };
    const widened = rules.RuleSet{ .rules = &.{
        .{ .name = "a", .tool = "Bash", .reason = "r", .match = &.{.{ .value = "x" }} },
        .{ .name = "b", .tool = "Write", .reason = "r", .match = &.{.{ .field = .file_path, .value = "y" }} },
    } };

    const before = try cli.wiringPlan(arena, narrow);
    try testing.expectEqualStrings("Bash", before[0].matcher.?);
    const wired = try wireHooks(arena, .{ .root = null }, GATE, before);

    const after = try cli.wiringPlan(arena, widened);
    try testing.expectEqualStrings("Bash|Write", after[0].matcher.?);

    // The command is already there, so `wiredFor` says yes — and `wiredExactly`,
    // which is what the installer asks, says no.
    const settings = try parseSettings(arena, wired);
    const entries = try cli.hookEntries(arena, settings.root.?);
    try testing.expect(cli.wiredFor(entries, .PreToolUse, GATE));
    try testing.expect(!cli.wiredExactly(entries, after[0], GATE));

    const change = try planWiring(arena, settings, GATE, after);
    try testing.expect(!change.isEmpty());
    try testing.expectEqual(@as(usize, 1), change.stale.len);
    try testing.expectEqual(rules.Event.PreToolUse, change.stale[0]);

    // One entry afterwards, carrying the widened matcher — not two, and not the
    // old one.
    const rewired = try wireHooks(arena, settings, GATE, after);
    const final = try cli.hookEntries(arena, (try parseSettings(arena, rewired)).root.?);
    var ours: usize = 0;
    for (final) |e| {
        if (!std.mem.eql(u8, e.command, GATE)) continue;
        ours += 1;
        try testing.expectEqualStrings("Bash|Write", e.matcher);
    }
    try testing.expectEqual(@as(usize, 1), ours);

    // And it is now idempotent at the new matcher.
    try testing.expect((try planWiring(arena, try parseSettings(arena, rewired), GATE, after)).isEmpty());
}

test "uninstall leaves other operators' hooks alone, on every event key" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const other =
        \\{ "hooks": { "PreToolUse": [
        \\  { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/usr/local/bin/other-gate" } ] }
        \\ ], "PostToolUse": [
        \\  { "matcher": "*", "hooks": [ { "type": "command", "command": "/usr/local/bin/notify" } ] }
        \\ ], "Stop": [
        \\  { "hooks": [ { "type": "command", "command": "/usr/local/bin/chime" } ] }
        \\ ] } }
    ;
    const plan = try planOver(arena, &.{ .PreToolUse, .PostToolUse, .Stop });
    const wired = try wireHooks(arena, try parseSettings(arena, other), GATE, plan);
    const removal = try removeHookEntry(arena, try parseSettings(arena, wired), GATE, null);
    try testing.expectEqual(@as(usize, 3), removal.removed);
    try expectSameJson(arena, other, removal.json.?);

    // And the other three hooks are still wired after ours are gone.
    const after = try parseSettings(arena, removal.json.?);
    try testing.expect(!try hookEntryPresent(arena, after, GATE, .PreToolUse));
    try testing.expect(try hookEntryPresent(arena, after, "/usr/local/bin/other-gate", .PreToolUse));
    try testing.expect(try hookEntryPresent(arena, after, "/usr/local/bin/notify", .PostToolUse));
    try testing.expect(try hookEntryPresent(arena, after, "/usr/local/bin/chime", .Stop));
}

test "uninstalling twice is a no-op the second time" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plan = try planOver(arena, &.{ .PreToolUse, .Stop });
    const wired = try wireHooks(arena, .{ .root = null }, GATE, plan);
    const first = try removeHookEntry(arena, try parseSettings(arena, wired), GATE, null);
    try testing.expectEqual(@as(usize, 2), first.removed);

    const second = try removeHookEntry(arena, try parseSettings(arena, first.json.?), GATE, null);
    try testing.expectEqual(@as(usize, 0), second.removed);
    try testing.expect(second.json == null);

    // Installing into nothing and uninstalling again leaves an empty object,
    // not a husk of empty containers.
    try expectSameJson(arena, "{}", first.json.?);
}

test "a settings file with no hooks at all is left untouched" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const removal = try removeHookEntry(arena, try parseSettings(arena, "{\"model\":\"opus\"}"), GATE, null);
    try testing.expectEqual(@as(usize, 0), removal.removed);
    try testing.expect(removal.json == null);
}

test "the shipped defaults wire the events they use, with a matcher that reaches every rule" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var loaded = try rules.parse(arena, default_rules_json);
    const plan = try cli.wiringPlan(arena, loaded.ruleSet());
    const wired = try wireHooks(arena, .{ .root = null }, GATE, plan);
    const settings = try parseSettings(arena, wired);

    for (plan) |entry| {
        try testing.expect(try hookEntryPresent(arena, settings, GATE, entry.event));
    }
    // The regression this closes: the old installer hard-wired
    // `"matcher": "Bash"`, so the shipped `Write` and any-tool rules could never
    // fire on a real install. Every rule's tool must be reachable now.
    const entries = try cli.hookEntries(arena, settings.root.?);
    for (loaded.ruleSet().rules) |rule| {
        if (!rule.event.descriptor().has_tool) continue;
        const matcher = for (entries) |e| {
            if (e.event == rule.event) break e.matcher;
        } else return error.TestExpectedWiring;
        const reachable = std.mem.eql(u8, matcher, "*") or
            std.mem.indexOf(u8, matcher, rule.toolPattern()) != null;
        if (!reachable) {
            std.debug.print("rule {s} wants tool {s}, matcher is {s}\n", .{ rule.name, rule.toolPattern(), matcher });
            return error.TestUnexpectedResult;
        }
    }
}

//! claude-hooker-gate — a fast PreToolUse permission gate for Claude Code.
//!
//! The binary has two modes, told apart by argument count alone:
//!
//!   - **no arguments** — hook mode, described below. This is how the harness
//!     invokes it: the `settings.json` entry is a bare command line and the
//!     event arrives on stdin, so hook mode passes no arguments *by
//!     construction* and cannot be reached accidentally from a CLI typo.
//!   - **any argument** — the operator CLI (`check`, `selftest`, `stats`,
//!     `version`, `help`); see `cli.zig`. Dispatch costs one iterator step and
//!     leaves the hook path below untouched.
//!
//! Reads the hook event JSON on stdin, works out WHICH event it is from
//! `hook_event_name`, evaluates only the rules scoped to that event, and (only)
//! on an enforced hit emits the response envelope THAT event accepts, carrying
//! the rule's reason. No match → no output, exit 0 → whatever the harness would
//! have done, it still does. Rules with the `log` decision are shadow-only:
//! they are recorded by the evaluator and deliberately produce no output here.
//!
//! Every event-specific fact — the payload keys, the response shape, whether a
//! refusal is even possible — comes from the descriptor table in `events.zig`.
//! There is no per-event branch in this file, and an event name this build has
//! never heard of is a clean exit 0: a future harness will send events this
//! binary predates, and inventing an answer for one (or failing on it) would be
//! strictly worse than saying nothing.
//!
//! Config resolution: $CLAUDE_HOOK_RULES_PATH, else ~/.claude/hook-rules.json.
//!
//! The repository the session runs in may add rules of its own, in
//! $CLAUDE_PROJECT_DIR/.claude/hook-rules.json (else the same path under the
//! event's `cwd`). They are evaluated BEFORE the global rules — one combined
//! first-match walk — so a project can pre-approve its own safe operations or
//! add prohibitions the operator's file never had. Only the project file's
//! `rules` are read: its `logging`, `tests`, and `allow_project_overlay` are
//! ignored, and the global file's `allow_project_overlay` (default true) is
//! what decides whether an overlay is consulted at all. See
//! `rules.resolveProjectPath` for the trust model.
//!
//! Every hit — enforced, shadow, or bypassed — is appended to the decision
//! log (see `decision_log.zig`). That is bookkeeping, strictly best-effort,
//! and deliberately runs *after* the decision has been written and flushed.
//!
//! Environment:
//!   CLAUDE_HOOK_RULES_PATH  rule file location
//!   CLAUDE_HOOK_LOG_PATH    decision log location (outranks logging.path)
//!   CLAUDE_HOOK_DISABLE     comma-separated rule names to switch off
//!   CLAUDE_PROJECT_DIR      repo root for the project rule overlay
//!
//! Failure policy: an unreadable or invalid config, or unreadable stdin,
//! exits 1 with a one-line stderr message. Per the hooks contract a non-2
//! nonzero exit is a NON-blocking error — the tool call proceeds and the
//! message is surfaced — so a broken config degrades to "gate off, loudly"
//! rather than "all commands blocked".
//!
//! One load failure has its own exit code: a rule file declaring a
//! `schema_version` NEWER than this build reads exits 78 (`cli.EX_CONFIG`)
//! instead of 1. Same non-blocking contract, different event — the operator's
//! policy is fine and the binary is behind it, so the message names both
//! versions and the command that fixes it. Without that distinction the newer
//! file would be rejected as a syntax error, which is exactly how enforcement
//! disappears silently; see `rules.SCHEMA_VERSION`.

const std = @import("std");
const rules = @import("rules.zig");
const protocol = @import("protocol.zig");
const decision_log = @import("decision_log.zig");
const cli = @import("cli.zig");

const MAX_EVENT_BYTES = 8 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    // ---- mode ----
    // One argument means the operator is driving; `cli.run` never returns.
    var probe = std.process.Args.Iterator.init(init.minimal.args);
    _ = probe.next(); // program name
    if (probe.next() != null) return cli.run(init);

    var stderr_buf: [512]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    // ---- stdin: the hook event ----
    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
    const event_bytes = stdin_reader.interface.allocRemaining(gpa, .limited(MAX_EVENT_BYTES)) catch |err| {
        return fail(stderr, "stdin read failed: {s}", .{@errorName(err)});
    };
    defer gpa.free(event_bytes);

    var loaded_event = protocol.parseEvent(gpa, event_bytes) catch |err| {
        return fail(stderr, "event parse failed: {s}", .{@errorName(err)});
    };
    defer loaded_event.deinit();
    const payload = loaded_event.payload();

    // An event this build does not know: exit 0, silently, having read no
    // config. Not an error — the harness gains events between releases, and the
    // gate's job on one it has never heard of is to be invisible.
    const event = payload.event orelse return;

    // Nothing to evaluate (no field of this event's payload carries text):
    // stay silent without even reading the config.
    if (payload.isEmpty()) return;

    // ---- rule config ----
    // The CLI resolves the same way through the same function, so `check`
    // cannot end up reading a different file than the hook enforces.
    const rules_path = (rules.resolvePath(
        gpa,
        init.environ_map.get("CLAUDE_HOOK_RULES_PATH"),
        null,
        init.environ_map.get("HOME"),
    ) catch |err| {
        return fail(stderr, "path resolution failed: {s}", .{@errorName(err)});
    }) orelse {
        return fail(stderr, "neither CLAUDE_HOOK_RULES_PATH nor HOME is set", .{});
    };
    defer gpa.free(rules_path);

    const rules_bytes = std.Io.Dir.cwd().readFileAlloc(io, rules_path, gpa, .limited(rules.MAX_CONFIG_BYTES)) catch |err| {
        return fail(stderr, "cannot read rules config {s}: {s}", .{ rules_path, @errorName(err) });
    };
    defer gpa.free(rules_bytes);

    // A refusal over `schema_version` is reported as itself, with its own exit
    // code, rather than as one more unreadable config. It is the one load
    // failure where the operator's document is correct and this binary is the
    // thing that is out of date, and the difference is the whole remedy.
    var schema_diag: rules.Diagnostic = .{};
    var loaded_rules = rules.parseDiagnosed(gpa, rules_bytes, &schema_diag) catch |err| switch (err) {
        error.RulesFromNewerSchema, error.InvalidSchemaVersion => {
            cli.writeSchemaRefusal(stderr, "claude-hooker-gate", rules_path, schema_diag.declared, schema_diag.declaredText()) catch {};
            stderr.flush() catch {};
            // Still a non-2 exit, so the tool call proceeds: refusing a policy
            // this build may not fully understand must not turn into blocking
            // every command the operator has. Loud, and open.
            std.process.exit(cli.EX_CONFIG);
        },
        else => return fail(stderr, "invalid rules config {s}: {s}", .{ rules_path, @errorName(err) }),
    };
    defer loaded_rules.deinit();

    const rule_set = loaded_rules.ruleSet();

    // ---- project overlay ----
    // A repository may ship rules of its own. They are evaluated ahead of the
    // global ones (see `rules.evaluateOverlay`), and only their `rules` are
    // read — logging and the overlay switch stay global-only.
    var loaded_project = loadProjectRules(io, gpa, .{
        .enabled = rule_set.allow_project_overlay,
        .project_dir = init.environ_map.get("CLAUDE_PROJECT_DIR"),
        .payload_cwd = payload.cwd,
        .global_path = rules_path,
        .stderr = stderr,
    });
    defer if (loaded_project) |*p| p.deinit();
    const project_rules: []const rules.Rule = if (loaded_project) |*p| p.ruleSet().rules else &.{};

    // ---- operator override ----
    // CLAUDE_HOOK_DISABLE names rules to switch off for this invocation.
    //
    // Why an environment variable is an OPERATOR control and not an escape
    // hatch for the agent: this process is spawned by the Claude Code harness
    // and inherits the HARNESS's environment. It does not inherit — and never
    // sees — the environment of the command being proposed. An agent writing
    // `CLAUDE_HOOK_DISABLE=no-pkill pkill -f x` only sets a variable inside
    // the shell the gate is deciding whether to permit, which is a child of a
    // decision that has not been made yet; the gate's own environment was
    // fixed when the harness started. Setting this for real means editing the
    // harness's launch environment (or `settings.json` `env`), which is
    // exactly the operator-owned surface the `protect-hook-config` rule
    // guards. Bypasses are recorded in the decision log regardless, so an
    // override is visible after the fact rather than silent.
    const disabled = rules.DisabledSet.init(init.environ_map.get("CLAUDE_HOOK_DISABLE") orelse "");

    // ---- evaluate + respond ----
    // Shadow (`log`) hits are collected in `result.shadowHits()` and bypassed
    // rules in `result.bypassedHits()`; neither is surfaced on the wire, only
    // the enforced decision is. A disabled rule is stepped over inside the
    // walk, so a bypassed deny does not hide an enabled rule below it.
    //
    // The allocator is threaded through because a structural matcher
    // (`command_word`, `argv`, `command_line`, `flag`, `flags`, `path_class`,
    // `signal`) parses and resolves
    // the command. That happens at most once per call, lazily: a rule file
    // with no structural matcher never builds a model and this is the same
    // allocation-free walk it has always been. `deinit` releases the model —
    // and must run AFTER `logHits`, which reads the resolved values a hit
    // borrows from it.
    var result = rules.evaluateOverlayIn(gpa, project_rules, rule_set.rules, payload.input, disabled);
    defer result.deinit();

    // The response shape is the EVENT's, not the decision's: `protocol` reads
    // the descriptor and writes `permissionDecision`, `decision.behavior`,
    // `decision: "block"`, `continue: false`, an elicitation `action`, or
    // nothing at all. `answer` carries back only what this function still has
    // to do — flush, and exit with the code the event's mechanism asked for.
    var answer = protocol.Answer.silent;
    if (result.enforced) |hit| {
        var stdout_buf: [8192]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
        const stdout = &stdout_writer.interface;
        answer = try protocol.writeDecision(stdout, event, hit.rule);
        if (answer.wrote_json) try stdout.flush();
    }

    // ---- record ----
    // Last, and never able to change what happened above: the decision is
    // already on the wire by the time a single byte of log is written.
    logHits(io, gpa, rule_set, payload, result, .{
        .env_path = init.environ_map.get("CLAUDE_HOOK_LOG_PATH"),
        .home = init.environ_map.get("HOME"),
        .stderr = stderr,
    });

    // Exit last, so the log line is written even for the one event whose
    // refusal is an exit code. Zero for everything else, which is the whole
    // contract: this gate answers in JSON and never by exiting.
    if (answer.exit_code != 0) std.process.exit(answer.exit_code);
}

/// Everything `loadProjectRules` needs to decide whether there is an overlay
/// and where it lives. Read from the environment and the payload by `main`.
const ProjectEnv = struct {
    /// The global file's `allow_project_overlay`. False means not even a
    /// stat: the operator has switched repo-contributed rules off.
    enabled: bool,
    project_dir: ?[]const u8,
    payload_cwd: []const u8,
    /// The global rule file, so an overlay that resolves to the very same
    /// path is not loaded (and evaluated) twice.
    global_path: []const u8,
    stderr: *std.Io.Writer,
};

/// A loaded project rule file and the bytes it was parsed from.
///
/// The two are held together because the parse BORROWS from those bytes:
/// std.json hands back slices into the source document for strings that need
/// no unescaping, so freeing the file contents while the rule set is still
/// live leaves every rule name and pattern pointing at reclaimed memory. The
/// global rule file has the same property; there it is `main`'s two defers
/// that keep the pair alive for the same scope.
const ProjectRules = struct {
    gpa: std.mem.Allocator,
    bytes: []u8,
    loaded: rules.LoadedRules,

    fn deinit(self: *ProjectRules) void {
        self.loaded.deinit();
        self.gpa.free(self.bytes);
    }

    fn ruleSet(self: *const ProjectRules) rules.RuleSet {
        return self.loaded.ruleSet();
    }
};

/// The repository's own rule file, or null when there is none to apply.
///
/// **Failure policy: never fail both closed and never fail silently.** A
/// missing overlay is the ordinary case and says nothing. An overlay that
/// exists but cannot be read or parsed costs one stderr note and is then
/// skipped — the global rules are still evaluated and still enforced. The
/// alternative, refusing to decide because a repo shipped broken JSON, would
/// let any repository switch the operator's gate off by committing a typo.
fn loadProjectRules(io: std.Io, gpa: std.mem.Allocator, env: ProjectEnv) ?ProjectRules {
    if (!env.enabled) return null;

    const path = (rules.resolveProjectPath(gpa, env.project_dir, env.payload_cwd) catch null) orelse return null;
    defer gpa.free(path);

    // $HOME as the project directory: the overlay *is* the global file.
    if (std.mem.eql(u8, path, env.global_path)) return null;

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(rules.MAX_CONFIG_BYTES)) catch |err| {
        // Absent is the norm — most directories carry no policy.
        if (err != error.FileNotFound) note(env.stderr, "cannot read project rules {s}: {s}", .{ path, @errorName(err) });
        return null;
    };

    var diag: rules.Diagnostic = .{};
    const loaded = rules.parseDiagnosed(gpa, bytes, &diag) catch |err| {
        gpa.free(bytes);
        // An overlay from a newer schema is skipped, not fatal — same policy as
        // any other broken overlay, for the same reason: a repository must not
        // be able to switch the operator's gate off. It is named precisely,
        // because "this repo's rules need a newer gate" is actionable and
        // "invalid project rules" is not.
        if (err == error.RulesFromNewerSchema) {
            var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            note(env.stderr, "project rules {s} declare schema_version {s} and this build reads {s}; skipped", .{
                path,
                if (diag.declared) |d| d.text(&theirs) else diag.declaredText(),
                rules.SCHEMA_VERSION.text(&mine),
            });
            return null;
        }
        note(env.stderr, "invalid project rules {s}: {s}", .{ path, @errorName(err) });
        return null;
    };
    return .{ .gpa = gpa, .bytes = bytes, .loaded = loaded };
}

/// One stderr line about something that did not stop the gate from deciding.
fn note(stderr: *std.Io.Writer, comptime fmt: []const u8, args: anytype) void {
    stderr.print("claude-hooker-gate: " ++ fmt ++ " (global rules still enforced)\n", args) catch {};
    stderr.flush() catch {};
}

/// The ambient bits `logHits` needs that do not come from the rule set or the
/// event. Read from the environment by `main` so the logging module — and this
/// function — stay free of process state.
const LogEnv = struct {
    env_path: ?[]const u8,
    home: ?[]const u8,
    stderr: *std.Io.Writer,
};

/// Append one line per hit. Best-effort throughout: nothing here returns an
/// error, and a failure costs at most one stderr note.
fn logHits(
    io: std.Io,
    gpa: std.mem.Allocator,
    rule_set: rules.RuleSet,
    payload: protocol.Payload,
    result: rules.Evaluation,
    env: LogEnv,
) void {
    if (!rule_set.logging.enabled) return;
    // Nothing matched: skip the path resolution and the open entirely.
    if (result.enforced == null and
        result.shadowHits().len == 0 and
        result.bypassedHits().len == 0 and
        !result.shadow_overflow and
        !result.bypassed_overflow) return;

    const path = decision_log.resolvePath(gpa, env.env_path, rule_set.logging.path, env.home) catch null;
    defer if (path) |p| gpa.free(p);

    var logger = decision_log.Logger.init(io, rule_set.logging, path, env.stderr);
    if (!logger.isActive()) return;

    const now = std.Io.Clock.real.now(io).toSeconds();
    const input = payload.input;

    // Dropped hits first: a reader must learn that the lines below are an
    // incomplete account before reading them.
    if (result.bypassed_overflow) {
        logger.record(decision_log.overflowEntry(now, payload.session_id, input, .bypassed));
    }
    if (result.shadow_overflow) {
        logger.record(decision_log.overflowEntry(now, payload.session_id, input, .shadow));
    }

    // Bypasses next: they explain why an expected decision is missing.
    for (result.bypassedHits()) |hit| {
        logger.record(.{
            .ts_unix = now,
            .session_id = payload.session_id,
            .input = input,
            .hit = hit,
            .decision = .bypassed,
        });
    }
    for (result.shadowHits()) |hit| {
        logger.record(.{
            .ts_unix = now,
            .session_id = payload.session_id,
            .input = input,
            .hit = hit,
            .decision = .log,
        });
    }
    if (result.enforced) |hit| {
        logger.record(.{
            .ts_unix = now,
            .session_id = payload.session_id,
            .input = input,
            .hit = hit,
            .decision = decision_log.LoggedDecision.fromDecision(hit.rule.decision),
        });
    }
}

fn fail(stderr: *std.Io.Writer, comptime fmt: []const u8, args: anytype) noreturn {
    stderr.print("claude-hooker-gate: " ++ fmt ++ " (gate inactive for this call)\n", args) catch {};
    stderr.flush() catch {};
    // Exit 1, not 2: per the hooks contract a non-2 exit is a NON-blocking
    // error, so a broken gate degrades to "off, loudly" — and a plain exit
    // avoids Zig's error-return trace polluting stderr.
    std.process.exit(1);
}

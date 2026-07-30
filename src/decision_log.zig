//! The decision log: one JSON line per rule hit, appended to a plain file.
//!
//! Every hit the evaluator produces is recorded — the enforced decision, each
//! shadow (`log`) hit, and each hit the operator bypassed with
//! `CLAUDE_HOOK_DISABLE`. That is what makes the gate reviewable: a rule that
//! never appears in the log is dead weight, a shadow rule that appears
//! constantly is a false-positive machine, and a bypass line is a record that
//! the operator turned something off and what it would have caught.
//!
//! Line shape (one per line, newline-terminated, no pretty printing):
//!
//!     {"ts_unix":1750000000,"session_id":"...","tool":"Bash",
//!      "rule":"no-pkill","decision":"deny",
//!      "matcher":{"kind":"word","field":"command","value":"pkill"},
//!      "span":"pkill","command_logged":false}
//!
//! `span` is the text that actually matched — a few bytes, safe to record
//! unconditionally. The *full* matched field (a whole command line, or a whole
//! file body for a `content` rule) is only included when the operator sets
//! `logging.log_commands`, because those bytes routinely carry secrets; when
//! they are included they are capped at `MAX_FIELD_BYTES` with a truncation
//! marker. `command_logged` states which of the two happened, so a reader is
//! never left guessing whether an absent `command` means "opted out" or
//! "empty".
//!
//! ### Schema addition: `resolved` and `origin`
//!
//! A structural matcher (`command_word`, `argv`, `command_line`, `flag`)
//! compares against a value the text does not necessarily spell out: a command
//! word recovered from `$P$K`, an argument recovered from `$X`, an alias or
//! function body. `span` still records the bytes the operator WROTE, so on its
//! own it would say `$P$K` and never say `pkill`. Two optional keys close
//! that gap:
//!
//!     ...,"span":"$P$K","resolved":"pkill","origin":"resolved_concat",...
//!
//!   - `resolved` — the value the matcher actually compared against, capped
//!                  like `span`.
//!   - `origin`   — how it got there: `literal`, `resolved_var`,
//!                  `resolved_concat`, `alias`, `function`,
//!                  `substitution_derived`, `unresolved_dynamic`.
//!
//! Both are **additive and omitted entirely** — not emitted as null — when the
//! hit carries no provenance, which is every hit from a textual matcher and
//! from the `signal` kind. A consumer written before this change reads every
//! line it used to read, unchanged; a consumer that wants the recovered value
//! gets it without having to re-parse the command.
//!
//! Two lines have no rule behind them in the operator's file. `_overflow`
//! (see `overflowEntry`) records that the evaluator dropped hits it had no
//! room for. And the file itself is bounded: at open time a log larger than
//! `logging.max_bytes` is moved to `<path>.1` and a fresh one is started, so
//! the log cannot grow without limit on an operator's home directory.
//!
//! **Everything here is best-effort.** The gate's job is to produce a
//! decision; logging is bookkeeping around it. Any failure — unwritable path,
//! full disk, oversized line — produces a single note on stderr and is then
//! dropped. No error from this module ever reaches the decision path.
//!
//! The module reads no environment and opens nothing on construction: paths
//! and settings arrive as parameters (see `resolvePath`), which is what lets
//! the whole thing be exercised from unit tests without touching process
//! state.

const std = @import("std");
const rules = @import("rules.zig");

/// Cap on the matched-field text recorded when `log_commands` is on. Big
/// enough for any command a person would type and for the interesting head of
/// a file body; small enough that a runaway `content` rule cannot turn the log
/// into a copy of the repository.
pub const MAX_FIELD_BYTES = 4 * 1024;

/// Scratch needed to build the (possibly truncated) field text plus marker.
const FIELD_BUF_BYTES = MAX_FIELD_BYTES + 64;

/// Scratch for one serialized line. Generous: JSON escaping can expand a
/// single control byte sixfold (into a six-character escape), and a line
/// carries at most two capped texts (`span` and `command`) plus small
/// operator-authored strings.
const LINE_BUF_BYTES = 64 * 1024;

/// Basename of the log inside `~/.claude` when nothing else is configured.
pub const DEFAULT_LOG_NAME = "hook-gate-log.jsonl";

/// What the line says happened. Mirrors `rules.Decision`, plus the one state
/// that has no rule-file spelling: a rule that matched and would have applied,
/// but that the operator switched off for this invocation.
pub const LoggedDecision = enum {
    deny,
    ask,
    allow,
    log,
    bypassed,

    pub fn fromDecision(decision: rules.Decision) LoggedDecision {
        return switch (decision) {
            .deny => .deny,
            .ask => .ask,
            .allow => .allow,
            .log => .log,
        };
    }

    pub fn wire(self: LoggedDecision) []const u8 {
        return @tagName(self);
    }
};

/// One hit, in the form the log needs: the evaluator's `Hit`, the input it was
/// measured against (spans are byte offsets into one of its fields), and the
/// ambient facts the evaluator does not know about.
pub const Entry = struct {
    /// Seconds since the Unix epoch. Supplied by the caller so that the
    /// formatter stays a pure function and tests are deterministic.
    ts_unix: i64,
    /// The harness's session id, or "" when the payload carried none.
    session_id: []const u8 = "",
    input: rules.Input,
    hit: rules.Hit,
    decision: LoggedDecision,

    /// The text of the field this hit was found in.
    pub fn fieldText(self: Entry) []const u8 {
        return self.input.text(self.hit.field);
    }

    /// The bytes that matched. Clamped rather than trusted: a hand-built
    /// `Entry` (tests, future callers) must not be able to slice out of
    /// bounds just because logging is best-effort.
    pub fn spanText(self: Entry) []const u8 {
        const text = self.fieldText();
        const start = @min(self.hit.span.start, text.len);
        const end = @min(self.hit.span.end(), text.len);
        return text[start..@max(start, end)];
    }
};

pub const Options = struct {
    /// Include the full matched field text as `command`. Off by default.
    log_commands: bool = false,
};

// ---------------------------------------------------------------------------
// the overflow marker
// ---------------------------------------------------------------------------

/// Which per-evaluation buffer ran out of room. The evaluator caps how many
/// simultaneous shadow and bypassed hits it records; when that cap is reached
/// the extras are dropped, and dropping them silently would make the log lie
/// by omission.
pub const OverflowBuffer = enum {
    shadow,
    bypassed,

    /// The matcher value the marker line carries, naming the buffer.
    pub fn label(self: OverflowBuffer) []const u8 {
        return switch (self) {
            .shadow => "shadow_hits",
            .bypassed => "bypassed_hits",
        };
    }
};

/// The synthetic rule a marker line is attributed to. Leading underscore so
/// it cannot be confused with — or collide with — an operator's rule, and
/// `log` because a marker is an observation about the log itself and must
/// never look like a decision that was enforced.
pub const overflow_rule: rules.Rule = .{
    .name = "_overflow",
    .tool = rules.TOOL_ANY,
    .decision = .log,
    .reason = "more simultaneous hits than the evaluator records; some were dropped from this log",
};

/// A line stating that hits were dropped. The span is empty — there are no
/// matched bytes to point at — and the matcher value names the buffer that
/// overflowed, so `stats` groups these under `_overflow` and a reader can
/// tell which kind of hit went missing.
pub fn overflowEntry(
    ts_unix: i64,
    session_id: []const u8,
    input: rules.Input,
    buffer: OverflowBuffer,
) Entry {
    return .{
        .ts_unix = ts_unix,
        .session_id = session_id,
        .input = input,
        .hit = .{
            .rule = &overflow_rule,
            .kind = .substring,
            .field = .command,
            .value = buffer.label(),
            .span = .{ .start = 0, .len = 0 },
        },
        .decision = .log,
    };
}

// ---------------------------------------------------------------------------
// line formatting
// ---------------------------------------------------------------------------

const LineMatcher = struct {
    kind: []const u8,
    field: []const u8,
    value: []const u8,
};

/// The serialized shape. Field order here is the field order on the wire.
const Line = struct {
    ts_unix: i64,
    session_id: []const u8,
    /// Which hook event produced the hit. Every line has one — a log written
    /// before events existed simply has none, and `stats` reads a missing key
    /// as `PreToolUse`, which is what those lines were.
    event: []const u8,
    tool: []const u8,
    rule: []const u8,
    decision: []const u8,
    matcher: LineMatcher,
    span: []const u8,
    /// The value a structural matcher compared against, when it differs from
    /// nothing at all. Omitted entirely for a textual or `signal` hit.
    resolved: ?[]const u8 = null,
    /// How `resolved` was arrived at. Omitted alongside it.
    origin: ?[]const u8 = null,
    command_logged: bool,
    /// Omitted entirely (not emitted as null) when `log_commands` is off.
    command: ?[]const u8 = null,
};

/// Serialize one entry as a single newline-terminated JSON line.
///
/// Escaping is std.json's job: rule names, matcher values, spans and command
/// text are all attacker- or operator-influenced, and none of them may be able
/// to inject a newline and forge a second log line.
pub fn writeLine(writer: *std.Io.Writer, entry: Entry, options: Options) std.Io.Writer.Error!void {
    var field_buf: [FIELD_BUF_BYTES]u8 = undefined;
    var span_buf: [FIELD_BUF_BYTES]u8 = undefined;
    var resolved_buf: [FIELD_BUF_BYTES]u8 = undefined;

    const line = Line{
        .ts_unix = entry.ts_unix,
        .session_id = entry.session_id,
        .event = entry.input.event.name(),
        .tool = entry.input.tool,
        .rule = entry.hit.rule.name,
        .decision = entry.decision.wire(),
        .matcher = .{
            .kind = @tagName(entry.hit.kind),
            .field = @tagName(entry.hit.field),
            .value = entry.hit.value,
        },
        .span = capped(entry.spanText(), &span_buf),
        .resolved = if (entry.hit.provenance) |p| capped(p.resolved, &resolved_buf) else null,
        .origin = if (entry.hit.provenance) |p| @tagName(p.origin) else null,
        .command_logged = options.log_commands,
        .command = if (options.log_commands) capped(entry.fieldText(), &field_buf) else null,
    };

    std.json.Stringify.value(line, .{ .emit_null_optional_fields = false }, writer) catch |err| switch (err) {
        error.WriteFailed => return error.WriteFailed,
    };
    try writer.writeByte('\n');
}

const TRUNCATION_MARKER = "…[truncated, {d} bytes total]";

/// `text`, or its first `MAX_FIELD_BYTES` bytes plus a marker naming the full
/// length. Truncation backs off to a UTF-8 boundary so the emitted string
/// stays valid JSON text rather than a half codepoint.
fn capped(text: []const u8, buf: []u8) []const u8 {
    if (text.len <= MAX_FIELD_BYTES) return text;
    const head = text[0..utf8BoundaryAtOrBefore(text, MAX_FIELD_BYTES)];
    var fixed = std.Io.Writer.fixed(buf);
    fixed.writeAll(head) catch return head;
    fixed.print(TRUNCATION_MARKER, .{text.len}) catch return head;
    return fixed.buffered();
}

/// The largest index `<= at` that does not sit inside a UTF-8 sequence.
/// Continuation bytes are `0b10xxxxxx`; a boundary is anything else.
fn utf8BoundaryAtOrBefore(text: []const u8, at: usize) usize {
    var end = @min(at, text.len);
    while (end > 0 and end < text.len and (text[end] & 0xC0) == 0x80) end -= 1;
    return end;
}

// ---------------------------------------------------------------------------
// path resolution
// ---------------------------------------------------------------------------

/// Where the log goes: `CLAUDE_HOOK_LOG_PATH`, else the rule file's
/// `logging.path`, else `$HOME/.claude/hook-gate-log.jsonl`. Returns null when
/// none of the three yields anything (no env override, no configured path, no
/// HOME) — logging is simply off in that case, which is the right answer for a
/// best-effort facility that must never fail a decision.
///
/// Every input is a plain parameter: the caller reads the environment, this
/// stays testable.
pub fn resolvePath(
    allocator: std.mem.Allocator,
    env_path: ?[]const u8,
    config_path: ?[]const u8,
    home: ?[]const u8,
) std.mem.Allocator.Error!?[]u8 {
    if (present(env_path)) |path| return try allocator.dupe(u8, path);
    if (present(config_path)) |path| return try allocator.dupe(u8, path);
    const home_dir = present(home) orelse return null;
    return try std.fs.path.join(allocator, &.{ home_dir, ".claude", DEFAULT_LOG_NAME });
}

/// An explicitly empty setting is treated as absent, so `CLAUDE_HOOK_LOG_PATH=`
/// falls through to the config rather than naming the empty path.
fn present(value: ?[]const u8) ?[]const u8 {
    const v = value orelse return null;
    return if (v.len == 0) null else v;
}

// ---------------------------------------------------------------------------
// the logger
// ---------------------------------------------------------------------------

pub const Logger = struct {
    io: std.Io,
    /// Resolved target. An empty path disables the logger just as surely as
    /// `enabled = false`.
    path: []const u8,
    enabled: bool,
    options: Options,
    /// Where the one-and-only failure note goes. Null silences even that.
    stderr: ?*std.Io.Writer,
    /// A broken log stays broken for the life of the process; nobody needs the
    /// same message once per hit.
    noted_failure: bool = false,
    /// Rotate above this size; zero means never. See `maybeRotate`.
    max_bytes: u64 = 0,
    /// The size check happens once, before the first line this process
    /// writes. A gate invocation appends a handful of lines at most, so
    /// re-checking per line would only buy the ability to rotate mid-batch.
    rotate_checked: bool = false,

    pub fn init(
        io: std.Io,
        config: rules.Logging,
        resolved_path: ?[]const u8,
        stderr: ?*std.Io.Writer,
    ) Logger {
        return .{
            .io = io,
            .path = resolved_path orelse "",
            .enabled = config.enabled,
            .options = .{ .log_commands = config.log_commands },
            .stderr = stderr,
            .max_bytes = config.max_bytes,
        };
    }

    /// A logger that writes nothing — for callers that resolved no path.
    pub fn disabled(io: std.Io) Logger {
        return .{ .io = io, .path = "", .enabled = false, .options = .{}, .stderr = null };
    }

    pub fn isActive(self: *const Logger) bool {
        return self.enabled and self.path.len > 0;
    }

    /// Append one line. Never fails: a problem is noted once on stderr and
    /// then swallowed, because a gate that stops deciding when its log breaks
    /// is worse than a gate with a gap in its log.
    pub fn record(self: *Logger, entry: Entry) void {
        if (!self.isActive()) return;
        self.append(entry) catch |err| self.note(err);
    }

    fn append(self: *Logger, entry: Entry) !void {
        if (!self.rotate_checked) {
            self.rotate_checked = true;
            self.maybeRotate();
        }
        var buf: [LINE_BUF_BYTES]u8 = undefined;
        var fixed = std.Io.Writer.fixed(&buf);
        try writeLine(&fixed, entry, self.options);
        try appendLine(self.io, self.path, fixed.buffered());
    }

    /// If the log has grown past `max_bytes`, move it aside to `<path>.1` —
    /// replacing whatever `.1` was there — so the next append starts a fresh
    /// file.
    ///
    /// Best-effort like everything else here, and silent: a failed rotation
    /// costs nothing but a log that keeps growing, which is strictly better
    /// than a noisy gate. `rename` is atomic, so a reader either sees the old
    /// file or the new one, never a half-moved log; a concurrent gate process
    /// that had already opened the file simply writes its line into the
    /// rotated generation.
    fn maybeRotate(self: *Logger) void {
        if (self.max_bytes == 0) return;
        const cwd = std.Io.Dir.cwd();
        const stat = cwd.statFile(self.io, self.path, .{}) catch return;
        if (stat.size <= self.max_bytes) return;

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const rotated = std.fmt.bufPrint(&buf, "{s}.1", .{self.path}) catch return;
        cwd.rename(self.path, cwd, rotated, self.io) catch return;
    }

    fn note(self: *Logger, err: anyerror) void {
        if (self.noted_failure) return;
        self.noted_failure = true;
        const stderr = self.stderr orelse return;
        stderr.print(
            "claude-hooker-gate: decision log unavailable ({s}: {s}); decisions are unaffected\n",
            .{ self.path, @errorName(err) },
        ) catch {};
        stderr.flush() catch {};
    }
};

/// One open-append-close per line, with a single `write` in between.
///
/// `O_APPEND` is what makes this safe without a lock: the kernel makes the
/// seek-to-end and the write one atomic step for a regular file, so two gate
/// processes racing on the same log interleave whole lines instead of
/// corrupting each other's. std.Io.Dir's `createFile` has no append mode in
/// 0.16, hence the direct `openat`; the fd is then wrapped in an `std.Io.File`
/// so the write goes through the normal Io interface.
///
/// No handle is held across invocations — the gate is a short-lived process
/// and a held fd would only be a way to lose a line on an unclean exit.
fn appendLine(io: std.Io, path: []const u8, line: []const u8) !void {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer file.close(io);
    try file.writeStreamingAll(io, line);
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testRule(name: []const u8, decision: rules.Decision) rules.Rule {
    return .{ .name = name, .decision = decision, .reason = "because" };
}

fn renderLine(allocator: std.mem.Allocator, entry: Entry, options: Options) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();
    try writeLine(&aw.writer, entry, options);
    return aw.toOwnedSlice();
}

test "a rendered line parses back and carries the whole schema" {
    const rule = testRule("no-pkill", .deny);
    const command = "bash -lc \"pkill -f svc\"";
    const entry = Entry{
        .ts_unix = 1_750_000_000,
        .session_id = "sess-abc",
        .input = .{ .tool = "Bash", .command = command },
        .hit = .{ .rule = &rule, .kind = .word, .field = .command, .value = "pkill", .span = .{ .start = 10, .len = 5 } },
        .decision = .deny,
    };

    const line = try renderLine(testing.allocator, entry, .{});
    defer testing.allocator.free(line);

    try testing.expect(std.mem.endsWith(u8, line, "\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqual(@as(i64, 1_750_000_000), obj.get("ts_unix").?.integer);
    try testing.expectEqualStrings("sess-abc", obj.get("session_id").?.string);
    try testing.expectEqualStrings("Bash", obj.get("tool").?.string);
    try testing.expectEqualStrings("no-pkill", obj.get("rule").?.string);
    try testing.expectEqualStrings("deny", obj.get("decision").?.string);
    try testing.expectEqualStrings("pkill", obj.get("span").?.string);
    try testing.expectEqual(false, obj.get("command_logged").?.bool);
    try testing.expect(obj.get("command") == null);

    const matcher = obj.get("matcher").?.object;
    try testing.expectEqualStrings("word", matcher.get("kind").?.string);
    try testing.expectEqualStrings("command", matcher.get("field").?.string);
    try testing.expectEqualStrings("pkill", matcher.get("value").?.string);

    // A textual hit carries no provenance, so the two structural keys are
    // absent entirely rather than present as null. Every consumer written
    // before they existed reads exactly the line it read before.
    try testing.expect(obj.get("resolved") == null);
    try testing.expect(obj.get("origin") == null);
}

test "a structural hit records the value it resolved and where it came from" {
    const rule = testRule("no-pkill", .deny);
    // The command the operator wrote says `$P$K`; the span records that, and
    // on its own it would never say `pkill`. These two keys are the whole
    // reason a reader of the log can tell what was about to run.
    const command = "P=pki; K=ll; $P$K -f svc";
    const entry = Entry{
        .ts_unix = 1_750_000_000,
        .session_id = "s",
        .input = .{ .tool = "Bash", .command = command },
        .hit = .{
            .rule = &rule,
            .kind = .command_word,
            .field = .command,
            .value = "pkill",
            .span = .{ .start = 13, .len = 4 },
            .provenance = .{
                .resolved = "pkill",
                .origin = .resolved_concat,
                .depth = 0,
                .wrapper = .top,
            },
        },
        .decision = .deny,
    };

    const line = try renderLine(testing.allocator, entry, .{});
    defer testing.allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("command_word", obj.get("matcher").?.object.get("kind").?.string);
    try testing.expectEqualStrings("$P$K", obj.get("span").?.string);
    try testing.expectEqualStrings("pkill", obj.get("resolved").?.string);
    try testing.expectEqualStrings("resolved_concat", obj.get("origin").?.string);
    // Still one line, still no way for a recovered value to forge a second.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
}

test "a literal structural hit still records its origin, so the key is predictable" {
    const rule = testRule("no-pkill", .deny);
    const command = "sudo pkill -9 svc";
    const entry = Entry{
        .ts_unix = 1,
        .input = .{ .tool = "Bash", .command = command },
        .hit = .{
            .rule = &rule,
            .kind = .command_word,
            .field = .command,
            .value = "pkill",
            .span = .{ .start = 5, .len = 5 },
            .provenance = .{ .resolved = "pkill", .origin = .literal, .depth = 1, .wrapper = .privilege },
        },
        .decision = .deny,
    };
    const line = try renderLine(testing.allocator, entry, .{});
    defer testing.allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    // Present exactly when the hit carries provenance — never "sometimes",
    // which is what would make a consumer guess.
    try testing.expectEqualStrings("pkill", parsed.value.object.get("resolved").?.string);
    try testing.expectEqualStrings("literal", parsed.value.object.get("origin").?.string);
}

test "a recovered value is capped like every other operator-influenced string" {
    const rule = testRule("big", .log);
    const huge = "x" ** (MAX_FIELD_BYTES + 100);
    const entry = Entry{
        .ts_unix = 1,
        .input = .{ .tool = "Bash", .command = "cmd" },
        .hit = .{
            .rule = &rule,
            .kind = .command_line,
            .field = .command,
            .value = "cmd",
            .span = .{ .start = 0, .len = 3 },
            .provenance = .{ .resolved = huge, .origin = .resolved_var },
        },
        .decision = .log,
    };
    const line = try renderLine(testing.allocator, entry, .{});
    defer testing.allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const resolved = parsed.value.object.get("resolved").?.string;
    try testing.expect(resolved.len < huge.len);
    try testing.expect(std.mem.indexOf(u8, resolved, "truncated") != null);
}

test "every decision spelling round-trips, including bypassed" {
    const cases = [_]struct { decision: LoggedDecision, wire: []const u8 }{
        .{ .decision = .deny, .wire = "deny" },
        .{ .decision = .ask, .wire = "ask" },
        .{ .decision = .allow, .wire = "allow" },
        .{ .decision = .log, .wire = "log" },
        .{ .decision = .bypassed, .wire = "bypassed" },
    };
    const rule = testRule("r", .deny);
    for (cases) |case| {
        const entry = Entry{
            .ts_unix = 1,
            .input = .{ .command = "ls" },
            .hit = .{ .rule = &rule, .kind = .tokens, .field = .command, .value = "ls", .span = .{ .start = 0, .len = 2 } },
            .decision = case.decision,
        };
        const line = try renderLine(testing.allocator, entry, .{});
        defer testing.allocator.free(line);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings(case.wire, parsed.value.object.get("decision").?.string);
    }

    try testing.expectEqual(LoggedDecision.deny, LoggedDecision.fromDecision(.deny));
    try testing.expectEqual(LoggedDecision.ask, LoggedDecision.fromDecision(.ask));
    try testing.expectEqual(LoggedDecision.allow, LoggedDecision.fromDecision(.allow));
    try testing.expectEqual(LoggedDecision.log, LoggedDecision.fromDecision(.log));
}

test "log_commands is opt-in and carries the matched field, not the command field" {
    const rule = testRule("secret-in-content", .deny);
    const body = "TOKEN=hunter2\n";
    const entry = Entry{
        .ts_unix = 2,
        .input = .{ .tool = "Write", .command = "unused", .file_path = "/x/app.env", .content = body },
        .hit = .{ .rule = &rule, .kind = .word, .field = .content, .value = "TOKEN", .span = .{ .start = 0, .len = 5 } },
        .decision = .deny,
    };

    const off = try renderLine(testing.allocator, entry, .{ .log_commands = false });
    defer testing.allocator.free(off);
    try testing.expect(std.mem.indexOf(u8, off, "hunter2") == null);
    try testing.expect(std.mem.indexOf(u8, off, "\"command_logged\":false") != null);

    const on = try renderLine(testing.allocator, entry, .{ .log_commands = true });
    defer testing.allocator.free(on);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, on, .{});
    defer parsed.deinit();
    try testing.expectEqual(true, parsed.value.object.get("command_logged").?.bool);
    // The *matched* field is the one recorded — content here, not `command`.
    try testing.expectEqualStrings(body, parsed.value.object.get("command").?.string);
}

test "an over-long field is truncated with a marker and stays valid JSON" {
    const rule = testRule("big", .log);
    const huge = try testing.allocator.alloc(u8, MAX_FIELD_BYTES * 3);
    defer testing.allocator.free(huge);
    @memset(huge, 'x');
    // A control character and a quote, to prove escaping survives truncation.
    huge[5] = '\n';
    huge[6] = '"';

    const entry = Entry{
        .ts_unix = 3,
        .input = .{ .command = huge },
        .hit = .{ .rule = &rule, .kind = .substring, .field = .command, .value = "xx", .span = .{ .start = 0, .len = 2 } },
        .decision = .log,
    };
    const line = try renderLine(testing.allocator, entry, .{ .log_commands = true });
    defer testing.allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const command = parsed.value.object.get("command").?.string;
    try testing.expect(command.len < huge.len);
    try testing.expect(command.len >= MAX_FIELD_BYTES);
    try testing.expect(std.mem.indexOf(u8, command, "truncated") != null);
    try testing.expect(std.mem.indexOf(u8, command, "12288") != null);
}

test "truncation lands on a UTF-8 boundary" {
    // Fill exactly up to the cap with ASCII, then a 3-byte codepoint that
    // straddles it: the cut must drop the whole codepoint, not split it.
    const cp = "€"; // 3 bytes
    const text = try testing.allocator.alloc(u8, MAX_FIELD_BYTES + 16);
    defer testing.allocator.free(text);
    @memset(text, 'a');
    @memcpy(text[MAX_FIELD_BYTES - 1 ..][0..cp.len], cp);

    var buf: [FIELD_BUF_BYTES]u8 = undefined;
    const out = capped(text, &buf);
    try testing.expect(std.unicode.utf8ValidateSlice(out[0 .. MAX_FIELD_BYTES - 1]));
    try testing.expectEqual(@as(usize, MAX_FIELD_BYTES - 1), std.mem.indexOf(u8, out, "…").?);

    // Short text is returned untouched, no marker.
    try testing.expectEqualStrings("short", capped("short", &buf));
}

test "a span is clamped to its field rather than trusted" {
    const rule = testRule("r", .deny);
    const entry = Entry{
        .ts_unix = 4,
        .input = .{ .command = "abc" },
        .hit = .{ .rule = &rule, .kind = .substring, .field = .command, .value = "abcdef", .span = .{ .start = 2, .len = 99 } },
        .decision = .deny,
    };
    try testing.expectEqualStrings("c", entry.spanText());
}

test "path precedence: env beats config beats HOME default" {
    const a = testing.allocator;

    const from_env = (try resolvePath(a, "/tmp/env.jsonl", "/tmp/cfg.jsonl", "/home/u")).?;
    defer a.free(from_env);
    try testing.expectEqualStrings("/tmp/env.jsonl", from_env);

    const from_cfg = (try resolvePath(a, null, "/tmp/cfg.jsonl", "/home/u")).?;
    defer a.free(from_cfg);
    try testing.expectEqualStrings("/tmp/cfg.jsonl", from_cfg);

    const from_home = (try resolvePath(a, null, null, "/home/u")).?;
    defer a.free(from_home);
    try testing.expectEqualStrings("/home/u/.claude/" ++ DEFAULT_LOG_NAME, from_home);

    // An empty setting is absent, not "the empty path".
    const empty_env = (try resolvePath(a, "", "/tmp/cfg.jsonl", "/home/u")).?;
    defer a.free(empty_env);
    try testing.expectEqualStrings("/tmp/cfg.jsonl", empty_env);

    // Nothing resolvable at all: logging is simply off.
    try testing.expect((try resolvePath(a, null, null, null)) == null);
    try testing.expect((try resolvePath(a, null, null, "")) == null);
}

// ---- writing to a real file ----------------------------------------------

const LogFixture = struct {
    tmp: testing.TmpDir,
    dir_path: []u8,
    log_path: []u8,

    fn init(name: []const u8) !LogFixture {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const dir_path = try std.fmt.allocPrint(
            testing.allocator,
            ".zig-cache" ++ std.fs.path.sep_str ++ "tmp" ++ std.fs.path.sep_str ++ "{s}",
            .{tmp.sub_path},
        );
        errdefer testing.allocator.free(dir_path);
        const log_path = try std.fs.path.join(testing.allocator, &.{ dir_path, name });
        return .{ .tmp = tmp, .dir_path = dir_path, .log_path = log_path };
    }

    fn deinit(self: *LogFixture) void {
        testing.allocator.free(self.log_path);
        testing.allocator.free(self.dir_path);
        self.tmp.cleanup();
    }

    fn read(self: *LogFixture) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(testing.io, self.log_path, testing.allocator, .limited(1 << 20));
    }

    fn exists(self: *LogFixture) bool {
        std.Io.Dir.cwd().access(testing.io, self.log_path, .{}) catch return false;
        return true;
    }
};

fn sampleEntry(rule: *const rules.Rule, decision: LoggedDecision) Entry {
    return .{
        .ts_unix = 1_700_000_000,
        .session_id = "s1",
        .input = .{ .tool = "Bash", .command = "git add -A" },
        .hit = .{ .rule = rule, .kind = .tokens, .field = .command, .value = "git add -A", .span = .{ .start = 0, .len = 10 } },
        .decision = decision,
    };
}

test "records append: repeated writes accumulate whole lines" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("no-git-add-all", .deny);
    var logger = Logger.init(testing.io, .{}, fixture.log_path, null);
    try testing.expect(logger.isActive());

    logger.record(sampleEntry(&rule, .deny));
    logger.record(sampleEntry(&rule, .bypassed));
    // A second logger, as a second process would: appends rather than truncates.
    var again = Logger.init(testing.io, .{}, fixture.log_path, null);
    again.record(sampleEntry(&rule, .log));

    const body = try fixture.read();
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, body, "\n"));

    var it = std.mem.tokenizeScalar(u8, body, '\n');
    const expected = [_][]const u8{ "deny", "bypassed", "log" };
    var i: usize = 0;
    while (it.next()) |raw| : (i += 1) {
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, raw, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings(expected[i], parsed.value.object.get("decision").?.string);
    }
    try testing.expectEqual(@as(usize, 3), i);
}

test "logging.enabled=false writes nothing at all" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("r", .deny);
    var logger = Logger.init(testing.io, .{ .enabled = false }, fixture.log_path, null);
    try testing.expect(!logger.isActive());
    logger.record(sampleEntry(&rule, .deny));

    // Not merely empty — never created.
    try testing.expect(!fixture.exists());
}

test "an unresolvable path disables the logger instead of failing" {
    const rule = testRule("r", .deny);
    var logger = Logger.init(testing.io, .{}, null, null);
    try testing.expect(!logger.isActive());
    logger.record(sampleEntry(&rule, .deny));
    try testing.expect(!logger.noted_failure);
}

test "an unwritable path notes once on stderr and keeps going" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    // A path whose parent directory does not exist.
    const bad = try std.fs.path.join(testing.allocator, &.{ fixture.dir_path, "no-such-dir", "log.jsonl" });
    defer testing.allocator.free(bad);

    var note_buf: [512]u8 = undefined;
    var note = std.Io.Writer.fixed(&note_buf);

    const rule = testRule("r", .deny);
    var logger = Logger.init(testing.io, .{}, bad, &note);
    logger.record(sampleEntry(&rule, .deny));
    logger.record(sampleEntry(&rule, .deny));
    logger.record(sampleEntry(&rule, .deny));

    try testing.expect(logger.noted_failure);
    const noted = note.buffered();
    try testing.expect(std.mem.indexOf(u8, noted, "decision log unavailable") != null);
    try testing.expect(std.mem.indexOf(u8, noted, "decisions are unaffected") != null);
    // One note for three failures.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, noted, "\n"));
}

test "log_commands writes the command through to the file" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("no-git-add-all", .deny);
    var logger = Logger.init(testing.io, .{ .log_commands = true }, fixture.log_path, null);
    logger.record(sampleEntry(&rule, .deny));

    const body = try fixture.read();
    defer testing.allocator.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, std.mem.trimEnd(u8, body, "\n"), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("git add -A", parsed.value.object.get("command").?.string);
}

// ---- end-to-end with the evaluator ---------------------------------------

const bypass_rules_json =
    \\{
    \\  "logging": { "enabled": true, "log_commands": false },
    \\  "rules": [
    \\    { "name": "watch-git", "decision": "log", "reason": "observe",
    \\      "match": [ { "kind": "word", "value": "git" } ] },
    \\    { "name": "no-git-add-all", "decision": "deny", "reason": "stage explicitly",
    \\      "match": [ { "kind": "tokens", "value": "git add -A" } ] },
    \\    { "name": "ask-any-git-add", "decision": "ask", "reason": "confirm",
    \\      "match": [ { "kind": "tokens", "value": "git add" } ] }
    \\  ]
    \\}
;

test "bypassed flow: the disabled rule is logged, the next rule still enforces" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    var loaded = try rules.parse(testing.allocator, bypass_rules_json);
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    const input = rules.Input{ .tool = "Bash", .command = "git add -A" };
    const result = rules.evaluateWith(rule_set, input, .init("no-git-add-all"));

    // The deny is bypassed; the ask BELOW it is what gets enforced.
    try testing.expectEqual(@as(usize, 1), result.bypassedHits().len);
    try testing.expectEqualStrings("no-git-add-all", result.bypassedHits()[0].rule.name);
    const enforced = result.enforced orelse return error.TestExpectedMatch;
    try testing.expectEqualStrings("ask-any-git-add", enforced.rule.name);

    var logger = Logger.init(testing.io, rule_set.logging, fixture.log_path, null);
    for (result.bypassedHits()) |hit| {
        logger.record(.{ .ts_unix = 9, .session_id = "s", .input = input, .hit = hit, .decision = .bypassed });
    }
    for (result.shadowHits()) |hit| {
        logger.record(.{ .ts_unix = 9, .session_id = "s", .input = input, .hit = hit, .decision = .log });
    }
    logger.record(.{
        .ts_unix = 9,
        .session_id = "s",
        .input = input,
        .hit = enforced,
        .decision = LoggedDecision.fromDecision(enforced.rule.decision),
    });

    const body = try fixture.read();
    defer testing.allocator.free(body);

    var it = std.mem.tokenizeScalar(u8, body, '\n');
    const want = [_][2][]const u8{
        .{ "no-git-add-all", "bypassed" },
        .{ "watch-git", "log" },
        .{ "ask-any-git-add", "ask" },
    };
    var i: usize = 0;
    while (it.next()) |raw| : (i += 1) {
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, raw, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings(want[i][0], parsed.value.object.get("rule").?.string);
        try testing.expectEqualStrings(want[i][1], parsed.value.object.get("decision").?.string);
    }
    try testing.expectEqual(@as(usize, 3), i);
}

// ---- rotation -------------------------------------------------------------

fn rotatedPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.1", .{path});
}

test "a log past max_bytes is moved aside and a fresh one started" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("no-git-add-all", .deny);

    // Fill the log well past a deliberately tiny cap.
    var filling = Logger.init(testing.io, .{ .max_bytes = 64 }, fixture.log_path, null);
    filling.record(sampleEntry(&rule, .deny));
    filling.record(sampleEntry(&rule, .deny));
    const before = try fixture.read();
    defer testing.allocator.free(before);
    try testing.expect(before.len > 64);

    // A new process (a new Logger) checks the size once and rotates.
    var rotating = Logger.init(testing.io, .{ .max_bytes = 64 }, fixture.log_path, null);
    rotating.record(sampleEntry(&rule, .ask));

    const fresh = try fixture.read();
    defer testing.allocator.free(fresh);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, fresh, "\n"));
    try testing.expect(std.mem.indexOf(u8, fresh, "\"ask\"") != null);

    // The previous generation is intact beside it.
    const rotated = try rotatedPath(testing.allocator, fixture.log_path);
    defer testing.allocator.free(rotated);
    const kept = try std.Io.Dir.cwd().readFileAlloc(testing.io, rotated, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings(before, kept);
}

test "rotation replaces the previous generation rather than accumulating" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("r", .deny);
    const rotated = try rotatedPath(testing.allocator, fixture.log_path);
    defer testing.allocator.free(rotated);

    // Three separate "processes", each finding an over-cap log.
    for (0..3) |_| {
        var logger = Logger.init(testing.io, .{ .max_bytes = 1 }, fixture.log_path, null);
        logger.record(sampleEntry(&rule, .deny));
    }

    const live = try fixture.read();
    defer testing.allocator.free(live);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, live, "\n"));

    const kept = try std.Io.Dir.cwd().readFileAlloc(testing.io, rotated, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(kept);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, kept, "\n"));

    // Exactly two generations exist: no .2 was ever created.
    const second = try std.fmt.allocPrint(testing.allocator, "{s}.2", .{fixture.log_path});
    defer testing.allocator.free(second);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().access(testing.io, second, .{}),
    );
}

test "a log under the cap, and max_bytes = 0, are left alone" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    const rule = testRule("r", .deny);
    var first = Logger.init(testing.io, .{}, fixture.log_path, null);
    first.record(sampleEntry(&rule, .deny));

    // Default cap: nowhere near it.
    var second = Logger.init(testing.io, .{}, fixture.log_path, null);
    second.record(sampleEntry(&rule, .deny));
    // Rotation switched off entirely, with a cap the log has long passed.
    var third = Logger.init(testing.io, .{ .max_bytes = 0 }, fixture.log_path, null);
    third.record(sampleEntry(&rule, .deny));

    const body = try fixture.read();
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, body, "\n"));

    const rotated = try rotatedPath(testing.allocator, fixture.log_path);
    defer testing.allocator.free(rotated);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().access(testing.io, rotated, .{}),
    );
}

test "the configured cap reaches the logger, and defaults to ten megabytes" {
    var loaded = try rules.parse(testing.allocator, "{ \"rules\": [], \"logging\": { \"max_bytes\": 4096 } }");
    defer loaded.deinit();
    const cfg = loaded.ruleSet().logging;
    try testing.expectEqual(@as(u64, 4096), cfg.max_bytes);

    const logger = Logger.init(testing.io, cfg, "/tmp/x.jsonl", null);
    try testing.expectEqual(@as(u64, 4096), logger.max_bytes);
    try testing.expect(!logger.rotate_checked);

    var defaults = try rules.parse(testing.allocator, "{ \"rules\": [] }");
    defer defaults.deinit();
    try testing.expectEqual(@as(u64, 10 * 1024 * 1024), defaults.ruleSet().logging.max_bytes);
}

// ---- the overflow marker --------------------------------------------------

test "an overflow marker names its buffer and reads as a log line" {
    const input = rules.Input{ .tool = "Bash", .command = "git status" };
    const entry = overflowEntry(1_700_000_000, "s1", input, .shadow);

    const line = try renderLine(testing.allocator, entry, .{});
    defer testing.allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings("_overflow", obj.get("rule").?.string);
    try testing.expectEqualStrings("log", obj.get("decision").?.string);
    try testing.expectEqualStrings("shadow_hits", obj.get("matcher").?.object.get("value").?.string);
    // No matched bytes to point at.
    try testing.expectEqualStrings("", obj.get("span").?.string);
    try testing.expectEqualStrings("Bash", obj.get("tool").?.string);

    const bypassed = overflowEntry(1, "", input, .bypassed);
    try testing.expectEqualStrings("bypassed_hits", bypassed.hit.value);
    try testing.expectEqualStrings("_overflow", bypassed.hit.rule.name);
}

test "an evaluation that overflows produces a marker line ahead of the hits" {
    var fixture = try LogFixture.init("log.jsonl");
    defer fixture.deinit();

    // More simultaneously-matching log rules than the evaluator records.
    var rule_buf: [rules.MAX_SHADOW_HITS + 4]rules.Rule = undefined;
    for (&rule_buf) |*rule| {
        rule.* = .{
            .name = "watch",
            .decision = .log,
            .reason = "observe",
            .match = &.{.{ .kind = .word, .value = "git" }},
        };
    }

    const input = rules.Input{ .tool = "Bash", .command = "git status" };
    const result = rules.evaluateOverlay(&.{}, &rule_buf, input, .none);
    try testing.expect(result.shadow_overflow);

    // The same order `main` writes in: the marker, then the hits it qualifies.
    var logger = Logger.init(testing.io, .{}, fixture.log_path, null);
    if (result.shadow_overflow) logger.record(overflowEntry(7, "s", input, .shadow));
    for (result.shadowHits()) |hit| {
        logger.record(.{ .ts_unix = 7, .session_id = "s", .input = input, .hit = hit, .decision = .log });
    }

    const body = try fixture.read();
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, rules.MAX_SHADOW_HITS + 1), std.mem.count(u8, body, "\n"));

    var it = std.mem.tokenizeScalar(u8, body, '\n');
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, it.next().?, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("_overflow", parsed.value.object.get("rule").?.string);
}

test "the logging block drives the logger's behavior" {
    const json =
        \\{ "logging": { "enabled": false, "log_commands": true, "path": "/tmp/custom.jsonl" }, "rules": [] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    const cfg = loaded.ruleSet().logging;

    var logger = Logger.init(testing.io, cfg, cfg.path, null);
    try testing.expect(!logger.isActive());
    try testing.expect(logger.options.log_commands);
    try testing.expectEqualStrings("/tmp/custom.jsonl", logger.path);
}

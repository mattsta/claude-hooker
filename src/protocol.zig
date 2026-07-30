//! Claude Code hook wire protocol: one payload parse in, one event-specific
//! response envelope out.
//!
//! ## Input (stdin)
//!
//! The hook event JSON. `hook_event_name` says which event it is; everything
//! matchable about it comes from `events.Descriptor.bindings`, which names the
//! payload keys that event supplies and the `Field` each one becomes. So this
//! module holds ONE flat struct covering every key any event can carry
//! (`RawEvent`) and ONE total switch from a `Source` to the slice it names
//! (`textOf`) — not thirty parses. Adding an event's payload is a row in the
//! table plus, at most, a key here.
//!
//! Unknown fields are ignored throughout, deliberately: the harness adds keys
//! to payloads between releases, and a gate that refused a payload it did not
//! fully recognize would stop enforcing on the day of an upgrade. (Rule FILES
//! are the opposite — there, an unknown key is a typo in operator-authored
//! policy and is refused. See `rules.parse`.)
//!
//! Two top-level keys are read but never matched on: `session_id`, which
//! attributes a logged hit to the session that produced it, and `cwd`, the
//! fallback used to locate a project rule overlay.
//!
//! ## Output (stdout)
//!
//! The response envelope — and there is no such thing as "the" response
//! envelope. Every event answers differently, so the shape comes from
//! `Descriptor.block`:
//!
//!   - `PreToolUse`             `hookSpecificOutput.permissionDecision`
//!   - `PermissionRequest`      `hookSpecificOutput.decision.behavior`
//!   - `Stop`, `PostToolUse`,
//!     `UserPromptSubmit`, …    top-level `decision: "block"` + `reason`
//!   - `TeammateIdle`, `Task*`  top-level `continue: false` + `stopReason`
//!   - `Elicitation`            `hookSpecificOutput.action: "decline"`
//!   - `WorktreeCreate`         no envelope at all: exit 1
//!   - the thirteen advisory
//!     events                   nothing; there is nothing to say
//!
//! Emitting nothing and exiting 0 means "no opinion" — whatever the harness
//! would have done, it still does.
//!
//! **Exit 2 is never used.** Per the hooks contract, exit 2 makes the harness
//! read stderr as the refusal and DISCARD any JSON on stdout. Answering with
//! JSON is strictly better here: it carries the decision *and* the operator's
//! reason in one structured value the harness attributes correctly, on every
//! event that has an envelope. Mixing the two would mean two output contracts,
//! and the one that silently throws away the reason would be the one used in
//! the cases that matter most. `WorktreeCreate` is the sole event with no
//! envelope — it fails on any nonzero exit — so its refusal is exit 1, which is
//! still not exit 2.

const std = @import("std");
const rules = @import("rules.zig");
const events = @import("events.zig");

pub const Event = events.Event;

/// One parsed payload, ready to evaluate.
pub const Payload = struct {
    /// Null for an event name this build does not know. Not an error: a future
    /// harness may send one, and the only safe answer is silence — see
    /// `main.zig`.
    event: ?Event,
    /// The matchable view, with every field this event's bindings supply.
    input: rules.Input,
    /// The harness's conversation id, or "" when the payload omits it. Not
    /// matched on — it exists so the decision log can attribute a hit to the
    /// session that produced it.
    session_id: []const u8 = "",
    /// The directory the session is rooted in, or "" when the payload omits
    /// it. Not matched on either: it is the fallback used to locate a project
    /// rule overlay when `$CLAUDE_PROJECT_DIR` is unset.
    cwd: []const u8 = "",

    /// True when no field carries text to match against — nothing for the
    /// gate to have an opinion about.
    pub fn isEmpty(self: Payload) bool {
        return self.input.isEmpty();
    }
};

pub const ParseError = error{InvalidEvent} || std.mem.Allocator.Error;

/// Parsed payload plus its backing arena; call `deinit` when done.
///
/// The two travel together because the parse BORROWS from the source bytes and
/// from the arena: std.json hands back slices into the document for strings
/// that need no unescaping, so the payload's fields point into memory this
/// value owns.
pub const LoadedEvent = struct {
    parsed: std.json.Parsed(RawEvent),
    /// `changed_keys` flattened to a space-separated line, allocated in the
    /// parse's own arena. A JSON array is not a text field, and the matchers
    /// are all textual, so the one array any event binds is joined once here
    /// rather than given a matcher kind of its own.
    joined_keys: []const u8 = "",

    pub fn deinit(self: *LoadedEvent) void {
        self.parsed.deinit();
    }

    /// The event this payload names, or null for one this build predates.
    pub fn event(self: *const LoadedEvent) ?Event {
        return Event.from(self.parsed.value.hook_event_name);
    }

    /// The matchable payload. An unknown event yields an empty input scoped to
    /// the default event, which matches nothing — but callers should be
    /// checking `event()` and exiting quietly instead of relying on that.
    pub fn payload(self: *const LoadedEvent) Payload {
        const raw = self.parsed.value;
        const found = self.event();
        var input = rules.Input{
            .event = found orelse events.DEFAULT_EVENT,
            .tool = raw.tool_name,
        };
        if (found) |e| {
            const descriptor = e.descriptor();
            // The whole per-event payload mapping, in three lines: the table
            // says which key feeds which field, and `textOf` says where a key
            // lives. There is no per-event branch anywhere in this function.
            for (descriptor.bindings) |b| {
                setField(&input, b.field, self.textOf(b.source));
            }
        }
        return .{
            .event = found,
            .input = input,
            .session_id = raw.session_id,
            .cwd = raw.cwd,
        };
    }

    /// The slice one payload key names. Total over `Source`, so a key added to
    /// the catalog cannot be left unwired.
    fn textOf(self: *const LoadedEvent, source: events.Source) []const u8 {
        const raw = self.parsed.value;
        const in = raw.tool_input;
        return switch (source) {
            .tool_command => in.command,
            // Edit carries the text being introduced as `new_string`; rules
            // should not have to know which tool produced the bytes, so it maps
            // onto the same field Write's `content` does. When a payload
            // somehow carries both, `content` wins — it is the field Write
            // actually uses, and picking one keeps spans measurable against a
            // single text.
            .tool_content => if (in.content.len > 0) in.content else in.new_string,
            .tool_file_path => in.file_path,
            .tool_output => raw.tool_output,
            .tool_error => raw.@"error",
            .prompt_text => raw.prompt_text,
            .command_name => raw.command_name,
            .last_assistant_message => raw.last_assistant_message,
            .message_text => raw.message_text,
            .notification_message => raw.message,
            .notification_type => raw.notification_type,
            .payload_source => raw.source,
            .payload_trigger => raw.trigger,
            .payload_reason => raw.reason,
            .stop_reason => raw.stop_reason,
            .error_type => raw.error_type,
            .permission_rule => raw.permission_rule,
            .config_source => raw.config_source,
            .changed_keys => self.joined_keys,
            .change_type => raw.change_type,
            .watched_file_path => raw.file_path,
            .new_cwd => raw.new_cwd,
            .agent_type => raw.agent_type,
            .server_name => raw.server_name,
            .task_description => raw.description,
        };
    }
};

fn setField(input: *rules.Input, field: rules.Field, text: []const u8) void {
    switch (field) {
        .command => input.command = text,
        .content => input.content = text,
        .file_path => input.file_path = text,
        .prompt => input.prompt = text,
        .output => input.output = text,
        .message => input.message = text,
        .trigger => input.trigger = text,
        .agent => input.agent = text,
    }
}

/// The nested `tool_input` of the tool events.
const RawToolInput = struct {
    command: []const u8 = "",
    content: []const u8 = "",
    new_string: []const u8 = "",
    file_path: []const u8 = "",
};

/// Every payload key any event can carry, flat and all-optional.
///
/// One struct rather than thirty: a key means the same thing wherever it
/// appears (`source` is a session source on `SessionStart` and on `Setup`;
/// `reason` is a reason on `WorktreeCreate` and on `SessionEnd`), so the table
/// can name it once and every event that has it reads the same field. Keys an
/// event does not send are simply absent, which is why every default is "".
const RawEvent = struct {
    hook_event_name: []const u8 = "",
    session_id: []const u8 = "",
    cwd: []const u8 = "",
    tool_name: []const u8 = "",
    tool_input: RawToolInput = .{},
    tool_output: []const u8 = "",
    /// `error` on the wire: `PostToolUseFailure`'s failure text.
    @"error": []const u8 = "",
    prompt_text: []const u8 = "",
    command_name: []const u8 = "",
    last_assistant_message: []const u8 = "",
    message_text: []const u8 = "",
    message: []const u8 = "",
    notification_type: []const u8 = "",
    source: []const u8 = "",
    trigger: []const u8 = "",
    reason: []const u8 = "",
    stop_reason: []const u8 = "",
    error_type: []const u8 = "",
    permission_rule: []const u8 = "",
    config_source: []const u8 = "",
    changed_keys: []const []const u8 = &.{},
    change_type: []const u8 = "",
    file_path: []const u8 = "",
    new_cwd: []const u8 = "",
    agent_type: []const u8 = "",
    server_name: []const u8 = "",
    description: []const u8 = "",
};

pub fn parseEvent(allocator: std.mem.Allocator, bytes: []const u8) ParseError!LoadedEvent {
    var parsed = std.json.parseFromSlice(RawEvent, allocator, bytes, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidEvent,
    };
    errdefer parsed.deinit();

    // Joined into the parse's own arena, so it lives exactly as long as every
    // other borrowed slice in the payload.
    const joined = try std.mem.join(
        parsed.arena.allocator(),
        " ",
        parsed.value.changed_keys,
    );
    return .{ .parsed = parsed, .joined_keys = joined };
}

// ---------------------------------------------------------------------------
// the response envelope
// ---------------------------------------------------------------------------

/// What the gate did about an enforced hit, so `main` can flush and exit
/// without knowing anything about mechanisms.
pub const Answer = struct {
    /// A response document was written to the writer.
    wrote_json: bool = false,
    /// The process exit code. Nonzero for exactly one event; never 2.
    exit_code: u8 = 0,

    /// Nothing was said and nothing was refused.
    pub const silent: Answer = .{};
};

const PermissionOutput = struct {
    hookEventName: []const u8,
    permissionDecision: []const u8,
    permissionDecisionReason: []const u8,
};

const Behavior = struct {
    behavior: []const u8,
};

const BehaviorOutput = struct {
    hookEventName: []const u8,
    decision: Behavior,
};

const ActionOutput = struct {
    hookEventName: []const u8,
    action: []const u8,
};

fn Wrapped(comptime T: type) type {
    return struct { hookSpecificOutput: T };
}

const BlockResponse = struct {
    decision: []const u8 = "block",
    reason: []const u8,
};

const ContinueResponse = struct {
    @"continue": bool = false,
    stopReason: []const u8,
};

/// Serialize the decision for `event` in the shape that event accepts, and say
/// what the process should do about it.
///
/// JSON escaping of the reason (quotes, newlines, unicode) is std.json's job —
/// reasons are operator-authored free text and must never be able to corrupt
/// the envelope.
///
/// Two cases write nothing and refuse nothing, and both are deliberate:
///
///   - a `log` rule is shadow-only, and reaching here with one is a caller bug
///     (asserted);
///   - a decision the event's envelope has no room for — an `ask` on `Stop`, a
///     `deny` on `SessionStart` — is a config bug the lint reports as an ERROR.
///     At run time it is silence rather than an invented envelope: a gate that
///     answered `Stop` with a `permissionDecision` would be making up protocol,
///     and the operator would have no way to see that it had.
pub fn writeDecision(
    writer: *std.Io.Writer,
    event: Event,
    rule: *const rules.Rule,
) !Answer {
    std.debug.assert(rule.decision.isEnforced());
    const descriptor = event.descriptor();
    if (!rule.decision.permittedBy(descriptor.vocabulary())) return .silent;

    const name = event.name();
    switch (descriptor.block) {
        // Advisory, and a display-only rewrite this gate does not perform. The
        // vocabulary check above has already returned for both; the arms exist
        // so the switch stays total and a new mechanism cannot be forgotten.
        .none, .display_content => return .silent,

        .permission_decision => {
            try std.json.Stringify.value(Wrapped(PermissionOutput){ .hookSpecificOutput = .{
                .hookEventName = name,
                .permissionDecision = rule.decision.wire(),
                .permissionDecisionReason = rule.reason,
            } }, .{}, writer);
        },

        .decision_behavior => {
            // No documented field carries a reason here, so the reason does not
            // travel — it is still recorded in the decision log, which is where
            // an operator finds out why a permission checkpoint was refused.
            try std.json.Stringify.value(Wrapped(BehaviorOutput){ .hookSpecificOutput = .{
                .hookEventName = name,
                .decision = .{ .behavior = rule.decision.wire() },
            } }, .{}, writer);
        },

        .decision_block => {
            try std.json.Stringify.value(BlockResponse{ .reason = rule.reason }, .{}, writer);
        },

        .continue_false => {
            try std.json.Stringify.value(ContinueResponse{ .stopReason = rule.reason }, .{}, writer);
        },

        .action => {
            // An elicitation is DECLINED, not denied: the vocabulary is
            // accept/decline/cancel, and `decline` is the one that refuses the
            // request without cancelling the whole tool call.
            try std.json.Stringify.value(Wrapped(ActionOutput){ .hookSpecificOutput = .{
                .hookEventName = name,
                .action = "decline",
            } }, .{}, writer);
        },

        .nonzero_exit => {
            // No envelope exists. The refusal IS the exit code, and the reason
            // goes to the decision log rather than to a field that does not
            // exist.
            return .{ .exit_code = descriptor.block_exit };
        },
    }
    return .{ .wrote_json = true };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Render one decision and hand back both the bytes and the answer.
fn render(buf: []u8, event: Event, rule: *const rules.Rule) !struct { text: []const u8, answer: Answer } {
    var fixed = std.Io.Writer.fixed(buf);
    const answer = try writeDecision(&fixed, event, rule);
    return .{ .text = fixed.buffered(), .answer = answer };
}

test "parse a real PreToolUse payload" {
    const payload =
        \\{"session_id":"abc","transcript_path":"/x","cwd":"/repo",
        \\ "hook_event_name":"PreToolUse","tool_name":"Bash",
        \\ "tool_input":{"command":"git add -A","description":"Stage all"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    const p = loaded.payload();
    try testing.expectEqual(Event.PreToolUse, p.event.?);
    try testing.expectEqualStrings("Bash", p.input.tool);
    try testing.expectEqualStrings("git add -A", p.input.command);
    try testing.expectEqualStrings("", p.input.content);
    try testing.expectEqualStrings("", p.input.file_path);
    try testing.expectEqualStrings("abc", p.session_id);
    try testing.expectEqualStrings("/repo", p.cwd);
    try testing.expect(!p.isEmpty());
}

test "a payload without session_id or cwd yields empty strings, not a parse error" {
    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expectEqualStrings("", loaded.payload().session_id);
    try testing.expectEqualStrings("", loaded.payload().cwd);
}

test "a payload with no hook_event_name at all is read as PreToolUse" {
    // The single-event gate's payloads, and every hand-written test fixture:
    // absent means the only event that existed, which is what keeps those
    // inputs meaning exactly what they meant.
    const payload =
        \\{"tool_name":"Bash","tool_input":{"command":"ls"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expect(loaded.event() == null);
    try testing.expectEqual(Event.PreToolUse, loaded.payload().input.event);
}

test "the payload cwd resolves a project overlay path when the env names none" {
    const payload =
        \\{"cwd":"/work/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();

    const path = (try rules.resolveProjectPath(testing.allocator, null, loaded.payload().cwd)).?;
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("/work/repo/.claude/hook-rules.json", path);
}

test "Write payloads expose content and file_path" {
    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"Write",
        \\ "tool_input":{"file_path":"/tmp/x.sh","content":"#!/bin/sh\nexit 0\n"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    const in = loaded.payload().input;
    try testing.expectEqualStrings("Write", in.tool);
    try testing.expectEqualStrings("", in.command);
    try testing.expectEqualStrings("/tmp/x.sh", in.file_path);
    try testing.expectEqualStrings("#!/bin/sh\nexit 0\n", in.content);
}

test "Edit's new_string maps onto the content field" {
    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/repo/run.sh",
        \\ "old_string":"echo a","new_string":"echo b"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    const in = loaded.payload().input;
    try testing.expectEqualStrings("echo b", in.content);
    try testing.expectEqualStrings("/repo/run.sh", in.file_path);
}

test "content wins when a payload carries both content and new_string" {
    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"Write",
        \\ "tool_input":{"content":"from content","new_string":"from new_string"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expectEqualStrings("from content", loaded.payload().input.content);
}

test "an event with no matchable fields is empty" {
    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"TodoWrite","tool_input":{"todos":[]}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expect(loaded.payload().isEmpty());
}

test "garbage input is a typed error" {
    try testing.expectError(error.InvalidEvent, parseEvent(testing.allocator, "not json"));
}

// ---- per-event payloads, driven through the table --------------------------

test "every event's own payload keys land on the fields the table names" {
    const cases = [_]struct {
        event: Event,
        json: []const u8,
        field: rules.Field,
        want: []const u8,
    }{
        .{
            .event = .UserPromptSubmit,
            .json =
            \\{"hook_event_name":"UserPromptSubmit","prompt_text":"delete everything"}
            ,
            .field = .prompt,
            .want = "delete everything",
        },
        .{
            .event = .PostToolUse,
            .json =
            \\{"hook_event_name":"PostToolUse","tool_name":"Bash",
            \\ "tool_input":{"command":"./x.sh"},"tool_output":"Terminated"}
            ,
            .field = .output,
            .want = "Terminated",
        },
        .{
            .event = .PostToolUseFailure,
            .json =
            \\{"hook_event_name":"PostToolUseFailure","tool_name":"Bash",
            \\ "tool_input":{"command":"ls /nope"},"error":"No such file or directory"}
            ,
            .field = .output,
            .want = "No such file or directory",
        },
        .{
            .event = .Stop,
            .json =
            \\{"hook_event_name":"Stop","stop_reason":"end_turn","last_assistant_message":"all done"}
            ,
            .field = .message,
            .want = "all done",
        },
        .{
            .event = .Stop,
            .json =
            \\{"hook_event_name":"Stop","stop_reason":"max_tokens"}
            ,
            .field = .trigger,
            .want = "max_tokens",
        },
        .{
            .event = .SessionStart,
            .json =
            \\{"hook_event_name":"SessionStart","source":"resume"}
            ,
            .field = .trigger,
            .want = "resume",
        },
        .{
            .event = .Notification,
            .json =
            \\{"hook_event_name":"Notification","notification_type":"idle_prompt","message":"waiting"}
            ,
            .field = .message,
            .want = "waiting",
        },
        .{
            .event = .SubagentStop,
            .json =
            \\{"hook_event_name":"SubagentStop","agent_type":"Explore","last_assistant_message":"found it"}
            ,
            .field = .agent,
            .want = "Explore",
        },
        .{
            .event = .FileChanged,
            .json =
            \\{"hook_event_name":"FileChanged","file_path":"/repo/.envrc","change_type":"modified"}
            ,
            .field = .file_path,
            .want = "/repo/.envrc",
        },
        .{
            .event = .CwdChanged,
            .json =
            \\{"hook_event_name":"CwdChanged","new_cwd":"/repo/sub","previous_cwd":"/repo"}
            ,
            .field = .file_path,
            .want = "/repo/sub",
        },
        .{
            .event = .PreCompact,
            .json =
            \\{"hook_event_name":"PreCompact","trigger":"auto"}
            ,
            .field = .trigger,
            .want = "auto",
        },
        .{
            .event = .ConfigChange,
            .json =
            \\{"hook_event_name":"ConfigChange","config_source":"project_settings",
            \\ "changed_keys":["hooks.PreToolUse","permissions.deny"]}
            ,
            .field = .content,
            .want = "hooks.PreToolUse permissions.deny",
        },
        .{
            .event = .Elicitation,
            .json =
            \\{"hook_event_name":"Elicitation","server_name":"github","tool_name":"mcp__github__pr"}
            ,
            .field = .agent,
            .want = "github",
        },
        .{
            .event = .MessageDisplay,
            .json =
            \\{"hook_event_name":"MessageDisplay","message_text":"here is the plan"}
            ,
            .field = .message,
            .want = "here is the plan",
        },
        .{
            .event = .SessionEnd,
            .json =
            \\{"hook_event_name":"SessionEnd","reason":"logout"}
            ,
            .field = .trigger,
            .want = "logout",
        },
    };

    for (cases) |case| {
        var loaded = try parseEvent(testing.allocator, case.json);
        defer loaded.deinit();
        const p = loaded.payload();
        try testing.expectEqual(case.event, p.event.?);
        try testing.expectEqual(case.event, p.input.event);
        try testing.expectEqualStrings(case.want, p.input.text(case.field));
        // And the table agrees that this event supplies the field at all.
        try testing.expect(case.event.descriptor().carries(case.field));
    }
}

test "a field an event does not carry stays empty, whatever the payload says" {
    // A `Stop` payload that somehow carries a command must not make a
    // `PreToolUse` command rule reachable: the bindings are the authority, not
    // the keys that happen to be present.
    const payload =
        \\{"hook_event_name":"Stop","stop_reason":"end_turn","tool_input":{"command":"rm -rf /"}}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expectEqualStrings("", loaded.payload().input.command);
    try testing.expectEqualStrings("end_turn", loaded.payload().input.trigger);
}

test "an event this build has never heard of parses cleanly and matches nothing" {
    const payload =
        \\{"hook_event_name":"QuantumEntanglementStart","spooky":true}
    ;
    var loaded = try parseEvent(testing.allocator, payload);
    defer loaded.deinit();
    try testing.expect(loaded.event() == null);
    try testing.expect(loaded.payload().event == null);
    try testing.expect(loaded.payload().isEmpty());
}

// ---- the response envelope ------------------------------------------------

test "PreToolUse answers with permissionDecision, and escapes the reason" {
    var buf: [512]u8 = undefined;
    const rule = rules.Rule{
        .name = "r",
        .reason = "Use \"git add <path>\" instead.\nOne file at a time.",
        .match = &.{},
    };
    const out = try render(&buf, .PreToolUse, &rule);
    try testing.expect(out.answer.wrote_json);
    try testing.expectEqual(@as(u8, 0), out.answer.exit_code);
    try testing.expect(std.mem.indexOf(u8, out.text, "\"hookEventName\":\"PreToolUse\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.text, "\"permissionDecision\":\"deny\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.text, "\\\"git add <path>\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.text, "\\n") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.text, .{});
    defer parsed.deinit();
}

test "allow and ask serialize as their own permissionDecision" {
    var buf: [512]u8 = undefined;
    for ([_]struct { d: rules.Decision, want: []const u8 }{
        .{ .d = .allow, .want = "\"permissionDecision\":\"allow\"" },
        .{ .d = .ask, .want = "\"permissionDecision\":\"ask\"" },
    }) |case| {
        const rule = rules.Rule{ .name = "r", .decision = case.d, .reason = "because", .match = &.{} };
        const out = try render(&buf, .PreToolUse, &rule);
        try testing.expect(std.mem.indexOf(u8, out.text, case.want) != null);
    }
}

test "each mechanism emits exactly its own envelope" {
    var buf: [1024]u8 = undefined;
    const rule = rules.Rule{ .name = "r", .reason = "policy says no", .match = &.{} };

    // PermissionRequest: decision.behavior, nested under hookSpecificOutput.
    {
        const out = try render(&buf, .PermissionRequest, &rule);
        try testing.expect(out.answer.wrote_json);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.text, .{});
        defer parsed.deinit();
        const hso = parsed.value.object.get("hookSpecificOutput").?.object;
        try testing.expectEqualStrings("PermissionRequest", hso.get("hookEventName").?.string);
        try testing.expectEqualStrings("deny", hso.get("decision").?.object.get("behavior").?.string);
        // Emphatically NOT a permissionDecision: that is PreToolUse's field.
        try testing.expect(hso.get("permissionDecision") == null);
    }

    // The decision:"block" family: top level, with the reason.
    for ([_]Event{ .Stop, .SubagentStop, .UserPromptSubmit, .PostToolUse, .PostToolBatch, .PreCompact, .ConfigChange }) |e| {
        const out = try render(&buf, e, &rule);
        try testing.expect(out.answer.wrote_json);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.text, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("block", parsed.value.object.get("decision").?.string);
        try testing.expectEqualStrings("policy says no", parsed.value.object.get("reason").?.string);
        try testing.expect(parsed.value.object.get("hookSpecificOutput") == null);
    }

    // continue:false, for the three unverified events.
    for ([_]Event{ .TeammateIdle, .TaskCreated, .TaskCompleted }) |e| {
        const out = try render(&buf, e, &rule);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.text, .{});
        defer parsed.deinit();
        try testing.expectEqual(false, parsed.value.object.get("continue").?.bool);
        try testing.expectEqualStrings("policy says no", parsed.value.object.get("stopReason").?.string);
    }

    // An elicitation is declined.
    for ([_]Event{ .Elicitation, .ElicitationResult }) |e| {
        const out = try render(&buf, e, &rule);
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.text, .{});
        defer parsed.deinit();
        const hso = parsed.value.object.get("hookSpecificOutput").?.object;
        try testing.expectEqualStrings("decline", hso.get("action").?.string);
    }

    // WorktreeCreate has no envelope: the exit code is the refusal.
    {
        const out = try render(&buf, .WorktreeCreate, &rule);
        try testing.expect(!out.answer.wrote_json);
        try testing.expectEqualStrings("", out.text);
        try testing.expectEqual(@as(u8, 1), out.answer.exit_code);
    }
}

test "an advisory event, and a decision its envelope has no room for, write nothing" {
    var buf: [512]u8 = undefined;
    const deny = rules.Rule{ .name = "r", .reason = "no", .match = &.{} };
    const ask = rules.Rule{ .name = "r", .decision = .ask, .reason = "no", .match = &.{} };
    const allow = rules.Rule{ .name = "r", .decision = .allow, .reason = "no", .match = &.{} };

    // Every advisory event, whatever the decision.
    for (events.all()) |*d| {
        if (!d.isAdvisory()) continue;
        for ([_]*const rules.Rule{ &deny, &ask, &allow }) |rule| {
            const out = try render(&buf, d.event, rule);
            try testing.expectEqualStrings("", out.text);
            try testing.expectEqual(Answer.silent, out.answer);
        }
    }

    // `ask` on a block-only event, and on a permission checkpoint.
    for ([_]Event{ .Stop, .PermissionRequest, .WorktreeCreate, .Elicitation }) |e| {
        const out = try render(&buf, e, &ask);
        try testing.expectEqualStrings("", out.text);
        try testing.expectEqual(Answer.silent, out.answer);
    }
    // `allow` where the vocabulary is deny-only.
    for ([_]Event{ .Stop, .UserPromptSubmit, .TaskCreated }) |e| {
        const out = try render(&buf, e, &allow);
        try testing.expectEqual(Answer.silent, out.answer);
    }
    // But `allow` IS expressible at a permission checkpoint.
    {
        const out = try render(&buf, .PermissionRequest, &allow);
        try testing.expect(out.answer.wrote_json);
        try testing.expect(std.mem.indexOf(u8, out.text, "\"behavior\":\"allow\"") != null);
    }
}

test "no envelope this gate writes is ever an exit 2" {
    var buf: [512]u8 = undefined;
    const rule = rules.Rule{ .name = "r", .reason = "no", .match = &.{} };
    for (events.all()) |*d| {
        const out = try render(&buf, d.event, &rule);
        try testing.expect(out.answer.exit_code != 2);
    }
}

test "the full pipeline: event JSON in, decision JSON out" {
    const rules_json =
        \\{ "rules": [ { "name": "protect-hook-config", "tool": "*", "decision": "deny",
        \\  "reason": "operator-owned",
        \\  "match": [ { "kind": "substring", "field": "file_path", "value": ".claude/settings.json" } ] } ] }
    ;
    var loaded_rules = try rules.parse(testing.allocator, rules_json);
    defer loaded_rules.deinit();

    const payload =
        \\{"hook_event_name":"PreToolUse","tool_name":"Edit",
        \\ "tool_input":{"file_path":"/h/.claude/settings.json","new_string":"{}"}}
    ;
    var loaded_event = try parseEvent(testing.allocator, payload);
    defer loaded_event.deinit();

    const p = loaded_event.payload();
    var result = rules.evaluate(loaded_rules.ruleSet(), p.input);
    defer result.deinit();
    const hit = result.enforced orelse return error.TestExpectedMatch;

    var buf: [512]u8 = undefined;
    const out = try render(&buf, p.event.?, hit.rule);
    try testing.expect(std.mem.indexOf(u8, out.text, "\"permissionDecision\":\"deny\"") != null);
}

test "the full pipeline for a non-tool event: a Stop rule answers with a block" {
    const rules_json =
        \\{ "schema_version": "1.1", "rules": [
        \\  { "name": "finish-the-checklist", "event": "Stop", "decision": "deny",
        \\    "reason": "the checklist is not done",
        \\    "match": [ { "kind": "word", "field": "message", "value": "TODO" } ] } ] }
    ;
    var loaded_rules = try rules.parse(testing.allocator, rules_json);
    defer loaded_rules.deinit();

    const payload =
        \\{"hook_event_name":"Stop","stop_reason":"end_turn",
        \\ "last_assistant_message":"I left a TODO in there"}
    ;
    var loaded_event = try parseEvent(testing.allocator, payload);
    defer loaded_event.deinit();

    const p = loaded_event.payload();
    var result = rules.evaluate(loaded_rules.ruleSet(), p.input);
    defer result.deinit();
    const hit = result.enforced orelse return error.TestExpectedMatch;

    var buf: [512]u8 = undefined;
    const out = try render(&buf, p.event.?, hit.rule);
    try testing.expect(std.mem.indexOf(u8, out.text, "\"decision\":\"block\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.text, "checklist is not done") != null);

    // And the very same rule file is inert for a tool call: one first-match
    // walk per event, so a Stop rule is unreachable from PreToolUse.
    var tool_result = rules.evaluate(loaded_rules.ruleSet(), .{
        .event = .PreToolUse,
        .tool = "Bash",
        .command = "echo TODO",
    });
    defer tool_result.deinit();
    try testing.expect(tool_result.enforced == null);
}

//! The hook event catalog: one descriptor per Claude Code hook event.
//!
//! ## Why this file exists at all
//!
//! Claude Code has thirty hook events, and almost nothing about them
//! generalizes. There is no shared "decision" field: `PreToolUse` answers with
//! `hookSpecificOutput.permissionDecision`, `PermissionRequest` with
//! `hookSpecificOutput.decision.behavior`, `Stop` with a top-level
//! `decision: "block"`, `Elicitation` with an `action`, and `WorktreeCreate`
//! with nothing but its exit code. Matchers do not generalize either — a tool
//! event's matcher is a regex over tool names, a session event's is one of a
//! closed set of exact strings, `FileChanged`'s is a list of literal filenames
//! that is NEVER a regex, and a third of the events take no matcher at all.
//! And thirteen events cannot refuse anything no matter what they emit.
//!
//! Written as thirty handlers, that becomes thirty places to be wrong, and the
//! wrongness is silent: a rule scoped to an advisory event, or answering with
//! the wrong envelope, does nothing and says nothing. So the whole of it is one
//! table. Dispatch reads it, the payload parse reads it, the response writer
//! reads it, the config lint reads it, the installer reads it to decide what to
//! wire, and the documentation test reads it to check the README. Adding an
//! event — or correcting a fact about one — is a row, and every consumer moves
//! with it because there is nowhere else to look.
//!
//! ## What a row promises
//!
//!   - `event`      the enum tag IS the wire name. `@tagName` is the exact
//!                  string the harness sends in `hook_event_name` and the exact
//!                  string that goes in `settings.json`, so the two can never
//!                  drift from each other or from the rule file's `event` key.
//!   - `block`      how — and whether — a refusal can be expressed. `.none` is
//!                  the advisory events, and the difference is load-bearing:
//!                  see `Mechanism`.
//!   - `matcher`    what the harness's `matcher` string means for this event.
//!   - `bindings`   which payload fields become matchable, and by which JSON
//!                  path. An event with no bindings carries nothing a rule can
//!                  read, which the lint reports rather than leaving as a rule
//!                  that never fires.
//!   - `context`    the response field this event injects context through, or
//!                  "" when it cannot. Recorded for the documentation and for
//!                  the lint's benefit; this gate does not inject context.
//!   - `verified`   false when the upstream documentation is thin enough that
//!                  the row is partly inference. A rule targeting one of those
//!                  is a lint WARNING — supported, but flagged.
//!
//! The decision vocabulary is NOT a column: it is derived from `block` by
//! `Mechanism.vocabulary`, because that is the only way the two can be
//! guaranteed consistent. An `ask` on an event whose mechanism is a bare
//! `decision: "block"` is not a policy choice with an unfortunate outcome, it
//! is a spelling the wire has no room for.
//!
//! ## What this gate deliberately does not do
//!
//! Every response this gate writes is `exit 0` plus JSON. Exit 2 and JSON are
//! mutually exclusive in the hooks contract — the harness ignores the document
//! when the process exits 2 — and a gate that sometimes speaks JSON and
//! sometimes speaks stderr has two output contracts to get right instead of
//! one. `WorktreeCreate` is the single exception in the table, because it is
//! the one event with no response envelope at all: it fails on ANY nonzero
//! exit, so `block_exit` is how its refusal is spelled. That is still never
//! exit 2.
//!
//! Context injection (`additionalContext`), input rewriting (`updatedInput`)
//! and output rewriting (`updatedToolOutput`, `displayContent`) are recorded
//! here and implemented nowhere: a gate whose job is to say no is easier to
//! trust than one that edits the conversation. The columns exist so the
//! documentation is complete and so adding the feature later is a change to the
//! writer rather than a change to the catalog.

const std = @import("std");

/// Every hook event, with the tag spelled exactly as the wire spells it.
///
/// The order is the order of the documentation table and of the README: the
/// session lifecycle, the prompt, the tool call, the turn, the notifications,
/// the ambient changes, compaction, MCP elicitation, and teardown. Rendering
/// reads this order, so the docs cannot be sorted differently from the code.
pub const Event = enum {
    SessionStart,
    Setup,
    UserPromptSubmit,
    UserPromptExpansion,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    PostToolBatch,
    PermissionRequest,
    PermissionDenied,
    Stop,
    SubagentStop,
    StopFailure,
    SubagentStart,
    TeammateIdle,
    TaskCreated,
    TaskCompleted,
    Notification,
    MessageDisplay,
    ConfigChange,
    CwdChanged,
    FileChanged,
    WorktreeCreate,
    WorktreeRemove,
    PreCompact,
    PostCompact,
    Elicitation,
    ElicitationResult,
    InstructionsLoaded,
    SessionEnd,

    /// The `hook_event_name` string, which is the tag itself.
    pub fn name(self: Event) []const u8 {
        return @tagName(self);
    }

    /// The event a `hook_event_name` names, or null for one this build has
    /// never heard of. Null is not an error anywhere: a future harness may send
    /// an event this binary predates, and the only correct answer to that is a
    /// silent exit 0 — see `main.zig`.
    pub fn from(text: []const u8) ?Event {
        return std.meta.stringToEnum(Event, text);
    }

    pub fn descriptor(self: Event) *const Descriptor {
        return &TABLE[@intFromEnum(self)];
    }
};

/// The event a rule is scoped to when it does not say. Every rule file written
/// before events existed is a file of `PreToolUse` rules, and this is what
/// keeps those files byte-for-byte unchanged in meaning.
pub const DEFAULT_EVENT: Event = .PreToolUse;

pub const COUNT = @typeInfo(Event).@"enum".fields.len;

// ---------------------------------------------------------------------------
// how a refusal is expressed
// ---------------------------------------------------------------------------

/// How an event's response says no — the single most event-specific thing
/// about the whole protocol.
///
/// `.none` is not "no mechanism implemented yet"; it is the documented fact
/// that the event's output cannot change anything. Thirteen of the thirty are
/// like that, and a `deny` rule scoped to one of them is a config bug that
/// would otherwise be a perfectly silent no-op — which is why the lint calls it
/// an error instead of tidying it away.
pub const Mechanism = enum {
    /// Advisory: nothing this gate writes can stop anything. Output is read
    /// (or, for several events, not even read) and the operation proceeds.
    none,
    /// `hookSpecificOutput.permissionDecision` — `PreToolUse` only, and the
    /// only mechanism with a three-way vocabulary.
    permission_decision,
    /// `hookSpecificOutput.decision.behavior` — `PermissionRequest` only.
    /// Two-valued: there is no "ask" at a checkpoint that already is one.
    decision_behavior,
    /// Top-level `decision: "block"` plus `reason`.
    decision_block,
    /// Top-level `continue: false` plus `stopReason`.
    continue_false,
    /// `hookSpecificOutput.action` — an MCP elicitation is declined, not
    /// denied.
    action,
    /// `hookSpecificOutput.displayContent` — a rewrite of what is shown on
    /// screen. Not a refusal: the transcript and the model's context keep the
    /// original text, so this cannot block and is grouped with the advisory
    /// events by `blocks`.
    display_content,
    /// No response envelope exists; ANY nonzero exit fails the operation. One
    /// event, `WorktreeCreate`.
    nonzero_exit,

    /// Can a rule using this mechanism actually stop something? False for the
    /// advisory events and for a display-only rewrite.
    pub fn blocks(self: Mechanism) bool {
        return switch (self) {
            .none, .display_content => false,
            .permission_decision,
            .decision_behavior,
            .decision_block,
            .continue_false,
            .action,
            .nonzero_exit,
            => true,
        };
    }

    /// Which enforced decisions this mechanism can carry.
    ///
    /// Derived rather than tabulated, deliberately: the vocabulary is a
    /// property of the wire shape, so deriving it makes "this event accepts
    /// `ask`" impossible to state incorrectly. `log` is absent because a shadow
    /// rule emits nothing at all and is therefore valid on every event,
    /// including the ones that can never refuse anything — observing an
    /// advisory event is the main thing an advisory event is good for.
    pub fn vocabulary(self: Mechanism) Vocabulary {
        return switch (self) {
            .none, .display_content => .{},
            .permission_decision => .{ .deny = true, .ask = true, .allow = true },
            .decision_behavior => .{ .deny = true, .allow = true },
            .decision_block, .continue_false, .action, .nonzero_exit => .{ .deny = true },
        };
    }

    /// The response field a refusal is written into, for documentation. Empty
    /// for the mechanisms that write no field.
    pub fn wireField(self: Mechanism) []const u8 {
        return switch (self) {
            .none => "",
            .permission_decision => "hookSpecificOutput.permissionDecision",
            .decision_behavior => "hookSpecificOutput.decision.behavior",
            .decision_block => "decision: \"block\"",
            .continue_false => "continue: false",
            .action => "hookSpecificOutput.action",
            .display_content => "hookSpecificOutput.displayContent",
            .nonzero_exit => "any nonzero exit",
        };
    }
};

/// The enforced decisions one event accepts. `log` is always accepted and so
/// is not a member; see `Mechanism.vocabulary`.
pub const Vocabulary = struct {
    deny: bool = false,
    ask: bool = false,
    allow: bool = false,

    pub fn isEmpty(self: Vocabulary) bool {
        return !self.deny and !self.ask and !self.allow;
    }

    /// The accepted spellings, as a comma-separated sentence for a diagnostic.
    /// `log` is named too, because a lint that says "this event accepts
    /// nothing" is only useful if it also says what to write instead.
    pub fn describe(self: Vocabulary) []const u8 {
        if (self.deny and self.ask and self.allow) return "deny, ask, allow, log";
        if (self.deny and self.allow) return "deny, allow, log";
        if (self.deny) return "deny, log";
        return "log";
    }
};

// ---------------------------------------------------------------------------
// what the harness's matcher means
// ---------------------------------------------------------------------------

/// How the `matcher` string in `settings.json` is interpreted for an event.
///
/// This is the harness's matcher, not this gate's: a rule narrows further with
/// its own `tool` and its own matchers. It is in the table because the
/// INSTALLER writes that string, and writing a regex where the harness wants a
/// literal filename — which is exactly what `FileChanged` does — is a wiring
/// that silently never fires.
pub const MatcherKind = enum {
    /// The event takes no matcher; a wired hook always fires.
    none,
    /// A regex over tool names, pipe-alternation included (`Edit|Write`,
    /// `mcp__.*`).
    tool_name,
    /// A regex over subagent types.
    agent_type,
    /// One of a closed set of exact strings, pipe-separated. Not a regex.
    exact_string,
    /// Literal filenames, pipe-separated. NEVER a regex — the harness splits
    /// the matcher on `|` and compares the results as names.
    exact_filename,
    /// The configured MCP server key.
    mcp_server,
    /// The slash command whose expansion is being submitted.
    command_name,

    /// Whether a matcher string may carry regex metacharacters at all.
    pub fn isRegex(self: MatcherKind) bool {
        return switch (self) {
            .tool_name, .agent_type => true,
            .none, .exact_string, .exact_filename, .mcp_server, .command_name => false,
        };
    }
};

// ---------------------------------------------------------------------------
// the matchable fields, and where they come from
// ---------------------------------------------------------------------------

/// The field of a hook payload a matcher reads.
///
/// Deliberately a small closed set rather than one name per payload key: a
/// rule says what KIND of text it is reading, and the table says which key of
/// which event supplies it. `word` on `prompt` then means the same thing
/// whatever event produced the prompt, and `command_word` on `command` reads a
/// shell command whether the call is being proposed (`PreToolUse`) or has
/// already run (`PostToolUse`).
///
/// The first three predate events and keep their exact meaning, which is what
/// makes every rule file written against the single-event gate still correct.
pub const Field = enum {
    /// A shell command string (`tool_input.command`).
    command,
    /// Text being introduced: `tool_input.content`, Edit's `new_string`, or
    /// the list of settings keys a `ConfigChange` touches.
    content,
    /// The path the event is about: a tool's `file_path`, a watched file, a new
    /// working directory.
    file_path,
    /// A user prompt.
    prompt,
    /// A tool's result: its output on success, its error text on failure.
    output,
    /// Prose the harness produced: an assistant message, a notification body,
    /// a task description.
    message,
    /// The event's own discriminator — the string its harness matcher would
    /// match: a session `source`, a compaction `trigger`, a notification type,
    /// a config source, a stop reason, a change type.
    trigger,
    /// Who: a subagent type, or an MCP server name.
    agent,

    /// True for the three fields that existed before this gate knew about
    /// events. Nothing branches on this — it is here so the documentation and
    /// the compatibility test can name the set rather than list it twice.
    pub fn isLegacy(self: Field) bool {
        return switch (self) {
            .command, .content, .file_path => true,
            .prompt, .output, .message, .trigger, .agent => false,
        };
    }
};

pub const FIELD_COUNT = @typeInfo(Field).@"enum".fields.len;

/// A payload key, named once so a binding can point at it and the
/// documentation can print its JSON path.
///
/// One value per distinct key, NOT per event: `source` is one source shared by
/// `SessionStart` and `Setup`, `reason` by `WorktreeCreate` and `SessionEnd`,
/// `trigger` by both compaction events. That is what keeps the payload parser
/// a single flat struct with one total switch over it, instead of thirty
/// bespoke parses.
pub const Source = enum {
    tool_command,
    tool_content,
    tool_file_path,
    tool_output,
    tool_error,
    prompt_text,
    command_name,
    last_assistant_message,
    message_text,
    notification_message,
    notification_type,
    payload_source,
    payload_trigger,
    payload_reason,
    stop_reason,
    error_type,
    permission_rule,
    config_source,
    changed_keys,
    change_type,
    watched_file_path,
    new_cwd,
    agent_type,
    server_name,
    task_description,

    /// The JSON path this reads, for the documentation table. Dotted where the
    /// key is nested, so a reader can check a row against a real payload.
    pub fn path(self: Source) []const u8 {
        return switch (self) {
            .tool_command => "tool_input.command",
            // Deliberately not `content|new_string`: a pipe would break the
            // markdown table this string is rendered into, even inside backticks.
            .tool_content => "tool_input.content or .new_string",
            .tool_file_path => "tool_input.file_path",
            .tool_output => "tool_output",
            .tool_error => "error",
            .prompt_text => "prompt_text",
            .command_name => "command_name",
            .last_assistant_message => "last_assistant_message",
            .message_text => "message_text",
            .notification_message => "message",
            .notification_type => "notification_type",
            .payload_source => "source",
            .payload_trigger => "trigger",
            .payload_reason => "reason",
            .stop_reason => "stop_reason",
            .error_type => "error_type",
            .permission_rule => "permission_rule",
            .config_source => "config_source",
            .changed_keys => "changed_keys",
            .change_type => "change_type",
            .watched_file_path => "file_path",
            .new_cwd => "new_cwd",
            .agent_type => "agent_type",
            .server_name => "server_name",
            .task_description => "description",
        };
    }
};

/// One payload key wired to one matchable field.
pub const Binding = struct {
    field: Field,
    source: Source,
};

// ---------------------------------------------------------------------------
// the descriptor
// ---------------------------------------------------------------------------

pub const Descriptor = struct {
    event: Event,
    /// How a refusal is expressed, or `.none` for an advisory event.
    block: Mechanism = .none,
    /// The exit code a refusal uses when there is no envelope for it. Zero
    /// everywhere except `WorktreeCreate`; never 2, which would make the
    /// harness discard the JSON this gate always writes.
    block_exit: u8 = 0,
    /// True when the event fires AFTER the thing it describes, so a refusal is
    /// feedback to the model rather than prevention. `PostToolUse` can say
    /// `decision: "block"`, but the tool has already run.
    feedback_only: bool = false,
    matcher: MatcherKind = .none,
    /// True when the payload carries `tool_name`, and therefore when a rule's
    /// `tool` field means anything. On every other event a `tool` other than
    /// `"*"` can never match, and the lint says so.
    has_tool: bool = false,
    bindings: []const Binding = &.{},
    /// The response field this event injects context through, or "" when it
    /// cannot. Documentation only — see the module header.
    context: []const u8 = "",
    /// The response field that rewrites what the event carried, or "".
    /// Documentation only.
    rewrite: []const u8 = "",
    /// False when this row is partly inference because the upstream docs are
    /// thin. A rule targeting one of these is a lint WARNING.
    verified: bool = true,
    /// When the event fires, in one clause. Printed by `events` and checked
    /// against the README.
    timing: []const u8,

    pub fn name(self: *const Descriptor) []const u8 {
        return self.event.name();
    }

    /// Advisory: nothing this gate can write will stop anything.
    pub fn isAdvisory(self: *const Descriptor) bool {
        return !self.block.blocks();
    }

    pub fn vocabulary(self: *const Descriptor) Vocabulary {
        return self.block.vocabulary();
    }

    /// Does this event's payload supply `field`? A matcher reading a field the
    /// event does not carry can never match, which is a lint error rather than
    /// a rule that quietly does nothing.
    pub fn carries(self: *const Descriptor, field: Field) bool {
        for (self.bindings) |b| {
            if (b.field == field) return true;
        }
        return false;
    }

    /// The source supplying `field`, or null. First binding wins, and no row
    /// binds one field twice.
    pub fn sourceOf(self: *const Descriptor, field: Field) ?Source {
        for (self.bindings) |b| {
            if (b.field == field) return b.source;
        }
        return null;
    }

    /// True when no payload key of this event is matchable, so no rule can be
    /// written for it at all. Four events are in this state because their
    /// payloads are undocumented beyond the common envelope; the lint names
    /// them rather than letting a rule sit there inert.
    pub fn hasNoMatchableField(self: *const Descriptor) bool {
        return self.bindings.len == 0;
    }
};

/// Shorthand used only inside the table below, so a row fits on a line or two
/// and the columns stay readable down the page.
fn bind(field: Field, source: Source) Binding {
    return .{ .field = field, .source = source };
}

/// The three fields every tool-call event exposes, shared so the events that
/// see the same `tool_input` cannot disagree about what is in it.
const tool_call_bindings = &[_]Binding{
    bind(.command, .tool_command),
    bind(.content, .tool_content),
    bind(.file_path, .tool_file_path),
};

/// THE TABLE. One row per event, in `Event` order; indexed by
/// `@intFromEnum`, which `Event.descriptor` relies on and
/// `TABLE is indexed by the enum` asserts.
pub const TABLE = [COUNT]Descriptor{
    .{
        .event = .SessionStart,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_source)},
        .context = "additionalContext",
        .timing = "after session init, before the first turn",
    },
    .{
        .event = .Setup,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_source)},
        .context = "additionalContext",
        .timing = "on --init-only / --init / --maintenance in -p mode",
    },
    .{
        .event = .UserPromptSubmit,
        .block = .decision_block,
        .bindings = &.{bind(.prompt, .prompt_text)},
        .context = "additionalContext",
        .timing = "after the user submits a prompt, before the model sees it",
    },
    .{
        .event = .UserPromptExpansion,
        .block = .decision_block,
        .matcher = .command_name,
        .bindings = &.{ bind(.prompt, .prompt_text), bind(.trigger, .command_name) },
        .timing = "when a slash command expands into a prompt",
    },
    .{
        .event = .PreToolUse,
        .block = .permission_decision,
        .matcher = .tool_name,
        .has_tool = true,
        .bindings = tool_call_bindings,
        .context = "additionalContext",
        .rewrite = "updatedInput",
        .timing = "before a tool call executes",
    },
    .{
        .event = .PostToolUse,
        .block = .decision_block,
        .feedback_only = true,
        .matcher = .tool_name,
        .has_tool = true,
        .bindings = &.{
            bind(.command, .tool_command),
            bind(.content, .tool_content),
            bind(.file_path, .tool_file_path),
            bind(.output, .tool_output),
        },
        .context = "additionalContext",
        .rewrite = "updatedToolOutput",
        .timing = "after a tool call succeeds",
    },
    .{
        .event = .PostToolUseFailure,
        .block = .decision_block,
        .feedback_only = true,
        .matcher = .tool_name,
        .has_tool = true,
        .bindings = &.{
            bind(.command, .tool_command),
            bind(.content, .tool_content),
            bind(.file_path, .tool_file_path),
            bind(.output, .tool_error),
        },
        .context = "additionalContext",
        .timing = "after a tool call fails",
    },
    .{
        .event = .PostToolBatch,
        .block = .decision_block,
        .context = "additionalContext",
        .timing = "after a batch of parallel tool calls, before the next model call",
    },
    .{
        .event = .PermissionRequest,
        .block = .decision_behavior,
        .matcher = .tool_name,
        .has_tool = true,
        .bindings = &.{
            bind(.command, .tool_command),
            bind(.content, .tool_content),
            bind(.file_path, .tool_file_path),
            bind(.trigger, .permission_rule),
        },
        .rewrite = "updatedInput",
        .timing = "when a tool call reaches a permission checkpoint",
    },
    .{
        .event = .PermissionDenied,
        .matcher = .tool_name,
        .has_tool = true,
        .bindings = tool_call_bindings,
        .timing = "after an automatic denial (the hook may ask for a retry)",
    },
    .{
        .event = .Stop,
        .block = .decision_block,
        .bindings = &.{ bind(.message, .last_assistant_message), bind(.trigger, .stop_reason) },
        .context = "additionalContext",
        .timing = "when the model finishes responding",
    },
    .{
        .event = .SubagentStop,
        .block = .decision_block,
        .matcher = .agent_type,
        .bindings = &.{
            bind(.message, .last_assistant_message),
            bind(.trigger, .stop_reason),
            bind(.agent, .agent_type),
        },
        .context = "additionalContext",
        .timing = "when a subagent finishes",
    },
    .{
        .event = .StopFailure,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .error_type)},
        .timing = "when a turn ends because of an API error (output ignored)",
    },
    .{
        .event = .SubagentStart,
        .matcher = .agent_type,
        .bindings = &.{bind(.agent, .agent_type)},
        .context = "additionalContext",
        .timing = "when a subagent is spawned",
    },
    .{
        .event = .TeammateIdle,
        .block = .continue_false,
        .bindings = &.{bind(.agent, .agent_type)},
        .verified = false,
        .timing = "when an agent-team teammate is about to go idle (UNVERIFIED)",
    },
    .{
        .event = .TaskCreated,
        .block = .continue_false,
        .bindings = &.{ bind(.message, .task_description), bind(.agent, .agent_type) },
        .verified = false,
        .timing = "when a task is created via the TaskCreate tool (UNVERIFIED)",
    },
    .{
        .event = .TaskCompleted,
        .block = .continue_false,
        .bindings = &.{ bind(.message, .task_description), bind(.agent, .agent_type) },
        .verified = false,
        .timing = "when a task is marked completed (UNVERIFIED)",
    },
    .{
        .event = .Notification,
        .matcher = .exact_string,
        .bindings = &.{ bind(.trigger, .notification_type), bind(.message, .notification_message) },
        .timing = "when Claude Code raises a notification",
    },
    .{
        .event = .MessageDisplay,
        .block = .display_content,
        .bindings = &.{bind(.message, .message_text)},
        .rewrite = "displayContent",
        .timing = "while an assistant message is displayed (screen only)",
    },
    .{
        .event = .ConfigChange,
        .block = .decision_block,
        .matcher = .exact_string,
        .bindings = &.{ bind(.trigger, .config_source), bind(.content, .changed_keys) },
        .timing = "when a settings or skills file changes mid-session",
    },
    .{
        .event = .CwdChanged,
        .bindings = &.{bind(.file_path, .new_cwd)},
        .timing = "when the working directory changes",
    },
    .{
        .event = .FileChanged,
        .matcher = .exact_filename,
        .bindings = &.{ bind(.file_path, .watched_file_path), bind(.trigger, .change_type) },
        .timing = "when a watched file changes on disk",
    },
    .{
        .event = .WorktreeCreate,
        .block = .nonzero_exit,
        .block_exit = 1,
        .bindings = &.{bind(.trigger, .payload_reason)},
        .timing = "while a worktree is being created",
    },
    .{
        .event = .WorktreeRemove,
        .bindings = &.{bind(.trigger, .payload_reason)},
        .timing = "when a worktree is removed at session exit or subagent finish",
    },
    .{
        .event = .PreCompact,
        .block = .decision_block,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_trigger)},
        .timing = "before context compaction",
    },
    .{
        .event = .PostCompact,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_trigger)},
        .timing = "after compaction completes",
    },
    .{
        .event = .Elicitation,
        .block = .action,
        .matcher = .mcp_server,
        .has_tool = true,
        .bindings = &.{bind(.agent, .server_name)},
        .timing = "when an MCP server asks the user for input mid-tool-call",
    },
    .{
        .event = .ElicitationResult,
        .block = .action,
        .matcher = .mcp_server,
        .has_tool = true,
        .bindings = &.{bind(.agent, .server_name)},
        .timing = "after the user answers an MCP elicitation, before the server does",
    },
    .{
        .event = .InstructionsLoaded,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_reason)},
        .timing = "when CLAUDE.md or a .claude/rules file is loaded",
    },
    .{
        .event = .SessionEnd,
        .matcher = .exact_string,
        .bindings = &.{bind(.trigger, .payload_reason)},
        .verified = false,
        .timing = "when the session terminates (payload UNVERIFIED)",
    },
};

/// Every descriptor, in table order.
pub fn all() []const Descriptor {
    return &TABLE;
}

pub fn descriptorOf(event: Event) *const Descriptor {
    return &TABLE[@intFromEnum(event)];
}

/// How many events cannot refuse anything. Computed, so the README's count and
/// the table's contents cannot disagree.
pub fn advisoryCount() usize {
    var n: usize = 0;
    for (&TABLE) |*d| {
        if (d.isAdvisory()) n += 1;
    }
    return n;
}

pub fn unverifiedCount() usize {
    var n: usize = 0;
    for (&TABLE) |*d| {
        if (!d.verified) n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "TABLE is indexed by the enum, and every row names its own event" {
    try testing.expectEqual(@as(usize, 30), COUNT);
    for (&TABLE, 0..) |*d, i| {
        try testing.expectEqual(@as(usize, i), @intFromEnum(d.event));
        // The row's own name round-trips through the wire spelling, which is
        // what lets `settings.json`, the rule file's `event` key, and
        // `hook_event_name` all be the same string.
        try testing.expectEqual(d.event, Event.from(d.name()).?);
    }
}

test "an unknown event name is null rather than an error" {
    try testing.expect(Event.from("SomethingTheHarnessAddedLater") == null);
    try testing.expect(Event.from("") == null);
    // Case matters: the wire spelling is exact.
    try testing.expect(Event.from("pretooluse") == null);
}

test "thirteen events are advisory, and four rows are unverified" {
    try testing.expectEqual(@as(usize, 13), advisoryCount());
    // TeammateIdle, TaskCreated and TaskCompleted (blocking behaviour and
    // payload alike) plus SessionEnd's payload shape.
    try testing.expectEqual(@as(usize, 4), unverifiedCount());

    const advisory = [_]Event{
        .SessionStart,   .Setup,          .Notification,     .StopFailure,
        .MessageDisplay, .SubagentStart,  .PermissionDenied, .CwdChanged,
        .FileChanged,    .WorktreeRemove, .PostCompact,      .InstructionsLoaded,
        .SessionEnd,
    };
    for (advisory) |e| try testing.expect(e.descriptor().isAdvisory());
    // And nothing else is.
    for (&TABLE) |*d| {
        if (!d.isAdvisory()) continue;
        const listed = for (advisory) |e| {
            if (e == d.event) break true;
        } else false;
        try testing.expect(listed);
    }
}

test "the vocabulary follows the mechanism, and only PreToolUse takes ask" {
    for (&TABLE) |*d| {
        const v = d.vocabulary();
        if (d.isAdvisory()) {
            try testing.expect(v.isEmpty());
        } else {
            try testing.expect(v.deny);
        }
        if (v.ask) try testing.expectEqual(Event.PreToolUse, d.event);
        if (v.allow) try testing.expect(d.event == .PreToolUse or d.event == .PermissionRequest);
    }
}

test "no row spells a refusal as exit 2, and only WorktreeCreate uses an exit at all" {
    for (&TABLE) |*d| {
        try testing.expect(d.block_exit != 2);
        if (d.block_exit != 0) try testing.expectEqual(Event.WorktreeCreate, d.event);
        if (d.block == .nonzero_exit) try testing.expect(d.block_exit != 0);
    }
}

test "a binding never names one field twice, and structural fields stay reachable" {
    for (&TABLE) |*d| {
        for (d.bindings, 0..) |x, i| {
            for (d.bindings[0..i]) |y| try testing.expect(x.field != y.field);
        }
        // Every event that carries a command carries a tool name too: a
        // structural matcher is only meaningful about a tool call.
        if (d.carries(.command)) try testing.expect(d.has_tool);
    }
}

test "the events with no matchable field are named, not discovered later" {
    const barren = [_]Event{.PostToolBatch};
    for (&TABLE) |*d| {
        if (!d.hasNoMatchableField()) continue;
        const listed = for (barren) |e| {
            if (e == d.event) break true;
        } else false;
        try testing.expect(listed);
    }
    for (barren) |e| try testing.expect(e.descriptor().hasNoMatchableField());
}

test "a tool field only means something where the payload carries a tool name" {
    for (&TABLE) |*d| {
        if (!d.has_tool) continue;
        // Every tool-bearing event is matched by tool name or by MCP server.
        try testing.expect(d.matcher == .tool_name or d.matcher == .mcp_server);
    }
}

test "FileChanged's matcher is never treated as a regex" {
    try testing.expect(!Event.FileChanged.descriptor().matcher.isRegex());
    try testing.expect(Event.PreToolUse.descriptor().matcher.isRegex());
}

test "every row has a timing clause and a wire field for its mechanism" {
    for (&TABLE) |*d| {
        try testing.expect(d.timing.len > 0);
        const wire = d.block.wireField();
        try testing.expectEqual(d.block == .none, wire.len == 0);
    }
}

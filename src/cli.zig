//! The operator CLI: `claude-hooker-gate <subcommand> ...`.
//!
//! The same binary is both the PreToolUse hook and the tool an operator uses
//! to understand it. The two modes are told apart by argument count and
//! nothing else: the harness invokes the gate with *no* arguments (the
//! `settings.json` entry is a bare command line, stdin carries the event), so
//! "any argument at all" means CLI. That keeps the hot path — spawn, read
//! stdin, decide — one iterator step away from where it is today, and makes
//! the two modes impossible to confuse in either direction.
//!
//! Subcommands:
//!
//!   - `check`    — evaluate one tool call and explain the outcome, with the
//!                  matched bytes underlined. The rehearsal for "why did the
//!                  gate do that?", answered without provoking the gate.
//!   - `selftest` — run the rule file's own `tests` cases, then lint the rule
//!                  set for the mistakes that silently weaken a policy.
//!   - `stats`    — aggregate the decision log per rule, so a rule that never
//!                  fires and a shadow rule that fires constantly are both
//!                  visible.
//!   - `doctor`   — diagnose an install: wiring, version drift between the
//!                  installed binary and the build being run, the live rules,
//!                  the log, the overlay, and every override that quietly
//!                  weakens the gate. One PASS/WARN/FAIL line per check.
//!   - `status`   — the same facts, compressed to one screen.
//!   - `diff-defaults`
//!                — what the shipped defaults gained since the operator's copy
//!                  was seeded, so an edited rule file can be upgraded without
//!                  being clobbered.
//!   - `version`, `help`.
//!
//! Exit codes are part of the interface:
//!
//!   0   `check`: no match, or an `allow` rule; `selftest`: everything passed
//!   1   `check`: `deny`;  `selftest`: a failing case or a lint error;
//!       `doctor`: at least one check FAILED
//!   2   `check`: `ask`
//!   64  usage (EX_USAGE) — `help`, an unknown subcommand, a bad flag
//!   65  the rule file is invalid (EX_DATAERR)
//!   66  the rule file cannot be read (EX_NOINPUT)
//!   70  an internal failure (EX_SOFTWARE)
//!   78  the rule file declares a NEWER `schema_version` than this binary
//!       speaks, or one that is not a version at all (EX_CONFIG)
//!
//! 78 is deliberately not 65. "Your rule file is invalid" and "your rule file
//! is from a newer release than this binary" are different events with
//! different remedies — the first is fixed by editing JSON, the second by
//! `./hookctl upgrade` — and a script that watches a fleet needs to tell a
//! typo apart from a half-finished rollout. See `rules.SCHEMA_VERSION`.
//!
//! `check` deliberately reuses the *same* path resolution and the *same*
//! `evaluateOverlay` call the hook uses (see `rules.resolvePath`), including
//! `CLAUDE_HOOK_DISABLE` and the project rule overlay, so what it prints is
//! what the gate would do rather than a second implementation that can drift.
//! An overlay changes the answer — a repo `allow` pre-empts a global `deny` —
//! so a `check` that ignored it would confidently disagree with the live hook
//! inside exactly the repositories where the disagreement matters most. Each
//! reported hit is labelled with the layer it came from.
//!
//! Everything with logic in it is a pure function over plain values —
//! argument slices, rule sets, log bytes, a writer. `run` is the only part
//! that touches process state, and it is deliberately thin.

const std = @import("std");
const builtin = @import("builtin");
const rules = @import("rules.zig");
const resolve = @import("resolve.zig");
const shell = @import("shell.zig");
const decision_log = @import("decision_log.zig");
const version = @import("version.zig");

pub const VERSION = version.VERSION;

pub const PROGRAM = "claude-hooker-gate";

/// Exit codes, from `sysexits.h` where one applies.
pub const EX_USAGE: u8 = 64;
pub const EX_DATAERR: u8 = 65;
pub const EX_NOINPUT: u8 = 66;
pub const EX_SOFTWARE: u8 = 70;
/// A rule file this binary is not equipped to read. `sysexits.h` calls 78 "a
/// configuration error", which is exactly the situation: the document is fine,
/// this reader is behind it.
pub const EX_CONFIG: u8 = 78;

/// Cap on the decision log `stats` will read. A log this large is already a
/// retention problem; refusing to read it beats spending a minute on it.
pub const MAX_LOG_BYTES = 64 * 1024 * 1024;

/// Columns available for rendered field text and wrapped reasons. Fixed rather
/// than terminal-derived: the output is routinely piped, diffed, and pasted
/// into an issue, and a stable width is worth more than a snug fit.
pub const RENDER_WIDTH = 88;

/// Cap on `settings.json`. It is a hand-edited config file, not a data set.
pub const MAX_SETTINGS_BYTES = 4 * 1024 * 1024;

/// The basename the gate is installed under. `doctor` matches on it to decide
/// whether a `PreToolUse` command in `settings.json` is one of ours or another
/// operator's tool that happens to share the hook.
pub const GATE_BINARY_NAME = "claude-hooker-gate";

/// The rules this binary carries. The installer seeds a fresh machine from
/// them; `diff-defaults` compares them against whatever the operator's copy
/// has become since. Both need the same bytes, so there is one embed.
pub const DEFAULT_RULES_JSON = @embedFile("default-rules.json");

/// The runner's constants file, read by the test that keeps the minimum Zig
/// version from drifting between here, `build.zig.zon` and the CI workflow.
/// `hookctl` itself is a thin entry point; its constants live in the package.
pub const RUNNER_CONSTANTS = "tools/hookctl/spec.py";

/// Every path one install owns, derived once from the directory it lives in.
///
/// One definition, shared by the installer and by `doctor`/`status`/
/// `diff-defaults`, so `--claude-dir` is a single substitution rather than
/// four independently-written joins that can disagree about where an install
/// is. Note what this is *not*: it is not a fourth path-resolution rule. The
/// rule file and the log still resolve through `rules.resolvePath` and
/// `decision_log.resolvePath`; this only supplies the value those two take in
/// their "explicit/configured" slot, which is exactly where `--rules` and
/// `logging.path` already sit.
pub const Layout = struct {
    claude_dir: []const u8,
    hooks_dir: []const u8,
    gate_dest: []const u8,
    rules_dest: []const u8,
    settings_path: []const u8,
    /// Where the log goes when the rule file names no `logging.path`.
    log_default: []const u8,

    pub fn init(gpa: std.mem.Allocator, claude_dir: []const u8) std.mem.Allocator.Error!Layout {
        const hooks_dir = try std.fs.path.join(gpa, &.{ claude_dir, "hooks" });
        return .{
            .claude_dir = claude_dir,
            .hooks_dir = hooks_dir,
            .gate_dest = try std.fs.path.join(gpa, &.{ hooks_dir, GATE_BINARY_NAME }),
            .rules_dest = try std.fs.path.join(gpa, &.{ claude_dir, rules.DEFAULT_RULES_NAME }),
            .settings_path = try std.fs.path.join(gpa, &.{ claude_dir, "settings.json" }),
            .log_default = try std.fs.path.join(gpa, &.{ claude_dir, decision_log.DEFAULT_LOG_NAME }),
        };
    }

    /// The install under a home directory: `$HOME/.claude`.
    pub fn forHome(gpa: std.mem.Allocator, home: []const u8) std.mem.Allocator.Error!Layout {
        return init(gpa, try std.fs.path.join(gpa, &.{ home, ".claude" }));
    }
};

pub const usage_text =
    \\usage: claude-hooker-gate <subcommand> [options]
    \\
    \\  check [--event NAME] [--tool NAME] [--file-path P] [--content C]
    \\        [--prompt T] [--output T] [--message T] [--trigger T] [--agent T]
    \\        [--rules PATH] [--claude-dir DIR] [--project-dir DIR] [--explain]
    \\        [--quiet] [--] <command...>
    \\        Evaluate one hook payload and explain the outcome: every shadow
    \\        hit, then the enforced decision with the matched bytes
    \\        underlined. Remaining arguments are joined with single spaces to
    \\        form the command, so no extra shell quoting is needed; use `--`
    \\        before a command that starts with a dash.
    \\        --event picks which hook event to evaluate as (default PreToolUse,
    \\        which is what every rule file means unless it says otherwise). The
    \\        remaining field flags supply the non-tool payload fields, named
    \\        exactly as a matcher names them, so `--prompt` exercises a rule
    \\        that reads `prompt`. `events` lists which event carries which.
    \\        --project-dir names the repository whose .claude/hook-rules.json
    \\        overlay is evaluated first, exactly as the hook does; it defaults
    \\        to $CLAUDE_PROJECT_DIR. Each hit is labelled project or global.
    \\        --explain also prints the parsed and resolved command model the
    \\        structural matcher kinds read: every invocation with its nesting
    \\        depth, wrapper, resolved command word and arguments, every alias
    \\        or function body that was re-lexed, and the signal flags.
    \\        Exit: 0 no match or allow, 1 deny, 2 ask.
    \\
    \\  selftest [--rules PATH] [--claude-dir DIR] [--json]
    \\        Run the `tests` cases the rule file carries — literal ones and
    \\        every case its `generate` blocks expand to, each reported on its
    \\        own line — then lint the rule set. Exit: 0 all cases pass and no
    \\        lint errors, 1 otherwise.
    \\
    \\  classes [NAME] [--json]
    \\        Print the built-in classes a rule may name instead of enumerating
    \\        members — home_or_root, filesystem_anchor, shell_names,
    \\        db_clients, package_managers, destructive_sql, traversal_commands,
    \\        recursive_readers, recursive_mutators — with every member, so what
    \\        a rule inherits from this binary is never hidden knowledge.
    \\
    \\  events [NAME] [--json]
    \\        Print the hook event catalog: for each of the 30 events, when it
    \\        fires, whether it can refuse anything and through which response
    \\        field, which decisions that field can carry, what its matcher
    \\        means, and which payload fields a rule can read. Thirteen events
    \\        are advisory — they cannot block, so a deny/ask/allow rule scoped
    \\        to one is a selftest ERROR rather than a silent no-op.
    \\
    \\  stats [--since 7d|24h|90m] [--log PATH] [--claude-dir DIR]
    \\        [--include-rotated] [--json]
    \\        Per-rule summary of the decision log: totals, enforced decisions,
    \\        shadow and bypassed counts, and how long ago each rule last fired.
    \\        --include-rotated also reads the previous generation (<log>.1),
    \\        oldest entries first, so a rotation does not truncate history.
    \\
    \\  doctor [--claude-dir DIR] [--rules PATH] [--project-dir DIR] [--json]
    \\        Diagnose one install, PASS/WARN/FAIL per check with a remediation
    \\        line under everything that is not passing: is a PreToolUse entry
    \\        wired and does its command exist and run; does the INSTALLED
    \\        binary's version match the build doing the diagnosing; do the live
    \\        rules parse, pass their own cases and lint clean; is the log
    \\        writable and rotating; is a project overlay active for this
    \\        directory and does it parse; is CLAUDE_HOOK_DISABLE switching
    \\        rules off; is anything overriding the default paths.
    \\        Exit: 1 if any check FAILS, 0 otherwise (a WARN is not a failure).
    \\
    \\  status [--claude-dir DIR] [--rules PATH] [--project-dir DIR] [--json]
    \\        One screen of the same facts: installed version, rule file and its
    \\        counts, overlay, log size and last hit, and what is switched off.
    \\
    \\  diff-defaults [--claude-dir DIR] [--rules PATH] [--json]
    \\        Compare the defaults THIS binary carries against the live rule
    \\        file: rules added, removed, or changed, and for a changed rule the
    \\        fields that differ. The upgrade path for a rule file you have
    \\        edited — it says what the shipped defaults gained without touching
    \\        your copy. Exit 0 whether or not anything differs.
    \\
    \\  version
    \\  help
    \\
    \\--claude-dir names the directory a whole install lives in (default
    \\~/.claude): its hook-rules.json, its settings.json, its log, its copy of
    \\the gate. Every subcommand that reads one of those accepts it, so an
    \\install can be inspected without being the one you are living in. An
    \\explicit --rules or --log outranks it; the environment outranks both.
    \\
    \\Environment:
    \\  CLAUDE_HOOK_RULES_PATH  rule file location (outranks --rules)
    \\  CLAUDE_HOOK_LOG_PATH    decision log location (outranks logging.path)
    \\  CLAUDE_HOOK_DISABLE     comma-separated rule names to switch off;
    \\                          honored by `check` exactly as by the hook
    \\  CLAUDE_PROJECT_DIR      repo root for the project rule overlay;
    \\                          --project-dir outranks it
    \\
    \\With no arguments this binary IS the PreToolUse hook: it reads the event
    \\JSON on stdin and writes the decision envelope on stdout.
    \\
;

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------

pub const CheckArgs = struct {
    /// Which hook event to evaluate as. Defaults to `PreToolUse`, so every
    /// `check <command>` an operator has ever typed still means what it meant.
    event: rules.Event = rules.Events.DEFAULT_EVENT,
    tool: []const u8 = "Bash",
    file_path: []const u8 = "",
    content: []const u8 = "",
    /// The non-tool payload fields, one flag each, named exactly as the matcher
    /// `field` is named — so a rule that reads `prompt` is exercised with
    /// `--prompt` and there is nothing to translate.
    prompt: []const u8 = "",
    output: []const u8 = "",
    message: []const u8 = "",
    trigger: []const u8 = "",
    agent: []const u8 = "",
    rules_path: ?[]const u8 = null,
    /// Read this install's rule file rather than the one under `$HOME/.claude`.
    /// `--rules` outranks it; see `Layout`.
    claude_dir: ?[]const u8 = null,
    /// The repository whose overlay to evaluate first. Null defers to
    /// `$CLAUDE_PROJECT_DIR`; the flag outranks it, because the flag is the
    /// operator asking "what would the gate do over *there*".
    project_dir: ?[]const u8 = null,
    quiet: bool = false,
    /// Also render the parsed + resolved command model: stages, depths,
    /// wrappers, command words with their resolutions, arguments, and the
    /// signal flags. Off by default — the compact report is the one an
    /// operator reads a hundred times.
    explain: bool = false,
    /// The positional words; joined with single spaces to form the command.
    command: []const []const u8 = &.{},
};

pub const SelftestArgs = struct {
    rules_path: ?[]const u8 = null,
    claude_dir: ?[]const u8 = null,
    json: bool = false,
};

pub const ClassesArgs = struct {
    json: bool = false,
    /// Print only this class, or every class when null.
    name: ?[]const u8 = null,
};

pub const EventsArgs = struct {
    json: bool = false,
    /// Emit the reference table as markdown, which is what the README quotes and
    /// what `hookctl audit` compares the README against.
    markdown: bool = false,
    /// Print only this event, or all thirty when null.
    name: ?[]const u8 = null,
};

pub const StatsArgs = struct {
    log_path: ?[]const u8 = null,
    /// Read this install's log and rule file rather than the ones under
    /// `$HOME/.claude`. `--log` outranks it for the log.
    claude_dir: ?[]const u8 = null,
    /// The `--since` window in seconds, or null for "everything".
    since_seconds: ?i64 = null,
    /// The operator's own spelling of the window, echoed back verbatim.
    since_spec: ?[]const u8 = null,
    /// Also read the rotated generation (`<log>.1`), oldest entries first.
    include_rotated: bool = false,
    json: bool = false,
};

/// The flags shared by the three subcommands that INSPECT an install rather
/// than evaluating a command: `doctor`, `status`, `diff-defaults`.
///
/// `claude_dir` is the whole reason they can be exercised at all: it points
/// every path in `Layout` at a sandbox, so a test — or a nervous operator —
/// can diagnose an install that is not the one they are living in.
pub const InspectArgs = struct {
    claude_dir: ?[]const u8 = null,
    rules_path: ?[]const u8 = null,
    /// The repository whose overlay to look for. Null defers to
    /// `$CLAUDE_PROJECT_DIR`, then to the current directory.
    project_dir: ?[]const u8 = null,
    json: bool = false,
};

/// Why an argument list could not be turned into a command. `arg` borrows
/// from the argument that caused it, so rendering needs no allocation.
pub const Fault = struct {
    pub const Kind = enum {
        unknown_subcommand,
        unknown_flag,
        missing_value,
        missing_input,
        bad_duration,
        /// `--event` naming something that is not in the event catalog. A hard
        /// usage error rather than a silent fall back to `PreToolUse`: checking
        /// the wrong event would answer a question nobody asked.
        unknown_event,
    };
    kind: Kind,
    arg: []const u8 = "",
};

pub const Command = union(enum) {
    check: CheckArgs,
    selftest: SelftestArgs,
    stats: StatsArgs,
    classes: ClassesArgs,
    events: EventsArgs,
    doctor: InspectArgs,
    status: InspectArgs,
    diff_defaults: InspectArgs,
    version,
    help,
    fault: Fault,
};

/// Parse the arguments *after* the program name.
pub fn parseArgs(args: []const []const u8) Command {
    if (args.len == 0) return .help;
    const sub = args[0];
    const rest = args[1..];
    if (eq(sub, "check")) return parseCheck(rest);
    if (eq(sub, "selftest")) return parseSelftest(rest);
    if (eq(sub, "stats")) return parseStats(rest);
    if (eq(sub, "classes")) return parseClasses(rest);
    if (eq(sub, "events")) return parseEvents(rest);
    if (eq(sub, "doctor")) return parseInspect(rest, .doctor);
    if (eq(sub, "status")) return parseInspect(rest, .status);
    if (eq(sub, "diff-defaults")) return parseInspect(rest, .diff_defaults);
    if (eq(sub, "version") or eq(sub, "--version") or eq(sub, "-V")) return .version;
    if (eq(sub, "help") or eq(sub, "--help") or eq(sub, "-h")) return .help;
    return .{ .fault = .{ .kind = .unknown_subcommand, .arg = sub } };
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const Flag = struct {
    name: []const u8,
    /// The `=value` half of `--flag=value`, when present.
    attached: ?[]const u8 = null,
};

fn splitFlag(arg: []const u8) Flag {
    if (std.mem.indexOfScalar(u8, arg, '=')) |at| {
        return .{ .name = arg[0..at], .attached = arg[at + 1 ..] };
    }
    return .{ .name = arg };
}

/// A dash-led argument that is not the bare "-" (a real argument to plenty of
/// commands) and not the "--" separator.
fn looksLikeFlag(arg: []const u8) bool {
    return arg.len >= 2 and arg[0] == '-' and !eq(arg, "--");
}

/// The value for a flag: the `=value` half, or the next argument. Advances
/// `index` past a consumed value.
fn flagValue(args: []const []const u8, index: *usize, flag: Flag) ?[]const u8 {
    if (flag.attached) |value| return value;
    if (index.* + 1 >= args.len) return null;
    index.* += 1;
    return args[index.*];
}

fn parseCheck(args: []const []const u8) Command {
    var out = CheckArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (eq(arg, "--")) {
            out.command = args[i + 1 ..];
            break;
        }
        // The first non-flag word begins the command; everything from there on
        // is command text, dashes and all, so `check rm -rf /x` needs no
        // quoting. A command that *starts* with a dash needs the `--` above.
        if (!looksLikeFlag(arg)) {
            out.command = args[i..];
            break;
        }
        const flag = splitFlag(arg);
        if (eq(flag.name, "--quiet") or eq(flag.name, "-q")) {
            out.quiet = true;
            continue;
        }
        if (eq(flag.name, "--explain")) {
            out.explain = true;
            continue;
        }
        const value = flagValue(args, &i, flag) orelse
            return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        if (eq(flag.name, "--event")) {
            out.event = rules.Event.from(value) orelse
                return .{ .fault = .{ .kind = .unknown_event, .arg = value } };
        } else if (eq(flag.name, "--tool")) {
            out.tool = value;
        } else if (eq(flag.name, "--file-path")) {
            out.file_path = value;
        } else if (eq(flag.name, "--content")) {
            out.content = value;
        } else if (eq(flag.name, "--prompt")) {
            out.prompt = value;
        } else if (eq(flag.name, "--output")) {
            out.output = value;
        } else if (eq(flag.name, "--message")) {
            out.message = value;
        } else if (eq(flag.name, "--trigger")) {
            out.trigger = value;
        } else if (eq(flag.name, "--agent")) {
            out.agent = value;
        } else if (eq(flag.name, "--rules")) {
            out.rules_path = value;
        } else if (eq(flag.name, "--claude-dir")) {
            out.claude_dir = value;
        } else if (eq(flag.name, "--project-dir")) {
            out.project_dir = value;
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    if (out.command.len == 0 and checkFields(out, "").isEmpty()) {
        return .{ .fault = .{ .kind = .missing_input, .arg = "check" } };
    }
    return .{ .check = out };
}

/// The payload `check` evaluates: the event, the tool, and every field flag.
///
/// `command` arrives separately because the positional words have to be joined
/// first, and joining needs an allocator that argument parsing does not have.
/// Passing `""` therefore answers "did the operator supply any field at all?"
/// without allocating — which is exactly what the usage check above needs.
pub fn checkFields(args: CheckArgs, command: []const u8) rules.Input {
    return .{
        .event = args.event,
        .tool = args.tool,
        .command = command,
        .content = args.content,
        .file_path = args.file_path,
        .prompt = args.prompt,
        .output = args.output,
        .message = args.message,
        .trigger = args.trigger,
        .agent = args.agent,
    };
}

fn parseSelftest(args: []const []const u8) Command {
    var out = SelftestArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag = splitFlag(args[i]);
        if (eq(flag.name, "--json")) {
            out.json = true;
        } else if (eq(flag.name, "--rules")) {
            out.rules_path = flagValue(args, &i, flag) orelse
                return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        } else if (eq(flag.name, "--claude-dir")) {
            out.claude_dir = flagValue(args, &i, flag) orelse
                return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    return .{ .selftest = out };
}

fn parseClasses(args: []const []const u8) Command {
    var out = ClassesArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (!looksLikeFlag(args[i])) {
            out.name = args[i];
            continue;
        }
        const flag = splitFlag(args[i]);
        if (eq(flag.name, "--json")) {
            out.json = true;
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    return .{ .classes = out };
}

/// `events` takes the same shape as `classes`, for the same reason: a bare
/// name narrows the catalog to one entry, and `--json` makes it machine-readable
/// so the README table can be checked against it.
fn parseEvents(args: []const []const u8) Command {
    var out = EventsArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (!looksLikeFlag(args[i])) {
            out.name = args[i];
            continue;
        }
        const flag = splitFlag(args[i]);
        if (eq(flag.name, "--json")) {
            out.json = true;
        } else if (eq(flag.name, "--markdown")) {
            out.markdown = true;
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    return .{ .events = out };
}

fn parseStats(args: []const []const u8) Command {
    var out = StatsArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag = splitFlag(args[i]);
        if (eq(flag.name, "--json")) {
            out.json = true;
        } else if (eq(flag.name, "--include-rotated")) {
            out.include_rotated = true;
        } else if (eq(flag.name, "--log")) {
            out.log_path = flagValue(args, &i, flag) orelse
                return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        } else if (eq(flag.name, "--claude-dir")) {
            out.claude_dir = flagValue(args, &i, flag) orelse
                return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        } else if (eq(flag.name, "--since")) {
            const raw = flagValue(args, &i, flag) orelse
                return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
            out.since_seconds = parseDuration(raw) orelse
                return .{ .fault = .{ .kind = .bad_duration, .arg = raw } };
            out.since_spec = raw;
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    return .{ .stats = out };
}

/// Which inspecting subcommand is being parsed. Only the variant differs —
/// and whether `--project-dir` means anything, since `diff-defaults` compares
/// the global file against the embedded defaults and never looks at an
/// overlay. Accepting a flag it would then ignore is worse than rejecting it.
const Inspect = enum { doctor, status, diff_defaults };

fn parseInspect(args: []const []const u8, which: Inspect) Command {
    var out = InspectArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag = splitFlag(args[i]);
        if (eq(flag.name, "--json")) {
            out.json = true;
            continue;
        }
        const value = flagValue(args, &i, flag) orelse
            return .{ .fault = .{ .kind = .missing_value, .arg = flag.name } };
        if (eq(flag.name, "--claude-dir")) {
            out.claude_dir = value;
        } else if (eq(flag.name, "--rules")) {
            out.rules_path = value;
        } else if (eq(flag.name, "--project-dir") and which != .diff_defaults) {
            out.project_dir = value;
        } else {
            return .{ .fault = .{ .kind = .unknown_flag, .arg = flag.name } };
        }
    }
    return switch (which) {
        .doctor => .{ .doctor = out },
        .status => .{ .status = out },
        .diff_defaults => .{ .diff_defaults = out },
    };
}

/// `90`, `45s`, `90m`, `24h`, `7d`, `2w` → seconds. A bare number is seconds.
/// Null for anything else, including a value that would overflow — a silently
/// wrong window is worse than a rejected one.
pub fn parseDuration(spec: []const u8) ?i64 {
    if (spec.len == 0) return null;
    const last = spec[spec.len - 1];
    const unit: i64 = switch (last) {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        'w' => 7 * 24 * 60 * 60,
        '0'...'9' => 1,
        else => return null,
    };
    const digits = if (std.ascii.isDigit(last)) spec else spec[0 .. spec.len - 1];
    if (digits.len == 0) return null;
    const count = std.fmt.parseInt(i64, digits, 10) catch return null;
    // A negative window would silently select nothing; reject it outright.
    if (count < 0) return null;
    return std.math.mul(i64, count, unit) catch null;
}

/// The positional words joined with single spaces. Joining rather than
/// requiring one quoted argument is the whole point: an operator types
/// `check git push --force`, not `check 'git push --force'`.
pub fn joinCommand(allocator: std.mem.Allocator, parts: []const []const u8) std.mem.Allocator.Error![]u8 {
    return std.mem.join(allocator, " ", parts);
}

fn writeFault(w: *std.Io.Writer, fault: Fault) !void {
    try w.print("{s}: ", .{PROGRAM});
    switch (fault.kind) {
        .unknown_subcommand => try w.print("unknown subcommand \"{s}\"\n", .{fault.arg}),
        .unknown_flag => try w.print("unknown option \"{s}\"\n", .{fault.arg}),
        .missing_value => try w.print("option \"{s}\" requires a value\n", .{fault.arg}),
        .missing_input => try w.print(
            "check needs something to evaluate: a command, or one of " ++
                "--file-path/--content/--prompt/--output/--message/--trigger/--agent\n",
            .{},
        ),
        .bad_duration => try w.print(
            "\"{s}\" is not a duration; use 90m, 24h, 7d, 2w, or a bare number of seconds\n",
            .{fault.arg},
        ),
        .unknown_event => {
            try w.print("\"{s}\" is not a hook event; run `{s} events` for the catalog\n", .{ fault.arg, PROGRAM });
        },
    }
}

// ---------------------------------------------------------------------------
// rendering primitives
// ---------------------------------------------------------------------------

const ELIDE = "\u{2026}"; // one cell, three bytes
const SPACES = " " ** 64;

fn pad(w: *std.Io.Writer, count: usize) !void {
    var left = count;
    while (left > 0) {
        const take = @min(left, SPACES.len);
        try w.writeAll(SPACES[0..take]);
        left -= take;
    }
}

/// Terminal columns a byte slice occupies, counting a UTF-8 sequence once.
/// Combining marks and double-width characters are not modelled — rule
/// patterns and command lines are overwhelmingly ASCII, and a one-column slip
/// on an emoji is not worth a width table.
fn displayWidth(text: []const u8) usize {
    var cells: usize = 0;
    for (text) |b| {
        if ((b & 0xC0) != 0x80) cells += 1;
    }
    return cells;
}

/// Write text with control bytes replaced one-for-one by `.` (the hexdump
/// convention). One byte in, one byte out, so the underline underneath stays
/// aligned even when the field is a whole heredoc or file body.
fn writeVisible(w: *std.Io.Writer, text: []const u8) !void {
    for (text) |b| {
        try w.writeByte(if (b < 0x20 or b == 0x7f) '.' else b);
    }
}

/// The largest index `<= at` that is not inside a UTF-8 sequence.
fn utf8BoundaryAtOrBefore(text: []const u8, at: usize) usize {
    var i = @min(at, text.len);
    while (i > 0 and i < text.len and (text[i] & 0xC0) == 0x80) i -= 1;
    return i;
}

pub const Window = struct {
    start: usize,
    end: usize,
    elided_left: bool = false,
    elided_right: bool = false,
};

/// The slice of `text` to print around `span` so the match is visible in at
/// most `width` columns. Short text is shown whole; long text keeps a quarter
/// of the width as left context, which puts the match near the start of the
/// line where the eye lands without losing what preceded it.
pub fn spanWindow(text: []const u8, span: rules.Span, width: usize) Window {
    if (text.len <= width) return .{ .start = 0, .end = text.len };

    const start = @min(span.start, text.len);
    const lead = width / 4;
    var s = if (start > lead) start - lead else 0;
    var e = s + width;
    if (e > text.len) {
        e = text.len;
        s = e - width;
    }
    s = utf8BoundaryAtOrBefore(text, s);
    e = utf8BoundaryAtOrBefore(text, e);
    return .{ .start = s, .end = e, .elided_left = s > 0, .elided_right = e < text.len };
}

/// Two lines: the field text (windowed) and a `^~~~` underline beneath the
/// matched bytes. This is the whole reason `Hit` carries a span — an operator
/// arguing with a rule needs to see *which* bytes it read, not just that it
/// fired.
pub fn writeRendered(
    w: *std.Io.Writer,
    indent: []const u8,
    text: []const u8,
    span: rules.Span,
    width: usize,
) !void {
    const win = spanWindow(text, span, width);

    try w.writeAll(indent);
    if (win.elided_left) try w.writeAll(ELIDE);
    try writeVisible(w, text[win.start..win.end]);
    if (win.elided_right) try w.writeAll(ELIDE);
    try w.writeByte('\n');

    const hit_start = @max(@min(span.start, text.len), win.start);
    const hit_end = @max(hit_start, @min(span.end(), win.end));

    try w.writeAll(indent);
    if (win.elided_left) try pad(w, 1);
    try pad(w, displayWidth(text[win.start..hit_start]));
    try w.writeByte('^');
    var cell: usize = 1;
    const cells = displayWidth(text[hit_start..hit_end]);
    while (cell < cells) : (cell += 1) try w.writeByte('~');
    try w.writeByte('\n');
}

/// Greedy word wrap at `width` columns, every line prefixed with `indent`.
/// Reasons are paragraphs of operator prose — the thing the model is shown on
/// a denial — and are unreadable as one 600-column line.
pub fn writeWrapped(w: *std.Io.Writer, indent: []const u8, text: []const u8, width: usize) !void {
    return writeWrappedFrom(w, indent, text, width, true);
}

/// As `writeWrapped`, except the first line CONTINUES whatever the caller has
/// already written on the current line: `indent` is applied to the wrapped
/// continuation lines only, and is assumed to be as wide as the label the
/// caller printed. For reports that put a paragraph beside a label.
pub fn writeWrappedAfter(w: *std.Io.Writer, indent: []const u8, text: []const u8, width: usize) !void {
    return writeWrappedFrom(w, indent, text, width, false);
}

fn writeWrappedFrom(
    w: *std.Io.Writer,
    indent: []const u8,
    text: []const u8,
    width: usize,
    indent_first: bool,
) !void {
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    // Continuing a line means the caller's label already occupies `indent`
    // worth of columns, so wrapping has to count from there or the first line
    // runs past the width every time.
    var column: usize = if (indent_first) 0 else displayWidth(indent);
    var first = true;
    while (it.next()) |word| {
        const cells = displayWidth(word);
        if (first) {
            if (indent_first) try w.writeAll(indent);
            first = false;
        } else if (column + 1 + cells > width) {
            try w.writeByte('\n');
            try w.writeAll(indent);
            column = 0;
        } else {
            try w.writeByte(' ');
            column += 1;
        }
        try w.writeAll(word);
        column += cells;
    }
    if (!first) try w.writeByte('\n');
}

/// `text` cut to `max_cells` columns with an ellipsis, control bytes made
/// visible. Used for one-line echoes of a field and for test case labels.
pub fn ellipsize(buf: []u8, text: []const u8, max_cells: usize) []const u8 {
    var written: usize = 0;
    var cells: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const b = text[i];
        if ((b & 0xC0) != 0x80) {
            if (cells == max_cells) break;
            cells += 1;
        }
        if (written == buf.len) break;
        buf[written] = if (b < 0x20 or b == 0x7f) '.' else b;
        written += 1;
    }
    if (i < text.len and written + ELIDE.len <= buf.len) {
        @memcpy(buf[written..][0..ELIDE.len], ELIDE);
        written += ELIDE.len;
    }
    return buf[0..written];
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/// The exit code a decision maps to: deny blocks (1), ask needs a human (2),
/// allow and no-match are both "nothing stops this" (0). Shell-usable:
/// `check ... || echo blocked`.
pub fn exitCodeFor(result: rules.Evaluation) u8 {
    const hit = result.enforced orelse return 0;
    return switch (hit.rule.decision) {
        .deny => 1,
        .ask => 2,
        .allow => 0,
        // Shadow rules never enforce; `evaluateWith` cannot produce this.
        .log => 0,
    };
}

fn decisionWord(result: rules.Evaluation) []const u8 {
    const hit = result.enforced orelse return "no-match";
    return hit.rule.decision.wire();
}

/// Which rule file a hit's rule came from. `evaluateOverlay` walks two slices
/// as one list and returns pointers straight out of them, so the layer is
/// recoverable from the pointer alone — no tag has to be threaded through the
/// evaluator, and `rules.zig` stays a pure function of two slices.
pub const Layer = enum {
    project,
    global,

    /// The parenthetical the report appends to a rule name. Empty when there
    /// is no overlay in play, so single-layer output is unchanged.
    pub fn suffix(self: ?Layer) []const u8 {
        const layer = self orelse return "";
        return switch (layer) {
            .project => " (project)",
            .global => " (global)",
        };
    }
};

/// The layer `rule` belongs to, given the project slice it might live in.
/// Null when there is no overlay at all — the caller then labels nothing.
pub fn layerOf(project: []const rules.Rule, rule: *const rules.Rule) ?Layer {
    if (project.len == 0) return null;
    const base = @intFromPtr(project.ptr);
    const at = @intFromPtr(rule);
    if (at >= base and at < base + project.len * @sizeOf(rules.Rule)) return .project;
    return .global;
}

pub const CheckOptions = struct {
    quiet: bool = false,
    width: usize = RENDER_WIDTH,
    /// Printed as a header so a surprising outcome names the file it came from.
    rules_path: ?[]const u8 = null,
    /// The overlay that was evaluated first, for layer labelling. Empty means
    /// no overlay, and then nothing is labelled.
    project: []const rules.Rule = &.{},
    /// Where the overlay was looked for. Printed even when nothing was loaded,
    /// so "I passed --project-dir and saw no project rules" has an answer.
    project_path: ?[]const u8 = null,
    /// Why `project` is empty despite `project_path` being set.
    project_note: ?[]const u8 = null,
    /// The parsed + resolved command to render under `explain :`. Null keeps
    /// the report exactly as compact as it has always been.
    explain: ?*const rules.Structure = null,
};

/// Print the evaluation and return the process exit code.
pub fn writeCheckReport(
    w: *std.Io.Writer,
    input: rules.Input,
    result: rules.Evaluation,
    options: CheckOptions,
) !u8 {
    const code = exitCodeFor(result);
    if (options.quiet) {
        try w.print("{s}\n", .{decisionWord(result)});
        return code;
    }

    if (options.rules_path) |path| try w.print("rules    : {s}\n", .{path});
    if (options.project_path) |path| {
        if (options.project_note) |note| {
            try w.print("project  : {s} ({s})\n", .{ path, note });
        } else {
            try w.print("project  : {s} ({d} rule(s), evaluated first)\n", .{ path, options.project.len });
        }
    }
    // The event first, because every other line means something different
    // depending on it — and because a decision that surprises an operator is
    // very often a decision about a different event than they had in mind.
    const descriptor = input.event.descriptor();
    try w.print("event    : {s}{s}\n", .{
        input.event.name(),
        if (descriptor.isAdvisory()) "  (advisory: nothing here can block)" else "",
    });
    if (descriptor.has_tool) try w.print("tool     : {s}\n", .{input.tool});
    var echo_buf: [512]u8 = undefined;
    // Every field, in `Field` order, so a new one cannot be added without
    // showing up here.
    inline for (@typeInfo(rules.Field).@"enum".fields) |f| {
        const field: rules.Field = @enumFromInt(f.value);
        const text = input.text(field);
        if (text.len > 0) {
            try w.print("{s: <9}: {s}\n", .{ @tagName(field), ellipsize(&echo_buf, text, options.width) });
        }
    }
    try w.writeByte('\n');

    // Bypassed first: they explain why an expected decision is missing.
    for (result.bypassedHits()) |hit| {
        try writeHit(w, "bypassed", hit, input, options);
        try w.print("           (switched off by CLAUDE_HOOK_DISABLE)\n", .{});
    }
    if (result.bypassed_overflow) try w.print("bypassed : ...and more (report truncated)\n", .{});

    for (result.shadowHits()) |hit| {
        try writeHit(w, "shadow", hit, input, options);
    }
    if (result.shadow_overflow) try w.print("shadow   : ...and more (report truncated)\n", .{});

    if (result.enforced) |hit| {
        try writeHit(w, hit.rule.decision.wire(), hit, input, options);
        try w.print("reason   :\n", .{});
        try writeWrapped(w, "           ", hit.rule.reason, options.width);
    } else {
        try w.print("no-match : no rule fires for this input.\n", .{});
    }

    if (options.explain) |st| {
        try w.writeByte('\n');
        try writeExplain(w, st, options.width);
    }
    return code;
}

/// One hit: which rule, which matcher, and the bytes it read underlined.
///
/// A structural matcher adds `resolved from "<as written>" via <origin>` when
/// the value it compared against is not what the text spells out. That is the
/// whole point of the provenance: an operator looking at
/// `deny : no-pkill  [command_word command "pkill" resolved from "$P$K" via
/// resolved_concat]` can see both what the rule matched and why those are the
/// bytes underneath the caret.
fn writeHit(
    w: *std.Io.Writer,
    label: []const u8,
    hit: rules.Hit,
    input: rules.Input,
    options: CheckOptions,
) !void {
    try w.print("{s: <9}: {s}{s}  [{s} {s} \"{s}\"", .{
        label,
        hit.rule.name,
        Layer.suffix(layerOf(options.project, hit.rule)),
        @tagName(hit.kind),
        @tagName(hit.field),
        hit.value,
    });
    if (hit.provenance) |p| {
        if (p.isRecovered()) {
            var written_buf: [80]u8 = undefined;
            const written = ellipsize(&written_buf, hit.span.slice(input.text(hit.field)), 48);
            try w.print(" resolved from \"{s}\" via {s}", .{ written, @tagName(p.origin) });
        }
    }
    try w.writeAll("]\n");
    try writeRendered(w, "           ", input.text(hit.field), hit.span, options.width);
}

// ---------------------------------------------------------------------------
// check --explain: the model a structural rule reads
// ---------------------------------------------------------------------------

/// Render the parsed + resolved command: every invocation with its depth, the
/// wrapper that reached it, its command word (annotated when resolution
/// recovered one), and its arguments; then every alias/function body that was
/// re-lexed; then the signal flags.
///
/// This is what makes a structural rule arguable. "Why did `command_word
/// pkill` not fire" has exactly one honest answer — the model does not contain
/// a command word `pkill` — and this prints the model.
/// One invocation's normalized option set: the short letters it carries however
/// they were bundled, its long options, and any attached values — the model a
/// `flags` matcher asks, printed so an operator can argue with it.
fn writeExplainFlags(
    w: *std.Io.Writer,
    cmd: *const shell.Command,
    rc: ?*const resolve.ResolvedCommand,
) !void {
    var vals: [shell.MAX_OPT_SCAN_ARGS][]const u8 = undefined;
    var n: usize = 0;
    for (cmd.args(), 0..) |a, k| {
        if (n == vals.len) break;
        vals[n] = if (rc) |r|
            (if (k + 1 < r.words.len) r.words[k + 1].text else a.text)
        else
            a.text;
        n += 1;
    }
    const args = vals[0..n];
    const flags = shell.scanFlags(args);
    if (flags.isEmpty() and !flags.end_of_options) return;

    try w.writeAll("       flags    :");
    var short_buf: [128]u8 = undefined;
    var shorts: usize = 0;
    var c: u8 = 33;
    while (c < 127) : (c += 1) {
        if (!flags.short.has(c)) continue;
        if (shorts == short_buf.len) break;
        short_buf[shorts] = c;
        shorts += 1;
    }
    if (shorts > 0) try w.print(" short {{{s}}}", .{short_buf[0..shorts]});

    var it = shell.OptIter{ .args = args };
    while (it.next()) |opt| {
        if (!opt.long) continue;
        try w.print(" --{s}", .{opt.name});
    }

    var values = shell.OptIter{ .args = args };
    while (values.next()) |opt| {
        if (!opt.has_value) continue;
        var vbuf: [64]u8 = undefined;
        const shown = ellipsize(&vbuf, opt.value, 24);
        try w.print(" {s}{s}={s}({s})", .{
            if (opt.long) "--" else "-",
            opt.name,
            shown,
            @tagName(opt.form),
        });
    }
    if (flags.end_of_options) try w.writeAll(" --");
    try w.writeByte('\n');
}

pub fn writeExplain(w: *std.Io.Writer, st: *const rules.Structure, width: usize) !void {
    const source = st.parsed.source;
    try w.print("explain  : {d} invocation(s), max depth {d}\n", .{
        st.parsed.commands.len,
        st.parsed.stats.max_depth,
    });

    var buf: [256]u8 = undefined;
    for (st.parsed.commands, 0..) |*cmd, i| {
        const rc: ?*const resolve.ResolvedCommand =
            if (i < st.resolved.commands.len) &st.resolved.commands[i] else null;

        try w.print("  [{d}] depth {d}  {s}  {s}", .{
            i,
            cmd.depth,
            @tagName(cmd.provenance),
            @tagName(cmd.connector),
        });
        if (cmd.parent) |p| try w.print("  parent [{d}]", .{p});
        if (cmd.is_remote) try w.writeAll("  remote");
        if (!cmd.is_process) try w.writeAll("  (not a process)");
        try w.writeByte('\n');

        if (rc) |r| {
            if (r.is_definition) {
                try w.print("       defines  : {s}()\n", .{r.base});
            }
        }

        if (cmd.name) |name| {
            const written = ellipsize(&buf, name.raw(source), width / 2);
            try w.print("       command  : {s}", .{written});
            if (rc) |r| {
                if (r.origin != .literal or !std.mem.eql(u8, r.base, cmd.base)) {
                    var base_buf: [128]u8 = undefined;
                    const shown = ellipsize(&base_buf, r.base, 64);
                    try w.print("  -> {s} via {s}", .{ shown, @tagName(r.origin) });
                }
            }
            try w.writeByte('\n');
        }

        const args = cmd.args();
        if (args.len > 0) {
            try w.writeAll("       args     :");
            for (args, 0..) |a, k| {
                const value = if (rc) |r|
                    (if (k + 1 < r.words.len) r.words[k + 1].text else a.text)
                else
                    a.text;
                const shown = ellipsize(&buf, value, 32);
                try w.print(" [{s}]", .{shown});
            }
            try w.writeByte('\n');
        }

        // The option set, read from the RESOLVED values — which is what a
        // `flags` matcher reads, so `X=-rf; rm $X /` shows `-r -f` here even
        // though the `rm` invocation's own text carries neither letter.
        try writeExplainFlags(w, cmd, rc);
    }

    for (st.resolved.expansions, 0..) |*ex, i| {
        const shown = ellipsize(&buf, ex.body, width / 2);
        try w.print("  expansion [{d}] {s} {s} -> \"{s}\"  ({d} invocation(s))\n", .{
            i,
            @tagName(ex.kind),
            ex.name,
            shown,
            ex.parsed.commands.len,
        });
        for (ex.parsed.commands, 0..) |*cmd, k| {
            if (cmd.name == null) continue;
            try w.print("       [{d}.{d}] {s}", .{ i, k, cmd.base });
            for (cmd.args()) |a| {
                const arg_shown = ellipsize(&buf, a.text, 32);
                try w.print(" [{s}]", .{arg_shown});
            }
            try w.writeByte('\n');
        }
    }

    try w.writeAll("  signals  :");
    var any = false;
    inline for (@typeInfo(@TypeOf(st.parsed.signals)).@"struct".fields) |f| {
        if (f.type == bool and @field(st.parsed.signals, f.name)) {
            try w.print(" {s}", .{f.name});
            any = true;
        }
    }
    inline for (@typeInfo(@TypeOf(st.resolved.signals)).@"struct".fields) |f| {
        if (f.type == bool and @field(st.resolved.signals, f.name)) {
            try w.print(" {s}", .{f.name});
            any = true;
        }
    }
    if (!any) try w.writeAll(" none");
    try w.writeByte('\n');

    // The counted structure, in the same vocabulary a `shape` matcher uses,
    // so `explain` is how an operator finds the number to compare against.
    const shape = shell.Shape.of(&st.parsed);
    try w.print(
        "  shape    : pipes {d}, statements {d}, chains {d}, stages {d}, redirects {d}, heredocs {d}, depth {d}",
        .{ shape.pipes, shape.statements, shape.chains, shape.stages, shape.redirects, shape.heredocs, shape.depth },
    );
    if (shape.truncated) try w.writeAll(" (a cap was hit; counts are floors)");
    try w.writeByte('\n');
}

// ---------------------------------------------------------------------------
// selftest: the rule file's own cases
// ---------------------------------------------------------------------------

/// Where a case came from: written out in the `tests` block, or expanded from a
/// `generate` declaration. Reported separately because the two carry different
/// weight — a literal case usually pins a specific historical bug, and a
/// generated one covers a combinatorial space no list of literals could.
pub const CaseSource = enum { literal, generated };

pub const CaseResult = struct {
    index: usize,
    ok: bool,
    input: rules.Input,
    expect: rules.ExpectDecision,
    expect_rule: ?[]const u8,
    /// Null when nothing was enforced.
    got: ?rules.Decision,
    got_rule: ?[]const u8,
    source: CaseSource = .literal,
    /// 1-based index of the `tests` entry this case came from.
    origin: usize = 0,

    pub fn gotWord(self: CaseResult) []const u8 {
        const decision = self.got orelse return "none";
        return decision.wire();
    }
};

/// One expanded case, before it is run.
pub const Case = struct {
    input: rules.Input,
    expect: rules.ExpectDecision,
    expect_rule: ?[]const u8 = null,
    source: CaseSource = .literal,
    origin: usize = 0,
};

/// One axis bound to one value, for template rendering.
const Binding = struct { name: []const u8, value: []const u8 };

fn bindingFor(bindings: []const Binding, name: []const u8) ?[]const u8 {
    for (bindings) |b| {
        if (eq(b.name, name)) return b.value;
    }
    return null;
}

/// Substitute `{axis}` placeholders and tidy the result.
///
/// An axis value may be empty (a near-miss "no flags at all"), which would leave
/// a double space; runs of whitespace are collapsed and the ends trimmed so the
/// generated command reads like something a person would have typed. A
/// placeholder naming no axis is left verbatim — the lint reports it, and
/// silently deleting it would generate a command asserting something else.
fn renderTemplate(
    arena: std.mem.Allocator,
    template: []const u8,
    bindings: []const Binding,
) ![]const u8 {
    var raw: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < template.len) {
        if (template[i] == '{') {
            if (std.mem.indexOfScalarPos(u8, template, i, '}')) |close| {
                if (bindingFor(bindings, template[i + 1 .. close])) |value| {
                    try raw.appendSlice(arena, value);
                    i = close + 1;
                    continue;
                }
            }
        }
        try raw.append(arena, template[i]);
        i += 1;
    }

    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, raw.items, " \t\r\n");
    while (it.next()) |word| {
        if (out.items.len > 0) try out.append(arena, ' ');
        try out.appendSlice(arena, word);
    }
    return out.items;
}

/// Step an odometer over the axes' value counts. Returns false when it wrapped,
/// i.e. when the product has been walked exactly once.
fn nextCombination(pick: []usize, axes: []const rules.GenAxis) bool {
    var i = pick.len;
    while (i > 0) {
        i -= 1;
        pick[i] += 1;
        if (pick[i] < axes[i].values.len) return true;
        pick[i] = 0;
    }
    return false;
}

/// Expand one `tests` entry into the cases it stands for: itself, or — for a
/// `generate` declaration — every positive combination followed by every
/// near-miss negative.
fn expandGenerated(
    arena: std.mem.Allocator,
    out: *std.ArrayList(Case),
    case: *const rules.RuleTest,
    gen: rules.Generator,
    origin: usize,
) !void {
    if (gen.axes.len == 0) return;
    for (gen.axes) |a| {
        if (a.values.len == 0) return;
    }

    var pick_buf: [8]usize = @splat(0);
    var bind_buf: [8]Binding = undefined;
    const n = @min(gen.axes.len, pick_buf.len);
    const pick = pick_buf[0..n];
    const bindings = bind_buf[0..n];

    // Every positive combination.
    @memset(pick, 0);
    while (true) {
        for (gen.axes[0..n], 0..) |a, i| bindings[i] = .{ .name = a.name, .value = a.values[pick[i]] };
        try out.append(arena, .{
            .input = .{
                .tool = case.input.tool,
                .command = try renderTemplate(arena, gen.command, bindings),
            },
            .expect = case.expect,
            .expect_rule = case.expect_rule,
            .source = .generated,
            .origin = origin,
        });
        if (!nextCombination(pick, gen.axes[0..n])) break;
    }

    // The near misses: one axis swapped for a value the rule must NOT fire on,
    // every other axis still positive. A generator over positives alone proves
    // only that the rule fires; these prove it fires for the reason claimed.
    for (gen.near_miss) |miss| {
        const target = for (gen.axes[0..n], 0..) |a, i| {
            if (eq(a.name, miss.name)) break i;
        } else continue;

        for (miss.values) |value| {
            @memset(pick, 0);
            while (true) {
                for (gen.axes[0..n], 0..) |a, i| {
                    bindings[i] = .{
                        .name = a.name,
                        .value = if (i == target) value else a.values[pick[i]],
                    };
                }
                try out.append(arena, .{
                    .input = .{
                        .tool = case.input.tool,
                        .command = try renderTemplate(arena, gen.command, bindings),
                    },
                    .expect = .none,
                    .source = .generated,
                    .origin = origin,
                });
                // The swapped axis contributes exactly one value, so it must not
                // also drive the odometer.
                if (!nextCombinationSkipping(pick, gen.axes[0..n], target)) break;
            }
        }
    }
}

fn nextCombinationSkipping(pick: []usize, axes: []const rules.GenAxis, skip: usize) bool {
    var i = pick.len;
    while (i > 0) {
        i -= 1;
        if (i == skip) continue;
        pick[i] += 1;
        if (pick[i] < axes[i].values.len) return true;
        pick[i] = 0;
    }
    return false;
}

/// Every case the rule file asserts, literal and generated, in file order.
pub fn expandCases(arena: std.mem.Allocator, rule_set: rules.RuleSet) ![]const Case {
    var out: std.ArrayList(Case) = .empty;
    for (rule_set.tests, 0..) |*case, i| {
        if (case.generate) |gen| {
            try expandGenerated(arena, &out, case, gen, i + 1);
            continue;
        }
        try out.append(arena, .{
            .input = case.resolvedInput(),
            .expect = case.expect,
            .expect_rule = case.expect_rule,
            .source = .literal,
            .origin = i + 1,
        });
    }
    return out.items;
}

/// A run of every case a rule file asserts, owning the commands the generators
/// built. Counts are split by source so the report can say what it ran.
pub const Suite = struct {
    pub const Counts = struct {
        total: usize = 0,
        passed: usize = 0,
    };

    arena: std.heap.ArenaAllocator,
    results: []CaseResult = &.{},
    literal: Counts = .{},
    generated: Counts = .{},

    pub fn deinit(self: *Suite) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn total(self: *const Suite) usize {
        return self.literal.total + self.generated.total;
    }

    pub fn passed(self: *const Suite) usize {
        return self.literal.passed + self.generated.passed;
    }

    pub fn allPassed(self: *const Suite) bool {
        return self.passed() == self.total();
    }
};

/// Expand and run every case the rule file carries. The returned suite owns the
/// generated command strings; call `deinit` when the results are consumed.
pub fn runSuite(gpa: std.mem.Allocator, rule_set: rules.RuleSet) !Suite {
    var suite = Suite{ .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer suite.arena.deinit();
    const arena = suite.arena.allocator();

    const cases = try expandCases(arena, rule_set);
    const results = try arena.alloc(CaseResult, cases.len);
    for (cases, results, 0..) |case, *result, i| {
        result.* = runOne(rule_set, case, i + 1);
        const counts = if (case.source == .literal) &suite.literal else &suite.generated;
        counts.total += 1;
        if (result.ok) counts.passed += 1;
    }
    suite.results = results;
    return suite;
}

/// Run one case. Deliberately uses `evaluate` (no disabled set): the cases
/// assert what the *file* says, and an operator's temporary
/// `CLAUDE_HOOK_DISABLE` must not be able to turn a red suite green.
pub fn runCase(rule_set: rules.RuleSet, case: *const rules.RuleTest, index: usize) CaseResult {
    return runOne(rule_set, .{
        .input = case.resolvedInput(),
        .expect = case.expect,
        .expect_rule = case.expect_rule,
        .origin = index,
    }, index);
}

/// Run one already-expanded case.
pub fn runOne(rule_set: rules.RuleSet, case: Case, index: usize) CaseResult {
    // A `CaseResult` borrows only from the rule set (names) and the case
    // (input), never from the structural model, so the model can be released
    // here rather than pushed onto every caller.
    var result = rules.evaluate(rule_set, case.input);
    defer result.deinit();

    var out = CaseResult{
        .index = index,
        .ok = false,
        .input = case.input,
        .expect = case.expect,
        .expect_rule = case.expect_rule,
        .got = null,
        .got_rule = null,
        .source = case.source,
        .origin = case.origin,
    };
    if (result.enforced) |hit| {
        out.got = hit.rule.decision;
        out.got_rule = hit.rule.name;
    }
    out.ok = switch (case.expect) {
        .none => out.got == null,
        else => blk: {
            const got = out.got orelse break :blk false;
            if (!eq(@tagName(case.expect), got.wire())) break :blk false;
            if (case.expect_rule) |want| break :blk eq(want, out.got_rule orelse "");
            break :blk true;
        },
    };
    return out;
}

/// A one-line description of what a case exercises: the first field of it that
/// carries anything, in `Field` order.
///
/// Derived from the enum rather than from a hand-written preference list so a
/// case for a new event cannot render as a blank line — which is exactly what a
/// `Stop` or `SessionStart` case did when this named only the three tool fields.
pub fn caseLabel(buf: []u8, input: rules.Input, max_cells: usize) []const u8 {
    inline for (@typeInfo(rules.Field).@"enum".fields) |f| {
        const text = input.text(@enumFromInt(f.value));
        if (text.len > 0) return ellipsize(buf, text, max_cells);
    }
    return "";
}

/// How a case's subject is named in the report: the tool for a tool event, the
/// event itself for one that has no tool.
pub fn caseSubject(input: rules.Input) []const u8 {
    return if (input.event.descriptor().has_tool) input.tool else input.event.name();
}

// ---------------------------------------------------------------------------
// selftest: lint
// ---------------------------------------------------------------------------

pub const Level = enum {
    // Spelled `error` on the wire, which is what a reader (and jq) expects.
    @"error",
    warn,
};

pub const Finding = struct {
    level: Level,
    /// The rule the finding is about — or, for a test case, the name it
    /// referenced. Borrowed from the rule set.
    rule: ?[]const u8 = null,
    /// 1-based index of the `tests` entry, when the finding is about one.
    test_index: ?usize = null,
    /// A fixed sentence; every varying detail is a field above it.
    message: []const u8,
};

/// Static checks over a rule set: the mistakes that make a rule quietly do
/// nothing, and the ones that make a policy weaker than it reads.
///
/// Deliberately not included: shadowing analysis ("this deny is unreachable
/// because an allow above it matches a superset"). Doing that honestly needs
/// pattern containment, and a lint that is right most of the time is worse
/// than no lint — an operator who learns to ignore the output has lost the
/// checks that *are* exact.
pub fn lint(allocator: std.mem.Allocator, rule_set: rules.RuleSet) ![]Finding {
    return lintWith(allocator, rule_set, &.{});
}

/// `lint` with the reference counts `rules.parse` recorded for the file's
/// declared sets, so a set nothing uses can be reported. Pass an empty slice
/// when the rule set was built in code rather than parsed — the checks that do
/// not need the counts still run.
pub fn lintWith(
    allocator: std.mem.Allocator,
    rule_set: rules.RuleSet,
    set_uses: []const u32,
) ![]Finding {
    var found: std.ArrayList(Finding) = .empty;
    errdefer found.deinit(allocator);

    for (rule_set.rules, 0..) |*rule, i| {
        if (rule.name.len == 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .message = "rule has an empty name; CLAUDE_HOOK_DISABLE and the decision log both key on it",
            });
        } else {
            for (rule_set.rules[0..i]) |*earlier| {
                if (eq(earlier.name, rule.name)) {
                    try found.append(allocator, .{
                        .level = .@"error",
                        .rule = rule.name,
                        .message = "duplicate rule name; disabling or reading the log for it is ambiguous",
                    });
                    break;
                }
            }
        }

        if (rule.reason.len == 0) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = rule.name,
                .message = "empty reason; the reason is the whole explanation the model and the user are shown",
            });
        }

        if (rule.match.len == 0 and rule.match_all.len == 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule.name,
                .message = "no positive matchers (match and match_all are both empty); this rule can never fire",
            });
        } else if (!canYieldEvidence(rule.match) and !canYieldEvidence(rule.match_all)) {
            // Every entry is a negative group, so nothing is left to point
            // at and the rule cannot fire — the same trap as a rule carrying
            // only `match_none`, one nesting level down.
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule.name,
                .message = "every positive entry is a negative group; a rule with no positive condition can never fire",
            });
        }

        try lintEvent(allocator, &found, rule);

        const descriptor = rule.event.descriptor();
        for ([_][]const rules.Matcher{ rule.match, rule.match_all, rule.match_none }) |list| {
            try lintMatchers(allocator, &found, rule.name, descriptor, list, 0, false);
        }

        if (rule.decision == .allow) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = rule.name,
                .message = "allow skips the permission PROMPT but not the permission RULES: a settings.json deny always wins, so a hook can only ever tighten. Keep its matchers narrow, and do not read it as a grant",
            });
        }
    }

    // Declared sets. A set exists to stop a rule enumerating; one that nothing
    // references is dead policy, and one with a single member is an indirection
    // the next reader has to follow to learn nothing.
    const set_names = rule_set.sets.map.keys();
    const set_members = rule_set.sets.map.values();
    for (set_names, set_members, 0..) |name, members, i| {
        if (members.len == 1) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = name,
                .message = "set has a single member; a set names a list, and a one-member set is an indirection with nothing behind it — write the value in the matcher",
            });
        }
        if (i < set_uses.len and set_uses[i] == 0) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = name,
                .message = "set is declared but no matcher references it; either a rule lost its \"$name\" reference or the set is dead policy",
            });
        }
    }

    for (rule_set.tests, 0..) |*case, i| {
        if (case.expect_rule) |name| {
            if (findRule(rule_set, name) == null) {
                try found.append(allocator, .{
                    .level = .@"error",
                    .rule = name,
                    .test_index = i + 1,
                    .message = "test expects a rule that does not exist",
                });
            }
        }
        if (case.generate) |gen| try lintGenerator(allocator, &found, case, gen, i + 1);
    }

    if (rule_set.tests.len == 0) {
        try found.append(allocator, .{
            .level = .warn,
            .message = "no tests block; the rule file asserts nothing about its own behavior",
        });
    }

    return found.toOwnedSlice(allocator);
}

/// Everything about a rule that its EVENT decides, checked against the
/// descriptor table.
///
/// This is the whole reason the table exists. Each finding here is a rule that
/// reads like policy and enforces nothing — the failure mode a multi-event gate
/// invites, because the wrongness is invisible: the rule parses, the file
/// selftests, the gate runs, and the event it is scoped to simply has no field
/// to read or no envelope to refuse with. So each one is an ERROR, not a
/// tidy-up, and each one names the fact from the table that makes it wrong.
fn lintEvent(
    allocator: std.mem.Allocator,
    found: *std.ArrayList(Finding),
    rule: *const rules.Rule,
) !void {
    const d = rule.event.descriptor();

    // 1. An enforced decision on an event whose response cannot carry it.
    //    Thirteen events can refuse nothing at all; several more can refuse but
    //    have no spelling for `ask` or `allow`.
    if (!rule.decision.permittedBy(d.vocabulary())) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule.name,
            .message = if (d.isAdvisory())
                "enforced decision on an ADVISORY event: this event's response cannot stop anything, so deny/ask/allow are silently ignored by the harness. Use \"decision\": \"log\" to observe it, or scope the rule to an event that can refuse"
            else
                "decision this event's response envelope has no field for; the mechanism is the one in the per-event reference table, and only the decisions it lists can be expressed (log always can)",
        });
    }

    // 2. A `tool` on an event whose payload has no tool name. The historical
    //    default is not reported — every rule for these events leaves it unset
    //    — only an explicit one, which is a rule that can never match.
    if (!d.has_tool) {
        if (rule.tool) |pattern| {
            if (!eq(pattern, rules.TOOL_ANY)) {
                try found.append(allocator, .{
                    .level = .@"error",
                    .rule = rule.name,
                    .message = "tool named on an event whose payload carries no tool_name; the comparison can never succeed, so the rule never fires. Drop the key, or use \"*\"",
                });
            }
        }
    }

    // 3. An event with nothing matchable in its payload. Not a mistake in the
    //    rule so much as a gap in what is documented upstream — but a rule
    //    scoped there cannot fire, and saying so beats leaving it inert.
    if (d.hasNoMatchableField()) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule.name,
            .message = "this event has no matchable payload field in the reference table, so no matcher can read anything and the rule can never fire",
        });
    }

    // 4. An event whose row is partly inference. Supported, and flagged: a
    //    WARNING rather than an error, because the rule may well work — nobody
    //    has been able to confirm the payload or the blocking behaviour.
    if (!d.verified) {
        try found.append(allocator, .{
            .level = .warn,
            .rule = rule.name,
            .message = "this event's payload and blocking behaviour are UNVERIFIED upstream; the rule is supported but its bindings are inference, so confirm it fires before relying on it",
        });
    }
}

/// Cap on the axes one generator may declare, matching the harness's own
/// bound. Eight axes over even two values each is 256 cases from one
/// declaration; more than that is a suite nobody reads.
pub const MAX_GEN_AXES = 8;

/// Check one `generate` declaration. Every finding here is about a generator
/// that expands to fewer cases than it looks like it does — the one failure mode
/// that would let a rule stop being tested while the suite still says OK.
fn lintGenerator(
    allocator: std.mem.Allocator,
    found: *std.ArrayList(Finding),
    case: *const rules.RuleTest,
    gen: rules.Generator,
    index: usize,
) !void {
    if (case.command != null or case.input.command.len > 0 or
        case.input.file_path.len > 0 or case.input.content.len > 0)
    {
        try found.append(allocator, .{
            .level = .@"error",
            .test_index = index,
            .message = "test carries both a generate block and a literal input; write one or the other, since only the generated cases would run",
        });
    }
    if (gen.command.len == 0) {
        try found.append(allocator, .{
            .level = .@"error",
            .test_index = index,
            .message = "generate block has an empty command template; there is nothing to expand",
        });
    }
    if (gen.axes.len == 0) {
        try found.append(allocator, .{
            .level = .@"error",
            .test_index = index,
            .message = "generate block declares no axes; the product is empty and the case asserts nothing",
        });
    }
    if (gen.axes.len > MAX_GEN_AXES) {
        try found.append(allocator, .{
            .level = .@"error",
            .test_index = index,
            .message = "generate block declares more axes than the harness expands; split it into two declarations",
        });
    }
    for (gen.axes) |axis| {
        if (axis.values.len == 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .test_index = index,
                .message = "generate axis has no values; the whole product collapses to nothing and every case it should have run silently disappears",
            });
        }
        if (!templateNames(gen.command, axis.name)) {
            try found.append(allocator, .{
                .level = .@"error",
                .test_index = index,
                .message = "generate axis does not appear in the command template as {name}; its values would never be substituted",
            });
        }
    }
    // Every placeholder must name an axis, or the generated command carries a
    // literal `{...}` and asserts something nobody wrote.
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, gen.command, i, '{')) |open| {
        const close = std.mem.indexOfScalarPos(u8, gen.command, open, '}') orelse break;
        const name = gen.command[open + 1 .. close];
        if (gen.axisNamed(name) == null) {
            try found.append(allocator, .{
                .level = .@"error",
                .test_index = index,
                .message = "command template names a placeholder with no matching axis; it would be left in the generated command verbatim",
            });
        }
        i = close + 1;
    }
    for (gen.near_miss) |miss| {
        if (gen.axisNamed(miss.name) == null) {
            try found.append(allocator, .{
                .level = .@"error",
                .test_index = index,
                .message = "near_miss names an axis the generator does not declare; those negatives would never be generated",
            });
        }
        if (miss.values.len == 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .test_index = index,
                .message = "near_miss axis has no values; it generates no negatives",
            });
        }
    }
    if (gen.near_miss.len == 0 and case.expect != .none) {
        try found.append(allocator, .{
            .level = .warn,
            .test_index = index,
            .message = "generate block declares no near_miss negatives; a product of positives shows only that the rule fires, not that it reads the axis it claims to — a rule matching everything would pass it",
        });
    }
}

fn templateNames(template: []const u8, name: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, template, i, '{')) |open| {
        const close = std.mem.indexOfScalarPos(u8, template, open, '}') orelse return false;
        if (eq(template[open + 1 .. close], name)) return true;
        i = close + 1;
    }
    return false;
}

/// Check one matcher list, descending into groups. `depth` counts the groups
/// already entered, matching `rules.nodeHit` exactly — a group this reports as
/// too deep is a group evaluation refuses to satisfy, so the operator hears
/// about it from the lint instead of from a rule that stopped firing.
///
/// `scoped` says whether an enclosing `invocation` group has bound the entries
/// to one stage, which changes what some of them MEAN — a `signal` is not
/// narrowed by the binding, and a short `flag` outside one is asking about a
/// letter with no program attached.
fn lintMatchers(
    allocator: std.mem.Allocator,
    found: *std.ArrayList(Finding),
    rule_name: []const u8,
    descriptor: *const rules.Events.Descriptor,
    list: []const rules.Matcher,
    depth: u8,
    scoped: bool,
) !void {
    for (list) |entry| {
        const g = entry.group() orelse {
            try lintLeaf(allocator, found, rule_name, descriptor, entry, scoped);
            continue;
        };
        if (entry.groupOpCount() > 1) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "group entry names more than one of any/all/none/invocation; split it into nested groups so the intended shape is the one that runs",
            });
        }
        if (std.mem.trim(u8, entry.value, " \t\r\n").len != 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "group entry also carries a matcher value; an entry is either a group or a matcher, and the value here is ignored",
            });
        }
        if (g.items.len == 0) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "empty group; an empty any/all/none/invocation is never satisfied, so the rule it sits in can never fire",
            });
            continue;
        }
        if (depth >= rules.MAX_GROUP_DEPTH) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "group nested too deeply; evaluation stops at MAX_GROUP_DEPTH and treats anything below it as unsatisfied",
            });
            continue;
        }
        if (g.op == .invocation and scoped) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = rule_name,
                .message = "invocation group inside another invocation group; the inner one cannot name a different invocation and evaluates as a plain all",
            });
        }
        try lintMatchers(allocator, found, rule_name, descriptor, g.items, depth + 1, scoped or g.op == .invocation);
    }
}

fn lintLeaf(
    allocator: std.mem.Allocator,
    found: *std.ArrayList(Finding),
    rule_name: []const u8,
    descriptor: *const rules.Events.Descriptor,
    matcher: rules.Matcher,
    scoped: bool,
) !void {
    if (std.mem.trim(u8, matcher.value, " \t\r\n").len == 0) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "matcher with an empty value; an empty pattern never matches",
        });
    } else if (hasBareStar(matcher)) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "matcher pattern \"*\" matches nothing; the only wildcard is a trailing * on a prefix",
        });
    }
    // A structural kind reads the parsed command; there is no command model
    // behind a file body, a path, a prompt, a tool result or a notification
    // type, so on any other field it can never match. That has to be an error
    // rather than a silent never-match: a rule that reads like protection and
    // provides none is worse than no rule. It is also the one lint that gets
    // MORE important as events multiply — `command_word` on a `prompt` looks
    // entirely reasonable and is a shell parser pointed at English.
    if (matcher.kind.isStructural() and matcher.field != .command) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "structural matcher kind on a non-command field; command_word, argv, command_line, flag, flags, path_class, signal, stage and shape parse a SHELL COMMAND, and there is no command behind content, file_path, prompt, output, message, trigger or agent. Use word/substring/tokens on those",
        });
    }
    // A matcher reading a field this event's payload does not supply. Purely a
    // table lookup, and the most valuable check in the file: it is what makes a
    // rule scoped to the wrong event a build failure instead of a rule nobody
    // notices has stopped mattering.
    if (!descriptor.carries(matcher.field) and !descriptor.hasNoMatchableField()) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "matcher reads a field this event's payload does not carry, so it can never match; the per-event reference table lists which fields each event supplies",
        });
    }
    if (matcher.kind == .signal and rules.SignalName.from(matcher.value) == null) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "unknown signal name; the vocabulary is eval_present, command_substitution, pipe_into_shell, decode_into_shell, heredoc_present, herestring_present, unterminated_quote, expansion_command_word, concatenated_command_word, unresolved_command_word, substitution_derived, opaque_command",
        });
    }
    // A `stage` value names one fact about an invocation's context. Closed
    // vocabulary, same treatment as `signal`: a typo must be an error, never a
    // matcher that quietly never fires.
    if (matcher.kind == .stage and rules.StageName.from(matcher.value) == null) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "unknown stage predicate; the vocabulary is pipe_target, pipe_source, nested, remote",
        });
    }
    // A `shape` value is a three-token comparison and nothing else.
    if (matcher.kind == .shape and rules.ShapeSpec.parse(matcher.value) == null) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "shape value is not `<metric> <op> <n>`; metrics are pipes, statements, chains, stages, redirects, heredocs, depth, and the operator is one of < <= == >= > (e.g. \"pipes > 1\")",
        });
    }
    // `signal` and `shape` describe the whole parse. Inside an invocation
    // group they still evaluate — as ordinary conjuncts — but the binding
    // does NOT narrow them to the bound stage, and reading them as scoped is
    // a mistake about what they mean.
    if (scoped and (matcher.kind == .signal or matcher.kind == .shape)) {
        try found.append(allocator, .{
            .level = .warn,
            .rule = rule_name,
            .message = "signal/shape matcher inside an invocation group is not narrowed by it; it describes the WHOLE command and evaluates as an ordinary conjunct — put it beside the group in match_all if that is what you meant",
        });
    }
    // A `flag` value names an option. Anything that is not a plausible one —
    // `-`, `--`, a path, a phrase — parses to nothing and matches nothing, so
    // it is a dead matcher rather than a loose one.
    if (matcher.kind == .flag) {
        if (rules.FlagPattern.parse(matcher.value) == null) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "flag value is not a plausible option; write short letters (\"f\", \"-f\", \"rf\") or a long option (\"--force\"), and nothing else",
            });
        } else if (!scoped and rules.FlagPattern.parse(matcher.value).? == .short) {
            // `-f` means force to `rm`, file to `tar`, and follow to `tail`.
            // Unscoped, a short flag asks about a letter with no program
            // attached, and a single-dash long option (`find -name`) reads
            // as a bundle carrying every letter in it.
            try found.append(allocator, .{
                .level = .warn,
                .rule = rule_name,
                .message = "short flag matcher outside an invocation group; a bare letter means different things to different programs, so scope it with {\"invocation\": [...]} naming the command word",
            });
        }
    }
    // A `flags` value is a list of option-name entries, each a `|` alternation.
    // The same scoping warning applies for the same reason.
    if (matcher.kind == .flags) {
        if (!rules.FlagsPattern.valid(matcher.value)) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "flags value is not an option set; write entries separated by spaces or commas, each entry one or more alternatives separated by | (\"r|R|--recursive f|--force\"), and nothing else",
            });
        } else if (!scoped and !rules.FlagsPattern.allLong(matcher.value)) {
            try found.append(allocator, .{
                .level = .warn,
                .rule = rule_name,
                .message = "short flags matcher outside an invocation group; a bare letter means different things to different programs, so scope it with {\"invocation\": [...]} naming the command word",
            });
        }
    }
    // A `path_class` value names one of the engine's PATH classes. An unknown
    // name — or a class of the wrong kind — can never match, and
    // `claude-hooker-gate classes` prints every valid one.
    if (matcher.kind == .path_class) {
        const class = rules.Classes.find(matcher.value);
        if (class == null or class.?.kind != .path) {
            try found.append(allocator, .{
                .level = .@"error",
                .rule = rule_name,
                .message = "path_class value is not a built-in path class; run `claude-hooker-gate classes` for the list (home_or_root, filesystem_anchor), and reference a command or phrase class as \"$class:<name>\" on command_word/argv instead",
            });
        }
    }
    // Case folding is opt-in per matcher and only some kinds honor it.
    // Setting it elsewhere reads like policy and does nothing.
    if (matcher.ignore_case and !matcher.kind.honorsIgnoreCase()) {
        try found.append(allocator, .{
            .level = .@"error",
            .rule = rule_name,
            .message = "ignore_case on a kind that does not honor it; command_word compares a program name (a filename, where case is identity), flag compares option letters (-r is not -R), and signal, stage and shape compare closed vocabularies",
        });
    }
}

/// Can this list produce a hit to report? A leaf can; an `any`/`all`/
/// `invocation` group can when some item can; a `none` group never can,
/// because "nothing matched" has no bytes behind it.
fn canYieldEvidence(list: []const rules.Matcher) bool {
    for (list) |entry| {
        const g = entry.group() orelse return true;
        switch (g.op) {
            .any, .all, .invocation => if (canYieldEvidence(g.items)) return true,
            .none => {},
        }
    }
    return false;
}

pub fn countErrors(findings: []const Finding) usize {
    var n: usize = 0;
    for (findings) |f| {
        if (f.level == .@"error") n += 1;
    }
    return n;
}

fn findRule(rule_set: rules.RuleSet, name: []const u8) ?*const rules.Rule {
    for (rule_set.rules) |*rule| {
        if (eq(rule.name, name)) return rule;
    }
    return null;
}

/// A `*` that is a whole pattern (or a whole token of a `tokens` pattern):
/// the matcher deliberately refuses it, so it is a silent dead rule. The
/// structural kinds inherit the same refusal from the same primitives —
/// `command_line` runs a token pattern, `command_word`/`argv` a single one —
/// so they are linted the same way. `signal` and `flag` have their own
/// shape checks (a closed vocabulary, and a plausible option spelling)
/// instead.
fn hasBareStar(matcher: rules.Matcher) bool {
    switch (matcher.kind) {
        .tokens, .command_line => {
            var it = std.mem.tokenizeAny(u8, matcher.value, " \t\r\n");
            while (it.next()) |token| {
                if (eq(token, "*")) return true;
            }
            return false;
        },
        .word, .substring, .command_word, .argv => return eq(matcher.value, "*"),
        .flag, .flags, .path_class, .signal, .stage, .shape => return false,
    }
}

// ---------------------------------------------------------------------------
// selftest: reporting
// ---------------------------------------------------------------------------

pub fn writeSelftestReport(
    w: *std.Io.Writer,
    rules_path: ?[]const u8,
    suite: *const Suite,
    findings: []const Finding,
) !u8 {
    if (rules_path) |path| try w.print("rules    : {s}\n", .{path});

    var label_buf: [256]u8 = undefined;
    for (suite.results) |result| {
        try w.print("{s}  #{d:<4} {s}: {s}", .{
            if (result.ok) "PASS" else "FAIL",
            result.index,
            caseSubject(result.input),
            caseLabel(&label_buf, result.input, 56),
        });
        // A generated case names the declaration it came from, so a failure
        // points at the `generate` block to fix rather than at a command that
        // appears nowhere in the file.
        if (result.source == .generated) try w.print("  [generated from #{d}]", .{result.origin});
        try w.writeByte('\n');
        if (!result.ok) {
            try w.print("          expected {s}", .{@tagName(result.expect)});
            if (result.expect_rule) |name| try w.print(" ({s})", .{name});
            try w.print(", got {s}", .{result.gotWord()});
            if (result.got_rule) |name| try w.print(" ({s})", .{name});
            try w.writeByte('\n');
        }
    }
    if (suite.total() == 0) try w.print("(no test cases in this rule file)\n", .{});

    for (findings) |finding| {
        try w.print("{s: <5} ", .{@tagName(finding.level)});
        if (finding.test_index) |index| try w.print("test #{d}: ", .{index});
        if (finding.rule) |name| try w.print("{s}: ", .{name});
        try w.print("{s}\n", .{finding.message});
    }

    const errors = countErrors(findings);
    const ok = suite.allPassed() and errors == 0;
    // The split is the point: a literal case pins a specific past mistake, a
    // generated one covers a space no list of literals could. A count that
    // merged them would hide a generator quietly expanding to nothing.
    try w.print("result   : {d} literal + {d} generated cases passed", .{
        suite.literal.passed,
        suite.generated.passed,
    });
    if (!suite.allPassed()) {
        try w.print(" ({d} of {d} FAILED)", .{ suite.total() - suite.passed(), suite.total() });
    }
    try w.print(", {d} lint error(s), {d} warning(s) -> {s}\n", .{
        errors,
        findings.len - errors,
        if (ok) "OK" else "FAIL",
    });
    return if (ok) 0 else 1;
}

const JsonCase = struct {
    index: usize,
    /// Which hook event the case exercises. Always present, so a consumer can
    /// group a suite by event without inferring one from the fields.
    event: []const u8,
    tool: []const u8,
    command: []const u8,
    file_path: []const u8,
    expect: []const u8,
    expect_rule: ?[]const u8,
    got: []const u8,
    got_rule: ?[]const u8,
    ok: bool,
    source: []const u8,
    origin: usize,
};

const JsonCounts = struct {
    total: usize,
    passed: usize,
};

const JsonFinding = struct {
    level: []const u8,
    rule: ?[]const u8,
    test_index: ?usize,
    message: []const u8,
};

const JsonSelftest = struct {
    rules_path: ?[]const u8,
    ok: bool,
    literal: JsonCounts,
    generated: JsonCounts,
    tests: []const JsonCase,
    lint: []const JsonFinding,
};

pub fn writeSelftestJson(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    rules_path: ?[]const u8,
    suite: *const Suite,
    findings: []const Finding,
) !u8 {
    const results = suite.results;
    const cases = try allocator.alloc(JsonCase, results.len);
    defer allocator.free(cases);
    for (results, 0..) |result, i| {
        cases[i] = .{
            .index = result.index,
            .event = result.input.event.name(),
            .tool = result.input.tool,
            .command = result.input.command,
            .file_path = result.input.file_path,
            .expect = @tagName(result.expect),
            .expect_rule = result.expect_rule,
            .got = result.gotWord(),
            .got_rule = result.got_rule,
            .ok = result.ok,
            .source = @tagName(result.source),
            .origin = result.origin,
        };
    }

    const lint_out = try allocator.alloc(JsonFinding, findings.len);
    defer allocator.free(lint_out);
    for (findings, 0..) |finding, i| {
        lint_out[i] = .{
            .level = @tagName(finding.level),
            .rule = finding.rule,
            .test_index = finding.test_index,
            .message = finding.message,
        };
    }

    const errors = countErrors(findings);
    const ok = suite.allPassed() and errors == 0;
    try std.json.Stringify.value(JsonSelftest{
        .rules_path = rules_path,
        .ok = ok,
        .literal = .{ .total = suite.literal.total, .passed = suite.literal.passed },
        .generated = .{ .total = suite.generated.total, .passed = suite.generated.passed },
        .tests = cases,
        .lint = lint_out,
    }, .{ .emit_null_optional_fields = false }, w);
    try w.writeByte('\n');
    return if (ok) 0 else 1;
}

// ---------------------------------------------------------------------------
// classes
// ---------------------------------------------------------------------------

/// Print the built-in classes and their members.
///
/// The classes are engine knowledge — they ship with the binary, and a rule that
/// names one inherits whatever this version thinks the members are. That is the
/// trade for not enumerating: the list moves without the rule file changing. So
/// the list must never be hidden knowledge, and this is the subcommand that
/// makes it printable, diffable, and pasteable into a review.
///
/// A `path` class prints its members too, but they are labelled: membership is
/// decided by NORMALIZING the argument, so `~/../` and `/usr/local/../..` are
/// members no list contains, and the printed spellings are the canonical ones
/// (which is also where the test generators draw their values).
pub fn writeClasses(w: *std.Io.Writer, only: ?[]const u8, width: usize) !u8 {
    var printed: usize = 0;
    for (&rules.Classes.all) |*class| {
        if (only) |want| {
            if (!eq(want, class.name)) continue;
        }
        printed += 1;
        try w.print("{s}  ({s})\n", .{ class.name, @tagName(class.kind) });
        try writeWrapped(w, "  ", class.about, width);
        switch (class.kind) {
            .command => try w.print("  reference as: {{\"kind\": \"command_word\", \"value\": \"$class:{s}\"}}\n", .{class.name}),
            .phrase => try w.print("  reference as: {{\"kind\": \"argv\", \"value\": \"$class:{s}\", \"ignore_case\": true}}\n", .{class.name}),
            .path => {
                try w.print("  reference as: {{\"kind\": \"path_class\", \"value\": \"{s}\"}}\n", .{class.name});
                try writeWrapped(
                    w,
                    "  ",
                    "membership is decided by normalizing the argument, not by comparing it; the spellings below are the canonical ones and what the test generators expand",
                    width,
                );
            },
        }
        try w.print("  members ({d}):\n", .{class.members.len});
        for (class.members) |m| try w.print("    {s}\n", .{m});
        try w.writeByte('\n');
    }
    if (printed == 0) {
        try w.print("{s}: no such class", .{PROGRAM});
        if (only) |want| try w.print(" \"{s}\"", .{want});
        try w.writeByte('\n');
        try w.writeAll("known classes:");
        for (&rules.Classes.all) |*class| try w.print(" {s}", .{class.name});
        try w.writeByte('\n');
        return EX_USAGE;
    }
    return 0;
}

const JsonClass = struct {
    name: []const u8,
    kind: []const u8,
    about: []const u8,
    members: []const []const u8,
};

pub fn writeClassesJson(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    only: ?[]const u8,
) !u8 {
    var list: std.ArrayList(JsonClass) = .empty;
    defer list.deinit(allocator);
    for (&rules.Classes.all) |*class| {
        if (only) |want| {
            if (!eq(want, class.name)) continue;
        }
        try list.append(allocator, .{
            .name = class.name,
            .kind = @tagName(class.kind),
            .about = class.about,
            .members = class.members,
        });
    }
    try std.json.Stringify.value(
        .{ .version = VERSION, .classes = list.items },
        .{ .emit_null_optional_fields = false },
        w,
    );
    try w.writeByte('\n');
    return if (list.items.len == 0) EX_USAGE else 0;
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

/// Print the event catalog: what each hook event carries, what it can refuse,
/// and how.
///
/// The same argument as `classes`, one level up. Which events exist, which
/// fields each one supplies, and which decisions each one can express are ENGINE
/// knowledge — a rule that names an event inherits whatever this version's
/// descriptor table says. That has to be printable, diffable and pasteable into
/// a review, or an operator writing a rule for `Stop` is guessing. It is also
/// what the README's per-event reference table is checked against, so the docs
/// cannot drift from the table by more than one failing audit check.
pub fn writeEvents(w: *std.Io.Writer, only: ?[]const u8, width: usize) !u8 {
    var printed: usize = 0;
    for (rules.Events.all()) |*d| {
        if (only) |want| {
            if (!eq(want, d.name())) continue;
        }
        printed += 1;
        try w.print("{s}\n", .{d.name()});
        try writeWrapped(w, "  ", d.timing, width);
        try w.print("  blocks     : ", .{});
        if (d.isAdvisory()) {
            try w.writeAll("NO — advisory only; deny/ask/allow are silently ignored, use \"log\"\n");
        } else {
            try w.print("{s}{s}\n", .{
                d.block.wireField(),
                if (d.feedback_only) " (feedback only — the thing already happened)" else "",
            });
        }
        try w.print("  decisions  : {s}\n", .{d.vocabulary().describe()});
        try w.print("  matcher    : {s}{s}\n", .{
            @tagName(d.matcher),
            if (d.matcher.isRegex()) " (regex)" else if (d.matcher == .none) "" else " (exact, never a regex)",
        });
        try w.print("  tool field : {s}\n", .{if (d.has_tool) "yes" else "no — a \"tool\" other than \"*\" can never match"});
        if (d.bindings.len == 0) {
            try w.writeAll("  fields     : none documented — no rule can be written for this event yet\n");
        } else {
            try w.writeAll("  fields     :");
            for (d.bindings, 0..) |b, i| {
                try w.print("{s} {s} <- {s}", .{
                    if (i == 0) "" else ",",
                    @tagName(b.field),
                    b.source.path(),
                });
            }
            try w.writeByte('\n');
        }
        if (d.context.len > 0) try w.print("  context    : {s} (not written by this gate)\n", .{d.context});
        if (d.rewrite.len > 0) try w.print("  rewrite    : {s} (not written by this gate)\n", .{d.rewrite});
        if (!d.verified) {
            try writeWrapped(w, "  ", "UNVERIFIED: this row's payload and blocking behaviour are inference from thin documentation; a rule scoped here is a lint warning", width);
        }
        try w.writeByte('\n');
    }
    if (printed == 0) {
        try w.print("{s}: no such event", .{PROGRAM});
        if (only) |want| try w.print(" \"{s}\"", .{want});
        try w.writeByte('\n');
        try w.writeAll("known events:");
        for (rules.Events.all()) |*d| try w.print(" {s}", .{d.name()});
        try w.writeByte('\n');
        return EX_USAGE;
    }
    return 0;
}

/// The event catalog as the exact markdown table the README quotes.
///
/// Rendered by the binary rather than maintained by hand, and compared BYTE FOR
/// BYTE against the README by `hookctl audit` — the same treatment
/// `./hookctl help` gets, and for the same reason. A thirty-row table of
/// event-specific protocol facts is precisely the documentation that rots: every
/// cell is a claim about the code, none of them is obviously wrong when it goes
/// stale, and the cost of a stale cell is an operator writing a rule that cannot
/// fire. So the table is generated, and the README's copy of it is an assertion.
pub fn writeEventsMarkdown(w: *std.Io.Writer) !u8 {
    try w.writeAll("| Event | When it fires | Refusal | Decisions | Matcher | Payload fields |\n");
    try w.writeAll("| ----- | ------------- | ------- | --------- | ------- | -------------- |\n");
    for (rules.Events.all()) |*d| {
        try w.print("| `{s}`{s} | {s} | ", .{
            d.name(),
            if (d.verified) "" else " ⚠",
            d.timing,
        });
        if (d.isAdvisory()) {
            try w.writeAll("— advisory");
        } else {
            try w.print("`{s}`{s}", .{
                d.block.wireField(),
                if (d.feedback_only) " (feedback only)" else "",
            });
        }
        try w.print(" | {s} | {s} | ", .{ d.vocabulary().describe(), @tagName(d.matcher) });
        if (d.bindings.len == 0) {
            try w.writeAll("—");
        } else {
            for (d.bindings, 0..) |b, i| {
                if (i > 0) try w.writeAll(", ");
                try w.print("`{s}` ← `{s}`", .{ @tagName(b.field), b.source.path() });
            }
        }
        try w.writeAll(" |\n");
    }
    return 0;
}

const JsonBinding = struct {
    field: []const u8,
    path: []const u8,
};

/// One descriptor row, on the wire. This is the shape the README's per-event
/// table is checked against — see `docs.check_event_table`.
const JsonEvent = struct {
    event: []const u8,
    advisory: bool,
    mechanism: []const u8,
    wire_field: []const u8,
    feedback_only: bool,
    decisions: []const u8,
    matcher: []const u8,
    matcher_is_regex: bool,
    has_tool: bool,
    fields: []const JsonBinding,
    context: []const u8,
    rewrite: []const u8,
    verified: bool,
    block_exit: u8,
    timing: []const u8,
};

pub fn writeEventsJson(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    only: ?[]const u8,
) !u8 {
    var list: std.ArrayList(JsonEvent) = .empty;
    defer list.deinit(allocator);
    for (rules.Events.all()) |*d| {
        if (only) |want| {
            if (!eq(want, d.name())) continue;
        }
        const bindings = try allocator.alloc(JsonBinding, d.bindings.len);
        for (d.bindings, bindings) |b, *out| {
            out.* = .{ .field = @tagName(b.field), .path = b.source.path() };
        }
        try list.append(allocator, .{
            .event = d.name(),
            .advisory = d.isAdvisory(),
            .mechanism = @tagName(d.block),
            .wire_field = d.block.wireField(),
            .feedback_only = d.feedback_only,
            .decisions = d.vocabulary().describe(),
            .matcher = @tagName(d.matcher),
            .matcher_is_regex = d.matcher.isRegex(),
            .has_tool = d.has_tool,
            .fields = bindings,
            .context = d.context,
            .rewrite = d.rewrite,
            .verified = d.verified,
            .block_exit = d.block_exit,
            .timing = d.timing,
        });
    }
    try std.json.Stringify.value(
        .{ .version = VERSION, .schema_version = SCHEMA_TEXT, .events = list.items },
        .{ .emit_null_optional_fields = false },
        w,
    );
    try w.writeByte('\n');
    return if (list.items.len == 0) EX_USAGE else 0;
}

/// The rule-file schema this build speaks, as text, for the JSON outputs that
/// report it. Rendered once at comptime so no caller needs a buffer.
pub const SCHEMA_TEXT = std.fmt.comptimePrint("{d}.{d}", .{
    rules.SCHEMA_VERSION.major,
    rules.SCHEMA_VERSION.minor,
});

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

/// One rule's row. Enforced decisions are counted separately from shadow and
/// bypassed hits: "fired 400 times, all of them shadow" and "fired 400 times,
/// all of them denials" are opposite facts about a rule.
pub const RuleStat = struct {
    rule: []const u8,
    /// The hook event the lines for this rule carried. A rule is scoped to
    /// exactly one event, so this is a property of the row rather than another
    /// axis to group by — and a log line that named no event is read as
    /// `PreToolUse`, which is what every line written before events existed was.
    event: []const u8 = "PreToolUse",
    total: usize = 0,
    deny: usize = 0,
    ask: usize = 0,
    allow: usize = 0,
    shadow: usize = 0,
    bypassed: usize = 0,
    /// Decisions this build does not know about; a forward-compatibility
    /// bucket rather than a reason to call the line malformed.
    other: usize = 0,
    last_ts: i64 = 0,
};

/// One hook event's share of the log: which events a policy is actually
/// working on, as opposed to which ones it has rules for.
///
/// Worth its own roll-up because the per-rule table cannot answer it. Thirty
/// events are wireable and a busy install may have rules on six of them; "the
/// `Stop` rules have never fired once" and "the `PostToolUse` observation is
/// carrying the whole log" are both facts about the policy's shape that no
/// single rule row shows.
pub const EventStat = struct {
    event: []const u8,
    total: usize = 0,
    enforced: usize = 0,
    shadow: usize = 0,
    bypassed: usize = 0,
    rules: usize = 0,
    last_ts: i64 = 0,
};

pub const StatsResult = struct {
    rules: []RuleStat,
    /// Per-event totals, busiest first. Derived from `rules`, so the two can
    /// never disagree about how many hits there were.
    events: []EventStat = &.{},
    /// Non-blank lines seen.
    lines: usize = 0,
    /// Lines that parsed and were counted.
    counted: usize = 0,
    /// Lines that did not parse, or carried no rule name.
    skipped: usize = 0,
    /// Lines dropped by `--since`.
    filtered: usize = 0,

    pub fn deinit(self: *StatsResult, allocator: std.mem.Allocator) void {
        for (self.rules) |stat| allocator.free(stat.rule);
        allocator.free(self.rules);
        allocator.free(self.events);
        self.rules = &.{};
        self.events = &.{};
    }
};

/// Only the fields the summary needs. Unknown keys are ignored, so a log
/// written by a newer gate still aggregates.
const LogLine = struct {
    ts_unix: i64 = 0,
    rule: []const u8 = "",
    decision: []const u8 = "",
    /// Absent on every line written before rules were scoped to events, and
    /// those lines were all `PreToolUse` — so the default is not a guess.
    event: []const u8 = "PreToolUse",
};

/// Fold a JSONL decision log into per-rule rows, newest-first by total.
///
/// A malformed line is counted and stepped over rather than fatal: the log is
/// appended to by concurrent short-lived processes and truncated by whatever
/// retention the operator runs, and a summary that refuses to print because of
/// one torn line is a summary nobody can use.
pub fn aggregate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    cutoff_unix: ?i64,
) !StatsResult {
    var stats: std.ArrayList(RuleStat) = .empty;
    errdefer {
        for (stats.items) |stat| allocator.free(stat.rule);
        stats.deinit(allocator);
    }

    var out = StatsResult{ .rules = &.{} };
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        out.lines += 1;

        var parsed = std.json.parseFromSlice(LogLine, allocator, line, .{
            .ignore_unknown_fields = true,
        }) catch {
            out.skipped += 1;
            continue;
        };
        defer parsed.deinit();
        const entry = parsed.value;
        if (entry.rule.len == 0) {
            out.skipped += 1;
            continue;
        }
        if (cutoff_unix) |cutoff| {
            if (entry.ts_unix < cutoff) {
                out.filtered += 1;
                continue;
            }
        }
        out.counted += 1;

        const stat = blk: {
            for (stats.items) |*existing| {
                if (eq(existing.rule, entry.rule)) break :blk existing;
            }
            try stats.append(allocator, .{
                .rule = try allocator.dupe(u8, entry.rule),
                // Borrowed from the LINE, which is about to be freed — so this
                // is normalized to the catalog's own static spelling, and an
                // event name a newer gate wrote is reported as unknown rather
                // than as a dangling slice.
                .event = eventName(entry.event),
            });
            break :blk &stats.items[stats.items.len - 1];
        };
        stat.total += 1;
        if (entry.ts_unix > stat.last_ts) stat.last_ts = entry.ts_unix;
        if (eq(entry.decision, "deny")) {
            stat.deny += 1;
        } else if (eq(entry.decision, "ask")) {
            stat.ask += 1;
        } else if (eq(entry.decision, "allow")) {
            stat.allow += 1;
        } else if (eq(entry.decision, "log")) {
            stat.shadow += 1;
        } else if (eq(entry.decision, "bypassed")) {
            stat.bypassed += 1;
        } else {
            stat.other += 1;
        }
    }

    out.rules = try stats.toOwnedSlice(allocator);
    std.mem.sort(RuleStat, out.rules, {}, byTotalDesc);
    out.events = try rollUpEvents(allocator, out.rules);
    return out;
}

/// The static name of a logged event, or a fixed marker for one this build has
/// never heard of.
///
/// Static on purpose: a `RuleStat` outlives the log line it was built from, and
/// the catalog's `@tagName` has program lifetime. A log written by a newer gate
/// therefore aggregates — it does not dangle, and it does not get counted as
/// `PreToolUse` either, which would be a quiet lie about which event a policy is
/// working on.
fn eventName(text: []const u8) []const u8 {
    const found = rules.Event.from(text) orelse return "(unknown event)";
    return found.name();
}

/// Fold the per-rule rows into per-event totals. Derived rather than counted a
/// second time during the scan, so the two views cannot disagree.
fn rollUpEvents(allocator: std.mem.Allocator, rows: []const RuleStat) ![]EventStat {
    var out: std.ArrayList(EventStat) = .empty;
    errdefer out.deinit(allocator);
    for (rows) |row| {
        const slot = blk: {
            for (out.items) |*existing| {
                if (eq(existing.event, row.event)) break :blk existing;
            }
            try out.append(allocator, .{ .event = row.event });
            break :blk &out.items[out.items.len - 1];
        };
        slot.rules += 1;
        slot.total += row.total;
        slot.enforced += row.deny + row.ask + row.allow;
        slot.shadow += row.shadow;
        slot.bypassed += row.bypassed;
        if (row.last_ts > slot.last_ts) slot.last_ts = row.last_ts;
    }
    const events_slice = try out.toOwnedSlice(allocator);
    std.mem.sort(EventStat, events_slice, {}, byEventTotalDesc);
    return events_slice;
}

fn byEventTotalDesc(_: void, a: EventStat, b: EventStat) bool {
    if (a.total != b.total) return a.total > b.total;
    return std.mem.order(u8, a.event, b.event) == .lt;
}

/// Concatenate log generations into one buffer, oldest first.
///
/// A newline is inserted at every seam that does not already have one. A log
/// generation can end mid-line — the last append before rotation may have been
/// torn by a crash, and the file is truncated by whatever retention the
/// operator runs — and fusing that partial line onto the first line of the next
/// generation would turn one malformed line into two. Empty parts contribute
/// nothing, so a missing generation costs no separator.
pub fn joinLogs(allocator: std.mem.Allocator, parts: []const []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (parts) |part| {
        if (part.len == 0) continue;
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.append(allocator, '\n');
        try out.appendSlice(allocator, part);
    }
    return out.toOwnedSlice(allocator);
}

/// Busiest first, then by name so the table is stable between runs.
fn byTotalDesc(_: void, a: RuleStat, b: RuleStat) bool {
    if (a.total != b.total) return a.total > b.total;
    return std.mem.order(u8, a.rule, b.rule) == .lt;
}

/// A coarse age: exact seconds stop being useful the moment they exceed a
/// minute, and the question this answers is "is this rule still live?".
pub fn humanizeAge(buf: []u8, age_seconds: i64) []const u8 {
    if (age_seconds < 0) return "in the future";
    const minute = 60;
    const hour = 60 * minute;
    const day = 24 * hour;
    if (age_seconds < minute) return std.fmt.bufPrint(buf, "{d}s ago", .{age_seconds}) catch "?";
    if (age_seconds < hour) return std.fmt.bufPrint(buf, "{d}m ago", .{@divTrunc(age_seconds, minute)}) catch "?";
    if (age_seconds < day) return std.fmt.bufPrint(buf, "{d}h ago", .{@divTrunc(age_seconds, hour)}) catch "?";
    return std.fmt.bufPrint(buf, "{d}d ago", .{@divTrunc(age_seconds, day)}) catch "?";
}

const NAME_COLUMN_MIN = 12;
const NAME_COLUMN_MAX = 40;
/// Wide enough that the longest header ("bypassed") keeps a space in front of
/// it, so the columns read as columns without a separator character.
const COUNT_COLUMN = 9;

fn writeLeftCell(w: *std.Io.Writer, text: []const u8, width: usize) !void {
    var buf: [256]u8 = undefined;
    const shown = ellipsize(&buf, text, width);
    try w.writeAll(shown);
    try pad(w, width -| displayWidth(shown));
}

fn writeCountCell(w: *std.Io.Writer, value: usize) !void {
    var buf: [24]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}", .{value}) catch "?";
    try pad(w, COUNT_COLUMN -| text.len);
    try w.writeAll(text);
}

fn writeHeadCell(w: *std.Io.Writer, text: []const u8) !void {
    try pad(w, COUNT_COLUMN -| text.len);
    try w.writeAll(text);
}

/// The aligned table. `now` is a parameter so the rendering is a pure function
/// and the "last hit" column is testable.
pub fn writeTable(w: *std.Io.Writer, result: StatsResult, now_unix: i64) !void {
    if (result.rules.len == 0) {
        try w.print("no entries match.\n", .{});
    } else {
        var name_width: usize = NAME_COLUMN_MIN;
        for (result.rules) |stat| name_width = @max(name_width, displayWidth(stat.rule));
        name_width = @min(name_width, NAME_COLUMN_MAX);

        try writeLeftCell(w, "rule", name_width);
        inline for (.{ "total", "deny", "ask", "allow", "shadow", "bypassed" }) |head| {
            try writeHeadCell(w, head);
        }
        try w.print("   last hit\n", .{});

        var age_buf: [32]u8 = undefined;
        for (result.rules) |stat| {
            try writeLeftCell(w, stat.rule, name_width);
            try writeCountCell(w, stat.total);
            try writeCountCell(w, stat.deny);
            try writeCountCell(w, stat.ask);
            try writeCountCell(w, stat.allow);
            try writeCountCell(w, stat.shadow);
            try writeCountCell(w, stat.bypassed);
            try w.print("   {s}\n", .{humanizeAge(&age_buf, now_unix - stat.last_ts)});
        }

        // The same hits, grouped by the hook event that produced them. Printed
        // only when there is more than one event in play: on a single-event
        // install it would restate the line above it, and a summary that pads
        // itself is a summary people stop reading.
        if (result.events.len > 1) {
            try w.writeByte('\n');
            try writeLeftCell(w, "event", name_width);
            inline for (.{ "total", "enforced", "shadow", "bypassed", "rules" }) |head| {
                try writeHeadCell(w, head);
            }
            try w.print("   last hit\n", .{});
            for (result.events) |ev| {
                try writeLeftCell(w, ev.event, name_width);
                try writeCountCell(w, ev.total);
                try writeCountCell(w, ev.enforced);
                try writeCountCell(w, ev.shadow);
                try writeCountCell(w, ev.bypassed);
                try writeCountCell(w, ev.rules);
                try w.print("   {s}\n", .{humanizeAge(&age_buf, now_unix - ev.last_ts)});
            }
        }
    }

    try w.print("\n{d} line(s) counted", .{result.counted});
    if (result.filtered > 0) try w.print(", {d} outside the window", .{result.filtered});
    if (result.skipped > 0) try w.print(", {d} skipped as malformed", .{result.skipped});
    try w.writeByte('\n');
}

const JsonStats = struct {
    log: []const u8,
    /// The rotated generation, when `--include-rotated` folded one in. Null
    /// (and omitted) otherwise, so its presence answers "did this summary see
    /// the rotated history?" without a second flag on the wire.
    rotated: ?[]const u8,
    exists: bool,
    now_unix: i64,
    since_seconds: ?i64,
    lines: usize,
    counted: usize,
    skipped: usize,
    filtered: usize,
    rules: []const RuleStat,
    events: []const EventStat,
};

pub const StatsJsonMeta = struct {
    log_path: []const u8,
    /// Set only when a rotated generation actually contributed bytes.
    rotated_path: ?[]const u8 = null,
    exists: bool,
    now_unix: i64,
    since_seconds: ?i64 = null,
};

pub fn writeStatsJson(w: *std.Io.Writer, meta: StatsJsonMeta, result: StatsResult) !void {
    try std.json.Stringify.value(JsonStats{
        .log = meta.log_path,
        .rotated = meta.rotated_path,
        .exists = meta.exists,
        .now_unix = meta.now_unix,
        .since_seconds = meta.since_seconds,
        .lines = result.lines,
        .counted = result.counted,
        .skipped = result.skipped,
        .filtered = result.filtered,
        .rules = result.rules,
        .events = result.events,
    }, .{ .emit_null_optional_fields = false }, w);
    try w.writeByte('\n');
}

// ---------------------------------------------------------------------------
// doctor + status: the facts
// ---------------------------------------------------------------------------

/// A byte count an operator has to judge at a glance.
pub fn humanizeBytes(buf: []u8, bytes: u64) []const u8 {
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var value: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    while (value >= 1024 and unit + 1 < units.len) : (unit += 1) value /= 1024;
    if (unit == 0) return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "?";
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "?";
}

/// One hook command a settings document wires up, and the event it is under.
pub const HookEntry = struct {
    /// The `hooks.<Event>` key this entry sits under. Null when the key names
    /// something this build has never heard of — reported as-is rather than
    /// dropped, because "somebody else's hook on an event I do not know" is a
    /// true and useful fact about a settings file.
    event: ?rules.Event = null,
    matcher: []const u8,
    command: []const u8,

    /// True when this looks like one of ours: the command's basename is the
    /// name the installer copies the gate under. Deliberately basename-only —
    /// an install that moved still has to be recognized as *this* tool's
    /// entry, or `doctor` would report a stale wiring as somebody else's hook.
    pub fn isGate(self: HookEntry) bool {
        return eq(std.fs.path.basename(self.command), GATE_BINARY_NAME);
    }
};

/// Every `hooks.<Event>[*].hooks[*].command` in a settings document, in file
/// order, across EVERY event key the file has.
///
/// Reading all of them rather than just `PreToolUse` is what lets `doctor`
/// answer the question a multi-event policy raises: not "is the gate wired?"
/// but "is it wired for each of the events my rules are scoped to?". A rule set
/// with `Stop` rules and no `hooks.Stop` entry is a policy that looks complete
/// and enforces two thirds of itself.
///
/// Shape errors are not reported: a `settings.json` whose `hooks` key is a
/// string is a file with no hook commands in it, which is exactly what the
/// caller then says.
pub fn hookEntries(
    allocator: std.mem.Allocator,
    root: std.json.Value,
) std.mem.Allocator.Error![]const HookEntry {
    var out: std.ArrayList(HookEntry) = .empty;
    const obj = switch (root) {
        .object => |o| o,
        else => return &.{},
    };
    const hooks = switch (obj.get("hooks") orelse return &.{}) {
        .object => |o| o,
        else => return &.{},
    };
    for (hooks.keys(), hooks.values()) |key, value| {
        const list = switch (value) {
            .array => |a| a,
            else => continue,
        };
        const event = rules.Event.from(key);
        for (list.items) |entry| {
            const entry_obj = switch (entry) {
                .object => |o| o,
                else => continue,
            };
            const matcher = switch (entry_obj.get("matcher") orelse std.json.Value{ .null = {} }) {
                .string => |s| s,
                else => "",
            };
            const inner = switch (entry_obj.get("hooks") orelse continue) {
                .array => |a| a,
                else => continue,
            };
            for (inner.items) |hook| {
                const hook_obj = switch (hook) {
                    .object => |o| o,
                    else => continue,
                };
                const command = switch (hook_obj.get("command") orelse continue) {
                    .string => |s| s,
                    else => continue,
                };
                try out.append(allocator, .{ .event = event, .matcher = matcher, .command = command });
            }
        }
    }
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// the wiring plan
// ---------------------------------------------------------------------------

/// One event the gate should be wired for, and the matcher to wire it with.
pub const WireEntry = struct {
    event: rules.Event,
    /// The `matcher` string for the settings entry, or null to omit the key —
    /// which makes the hook fire for every occurrence of the event.
    matcher: ?[]const u8 = null,
    /// How many rules are scoped to this event. Reported, so an operator can
    /// see why an event is wired.
    rules: usize = 0,
};

/// Which events a rule set needs wired, and with what matcher.
///
/// **Why the plan is derived from the RULES rather than fixed.** The single-event
/// installer wired `hooks.PreToolUse` with `"matcher": "Bash"`, which was wrong
/// in a way nothing caught: the shipped defaults include a rule on `Write` and
/// one on every tool (`"tool": "*"`), and a `Bash` matcher means the harness
/// never invokes the gate for a `Write` at all. Two shipped rules could not fire
/// on a real install. Deriving both halves — which events, and which tools
/// within an event — from the rules that actually exist is what closes that,
/// and it keeps the promise the other way too: an event with no rules is not
/// wired, so the gate is not woken thirty times a turn to say nothing.
///
/// The matcher is derived only where the harness's matcher is a TOOL NAME. On
/// every other event it means something a rule's `tool` field is not — a
/// session source, a notification type, a literal filename, an MCP server — so
/// the key is omitted and the hook fires for all of them, which is both correct
/// and the only honest option.
pub fn wiringPlan(
    allocator: std.mem.Allocator,
    rule_set: rules.RuleSet,
) std.mem.Allocator.Error![]const WireEntry {
    var out: std.ArrayList(WireEntry) = .empty;
    // Table order, so the plan an operator reads and the settings keys the
    // installer writes are in the catalog's order rather than the rule file's.
    for (rules.Events.all()) |*d| {
        var count: usize = 0;
        for (rule_set.rules) |rule| {
            if (rule.event == d.event) count += 1;
        }
        if (count == 0) continue;
        try out.append(allocator, .{
            .event = d.event,
            .matcher = if (d.matcher == .tool_name) try toolMatcher(allocator, rule_set, d.event) else null,
            .rules = count,
        });
    }
    return out.toOwnedSlice(allocator);
}

/// The tool-name matcher covering every rule scoped to `event`: `"*"` when any
/// of them applies to all tools, else the distinct tool names alternated.
fn toolMatcher(
    allocator: std.mem.Allocator,
    rule_set: rules.RuleSet,
    event: rules.Event,
) std.mem.Allocator.Error![]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(allocator);
    for (rule_set.rules) |rule| {
        if (rule.event != event) continue;
        const pattern = rule.toolPattern();
        if (eq(pattern, rules.TOOL_ANY)) return rules.TOOL_ANY;
        const seen = for (names.items) |n| {
            if (eq(n, pattern)) break true;
        } else false;
        if (!seen) try names.append(allocator, pattern);
    }
    if (names.items.len == 0) return rules.TOOL_ANY;
    return std.mem.join(allocator, "|", names.items);
}

/// Does `entries` already carry our gate under `event`?
pub fn wiredFor(entries: []const HookEntry, event: rules.Event, gate_dest: []const u8) bool {
    return matcherFor(entries, event, gate_dest) != null;
}

/// The matcher our gate's entry under `event` carries, or null when there is no
/// entry of ours there. An absent `matcher` key reads as `""`.
pub fn matcherFor(
    entries: []const HookEntry,
    event: rules.Event,
    gate_dest: []const u8,
) ?[]const u8 {
    for (entries) |entry| {
        if (entry.event != event) continue;
        if (eq(entry.command, gate_dest)) return entry.matcher;
    }
    return null;
}

/// Is our gate wired under `entry.event` with EXACTLY the matcher the plan calls
/// for?
///
/// The matcher has to be part of "already wired", not just the command. An entry
/// left in place with a stale matcher is the original single-event bug arriving by
/// a different road: a rule file that grows a `Write` rule needs `PreToolUse`
/// widened from `Bash` to `*`, and an installer that saw "our command is already
/// under PreToolUse" and stopped would leave the new rule permanently
/// unreachable — while reporting the install as verified.
pub fn wiredExactly(
    entries: []const HookEntry,
    entry: WireEntry,
    gate_dest: []const u8,
) bool {
    const found = matcherFor(entries, entry.event, gate_dest) orelse return false;
    return eq(found, entry.matcher orelse "");
}

/// The version number out of the one line `claude-hooker-gate version` prints.
///
/// Null for anything that is not exactly that line: a stranger binary sitting
/// at the gate's path must be reported as "did not answer", never as a version
/// that happens to be the last word of its output.
pub fn parseVersionLine(text: []const u8) ?[]const u8 {
    const line = std.mem.trim(u8, text, " \t\r\n");
    const prefix = PROGRAM ++ " ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = std.mem.trim(u8, line[prefix.len..], " \t\r\n");
    if (rest.len == 0) return null;
    if (std.mem.indexOfAny(u8, rest, " \t\r\n") != null) return null;
    return rest;
}

/// What a stat of the gate binary found. `missing` and a permission error are
/// different facts with different fixes, so they are different variants.
pub const BinaryProbe = union(enum) {
    missing,
    err: []const u8,
    ok: struct { size: u64, executable: bool },
};

/// One event's wiring, as the settings file and the rule file each see it.
pub const EventWiring = struct {
    event: rules.Event,
    /// Rules scoped to this event in the live rule file.
    rules: usize = 0,
    /// Our gate is wired under `hooks.<event>` in settings.json.
    wired: bool = false,
    /// The matcher the settings entry carries, when it is ours.
    matcher: []const u8 = "",
};

pub const WiringFacts = struct {
    settings_path: []const u8,
    settings: union(enum) {
        missing,
        unreadable: []const u8,
        invalid: []const u8,
        ok: []const HookEntry,
    },
    /// Where this install puts the gate.
    expected_command: []const u8,
    /// One row per event that either has rules or is wired — the join of the
    /// two files, which is the only place a "rules but no wiring" gap is
    /// visible. Empty when settings.json could not be read.
    events: []const EventWiring = &.{},
    /// The command of the first entry that names a gate, or null when nothing
    /// in the file does.
    wired_command: ?[]const u8 = null,
    /// `wired_command` is exactly `expected_command` — the entry points at the
    /// install being inspected rather than at an older one somewhere else.
    wired_here: bool = false,
    /// Probe of `wired_command`, or of `expected_command` when nothing is wired.
    binary: BinaryProbe = .missing,
};

pub const VersionFacts = struct {
    /// The version compiled into the binary doing the diagnosing. When that is
    /// a fresh `zig-out/bin/claude-hooker-gate`, this IS the source tree.
    source: []const u8,
    /// The binary that was asked, whether or not it answered.
    probed_path: []const u8,
    /// What `<probed_path> version` reported.
    installed: ?[]const u8 = null,
    /// Why there is no `installed` value, or a caveat about the one there is.
    note: ?[]const u8 = null,
    /// The binary being probed is the one running this check, so it is
    /// comparing a version against itself and cannot see drift.
    self_is_installed: bool = false,
};

pub const RulesFacts = struct {
    path: []const u8,
    state: union(enum) {
        unreadable: []const u8,
        invalid: []const u8,
        /// The file is from a schema this binary does not read. Not `invalid`:
        /// the operator's document is fine and their binary is behind it, which
        /// is a different problem with a different fix.
        schema_refused: struct {
            declared: ?rules.SchemaVersion,
            text: []const u8,
        },
        ok: struct {
            rules: usize,
            literal_total: usize,
            literal_passed: usize,
            generated_total: usize,
            generated_passed: usize,
            lint_errors: usize,
            lint_warnings: usize,
            /// How the file's `schema_version` compared. Never `.newer` — that
            /// load did not produce an `ok`.
            schema: rules.SchemaCompat = .current,

            pub fn cases(self: @This()) usize {
                return self.literal_total + self.generated_total;
            }

            pub fn failed(self: @This()) usize {
                return (self.literal_total - self.literal_passed) +
                    (self.generated_total - self.generated_passed);
            }
        },
    },
};

pub const LogFacts = struct {
    path: []const u8,
    /// The rule file's `logging.enabled`. False means not one line is written.
    enabled: bool = true,
    exists: bool = false,
    size: u64 = 0,
    /// Why the log — or the directory it would be created in — cannot be
    /// written. Null means it can.
    write_error: ?[]const u8 = null,
    rotated_exists: bool = false,
    rotated_size: u64 = 0,
    /// `logging.max_bytes`; zero means rotation is switched off.
    max_bytes: u64 = 0,
    /// Newest `ts_unix` in the live generation, or null when there are none.
    last_ts: ?i64 = null,
    entries: usize = 0,
};

pub const OverlayFacts = struct {
    /// The global file's `allow_project_overlay`.
    allowed: bool = true,
    /// Where an overlay was looked for. Null when there was nowhere to look.
    path: ?[]const u8 = null,
    state: enum {
        /// Neither --project-dir, nor $CLAUDE_PROJECT_DIR, nor a readable cwd.
        nowhere,
        absent,
        active,
        /// Present, but the global file switched overlays off.
        ignored,
        /// Resolved to the global rule file itself.
        same_file,
        unreadable,
        invalid,
    } = .nowhere,
    rules: usize = 0,
    err: ?[]const u8 = null,
};

pub const DisableFacts = struct {
    /// `CLAUDE_HOOK_DISABLE`, verbatim.
    spec: []const u8 = "",
    /// Entries that name a rule the live file actually has — these are the
    /// protections that are OFF right now.
    known: []const []const u8 = &.{},
    /// Entries that name nothing. A typo here is a rule the operator believes
    /// is disabled and is not, which is its own kind of surprise.
    unknown: []const []const u8 = &.{},
};

pub const EnvFacts = struct {
    rules_override: ?[]const u8 = null,
    log_override: ?[]const u8 = null,
    project_dir: ?[]const u8 = null,
};

/// What `codesign` says about the installed gate. macOS only — see the
/// `signature` section below for why this is a fact worth gathering at all.
pub const SignatureFacts = struct {
    /// False on every platform that does not require a code signature. A
    /// different answer from "unsigned", and the difference is the point: there
    /// is nothing to fix on Linux, and reporting a missing signature there
    /// would be a false alarm an operator learns to ignore.
    applicable: bool = signing_required,
    /// The OS this binary was built for, so the not-applicable line can name it.
    system: []const u8 = @tagName(builtin.os.tag),
    path: []const u8 = "",
    state: enum {
        /// `codesign --verify` accepted it.
        valid,
        /// Signed, but the signature no longer covers the bytes on disk.
        invalid,
        unsigned,
        /// `codesign` could not be run, so nothing is known.
        unavailable,
    } = .unavailable,
    /// The `flags=0x…(…)` and `Signature=…` text codesign printed, verbatim.
    /// An operator should be able to read the flags rather than take "ad-hoc"
    /// on trust.
    form: []const u8 = "",
    /// Whether that form is the ad-hoc signature this project installs.
    adhoc: bool = false,
    /// codesign's own first line when it refused, verbatim.
    note: []const u8 = "",
};

/// Everything `doctor` and `status` read, as plain values.
///
/// Gathering touches the filesystem and spawns one child process; deciding
/// what any of it MEANS does not. That split is what makes every verdict below
/// reachable from a unit test, including the ones that need a corrupt rule
/// file or a version that drifted.
pub const Facts = struct {
    claude_dir: []const u8,
    /// The binary running this check.
    self_path: []const u8,
    now_unix: i64 = 0,
    wiring: WiringFacts,
    version: VersionFacts,
    signature: SignatureFacts = .{},
    rules: RulesFacts,
    log: LogFacts,
    overlay: OverlayFacts = .{},
    disable: DisableFacts = .{},
    env: EnvFacts = .{},
};

// ---------------------------------------------------------------------------
// code signatures (macOS)
// ---------------------------------------------------------------------------
//
// Why this is here at all, when nothing else in this project cares what the
// loader thinks: on macOS a Mach-O whose code signature does not validate is
// killed — SIGKILL, no message, no exit status of its own making. A killed
// PreToolUse hook produces no decision envelope, and the hooks contract reads
// a missing answer as "proceed". So a broken signature does not make the gate
// strict; it makes it ABSENT, silently, on every tool call. That is the one
// failure mode in this system with no output at all, which is exactly why it
// is signed deliberately, verified afterwards, and reported even when fine.
//
// What this is NOT: a distribution story. This project is cloned and built —
// no release artifacts, no notarization, no Developer ID, nothing fetched and
// nothing to verify a download against. The signature is ad-hoc (`-s -`),
// which is precisely enough to satisfy the loader and requires no identity.
//
// One implementation, shared: the installer signs and verifies with it, and
// `doctor` diagnoses with it, so the two cannot disagree about what a valid
// signature is.

/// Whether this build's platform refuses to run an incorrectly signed binary.
/// Comptime, so every codesign call below vanishes on other platforms.
pub const signing_required = builtin.os.tag == .macos;

/// Absolute, because this runs from the installer as well as the CLI and must
/// not depend on the PATH a hook harness happened to inherit.
pub const CODESIGN = "/usr/bin/codesign";

/// Cap on what codesign may print, and the two argv shapes it is asked in.
const CODESIGN_OUTPUT_LIMIT = 8 * 1024;

/// codesign's own words for "there is no signature here at all".
const UNSIGNED_MARKER = "not signed at all";

/// The outcome of trying to (re-)sign a file ad-hoc.
pub const Resign = union(enum) {
    /// Not macOS, so nothing was attempted.
    skipped,
    signed,
    /// codesign ran and refused, or could not be run. Carries its first line.
    failed: []const u8,
};

/// Sign `path` ad-hoc, replacing whatever signature is there.
///
/// `--force` is not optional: a file that already carries a real signature is
/// refused without it, and this has to work on whatever is currently on disk.
/// Best-effort by design — the caller reports the failure rather than aborting
/// on it — because a machine without the command line tools should still get an
/// install, just a loudly-qualified one.
pub fn resignAdhoc(io: std.Io, gpa: std.mem.Allocator, path: []const u8) Resign {
    if (!signing_required) return .skipped;
    const result = std.process.run(gpa, io, .{
        .argv = &.{ CODESIGN, "--force", "--sign", "-", path },
        .stdout_limit = .limited(CODESIGN_OUTPUT_LIMIT),
        .stderr_limit = .limited(CODESIGN_OUTPUT_LIMIT),
    }) catch |err| return .{ .failed = @errorName(err) };
    switch (result.term) {
        .exited => |code| if (code == 0) return .signed,
        else => {},
    }
    // The LAST line, not the first: codesign narrates ("replacing existing
    // signature") before it refuses, and the refusal is the part worth
    // repeating.
    return .{ .failed = stripPathPrefix(lastLine(result.stderr, result.stdout), path) };
}

/// Ask the OS about `path`: two short child processes, or none.
///
/// Both questions are asked because neither answers the other. `--display`
/// prints what the signature CLAIMS to be — and prints `Signature=adhoc` for a
/// binary with a byte appended to it, which is exactly the state that gets a
/// process killed. Only `--verify` says whether the signature still covers the
/// bytes on disk.
pub fn inspectSignature(io: std.Io, gpa: std.mem.Allocator, path: []const u8) SignatureFacts {
    var out = SignatureFacts{ .path = path };
    if (!signing_required) return out;

    if (std.process.run(gpa, io, .{
        .argv = &.{ CODESIGN, "--display", "--verbose=2", path },
        .stdout_limit = .limited(CODESIGN_OUTPUT_LIMIT),
        .stderr_limit = .limited(CODESIGN_OUTPUT_LIMIT),
    })) |shown| {
        // codesign writes its description to stderr.
        out.form = signatureForm(gpa, shown.stderr) catch "";
        out.adhoc = std.mem.indexOf(u8, out.form, "adhoc") != null;
    } else |_| {}

    const verified = std.process.run(gpa, io, .{
        .argv = &.{ CODESIGN, "--verify", path },
        .stdout_limit = .limited(CODESIGN_OUTPUT_LIMIT),
        .stderr_limit = .limited(CODESIGN_OUTPUT_LIMIT),
    }) catch |err| {
        out.state = .unavailable;
        out.note = @errorName(err);
        return out;
    };
    switch (verified.term) {
        .exited => |code| if (code == 0) {
            out.state = .valid;
            return out;
        },
        else => {},
    }
    // codesign prefixes its complaint with the path it was given, which the
    // caller is already printing; keeping both would say it twice in one line.
    out.note = stripPathPrefix(firstLine(verified.stderr, verified.stdout), path);
    out.state = if (std.mem.indexOf(u8, out.note, UNSIGNED_MARKER) != null) .unsigned else .invalid;
    return out;
}

/// The `flags=…` and `Signature=…` fields out of a `codesign --display` report,
/// joined — the two lines an operator would look at, and nothing else.
pub fn signatureForm(gpa: std.mem.Allocator, described: []const u8) ![]const u8 {
    var flags: []const u8 = "";
    var signature: []const u8 = "";
    var lines = std.mem.splitScalar(u8, described, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "CodeDirectory ")) {
            var fields = std.mem.splitScalar(u8, line, ' ');
            while (fields.next()) |field| {
                if (std.mem.startsWith(u8, field, "flags=")) flags = field;
            }
        } else if (std.mem.startsWith(u8, line, "Signature=")) {
            signature = std.mem.trimEnd(u8, line, "\r");
        }
    }
    if (flags.len == 0) return signature;
    if (signature.len == 0) return flags;
    return std.fmt.allocPrint(gpa, "{s}, {s}", .{ flags, signature });
}

/// `<path>: something went wrong` -> `something went wrong`.
fn stripPathPrefix(line: []const u8, path: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, line, path)) return line;
    const rest = line[path.len..];
    if (!std.mem.startsWith(u8, rest, ": ")) return line;
    return rest[2..];
}

/// The first non-blank line of stderr, else of stdout: what a tool that refused
/// actually said, in the one line a report has room for.
fn firstLine(stderr: []const u8, stdout: []const u8) []const u8 {
    for ([_][]const u8{ stderr, stdout }) |text| {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len > 0) return trimmed;
        }
    }
    return "no output";
}

/// As `firstLine`, from the other end.
fn lastLine(stderr: []const u8, stdout: []const u8) []const u8 {
    for ([_][]const u8{ stderr, stdout }) |text| {
        var found: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len > 0) found = trimmed;
        }
        if (found) |line| return line;
    }
    return "no output";
}

// ---------------------------------------------------------------------------
// doctor: the diagnosis
// ---------------------------------------------------------------------------

pub const Health = enum {
    pass,
    warn,
    fail,

    pub fn word(self: Health) []const u8 {
        return switch (self) {
            .pass => "PASS",
            .warn => "WARN",
            .fail => "FAIL",
        };
    }
};

/// One diagnosed check. `id` is the stable machine name (the JSON key and what
/// the README's transcript is verified against); `title` is the column an
/// operator reads; `remedy` is the line printed underneath when the check is
/// not passing, and is null exactly when there is nothing to do.
pub const Check = struct {
    id: []const u8,
    title: []const u8,
    status: Health,
    detail: []const u8,
    remedy: ?[]const u8 = null,
};

/// How many checks are at each level.
pub const Tally = struct {
    pass: usize = 0,
    warn: usize = 0,
    fail: usize = 0,

    pub fn of(checks: []const Check) Tally {
        var out = Tally{};
        for (checks) |c| switch (c.status) {
            .pass => out.pass += 1,
            .warn => out.warn += 1,
            .fail => out.fail += 1,
        };
        return out;
    }

    /// A WARN is deliberately not a failure: `doctor` is run in scripts, and a
    /// gate that is working but has a lint warning must not break a pipeline.
    pub fn exitCode(self: Tally) u8 {
        return if (self.fail > 0) 1 else 0;
    }
};

const Checks = std.ArrayList(Check);

/// The checks, in the order an operator should read them: is the gate wired, is
/// it the gate you think it is, will the OS actually run it, are the rules
/// sound, is the log usable, is this repo contributing rules, and is anything
/// switched off.
pub fn diagnose(allocator: std.mem.Allocator, facts: Facts) std.mem.Allocator.Error![]const Check {
    var out: Checks = .empty;
    try diagnoseWiring(allocator, &out, facts);
    try diagnoseVersion(allocator, &out, facts);
    try diagnoseSignature(allocator, &out, facts);
    try diagnoseRules(allocator, &out, facts);
    try diagnoseLog(allocator, &out, facts);
    try diagnoseOverlay(allocator, &out, facts);
    try diagnoseDisable(allocator, &out, facts);
    try diagnoseEnv(allocator, &out, facts);
    return out.toOwnedSlice(allocator);
}

fn diagnoseWiring(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const w = facts.wiring;
    const id = "wiring";
    const title = "hook entries";
    const setup_hint = "run `./hookctl setup` (add --claude-dir to install into a sandbox)";

    switch (w.settings) {
        .missing => return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "no settings.json at {s}", .{w.settings_path}),
            .remedy = setup_hint,
        }),
        .unreadable => |err| return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "cannot read {s}: {s}", .{ w.settings_path, err }),
            .remedy = "fix the file permissions; the installer will not write a settings.json it cannot first read",
        }),
        .invalid => |err| return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "{s} is not valid JSON: {s}", .{ w.settings_path, err }),
            .remedy = "repair the JSON by hand — the installer refuses to rewrite a settings file it cannot parse, so nothing here can fix it for you",
        }),
        .ok => |entries| {
            if (w.wired_command == null) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .fail,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "no hook in {s} names a {s} ({d} hook(s) wired, none of them ours)",
                        .{ w.settings_path, GATE_BINARY_NAME, entries.len },
                    ),
                    .remedy = setup_hint,
                });
            }
        },
    }

    const command = w.wired_command.?;
    switch (w.binary) {
        .missing => return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "settings.json wires {s}, which does not exist — every tool call runs unguarded",
                .{command},
            ),
            .remedy = setup_hint,
        }),
        .err => |err| return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "cannot stat the wired command {s}: {s}", .{ command, err }),
            .remedy = setup_hint,
        }),
        .ok => |stat| {
            var size_buf: [32]u8 = undefined;
            const size = humanizeBytes(&size_buf, stat.size);
            if (!stat.executable) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .fail,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "wired to {s} ({s}) but it is not executable, so the harness cannot run it",
                        .{ command, size },
                    ),
                    .remedy = try std.fmt.allocPrint(allocator, "chmod +x {s}, or reinstall with `./hookctl setup`", .{command}),
                });
            }
            if (!w.wired_here) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "wired to {s}, which is not where this install lives ({s}) — the gate that runs is a different copy",
                        .{ command, w.expected_command },
                    ),
                    .remedy = "run `./hookctl setup` to wire this install, then delete the stale entry from settings.json",
                });
            }
            // The binary is fine and it is this one. What is left is the
            // question a multi-event policy makes possible: is it wired for
            // each event the rules are scoped to? An unwired event is not a
            // broken install — everything else still enforces — but the rules
            // under it never run, and nothing else in this report would say so.
            const gap = try wiringGap(allocator, w.events);
            if (gap.len > 0) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s} wires {s}, but the rule file also has rules for {s}, which nothing wires — those rules never run",
                        .{ w.settings_path, try wiringSummary(allocator, w.events), gap },
                    ),
                    .remedy = "run `./hookctl setup` to wire every event your rules use (it adds only the events that have rules, and removes the ones that no longer do)",
                });
            }
            return out.append(allocator, .{
                .id = id,
                .title = title,
                .status = .pass,
                .detail = try std.fmt.allocPrint(
                    allocator,
                    "{s} wires {s} -> {s} (present, executable, {s})",
                    .{ w.settings_path, try wiringSummary(allocator, w.events), command, size },
                ),
            });
        },
    }
}

/// `PreToolUse(*), Stop` — the events this install is wired for, with the
/// matcher each one carries.
fn wiringSummary(allocator: std.mem.Allocator, events_: []const EventWiring) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var first = true;
    for (events_) |row| {
        if (!row.wired) continue;
        if (!first) try out.appendSlice(allocator, ", ");
        first = false;
        try out.appendSlice(allocator, row.event.name());
        if (row.matcher.len > 0) {
            try out.append(allocator, '(');
            try out.appendSlice(allocator, row.matcher);
            try out.append(allocator, ')');
        }
    }
    if (first) try out.appendSlice(allocator, "nothing");
    return out.toOwnedSlice(allocator);
}

/// The events that have rules and no wiring, comma-separated. Empty when there
/// are none, which is the whole point of returning a string.
fn wiringGap(allocator: std.mem.Allocator, events_: []const EventWiring) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (events_) |row| {
        if (row.wired or row.rules == 0) continue;
        if (out.items.len > 0) try out.appendSlice(allocator, ", ");
        try out.appendSlice(allocator, row.event.name());
    }
    return out.toOwnedSlice(allocator);
}

fn diagnoseVersion(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const v = facts.version;
    const id = "version";
    const title = "version drift";
    // The single most confusing state this tool can be in: rules edited,
    // binary rebuilt, install forgotten. Everything looks right and the gate
    // enforcing decisions is last week's.
    const upgrade_hint = "run `./hookctl upgrade` — it rebuilds, shows what the shipped defaults gained, and reinstalls the binary while keeping your rules";

    const installed = v.installed orelse return out.append(allocator, .{
        .id = id,
        .title = title,
        .status = .fail,
        .detail = try std.fmt.allocPrint(
            allocator,
            "nothing to compare against this build ({s}): {s}",
            .{ v.source, v.note orelse "the installed binary reported no version" },
        ),
        .remedy = "run `./hookctl setup` to install the binary that goes with this tree",
    });

    if (!eq(installed, v.source)) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "installed {s} is {s}, this build is {s} — the gate enforcing your rules is NOT the tree you edited",
                .{ v.probed_path, installed, v.source },
            ),
            .remedy = upgrade_hint,
        });
    }

    if (v.self_is_installed) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .pass,
            .detail = try std.fmt.allocPrint(
                allocator,
                "installed {s} is {s} — but this diagnosis IS that binary, so it cannot see drift",
                .{ v.probed_path, installed },
            ),
            .remedy = "to compare against the source tree, run the freshly built gate: `./hookctl doctor` (or `zig build && zig-out/bin/" ++ GATE_BINARY_NAME ++ " doctor`)",
        });
    }

    return out.append(allocator, .{
        .id = id,
        .title = title,
        .status = .pass,
        .detail = try std.fmt.allocPrint(
            allocator,
            "installed {s} is {s}, matching this build",
            .{ v.probed_path, installed },
        ),
    });
}

fn diagnoseSignature(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const s = facts.signature;
    const id = "signature";
    const title = "code signature";

    if (!s.applicable) {
        // Not-applicable, not absent: there is nothing to fix on a platform
        // that does not police signatures, and a check that cried wolf there
        // would teach an operator to skim past this line on the platform where
        // it matters.
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .pass,
            .detail = try std.fmt.allocPrint(
                allocator,
                "not applicable on {s} — only macOS refuses to run a binary whose signature does not validate",
                .{s.system},
            ),
        });
    }

    // Said the same way in every failing branch, because it is the only reason
    // any of this is checked: the loader killing the gate looks exactly like
    // having no gate, and produces no output to notice.
    const danger = "macOS may SIGKILL it, and a killed gate fails OPEN — no decision, no log line, nothing enforced";
    const resign = try std.fmt.allocPrint(
        allocator,
        "re-sign it: `{s} --force --sign - {s}` — or reinstall with `./hookctl setup`, which signs and verifies",
        .{ CODESIGN, s.path },
    );

    switch (s.state) {
        .valid => {
            if (!s.adhoc) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s} validates, but {s} is not the ad-hoc signature this project installs",
                        .{ s.path, if (s.form.len > 0) s.form else "its signature" },
                    ),
                    .remedy = "nothing is broken and nothing needs a Developer ID here; this is worth knowing only because it means the binary was signed by something other than `./hookctl setup`",
                });
            }
            return out.append(allocator, .{
                .id = id,
                .title = title,
                .status = .pass,
                .detail = try std.fmt.allocPrint(
                    allocator,
                    "{s} is ad-hoc signed and `codesign --verify` accepts it ({s})",
                    .{ s.path, s.form },
                ),
            });
        },
        .invalid => return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{s} is signed but the signature does not cover the file on disk: {s} — {s}",
                .{ s.path, s.note, danger },
            ),
            .remedy = resign,
        }),
        .unsigned => return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{s} carries no code signature at all — {s}",
                .{ s.path, danger },
            ),
            .remedy = resign,
        }),
        .unavailable => return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .warn,
            .detail = try std.fmt.allocPrint(
                allocator,
                "cannot ask about {s}: {s} did not answer ({s}) — the signature is unknown, not known-good",
                .{ s.path, CODESIGN, s.note },
            ),
            .remedy = "install the Xcode command line tools (`xcode-select --install`), then `./hookctl doctor` again",
        }),
    }
}

fn diagnoseRules(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const id = "rules";
    const title = "live rules";
    switch (facts.rules.state) {
        .unreadable => |err| return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "cannot read {s}: {s}", .{ facts.rules.path, err }),
            .remedy = "`./hookctl setup` seeds it from the shipped defaults without overwriting anything that is already there",
        }),
        .invalid => |err| return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{s} does not parse: {s} — the gate fails OPEN on an invalid rule file, so nothing is being enforced",
                .{ facts.rules.path, err },
            ),
            .remedy = "fix the JSON, then `./hookctl selftest`; `./hookctl diff-defaults` shows how far your copy is from the shipped one",
        }),
        .schema_refused => |r| {
            var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            const speaks = rules.SCHEMA_VERSION.text(&mine);
            if (r.declared) |found| {
                var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .fail,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s} declares schema_version {s} and this build reads {s} — the gate REFUSES it and fails OPEN, so nothing is being enforced",
                        .{ facts.rules.path, found.text(&theirs), speaks },
                    ),
                    .remedy = "`./hookctl upgrade` rebuilds and reinstalls the gate; your rule file is not touched",
                });
            }
            return out.append(allocator, .{
                .id = id,
                .title = title,
                .status = .fail,
                .detail = try std.fmt.allocPrint(
                    allocator,
                    "{s} declares schema_version \"{s}\", which is not a major.minor version; this build reads {s} and refuses the file",
                    .{ facts.rules.path, r.text, speaks },
                ),
                .remedy = "set it to a major.minor version, or delete the key (which reads as the oldest schema), then `./hookctl selftest`",
            });
        },
        .ok => |s| {
            var buf: [256]u8 = undefined;
            const counts = std.fmt.bufPrint(&buf, "{d} rules, {d} literal + {d} generated cases", .{
                s.rules,
                s.literal_total,
                s.generated_total,
            }) catch "";
            if (s.failed() > 0 or s.lint_errors > 0) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .fail,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s}: {s}, {d} case(s) FAILING, {d} lint error(s)",
                        .{ facts.rules.path, counts, s.failed(), s.lint_errors },
                    ),
                    .remedy = "`./hookctl selftest` names every failing case and every lint error",
                });
            }
            if (s.cases() == 0) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s}: {d} rules and no test cases — nothing asserts these rules still fire",
                        .{ facts.rules.path, s.rules },
                    ),
                    .remedy = "add a `tests` block; see the `tests` section of README.md",
                });
            }
            if (s.lint_warnings > 0) {
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s}: {s} pass, but {d} lint warning(s)",
                        .{ facts.rules.path, counts, s.lint_warnings },
                    ),
                    .remedy = "`./hookctl selftest` prints each warning; they are advisory, not failures",
                });
            }
            // The one place an operator is told their file predates
            // `schema_version`. Deliberately NOT said by the hook on every tool
            // call: a warning that appears in a transcript hundreds of times a
            // day is a warning nobody reads, and the file is being enforced
            // correctly either way. `doctor` is where a papercut belongs.
            if (s.schema == .absent) {
                var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
                return out.append(allocator, .{
                    .id = id,
                    .title = title,
                    .status = .warn,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s}: {s} pass, lint clean, but the file declares no schema_version — it is read as {s}",
                        // The OLDEST schema, not this build's: a file with no
                        // declaration is read as the oldest one anybody could
                        // have written, which is the whole point of the default.
                        // Printing this build's version here would tell the
                        // operator their file is being read as something newer
                        // than it is.
                        .{ facts.rules.path, counts, rules.OLDEST_SCHEMA_VERSION.text(&mine) },
                    ),
                    .remedy = "add `\"schema_version\": \"1.2\"` at the top level; it is what lets a future gate tell your file apart from one it cannot read",
                });
            }
            var schema_note: []const u8 = "";
            if (s.schema == .older) {
                var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
                var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
                schema_note = try std.fmt.allocPrint(
                    allocator,
                    ", schema {s} (this build reads {s}; older is accepted as-is)",
                    .{ s.schema.older.text(&theirs), rules.SCHEMA_VERSION.text(&mine) },
                );
            }
            return out.append(allocator, .{
                .id = id,
                .title = title,
                .status = .pass,
                .detail = try std.fmt.allocPrint(
                    allocator,
                    "{s}: {s} pass, lint clean{s}",
                    .{ facts.rules.path, counts, schema_note },
                ),
            });
        },
    }
}

fn diagnoseLog(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const l = facts.log;
    const id = "log";
    const title = "decision log";

    if (!l.enabled) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .warn,
            .detail = try std.fmt.allocPrint(
                allocator,
                "logging is off in the rule file (logging.enabled = false): no decision is being recorded at {s}",
                .{l.path},
            ),
            .remedy = "set `\"logging\": {\"enabled\": true}` in the rule file if you want `./hookctl stats` to have anything to read",
        });
    }
    if (l.write_error) |err| {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(allocator, "cannot write {s}: {s}", .{ l.path, err }),
            .remedy = "fix the permissions on the log's directory, or point logging.path (or CLAUDE_HOOK_LOG_PATH) somewhere writable",
        });
    }

    // One buffer per rendered value: every one of these is a slice INTO its
    // buffer and they are all still live when the detail line is formatted.
    var size_buf: [32]u8 = undefined;
    var max_buf: [32]u8 = undefined;
    var rot_buf: [48]u8 = undefined;
    var age_buf: [32]u8 = undefined;
    var last_buf: [48]u8 = undefined;
    const size = humanizeBytes(&size_buf, l.size);
    const rotation = if (l.max_bytes == 0)
        "rotation OFF"
    else
        std.fmt.bufPrint(&rot_buf, "rotates at {s}", .{humanizeBytes(&max_buf, l.max_bytes)}) catch "rotates";
    const rotated = if (l.rotated_exists) ", one rotated generation kept" else "";
    const last = if (l.last_ts) |ts|
        std.fmt.bufPrint(&last_buf, ", last hit {s}", .{humanizeAge(&age_buf, facts.now_unix - ts)}) catch ""
    else
        "";

    if (!l.exists) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .pass,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{s} does not exist yet, and its directory is writable — nothing has matched",
                .{l.path},
            ),
        });
    }
    // Rotation off is not an error the operator made by accident often, but an
    // unbounded append-only file in a home directory is a slow-motion outage,
    // so it is said out loud every time rather than only past some size.
    if (l.max_bytes == 0) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .warn,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{s} is {s} and rotation is disabled (logging.max_bytes = 0), so it grows without bound",
                .{ l.path, size },
            ),
            .remedy = "set logging.max_bytes in the rule file (10485760 is the built-in default)",
        });
    }
    return out.append(allocator, .{
        .id = id,
        .title = title,
        .status = .pass,
        .detail = try std.fmt.allocPrint(
            allocator,
            "{s} is writable — {s}, {d} entr(ies), {s}{s}{s}",
            .{ l.path, size, l.entries, rotation, rotated, last },
        ),
    });
}

fn diagnoseOverlay(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const o = facts.overlay;
    const id = "overlay";
    const title = "project overlay";
    const detail: []const u8, const status: Health, const remedy: ?[]const u8 = switch (o.state) {
        .nowhere => .{
            "nowhere to look for a project overlay: no --project-dir, no $CLAUDE_PROJECT_DIR, no readable working directory",
            .pass,
            null,
        },
        .absent => .{
            try std.fmt.allocPrint(allocator, "no overlay at {s} — this directory contributes no rules", .{o.path.?}),
            .pass,
            null,
        },
        .active => .{
            try std.fmt.allocPrint(
                allocator,
                "{s} is active: {d} rule(s), evaluated BEFORE the global file",
                .{ o.path.?, o.rules },
            ),
            .pass,
            null,
        },
        .ignored => .{
            try std.fmt.allocPrint(
                allocator,
                "{s} exists but the global file sets allow_project_overlay = false, so the hook never reads it",
                .{o.path.?},
            ),
            .warn,
            "set allow_project_overlay to true in the global rule file if this repository's rules are meant to apply",
        },
        .same_file => .{
            try std.fmt.allocPrint(
                allocator,
                "{s} resolves to the global rule file itself; it is not evaluated twice",
                .{o.path.?},
            ),
            .pass,
            null,
        },
        .unreadable => .{
            try std.fmt.allocPrint(
                allocator,
                "{s} exists but cannot be read: {s} — the hook skips it, so this repository's rules are NOT applied",
                .{ o.path.?, o.err orelse "?" },
            ),
            .fail,
            "fix the file permissions, then `./hookctl doctor` again",
        },
        .invalid => .{
            try std.fmt.allocPrint(
                allocator,
                "{s} does not parse: {s} — the hook skips it, so this repository's rules are NOT applied",
                .{ o.path.?, o.err orelse "?" },
            ),
            .fail,
            "fix the overlay's JSON; `./hookctl selftest --rules <overlay>` will parse and lint it on its own",
        },
    };
    try out.append(allocator, .{ .id = id, .title = title, .status = status, .detail = detail, .remedy = remedy });
}

fn diagnoseDisable(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    const d = facts.disable;
    const id = "disabled";
    const title = "CLAUDE_HOOK_DISABLE";

    if (d.spec.len == 0) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .pass,
            .detail = "not set — every rule in the file is live",
        });
    }
    // A disabled rule is a protection the operator believes they have. It is
    // recorded in the decision log as `bypassed`, but nothing else shouts, so
    // this is where it gets shouted about.
    if (d.known.len > 0) {
        return out.append(allocator, .{
            .id = id,
            .title = title,
            .status = .fail,
            .detail = try std.fmt.allocPrint(
                allocator,
                "{d} rule(s) are switched OFF right now: {s}{s}",
                .{
                    d.known.len,
                    try joinNames(allocator, d.known),
                    if (d.unknown.len > 0)
                        try std.fmt.allocPrint(
                            allocator,
                            " (and {d} entr(ies) naming no rule: {s})",
                            .{ d.unknown.len, try joinNames(allocator, d.unknown) },
                        )
                    else
                        "",
                },
            ),
            .remedy = "unset CLAUDE_HOOK_DISABLE in the environment the harness starts with (settings.json `env`, or your shell profile) and restart the session; matches are logged as `bypassed` until you do",
        });
    }
    return out.append(allocator, .{
        .id = id,
        .title = title,
        .status = .warn,
        .detail = try std.fmt.allocPrint(
            allocator,
            "set to \"{s}\", which names no rule in {s} — nothing is disabled, and nothing you meant to disable is",
            .{ d.spec, facts.rules.path },
        ),
        .remedy = "correct the spelling (`./hookctl status` lists the live rule count; `./hookctl selftest` lists the rules) or unset it",
    });
}

fn diagnoseEnv(allocator: std.mem.Allocator, out: *Checks, facts: Facts) !void {
    var parts: std.ArrayList([]const u8) = .empty;
    if (facts.env.rules_override) |p| {
        try parts.append(allocator, try std.fmt.allocPrint(allocator, "CLAUDE_HOOK_RULES_PATH={s}", .{p}));
    }
    if (facts.env.log_override) |p| {
        try parts.append(allocator, try std.fmt.allocPrint(allocator, "CLAUDE_HOOK_LOG_PATH={s}", .{p}));
    }
    if (facts.env.project_dir) |p| {
        try parts.append(allocator, try std.fmt.allocPrint(allocator, "CLAUDE_PROJECT_DIR={s}", .{p}));
    }
    try out.append(allocator, .{
        .id = "environment",
        .title = "path overrides",
        .status = .pass,
        .detail = if (parts.items.len == 0)
            "no path override in effect; the rule file and log under the claude dir are what the gate reads"
        else
            try std.fmt.allocPrint(allocator, "in effect: {s}", .{try joinNames(allocator, parts.items)}),
    });
}

fn joinNames(allocator: std.mem.Allocator, names: []const []const u8) std.mem.Allocator.Error![]const u8 {
    return std.mem.join(allocator, ", ", names);
}

// ---------------------------------------------------------------------------
// doctor + status: reporting
// ---------------------------------------------------------------------------

/// Width of the check-id column, so the PASS/WARN/FAIL words and the details
/// line up under each other whatever order the checks come in.
const CHECK_ID_COLUMN = 12;

pub fn writeDoctorReport(
    w: *std.Io.Writer,
    facts: Facts,
    checks: []const Check,
    width: usize,
) !u8 {
    // The version printed here is the version DOING the diagnosing, which is
    // half of the drift comparison below. The path of that binary is in the
    // JSON (`diagnosing`) rather than here: it is a machine detail, and the
    // one case where it changes a verdict — probing itself — is stated by the
    // version check in words.
    try w.print("{s} doctor {s}\n", .{ PROGRAM, VERSION });
    try w.print("claude dir : {s}\n\n", .{facts.claude_dir});

    for (checks) |c| {
        try w.print("{s}  ", .{c.status.word()});
        try writeLeftCell(w, c.id, CHECK_ID_COLUMN);
        try writeWrappedAfter(w, " " ** (6 + CHECK_ID_COLUMN), c.detail, width);
        // The remediation line is the difference between a diagnosis and a
        // complaint, so it is printed for everything that is not passing —
        // and a check with nothing to do carries no remedy to print.
        if (c.status != .pass) {
            if (c.remedy) |remedy| {
                try w.writeAll("      -> ");
                try writeWrappedAfter(w, " " ** 9, remedy, width);
            }
        }
    }

    const tally = Tally.of(checks);
    try w.print("\nresult     : {d} pass, {d} warn, {d} fail -> {s}\n", .{
        tally.pass,
        tally.warn,
        tally.fail,
        if (tally.fail > 0) "NOT HEALTHY" else if (tally.warn > 0) "OK, with warnings" else "healthy",
    });
    return tally.exitCode();
}

const JsonCheck = struct {
    id: []const u8,
    title: []const u8,
    status: []const u8,
    detail: []const u8,
    remedy: ?[]const u8,
};

const JsonDoctor = struct {
    version: []const u8,
    claude_dir: []const u8,
    diagnosing: []const u8,
    ok: bool,
    pass: usize,
    warn: usize,
    fail: usize,
    checks: []const JsonCheck,
};

pub fn writeDoctorJson(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    facts: Facts,
    checks: []const Check,
) !u8 {
    const rows = try allocator.alloc(JsonCheck, checks.len);
    defer allocator.free(rows);
    for (checks, 0..) |c, i| {
        rows[i] = .{
            .id = c.id,
            .title = c.title,
            .status = @tagName(c.status),
            .detail = c.detail,
            .remedy = c.remedy,
        };
    }
    const tally = Tally.of(checks);
    try std.json.Stringify.value(JsonDoctor{
        .version = VERSION,
        .claude_dir = facts.claude_dir,
        .diagnosing = facts.self_path,
        .ok = tally.fail == 0,
        .pass = tally.pass,
        .warn = tally.warn,
        .fail = tally.fail,
        .checks = rows,
    }, .{}, w);
    try w.writeByte('\n');
    return tally.exitCode();
}

/// The one-screen summary: the same facts, six lines, no diagnosis.
///
/// `doctor` answers "what is wrong"; this answers "what am I running", which
/// is the question asked far more often and deserves not to scroll.
pub fn writeStatus(allocator: std.mem.Allocator, w: *std.Io.Writer, facts: Facts) !u8 {
    var size_buf: [32]u8 = undefined;
    var age_buf: [32]u8 = undefined;

    try w.print("gate       : ", .{});
    if (facts.version.installed) |installed| {
        try w.print("{s} at {s}", .{ installed, facts.version.probed_path });
        if (!eq(installed, facts.version.source)) {
            try w.print("  (DRIFT: this build is {s})", .{facts.version.source});
        }
        try w.writeByte('\n');
    } else {
        try w.print("NOT INSTALLED at {s} (this build is {s})\n", .{
            facts.version.probed_path,
            facts.version.source,
        });
    }

    try w.print("wiring     : ", .{});
    if (facts.wiring.wired_command) |command| {
        try w.print("{s} -> {s}{s}\n", .{
            try wiringSummary(allocator, facts.wiring.events),
            command,
            if (facts.wiring.wired_here) "" else "  (NOT this install)",
        });
        // Events with rules that nothing wires. On the line under the wiring,
        // because it is the same subject and because a status screen that hides
        // it would be describing a policy that is not the one running.
        const gap = try wiringGap(allocator, facts.wiring.events);
        if (gap.len > 0) try w.print("             UNWIRED (rules never run): {s}\n", .{gap});
    } else {
        try w.print("no {s} entry in {s}\n", .{ GATE_BINARY_NAME, facts.wiring.settings_path });
    }

    try w.print("rules      : {s}\n", .{facts.rules.path});
    switch (facts.rules.state) {
        .unreadable => |err| try w.print("             UNREADABLE: {s}\n", .{err}),
        .invalid => |err| try w.print("             INVALID: {s} (the gate enforces nothing)\n", .{err}),
        .schema_refused => |r| {
            var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            try w.print("             REFUSED: schema_version {s}, this build reads {s} (the gate enforces nothing; run `./hookctl upgrade`)\n", .{
                if (r.declared) |d| d.text(&theirs) else r.text,
                rules.SCHEMA_VERSION.text(&mine),
            });
        },
        .ok => |s| try w.print("             {d} rules, {d} cases ({d} literal + {d} generated), {s}\n", .{
            s.rules,
            s.cases(),
            s.literal_total,
            s.generated_total,
            if (s.failed() > 0 or s.lint_errors > 0) "SELFTEST FAILING" else "selftest OK",
        }),
    }

    try w.print("overlay    : ", .{});
    switch (facts.overlay.state) {
        .active => try w.print("{s} ({d} rules, evaluated first)\n", .{ facts.overlay.path.?, facts.overlay.rules }),
        .absent => try w.print("none for this directory\n", .{}),
        .nowhere => try w.print("no project directory to look in\n", .{}),
        .ignored => try w.print("{s} present but IGNORED (allow_project_overlay = false)\n", .{facts.overlay.path.?}),
        .same_file => try w.print("resolves to the global rule file; not evaluated twice\n", .{}),
        .unreadable => try w.print("{s} UNREADABLE ({s})\n", .{ facts.overlay.path.?, facts.overlay.err orelse "?" }),
        .invalid => try w.print("{s} INVALID ({s}); the hook skips it\n", .{ facts.overlay.path.?, facts.overlay.err orelse "?" }),
    }

    try w.print("log        : ", .{});
    if (!facts.log.enabled) {
        try w.print("logging is OFF in the rule file\n", .{});
    } else if (!facts.log.exists) {
        try w.print("{s} (nothing logged yet)\n", .{facts.log.path});
    } else {
        try w.print("{s}, {d} entr(ies), last hit {s}\n", .{
            humanizeBytes(&size_buf, facts.log.size),
            facts.log.entries,
            if (facts.log.last_ts) |ts| humanizeAge(&age_buf, facts.now_unix - ts) else "never",
        });
    }

    try w.print("disabled   : ", .{});
    if (facts.disable.spec.len == 0) {
        try w.print("nothing\n", .{});
    } else {
        try w.print("{d} live rule(s) OFF via CLAUDE_HOOK_DISABLE", .{facts.disable.known.len});
        for (facts.disable.known, 0..) |name, i| {
            try w.writeAll(if (i == 0) ": " else ", ");
            try w.writeAll(name);
        }
        try w.writeByte('\n');
    }
    return 0;
}

const JsonStatusRules = struct {
    path: []const u8,
    state: []const u8,
    @"error": ?[]const u8 = null,
    rules: usize = 0,
    cases: usize = 0,
    literal: usize = 0,
    generated: usize = 0,
    selftest_ok: bool = false,
    /// The `schema_version` the file declares, or null when it declares none.
    /// Present on the refusal too — that is the field a fleet script keys on.
    schema_version: ?[]const u8 = null,
    /// What this build reads, so a consumer can compare without knowing the
    /// binary's release number.
    schema_read: []const u8 = "",
};

const JsonStatus = struct {
    version: []const u8,
    claude_dir: []const u8,
    installed_version: ?[]const u8,
    gate_path: []const u8,
    version_drift: bool,
    wired_command: ?[]const u8,
    wired_here: bool,
    settings_path: []const u8,
    rules: JsonStatusRules,
    overlay_state: []const u8,
    overlay_path: ?[]const u8,
    overlay_rules: usize,
    logging_enabled: bool,
    log_path: []const u8,
    log_exists: bool,
    log_bytes: u64,
    log_entries: usize,
    log_last_ts: ?i64,
    disabled: []const []const u8,
    disabled_unknown: []const []const u8,
    now_unix: i64,
};

pub fn writeStatusJson(w: *std.Io.Writer, facts: Facts) !u8 {
    // Rendered into this frame's buffers: the document is stringified below,
    // before either goes out of scope.
    var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
    var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
    const read = rules.SCHEMA_VERSION.text(&mine);
    const rules_json: JsonStatusRules = switch (facts.rules.state) {
        .unreadable => |err| .{ .path = facts.rules.path, .state = "unreadable", .@"error" = err, .schema_read = read },
        .invalid => |err| .{ .path = facts.rules.path, .state = "invalid", .@"error" = err, .schema_read = read },
        .schema_refused => |r| .{
            .path = facts.rules.path,
            .state = "schema_refused",
            .@"error" = "RulesFromNewerSchema",
            .schema_version = if (r.declared) |d| d.text(&theirs) else r.text,
            .schema_read = read,
        },
        .ok => |s| .{
            .path = facts.rules.path,
            .state = "ok",
            .rules = s.rules,
            .cases = s.cases(),
            .literal = s.literal_total,
            .generated = s.generated_total,
            .selftest_ok = s.failed() == 0 and s.lint_errors == 0,
            .schema_version = switch (s.schema) {
                .current => read,
                .older => |v| v.text(&theirs),
                // Absent stays absent in the JSON. A consumer must be able to
                // see that the file declares nothing, not be handed the version
                // it was READ as and conclude the operator wrote it.
                .absent => null,
                .newer => unreachable,
            },
            .schema_read = read,
        },
    };
    try std.json.Stringify.value(JsonStatus{
        .version = VERSION,
        .claude_dir = facts.claude_dir,
        .installed_version = facts.version.installed,
        .gate_path = facts.version.probed_path,
        .version_drift = if (facts.version.installed) |v| !eq(v, facts.version.source) else true,
        .wired_command = facts.wiring.wired_command,
        .wired_here = facts.wiring.wired_here,
        .settings_path = facts.wiring.settings_path,
        .rules = rules_json,
        .overlay_state = @tagName(facts.overlay.state),
        .overlay_path = facts.overlay.path,
        .overlay_rules = facts.overlay.rules,
        .logging_enabled = facts.log.enabled,
        .log_path = facts.log.path,
        .log_exists = facts.log.exists,
        .log_bytes = facts.log.size,
        .log_entries = facts.log.entries,
        .log_last_ts = facts.log.last_ts,
        .disabled = facts.disable.known,
        .disabled_unknown = facts.disable.unknown,
        .now_unix = facts.now_unix,
    }, .{}, w);
    try w.writeByte('\n');
    return 0;
}

// ---------------------------------------------------------------------------
// diff-defaults
// ---------------------------------------------------------------------------

/// The fields of a rule that can differ between two rule sets. Not every field
/// of `rules.Rule` — `name` is the key the two sides are matched on, so it
/// cannot differ by construction.
pub const RuleField = enum { tool, event, decision, reason, match, match_all, match_none };

pub const RuleDelta = struct {
    name: []const u8,
    /// Which fields differ. Empty for a rule that exists on one side only.
    fields: []const RuleField = &.{},
};

/// A top-level section other than `rules` whose value differs. Rendered
/// values rather than typed ones: the point is to say "your `logging` block is
/// not the shipped one", not to diff it field by field.
pub const SectionDelta = struct {
    name: []const u8,
    defaults: []const u8,
    live: []const u8,
};

/// What an operator's rule file has become, relative to the defaults this
/// binary ships.
pub const DefaultsDiff = struct {
    /// In the shipped defaults and not in the live file: what adopting this
    /// version would gain.
    added: []const RuleDelta = &.{},
    /// In the live file and not in the defaults: the operator's own rules, or
    /// a default this version dropped. Either way, never touched.
    removed: []const RuleDelta = &.{},
    changed: []const RuleDelta = &.{},
    /// Rules present in both and identical.
    same: usize = 0,
    sections: []const SectionDelta = &.{},

    pub fn inSync(self: DefaultsDiff) bool {
        return self.added.len == 0 and self.removed.len == 0 and
            self.changed.len == 0 and self.sections.len == 0;
    }
};

/// Canonical JSON for one matcher list, used as the comparison key.
///
/// Serializing beats a field-by-field walk for a reason worth stating: both
/// sides have been through `rules.parse`, which expands `$class:` and `$set`
/// references into plain groups. So a default that was rewritten from seven
/// hand-listed members into one class reference compares EQUAL to the operator's
/// enumeration of the same members — which is right, because the two behave
/// identically. What this reports is a change in what a rule MATCHES, not a
/// change in how it was spelled.
fn matcherKey(allocator: std.mem.Allocator, list: []const rules.Matcher) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    try std.json.Stringify.value(list, .{ .emit_null_optional_fields = false }, &out.writer);
    return out.written();
}

fn ruleFields(allocator: std.mem.Allocator, a: rules.Rule, b: rules.Rule) ![]const RuleField {
    var fields: std.ArrayList(RuleField) = .empty;
    // `toolPattern` rather than `tool`: an operator's copy that spells out the
    // historical default is not a difference from a shipped rule that leaves it
    // implicit, and reporting it as one would make `diff-defaults` noisy about
    // nothing on every upgrade.
    if (!eq(a.toolPattern(), b.toolPattern())) try fields.append(allocator, .tool);
    if (a.event != b.event) try fields.append(allocator, .event);
    if (a.decision != b.decision) try fields.append(allocator, .decision);
    if (!eq(a.reason, b.reason)) try fields.append(allocator, .reason);
    inline for (.{ .match, .match_all, .match_none }) |field| {
        const name = @tagName(field);
        if (!eq(try matcherKey(allocator, @field(a, name)), try matcherKey(allocator, @field(b, name)))) {
            try fields.append(allocator, field);
        }
    }
    return fields.toOwnedSlice(allocator);
}

fn findRuleNamed(set: rules.RuleSet, name: []const u8) ?rules.Rule {
    for (set.rules) |rule| {
        if (eq(rule.name, name)) return rule;
    }
    return null;
}

pub fn diffDefaults(
    allocator: std.mem.Allocator,
    defaults: rules.RuleSet,
    live: rules.RuleSet,
) !DefaultsDiff {
    var added: std.ArrayList(RuleDelta) = .empty;
    var removed: std.ArrayList(RuleDelta) = .empty;
    var changed: std.ArrayList(RuleDelta) = .empty;
    var same: usize = 0;

    for (defaults.rules) |shipped| {
        const mine = findRuleNamed(live, shipped.name) orelse {
            try added.append(allocator, .{ .name = shipped.name });
            continue;
        };
        const fields = try ruleFields(allocator, shipped, mine);
        if (fields.len == 0) {
            same += 1;
        } else {
            try changed.append(allocator, .{ .name = shipped.name, .fields = fields });
        }
    }
    for (live.rules) |mine| {
        if (findRuleNamed(defaults, mine.name) == null) {
            try removed.append(allocator, .{ .name = mine.name });
        }
    }

    var sections: std.ArrayList(SectionDelta) = .empty;
    // First, because it is the one difference that can stop the live file from
    // being read at all by a future binary. A seeded file declares the shipped
    // schema; a file seeded before the field existed declares nothing, and
    // saying so here is how an operator finds out that adding one line makes
    // their policy legible to the next release.
    {
        var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
        const a = defaults.schema_version orelse "absent";
        const b = live.schema_version orelse "absent";
        if (!eq(a, b)) try sections.append(allocator, .{
            .name = "schema_version",
            .defaults = a,
            .live = if (live.schema_version) |v| v else try std.fmt.allocPrint(
                allocator,
                "absent (read as {s})",
                // The oldest schema, which is what an undeclared file is read
                // as — not this build's version. See `rules.OLDEST_SCHEMA_VERSION`.
                .{rules.OLDEST_SCHEMA_VERSION.text(&mine)},
            ),
        });
    }
    if (defaults.tests.len != live.tests.len) {
        try sections.append(allocator, .{
            .name = "tests",
            .defaults = try std.fmt.allocPrint(allocator, "{d} declaration(s)", .{defaults.tests.len}),
            .live = try std.fmt.allocPrint(allocator, "{d} declaration(s)", .{live.tests.len}),
        });
    }
    {
        const a = try joinNames(allocator, defaults.sets.map.keys());
        const b = try joinNames(allocator, live.sets.map.keys());
        if (!eq(a, b)) try sections.append(allocator, .{
            .name = "sets",
            .defaults = if (a.len == 0) "none" else a,
            .live = if (b.len == 0) "none" else b,
        });
    }
    {
        const a = try renderJson(allocator, defaults.logging);
        const b = try renderJson(allocator, live.logging);
        if (!eq(a, b)) try sections.append(allocator, .{ .name = "logging", .defaults = a, .live = b });
    }
    if (defaults.allow_project_overlay != live.allow_project_overlay) {
        try sections.append(allocator, .{
            .name = "allow_project_overlay",
            .defaults = if (defaults.allow_project_overlay) "true" else "false",
            .live = if (live.allow_project_overlay) "true" else "false",
        });
    }

    return .{
        .added = try added.toOwnedSlice(allocator),
        .removed = try removed.toOwnedSlice(allocator),
        .changed = try changed.toOwnedSlice(allocator),
        .same = same,
        .sections = try sections.toOwnedSlice(allocator),
    };
}

fn renderJson(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    try std.json.Stringify.value(value, .{ .emit_null_optional_fields = false }, &out.writer);
    return out.written();
}

fn writeFieldList(w: *std.Io.Writer, fields: []const RuleField) !void {
    for (fields, 0..) |field, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll(@tagName(field));
    }
}

pub fn writeDefaultsDiff(
    w: *std.Io.Writer,
    live_path: []const u8,
    diff: DefaultsDiff,
    width: usize,
) !u8 {
    try w.print("defaults   : embedded in {s} {s}\n", .{ PROGRAM, VERSION });
    try w.print("live       : {s}\n\n", .{live_path});

    if (diff.inSync()) {
        try w.print("no differences: your rule file is exactly the {d} shipped rule(s).\n", .{diff.same});
        return 0;
    }

    for (diff.added) |delta| {
        try w.print("+ {s}\n", .{delta.name});
        try writeWrapped(w, "    ", "new in the shipped defaults; your file does not have it. Copy the rule in to adopt it, or ignore it deliberately.", width);
    }
    for (diff.changed) |delta| {
        try w.print("~ {s}  (", .{delta.name});
        try writeFieldList(w, delta.fields);
        try w.writeAll(")\n");
        try writeWrapped(w, "    ", "the shipped version of this rule differs from yours in the fields above; yours is what the gate enforces.", width);
    }
    for (diff.removed) |delta| {
        try w.print("- {s}\n", .{delta.name});
        try writeWrapped(w, "    ", "only in your file: either a rule you wrote, or a default this version no longer ships. Nothing here will remove it.", width);
    }
    if (diff.same > 0) try w.print("= {d} rule(s) identical\n", .{diff.same});

    if (diff.sections.len > 0) {
        try w.writeAll("\nother sections:\n");
        for (diff.sections) |section| {
            try w.print("  {s}\n", .{section.name});
            try w.print("    defaults: {s}\n", .{section.defaults});
            try w.print("    live    : {s}\n", .{section.live});
        }
    }

    try w.print("\nresult     : {d} added, {d} changed, {d} yours only, {d} identical\n", .{
        diff.added.len,
        diff.changed.len,
        diff.removed.len,
        diff.same,
    });
    // Exit 0 either way, deliberately: "your rules differ from the defaults"
    // is the normal, intended state of a customized install, and `upgrade`
    // pipes this through on its way to reinstalling the binary.
    return 0;
}

const JsonRuleDelta = struct {
    name: []const u8,
    fields: []const []const u8 = &.{},
};

const JsonDefaultsDiff = struct {
    version: []const u8,
    live: []const u8,
    in_sync: bool,
    added: []const JsonRuleDelta,
    changed: []const JsonRuleDelta,
    removed: []const JsonRuleDelta,
    identical: usize,
    sections: []const SectionDelta,
};

fn jsonDeltas(allocator: std.mem.Allocator, deltas: []const RuleDelta) ![]const JsonRuleDelta {
    const out = try allocator.alloc(JsonRuleDelta, deltas.len);
    for (deltas, 0..) |delta, i| {
        const names = try allocator.alloc([]const u8, delta.fields.len);
        for (delta.fields, 0..) |field, j| names[j] = @tagName(field);
        out[i] = .{ .name = delta.name, .fields = names };
    }
    return out;
}

pub fn writeDefaultsDiffJson(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    live_path: []const u8,
    diff: DefaultsDiff,
) !u8 {
    try std.json.Stringify.value(JsonDefaultsDiff{
        .version = VERSION,
        .live = live_path,
        .in_sync = diff.inSync(),
        .added = try jsonDeltas(allocator, diff.added),
        .changed = try jsonDeltas(allocator, diff.changed),
        .removed = try jsonDeltas(allocator, diff.removed),
        .identical = diff.same,
        .sections = diff.sections,
    }, .{}, w);
    try w.writeByte('\n');
    return 0;
}

// ---------------------------------------------------------------------------
// process plumbing — the only part that knows there is a process
// ---------------------------------------------------------------------------

/// The ambient settings the CLI reads, lifted out of the environment by `run`
/// so every command below is a function of plain values.
pub const Env = struct {
    rules_path: ?[]const u8 = null,
    log_path: ?[]const u8 = null,
    disable: []const u8 = "",
    home: ?[]const u8 = null,
    /// The harness's own statement about which repo a session belongs to. The
    /// hook reads it to locate an overlay; `check` reads it so that running
    /// inside a repo with an overlay gives the same answer the hook would.
    project_dir: ?[]const u8 = null,
};

const Ctx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    env: Env,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    now_unix: i64,
};

/// CLI entry point. `main` routes here when the process was given any
/// argument at all; it never returns without flushing.
pub fn run(init: std.process.Init) !void {
    const io = init.io;
    // One-shot process: everything comes from the process arena, so no command
    // below has to own a teardown path.
    const gpa = init.arena.allocator();

    var stdout_buf: [16 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buf);

    var ctx = Ctx{
        .io = io,
        .gpa = gpa,
        .env = .{
            .rules_path = init.environ_map.get("CLAUDE_HOOK_RULES_PATH"),
            .log_path = init.environ_map.get("CLAUDE_HOOK_LOG_PATH"),
            .disable = init.environ_map.get("CLAUDE_HOOK_DISABLE") orelse "",
            .home = init.environ_map.get("HOME"),
            .project_dir = init.environ_map.get("CLAUDE_PROJECT_DIR"),
        },
        .out = &stdout_writer.interface,
        .err = &stderr_writer.interface,
        .now_unix = std.Io.Clock.real.now(io).toSeconds(),
    };

    var argv: std.ArrayList([]const u8) = .empty;
    var args_it = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_it.next(); // program name
    while (args_it.next()) |arg| try argv.append(gpa, arg);

    const code = dispatch(&ctx, argv.items) catch |err| blk: {
        ctx.err.print("{s}: {s}\n", .{ PROGRAM, @errorName(err) }) catch {};
        break :blk EX_SOFTWARE;
    };

    ctx.out.flush() catch {};
    ctx.err.flush() catch {};
    std.process.exit(code);
}

fn dispatch(ctx: *Ctx, argv: []const []const u8) !u8 {
    switch (parseArgs(argv)) {
        .check => |args| return cmdCheck(ctx, args),
        .selftest => |args| return cmdSelftest(ctx, args),
        .stats => |args| return cmdStats(ctx, args),
        .classes => |args| {
            if (args.json) return writeClassesJson(ctx.gpa, ctx.out, args.name);
            return writeClasses(ctx.out, args.name, RENDER_WIDTH);
        },
        .events => |args| {
            if (args.markdown) return writeEventsMarkdown(ctx.out);
            if (args.json) return writeEventsJson(ctx.gpa, ctx.out, args.name);
            return writeEvents(ctx.out, args.name, RENDER_WIDTH);
        },
        .doctor => |args| return cmdDoctor(ctx, args),
        .status => |args| return cmdStatus(ctx, args),
        .diff_defaults => |args| return cmdDiffDefaults(ctx, args),
        .version => {
            try ctx.out.print("{s} {s}\n", .{ PROGRAM, VERSION });
            return 0;
        },
        .help => {
            try ctx.err.writeAll(usage_text);
            return EX_USAGE;
        },
        .fault => |fault| {
            try writeFault(ctx.err, fault);
            try ctx.err.writeAll(usage_text);
            return EX_USAGE;
        },
    }
}

/// A rule set plus where it came from. The path is printed, so it is kept.
/// No `deinit`: the parse is backed by the process arena and every borrowed
/// rule name, pattern, and reason has to outlive the report that prints them.
const LoadedConfig = struct {
    path: []const u8,
    loaded: rules.LoadedRules,

    fn ruleSet(self: *const LoadedConfig) rules.RuleSet {
        return self.loaded.ruleSet();
    }
};

/// A rule file load whose failure is a VALUE, not a message and an exit code.
///
/// `doctor` needs the failure itself — "your rule file does not parse" is one
/// of the things it exists to report, with a remediation line, alongside six
/// other checks — while every other subcommand needs to print it and stop.
/// Both go through this, so there is still exactly one resolution and one parse.
const RulesLoad = union(enum) {
    ok: LoadedConfig,
    /// Nothing resolvable: no environment override, no explicit path, no HOME.
    no_path,
    unreadable: Failure,
    invalid: Failure,
    /// The file declares a `schema_version` this binary cannot honour. Its own
    /// case rather than an `invalid` with a different message, because every
    /// surface that reports it — the exit code, `doctor`'s remedy, the stderr
    /// line — has to say something different. See `rules.SCHEMA_VERSION`.
    schema_refused: SchemaRefusal,

    const Failure = struct { path: []const u8, err: []const u8 };

    const SchemaRefusal = struct {
        path: []const u8,
        /// The version the file declares, when it is a well-formed one. Null
        /// means `schema_version` was present but was not `major.minor`.
        declared: ?rules.SchemaVersion,
        /// The raw text, for the "that is not a version" case.
        text: []const u8,
    };
};

fn loadConfigQuiet(ctx: *Ctx, explicit_path: ?[]const u8) !RulesLoad {
    const path = try rules.resolvePath(ctx.gpa, ctx.env.rules_path, explicit_path, ctx.env.home) orelse
        return .no_path;
    const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(rules.MAX_CONFIG_BYTES)) catch |err| {
        return .{ .unreadable = .{ .path = path, .err = @errorName(err) } };
    };
    var diag: rules.Diagnostic = .{};
    const loaded = rules.parseDiagnosed(ctx.gpa, bytes, &diag) catch |err| switch (err) {
        error.RulesFromNewerSchema, error.InvalidSchemaVersion => return .{
            .schema_refused = .{
                .path = path,
                .declared = diag.declared,
                // The diagnostic's buffer is on this stack frame, so the text is
                // copied out for the report that outlives it.
                .text = try ctx.gpa.dupe(u8, diag.declaredText()),
            },
        },
        else => return .{ .invalid = .{ .path = path, .err = @errorName(err) } },
    };
    return .{ .ok = .{ .path = path, .loaded = loaded } };
}

/// The one wording of the refusal, shared by the hook path and every
/// subcommand: both versions and the command that fixes it.
///
/// It names `hookctl upgrade` rather than "rebuild and reinstall" because the
/// operator reading this line is by definition running a binary older than
/// their policy, and there is exactly one verb that fixes that.
pub fn writeSchemaRefusal(
    w: *std.Io.Writer,
    program: []const u8,
    path: []const u8,
    declared: ?rules.SchemaVersion,
    text: []const u8,
) !void {
    var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
    const speaks = rules.SCHEMA_VERSION.text(&mine);
    if (declared) |found| {
        var theirs: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
        try w.print(
            "{s}: {s} declares schema_version {s}, and this build reads {s} — refusing to " ++
                "enforce a policy it may not fully understand.\n" ++
                "  run `./hookctl upgrade` to rebuild and reinstall the gate (your rule file is not touched).\n",
            .{ program, path, found.text(&theirs), speaks },
        );
    } else {
        try w.print(
            "{s}: {s} declares schema_version \"{s}\", which is not a major.minor version; " ++
                "this build reads {s}.\n" ++
                "  fix the value (or delete the key, which reads as the oldest schema), then `./hookctl selftest`.\n",
            .{ program, path, text, speaks },
        );
    }
}

/// Load the rule file through the same resolution the hook uses, reporting
/// every failure the way an operator needs to see it.
fn loadConfig(ctx: *Ctx, explicit_path: ?[]const u8) !union(enum) { ok: LoadedConfig, code: u8 } {
    switch (try loadConfigQuiet(ctx, explicit_path)) {
        .ok => |config| return .{ .ok = config },
        .no_path => {
            try ctx.err.print(
                "{s}: no rule file to read: set CLAUDE_HOOK_RULES_PATH, pass --rules, or set HOME\n",
                .{PROGRAM},
            );
            return .{ .code = EX_NOINPUT };
        },
        .unreadable => |failure| {
            try ctx.err.print("{s}: cannot read {s}: {s}\n", .{ PROGRAM, failure.path, failure.err });
            return .{ .code = EX_NOINPUT };
        },
        .invalid => |failure| {
            try ctx.err.print("{s}: invalid rule file {s}: {s}\n", .{ PROGRAM, failure.path, failure.err });
            return .{ .code = EX_DATAERR };
        },
        .schema_refused => |refusal| {
            try writeSchemaRefusal(ctx.err, PROGRAM, refusal.path, refusal.declared, refusal.text);
            return .{ .code = EX_CONFIG };
        },
    }
}

/// The project layer as `check` found it: the rules to evaluate first, where
/// they were looked for, and — when there are none — why.
const Overlay = struct {
    path: ?[]const u8 = null,
    rules: []const rules.Rule = &.{},
    note: ?[]const u8 = null,

    const absent: Overlay = .{};
};

/// Resolve and load the project overlay the way `main.zig` does, and fail the
/// same way: an overlay that is missing, unreadable, or invalid is skipped
/// rather than fatal, because the hook would enforce the global rules anyway
/// and `check` exists to predict the hook.
///
/// The one difference is that every skip is *stated*. The hook can afford a
/// silent no-overlay; a tool whose whole job is explaining a decision cannot.
fn loadOverlay(ctx: *Ctx, config: LoadedConfig, explicit_dir: ?[]const u8) !Overlay {
    const root = explicit_dir orelse ctx.env.project_dir;
    const path = (try rules.resolveProjectPath(ctx.gpa, root, null)) orelse return .absent;

    if (!config.ruleSet().allow_project_overlay) {
        return .{ .path = path, .note = "not read: the global file sets allow_project_overlay to false" };
    }
    // $HOME as the project directory: the overlay IS the global file.
    if (eq(path, config.path)) {
        return .{ .path = path, .note = "same file as the global rules; not evaluated twice" };
    }

    const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(rules.MAX_CONFIG_BYTES)) catch |err| switch (err) {
        error.FileNotFound => return .{ .path = path, .note = "no overlay file here" },
        else => return .{
            .path = path,
            .note = try std.fmt.allocPrint(ctx.gpa, "unreadable: {s}; the hook would skip it too", .{@errorName(err)}),
        },
    };
    var diag: rules.Diagnostic = .{};
    const loaded = rules.parseDiagnosed(ctx.gpa, bytes, &diag) catch |err| {
        if (err == error.RulesFromNewerSchema) {
            var mine: [rules.SchemaVersion.TEXT_MAX]u8 = undefined;
            return .{ .path = path, .note = try std.fmt.allocPrint(
                ctx.gpa,
                "declares schema_version {s} and this build reads {s}; the hook would skip it too",
                .{ diag.declaredText(), rules.SCHEMA_VERSION.text(&mine) },
            ) };
        }
        return .{
            .path = path,
            .note = try std.fmt.allocPrint(ctx.gpa, "invalid: {s}; the hook would skip it too", .{@errorName(err)}),
        };
    };
    return .{ .path = path, .rules = loaded.ruleSet().rules };
}

/// The rule file a subcommand should read: an explicit `--rules`, else the one
/// belonging to the install `--claude-dir` names, else nothing (and the
/// resolution falls through to `$HOME/.claude` as it always has).
///
/// This is the whole implementation of `--claude-dir` outside `doctor`: it
/// fills the *explicit* slot of `rules.resolvePath`, which is the slot `--rules`
/// already occupies. `CLAUDE_HOOK_RULES_PATH` still outranks both.
fn rulesFor(ctx: *Ctx, rules_path: ?[]const u8, claude_dir: ?[]const u8) !?[]const u8 {
    if (rules_path) |path| return path;
    const dir = claude_dir orelse return null;
    if (dir.len == 0) return null;
    return (try Layout.init(ctx.gpa, dir)).rules_dest;
}

fn cmdCheck(ctx: *Ctx, args: CheckArgs) !u8 {
    const config = switch (try loadConfig(ctx, try rulesFor(ctx, args.rules_path, args.claude_dir))) {
        .code => |code| return code,
        .ok => |config| config,
    };
    const input = checkFields(args, try joinCommand(ctx.gpa, args.command));
    const overlay = try loadOverlay(ctx, config, args.project_dir);
    // The same call the hook makes: both layers, disabled set and all — and
    // the same single lazy parse behind any structural matcher.
    var result = rules.evaluateOverlayIn(
        ctx.gpa,
        overlay.rules,
        config.ruleSet().rules,
        input,
        .init(ctx.env.disable),
    );
    defer result.deinit();

    // `--explain` renders the model whether or not a rule asked for it: the
    // operator's question is often "why did NOTHING fire", and the answer is
    // in a structure no rule looked at. Built here only when the evaluation
    // did not already build one.
    var forced: ?*rules.Structure = null;
    defer if (forced) |st| st.deinit();
    if (args.explain and !args.quiet and result.structure == null and input.command.len > 0) {
        forced = rules.Structure.init(ctx.gpa, input.command) catch null;
    }

    return writeCheckReport(ctx.out, input, result, .{
        .quiet = args.quiet,
        .rules_path = config.path,
        .project = overlay.rules,
        .project_path = overlay.path,
        .project_note = overlay.note,
        .explain = if (args.explain) result.structure orelse forced else null,
    });
}

fn cmdSelftest(ctx: *Ctx, args: SelftestArgs) !u8 {
    const config = switch (try loadConfig(ctx, try rulesFor(ctx, args.rules_path, args.claude_dir))) {
        .code => |code| return code,
        .ok => |config| config,
    };
    const rule_set = config.ruleSet();
    var suite = try runSuite(ctx.gpa, rule_set);
    defer suite.deinit();
    const findings = try lintWith(ctx.gpa, rule_set, config.loaded.set_uses);
    if (args.json) return writeSelftestJson(ctx.gpa, ctx.out, config.path, &suite, findings);
    return writeSelftestReport(ctx.out, config.path, &suite, findings);
}

fn cmdStats(ctx: *Ctx, args: StatsArgs) !u8 {
    const explicit_rules = try rulesFor(ctx, null, args.claude_dir);
    // The log lives wherever the *gate* would put it, which includes the rule
    // file's `logging.path`. Reading the config is best-effort here: `stats`
    // must still work when the policy file is missing or broken. Falling back
    // to the claude dir's own default name means `--claude-dir` reaches the log
    // of an install whose rule file names no path — again through the slot the
    // configured path already occupies, not a new rule.
    const configured_path: ?[]const u8 = blk: {
        const fallback: ?[]const u8 = if (args.claude_dir) |dir|
            (try Layout.init(ctx.gpa, dir)).log_default
        else
            null;
        const maybe_path = rules.resolvePath(ctx.gpa, ctx.env.rules_path, explicit_rules, ctx.env.home) catch break :blk fallback;
        const path = maybe_path orelse break :blk fallback;
        const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(rules.MAX_CONFIG_BYTES)) catch break :blk fallback;
        const loaded = rules.parse(ctx.gpa, bytes) catch break :blk fallback;
        const configured = loaded.ruleSet().logging.path orelse break :blk fallback;
        break :blk if (configured.len == 0) fallback else configured;
    };

    const log_path = try decision_log.resolvePath(
        ctx.gpa,
        args.log_path orelse ctx.env.log_path,
        configured_path,
        ctx.env.home,
    ) orelse {
        try ctx.err.print(
            "{s}: no decision log to read: pass --log, set CLAUDE_HOOK_LOG_PATH, or set HOME\n",
            .{PROGRAM},
        );
        return EX_NOINPUT;
    };

    const cutoff: ?i64 = if (args.since_seconds) |window| ctx.now_unix - window else null;

    // Oldest generation first, so the concatenation reads in the order the
    // lines were written even though `aggregate` itself is order-independent.
    var rotated_path: ?[]const u8 = null;
    var rotated_bytes: []const u8 = "";
    if (args.include_rotated) {
        const candidate = try std.fmt.allocPrint(ctx.gpa, "{s}.1", .{log_path});
        switch (try readLog(ctx, candidate)) {
            .code => |code| return code,
            .missing => {},
            .bytes => |bytes| {
                rotated_path = candidate;
                rotated_bytes = bytes;
            },
        }
    }

    var live_bytes: []const u8 = "";
    var live_exists = false;
    switch (try readLog(ctx, log_path)) {
        .code => |code| return code,
        .missing => {},
        .bytes => |bytes| {
            live_bytes = bytes;
            live_exists = true;
        },
    }

    // Neither generation exists: not an error, just a gate that has never
    // matched anything (or logging switched off).
    if (!live_exists and rotated_path == null) {
        if (args.json) {
            try writeStatsJson(ctx.out, .{
                .log_path = log_path,
                .exists = false,
                .now_unix = ctx.now_unix,
                .since_seconds = args.since_seconds,
            }, .{ .rules = &.{} });
        } else {
            try ctx.out.print(
                "no decision log yet at {s} — nothing has matched, or logging is off.\n",
                .{log_path},
            );
        }
        return 0;
    }

    const bytes = try joinLogs(ctx.gpa, &.{ rotated_bytes, live_bytes });
    const result = try aggregate(ctx.gpa, bytes, cutoff);
    if (args.json) {
        try writeStatsJson(ctx.out, .{
            .log_path = log_path,
            .rotated_path = rotated_path,
            .exists = live_exists,
            .now_unix = ctx.now_unix,
            .since_seconds = args.since_seconds,
        }, result);
        return 0;
    }
    try ctx.out.print("log      : {s}{s}\n", .{ log_path, if (live_exists) "" else " (absent)" });
    if (args.include_rotated) {
        try ctx.out.print("rotated  : {s}\n", .{rotated_path orelse "none — nothing has rotated yet"});
    }
    if (args.since_spec) |spec| try ctx.out.print("since    : the last {s}\n", .{spec});
    try ctx.out.writeByte('\n');
    try writeTable(ctx.out, result, ctx.now_unix);
    return 0;
}

// ---------------------------------------------------------------------------
// doctor / status / diff-defaults: gathering
// ---------------------------------------------------------------------------

/// The install being inspected: `--claude-dir`, else `$HOME/.claude`. Null
/// when there is neither, which is the one unrecoverable case — there is no
/// install to have an opinion about.
fn layoutFor(ctx: *Ctx, claude_dir: ?[]const u8) !?Layout {
    if (claude_dir) |dir| {
        if (dir.len > 0) return try Layout.init(ctx.gpa, dir);
    }
    const home = ctx.env.home orelse return null;
    if (home.len == 0) return null;
    return try Layout.forHome(ctx.gpa, home);
}

fn probeBinary(io: std.Io, path: []const u8) BinaryProbe {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .{ .err = @errorName(err) },
    };
    // Existence and executability are separate questions with separate fixes:
    // a gate the harness cannot exec is as inert as one that is not there, and
    // says so with a different remedy.
    const executable = blk: {
        std.Io.Dir.cwd().access(io, path, .{ .execute = true }) catch break :blk false;
        break :blk true;
    };
    return .{ .ok = .{ .size = stat.size, .executable = executable } };
}

/// Ask the installed gate what version it is, by running it.
///
/// Running it rather than reading it is the point: the question is what the
/// harness will execute, and the only authority on that is the binary itself.
/// A `version` subcommand is chosen because it is the one invocation that
/// touches no rule file, no log, and no settings.
fn probeVersion(ctx: *Ctx, gate_path: []const u8, self_path: []const u8) !VersionFacts {
    var out = VersionFacts{
        .source = VERSION,
        .probed_path = gate_path,
        .self_is_installed = eq(self_path, gate_path),
    };
    switch (probeBinary(ctx.io, gate_path)) {
        .missing => {
            out.note = "there is no binary at that path";
            return out;
        },
        .err => |err| {
            out.note = try std.fmt.allocPrint(ctx.gpa, "cannot stat it: {s}", .{err});
            return out;
        },
        .ok => |stat| if (!stat.executable) {
            out.note = "the file is there but is not executable";
            return out;
        },
    }

    const result = std.process.run(ctx.gpa, ctx.io, .{
        .argv = &.{ gate_path, "version" },
        .stdout_limit = .limited(4 * 1024),
        .stderr_limit = .limited(4 * 1024),
    }) catch |err| {
        out.note = try std.fmt.allocPrint(ctx.gpa, "could not be run: {s}", .{@errorName(err)});
        return out;
    };
    switch (result.term) {
        .exited => |code| if (code != 0) {
            out.note = try std.fmt.allocPrint(ctx.gpa, "`version` exited {d}", .{code});
            return out;
        },
        else => {
            out.note = "`version` did not exit normally";
            return out;
        },
    }
    if (parseVersionLine(result.stdout)) |value| {
        out.installed = value;
        return out;
    }
    var buf: [96]u8 = undefined;
    out.note = try std.fmt.allocPrint(
        ctx.gpa,
        "it is not a {s}: `version` printed \"{s}\"",
        .{ PROGRAM, ellipsize(&buf, std.mem.trim(u8, result.stdout, " \t\r\n"), 48) },
    );
    return out;
}

/// The two files' views of one install's wiring, joined per event.
///
/// Both directions matter and each is a different fault: an event with rules
/// and no wiring is policy that never runs, and an event wired with no rules is
/// a process spawned on every occurrence of it to decide nothing.
fn joinWiring(
    allocator: std.mem.Allocator,
    entries: []const HookEntry,
    rule_set: ?rules.RuleSet,
    gate_dest: []const u8,
) std.mem.Allocator.Error![]const EventWiring {
    var out: std.ArrayList(EventWiring) = .empty;
    for (rules.Events.all()) |*d| {
        var row = EventWiring{ .event = d.event };
        if (rule_set) |set| {
            for (set.rules) |rule| {
                if (rule.event == d.event) row.rules += 1;
            }
        }
        for (entries) |entry| {
            if (entry.event != d.event) continue;
            if (!eq(entry.command, gate_dest)) continue;
            row.wired = true;
            row.matcher = entry.matcher;
            break;
        }
        if (row.rules == 0 and !row.wired) continue;
        try out.append(allocator, row);
    }
    return out.toOwnedSlice(allocator);
}

fn gatherWiring(ctx: *Ctx, layout: Layout, rule_set: ?rules.RuleSet) !WiringFacts {
    var out = WiringFacts{
        .settings_path = layout.settings_path,
        .settings = .missing,
        .expected_command = layout.gate_dest,
    };
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        ctx.io,
        layout.settings_path,
        ctx.gpa,
        .limited(MAX_SETTINGS_BYTES),
    ) catch |err| switch (err) {
        error.FileNotFound => return out,
        else => {
            out.settings = .{ .unreadable = @errorName(err) };
            return out;
        },
    };
    const root = std.json.parseFromSliceLeaky(std.json.Value, ctx.gpa, bytes, .{}) catch |err| {
        out.settings = .{ .invalid = @errorName(err) };
        return out;
    };
    const entries = try hookEntries(ctx.gpa, root);
    out.settings = .{ .ok = entries };
    out.events = try joinWiring(ctx.gpa, entries, rule_set, layout.gate_dest);
    // An entry pointing exactly here wins over one pointing at another copy,
    // so a machine carrying both a stale and a current wiring is reported by
    // the one that matches this install rather than by whichever came first.
    for (entries) |entry| {
        if (!entry.isGate()) continue;
        const here = eq(entry.command, layout.gate_dest);
        if (out.wired_command == null or here) {
            out.wired_command = entry.command;
            out.wired_here = here;
        }
        if (here) break;
    }
    out.binary = probeBinary(ctx.io, out.wired_command orelse layout.gate_dest);
    return out;
}

fn gatherLog(ctx: *Ctx, layout: Layout, logging: rules.Logging) !LogFacts {
    // The same three-source resolution the gate uses. `layout.log_default`
    // occupies the "configured" slot when the rule file names no path, which
    // is what makes --claude-dir reach the log without inventing a rule: for a
    // real install it is byte-identical to what HOME would have produced.
    const configured: ?[]const u8 = blk: {
        if (logging.path) |p| {
            if (p.len > 0) break :blk p;
        }
        break :blk layout.log_default;
    };
    const path = (try decision_log.resolvePath(ctx.gpa, ctx.env.log_path, configured, ctx.env.home)) orelse
        layout.log_default;

    var out = LogFacts{ .path = path, .enabled = logging.enabled, .max_bytes = logging.max_bytes };
    const cwd = std.Io.Dir.cwd();

    if (cwd.statFile(ctx.io, path, .{})) |stat| {
        out.exists = true;
        out.size = stat.size;
        cwd.access(ctx.io, path, .{ .write = true }) catch |err| {
            out.write_error = @errorName(err);
        };
    } else |err| switch (err) {
        error.FileNotFound => {
            // Never written is the normal state of a fresh install. What
            // matters then is whether the first line WOULD land.
            const dir = std.fs.path.dirname(path) orelse ".";
            cwd.access(ctx.io, dir, .{ .write = true }) catch |dir_err| {
                out.write_error = try std.fmt.allocPrint(
                    ctx.gpa,
                    "its directory {s} is not writable: {s}",
                    .{ dir, @errorName(dir_err) },
                );
            };
        },
        else => out.write_error = @errorName(err),
    }

    const rotated = try std.fmt.allocPrint(ctx.gpa, "{s}.1", .{path});
    if (cwd.statFile(ctx.io, rotated, .{})) |stat| {
        out.rotated_exists = true;
        out.rotated_size = stat.size;
    } else |_| {}

    if (out.exists and out.size > 0) {
        if (cwd.readFileAlloc(ctx.io, path, ctx.gpa, .limited(MAX_LOG_BYTES))) |bytes| {
            // The same aggregation `stats` prints, so "how many entries" and
            // "how long ago" cannot disagree between the two subcommands.
            const summary = try aggregate(ctx.gpa, bytes, null);
            out.entries = summary.counted;
            for (summary.rules) |stat| {
                if (out.last_ts == null or stat.last_ts > out.last_ts.?) out.last_ts = stat.last_ts;
            }
        } else |_| {}
    }
    return out;
}

fn gatherOverlay(
    ctx: *Ctx,
    args: InspectArgs,
    cwd_path: ?[]const u8,
    global_path: []const u8,
    allowed: bool,
) !OverlayFacts {
    var out = OverlayFacts{ .allowed = allowed };
    // The hook's own resolution, with the working directory standing in for
    // the `cwd` a hook event would have carried: "is this repository adding
    // rules to my session" is a question about where the operator is standing.
    const root = args.project_dir orelse ctx.env.project_dir;
    const path = (try rules.resolveProjectPath(ctx.gpa, root, cwd_path)) orelse return out;
    out.path = path;
    if (eq(path, global_path)) {
        out.state = .same_file;
        return out;
    }
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        ctx.io,
        path,
        ctx.gpa,
        .limited(rules.MAX_CONFIG_BYTES),
    ) catch |err| switch (err) {
        error.FileNotFound => {
            out.state = .absent;
            return out;
        },
        else => {
            out.state = .unreadable;
            out.err = @errorName(err);
            return out;
        },
    };
    // Switched off is only worth saying when there is something being ignored.
    if (!allowed) {
        out.state = .ignored;
        return out;
    }
    const loaded = rules.parse(ctx.gpa, bytes) catch |err| {
        out.state = .invalid;
        out.err = @errorName(err);
        return out;
    };
    out.state = .active;
    out.rules = loaded.ruleSet().rules.len;
    return out;
}

fn gatherDisable(ctx: *Ctx, rule_set: ?rules.RuleSet) !DisableFacts {
    var out = DisableFacts{ .spec = ctx.env.disable };
    if (out.spec.len == 0) return out;
    var known: std.ArrayList([]const u8) = .empty;
    var unknown: std.ArrayList([]const u8) = .empty;
    // Split exactly as `DisabledSet.contains` does, so what is listed here is
    // what the evaluator will actually step over.
    var it = std.mem.splitScalar(u8, out.spec, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t\r\n");
        if (entry.len == 0) continue;
        // With no readable rule file there is no list to check against; the
        // rules check is already failing loudly, so these are reported as
        // naming nothing rather than as confirmed-off protections.
        const names_a_rule = if (rule_set) |set| findRuleNamed(set, entry) != null else false;
        try (if (names_a_rule) &known else &unknown).append(ctx.gpa, entry);
    }
    out.known = try known.toOwnedSlice(ctx.gpa);
    out.unknown = try unknown.toOwnedSlice(ctx.gpa);
    return out;
}

/// Read everything `doctor` and `status` report on. The only function here
/// that touches the filesystem or spawns anything.
fn gatherFacts(ctx: *Ctx, layout: Layout, args: InspectArgs) !Facts {
    const cwd_path: ?[]const u8 = std.process.currentPathAlloc(ctx.io, ctx.gpa) catch null;
    const self_path = std.process.executablePathAlloc(ctx.io, ctx.gpa) catch "";

    // `--rules` outranks the claude dir and CLAUDE_HOOK_RULES_PATH outranks
    // both: the same precedence, through the same call, as every other
    // subcommand. For an install with no overrides `layout.rules_dest` is
    // exactly what the HOME fallback would have produced.
    const load = try loadConfigQuiet(ctx, args.rules_path orelse layout.rules_dest);
    var rule_set: ?rules.RuleSet = null;
    var set_uses: []const u32 = &.{};
    var schema: rules.SchemaCompat = .absent;
    var rules_facts: RulesFacts = switch (load) {
        .no_path => .{ .path = layout.rules_dest, .state = .{ .unreadable = "no path resolved" } },
        .unreadable => |f| .{ .path = f.path, .state = .{ .unreadable = f.err } },
        .invalid => |f| .{ .path = f.path, .state = .{ .invalid = f.err } },
        .schema_refused => |r| .{
            .path = r.path,
            .state = .{ .schema_refused = .{ .declared = r.declared, .text = r.text } },
        },
        .ok => |config| blk: {
            rule_set = config.ruleSet();
            set_uses = config.loaded.set_uses;
            schema = config.loaded.schema;
            break :blk .{ .path = config.path, .state = .{ .unreadable = "unreached" } };
        },
    };
    if (rule_set) |set| {
        // Exactly what `selftest` runs, counted rather than printed.
        var suite = try runSuite(ctx.gpa, set);
        defer suite.deinit();
        const findings = try lintWith(ctx.gpa, set, set_uses);
        const errors = countErrors(findings);
        rules_facts.state = .{ .ok = .{
            .rules = set.rules.len,
            .literal_total = suite.literal.total,
            .literal_passed = suite.literal.passed,
            .generated_total = suite.generated.total,
            .generated_passed = suite.generated.passed,
            .lint_errors = errors,
            .lint_warnings = findings.len - errors,
            .schema = schema,
        } };
    }

    const wiring = try gatherWiring(ctx, layout, rule_set);
    return .{
        .claude_dir = layout.claude_dir,
        .self_path = self_path,
        .now_unix = ctx.now_unix,
        .wiring = wiring,
        .version = try probeVersion(ctx, wiring.wired_command orelse layout.gate_dest, self_path),
        // The binary the harness will actually execute is the one whose
        // signature decides whether there is a gate at all, so this asks about
        // the wired command rather than about where this install would put one.
        // Off macOS it spawns nothing.
        .signature = inspectSignature(ctx.io, ctx.gpa, wiring.wired_command orelse layout.gate_dest),
        .rules = rules_facts,
        .log = try gatherLog(ctx, layout, if (rule_set) |set| set.logging else .{}),
        .overlay = try gatherOverlay(
            ctx,
            args,
            cwd_path,
            rules_facts.path,
            if (rule_set) |set| set.allow_project_overlay else true,
        ),
        .disable = try gatherDisable(ctx, rule_set),
        .env = .{
            .rules_override = ctx.env.rules_path,
            .log_override = ctx.env.log_path,
            .project_dir = ctx.env.project_dir,
        },
    };
}

fn cmdDoctor(ctx: *Ctx, args: InspectArgs) !u8 {
    const layout = (try layoutFor(ctx, args.claude_dir)) orelse return noInstall(ctx);
    const facts = try gatherFacts(ctx, layout, args);
    const checks = try diagnose(ctx.gpa, facts);
    if (args.json) return writeDoctorJson(ctx.gpa, ctx.out, facts, checks);
    return writeDoctorReport(ctx.out, facts, checks, RENDER_WIDTH);
}

fn cmdStatus(ctx: *Ctx, args: InspectArgs) !u8 {
    const layout = (try layoutFor(ctx, args.claude_dir)) orelse return noInstall(ctx);
    const facts = try gatherFacts(ctx, layout, args);
    if (args.json) return writeStatusJson(ctx.out, facts);
    return writeStatus(ctx.gpa, ctx.out, facts);
}

fn cmdDiffDefaults(ctx: *Ctx, args: InspectArgs) !u8 {
    const layout = (try layoutFor(ctx, args.claude_dir)) orelse return noInstall(ctx);
    const live = switch (try loadConfig(ctx, args.rules_path orelse layout.rules_dest)) {
        .code => |code| return code,
        .ok => |config| config,
    };
    // If this fails the binary is broken, not the operator's file — the
    // installer runs the same bytes through the whole selftest before it will
    // install anything, so reaching this is a build that should not exist.
    const shipped = rules.parse(ctx.gpa, DEFAULT_RULES_JSON) catch |err| {
        try ctx.err.print(
            "{s}: the defaults embedded in this binary do not parse: {s}\n",
            .{ PROGRAM, @errorName(err) },
        );
        return EX_SOFTWARE;
    };
    const diff = try diffDefaults(ctx.gpa, shipped.ruleSet(), live.ruleSet());
    if (args.json) return writeDefaultsDiffJson(ctx.gpa, ctx.out, live.path, diff);
    return writeDefaultsDiff(ctx.out, live.path, diff, RENDER_WIDTH);
}

fn noInstall(ctx: *Ctx) !u8 {
    try ctx.err.print(
        "{s}: no install to inspect: pass --claude-dir <dir> or set HOME\n",
        .{PROGRAM},
    );
    return EX_NOINPUT;
}

/// One log generation's bytes, or the reason there are none. A missing file is
/// ordinary; anything else is the operator's problem and gets an exit code.
const LogRead = union(enum) { bytes: []const u8, missing, code: u8 };

fn readLog(ctx: *Ctx, path: []const u8) !LogRead {
    const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .limited(MAX_LOG_BYTES)) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => {
            try ctx.err.print("{s}: cannot read {s}: {s}\n", .{ PROGRAM, path, @errorName(err) });
            return .{ .code = EX_NOINPUT };
        },
    };
    return .{ .bytes = bytes };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Collect a writer-producing call into a heap slice for assertions.
fn capture(allocator: std.mem.Allocator) std.Io.Writer.Allocating {
    return std.Io.Writer.Allocating.init(allocator);
}

// ---- argument parsing -----------------------------------------------------

test "the version constant and build.zig.zon agree" {
    // Single-sourcing the version is a convention; this is the enforcement.
    // Tests run from the project root, as the decision-log fixtures also rely on.
    const zon = try std.Io.Dir.cwd().readFileAlloc(testing.io, "build.zig.zon", testing.allocator, .limited(64 * 1024));
    defer testing.allocator.free(zon);
    var needle_buf: [64]u8 = undefined;
    const needle = try std.fmt.bufPrint(&needle_buf, ".version = \"{s}\"", .{VERSION});
    try testing.expect(std.mem.indexOf(u8, zon, needle) != null);
}

test "the minimum Zig version is written down once" {
    // Three files name the toolchain: `build.zig.zon` (what the build requires),
    // the runner's constants (what its no-toolchain message tells you to
    // install), and the CI workflow (what the runners actually install). Zig is
    // pre-1.0 and breaks between releases, so a disagreement here means the
    // version an operator is told to install is not the version anything was
    // tested with.
    //
    // Two of the three are checked here. The workflow's pin is checked by the
    // workflow itself, against this same file, because a test cannot know which
    // runner image is in use.
    const zon = try std.Io.Dir.cwd().readFileAlloc(testing.io, "build.zig.zon", testing.allocator, .limited(64 * 1024));
    defer testing.allocator.free(zon);
    const at = std.mem.indexOf(u8, zon, ".minimum_zig_version = \"") orelse return error.NoMinimumZigVersion;
    const rest = zon[at + ".minimum_zig_version = \"".len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return error.NoMinimumZigVersion;
    const minimum = rest[0..end];

    // `hookctl` itself is a thin entry point; its constants live in the package
    // it dispatches to, and this reads the one file that declares them.
    const runner = try std.Io.Dir.cwd().readFileAlloc(testing.io, RUNNER_CONSTANTS, testing.allocator, .limited(1024 * 1024));
    defer testing.allocator.free(runner);
    var needle_buf: [64]u8 = undefined;
    const needle = try std.fmt.bufPrint(&needle_buf, "MIN_ZIG = \"{s}\"", .{minimum});
    if (std.mem.indexOf(u8, runner, needle) == null) {
        std.debug.print(
            "build.zig.zon requires Zig {s}, but {s}'s MIN_ZIG says something else\n",
            .{ minimum, RUNNER_CONSTANTS },
        );
        return error.MinimumZigVersionDrifted;
    }
}

test "subcommands and their aliases" {
    try testing.expect(parseArgs(&.{"version"}) == .version);
    try testing.expect(parseArgs(&.{"--version"}) == .version);
    try testing.expect(parseArgs(&.{"-V"}) == .version);
    try testing.expect(parseArgs(&.{"help"}) == .help);
    try testing.expect(parseArgs(&.{"--help"}) == .help);
    try testing.expect(parseArgs(&.{"-h"}) == .help);
    try testing.expect(parseArgs(&.{}) == .help);

    const unknown = parseArgs(&.{"chekc"});
    try testing.expectEqual(Fault.Kind.unknown_subcommand, unknown.fault.kind);
    try testing.expectEqualStrings("chekc", unknown.fault.arg);
}

test "check: positionals are joined, flags may precede them" {
    const parsed = parseArgs(&.{ "check", "--tool", "Bash", "git", "push", "--force", "origin" });
    const args = parsed.check;
    try testing.expectEqualStrings("Bash", args.tool);
    try testing.expectEqual(@as(usize, 4), args.command.len);

    const joined = try joinCommand(testing.allocator, args.command);
    defer testing.allocator.free(joined);
    // Everything after the first positional is command text, dashes included.
    try testing.expectEqualStrings("git push --force origin", joined);
}

test "check: the -- separator lets a command start with a dash" {
    const parsed = parseArgs(&.{ "check", "--quiet", "--", "--weird-command", "-x" });
    try testing.expect(parsed.check.quiet);
    const joined = try joinCommand(testing.allocator, parsed.check.command);
    defer testing.allocator.free(joined);
    try testing.expectEqualStrings("--weird-command -x", joined);
}

test "check: attached and detached flag values, all fields" {
    const parsed = parseArgs(&.{
        "check",
        "--tool=Write",
        "--file-path",
        "/h/.claude/settings.json",
        "--content=hello world",
        "--rules=/tmp/r.json",
    });
    const args = parsed.check;
    try testing.expectEqualStrings("Write", args.tool);
    try testing.expectEqualStrings("/h/.claude/settings.json", args.file_path);
    try testing.expectEqualStrings("hello world", args.content);
    try testing.expectEqualStrings("/tmp/r.json", args.rules_path.?);
    try testing.expectEqual(@as(usize, 0), args.command.len);
}

test "check: nothing to evaluate, missing values, and unknown flags are faults" {
    try testing.expectEqual(Fault.Kind.missing_input, parseArgs(&.{"check"}).fault.kind);
    try testing.expectEqual(Fault.Kind.missing_input, parseArgs(&.{ "check", "--quiet" }).fault.kind);

    const missing = parseArgs(&.{ "check", "--tool" });
    try testing.expectEqual(Fault.Kind.missing_value, missing.fault.kind);
    try testing.expectEqualStrings("--tool", missing.fault.arg);

    const unknown = parseArgs(&.{ "check", "--toool", "Bash", "ls" });
    try testing.expectEqual(Fault.Kind.unknown_flag, unknown.fault.kind);
    try testing.expectEqualStrings("--toool", unknown.fault.arg);

    // A bare "-" is a command word, not a flag.
    const dash = parseArgs(&.{ "check", "cat", "-" });
    try testing.expectEqual(@as(usize, 2), dash.check.command.len);
}

test "selftest and stats argument parsing" {
    const st = parseArgs(&.{ "selftest", "--json", "--rules", "/tmp/r.json" }).selftest;
    try testing.expect(st.json);
    try testing.expectEqualStrings("/tmp/r.json", st.rules_path.?);

    const stats = parseArgs(&.{ "stats", "--since", "7d", "--log=/tmp/l.jsonl", "--json" }).stats;
    try testing.expect(stats.json);
    try testing.expectEqualStrings("/tmp/l.jsonl", stats.log_path.?);
    try testing.expectEqual(@as(i64, 7 * 24 * 3600), stats.since_seconds.?);
    try testing.expectEqualStrings("7d", stats.since_spec.?);

    const bad = parseArgs(&.{ "stats", "--since", "yesterday" });
    try testing.expectEqual(Fault.Kind.bad_duration, bad.fault.kind);
    try testing.expectEqualStrings("yesterday", bad.fault.arg);

    try testing.expectEqual(Fault.Kind.unknown_flag, parseArgs(&.{ "stats", "--nope" }).fault.kind);
    try testing.expectEqual(Fault.Kind.missing_value, parseArgs(&.{ "selftest", "--rules" }).fault.kind);
}

test "duration parsing" {
    try testing.expectEqual(@as(i64, 45), parseDuration("45s").?);
    try testing.expectEqual(@as(i64, 45), parseDuration("45").?);
    try testing.expectEqual(@as(i64, 90 * 60), parseDuration("90m").?);
    try testing.expectEqual(@as(i64, 24 * 3600), parseDuration("24h").?);
    try testing.expectEqual(@as(i64, 7 * 86400), parseDuration("7d").?);
    try testing.expectEqual(@as(i64, 2 * 7 * 86400), parseDuration("2w").?);
    try testing.expectEqual(@as(i64, 0), parseDuration("0d").?);

    try testing.expect(parseDuration("") == null);
    try testing.expect(parseDuration("d") == null);
    try testing.expect(parseDuration("-3d") == null);
    try testing.expect(parseDuration("7 d") == null);
    try testing.expect(parseDuration("7y") == null);
    try testing.expect(parseDuration("99999999999999999999d") == null);
}

test "joined commands keep single spacing regardless of how they were typed" {
    const joined = try joinCommand(testing.allocator, &.{ "cd", "/x", "&&", "ls" });
    defer testing.allocator.free(joined);
    try testing.expectEqualStrings("cd /x && ls", joined);

    const empty = try joinCommand(testing.allocator, &.{});
    defer testing.allocator.free(empty);
    try testing.expectEqualStrings("", empty);
}

// ---- rendering ------------------------------------------------------------

test "span window: short text is shown whole, long text is windowed around the span" {
    const short = "git add -A";
    const whole = spanWindow(short, .{ .start = 4, .len = 3 }, 40);
    try testing.expectEqual(@as(usize, 0), whole.start);
    try testing.expectEqual(short.len, whole.end);
    try testing.expect(!whole.elided_left and !whole.elided_right);

    const long = "x" ** 300;
    const middle = spanWindow(long, .{ .start = 150, .len = 5 }, 40);
    try testing.expect(middle.elided_left and middle.elided_right);
    try testing.expectEqual(@as(usize, 40), middle.end - middle.start);
    try testing.expect(middle.start <= 150 and middle.end >= 155);

    // A span at the very end still lands inside the window.
    const tail = spanWindow(long, .{ .start = 295, .len = 5 }, 40);
    try testing.expect(tail.elided_left and !tail.elided_right);
    try testing.expectEqual(@as(usize, 300), tail.end);
    try testing.expect(tail.start <= 295);
}

test "rendered underline sits under the matched bytes" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    const command = "cd /x && git add -A .";
    // "git add -A" starts at byte 9 and is 10 bytes long.
    try writeRendered(&aw.writer, "  ", command, .{ .start = 9, .len = 10 }, 88);

    const expected = "  " ++ command ++ "\n" ++
        "  " ++ (" " ** 9) ++ "^" ++ ("~" ** 9) ++ "\n";
    try testing.expectEqualStrings(expected, aw.written());
}

test "rendered lines keep alignment through control bytes and multi-byte text" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    // A heredoc: the newline must become one visible column, not a line break.
    const command = "py <<EOF\nprint\nEOF";
    try writeRendered(&aw.writer, "", command, .{ .start = 3, .len = 2 }, 88);
    const out = aw.written();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, out, "\n"));
    try testing.expectEqualStrings("py <<EOF.print.EOF\n   ^~\n", out);

    // A 3-byte codepoint occupies one column, so the caret still lines up.
    var second = capture(testing.allocator);
    defer second.deinit();
    const text = "\u{20ac}\u{20ac} rm -rf /";
    try writeRendered(&second.writer, "", text, .{ .start = 7, .len = 5 }, 88);
    try testing.expectEqualStrings("\u{20ac}\u{20ac} rm -rf /\n   ^~~~~\n", second.written());
}

test "a long field is windowed with ellipsis markers on both sides" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    const text = "a" ** 100 ++ "pkill" ++ "b" ** 100;
    try writeRendered(&aw.writer, "", text, .{ .start = 100, .len = 5 }, 40);

    const out = aw.written();
    var lines = std.mem.splitScalar(u8, out, '\n');
    const body = lines.next().?;
    const underline = lines.next().?;
    try testing.expect(std.mem.startsWith(u8, body, ELIDE));
    try testing.expect(std.mem.endsWith(u8, body, ELIDE));
    try testing.expect(std.mem.indexOf(u8, body, "pkill") != null);
    // The caret column equals the display offset of the match in the line.
    const caret = std.mem.indexOfScalar(u8, underline, '^').?;
    const shown_before = std.mem.indexOf(u8, body, "pkill").?;
    try testing.expectEqual(displayWidth(body[0..shown_before]), displayWidth(underline[0..caret]));
    try testing.expectEqual(@as(usize, 5), std.mem.count(u8, underline, "~") + 1);
}

test "reasons are wrapped at the render width" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeWrapped(&aw.writer, "> ", "one two three four five six seven", 12);
    try testing.expectEqualStrings(
        "> one two\n> three four\n> five six\n> seven\n",
        aw.written(),
    );

    var empty = capture(testing.allocator);
    defer empty.deinit();
    try writeWrapped(&empty.writer, "> ", "   ", 12);
    try testing.expectEqualStrings("", empty.written());
}

test "ellipsize trims to a column count and makes control bytes visible" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("abc", ellipsize(&buf, "abc", 10));
    try testing.expectEqualStrings("abcde" ++ ELIDE, ellipsize(&buf, "abcdefgh", 5));
    try testing.expectEqualStrings("a.b", ellipsize(&buf, "a\nb", 10));
}

// ---- check reporting ------------------------------------------------------

const check_rules = rules.RuleSet{
    .rules = &.{
        .{
            .name = "watch-git",
            .decision = .log,
            .reason = "observational",
            .match = &.{.{ .kind = .word, .value = "git" }},
        },
        .{
            .name = "no-git-add-all",
            .decision = .deny,
            .reason = "Stage paths explicitly.",
            .match = &.{.{ .kind = .tokens, .value = "git add -A" }},
        },
        .{
            .name = "ask-force-push",
            .decision = .ask,
            .reason = "Force pushes rewrite shared history.",
            .match = &.{.{ .kind = .substring, .value = "push --force" }},
        },
        .{
            .name = "allow-changelog",
            .decision = .allow,
            .reason = "pre-approved",
            .match = &.{.{ .kind = .tokens, .value = "touch CHANGELOG.md" }},
        },
    },
};

fn checkReport(allocator: std.mem.Allocator, input: rules.Input, disabled: rules.DisabledSet, quiet: bool) !struct { text: []u8, code: u8 } {
    var aw = capture(allocator);
    errdefer aw.deinit();
    const result = rules.evaluateWith(check_rules, input, disabled);
    const code = try writeCheckReport(&aw.writer, input, result, .{ .quiet = quiet, .width = 88 });
    return .{ .text = try aw.toOwnedSlice(), .code = code };
}

test "check report: a denial names the rule, underlines the match, and exits 1" {
    const report = try checkReport(testing.allocator, .{ .command = "cd /x && git add -A" }, .none, false);
    defer testing.allocator.free(report.text);

    try testing.expectEqual(@as(u8, 1), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "deny     : no-git-add-all  [tokens command \"git add -A\"]") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "^~~~~~~~~") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "Stage paths explicitly.") != null);
    // The shadow rule above the denial is reported too, and does not decide.
    try testing.expect(std.mem.indexOf(u8, report.text, "shadow   : watch-git") != null);
}

test "check report: ask exits 2, allow and no-match exit 0" {
    const ask = try checkReport(testing.allocator, .{ .command = "git push --force" }, .none, false);
    defer testing.allocator.free(ask.text);
    try testing.expectEqual(@as(u8, 2), ask.code);
    try testing.expect(std.mem.indexOf(u8, ask.text, "ask      : ask-force-push") != null);

    const allow = try checkReport(testing.allocator, .{ .command = "touch CHANGELOG.md" }, .none, false);
    defer testing.allocator.free(allow.text);
    try testing.expectEqual(@as(u8, 0), allow.code);
    try testing.expect(std.mem.indexOf(u8, allow.text, "allow    : allow-changelog") != null);

    const clean = try checkReport(testing.allocator, .{ .command = "ls -la" }, .none, false);
    defer testing.allocator.free(clean.text);
    try testing.expectEqual(@as(u8, 0), clean.code);
    try testing.expect(std.mem.indexOf(u8, clean.text, "no-match") != null);
}

test "check report: a bypassed rule is shown as bypassed and the next rule decides" {
    const report = try checkReport(
        testing.allocator,
        .{ .command = "git add -A && git push --force" },
        .init("no-git-add-all"),
        false,
    );
    defer testing.allocator.free(report.text);

    try testing.expect(std.mem.indexOf(u8, report.text, "bypassed : no-git-add-all") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "CLAUDE_HOOK_DISABLE") != null);
    // The ask below it is what is enforced now.
    try testing.expectEqual(@as(u8, 2), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "ask      : ask-force-push") != null);
}

test "check report: quiet prints one word and still carries the exit code" {
    const quiet = try checkReport(testing.allocator, .{ .command = "git add -A" }, .none, true);
    defer testing.allocator.free(quiet.text);
    try testing.expectEqualStrings("deny\n", quiet.text);
    try testing.expectEqual(@as(u8, 1), quiet.code);

    const clean = try checkReport(testing.allocator, .{ .command = "ls" }, .none, true);
    defer testing.allocator.free(clean.text);
    try testing.expectEqualStrings("no-match\n", clean.text);
    try testing.expectEqual(@as(u8, 0), clean.code);
}

test "check report: a Write-shaped call reports the field it matched" {
    const rule_set = rules.RuleSet{
        .rules = &.{.{
            .name = "protect-hook-config",
            .tool = "*",
            .reason = "operator-owned",
            .match = &.{.{ .kind = .substring, .field = .file_path, .value = ".claude/settings.json" }},
        }},
    };
    const input = rules.Input{ .tool = "Write", .file_path = "/h/.claude/settings.json", .content = "{}" };
    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeCheckReport(&aw.writer, input, rules.evaluate(rule_set, input), .{});
    try testing.expectEqual(@as(u8, 1), code);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "tool     : Write") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "[substring file_path \".claude/settings.json\"]") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "^~~~~~~~~~~~~~~~~~~~") != null);
}

// ---- check: the project overlay -------------------------------------------

test "check: --project-dir parses, attached or detached" {
    const detached = parseArgs(&.{ "check", "--project-dir", "/work/repo", "git", "add", "-A" }).check;
    try testing.expectEqualStrings("/work/repo", detached.project_dir.?);
    try testing.expectEqual(@as(usize, 3), detached.command.len);

    const attached = parseArgs(&.{ "check", "--project-dir=/work/other", "ls" }).check;
    try testing.expectEqualStrings("/work/other", attached.project_dir.?);

    // Absent means "defer to $CLAUDE_PROJECT_DIR", which is the null case.
    try testing.expect(parseArgs(&.{ "check", "ls" }).check.project_dir == null);
    try testing.expectEqual(Fault.Kind.missing_value, parseArgs(&.{ "check", "--project-dir" }).fault.kind);
}

/// A repo that pre-approves one sweep the global file forbids and adds a
/// prohibition of its own.
const overlay_rules = [_]rules.Rule{
    .{
        .name = "repo-allows-add-all",
        .decision = .allow,
        .reason = "generated tree, staged wholesale by design",
        .match = &.{.{ .kind = .tokens, .value = "git add -A" }},
    },
    .{
        .name = "repo-no-deploy",
        .decision = .deny,
        .reason = "deploys go through CI in this repo",
        .match = &.{.{ .kind = .tokens, .value = "make deploy" }},
    },
};

test "layerOf: a rule is attributed by the slice it lives in" {
    try testing.expectEqual(Layer.project, layerOf(&overlay_rules, &overlay_rules[0]).?);
    try testing.expectEqual(Layer.project, layerOf(&overlay_rules, &overlay_rules[1]).?);
    try testing.expectEqual(Layer.global, layerOf(&overlay_rules, &check_rules.rules[0]).?);

    // With no overlay there is nothing to disambiguate, so nothing is labelled.
    try testing.expect(layerOf(&.{}, &check_rules.rules[0]) == null);
    try testing.expectEqualStrings("", Layer.suffix(null));
    try testing.expectEqualStrings(" (project)", Layer.suffix(.project));
    try testing.expectEqualStrings(" (global)", Layer.suffix(.global));
}

fn overlayReport(allocator: std.mem.Allocator, input: rules.Input, options: CheckOptions) !struct { text: []u8, code: u8 } {
    var aw = capture(allocator);
    errdefer aw.deinit();
    const result = rules.evaluateOverlay(options.project, check_rules.rules, input, .none);
    const code = try writeCheckReport(&aw.writer, input, result, options);
    return .{ .text = try aw.toOwnedSlice(), .code = code };
}

test "check report: a project allow pre-empts the global deny, and says so" {
    const report = try overlayReport(testing.allocator, .{ .command = "git add -A" }, .{
        .project = &overlay_rules,
        .project_path = "/work/repo/.claude/hook-rules.json",
        .rules_path = "/home/u/.claude/hook-rules.json",
    });
    defer testing.allocator.free(report.text);

    // Without the overlay this is a denial (exit 1); with it, nothing stops it.
    try testing.expectEqual(@as(u8, 0), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "allow    : repo-allows-add-all (project)") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "project  : /work/repo/.claude/hook-rules.json (2 rule(s), evaluated first)") != null);
    // The global shadow rule is still reported, and labelled as global.
    try testing.expect(std.mem.indexOf(u8, report.text, "shadow   : watch-git (global)") != null);
}

test "check report: a global rule the overlay is silent about is labelled global" {
    const report = try overlayReport(testing.allocator, .{ .command = "git push --force" }, .{
        .project = &overlay_rules,
        .project_path = "/work/repo/.claude/hook-rules.json",
    });
    defer testing.allocator.free(report.text);
    try testing.expectEqual(@as(u8, 2), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "ask      : ask-force-push (global)") != null);
}

test "check report: with no overlay, nothing is labelled and the output is unchanged" {
    const report = try overlayReport(testing.allocator, .{ .command = "git add -A" }, .{});
    defer testing.allocator.free(report.text);
    try testing.expectEqual(@as(u8, 1), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "deny     : no-git-add-all  [tokens") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "(global)") == null);
    try testing.expect(std.mem.indexOf(u8, report.text, "project  :") == null);
}

test "check report: a resolved-but-unusable overlay states why it contributed nothing" {
    const report = try overlayReport(testing.allocator, .{ .command = "make deploy prod" }, .{
        .project_path = "/work/repo/.claude/hook-rules.json",
        .project_note = "not read: the global file sets allow_project_overlay to false",
    });
    defer testing.allocator.free(report.text);

    // The repo's deny never applies, so nothing fires at all.
    try testing.expectEqual(@as(u8, 0), report.code);
    try testing.expect(std.mem.indexOf(
        u8,
        report.text,
        "project  : /work/repo/.claude/hook-rules.json (not read: the global file sets allow_project_overlay to false)",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "no-match") != null);
}

// ---- selftest -------------------------------------------------------------

const selftest_fixture = @embedFile("testdata/selftest-rules.json");

test "runCase: pass, decision mismatch, and expect_rule mismatch" {
    const rule_set = rules.RuleSet{
        .rules = check_rules.rules,
        .tests = &.{
            .{ .command = "git add -A", .expect = .deny, .expect_rule = "no-git-add-all" },
            .{ .command = "ls -la", .expect = .none },
            // Wrong decision.
            .{ .command = "git add -A", .expect = .ask },
            // Right decision, wrong rule.
            .{ .command = "git add -A", .expect = .deny, .expect_rule = "watch-git" },
            // Expected nothing, got a denial.
            .{ .command = "git add -A", .expect = .none },
        },
    };
    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();
    const results = suite.results;

    try testing.expect(results[0].ok);
    try testing.expectEqual(@as(usize, 1), results[0].index);
    try testing.expectEqual(@as(usize, 0), suite.generated.total);
    try testing.expectEqual(results.len, suite.literal.total);
    try testing.expectEqualStrings("no-git-add-all", results[0].got_rule.?);
    try testing.expect(results[1].ok);
    try testing.expectEqualStrings("none", results[1].gotWord());

    try testing.expect(!results[2].ok);
    try testing.expectEqualStrings("deny", results[2].gotWord());
    try testing.expect(!results[3].ok);
    try testing.expectEqualStrings("no-git-add-all", results[3].got_rule.?);
    try testing.expect(!results[4].ok);
}

test "selftest report: failures are explained and set the exit code" {
    const rule_set = rules.RuleSet{
        .rules = check_rules.rules,
        .tests = &.{
            .{ .command = "git add -A", .expect = .deny, .expect_rule = "no-git-add-all" },
            .{ .command = "git add -A", .expect = .ask, .expect_rule = "ask-force-push" },
        },
    };
    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();

    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeSelftestReport(&aw.writer, "/tmp/r.json", &suite, &.{});
    const out = aw.written();

    try testing.expectEqual(@as(u8, 1), code);
    try testing.expect(std.mem.indexOf(u8, out, "PASS  #1    Bash: git add -A") != null);
    try testing.expect(std.mem.indexOf(u8, out, "FAIL  #2") != null);
    try testing.expect(std.mem.indexOf(u8, out, "expected ask (ask-force-push), got deny (no-git-add-all)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "1 literal + 0 generated cases passed (1 of 2 FAILED)") != null);
}

test "selftest report: lint errors fail an otherwise green suite" {
    const findings = [_]Finding{
        .{ .level = .warn, .rule = "allow-changelog", .message = "warned" },
        .{ .level = .@"error", .rule = "dup", .message = "broken" },
    };
    var empty = Suite{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    defer empty.deinit();

    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeSelftestReport(&aw.writer, null, &empty, &findings);
    try testing.expectEqual(@as(u8, 1), code);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "(no test cases in this rule file)") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "error dup: broken") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "warn  allow-changelog: warned") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        aw.written(),
        "0 literal + 0 generated cases passed, 1 lint error(s), 1 warning(s) -> FAIL",
    ) != null);

    // Warnings alone are not a failure.
    var warn_only = capture(testing.allocator);
    defer warn_only.deinit();
    try testing.expectEqual(@as(u8, 0), try writeSelftestReport(&warn_only.writer, null, &empty, findings[0..1]));
}

test "lint: the checks that catch a rule which cannot fire" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "dup", .reason = "r", .match = &.{.{ .value = "a" }} },
            .{ .name = "dup", .reason = "r", .match = &.{.{ .value = "b" }} },
            .{ .name = "negative-only", .reason = "r", .match_none = &.{.{ .value = "x" }} },
            .{ .name = "star", .reason = "r", .match = &.{.{ .kind = .tokens, .value = "rm *" }} },
            .{ .name = "bare-star-word", .reason = "r", .match = &.{.{ .kind = .word, .value = "*" }} },
            .{ .name = "blank", .reason = "r", .match = &.{.{ .value = "  " }} },
            .{ .name = "no-reason", .reason = "", .match = &.{.{ .value = "a" }} },
            .{ .name = "grant", .decision = .allow, .reason = "r", .match = &.{.{ .value = "a" }} },
        },
        .tests = &.{
            .{ .command = "a", .expect = .deny, .expect_rule = "no-such-rule" },
            .{ .command = "a", .expect = .deny, .expect_rule = "dup" },
        },
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "dup", "duplicate rule name"));
    try testing.expect(hasFinding(findings, .@"error", "negative-only", "no positive matchers"));
    try testing.expect(hasFinding(findings, .@"error", "star", "matches nothing"));
    try testing.expect(hasFinding(findings, .@"error", "bare-star-word", "matches nothing"));
    try testing.expect(hasFinding(findings, .@"error", "blank", "empty value"));
    try testing.expect(hasFinding(findings, .warn, "no-reason", "empty reason"));
    try testing.expect(hasFinding(findings, .warn, "grant", "skips the permission PROMPT but not the permission RULES"));
    try testing.expect(hasFinding(findings, .@"error", "no-such-rule", "does not exist"));

    // The test that names a real rule produces nothing.
    var unknown_refs: usize = 0;
    for (findings) |f| {
        if (f.test_index != null) unknown_refs += 1;
    }
    try testing.expectEqual(@as(usize, 1), unknown_refs);
    try testing.expectEqual(@as(usize, 6), countErrors(findings));
}

test "lint: a decision an event cannot express is an ERROR, not a silent no-op" {
    // The failure mode this whole check exists for. Every rule below parses,
    // selftests as a rule, and enforces exactly nothing — because the event it
    // is scoped to has no field in its response envelope to carry the answer.
    const rule_set = rules.RuleSet{
        .rules = &.{
            // Advisory events: thirteen of the thirty can refuse nothing.
            .{ .name = "deny-on-session-start", .event = .SessionStart, .reason = "r", .match = &.{.{ .field = .trigger, .value = "startup" }} },
            .{ .name = "ask-on-notification", .event = .Notification, .decision = .ask, .reason = "r", .match = &.{.{ .field = .trigger, .value = "idle_prompt" }} },
            .{ .name = "allow-on-file-changed", .event = .FileChanged, .decision = .allow, .reason = "r", .match = &.{.{ .field = .file_path, .value = ".envrc" }} },
            // Blockable, but with no spelling for this decision.
            .{ .name = "ask-on-stop", .event = .Stop, .decision = .ask, .reason = "r", .match = &.{.{ .field = .message, .value = "TODO" }} },
            .{ .name = "allow-on-prompt", .event = .UserPromptSubmit, .decision = .allow, .reason = "r", .match = &.{.{ .field = .prompt, .value = "x" }} },
            // And the same events observed instead of enforced: no finding.
            .{ .name = "log-on-session-start", .event = .SessionStart, .decision = .log, .reason = "r", .match = &.{.{ .field = .trigger, .value = "startup" }} },
            .{ .name = "log-on-message-display", .event = .MessageDisplay, .decision = .log, .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
        },
        .tests = &.{.{ .command = "a", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "deny-on-session-start", "ADVISORY event"));
    try testing.expect(hasFinding(findings, .@"error", "ask-on-notification", "ADVISORY event"));
    try testing.expect(hasFinding(findings, .@"error", "allow-on-file-changed", "ADVISORY event"));
    // A `deny` rule on an advisory event is told what to write instead.
    try testing.expect(hasFinding(findings, .@"error", "deny-on-session-start", "\"decision\": \"log\""));

    try testing.expect(hasFinding(findings, .@"error", "ask-on-stop", "no field for"));
    try testing.expect(hasFinding(findings, .@"error", "allow-on-prompt", "no field for"));

    // The two shadow rules are fine: observing an event that cannot refuse
    // anything is the main thing an advisory event is good for.
    for (findings) |f| {
        const name = f.rule orelse continue;
        try testing.expect(!eq(name, "log-on-session-start"));
        try testing.expect(!eq(name, "log-on-message-display"));
    }
    try testing.expectEqual(@as(usize, 5), countErrors(findings));
}

test "lint: a matcher an event's payload cannot feed is an ERROR" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            // `Stop` carries a message and a stop reason. It does not carry a
            // command, a file path, or a prompt.
            .{ .name = "stop-reads-command", .event = .Stop, .reason = "r", .match = &.{.{ .field = .command, .value = "rm" }} },
            .{ .name = "stop-reads-file-path", .event = .Stop, .reason = "r", .match = &.{.{ .field = .file_path, .value = "/etc" }} },
            // A structural kind is a SHELL PARSER. Pointing one at a prompt or a
            // tool result looks entirely reasonable and is meaningless.
            .{ .name = "shell-parser-on-a-prompt", .event = .UserPromptSubmit, .reason = "r", .match = &.{.{ .kind = .command_word, .field = .prompt, .value = "rm" }} },
            .{ .name = "shell-parser-on-output", .event = .PostToolUse, .reason = "r", .match = &.{.{ .kind = .argv, .field = .output, .value = "rm" }} },
            .{ .name = "signal-on-a-message", .event = .Stop, .reason = "r", .match = &.{.{ .kind = .signal, .field = .message, .value = "eval_present" }} },
            // Textual kinds on the new fields are exactly right, and silent.
            .{ .name = "word-on-a-prompt", .event = .UserPromptSubmit, .reason = "r", .match = &.{.{ .kind = .word, .field = .prompt, .value = "force-push" }} },
            .{ .name = "substring-on-output", .event = .PostToolUse, .decision = .log, .reason = "r", .match = &.{.{ .kind = .substring, .field = .output, .value = "Traceback" }} },
            .{ .name = "tokens-on-a-message", .event = .Stop, .reason = "r", .match = &.{.{ .kind = .tokens, .field = .message, .value = "not done" }} },
        },
        .tests = &.{.{ .command = "a", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "stop-reads-command", "does not carry"));
    try testing.expect(hasFinding(findings, .@"error", "stop-reads-file-path", "does not carry"));
    try testing.expect(hasFinding(findings, .@"error", "shell-parser-on-a-prompt", "parse a SHELL COMMAND"));
    try testing.expect(hasFinding(findings, .@"error", "shell-parser-on-output", "parse a SHELL COMMAND"));
    try testing.expect(hasFinding(findings, .@"error", "signal-on-a-message", "parse a SHELL COMMAND"));

    for (findings) |f| {
        const name = f.rule orelse continue;
        try testing.expect(!eq(name, "word-on-a-prompt"));
        try testing.expect(!eq(name, "substring-on-output"));
        try testing.expect(!eq(name, "tokens-on-a-message"));
    }
}

test "lint: a tool on an event with no tool name, and an unverified event, are reported" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "tool-on-stop", .event = .Stop, .tool = "Bash", .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
            // `"*"` is not a mistake: it says "every tool", which is true of an
            // event with no tools at all.
            .{ .name = "star-on-stop", .event = .Stop, .tool = "*", .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
            // Unspecified is how every rule for these events is written.
            .{ .name = "quiet-on-stop", .event = .Stop, .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
            // Supported, and flagged: nobody has confirmed the payload.
            .{ .name = "on-task-created", .event = .TaskCreated, .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
            // An event with nothing matchable at all.
            .{ .name = "on-post-tool-batch", .event = .PostToolBatch, .reason = "r", .match = &.{.{ .value = "x" }} },
        },
        .tests = &.{.{ .command = "a", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "tool-on-stop", "carries no tool_name"));
    try testing.expect(hasFinding(findings, .warn, "on-task-created", "UNVERIFIED"));
    try testing.expect(hasFinding(findings, .@"error", "on-post-tool-batch", "no matchable payload field"));

    for (findings) |f| {
        const name = f.rule orelse continue;
        try testing.expect(!eq(name, "star-on-stop"));
        try testing.expect(!eq(name, "quiet-on-stop"));
    }
}

test "lint: every event in the catalog can carry a shadow rule without complaint" {
    // The table's own consistency, checked from the outside: for each event,
    // build a `log` rule reading a field that event actually supplies, and
    // expect silence. An event that cannot even be observed is either a table
    // row with no bindings (named, and reported as such) or a bug.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    for (rules.Events.all()) |*d| {
        if (d.hasNoMatchableField()) continue;
        const field = d.bindings[0].field;
        const rule_set = rules.RuleSet{
            .rules = &.{.{
                .name = "observe",
                .event = d.event,
                .decision = .log,
                .reason = "r",
                .match = &.{.{ .kind = .substring, .field = field, .value = "x" }},
            }},
            .tests = &.{.{ .command = "a", .expect = .none }},
        };
        const findings = try lintWith(gpa, rule_set, &.{});
        for (findings) |f| {
            const name = f.rule orelse continue;
            if (!eq(name, "observe")) continue;
            // Only the unverified rows may say anything, and only a warning.
            if (f.level == .warn and !d.verified) continue;
            std.debug.print("event {s}: unexpected {s}: {s}\n", .{ d.name(), @tagName(f.level), f.message });
            return error.TestUnexpectedResult;
        }
    }
}

test "lint: the group checks reach inside the nesting" {
    // Every mistake a group makes possible, each in its own rule, and each one
    // a rule that would otherwise look like protection and provide none.
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "empty-group", .reason = "r", .match = &.{.{ .any = &.{} }} },
            .{
                .name = "star-in-group",
                .reason = "r",
                .match = &.{.{ .any = &.{ .{ .kind = .command_word, .value = "rm" }, .{ .kind = .argv, .value = "*" } } }},
            },
            .{
                .name = "structural-on-content",
                .reason = "r",
                .match_all = &.{.{ .all = &.{.{ .any = &.{.{ .kind = .command_word, .field = .content, .value = "pkill" }} }} }},
            },
            .{
                .name = "blank-in-group",
                .reason = "r",
                .match_none = &.{.{ .any = &.{.{ .kind = .word, .value = " " }} }},
            },
            .{
                .name = "two-operators",
                .reason = "r",
                .match = &.{.{ .any = &.{.{ .value = "a" }}, .none = &.{.{ .value = "b" }} }},
            },
            .{
                .name = "group-with-a-value",
                .reason = "r",
                .match = &.{.{ .value = "a", .any = &.{.{ .value = "b" }} }},
            },
            .{
                .name = "bad-signal-in-group",
                .reason = "r",
                .match = &.{.{ .any = &.{.{ .kind = .signal, .value = "heredoc" }} }},
            },
            .{
                .name = "negative-only-group",
                .reason = "r",
                .match_all = &.{.{ .none = &.{.{ .value = "x" }} }},
            },
            .{
                .name = "bad-stage",
                .reason = "r",
                .match = &.{.{ .kind = .stage, .value = "piped" }},
            },
            .{
                .name = "bad-shape",
                .reason = "r",
                .match = &.{.{ .kind = .shape, .value = "pipes maximum 2" }},
            },
            .{
                .name = "shape-in-invocation",
                .reason = "r",
                .match = &.{.{ .invocation = &.{
                    .{ .kind = .command_word, .value = "psql" },
                    .{ .kind = .shape, .value = "pipes > 1" },
                } }},
            },
            .{
                .name = "too-deep",
                .reason = "r",
                .match = &.{
                    .{ .any = &.{.{ .all = &.{.{ .any = &.{.{ .all = &.{.{ .any = &.{.{ .value = "deep" }} }} }} }} }} },
                },
            },
        },
        .tests = &.{.{ .command = "a", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "empty-group", "empty group"));
    try testing.expect(hasFinding(findings, .@"error", "star-in-group", "matches nothing"));
    try testing.expect(hasFinding(findings, .@"error", "structural-on-content", "non-command field"));
    try testing.expect(hasFinding(findings, .@"error", "blank-in-group", "empty value"));
    try testing.expect(hasFinding(findings, .@"error", "two-operators", "more than one of any/all/none"));
    try testing.expect(hasFinding(findings, .@"error", "group-with-a-value", "also carries a matcher value"));
    try testing.expect(hasFinding(findings, .@"error", "bad-signal-in-group", "unknown signal name"));
    try testing.expect(hasFinding(findings, .@"error", "bad-stage", "unknown stage predicate"));
    try testing.expect(hasFinding(findings, .@"error", "bad-shape", "shape value is not"));
    try testing.expect(hasFinding(findings, .warn, "shape-in-invocation", "not narrowed by it"));
    try testing.expect(hasFinding(findings, .@"error", "negative-only-group", "no positive condition"));
    try testing.expect(hasFinding(findings, .@"error", "too-deep", "nested too deeply"));

    // An empty group is also a rule that can never fire, and both halves of
    // that are worth saying: the shape is wrong AND the rule is dead.
    try testing.expect(hasFinding(findings, .@"error", "empty-group", "no positive condition"));
}

test "lint: a rule set that uses groups correctly is clean" {
    const rule_set = rules.RuleSet{
        .rules = &.{.{
            .name = "destructive-sql",
            .reason = "r",
            .match_all = &.{
                .{ .any = &.{ .{ .kind = .argv, .value = "DROP TABLE" }, .{ .kind = .argv, .value = "drop table" } } },
                .{ .any = &.{ .{ .kind = .command_word, .value = "psql" }, .{ .kind = .command_word, .value = "mysql" } } },
            },
        }},
        .tests = &.{.{ .command = "psql -c \"DROP TABLE t\"", .expect = .deny }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), findings.len);
}

test "lint: the invocation, flag and ignore_case shapes" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "empty-invocation", .reason = "r", .match = &.{.{ .invocation = &.{} }} },
            .{
                .name = "bad-flag",
                .reason = "r",
                .match = &.{.{ .invocation = &.{ .{ .kind = .command_word, .value = "rm" }, .{ .kind = .flag, .value = "/etc" } } }},
            },
            .{
                .name = "dash-only-flag",
                .reason = "r",
                .match = &.{.{ .invocation = &.{ .{ .kind = .command_word, .value = "rm" }, .{ .kind = .flag, .value = "--" } } }},
            },
            .{
                .name = "folded-command-word",
                .reason = "r",
                .match = &.{.{ .kind = .command_word, .value = "psql", .ignore_case = true }},
            },
            .{
                .name = "folded-flag",
                .reason = "r",
                .match = &.{.{ .invocation = &.{ .{ .kind = .command_word, .value = "rm" }, .{ .kind = .flag, .value = "r", .ignore_case = true } } }},
            },
            .{
                .name = "folded-signal",
                .reason = "r",
                .match = &.{.{ .kind = .signal, .value = "eval_present", .ignore_case = true }},
            },
            .{
                .name = "unscoped-flag",
                .reason = "r",
                .match = &.{.{ .kind = .flag, .value = "f" }},
            },
            .{
                .name = "nested-invocation",
                .reason = "r",
                .match = &.{.{ .invocation = &.{ .{ .kind = .command_word, .value = "rm" }, .{ .invocation = &.{.{ .kind = .flag, .value = "r" }} } } }},
            },
            .{
                .name = "invocation-too-deep",
                .reason = "r",
                .match = &.{
                    .{ .any = &.{.{ .all = &.{.{ .any = &.{.{ .all = &.{.{ .invocation = &.{.{ .kind = .command_word, .value = "rm" }} }} }} }} }} },
                },
            },
        },
        .tests = &.{.{ .command = "a", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "empty-invocation", "empty group"));
    try testing.expect(hasFinding(findings, .@"error", "bad-flag", "not a plausible option"));
    try testing.expect(hasFinding(findings, .@"error", "dash-only-flag", "not a plausible option"));
    try testing.expect(hasFinding(findings, .@"error", "folded-command-word", "ignore_case on a kind"));
    try testing.expect(hasFinding(findings, .@"error", "folded-flag", "ignore_case on a kind"));
    try testing.expect(hasFinding(findings, .@"error", "folded-signal", "ignore_case on a kind"));
    try testing.expect(hasFinding(findings, .@"error", "invocation-too-deep", "nested too deeply"));

    // Two warnings, both about a shape that RUNS but does not mean what it
    // looks like: an unscoped short flag, and a re-binding that cannot rebind.
    try testing.expect(hasFinding(findings, .warn, "unscoped-flag", "outside an invocation group"));
    try testing.expect(hasFinding(findings, .warn, "nested-invocation", "inside another invocation group"));

    // A long flag outside a group is fine — `--force` means one thing.
    try testing.expect(!hasFinding(findings, .warn, "bad-flag", "outside an invocation group"));
}

test "lint: a rule using invocation, flag and ignore_case correctly is clean" {
    const rule_set = rules.RuleSet{
        .rules = &.{.{
            .name = "destructive-sql",
            .reason = "r",
            .match_all = &.{.{ .invocation = &.{
                .{ .any = &.{ .{ .kind = .command_word, .value = "psql" }, .{ .kind = .command_word, .value = "mysql" } } },
                .{ .kind = .argv, .value = "DROP TABLE", .ignore_case = true },
                .{ .any = &.{ .{ .kind = .flag, .value = "c" }, .{ .kind = .flag, .value = "--command" } } },
            } }},
        }},
        .tests = &.{.{ .command = "psql -c \"drop table t\"", .expect = .deny }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), findings.len);
}

fn hasFinding(findings: []const Finding, level: Level, rule: ?[]const u8, needle: []const u8) bool {
    for (findings) |finding| {
        if (finding.level != level) continue;
        if (rule) |want| {
            const got = finding.rule orelse continue;
            if (!eq(got, want)) continue;
        }
        if (std.mem.indexOf(u8, finding.message, needle) != null) return true;
    }
    return false;
}

// ---- generated cases ------------------------------------------------------

test "a generator expands to the whole product, and to near misses from it" {
    const json =
        \\{ "rules": [ { "name": "rm-home", "reason": "r", "match_all": [ { "invocation": [
        \\  { "kind": "command_word", "value": "rm" },
        \\  { "kind": "flags", "value": "r|R|--recursive" },
        \\  { "kind": "path_class", "value": "home_or_root" } ] } ] } ],
        \\  "tests": [
        \\    { "command": "rm -rf /", "expect": "deny", "expect_rule": "rm-home" },
        \\    { "expect": "deny", "expect_rule": "rm-home", "generate": {
        \\      "command": "rm {flags} {target}",
        \\      "axes": [
        \\        { "name": "flags", "values": ["-rf", "-fr", "-r -f"] },
        \\        { "name": "target", "values": ["/", "~", "$HOME/.config", "/usr/local/../.."] } ],
        \\      "near_miss": [
        \\        { "name": "flags", "values": ["-f"] },
        \\        { "name": "target", "values": ["./build", "/tmp/x"] } ] } } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();

    // 3 flags x 4 targets positives; 1 near-miss flag x 4 targets plus
    // 2 near-miss targets x 3 flags negatives.
    try testing.expectEqual(@as(usize, 1), suite.literal.total);
    try testing.expectEqual(@as(usize, 12 + 4 + 6), suite.generated.total);
    try testing.expectEqual(suite.total(), suite.passed());

    // The literal case comes first, in file order, and every generated case
    // names the declaration it came from.
    try testing.expectEqual(CaseSource.literal, suite.results[0].source);
    try testing.expectEqual(CaseSource.generated, suite.results[1].source);
    try testing.expectEqual(@as(usize, 2), suite.results[1].origin);
    try testing.expectEqualStrings("rm -rf /", suite.results[1].input.command);
    // The positives assert the declared decision; the near misses assert none.
    try testing.expectEqual(rules.ExpectDecision.deny, suite.results[12].expect);
    try testing.expectEqual(rules.ExpectDecision.none, suite.results[13].expect);
    try testing.expect(std.mem.startsWith(u8, suite.results[13].input.command, "rm -f "));

    var aw = capture(testing.allocator);
    defer aw.deinit();
    _ = try writeSelftestReport(&aw.writer, null, &suite, &.{});
    try testing.expect(std.mem.indexOf(u8, aw.written(), "[generated from #2]") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        aw.written(),
        "1 literal + 22 generated cases passed",
    ) != null);
}

test "a generated case that fails names the generator, not a phantom test" {
    // The rule only catches `-rf` as one bundle, so the `-r -f` expansion must
    // fail — which is exactly the trapdoor a generator exists to find.
    const json =
        \\{ "rules": [ { "name": "narrow", "reason": "r", "match_all": [ { "invocation": [
        \\  { "kind": "command_word", "value": "rm" },
        \\  { "kind": "flag", "value": "rf" } ] } ] } ],
        \\  "tests": [ { "expect": "deny", "expect_rule": "narrow", "generate": {
        \\    "command": "rm {flags} /x",
        \\    "axes": [ { "name": "flags", "values": ["-rf", "-r -f"] } ],
        \\    "near_miss": [ { "name": "flags", "values": ["-v"] } ] } } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    var suite = try runSuite(testing.allocator, loaded.ruleSet());
    defer suite.deinit();

    try testing.expectEqual(@as(usize, 3), suite.generated.total);
    try testing.expectEqual(@as(usize, 2), suite.generated.passed);

    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeSelftestReport(&aw.writer, null, &suite, &.{});
    try testing.expectEqual(@as(u8, 1), code);
    const out = aw.written();
    try testing.expect(std.mem.indexOf(u8, out, "FAIL  #2") != null);
    try testing.expect(std.mem.indexOf(u8, out, "rm -r -f /x") != null);
    try testing.expect(std.mem.indexOf(u8, out, "[generated from #1]") != null);
    try testing.expect(std.mem.indexOf(u8, out, "(1 of 3 FAILED)") != null);
}

test "template rendering: substitution, an empty value, and an unknown placeholder" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("rm -rf /", try renderTemplate(a, "rm {f} {t}", &.{
        .{ .name = "f", .value = "-rf" },
        .{ .name = "t", .value = "/" },
    }));
    // An empty axis value leaves no double space behind.
    try testing.expectEqualStrings("rm /", try renderTemplate(a, "rm {f} {t}", &.{
        .{ .name = "f", .value = "" },
        .{ .name = "t", .value = "/" },
    }));
    // A placeholder with no axis is left verbatim: the lint reports it, and
    // deleting it silently would assert something nobody wrote.
    try testing.expectEqualStrings("rm {nope} /", try renderTemplate(a, "rm {nope} {t}", &.{
        .{ .name = "t", .value = "/" },
    }));
}

test "lint: the ways a generator can quietly expand to nothing" {
    const cases = [_]struct { needle: []const u8, json: []const u8 }{
        .{
            .needle = "generate axis has no values",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "expect": "deny", "generate": { "command": "rm {f}",
            \\    "axes": [ { "name": "f", "values": [] } ] } } ] }
            ,
        },
        .{
            .needle = "does not appear in the command template",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "expect": "deny", "generate": { "command": "rm -rf /",
            \\    "axes": [ { "name": "f", "values": ["-rf"] } ] } } ] }
            ,
        },
        .{
            .needle = "placeholder with no matching axis",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "expect": "deny", "generate": { "command": "rm {f} {t}",
            \\    "axes": [ { "name": "f", "values": ["-rf"] } ] } } ] }
            ,
        },
        .{
            .needle = "near_miss names an axis the generator does not declare",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "expect": "deny", "generate": { "command": "rm {f}",
            \\    "axes": [ { "name": "f", "values": ["-rf"] } ],
            \\    "near_miss": [ { "name": "t", "values": ["./x"] } ] } } ] }
            ,
        },
        .{
            .needle = "both a generate block and a literal input",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "command": "rm -rf /", "expect": "deny", "generate": { "command": "rm {f}",
            \\    "axes": [ { "name": "f", "values": ["-rf"] } ] } } ] }
            ,
        },
        .{
            .needle = "declares no axes",
            .json =
            \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "x" } ] } ],
            \\  "tests": [ { "expect": "deny", "generate": { "command": "rm -rf /", "axes": [] } } ] }
            ,
        },
    };
    for (cases) |c| {
        var loaded = try rules.parse(testing.allocator, c.json);
        defer loaded.deinit();
        const findings = try lintWith(testing.allocator, loaded.ruleSet(), loaded.set_uses);
        defer testing.allocator.free(findings);
        if (!hasFinding(findings, .@"error", null, c.needle)) {
            std.debug.print("lint missed \"{s}\" in: {s}\n", .{ c.needle, c.json });
            return error.LintFindingMissing;
        }
    }
}

test "lint: a generator with no near misses is a warning, not an error" {
    const json =
        \\{ "rules": [ { "name": "r", "reason": "r", "match": [ { "value": "rm" } ] } ],
        \\  "tests": [ { "expect": "deny", "generate": { "command": "rm {f} /",
        \\    "axes": [ { "name": "f", "values": ["-rf"] } ] } } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    const findings = try lintWith(testing.allocator, loaded.ruleSet(), loaded.set_uses);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), countErrors(findings));
    try testing.expect(hasFinding(findings, .warn, null, "no near_miss negatives"));
}

test "lint: the new matcher kinds are checked for shape and for scope" {
    const json =
        \\{ "rules": [
        \\  { "name": "bad-flags", "reason": "r", "match": [
        \\    { "kind": "flags", "value": "/etc" } ] },
        \\  { "name": "unscoped-flags", "reason": "r", "match": [
        \\    { "kind": "flags", "value": "r|R" } ] },
        \\  { "name": "scoped-flags", "reason": "r", "match": [ { "invocation": [
        \\    { "kind": "command_word", "value": "rm" },
        \\    { "kind": "flags", "value": "r|R" } ] } ] },
        \\  { "name": "long-flags", "reason": "r", "match": [
        \\    { "kind": "flags", "value": "--recursive" } ] },
        \\  { "name": "bad-class", "reason": "r", "match": [
        \\    { "kind": "path_class", "value": "nope" } ] },
        \\  { "name": "wrong-kind-class", "reason": "r", "match": [
        \\    { "kind": "path_class", "value": "db_clients" } ] },
        \\  { "name": "folded-flags", "reason": "r", "match": [
        \\    { "kind": "flags", "value": "--force", "ignore_case": true } ] } ],
        \\  "tests": [ { "command": "x", "expect": "none" } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    const findings = try lintWith(testing.allocator, loaded.ruleSet(), loaded.set_uses);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "bad-flags", "not an option set"));
    try testing.expect(hasFinding(findings, .warn, "unscoped-flags", "short flags matcher outside"));
    try testing.expect(!hasFinding(findings, .warn, "scoped-flags", "short flags matcher outside"));
    // An all-long option set says which program it means by its own spelling.
    try testing.expect(!hasFinding(findings, .warn, "long-flags", "short flags matcher outside"));
    try testing.expect(hasFinding(findings, .@"error", "bad-class", "not a built-in path class"));
    try testing.expect(hasFinding(findings, .@"error", "wrong-kind-class", "not a built-in path class"));
    try testing.expect(hasFinding(findings, .@"error", "folded-flags", "ignore_case on a kind"));
}

test "lint: an unused set and a one-member set are warnings" {
    const json =
        \\{ "sets": { "used": ["a", "b"], "unused": ["c", "d"], "single": ["e"] },
        \\  "rules": [ { "name": "r", "reason": "r", "match": [
        \\    { "kind": "argv", "value": "$used" },
        \\    { "kind": "argv", "value": "$single" } ] } ],
        \\  "tests": [ { "command": "x", "expect": "none" } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();
    const findings = try lintWith(testing.allocator, loaded.ruleSet(), loaded.set_uses);
    defer testing.allocator.free(findings);

    try testing.expectEqual(@as(usize, 0), countErrors(findings));
    try testing.expect(hasFinding(findings, .warn, "unused", "no matcher references it"));
    try testing.expect(!hasFinding(findings, .warn, "used", "no matcher references it"));
    try testing.expect(hasFinding(findings, .warn, "single", "single member"));
    // Without the parse's usage counts the reference check is skipped rather
    // than guessed at, and the shape check still runs.
    const blind = try lint(testing.allocator, loaded.ruleSet());
    defer testing.allocator.free(blind);
    try testing.expect(!hasFinding(blind, .warn, "unused", "no matcher references it"));
    try testing.expect(hasFinding(blind, .warn, "single", "single member"));
}

// ---- classes --------------------------------------------------------------

test "classes prints every class, its members, and how to reference it" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    try testing.expectEqual(@as(u8, 0), try writeClasses(&aw.writer, null, RENDER_WIDTH));
    const out = aw.written();

    for (&rules.Classes.all) |*class| {
        if (std.mem.indexOf(u8, out, class.name) == null) {
            std.debug.print("class {s} is not printed\n", .{class.name});
            return error.ClassNotPrinted;
        }
        for (class.members) |m| {
            if (std.mem.indexOf(u8, out, m) != null) continue;
            std.debug.print("class {s} member {s} is not printed\n", .{ class.name, m });
            return error.ClassMemberNotPrinted;
        }
    }
    // The reference spelling is printed, because a class nobody can name is
    // engine trivia rather than a mechanism.
    try testing.expect(std.mem.indexOf(u8, out, "\"$class:db_clients\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"kind\": \"path_class\", \"value\": \"home_or_root\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "normalizing the argument") != null);
}

test "classes NAME prints one, and an unknown name is a usage error" {
    var one = capture(testing.allocator);
    defer one.deinit();
    try testing.expectEqual(@as(u8, 0), try writeClasses(&one.writer, "db_clients", RENDER_WIDTH));
    try testing.expect(std.mem.indexOf(u8, one.written(), "psql") != null);
    try testing.expect(std.mem.indexOf(u8, one.written(), "home_or_root") == null);

    var bad = capture(testing.allocator);
    defer bad.deinit();
    try testing.expectEqual(@as(u8, EX_USAGE), try writeClasses(&bad.writer, "nope", RENDER_WIDTH));
    try testing.expect(std.mem.indexOf(u8, bad.written(), "no such class \"nope\"") != null);
    try testing.expect(std.mem.indexOf(u8, bad.written(), "known classes:") != null);
}

test "classes --json round-trips into something a rule file can be built from" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    try testing.expectEqual(@as(u8, 0), try writeClassesJson(testing.allocator, &aw.writer, null));

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const list = parsed.value.object.get("classes").?.array;
    try testing.expectEqual(rules.Classes.all.len, list.items.len);
    const first = list.items[0].object;
    try testing.expectEqualStrings("home_or_root", first.get("name").?.string);
    try testing.expectEqualStrings("path", first.get("kind").?.string);
    try testing.expect(first.get("members").?.array.items.len > 0);

    var single = capture(testing.allocator);
    defer single.deinit();
    try testing.expectEqual(@as(u8, EX_USAGE), try writeClassesJson(testing.allocator, &single.writer, "nope"));
}

test "classes parses as a subcommand, with a name and --json" {
    try testing.expect(parseArgs(&.{"classes"}).classes.name == null);
    try testing.expect(!parseArgs(&.{"classes"}).classes.json);
    try testing.expect(parseArgs(&.{ "classes", "--json" }).classes.json);
    try testing.expectEqualStrings("db_clients", parseArgs(&.{ "classes", "db_clients" }).classes.name.?);
    try testing.expectEqualStrings("db_clients", parseArgs(&.{ "classes", "--json", "db_clients" }).classes.name.?);
    try testing.expectEqual(Fault.Kind.unknown_flag, parseArgs(&.{ "classes", "--nope" }).fault.kind);
    // The subcommand is named in the usage text, or nobody finds it.
    try testing.expect(std.mem.indexOf(u8, usage_text, "classes [NAME]") != null);
}

test "lint: a clean rule set with tests produces no findings at all" {
    const rule_set = rules.RuleSet{
        .rules = &.{.{ .name = "no-git-add-all", .reason = "r", .match = &.{.{ .value = "git add -A" }} }},
        .tests = &.{.{ .command = "git add -A", .expect = .deny, .expect_rule = "no-git-add-all" }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), findings.len);
}

test "lint: a rule file with no tests is warned about, not failed" {
    const rule_set = rules.RuleSet{
        .rules = &.{.{ .name = "r", .reason = "r", .match = &.{.{ .value = "a" }} }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 1), findings.len);
    try testing.expectEqual(Level.warn, findings[0].level);
    try testing.expectEqual(@as(usize, 0), countErrors(findings));
}

test "the shipped default rules lint clean and their cases pass" {
    var loaded = try rules.parse(testing.allocator, @embedFile("default-rules.json"));
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    const findings = try lintWith(testing.allocator, rule_set, loaded.set_uses);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), countErrors(findings));

    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();
    for (suite.results) |result| try testing.expect(result.ok);
    // The shipped file leans on generators; a change that quietly emptied one
    // would still pass every literal case.
    try testing.expect(suite.generated.total >= 100);
}

test "the selftest fixture passes end to end and its JSON round-trips" {
    var loaded = try rules.parse(testing.allocator, selftest_fixture);
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();
    const results = suite.results;
    try testing.expect(results.len >= 4);
    for (results) |result| try testing.expect(result.ok);

    const findings = try lintWith(testing.allocator, rule_set, loaded.set_uses);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 0), countErrors(findings));

    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeSelftestJson(testing.allocator, &aw.writer, "/tmp/r.json", &suite, findings);
    try testing.expectEqual(@as(u8, 0), code);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expect(root.get("ok").?.bool);
    try testing.expectEqual(results.len, root.get("tests").?.array.items.len);
    try testing.expectEqual(results.len, @as(usize, @intCast(root.get("literal").?.object.get("passed").?.integer)));
    try testing.expect(root.get("tests").?.array.items[0].object.get("ok").?.bool);
    // Optional fields are omitted rather than emitted as null.
    try testing.expect(root.get("lint").?.array.items.len == findings.len);
}

// ---- the cookbook ---------------------------------------------------------

const cookbook_fixture = @embedFile("testdata/cookbook-recipes.json");
/// The cookbook itself, embedded so the "every recipe is the fixture's rule"
/// claim on its first page is a checked fact. Wired up in `build.zig`, and only
/// for the test build.
const cookbook_doc = @embedFile("cookbook_md");

/// `text` with every byte of JSON-insignificant whitespace removed: anything
/// outside a string literal. What survives is exactly the document — names,
/// values, structure — with formatting gone.
///
/// This is what makes the cookbook identity tests immune to formatters. The
/// same rule object lives at two different indent depths (four spaces deep in
/// the fixture's `rules` array, at column zero in the document's fence), and a
/// width-limited formatter legally wraps the same JSON differently at the two
/// depths — so any byte-level comparison is a fight with whichever formatter
/// ran last. Whitespace outside strings is the one thing JSON promises means
/// nothing, so it is the one thing this comparison discards.
fn stripJsonWhitespace(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var in_string = false;
    var escaped = false;
    for (text) |byte| {
        if (in_string) {
            try out.append(gpa, byte);
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
            continue;
        }
        switch (byte) {
            '"' => {
                in_string = true;
                try out.append(gpa, byte);
            },
            ' ', '\t', '\r', '\n' => {},
            else => try out.append(gpa, byte),
        }
    }
    return out.toOwnedSlice(gpa);
}

/// Whether `fragment` appears in `haystack` once both are reduced to their
/// JSON-significant bytes. A trailing comma on the fragment is dropped first:
/// an element quoted on its own never carries the array separator, and an
/// element that is last in the fixture's array has none.
fn containsJsonFragment(gpa: std.mem.Allocator, haystack_flat: []const u8, fragment: []const u8) !bool {
    const flat = try stripJsonWhitespace(gpa, fragment);
    defer gpa.free(flat);
    const wanted = std.mem.trimEnd(u8, flat, ",");
    return std.mem.indexOf(u8, haystack_flat, wanted) != null;
}

test "stripJsonWhitespace keeps string bytes and drops the rest" {
    const flat = try stripJsonWhitespace(
        testing.allocator,
        "{\n  \"reason\": \"two  spaces stay\",\n  \"v\": [ 1,\t2 ]\n}",
    );
    defer testing.allocator.free(flat);
    try testing.expectEqualStrings("{\"reason\":\"two  spaces stay\",\"v\":[1,2]}", flat);
    // An escaped quote must not end the string early, or everything after it
    // would be treated as structure and stripped.
    const tricky = try stripJsonWhitespace(testing.allocator, "{ \"a\": \"say \\\" it\" }");
    defer testing.allocator.free(tricky);
    try testing.expectEqualStrings("{\"a\":\"say \\\" it\"}", tricky);
}

/// Walk the ```json fenced blocks of a markdown document.
const FenceIter = struct {
    doc: []const u8,
    at: usize = 0,

    fn next(self: *FenceIter) ?[]const u8 {
        const open = "```json\n";
        while (std.mem.indexOfPos(u8, self.doc, self.at, open)) |start| {
            const body = start + open.len;
            const close = std.mem.indexOfPos(u8, self.doc, body, "\n```") orelse return null;
            self.at = close + 4;
            return self.doc[body..close];
        }
        return null;
    }
};

test "every rule JSON in the cookbook is the fixture's rule, exactly" {
    // The document claims its recipes ARE the fixture's rules — same names,
    // same values, same structure — so a recipe can be copied into a rule file
    // and behave exactly as documented. This is the check that makes the claim
    // true: a rule edited in one place and not the other fails here rather
    // than shipping a recipe that does something else. The comparison ignores
    // whitespace outside strings and nothing else: formatters re-wrap the same
    // JSON differently at the page's and the fixture's indent depths, and a
    // byte-level comparison was a permanent fight with whichever ran last.
    const fixture_flat = try stripJsonWhitespace(testing.allocator, cookbook_fixture);
    defer testing.allocator.free(fixture_flat);
    var seen: usize = 0;
    var it = FenceIter{ .doc = cookbook_doc };
    while (it.next()) |block| {
        if (!std.mem.startsWith(u8, block, "{\n  \"name\":")) continue;
        seen += 1;
        if (try containsJsonFragment(testing.allocator, fixture_flat, block)) continue;
        const eol = std.mem.indexOfScalar(u8, block[12..], '\n') orelse block.len - 12;
        std.debug.print(
            "cookbook rule block is not the fixture's rule: {s}\n",
            .{block[12 .. 12 + eol]},
        );
        return error.CookbookRuleDrifted;
    }
    // One block per shipped rule, or the document has quietly stopped
    // documenting one of them.
    var loaded = try rules.parse(testing.allocator, cookbook_fixture);
    defer loaded.deinit();
    try testing.expectEqual(loaded.ruleSet().rules.len, seen);
}

test "every test case in the cookbook is a case the fixture actually runs" {
    const fixture_flat = try stripJsonWhitespace(testing.allocator, cookbook_fixture);
    defer testing.allocator.free(fixture_flat);
    var it = FenceIter{ .doc = cookbook_doc };
    var cases: usize = 0;
    while (it.next()) |block| {
        if (std.mem.startsWith(u8, block, "{\n  \"name\":")) continue;
        var lines = std.mem.splitScalar(u8, block, '\n');
        while (lines.next()) |line| {
            const t = std.mem.trim(u8, line, " \t\r");
            // One-line case objects. A multi-line `input` case is wrapped for
            // the page's width and cannot be compared line for line, so those
            // are covered by the fixture's own run rather than here.
            if (!std.mem.startsWith(u8, t, "{ \"command\"")) continue;
            cases += 1;
            if (try containsJsonFragment(testing.allocator, fixture_flat, t)) continue;
            std.debug.print("cookbook case is not in the fixture: {s}\n", .{t});
            return error.CookbookCaseDrifted;
        }
    }
    try testing.expect(cases >= 60);
}

test "the cookbook's quoted selftest verdict is the one selftest prints" {
    // The document opens with the exact result line. A count that drifts is the
    // cheapest possible signal that the fixture grew or shrank without the page
    // being reread.
    var loaded = try rules.parse(testing.allocator, cookbook_fixture);
    defer loaded.deinit();
    var suite = try runSuite(testing.allocator, loaded.ruleSet());
    defer suite.deinit();

    var buf: [128]u8 = undefined;
    const want = try std.fmt.bufPrint(
        &buf,
        "result   : {d} literal + {d} generated cases passed, 0 lint error(s), 1 warning(s) -> OK",
        .{ suite.literal.passed, suite.generated.passed },
    );
    if (std.mem.indexOf(u8, cookbook_doc, want) == null) {
        std.debug.print("the cookbook does not quote: {s}\n", .{want});
        return error.CookbookVerdictDrifted;
    }
}

test "every RULES_COOKBOOK recipe still does what the cookbook says it does" {
    // The cookbook is prose; this fixture is the same rules with their cases,
    // run through the same `selftest` machinery an operator would. A recipe
    // that stops matching — or starts matching something the cookbook lists
    // under "does NOT catch" — fails here rather than rotting in a document.
    var loaded = try rules.parse(testing.allocator, cookbook_fixture);
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();
    var label_buf: [128]u8 = undefined;
    for (suite.results) |result| {
        if (result.ok) continue;
        std.debug.print("cookbook case #{d} ({s}: {s}): expected {s}, got {s}\n", .{
            result.index,
            caseSubject(result.input),
            caseLabel(&label_buf, result.input, 72),
            @tagName(result.expect),
            result.gotWord(),
        });
        return error.CookbookCaseFailed;
    }

    const findings = try lintWith(testing.allocator, rule_set, loaded.set_uses);
    defer testing.allocator.free(findings);
    for (findings) |finding| {
        if (finding.level != .@"error") continue;
        std.debug.print("cookbook lint error ({s}): {s}\n", .{ finding.rule orelse "-", finding.message });
        return error.CookbookLintFailed;
    }

    // Every decision the gate can reach is exercised by at least one recipe,
    // so the cookbook stays a tour of the whole schema rather than of `deny`.
    var seen = std.EnumSet(rules.Decision).initEmpty();
    for (rule_set.rules) |rule| seen.insert(rule.decision);
    try testing.expectEqual(@as(usize, 4), seen.count());

    // The one lint warning the cookbook expects: `allow` is called out every
    // time, because it skips the permission prompt outright.
    try testing.expect(hasFinding(findings, .warn, "allow-repo-clean-scratch", "skips the permission PROMPT but not the permission RULES"));
}

test "selftest JSON reports a failing case as ok:false" {
    const rule_set = rules.RuleSet{
        .rules = check_rules.rules,
        .tests = &.{.{ .command = "ls", .expect = .deny }},
    };
    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();

    var aw = capture(testing.allocator);
    defer aw.deinit();
    const code = try writeSelftestJson(testing.allocator, &aw.writer, null, &suite, &.{});
    try testing.expectEqual(@as(u8, 1), code);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    try testing.expect(!parsed.value.object.get("ok").?.bool);
    const case = parsed.value.object.get("tests").?.array.items[0].object;
    try testing.expect(!case.get("ok").?.bool);
    try testing.expectEqualStrings("none", case.get("got").?.string);
    try testing.expect(case.get("expect_rule") == null);
}

// ---- stats ----------------------------------------------------------------

const stats_fixture = @embedFile("testdata/stats-sample.jsonl");

test "aggregate: per-rule totals split by decision, newest-first" {
    const bytes =
        \\{"ts_unix":100,"rule":"no-pkill","decision":"deny"}
        \\{"ts_unix":200,"rule":"no-pkill","decision":"deny"}
        \\{"ts_unix":300,"rule":"no-pkill","decision":"bypassed"}
        \\{"ts_unix":150,"rule":"watch","decision":"log"}
        \\{"ts_unix":160,"rule":"ask-me","decision":"ask"}
        \\{"ts_unix":170,"rule":"grant","decision":"allow"}
        \\{"ts_unix":180,"rule":"future","decision":"quarantine"}
    ;
    var result = try aggregate(testing.allocator, bytes, null);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 7), result.lines);
    try testing.expectEqual(@as(usize, 7), result.counted);
    try testing.expectEqual(@as(usize, 0), result.skipped);
    try testing.expectEqual(@as(usize, 5), result.rules.len);

    // Busiest rule first.
    const top = result.rules[0];
    try testing.expectEqualStrings("no-pkill", top.rule);
    try testing.expectEqual(@as(usize, 3), top.total);
    try testing.expectEqual(@as(usize, 2), top.deny);
    try testing.expectEqual(@as(usize, 1), top.bypassed);
    try testing.expectEqual(@as(i64, 300), top.last_ts);

    // Ties break by name, so the table is stable run to run.
    try testing.expectEqualStrings("ask-me", result.rules[1].rule);
    try testing.expectEqual(@as(usize, 1), result.rules[1].ask);
    try testing.expectEqualStrings("future", result.rules[2].rule);
    try testing.expectEqual(@as(usize, 1), result.rules[2].other);
    try testing.expectEqualStrings("grant", result.rules[3].rule);
    try testing.expectEqual(@as(usize, 1), result.rules[3].allow);
    try testing.expectEqualStrings("watch", result.rules[4].rule);
    try testing.expectEqual(@as(usize, 1), result.rules[4].shadow);
}

test "aggregate: malformed lines are counted and stepped over" {
    const bytes =
        \\{"ts_unix":100,"rule":"a","decision":"deny"}
        \\not json at all
        \\{"ts_unix":101,"decision":"deny"}
        \\
        \\
        \\{"ts_unix":102,"rule":"a","decision":"deny"}
        \\{"ts_unix":103,"rule":
    ;
    var result = try aggregate(testing.allocator, bytes, null);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 5), result.lines);
    try testing.expectEqual(@as(usize, 2), result.counted);
    try testing.expectEqual(@as(usize, 3), result.skipped);
    try testing.expectEqual(@as(usize, 1), result.rules.len);
    try testing.expectEqual(@as(usize, 2), result.rules[0].total);
}

test "aggregate: --since drops entries older than the cutoff" {
    const bytes =
        \\{"ts_unix":100,"rule":"old","decision":"deny"}
        \\{"ts_unix":500,"rule":"new","decision":"deny"}
        \\{"ts_unix":499,"rule":"old","decision":"deny"}
    ;
    var result = try aggregate(testing.allocator, bytes, 500);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), result.filtered);
    try testing.expectEqual(@as(usize, 1), result.counted);
    try testing.expectEqual(@as(usize, 1), result.rules.len);
    try testing.expectEqualStrings("new", result.rules[0].rule);
}

test "aggregate: an unknown key in a line does not make it malformed" {
    const bytes =
        \\{"ts_unix":1,"rule":"a","decision":"deny","matcher":{"kind":"word"},"span":"x","future":[1,2]}
    ;
    var result = try aggregate(testing.allocator, bytes, null);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), result.counted);
    try testing.expectEqual(@as(usize, 1), result.rules[0].deny);
}

test "aggregate: an empty log yields an empty, printable summary" {
    var result = try aggregate(testing.allocator, "", null);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), result.rules.len);

    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeTable(&aw.writer, result, 1000);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "no entries match.") != null);
}

test "humanized ages" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0s ago", humanizeAge(&buf, 0));
    try testing.expectEqualStrings("59s ago", humanizeAge(&buf, 59));
    try testing.expectEqualStrings("1m ago", humanizeAge(&buf, 60));
    try testing.expectEqualStrings("45m ago", humanizeAge(&buf, 45 * 60));
    try testing.expectEqualStrings("1h ago", humanizeAge(&buf, 90 * 60));
    try testing.expectEqualStrings("2h ago", humanizeAge(&buf, 2 * 3600 + 5));
    try testing.expectEqualStrings("7d ago", humanizeAge(&buf, 7 * 86400));
    try testing.expectEqualStrings("in the future", humanizeAge(&buf, -5));
}

test "the stats table aligns its columns and reports what it skipped" {
    var result = try aggregate(testing.allocator, stats_fixture, null);
    defer result.deinit(testing.allocator);

    var aw = capture(testing.allocator);
    defer aw.deinit();
    // The fixture's newest entry is at 1750003600.
    try writeTable(&aw.writer, result, 1_750_003_600 + 3 * 86400);
    const out = aw.written();

    var lines = std.mem.splitScalar(u8, out, '\n');
    const header = lines.next().?;
    const first = lines.next().?;
    const second = lines.next().?;
    try testing.expect(std.mem.startsWith(u8, header, "rule "));
    try testing.expect(std.mem.indexOf(u8, header, "total") != null);
    try testing.expect(std.mem.indexOf(u8, header, "bypassed") != null);
    try testing.expect(std.mem.indexOf(u8, header, "last hit") != null);
    // Right-aligned counts: every row's "total" digit ends in the same column
    // as the header's "total" does, which is what makes the table scannable.
    const total_end = std.mem.indexOf(u8, header, "total").? + "total".len;
    try testing.expect(std.ascii.isDigit(first[total_end - 1]));
    try testing.expect(!std.ascii.isDigit(first[total_end]));
    try testing.expect(std.ascii.isDigit(second[total_end - 1]));
    try testing.expect(std.mem.indexOf(u8, first, "no-pkill") != null);
    try testing.expect(std.mem.indexOf(u8, out, "3d ago") != null);
    try testing.expect(std.mem.indexOf(u8, out, "skipped as malformed") != null);
}

test "stats JSON carries the counts and the raw timestamps" {
    var result = try aggregate(testing.allocator, stats_fixture, null);
    defer result.deinit(testing.allocator);

    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeStatsJson(&aw.writer, .{
        .log_path = "/tmp/log.jsonl",
        .exists = true,
        .now_unix = 1_750_010_000,
        .since_seconds = 604_800,
    }, result);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("/tmp/log.jsonl", root.get("log").?.string);
    try testing.expect(root.get("exists").?.bool);
    try testing.expectEqual(@as(i64, 604_800), root.get("since_seconds").?.integer);
    try testing.expect(root.get("skipped").?.integer > 0);
    // No rotated generation was folded in, so the key is absent rather than null.
    try testing.expect(root.get("rotated") == null);

    const rows = root.get("rules").?.array.items;
    try testing.expect(rows.len > 0);
    const top = rows[0].object;
    try testing.expectEqualStrings("no-pkill", top.get("rule").?.string);
    try testing.expect(top.get("total").?.integer >= top.get("deny").?.integer);
    try testing.expectEqual(@as(i64, 1_750_003_600), top.get("last_ts").?.integer);
}

test "a missing log renders as an empty JSON summary rather than an error" {
    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeStatsJson(&aw.writer, .{
        .log_path = "/nope/log.jsonl",
        .exists = false,
        .now_unix = 1000,
    }, .{ .rules = &.{} });

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    try testing.expect(!parsed.value.object.get("exists").?.bool);
    try testing.expectEqual(@as(usize, 0), parsed.value.object.get("rules").?.array.items.len);
}

// ---- rotated generations --------------------------------------------------

test "stats: --include-rotated parses and defaults off" {
    try testing.expect(!parseArgs(&.{ "stats", "--json" }).stats.include_rotated);
    try testing.expect(parseArgs(&.{ "stats", "--include-rotated" }).stats.include_rotated);
    const both = parseArgs(&.{ "stats", "--include-rotated", "--since", "7d", "--log=/tmp/l.jsonl" }).stats;
    try testing.expect(both.include_rotated);
    try testing.expectEqualStrings("/tmp/l.jsonl", both.log_path.?);
}

test "joinLogs: a seam always falls on a line break" {
    const a = testing.allocator;

    // The rotated generation ended mid-line (a torn final append). Fusing it
    // onto the next generation's first line would destroy BOTH entries.
    const torn = try joinLogs(a, &.{ "{\"rule\":\"a\"", "{\"ts_unix\":1,\"rule\":\"b\",\"decision\":\"deny\"}\n" });
    defer a.free(torn);
    try testing.expectEqualStrings(
        "{\"rule\":\"a\"\n{\"ts_unix\":1,\"rule\":\"b\",\"decision\":\"deny\"}\n",
        torn,
    );

    // A generation that already ends in a newline gains no second one.
    const clean = try joinLogs(a, &.{ "x\n", "y\n" });
    defer a.free(clean);
    try testing.expectEqualStrings("x\ny\n", clean);

    // Absent generations contribute nothing, not an empty line.
    const only_live = try joinLogs(a, &.{ "", "y\n" });
    defer a.free(only_live);
    try testing.expectEqualStrings("y\n", only_live);

    const nothing = try joinLogs(a, &.{ "", "" });
    defer a.free(nothing);
    try testing.expectEqualStrings("", nothing);
}

test "rotated plus live aggregates as one history, oldest first" {
    const a = testing.allocator;
    const rotated =
        \\{"ts_unix":100,"rule":"no-pkill","decision":"deny"}
        \\{"ts_unix":200,"rule":"watch","decision":"log"}
    ;
    const live =
        \\{"ts_unix":900,"rule":"no-pkill","decision":"deny"}
    ;

    // Live alone: the rotated history is invisible.
    var live_only = try aggregate(a, live, null);
    defer live_only.deinit(a);
    try testing.expectEqual(@as(usize, 1), live_only.rules.len);
    try testing.expectEqual(@as(usize, 1), live_only.rules[0].total);

    const both = try joinLogs(a, &.{ rotated, live });
    defer a.free(both);
    var merged = try aggregate(a, both, null);
    defer merged.deinit(a);

    try testing.expectEqual(@as(usize, 3), merged.counted);
    try testing.expectEqual(@as(usize, 0), merged.skipped);
    try testing.expectEqual(@as(usize, 2), merged.rules.len);
    try testing.expectEqualStrings("no-pkill", merged.rules[0].rule);
    try testing.expectEqual(@as(usize, 2), merged.rules[0].deny);
    // "Last hit" still comes from the newest line, whichever generation it is in.
    try testing.expectEqual(@as(i64, 900), merged.rules[0].last_ts);
    try testing.expectEqualStrings("watch", merged.rules[1].rule);
    try testing.expectEqual(@as(usize, 1), merged.rules[1].shadow);
}

test "stats JSON names the rotated generation only when one contributed" {
    var result = try aggregate(testing.allocator, "{\"ts_unix\":1,\"rule\":\"a\",\"decision\":\"deny\"}", null);
    defer result.deinit(testing.allocator);

    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeStatsJson(&aw.writer, .{
        .log_path = "/tmp/log.jsonl",
        .rotated_path = "/tmp/log.jsonl.1",
        .exists = true,
        .now_unix = 1000,
    }, result);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("/tmp/log.jsonl.1", parsed.value.object.get("rotated").?.string);
    // A window that was never asked for stays off the wire entirely.
    try testing.expect(parsed.value.object.get("since_seconds") == null);
}

// ---- structural rules: reporting, explaining, and linting -----------------

const structural_fixture = @embedFile("testdata/structural-rules.json");

/// A check report for a rule set that may contain structural matchers: the
/// evaluation owns a parsed command model, and the report borrows resolved
/// values out of it, so the render has to happen before the release.
fn structuralReport(
    allocator: std.mem.Allocator,
    rule_set: rules.RuleSet,
    command: []const u8,
    explain: bool,
) !struct { text: []u8, code: u8 } {
    var aw = capture(allocator);
    errdefer aw.deinit();
    const input = rules.Input{ .command = command };
    var result = rules.evaluateIn(allocator, rule_set, input, .none);
    defer result.deinit();
    const code = try writeCheckReport(&aw.writer, input, result, .{
        .width = 88,
        .explain = if (explain) result.structure else null,
    });
    return .{ .text = try aw.toOwnedSlice(), .code = code };
}

test "check report: a recovered command word says what it resolved from" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const report = try structuralReport(
        testing.allocator,
        loaded.ruleSet(),
        "P=pki; K=ll; $P$K -f myserver",
        false,
    );
    defer testing.allocator.free(report.text);

    try testing.expectEqual(@as(u8, 1), report.code);
    // The matcher line carries the provenance...
    try testing.expect(std.mem.indexOf(
        u8,
        report.text,
        "[command_word command \"pkill\" resolved from \"$P$K\" via resolved_concat]",
    ) != null);
    // ...and the underline sits under the bytes the operator actually wrote,
    // 13 columns in, not under a value that appears nowhere in the text.
    try testing.expect(std.mem.indexOf(
        u8,
        report.text,
        "           P=pki; K=ll; $P$K -f myserver\n                        ^~~~\n",
    ) != null);
}

test "check report: a hit from inside a group names the leaf that fired" {
    // A group must not blur the report. `check` is what an operator reads to
    // learn WHY a rule fired, and "one of nine alternatives matched" is not
    // an answer.
    const json =
        \\{ "rules": [ { "name": "no-destructive-sql", "reason": "r",
        \\  "match_all": [
        \\    { "any": [
        \\      { "kind": "argv", "value": "TRUNCATE TABLE" },
        \\      { "kind": "argv", "value": "DROP TABLE" } ] },
        \\    { "any": [
        \\      { "kind": "command_word", "value": "psql" },
        \\      { "kind": "command_word", "value": "mysql" } ] } ] } ] }
    ;
    var loaded = try rules.parse(testing.allocator, json);
    defer loaded.deinit();

    const report = try structuralReport(
        testing.allocator,
        loaded.ruleSet(),
        "psql -h db -c \"DROP TABLE users\"",
        false,
    );
    defer testing.allocator.free(report.text);

    try testing.expectEqual(@as(u8, 1), report.code);
    try testing.expect(std.mem.indexOf(u8, report.text, "[argv command \"DROP TABLE\"]") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        report.text,
        "psql -h db -c \"DROP TABLE users\"\n                          ^~~~~~~~~~\n",
    ) != null);
}

test "check report: a literal structural hit adds no annotation at all" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const report = try structuralReport(testing.allocator, loaded.ruleSet(), "sudo pkill -9 svc", false);
    defer testing.allocator.free(report.text);
    try testing.expect(std.mem.indexOf(u8, report.text, "[command_word command \"pkill\"]") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "resolved from") == null);
}

test "check report: an argv hit underlines inside the quoted region" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const report = try structuralReport(
        testing.allocator,
        loaded.ruleSet(),
        "psql -h db -c \"DROP TABLE users\"",
        false,
    );
    defer testing.allocator.free(report.text);
    try testing.expect(std.mem.indexOf(u8, report.text, "[argv command \"DROP TABLE\"]") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        report.text,
        "psql -h db -c \"DROP TABLE users\"\n                          ^~~~~~~~~~\n",
    ) != null);
}

test "check --explain renders the model an operator has to argue with" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const report = try structuralReport(
        testing.allocator,
        loaded.ruleSet(),
        "sudo bash -lc \"cd /repo && git add -A\"",
        true,
    );
    defer testing.allocator.free(report.text);

    // Every invocation, with the wrapper chain that reached it.
    try testing.expect(std.mem.indexOf(u8, report.text, "explain  : ") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "[0] depth 0  top") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "[1] depth 1  privilege") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "[3] depth 2  shell_c") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "command  : git") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "args     : [add] [-A]") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "signals  :") != null);
}

test "check --explain names the resolution and the body it re-lexed" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const report = try structuralReport(
        testing.allocator,
        loaded.ruleSet(),
        "alias k='pkill -f svc'; k",
        true,
    );
    defer testing.allocator.free(report.text);
    try testing.expect(std.mem.indexOf(u8, report.text, "-> pkill via alias") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "expansion [0] alias k -> \"pkill -f svc\"") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "alias_defined") != null);
    try testing.expect(std.mem.indexOf(u8, report.text, "alias_expanded") != null);
}

test "check --explain is off by default: the compact report is byte-identical" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();

    const quiet_form = try structuralReport(testing.allocator, loaded.ruleSet(), "sudo pkill -9 svc", false);
    defer testing.allocator.free(quiet_form.text);
    const loud_form = try structuralReport(testing.allocator, loaded.ruleSet(), "sudo pkill -9 svc", true);
    defer testing.allocator.free(loud_form.text);

    try testing.expect(std.mem.indexOf(u8, quiet_form.text, "explain  :") == null);
    try testing.expect(std.mem.startsWith(u8, loud_form.text, quiet_form.text));
    try testing.expectEqual(quiet_form.code, loud_form.code);
}

test "--explain parses as a flag and leaves the command alone" {
    const cmd = parseArgs(&.{ "check", "--explain", "git", "add", "-A" });
    try testing.expect(cmd.check.explain);
    try testing.expectEqual(@as(usize, 3), cmd.check.command.len);
    try testing.expect(!parseArgs(&.{ "check", "git", "add" }).check.explain);
}

test "the shipped structural fixture passes its own cases and lints clean" {
    var loaded = try rules.parse(testing.allocator, structural_fixture);
    defer loaded.deinit();
    const rule_set = loaded.ruleSet();

    var suite = try runSuite(testing.allocator, rule_set);
    defer suite.deinit();
    try testing.expect(suite.results.len >= 10);
    for (suite.results) |case| {
        if (!case.ok) {
            std.debug.print("case #{d} ({s}) expected {s}, got {s}\n", .{
                case.index,
                case.input.command,
                @tagName(case.expect),
                case.gotWord(),
            });
            return error.TestUnexpectedResult;
        }
    }

    const findings = try lintWith(testing.allocator, rule_set, loaded.set_uses);
    defer testing.allocator.free(findings);
    // One warning (the allow rule), no errors.
    try testing.expectEqual(@as(usize, 0), countErrors(findings));
}

test "lint: a structural kind on content or file_path is an error, not a dead rule" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{
                .name = "on-content",
                .reason = "r",
                .match = &.{.{ .kind = .command_word, .field = .content, .value = "pkill" }},
            },
            .{
                .name = "on-path",
                .reason = "r",
                .match = &.{.{ .kind = .argv, .field = .file_path, .value = "x" }},
            },
            .{
                .name = "signal-on-content",
                .reason = "r",
                .match_all = &.{.{ .kind = .signal, .field = .content, .value = "eval_present" }},
            },
            .{
                .name = "carve-out-on-content",
                .reason = "r",
                .match = &.{.{ .kind = .word, .value = "x" }},
                .match_none = &.{.{ .kind = .command_line, .field = .content, .value = "rm -rf" }},
            },
            // The same kinds on `command` are fine.
            .{
                .name = "on-command",
                .reason = "r",
                .match = &.{.{ .kind = .command_word, .value = "pkill" }},
            },
        },
        .tests = &.{.{ .command = "pkill x", .expect = .deny }},
    };

    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    inline for (.{ "on-content", "on-path", "signal-on-content", "carve-out-on-content" }) |name| {
        try testing.expect(hasFinding(findings, .@"error", name, "structural matcher kind on a non-command field"));
    }
    try testing.expect(!hasFinding(findings, .@"error", "on-command", "structural matcher kind"));
    // Exactly four: the well-placed matcher contributes nothing.
    try testing.expectEqual(@as(usize, 4), countErrors(findings));
}

test "lint: an unknown signal name is an error naming the vocabulary" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "typo", .reason = "r", .match = &.{.{ .kind = .signal, .value = "eval" }} },
            .{ .name = "cased", .reason = "r", .match = &.{.{ .kind = .signal, .value = "EVAL_PRESENT" }} },
            .{ .name = "good", .reason = "r", .match = &.{.{ .kind = .signal, .value = "opaque_command" }} },
        },
        .tests = &.{.{ .command = "eval x", .expect = .deny }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);

    try testing.expect(hasFinding(findings, .@"error", "typo", "unknown signal name"));
    try testing.expect(hasFinding(findings, .@"error", "cased", "unknown signal name"));
    try testing.expect(!hasFinding(findings, .@"error", "good", "unknown signal name"));
    try testing.expectEqual(@as(usize, 2), countErrors(findings));
}

test "lint: the bare-star refusal covers the structural kinds too" {
    const rule_set = rules.RuleSet{
        .rules = &.{
            .{ .name = "w", .reason = "r", .match = &.{.{ .kind = .command_word, .value = "*" }} },
            .{ .name = "a", .reason = "r", .match = &.{.{ .kind = .argv, .value = "*" }} },
            .{ .name = "l", .reason = "r", .match = &.{.{ .kind = .command_line, .value = "git *" }} },
        },
        .tests = &.{.{ .command = "x", .expect = .none }},
    };
    const findings = try lint(testing.allocator, rule_set);
    defer testing.allocator.free(findings);
    try testing.expectEqual(@as(usize, 3), countErrors(findings));
    inline for (.{ "w", "a", "l" }) |name| {
        try testing.expect(hasFinding(findings, .@"error", name, "matches nothing"));
    }
}

// ---- usage ----------------------------------------------------------------

test "usage names every subcommand and both modes" {
    inline for (.{
        "check",
        "selftest",
        "stats",
        "classes",
        "doctor",
        "status",
        "diff-defaults",
        "version",
        "help",
        "stdin",
    }) |needle| {
        try testing.expect(std.mem.indexOf(u8, usage_text, needle) != null);
    }
    var aw = capture(testing.allocator);
    defer aw.deinit();
    try writeFault(&aw.writer, .{ .kind = .unknown_subcommand, .arg = "nope" });
    try testing.expectEqualStrings("claude-hooker-gate: unknown subcommand \"nope\"\n", aw.written());
}

// ---- doctor, status, diff-defaults ----------------------------------------

test "the inspecting subcommands parse, and reject a flag they would ignore" {
    switch (parseArgs(&.{ "doctor", "--claude-dir", "/sb", "--json" })) {
        .doctor => |args| {
            try testing.expectEqualStrings("/sb", args.claude_dir.?);
            try testing.expect(args.json);
            try testing.expect(args.rules_path == null);
        },
        else => return error.NotDoctor,
    }
    switch (parseArgs(&.{ "status", "--rules=/r.json", "--project-dir", "/repo" })) {
        .status => |args| {
            try testing.expectEqualStrings("/r.json", args.rules_path.?);
            try testing.expectEqualStrings("/repo", args.project_dir.?);
            try testing.expect(!args.json);
        },
        else => return error.NotStatus,
    }
    switch (parseArgs(&.{ "diff-defaults", "--claude-dir", "/sb" })) {
        .diff_defaults => |args| try testing.expectEqualStrings("/sb", args.claude_dir.?),
        else => return error.NotDiff,
    }
    // `diff-defaults` never looks at an overlay, so accepting --project-dir
    // would be accepting a flag it then ignores.
    switch (parseArgs(&.{ "diff-defaults", "--project-dir", "/repo" })) {
        .fault => |fault| {
            try testing.expectEqual(Fault.Kind.unknown_flag, fault.kind);
            try testing.expectEqualStrings("--project-dir", fault.arg);
        },
        else => return error.ShouldHaveFaulted,
    }
    switch (parseArgs(&.{ "doctor", "--claude-dir" })) {
        .fault => |fault| try testing.expectEqual(Fault.Kind.missing_value, fault.kind),
        else => return error.ShouldHaveFaulted,
    }
}

test "one claude dir substitutes every path an install owns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const layout = try Layout.init(arena.allocator(), "/sb");
    try testing.expectEqualStrings("/sb/hooks", layout.hooks_dir);
    try testing.expectEqualStrings("/sb/hooks/claude-hooker-gate", layout.gate_dest);
    try testing.expectEqualStrings("/sb/hook-rules.json", layout.rules_dest);
    try testing.expectEqualStrings("/sb/settings.json", layout.settings_path);
    try testing.expectEqualStrings("/sb/hook-gate-log.jsonl", layout.log_default);

    // And the real install is the same construction under $HOME/.claude, so a
    // sandbox diagnosis exercises the same joins as a live one.
    const home = try Layout.forHome(arena.allocator(), "/home/u");
    try testing.expectEqualStrings("/home/u/.claude/hook-rules.json", home.rules_dest);
    try testing.expectEqualStrings("/home/u/.claude/hooks/claude-hooker-gate", home.gate_dest);
}

test "a version line is read, and a stranger binary's output is not" {
    try testing.expectEqualStrings("0.2.0", parseVersionLine("claude-hooker-gate 0.2.0\n").?);
    try testing.expectEqualStrings("9.9.9-rc1", parseVersionLine("  claude-hooker-gate 9.9.9-rc1  ").?);
    // Anything that is not exactly the one line the gate prints: a version
    // number invented from someone else's output would be worse than silence.
    try testing.expect(parseVersionLine("some-other-tool 1.0\n") == null);
    try testing.expect(parseVersionLine("claude-hooker-gate\n") == null);
    try testing.expect(parseVersionLine("claude-hooker-gate 1.0 extra\n") == null);
    try testing.expect(parseVersionLine("") == null);
}

test "byte counts an operator can judge at a glance" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0 B", humanizeBytes(&buf, 0));
    try testing.expectEqualStrings("512 B", humanizeBytes(&buf, 512));
    try testing.expectEqualStrings("1.0 KiB", humanizeBytes(&buf, 1024));
    try testing.expectEqualStrings("10.0 MiB", humanizeBytes(&buf, 10 * 1024 * 1024));
}

test "hook commands are read out of every event key, shape errors and all" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const doc =
        \\{ "model": "opus",
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/usr/local/bin/other-gate" } ] },
        \\      { "matcher": "*", "hooks": [ { "type": "command", "command": "/sb/hooks/claude-hooker-gate" } ] },
        \\      { "matcher": "Write", "hooks": "not an array" },
        \\      "not an object"
        \\    ],
        \\    "Stop": [ { "hooks": [ { "command": "/sb/hooks/claude-hooker-gate" } ] } ],
        \\    "PostToolUse": [ { "hooks": [ { "command": "/bin/notify" } ] } ],
        \\    "SomeFutureEvent": [ { "hooks": [ { "command": "/bin/whatever" } ] } ]
        \\  } }
    ;
    const root = try std.json.parseFromSliceLeaky(std.json.Value, gpa, doc, .{});
    const entries = try hookEntries(gpa, root);
    try testing.expectEqual(@as(usize, 5), entries.len);
    try testing.expectEqualStrings("/usr/local/bin/other-gate", entries[0].command);
    try testing.expectEqual(rules.Event.PreToolUse, entries[0].event.?);
    try testing.expect(!entries[0].isGate());
    try testing.expectEqualStrings("/sb/hooks/claude-hooker-gate", entries[1].command);
    try testing.expect(entries[1].isGate());
    try testing.expectEqualStrings("*", entries[1].matcher);

    // Our gate under a second event key, found as such.
    try testing.expect(wiredFor(entries, .Stop, "/sb/hooks/claude-hooker-gate"));
    try testing.expect(wiredFor(entries, .PreToolUse, "/sb/hooks/claude-hooker-gate"));
    // Somebody else's PostToolUse hook is not ours.
    try testing.expect(!wiredFor(entries, .PostToolUse, "/sb/hooks/claude-hooker-gate"));
    // An event key this build has never heard of is reported, not dropped: the
    // entry is there with a null event, because "somebody else's hook on an
    // event I do not know" is a true fact about a settings file.
    var unknown_events: usize = 0;
    for (entries) |entry| {
        if (entry.event == null) unknown_events += 1;
    }
    try testing.expectEqual(@as(usize, 1), unknown_events);

    // A settings.json with no hooks at all is a file with no hook commands in
    // it, not an error.
    const bare = try std.json.parseFromSliceLeaky(std.json.Value, gpa, "{\"model\":\"opus\"}", .{});
    try testing.expectEqual(@as(usize, 0), (try hookEntries(gpa, bare)).len);
    const wrong = try std.json.parseFromSliceLeaky(std.json.Value, gpa, "{\"hooks\":\"nope\"}", .{});
    try testing.expectEqual(@as(usize, 0), (try hookEntries(gpa, wrong)).len);
}

test "the wiring plan follows the rules: which events, and which tools inside one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // The bug this closes: a Write rule and an any-tool rule under a `Bash`
    // matcher never fire, because the harness never invokes the gate for them.
    const set = rules.RuleSet{ .rules = &.{
        .{ .name = "a", .reason = "r", .match = &.{.{ .value = "x" }} },
        .{ .name = "b", .tool = "Write", .reason = "r", .match = &.{.{ .value = "x" }} },
        .{ .name = "c", .event = .Stop, .reason = "r", .match = &.{.{ .field = .message, .value = "x" }} },
    } };
    const plan = try wiringPlan(gpa, set);
    try testing.expectEqual(@as(usize, 2), plan.len);
    try testing.expectEqual(rules.Event.PreToolUse, plan[0].event);
    try testing.expectEqualStrings("Bash|Write", plan[0].matcher.?);
    try testing.expectEqual(@as(usize, 2), plan[0].rules);
    // Stop's matcher is not a tool name, so the key is omitted and the hook
    // fires for every Stop.
    try testing.expectEqual(rules.Event.Stop, plan[1].event);
    try testing.expect(plan[1].matcher == null);

    // One any-tool rule widens the whole event to `*`.
    const wide = rules.RuleSet{ .rules = &.{
        .{ .name = "a", .tool = "Bash", .reason = "r", .match = &.{.{ .value = "x" }} },
        .{ .name = "b", .tool = "*", .reason = "r", .match = &.{.{ .value = "x" }} },
    } };
    const wide_plan = try wiringPlan(gpa, wide);
    try testing.expectEqualStrings("*", wide_plan[0].matcher.?);

    // The shipped defaults: the events they actually need, no more, in table
    // order rather than rule-file order.
    var shipped = try rules.parse(gpa, DEFAULT_RULES_JSON);
    defer shipped.deinit();
    const shipped_plan = try wiringPlan(gpa, shipped.ruleSet());
    try testing.expectEqual(@as(usize, 3), shipped_plan.len);
    try testing.expectEqual(rules.Event.SessionStart, shipped_plan[0].event);
    try testing.expect(shipped_plan[0].matcher == null);
    try testing.expectEqual(rules.Event.PreToolUse, shipped_plan[1].event);
    // And `*`, because `protect-hook-config` applies to every tool. A `Bash`
    // matcher here would silently disable it — which is exactly what the
    // single-event installer did.
    try testing.expectEqualStrings("*", shipped_plan[1].matcher.?);
    try testing.expectEqual(rules.Event.PostToolUse, shipped_plan[2].event);
    try testing.expectEqualStrings("Bash", shipped_plan[2].matcher.?);
}

/// A fully healthy install, as `gatherFacts` would report it. Every failure
/// test below is this with one field changed, which is the point: each verdict
/// is pinned to exactly the fact that produces it.
fn healthyFacts() Facts {
    return .{
        .claude_dir = "/sb",
        .self_path = "/repo/zig-out/bin/claude-hooker-gate",
        .now_unix = 1_700_000_000,
        .wiring = .{
            .settings_path = "/sb/settings.json",
            .settings = .{ .ok = &.{.{
                .event = .PreToolUse,
                .matcher = "*",
                .command = "/sb/hooks/claude-hooker-gate",
            }} },
            .expected_command = "/sb/hooks/claude-hooker-gate",
            .events = &.{
                .{ .event = .PreToolUse, .rules = 11, .wired = true, .matcher = "*" },
                .{ .event = .PostToolUse, .rules = 1, .wired = true, .matcher = "Bash" },
            },
            .wired_command = "/sb/hooks/claude-hooker-gate",
            .wired_here = true,
            .binary = .{ .ok = .{ .size = 787_632, .executable = true } },
        },
        .version = .{
            .source = VERSION,
            .probed_path = "/sb/hooks/claude-hooker-gate",
            .installed = VERSION,
        },
        // A healthy macOS install, stated rather than probed: every signature
        // verdict below is this with one field changed, and the not-applicable
        // path is reached by setting `applicable = false` rather than by needing
        // a machine that is not this one.
        .signature = .{
            .applicable = true,
            .system = "macos",
            .path = "/sb/hooks/claude-hooker-gate",
            .state = .valid,
            .form = "flags=0x20002(adhoc,linker-signed), Signature=adhoc",
            .adhoc = true,
        },
        .rules = .{
            .path = "/sb/hook-rules.json",
            .state = .{ .ok = .{
                .rules = 12,
                .literal_total = 97,
                .literal_passed = 97,
                .generated_total = 390,
                .generated_passed = 390,
                .lint_errors = 0,
                .lint_warnings = 0,
            } },
        },
        .log = .{
            .path = "/sb/hook-gate-log.jsonl",
            .enabled = true,
            .exists = true,
            .size = 4096,
            .max_bytes = 10 * 1024 * 1024,
            .last_ts = 1_699_999_940,
            .entries = 12,
        },
        .overlay = .{ .allowed = true, .path = "/repo/.claude/hook-rules.json", .state = .absent },
    };
}

fn findCheck(checks: []const Check, id: []const u8) Check {
    for (checks) |c| {
        if (eq(c.id, id)) return c;
    }
    return .{ .id = "missing", .title = "missing", .status = .fail, .detail = "" };
}

fn diagnoseIn(arena: std.mem.Allocator, facts: Facts) ![]const Check {
    return diagnose(arena, facts);
}

test "doctor: a healthy install passes every check and exits zero" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const checks = try diagnoseIn(arena.allocator(), healthyFacts());
    // The inventory is part of the interface: `status`, the JSON, and the
    // README's transcript are all written against these ids.
    const want = [_][]const u8{ "wiring", "version", "signature", "rules", "log", "overlay", "disabled", "environment" };
    try testing.expectEqual(want.len, checks.len);
    for (want, checks) |id, c| {
        try testing.expectEqualStrings(id, c.id);
        try testing.expectEqual(Health.pass, c.status);
    }
    const tally = Tally.of(checks);
    try testing.expectEqual(want.len, tally.pass);
    try testing.expectEqual(@as(u8, 0), tally.exitCode());
}

test "doctor: the signature check, from valid to killed-on-sight" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Valid and ad-hoc: the flags are quoted so an operator can read them
    // rather than take "ad-hoc" on trust.
    var check = findCheck(try diagnoseIn(gpa, healthyFacts()), "signature");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "adhoc,linker-signed") != null);
    try testing.expect(check.remedy == null);

    // A byte appended to the installed gate: `--display` still says adhoc, and
    // only `--verify` catches it. The danger is named, and so is the repair.
    var facts = healthyFacts();
    facts.signature.state = .invalid;
    facts.signature.note = "main executable failed strict validation";
    check = findCheck(try diagnoseIn(gpa, facts), "signature");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "failed strict validation") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "fails OPEN") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "--force --sign -") != null);
    try testing.expectEqual(@as(u8, 1), Tally.of(try diagnoseIn(gpa, facts)).exitCode());

    facts = healthyFacts();
    facts.signature.state = .unsigned;
    facts.signature.adhoc = false;
    facts.signature.form = "";
    check = findCheck(try diagnoseIn(gpa, facts), "signature");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "no code signature at all") != null);

    // Not knowing is a warning, never a pass: `doctor` runs in scripts, and a
    // machine without the command line tools still has a working gate.
    facts = healthyFacts();
    facts.signature.state = .unavailable;
    facts.signature.note = "FileNotFound";
    check = findCheck(try diagnoseIn(gpa, facts), "signature");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "not known-good") != null);

    // Signed by something else entirely. Valid, so not a failure — but this
    // project never asks for a Developer ID, so it is worth a line.
    facts = healthyFacts();
    facts.signature.adhoc = false;
    facts.signature.form = "flags=0x10000(runtime), Signature=size=9000";
    check = findCheck(try diagnoseIn(gpa, facts), "signature");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "not the ad-hoc signature") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "Developer ID") != null);
}

test "signature: the real codesign, asked about this test binary" {
    // The one test here that spawns the actual tool. Everything else about
    // signatures is a pure function over stated facts, but SOMETHING has to
    // prove the parsing matches what `codesign` prints on a real machine — a
    // report built from output nobody ever compared is exactly the kind of
    // quiet lie this check exists to prevent.
    if (!signing_required) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Zig's linker ad-hoc signs what it emits, including test binaries, so this
    // process's own executable is a valid subject.
    const self_path = try std.process.executablePathAlloc(testing.io, gpa);
    const facts = inspectSignature(testing.io, gpa, self_path);
    try testing.expect(facts.applicable);
    switch (facts.state) {
        .valid => {
            try testing.expect(facts.adhoc);
            try testing.expect(std.mem.indexOf(u8, facts.form, "adhoc") != null);
            try testing.expect(std.mem.indexOf(u8, facts.form, "Signature=") != null);
        },
        // A machine without the command line tools cannot answer, and must not
        // be reported as failing. Anything else is a real disagreement.
        .unavailable => {},
        .invalid, .unsigned => {
            std.debug.print("codesign rejected this test binary: {s}\n", .{facts.note});
            return error.TestBinaryNotSigned;
        },
    }
}

test "signature form: the two fields an operator would read, and nothing else" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Real `codesign --display --verbose=2` output for a gate as the Zig linker
    // emits it. Note what is NOT taken from it: the executable path (the caller
    // already knows it) and the hash counts (nothing acts on them).
    const linker_signed =
        \\Executable=/sb/hooks/claude-hooker-gate
        \\Identifier=claude-hooker-gate
        \\Format=Mach-O thin (arm64)
        \\CodeDirectory v=20400 size=7465 flags=0x20002(adhoc,linker-signed) hashes=230+0 location=embedded
        \\Signature=adhoc
        \\Info.plist=not bound
        \\TeamIdentifier=not set
        \\
    ;
    try testing.expectEqualStrings(
        "flags=0x20002(adhoc,linker-signed), Signature=adhoc",
        try signatureForm(gpa, linker_signed),
    );

    // And after `codesign --force --sign -`, which is the shape a repaired gate
    // has: a real ad-hoc signature rather than a linker-generated one.
    const resigned =
        \\Executable=/sb/hooks/claude-hooker-gate
        \\CodeDirectory v=20400 size=29604 flags=0x2(adhoc) hashes=919+2 location=embedded
        \\Signature=adhoc
        \\
    ;
    try testing.expectEqualStrings("flags=0x2(adhoc), Signature=adhoc", try signatureForm(gpa, resigned));

    // Nothing recognisable: reported as empty rather than as a guess.
    try testing.expectEqualStrings("", try signatureForm(gpa, "codesign: not signed at all\n"));
    // Only one of the two fields present is still worth printing.
    try testing.expectEqualStrings("Signature=adhoc", try signatureForm(gpa, "Signature=adhoc\n"));
}

test "doctor: off macOS the signature check is not-applicable rather than absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The whole non-Darwin path, exercised by stating the platform instead of
    // needing one: the check must still be EMITTED (the README's transcript and
    // the JSON are written against a fixed inventory of ids) and must not
    // invent a problem.
    var facts = healthyFacts();
    facts.signature = .{ .applicable = false, .system = "linux" };
    const checks = try diagnoseIn(arena.allocator(), facts);
    const check = findCheck(checks, "signature");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "not applicable on linux") != null);
    try testing.expect(check.remedy == null);
    try testing.expectEqual(@as(usize, 8), checks.len);
    try testing.expectEqual(@as(u8, 0), Tally.of(checks).exitCode());
}

test "doctor: a missing installed binary fails the wiring and the version check" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var facts = healthyFacts();
    facts.wiring.binary = .missing;
    facts.version.installed = null;
    facts.version.note = "there is no binary at that path";

    const checks = try diagnoseIn(arena.allocator(), facts);
    const wiring = findCheck(checks, "wiring");
    try testing.expectEqual(Health.fail, wiring.status);
    try testing.expect(std.mem.indexOf(u8, wiring.detail, "does not exist") != null);
    try testing.expect(std.mem.indexOf(u8, wiring.remedy.?, "hookctl setup") != null);

    const drift = findCheck(checks, "version");
    try testing.expectEqual(Health.fail, drift.status);
    try testing.expect(std.mem.indexOf(u8, drift.detail, "no binary at that path") != null);
    try testing.expectEqual(@as(u8, 1), Tally.of(checks).exitCode());
}

test "doctor: an event with rules and no wiring is a WARN that names it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The multi-event failure mode: everything installs, everything selftests,
    // and a third of the policy never runs because nothing wired the event.
    var facts = healthyFacts();
    facts.wiring.events = &.{
        .{ .event = .PreToolUse, .rules = 11, .wired = true, .matcher = "*" },
        .{ .event = .Stop, .rules = 2, .wired = false },
        .{ .event = .SessionStart, .rules = 1, .wired = false },
    };
    const checks = try diagnoseIn(arena.allocator(), facts);
    const wiring = findCheck(checks, "wiring");
    try testing.expectEqual(Health.warn, wiring.status);
    // WARN, not FAIL: the wired events are still enforcing.
    try testing.expect(std.mem.indexOf(u8, wiring.detail, "Stop, SessionStart") != null);
    try testing.expect(std.mem.indexOf(u8, wiring.detail, "never run") != null);
    try testing.expect(std.mem.indexOf(u8, wiring.detail, "PreToolUse(*)") != null);
    try testing.expect(std.mem.indexOf(u8, wiring.remedy.?, "hookctl setup") != null);
    try testing.expectEqual(@as(u8, 0), Tally.of(checks).exitCode());

    // An event wired with no rules is not a gap: the operator may have deleted
    // a rule and not reinstalled, and the gate answering "no opinion" is
    // harmless. `setup` tidies it; `doctor` does not nag.
    var extra = healthyFacts();
    extra.wiring.events = &.{
        .{ .event = .PreToolUse, .rules = 11, .wired = true, .matcher = "*" },
        .{ .event = .Stop, .rules = 0, .wired = true },
    };
    try testing.expectEqual(Health.pass, findCheck(try diagnoseIn(arena.allocator(), extra), "wiring").status);
}

test "doctor: version drift is a failure that names both versions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var facts = healthyFacts();
    facts.version.installed = "0.1.9";
    facts.version.source = "0.2.0";

    const check = findCheck(try diagnoseIn(arena.allocator(), facts), "version");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "0.1.9") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "0.2.0") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "upgrade") != null);
}

test "doctor: probing itself passes, and says why it cannot see drift" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var facts = healthyFacts();
    facts.self_path = "/sb/hooks/claude-hooker-gate";
    facts.version.self_is_installed = true;

    const check = findCheck(try diagnoseIn(arena.allocator(), facts), "version");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "cannot see drift") != null);
}

test "doctor: a wiring that points at another copy is a warning, not a pass" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var facts = healthyFacts();
    facts.wiring.wired_command = "/old/hooks/claude-hooker-gate";
    facts.wiring.wired_here = false;

    const check = findCheck(try diagnoseIn(arena.allocator(), facts), "wiring");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "/old/hooks/claude-hooker-gate") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "/sb/hooks/claude-hooker-gate") != null);
    // A warning is not a failure: the gate still runs.
    try testing.expectEqual(@as(u8, 0), Tally.of(try diagnoseIn(arena.allocator(), facts)).exitCode());
}

test "doctor: an unexecutable gate, a missing settings file, and an unparseable one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.wiring.binary = .{ .ok = .{ .size = 787_632, .executable = false } };
    var check = findCheck(try diagnoseIn(gpa, facts), "wiring");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "not executable") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "chmod +x") != null);

    facts = healthyFacts();
    facts.wiring.settings = .missing;
    facts.wiring.wired_command = null;
    check = findCheck(try diagnoseIn(gpa, facts), "wiring");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "no settings.json") != null);

    facts = healthyFacts();
    facts.wiring.settings = .{ .invalid = "SyntaxError" };
    facts.wiring.wired_command = null;
    check = findCheck(try diagnoseIn(gpa, facts), "wiring");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "not valid JSON") != null);

    // Wired, but by somebody else's tool only.
    facts = healthyFacts();
    facts.wiring.settings = .{ .ok = &.{.{ .matcher = "Bash", .command = "/usr/local/bin/other-gate" }} };
    facts.wiring.wired_command = null;
    check = findCheck(try diagnoseIn(gpa, facts), "wiring");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "none of them ours") != null);
}

test "doctor: the rule file's own verdicts become the rules check" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.rules.state = .{ .invalid = "InvalidRules" };
    var check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.fail, check.status);
    // The failure mode that matters: an invalid rule file means the gate is
    // OFF, not that it is strict.
    try testing.expect(std.mem.indexOf(u8, check.detail, "fails OPEN") != null);

    facts = healthyFacts();
    facts.rules.state = .{ .unreadable = "AccessDenied" };
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "AccessDenied") != null);

    facts = healthyFacts();
    facts.rules.state.ok.generated_passed = 388;
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "2 case(s) FAILING") != null);

    facts = healthyFacts();
    facts.rules.state.ok.lint_warnings = 1;
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.warn, check.status);

    facts = healthyFacts();
    facts.rules.state.ok.literal_total = 0;
    facts.rules.state.ok.literal_passed = 0;
    facts.rules.state.ok.generated_total = 0;
    facts.rules.state.ok.generated_passed = 0;
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "no test cases") != null);
}

test "doctor: a rule file from a newer schema is its own failure, with its own remedy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.rules.state = .{ .schema_refused = .{ .declared = .{ .major = 2, .minor = 0 }, .text = "2.0" } };
    var check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.fail, check.status);
    // Both versions, so the operator can see which side is behind.
    try testing.expect(std.mem.indexOf(u8, check.detail, "schema_version 2.0") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "reads 1.2") != null);
    // The consequence, stated: a refused policy is an absent policy.
    try testing.expect(std.mem.indexOf(u8, check.detail, "fails OPEN") != null);
    // And the exact command, not a description of one.
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "./hookctl upgrade") != null);

    // A `schema_version` that is not a version at all is a different mistake
    // with a different fix: it is the operator's typo, not a stale binary.
    facts.rules.state = .{ .schema_refused = .{ .declared = null, .text = "tomorrow" } };
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "\"tomorrow\"") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "major.minor") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "upgrade") == null);
}

test "doctor: a rule file with no schema_version warns, and one with an older schema does not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Every rule file seeded before the field existed is in this state, so it
    // must be a WARN and never a failure — the policy is being enforced exactly
    // as written.
    var facts = healthyFacts();
    facts.rules.state.ok.schema = .absent;
    var check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "no schema_version") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "read as 1.0") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "\"schema_version\": \"1.2\"") != null);

    // Older is a pass: this binary understands every construct an older
    // document can contain. It is still named, because after a major bump an
    // operator wants to know their file predates it.
    facts = healthyFacts();
    facts.rules.state.ok.schema = .{ .older = .{ .major = 0, .minor = 9 } };
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "schema 0.9") != null);

    // And the ordinary case says nothing at all about the schema: a line that
    // appears on every healthy install is a line nobody reads.
    facts = healthyFacts();
    check = findCheck(try diagnoseIn(gpa, facts), "rules");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "schema") == null);
}

test "status --json reports the declared schema and the one this build reads" {
    var out = capture(testing.allocator);
    defer out.deinit();
    var facts = healthyFacts();
    facts.rules.state.ok.schema = .absent;
    _ = try writeStatusJson(&out.writer, facts);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
    defer parsed.deinit();
    const rules_obj = parsed.value.object.get("rules").?.object;
    // Absent stays absent: a consumer must be able to tell a file that declares
    // nothing from one that declares 1.0.
    try testing.expectEqual(std.json.Value.null, rules_obj.get("schema_version").?);
    try testing.expectEqualStrings("1.2", rules_obj.get("schema_read").?.string);

    var refused = capture(testing.allocator);
    defer refused.deinit();
    facts.rules.state = .{ .schema_refused = .{ .declared = .{ .major = 3, .minor = 4 }, .text = "3.4" } };
    _ = try writeStatusJson(&refused.writer, facts);
    var parsed2 = try std.json.parseFromSlice(std.json.Value, testing.allocator, refused.written(), .{});
    defer parsed2.deinit();
    const refused_obj = parsed2.value.object.get("rules").?.object;
    try testing.expectEqualStrings("schema_refused", refused_obj.get("state").?.string);
    try testing.expectEqualStrings("3.4", refused_obj.get("schema_version").?.string);
    try testing.expectEqualStrings("1.2", refused_obj.get("schema_read").?.string);
}

test "the refusal message names both versions and the command that fixes it" {
    var out = capture(testing.allocator);
    defer out.deinit();
    try writeSchemaRefusal(&out.writer, PROGRAM, "/sb/hook-rules.json", .{ .major = 2, .minor = 3 }, "2.3");
    const text = out.written();
    try testing.expect(std.mem.indexOf(u8, text, "/sb/hook-rules.json") != null);
    try testing.expect(std.mem.indexOf(u8, text, "schema_version 2.3") != null);
    try testing.expect(std.mem.indexOf(u8, text, "reads 1.2") != null);
    try testing.expect(std.mem.indexOf(u8, text, "`./hookctl upgrade`") != null);
    // The reassurance that makes the remedy safe to follow.
    try testing.expect(std.mem.indexOf(u8, text, "rule file is not touched") != null);

    var bad = capture(testing.allocator);
    defer bad.deinit();
    try writeSchemaRefusal(&bad.writer, PROGRAM, "/sb/hook-rules.json", null, "later");
    try testing.expect(std.mem.indexOf(u8, bad.written(), "not a major.minor version") != null);
    try testing.expect(std.mem.indexOf(u8, bad.written(), "upgrade") == null);
}

test "a rule file from a newer schema exits 78, and a broken one still exits 65" {
    // The end-to-end claim, at the level an operator and a fleet script both
    // see: the two failures have different exit codes. `src/testdata/
    // future-schema-rules.json` is a real document from a hypothetical later
    // release — a newer `schema_version` AND constructs this binary has never
    // heard of — which is precisely the file that used to come back as a syntax
    // error and take enforcement with it.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var out = capture(testing.allocator);
    defer out.deinit();
    var err = capture(testing.allocator);
    defer err.deinit();
    var ctx = Ctx{
        .io = testing.io,
        .gpa = arena.allocator(),
        .env = .{},
        .out = &out.writer,
        .err = &err.writer,
        .now_unix = 1_700_000_000,
    };

    switch (try loadConfig(&ctx, "src/testdata/future-schema-rules.json")) {
        .ok => return error.TestUnexpectedResult,
        .code => |code| {
            try testing.expectEqual(EX_CONFIG, code);
            try testing.expect(code != EX_DATAERR);
        },
    }
    try testing.expect(std.mem.indexOf(u8, err.written(), "schema_version 2.0") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "./hookctl upgrade") != null);

    // A file that is genuinely not a rule document is still EX_DATAERR, so the
    // new code means one thing and one thing only.
    err.clearRetainingCapacity();
    switch (try loadConfig(&ctx, "src/testdata/shell-corpus.txt")) {
        .ok => return error.TestUnexpectedResult,
        .code => |code| try testing.expectEqual(EX_DATAERR, code),
    }
    try testing.expect(std.mem.indexOf(u8, err.written(), "invalid rule file") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "schema") == null);
}

test "diff-defaults reports a live file that declares no schema_version" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var shipped = try rules.parse(gpa, DEFAULT_RULES_JSON);
    defer shipped.deinit();

    // The state every install seeded before the field existed is in.
    var live_set = shipped.ruleSet();
    live_set.schema_version = null;
    const diff = try diffDefaults(gpa, shipped.ruleSet(), live_set);
    try testing.expect(!diff.inSync());
    try testing.expectEqualStrings("schema_version", diff.sections[0].name);
    try testing.expectEqualStrings("1.2", diff.sections[0].defaults);
    try testing.expect(std.mem.indexOf(u8, diff.sections[0].live, "absent") != null);
    try testing.expect(std.mem.indexOf(u8, diff.sections[0].live, "read as 1.0") != null);

    // A file that already declares the shipped version says nothing here: the
    // section exists to report a difference, not to narrate agreement.
    const same = try diffDefaults(gpa, shipped.ruleSet(), shipped.ruleSet());
    try testing.expect(same.inSync());
}

test "doctor: the log check separates off, unwritable, and unbounded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.log.enabled = false;
    var check = findCheck(try diagnoseIn(gpa, facts), "log");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "logging is off") != null);

    facts = healthyFacts();
    facts.log.write_error = "AccessDenied";
    check = findCheck(try diagnoseIn(gpa, facts), "log");
    try testing.expectEqual(Health.fail, check.status);

    facts = healthyFacts();
    facts.log.max_bytes = 0;
    check = findCheck(try diagnoseIn(gpa, facts), "log");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "rotation is disabled") != null);

    facts = healthyFacts();
    facts.log.rotated_exists = true;
    check = findCheck(try diagnoseIn(gpa, facts), "log");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "rotated generation") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "last hit") != null);
}

test "doctor: a broken overlay fails, an ignored one warns, an absent one passes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.overlay = .{ .path = "/repo/.claude/hook-rules.json", .state = .invalid, .err = "InvalidRules" };
    var check = findCheck(try diagnoseIn(gpa, facts), "overlay");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "NOT applied") != null);

    facts = healthyFacts();
    facts.overlay = .{ .allowed = false, .path = "/repo/.claude/hook-rules.json", .state = .ignored };
    check = findCheck(try diagnoseIn(gpa, facts), "overlay");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "allow_project_overlay") != null);

    facts = healthyFacts();
    facts.overlay = .{ .path = "/repo/.claude/hook-rules.json", .state = .active, .rules = 3 };
    check = findCheck(try diagnoseIn(gpa, facts), "overlay");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "3 rule(s)") != null);
}

test "doctor: a disabled rule is a failure that names it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.disable = .{
        .spec = "no-pkill,typo-rule",
        .known = &.{"no-pkill"},
        .unknown = &.{"typo-rule"},
    };
    var check = findCheck(try diagnoseIn(gpa, facts), "disabled");
    try testing.expectEqual(Health.fail, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "no-pkill") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "typo-rule") != null);
    try testing.expect(std.mem.indexOf(u8, check.remedy.?, "CLAUDE_HOOK_DISABLE") != null);

    // Set, but naming nothing: nothing is off, and nothing the operator meant
    // to switch off is either.
    facts = healthyFacts();
    facts.disable = .{ .spec = "no-pkil", .unknown = &.{"no-pkil"} };
    check = findCheck(try diagnoseIn(gpa, facts), "disabled");
    try testing.expectEqual(Health.warn, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "names no rule") != null);
}

test "doctor: path overrides are reported without being judged" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var facts = healthyFacts();
    facts.env = .{ .rules_override = "/elsewhere/rules.json", .log_override = "/elsewhere/log.jsonl" };
    const check = findCheck(try diagnoseIn(arena.allocator(), facts), "environment");
    try testing.expectEqual(Health.pass, check.status);
    try testing.expect(std.mem.indexOf(u8, check.detail, "CLAUDE_HOOK_RULES_PATH=/elsewhere/rules.json") != null);
    try testing.expect(std.mem.indexOf(u8, check.detail, "CLAUDE_HOOK_LOG_PATH=/elsewhere/log.jsonl") != null);
}

test "doctor report: a failing check carries its remediation line, and sets the exit code" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.version.installed = "0.1.9";
    const checks = try diagnoseIn(gpa, facts);

    var aw = capture(gpa);
    const code = try writeDoctorReport(&aw.writer, facts, checks, RENDER_WIDTH);
    const text = aw.written();
    try testing.expectEqual(@as(u8, 1), code);
    try testing.expect(std.mem.indexOf(u8, text, "claude dir : /sb") != null);
    try testing.expect(std.mem.indexOf(u8, text, "FAIL  version") != null);
    try testing.expect(std.mem.indexOf(u8, text, "      -> ") != null);
    try testing.expect(std.mem.indexOf(u8, text, "NOT HEALTHY") != null);
    // A passing check prints no remediation line even when it carries one.
    try testing.expect(std.mem.indexOf(u8, text, "PASS  wiring") != null);
    try testing.expect(std.mem.indexOf(u8, text, "result     : 7 pass, 0 warn, 1 fail") != null);
}

test "doctor report: healthy output says so in one word" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const facts = healthyFacts();
    var aw = capture(gpa);
    const code = try writeDoctorReport(&aw.writer, facts, try diagnoseIn(gpa, facts), RENDER_WIDTH);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "-> healthy") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "-> ") != null);
}

test "doctor JSON carries every check, its status and its remedy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.log.enabled = false;
    const checks = try diagnoseIn(gpa, facts);

    var aw = capture(gpa);
    const code = try writeDoctorJson(gpa, &aw.writer, facts, checks);
    // A warning is not a failure.
    try testing.expectEqual(@as(u8, 0), code);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expect(root.get("ok").?.bool);
    try testing.expectEqual(@as(i64, 1), root.get("warn").?.integer);
    try testing.expectEqualStrings("/repo/zig-out/bin/claude-hooker-gate", root.get("diagnosing").?.string);
    const rows = root.get("checks").?.array;
    try testing.expectEqual(@as(usize, 8), rows.items.len);
    try testing.expectEqualStrings("wiring", rows.items[0].object.get("id").?.string);
    // The log check is the fourth after `signature` joined the inventory.
    try testing.expectEqualStrings("log", rows.items[4].object.get("id").?.string);
    try testing.expectEqualStrings("warn", rows.items[4].object.get("status").?.string);
    try testing.expect(rows.items[4].object.get("remedy").? != .null);
}

test "status: one screen, and drift is called out on the first line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var aw = capture(gpa);
    _ = try writeStatus(gpa, &aw.writer, healthyFacts());
    const healthy = aw.written();
    try testing.expect(std.mem.indexOf(u8, healthy, "gate       : " ++ VERSION ++ " at /sb/hooks/claude-hooker-gate") != null);
    try testing.expect(std.mem.indexOf(u8, healthy, "12 rules, 487 cases (97 literal + 390 generated), selftest OK") != null);
    try testing.expect(std.mem.indexOf(u8, healthy, "overlay    : none for this directory") != null);
    try testing.expect(std.mem.indexOf(u8, healthy, "disabled   : nothing") != null);
    try testing.expect(std.mem.indexOf(u8, healthy, "DRIFT") == null);

    var drifted = healthyFacts();
    drifted.version.installed = "0.1.9";
    drifted.disable = .{ .spec = "no-pkill", .known = &.{"no-pkill"} };
    var aw2 = capture(gpa);
    _ = try writeStatus(gpa, &aw2.writer, drifted);
    try testing.expect(std.mem.indexOf(u8, aw2.written(), "(DRIFT: this build is " ++ VERSION ++ ")") != null);
    try testing.expect(std.mem.indexOf(u8, aw2.written(), "1 live rule(s) OFF via CLAUDE_HOOK_DISABLE: no-pkill") != null);
}

test "status: a missing install and a broken rule file are both stated plainly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.version.installed = null;
    facts.wiring.wired_command = null;
    facts.rules.state = .{ .invalid = "InvalidRules" };

    var aw = capture(gpa);
    _ = try writeStatus(gpa, &aw.writer, facts);
    const text = aw.written();
    try testing.expect(std.mem.indexOf(u8, text, "NOT INSTALLED") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no claude-hooker-gate entry in /sb/settings.json") != null);
    try testing.expect(std.mem.indexOf(u8, text, "INVALID: InvalidRules") != null);
}

test "status JSON carries the fields a script would branch on" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var facts = healthyFacts();
    facts.version.installed = "0.1.9";
    var aw = capture(gpa);
    _ = try writeStatusJson(&aw.writer, facts);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expect(root.get("version_drift").?.bool);
    try testing.expectEqualStrings("0.1.9", root.get("installed_version").?.string);
    try testing.expect(root.get("wired_here").?.bool);
    try testing.expectEqual(@as(i64, 487), root.get("rules").?.object.get("cases").?.integer);
    try testing.expect(root.get("rules").?.object.get("selftest_ok").?.bool);
    try testing.expectEqualStrings("absent", root.get("overlay_state").?.string);
}

// ---- diff-defaults --------------------------------------------------------

const diff_defaults_json =
    \\{ "rules": [
    \\    { "name": "keep", "reason": "unchanged", "match": [ { "kind": "tokens", "value": "git add -A" } ] },
    \\    { "name": "edited", "reason": "the shipped reason", "match": [ { "kind": "word", "value": "pkill" } ] },
    \\    { "name": "brand-new", "decision": "ask", "reason": "new in this release",
    \\      "match": [ { "kind": "command_word", "value": "dd" } ] }
    \\  ],
    \\  "tests": [ { "command": "git add -A", "expect": "deny" } ] }
;

const diff_live_json =
    \\{ "rules": [
    \\    { "name": "keep", "reason": "unchanged", "match": [ { "kind": "tokens", "value": "git add -A" } ] },
    \\    { "name": "edited", "decision": "ask", "reason": "my own reason",
    \\      "match": [ { "kind": "word", "value": "pkill" }, { "kind": "word", "value": "killall" } ] },
    \\    { "name": "mine", "reason": "a rule I wrote", "match": [ { "kind": "word", "value": "shutdown" } ] }
    \\  ],
    \\  "logging": { "enabled": false },
    \\  "tests": [ { "command": "git add -A", "expect": "deny" },
    \\             { "command": "shutdown now", "expect": "deny" } ] }
;

test "diff-defaults: added, changed with the fields, and the operator's own rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const shipped = try rules.parse(gpa, diff_defaults_json);
    const live = try rules.parse(gpa, diff_live_json);
    const diff = try diffDefaults(gpa, shipped.ruleSet(), live.ruleSet());

    try testing.expect(!diff.inSync());
    try testing.expectEqual(@as(usize, 1), diff.same);

    try testing.expectEqual(@as(usize, 1), diff.added.len);
    try testing.expectEqualStrings("brand-new", diff.added[0].name);

    try testing.expectEqual(@as(usize, 1), diff.removed.len);
    try testing.expectEqualStrings("mine", diff.removed[0].name);

    try testing.expectEqual(@as(usize, 1), diff.changed.len);
    try testing.expectEqualStrings("edited", diff.changed[0].name);
    try testing.expectEqualSlices(
        RuleField,
        &.{ .decision, .reason, .match },
        diff.changed[0].fields,
    );

    // Non-rule sections matter to an upgrade too: a `logging` block that
    // stopped matching the default is exactly the kind of thing an operator
    // changed once and forgot.
    var saw_logging = false;
    var saw_tests = false;
    for (diff.sections) |section| {
        if (eq(section.name, "logging")) saw_logging = true;
        if (eq(section.name, "tests")) saw_tests = true;
    }
    try testing.expect(saw_logging);
    try testing.expect(saw_tests);
}

test "diff-defaults: an unedited file is in sync, and says so in one line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const a = try rules.parse(gpa, diff_defaults_json);
    const b = try rules.parse(gpa, diff_defaults_json);
    const diff = try diffDefaults(gpa, a.ruleSet(), b.ruleSet());
    try testing.expect(diff.inSync());
    try testing.expectEqual(@as(usize, 3), diff.same);

    var aw = capture(gpa);
    const code = try writeDefaultsDiff(&aw.writer, "/sb/hook-rules.json", diff, RENDER_WIDTH);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "no differences") != null);
}

test "diff-defaults: a reference and the enumeration it expands to are the same rule" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Both sides are compared AFTER reference expansion, so a default that was
    // rewritten from a hand-written list into a `$set` over the same members
    // reports as identical — which is right, because the two match the same
    // commands. What the diff reports is a change in behaviour, not in spelling.
    // The group entry carries the leaf `kind` because that is what expansion
    // produces: `expandEntry` keeps the referencing matcher's kind on the group
    // it builds. A group's own `kind` is inert either way.
    const enumerated =
        \\{ "rules": [ { "name": "r", "reason": "x",
        \\    "match": [ { "kind": "word", "any": [ { "kind": "word", "value": "a" },
        \\                                          { "kind": "word", "value": "b" } ] } ] } ],
        \\  "tests": [ { "command": "a", "expect": "deny" } ] }
    ;
    const referenced =
        \\{ "sets": { "names": ["a", "b"] },
        \\  "rules": [ { "name": "r", "reason": "x",
        \\    "match": [ { "kind": "word", "value": "$names" } ] } ],
        \\  "tests": [ { "command": "a", "expect": "deny" } ] }
    ;
    const a = try rules.parse(gpa, enumerated);
    const b = try rules.parse(gpa, referenced);
    const diff = try diffDefaults(gpa, a.ruleSet(), b.ruleSet());
    try testing.expectEqual(@as(usize, 0), diff.changed.len);
    try testing.expectEqual(@as(usize, 1), diff.same);
    // The `sets` block itself did change, and that is reported as a section.
    try testing.expectEqual(@as(usize, 1), diff.sections.len);
    try testing.expectEqualStrings("sets", diff.sections[0].name);
}

test "diff-defaults report and JSON name every rule and every differing field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const shipped = try rules.parse(gpa, diff_defaults_json);
    const live = try rules.parse(gpa, diff_live_json);
    const diff = try diffDefaults(gpa, shipped.ruleSet(), live.ruleSet());

    var aw = capture(gpa);
    _ = try writeDefaultsDiff(&aw.writer, "/sb/hook-rules.json", diff, RENDER_WIDTH);
    const text = aw.written();
    try testing.expect(std.mem.indexOf(u8, text, "+ brand-new") != null);
    try testing.expect(std.mem.indexOf(u8, text, "~ edited  (decision, reason, match)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "- mine") != null);
    try testing.expect(std.mem.indexOf(u8, text, "= 1 rule(s) identical") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 added, 1 changed, 1 yours only") != null);

    var aw2 = capture(gpa);
    _ = try writeDefaultsDiffJson(gpa, &aw2.writer, "/sb/hook-rules.json", diff);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, aw2.written(), .{});
    const root = parsed.value.object;
    try testing.expect(!root.get("in_sync").?.bool);
    try testing.expectEqualStrings("brand-new", root.get("added").?.array.items[0].object.get("name").?.string);
    const fields = root.get("changed").?.array.items[0].object.get("fields").?.array;
    try testing.expectEqual(@as(usize, 3), fields.items.len);
    try testing.expectEqualStrings("decision", fields.items[0].string);
}

test "the defaults this binary carries are what diff-defaults compares against" {
    // `install.zig` seeds a fresh machine from these exact bytes and refuses to
    // install if they fail their own selftest. If the two ever stopped being
    // the same embed, `diff-defaults` would compare an operator's file against
    // rules nothing ever installed.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const shipped = try rules.parse(gpa, DEFAULT_RULES_JSON);
    const seeded = try rules.parse(gpa, DEFAULT_RULES_JSON);
    const diff = try diffDefaults(gpa, shipped.ruleSet(), seeded.ruleSet());
    try testing.expect(diff.inSync());
    try testing.expect(diff.same >= 6);
}

test "wrapped continuation lines account for the label already on the line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var aw = capture(arena.allocator());
    try aw.writer.writeAll("LABEL ");
    try writeWrappedAfter(&aw.writer, "      ", "one two three four five", 12);
    // The first line continues after "LABEL " and is measured from column 6,
    // so it fits fewer words than a fresh line would.
    try testing.expectEqualStrings(
        \\LABEL one
        \\      two three
        \\      four five
        \\
    , aw.written());
}

test "--claude-dir reaches the rule file of any install, and --rules still outranks it" {
    switch (parseArgs(&.{ "check", "--claude-dir", "/sb", "ls" })) {
        .check => |args| try testing.expectEqualStrings("/sb", args.claude_dir.?),
        else => return error.NotCheck,
    }
    switch (parseArgs(&.{ "selftest", "--claude-dir=/sb" })) {
        .selftest => |args| try testing.expectEqualStrings("/sb", args.claude_dir.?),
        else => return error.NotSelftest,
    }
    switch (parseArgs(&.{ "stats", "--claude-dir", "/sb", "--since", "7d" })) {
        .stats => |args| {
            try testing.expectEqualStrings("/sb", args.claude_dir.?);
            try testing.expectEqual(@as(i64, 7 * 24 * 60 * 60), args.since_seconds.?);
        },
        else => return error.NotStats,
    }
    // Both given: the explicit file wins, which is the same precedence
    // `rules.resolvePath` already gives an explicit path over the HOME default.
    switch (parseArgs(&.{ "check", "--claude-dir", "/sb", "--rules", "/r.json", "ls" })) {
        .check => |args| {
            try testing.expectEqualStrings("/sb", args.claude_dir.?);
            try testing.expectEqualStrings("/r.json", args.rules_path.?);
        },
        else => return error.NotCheck,
    }
}

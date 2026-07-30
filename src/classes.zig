//! Engine knowledge: textual path normalization, and the named classes a rule
//! may point at instead of enumerating members.
//!
//! ## Why this module exists
//!
//! A rule file that lists spellings is a rule file with holes in it. `rm -rf /`
//! and `rm -rf /usr/local/../..` delete the same thing; `find /` and `find ~`
//! walk the same disk; `psql` and `duckdb` take the same `DROP TABLE`. Every one
//! of those lists is combinatorial in something the operator does not control,
//! and the list is always one spelling short.
//!
//! So the spellings live HERE, versioned with the binary, behind two mechanisms:
//!
//!   - **path normalization** — `~/../`, `$HOME/`, `/usr/local/../..` and
//!     `/Users/me/..` are reduced to what they name before anything asks which
//!     class they are in;
//!   - **classes** — `home_or_root`, `shell_names`, `db_clients`,
//!     `package_managers`, `destructive_sql`, `traversal_commands`,
//!     `recursive_readers`, `recursive_mutators`, `filesystem_anchor`. A rule
//!     names the class; the members ship with the gate, and
//!     `claude-hooker-gate classes` prints every one of them so nothing here is
//!     hidden knowledge.
//!
//! ## Normalization is TEXTUAL, and that is a promise
//!
//! Nothing here touches the filesystem: no `stat`, no `realpath`, no `getcwd`,
//! no reading `$HOME`. A gate runs on every tool call, before the command does,
//! and a decision that depends on what is on disk is a decision that changes
//! under the operator's feet. So `~` and a resolvable `$HOME` are recognized as
//! a *root marker* rather than expanded to a value: the gate never needs to know
//! which home directory it is, only that the path is rooted at one. That is also
//! why `~/..` is answerable — it is above home, therefore a system directory,
//! whatever home turns out to be.
//!
//! What it does: expands `~`/`$HOME` to a root marker, collapses `.` and `..`,
//! strips redundant and trailing slashes (remembering that a trailing one was
//! written), and notes globs and unreadable expansions. What it refuses to do:
//! guess. A component carrying `$VAR` stays that component; a path rooted at
//! `$TMPDIR` is a relative path as far as this module is concerned, because the
//! text does not say where it goes.

const std = @import("std");
const shell = @import("shell.zig");

// ---------------------------------------------------------------------------
// path normalization
// ---------------------------------------------------------------------------

/// What a path is measured from.
pub const PathRoot = enum {
    /// Starts at `/`.
    absolute,
    /// Starts at the invoking user's home: `~`, `~/`, `$HOME`, `${HOME}`.
    home,
    /// Everything else, including a path rooted at a variable this module
    /// cannot read (`$TMPDIR/x`) — the text does not say where it goes, so
    /// nothing may claim it does.
    relative,
};

/// Cap on the components one normalized path keeps. A path deeper than this is
/// pathological, and the tail of it is never what decides a class.
pub const MAX_COMPONENTS: usize = 32;

/// One path, normalized textually. `comps` borrow from the input string.
pub const NormalPath = struct {
    root: PathRoot = .relative,
    comps_buf: [MAX_COMPONENTS][]const u8 = undefined,
    comps_len: usize = 0,
    /// `..` components that could not be popped: above home for a `home` path,
    /// above the working directory for a relative one. An absolute path cannot
    /// escape, because `/..` is `/`.
    escaped: usize = 0,
    /// The path was written with a trailing `/` — a promise that it is a
    /// directory, which is worth keeping even though it changes no component.
    trailing_slash: bool = false,
    /// A glob metacharacter appears somewhere in it.
    has_glob: bool = false,
    /// Some component carries an expansion this reader cannot evaluate.
    dynamic: bool = false,
    /// Components past `MAX_COMPONENTS` were dropped.
    truncated: bool = false,

    pub fn comps(self: *const NormalPath) []const []const u8 {
        return self.comps_buf[0..self.comps_len];
    }

    /// Depth below the root. `/` and `~` are 0.
    pub fn depth(self: *const NormalPath) usize {
        return self.comps_len;
    }

    /// The first `n` components, joined with `/`. Used to test a class's
    /// prefix lists.
    pub fn startsWithComps(self: *const NormalPath, want: []const []const u8) bool {
        if (want.len > self.comps_len) return false;
        for (want, 0..) |w, i| {
            if (!std.mem.eql(u8, w, self.comps_buf[i])) return false;
        }
        return true;
    }

    /// Render the normalized path back to text, for `--explain` and for tests.
    /// Truncates rather than failing when the buffer is short: this is a display
    /// path, never a decision path.
    pub fn render(self: *const NormalPath, buf: []u8) []const u8 {
        var n: usize = 0;
        const put = struct {
            fn f(dst: []u8, at: *usize, s: []const u8) void {
                const take = @min(s.len, dst.len - at.*);
                @memcpy(dst[at.*..][0..take], s[0..take]);
                at.* += take;
            }
        }.f;
        switch (self.root) {
            .absolute => put(buf, &n, "/"),
            .home => put(buf, &n, "~/"),
            .relative => {},
        }
        for (0..self.escaped) |_| put(buf, &n, "../");
        for (self.comps()) |c| {
            put(buf, &n, c);
            put(buf, &n, "/");
        }
        // A single trailing slash is the root's own; anything deeper only keeps
        // one when the operator wrote one.
        if (n > 1 and buf[n - 1] == '/' and !self.trailing_slash) n -= 1;
        if (n == 0) put(buf, &n, ".");
        return buf[0..n];
    }
};

const home_prefixes = [_][]const u8{ "$HOME", "${HOME}" };

/// Reduce a path-ish argument to what it names. Never fails: an empty or
/// nonsense argument is a relative path with no components, which is in no
/// class.
pub fn normalize(arg: []const u8) NormalPath {
    var out = NormalPath{};
    if (arg.len == 0) return out;

    out.has_glob = std.mem.indexOfAny(u8, arg, "*?[") != null;
    out.trailing_slash = arg.len > 1 and arg[arg.len - 1] == '/';

    var rest = arg;
    if (arg[0] == '/') {
        out.root = .absolute;
        rest = arg[1..];
    } else if (arg[0] == '~' and (arg.len == 1 or arg[1] == '/')) {
        out.root = .home;
        rest = arg[1..];
    } else blk: {
        for (home_prefixes) |p| {
            if (!std.mem.startsWith(u8, arg, p)) continue;
            if (arg.len > p.len and arg[p.len] != '/') continue;
            out.root = .home;
            rest = arg[p.len..];
            break :blk;
        }
    }

    var it = std.mem.splitScalar(u8, rest, '/');
    while (it.next()) |raw| {
        if (raw.len == 0 or std.mem.eql(u8, raw, ".")) continue;
        if (std.mem.eql(u8, raw, "..")) {
            if (out.comps_len > 0) {
                out.comps_len -= 1;
            } else switch (out.root) {
                // `/..` is `/`: an absolute path cannot climb past the root.
                .absolute => {},
                .home, .relative => out.escaped += 1,
            }
            continue;
        }
        if (std.mem.indexOfAny(u8, raw, "$`") != null) out.dynamic = true;
        if (out.comps_len == MAX_COMPONENTS) {
            out.truncated = true;
            continue;
        }
        out.comps_buf[out.comps_len] = raw;
        out.comps_len += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// the path classes
// ---------------------------------------------------------------------------

/// Top-level directories that belong to the system or hold every user's home.
/// Deliberately NOT here: `tmp`, and anything else a task legitimately owns.
///
/// The list is the UNION of what Linux and macOS put at the root, not one
/// platform's. Both halves are carried everywhere on purpose: normalization is
/// textual and never asks the filesystem what exists (see the module header), so
/// a Linux entry costs a macOS operator nothing except a member that never
/// appears — while a missing entry is a whole top-level directory the traversal
/// and mutation rules quietly stop covering. `Volumes` and `Network` are
/// macOS's; `snap`, `proc`, `sys` and `srv` are Linux's.
const system_roots = [_][]const u8{
    "usr",    "etc",     "var",          "bin",     "sbin",    "lib",   "lib32",
    "lib64",  "opt",     "boot",         "dev",     "proc",    "sys",   "root",
    "run",    "srv",     "mnt",          "media",   "home",    "snap",  "Users",
    "System", "Library", "Applications", "Volumes", "private", "cores", "Network",
};

/// Prefixes that are scratch space, however system-owned the directory above
/// them looks. A rule about system directories that swallows the one place a
/// task is *supposed* to write is a rule an operator switches off.
///
/// Again the union, and again for a reason that is not symmetry: the false
/// positive this list prevents is a DENY on the working directory the harness
/// itself handed the task, which is the single most likely way an operator
/// concludes the gate is broken and turns it off.
///
///   - macOS: `$TMPDIR` is `/var/folders/...` and session scratch is under
///     `/private/tmp` (`/tmp` is a symlink to it, and `getcwd` reports the
///     resolved form);
///   - Linux: `$XDG_RUNTIME_DIR` is `/run/user/<uid>` and `/dev/shm` is the
///     standard shared-memory scratch — both sit under a system root
///     (`run`, `dev`) and would otherwise be read as system directories.
const temp_prefixes = [_][]const []const u8{
    &.{"tmp"},
    &.{ "var", "tmp" },
    &.{ "var", "folders" },
    &.{ "private", "tmp" },
    &.{ "private", "var", "tmp" },
    &.{ "private", "var", "folders" },
    &.{ "run", "user" },
    &.{ "dev", "shm" },
};

fn isSystemRoot(comp: []const u8) bool {
    for (system_roots) |r| {
        if (std.mem.eql(u8, r, comp)) return true;
    }
    return false;
}

fn underTempRoot(p: *const NormalPath) bool {
    for (temp_prefixes) |prefix| {
        if (p.startsWithComps(prefix)) return true;
    }
    return false;
}

/// Is this path rooted at the user's home or in a system directory — i.e. is
/// deleting it recursively something no task owns?
///
///   - a relative path never is: `./build`, `node_modules`, `dist` are what a
///     task creates and what it may destroy;
///   - a home-rooted path always is, at any depth: `$HOME/.config` and
///     `~/repos/x` are the operator's, not the task's;
///   - an absolute path is when it is `/` itself or sits under a system root,
///     EXCEPT under a scratch root (`/tmp`, `/var/tmp`, `/var/folders`,
///     `/private/tmp`, `/run/user`, `/dev/shm` — see `temp_prefixes`), which is
///     exactly where a task is supposed to write.
pub fn inHomeOrRoot(arg: []const u8) bool {
    const p = normalize(arg);
    return pathInHomeOrRoot(&p);
}

pub fn pathInHomeOrRoot(p: *const NormalPath) bool {
    return switch (p.root) {
        .relative => false,
        .home => true,
        .absolute => blk: {
            if (p.depth() == 0) break :blk true;
            if (underTempRoot(p)) break :blk false;
            break :blk isSystemRoot(p.comps()[0]);
        },
    };
}

/// Is this path an ANCHOR for a whole-world traversal — a place a walk starts
/// when it means "everything"?
///
/// Tighter than `home_or_root` on purpose. `chmod -R` over `/Users/me/project`
/// is unrecoverable and belongs to the deny tier; `find /Users/me/project` is an
/// ordinary bounded search and must not prompt. So an anchor is the root itself,
/// a single system top-level directory, or the home directory itself — never
/// something below them.
pub fn isFilesystemAnchor(arg: []const u8) bool {
    const p = normalize(arg);
    return pathIsFilesystemAnchor(&p);
}

pub fn pathIsFilesystemAnchor(p: *const NormalPath) bool {
    return switch (p.root) {
        .relative => false,
        // `~`, `~/`, `$HOME` — and `~/..`, which is higher still.
        .home => p.depth() == 0,
        .absolute => blk: {
            if (p.depth() == 0) break :blk true;
            if (p.depth() > 1) break :blk false;
            break :blk isSystemRoot(p.comps()[0]);
        },
    };
}

// ---------------------------------------------------------------------------
// the class catalog
// ---------------------------------------------------------------------------

pub const Kind = enum {
    /// Members are command basenames; use with `command_word`.
    command,
    /// Members are phrases; use with `argv` (or `substring` on a file body).
    phrase,
    /// Membership is decided by normalizing the argument, not by comparing it;
    /// use with `path_class`. The member list is what the class RECOGNIZES —
    /// a reading aid and the source the test generators draw from.
    path,
};

pub const Class = struct {
    name: []const u8,
    kind: Kind,
    /// One sentence: what the class is for, and what it deliberately excludes.
    about: []const u8,
    members: []const []const u8,

    /// Is `value` a member? For a path class this normalizes first, which is
    /// the whole reason path classes are not member lists.
    pub fn contains(self: Class, value: []const u8) bool {
        return switch (self.kind) {
            .command, .phrase => blk: {
                for (self.members) |m| {
                    if (std.mem.eql(u8, m, value)) break :blk true;
                }
                break :blk false;
            },
            .path => self.containsPath(value),
        };
    }

    fn containsPath(self: Class, value: []const u8) bool {
        const p = normalize(value);
        if (std.mem.eql(u8, self.name, "home_or_root")) return pathInHomeOrRoot(&p);
        if (std.mem.eql(u8, self.name, "filesystem_anchor")) return pathIsFilesystemAnchor(&p);
        return false;
    }
};

const db_clients = [_][]const u8{
    "psql",    "mysql",             "mariadb",   "sqlite3", "sqlcmd",
    "mongosh", "clickhouse-client", "cockroach", "duckdb",
};

const package_managers = [_][]const u8{
    "apt",     "apt-get", "aptitude", "dpkg",   "yum",  "dnf",  "rpm",
    "zypper",  "pacman",  "apk",      "emerge", "brew", "port", "snap",
    "flatpak", "pip",     "pip3",     "pipx",   "npm",  "pnpm", "yarn",
    "gem",     "cargo",   "conda",    "mamba",
};

const destructive_sql = [_][]const u8{
    "DROP TABLE", "DROP DATABASE", "DROP SCHEMA", "TRUNCATE TABLE",
};

const traversal_commands = [_][]const u8{ "find", "du", "tree", "rg", "ag", "ack" };

const recursive_readers = [_][]const u8{ "grep", "egrep", "fgrep", "ls", "cp", "wc" };

const recursive_mutators = [_][]const u8{ "chmod", "chown", "chgrp", "rsync" };

/// The ad-hoc stream-transformation tools: the vocabulary a shell program
/// gets assembled from, one fragment at a time. Deliberately NOT `grep` —
/// searching is reading, and `grep -n pattern file` on its own mutates and
/// composes nothing.
const stream_editors = [_][]const u8{ "sed", "awk", "gawk", "mawk", "tr", "cut" };

/// Canonical spellings `home_or_root` recognizes. Every one of them is in the
/// class (asserted below), and the cross-product test generators draw their
/// targets from exactly this list — so a normalization change is a test change
/// rather than a silent policy change.
const home_or_root_members = [_][]const u8{
    "/",                "~",          "~/",            "~/..",
    "$HOME",            "$HOME/",     "$HOME/.config", "/usr",
    "/usr/local/../..", "/etc/nginx", "/var/lib",      "/Users",
    "/Users/me/..",     "/home",      "/System",       "/Library",
};

const filesystem_anchor_members = [_][]const u8{
    "/",    "~",      "~/",    "$HOME",   "/usr",     "/etc", "/var",
    "/opt", "/Users", "/home", "/System", "/Library",
};

/// Every class the engine ships, in printing order.
pub const all = [_]Class{
    .{
        .name = "home_or_root",
        .kind = .path,
        .about = "the operator's home or a system directory, at any depth, after normalization; never a relative path and never scratch space (/tmp, /var/tmp, /var/folders, /private/tmp, /run/user, /dev/shm)",
        .members = &home_or_root_members,
    },
    .{
        .name = "filesystem_anchor",
        .kind = .path,
        .about = "a place a whole-world walk starts: / itself, one system top-level directory, or the home directory itself — never something below them",
        .members = &filesystem_anchor_members,
    },
    .{
        .name = "shell_names",
        .kind = .command,
        .about = "programs that re-parse whatever they are given, which is what makes a pipe into one an execution of unread code",
        .members = &shell.shell_name_list,
    },
    .{
        .name = "db_clients",
        .kind = .command,
        .about = "database clients that take a statement as an argument, where a schema-destroying statement is unrecoverable without a restore",
        .members = &db_clients,
    },
    .{
        .name = "package_managers",
        .kind = .command,
        .about = "installers that change the machine or the environment out from under the project",
        .members = &package_managers,
    },
    .{
        .name = "destructive_sql",
        .kind = .phrase,
        .about = "statements that destroy schema rather than rows; match with ignore_case, since SQL keywords are case-insensitive",
        .members = &destructive_sql,
    },
    .{
        .name = "traversal_commands",
        .kind = .command,
        .about = "programs that walk everything below their starting point by default, so naming an anchor is naming the whole disk",
        .members = &traversal_commands,
    },
    .{
        .name = "recursive_readers",
        .kind = .command,
        .about = "programs that walk everything below their starting point only when asked recursively; pair with a recursion flag",
        .members = &recursive_readers,
    },
    .{
        .name = "recursive_mutators",
        .kind = .command,
        .about = "programs that CHANGE every file below their starting point; over home or a system directory this is unrecoverable without a restore",
        .members = &recursive_mutators,
    },
    .{
        .name = "stream_editors",
        .kind = .command,
        .about = "ad-hoc stream-transformation tools (sed, awk, tr, cut) — the fragments shell programs get assembled from instead of being real programs",
        .members = &stream_editors,
    },
};

pub fn find(name: []const u8) ?*const Class {
    for (&all) |*c| {
        if (std.mem.eql(u8, c.name, name)) return c;
    }
    return null;
}

/// The `$class:` reference prefix a matcher value may carry.
pub const REF_PREFIX = "$class:";

/// The class a matcher value references, or null when it references none.
/// `$class:nope` returns null too — the lint reports it, and an unknown class
/// must never be a matcher that quietly matches nothing.
pub fn referenced(value: []const u8) ?*const Class {
    if (!std.mem.startsWith(u8, value, REF_PREFIX)) return null;
    return find(value[REF_PREFIX.len..]);
}

pub fn isReference(value: []const u8) bool {
    return std.mem.startsWith(u8, value, REF_PREFIX);
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectNormal(arg: []const u8, want: []const u8) !void {
    const p = normalize(arg);
    var buf: [256]u8 = undefined;
    const got = p.render(&buf);
    if (!std.mem.eql(u8, want, got)) {
        std.debug.print("normalize({s}) = {s}, want {s}\n", .{ arg, got, want });
        return error.NormalizeMismatch;
    }
}

test "normalization: dots collapse, slashes tidy, ~ and $HOME are one root" {
    try expectNormal("/usr/local/../..", "/");
    try expectNormal("/usr/local/..", "/usr");
    try expectNormal("/Users/me/..", "/Users");
    try expectNormal("//usr///local//", "/usr/local/");
    try expectNormal("/./a/./b", "/a/b");
    try expectNormal("/..", "/");
    try expectNormal("/../../..", "/");
    try expectNormal("~", "~");
    try expectNormal("~/", "~/");
    try expectNormal("$HOME", "~");
    try expectNormal("${HOME}/.config", "~/.config");
    try expectNormal("~/../", "~/../");
    try expectNormal("~/..", "~/..");
    try expectNormal("./build", "build");
    try expectNormal("node_modules", "node_modules");
    try expectNormal("a/b/../c", "a/c");
    try expectNormal("..", "..");
    try expectNormal(".", ".");
    try expectNormal("", ".");
}

test "normalization: roots, globs, trailing slashes and unreadable components" {
    try testing.expectEqual(PathRoot.absolute, normalize("/etc").root);
    try testing.expectEqual(PathRoot.home, normalize("~/x").root);
    try testing.expectEqual(PathRoot.home, normalize("$HOME/x").root);
    // `~user` is somebody else's home and is not this marker.
    try testing.expectEqual(PathRoot.relative, normalize("~root/x").root);
    // A path rooted at a variable this module cannot read says nothing about
    // where it goes, so it claims nothing.
    try testing.expectEqual(PathRoot.relative, normalize("$TMPDIR/x").root);
    try testing.expect(normalize("$TMPDIR/x").dynamic);

    try testing.expect(normalize("/etc/*.conf").has_glob);
    try testing.expect(!normalize("/etc/nginx").has_glob);
    try testing.expect(normalize("/etc/").trailing_slash);
    try testing.expect(!normalize("/etc").trailing_slash);
    try testing.expectEqual(@as(usize, 1), normalize("~/..").escaped);
    try testing.expectEqual(@as(usize, 0), normalize("/..").escaped);
}

test "home_or_root: what no task owns, and what every task does" {
    const yes = [_][]const u8{
        "/",              "~/../",          "/usr/local/../..", "$HOME/",
        "~",              "$HOME",          "/Users/me/..",     "/etc/nginx",
        "/usr/local/lib", "/var/lib/thing", "$HOME/.config",    "/Users/me/project",
        "/home",          "${HOME}/x",      "~/repos/x",        "/System/Library",
    };
    for (yes) |a| {
        if (!inHomeOrRoot(a)) {
            std.debug.print("expected {s} in home_or_root\n", .{a});
            return error.NotInClass;
        }
    }

    const no = [_][]const u8{
        "./build",         "build",     "node_modules", "dist/x",
        "/tmp/scratch",    "/tmp",      "/var/tmp/x",   "/var/folders/ab/cd",
        "/private/tmp/x",  "$TMPDIR/x", "../sibling",   "/repo/src",
        "/data/warehouse", "out.tgz",   ".",            "",
    };
    for (no) |a| {
        if (inHomeOrRoot(a)) {
            std.debug.print("expected {s} NOT in home_or_root\n", .{a});
            return error.UnexpectedClassMember;
        }
    }
}

test "the path classes cover both platforms' roots and both platforms' scratch space" {
    // Normalization is textual, so these answers are the same on every machine —
    // which is exactly why the lists have to be the union rather than the host's.
    // The failure this prevents is asymmetric and worth naming:
    //
    //   - a scratch directory read as a system directory is a false DENY on the
    //     working directory the harness just handed the task, which is how an
    //     operator decides the gate is broken;
    //   - a top-level directory missing from `system_roots` is a whole tree the
    //     traversal and mutation rules silently stop covering.
    //
    // Linux scratch space, which sits under a system root and must still be
    // writable: `$XDG_RUNTIME_DIR` and shared memory.
    const scratch = [_][]const u8{
        "/run/user/1000", "/run/user/1000/build", "/run/user",
        "/dev/shm",       "/dev/shm/cache",       "/tmp/x",
        "/var/tmp/x",     "/var/folders/ab/cd",   "/private/tmp/x",
    };
    for (scratch) |a| {
        if (inHomeOrRoot(a)) {
            std.debug.print("expected scratch {s} NOT in home_or_root\n", .{a});
            return error.UnexpectedClassMember;
        }
    }
    // The rest of `/run` and `/dev` is still the system: the exemption is the
    // two scratch prefixes, not their parents.
    const system = [_][]const u8{
        "/run",       "/run/systemd", "/dev",       "/dev/sda", "/snap",
        "/snap/core", "/proc/1",      "/sys/class", "/srv/www", "/Volumes/Data",
    };
    for (system) |a| {
        if (!inHomeOrRoot(a)) {
            std.debug.print("expected system {s} in home_or_root\n", .{a});
            return error.NotInClass;
        }
    }
    // And each platform's top-level directories are anchors, so a whole-world
    // walk is caught wherever it is started from.
    const anchors = [_][]const u8{ "/snap", "/proc", "/sys", "/srv", "/run", "/dev", "/Volumes", "/Network" };
    for (anchors) |a| {
        if (!isFilesystemAnchor(a)) {
            std.debug.print("expected {s} to be an anchor\n", .{a});
            return error.NotInClass;
        }
    }
}

test "filesystem_anchor is tighter than home_or_root, on purpose" {
    const yes = [_][]const u8{ "/", "~", "~/", "$HOME", "/usr", "/etc/", "/Users", "/home" };
    for (yes) |a| {
        if (!isFilesystemAnchor(a)) {
            std.debug.print("expected {s} to be an anchor\n", .{a});
            return error.NotInClass;
        }
    }
    // Everything below an anchor is an ordinary bounded target: a read-only
    // walk of it must not prompt, even though a recursive CHMOD of it is denied.
    const no = [_][]const u8{
        "/Users/me/project", "~/repos/x", "/etc/nginx", "/usr/local", "./build",
        "src",               "/tmp",      "$TMPDIR",    "../..",
    };
    for (no) |a| {
        if (isFilesystemAnchor(a)) {
            std.debug.print("expected {s} NOT to be an anchor\n", .{a});
            return error.UnexpectedClassMember;
        }
        // ...and an anchor is always in home_or_root, never the reverse.
        if (isFilesystemAnchor(a) and !inHomeOrRoot(a)) return error.ClassesDisagree;
    }
}

test "every path class member really is in its own class" {
    for (&all) |*c| {
        if (c.kind != .path) continue;
        for (c.members) |m| {
            if (c.contains(m)) continue;
            std.debug.print("class {s} lists {s}, which is not in it\n", .{ c.name, m });
            return error.ClassMemberNotInClass;
        }
    }
}

test "the catalog: unique names, non-empty members, and every one documented" {
    for (&all, 0..) |*c, i| {
        try testing.expect(c.name.len > 0);
        try testing.expect(c.about.len > 20);
        try testing.expect(c.members.len > 0);
        for (all[0..i]) |*earlier| {
            try testing.expect(!std.mem.eql(u8, earlier.name, c.name));
        }
    }
    try testing.expect(find("home_or_root") != null);
    try testing.expect(find("nope") == null);
    try testing.expect(referenced("$class:db_clients") != null);
    try testing.expect(referenced("$class:nope") == null);
    try testing.expect(referenced("psql") == null);
    try testing.expect(isReference("$class:nope"));
}

test "command classes agree with the lexer's own list" {
    const shells = find("shell_names").?;
    for (shells.members) |m| try testing.expect(shell.isShellName(m));
    try testing.expect(shells.contains("bash"));
    try testing.expect(!shells.contains("python"));
    try testing.expect(find("db_clients").?.contains("duckdb"));
    try testing.expect(find("destructive_sql").?.contains("DROP TABLE"));
}

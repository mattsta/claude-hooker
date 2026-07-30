"""The types the runner is built out of.

Every value that travels between two functions in this package has a type
here, and every one of them is a frozen dataclass. That is the same discipline
the Zig side keeps (`Layout`, `Facts`, `Check`) and it is kept for the same
reason: the runner's job is to say true things about an install, and a tuple of
strings threaded through six call sites is how a tool starts saying things that
used to be true.

Two rules hold in this module:

  * nothing here does any work — no filesystem, no subprocess, no printing.
    `discovery` resolves, `proc` runs, `ui` prints, the `verbs` decide. A type
    that cannot act cannot surprise anyone.
  * every path is a `Path` and every choice is an enum. `"built"` and
    `"installed"` are a `GateSource`; "takes no arguments" is an `ArgShape`.
    A misspelled string is then an AttributeError at import rather than a verb
    that quietly stops doing the thing it says it does.

`Process` is a Protocol rather than the concrete `proc.Runner` so that a test
can hand a verb a recorder and read back the argv it would have run. That is
the only reason the indirection exists, and it is a good one: every external
command this tool issues is then observable without spawning anything.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Protocol

#: The oldest interpreter this runner supports. The entry point refuses
#: anything older with one clear line and exit 69 — never a traceback — and
#: `ruff.toml`'s `target-version` must match, so modernization can never
#: outrun this floor. A machine whose only python3 is older (some macOS
#: system interpreters) needs a newer one on PATH before `./hookctl` runs.
MIN_PYTHON = (3, 11)

#: Spelled `@dataclass(**FROZEN)` throughout: every value that crosses a
#: function boundary is frozen and slotted. One constant rather than two
#: keyword arguments at forty call sites, so the discipline has exactly one
#: place to be stated — and relaxed, if that day ever comes.
FROZEN: dict[str, bool] = {"frozen": True, "slots": True}

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

# Exit codes. 64 is sysexits' EX_USAGE and 69 its EX_UNAVAILABLE, matching what
# the Zig side already uses; anything else is passed through from the child.
EX_OK = 0
EX_FAIL = 1
EX_USAGE = 64
EX_UNAVAILABLE = 69
# What `timeout(1)` reports when it had to kill what it was watching. Spelled
# the same here so that a step this runner gave up on is distinguishable in a
# script from a step that ran and failed.
EX_TIMEOUT = 124
# What a shell reports for a process killed by SIGINT, which is what a
# Ctrl-C'd runner should look like to the shell that started it.
EX_INTERRUPTED = 130

# ---------------------------------------------------------------------------
# wall-clock budgets
# ---------------------------------------------------------------------------

# Every child this runner spawns is bounded, because an unbounded one is the
# incident these numbers exist because of: a `zig build test` whose invoker died
# was left with PPID 1, its compiled test binaries still executing an infinite
# loop from a half-finished refactor, and it spun for eleven hours at 100% CPU
# while every gate reported green — the spinning binary was built from source
# that no longer existed, so nothing that read the source could see it.
#
# The numbers are ceilings, not estimates: they are meant to be far above any
# honest run on any machine and far below "nobody is watching any more".

#: A compile, a test run, a `zig fmt`, an install. This repository's own suite
#: is well under a minute; five minutes is a machine in trouble.
DEFAULT_BUILD_TIMEOUT = 300.0

#: `cross` compiles the binaries *and* every test module for three Linux
#: targets. It is the one step whose honest duration is tens of minutes.
CROSS_TIMEOUT = 1800.0

#: `--timeout SECONDS`, and the environment variable that means the same thing.
#: The flag wins; both are floors of one second, because `--timeout 0` spelled
#: "unbounded" would reintroduce the bug.
TIMEOUT_FLAG = "--timeout"
TIMEOUT_ENV = "HOOKCTL_TIMEOUT"
MIN_TIMEOUT = 1.0

MIN_ZIG = "0.16.0"

# Everything this package reads and everything it decodes is UTF-8: the README,
# the rule documents, and the gate's own output, which is full of em-dashes. It
# is stated explicitly at every boundary rather than left to the locale, because
# the default is `locale.getpreferredencoding()` — always UTF-8 on macOS, and
# `ascii` on Linux under `LC_ALL=C`. A tool that works on the author's laptop
# and raises UnicodeDecodeError on a CI runner is worse than one that never
# worked.
ENCODING = "utf-8"

GATE_NAME = "claude-hooker-gate"
INSTALLER_NAME = "claude-hooker-install"

# The name the installer gives the operator's policy document and its log,
# inside the claude dir. Duplicated from the Zig side on purpose: `Paths` is
# the one place in this package that knows the layout, and these are the two
# strings it needs to know it.
RULES_NAME = "hook-rules.json"
LOG_NAME = "hook-gate-log.jsonl"
SETTINGS_NAME = "settings.json"

# The two rule documents the catalog is read from: the defaults `setup` seeds,
# and the cookbook's fixture — which the RULES_COOKBOOK asserts is byte-identical
# to every recipe it documents, and is therefore machine-adoptable.
SHIPPED_RULES_FILE = "src/default-rules.json"
COOKBOOK_RULES_FILE = "src/testdata/cookbook-recipes.json"

# The rule documents that must all pass their own cases and lint clean. Each is
# a real policy file: the shipped defaults, the CLI's fixture, the cookbook's
# fixture, and the structural-matcher fixture.
RULE_FILES: tuple[str, ...] = (
    SHIPPED_RULES_FILE,
    "src/testdata/selftest-rules.json",
    COOKBOOK_RULES_FILE,
    "src/testdata/structural-rules.json",
)


# ---------------------------------------------------------------------------
# the platform
# ---------------------------------------------------------------------------


@dataclass(**FROZEN)
class Platform:
    """The machine, reduced to the one question this tool asks of it.

    `needs_signing` is a field rather than a `system == "Darwin"` test spelled
    out at each use, so the whole macOS path can be exercised on any machine by
    constructing the other value. A platform check written inline is a branch
    that only ever runs on the developer's own laptop.
    """

    system: str
    arch: str
    needs_signing: bool


# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------


@dataclass(**FROZEN)
class Paths:
    """Every path this tool knows about, derived once from two directories.

    The ONE place that knows the layout. `--claude-dir` is then a single
    substitution rather than six independently-written joins that can disagree
    about where an install is — the same property `cli.Layout` gives the Zig
    side, and the reason a sandbox install is trustworthy enough to test in.
    """

    project_root: Path
    claude_dir: Path
    built_gate: Path
    built_installer: Path
    installed_gate: Path
    rules_path: Path
    log_path: Path
    settings_path: Path
    readme: Path

    @classmethod
    def of(cls, project_root: Path, claude_dir: Path) -> Paths:
        bin_dir = project_root / "zig-out" / "bin"
        hooks_dir = claude_dir / "hooks"
        return cls(
            project_root=project_root,
            claude_dir=claude_dir,
            built_gate=bin_dir / GATE_NAME,
            built_installer=bin_dir / INSTALLER_NAME,
            installed_gate=hooks_dir / GATE_NAME,
            rules_path=claude_dir / RULES_NAME,
            log_path=claude_dir / LOG_NAME,
            settings_path=claude_dir / SETTINGS_NAME,
            readme=project_root / "README.md",
        )

    def display(self, path: Path) -> str:
        """How a path is spelled in output.

        Children run with the repository root as their cwd, so anything under
        it is named by its repo-relative path: no machine-specific absolute
        path is ever printed that was not the operator's own argument.
        """
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)


# ---------------------------------------------------------------------------
# the toolchain and the binaries
# ---------------------------------------------------------------------------


@dataclass(**FROZEN)
class Toolchain:
    """The Zig compiler, or the fact that there isn't one.

    This project ships as source — there is no prebuilt binary to fall back on
    — so "no toolchain" is a first-class state with its own message, not an
    exception. Tests reach it by constructing `Toolchain.absent()` rather than
    by moving `zig` out of the way.
    """

    path: str | None = None
    version: str | None = None
    present: bool = False

    @classmethod
    def absent(cls) -> Toolchain:
        return cls()

    def with_version(self, version: str | None) -> Toolchain:
        return replace(self, version=version)

    def describe(self) -> str:
        """`zig <version> at <path>`, with whatever of that is known."""
        if not self.present:
            return f"not on PATH; install {MIN_ZIG}+"
        if self.version:
            return f"zig {self.version} at {self.path}"
        return f"zig at {self.path}"


class GateSource(Enum):
    """Which of the two gate binaries a verb is talking to."""

    built = "built"
    installed = "installed"


@dataclass(**FROZEN)
class GateBinary:
    path: Path
    source: GateSource
    version: str | None = None

    @property
    def is_built(self) -> bool:
        return self.source is GateSource.built

    def with_version(self, version: str | None) -> GateBinary:
        return replace(self, version=version)


class GateNotice(Enum):
    """Why the choice of gate is worth saying out loud.

    Saying it on every run would train the reader to skip the line that
    matters, so the choice is announced only when it could change the answer.
    """

    #: The two binaries are the same bytes, or there is only one. Say nothing.
    quiet = "quiet"
    #: Using the freshly built gate while a *different* one is installed.
    built_differs = "built_differs"
    #: Nothing is built; the installed gate is standing in.
    installed_fallback = "installed_fallback"


@dataclass(**FROZEN)
class GateChoice:
    """Which gate a passthrough verb will run, and why.

    The freshly built one wins: it is the tree the operator is looking at, and
    for `doctor` it is the only binary that can see version drift at all.
    """

    gate: GateBinary | None
    notice: GateNotice = GateNotice.quiet
    installed: Path | None = None

    @property
    def resolved(self) -> bool:
        return self.gate is not None


# ---------------------------------------------------------------------------
# running things
# ---------------------------------------------------------------------------


class RunMode(Enum):
    """What happens to a child's stdout and stderr."""

    #: The child writes straight to this process's stdio. For anything an
    #: operator is watching: `zig build`, the installer, the gate.
    inherit = "inherit"
    #: Captured and returned. For anything whose output is parsed.
    capture = "capture"
    #: Captured, and replayed only if the child failed. For a step whose
    #: success is a single tick in a report and whose failure is the whole
    #: reason the report exists.
    quiet = "quiet"


@dataclass(**FROZEN)
class RunResult:
    """One external command, and what came of it.

    Carries the argv it actually ran so that a failure can be reported as
    something reproducible by hand rather than as "a subprocess failed".
    """

    argv: tuple[str, ...]
    code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    #: The runner gave up on this one and killed its process group. A separate
    #: fact from "exited nonzero": a step that was killed proved nothing, and
    #: the report has to say which step and after how long rather than let a
    #: timeout look like a test failure.
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    def first_error_line(self) -> str:
        """The most useful single line for a one-line report."""
        for text in (self.stderr, self.stdout):
            for line in text.splitlines():
                if line.strip():
                    return line.strip()
        return f"exited {self.code}"


class Process(Protocol):
    """The single subprocess chokepoint, as its callers see it.

    A Protocol rather than the concrete runner so a test can substitute a
    recorder: every external command this tool issues is then observable
    without spawning anything.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        mode: RunMode = RunMode.inherit,
        timeout: float | None = None,
        scrub_env: bool = False,
    ) -> RunResult: ...


# ---------------------------------------------------------------------------
# the process table
# ---------------------------------------------------------------------------


@dataclass(**FROZEN)
class ProcessRecord:
    """One row of `ps`, parsed.

    `elapsed` is seconds rather than the `[[DD-]HH:]MM:SS` string `ps` prints,
    and `cpu` is a float that may exceed 100 on a multi-core Linux box. Both are
    numbers here so that "has this been alive for eleven hours" is a comparison
    rather than a second parse at each call site.
    """

    pid: int
    ppid: int
    uid: int
    elapsed: float
    cpu: float
    rss_kib: int
    command: str

    @property
    def exe(self) -> str:
        """The first token of the command line, as `ps` printed it.

        Not resolved to an absolute path: it may be relative (`zig build` runs
        its test binaries as `./.zig-cache/o/<hash>/test`) and resolving it
        would need the process's own cwd, which is a separate probe. Where the
        relative spelling matters, `attribution` is what interprets it.
        """
        return self.command.split(" ", 1)[0]

    @property
    def name(self) -> str:
        return self.exe.rsplit("/", 1)[-1]

    @property
    def orphaned(self) -> bool:
        """Reparented to init, which is what "its invoker died" looks like.

        This is the single most load-bearing fact in this module. A build runner
        with PPID 1 is one whose invoker is gone and which nothing is waiting
        on: no shell will reap it, no gate will notice it, and its own children
        outlive it in turn.
        """
        return self.ppid == 1


@dataclass(**FROZEN)
class ProcessTable:
    """Every process `ps` listed, or the fact that it could not be asked.

    `available=False` is not "no processes": it is "this machine would not tell
    us", which has to be reported as not-applicable rather than as clean, or the
    check that exists to catch a runaway would report green on the one machine
    where it cannot see.
    """

    records: tuple[ProcessRecord, ...] = ()
    available: bool = True
    note: str = ""

    def find(self, pid: int) -> ProcessRecord | None:
        for record in self.records:
            if record.pid == pid:
                return record
        return None

    def parent_of(self, pid: int) -> int | None:
        record = self.find(pid)
        return None if record is None else record.ppid

    def lineage(self, pid: int) -> frozenset[int]:
        """`pid`, every ancestor of it, and every descendant of it.

        The exclusion set. A reaper that can match its own process tree is a
        reaper that kills the build it was run to protect — and `hookctl build`
        spawns exactly the kind of child this module hunts for.
        """
        found = {pid}
        walking = pid
        # Upwards. Bounded by the record count: a cycle in the ppid graph cannot
        # happen, but a truncated read of one could.
        for _ in range(len(self.records) + 1):
            parent = self.parent_of(walking)
            if parent is None or parent in found or parent <= 1:
                break
            found.add(parent)
            walking = parent
        # Downwards, to a fixed point.
        for _ in range(len(self.records) + 1):
            grew = False
            for record in self.records:
                if record.ppid in found and record.pid not in found:
                    found.add(record.pid)
                    grew = True
            if not grew:
                break
        return frozenset(found)


class ProcessKind(Enum):
    """What makes a process one of this toolchain's, in the words used to
    report it. `ps` alone cannot say "this is a build"; these are the four
    shapes `zig build` actually leaves in a process table."""

    #: `zig build <step>` — the invocation an operator typed.
    build_step = "zig build"
    #: The compiled build runner under `.zig-cache/o/<hash>/build`, which is the
    #: process that carries the absolute project root in its argv.
    build_runner = "build runner"
    #: A compiler process. On macOS these show up as a bare `(zig)`, with no
    #: argv at all, which is why membership is decided by ancestry too.
    compiler = "compiler"
    #: A compiled test binary under `.zig-cache/o/<hash>/`. The thing that spun.
    test_binary = "test binary"
    #: Something out of `zig-out/`, i.e. one of this project's own products.
    built_binary = "built binary"


class Attribution(Enum):
    """Whose checkout a process belongs to."""

    this_project = "this_project"
    other_project = "other_project"
    #: Shortlisted, but nothing tied it to a root: no absolute path in the argv,
    #: no readable cwd, no shortlisted relative. Reported under `--all`, never
    #: killed by the project-scoped default.
    unknown = "unknown"


class ProcessFlag(Enum):
    """Why a process is worth saying out loud."""

    #: PPID 1: its invoker died and nothing is waiting on it.
    orphaned = "orphaned"
    #: Burning a core. Alone this is also what a healthy compile looks like,
    #: which is why acting on it automatically needs a second flag.
    pegged = "pegged"
    #: Alive past the threshold. Suspicious, not damning: `cross` is allowed to
    #: take half an hour.
    long_running = "long-running"


@dataclass(**FROZEN)
class Thresholds:
    """The two numbers the verdicts turn on, as one value so a test can state
    them instead of waiting for them."""

    long_running: float = 600.0
    pegged: float = 80.0


@dataclass(**FROZEN)
class Candidate:
    """One process this runner recognises, with why it was recognised, whose
    checkout it belongs to, and what is wrong with it."""

    record: ProcessRecord
    kind: ProcessKind
    attribution: Attribution
    flags: tuple[ProcessFlag, ...] = ()

    @property
    def pid(self) -> int:
        return self.record.pid

    @property
    def mine(self) -> bool:
        return self.attribution is Attribution.this_project

    @property
    def orphaned(self) -> bool:
        return ProcessFlag.orphaned in self.flags

    @property
    def pegged(self) -> bool:
        return ProcessFlag.pegged in self.flags

    @property
    def long_running(self) -> bool:
        return ProcessFlag.long_running in self.flags

    @property
    def fatal(self) -> bool:
        """Orphaned or pegged: what `doctor` refuses to call healthy."""
        return self.orphaned or self.pegged

    @property
    def runaway(self) -> bool:
        """What may be killed WITHOUT being asked to.

        Deliberately stricter than `fatal`. An orphan is unambiguous. A pegged
        process that has only been alive for ten seconds is a compile doing its
        job, and an auto-reap that killed it would be a worse bug than the one
        this module exists for — so pegging only counts automatically once it
        has also outlasted the threshold.
        """
        return self.orphaned or (self.pegged and self.long_running)

    def why(self) -> str:
        return ", ".join(f.value for f in self.flags) if self.flags else "healthy"


class Scope(Enum):
    """How wide `reap` and the `processes` check look."""

    #: This checkout only. The default, because killing another checkout's build
    #: is not this command's business.
    project = "project"
    #: Every zig build process this user owns, with the out-of-project ones
    #: marked. For the machine-is-on-fire case.
    everything = "all"


@dataclass(**FROZEN)
class ProcessScan:
    """The whole answer to "what of this toolchain's is running"."""

    candidates: tuple[Candidate, ...] = ()
    available: bool = True
    note: str = ""
    thresholds: Thresholds = Thresholds()

    def in_scope(self, scope: Scope) -> tuple[Candidate, ...]:
        if scope is Scope.everything:
            return self.candidates
        return tuple(c for c in self.candidates if c.mine)

    def fatal(self, scope: Scope = Scope.project) -> tuple[Candidate, ...]:
        return tuple(c for c in self.in_scope(scope) if c.fatal)

    def runaway(self, scope: Scope = Scope.project) -> tuple[Candidate, ...]:
        return tuple(c for c in self.in_scope(scope) if c.runaway)

    def long_running(self, scope: Scope = Scope.project) -> tuple[Candidate, ...]:
        return tuple(c for c in self.in_scope(scope) if c.long_running and not c.fatal)


@dataclass(**FROZEN)
class CwdRecord:
    """One process's working directory, as `lsof` or `/proc` reported it."""

    pid: int
    cwd: str


class KillSignal(Enum):
    """The two signals, in the order they are sent. There is no third."""

    term = "SIGTERM"
    kill = "SIGKILL"


@dataclass(**FROZEN)
class KillAttempt:
    """One signal, to one EXPLICIT pid.

    Every kill this package performs is a numbered pid that was printed first.
    Nothing here ever matches a pattern: the shipped policy denies `pkill` for
    the reason that applies with full force to a reaper — a pattern written to
    match "the runaway build" matches the process doing the matching, and this
    is a Python process whose argv contains the very strings it is hunting.
    """

    pid: int
    signal: KillSignal
    #: False when the pid was already gone, which is a success, not an error.
    delivered: bool = True
    note: str = ""


@dataclass(**FROZEN)
class ReapOutcome:
    """What a kill sequence did, in order."""

    attempts: tuple[KillAttempt, ...] = ()
    killed: tuple[int, ...] = ()
    survivors: tuple[int, ...] = ()

    @property
    def acted(self) -> bool:
        return bool(self.attempts)

    def signals_to(self, pid: int) -> tuple[KillSignal, ...]:
        return tuple(a.signal for a in self.attempts if a.pid == pid)


class Signals(Protocol):
    """Sending a signal and asking whether a pid is still there.

    A Protocol for the same reason `Process` is one: the kill sequence is the
    part of this that must be tested, and testing it against real processes is
    how the incident being fixed here started.
    """

    def send(self, pid: int, signal: KillSignal) -> KillAttempt: ...

    def alive(self, pid: int) -> bool: ...


class Clock(Protocol):
    """Monotonic time and sleeping, injectable so the grace period between
    SIGTERM and SIGKILL costs a test nothing."""

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


# ---------------------------------------------------------------------------
# diagnosis
# ---------------------------------------------------------------------------


class Health(Enum):
    """The gate's three verdicts, spelled the same way here.

    `ok` rather than `pass` only because `pass` is a keyword; the *value* is
    `"pass"`, which is what the gate's `doctor --json` emits and therefore what
    a merged document has to carry.
    """

    ok = "pass"
    warn = "warn"
    fail = "fail"

    def word(self) -> str:
        return {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[self.value]


@dataclass(**FROZEN)
class DoctorCheck:
    """One diagnosed check, in the same shape `cli.Check` has on the Zig side.

    The runner contributes one of these to `doctor`: the gate diagnoses an
    INSTALL, and "is a stale build process from this checkout still running" is
    a question about a checkout, which an installed gate in someone else's
    `~/.claude` has no way to answer.
    """

    id: str
    title: str
    status: Health
    detail: str
    remedy: str | None = None

    @property
    def failed(self) -> bool:
        return self.status is Health.fail

    def exit_code(self) -> int:
        """A WARN is not a failure, for the reason the gate gives: `doctor` runs
        in scripts, and a warning must not break a pipeline."""
        return EX_FAIL if self.failed else EX_OK


# ---------------------------------------------------------------------------
# code signatures (macOS)
# ---------------------------------------------------------------------------


class SignatureState(Enum):
    """What `codesign` says about a Mach-O.

    The distinction that matters is between `unsigned`/`invalid` and
    `unavailable`: the first two are a binary macOS may refuse to run, the
    third is not knowing, and reporting "not knowing" as "fine" is how a tool
    ends up shipping a gate that is silently killed on first use.
    """

    #: `codesign --verify` accepted it.
    valid = "valid"
    #: Signed, but the signature does not cover the bytes on disk any more.
    invalid = "invalid"
    #: Not signed at all.
    unsigned = "unsigned"
    #: `codesign` could not be run, so nothing is known.
    unavailable = "unavailable"
    #: Not a macOS install. There is no signature to have an opinion about.
    not_applicable = "not_applicable"


@dataclass(**FROZEN)
class SignatureReport:
    """One `codesign` verdict on one file, with the OS's own words kept.

    `form` is the `flags=0x…(…)` line verbatim, because "ad-hoc" is a claim and
    the operator should be able to read the flags for themselves.
    """

    path: Path
    state: SignatureState
    form: str = ""
    #: codesign's own first line when it refused, verbatim.
    note: str = ""

    @property
    def adhoc(self) -> bool:
        return "adhoc" in self.form

    @property
    def ok(self) -> bool:
        return self.state in (SignatureState.valid, SignatureState.not_applicable)


# ---------------------------------------------------------------------------
# audit results
# ---------------------------------------------------------------------------


@dataclass(**FROZEN)
class AuditCheck:
    """One mechanical consistency check, with the count it asserted.

    `detail` carries the numbers rather than a prose summary, because the
    numbers are what make a quiet slide back toward hand-maintained lists
    visible in a diff.
    """

    name: str
    ok: bool
    detail: str = ""

    @property
    def failed(self) -> bool:
        return not self.ok


@dataclass(**FROZEN)
class AuditReport:
    """An accumulating set of checks, aggregated at the end.

    Frozen, so a report is built by `plus` returning a new one rather than by
    appending to a list some other function also holds — the failure mode where
    two halves of a report disagree about what ran cannot happen.
    """

    checks: tuple[AuditCheck, ...] = ()

    @classmethod
    def of(cls, checks: Iterable[AuditCheck]) -> AuditReport:
        return cls(tuple(checks))

    def plus(self, *checks: AuditCheck) -> AuditReport:
        return AuditReport(self.checks + checks)

    def extend(self, checks: Iterable[AuditCheck]) -> AuditReport:
        return AuditReport(self.checks + tuple(checks))

    @property
    def failures(self) -> tuple[AuditCheck, ...]:
        return tuple(c for c in self.checks if c.failed)

    @property
    def passed(self) -> int:
        return len(self.checks) - len(self.failures)

    @property
    def failed(self) -> int:
        return len(self.failures)

    @property
    def ok(self) -> bool:
        return not self.failures

    def exit_code(self) -> int:
        return EX_OK if self.ok else EX_FAIL


# ---------------------------------------------------------------------------
# the rule catalog
# ---------------------------------------------------------------------------


class RuleOrigin(Enum):
    """Which document a catalog rule was read from.

    `shipped` is authoritative where the two overlap: it is what `setup` seeds
    and what `diff-defaults` compares an operator's file against, so a rule
    adopted by name must be the same bytes those two verbs are talking about.
    """

    shipped = "shipped"
    cookbook = "cookbook"


@dataclass(**FROZEN)
class CatalogRule:
    """One adoptable rule: the rule object itself, the test cases that name it,
    and the file-local sets those two reference.

    `rule` and `tests` are the parsed JSON, verbatim — not a retyping of the
    schema. The gate owns the schema; this runner's job is to carry a rule from
    a catalog document into an operator's file without changing a byte of it,
    and a dataclass that re-spelled every field would be a second place for the
    schema to exist.

    `position` is the rule's index in the catalog's canonical first-match-wins
    order, so an adopted rule can be INSERTED where the catalog would have put
    it rather than appended where it may never fire (an `allow` carve-out
    appended after the deny it carves out of is a no-op).
    """

    name: str
    origin: RuleOrigin
    event: str
    tool: str | None
    decision: str
    reason: str
    position: int
    rule: dict
    tests: tuple[dict, ...] = ()
    sets: tuple[str, ...] = ()


@dataclass(**FROZEN)
class Catalog:
    """Every rule this repository ships or documents, in one adoptable list.

    The union of the shipped defaults and the cookbook fixture, in the
    cookbook's documented first-match-wins order. Nothing here is
    hand-maintained: both documents are parsed at call time, and the audit
    composes and selftests what this produces, so the catalog cannot quietly
    drift from the files it claims to describe.
    """

    schema_version: str
    entries: tuple[CatalogRule, ...] = ()
    #: The union of both documents' file-local `sets` (shipped wins a clash).
    sets: dict = field(default_factory=dict)

    def find(self, name: str) -> CatalogRule | None:
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def names(self) -> tuple[str, ...]:
        return tuple(entry.name for entry in self.entries)


@dataclass(**FROZEN)
class Selection:
    """One chosen rule, and whether it starts in shadow.

    `shadow` adopts the rule with its decision demoted to `log` — the
    shadow-first rollout the README teaches, as a flag instead of a hand edit.
    """

    name: str
    shadow: bool = False


@dataclass(**FROZEN)
class Bundle:
    """A themed group of catalog rules, described in the words a first-time
    operator actually has.

    "14 shipped rules" is a maintainer's noun; nobody choosing a policy for
    the first time knows what is in it. A bundle is the user-facing unit of
    choice instead: a name, one sentence about what it stops, and its member
    rules — which `init` offers take-or-leave and `rules add` accepts by name.
    The membership is curated by hand, so the audit holds it to account:
    bundles must partition the catalog (each rule in exactly one, the
    leftovers explicitly known), every member must exist, and every bundle's
    composition must pass the gate's selftest.
    """

    name: str
    title: str
    rules: tuple[str, ...]


@dataclass(**FROZEN)
class RuleWrite:
    """What became of one attempt to write a rule document.

    Every write of an operator's rule file goes through one pipeline — compose,
    selftest the composition, back the old file up, swap the new one in — and
    this is that pipeline's answer. `draft` is set instead of `target` being
    touched when the gate rejected the composition: the rejected document is
    kept where the operator can read, fix and re-lint it, because a wizard that
    discarded ten minutes of answers over one bad matcher would not be used
    twice.
    """

    ok: bool
    target: Path
    backup: Path | None = None
    draft: Path | None = None
    selftest: RunResult | None = None


class Profile(Enum):
    """The named starting points `init` offers.

    `custom` is deliberately absent: it is not a composition this enum can
    describe, it is the interactive walkthrough that produces one.
    """

    #: The shipped defaults, verbatim — the same document `setup` seeds.
    recommended = "recommended"
    #: The shipped defaults with every decision demoted to `log`: full
    #: shadow-first, nothing enforced until the operator promotes it.
    observe = "observe"
    #: Only the machine-guards: the rules that protect the host and the gate
    #: itself, plus the session marker that makes an empty log meaningful.
    minimal = "minimal"


# ---------------------------------------------------------------------------
# the verb table
# ---------------------------------------------------------------------------


class ArgShape(Enum):
    """What a verb does with the arguments after it."""

    #: Takes none. Anything after the verb is a usage error, said before any
    #: work is done — `verify` and `audit` run the whole repository, and a
    #: typo'd flag must not be silently ignored for two minutes.
    none = "none"
    #: Forwarded to whatever child the verb runs.
    forwarded = "forwarded"


@dataclass(**FROZEN)
class VerbGroup:
    """A section of `help`. The heading is data, so `help` and the README's
    verb table cannot disagree about which verbs are an operator's business."""

    name: str
    heading: str


@dataclass(**FROZEN)
class Verb:
    """One verb, completely described.

    Everything dispatch, `help`, and the README doc check need is here, which
    is what makes those three impossible to drift apart: they all read this
    table and there is nowhere else to read.
    """

    name: str
    group: str
    summary: str
    handler: Handler
    args: ArgShape = ArgShape.forwarded
    #: The verb cannot work without `zig`. Checked once, centrally, before the
    #: handler is entered, so no handler has to remember to.
    needs_toolchain: bool = False
    #: Non-empty for a verb that is a thin front for a gate subcommand: these
    #: are the arguments that go before the operator's own.
    gate_args: tuple[str, ...] = ()
    #: Rebuild zig-out first, because this verb's answer is a comparison
    #: against the working tree.
    refresh_build: bool = False
    #: The wall-clock ceiling for each child this verb spawns, overridable with
    #: `--timeout`. Per verb rather than global because the honest durations
    #: differ by two orders of magnitude — see `CROSS_TIMEOUT`.
    timeout: float = DEFAULT_BUILD_TIMEOUT
    #: Look for, and kill, a runaway left by a previous run before starting.
    #: Set on the verbs that compile: a stale spinner must not compete for CPU
    #: with the run that is about to happen. Deliberately NOT set on `doctor`,
    #: whose whole job is to report what is there.
    auto_reap: bool = False
    #: This verb's answer is the gate's plus a diagnosis only the runner can
    #: make. Data rather than a second handler, so `help`, dispatch and the one
    #: passthrough handler still read one table.
    runner_checks: bool = False

    @property
    def passthrough(self) -> bool:
        return bool(self.gate_args)


@dataclass(**FROZEN)
class Context:
    """Everything a handler is allowed to know.

    A handler is a pure-ish function of this: it reads the resolved layout,
    issues commands through `process`, and returns an exit code. It never reads
    `sys.argv`, never calls `os.environ`, and never imports the registry —
    `verbs` is passed in, which is what keeps `help`, dispatch and the doc
    check reading one table.
    """

    verb: Verb
    args: tuple[str, ...]
    paths: Paths
    toolchain: Toolchain
    platform: Platform
    process: Process
    verbs: tuple[Verb, ...]
    groups: tuple[VerbGroup, ...]
    #: The resolved wall-clock ceiling for this run's children: the verb's
    #: default unless `--timeout` or `HOOKCTL_TIMEOUT` said otherwise. Resolved
    #: once, in `main`, so no handler has to read the environment to find out
    #: how long it is allowed to take.
    timeout: float = DEFAULT_BUILD_TIMEOUT

    def gate_argv(self, gate: GateBinary) -> str:
        return self.paths.display(gate.path) if gate.is_built else str(gate.path)


#: A verb's implementation. Takes the frozen context, returns an exit code.
Handler = Callable[[Context], int]

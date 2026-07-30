"""Finding, judging and killing this checkout's own build and test processes.

This module exists because of a specific failure, and the shape of the failure
is the shape of the code:

    An orphaned `zig build test` runner and two of its compiled test binaries
    spun at 100% CPU for eleven hours and took a machine down. `zig build`
    spawns its test binaries as CHILDREN; when the invoking process died, the
    runner was reparented to init (PPID 1) and its children survived it. They
    went on executing whatever had been compiled at that instant — including an
    infinite loop from a half-finished refactor. Every gate reported green the
    entire time, because the code that was spinning no longer existed on disk.

Three properties follow from that, and they are the whole design:

  * **A gate that reads source cannot see this.** The only witness is the
    process table, so the process table is what gets read.
  * **`ps` cannot tell you whose checkout a process belongs to.** The top-level
    `zig build test` has no path in its argv at all, and the test binaries are
    spawned as `./.zig-cache/o/<hash>/test` — relative. The one process that
    does carry the absolute project root is the compiled build runner in the
    middle. So membership is decided by three signals in order: an absolute path
    in the argv, a relative path that resolves to a file that exists under this
    root, the process's own working directory — and then propagated along the
    parent/child graph, which is what attributes both the pathless parent and
    the relative-pathed children.
  * **Killing is by explicit pid, always.** The shipped policy denies `pkill`,
    and a reaper is the strongest case for that rule rather than an exception to
    it: any pattern broad enough to match "the runaway build" also matches the
    process doing the matching, whose own argv contains the strings it is
    hunting. Every pid killed here was printed first.

The split is the same one the rest of the package keeps. Everything from
`parse_table` to `classify` is pure — text and frozen values in, frozen values
out — and is where the interesting decisions live. The two impure functions
(`list_processes`, `probe_cwds`) go through `spec.Process`, so the tests drive
the whole thing from fixture `ps` output with no process ever spawned. That is
not a stylistic preference: synthesising real long-running processes in a test
suite is how the incident above started.
"""

from __future__ import annotations

import os
import signal
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import ui
from .proc import PROBE_TIMEOUT
from .spec import (
    FROZEN,
    Attribution,
    Candidate,
    Clock,
    CwdRecord,
    DoctorCheck,
    Health,
    KillAttempt,
    KillSignal,
    Platform,
    ProcessFlag,
    ProcessKind,
    ProcessRecord,
    ProcessScan,
    ProcessTable,
    ReapOutcome,
    RunMode,
    Scope,
    Signals,
    Thresholds,
)

# ---------------------------------------------------------------------------
# asking the machine (the only two impure functions here)
# ---------------------------------------------------------------------------

#: The columns, in order, that `parse_table` expects. Identical on both
#: platforms; only the flag that means "every process" differs.
PS_COLUMNS = "pid=,ppid=,uid=,etime=,pcpu=,rss="

#: macOS. `-ax` is every process including the ones with no controlling
#: terminal — an orphan has none, so without `-x` the reaper cannot see the
#: thing it exists for. `-ww` because BSD `ps` truncates the command column to
#: the terminal width otherwise, and the part it truncates is the path this
#: module attributes processes by.
PS_DARWIN: tuple[str, ...] = ("ps", "-axww", "-o", PS_COLUMNS + ",command=")

#: Linux. `-e` is the POSIX spelling of "every process"; on macOS `-e` means
#: "show the environment", which is why this is not one command line. procps
#: calls the full command line `args` (`command` is accepted as an alias, but
#: `args` is the documented name), and `-ww` disables truncation here too.
PS_LINUX: tuple[str, ...] = ("ps", "-eww", "-o", PS_COLUMNS + ",args=")

#: A process's working directory. Linux has it as a symlink in `/proc` and needs
#: no subprocess at all; macOS has no `/proc`, so `lsof` is asked — for a
#: batch of pids in one call, in its stable machine-readable `-F` form.
LSOF: tuple[str, ...] = ("lsof", "-a", "-d", "cwd", "-Fn", "-p")

#: How many pids are worth an `lsof`. The shortlist is normally empty and never
#: large; the cap is here so that a machine in a strange state cannot turn a
#: diagnostic into a stall.
CWD_PROBE_LIMIT = 32


def ps_argv(platform: Platform) -> tuple[str, ...]:
    return PS_DARWIN if platform.system == "Darwin" else PS_LINUX


def list_processes(process, platform: Platform) -> ProcessTable:
    """Every process on the machine, or the fact that it could not be asked.

    A `ps` that is missing, refused or silent is reported as `available=False`
    with the reason. It must not read as "nothing is running": the whole value
    of this check is that it notices a runaway, and a check that says "clean"
    when it cannot see is worse than no check.
    """
    result = process.run(ps_argv(platform), mode=RunMode.capture, timeout=PROBE_TIMEOUT)
    if not result.ok:
        return ProcessTable(available=False, note=result.first_error_line())
    records = parse_table(result.stdout)
    if not records:
        return ProcessTable(
            available=False, note="`ps` listed no processes it could parse"
        )
    return ProcessTable(records=records)


def probe_cwds(
    process, platform: Platform, pids: Sequence[int]
) -> tuple[CwdRecord, ...]:
    """The working directories of `pids`, for the ones that can be read.

    The last attribution signal, and the only one that can place the top-level
    `zig build test` — whose argv is those three words and nothing else. A pid
    whose cwd cannot be read simply does not appear in the result: not knowing
    is `Attribution.unknown`, never a match.
    """
    wanted = tuple(pids)[:CWD_PROBE_LIMIT]
    if not wanted:
        return ()
    if platform.system != "Darwin":
        found = []
        for pid in wanted:
            try:
                found.append(
                    CwdRecord(pid=pid, cwd=str(Path(f"/proc/{pid}/cwd").readlink()))
                )
            except OSError:
                continue
        return tuple(found)
    result = process.run(
        (*LSOF, ",".join(str(p) for p in wanted)),
        mode=RunMode.capture,
        timeout=PROBE_TIMEOUT,
    )
    # `lsof` exits nonzero when any pid has gone away, which is normal here and
    # not a reason to discard the rows for the pids that are still there.
    return parse_lsof(result.stdout)


# ---------------------------------------------------------------------------
# parsing (pure)
# ---------------------------------------------------------------------------


def parse_elapsed(text: str) -> float | None:
    """`ps`'s `etime`, in seconds.

    One parser for both platforms, because they agree on the format:
    `[[DD-]HH:]MM:SS`. They disagree only on padding, which `strip` handles.
    Eleven hours reads as `11:02:33`; the eleven-hour case is why this is a
    number and not a string.
    """
    rest = text.strip()
    if not rest:
        return None
    days = 0
    if "-" in rest:
        head, _, rest = rest.partition("-")
        try:
            days = int(head)
        except ValueError:
            return None
    parts = rest.split(":")
    if len(parts) > 3:
        return None
    while len(parts) < 3:
        parts.insert(0, "0")
    try:
        hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
    except ValueError:
        return None
    return days * 86400.0 + hours * 3600.0 + minutes * 60.0 + seconds


def parse_table(text: str) -> tuple[ProcessRecord, ...]:
    """`ps` output into records. Unparseable lines are skipped, not guessed at.

    The command is the rest of the line rather than a seventh field, because it
    contains spaces — that is the entire reason it is the last column in
    `PS_COLUMNS`.
    """
    found: list[ProcessRecord] = []
    for line in text.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 7:
            continue
        elapsed = parse_elapsed(fields[3])
        if elapsed is None:
            continue
        try:
            record = ProcessRecord(
                pid=int(fields[0]),
                ppid=int(fields[1]),
                uid=int(fields[2]),
                elapsed=elapsed,
                cpu=float(fields[4]),
                rss_kib=int(fields[5]),
                command=fields[6].strip(),
            )
        except ValueError:
            continue
        if record.command:
            found.append(record)
    return tuple(found)


def parse_lsof(text: str) -> tuple[CwdRecord, ...]:
    """`lsof -Fn` output: a `p<pid>` line, then an `n<path>` line per file.

    Only `cwd` was asked for, so there is one path per pid — but the format is
    stateful, so the pid is carried forward rather than assumed to be adjacent.
    """
    found: list[CwdRecord] = []
    pid: int | None = None
    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            try:
                pid = int(value)
            except ValueError:
                pid = None
        elif tag == "n" and pid is not None:
            found.append(CwdRecord(pid=pid, cwd=value))
            pid = None
    return tuple(found)


# ---------------------------------------------------------------------------
# recognising a build process (pure)
# ---------------------------------------------------------------------------

CACHE_DIR = ".zig-cache"
CACHE_OBJECTS = CACHE_DIR + "/o/"
OUT_DIR = "zig-out/"

#: The build runner's own basename inside the cache. Everything else compiled
#: into `.zig-cache/o/<hash>/` and then executed is a test binary.
BUILD_RUNNER_NAME = "build"


def kind_of(record: ProcessRecord) -> ProcessKind | None:
    """What sort of build process this is, or None if it is not one.

    Four shapes, all four of which really occur (this list was read off a live
    `zig build test`, not imagined):

        zig build test
        .zig-cache/o/<hash>/build /path/to/zig /path/to/lib <ROOT> .zig-cache …
        (zig)
        ./.zig-cache/o/<hash>/test --cache-dir=./.zig-cache --listen=-

    The third is macOS reporting a compiler process whose argv it cannot show.
    It carries no information whatsoever beyond its ppid, which is exactly why
    attribution has to propagate along the process graph.
    """
    exe = record.exe
    name = record.name
    if name in ("zig", "(zig)"):
        rest = record.command[len(exe) :]
        return (
            ProcessKind.build_step
            if rest.split()[:1] == ["build"]
            else ProcessKind.compiler
        )
    if CACHE_OBJECTS in exe:
        return (
            ProcessKind.build_runner
            if name == BUILD_RUNNER_NAME
            else ProcessKind.test_binary
        )
    if OUT_DIR in exe:
        return ProcessKind.built_binary
    return None


def shortlist(
    table: ProcessTable, *, uid: int, exclude: Iterable[int] = ()
) -> tuple[ProcessRecord, ...]:
    """Every process on the machine that is one of this toolchain's, ours, and
    not us.

    `exclude` is the running command's own lineage — see `ProcessTable.lineage`.
    Without it, `hookctl build`'s auto-reap would find the `zig build` it is
    about to wait on and kill it, which would be a worse bug than the one this
    module is for.
    """
    barred = set(exclude)
    return tuple(
        r
        for r in table.records
        if r.uid == uid and r.pid not in barred and kind_of(r) is not None
    )


# ---------------------------------------------------------------------------
# attribution (pure)
# ---------------------------------------------------------------------------

#: Path fragments that make an absolute path somebody's *checkout* rather than
#: an installed toolchain. `/opt/homebrew/.../bin/zig` is not another project.
PROJECT_MARKERS = ("/" + CACHE_DIR, "/" + OUT_DIR.rstrip("/"))


def _tokens(command: str) -> tuple[str, ...]:
    return tuple(t for t in command.split(" ") if t)


def _direct_attribution(
    record: ProcessRecord,
    root: str,
    cwd: str | None,
    exists: Callable[[str], bool],
) -> Attribution:
    """What one record says about itself, ignoring its relatives.

    Ordered so that a positive match on this root always wins: a command line
    can mention several paths, and being able to see our own root anywhere in it
    is stronger evidence than an unrecognised path being present.
    """
    tokens = _tokens(record.command)
    prefix = root.rstrip("/") + "/"
    for token in tokens:
        bare = token.split("=", 1)[-1]
        if bare == root or bare.startswith(prefix):
            return Attribution.this_project
    # A relative cache path — how `zig build` spells the test binaries it runs —
    # belongs to this root if that exact file is in this root's cache. The hashes
    # are content-addressed, so this is a strong match rather than a guess.
    for token in tokens:
        bare = token.split("=", 1)[-1]
        if bare.startswith("/") or CACHE_DIR not in bare:
            continue
        # `bare[2:]`, not `lstrip("./")`: `lstrip` takes a SET of characters, so
        # it would eat the leading dot of `./.zig-cache` as well as the slash and
        # leave `zig-cache/...`, which resolves to nothing and silently fails to
        # attribute the exact processes this is here for.
        relative = bare.removeprefix("./")
        if exists(str(Path(root) / relative)):
            return Attribution.this_project
    if cwd is not None:
        if cwd == root or cwd.startswith(prefix):
            return Attribution.this_project
        return Attribution.other_project
    for token in tokens:
        bare = token.split("=", 1)[-1]
        if bare.startswith("/") and any(marker in bare for marker in PROJECT_MARKERS):
            return Attribution.other_project
    return Attribution.unknown


def attribute(
    records: Sequence[ProcessRecord],
    root: str,
    *,
    cwds: Sequence[CwdRecord] = (),
    exists: Callable[[str], bool] = os.path.exists,
) -> tuple[Candidate, ...]:
    """Decide, for each shortlisted record, whose checkout it belongs to.

    Two phases. First each record is asked about itself. Then the answers are
    shared across connected components of the parent/child graph *restricted to
    the shortlist*, which is what makes the pathless `zig build test` and the
    relatively-pathed `./.zig-cache/o/<hash>/test` inherit the attribution of
    the build runner between them — the one process that spells the root out.

    Restricting the graph to the shortlist is what stops that propagation from
    escaping: the build runner's grandparent is a shell, which is not a build
    process, so the component ends there rather than swallowing the session.
    """
    by_pid = {r.pid: r for r in records}
    cwd_of = {c.pid: c.cwd for c in cwds}

    # Connected components over parent edges where both ends are shortlisted,
    # by the plainest possible union-find: these graphs have a handful of nodes.
    parent: dict[int, int] = {pid: pid for pid in by_pid}

    def group_of(pid: int) -> int:
        seen: set[int] = set()
        while parent[pid] != pid and pid not in seen:
            seen.add(pid)
            pid = parent[pid]
        return pid

    for record in records:
        if record.ppid in by_pid:
            mine, theirs = group_of(record.pid), group_of(record.ppid)
            if mine != theirs:
                parent[mine] = theirs

    verdicts: dict[int, Attribution] = {
        group_of(pid): Attribution.unknown for pid in by_pid
    }
    for record in records:
        answer = _direct_attribution(record, root, cwd_of.get(record.pid), exists)
        group = group_of(record.pid)
        if verdicts[group] is Attribution.this_project:
            # Absorbing: one process in a component naming this root places the
            # whole component, and nothing can argue it back out.
            continue
        if answer is Attribution.this_project or verdicts[group] is Attribution.unknown:
            verdicts[group] = answer

    return tuple(
        Candidate(
            record=record,
            kind=kind_of(record) or ProcessKind.compiler,
            attribution=verdicts[group_of(record.pid)],
        )
        for record in records
    )


# ---------------------------------------------------------------------------
# the verdict (pure)
# ---------------------------------------------------------------------------


def flags_for(record: ProcessRecord, thresholds: Thresholds) -> tuple[ProcessFlag, ...]:
    """What is wrong with one process, in the order it is worth reading."""
    found: list[ProcessFlag] = []
    if record.orphaned:
        found.append(ProcessFlag.orphaned)
    if record.cpu > thresholds.pegged:
        found.append(ProcessFlag.pegged)
    if record.elapsed > thresholds.long_running:
        found.append(ProcessFlag.long_running)
    return tuple(found)


def classify(
    table: ProcessTable,
    root: str,
    *,
    uid: int,
    self_pid: int,
    cwds: Sequence[CwdRecord] = (),
    thresholds: Thresholds = Thresholds(),
    exists: Callable[[str], bool] = os.path.exists,
) -> ProcessScan:
    """The whole judgement, from a process table to a `ProcessScan`.

    Pure: every input is a value, including the clock (`elapsed` comes out of
    `ps`) and the filesystem (`exists`). This is the function the tests spend
    most of their time in, and it is the one that would have caught the eleven
    hours on its first run.
    """
    if not table.available:
        return ProcessScan(available=False, note=table.note, thresholds=thresholds)
    candidates = attribute(
        shortlist(table, uid=uid, exclude=table.lineage(self_pid)),
        root,
        cwds=cwds,
        exists=exists,
    )
    return ProcessScan(
        candidates=tuple(
            Candidate(
                record=c.record,
                kind=c.kind,
                attribution=c.attribution,
                flags=flags_for(c.record, thresholds),
            )
            for c in sorted(candidates, key=lambda c: c.record.pid)
        ),
        thresholds=thresholds,
    )


def scan(
    process,
    platform: Platform,
    root: Path,
    *,
    thresholds: Thresholds = Thresholds(),
    uid: int | None = None,
    self_pid: int | None = None,
) -> ProcessScan:
    """`classify`, with the machine asked for the two things only it knows.

    The cwd probe is deliberately second and conditional: it costs an `lsof` on
    macOS, and it is only needed for a shortlisted process that nothing else
    could place — which, on a healthy machine with an empty shortlist, is never.
    """
    table = list_processes(process, platform)
    resolved_uid = os.getuid() if uid is None else uid
    resolved_pid = os.getpid() if self_pid is None else self_pid
    first = classify(
        table,
        str(root),
        uid=resolved_uid,
        self_pid=resolved_pid,
        thresholds=thresholds,
    )
    unplaced = tuple(
        c.pid for c in first.candidates if c.attribution is Attribution.unknown
    )
    if not unplaced:
        return first
    return classify(
        table,
        str(root),
        uid=resolved_uid,
        self_pid=resolved_pid,
        cwds=probe_cwds(process, platform, unplaced),
        thresholds=thresholds,
    )


# ---------------------------------------------------------------------------
# killing (explicit pids, TERM then KILL)
# ---------------------------------------------------------------------------


#: The two signals, as numbers, in one place. `os.kill` takes a number and a
#: pid and nothing else — there is no name-matching form of it to reach for by
#: accident, which is part of why it is the only kill primitive used here.
SIGNAL_NUMBERS = {KillSignal.term: signal.SIGTERM, KillSignal.kill: signal.SIGKILL}


@dataclass(**FROZEN)
class OsSignals:
    """`Signals` against the real machine. `os.kill`, one explicit pid at a time."""

    def send(self, pid: int, which: KillSignal) -> KillAttempt:
        try:
            os.kill(pid, SIGNAL_NUMBERS[which])
        except ProcessLookupError:
            # It exited between the scan and the signal, which is the outcome
            # being asked for, not a failure.
            return KillAttempt(
                pid=pid, signal=which, delivered=False, note="already gone"
            )
        except PermissionError:
            return KillAttempt(
                pid=pid, signal=which, delivered=False, note="not ours to signal"
            )
        return KillAttempt(pid=pid, signal=which, delivered=True)

    def alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


@dataclass(**FROZEN)
class WallClock:
    """`Clock` against the real machine."""

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def kill_order(candidates: Sequence[Candidate]) -> tuple[int, ...]:
    """The pids to signal, ancestors first.

    A build runner that is still alive can start another compile, so it is asked
    to stop before its children are. Within a generation the order is by pid, so
    that the transcript is reproducible.
    """
    pids = {c.pid for c in candidates}

    def depth(candidate: Candidate) -> int:
        found = 0
        walking = candidate.record.ppid
        parents = {c.pid: c.record.ppid for c in candidates}
        seen = set()
        while walking in pids and walking not in seen:
            seen.add(walking)
            found += 1
            walking = parents.get(walking, 0)
        return found

    return tuple(c.pid for c in sorted(candidates, key=lambda c: (depth(c), c.pid)))


def kill(
    pids: Sequence[int],
    signals: Signals,
    clock: Clock,
    *,
    grace: float = 2.0,
    poll: float = 0.05,
) -> ReapOutcome:
    """SIGTERM every pid, wait, SIGKILL the survivors, then check.

    Every pid here is a number that came out of a scan and was printed before
    this was called. There is no pattern anywhere in this function and there must
    never be one: `pkill zig` typed by a reaper matches the reaper.
    """
    targets = tuple(pids)
    if not targets:
        return ReapOutcome()
    attempts = [signals.send(pid, KillSignal.term) for pid in targets]

    deadline = clock.now() + grace
    while clock.now() < deadline:
        if not any(signals.alive(pid) for pid in targets):
            break
        clock.sleep(poll)

    stubborn = tuple(pid for pid in targets if signals.alive(pid))
    attempts += [signals.send(pid, KillSignal.kill) for pid in stubborn]
    if stubborn:
        deadline = clock.now() + grace
        while clock.now() < deadline:
            if not any(signals.alive(pid) for pid in stubborn):
                break
            clock.sleep(poll)

    survivors = tuple(pid for pid in targets if signals.alive(pid))
    return ReapOutcome(
        attempts=tuple(attempts),
        killed=tuple(pid for pid in targets if pid not in survivors),
        survivors=survivors,
    )


# ---------------------------------------------------------------------------
# the diagnosis (pure)
# ---------------------------------------------------------------------------

CHECK_ID = "processes"
CHECK_TITLE = "build and test processes"
REMEDY = (
    "run `./hookctl reap` — it prints every process with its pid, then kills those pids "
    "(SIGTERM, then SIGKILL); `--dry-run` lists without killing"
)

#: How many processes a one-line detail names before it summarises the rest.
DETAIL_LIMIT = 3


def describe(candidate: Candidate) -> str:
    """One process, in the words a check detail uses."""
    record = candidate.record
    return (
        f"pid {record.pid} ({candidate.kind.value}, {candidate.why()}, "
        f"up {ui.human_elapsed(record.elapsed)}, {record.cpu:.0f}% cpu)"
    )


def _joined(candidates: Sequence[Candidate]) -> str:
    shown = "; ".join(describe(c) for c in candidates[:DETAIL_LIMIT])
    extra = len(candidates) - DETAIL_LIMIT
    return shown + (f"; and {extra} more" if extra > 0 else "")


def doctor_check(scanned: ProcessScan) -> DoctorCheck:
    """The runner's contribution to `doctor`.

    Would have caught the eleven-hour spin on its first run: the orphan was PPID
    1 and both test binaries were at 100% CPU, and every one of those three
    facts is in `ps` whatever the source tree says.
    """
    if not scanned.available:
        return DoctorCheck(
            CHECK_ID,
            CHECK_TITLE,
            Health.ok,
            f"not applicable: {scanned.note or 'this machine would not list its processes'}",
        )
    fatal = scanned.fatal()
    if fatal:
        orphans = sum(1 for c in fatal if c.orphaned)
        pegged = sum(1 for c in fatal if c.pegged)
        counted = ", ".join(
            part
            for part in (
                f"{orphans} orphaned (PPID 1)" if orphans else "",
                f"{pegged} above {scanned.thresholds.pegged:.0f}% cpu"
                if pegged
                else "",
            )
            if part
        )
        return DoctorCheck(
            CHECK_ID,
            CHECK_TITLE,
            Health.fail,
            f"{len(fatal)} build/test process(es) from this checkout should not be running — "
            f"{counted}: {_joined(fatal)}. An orphan goes on executing the code it was "
            f"COMPILED from, so the source tree and every gate that reads it stay green while it burns cpu",
            REMEDY,
        )
    slow = scanned.long_running()
    if slow:
        return DoctorCheck(
            CHECK_ID,
            CHECK_TITLE,
            Health.warn,
            f"{len(slow)} build/test process(es) have been running longer than "
            f"{ui.human_elapsed(scanned.thresholds.long_running)}: {_joined(slow)}",
            REMEDY,
        )
    live = scanned.in_scope(Scope.project)
    if live:
        return DoctorCheck(
            CHECK_ID,
            CHECK_TITLE,
            Health.ok,
            f"{len(live)} build process(es) from this checkout are running, all parented and "
            f"within their budget: {_joined(live)}",
        )
    return DoctorCheck(
        CHECK_ID,
        CHECK_TITLE,
        Health.ok,
        "no build or test process from this checkout is running",
    )

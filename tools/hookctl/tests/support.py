"""Test doubles: a process that records instead of spawning, and a context
builder.

`FakeProcess` is the whole reason `spec.Process` is a Protocol. Every external
command the runner issues arrives here as an argv it can be asked about, and
canned replies can put a verb into any state a real machine could be in —
including the ones that are hard to arrange on purpose, like a `codesign` that
reports a broken signature.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..registry import GROUPS, VERBS, find
from ..spec import (
    Context,
    KillAttempt,
    KillSignal,
    Paths,
    Platform,
    RunMode,
    RunResult,
    Toolchain,
    Verb,
)

DARWIN = Platform(system="Darwin", arch="arm64", needs_signing=True)
LINUX = Platform(system="Linux", arch="x86_64", needs_signing=False)

ZIG = Toolchain(path="/usr/local/bin/zig", version="0.16.0", present=True)


@dataclass
class FakeProcess:
    """Records every command; answers from `replies`, else exit 0 and no output.

    `replies` is matched on the first argv element that contains a key, which
    keeps the tests readable: `{"codesign --verify": RunResult(...)}` rather
    than a full argv tuple.
    """

    replies: dict[str, RunResult] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    modes: list[RunMode] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        mode: RunMode = RunMode.inherit,
        timeout: float | None = None,
        scrub_env: bool = False,
    ) -> RunResult:
        args = tuple(str(a) for a in argv)
        self.calls.append(args)
        self.modes.append(mode)
        joined = " ".join(args)
        for key, reply in self.replies.items():
            if key in joined:
                return reply
        return RunResult(argv=args, code=0)

    @property
    def commands(self) -> list[str]:
        return [" ".join(c) for c in self.calls]

    def ran(self, fragment: str) -> bool:
        return any(fragment in c for c in self.commands)


def reply(code: int = 0, stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(argv=(), code=code, stdout=stdout, stderr=stderr)


def project_root() -> Path:
    """The tree these tests are part of."""
    return Path(__file__).resolve().parents[3]


def paths_in(tmp: Path, *, root: Path | None = None) -> Paths:
    return Paths.of(root or project_root(), tmp / "claude")


def context(
    verb: str | Verb = "doctor",
    args: Sequence[str] = (),
    *,
    paths: Paths | None = None,
    toolchain: Toolchain = ZIG,
    platform: Platform = DARWIN,
    process: FakeProcess | None = None,
) -> Context:
    resolved = verb if isinstance(verb, Verb) else find(verb)
    assert resolved is not None, f"no such verb: {verb}"
    return Context(
        verb=resolved,
        args=tuple(args),
        paths=paths or Paths.of(project_root(), project_root() / "build" / "sandbox"),
        toolchain=toolchain,
        platform=platform,
        process=process or FakeProcess(),
        verbs=VERBS,
        groups=GROUPS,
    )


def write(path: Path, contents: str = "binary") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def executable(path: Path, contents: str = "binary") -> Path:
    write(path, contents)
    path.chmod(0o755)
    return path


#: A callable that stands in for `shutil.which`, so `discovery.toolchain` can be
#: asked what it does on a machine with and without a compiler.
def which(found: str | None) -> Callable[[str], str | None]:
    return lambda _name: found


@dataclass
class FakeSignals:
    """A `Signals` that records instead of signalling.

    The reason the kill sequence is testable at all. `dies_on` decides which
    signal a pid honours, so "ignores SIGTERM, dies on SIGKILL" — the case the
    escalation exists for — is a value in a test rather than a process somebody
    has to arrange.
    """

    living: set = field(default_factory=set)
    #: pid -> the signal that actually kills it. SIGTERM unless stated.
    dies_on: dict = field(default_factory=dict)
    sent: list = field(default_factory=list)

    def send(self, pid: int, which: KillSignal) -> KillAttempt:
        self.sent.append((pid, which))
        if pid not in self.living:
            return KillAttempt(
                pid=pid, signal=which, delivered=False, note="already gone"
            )
        if self.dies_on.get(pid, KillSignal.term) is which or which is KillSignal.kill:
            self.living.discard(pid)
        return KillAttempt(pid=pid, signal=which, delivered=True)

    def alive(self, pid: int) -> bool:
        return pid in self.living

    @property
    def order(self) -> list:
        """The signals in the order they were sent, as `(pid, name)` pairs."""
        return [(pid, sig.value) for pid, sig in self.sent]


@dataclass
class FakeClock:
    """A `Clock` whose time only moves when something sleeps.

    A grace period between SIGTERM and SIGKILL then costs a test nothing, and
    the escalation is exercised deterministically instead of by racing a real
    two seconds.
    """

    ticks: float = 0.0
    slept: list = field(default_factory=list)

    def now(self) -> float:
        return self.ticks

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.ticks += seconds

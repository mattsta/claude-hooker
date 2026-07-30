"""Asking the operator questions: the one place stdin is read.

`init` and `rules new` are conversations, and a conversation needs exactly
three moves: a free answer, a yes/no, and a pick-one. `Console` provides those
three and nothing else, over an injectable reader, so a test can script an
entire wizard as a list of answers and assert the document it produced —
the same reason `spec.Process` is a Protocol.

Two behaviours are policy rather than convenience:

  * end-of-input is `Aborted`, everywhere, and every aborted wizard writes
    nothing. A pipe that runs dry half-way through a walkthrough must not
    install half a policy.
  * every prompt states its default and Enter takes it. An operator who holds
    Enter through `init` gets the recommended profile — the same outcome as
    `setup` — which is what a default is for.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .spec import FROZEN


class Aborted(Exception):
    """The operator (or the end of stdin) ended the conversation. The caller
    prints one line and writes nothing."""


def _read_line(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError as end:
        raise Aborted() from end


def stdin_is_interactive() -> bool:
    """Whether there is a person on the other end of stdin.

    Used only to decide whether a verb may *start* a conversation nothing asked
    for — a piped stdin can still answer prompts (that is how the wizards are
    exercised end to end), but a script that ran `init` bare gets told to pass
    `--profile` rather than a menu it cannot see.
    """
    try:
        return sys.stdin.isatty()
    except ValueError:
        return False


@dataclass(**FROZEN)
class Choice:
    """One option in a `choose` menu: the value returned, and its one-liner."""

    key: str
    label: str


@dataclass(**FROZEN)
class Console:
    """The three moves, over an injectable line reader.

    The reader gets the rendered prompt and returns the operator's line;
    `Aborted` propagates from it. Prompts go through the reader (i.e. through
    `input`) rather than through `ui.out` so they land on stdout *unbuffered
    ahead of the read*, and so a scripted reader sees exactly what a person
    would have.
    """

    read: Callable[[str], str] = field(default=_read_line)

    def ask(self, question: str, default: str = "") -> str:
        """A free answer; Enter takes the stated default (which may be empty)."""
        suffix = f" [{default}]" if default else ""
        answer = self.read(f"{question}{suffix}: ").strip()
        return answer or default

    def confirm(self, question: str, *, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = self.read(f"{question} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def choose(self, question: str, options: Sequence[Choice], default: str) -> str:
        """Pick one of a numbered list; Enter takes the stated default's key."""
        print(question)
        for index, option in enumerate(options, start=1):
            marker = "*" if option.key == default else " "
            print(f"  {index}.{marker} {option.key:<12} {option.label}")
        while True:
            answer = self.read(
                f"choice [1-{len(options)}, Enter = {default}]: "
            ).strip()
            if not answer:
                return default
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return options[int(answer) - 1].key
            for option in options:
                if answer == option.key:
                    return option.key

"""The console: three moves, scripted end to end.

`Console` is what makes the wizards testable — a reader is injected and the
whole conversation becomes a list. These tests pin the behaviours the wizards
lean on: Enter takes the stated default, junk is re-asked rather than guessed
at, and running out of answers is `Aborted`, never a half-finished write.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from ..interact import Aborted, Choice, Console


def scripted(*answers: str) -> Console:
    feed = list(answers)

    def read(prompt: str) -> str:
        if not feed:
            raise Aborted()
        return feed.pop(0)

    return Console(read=read)


class Ask(unittest.TestCase):
    def test_enter_takes_the_default(self):
        self.assertEqual("Bash", scripted("").ask("tool", default="Bash"))

    def test_an_answer_wins(self):
        self.assertEqual("Write", scripted("Write").ask("tool", default="Bash"))

    def test_out_of_answers_aborts(self):
        with self.assertRaises(Aborted):
            scripted().ask("tool")


class Confirm(unittest.TestCase):
    def test_defaults_and_spellings(self):
        self.assertTrue(scripted("").confirm("go?"))
        self.assertFalse(scripted("").confirm("go?", default=False))
        self.assertTrue(scripted("YES").confirm("go?", default=False))
        self.assertFalse(scripted("n").confirm("go?"))

    def test_junk_is_reasked(self):
        self.assertTrue(scripted("wat", "y").confirm("go?", default=False))


class Choose(unittest.TestCase):
    OPTIONS = (Choice("a", "first"), Choice("b", "second"))

    def pick(self, *answers: str) -> str:
        with redirect_stdout(io.StringIO()):
            return scripted(*answers).choose("which?", self.OPTIONS, "a")

    def test_by_number_by_key_and_by_default(self):
        self.assertEqual("b", self.pick("2"))
        self.assertEqual("b", self.pick("b"))
        self.assertEqual("a", self.pick(""))

    def test_junk_is_reasked(self):
        self.assertEqual("a", self.pick("9", "zzz", "1"))

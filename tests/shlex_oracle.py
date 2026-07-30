#!/usr/bin/env python3
"""Emit the reference word split for every line of the shell lexer corpus.

Python's `shlex` is the closest thing to a second implementation of POSIX word
splitting that is already on every machine this project builds on, so it is
used as an oracle: `src/shell.zig` must agree with it wherever the two model
the same thing.

    tests/shlex_oracle.py [corpus] > src/testdata/shell-oracle.jsonl

Input is `src/testdata/shell-corpus.txt`. `##` lines and empty lines are
skipped; the two-character sequence `\\N` in a corpus line stands for a
newline byte. Lines after the `%%DIVERGENT` marker are recorded with
`"section": "divergent"` and are NOT asserted against: they are the cases
where the Zig lexer implements POSIX shell and shlex does not (operators,
substitutions, ANSI-C quoting, comments, heredocs, and shlex's own handling of
a backslash inside double quotes). The corpus file documents each one.

Output is one JSON object per line:

    {"n": 1, "section": "core", "input": "ls -la", "words": ["ls", "-la"]}
    {"n": 2, "section": "core", "input": "echo \\"x", "error": "no closing quotation"}

This script is deliberately a real file rather than an inline `python3 -c`
invocation: a one-liner interpreter call is exactly the shape this project's
own gate refuses, and a checked-in script is reviewable besides.
"""

import json
import shlex
import sys
from pathlib import Path

MARKER = "%%DIVERGENT"


def decode(line: str) -> str:
    """Expand the corpus's one escape: `\\N` means a newline byte."""
    out = []
    i = 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == "N":
            out.append("\n")
            i += 2
        else:
            out.append(line[i])
            i += 1
    return "".join(out)


def records(path: Path):
    section = "core"
    n = 0
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.strip() == MARKER:
                section = "divergent"
                continue
            if not line.strip() or line.startswith("##"):
                continue
            n += 1
            text = decode(line)
            rec = {"n": n, "section": section, "input": text}
            try:
                rec["words"] = shlex.split(text, comments=False, posix=True)
            except ValueError as exc:
                rec["error"] = str(exc)
            yield rec


def main() -> int:
    # The corpus is genuinely non-ASCII (Japanese, accents, an emoji) and the
    # records carry it through unchanged, so stdout has to be UTF-8 no matter
    # what the machine's locale says. Left to the default it is UTF-8 on macOS
    # unconditionally and `ascii` on Linux under `LC_ALL=C`, where this would
    # raise UnicodeEncodeError instead of emitting the oracle — a portability
    # failure disguised as a lexer failure.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")

    here = Path(__file__).resolve().parent
    default = here.parent / "src" / "testdata" / "shell-corpus.txt"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    if not path.exists():
        sys.stderr.write(f"shlex_oracle: no corpus at {path}\n")
        return 2
    for rec in records(path):
        sys.stdout.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

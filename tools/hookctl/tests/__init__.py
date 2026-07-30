"""The runner's own tests. `./hookctl selfcheck`, and folded into `verify`.

Stdlib `unittest`, no dependency, no fixture framework, and — with one
deliberate exception — no subprocesses: what is being tested here is the
DECIDING, and every decision this package makes was made a pure function of
frozen values precisely so that it could be tested without a machine that is in
the interesting state.

That is what the four hardest cases below rely on:

  * **no Zig toolchain.** Tested by constructing `Toolchain.absent()`, not by
    moving `zig` out of the way.
  * **not macOS.** Tested by constructing a `Platform` with
    `needs_signing=False`, not by finding a Linux box.
  * **which of two gate binaries answers.** Tested with two files in a temp
    directory, because that is genuinely a filesystem question.
  * **every external command.** Tested by handing a verb a `FakeProcess` and
    reading back the argv it would have run.
"""

# claude-hooker

A small, fast **hook gate** for Claude Code, in Zig. One native binary evaluates
Claude Code's hook events — a proposed tool call, a submitted prompt, a finished
turn, a config change, and 26 more — against an operator-authored JSON rule file
and, on a hit, returns the structured response envelope **that event** accepts,
carrying a _human explanation of why_, so the model and the user see a reason and
an alternative instead of a bare refusal.

All 30 events are supported from [one descriptor
table](#hook-events): which payload fields each one carries, which response field
carries a refusal, which decisions that field can hold, and which of the thirty
cannot refuse anything at all (thirteen of them — and a `deny` rule scoped to one
is a config error this tool reports rather than a silent no-op).

No shell scripts, no daemon, no network. The gate is a short-lived process that
reads one JSON document on stdin and writes at most one JSON document on
stdout.

> **Read the [threat model](#threat-model) before you rely on this.** It is a
> habit-breaker for a cooperative model, not a containment boundary. Text
> matching is bypassable by construction, and this document says exactly how.

> **Built when you clone it.** There are no prebuilt binaries, no release
> artifacts and nothing to download and verify: `git clone`, then
> `./hookctl setup`. The only prerequisite is a Zig toolchain (and a `python3`
> for the test-time parity oracle).

---

## Contents

- [How it works](#how-it-works)
- [Quickstart](#quickstart)
- [The runner: `hookctl`](#the-runner-hookctl)
- [Choosing and managing rules](#choosing-and-managing-rules)
- [Configuration reference](#configuration-reference)
- [Hook events](#hook-events)
- [Operator CLI](#operator-cli)
- [Exit codes](#exit-codes)
- [Observability: the decision log](#observability-the-decision-log)
- [Shadow-first rollout](#shadow-first-rollout)
- [Project rule overlays](#project-rule-overlays)
- [Install, uninstall, purge](#install-uninstall-purge)
- [Environment variables](#environment-variables)
- [How commands are parsed](#how-commands-are-parsed)
- [Threat model](#threat-model)
- [Layout](#layout)
- [Contributing and releasing](#contributing-and-releasing)
- [Licence and attribution](#licence-and-attribution)
- [Roadmap](#roadmap)

---

## How it works

```
                        ┌──────────────────────────────────────────────┐
  Claude Code           │            claude-hooker-gate                │
      │                 │                                              │
      │  hook event     │  1. hook_event_name → the descriptor table   │
      ├────(stdin)─────▶│     parse only the fields THAT event binds   │
      │                 │     (unknown event → exit 0, silently)       │
      │                 │                                              │
      │                 │  2. load rules                               │
      │                 │       project  $CLAUDE_PROJECT_DIR/.claude/  │
      │                 │                hook-rules.json   ─┐          │
      │                 │       global   ~/.claude/         │ one      │
      │                 │                hook-rules.json   ─┘ walk     │
      │                 │                                              │
      │                 │  3. first match wins, among THAT event's     │
      │                 │     rules only (project layer first)         │
      │                 │       deny / ask / allow  → enforced         │
      │  no match       │       log                 → shadow, silent   │
      │◀───(exit 0,─────┤       disabled            → bypassed         │
      │   no output)    │                                              │
      │                 │  4. write THAT event's envelope shape        │
      │  match          │                                              │
      │◀───(stdout)─────┤  5. append every hit to the decision log     │
      │                 │     (best-effort, strictly after step 4)     │
      ▼                 └──────────────────────────────────────────────┘

  PreToolUse            {"hookSpecificOutput":{"hookEventName":"PreToolUse",
                          "permissionDecision":"deny"|"ask"|"allow",
                          "permissionDecisionReason":"<the reason, verbatim>"}}
  PermissionRequest     {"hookSpecificOutput":{"hookEventName":…,
                          "decision":{"behavior":"deny"|"allow"}}}
  Stop, UserPromptSubmit,
  PostToolUse, PreCompact,
  ConfigChange, …       {"decision":"block","reason":"<the reason>"}
  TeammateIdle, Task*   {"continue":false,"stopReason":"<the reason>"}
  Elicitation           {"hookSpecificOutput":{"hookEventName":…,"action":"decline"}}
  WorktreeCreate        (no envelope exists — exit 1)
  the 13 advisory events (nothing can be refused — `log` only)
```

Never `exit 2`: the hooks contract makes exit 2 and JSON output mutually
exclusive, and the JSON carries the reason. See
[why this gate never exits 2](#why-this-gate-never-exits-2).

Two binaries and one runner:

- **`claude-hooker-gate`** — the hook itself, and the operator CLI. With **no
  arguments** it is the hook (stdin → decision). With **any argument** it is
  the CLI (`check`, `selftest`, `classes`, `events`, `stats`, `doctor`,
  `status`, `diff-defaults`, `version`, `help`). The harness invokes hooks with a
  bare command line, so the two modes cannot be confused in either direction.
- **`claude-hooker-install`** — the installer. Copies the gate into
  `~/.claude/hooks/`, seeds `~/.claude/hook-rules.json`, and merges a hook entry
  into `~/.claude/settings.json` — one per event the rules actually use, and only
  those — after a timestamped backup.
- **`./hookctl`** — the one thing you actually type. It builds, installs,
  upgrades, diagnoses, and runs the repository's own gate, so operating this
  needs one mental model instead of three (`zig build`, the installer, and the
  gate's own subcommands). See [the runner](#the-runner-hookctl).

**Failure policy.** An unreadable or invalid rule file, or unreadable stdin,
exits `1` with one line on stderr. Per the hooks contract a non-`2` nonzero
exit is a _non-blocking_ error: the tool call proceeds and the message is
surfaced. A broken gate therefore degrades to "off, loudly" rather than
"everything blocked". Unknown JSON keys in a rule file are rejected outright —
a typo'd `"reasn"` must never silently weaken a rule.

---

## Quickstart

You need a [Zig](https://ziglang.org/download/) toolchain, 0.16.0 or newer.
This project ships as source and is built when it is cloned — there are no
prebuilt binaries to download.

<!-- hookctl:quickstart -->

```sh
./hookctl setup                 # build, install, verify — the one command (shipped defaults)
./hookctl init                  # ...or choose your rules first: profiles, or rule by rule
./hookctl doctor                # is it actually working? PASS/WARN/FAIL + a fix for each
./hookctl status                # one screen: version, rules, overlay, log, what is off
./hookctl check 'git add -A'    # what would the gate do about this command?
```

That is the whole operator surface. `setup` seeds the shipped defaults and is
done; `init` asks first — nine themed bundles ("break the agent's worst shell
habits", "nothing irreversible happens to this machine", …), each rule beside
a plain-language line about what it stops, taken whole or cherry-picked,
enforced or started in shadow — and `./hookctl rules` manages the file from
then on ([choosing and managing rules](#choosing-and-managing-rules)).
`./hookctl help` lists every verb, grouped into the ones an operator needs and
the ones a contributor needs; the [verb reference](#verb-reference) below is
the same list with one line each.

Two things to know about timing:

- **Hooks are snapshotted when a Claude Code session starts.** Installing or
  uninstalling takes effect in **new** sessions. An open session keeps the
  hook wiring it started with.
- **Rule edits are live.** The gate re-reads `hook-rules.json` on every single
  call, so editing rules changes behaviour on the very next tool call — no
  reinstall, no restart. This is also why the shipped
  [`protect-hook-config`](RULES_COOKBOOK.md#11-protect-hook-config) rule
  matters: a file that takes effect instantly is a file the agent must not be
  able to write.

Try it without installing anything — `./hookctl build && ./hookctl check ...`
needs no install at all, and the `--rules` flag points at any rule file:

```console
$ claude-hooker-gate check --rules src/default-rules.json cd /x '&&' git add -A '&&' git commit -m wip
rules    : src/default-rules.json
event    : PreToolUse
tool     : Bash
command  : cd /x && git add -A && git commit -m wip

deny     : no-git-add-all  [command_line command "add -A"]
           cd /x && git add -A && git commit -m wip
                        ^~~~~~
reason   :
           Blanket staging is denied because it sweeps in unintended files (secrets, temp files,
           generated artifacts), and `sudo git add -A`, `git -C <dir> add -A` and `bash -lc "git
           add ."` all sweep exactly the same way. Stage paths explicitly with `git add <path>
           ...`, or `git add -u` for tracked-only changes.
```

The underline sits on `add -A` rather than on `git add -A` because the shipped
rule is structural: it asks whether some invocation of `git` reconstructs to
`add -A ...`, and the bytes it compared are the subcommand and its flag. See
[how commands are parsed](#how-commands-are-parsed).

---

## The runner: `hookctl`

`hookctl` at the repository root is a thin entry point; the runner itself is the
stdlib-only Python package in [`tools/hookctl/`](#layout) — no dependencies,
ever. It is the operator-facing surface: one runner, one mental model. Everything
it does it does by shelling out to `zig build` and to the two binaries that
produces — `zig build setup`, `zig build check` and friends still work, and are
literally what these verbs run.

Two jobs cannot be done by the binaries themselves, which is why the runner
exists at all: **building them** (a binary cannot compile itself into
existence, so the very first command a new user types cannot be the gate), and
**running every mechanical consistency check the repository has** across four
rule fixtures, the class catalog, and this document.

Inside, it is built the way the Zig side is: every value that crosses a function
boundary is a frozen dataclass (`Verb`, `Paths`, `Toolchain`, `GateBinary`,
`RunResult`, `AuditReport`), resolution is pure, and there is exactly **one**
place that spawns a process, **one** that knows the install layout, and **one**
verb table — which is what `help`, dispatch and the README's verb-table check all
read, so they cannot drift apart. `./hookctl selfcheck` runs its unit tests; they
are also folded into `verify`.

> The transcripts in this section were captured against a throwaway install at
> `/tmp/hookctl-demo`, with a throwaway repository overlay at
> `/tmp/hookctl-demo-repo`. Every verb that touches an install takes
> `--claude-dir`, so you can reproduce all of it without going near
> `~/.claude`.

### Verb reference

<!-- hookctl:verbs -->

| Verb                       | Group    | What it does                                                                                                                                                                      |
| -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setup`                    | operator | Build release → install → verify. The one command a new install needs.                                                                                                            |
| `init`                     | operator | Choose your rules — a named profile, or a walkthrough of the whole catalog — selftest the composition, then install. The guided first run.                                        |
| `upgrade`                  | operator | Rebuild, print `diff-defaults`, reinstall the binary. **Your rule file is kept** unless you pass `--force-rules`.                                                                 |
| `uninstall [--purge]`      | operator | Remove every gate hook entry, on every event. `--purge` also drops the binary and the log — never the rule file.                                                                  |
| `status`                   | operator | One screen: installed version, rules and their counts, overlay, log, what is switched off.                                                                                        |
| `doctor`                   | operator | Every check `PASS`/`WARN`/`FAIL`, each failure with a remediation line. Exits `1` if anything `FAIL`s.                                                                            |
| `diff-defaults`            | operator | What the shipped defaults gained since your rule file was seeded, without touching your copy.                                                                                     |
| `rules [SUB]`              | operator | The catalog against your live file: `list`, `show`, `add [--shadow]`, `remove`, `promote`, `demote`, and the `new` authoring interview.                                           |
| `check '<command>'`        | operator | Ask the gate what it would do about one command, with the matched bytes underlined.                                                                                               |
| `explain '<command>'`      | operator | As `check`, plus the parsed and resolved command model the structural matchers read.                                                                                              |
| `stats`                    | operator | Per-rule summary of the decision log.                                                                                                                                             |
| `classes`                  | operator | The built-in classes a rule may name instead of enumerating, and their members.                                                                                                   |
| `events [NAME]`            | operator | The 30 hook events: when each fires, what its payload carries, and which decisions its response can express.                                                                      |
| `selftest`                 | operator | Run the rule file's own cases, then lint the rule set.                                                                                                                            |
| `version`                  | operator | The gate's version.                                                                                                                                                               |
| `help`                     | operator | The verb list, grouped, with the `check` vs `verify` note.                                                                                                                        |
| `build`                    | dev      | Both binaries into `zig-out/bin`, in the same release mode `setup` installs.                                                                                                      |
| `test`                     | dev      | Unit tests only (`zig build test`).                                                                                                                                               |
| `selfcheck`                | dev      | The runner's **own** unit tests (`tools/hookctl/tests`, stdlib `unittest`). Needs no toolchain; folded into `verify`.                                                             |
| `verify`                   | dev      | **The gate.** Unit tests + both binaries + the shlex parity oracle + the runner's tests + the documentation checks.                                                               |
| `parity`                   | dev      | Regenerate the shlex oracle from the corpus and diff it against the checked-in copy.                                                                                              |
| `cross`                    | dev      | Compile the binaries **and every test module** for Linux (x86_64 glibc, aarch64 glibc, x86_64 musl) without running them.                                                         |
| `fmt`                      | dev      | `zig fmt` over `src/` and `build.zig`; `--check` only reports.                                                                                                                    |
| `audit`                    | dev      | Every mechanical consistency check, with its counts.                                                                                                                              |
| `reap [--dry-run] [--all]` | dev      | Find and kill this checkout's stale build/test processes, **by explicit pid**. Exits `1` if it found anything. See [process hygiene](#process-hygiene-orphans-timeouts-and-reap). |

**`check` versus `verify`.** `check` is the _gate's_ verb — it asks what the
gate would do about one command. The _repository's_ gate, the thing that used to
be `zig build check`, is `verify`. The collision is resolved in favour of the
operator: someone diagnosing a denial types `check` far more often than someone
about to commit, and `verify` says what it does. There is deliberately no
`hookctl check` that means "run the test suite", and `zig build check` still
exists and still means the build-side gate.

The list above is checked against the implementation: `hookctl audit` fails if a
verb exists and is not in that table, or is in the table and does not exist.

<!-- hookctl:help -->

```console
$ ./hookctl help
hookctl — the one runner for claude-hooker.

usage: ./hookctl <verb> [options]

operator verbs — installing and operating the gate
  setup          build, install and verify — the one command a new install needs
  init           choose your rules, then install — the guided first run
  upgrade        rebuild, show what the defaults gained, reinstall (keeps your rules)
  uninstall      remove every gate hook entry; --purge also drops binary and log
  status         one screen: version, rules, overlay, log, what is switched off
  doctor         diagnose the install, PASS/WARN/FAIL with a fix for each problem
  diff-defaults  what the shipped defaults gained since your rule file was seeded
  rules          list, adopt, shadow, promote, remove or author rules
  check          ask the gate what it would do about one command
  explain        as `check`, plus the parsed and resolved command model
  stats          per-rule summary of the decision log
  classes        the built-in classes a rule may name, and their members
  events         the 30 hook events: what each carries, and what it can refuse
  selftest       run the rule file's own cases, then lint it
  version        the gate's version
  help           this message

dev verbs — working on this repository (these need `zig` on PATH)
  build          compile both binaries into zig-out/bin
  test           unit tests only
  selfcheck      hookctl's own unit tests (no toolchain needed; folded into verify)
  verify         THE GATE: tests + both binaries + shlex parity + doc checks
  parity         regenerate the shlex oracle and diff it against the checked-in copy
  cross          compile the binaries and all tests for Linux (x86_64, aarch64) without running
  fmt            zig fmt over src/ and build.zig (add --check to only report)
  audit          every mechanical consistency check, with its counts
  reap           kill this checkout's stale build/test processes (--dry-run, --all)

check vs verify
  `check` is the GATE's verb: it asks what the gate would do about one
  command (`./hookctl check 'git add -A'`). The repository's own gate — unit
  tests, both binaries, the shlex parity oracle, the doc checks — is `verify`.
  There is deliberately no `hookctl check` that means the second thing.

paths and sandboxes
  Every verb that touches an install accepts --claude-dir DIR, which moves the
  whole install (binary, rules, settings.json, log) into DIR. Without it the
  install is ~/.claude. Relative paths are resolved against your cwd.

the underlying steps still work
  This shells out to `zig build` — `zig build setup`, `zig build check` and
  friends are unchanged and are exactly what these verbs run.
```

### `setup` — build, install, verify

<!-- hookctl:setup -->

```console
$ ./hookctl setup --claude-dir /tmp/hookctl-demo
== build ==
zig-out/bin/claude-hooker-gate, zig-out/bin/claude-hooker-install (release)

== install ==
selftest: embedded default rules OK (497 cases, 0 lint warning(s))
claude-hooker-install plan:
  gate    : zig-out/bin/claude-hooker-gate -> /tmp/hookctl-demo/hooks/claude-hooker-gate
  rules   : /tmp/hookctl-demo/hook-rules.json (seed default)
  settings: /tmp/hookctl-demo/settings.json (rewrite hook entries (backup first))
    SessionStart         (all)      1 rule(s)  ADD
    PreToolUse           *          12 rule(s)  ADD
    PostToolUse          Bash       1 rule(s)  ADD
verify:
  ok   gate    : /tmp/hookctl-demo/hooks/claude-hooker-gate (1130240 bytes)
  ok   signature: /tmp/hookctl-demo/hooks/claude-hooker-gate (flags=0x20002(adhoc,linker-signed), Signature=adhoc)
  ok   rules   : /tmp/hookctl-demo/hook-rules.json (14 rules, 110 cases)
  ok   settings: /tmp/hookctl-demo/settings.json (3 event(s) wired: SessionStart PreToolUse PostToolUse)
done. Hooks are snapshotted at session start — takes effect in NEW Claude Code sessions.
== signature ==
   ok   /tmp/hookctl-demo/hooks/claude-hooker-gate: flags=0x20002(adhoc,linker-signed), Signature=adhoc
        `codesign --verify` accepts it; no Developer ID is involved or required.
```

Four properties of that run are worth naming, because they are what make it
safe to type on a machine you care about:

- the **embedded** defaults are run through the whole `selftest` machinery
  before anything is written, and a failure aborts the install;
- `settings.json` is **backed up** to a timestamped sibling before it is
  touched, and an existing `hook-rules.json` is **never** overwritten without
  `--force-rules`;
- every artifact is **verified by reading it back**, not by trusting the write;
- on macOS the installed binary's **code signature** is verified, and repaired
  if it does not validate — because a gate the loader kills fails **open** and
  says nothing at all. See [macOS code signing](#macos-code-signing). The
  `== signature ==` section is `hookctl` asking `codesign` the same question
  again afterwards, independently; off macOS neither line appears.

`--dry-run` prints the plan and writes nothing. `--claude-dir` moves the whole
install; without it, it is `~/.claude`.

### `upgrade` — the path for a rule file you have edited

`upgrade` rebuilds, shows you what the shipped defaults gained, and reinstalls
the **binary only**. Your rule file is your policy document; nothing here
rewrites it unless you say `--force-rules`. Rule edits are live on the next tool
call, so adopting something from the diff needs no reinstall at all.

### `verify` and `audit` — the two dev gates

`verify` is what runs before a commit: `zig build check` (unit tests and both
binaries compiling), then the shlex parity oracle as its own step, then the
runner's own unit tests (`./hookctl selfcheck` — arg parsing, which binary
answers, the verb table's integrity, the signature verdicts), then the
documentation checks that live in `hookctl` because they are about `hookctl`.

`audit` is the wider one: every mechanical consistency check the repository has,
each with its **counts**. The counts are the point. A green tick says "nothing
broke"; the numbers say "and here is how much is still being asserted", which is
what makes a quiet slide back toward hand-maintained lists visible in a diff.
The per-rule table is the clearest example — a rule whose `literal` column grows
while its `ref` column shrinks has stopped inheriting a class and started
copying it.

<!-- hookctl:audit -->

```console
$ ./hookctl audit
== build and tests ==
   ok   toolchain present — zig 0.16.0 at /opt/homebrew/bin/zig
   ok   unit tests (includes the doc-vs-fixture identity tests)
   ok   both binaries compile
   ok   shlex parity oracle is not stale
   ok   hookctl's own unit tests — 265 tests

== rule fixtures: their own cases, and lint ==
   ok   src/default-rules.json — 107 literal + 390 generated cases pass, 0 lint error(s), 0 warning(s)
   ok   src/testdata/selftest-rules.json — 19 literal + 0 generated cases pass, 0 lint error(s), 0 warning(s)
   ok   src/testdata/cookbook-recipes.json — 195 literal + 572 generated cases pass, 0 lint error(s), 1 warning(s)
   ok   src/testdata/structural-rules.json — 18 literal + 13 generated cases pass, 0 lint error(s), 1 warning(s)
   total: 339 literal + 975 generated cases, 0 lint error(s), 2 warning(s) across 4 rule file(s)

== the catalog: init profiles and co-adoption, composed then selftested ==
   ok   bundles and blurbs cover the catalog exactly — 9 bundles + 1 unbundled = 28 rules, 28 blurbs
   ok   profile `recommended` composes and passes selftest — 14 rule(s), 107 literal + 390 generated cases
   ok   profile `observe` composes and passes selftest — 14 rule(s), 107 literal + 390 generated cases
   ok   profile `minimal` composes and passes selftest — 4 rule(s), 22 literal + 150 generated cases
   ok   bundle `agent-hygiene` composes and passes selftest — 4 rule(s), 32 literal + 240 generated cases
   ok   bundle `machine-guards` composes and passes selftest — 3 rule(s), 25 literal + 290 generated cases
   ok   bundle `git-discipline` composes and passes selftest — 3 rule(s), 16 literal + 42 generated cases
   ok   bundle `opaque-execution` composes and passes selftest — 5 rule(s), 8 literal + 0 generated cases
   ok   bundle `database-safety` composes and passes selftest — 2 rule(s), 8 literal + 0 generated cases
   ok   bundle `secrets-and-config` composes and passes selftest — 3 rule(s), 5 literal + 0 generated cases
   ok   bundle `observability` composes and passes selftest — 3 rule(s), 0 literal + 0 generated cases
   ok   bundle `command-shape` composes and passes selftest — 2 rule(s), 4 literal + 0 generated cases
   ok   bundle `single-entrypoint` composes and passes selftest — 2 rule(s), 0 literal + 0 generated cases
   ok   the whole catalog co-adopted passes selftest — 28 rule(s), 100 literal + 572 generated cases

== per-rule enumeration counts (a rising 'literal' column is drift back to hand-listing) ==
   src/default-rules.json: 14 rules, 31 literal leaf/leaves, 11 class/set reference(s)
       no-pkill                                    1 literal    0 ref
       no-inline-python                            4 literal    0 ref
       no-heredoc-python                           3 literal    0 ref
       no-git-add-all                              4 literal    0 ref
       deny-recursive-mutation-from-anchor        10 literal    5 ref
       protect-hook-config                         2 literal    0 ref
       ask-whole-world-traversal                   1 literal    4 ref
       wrapper-script-shadow                       1 literal    0 ref
       observe-script-file-run                     1 literal    1 ref
       observe-session-start                       0 literal    1 ref
       watch-eval                                  1 literal    0 ref
       watch-pipe-into-shell                       1 literal    0 ref
       watch-decode-into-shell                     1 literal    0 ref
       watch-unresolved-command-word               1 literal    0 ref
   [... the other three fixtures, rule by rule, elided ...]
   total: 54 rules, 114 literal leaf/leaves, 31 reference(s)

== class membership (what a rule inherits from the binary) ==
   home_or_root             path      16 member(s)
   filesystem_anchor        path      12 member(s)
   shell_names              command    8 member(s)
   db_clients               command    9 member(s)
   package_managers         command   25 member(s)
   destructive_sql          phrase     4 member(s)
   traversal_commands       command    6 member(s)
   recursive_readers        command    6 member(s)
   recursive_mutators       command    4 member(s)
   stream_editors           command    6 member(s)
   total: 10 classes, 96 members

== documentation ==
   ok   README quotes `./hookctl help` verbatim
   ok   README's verb table matches the implementation — 25 verbs
   ok   README's quickstart leads with ./hookctl
   ok   README quotes the per-event table verbatim — 30 events
   ok   README's doctor transcript names every check — 8 checks
   ok   README's status transcript names every line — 6 lines

audit: 30 check(s) passed, 0 failed
```

That is the only block in this document with anything elided, and it says so:
the per-rule tables for the other three fixtures are the same shape, 27 more
rows.

### Process hygiene: orphans, timeouts, and `reap`

**The failure this exists for, concretely.** An orphaned `zig build test` runner
and two of its compiled test binaries once spun at 100% CPU each for **eleven
hours** and took a machine down. The mechanism is ordinary and will happen
again: `zig build` spawns its test binaries as **children**, so when the process
that invoked `zig build` dies — a killed agent, a closed terminal, a crashed
wrapper — the runner is reparented to init (PPID 1) and its children outlive it.

The part worth internalising is why nothing noticed:

> **An orphan goes on executing the code it was COMPILED from, not the code on
> disk.** The binary that was spinning had been built from a half-finished
> refactor containing an infinite loop. That source was long gone. So every gate
> that reads the source tree — `verify`, `audit`, `test`, CI — was green the
> entire time, and was **right** to be green. There was nothing wrong with the
> repository. The only witness to a runaway process is the process table, so
> that is what these three mechanisms read.

#### `reap` — find them and kill them, by pid

```console
$ ./hookctl reap --dry-run
== 3 process(es) found ==
    pid   ppid  elapsed    %cpu       rss  state              command
  39262      1  11h04m     99.8   39.9 MiB  orphaned, pegged, long-running zig build test
  39293  39267  11h04m     99.4    6.1 MiB  pegged, long-running ./.zig-cache/o/99bca0/test --listen=-
  39295  39267  11h04m     98.7    6.0 MiB  pegged, long-running ./.zig-cache/o/541236/test --listen=-

--dry-run: nothing was signalled. Without it, those 3 pid(s) would be sent SIGTERM, given a moment, then SIGKILL.
```

- **Detection.** Four process shapes are recognised, because those are the four
  a real `zig build` leaves behind: `zig build <step>`, the compiled build runner
  under `.zig-cache/o/<hash>/build`, a compiler process (macOS shows these as a
  bare `(zig)` with no argv at all), and a compiled test binary under
  `.zig-cache/o/<hash>/`. Membership of **this** checkout is decided by an
  absolute project path in the argv, else a relative `.zig-cache` path that
  resolves to a file that really is in this root's cache, else the process's own
  working directory — and then shared along the parent/child graph. That last
  step is not optional: the top-level `zig build test` has **no path in its argv
  whatsoever**, and the test binaries are spawned with **relative** paths. Only
  the build runner in the middle spells the root out.
- **Killing.** SIGTERM to every pid, a two-second grace, then SIGKILL to whatever
  is left, then a check that the pids are actually gone. Every pid is printed
  before it is signalled, and **the kill is always by explicit pid** — never a
  pattern. The shipped `no-pkill` rule is not an obstacle worked around here, it
  is the same lesson: any pattern broad enough to match "the runaway zig build"
  also matches the process doing the matching, whose own argv contains the words
  it is searching for.
- **Scope.** This checkout by default. `--all` widens to every zig build process
  you own, with out-of-project ones marked `[other project]`, for when the
  machine is on fire and you do not care whose build it is.
- **Exit code.** `1` if it found anything, `0` if the checkout is clean, so
  `./hookctl reap --dry-run` is usable as a condition. `69` if `ps` could not be
  run at all — because "I could not look" must never read as "nothing is there".

#### The `processes` check in `doctor`

`./hookctl doctor` prints the gate's eight checks about the **install**, then one
more, from the runner, about **this working tree**:

```console
result     : 8 pass, 0 warn, 0 fail -> healthy

== this checkout's own build processes (not part of the install) ==
FAIL  processes   2 build/test process(es) from this checkout should not be running — 1 orphaned
                  (PPID 1), 2 above 80% cpu: pid 39262 (zig build, orphaned, pegged, long-running,
                  up 11h04m, 100% cpu); pid 39293 (test binary, pegged, long-running, up 11h04m,
                  99% cpu). An orphan goes on executing the code it was COMPILED from, so the
                  source tree and every gate that reads it stay green while it burns cpu
      -> run `./hookctl reap` — it prints every process with its pid, then kills those pids
         (SIGTERM, then SIGKILL); `--dry-run` lists without killing
```

| Verdict                | When                                                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FAIL`                 | Anything **orphaned** (PPID 1) or **pegged** (>80% CPU).                                                                                                      |
| `WARN`                 | Anything alive longer than the threshold (default **10 minutes**) that is neither orphaned nor pegged.                                                        |
| `PASS`                 | Nothing running; or a live build that is parented, young and within budget (which it names, rather than claiming the machine is idle).                        |
| `PASS`, not applicable | `ps` could not be run. Reported as **not applicable** with the reason, never as absent — a check that says "clean" when it cannot see is worse than no check. |

**Why this check is in the Python runner rather than in `src/cli.zig` with the
other eight.** Two reasons, both about ownership. First, the gate diagnoses an
**install**: a `~/.claude` with a binary, a rule file and a log. "Is a build
process from this checkout still spinning" is a question about a **working
tree**, and an installed gate on a machine with no clone beside it cannot answer
it — it has no root to compare against. Second, the detection heuristics and the
kill sequence already have to exist in the runner, because `reap` is a runner
verb and the remediation line points at it. Implementing `ps` parsing,
orphan/pegged classification and project attribution a second time in Zig would
mean two implementations of the same judgement, free to disagree, in a codebase
whose whole discipline is one table read by everything. So `doctor`'s count on
the Zig side stays at **eight**, and the ninth line is contributed by the runner
and clearly labelled as being about something else. `doctor --json` merges it
into the same document (with the tallies recomputed), so a script sees one valid
object with nine checks.

`doctor` is also the one compiling verb that deliberately does **not** auto-reap:
a diagnosis that quietly tidied up first could never show you what you ran it to
find.

#### Bounded runs, and what a timeout kills

Every child `hookctl` spawns is bounded, and a timeout kills the child's whole
**process group**:

| Verb                                                                                                                                           | Budget per child                                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `build`, `test`, `parity`, `fmt`, `verify`, `audit`, `setup`, `upgrade`, `uninstall`, and the rebuild before `doctor`/`status`/`diff-defaults` | **300 s** (5 minutes)                                                                              |
| `cross`                                                                                                                                        | **1800 s** (30 minutes) — it compiles the binaries _and_ every test module for three Linux targets |
| A probe (`zig version`, `codesign`, `ps`, `lsof`)                                                                                              | **30 s**                                                                                           |

Override with `--timeout SECONDS` on any verb (including the ones that otherwise
take no arguments — it is consumed by the runner and never forwarded to a child)
or with `HOOKCTL_TIMEOUT` in the environment; the flag wins. A value below one
second is refused out loud and the verb's default is used instead. There is
deliberately **no spelling of "unbounded"**: `--timeout 0` is the bug.

Three details that are the whole point:

- **Children are spawned with `start_new_session=True`,** which makes each child
  the leader of its own process group. Without that there is no handle on the
  grandchildren at all — and the grandchildren are what burn the CPU.
- **A timeout signals the group, not the child.** SIGTERM to the group, a grace
  period, SIGKILL to the group, then the direct child is reaped and the group is
  **checked** for survivors. `hookctl` reports which step timed out, how long it
  actually ran, and whether anything outlived SIGKILL:

  ```console
  $ ./hookctl test --timeout 2
  hookctl: `zig build test` was still running after 2s and was killed.
  hookctl:   zig build test: no answer after 2s (ran 2.1s), killed its process group; no survivors
  hookctl:   raise the budget with `--timeout SECONDS` if this machine is honestly that slow.
  ```

  The exit code is **124**, the same code `timeout(1)` uses, so a script can tell
  "I gave up on it" apart from "it ran and failed".

- **Ctrl-C is handled here too.** A child in its own session is no longer in the
  terminal's foreground process group, so the SIGINT from a Ctrl-C reaches
  `hookctl` and _not_ the build. `hookctl` kills the group before re-raising —
  otherwise `start_new_session=True` would itself have become a new way to
  manufacture the orphan it exists to prevent.

#### Auto-reap before a build

`setup`, `upgrade`, `check`, `build`, `test`, `parity`, `cross`, `verify` and
`audit` look for a previous run's runaway before they start, and say nothing
unless they actually killed something:

```console
$ ./hookctl test
hookctl: a previous run left 1 process(es) of this checkout running:
hookctl:   pid 39262 (zig build, orphaned, pegged, long-running, up 11h04m, 100% cpu) zig build test
hookctl: reaped 39262 before starting
```

Acting without being asked is held to a **higher bar** than reporting. Auto-reap
kills only what is unambiguous — an orphan, or something both pegged _and_ past
the elapsed threshold. A process at 95% CPU that started thirty seconds ago is a
compile doing its job, and a silent reaper that killed a colleague's honest build
would be a worse bug than the one all of this is for. Typed `reap` is not so
cautious: you said so, and a live build is included.

### Without a Zig toolchain

There is nothing to download. `hookctl` says so in one line rather than failing
somewhere deeper, names what to install, and — if a gate is already installed —
lists the verbs that still work through it (`status`, `doctor`, `check`,
`explain`, `stats`, `classes`, `selftest`, `version`, `diff-defaults`). It exits
`69` (`EX_UNAVAILABLE`) and never prints a traceback.

### For contributors

`hookctl` shells out; it does not reimplement. Every dev verb is a thin wrapper
over a `zig build` step, and every operator verb is either the installer or a
gate subcommand:

| Verb                | Runs                                                         |
| ------------------- | ------------------------------------------------------------ |
| `build`             | `zig build --release`                                        |
| `test`              | `zig build test`                                             |
| `verify`            | `zig build check`, then the doc checks in `hookctl`          |
| `parity`            | `zig build parity`                                           |
| `setup` / `upgrade` | `zig build --release`, then `claude-hooker-install --gate …` |
| `uninstall`         | `claude-hooker-install --uninstall`                          |
| `reap`              | `ps` (and `lsof` on macOS) to look, then `kill(2)` by pid    |
| everything else     | `claude-hooker-gate <subcommand>`                            |

Every one of those children is spawned in its **own session** with a wall-clock
budget, and a timeout kills the whole process group — see
[process hygiene](#process-hygiene-orphans-timeouts-and-reap).

Which gate binary a passthrough verb uses: the freshly built
`zig-out/bin/claude-hooker-gate` wins over the installed one, and the choice is
announced on stderr only when the two are **not the same bytes** — announcing it
every time would train you to skip the line that matters. `doctor`, `status` and
`diff-defaults` additionally run an incremental `zig build --release` first, so
the version they compare the install against is your working tree rather than
whatever was last built.

---

## Choosing and managing rules

Two documents in this repository already carry a tested rule for most things an
operator wants: the shipped defaults (`src/default-rules.json`, what `setup`
seeds wholesale) and the [cookbook](RULES_COOKBOOK.md)'s fixture, which a unit
test holds identical to every recipe on that page. Together they are **the
catalog**, and `init` and `rules` are the two verbs that work from it — so
adopting a recipe is a verb, not a copy-paste of a rule, its test cases, and
whatever named set it references.

Every path that writes your rule file — every one — goes through the same
pipeline: the composed document is **selftested by the gate itself** before a
byte lands, the previous file is copied to a timestamped `.bak-<seconds>`
sibling (the same naming the installer uses for `settings.json`), and the swap
is atomic. A rejected composition is kept as a `.draft` sibling with the gate's
complaint printed, and your live file is not touched. Rule edits are live on
the gate's very next call, which is exactly why nothing may land unvalidated.

### `init` — the guided first run

`./hookctl setup` is still the one-command path. `./hookctl init` is the other
door, and it is built for someone who has never seen this catalog: the unit of
choice is the **bundle** — a themed group, each rule beside a plain-language
line about what it stops — not a rule count you have no way to evaluate.

```
How do you want to choose?
  1.* bundles      the 9 themed bundles — see what each one stops, take or leave each
  2.  everything   all 9 bundles at once (27 rules)
  3.  minimal      just the 4 machine-guards (protect this machine and the gate itself)
  4.  rule-by-rule the whole catalog, one decision per rule

-- agent-hygiene: break the agent's worst shell habits --
   deny   no-pkill                             pkill kills by pattern — it has killed the agent's own shell
   deny   no-inline-python                     `python -c` / stdin one-liners: throwaway code nobody reviews
   deny   no-heredoc-python                    a heredoc piped into python — the same habit in disguise
   ask    ask-whole-world-traversal            find/grep/du from `/` or `~` floods context; asks first
   take this bundle? [Y/n/s]
```

The nine bundles: `agent-hygiene` (the poor-engineering habits: `pkill`,
inline `python -c` / stdin programs, whole-disk `find` from `/` or `~`),
`machine-guards` (nothing irreversible happens to this machine),
`git-discipline`, `opaque-execution` (`curl | bash` and friends),
`database-safety`, `secrets-and-config`, `observability`, `command-shape`
(the [structure of a command](#stage--one-invocations-context): no pipes into
`head`/`tail`, a shadow watch on long pipelines), and `single-entrypoint` — a
**posture**: every action is one real program with arguments, no shell
plumbing, no `sed`/`awk` fragments. It ships as `log` so the decision log
measures your real work first; when your entry points cover it,
`./hookctl rules promote single-entrypoint-only --to deny` enforces
([recipe 23](RULES_COOKBOOK.md#23-single-entrypoint-only)). Every answer is
`y` / `n` / `s` — `s` takes the bundle in **shadow** (log-only). Skipped
bundles get an a-la-carte pass afterwards, so cherry-picking single rules is
one more question, not a different mode. The walkthrough ends with one more
choice — **enforce now, or start everything in shadow** — so the cautious
rollout is a single keystroke, and Enter all the way through produces the full
recommended set.

The bundle curation is audited, not trusted: every bundle (and the whole
catalog co-adopted) is composed and run through the gate's `selftest` by
`audit`, every rule must belong to exactly one bundle (or be an explicitly
known extra), and every rule must have its one-line description — a rename in
the catalog that leaves a bundle or a blurb stale is a failing check.

Non-interactively (scripts, CI): `--profile recommended|observe|minimal`
(`recommended` is the shipped defaults — the same rules, cases and sets
`setup` seeds; `observe` is the same demoted to log), or one or more
`--bundle NAME`, with `--shadow` demoting whatever was chosen. Plus
`--dry-run` (compose and selftest, write nothing), `--no-install`,
`--force-rules` (an existing file is otherwise never replaced without a
question), `--yes`, and `--claude-dir` as everywhere else. An aborted run —
Ctrl-D, a declined confirmation, a failed selftest — writes **nothing**.

### `rules` — the file's lifecycle from then on

```console
$ ./hookctl rules                      # the catalog against your live file, by bundle
$ ./hookctl rules show no-rm-rf-home-or-root
$ ./hookctl rules add machine-guards   # a whole bundle at once...
$ ./hookctl rules add ask-sudo --shadow   # ...or one rule, a la carte
$ ./hookctl rules promote ask-sudo     # shadow -> the catalog's enforced form
$ ./hookctl rules promote single-entrypoint-only --to deny   # a watch rule, raised to enforcement
$ ./hookctl rules demote no-git-add-all
$ ./hookctl rules remove wrapper-script-shadow
$ ./hookctl rules new                  # author a rule, interviewed step by step
```

- **`list`** (the default) shows every rule in your file — `installed`,
  `shadowed`, `edited`, or `yours`, each with its bundle — and everything you
  have not adopted, grouped by bundle with its plain-language line. It reads;
  it needs no gate and no toolchain.
- **`add NAME`** takes a rule **or a whole bundle**. A rule arrives **with its
  test cases and any file-local sets it references**, inserted at the
  catalog's first-match-wins position rather than appended — an `allow`
  carve-out appended after the deny it carves out of would be a no-op. A
  bundle adds whichever of its rules you do not already have, as one write.
  `--shadow` adopts either as `log`. A clash with a set you already define
  keeps **your** definition.
- **`remove NAME`** takes out the rule, the cases that name it, the exact
  shadow-period rewrites of those cases, and any catalog set nothing else
  references. Sets and cases you wrote by hand stay.
- **`promote` / `demote`** are the mechanical ends of the shadow-first method:
  the demotion is exactly one transform (`decision` → `log`, a stated prefix on
  the reason, case expectations rewritten to `none`), so promotion can restore
  the catalog's enforced rule _and_ its original cases, deterministically. A
  rule the catalog ships as `log` — the watch rules, the `single-entrypoint`
  posture — has no enforced form to restore, so its promotion states one:
  `promote NAME --to deny` (or `--to ask`) strips the reason's observational
  lead-in and enforces the rest verbatim; `demote` returns the catalog's
  `log` form exactly.
- **`new`** interviews you: event, tool, consequence (defaulting to `log`,
  because the cookbook's step one is a shadow period), what to match — offered
  as situations ("a program must never run", "one of its options is not",
  "edits to a path") rather than matcher-kind names — the reason, with the
  [style guide](RULES_COOKBOOK.md#reasons-are-prompts-a-style-guide) formula in
  front of the answer box, and at least one must-catch and one must-not-catch
  case. On success your first case is replayed through `check` so you see the
  matched bytes underlined before you trust it.

A mutation that changes **which events** your rules use ends with a reminder to
run `./hookctl setup` again: the installer wires exactly the events the rule
file uses, and hooks are snapshotted at session start.

The catalog cannot rot: `audit` asserts the bundle partition and the per-rule
blurbs correspond to the catalog exactly, then composes every profile, every
bundle, and the whole catalog co-adopted at once, and runs each composition
through the real gate's `selftest`, with counts.

---

## Configuration reference

The rule file is a single JSON document. Its default location is
`~/.claude/hook-rules.json`; see [environment variables](#environment-variables)
for the overrides. It is capped at **1 MiB** — a policy document is a page or
two, and refusing to read a larger one beats reading it slowly on every tool
call.

### Top level

| Field                   | Type   | Default | Meaning                                                                                                         |
| ----------------------- | ------ | ------- | --------------------------------------------------------------------------------------------------------------- |
| `schema_version`        | string | absent  | `"major.minor"` — the schema this document is written for. See [below](#schema-versions-and-compatibility).     |
| `rules`                 | array  | `[]`    | The policy, in order. **First match wins.**                                                                     |
| `tests`                 | array  | `[]`    | Cases the file asserts about itself; run by `selftest`.                                                         |
| `sets`                  | object | `{}`    | Named value lists matchers may reference — see [sets](#sets-and-classes-naming-a-list-instead-of-repeating-it). |
| `logging`               | object | `{}`    | Decision-log settings — see [logging](#logging).                                                                |
| `allow_project_overlay` | bool   | `true`  | May a repository contribute rules? Only the **global** file's setting is read.                                  |

Unknown keys anywhere in the document are a hard parse error.

### Schema versions and compatibility

Unknown keys being fatal is the right default — a typo'd `"reasn"` must fail
loudly rather than silently weaken a rule. But it has a consequence that is not
obvious, and it used to be a real hole:

> A rule file written by a **newer** gate — one using a matcher kind, a field, or
> a group operator this binary has never heard of — fails to parse **as a whole**.
> And because the hook fails OPEN on an unreadable config (which is the right
> policy: a gate that blocks every command when its config is broken is worse
> than no gate), the result was a silent, total loss of enforcement, reported as
> a syntax error about a key that is perfectly valid one release later.

`schema_version` is what makes that case diagnosable:

```json
{
  "schema_version": "1.1",
  "rules": [...]
}
```

The current schema is **1.2**. Version `1.1` added the rule-level `event` key and
the five payload fields beyond the original three; version `1.2` added the
[`stage`](#stage--one-invocations-context) and
[`shape`](#shape--counted-structure-of-the-whole-command) matcher kinds. Both
were additive, so every `1.0` and `1.1` document is still valid and still means
exactly what it meant. On load:

| The file declares…              | What happens                                                                                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| the same version                | Loaded.                                                                                                                                                                                                    |
| an **older** version            | Loaded, and named in `doctor`'s `rules` line. Every construct an older document can contain is understood, so there is nothing to refuse.                                                                  |
| **nothing**                     | Loaded, read as the oldest known schema (**1.0**), and `doctor` `WARN`s once with the line to add. Every rule file seeded before this field existed is in this state, so it is deliberately **not** fatal. |
| a **newer** version             | **Refused**, with both versions named and `./hookctl upgrade` as the remedy. Exit **78**, not 65.                                                                                                          |
| something that is not a version | Refused the same way, telling you to fix the value or delete the key. Exit **78**.                                                                                                                         |

The version is read _before_ the strict parse, which is the whole trick: read
afterwards it would be unreachable in exactly the case it exists for.

**Bump policy.**

- **Minor** — additive: a new matcher `kind`, a new class, a new signal name, a
  new group operator, a new event, a new top-level field. Every document valid
  under the previous minor is still valid.
- **Major** — a change in what an existing construct _means_, or its removal. A
  document written for an older major may match differently.

Both point the same way for the reader: because a minor bump can introduce a
spelling an older binary does not know, **any** newer version — major or minor —
is refused rather than attempted. Older is always accepted.

Where you will see this: `doctor`'s `rules` check, `status`'s `rules` line,
`status --json` (`rules.schema_version` and `rules.schema_read`), and
`diff-defaults`, which reports a `schema_version` section when your file's
differs from the shipped defaults'. A newer file in a _project overlay_ is
skipped with a note rather than fatal — same policy as any other broken overlay,
because a repository must not be able to switch the operator's gate off.

### A rule

| Field        | Type             | Default        | Meaning                                                                                                                                                                    |
| ------------ | ---------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`       | string           | required       | Unique. `CLAUDE_HOOK_DISABLE` and every log line key on it.                                                                                                                |
| `event`      | enum             | `"PreToolUse"` | Which hook event this rule is scoped to — see [hook events](#hook-events). One event per rule, and only that event's rules are walked for a payload.                       |
| `tool`       | string           | `"Bash"`       | Compared exactly against the payload's tool name, or `"*"` for every tool. Meaningful only on the events that carry one; naming a tool on any other event is a lint error. |
| `decision`   | enum             | `"deny"`       | `deny` \| `ask` \| `allow` \| `log` — see [decisions](#decisions). **Which of these an event can express is event-specific.**                                              |
| `reason`     | string           | required       | Shown to the model **and** the user. This is the whole point; see below.                                                                                                   |
| `match`      | array of entries | `[]`           | **Any-of.** One satisfied entry satisfies this list.                                                                                                                       |
| `match_all`  | array of entries | `[]`           | **All-of.** Every entry must be satisfied.                                                                                                                                 |
| `match_none` | array of entries | `[]`           | **None-of.** Any satisfied entry here suppresses the rule. Purely subtractive.                                                                                             |

Every populated list must be satisfied simultaneously. A rule with only
`match_none` can never fire — at least one of `match`/`match_all` has to supply
the positive condition — and `selftest`'s lint reports that as an error.

### A matcher

An entry of those three lists is **either a matcher or a group**.

| Field         | Type   | Default     | Meaning                                                                                                                                                                                       |
| ------------- | ------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kind`        | enum   | `"tokens"`  | `tokens` \| `word` \| `substring` \| `command_word` \| `argv` \| `command_line` \| `flag` \| `flags` \| `path_class` \| `signal` \| `stage` \| `shape` — see [matcher kinds](#matcher-kinds). |
| `field`       | enum   | `"command"` | `command` \| `content` \| `file_path` \| `prompt` \| `output` \| `message` \| `trigger` \| `agent` — see [fields](#fields). Reading a field the rule's event does not carry is a lint error.  |
| `value`       | string | required    | The pattern — or a [reference](#sets-and-classes-naming-a-list-instead-of-repeating-it) (`"$class:db_clients"`, `"$protected_branches"`). An empty pattern never matches.                     |
| `ignore_case` | bool   | `false`     | Fold ASCII case. Honored by `tokens`, `word`, `substring`, `argv`, `command_line` — see [case](#ignore_case--opt-in-case-folding).                                                            |

### Groups: `(A or B) AND (C or D)`

The three lists alone are exactly one conjunction with one disjunction inside
it. That cannot say _"a destructive SQL statement AND a database client"_, and
without the second half a rule that names the statement denies
`git commit -m "drop table users migration"` for saying the words — the
mention-versus-execution confusion the structural kinds exist to end.

So any entry may instead be a group:

| Field        | Type             | Satisfied when                                              |
| ------------ | ---------------- | ----------------------------------------------------------- |
| `any`        | array of entries | at least one entry is satisfied                             |
| `all`        | array of entries | every entry is satisfied                                    |
| `none`       | array of entries | no entry is satisfied (an inline carve-out)                 |
| `invocation` | array of entries | every entry is satisfied **by one and the same invocation** |

```json
"match_all": [
  { "any": [
    { "kind": "argv", "value": "DROP TABLE" },
    { "kind": "argv", "value": "TRUNCATE TABLE" } ] },
  { "any": [
    { "kind": "command_word", "value": "psql" },
    { "kind": "command_word", "value": "mysql" } ] }
]
```

Rules of the road, all of them enforced by `selftest`'s lint:

- An entry is a group **or** a matcher, never both: a group carries no `value`,
  and naming two of `any`/`all`/`none`/`invocation` on one entry is an error.
- An **empty** group (`{"any": []}`) is never satisfied — vacuous truth in a
  positive list would silently widen the rule to everything.
- Groups nest up to **4 levels**; deeper is an error, and evaluation treats an
  over-deep group as unsatisfied rather than recursing into it.
- A satisfied `none` group supplies **no evidence** — nothing matched, so there
  are no bytes to underline. It still constrains the rule, but it cannot be the
  hit that gets reported, and a rule whose entire positive condition is `none`
  groups never fires (the lint says so).
- A group reports the **leaf that actually hit**, so `check` and the decision
  log stay exactly as specific as they were before groups existed.

Groups are purely additive: a rule file written before they existed contains
only matchers, parses identically, and behaves identically.

### `invocation`: which _stage_ each half is about

The example above has a hole, and it is not the one groups fixed. `any` and
`all` combine independent **existential** claims over the whole command line —
_some_ invocation is `psql`, _some_ argument anywhere is `DROP TABLE` — and
both of those are true of:

```
psql -l && git commit -m "drop table x"
```

...where the two halves come from two entirely different stages. `command_line`
is the only per-invocation matcher, and it is an anchored token run, so it
cannot say "this invocation's arguments contain X somewhere".

`{"invocation": [...]}` is that missing operator. It is satisfied only when a
**single stage** satisfies every child, and it reports that stage's evidence,
so the underline `check` draws and the span the log records stay pointed at the
invocation the rule is about:

```json
"match_all": [
  { "invocation": [
    { "any": [
      { "kind": "command_word", "value": "psql" },
      { "kind": "command_word", "value": "mysql" } ] },
    { "kind": "argv", "value": "DROP TABLE", "ignore_case": true } ] }
]
```

| Input                                         | Fires? | Why                                            |
| --------------------------------------------- | ------ | ---------------------------------------------- |
| `psql -c "DROP TABLE users"`                  | yes    | one stage carries both halves                  |
| `bash -lc 'psql -c "DROP TABLE users"'`       | yes    | a nested stage is an invocation like any other |
| `sudo psql -q -c 'drop table users'`          | yes    | the wrapper is unwrapped before the binding    |
| **`psql -l && git commit -m "drop table x"`** | **no** | two stages; neither one carries both halves    |
| `psql -c 'SELECT 1'`                          | no     | each half is still required                    |

Four things about the binding, all of them tested and linted:

- `any`, `all` and `none` **nest inside it and stay scoped** — a `none`
  carve-out inside an `invocation` group asks about _that stage's_ arguments,
  not about any argument anywhere.
- The **textual** kinds (`tokens`, `word`, `substring`) and `signal` are
  **not** narrowed by it. They are not properties of an invocation: the first
  three read raw field bytes and `signal` describes the whole parse. They still
  evaluate as ordinary conjuncts, and the lint warns, because reading one as
  scoped would be a mistake about what it means.
- An `invocation` group **inside** another cannot name a different invocation,
  so it degenerates to a plain `all` over the same binding (and warns).
- A stage that names no command (`FOO=bar`, `> out`) and a function _definition_
  are not invocations, so nothing binds to them.

Reach for it whenever a rule names both a program and something about that
program's own arguments. `check --explain` prints the invocation list the
binding walks, which is how you argue with the result.

### Matcher kinds

Deliberately no regex. Two families:

- **textual** — `tokens`, `word`, `substring` read the raw bytes of a field.
  They are honest about what they are, and the
  [threat model](#threat-model) says exactly what defeats them.
- **structural** — `command_word`, `argv`, `command_line`, `flag`, `flags`,
  `path_class`, `signal`, `stage`, `shape` read the _parsed and resolved_
  command: pipeline stages, nested program text, quote-stripped arguments,
  normalized paths, the invocation's option set, variables the command string
  itself assigns, each invocation's position in the pipeline, and the counted
  structure of the whole thing. They are the answer to the quoting trap, to
  fragment assembly, and to enumerating spellings.

Textual behaviour has not changed and will not: a rule file written before the
structural kinds existed evaluates byte-for-byte identically, and a rule file
that uses none of them never pays for them (nothing is parsed).

#### Which kind for which job

Nearly every rule that goes wrong went wrong here — by asking a question of the
bytes when it meant to ask it of the command, or the reverse. The twelve kinds
answer twelve different questions:

| You want to say…                                                      | Use                                     | Not                                                                      |
| --------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------ |
| "this **program** must not run"                                       | `command_word`                          | `word`/`tokens`, which also fire on `echo pkill is bad`                  |
| "this program must not run **with these options**"                    | `flags`, inside an `invocation` group   | one `flag` per spelling — `-rf`, `-fr`, `-r -f` are one option set       |
| "this program must not run **with this one option**"                  | `flag`, inside an `invocation` group    | `argv`, which cannot see `-r` inside `-vrf`                              |
| "not **anywhere under home or a system path**"                        | `path_class`                            | a list of `argv` prefixes, which `~/../` and `/usr/../..` walk past      |
| "some **argument** carries this value or phrase"                      | `argv`                                  | `tokens`, which the quoting trap defeats                                 |
| "this **whole invocation shape** is forbidden"                        | `command_line`                          | `tokens`, which is unanchored and fires on a mention                     |
| "the text does not say what will run"                                 | `signal`                                | anything else — nothing else can express it                              |
| "these bytes appear in a file **body**"                               | `word` / `substring` on `content`       | any structural kind (lint error)                                         |
| "this **path** is off limits"                                         | `substring` on `file_path`, `tool: "*"` | a per-tool rule per tool                                                 |
| "these exact bytes, spacing included, appear"                         | `substring`                             | `word`/`argv`, which flex internal whitespace                            |
| "this program, only **as a pipe target** (or source, nested, remote)" | `stage`, inside an `invocation` group   | `command_word` alone, which also fires on the harmless file-operand use  |
| "**too many** pipes/statements at all, whatever runs"                 | `shape` (`"pipes > 1"`)                 | counting `\|` bytes, which quoted data defeats and wrappers double-count |

Two rules of thumb behind the table:

- **A structural kind reads `command` and nothing else.** There is no command
  model behind a file body or a path, so `content` and `file_path` rules are
  necessarily textual — and that is fine, because a file body is text.
- **Ban the program with `command_word`, then qualify it with `flag`/`argv`
  inside an `invocation` group.** That pairing is what makes a rule specific to
  one invocation instead of true of the whole command line; see
  [`invocation`](#invocation-which-stage-each-half-is-about).

#### `tokens` — a contiguous run of whitespace-separated tokens

The pattern's tokens must appear as a contiguous, exactly-equal run anywhere in
the field. Whitespace in the input is normalized; the pattern is not a shell
parser.

```json
{ "kind": "tokens", "value": "git add -A" }
```

| Input                     | Fires? | Why                                                       |
| ------------------------- | ------ | --------------------------------------------------------- |
| `git add -A`              | yes    | exact run                                                 |
| `cd /x && git   add -A .` | yes    | position and spacing do not matter                        |
| `git add -Av`             | no     | `-Av` is a different token (flag folding is not modelled) |
| `git add file-A`          | no     | `file-A` is a different token                             |

**The quoting trap.** Tokenizing splits on whitespace and nothing else, so a
quote glues to the token beside it: in `psql -c "DROP TABLE users"` the tokens
are `psql`, `-c`, `"DROP`, `TABLE`, `users"`, and a `tokens` pattern for
`DROP TABLE` does **not** fire. Use `tokens` for command words that appear
unquoted; use `substring` (below) when the exact bytes are what you mean; and
use [`argv`](#argv--one-argument-quote-stripped-and-resolved) when what you
actually mean is "an argument containing this phrase", which is the case the
trap is really about.

#### `word` — a name with a boundary on both sides

The pattern occurs with a non-name character (or a string edge) immediately
before and after. Name characters are alphanumerics, `_`, `-`, and `.`.

```json
{ "kind": "word", "value": "pkill" }
```

| Input                                         | Fires? | Why                                                                                                |
| --------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------- |
| `bash -lc "pkill -f svc"`                     | yes    | quotes are boundaries — this is the point of `word`                                                |
| `/usr/bin/pkill -f x`                         | yes    | `/` is a boundary                                                                                  |
| `true;pkill x`, `(pkill x)`, `cat f\|pkill x` | yes    | `;`, `(`, `\|` are boundaries                                                                      |
| `K=pkill; $K x`                               | yes    | `=` is a boundary                                                                                  |
| `mypkillx`, `echo pkills`                     | no     | embedded in a longer word                                                                          |
| `cat notes-about-pkill.md`                    | no     | `-` and `.` are **name** characters, so a hyphenated or dotted compound is not an execution vector |

That last row is a deliberate departure from the classic
`(^|[^[:alnum:]_])pat([^[:alnum:]_]|$)` grep, which false-positives on every
filename that mentions the command.

#### `substring` — plain bytes

```json
{ "kind": "substring", "value": "push --force" }
```

No boundaries, no tokenization. Use it for two things: punctuation-bearing
fragments (`<<`, `--force`, `.claude/settings.json`) where the other kinds have
no notion of what you are looking for, and multi-word phrases that will arrive
inside quotes, where `tokens` cannot see them. The cost is that whitespace must
then match exactly — `DROP  TABLE` with two spaces is a different string. That
is the one place `substring` is stricter than `word` and `argv`, which flex
internal whitespace (below); pick `substring` when the exact bytes, spacing
included, are the point.

#### The one wildcard: a trailing `*`

A `tokens` **pattern token**, or a whole `word` value, ending in `*`
prefix-matches. A bare `*` matches nothing at all (an any-token wildcard invites
rules far broader than their author intended, so it is refused and linted).

```json
{ "kind": "tokens", "value": "python* -c*" }
```

Fires on `python -c 'x'`, `python3 -c "y"`, `python3.14 -c 'z'`,
`uv run python -c 'x'`, and `python3 -c'glued'`. Does **not** fire on
`python3 script.py`, `uv run python -m pytest`, or `python3 --version`.

For `word`, a trailing `*` also waives the _right_ boundary — `python*` hits
`python3.14`, and, deliberately loosely, any word starting with `python`. The
reported span still covers only the literal prefix.

---

#### `command_word` — what will actually run, at any depth

Matches the command word of any invocation the parser finds, **basename
normalized** and compared against the **resolved** value. A trailing `*`
prefix-matches, exactly as in `tokens`.

```json
{ "kind": "command_word", "value": "pkill" }
```

| Input                                                                                                           | Fires? | Why                                                      |
| --------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------- |
| `pkill -f svc`                                                                                                  | yes    | written out                                              |
| `bash -lc "cd /srv && pkill -f svc"`                                                                            | yes    | nested program text is re-lexed                          |
| `sudo pkill`, `env A=1 pkill`, `timeout 5 pkill`, `xargs pkill`, `uv run pkill`, `ssh host pkill`, `$(pkill x)` | yes    | every wrapper the lexer models                           |
| `/usr/bin/pkill`, `./pkill`, `\pkill`                                                                           | yes    | normalized to a basename                                 |
| `P=pki; K=ll; $P$K -f svc`                                                                                      | yes    | resolved from the assignments in the same string         |
| `CMD=pkill; $CMD -f svc`                                                                                        | yes    | same                                                     |
| `alias k='pkill -f svc'; k`                                                                                     | yes    | the alias body is re-lexed at the invocation             |
| `stop() { pkill -f svc; }; stop`                                                                                | yes    | so is the function body                                  |
| **`echo pkill is bad`**                                                                                         | **no** | argument position is a _mention_, not an execution       |
| `stop() { pkill -f svc; }` (never called)                                                                       | no     | a body nothing invokes runs nothing                      |
| `$CMD -f svc` (CMD never assigned)                                                                              | no     | nothing in the text says what it is, and nothing guesses |

That "no" on `echo pkill is bad` is the whole point. `word` fires there and
always will; `command_word` is how you ask the narrower question.

#### `argv` — one argument, quote-stripped and resolved

Matches any _argument_ of any invocation. The pattern is matched **inside one
argument's value** with `word` boundaries — so a multi-word phrase that arrived
inside quotes is reachable, and a flag that arrived through a variable is too.

```json
{ "kind": "argv", "value": "DROP TABLE" }
```

| Input                                  | Fires? | Why                                                                                                                    |
| -------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------- |
| `psql -c "DROP TABLE users"`           | yes    | the argument carries the phrase; the quoting trap is gone                                                              |
| `psql -h db -c 'DROP TABLE x CASCADE'` | yes    | position and quote style do not matter                                                                                 |
| `psql -c "DROP  TABLE users"`          | yes    | one space in the pattern matches a whitespace run of any length; the span underlines the bytes as typed                |
| `psql -c "DROP MY TABLE users"`        | no     | flexible spacing, not a flexible phrase                                                                                |
| `X=-rf; rm $X /` with value `-rf`      | yes    | resolved; the span underlines `$X`                                                                                     |
| `rm --recursive-force /` with `-rf`    | no     | word boundaries, the same ones `word` uses                                                                             |
| `rm -vrf /etc` with value `-rf`        | no     | word boundaries know nothing about flag clustering — that is what [`flag`](#flag--one-option-read-as-an-option) is for |

#### `command_line` — the whole invocation, reconstructed

The command word plus its resolved arguments, joined and matched with `tokens`
semantics **anchored at the command word**. Quoting and wrapper noise are gone
before the comparison.

```json
{ "kind": "command_line", "value": "git add -A" }
```

| Input                                                  | Fires? | Why                                           |
| ------------------------------------------------------ | ------ | --------------------------------------------- |
| `git add -A`, `sudo git add -A`, `/usr/bin/git add -A` | yes    | one invocation, matched from its command word |
| `bash -lc 'cd /repo && git add -A && git commit'`      | yes    | the nested stage is its own invocation        |
| `F=-A; git add $F`                                     | yes    | arguments are resolved first                  |
| **`echo git add -A`**                                  | **no** | anchored: the phrase is an argument here      |
| `git add; true -A`                                     | no     | a run must be inside ONE invocation           |

Anchoring is what separates this from `tokens`. Use `argv` to ask about an
argument and `tokens` to ask about the raw text.

#### `flag` — one option, read as an option

`argv` matches with word boundaries **inside one argument**, which is exactly
wrong for options: `rm -vrf /etc/nginx` carries `-r` and `-f`, and no `argv`
pattern short of enumerating every cluster finds them. `flag` reads the
argument as options instead.

```json
{ "kind": "flag", "value": "r" }
```

| `value`       | Means                                  | Matches                     | Does not match             |
| ------------- | -------------------------------------- | --------------------------- | -------------------------- |
| `"f"`, `"-f"` | the short option `-f`                  | `-f`, `-vrf`, `-rf`, `-f=x` | `--force`, `-vr`, `file`   |
| `"rf"`        | short `-r` **and** `-f`, in one bundle | `-rf`, `-vfr`               | `-r` alone, `-r -f`        |
| `"--force"`   | the long option                        | `--force`, `--force=yes`    | `--force-with-lease`, `-f` |

- **Case is identity.** `-r` and `-R` are different options on every tool that
  has both, so `flag` never folds case and `ignore_case` on it is a lint error.
- **A cluster value wants every letter in one argument.** `"rf"` hits `-rf`,
  but `rm -r -f` splits them across two arguments. That is what
  [`flags`](#flags--the-whole-option-set-however-it-was-spelled) is for; reach
  for `flag` only when you mean one option in one bundle.
- **The long boundary is a carve-out.** Because `--force` does not match
  `--force-with-lease`, a force-push rule needs no `match_none` for the safe
  spelling — which is one enumeration hack the shipped cookbook recipe no
  longer carries.
- **Scope it.** `-f` means _force_ to `rm`, _file_ to `tar`, and _follow_ to
  `tail`; and a tool that uses single-dash **long** options (`find -name`,
  `java -version`) reads as a bundle carrying every letter in it. So a short
  `flag` belongs inside an [`invocation` group](#invocation-which-stage-each-half-is-about)
  naming the command word, and `selftest` warns when one is not.

#### `flags` — the whole option set, however it was spelled

`flag` asks about one option in one argument. That leaves you enumerating what
POSIX lets a person type: `rm -rf`, `-fr`, `-vrf`, `-r -f`, `-Rf`,
`--recursive --force` are **six patterns for one policy**, and the seventh
spelling walks past all six. `flags` asks about the invocation's option **set**,
which all of those share.

```json
{ "kind": "flags", "value": "r|R|--recursive f|--force" }
```

The value is a list of **entries** separated by spaces or commas; every entry
must be satisfied. An entry is a list of **alternatives** separated by `|`; any
one satisfies it. Each alternative is spelled exactly as `flag` spells it.

| `value`               | Reads as                             | Fires on                                  | Does not fire on           |
| --------------------- | ------------------------------------ | ----------------------------------------- | -------------------------- |
| `"r f"`               | `r` and `f`                          | `-rf`, `-fr`, `-vrf`, `-r -f`, `-r -v -f` | `-r`, `-f`, `-rF`          |
| `"rf"`                | same — a multi-letter entry is a set | `-rf`, `-r -f`                            | `-r`, `-f`                 |
| `"r\|R\|--recursive"` | any spelling of recursion            | `-r`, `-R`, `-vR`, `--recursive`          | `-f`, `--recurse`          |
| `"--force"`           | the long option only                 | `--force`, `--force=yes`                  | `-f`, `--force-with-lease` |

- **The set spans the whole invocation.** `"rf"` is satisfied by `rm -r -f`,
  which `flag "rf"` (one bundle) is not. That difference is the point.
- **Case is identity**, as with `flag`: `ignore_case` on it is a lint error.
- **A bare `-` is an argument and a bare `--` ends the options.** `python -`
  reads a program on stdin; nothing after `rm -- -rf` is an option.
- **The set is built from the RESOLVED values**, so `X=-rf; rm $X /` carries
  `r` and `f` even though the `rm` invocation's own text carries neither.
  `check --explain` prints the set it computed.
- **Scope it**, for the same reason `flag` needs scoping — and `selftest` warns
  the same way when a short entry sits outside an `invocation` group.

#### `path_class` — a normalized path, not a spelling

`{"kind":"argv","value":"/etc*"}` is a guess about how somebody will write a
path, and `rm -rf ~/../`, `rm -rf /usr/local/../..`, `rm -rf $HOME/` and
`rm -rf /Users/me/..` all walk past a list of them. `path_class` asks whether an
argument, **after normalization**, is in one of the engine's path classes.

```json
{ "kind": "path_class", "value": "home_or_root" }
```

| Class               | Members                                                                                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `home_or_root`      | home at any depth, `/` itself, or anything under a system top-level directory — but **never** a relative path and never scratch space (`/tmp`, `/var/folders`, `/private/tmp`) |
| `filesystem_anchor` | `/` itself, one system top-level directory, or the home directory itself — never anything below them                                                                           |

Normalization is **textual and touches no filesystem** — no `stat`, no
`realpath`, no reading `$HOME`. A gate that consulted the disk would decide
differently from one minute to the next. So:

- `~` and a resolvable `$HOME`/`${HOME}` become a _root marker_, not a value.
  The gate never needs to know which home directory it is — only that `~/..` is
  above it and therefore a system directory, whatever it turns out to be.
- `.` and `..` collapse (`/usr/local/../..` → `/`, and `/..` is `/`), redundant
  and trailing slashes are stripped (a trailing one is remembered), and globs
  are noted.
- A path rooted at a variable this reader **cannot** read — `$TMPDIR/x` — is a
  relative path here, because the text does not say where it goes and nothing
  may pretend it does.
- An **option word** is never read as a path, so `-rf` cannot be an anchor. The
  value of a value-taking option is (`tar -C /` really does name `/`).

`claude-hooker-gate classes` prints both classes with every canonical spelling.

Putting the two new kinds together, the whole rm-rf rule is three matchers:

```json
"match_all": [
  { "invocation": [
    { "kind": "command_word", "value": "rm" },
    { "kind": "flags", "value": "r|R|--recursive" },
    { "kind": "path_class", "value": "home_or_root" } ] }
]
```

That denies `rm -vrf /etc/nginx`, `rm -Rf ~`, `rm -rf ~/../`,
`rm -rf /usr/local/../..` and `D=/; rm -rf "$D"` — clustered, reordered,
capitalized differently, written round the houses, and assembled at run time —
and leaves `tar -xzf archive.tgz` (an `f`, but not `rm`'s),
`rm -rf ./build && ls /etc` (recursion here, system path there) and
`rm -rf /tmp/scratch-1` alone. The shipped
[recipe 7](RULES_COOKBOOK.md#7-no-rm-rf-home-or-root) is this rule plus a
`--no-preserve-root` carve-in.

### `sets` and classes: naming a list instead of repeating it

Two kinds of reference may appear **as a whole matcher value**. Both are resolved
once, when the file is parsed, into the `any` group they replace — so evaluation,
the lint, `check`'s underline and the decision log all behave exactly as if you
had typed the group out.

| Reference               | Comes from                                                                          | Unknown name               |
| ----------------------- | ----------------------------------------------------------------------------------- | -------------------------- |
| `"$class:db_clients"`   | the **engine**, versioned with the binary; `claude-hooker-gate classes` prints them | hard parse error (exit 65) |
| `"$protected_branches"` | the **rule file**'s own `sets` block                                                | hard parse error (exit 65) |

```json
{
  "sets": {
    "protected_branches": ["main", "master", "trunk", "release", "production"]
  },
  "rules": [
    {
      "name": "ask-force-push-protected-branch",
      "decision": "ask",
      "reason": "…",
      "match_all": [
        {
          "invocation": [
            { "kind": "command_word", "value": "git" },
            { "kind": "argv", "value": "push" },
            { "kind": "flags", "value": "f|--force" },
            { "kind": "argv", "value": "$protected_branches" }
          ]
        }
      ]
    }
  ]
}
```

Rules of the road:

- **Set names are lowercase** (`[a-z][a-z0-9_]*`). That is not style: it is what
  makes `{"kind":"argv","value":"$HOME"}` a literal `$HOME` — a value a path
  matcher genuinely carries — rather than a reference to a set nobody declared.
  A name outside that shape is a parse error, because nothing could reference it.
- **An unknown reference is fatal, not inert.** A matcher compared against a
  literal `"$brnaches"` would match nothing and read like protection. Fatal means
  fatal: the whole file fails to parse, so — exactly as with a JSON syntax error
  — `selftest` and `check` exit **65**, and the hook itself fails open for that
  call with a note on stderr. That is the cost of refusing to ship a silent hole,
  and the reason the installer runs `selftest` over the embedded defaults before
  it will install anything.
- **A set member may not be a reference.** Self-reference and recursion are
  rejected outright rather than bounded — a set is a list of values.
- **An empty set is a parse error**; an `any` over nothing is never satisfied, so
  every rule referencing it would silently stop firing.
- A **path** class may not be referenced with `$class:` — its membership is
  decided by normalizing, not by comparing, so the member list is not the test.
  Use `kind: "path_class"`, which is a parse error to get wrong.
- The lint warns about a set **nothing references** (dead policy) and a set with
  a **single member** (an indirection with nothing behind it).

The trade is explicit: naming a class means the rule inherits whatever **this
version of the binary** thinks the members are. That is why `classes` exists and
why its output is printable, diffable, and pasteable into a review.

#### `ignore_case` — opt-in case folding

Any matcher may carry `"ignore_case": true`. It defaults to **false**, and that
default is load-bearing: a command word is a filename, `PSQL` is not `psql`,
and folding by default would silently widen every command rule in the file.

| Kind                                                  | Honors `ignore_case`?                         |
| ----------------------------------------------------- | --------------------------------------------- |
| `tokens`, `word`, `substring`, `argv`, `command_line` | yes                                           |
| `command_word`                                        | no — a program name is a filename             |
| `flag`, `flags`                                       | no — `-r` is not `-R`                         |
| `path_class`                                          | no — a class name, and paths are case-bearing |
| `signal`                                              | no — a closed vocabulary, not text            |

Setting it on one of the three that cannot honor it is a **lint error**, not a
silent no-op. So a destructive-SQL rule folds the _statement_ and not the
_client_:

```json
{
  "invocation": [
    { "kind": "command_word", "value": "psql" },
    { "kind": "argv", "value": "DROP TABLE", "ignore_case": true }
  ]
}
```

`Drop Table users` and `drop TABLE users` both fire; `PSQL -c "DROP TABLE
users"` does not, which is the control that proves the command word half never
folded.

#### `signal` — what the parser noticed but could not resolve

Matches a named flag of the parse/resolve report. The vocabulary is closed; a
name outside it is a **lint error**, never a rule that silently never fires.

```json
{ "kind": "signal", "value": "opaque_command" }
```

| `value`                     | Set when                                                                                                                                                                                        |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eval_present`              | `eval` appears as a command word                                                                                                                                                                |
| `command_substitution`      | `$(...)` or backticks appear anywhere                                                                                                                                                           |
| `pipe_into_shell`           | something is piped into a shell (`curl … \| bash`) — read through the privilege/env wrappers, so `\| sudo bash`, `\| env bash` and `\| xargs bash -c` all count, while `\| sudo tee f` does not |
| `decode_into_shell`         | a decoder (`base64`, `xxd`, …) feeds a shell in the same pipeline, unwrapped the same way                                                                                                       |
| `heredoc_present`           | a `<<` / `<<-` heredoc redirect appears                                                                                                                                                         |
| `herestring_present`        | a `<<<` here-string redirect appears                                                                                                                                                            |
| `unterminated_quote`        | a quote ran to the end of the text                                                                                                                                                              |
| `expansion_command_word`    | some command word is exactly one expansion (`$CMD -f x`)                                                                                                                                        |
| `concatenated_command_word` | some command word is assembled from pieces (`$P$K -f x`)                                                                                                                                        |
| `unresolved_command_word`   | a command word is indirect and **nothing in the text says what it is**                                                                                                                          |
| `substitution_derived`      | some word's value comes from a command or process substitution                                                                                                                                  |
| `opaque_command`            | the union that means _something will run that this reader could not name_: `unresolved_command_word`, `eval_present`, `decode_into_shell`, or nesting past the depth cap                        |

`opaque_command` deliberately excludes the two raw expansion signals.
`P=pki; K=ll; $P$K` is written indirectly and is nonetheless perfectly
readable; calling it opaque would be a lie, and a signal that cries wolf is one
an operator learns to ignore.

A `signal` hit underlines the evidence where there is one (the `eval` word, the
unresolvable command word, the shell on the receiving end of the pipe, the
heredoc operator) and the whole command where there is not.

`heredoc_present` exists so a heredoc rule can be fully structural. The textual
alternative, `{"kind":"substring","value":"<<"}`, also fires on a left-shift
inside a quoted argument (`python -c 'print(1 << 3)'`) and on a `<<` in a
grep pattern; the signal reads the parse, so only a real redirect counts.
Heredoc _bodies_ are still exposed but not lexed — a heredoc fed to `python3`
is Python, not shell.

#### `stage` — one invocation's context

Matches one fact about an invocation's **position** — how it sits in the
command — where every other structural kind matches its content. The
vocabulary is closed (a name outside it is a lint error, like `signal`'s):

| Value         | Satisfied by an invocation that…                                            |
| ------------- | --------------------------------------------------------------------------- |
| `pipe_target` | reads from a pipe (`cat f \| head` — the `head` stage)                      |
| `pipe_source` | feeds a pipe (`curl url \| sh` — the `curl` stage)                          |
| `nested`      | was written inside nested program text (`bash -c "..."`, `$(...)`, `(...)`) |
| `remote`      | runs on another host, reached through `ssh`                                 |

Designed to sit **inside an `invocation` group** beside the content kinds, so
"head, _as a pipe target_" is one binding on one stage:

```json
{
  "invocation": [
    { "kind": "command_word", "value": "head" },
    { "kind": "stage", "value": "pipe_target" }
  ]
}
```

| Input                         | Fires? | Why                                            |
| ----------------------------- | ------ | ---------------------------------------------- |
| `cat error.log \| head`       | yes    | head reads from a pipe                         |
| `cat f \| sudo head -5`       | yes    | the wrapper inherits the pipeline context      |
| `bash -lc 'cat x \| head -3'` | yes    | a nested stage is an invocation like any other |
| `head -20 error.log`          | no     | a file operand — no pipe                       |
| `echo head \| cat`            | no     | a mention in argument position                 |
| `cat f \| grep head`          | no     | a pipe whose target is someone else            |

Unscoped, a `stage` matcher is existential — "some invocation is a pipe
target" — exactly parallel to an unscoped `command_word`. See
[recipe 21](RULES_COOKBOOK.md#21-no-pipe-to-pager).

#### `shape` — counted structure of the whole command

Compares a **count** of the parsed structure against a threshold. The value is
a three-token comparison — `<metric> <op> <n>`, operators `<` `<=` `==` `>=`
`>` — and anything else is a lint error:

```json
{ "kind": "shape", "value": "pipes > 1" }
{ "kind": "shape", "value": "statements > 1" }
```

| Metric       | Counts                                             |
| ------------ | -------------------------------------------------- |
| `pipes`      | `\|` and `\|&` joins                               |
| `statements` | `;`, `&` and newline joins — sequential statements |
| `chains`     | `&&` and `\|\|` joins — conditional chaining       |
| `stages`     | invocations that name a program                    |
| `redirects`  | redirections of every kind                         |
| `heredocs`   | `<<` / `<<-` heredocs and `<<<` here-strings       |
| `depth`      | the deepest nesting level any command was found at |

The counts read the **parse**, never the bytes: `echo 'a; b; c'` counts zero
statements (data, not structure), `bash -c 'a | b | c'` counts two pipes (a
wrapper does not launder a pipeline), and `cat f | sudo head` counts **one**
pipe — `sudo head` is the same join seen through a wrapper, not a second one.
Like `signal`, `shape` describes the whole parse, so an `invocation` group
does not narrow it (and the lint warns if one tries). When a lexer cap is hit,
every count is a floor: `>` and `>=` still conclude, while `<`, `<=` and `==`
refuse to fire rather than under-count their way to a wrong answer. `check
--explain` prints a `shape :` line with every metric, which is how you find
the number to compare against. See
[recipe 22](RULES_COOKBOOK.md#22-watch-long-pipelines).

#### Structural kinds read `command`, and only `command`

There is no command model behind a file body or a path. A structural matcher —
`command_word`, `argv`, `command_line`, `flag`, `flags`, `path_class`,
`signal`, `stage`, `shape` — with `"field": "content"` or
`"field": "file_path"` can never match, so `selftest` reports it as a
**lint error** rather than leaving a rule that reads like protection and
provides none.

### Fields

A matcher names which part of the payload it reads. Each field is tokenized
lazily and at most once per evaluation, no matter how many matchers read it —
and the command is parsed and resolved lazily and at most once per evaluation,
shared by every structural matcher in every rule and **both overlay layers**.

There are eight, deliberately, rather than one name per payload key across
thirty events: a rule says what **kind** of text it is reading, and the
[per-event table](#the-per-event-reference) says which key of which event
supplies it. `word` on `prompt` then means the same thing whatever produced the
prompt, and `command_word` on `command` reads a shell command whether the call
is being proposed or has already run.

| `field`     | Populated from                                                                                                                                 | Structural kinds |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `command`   | `tool_input.command` — a shell command string                                                                                                  | yes              |
| `content`   | Write's `content`, **and Edit's `new_string`** (folded together); a `ConfigChange`'s `changed_keys`                                            | no (lint error)  |
| `file_path` | The target path of a file-writing tool; a watched file; a new working directory                                                                | no (lint error)  |
| `prompt`    | A user prompt (`prompt_text`)                                                                                                                  | no (lint error)  |
| `output`    | A tool's result — its output on success, its error text on failure                                                                             | no (lint error)  |
| `message`   | Prose the harness produced: an assistant message, a notification body, a task description                                                      | no (lint error)  |
| `trigger`   | The event's own discriminator — a session `source`, a compaction `trigger`, a notification type, a config source, a stop reason, a change type | no (lint error)  |
| `agent`     | Who: a subagent type, or an MCP server name                                                                                                    | no (lint error)  |

Folding `new_string` into `content` is what lets one rule cover both Write and
Edit without knowing which tool produced the bytes.

Two lint errors are worth stating outright, because both are rules that read
like protection and provide none:

- **A structural kind on any field but `command`.** `command_word`, `argv`,
  `command_line`, `flag`, `flags`, `path_class` and `signal` parse a **shell
  command**. There is no command behind a file body, a path, a prompt, a tool
  result or a notification type, so a structural matcher there can never match.
  `{"kind": "command_word", "field": "prompt", "value": "rm"}` looks entirely
  reasonable and is a shell parser pointed at English; use `word`, `substring`
  or `tokens` on those fields.
- **A field the rule's event does not carry.** `{"event": "Stop", "field":
"command"}` is a `Stop` payload asked for a command it has never had. Which
  event supplies which field is a table lookup, so this is mechanical.

### Decisions

| `decision` | Effect                                                            | Exit of `check` | Appears in the log as |
| ---------- | ----------------------------------------------------------------- | --------------- | --------------------- |
| `deny`     | Refused; the reason is shown.                                     | 1               | `deny`                |
| `ask`      | Downgraded to a confirmation prompt. **`PreToolUse` only.**       | 2               | `ask`                 |
| `allow`    | Skips the permission **prompt**. Does _not_ override a deny rule. | 0               | `allow`               |
| `log`      | Nothing. Recorded only — _shadow mode_. Valid on **every** event. | 0               | `log`                 |

**Which of these an event can express is a property of that event's response
envelope, not a preference.** There is no shared "decision" field in the hooks
protocol: `PreToolUse` answers with `permissionDecision` (the only three-way
vocabulary), `PermissionRequest` with `decision.behavior` (allow/deny — there is
no "ask" at a checkpoint that already is one), `Stop` and its family with a
top-level `decision: "block"` (deny only), and thirteen events with nothing that
can change anything at all. A decision the envelope has no field for is a
**selftest ERROR**, not a rule with an unfortunate outcome — see
[hook events](#hook-events). `log` is always valid, because a shadow rule emits
nothing.

A worked example of each, in the shape the shipped rule files actually use — a
structural matcher for anything about a command, a textual one only where there
is no command to read:

```json
{
  "name": "no-rm-rf-root",
  "decision": "deny",
  "reason": "A recursive delete rooted at / takes out files no part of this task owns, and there is no undo. Delete the directory you created: `rm -rf ./build`.",
  "match_all": [
    {
      "invocation": [
        { "kind": "command_word", "value": "rm" },
        { "kind": "flag", "value": "r" },
        { "kind": "argv", "value": "/" }
      ]
    }
  ]
}
```

```json
{
  "name": "ask-sudo",
  "decision": "ask",
  "reason": "Anything under sudo escapes this project and changes the machine, where nothing here can roll it back. If a tool is missing, install it into the project: `uv add <package>`.",
  "match": [{ "kind": "command_word", "value": "sudo" }],
  "match_none": [{ "kind": "command_line", "value": "sudo -n true" }]
}
```

```json
{
  "name": "allow-repo-clean-scratch",
  "decision": "allow",
  "reason": "Pre-approved: this repository's scratch cleanup is bounded to a directory the build owns.",
  "match": [{ "kind": "command_line", "value": "make clean-scratch" }]
}
```

```json
{
  "name": "watch-destructive-sql",
  "tool": "*",
  "decision": "log",
  "reason": "Observational only — this call is NOT blocked. Recorded so the operator can see whether these are migrations or something else before deciding whether to promote this rule to deny.",
  "match": [{ "kind": "substring", "field": "content", "value": "DROP TABLE" }]
}
```

#### What `allow` actually does — and does not

`allow` is the one decision whose name oversells it, so read this before using
it. **A hook can only ever tighten permissions, never loosen them.**

- A `deny` rule in `settings.json` `permissions` **always wins** over a hook's
  `allow`. The harness consults its own permission rules regardless of what a
  hook said, so `allow` cannot grant access to anything the operator's settings
  forbid. It is not an override, an escalation, or a bypass.
- What it does do is skip the interactive permission **prompt** for a call that
  would otherwise have raised one. That is genuinely useful — a repository
  pre-approving its own bounded operations — and genuinely narrow.
- The `bypassPermissions` mode is the mirror image: a `PreToolUse` **deny** holds
  even there. Refusals are the direction hooks are authoritative in.

Two warnings then follow from _first match wins_:

- **An `allow` rule placed above a `deny` rule in this file silently defeats
  it.** Not the harness's deny rules — this file's. Keep an allow's matchers
  pinned to an exact command shape, and prefer adding a `match_none` carve-out to
  the deny rule over writing a broad allow. `selftest` warns on every `allow`
  rule for this reason.
- **`log` never stops evaluation.** A matching `log` rule is recorded and the
  walk continues, so a shadow rule can sit anywhere in the file — including
  after the rule that enforces — without changing any decision.

### `tests` — the rule file asserts things about itself

```json
"tests": [
  { "command": "git add -A", "expect": "deny", "expect_rule": "no-git-add-all" },
  { "command": "git add src/main.zig", "expect": "none" },
  {
    "input": { "tool": "Write", "file_path": "/h/.claude/settings.json", "content": "{}" },
    "expect": "deny",
    "expect_rule": "protect-hook-config"
  }
]
```

| Field         | Type   | Meaning                                                                      |
| ------------- | ------ | ---------------------------------------------------------------------------- |
| `command`     | string | Shorthand: tool `Bash`, only this command, every other field empty.          |
| `input`       | object | Full form: `{tool, command, content, file_path}`, each defaulting to empty.  |
| `generate`    | object | A cross product to expand instead of one literal case — see below.           |
| `expect`      | enum   | `deny` \| `ask` \| `allow` \| `none`, where `none` means _no rule enforces_. |
| `expect_rule` | string | Optional. The `name` that must have produced the decision.                   |

Cases run against the **whole file**, first-match-wins, exactly as the hook
would — so a case also proves that no earlier rule steals the input. They are
run with no disabled set, so an operator's temporary `CLAUDE_HOOK_DISABLE`
cannot turn a red suite green.

A shadow (`log`) rule's cases assert `"expect": "none"` — that _is_ the
assertion that it does not block. To confirm a shadow rule actually fires, use
`check`, which prints shadow hits explicitly.

#### `generate` — the cross product, and the near misses

Killing enumeration in a rule only moves the risk. A `flags` matcher and a
`path_class` cover spellings no test names, and the next person to touch either
one has no way to know which spellings mattered. So a rule that stopped
enumerating declares the product instead:

```json
{
  "generate": {
    "command": "rm {flags} {target}",
    "axes": [
      {
        "name": "flags",
        "values": ["-rf", "-fr", "-vrf", "-r -f", "-Rf", "--recursive --force"]
      },
      { "name": "target", "values": ["$class:home_or_root"] }
    ],
    "near_miss": [
      { "name": "flags", "values": ["-f", "-i"] },
      { "name": "target", "values": ["./build", "/tmp/scratch"] }
    ]
  },
  "expect": "deny",
  "expect_rule": "no-rm-rf-home-or-root"
}
```

| Field       | Type   | Meaning                                                                                                 |
| ----------- | ------ | ------------------------------------------------------------------------------------------------------- |
| `command`   | string | The command text, with one `{axis}` placeholder per axis.                                               |
| `axes`      | array  | `{name, values}`. Every **combination** of the values must produce the declared decision.               |
| `near_miss` | array  | `{name, values}` naming an axis. Substituting one of these **for that axis alone** must produce `none`. |

- Axis values may be [references](#sets-and-classes-naming-a-list-instead-of-repeating-it):
  `"$class:home_or_root"` expands to the class's canonical spellings,
  `"$protected_branches"` to the file's own set. A **path** class _is_
  expandable here, unlike in a matcher value — the member list is exactly what a
  generator wants, and it comes from the engine, so a normalization change shows
  up as a test change instead of a silent policy change.
- **One axis changed at a time** is what makes a negative a _near miss_ rather
  than an unrelated command: it proves the rule reads the axis it claims to
  read. A generator over positives alone would be passed by a rule that matches
  everything, so `selftest` **warns** when a `generate` block declares no
  `near_miss`.
- Every expansion is reported as its **own** PASS/FAIL line, tagged with the
  declaration it came from, and the counts are reported separately from the
  literal cases.
- Generators are **not** a replacement for literal cases. A literal case pins a
  specific past mistake — a spelling that once escaped, a false positive that
  was once fixed — and a generator must never quietly absorb one: the product
  covers a space, the literal names an event. The shipped files carry both, and
  the lint refuses a case that declares `generate` **and** a literal input.

### `logging`

| Field          | Type         | Default    | Meaning                                                                                                    |
| -------------- | ------------ | ---------- | ---------------------------------------------------------------------------------------------------------- |
| `enabled`      | bool         | `true`     | Master switch. Off means not one line is written.                                                          |
| `log_commands` | bool         | `false`    | Include the **full** matched field text. Off by default: commands and file bodies routinely carry secrets. |
| `path`         | string\|null | `null`     | Where to write. Null means `~/.claude/hook-gate-log.jsonl`. `CLAUDE_HOOK_LOG_PATH` outranks both.          |
| `max_bytes`    | integer      | `10485760` | Rotate above this size (10 MiB). `0` disables rotation.                                                    |

### Limits

Everything is bounded, and every bound is visible rather than silent.

| Limit                      | Value  | What happens at the edge                                            |
| -------------------------- | ------ | ------------------------------------------------------------------- |
| Rule file size             | 1 MiB  | Refused to load (`check`/`selftest` exit 65/66; the hook exits 1).  |
| Group nesting depth        | 4      | Lint error; evaluation treats the over-deep group as unsatisfied.   |
| Tokens per field           | 512    | Later tokens are not tokenized for `tokens` matching.               |
| Simultaneous shadow hits   | 16     | Extras dropped; an `_overflow` line is written.                     |
| Simultaneous bypassed hits | 16     | Extras dropped; an `_overflow` line is written.                     |
| Logged field text          | 4 KiB  | Truncated on a UTF-8 boundary with a marker naming the full length. |
| Log read by `stats`        | 64 MiB | Refused; that is a retention problem, not a reporting one.          |

The lexer and the resolution pass carry their own caps, every one of which
raises a signal rather than truncating silently — see
[the caps](#the-caps-and-what-hitting-one-means).

---

## Hook events

Claude Code fires **30** hook events, and almost nothing about them generalizes.
That is the single most important fact about writing rules for anything other
than a tool call, so it is stated plainly before the table:

- **There is no shared "decision" field.** `PreToolUse` answers with
  `hookSpecificOutput.permissionDecision`; `PermissionRequest` with
  `hookSpecificOutput.decision.behavior`; `Stop`, `UserPromptSubmit`,
  `PostToolUse`, `PostToolBatch`, `PreCompact` and `ConfigChange` with a
  top-level `decision: "block"`; the task/teammate events with `continue: false`;
  an MCP elicitation with an `action`; `MessageDisplay` with a display-only
  `displayContent`; and `WorktreeCreate` with nothing but its exit code.
- **Thirteen events cannot refuse anything.** Whatever they emit, the operation
  proceeds. A `deny`/`ask`/`allow` rule scoped to one of them is a **selftest
  ERROR** — a config bug that would otherwise be a perfectly silent no-op.
- **Matchers mean different things.** A tool event's matcher is a regex over tool
  names; a session or compaction event's is one of a closed set of exact strings;
  `FileChanged`'s is a list of literal filenames and is **never** a regex; a
  third of the events take no matcher at all.
- **`PostToolUse` and `PostToolUseFailure` cannot prevent anything** — the tool
  has already run. They can still answer `decision: "block"`, which is feedback
  to the model rather than prevention, which is why the table calls it that.

Every one of those facts lives in **one descriptor table** in `src/events.zig`.
Dispatch, the payload parse, the response writer, the config lint, the installer
and this documentation all read that table, so adding an event — or correcting a
fact about one — is a row rather than a new code path.

### The per-event reference

Generated from the descriptor table by `claude-hooker-gate events --markdown` and
compared **cell for cell** against this table by `./hookctl audit` (column
alignment is the formatter's; every fact is the binary's). `⚠` marks a
row that is partly inference because the upstream documentation is thin; a rule
scoped to one of those is a lint **warning**. `←` reads "is populated from".

<!-- hookctl:events -->

| Event                 | When it fires                                                     | Refusal                                 | Decisions             | Matcher        | Payload fields                                                                                                                                         |
| --------------------- | ----------------------------------------------------------------- | --------------------------------------- | --------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SessionStart`        | after session init, before the first turn                         | — advisory                              | log                   | exact_string   | `trigger` ← `source`                                                                                                                                   |
| `Setup`               | on --init-only / --init / --maintenance in -p mode                | — advisory                              | log                   | exact_string   | `trigger` ← `source`                                                                                                                                   |
| `UserPromptSubmit`    | after the user submits a prompt, before the model sees it         | `decision: "block"`                     | deny, log             | none           | `prompt` ← `prompt_text`                                                                                                                               |
| `UserPromptExpansion` | when a slash command expands into a prompt                        | `decision: "block"`                     | deny, log             | command_name   | `prompt` ← `prompt_text`, `trigger` ← `command_name`                                                                                                   |
| `PreToolUse`          | before a tool call executes                                       | `hookSpecificOutput.permissionDecision` | deny, ask, allow, log | tool_name      | `command` ← `tool_input.command`, `content` ← `tool_input.content or .new_string`, `file_path` ← `tool_input.file_path`                                |
| `PostToolUse`         | after a tool call succeeds                                        | `decision: "block"` (feedback only)     | deny, log             | tool_name      | `command` ← `tool_input.command`, `content` ← `tool_input.content or .new_string`, `file_path` ← `tool_input.file_path`, `output` ← `tool_output`      |
| `PostToolUseFailure`  | after a tool call fails                                           | `decision: "block"` (feedback only)     | deny, log             | tool_name      | `command` ← `tool_input.command`, `content` ← `tool_input.content or .new_string`, `file_path` ← `tool_input.file_path`, `output` ← `error`            |
| `PostToolBatch`       | after a batch of parallel tool calls, before the next model call  | `decision: "block"`                     | deny, log             | none           | —                                                                                                                                                      |
| `PermissionRequest`   | when a tool call reaches a permission checkpoint                  | `hookSpecificOutput.decision.behavior`  | deny, allow, log      | tool_name      | `command` ← `tool_input.command`, `content` ← `tool_input.content or .new_string`, `file_path` ← `tool_input.file_path`, `trigger` ← `permission_rule` |
| `PermissionDenied`    | after an automatic denial (the hook may ask for a retry)          | — advisory                              | log                   | tool_name      | `command` ← `tool_input.command`, `content` ← `tool_input.content or .new_string`, `file_path` ← `tool_input.file_path`                                |
| `Stop`                | when the model finishes responding                                | `decision: "block"`                     | deny, log             | none           | `message` ← `last_assistant_message`, `trigger` ← `stop_reason`                                                                                        |
| `SubagentStop`        | when a subagent finishes                                          | `decision: "block"`                     | deny, log             | agent_type     | `message` ← `last_assistant_message`, `trigger` ← `stop_reason`, `agent` ← `agent_type`                                                                |
| `StopFailure`         | when a turn ends because of an API error (output ignored)         | — advisory                              | log                   | exact_string   | `trigger` ← `error_type`                                                                                                                               |
| `SubagentStart`       | when a subagent is spawned                                        | — advisory                              | log                   | agent_type     | `agent` ← `agent_type`                                                                                                                                 |
| `TeammateIdle` ⚠     | when an agent-team teammate is about to go idle (UNVERIFIED)      | `continue: false`                       | deny, log             | none           | `agent` ← `agent_type`                                                                                                                                 |
| `TaskCreated` ⚠      | when a task is created via the TaskCreate tool (UNVERIFIED)       | `continue: false`                       | deny, log             | none           | `message` ← `description`, `agent` ← `agent_type`                                                                                                      |
| `TaskCompleted` ⚠    | when a task is marked completed (UNVERIFIED)                      | `continue: false`                       | deny, log             | none           | `message` ← `description`, `agent` ← `agent_type`                                                                                                      |
| `Notification`        | when Claude Code raises a notification                            | — advisory                              | log                   | exact_string   | `trigger` ← `notification_type`, `message` ← `message`                                                                                                 |
| `MessageDisplay`      | while an assistant message is displayed (screen only)             | — advisory                              | log                   | none           | `message` ← `message_text`                                                                                                                             |
| `ConfigChange`        | when a settings or skills file changes mid-session                | `decision: "block"`                     | deny, log             | exact_string   | `trigger` ← `config_source`, `content` ← `changed_keys`                                                                                                |
| `CwdChanged`          | when the working directory changes                                | — advisory                              | log                   | none           | `file_path` ← `new_cwd`                                                                                                                                |
| `FileChanged`         | when a watched file changes on disk                               | — advisory                              | log                   | exact_filename | `file_path` ← `file_path`, `trigger` ← `change_type`                                                                                                   |
| `WorktreeCreate`      | while a worktree is being created                                 | `any nonzero exit`                      | deny, log             | none           | `trigger` ← `reason`                                                                                                                                   |
| `WorktreeRemove`      | when a worktree is removed at session exit or subagent finish     | — advisory                              | log                   | none           | `trigger` ← `reason`                                                                                                                                   |
| `PreCompact`          | before context compaction                                         | `decision: "block"`                     | deny, log             | exact_string   | `trigger` ← `trigger`                                                                                                                                  |
| `PostCompact`         | after compaction completes                                        | — advisory                              | log                   | exact_string   | `trigger` ← `trigger`                                                                                                                                  |
| `Elicitation`         | when an MCP server asks the user for input mid-tool-call          | `hookSpecificOutput.action`             | deny, log             | mcp_server     | `agent` ← `server_name`                                                                                                                                |
| `ElicitationResult`   | after the user answers an MCP elicitation, before the server does | `hookSpecificOutput.action`             | deny, log             | mcp_server     | `agent` ← `server_name`                                                                                                                                |
| `InstructionsLoaded`  | when CLAUDE.md or a .claude/rules file is loaded                  | — advisory                              | log                   | exact_string   | `trigger` ← `reason`                                                                                                                                   |
| `SessionEnd` ⚠       | when the session terminates (payload UNVERIFIED)                  | — advisory                              | log                   | exact_string   | `trigger` ← `reason`                                                                                                                                   |

`claude-hooker-gate events [NAME]` prints the same catalog in prose, including the
context and rewrite fields this gate deliberately does not write.

### Advisory-only events: the thirteen that cannot block

`SessionStart`, `Setup`, `Notification`, `StopFailure`, `MessageDisplay`,
`SubagentStart`, `PermissionDenied`, `CwdChanged`, `FileChanged`,
`WorktreeRemove`, `PostCompact`, `InstructionsLoaded`, `SessionEnd`.

Use `"decision": "log"` on these. Observing an event that cannot refuse anything
is the main thing an advisory event is good for — the shipped
`observe-session-start` rule is exactly that, and it exists so that an empty
decision log means "the gate was wired and had nothing to object to" rather than
"the gate was never wired at all".

### Unverified events: four rows that are partly inference

`TeammateIdle`, `TaskCreated` and `TaskCompleted` appear in the upstream event
table but have no detailed documentation, so their blocking behaviour **and**
their payloads are inference here. `SessionEnd`'s matcher values are documented
but its payload shape is not. All four are supported and all four are flagged: a
rule scoped to one is a selftest **warning**, and the fields it can read are a
guess until somebody confirms them empirically.

### Why this gate never exits 2

The hooks contract has two ways to refuse: exit 2 with a message on stderr, or
exit 0 with a JSON response document. **They are mutually exclusive** — exit 2
makes the harness ignore stdout entirely. This gate always writes JSON and always
exits 0, because the JSON carries the decision _and_ the operator's reason in one
structured value the harness attributes correctly, on every event that has a
response envelope at all. Supporting both would mean two output contracts to get
right, and the one that silently discards the reason would be the one used in the
cases that matter most.

`WorktreeCreate` is the single exception, because it is the one event with **no**
response envelope: it fails on any nonzero exit. Its refusal is therefore exit 1
— still never exit 2, and the reason goes to the decision log rather than to a
field that does not exist.

### One first-match walk per event

A rule is scoped to exactly one event, and only that event's rules are walked for
a given payload. That is not an optimization; it is what makes the enforced
decision answerable. A rule that applied to two events could be satisfied by a
payload whose envelope has no field for the decision it asked for.

The consequence worth knowing: `event` **defaults to `PreToolUse`**, so every
rule file written before events existed is a file of `PreToolUse` rules and means
exactly what it always meant. Adding `event` and the five new fields is why the
schema went to `1.1`; see
[schema versions](#schema-versions-and-compatibility).

### Which events get wired

`settings.json` decides which events the harness invokes a hook for, so the
installer derives the wiring from the rules: an entry for **every event that has
rules, and only those**, with a tool-name matcher covering exactly the tools that
event's rules name. `doctor` reports the wiring per event and **WARNs** when the
rule file has rules for an event nothing wires — policy that looks complete and
never runs. See [install](#install-uninstall-purge).

---

## Operator CLI

Every transcript below is captured from a real run of this binary. Reach these
through [`hookctl`](#the-runner-hookctl) — `./hookctl check '<command>'`,
`./hookctl doctor`, `./hookctl selftest` — or invoke the gate directly, which is
all `hookctl` does. The `doctor` / `status` / `diff-defaults` transcripts were
captured against the same throwaway install as the runner section
(`/tmp/hookctl-demo`, overlay at `/tmp/hookctl-demo-repo`); the rest read a rule
file out of this repository and need no install at all.

### `check` — why did the gate do that?

Evaluates one proposed tool call through the _same_ path resolution, the _same_
overlay walk, and the _same_ disabled set the hook uses, so it predicts the hook
rather than reimplementing it.

```console
$ claude-hooker-gate check --rules src/testdata/cookbook-recipes.json git push --force origin main
rules    : src/testdata/cookbook-recipes.json
event    : PreToolUse
tool     : Bash
command  : git push --force origin main

ask      : ask-force-push-protected-branch  [command_word command "git"]
           git push --force origin main
           ^~~
reason   :
           Force-pushing main or master rewrites history other people have already pulled, and
           their next pull will fail or silently lose commits — `-f`, `-vf` and `--force` are the
           same flag. If the remote must change, push a branch and open a PR: `git push origin
           HEAD:fix/<name>`; if you truly must overwrite, `--force-with-lease` at least refuses
           when someone else pushed first.
```

The underline is the whole reason a hit carries a byte span: an operator
arguing with a rule needs to see _which bytes_ it read.

That rule is an `invocation` group of four conjuncts, and the hit reported for a
conjunction is its **first** satisfied leaf — here `command_word "git"`. All
four matched; one of them has to be the one shown. `--explain` is how you see
the other three.

A structural hit adds _what those bytes turned out to mean_. The command below
contains no `pkill` token anywhere — the shell assembles one — and the report
names both the value the rule matched and the bytes that produced it:

```console
$ claude-hooker-gate check --rules src/testdata/structural-rules.json -- 'P=pki; K=ll; $P$K -f myserver'
rules    : src/testdata/structural-rules.json
event    : PreToolUse
tool     : Bash
command  : P=pki; K=ll; $P$K -f myserver

deny     : no-process-killer  [command_word command "pkill" resolved from "$P$K" via resolved_concat]
           P=pki; K=ll; $P$K -f myserver
                        ^~~~
reason   :
           A pattern-matching process killer takes down anything whose command line happens to
           match, including this session and unrelated work on the same machine. Find the process
           first (`ps aux | grep '[m]yserver'`) and kill the PID you actually meant.
```

`via <origin>` is one of `literal`, `resolved_var`, `resolved_concat`, `alias`,
`function`, `substitution_derived`, `unresolved_dynamic`. It is omitted
entirely for a hit on bytes the operator wrote as they read.

#### `check --explain` — the model, not just the verdict

When a structural rule fires unexpectedly, or fails to fire, the honest answer
is in the parsed command. `--explain` prints it: every invocation with its
nesting depth, the wrapper that reached it, its resolved command word and
arguments, every alias or function body that was re-lexed, and the signal
flags. Default output is unchanged — the compact report is the one an operator
reads a hundred times.

```console
$ claude-hooker-gate check --rules src/testdata/structural-rules.json --explain \
    -- 'sudo bash -lc "cd /repo && git add -A"'
rules    : src/testdata/structural-rules.json
event    : PreToolUse
tool     : Bash
command  : sudo bash -lc "cd /repo && git add -A"

deny     : no-git-add-all-anywhere  [command_line command "git add -A"]
           sudo bash -lc "cd /repo && git add -A"
                                      ^~~~~~~~~~
reason   :
           `git add -A` sweeps in unintended files (secrets, temp files, generated artifacts), and
           wrapping it in `bash -lc` or a subshell does not change that. Stage paths explicitly
           with `git add <path> ...`, or `git add -u` for tracked-only changes.

explain  : 5 invocation(s), max depth 3
  [0] depth 0  top  first
       command  : sudo
       args     : [bash] [-lc] [cd /repo && git add -A]
       flags    : short {cl}
  [1] depth 1  privilege  first  parent [0]
       command  : bash
       args     : [-lc] [cd /repo && git add -A]
       flags    : short {cl}
  [2] depth 2  shell_c  first  parent [1]
       command  : cd
       args     : [/repo]
  [3] depth 2  shell_c  andand  parent [1]
       command  : git
       args     : [add] [-A]
       flags    : short {A}
  [4] depth 3  subcommand  andand  parent [3]  (not a process)
       command  : add
       args     : [-A]
       flags    : short {A}
  signals  : none
```

The `flags` line is the [normalized option set](#flags--the-whole-option-set-however-it-was-spelled)
a `flags` matcher reads — `-lc` is `{c,l}` whether it was written clustered or
separately — and it is computed from the **resolved** values, so
`X=-rf; rm $X /` shows `{f,r}` on an invocation whose own text carries neither
letter. Invocations with no options print no line.

An alias or function shows the body that was read and where it went:

```console
$ claude-hooker-gate check --rules src/testdata/structural-rules.json --explain -- "alias k='pkill -f svc'; k"
rules    : src/testdata/structural-rules.json
event    : PreToolUse
tool     : Bash
command  : alias k='pkill -f svc'; k

deny     : no-process-killer  [command_word command "pkill" resolved from "k" via alias]
           alias k='pkill -f svc'; k
                                   ^
reason   :
           A pattern-matching process killer takes down anything whose command line happens to
           match, including this session and unrelated work on the same machine. Find the process
           first (`ps aux | grep '[m]yserver'`) and kill the PID you actually meant.

explain  : 2 invocation(s), max depth 0
  [0] depth 0  top  first
       command  : alias
       args     : [k=pkill -f svc]
  [1] depth 0  top  seq
       command  : k  -> pkill via alias
  expansion [0] alias k -> "pkill -f svc"  (1 invocation(s))
       [0.0] pkill [-f] [svc]
  signals  : alias_defined alias_expanded
```

Note the underline: it sits on the `k` that was _invoked_, not on the alias
definition, because an alias body's bytes are not a contiguous run of the
original text and the invocation is the honest thing to point at. A function
body _is_ a contiguous slice, so it underlines the command word inside the body:

```console
$ claude-hooker-gate check --rules src/default-rules.json --explain -- 'k() { pkill -f "$1"; }; k worker'
rules    : src/default-rules.json
event    : PreToolUse
tool     : Bash
command  : k() { pkill -f "$1"; }; k worker

deny     : no-pkill  [command_word command "pkill" resolved from "pkill" via function]
           k() { pkill -f "$1"; }; k worker
                 ^~~~~
reason   :
           pkill is forbidden (self-match risk — it has killed the agent's own shell before), and
           wrapping it in `sudo`, `bash -lc`, `xargs`, an alias or a variable does not change what
           runs. Kill by explicit PID instead: `kill -9 <pid>`; for liveness probes use the
           `[p]attern` bracket-trick with `ps`/`grep` (e.g. `ps aux | grep '[m]yproc'`).

explain  : 3 invocation(s), max depth 0
  [0] depth 0  top  first
       defines  : k()
       command  : k
       args     : [{] [pkill] [-f] [$1]
       flags    : short {f} -f=$1(separate)
  [1] depth 0  top  seq
       command  : }
  [2] depth 0  top  seq
       command  : k  -> k via function
       args     : [worker]
  expansion [0] function k -> " pkill -f "$1"; "  (1 invocation(s))
       [0.0] pkill [-f] [$1]
  signals  : function_defined function_expanded
```

`explain` prints the model as it is, including the parts a shell would read
differently: the definition stage's `{` and the closing `}` are words to the
lexer, and `[0]` is flagged `defines : k()` so the `invocation` binding skips
it. Nothing there executes — the body that does is the `expansion` block.

Non-Bash calls take `--tool`, `--file-path`, and `--content`:

```console
$ claude-hooker-gate check --rules src/default-rules.json --tool Write \
    --file-path /Users/dev/.claude/settings.json --content '{}'
rules    : src/default-rules.json
event    : PreToolUse
tool     : Write
file_path: /Users/dev/.claude/settings.json
content  : {}

deny     : protect-hook-config  [substring file_path ".claude/settings.json"]
           /Users/dev/.claude/settings.json
                      ^~~~~~~~~~~~~~~~~~~~~
reason   :
           The gate's own policy files (`hook-rules.json`, `.claude/settings.json`) are
           operator-owned: a gate that can rewrite its own rules is not a gate. If a rule is wrong,
           too broad, or blocking legitimate work, say so and ask the operator to edit the file —
           do not edit it, copy it, or route around it.
```

Shadow hits are reported above the decision, and control bytes are rendered as
`.` one-for-one so the underline stays aligned even when the field is a whole
file body:

```console
$ claude-hooker-gate check --rules src/default-rules.json --tool Write \
    --file-path /repo/scripts/restart.sh --content "$(printf '#!/bin/sh\npkill -f myserver\n')"
rules    : src/default-rules.json
event    : PreToolUse
tool     : Write
file_path: /repo/scripts/restart.sh
content  : #!/bin/sh.pkill -f myserver

shadow   : wrapper-script-shadow  [word content "pkill"]
           #!/bin/sh.pkill -f myserver
                     ^~~~~
no-match : no rule fires for this input.
```

Nothing matching is stated, not implied:

```console
$ claude-hooker-gate check --rules src/default-rules.json git add src/rules.zig README.md
rules    : src/default-rules.json
event    : PreToolUse
tool     : Bash
command  : git add src/rules.zig README.md

no-match : no rule fires for this input.
```

`--quiet` prints one word and keeps the exit code, for scripting:

```console
$ claude-hooker-gate check --rules src/default-rules.json --quiet pkill -f myserver
deny
```

`--project-dir` evaluates a repository's overlay first — see
[project rule overlays](#project-rule-overlays).

Arguments after the first non-flag word are all command text, dashes included,
joined with single spaces: `check rm -rf /x` needs no quoting. Use `--` before
a command that itself starts with a dash.

### `selftest` — do the rules do what the file says?

Runs the file's own `tests` — the literal cases and every case its
[`generate` blocks](#generate--the-cross-product-and-the-near-misses) expand to,
each on its own line — then lints the rule set.

```console
$ claude-hooker-gate selftest --rules src/testdata/structural-rules.json
rules    : src/testdata/structural-rules.json
PASS  #1    Bash: bash -lc "pkill -f myserver"
PASS  #2    Bash: sudo pkill -9 myserver
PASS  #3    Bash: P=pki; K=ll; $P$K -f myserver
PASS  #4    Bash: X=-rf; rm $X /var/lib/thing
PASS  #5    Bash: rm -vrf /var/lib/thing
PASS  #6    Bash: rm -R -f /var/lib/thing
...
PASS  #19   Bash: rm -rf /var/lib/thing  [generated from #19]
PASS  #20   Bash: rm -fr /var/lib/thing  [generated from #19]
PASS  #21   Bash: rm -vrf /var/lib/thing  [generated from #19]
...
PASS  #31   Bash: rm -i /var/lib/thing  [generated from #19]
warn  echoing-a-command-name-is-fine: allow grants the call outright and skips the permission prompt; keep its matchers narrow
result   : 18 literal + 13 generated cases passed, 0 lint error(s), 1 warning(s) -> OK
```

The counts are split on purpose. A literal case pins a specific past mistake; a
generated one covers a space no list of literals could. A single merged total
would hide a generator that quietly expanded to nothing — which is the one way a
suite can go green while the rule it was protecting stopped being tested.

The shipped defaults carry a much larger suite; only its head and its verdict are
reproduced here:

```console
$ claude-hooker-gate selftest --rules src/default-rules.json
rules    : src/default-rules.json
PASS  #1    Bash: pkill -f myserver
PASS  #2    Bash: bash -lc "pkill -f myserver"
PASS  #3    Bash: sudo pkill -9 myserver
PASS  #4    Bash: /usr/bin/pkill -f worker
PASS  #5    Bash: env FOO=1 pkill -f worker
PASS  #6    Bash: find . -name '*.pid' | xargs pkill -f
PASS  #7    Bash: timeout 5 pkill -f worker
PASS  #8    Bash: uv run pkill -f worker
PASS  #9    Bash: cd /tmp && (pkill -f worker)
PASS  #10   Bash: P=pki; K=ll; $P$K -f myserver
PASS  #11   Bash: CMD=pkill; $CMD -9 worker
PASS  #12   Bash: alias k=pkill; k -f worker
PASS  #13   Bash: k() { pkill -f "$1"; }; k worker
...
result   : 107 literal + 390 generated cases passed, 0 lint error(s), 0 warning(s) -> OK
```

The lint catches the mistakes that make a policy quietly weaker than it reads:

| Level | Finding                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------- |
| error | empty rule name — `CLAUDE_HOOK_DISABLE` and the log both key on it                                                        |
| error | duplicate rule name — disabling or reading the log for it is ambiguous                                                    |
| error | no positive matchers (`match` and `match_all` both empty) — the rule can never fire                                       |
| error | every positive entry is a negative group — a rule with no positive condition can never fire                               |
| error | matcher with an empty value — an empty pattern never matches                                                              |
| error | pattern `"*"` — matches nothing; the only wildcard is a trailing `*` on a prefix                                          |
| error | a structural kind on `content` or `file_path` — there is no command model there, so it can never match                    |
| error | a `signal` value outside the documented vocabulary — a typo'd signal name is a dead rule                                  |
| error | a `flag` value that is not a plausible option (`-`, `--`, a path, a phrase)                                               |
| error | a `flags` value that is not an option set (entries of `\|`-separated option names)                                        |
| error | a `path_class` value naming no built-in path class — run `classes` for the list                                           |
| error | `ignore_case` on `command_word`, `flag`, `flags`, `path_class` or `signal` — those kinds cannot honor it                  |
| error | an empty group (`{"any": []}`) — never satisfied, so its rule can never fire                                              |
| error | a group entry naming more than one of `any`/`all`/`none`/`invocation`                                                     |
| error | a group entry that also carries a matcher `value` — an entry is one or the other                                          |
| error | a group nested past `MAX_GROUP_DEPTH` — evaluation treats it as unsatisfied                                               |
| error | a test expects a rule that does not exist                                                                                 |
| error | a `generate` axis with no values — the whole product collapses and asserts nothing                                        |
| error | a `generate` axis missing from the command template, or a `{placeholder}` with no axis                                    |
| error | a `near_miss` naming an axis the generator does not declare — those negatives never run                                   |
| error | a test carrying both `generate` and a literal input — only the generated cases would run                                  |
| warn  | empty reason — the reason is the whole explanation the model and user are shown                                           |
| warn  | `allow` grants the call outright and skips the prompt; keep its matchers narrow                                           |
| warn  | a short `flag`/`flags` matcher outside an `invocation` group — a bare letter means different things to different programs |
| warn  | an `invocation` group inside another — the inner one degenerates to a plain `all`                                         |
| warn  | a `generate` block with no `near_miss` — a product of positives is passed by a rule that matches everything               |
| warn  | a declared `set` nothing references — dead policy                                                                         |
| warn  | a `set` with a single member — an indirection with nothing behind it                                                      |
| warn  | no `tests` block — the file asserts nothing about its own behaviour                                                       |

Warnings never fail the run; errors and failing cases both exit 1. An
unresolvable `$class:`/`$set` reference never reaches the lint at all — the file
does not parse, and `selftest` exits **65**.

Deliberately **not** linted: shadowing analysis ("this deny is unreachable
because an allow above it matches a superset"). Doing that honestly needs
pattern containment, and a lint that is right most of the time trains operators
to ignore the output — which costs them the checks that _are_ exact.

`--json` emits the same result as one object (`rules_path`, `ok`, `literal`,
`generated`, `tests[]`, `lint[]`) for CI. Each case carries its `source`
(`literal` or `generated`) and the `origin` index of the `tests` entry it came
from.

### `classes` — what a rule inherits from the binary

The [classes](#sets-and-classes-naming-a-list-instead-of-repeating-it) a rule may
name instead of enumerating members ship **with the gate**, which means a rule
that names one inherits whatever this version thinks the members are. That trade
is only acceptable if the list is never hidden knowledge:

```console
$ claude-hooker-gate classes filesystem_anchor
filesystem_anchor  (path)
  a place a whole-world walk starts: / itself, one system top-level directory, or the home
  directory itself — never something below them
  reference as: {"kind": "path_class", "value": "filesystem_anchor"}
  membership is decided by normalizing the argument, not by comparing it; the spellings
  below are the canonical ones and what the test generators expand
  members (12):
    /
    ~
    ~/
    $HOME
    /usr
    /etc
    /var
    /opt
    /Users
    /home
    /System
    /Library
```

With no argument it prints every class; `--json` emits `{version, classes[]}`, so
a CI job can diff the catalog across gate versions and see a policy widen or
narrow before it does. An unknown name exits **64** and lists the real ones.

### `doctor` — is this install actually working?

Eight checks from the gate, each `PASS`, `WARN` or `FAIL`, each failure carrying a
line that says what to do about it — plus a ninth from the runner about this
working tree's build processes when you go through `./hookctl`. `--json` for
scripts; `--claude-dir` to diagnose an install that is not the one you are living
in. **Exit `1` if any check `FAIL`s**; a `WARN` is not a failure, because a gate
that works but has a lint warning must not break a pipeline.

<!-- hookctl:doctor -->

```console
$ ./hookctl doctor --claude-dir /tmp/hookctl-demo
claude-hooker-gate doctor 0.2.0
claude dir : /tmp/hookctl-demo

PASS  wiring      /tmp/hookctl-demo/settings.json
                  wires SessionStart, PreToolUse(*), PostToolUse(Bash) ->
                  /tmp/hookctl-demo/hooks/claude-hooker-gate
                  (present, executable, 1.1 MiB)
PASS  version     installed
                  /tmp/hookctl-demo/hooks/claude-hooker-gate
                  is 0.2.0, matching this build
PASS  signature   /tmp/hookctl-demo/hooks/claude-hooker-gate
                  is ad-hoc signed and `codesign --verify` accepts it (flags=0x20002(adhoc,linker-signed),
                  Signature=adhoc)
PASS  rules       /tmp/hookctl-demo/hook-rules.json:
                  14 rules, 107 literal + 390 generated cases pass, lint clean
PASS  log         /tmp/hookctl-demo/hook-gate-log.jsonl
                  does not exist yet, and its directory is writable — nothing has matched
PASS  overlay     no overlay at
                  /tmp/hookctl-demo/.claude/hook-rules.json
                  — this directory contributes no rules
PASS  disabled    not set — every rule in the file is live
PASS  environment no path override in effect; the rule file and log under the claude dir
                  are what the gate reads

result     : 8 pass, 0 warn, 0 fail -> healthy

== this checkout's own build processes (not part of the install) ==
PASS  processes   no build or test process from this checkout is running
```

The `processes` line is the runner's, not the gate's, and is about this working
tree rather than about the install — see
[process hygiene](#process-hygiene-orphans-timeouts-and-reap) for why it lives
there and what it can say. Everything above the `result` line is the gate's.

The eight, and what each one is actually asking:

| Check         | The question                                                                                                                                                                                                                                                     |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wiring`      | Is the gate wired in this install's `settings.json`, for **every event the rule file has rules for**; does its command **exist**; and is it **executable**? An event with rules and no wiring is a `WARN` naming it — policy that looks complete and never runs. |
| `version`     | Does the **installed binary's** version match the build doing the diagnosing?                                                                                                                                                                                    |
| `signature`   | macOS only: is the installed gate ad-hoc signed, and does `codesign --verify` still accept it? On every other platform, `not applicable`. See [macOS code signing](#macos-code-signing).                                                                         |
| `rules`       | Does the live rule file parse, pass its own cases, and lint clean — with the counts?                                                                                                                                                                             |
| `log`         | Is the log writable, how big is it, is rotation on, has anything rotated, when did a rule last fire?                                                                                                                                                             |
| `overlay`     | Is a project overlay active for this directory, and does **it** parse?                                                                                                                                                                                           |
| `disabled`    | Is `CLAUDE_HOOK_DISABLE` switching rules off — and **which ones**?                                                                                                                                                                                               |
| `environment` | Is `CLAUDE_HOOK_RULES_PATH` / `CLAUDE_HOOK_LOG_PATH` / `CLAUDE_PROJECT_DIR` moving anything? Informational, always `PASS`.                                                                                                                                       |

**Why the version check is the one that earns this subcommand.** Edit rules,
rebuild, forget to reinstall — and everything looks right while the gate
enforcing decisions is last week's binary. Nothing else in the system notices,
because a stale gate is a perfectly functional gate. So it is checked out loud.
The transcript below was produced by bumping `src/version.zig` to `0.3.0`
without reinstalling, and by setting `CLAUDE_HOOK_DISABLE` — the two states this
subcommand exists to make impossible to sit in unknowingly:

<!-- hookctl:doctor-unhealthy -->

```console
$ CLAUDE_HOOK_DISABLE='no-pkill,protect-hook-config' \
    ./hookctl doctor --claude-dir /tmp/hookctl-demo --project-dir /tmp/hookctl-demo-repo ; echo $?
claude-hooker-gate doctor 0.3.0
claude dir : /tmp/hookctl-demo

PASS  wiring      /tmp/hookctl-demo/settings.json
                  wires SessionStart, PreToolUse(*), PostToolUse(Bash) ->
                  /tmp/hookctl-demo/hooks/claude-hooker-gate
                  (present, executable, 1.1 MiB)
FAIL  version     installed /tmp/hookctl-demo/hooks/claude-hooker-gate is 0.2.0, this
                  build is 0.3.0 — the gate enforcing your rules is NOT the tree you edited
      -> run `./hookctl upgrade` — it rebuilds, shows what the shipped defaults gained,
         and reinstalls the binary while keeping your rules
PASS  signature   /tmp/hookctl-demo/hooks/claude-hooker-gate is ad-hoc signed and
                  `codesign --verify` accepts it (flags=0x20002(adhoc,linker-signed), Signature=adhoc)
PASS  rules       /tmp/hookctl-demo/hook-rules.json:
                  14 rules, 107 literal + 390 generated cases pass, lint clean
PASS  log         /tmp/hookctl-demo/hook-gate-log.jsonl is writable — 226 B, 3
                  entr(ies), rotates at 10.0 MiB, last hit 4m ago
PASS  overlay     /tmp/hookctl-demo-repo/.claude/hook-rules.json is active: 1 rule(s),
                  evaluated BEFORE the global file
FAIL  disabled    2 rule(s) are switched OFF right now: no-pkill, protect-hook-config
      -> unset CLAUDE_HOOK_DISABLE in the environment the harness starts with
         (settings.json `env`, or your shell profile) and restart the session; matches are logged
         as `bypassed` until you do
PASS  environment no path override in effect; the rule file and log under the claude dir
                  are what the gate reads

result     : 6 pass, 0 warn, 2 fail -> NOT HEALTHY
1
```

Two things that transcript is deliberately showing:

- **A silently weakened gate is shouted about.** `CLAUDE_HOOK_DISABLE` is an
  operator control, not an escape hatch (see
  [environment variables](#environment-variables)), but a protection that is off
  is a protection you think you have. The check names every rule it actually
  switched off, and names separately any entry that matches no rule — because a
  typo'd name is a rule you believe is disabled and is not.
- **`doctor` asks the installed binary, by running it.** The only authority on
  what the harness will execute is that file, so the version comes from
  `<installed gate> version` rather than from a filename or a timestamp. Which
  is also why `./hookctl doctor` builds first: run the _installed_ gate's own
  `doctor` and it compares itself against itself, which it says out loud rather
  than reporting a false `PASS`.

Every other failure has the same shape. Delete the installed binary and `wiring`
and `version` both `FAIL` (`does not exist — every tool call runs unguarded`).
Corrupt the rule file and `rules` `FAIL`s with the fact that matters most —
`the gate fails OPEN on an invalid rule file, so nothing is being enforced`.
Break a project overlay and `overlay` `FAIL`s with `the hook skips it, so this
repository's rules are NOT applied`, because a broken overlay is silent
otherwise. Switch rotation off and `log` `WARN`s.

### `status` — what am I running?

The same facts, six lines, no diagnosis. This is the question asked far more
often than "what is wrong", and it deserves not to scroll.

<!-- hookctl:status -->

```console
$ ./hookctl status --claude-dir /tmp/hookctl-demo
gate       : 0.2.0 at /tmp/hookctl-demo/hooks/claude-hooker-gate
wiring     : SessionStart, PreToolUse(*), PostToolUse(Bash) -> /tmp/hookctl-demo/hooks/claude-hooker-gate
rules      : /tmp/hookctl-demo/hook-rules.json
             14 rules, 497 cases (107 literal + 390 generated), selftest OK
overlay    : none for this directory
log        : /tmp/hookctl-demo/hook-gate-log.jsonl (nothing logged yet)
disabled   : nothing
```

Drift is called out on the first line (`0.2.0 at … (DRIFT: this build is
0.3.0)`), a wiring that points somewhere else gets `(NOT this install)`, and a
rule file whose own cases are failing says `SELFTEST FAILING` rather than a
count you have to interpret. `--json` carries `version_drift`, `wired_here`,
`selftest_ok`, `overlay_state`, and the raw log timestamp.

### `diff-defaults` — what did the defaults gain?

The rule file is seeded once, on install, and then it is yours. That is the
right trade — it is a policy document, not a managed resource — but it means an
unedited copy slowly falls behind the shipped one and an _edited_ copy has no
safe way to catch up. `diff-defaults` is that way: it compares the defaults
**embedded in the binary** against your live file and reports what changed, by
name, without touching anything.

<!-- hookctl:diff-defaults -->

```console
$ ./hookctl diff-defaults --claude-dir /tmp/hookctl-demo
defaults   : embedded in claude-hooker-gate 0.2.0
live       : /tmp/hookctl-demo/hook-rules.json

+ no-heredoc-python
    new in the shipped defaults; your file does not have it. Copy the rule in to adopt it,
    or ignore it deliberately.
~ no-pkill  (decision, reason)
    the shipped version of this rule differs from yours in the fields above; yours is what
    the gate enforces.
- house-no-force-push
    only in your file: either a rule you wrote, or a default this version no longer ships.
    Nothing here will remove it.
= 10 rule(s) identical

other sections:
  tests
    defaults: 100 declaration(s)
    live    : 101 declaration(s)
  logging
    defaults: {"enabled":true,"log_commands":false,"max_bytes":10485760}
    live    : {"enabled":true,"log_commands":false,"max_bytes":0}

result     : 1 added, 1 changed, 1 yours only, 10 identical
```

`+` is what adopting this version would gain, `~` is a shipped rule you have
edited (with the fields that differ: `tool`, `decision`, `reason`, `match`,
`match_all`, `match_none`), and `-` is yours — either a rule you wrote or a
default that was dropped upstream. Nothing is prescriptive: it exits `0` whether
or not anything differs, because "my rules differ from the defaults" is the
normal, intended state of a customized install. `--json` carries `in_sync`.

**Both sides are compared after reference expansion**, which is what makes the
report about behaviour rather than spelling: a default rewritten from seven
hand-listed members into one `$class:` reference over the same members compares
**identical**, because the two match the same commands. What shows up as
`~ changed` is a change in what a rule matches.

`./hookctl upgrade` prints this on its way to reinstalling the binary, so the
one command you run after a `git pull` also tells you what your policy file is
missing.

### `stats` — which rules are actually load-bearing?

```console
$ claude-hooker-gate stats --log rot-log.jsonl
log      : rot-log.jsonl

rule              total     deny      ask    allow   shadow bypassed   last hit
no-pkill              2        2        0        0        0        0   0s ago
no-git-add-all        1        1        0        0        0        0   0s ago

3 line(s) counted
```

Enforced decisions are counted separately from shadow and bypassed hits,
because "fired 400 times, all shadow" and "fired 400 times, all denials" are
opposite facts about a rule. A rule that never appears at all is dead weight.

(The `last hit` column and the `now_unix`/`last_ts` values in the JSON form are
relative to when the command ran, so they will differ in your own output. Every
other number in these transcripts is reproducible.)

`--since 7d|24h|90m|2w|<seconds>` bounds the window. `--json` emits the raw
numbers and timestamps. `--include-rotated` is covered
[below](#observability-the-decision-log).

A malformed line is counted and stepped over rather than fatal: the log is
appended to by concurrent short-lived processes, and a summary that refuses to
print because of one torn line is a summary nobody can use.

---

## Exit codes

| Code | Meaning                                                                                                                                                                                                                                                                                         |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | `check`: no match, or an `allow` rule. `selftest`: everything passed. `doctor`: no check failed (a `WARN` is not a failure). `stats`, `status`, `diff-defaults`: always.                                                                                                                        |
| 1    | `check`: `deny`. `selftest`: a failing case or a lint error. `doctor`: at least one check `FAIL`ed. The hook: a broken config (non-blocking, per the failure policy) — and, for `WorktreeCreate` alone, an enforced `deny`, since that is the one event whose refusal has no response envelope. |
| 2    | `check`: `ask`. **Never** what the hook itself exits: exit 2 and JSON output are mutually exclusive in the hooks contract, and the JSON is what carries the reason — see [why this gate never exits 2](#why-this-gate-never-exits-2).                                                           |
| 64   | Usage (`EX_USAGE`) — `help`, an unknown subcommand, a bad flag, a bad `--since`.                                                                                                                                                                                                                |
| 65   | The rule file is invalid (`EX_DATAERR`) — bad JSON, an unknown key, or an unresolvable `$class:`/`$set` reference.                                                                                                                                                                              |
| 66   | The rule file, or a named log, cannot be read (`EX_NOINPUT`); or there is no install to inspect (no `--claude-dir`, no `HOME`).                                                                                                                                                                 |
| 70   | An internal failure (`EX_SOFTWARE`).                                                                                                                                                                                                                                                            |
| 78   | The rule file declares a `schema_version` **newer** than this binary reads, or one that is not a version at all (`EX_CONFIG`) — see [schema versions](#schema-versions-and-compatibility).                                                                                                      |

`hookctl` passes the binary's exit code through unchanged, and adds two of its
own: **64** for an unknown verb, and **69** (`EX_UNAVAILABLE`) when a verb needs
the Zig toolchain and `zig` is not on `PATH`.

Verified, in order:

```console
$ claude-hooker-gate check --rules src/testdata/cookbook-recipes.json --quiet git push --force origin main ; echo $?
ask
2
$ claude-hooker-gate check --toool Bash ls ; echo $?
claude-hooker-gate: unknown option "--toool"
usage: claude-hooker-gate <subcommand> [options]
...
64
$ claude-hooker-gate check --rules /tmp/chm-bad-rules.json ls ; echo $?
claude-hooker-gate: invalid rule file /tmp/chm-bad-rules.json: InvalidRules
65
$ claude-hooker-gate check --rules /tmp/chm-no-such-rules.json ls ; echo $?
claude-hooker-gate: cannot read /tmp/chm-no-such-rules.json: FileNotFound
66
$ claude-hooker-gate selftest --rules src/testdata/future-schema-rules.json ; echo $?
claude-hooker-gate: src/testdata/future-schema-rules.json declares schema_version 2.0, and this build reads 1.1 — refusing to enforce a policy it may not fully understand.
  run `./hookctl upgrade` to rebuild and reinstall the gate (your rule file is not touched).
78
```

**78 is deliberately not 65.** "Your rule file is invalid" and "your rule file is
from a newer release than this binary" are different events with different fixes —
the first is fixed by editing JSON, the second by `./hookctl upgrade` — and a
script watching a fleet has to tell a typo apart from a half-finished rollout.

**Redirection behaves the way a shell script expects.** The gate writes stdout
and stderr as streams, so two invocations sharing one redirect append rather than
overwrite, and `>>` accumulates across invocations:

```console
$ { claude-hooker-gate version; claude-hooker-gate version; } > two.txt ; cat two.txt
claude-hooker-gate 0.2.0
claude-hooker-gate 0.2.0
```

**Hook mode is different.** As the hook, the gate exits `0` whether or not
anything matched — the _envelope_ carries the decision, not the exit status. It
exits `1` only when it could not function at all (unreadable stdin, missing or
invalid rule file), which the hooks contract treats as a non-blocking error.

---

## Observability: the decision log

Every hit — enforced, shadow, or bypassed — is appended as one JSON line. This
is what makes the gate reviewable rather than merely present.

Three lines from one run of the shipped defaults — a `deny`, a shadow hit, and a
`deny` on a command word the text never spells out:

```json
{"ts_unix":1785364309,"session_id":"s-4f2a","tool":"Bash","rule":"no-git-add-all","decision":"deny","matcher":{"kind":"command_line","field":"command","value":"add -A"},"span":"add -A","resolved":"add -A","origin":"literal","command_logged":false}
{"ts_unix":1785364309,"session_id":"s-91bc","tool":"Write","rule":"wrapper-script-shadow","decision":"log","matcher":{"kind":"word","field":"content","value":"pkill"},"span":"pkill","command_logged":false}
{"ts_unix":1785364309,"session_id":"s-4f2a","tool":"Bash","rule":"no-pkill","decision":"deny","matcher":{"kind":"command_word","field":"command","value":"pkill"},"span":"$P$K","resolved":"pkill","origin":"resolved_concat","command_logged":false}
```

### Line schema

| Key              | Type    | Notes                                                                                                                                                          |
| ---------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ts_unix`        | integer | Seconds since the epoch.                                                                                                                                       |
| `session_id`     | string  | From the event; `""` when the payload carried none.                                                                                                            |
| `event`          | string  | Which hook event produced the hit. Absent on a log written before events existed; `stats` reads a missing key as `PreToolUse`, which is what those lines were. |
| `tool`           | string  | The tool name the payload named; `""` on an event that carries none.                                                                                           |
| `rule`           | string  | The rule's `name`, or the synthetic `_overflow`.                                                                                                               |
| `decision`       | string  | `deny` \| `ask` \| `allow` \| `log` \| **`bypassed`**                                                                                                          |
| `matcher`        | object  | `{kind, field, value}` — which matcher fired, in which field.                                                                                                  |
| `span`           | string  | The bytes that actually matched. A few bytes; recorded unconditionally.                                                                                        |
| `resolved`       | string  | **Only** for a structural hit: the value the matcher compared against. Capped like `span`.                                                                     |
| `origin`         | string  | **Only** for a structural hit: `literal` \| `resolved_var` \| `resolved_concat` \| `alias` \| `function` \| `substitution_derived` \| `unresolved_dynamic`.    |
| `command_logged` | bool    | Whether `command` below is present. Never leaves a reader guessing.                                                                                            |
| `command`        | string  | **Only** when `logging.log_commands` is on: the full matched field text, capped at 4 KiB with a truncation marker.                                             |

`resolved` and `origin` are the structural half of the same promise `span`
makes. `span` records what the operator _wrote_, which for a recovered command
word is `$P$K` and never says `pkill`:

That is the third line of the sample above, written by the shipped `no-pkill`
rule: `span` says `$P$K`, `resolved` says `pkill`, and `origin` says how the
reader got from one to the other. The hook's own output for the same call is the
envelope and nothing else:

```console
$ printf '%s' '{"session_id":"s-4f2a","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"P=pki; K=ll; $P$K -f myserver"}}' | claude-hooker-gate
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"pkill is forbidden (self-match risk — it has killed the agent's own shell before), and wrapping it in `sudo`, `bash -lc`, `xargs`, an alias or a variable does not change what runs. Kill by explicit PID instead: `kill -9 <pid>`; for liveness probes use the `[p]attern` bracket-trick with `ps`/`grep` (e.g. `ps aux | grep '[m]yproc'`)."}}
```

`resolved` and `origin` are **additive and omitted entirely** — not emitted as null — for every
hit from a textual matcher and from the `signal` kind. A consumer written
before they existed reads every line it read before, unchanged.

Three things in that schema exist because the alternative would be a log that
lies:

- **`bypassed`** has no spelling in the rule file. It means the rule matched and
  would have applied, but the operator's `CLAUDE_HOOK_DISABLE` switched it off.
  An override is an operator action, and the record of what it would have caught
  is exactly what makes it auditable afterwards.
- **`_overflow`** is a synthetic rule name (leading underscore so it cannot
  collide with an operator's) recorded when more than 16 shadow or bypassed
  hits matched at once. Its `matcher.value` names which buffer overflowed
  (`shadow_hits` or `bypassed_hits`), and it is written _before_ the lines it
  qualifies, so a reader learns the account is incomplete before reading it.
- **`command_logged`** distinguishes "the operator opted out" from "the field
  was empty".

Escaping is `std.json`'s: rule names, matcher values, spans and command text
are all operator- or agent-influenced, and none of them can inject a newline
and forge a second log line.

The whole facility is **best-effort**. It runs strictly _after_ the decision has
been written and flushed, and any failure — unwritable path, full disk — costs
one stderr note per process and is then dropped. A gate that stops deciding
when its log breaks is worse than a gate with a gap in its log.

Writes are `open(O_APPEND)` + one `write` + `close`, with no handle held across
invocations, so concurrent gate processes interleave whole lines instead of
corrupting each other.

### Rotation, and not losing what rotated

Above `logging.max_bytes` (10 MiB by default) the log is `rename`d to
`<path>.1` — replacing any previous `.1` — and a fresh file is started.
Exactly one generation is kept, deliberately: the log is a review aid, not an
archive, and an unbounded file on an operator's home directory is a
slow-motion outage.

That means `stats` on the live log alone can be silently missing history.
`--include-rotated` folds `<path>.1` back in, oldest entries first:

```console
$ claude-hooker-gate stats --log rot-log.jsonl
log      : rot-log.jsonl

rule              total     deny      ask    allow   shadow bypassed   last hit
no-pkill              2        2        0        0        0        0   0s ago
no-git-add-all        1        1        0        0        0        0   0s ago

3 line(s) counted

$ claude-hooker-gate stats --log rot-log.jsonl --include-rotated
log      : rot-log.jsonl
rotated  : rot-log.jsonl.1

rule                     total     deny      ask    allow   shadow bypassed   last hit
no-pkill                     3        3        0        0        0        0   0s ago
no-git-add-all               2        2        0        0        0        0   0s ago
wrapper-script-shadow        1        0        0        0        1        0   0s ago

6 line(s) counted
```

A whole rule — the shadow rule whose evidence the rollout depends on —
reappears. The JSON form names the generation it read, so a consumer can tell
whether a summary saw the rotated history:

```console
$ claude-hooker-gate stats --log rot-log.jsonl --include-rotated --json
{"log":"rot-log.jsonl","rotated":"rot-log.jsonl.1","exists":true,"now_unix":1785364361,"lines":6,"counted":6,"skipped":0,"filtered":0,"rules":[{"rule":"no-pkill","total":3,"deny":3,"ask":0,"allow":0,"shadow":0,"bypassed":0,"other":0,"last_ts":1785364361},{"rule":"no-git-add-all","total":2,"deny":2,"ask":0,"allow":0,"shadow":0,"bypassed":0,"other":0,"last_ts":1785364361},{"rule":"wrapper-script-shadow","total":1,"deny":0,"ask":0,"allow":0,"shadow":1,"bypassed":0,"other":0,"last_ts":1785364361}]}
```

The two generations are concatenated with a line break guaranteed at the seam:
a generation can end mid-line (a torn final append before rotation), and fusing
that fragment onto the next generation's first line would turn one malformed
line into two.

---

## Shadow-first rollout

Never ship a new rule as `deny`. Ship it as `log`, watch what it would have
caught, then promote it.

The method below is what the tooling now does for you:
`./hookctl init --profile observe` starts a whole install this way,
`./hookctl rules add <name> --shadow` adopts one catalog rule as `log`,
`./hookctl rules promote <name>` restores the enforced form (cases included)
when it has earned it, and `./hookctl rules new` defaults new rules to `log` —
see [choosing and managing rules](#choosing-and-managing-rules). The steps are
still worth reading, because they are the judgement the verbs cannot make for
you: what the evidence looks like, and when a rule has earned promotion.

**1. Write the rule with `"decision": "log"`.** It now records every match and
blocks nothing. Give it the reason it will eventually carry, so the eventual
promotion is a one-word edit.

```json
{
  "name": "watch-destructive-sql",
  "tool": "*",
  "decision": "log",
  "reason": "Observational only — this call is NOT blocked. It names a schema-destroying statement (DROP/TRUNCATE), which in a repo with a live database is unrecoverable without a restore.",
  "match": [
    { "kind": "substring", "value": "DROP TABLE" },
    { "kind": "substring", "field": "content", "value": "DROP TABLE" }
  ]
}
```

A shadow rule is the one place a deliberately broad matcher is correct: it costs
a log line, not a blocked task, and the breadth is what tells you where the real
boundary is. (The shipped
[recipe 16](RULES_COOKBOOK.md#16-watch-destructive-sql) ended up narrowed to
`content` alone, once a structural `deny` rule took over the command half — which
is exactly the sort of thing the shadow period is for finding out.)

**2. Confirm it fires at all.** `selftest` cases for a shadow rule can only
assert `none`; `check` shows the shadow hit directly, and prints the exact bytes
it read.

**3. Let it run.** A week is usually enough.

**4. Read the evidence.**

```sh
claude-hooker-gate stats --since 7d --include-rotated
```

Three outcomes, three different actions:

| What `stats` shows            | What it means                              | Do this                                                                                                                                 |
| ----------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Zero hits                     | The pattern never occurs, or never matches | Check with `check` that it _can_ fire, then delete it — a rule that cannot fire is worse than no rule, because it reads like protection |
| Steady hits, all of them real | The rule earns its place                   | Promote: `"decision": "log"` → `"deny"` (or `"ask"`)                                                                                    |
| Hits, mostly false positives  | The pattern is too broad                   | Narrow the matchers, or add a `match_none` carve-out, and keep watching                                                                 |

**5. Promote, and add a `tests` case** in the same edit — one positive, and one
negative drawn from whatever false positive you had to carve out. The case is
what stops the next person from re-widening it.

**6. Keep the shadow rule if it is about workarounds.** The shipped
`wrapper-script-shadow` is permanently `log`: it watches Write calls whose
_content_ names a denied command, which is the shape of a wrapper script that
would run the denied command out from under the gate. It is not evidence of bad
faith — plenty of legitimate scripts mention the command they manage — so it
observes rather than blocks, and gives the operator the data to decide. Its
`PostToolUse` companion `observe-script-file-run` records the other half: a shell
handed a file rather than a command string, so what ran is whatever that file
contained. Advisory and post-call events are where shadow rules earn most of their
keep, because observing is all they can do.

---

## Project rule overlays

A repository may ship rules of its own in `.claude/hook-rules.json`, located via
`$CLAUDE_PROJECT_DIR` (else the event's `cwd`). They are evaluated **before**
the global rules — one combined first-match walk, not a merge — exactly as if
the operator had pasted them at the top of their own file.

Only the project file's `rules` participate. Its `logging`, `tests`, and
`allow_project_overlay` are ignored, so a repo cannot redirect the operator's
audit trail or grant itself an overlay.

With `HOME=home` and a repo checked out at `repo/`, the same command reads two
different ways:

```console
$ claude-hooker-gate check git add -A
rules    : home/.claude/hook-rules.json
event    : PreToolUse
tool     : Bash
command  : git add -A

deny     : no-git-add-all  [command_line command "add -A"]
           git add -A
               ^~~~~~
reason   :
           Blanket staging is denied because it sweeps in unintended files (secrets, temp files,
           generated artifacts), and `sudo git add -A`, `git -C <dir> add -A` and `bash -lc "git
           add ."` all sweep exactly the same way. Stage paths explicitly with `git add <path>
           ...`, or `git add -u` for tracked-only changes.
```

```console
$ claude-hooker-gate check --project-dir repo git add -A
rules    : home/.claude/hook-rules.json
project  : repo/.claude/hook-rules.json (2 rule(s), evaluated first)
event    : PreToolUse
tool     : Bash
command  : git add -A

allow    : repo-allows-add-all (project)  [command_line command "git add -A"]
           git add -A
           ^~~~~~~~~~
reason   :
           This repository's src/generated/ tree is regenerated wholesale, so staging everything is
           the intended workflow here.
```

A project rule need not be a grant — the second rule in that overlay is a
prohibition the global file never had, and it is labelled the same way:

```console
$ claude-hooker-gate check --project-dir repo --tool Write --file-path /w/repo/src/generated/api.zig --content 'x'
rules    : home/.claude/hook-rules.json
project  : repo/.claude/hook-rules.json (2 rule(s), evaluated first)
event    : PreToolUse
tool     : Write
file_path: /w/repo/src/generated/api.zig
content  : x

deny     : repo-protects-generated (project)  [substring file_path "src/generated/"]
           /w/repo/src/generated/api.zig
                   ^~~~~~~~~~~~~~
reason   :
           src/generated/ is produced by `make codegen`; edit the generator and regenerate instead
           of hand-editing the output.
```

> ### ⚠️ A repository's `allow` pre-empts your `deny`
>
> That is not a bug — a repo knows which of its own operations are safe, and
> that is the entire point of the overlay. But it means **cloning a repository
> and starting a session in it is enough to change what your gate permits**,
> with no prompt and no diff you were shown. A committed
> `.claude/hook-rules.json` containing one `allow` rule matching `rm -rf /`
> would do exactly what it says.
>
> Two things bound it, and you should understand both:
>
> 1. **The global file decides whether overlays are read at all.** Set
>    `"allow_project_overlay": false` in `~/.claude/hook-rules.json` before
>    working in a repository you do not trust. A project file cannot flip that
>    switch for itself — only the global file's setting is ever read.
> 2. **`protect-hook-config` bounds takeover, not introduction.** The shipped
>    rule denies agent writes to _any_ path containing `hook-rules.json`, the
>    overlay included, so a model cannot widen the policy mid-session. It does
>    nothing about an overlay that was already committed before you cloned. Read
>    `.claude/` in a new repository the way you would read its `Makefile`.
>
> `check --project-dir <repo>` is how you read it: it prints the overlay path,
> how many rules it contributed, and labels every hit `(project)` or `(global)`.

When overlays are off, or the file is missing, unreadable, or invalid, `check`
says so rather than silently showing you a single-layer answer:

```console
$ claude-hooker-gate check --project-dir nowhere git add -A
rules    : home/.claude/hook-rules.json
project  : nowhere/.claude/hook-rules.json (no overlay file here)
event    : PreToolUse
tool     : Bash
command  : git add -A

deny     : no-git-add-all  [command_line command "add -A"]
           git add -A
               ^~~~~~
reason   :
           Blanket staging is denied because it sweeps in unintended files (secrets, temp files,
           generated artifacts), and `sudo git add -A`, `git -C <dir> add -A` and `bash -lc "git
           add ."` all sweep exactly the same way. Stage paths explicitly with `git add <path>
           ...`, or `git add -u` for tracked-only changes.
```

The hook behaves the same way for a broken overlay: one stderr note, then the
global rules are enforced anyway. Refusing to decide because a repo committed a
typo would let any repository switch the gate off.

---

## Install, uninstall, purge

**Use `./hookctl setup`** — it builds release, installs, and verifies; see
[the runner](#the-runner-hookctl) for the transcript. `./hookctl uninstall
[--purge]` reverses it. This section documents the installer underneath, which
is what those verbs run and what you reach for when you want its flags directly.

`zig build setup` also still works: it builds both binaries and runs the
installer against the freshly built gate, with everything after `--` passed
through.

The installer runs the **embedded** default rules through the same `selftest`
machinery an operator would, and refuses to install anything if they fail. A
shipped default that does not pass its own cases is a bug that must never reach
a machine.

```console
$ claude-hooker-install --gate ./claude-hooker-gate --claude-dir ./inst --dry-run
selftest: embedded default rules OK (497 cases, 0 lint warning(s))
claude-hooker-install plan:
  gate    : ./claude-hooker-gate -> ./inst/hooks/claude-hooker-gate
  rules   : ./inst/hook-rules.json (seed default)
  settings: ./inst/settings.json (rewrite hook entries (backup first))
    SessionStart         (all)      1 rule(s)  ADD
    PreToolUse           *          12 rule(s)  ADD
    PostToolUse          Bash       1 rule(s)  ADD
dry run: nothing written.
```

For real, it verifies by **reading back** what it wrote — a successful `write`
is not evidence that the file the gate will later load actually parses:

```console
$ claude-hooker-install --gate ./claude-hooker-gate --claude-dir ./inst
selftest: embedded default rules OK (497 cases, 0 lint warning(s))
claude-hooker-install plan:
  gate    : ./claude-hooker-gate -> ./inst/hooks/claude-hooker-gate
  rules   : ./inst/hook-rules.json (seed default)
  settings: ./inst/settings.json (rewrite hook entries (backup first))
    SessionStart         (all)      1 rule(s)  ADD
    PreToolUse           *          12 rule(s)  ADD
    PostToolUse          Bash       1 rule(s)  ADD
verify:
  ok   gate    : ./inst/hooks/claude-hooker-gate (1130240 bytes)
  ok   rules   : ./inst/hook-rules.json (14 rules, 110 cases)
  ok   settings: ./inst/settings.json (3 event(s) wired: SessionStart PreToolUse PostToolUse)
done. Hooks are snapshotted at session start — takes effect in NEW Claude Code sessions.
```

(The byte count is whatever your `zig build` produced. The rule and case counts
are `src/default-rules.json`'s: a test pins the rule count at exactly 14 — and
the per-event split at 12 `PreToolUse`, one `PostToolUse`, one `SessionStart` —
and puts floors under the `tests` block, so the numbers move only when the
shipped policy does. The verify line counts `tests` **entries** — 107 literal
cases plus three `generate` declarations — while the selftest line above counts
the 497 cases those entries actually run.)

**The plan is derived from the rules, not fixed.** One entry per event the live
policy has rules for, with a tool-name matcher covering exactly the tools those
rules name. That is not cosmetic: the single-event installer hard-wired
`"matcher": "Bash"`, and the shipped defaults include a rule on `Write` and one on
every tool — so the harness never invoked the gate for them and two shipped rules
could not fire. Deriving both halves closes that, and it holds in the other
direction too: an event whose rules are deleted is **unwired** by the next
install, so the harness stops spawning the gate on every occurrence of it to
decide nothing.

It is idempotent — run it again and it changes nothing:

```console
  rules   : ./inst/hook-rules.json (keep existing)
  settings: ./inst/settings.json (already wired for every event the rules use, no change)
    SessionStart         (all)      1 rule(s)  already wired
    PreToolUse           *          12 rule(s)  already wired
    PostToolUse          Bash       1 rule(s)  already wired
```

The entries it merges, for the shipped defaults:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "./inst/hooks/claude-hooker-gate" }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "./inst/hooks/claude-hooker-gate" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "./inst/hooks/claude-hooker-gate" }
        ]
      }
    ]
  }
}
```

`SessionStart` carries **no** `matcher` key, deliberately: on that event the
harness would compare the string against a session source rather than a tool name,
and any value invented here would silently narrow the hook to nothing. The key is
written only where the event's matcher genuinely is a tool name — see the
`Matcher` column of the [per-event table](#the-per-event-reference).

`settings.json` is rewritten through a JSON round-trip, so key order and
formatting may change; the timestamped `.bak-<epoch>` beside it preserves the
original bytes.

### Flags

| Flag                 | Effect                                                                                                                     |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `--gate <path>`      | The gate binary to install. Supplied automatically by `./hookctl setup` and `zig build setup`.                             |
| `--claude-dir <dir>` | Target directory, default `~/.claude`. Use it to install into a sandbox.                                                   |
| `--dry-run`          | Print the plan, write nothing.                                                                                             |
| `--force-rules`      | Overwrite an existing `hook-rules.json` with the embedded default. Without it, an existing rule file is **never** touched. |
| `--uninstall`        | Remove **every** gate entry from `settings.json`, on every event key (after a backup). Rules, log, and binary stay.        |
| `--purge`            | With `--uninstall`, also remove the gate binary, the decision log, and its rotated generation.                             |

Uninstall matches **our** entries by the installed gate's command path, under
every event key, so an operator's other gates, linters, and loggers in the same
arrays survive untouched, and emptied containers are dropped rather than left as
`"hooks": {"PreToolUse": []}` scars.

```console
$ claude-hooker-install --uninstall --purge --claude-dir ./inst
claude-hook-uninstall plan:
  settings: ./inst/settings.json (remove every gate entry (backup first))
  gate    : ./inst/hooks/claude-hooker-gate (REMOVE)
  log     : ./inst/hook-gate-log.jsonl (REMOVE)
  rules   : ./inst/hook-rules.json (keep — operator property, never removed)
  backup  : ./inst/settings.json.bak-1785364361
removed 1 gate entry/entries from ./inst/settings.json
  removed gate: ./inst/hooks/claude-hooker-gate
remaining:
  rules   : ./inst/hook-rules.json
  log     : ./inst/hook-gate-log.jsonl (absent)
  gate    : ./inst/hooks/claude-hooker-gate (absent)
  settings: ./inst/settings.json
done. Existing Claude Code sessions keep the snapshotted hook until they restart.
```

**`--purge` never removes the rule file.** It is the operator's own policy
document, and it is theirs to delete or keep. The `remaining:` block exists so
nobody has to guess what "uninstalled" left behind.

### macOS code signing

On macOS, a Mach-O binary whose code signature does not validate is **killed by
the kernel** — SIGKILL, no message, exit `137` if anything is watching. For a
PreToolUse hook that is the worst possible failure, because of what the hooks
contract says next: a hook that produces no decision envelope is a hook that
**allows** the tool call. So a gate with a broken signature does not become
strict. It becomes **absent**, on every single tool call, with no error, no
denial and no log line to notice. Nothing else in this system fails that
quietly, which is why the signature is checked out loud even when it is fine.

**What we sign with, and what we never do.** The signature is **ad-hoc**
(`codesign --sign -`): no identity, no certificate, no Developer ID, no
notarization, no stapling. This project is cloned and built — it ships no
binaries and no release artifacts, so there is nothing to download, nothing to
notarize, and nobody for a signature to attest to. Ad-hoc is exactly enough to
satisfy the loader on both arm64 and x86_64, and it costs nothing to reproduce
on any machine. If a future gate ever needs a real identity, that is a
distribution decision and it is not one this file is quietly making.

**What the installer does.** Zig's linker already emits an
`adhoc,linker-signed` binary, and copying a file preserves its signature — so
the installed gate normally validates the moment it lands. `claude-hooker-install`
therefore:

1. copies the gate into `<claude-dir>/hooks/`;
2. asks `codesign --verify` about the copy;
3. **re-signs it ad-hoc only if that fails**, printing the exact command it ran
   (or the exact reason it could not);
4. asks again, and reports the answer as an `ok`/`warn`/`FAIL signature:` line
   in its `verify:` block. A `FAIL` here **fails the install** — it will not
   silently leave behind a binary the OS may refuse to run.

Step 3 is deliberately conditional. Re-signing rewrites the file, which would
make the installed gate differ byte-for-byte from `zig-out/bin/claude-hooker-gate`
— and the runner compares those two to tell you when the gate enforcing your
rules is not the one you just built. Signing unconditionally would make that
warning fire on every run and mean nothing. So the invariant is kept, and the
signature is repaired exactly when it is actually broken.

**What breaks a signature.** Anything that rewrites, strips, appends to, or
patches the installed file: `strip`, an appended payload, a partial copy, a
patcher, an editor that rewrites in place. The check is not paranoia — it is the
only thing standing between one of those and a silently unguarded session.

**Checking and repairing by hand.** `./hookctl doctor` reports it as the
`signature` check, and these are the two commands it runs:

```console
$ codesign --display --verbose=2 ~/.claude/hooks/claude-hooker-gate
Executable=/Users/you/.claude/hooks/claude-hooker-gate
Identifier=claude-hooker-gate
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=2121 flags=0x20002(adhoc,linker-signed) hashes=63+0 location=embedded
Signature=adhoc

$ codesign --verify --verbose=2 ~/.claude/hooks/claude-hooker-gate
/Users/you/.claude/hooks/claude-hooker-gate: valid on disk
/Users/you/.claude/hooks/claude-hooker-gate: satisfies its Designated Requirement

$ codesign --force --sign - ~/.claude/hooks/claude-hooker-gate   # the repair
```

Both are needed, and this is the trap worth knowing: **`--display` does not
verify**. Append a single byte to a signed gate and `--display` still cheerfully
prints `Signature=adhoc`, because it reads what the signature _claims_. Only
`--verify` reads whether it still covers the bytes on disk:

```console
$ printf 'x' >> ./inst/hooks/claude-hooker-gate     # simulate a rewrite
$ codesign --verify ./inst/hooks/claude-hooker-gate
./inst/hooks/claude-hooker-gate: main executable failed strict validation
$ ./hookctl doctor --claude-dir ./inst | grep -A3 signature
FAIL  signature   ./inst/hooks/claude-hooker-gate is signed but the signature does not
                  cover the file on disk: main executable failed strict validation —
                  macOS may SIGKILL it, and a killed gate fails OPEN — no decision, no log
                  line, nothing enforced
      -> re-sign it: `/usr/bin/codesign --force --sign - ./inst/hooks/claude-hooker-gate`
         — or reinstall with `./hookctl setup`, which signs and verifies
```

Note the hedge in that message: `may` SIGKILL. Whether a given corruption is
fatal depends on which pages the kernel validates and when, so an invalid
signature is sometimes survivable — which is precisely why it must not be left
in place on the strength of "it seemed to work".

**Off macOS this whole section is a no-op.** No `codesign` is invoked, no
signing is attempted, and `doctor`'s `signature` check reports
`not applicable on linux` rather than a missing signature — a different answer
from "unsigned", because there is nothing to fix and a check that cried wolf
here would teach you to skim past it on the platform where it matters.

---

## Environment variables

| Variable                 | Read by                   | Meaning                                                                                        |
| ------------------------ | ------------------------- | ---------------------------------------------------------------------------------------------- |
| `CLAUDE_HOOK_RULES_PATH` | hook + CLI                | Rule file location. **Outranks `--rules`.**                                                    |
| `CLAUDE_HOOK_LOG_PATH`   | hook + CLI                | Decision log location. Outranks `logging.path`.                                                |
| `CLAUDE_HOOK_DISABLE`    | hook + `check` + `doctor` | Comma-separated rule names to switch off for this invocation. `doctor` `FAIL`s and names them. |
| `CLAUDE_PROJECT_DIR`     | hook + `check` + `doctor` | Repo root for the project overlay. `--project-dir` outranks it.                                |
| `HOME`                   | hook + CLI                | Last-resort base for `~/.claude/hook-rules.json` and the default log.                          |

`doctor` and `status` report the first two as a check of their own, because a
rule file being read from somewhere other than the claude dir is the kind of
thing that is obvious once said and invisible otherwise.

An explicitly empty setting (`CLAUDE_HOOK_RULES_PATH=`) is treated as _absent_
and falls through to the next source, rather than naming the empty path.

**Why the environment outranks the flag.** The operator's ambient configuration
is the authority: a CLI session must not be able to inspect a _different_ rule
file than the one the hook enforces without changing the same variable the hook
reads. `check` is only useful if it cannot lie about what the hook will do.

**Why `CLAUDE_HOOK_DISABLE` is an operator control and not an agent escape
hatch.** The gate is spawned by the Claude Code harness and inherits the
_harness's_ environment. It never sees the environment of the command it is
deciding about. An agent writing `CLAUDE_HOOK_DISABLE=no-pkill pkill -f x` only
sets a variable inside the shell the gate has not yet permitted — a child of a
decision that has not been made. Setting it for real means editing the harness's
launch environment or `settings.json`'s `env` block, which is exactly the
surface `protect-hook-config` guards. And every bypass is logged as `bypassed`,
so an override is visible after the fact rather than silent.

```console
$ CLAUDE_HOOK_DISABLE=no-git-add-all claude-hooker-gate check git add -A
rules    : home/.claude/hook-rules.json
event    : PreToolUse
tool     : Bash
command  : git add -A

bypassed : no-git-add-all  [command_line command "add -A"]
           git add -A
               ^~~~~~
           (switched off by CLAUDE_HOOK_DISABLE)
no-match : no rule fires for this input.
```

A disabled rule is stepped _over_ inside the walk rather than filtered out of a
finished result, so a disabled `deny` above an enabled `deny` still leaves the
second one enforced.

---

## How commands are parsed

Everything the seven structural kinds know comes from two passes over the one
command string the event carried, plus one pure function over the result:
`src/shell.zig` lexes it into a command model (including each invocation's
normalized option set), `src/resolve.zig` reads the values the string itself
assigns, and `src/classes.zig` normalizes a path-ish argument textually so a
class can be asked about it. The first two are lazy — a rule file with no
structural matcher never builds either, and a file with twenty builds them once
and shares them across every rule and both overlay layers. `check --explain` prints exactly what they produced, which is the only
honest way to argue with a structural rule.

### The lexer, and how far we trust it

`src/shell.zig` is a POSIX-sh **lexer**, not a shell. It implements the word
rules: `'...'` is literal, `"..."` honours `\` only before ``$ ` " \`` and a
newline, `$'...'` is ANSI-C, a backslash escapes outside quotes, `\<newline>` is
a line continuation everywhere, and `#` begins a comment at a word boundary. An
unterminated quote yields a _partial_ word plus a signal rather than an error:
this code runs on hostile-ish input on every tool call and must never fail.

Word splitting is checked against Python's `shlex` as an oracle.
`src/testdata/shell-corpus.txt` is a 259-line file carrying **186 cases** (its
`##` comments, blank lines and the `%%DIVERGENT` marker are not cases);
`tests/shlex_oracle.py` turns them into `src/testdata/shell-oracle.jsonl`, one
JSON record each — **158 `core` and 28 `divergent`**. A Zig test asserts the
lexer against that checked-in file, and asserts one record per corpus case, so a
corpus that grew without a regenerated oracle fails the build rather than
silently going unchecked. `zig build parity` re-runs the Python and diffs the
result against the checked-in copy, which is what proves the oracle's own
numbers are still what `shlex` says. `zig build check` includes parity when a
`python3` is on `PATH` and skips it silently when one is not, because the Zig
half of the assertion needs no interpreter — a Zig project's one-command gate
must not stop working on a machine without an interpreter.

The 28 `divergent` records are the deliberate disagreements, and they are
asserted to _keep_ diverging rather than being ignored. `shlex` is not a shell
either: it has no operators, no substitutions, no comments, no ANSI-C quoting
and no heredocs, and it treats a backslash inside double quotes differently from
POSIX. Where the two differ, POSIX wins and the corpus's DIVERGENCE section says
why.

### From text to invocations

One parse produces one flat list of `Command`s. A command is a **pipeline
stage** — or a command reached by unwrapping one — and carries:

| Part                            | What it is                                                                                                                                                                                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `prefix`                        | Leading reserved words that were stripped — `if` `then` `elif` `else` `while` `until` `do` `!` `{` — so `if pkill x; then` still surfaces a command word                                                                                                           |
| `assignments`                   | The `NAME=value` prefix, split out — `FOO=bar cmd` binds to that invocation only                                                                                                                                                                                   |
| `name` / `base`                 | The command word, and the command word reduced to a basename: `/usr/bin/pkill`, `./pkill` and `\pkill` all normalize to `pkill`                                                                                                                                    |
| `words`                         | The command word and its arguments, redirect targets removed                                                                                                                                                                                                       |
| `redirects`                     | Redirections, attached to the stage — `2>&1` must not look like an argument `2` and an argument `1`                                                                                                                                                                |
| `flags`                         | The **normalized option set**: which short letters appear anywhere in the invocation, how many long options and attached values it carries, and whether a bare `--` ended the options. `-vrf`, `-fr` and `-r -f` produce the same set, which is what `flags` reads |
| `connector`                     | How the stage joins the one before it: `first`, `;`, `&&`, `\|\|`, `\|`, `\|&`, `&`, newline                                                                                                                                                                       |
| `depth`, `parent`, `provenance` | Where the stage came from, and through what                                                                                                                                                                                                                        |
| `span` (per word)               | A byte range in the **original** text, so a hit found three levels down still underlines what the operator wrote                                                                                                                                                   |

Nothing is expanded. `$VAR`, `$(...)`, globs and aliases are recorded as
_syntax_; the lexer never invents a value it cannot see. What it cannot read
surfaces as a [`signal`](#signal--what-the-parser-noticed-but-could-not-resolve)
instead, which is what lets a rule treat "I cannot see this command" as its own
condition.

**Options are read as options, once.** One `Opt` per short letter and one per
long option, left to right, with `--name=value` and `-o=value` carrying their
value. A value written as the **following** word (`-C dir`, `--file x`) is
offered as that option's value _and_ stays an argument, because which of the two
it is cannot be known without a per-tool option table — the model reports both
readings rather than picking one. The bare `-` is an argument (it is stdin to
plenty of programs) and the bare `--` is the end-of-options separator; neither is
an option. A short bundle carrying a glued value (`-oLOGFILE`) is
indistinguishable from a bundle of letters, so nothing guesses: the letters are
recorded and no value is.

### The wrappers it unwraps

A gate that only sees the outermost command is stepped around in one word. So
the lexer re-lexes what a wrapper will run and records the construct that
reached it. This is the complete table as shipped, with the `provenance` value
each produces:

| Construct                                                                                          | `provenance`      | Notes                                                      |
| -------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------- |
| written directly                                                                                   | `top`             | depth 0                                                    |
| `sh` \| `bash` \| `zsh` \| `dash` \| `ksh` \| `ksh93` \| `mksh` \| `ash`, with a `-c`-bearing flag | `shell_c`         | the program **text** argument, re-lexed                    |
| `eval`                                                                                             | `eval_arg`        | every argument re-lexed; sets `eval_present`               |
| `$( ... )`                                                                                         | `command_sub`     |                                                            |
| `` ` ... ` ``                                                                                      | `backtick`        |                                                            |
| `<( ... )` / `>( ... )`                                                                            | `process_sub`     |                                                            |
| `( ... )`                                                                                          | `subshell`        |                                                            |
| `env [VAR=x ...]`                                                                                  | `env_prefix`      |                                                            |
| `sudo` / `doas`                                                                                    | `privilege`       |                                                            |
| `nohup` `setsid` `stdbuf` `nice` `ionice` `time` `chrt` `taskset`                                  | `prefix_runner`   |                                                            |
| `timeout [flags] DURATION`                                                                         | `timeout_runner`  | the duration is skipped                                    |
| `xargs`                                                                                            | `xargs_child`     |                                                            |
| `command` / `builtin` / `exec`                                                                     | `builtin_wrapper` |                                                            |
| `watch`                                                                                            | `watch_child`     | one syntax-bearing word is program text, otherwise an argv |
| `ssh`                                                                                              | `remote_shell`    | also sets `is_remote`                                      |
| `uv` `poetry` `pipx` `pnpm` `rye` `hatch` + `run`/`exec`/`dlx`, and `npx` / `bunx`                 | `project_runner`  |                                                            |
| `git` / `make` / `gmake`                                                                           | `subcommand`      | **not a process** — `add` is not a program                 |
| `docker` / `podman` + `run`/`exec`                                                                 | `container`       | flags and the image/container are skipped                  |

Two entries there earn their footnotes. `subcommand` exists so
`command_line "add -A"` can be asked of the `git` stage while `command_word`
never claims that `add` is a program: the stage is flagged `is_process = false`
and `command_word` skips it. And a subset of the wrappers — `privilege`,
`env_prefix`, `prefix_runner`, `timeout_runner`, `builtin_wrapper`,
`xargs_child` — are **transparent**: they exec the wrapped program in place, so
`curl … | sudo bash` is `curl … | bash` for every pipeline question, which is
the difference between `pipe_into_shell` firing and not.

The known imprecisions are worth naming, because they are where a rule will
surprise you: `ssh host a b c` is modelled as an argv, though ssh actually
joins the words and lets the _remote_ shell re-parse them; the `xargs`, `watch`,
`timeout`, `sudo`, `env`, `git`, `make` and `docker` flag tables are the common
options, not the complete ones, and an unknown value-taking option shifts the
command word by one; and a heredoc body is **exposed but not lexed** — a heredoc
fed to `python3` is Python, not shell, so what is reported is that one _exists_
(`heredoc_present`), not what is in it.

### The resolution pass

`shell.zig` reports `$P$K` as syntax because a variable's value is not knowable
in general. In `P=pki; K=ll; $P$K -f myserver` it _is_ knowable: the assignments
and the use are in the same string, in order, with no branching between them.
`src/resolve.zig` is that reader — straight-line constant propagation over the
parse, and nothing more:

- **No execution, no subprocess, no filesystem, no ambient environment.** A
  variable this text never assigns is unknown, full stop.
- **No branching analysis.** `if x; then P=a; else P=b; fi; $P` is two
  assignments in text order and the last one wins, which is what a straight-line
  reading says and not what the shell will do.
- **No fixed point.** Every value is resolved at the moment it is bound, so
  `A=$B; B=$A` terminates by construction rather than by a visited-set.

What it does resolve: `VAR=value` stages,
`export`/`declare`/`local`/`typeset`/`readonly VAR=value`, `env VAR=value cmd`,
assignment _prefixes_ (which bind to one invocation and must never leak to a
later stage), `$VAR` / `${VAR}` and any concatenation of literals, quoted runs
and expansions — `$P$K`, `${P}ill`, `"$P"kill`, `$P"kill"` — in the command word
**and** in every argument, so `X=-rf; rm $X /` is catchable on the flag. It also
records `alias k='cmd -f x'` and `name() { body }` and re-lexes their bodies at
the invocation that names them.

Every resolved word reports the **origin** of its value, and that origin is what
`check` prints as `via <origin>` and the log records as `origin`:

| `origin`               | Means                                                                                                                                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `literal`              | Written out; no expansion took part. Omitted from `check`'s report.                                                                                                                               |
| `resolved_var`         | The whole word was one expansion and it was known: `$CMD`, `${CMD}`.                                                                                                                              |
| `resolved_concat`      | Assembled from pieces, all known: `$P$K`, `${P}ill`, `"$P"kill`.                                                                                                                                  |
| `alias`                | The command word named an alias defined in the same text.                                                                                                                                         |
| `function`             | The command word named a shell function defined in the same text.                                                                                                                                 |
| `substitution_derived` | Some piece was a command or process substitution. Not resolved here — but `shell.zig` has already lexed the substitution's own text, so `$(which pkill)` still surfaces `which`.                  |
| `unresolved_dynamic`   | Some piece is an expansion this pass cannot read: an unknown variable, a parameter expansion with an operator, arithmetic, `$@`, or a word whose quoting made the expansion boundaries ambiguous. |

Two rules keep it from guessing, and both matter more than the extra coverage
guessing would buy. It resolves a word only when **every** expansion in it is
known — one unknown piece leaves the whole word unresolved and flagged, because
a wrong resolution would make the decision log lie about what was going to run.
And when quoting made the expansion boundaries ambiguous it refuses rather than
picks: `"$P"kill` and `$Pkill` decode to the same bytes and only the first is a
two-piece word, so when a scan of the decoded text finds a different number of
expansions than the lexer counted (`'$P'$K`), the word is left alone.

Deliberately not read, because reading them would mean guessing: parameter
expansion with an operator (`${VAR:-x}`, `${#VAR}`, `${VAR/a/b}`), arithmetic,
`$@` / `$*` / `$?`, array and associative syntax, `read VAR`, and anything a
loop or a conditional would decide.

### The caps, and what hitting one means

Every cap is a signal, not a truncation nobody hears about.

| Cap                                     | Value   | Internal flag it sets                    |
| --------------------------------------- | ------- | ---------------------------------------- |
| Input bytes                             | 128 KiB | `input_truncated`                        |
| Nesting depth                           | 8       | `depth_capped` (and so `opaque_command`) |
| Commands per parse                      | 256     | `command_cap`                            |
| Words per stage                         | 512     | `word_cap`                               |
| Assignment hops behind one value        | 8       | `chain_capped` (value left unresolved)   |
| Bytes in one resolved value             | 4096    | `value_capped` (value left unresolved)   |
| Live bindings                           | 128     | `binding_cap` (later ones not recorded)  |
| Alias/function bodies re-lexed          | 16      | `expansion_cap` (later ones not read)    |
| Tokens per reconstructed `command_line` | 256     | none — the tail is simply not compared   |

Only `depth_capped` is reachable from a rule, through `opaque_command`, and it is
the load-bearing one: a `bash -c` chain deep enough to outrun the reader reports
itself as opaque instead of quietly reporting nothing. The rest are visible in
`check --explain`'s `signals` line, which prints every flag both passes set —
including the ones with no `signal` spelling, like `alias_defined` and
`function_expanded`.

---

## Threat model

**This gate is a habit-breaker for a cooperative model. It is not a containment
boundary, and nothing in it should be relied on as one.**

That distinction is the most important sentence in this document, so here is
exactly what it means.

### What the structural kinds genuinely close

The gate shipped textual-only once, and the honest accounting of that version
was short: any transformation that preserves what the shell does while changing
what the text says defeated it. Several of those transformations are now closed,
and being precise about which is the whole point of this section.

`command_word`, `argv`, `command_line`, `flag`, `flags` and `path_class` read a
real lexer's output plus straight-line constant propagation over the one command
string ([how commands are parsed](#how-commands-are-parsed)). Every row below is a
`tests` case in a shipped rule file, not an aspiration:

| Evasion                                                                                                           | Closed by                                                             | Evidence                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Quoting.** `psql -c "DROP TABLE users"` tokenizes as `"DROP`, `TABLE`, `users"`                                 | `argv` reads the quote-stripped argument                              | `no-destructive-sql` fires; so does `DROP  TABLE` with two spaces                                                                 |
| **Wrapper evasion.** `sudo`, `bash -lc`, `env FOO=1`, `timeout 5`, `xargs`, `uv run`, `( ... )`                   | the lexer re-lexes what each wrapper runs                             | one `no-pkill` case each in `src/default-rules.json`; the [full wrapper table](#the-wrappers-it-unwraps) is longer than the cases |
| **Path / basename evasion.** `/usr/bin/pkill`                                                                     | `command_word` compares a basename                                    | a `no-pkill` case; `./pkill` and `\pkill` normalize the same way                                                                  |
| **Mention-vs-execution false positives.** `echo pkill is bad`, `cat pkill.md`, `git commit -m "stop using pkill"` | `command_word` reads command position only                            | all three are `"expect": "none"` cases                                                                                            |
| **Fragment assembly.** `P=pki; K=ll; "$P$K" -f myserver`                                                          | constant propagation over the same string                             | `no-pkill` fires; `span` is `$P$K`, `resolved` is `pkill`                                                                         |
| **Variable-borne flags and targets.** `X=-rf; rm $X /`, `D=/; rm -rf "$D"`                                        | arguments are resolved too                                            | `no-recursive-force-delete`, `no-rm-rf-home-or-root` cases                                                                        |
| **Alias / function indirection.** `alias k=pkill; k -f w`, `k() { pkill -f "$1"; }; k w`                          | bodies are re-lexed at the invocation                                 | `no-pkill` cases; `origin` is `alias` / `function`                                                                                |
| **Flag clustering.** `rm -vrf /etc/nginx`, `git push -vf origin main`                                             | `flag` reads options as options                                       | `no-rm-rf-home-or-root`, `ask-force-push-protected-branch` cases                                                                  |
| **Flag SPELLING.** `-rf`, `-fr`, `-vrf`, `-r -f`, `-Rf`, `--recursive --force`                                    | `flags` reads the invocation's option set, so the six are one pattern | the generated cross product on `no-rm-rf-home-or-root`, and `no-recursive-force-delete` in the structural fixture                 |
| **Path SPELLING.** `rm -rf ~/../`, `/usr/local/../..`, `$HOME/`, `/Users/me/..`                                   | `path_class` normalizes before it decides                             | the generated cross product over every `home_or_root` spelling                                                                    |
| **Cross-invocation false positives.** `psql -l && git commit -m "drop table x"`                                   | `invocation` co-scopes both halves                                    | `"expect": "none"` in the cookbook fixture                                                                                        |

That list is real coverage and it is worth having. What it is **not** is a
closure property.

### What still defeats it, by construction

Nothing here is exotic, and no amount of further parsing closes any of it:

- **A value supplied from the real environment.** `$CMD` set by the harness, a
  file, a previous tool call, `read VAR`. The propagation reads only what _this
  string_ assigns; a variable the string never assigns is unknown, full stop.
  `check -- '$CMD -f worker'` against the shipped defaults enforces nothing — it
  only shadow-logs the shape, which is the next section.
- **`eval` on computed text.** `eval "$(build_it)"` runs something no reader
  can name. Reported, never resolved.
- **A decoded payload.** `base64 -d p | sh`, `curl … | sh`. The program does not
  exist as text at decision time.
- **A wrapper script whose body is written elsewhere and then invoked by path.**
  `Write scripts/stop.sh`, then `sh scripts/stop.sh`. The gate sees a Write of a
  file and a Bash call naming a path; neither carries the denied command word,
  and `check -- 'sh scripts/stop.sh'` reports `no-match`.

  Two shipped shadow rules now record the two halves, and it is worth being
  precise about how much that is worth. `wrapper-script-shadow` records the
  **write** — a Write whose content names a denied command. `observe-script-file-run`
  is a `PostToolUse` rule and records the **run** — a shell handed a file rather
  than a command string, which is the only form of the question a pre-call rule
  cannot answer, because a pre-call rule records what was _proposed_ and this one
  records what actually _executed_. Adjacent in the decision log they are
  evidence; individually each is ordinary. Neither blocks, the gate does not
  claim to connect them, and the coverage is partial in a specific way:
  `./scripts/stop.sh`, executed directly without naming a shell, is not matched,
  because the engine's only wildcard is a trailing `*` on a token and "any command
  word ending in `.sh`" is not expressible. Nothing here reads the script's
  contents.

- **Branching and loops.** The propagation is straight-line by design:
  `if x; then P=a; else P=b; fi; $P` is read as two assignments in text order
  with the last one winning, which is _not_ what the shell will do. A rule that
  depended on that reading would be wrong, and a reader that pretended otherwise
  would be worse.
- **Heredoc bodies.** Modelled and exposed, deliberately not lexed — a heredoc
  fed to `python3` is Python, not shell. What is knowable is that one _exists_.
- **A working directory that moves.** `path_class` and the traversal rules read
  the path an argument _names_, and normalization is textual, so `cd / && find .`
  and `cd ~ && rm -rf .` walk past a rule that catches `find /` and `rm -rf ~`.
  Closing it needs real cwd tracking across `cd`, `pushd`, subshells and
  `&&`/`||` ordering — a second interpreter, with its own failure mode of
  confidently tracking a directory the shell did not go to. Left open, and named
  here, rather than half-done: a `cd` whose argument is itself an anchor is
  visible in `check --explain`, and the shipped rules do not pretend to see it.
- **A path this reader cannot resolve.** `$TMPDIR/x` and `$PROJECT/build` are
  relative paths as far as normalization is concerned, because the text does not
  say where they go. That direction is deliberate — a path class that guessed
  would deny scratch space — but it does mean `rm -rf "$SOMEVAR"` where the
  variable holds `/` is not caught unless the string itself assigns it.
- **A different mechanism entirely.** A `Makefile` target, a language runtime's
  `subprocess`, a tool that emits no PreToolUse event the rules cover, or the
  same action performed by a spelling nobody enumerated (`killall` for `pkill`,
  `dropdb` for `DROP DATABASE`).

The propagation targets **accidental** evasion — a model reaching for a variable
or a helper function because that is how it would naturally write the line — not
a determined adversary. An adversary has `eval` on a decoded payload, and nothing
here reads that. The reader also refuses to guess: one unreadable piece leaves a
word unresolved and flagged rather than resolved wrongly, because a wrong
resolution would make the decision log lie about what was going to run.

### The honest mitigation for the opaque half: say so out loud

The gate cannot read an opaque command. It **can** say, precisely and
mechanically, _"this command is opaque"_ — and that is what the `signal` kind is
for. It is the one thing a matcher can express that no amount of pattern-writing
can.

The shipped defaults use it exactly that way: four `log` rules, blocking
nothing, whose whole job is to put the unreadable shapes into the decision log
where an operator can count them.

| Shipped shadow rule             | Signal                    | What lands in the log                                       |
| ------------------------------- | ------------------------- | ----------------------------------------------------------- |
| `watch-eval`                    | `eval_present`            | a string was assembled and executed                         |
| `watch-pipe-into-shell`         | `pipe_into_shell`         | code nobody read was executed, including via `\| sudo bash` |
| `watch-decode-into-shell`       | `decode_into_shell`       | a payload was decoded straight into a shell                 |
| `watch-unresolved-command-word` | `unresolved_command_word` | the program was named by something the text does not assign |

Two of them at once, on a command that says nothing about what it will run:

```console
$ claude-hooker-gate check --rules src/default-rules.json -- 'eval "$(build_it)"'
rules    : src/default-rules.json
event    : PreToolUse
tool     : Bash
command  : eval "$(build_it)"

shadow   : watch-eval  [signal command "eval_present"]
           eval "$(build_it)"
           ^~~~
shadow   : watch-unresolved-command-word  [signal command "unresolved_command_word"]
           eval "$(build_it)"
                 ^~~~~~~~~~~
no-match : no rule fires for this input.
```

`opaque_command` is the union of those conditions plus `depth_capped`, for a rule
that wants one matcher instead of four. It deliberately excludes the raw
expansion signals: `P=pki; K=ll; $P$K` is indirect and perfectly readable, and
calling it opaque would be a lie — a signal that cries wolf is one an operator
learns to ignore.

This does not stop anything. It converts "the gate saw nothing" into "the gate
recorded that it could not see", which is the difference between a blind spot and
a measured one. `stats --since 7d` turns it into a number, and a number is
something an operator can act on.

### What actually mitigates, honestly

Four things, and their limits:

0. **The structural matcher kinds read what will run, not what was typed.** They
   close the table above — the cheapest evasions and the commonest
   false-positive sources — and they are **a better reader, not a boundary**: the
   list in the previous section still defeats them completely.
1. **The `field` selector catches artifacts, not just commands.** A rule on
   `content` or `file_path` sees the wrapper script _being written_ — the
   shipped `wrapper-script-shadow` does exactly this. It raises the cost of the
   detour from "one line" to "one line plus not writing it down", and it makes
   the detour _visible_ in the log. It does not prevent it.
2. **`protect-hook-config` bounds self-modification.** The gate's policy files
   are denied to every tool, on any path containing `hook-rules.json` or
   `.claude/settings.json`. Combined with rules being re-read on every call —
   an edit would take effect instantly — this is what stops "the gate that
   rewrites its own rules". It is a real, load-bearing property. It is also
   only as strong as the file-path matcher, and a determined process can move
   files.
3. **Shadow observation and the decision log.** `log` rules, `bypassed` lines,
   and `_overflow` markers mean the operator can _see_ what the policy is
   catching, what it is missing, and when someone switched it off. The control
   here is the record, not the block.

### What actually works: reasons are prompts

The gate's real mechanism is not the refusal. It is the
`permissionDecisionReason`, which is injected into the model's context
verbatim. A reason that names the concrete risk and the exact approved
alternative redirects behaviour; a reason that says "not allowed" invites a
workaround, because the model still has a task to finish and no better idea.

That is why `reason` is a required field, why an empty one is linted, and why
the [cookbook](RULES_COOKBOOK.md) spends a section on how to write one.

**The evidence is this project.** A gate built from this source was live in the
sessions that wrote it, enforcing the default rules against its own authors.
Over the course of development it blocked, repeatedly:

- `pkill` in liveness checks — the sessions used explicit PIDs and the
  `ps aux | grep '[m]yproc'` bracket trick named in the reason;
- inline `python3 -c` for JSON munging — the sessions used `jq`, which the
  reason's "use the project's harness" pointed at;
- `git add -A` — the sessions staged explicit paths;
- heredocs fed to an interpreter — the sessions wrote a real script file and ran
  it;
- writes to any `*hook-rules.json` — which is why this repository's cookbook
  fixture is named `cookbook-recipes.json`, and why proposed policy changes were
  taken to the operator rather than applied.

It happened again in the session that reconciled this documentation. Capturing a
transcript for the `no-pkill` section requires running a command containing the
word `pkill`, and `no-pkill` denies that; the reason names an alternative, and the
alternative used was the one it names — put the text in a file and run the file,
which is why every transcript on this page was captured through a checked-in
script rather than typed at the shell. Same for the `python -c` and heredoc
sections. That is not a footnote about tooling: the documentation you are reading
was written under the policy it documents, and the policy shaped how.

In every case the stated alternative was used. That is the mechanism working
exactly as designed — _and_ the honest measure of its limit: each of those
blocks could have been stepped around in one line by a model that wanted to.
Nothing forced compliance. A clearly-argued reason obtained it.

### What this is not

- **Not a sandbox.** The gate runs with the harness's privileges and can only
  see what PreToolUse hands it.
- **Not a defence against an adversarial model or a prompt-injected one.** Both
  categories defeat it trivially, per above.
- **Not a defence against a human with shell access.** They can edit the rule
  file; that is the intended operator workflow.
- **Not multi-tenant, not authenticated, not tamper-evident.** The rule file's
  and the log's file permissions are the access control.

The real boundary is elsewhere: OS permissions, the harness's own permission
prompts, credential scoping, and review. This gate sits _inside_ that boundary
and makes a cooperative agent's default path the safe one, while leaving a
record of every time the question came up.

---

## Layout

```
hookctl                              THE runner's entry point, and nothing else: `tools/` onto the
                                     import path, argv into the package, exit code out
tools/hookctl/                       the runner itself — a stdlib-only Python package, no
                                     dependencies, ever. `__init__.py` is the map; `spec.py` holds
                                     every frozen dataclass that crosses a function boundary,
                                     `discovery.py` resolves (project root, toolchain, WHICH gate
                                     binary answers), `proc.py` is the single subprocess
                                     chokepoint, `registry.py` is the one verb table that `help`,
                                     dispatch and the doc check all read, `docs.py` is README.md as
                                     an assertion about the code, `signing.py` is what `codesign`
                                     says about an install, `rulecatalog.py` is the shipped +
                                     cookbook rule catalog and its pure transforms, `rulewrite.py`
                                     is the one gate-checked pipeline every rule-file write goes
                                     through, `interact.py` is the injectable console the wizards
                                     ask questions with, and `verbs/` is one module per family
tools/hookctl/tests/                 the runner's own unit tests (`./hookctl selfcheck`, and folded
                                     into `verify`): arg parsing, discovery precedence, verb-table
                                     integrity, audit aggregation, signature verdicts, and the
                                     no-toolchain and non-macOS paths by injection
build.zig                            gate + installer + `test` / `check` / `parity` / `cross` /
                                     `setup` steps
build.zig.zon                        package manifest (version pinned to src/version.zig by a test)
README.md                            this document
RULES_COOKBOOK.md                    recipes: what each catches, what it does not, how to word it
CHANGELOG.md                         Keep-a-Changelog history, with a `Changed behavior` section
                                     per release for anything an operator would notice
LICENSE                              MIT, plus the NOTICE about shlex (see licence and attribution)
.github/workflows/ci.yml             `verify` + `audit` + a fresh-clone build on ubuntu-latest and
                                     macos-latest, with the Zig pin asserted against build.zig.zon

src/main.zig                         hook entrypoint: stdin event -> decision -> log
src/cli.zig                          operator CLI: check / selftest / stats / classes / events /
                                     doctor / status / diff-defaults / version / help, plus the
                                     lint, the test-case generators, the stats aggregator, the
                                     wiring plan, the install Layout, and the doctor facts +
                                     diagnosis
src/rules.zig                        schema, JSON loading, matching, overlay evaluation,
                                     reference expansion ($class:, $set)
src/shell.zig                        POSIX-sh lexer + structural command model, including the
                                     normalized option set (see below)
src/classes.zig                      textual path normalization + the built-in class catalog
                                     (`classes` prints it)
src/resolve.zig                      straight-line constant propagation over that model:
                                     variables, aliases, functions (see below)
src/events.zig                       THE EVENT TABLE: one descriptor per hook event — the wire
                                     name, which payload keys are matchable and by which JSON path,
                                     how (and whether) a refusal can be expressed, what its matcher
                                     means, and whether the row is verified. Dispatch, the payload
                                     parse, the response writer, the lint, the installer and the
                                     README's table all read it
src/protocol.zig                     per-event payload parsing + per-event response envelope, both
                                     driven by that table
src/decision_log.zig                 JSONL line schema, rotation, atomic append
src/install.zig                      installer: embedded-rules selftest gate, copy, seed,
                                     settings.json surgery for every event the rules use,
                                     verify-by-read-back per event
src/version.zig                      the single VERSION constant

src/default-rules.json               the 14 shipped defaults (12 PreToolUse, one PostToolUse,
                                     one SessionStart) + 107 literal and 390 generated cases,
                                     embedded and seeded on install
src/testdata/selftest-rules.json     fixture exercising every decision, every field and five
                                     events (10 rules, 19 cases)
src/testdata/structural-rules.json   fixture exercising the structural kinds (6 rules, 18
                                     literal + 13 generated cases), with the cases that pin
                                     what they do and do not match
src/testdata/cookbook-recipes.json   every RULES_COOKBOOK recipe plus its cases (24 rules,
                                     195 literal + 572 generated cases), so the cookbook
                                     cannot rot
src/testdata/stats-sample.jsonl      decision-log fixture, including one deliberately torn line
src/testdata/shell-corpus.txt        shell lexer parity corpus (186 cases), and the
                                     divergence register
src/testdata/shell-oracle.jsonl      what Python's shlex says about every corpus case
src/testdata/future-schema-rules.json  a rule file from a hypothetical LATER release: deliberately
                                     unloadable, so the schema refusal is tested against a real
                                     document rather than a contrived string
tests/shlex_oracle.py                regenerates that oracle; run by `zig build parity`
```

The two modules the structural kinds are built on — `src/shell.zig`'s lexer and
command model, and `src/resolve.zig`'s constant propagation — are described in
[how commands are parsed](#how-commands-are-parsed), including the complete
wrapper table, the `Origin` vocabulary, the shlex parity oracle, and every cap.
Each module's header comment is the canonical reference for the rest.

Tests live beside the code they exercise, at the bottom of each module.

---

## Contributing and releasing

### Before you commit

```console
$ ./hookctl verify     # unit tests + both binaries + shlex parity + doc checks
$ ./hookctl audit      # every mechanical consistency check, with its counts
```

`verify` is the gate. If you touched `./hookctl help`, the verb list, or
anything `doctor`/`status` prints, the documentation checks will fail until the
`<!-- hookctl:* -->` blocks in this file are updated to match — that is the
point of them. `./hookctl cross` additionally compiles everything for Linux
without running it, which is the cheapest way to catch a platform break from a
macOS laptop. CI runs `verify`, `audit`, `cross`, and a fresh-clone build on
both ubuntu-latest and macos-latest.

### Releasing

There are no artifacts to publish — this project is built when it is cloned —
so a release is a version bump and a tag:

1. **Bump the version in both places, together.** `.version` in
   `build.zig.zon` and `VERSION` in `src/version.zig`. Nothing in the toolchain
   ties them, so a test does: "the version constant and build.zig.zon agree"
   fails the build when they drift.
2. **Decide whether the rule-file schema moved.** If this release added a
   matcher kind, a class, a signal, a group operator, or a top-level field, bump
   the minor of `rules.SCHEMA_VERSION` and of `"schema_version"` in
   `src/default-rules.json` and the fixtures — see
   [schema versions](#schema-versions-and-compatibility). If the meaning of an
   existing construct changed, bump the major.
3. **Add a `CHANGELOG.md` entry**, with a `### Changed behavior` subsection for
   anything an operator would notice.
4. `./hookctl verify` and `./hookctl audit`, both green.
5. Tag: `git tag -a v<version> -m "<version>"` and push the tag.

Bumping the Zig requirement means editing `minimum_zig_version` in
`build.zig.zon`, `MIN_ZIG` in `hookctl`, and `ZIG_VERSION` in
`.github/workflows/ci.yml`. A test checks the first two against each other and
the workflow checks itself against the first, so all three cannot drift quietly.

---

## Licence and attribution

**MIT** — see [LICENSE](LICENSE). It was chosen because this is a small
operator tool with no dependencies whose whole value is being read, copied, and
adapted; a permissive licence with a one-paragraph text is the least friction
between someone and a rule file they need.

### The shell lexer and Python's `shlex`

Two things in this repository sit near CPython, and neither one copies it.

`src/shell.zig` **reimplements** POSIX shell word-splitting semantics — quoting,
escapes, operators, assignment prefixes, pipelines. It was written against the
POSIX shell command language specification and against observed behaviour. No
CPython source was copied, translated, or transliterated into it: the agreement
between the two is an agreement about what a shell does, which is a
specification, not an expression.

`tests/shlex_oracle.py` **calls** the standard library's `shlex` module at test
time and records what it returns. That is ordinary use of an installed library
by a program that imports it — the same relationship any script has with the
stdlib. `shlex` itself is not vendored, redistributed, or shipped: the script is
28 lines of `import shlex` and a loop, it runs only under `zig build parity`,
and it is not part of either binary.

What that means for licensing: nothing in the built artifacts derives from
CPython, so no Python licence terms attach to them. The checked-in
`src/testdata/shell-oracle.jsonl` is the _output_ of running that script over
this project's own corpus — data about behaviour, generated from inputs written
here.

---

## Roadmap

Already done, and no longer on this list: per-project rule overlays, Write/Edit
`content`/`file_path` rules, the `allow` and `log` decisions, the decision log
with rotation, `check` / `selftest` / `stats` / `classes` / `events`,
`claude-hooker-install --uninstall --purge`, the structural matcher kinds
(`command_word`, `argv`, `command_line`, `flag`, `signal`) with `check --explain`,
the `any` / `all` / `none` / `invocation` group operators, opt-in `ignore_case`,
the `doctor` / `status` / `diff-defaults` subcommands, the `hookctl` runner that
collapses the whole operator surface into one command, and **all 30 hook events
from one descriptor table**, with per-event wiring derived from the rules.

Worth considering next:

- **Context injection.** The table already records which events accept
  `additionalContext` and which accept a rewrite (`updatedInput`,
  `updatedToolOutput`, `displayContent`); none of it is written. Adding it is a
  change to the response writer rather than to the catalog, and it is deliberately
  not there yet — a gate whose job is to say no is easier to trust than one that
  edits the conversation.
- **Empirical confirmation of the four unverified rows.** `TeammateIdle`,
  `TaskCreated`, `TaskCompleted` and `SessionEnd`'s payload are inference; a
  session that actually fires them would turn four lint warnings into facts. The
  table is where the corrections go.
- **`PostToolBatch` has no matchable field**, because its payload is undocumented
  beyond the common envelope, so no rule can be written for it. One binding is all
  that is missing.
- `check --json`, for the same CI use `selftest --json` already serves.
- More than one retained log generation, if the shadow-first workflow starts
  outrunning 10 MiB.
- A `severity`/`tag` field on rules, so `stats` can group a policy by theme
  rather than only by rule name.

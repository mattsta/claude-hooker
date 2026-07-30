# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

There are no release artifacts to download. This project is built when it is
cloned — `git clone`, then `./hookctl setup` — so a version here is a tag and a
source tree, nothing else.

Two version numbers move independently:

- the **binary** version (`src/version.zig` and `build.zig.zon`), which is what
  these headings are;
- the **rule-file schema** version (`rules.SCHEMA_VERSION`, currently `1.2`),
  which only moves when the set of accepted rule documents changes. Its bump
  policy is in the [README](README.md#schema-versions-and-compatibility).

## [Unreleased]

### Added

- **The `single-entrypoint` posture: every action is one real program with
  arguments.** Two cookbook recipes, bundled, for the shop where all work
  goes through project CLIs with clean parameterization and nothing is
  assembled from shell fragments:
  - **`single-entrypoint-only`** (recipe 23) fires on any shell plumbing at
    all — `;`/`&`/newline statements, pipes, `&&`/`||` chains, redirects,
    heredocs, command substitution — seven matchers over the `shape` and
    `signal` kinds. An env-assignment prefix, a wrapper (`uv run`, `sudo`,
    `timeout`) and any number of arguments pass untouched: that IS the
    posture.
  - **`no-adhoc-stream-editors`** (recipe 24) watches the fragments the
    plumbing connects, via a new built-in `stream_editors` class (`sed`,
    `awk`, `gawk`, `mawk`, `tr`, `cut` — deliberately not `grep`: searching
    is reading).
  - Both ship as `log`, so the catalog stays conflict-free and the decision
    log measures a shop's real work before anything is refused. Graduation is
    a verb: **`rules promote NAME --to deny|ask`** raises a catalog-`log`
    rule to enforcement — the reason's observational lead-in is stripped and
    the rest enforced verbatim — and works for every watch rule, not just the
    posture. `demote` returns the catalog's `log` form exactly. A bare
    `promote` on a watch rule is refused with the `--to` spelling in the
    message, because the catalog has no enforced form to restore.

### Changed

- **Minimum Python is 3.11** for the runner and the test-time oracle. The
  entry point turns an older interpreter away with one line naming the
  version and exit 69 — never a traceback — and the platform-interpreter
  test asserts whichever side of the floor `/usr/bin/python3` falls on: a
  supported one runs the runner, an older one gets the clean refusal. A
  machine whose only python3 is older needs a newer one on PATH first.
- **One lint configuration** (`ruff.toml`): ruff's defaults plus import
  order, pyupgrade (bounded by `target-version = "py311"`, which a test pins
  to `MIN_PYTHON`), simplifications, pathlib, FURB and PGH — so `ruff check`
  asserts the same thing on every machine and in CI. `os.path` is gone from
  the runner in favour of `pathlib` everywhere except two `# noqa: PTH100`
  sites that are deliberate: `--claude-dir` values are made absolute with
  `os.path.abspath`, not `Path.resolve()`, because resolving would rewrite a
  symlinked claude dir into its target everywhere the path lands, including
  `settings.json`.

## [0.3.0] — 2026-07-30

### Added

- **Rules about the STRUCTURE of a command, not just its words: the `stage`
  and `shape` matcher kinds (rule-file schema `1.1` → `1.2`, additive).**
  - **`stage`** — one fact about an invocation's _context_: `pipe_target`
    (reads from a pipe), `pipe_source` (feeds one), `nested` (inside
    `bash -c` / a substitution / a subshell), `remote` (via ssh). A closed
    vocabulary like `signal`'s (a typo is a lint error), designed to sit
    inside an `invocation` group beside the content kinds — so "head, **as a
    pipe target**" is one binding: fires on `cat f | head`, on
    `cat f | timeout 5 head` (a wrapper inherits pipeline context) and on
    `bash -lc 'cat x | head'`, and not on `head -20 f` or `echo head | cat`.
    `remote` holds for both ssh spellings — `ssh host "rm -rf /srv"` and
    `ssh host rm -rf /srv` alike.
  - **`shape`** — a count of the parsed structure compared to a threshold:
    `"pipes > 1"`, `"statements > 1"`. Metrics: `pipes`, `statements`,
    `chains`, `stages`, `redirects`, `heredocs`, `depth`; a three-token
    grammar and nothing more. Counts read the parse, never the bytes — a `;`
    in a quoted string counts nothing, `bash -c 'a | b | c'` counts fully,
    and `cat f | sudo head` counts ONE pipe, because a wrapper-derived view
    inherits its wrapper's join (a new `Command.joins` fact in the lexer)
    rather than adding a second. When a lexer cap is hit every count is a
    floor: `>`/`>=` still conclude, `<`/`<=`/`==` refuse to fire rather than
    under-count. Evidence points at the occurrence that crossed the
    threshold, and `check --explain` prints a `shape :` line with every
    metric.
  - **Two cookbook recipes and a bundle carry it to operators**: recipe 21
    `no-pipe-to-pager` (deny `| head` / `| tail`: the cut hides the bytes
    that mattered — bound the producer instead) and recipe 22
    `watch-long-pipelines` (`pipes > 2` as `log`: measure your real pipeline
    distribution before picking a limit), bundled as `command-shape` for
    `init` and `rules add`, with new authoring-interview templates ("a
    program only in a position…", "the command's counted structure…").
    Catalog-driven edits now also RAISE a file's `schema_version` to the
    catalog's when adopting: an under-declared file would fail on an older
    gate as a syntax error instead of the version refusal the field exists
    to produce.

- **A first run that asks, and a rule file with a lifecycle.** Before this, the
  shipped defaults were take-it-or-leave-it (seeded wholesale from a file in
  `src/` nobody would think to look in), the cookbook's recipes were
  copy-paste-only despite each being held identical to a machine-readable
  fixture, and the shadow-first rollout the README teaches had no tooling at
  all. Two operator verbs close that, built on one **catalog** — the union of
  the shipped defaults and the cookbook fixture, parsed at call time and never
  hand-maintained:
  - **`./hookctl init`** — the guided first run, built for someone who has
    never seen the catalog. The unit of choice is the **bundle**: seven themed
    groups (`agent-hygiene` — the poor-engineering habits: `pkill`, inline
    `python -c` / stdin programs, whole-disk traversal from `/` or `~`;
    `machine-guards`; `git-discipline`; `opaque-execution`;
    `database-safety`; `secrets-and-config`; `observability`), each rule shown
    with a plain-language line about what it stops, answered y / n /
    s(hadow) per bundle — with an a-la-carte pass over whatever was skipped,
    a rule-by-rule mode for cherry-pickers, and a closing enforce-or-shadow
    question so the cautious rollout is one keystroke. Non-interactive
    spellings for scripts: `--profile recommended|observe|minimal`
    (`recommended` is the shipped defaults verbatim), repeatable
    `--bundle NAME`, `--shadow`, `--dry-run`, `--no-install`,
    `--force-rules`, `--yes`. An existing rule file is never replaced without
    a question (or `--force-rules`), and an aborted run — a Ctrl-D, a
    declined confirmation, a failed selftest — writes nothing.
  - **`./hookctl rules`** — the lifecycle after that. `list` (the catalog
    against your live file, grouped by bundle: installed / shadowed / edited /
    yours / available, each with its plain-language line), `show`,
    `add NAME [--shadow]` (a rule **or a whole bundle**; a rule arrives with
    its test cases and any named set it references, inserted at the catalog's
    first-match-wins position rather than appended; a bundle adds whichever
    of its rules are missing, as one write), `remove` (takes out what
    `add` brought, and only that — hand-written cases and sets stay),
    `promote` / `demote` (the mechanical ends of the shadow-first method: the
    demotion is one exactly-invertible transform, so promotion restores the
    catalog's enforced rule and its original cases deterministically), and
    `new` — an authoring interview that asks the judgement calls (event,
    consequence, what to match offered as situations rather than kind names,
    the reason with the style-guide formula in view, one must-catch and one
    must-not-catch case minimum), defaults the decision to `log` because the
    cookbook's step one is a shadow period, and replays the first case through
    `check` so the matched bytes are seen underlined before the rule is
    trusted.
  - **One write pipeline for all of it** (`rulewrite.py`): every mutation is
    selftested **by the gate binary itself** before a byte lands, the previous
    file is backed up to a timestamped `.bak-<seconds>` sibling (the
    installer's own naming), the swap is atomic, and a rejected composition is
    kept as a `.draft` sibling instead of half-landing. A mutation that
    changes which events the rules use says so, because the installer wires
    exactly the events the rule file uses.
  - **`audit` holds the curation to account**: the bundle partition and the
    per-rule blurbs must correspond to the catalog exactly (every rule in
    exactly one bundle or explicitly unbundled, every rule described, no
    stale descriptions), and every profile, every bundle, and the whole
    catalog co-adopted at once is composed and run through the real gate's
    `selftest`, with counts — so a rule renamed in either source document, a
    set that stops travelling, or two catalog rules whose cases contradict
    each other under co-adoption is a failing check rather than a surprise
    during someone's first run.

- **Process hygiene: nothing this runner starts can outlive it, and nothing a
  previous run abandoned goes unnoticed.** An orphaned `zig build test` and two
  of its compiled test binaries once spun at 100% CPU each for eleven hours and
  took a machine down, and every gate stayed green throughout — correctly, because
  the binaries that were spinning had been compiled from a half-finished refactor
  whose source no longer existed. A gate that reads the source tree cannot see
  that class of failure at all. Four mechanisms, all in the Python runner:
  - **`reap [--dry-run] [--all]`** finds this checkout's build and test processes
    and kills them **by explicit pid** — SIGTERM, a grace period, SIGKILL, then a
    check that the pids are really gone. Never a pattern: the shipped `no-pkill`
    rule is the same lesson, because any pattern broad enough to match "the
    runaway zig build" matches the process doing the matching. Default scope is
    this checkout; `--all` widens to every zig build the user owns, marking the
    ones that are not ours. Exits `1` when it found something, so `--dry-run` is
    usable as a condition, and `69` when `ps` could not be run — because "I could
    not look" must never read as "nothing is there".
  - **A `processes` check in `doctor`**, which would have caught the eleven hours
    on its first run: `FAIL` on anything orphaned (PPID 1) or pegged (>80% CPU),
    `WARN` past ten minutes, remediation `./hookctl reap`, and _not applicable_
    rather than absent where the process table cannot be read. It is contributed
    by the runner rather than by `src/cli.zig` because the gate diagnoses an
    INSTALL and this is a question about a WORKING TREE — an installed gate with
    no clone beside it has no root to compare against — and because a second
    implementation of the heuristics in Zig would be a second thing to be wrong.
    `doctor --json` merges the row into the gate's document with the tallies
    recomputed, so scripts still parse one object.
  - **Bounded runs.** Every child gets a wall-clock budget: five minutes for a
    build, test or install, thirty for `cross` (it compiles three Linux targets),
    thirty seconds for a probe. `--timeout SECONDS` or `HOOKCTL_TIMEOUT` override
    it; there is deliberately no spelling of "unbounded". Children are spawned in
    their own session so that a timeout can SIGTERM then SIGKILL the whole process
    **group** — the grandchildren surviving is precisely the bug — after which the
    group is checked for survivors and the step that timed out is named with its
    elapsed time. Exit `124`, as `timeout(1)` uses, so a killed step is
    distinguishable from a failed one. Ctrl-C kills the group too: a child in its
    own session no longer receives the terminal's SIGINT, so without that the fix
    would have become a new way to make an orphan.
  - **Auto-reap** before `setup`, `upgrade`, `check`, `build`, `test`, `parity`,
    `cross`, `verify` and `audit`, announced only when it actually killed
    something. Acting unasked is held to a higher bar than reporting: it kills
    only an orphan, or something both pegged and long-running, because a process
    at 95% CPU that started thirty seconds ago is a compile doing its job.
    `doctor` deliberately does not auto-reap — a diagnosis that tidied up first
    could never show you what you ran it to find.

- **All 30 hook events, from one descriptor table.** Rules gained an `event` key
  and the gate now answers every Claude Code hook event, not just `PreToolUse`.
  The point is the shape rather than the count: **one** `const` table in
  `src/events.zig` carries, per event, the exact wire name, which payload keys are
  matchable and by which JSON path, whether a refusal is possible and through
  which response field, the decision vocabulary that field can carry, what its
  matcher means, and whether the row is verified. Dispatch, the payload parse, the
  response writer, the config lint, the installer's wiring plan, and the README's
  reference table all read that table — so adding an event, or correcting a fact
  about one, is a row rather than a new code path. Thirty hand-written handlers
  would have been thirty places to be wrong, silently.
  - **Response envelopes are per-event, because the protocol is.**
    `hookSpecificOutput.permissionDecision` for `PreToolUse`,
    `hookSpecificOutput.decision.behavior` for `PermissionRequest`, top-level
    `decision: "block"` for the `Stop`/`UserPromptSubmit`/`PostToolUse`/
    `PostToolBatch`/`PreCompact`/`ConfigChange` family, `continue: false` for the
    task and teammate events, `action: "decline"` for MCP elicitation, and — for
    `WorktreeCreate`, the one event with no envelope at all — exit 1. Never
    `exit 2`, which the hooks contract makes mutually exclusive with the JSON that
    carries the operator's reason.
  - **A rule that cannot work is now an error rather than a silence.** A
    `deny`/`ask`/`allow` scoped to one of the **thirteen advisory** events, a
    decision the event's envelope has no field for (`ask` on `Stop`), a matcher
    reading a field the event's payload does not carry (`command` on `Stop`), a
    structural kind on a field with no shell command behind it (`command_word` on
    a prompt), or a `tool` on an event with no tool name — every one is a
    `selftest` **ERROR**. A rule on one of the four **unverified** rows
    (`TeammateIdle`, `TaskCreated`, `TaskCompleted`, `SessionEnd`'s payload) is a
    **warning**.
  - **Five new matcher fields** — `prompt`, `output`, `message`, `trigger`,
    `agent` — carrying the non-tool payloads. Textual kinds work on all of them;
    the structural kinds stay `command`-only, because a shell parser pointed at
    English is not a policy.
  - **`events` subcommand** (`./hookctl events [NAME]`), printing the catalog. Its
    `--markdown` form renders the README's per-event table, which `audit` then
    compares byte for byte.
  - **Two shipped defaults, both `log`.** `observe-script-file-run` (`PostToolUse`)
    records a shell handed a _file_ rather than a command string — the half of the
    documented wrapper-script gap that only a post-call event can answer, since a
    pre-call rule records what was proposed rather than what ran.
    `observe-session-start` (`SessionStart`) writes one line per session, so an
    empty decision log means "wired, nothing objectionable" rather than "never
    wired" — an absent gate is silent by construction.

- **macOS ad-hoc signature handling, made explicit.** Zig's linker already emits
  `adhoc,linker-signed` binaries, so this worked by accident before; any
  operation that rewrites or appends to the gate breaks the signature, macOS may
  then `SIGKILL` it, and a killed gate fails _open_ — silently, with no
  enforcement. The installer now verifies the signature after copying, re-signs
  ad-hoc only if verification fails (so an untouched binary keeps its bytes),
  re-verifies, and prints a `signature` line; a failure fails the install.
  `doctor` gained a `signature` check (eighth) with the exact re-sign command as
  its remediation. Both `codesign --display` _and_ `--verify` are consulted,
  because `--display` alone still reports `Signature=adhoc` for a binary with an
  appended byte. No Developer ID and no notarization are required or used — a
  valid non-ad-hoc signature is reported, never demanded.
- **`selfcheck`** — runs the runner's own Python tests; needs no Zig toolchain.

### Changed

- **The cookbook identity tests compare documents, not bytes.** The unit test
  that holds every cookbook recipe identical to the fixture now ignores
  whitespace outside JSON strings — and nothing else. The byte-level
  comparison was a permanent fight with formatters: the same rule sits at
  different indent depths on the page and in the fixture, and a width-limited
  formatter (Prettier included) legally wraps the two differently, so every
  markdown reformat broke the check without changing a single rule. Everything
  JSON defines as significant is still compared, so the guarantee the page
  states — copy a recipe and it behaves exactly as documented — is unchanged,
  and Prettier now owns the page's formatting outright.
- **Rule-file schema `1.0` → `1.1`.** Additive: `event` on a rule, and the five new
  matcher fields. Every `1.0` document is still valid and still means exactly what
  it meant, because `event` defaults to `PreToolUse` — which is what a file written
  before events existed _was_. A `1.1` file handed to a `1.0` gate is refused by
  version, with both versions named, rather than failing as a syntax error over the
  unknown `event` key; that refusal is the whole reason the field exists.
- **The installer wires the events the rules use, and only those.** Previously it
  hard-wired `hooks.PreToolUse` with `"matcher": "Bash"`. That was a real hole: the
  shipped defaults include a rule on `Write` and one on every tool
  (`protect-hook-config`), and a `Bash` matcher means the harness never invokes the
  gate for them — **two shipped rules could not fire on any real install, and
  nothing said so.** The plan is now derived from the live rule file: one entry per
  event with rules, with a tool-name matcher covering exactly the tools those rules
  name (`*` when any of them applies to every tool), and the `matcher` key omitted
  entirely on events where the harness would compare it against something that is
  not a tool name. It holds in reverse too — an event whose rules are deleted is
  unwired by the next install. `--uninstall` removes our entries under every event
  key.
- **`doctor`'s `wiring` check reports per event, and WARNs on a gap.** An event with
  rules that nothing wires is policy that looks complete and never runs; it is now
  a named warning rather than an invisible state. Still eight checks. `status`
  gained the same per-event line, and its `UNWIRED (rules never run):` line when
  there is a gap.
- **The decision log carries `event`.** `stats` groups by it — a second small table
  under the per-rule one — and reads a line with no `event` key as `PreToolUse`,
  which is what every line written before this release was.
- **`check` leads with the event, and takes `--event` plus one flag per new field.**
  `--prompt`, `--output`, `--message`, `--trigger`, `--agent`, named exactly as the
  matcher `field` is named. Every existing `check '<command>'` means what it always
  meant.
- **The `allow` guidance was overstated and is now correct.** A settings-level deny
  rule always beats a hook's `allow`: hooks can only ever tighten, never loosen.
  `allow` skips the permission _prompt_, and that is all it does — it is not an
  override, an escalation, or a bypass. The `selftest` warning says so too.
- **The runner is a typed package, not a script.** `hookctl` is now a 40-line
  entry point over `tools/hookctl/`: frozen dataclasses for every value that
  crosses a boundary, pure resolution in `discovery.py`, one subprocess
  chokepoint in `proc.py`, one `VERBS` table that `help`, dispatch and the
  README check all read, and 128 stdlib `unittest` tests. Every pre-existing
  verb's output was diffed byte-for-byte against the old runner; the only
  intended differences are the new `selfcheck` verb and the `signature` section
  in `setup`/`upgrade`.
- **Minimum Python is 3.9** (what macOS ships at `/usr/bin/python3`), so the
  runner works before anyone installs a newer interpreter. A test starts the
  entry point under `/usr/bin/python3` to keep that true.

## [0.2.0] — 2026-07-29

The structural-matching release. Substring matching over a command line is the
wrong primitive for a policy question — `--all` fires on `--allow-empty`, a rule
against `pkill` fires inside `# do not pkill`, and a list of spellings is always
one spelling short. Everything below follows from replacing text matching with
matching against a _parsed and resolved_ command.

### Added

- **A POSIX shell lexer** (`src/shell.zig`) — word splitting, quoting, escapes,
  operators and separators, plus the structure above the words: pipelines,
  command lists, subshells, redirections, assignment prefixes, and a normalized
  option set that knows `-rf`, `-fr`, `-r -f` and `--recursive --force` are one
  thing.
- **A `shlex` parity oracle** (`tests/shlex_oracle.py`,
  `src/testdata/shell-corpus.txt`, `src/testdata/shell-oracle.jsonl`,
  `zig build parity`). The corpus is fed to Python's stdlib `shlex` and the
  result is checked in; the lexer asserts against the checked-in copy and
  `parity` proves the copy is still what `shlex` actually says. A disagreement
  with the reference implementation is a build failure rather than an opinion,
  and the corpus growing without the oracle growing is also a build failure.
  The corpus carries a divergence register for the cases where the Zig lexer
  implements POSIX shell and `shlex` does not.
- **A resolution pass** (`src/resolve.zig`) — straight-line constant propagation
  over the command model, so `P=pki; K=ll; $P$K -f x` is catchable. It resolves
  `$VAR`/`${VAR}` and concatenations in the command word and in every argument,
  assignment prefixes with invocation-only visibility,
  `export`/`declare`/`local`/`readonly`, `env VAR=v cmd`, and re-lexed alias and
  function bodies. No execution, no filesystem, no ambient environment, no
  branching analysis, no fixed point. One unknown piece leaves the whole word
  unresolved: a wrong resolution would make the log lie about what was going to
  run.
- **Provenance on every hit** — each resolved word keeps the span of the bytes
  the operator wrote, plus an `Origin` (`literal`, `resolved_var`,
  `resolved_concat`, `alias`, `function`, `substitution_derived`,
  `unresolved_dynamic`). `check --explain` prints the parsed and resolved model.
- **Five structural matcher kinds** — `command_word`, `argv`, `command_line`,
  `flag`/`flags`, `path_class`, `signal`. They ask about things that exist in the
  model rather than in the bytes.
- **Group operators** — `any`, `all`, `none`, and `invocation`, which co-scopes
  its children to a single command in a pipeline, so `git add -A` cannot be
  satisfied by a `git` in one stage and an `-A` in another.
- **Built-in classes** (`src/classes.zig`, `claude-hooker-gate classes`) —
  `home_or_root`, `filesystem_anchor`, `shell_names`, `db_clients`,
  `package_managers`, `destructive_sql`, `traversal_commands`,
  `recursive_readers`, `recursive_mutators`. Enumerations move out of rule files
  and into the binary, behind textual path normalization: `~/../`, `$HOME/` and
  `/usr/local/../..` are reduced to what they name before anything asks which
  class they are in. Nothing here touches the filesystem.
- **File-local `sets`** — `"sets": {"protected_branches": [...]}`, referenced as
  `$name`. Resolved once at parse time by rewriting the matcher tree into
  ordinary groups, so a reference cannot behave differently from the enumeration
  it replaces; an unresolvable reference is a hard error, never an inert matcher.
- **Generated test cases** — a `generate` block takes axes (which may themselves
  name classes and sets) and expands the cross product, with a `near_miss` axis
  for the cases that must _not_ fire. Coverage grows with the class catalog
  instead of with the author's patience.
- **Two traversal tiers** — the `ask` tier for a whole-world _read_ walk from a
  filesystem anchor, and the `deny` tier for a recursive _mutation_ rooted at
  home or a system directory. A read of a bounded directory must not prompt; an
  unrecoverable recursive `chmod` must not merely prompt.
- **The decision log** (`src/decision_log.zig`) — one JSON line per hit:
  enforced, shadow (`log`), and bypassed. `span` is always recorded;
  `resolved`/`origin` are added when the hit has provenance, and are omitted
  rather than null so an older reader is unaffected. The full matched field stays
  behind `logging.log_commands` because commands and file bodies carry secrets.
  One rotation generation at `logging.max_bytes`. Everything is best-effort and
  runs after the decision is on the wire.
- **The operator CLI** — `check` (with the matched bytes underlined), `explain`,
  `selftest`, `lint`, `stats`, `classes`, `status`, `doctor`, `diff-defaults`,
  `version`. `check` goes through the same path resolution and the same
  evaluation the hook does, overlay included, so it cannot answer about a
  different file than the one being enforced.
- **`hookctl`** — one runner for the whole surface, so operating this tool does
  not require knowing that Zig exists. `setup`, `upgrade`, `uninstall`, the
  passthrough operator verbs, and the dev verbs `build`, `test`, `verify`,
  `parity`, `cross`, `fmt`, `audit`. `verify` is the pre-commit gate; `audit`
  prints every mechanical consistency check _with its counts_, which is what
  makes a quiet slide back toward hand-maintained lists visible in a diff.
- **Project rule overlays** — `$CLAUDE_PROJECT_DIR/.claude/hook-rules.json`,
  evaluated before the global rules. Only the overlay's `rules` are read; the
  global file's `allow_project_overlay` decides whether one is consulted at all,
  and a broken overlay is skipped with a note rather than being fatal, because
  otherwise any repository could switch the operator's gate off with a typo.
- **`doctor`, `status` and `diff-defaults`** — the install diagnosed with a
  remediation line per failure, the same facts on one screen, and what the
  shipped defaults gained since a rule file was seeded (without touching it).
- **Mechanically checked documentation** — the README's `./hookctl help` block is
  compared byte for byte, its verb table against the implemented verbs, and its
  `doctor`/`status` transcripts against the checks and labels the binary emits.
  Every rule JSON in `RULES_COOKBOOK.md` is asserted byte-identical to a fixture
  that runs its own cases.
- **`schema_version` on rule files**, with a compatibility gate. See _Changed
  behavior_.
- **CI** (`.github/workflows/ci.yml`) — `verify`, `audit` and a fresh-clone build
  on ubuntu-latest and macos-latest, with the pinned Zig version asserted against
  `build.zig.zon`'s `minimum_zig_version`.
- **`zig build cross` / `./hookctl cross`** — compiles the binaries _and every
  test module_ for x86_64-linux (glibc and musl) and aarch64-linux without
  running them, so a platform break is findable from a macOS laptop.
- **A `LICENSE`** (MIT) with a NOTICE stating plainly that `src/shell.zig`
  reimplements POSIX/`shlex` semantics rather than copying CPython source, and
  that `tests/shlex_oracle.py` merely calls the stdlib `shlex` as a test-time
  oracle.

### Changed behavior

Everything in this section is operator-visible.

- **Rule files may now declare `"schema_version"` (`major.minor`), and the loader
  acts on it.** A file declaring a version **newer** than the binary reads is
  **refused** — with both versions named and `./hookctl upgrade` as the remedy —
  and exits **78** (`EX_CONFIG`), a new code distinct from 65 (invalid rules).
  This closes a silent failure: unknown fields are a hard parse error, so a rule
  file from a newer gate used to fail to parse _as a whole_, and because the hook
  fails OPEN on an unreadable config, enforcement stopped completely while the
  message blamed a syntax error on a key that was perfectly valid. A file
  declaring an **older** version is accepted unchanged. A file declaring
  **nothing** — which is every rule file seeded before this release — is accepted,
  read as schema `1.0`, and reported once by `doctor` as a `WARN`; it is
  deliberately not fatal. The version is read _before_ the strict parse, or it
  would be unreachable in the case it exists for.
- **`doctor` can now `WARN` on an install that was `PASS`-clean before**, if the
  rule file predates `schema_version`. Adding one line clears it. `doctor` still
  exits 0 on warnings.
- **`status --json` gained `rules.schema_version` and `rules.schema_read`**, and
  `rules.state` gained the value `"schema_refused"`. Existing fields are
  unchanged.
- **`diff-defaults` now reports a `schema_version` section** when an operator's
  file differs from the shipped defaults — which, for any file seeded before this
  release, it does. Nothing is written; the exit code is still 0.
- **The seeded defaults now carry `"schema_version": "1.0"`.** Existing rule
  files are never rewritten, so this only affects a fresh seed (or an explicit
  `--force-rules`).
- **`home_or_root` no longer claims Linux scratch space.** `/run/user/<uid>`
  (`$XDG_RUNTIME_DIR`) and `/dev/shm` are now scratch prefixes alongside `/tmp`,
  `/var/tmp`, `/var/folders` and `/private/tmp`. Both sit under a system root, so
  a recursive delete or `chmod` inside the directory the harness itself handed
  the task used to be **denied** on Linux. The rest of `/run` and `/dev` is still
  the system.
- **`snap` is now a system root**, so `find /snap` trips the whole-world
  traversal tier on Ubuntu the way `find /usr` always did. The path-class lists
  are now the union of both platforms' roots rather than macOS's.
- **`./hookctl verify` now runs the parity oracle as its own step.** `zig build
check` folds parity in only when `zig build` finds a `python3`, and is green
  without one; `hookctl` is itself Python, so a skip there was a lie. On a machine
  where `zig` cannot find `python3`, `verify` now fails loudly instead of passing
  quietly.
- **`hookctl` and the oracle script now state UTF-8 explicitly** at every read,
  child-decode and write. The default is locale-derived — always UTF-8 on macOS,
  `ascii` under a C locale on Linux — which made both tools work on a laptop and
  raise `UnicodeDecodeError` on a runner.

### Fixed

- A rule file from a newer schema no longer takes enforcement down silently; see
  _Changed behavior_.
- `zig build parity` no longer fails on a machine with no `diff` on `PATH` with an
  opaque spawn error: the program is looked up and the failure names it.

## [0.1.0]

The first working gate: hook-mode evaluation of a PreToolUse event against a JSON
rule file, `deny`/`ask`/`allow`/`log` decisions carrying a human reason, textual
matcher kinds (`tokens`, `word`, `substring`) over the `command`, `content` and
`file_path` fields, the `claude-hooker-install` installer with `settings.json`
surgery and backups, and `CLAUDE_HOOK_RULES_PATH` / `CLAUDE_HOOK_LOG_PATH` /
`CLAUDE_HOOK_DISABLE`.

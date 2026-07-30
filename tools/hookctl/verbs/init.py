"""`init` — choose your rules, then install: the guided first run.

`setup` is the one-command path and seeds the shipped defaults wholesale. This
is the other door, and it is built for someone who has never seen this catalog:
nothing here assumes the operator knows what "the 14 shipped rules" are. The
unit of choice is the **bundle** — a themed group with a plain-language line
per rule ("pkill kills by pattern — it has killed the agent's own shell"), take
or leave each — with an a-la-carte pass for cherry-picking single rules, and a
final enforce-or-shadow question so a cautious start is one keystroke. The
steps, in order:

  1. build the binaries (the composed document is judged by the gate itself,
     so the gate has to exist first);
  2. choose — interactively (bundles / everything / minimal / rule-by-rule),
     or from flags: `--profile recommended|observe|minimal`, or one or more
     `--bundle NAME`, with `--shadow` demoting whatever was chosen to `log`;
  3. write the composition through the one validated pipeline (`rulewrite`):
     gate selftest first, timestamped backup of anything replaced, atomic swap;
  4. install, exactly as `setup` would have — the installer keeps the rule
     file that is now in place and wires precisely the events it uses.

An existing rule file is never replaced silently: interactively it is a
question (default no), non-interactively it requires `--force-rules`. And a
run that ends early — Ctrl-D, a declined confirmation, a failed selftest —
writes nothing at all; there is no half-adopted state to clean up.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from .. import argv as argv_mod
from .. import rulecatalog, rulewrite, ui
from ..interact import Aborted, Choice, Console, stdin_is_interactive
from ..rulecatalog import BUNDLES, MINIMAL_RULES, UNBUNDLED, blurb
from ..spec import (
    EX_FAIL,
    EX_UNAVAILABLE,
    EX_USAGE,
    SHIPPED_RULES_FILE,
    Bundle,
    Catalog,
    Context,
    Profile,
    RuleWrite,
    Selection,
)
from . import operator
from .passthrough import resolve_gate

#: Everything `init` understands. Anything else is refused before any work.
FLAGS = (
    "--profile",
    "--bundle",
    "--shadow",
    "--claude-dir",
    "--dry-run",
    "--no-install",
    "--force-rules",
    "--yes",
)

#: How the operator answers one take-or-leave question.
INCLUDE, SKIP, SHADOW = "y", "n", "s"

#: The interactive menu's four ways in.
BY_BUNDLE, EVERYTHING, MINIMAL, RULE_BY_RULE = (
    "bundles",
    "everything",
    "minimal",
    "rule-by-rule",
)


def parse_profile(stated: str | None) -> Profile | None:
    if stated is None:
        return None
    return Profile(stated)


def unknown_flags(args: tuple) -> tuple:
    """Anything in `args` that `init` does not understand."""
    rest = argv_mod.without_flag_value(args, "--profile")
    rest = argv_mod.without_flag_value(rest, "--bundle")
    rest = argv_mod.without_flag_value(rest, argv_mod.CLAUDE_DIR)
    for flag in ("--shadow", "--dry-run", "--no-install", "--force-rules", "--yes"):
        rest = argv_mod.without_flag(rest, flag)
    return rest


def bundled_rule_names() -> tuple:
    return tuple(name for bundle in BUNDLES for name in bundle.rules)


def decision_counts(doc: dict) -> str:
    counts: dict = {}
    for rule in doc.get("rules", []):
        decision = rulecatalog.decision_of(rule)
        counts[decision] = counts.get(decision, 0) + 1
    order = ("deny", "ask", "allow", "log")
    parts = [f"{counts[d]} {d}" for d in order if d in counts]
    return ", ".join(parts) if parts else "none"


def show_composition(doc: dict) -> None:
    rules = doc.get("rules", [])
    cases = len(doc.get("tests", []))
    ui.out()
    ui.out(f"{len(rules)} rule(s) ({decision_counts(doc)}), {cases} self-test case(s)")
    for rule in rules:
        name = rule.get("name", "?")
        ui.out(f"   {rulecatalog.decision_of(rule):<6} {name:<38} {blurb(name)}")


# ---------------------------------------------------------------------------
# the interactive choosers
# ---------------------------------------------------------------------------


def intro() -> None:
    ui.out("The gate only ever does what your rule file says. Pick a starting")
    ui.out("point — nothing is final: `./hookctl rules` adds, removes, or shadows")
    ui.out("any single rule later, and rule edits are live with no reinstall.")
    ui.out()


def method_menu(console: Console) -> str:
    bundled = len(bundled_rule_names())
    options = (
        Choice(
            BY_BUNDLE,
            f"the {len(BUNDLES)} themed bundles — see what each one stops, take or leave each",
        ),
        Choice(EVERYTHING, f"all {len(BUNDLES)} bundles at once ({bundled} rules)"),
        Choice(
            MINIMAL,
            f"just the {len(MINIMAL_RULES)} machine-guards (protect this machine and the gate itself)",
        ),
        Choice(RULE_BY_RULE, "the whole catalog, one decision per rule"),
    )
    return console.choose("How do you want to choose?", options, BY_BUNDLE)


def show_bundle(bundle: Bundle, catalog: Catalog) -> None:
    ui.out()
    ui.out(f"-- {bundle.name}: {bundle.title} --")
    for name in bundle.rules:
        entry = catalog.find(name)
        decision = entry.decision if entry is not None else "?"
        ui.out(f"   {decision:<6} {name:<36} {blurb(name)}")


def tri_state(console: Console, question: str, default: str) -> str:
    """One take-or-leave-or-shadow answer. Enter takes the stated default."""
    hint = "Y/n/s" if default == INCLUDE else "y/N/s"
    while True:
        answer = console.read(f"   {question} [{hint}]: ").strip().lower()
        if not answer:
            return default
        if answer in (INCLUDE, "yes"):
            return INCLUDE
        if answer in (SKIP, "no"):
            return SKIP
        if answer in (SHADOW, "shadow"):
            return SHADOW


def pick_rules(console: Console, catalog: Catalog, names: tuple, default: str) -> list:
    """One tri-state answer per named rule, each shown with its blurb."""
    selections: list = []
    for name in names:
        entry = catalog.find(name)
        decision = entry.decision if entry is not None else "?"
        ui.out(f"   {decision:<6} {name:<36} {blurb(name)}")
        answer = tri_state(console, f"include {name}?", default)
        if answer == INCLUDE:
            selections.append(Selection(name))
        elif answer == SHADOW:
            selections.append(Selection(name, shadow=True))
    return selections


def bundle_walkthrough(console: Console, catalog: Catalog) -> list:
    """Take-or-leave per bundle, then the leftovers, then an a-la-carte pass
    over whatever was skipped."""
    ui.out("Answer y (take it), n (leave it), or s (take it in shadow: log-only,")
    ui.out("nothing blocked until you promote it).")
    selections: list = []
    skipped: list = []
    for bundle in BUNDLES:
        show_bundle(bundle, catalog)
        answer = tri_state(console, "take this bundle?", INCLUDE)
        if answer == INCLUDE:
            selections.extend(Selection(name) for name in bundle.rules)
        elif answer == SHADOW:
            selections.extend(Selection(name, shadow=True) for name in bundle.rules)
        else:
            skipped.append(bundle)
    if UNBUNDLED:
        ui.out()
        ui.out("-- outside every bundle --")
        selections.extend(pick_rules(console, catalog, UNBUNDLED, SKIP))
    if skipped:
        ui.out()
        names = ", ".join(b.name for b in skipped)
        if console.confirm(
            f"You left out {names}. Cherry-pick single rules from those?",
            default=False,
        ):
            for bundle in skipped:
                ui.out()
                ui.out(f"-- {bundle.name}: {bundle.title} --")
                selections.extend(pick_rules(console, catalog, bundle.rules, SKIP))
    return selections


def rule_by_rule(console: Console, catalog: Catalog) -> list:
    """Every catalog rule, one decision each, grouped by its bundle."""
    ui.out("Answer y (include), n (skip), or s (include in shadow: log-only).")
    ui.out("Enter includes bundled rules and skips the unbundled extras.")
    selections: list = []
    for bundle in BUNDLES:
        ui.out()
        ui.out(f"-- {bundle.name}: {bundle.title} --")
        selections.extend(pick_rules(console, catalog, bundle.rules, INCLUDE))
    if UNBUNDLED:
        ui.out()
        ui.out("-- outside every bundle --")
        selections.extend(pick_rules(console, catalog, UNBUNDLED, SKIP))
    return selections


def mode_question(console: Console, selections: list) -> list:
    """Enforce now, or start the whole selection in shadow.

    Asked after a bundle-level choice, where the operator has not had per-rule
    shadow control. A `shadow` answer demotes everything — including bundles
    already taken as `s`, which is the same outcome twice, harmlessly.
    """
    picked = console.choose(
        "Enforce now, or watch first?",
        (
            Choice(
                "enforce",
                "deny/ask rules act immediately (shadowed bundles stay shadowed)",
            ),
            Choice(
                "shadow",
                "EVERYTHING starts as log — watch `./hookctl stats`, then `rules promote`",
            ),
        ),
        "enforce",
    )
    if picked == "shadow":
        return [Selection(s.name, shadow=True) for s in selections]
    return selections


def choose_interactively(console: Console, catalog: Catalog) -> list:
    intro()
    method = method_menu(console)
    if method == BY_BUNDLE:
        selections = bundle_walkthrough(console, catalog)
    elif method == EVERYTHING:
        selections = [Selection(name) for name in bundled_rule_names()]
    elif method == MINIMAL:
        selections = [Selection(name) for name in MINIMAL_RULES]
    else:
        return rule_by_rule(console, catalog)
    if not selections:
        return selections
    ui.out()
    return mode_question(console, selections)


# ---------------------------------------------------------------------------
# the non-interactive spellings
# ---------------------------------------------------------------------------


def compose_from_flags(
    catalog: Catalog,
    shipped_doc: dict,
    profile: Profile | None,
    bundles: tuple,
    shadow: bool,
) -> dict:
    """The document the flags describe. `--shadow` demotes whatever was chosen."""
    if profile is not None:
        doc = rulecatalog.profile_document(catalog, profile, shipped_doc)
        return rulecatalog.shadowed_document(doc) if shadow else doc
    names: list = []
    for stated in bundles:
        bundle = rulecatalog.bundle_named(stated)
        if bundle is None:
            raise KeyError(stated)
        names.extend(bundle.rules)
    return rulecatalog.compose(
        catalog, tuple(Selection(name, shadow=shadow) for name in names)
    )


# ---------------------------------------------------------------------------
# the rest of the run
# ---------------------------------------------------------------------------


def dry_run_check(ctx: Context, gate_argv: str, doc: dict, target: Path) -> int:
    """Selftest the composition somewhere disposable and report; write nothing."""
    with tempfile.TemporaryDirectory(prefix="hookctl-init-") as tmp:
        probe = Path(tmp) / "hook-rules.json"
        probe.write_text(rulewrite.render(doc), encoding="utf-8")
        result = rulewrite.selftest(ctx.process, gate_argv, probe, ctx.timeout)
    if not result.ok:
        ui.note("the composed document did not pass the gate's selftest (above).")
        return EX_FAIL
    ui.out(f"selftest : {rulewrite.summary_line(result)}")
    ui.out()
    ui.out(f"--dry-run: {target} would be written; nothing was.")
    return 0


def report_write(outcome: RuleWrite) -> None:
    if outcome.selftest is not None:
        ui.out(f"selftest : {rulewrite.summary_line(outcome.selftest)}")
    ui.out(f"wrote    : {outcome.target}")
    if outcome.backup is not None:
        ui.out(f"backup   : {outcome.backup}")


def init(ctx: Context, console: Console | None = None) -> int:
    args = argv_mod.absolutize(ctx.args)
    leftover = unknown_flags(args)
    if leftover:
        ui.rejects_flag(ctx.verb.name, leftover[0], FLAGS)
        return EX_USAGE
    try:
        profile = parse_profile(argv_mod.flag_value(args, "--profile"))
    except ValueError:
        stated = argv_mod.flag_value(args, "--profile")
        ui.note(
            f"--profile {stated!r} is not one of: "
            + ", ".join(p.value for p in Profile)
        )
        ui.note("  (or pick bundles: --bundle NAME, repeatable; `rules` lists them).")
        return EX_USAGE
    bundles = argv_mod.flag_values(args, "--bundle")
    shadow = argv_mod.has_flag(args, "--shadow")
    if profile is not None and bundles:
        ui.note("--profile and --bundle are two ways of answering the same question;")
        ui.note("  pass one or the other.")
        return EX_USAGE
    interactive = console is not None or stdin_is_interactive()
    if profile is None and not bundles and not interactive:
        ui.note("stdin is not a terminal, so the interactive walkthrough cannot run.")
        ui.note(
            "  pass --profile "
            + "|".join(p.value for p in Profile)
            + ", or --bundle NAME (repeatable; `./hookctl rules` lists the bundles)."
        )
        return EX_USAGE
    console = console or Console()
    dry = argv_mod.has_flag(args, "--dry-run")
    assume_yes = argv_mod.has_flag(args, "--yes")

    code = operator.build_release(ctx)
    if code:
        return code
    gate = resolve_gate(ctx, announce=False)
    if gate is None:
        return EX_UNAVAILABLE
    gate_argv = ctx.gate_argv(gate)

    catalog = rulecatalog.load_catalog(ctx.paths.project_root)
    shipped_doc = rulecatalog.load_doc(ctx.paths.project_root / SHIPPED_RULES_FILE)

    ui.out()
    ui.section("choose rules")
    try:
        if profile is not None or bundles:
            try:
                doc = compose_from_flags(catalog, shipped_doc, profile, bundles, shadow)
            except KeyError as unknown:
                ui.note(f"--bundle {unknown.args[0]!r} is not a bundle; they are:")
                for bundle in BUNDLES:
                    ui.note(f"  {bundle.name:<20} {bundle.title}")
                return EX_USAGE
        else:
            selections = choose_interactively(console, catalog)
            if not selections:
                ui.note("nothing selected; nothing to write.")
                return EX_FAIL
            doc = rulecatalog.compose(catalog, tuple(selections))
        show_composition(doc)

        if dry:
            ui.out()
            return dry_run_check(ctx, gate_argv, doc, ctx.paths.rules_path)

        target = ctx.paths.rules_path
        if target.exists() and not argv_mod.has_flag(args, "--force-rules"):
            ui.out()
            if not interactive:
                ui.note(f"{target} already exists; pass --force-rules to replace it")
                ui.note("  (a timestamped backup is kept either way).")
                return EX_FAIL
            if not console.confirm(
                f"{target} exists — replace it? (a timestamped backup is kept)",
                default=False,
            ):
                ui.out("kept your existing rules; nothing was written.")
                return 0

        ui.out()
        ui.section("write rules")
        outcome = rulewrite.validated_write(
            ctx.process, gate_argv, target, doc, ctx.timeout
        )
        if not outcome.ok:
            ui.note("the gate rejected the composition, so your file was not touched.")
            ui.note(f"  the rejected document is at {outcome.draft} — fix it and run")
            ui.note(f"  `./hookctl selftest --rules {outcome.draft}` until it passes.")
            return EX_FAIL
        report_write(outcome)

        installing = not argv_mod.has_flag(args, "--no-install")
        if installing and interactive and not assume_yes:
            ui.out()
            installing = console.confirm(
                "install now? (wires the gate into settings.json; new sessions only)"
            )
    except Aborted:
        ui.out()
        ui.note("aborted; nothing was written.")
        return EX_FAIL

    if installing:
        ui.out()
        ui.section("install")
        code = operator.run_installer(ctx, argv_mod.flag_only(args))
        if code:
            return code
        operator.report_signature(ctx, argv_mod.flag_only(args))

    ui.out()
    ui.out("Hooks are snapshotted at session start — the gate acts in NEW sessions.")
    ui.out("`./hookctl status` shows the install; `./hookctl rules` manages the file;")
    ui.out("rule edits are live on the gate's next call, with no reinstall.")
    if profile is Profile.observe or shadow:
        ui.out()
        ui.out("Everything is in shadow. Watch `./hookctl stats` for a few days, then")
        ui.out("promote what earned it: `./hookctl rules promote <name>`.")
    return 0

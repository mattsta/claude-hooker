"""`rules` — the rule file's whole lifecycle, after `init` or `setup` seeded it.

Adopting a catalog rule means carrying its rule object, its test cases, and
any named set it references into the live file, at the right first-match-wins
position; a shadow-first rollout means demoting decisions and rewriting test
expectations, then reversing both exactly. Every one of those moves is
mechanical, so they are verbs:

    rules [list]            the catalog against your live file: what is
                            installed, shadowed, edited, yours, or available
    rules show NAME         one rule in full: JSON, cases, sets, status
    rules add NAME          adopt a rule — with its cases and sets, inserted
                            where the catalog's order says it can fire;
                            `--shadow` adopts it as `log`
    rules remove NAME       take one out, with the cases and sets it brought
    rules promote NAME      shadow -> the catalog's enforced form, cases too
    rules demote NAME       enforced -> shadow, cases rewritten to match
    rules new               author a new rule, interviewed step by step

Every mutation goes through `rulewrite.validated_write`: the gate's own
`selftest` judges the result before a byte lands, the old file is backed up to
a timestamped sibling, and the swap is atomic. This runner never decides what a
valid rule document is — the binary that enforces it does.

`list` and `show` read; they need no gate and no toolchain. The mutations need
a gate binary (built or installed — the usual resolution) because validation is
non-negotiable.
"""

from __future__ import annotations

from pathlib import Path

from .. import argv as argv_mod
from .. import rulecatalog, rulewrite, ui
from ..interact import Aborted, Console
from ..rulecatalog import BUNDLES, UNBUNDLED, blurb, bundle_of, decision_of
from ..spec import EX_FAIL, EX_UNAVAILABLE, EX_USAGE, Catalog, Context, RuleWrite
from .passthrough import resolve_gate

SUBVERBS = ("list", "show", "add", "remove", "promote", "demote", "new")
SHADOW_FLAG = "--shadow"
TO_FLAG = "--to"


# ---------------------------------------------------------------------------
# how a live rule relates to its catalog entry
# ---------------------------------------------------------------------------


def live_state(entry, live: dict) -> str:
    """One word about a live copy of a catalog rule, for the `list` table."""
    if live == entry.rule:
        return "installed"
    if live == rulecatalog.shadowed_rule(entry.rule):
        return f"shadowed (catalog: {entry.decision})"
    return "edited (differs from the catalog copy)"


def load_live(path: Path) -> dict | None:
    return rulecatalog.load_doc(path) if path.is_file() else None


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------


def list_rules(ctx: Context, catalog: Catalog, live_doc: dict | None) -> int:
    target = ctx.paths.rules_path
    if live_doc is None:
        ui.section(f"no rule file at {target}")
        ui.out("`./hookctl init` composes one (guided); `./hookctl setup` seeds the")
        ui.out("shipped defaults. The catalog below is what either can draw on.")
    else:
        rules = live_doc.get("rules", [])
        schema = live_doc.get("schema_version", "unstated")
        ui.section(f"your rule file: {target} — {len(rules)} rule(s), schema {schema}")
        for rule in rules:
            name = rule.get("name", "?")
            entry = catalog.find(name)
            home = bundle_of(name)
            tag = home.name if home is not None else "-"
            state = (
                "yours (not in the catalog)"
                if entry is None
                else live_state(entry, rule)
            )
            ui.out(f"   {decision_of(rule):<6} {name:<38} {tag:<19} {state}")

    live_names = {r.get("name") for r in (live_doc or {}).get("rules", [])}
    available = [e for e in catalog.entries if e.name not in live_names]
    ui.out()
    if not available:
        ui.section("nothing left to adopt — your file carries every catalog rule")
        return 0
    ui.section(
        "available — `rules add <rule>` adopts one, `rules add <bundle>` a theme "
        "(`--shadow`: as log)"
    )
    missing = {e.name for e in available}
    for bundle in BUNDLES:
        wanted = [name for name in bundle.rules if name in missing]
        if not wanted:
            continue
        ui.out(f"-- {bundle.name}: {bundle.title} --")
        for name in wanted:
            entry = catalog.find(name)
            ui.out(f"   {entry.decision:<6} {name:<38} {blurb(name)}")
    leftovers = [name for name in UNBUNDLED if name in missing]
    if leftovers:
        ui.out("-- outside every bundle --")
        for name in leftovers:
            entry = catalog.find(name)
            ui.out(f"   {entry.decision:<6} {name:<38} {blurb(name)}")
    return 0


def show_rule(ctx: Context, catalog: Catalog, live_doc: dict | None, name: str) -> int:
    entry = catalog.find(name)
    live = rulecatalog.live_rule(live_doc or {}, name)
    if entry is None and live is None:
        ui.note(f"no rule named {name!r} in the catalog or in your file;")
        ui.note("  `./hookctl rules` lists both.")
        return EX_USAGE
    shown = live if live is not None else (entry.rule if entry else {})
    if entry is None:
        ui.section(f"{name} — yours (not in the catalog)")
    else:
        state = "not adopted" if live is None else live_state(entry, live)
        home = bundle_of(name)
        tag = f"bundle {home.name}" if home is not None else "no bundle"
        ui.section(f"{name} — {tag}, {entry.decision} on {entry.event}; {state}")
        if blurb(name):
            ui.out(blurb(name))
        if entry.tests:
            ui.out(
                f"carries {len(entry.tests)} case(s)"
                + (f" and set(s): {', '.join(entry.sets)}" if entry.sets else "")
            )
    ui.out(rulewrite.render(shown).rstrip("\n"))
    return 0


# ---------------------------------------------------------------------------
# the mutations
# ---------------------------------------------------------------------------


def finish_write(
    ctx: Context, outcome: RuleWrite, before: dict, after: dict, did: str
) -> int:
    """Report one validated write, plus the one consequence a file edit cannot
    carry by itself: event wiring. The installer wires exactly the events the
    rule file uses, so a mutation that changes that set needs an install pass
    before the new event's rules can ever fire."""
    if not outcome.ok:
        ui.note(f"the gate rejected the result, so {outcome.target} was not touched.")
        ui.note(f"  the rejected document is at {outcome.draft}; the selftest output")
        ui.note("  above says what is wrong with it.")
        return EX_FAIL
    ui.out(did)
    if outcome.selftest is not None:
        ui.out(f"selftest : {rulewrite.summary_line(outcome.selftest)}")
    if outcome.backup is not None:
        ui.out(f"backup   : {outcome.backup}")
    ui.out("Rule edits are live on the gate's next call — no reinstall needed.")
    grown = rulecatalog.doc_events(after) - rulecatalog.doc_events(before)
    lost = rulecatalog.doc_events(before) - rulecatalog.doc_events(after)
    if grown or lost:
        changed = ", ".join(sorted(grown | lost))
        ui.out(f"Event wiring changed ({changed}): run `./hookctl setup` to rewire")
        ui.out("settings.json — hooks are snapshotted, so new sessions pick it up.")
    return 0


def add_rule(
    ctx: Context,
    gate_argv: str,
    catalog: Catalog,
    live_doc: dict | None,
    name: str,
    shadow: bool,
) -> int:
    if catalog.find(name) is None and rulecatalog.bundle_named(name) is not None:
        return add_bundle(ctx, gate_argv, catalog, live_doc, name, shadow)
    entry = catalog.find(name)
    if entry is None:
        ui.note(f"{name!r} is neither a catalog rule nor a bundle;")
        ui.note("  `./hookctl rules` lists both.")
        return EX_USAGE
    doc = live_doc or {"schema_version": catalog.schema_version, "rules": []}
    if rulecatalog.live_rule(doc, name) is not None:
        ui.note(f"{name!r} is already in your file.")
        ui.note("  `./hookctl rules show " + name + "` prints it; `promote`/`demote`")
        ui.note("  move it between shadow and enforced.")
        return EX_FAIL
    after = rulecatalog.with_rule_added(doc, catalog, name, shadow)
    outcome = rulewrite.validated_write(
        ctx.process, gate_argv, ctx.paths.rules_path, after, ctx.timeout
    )
    how = "as log (shadow)" if shadow else f"as {entry.decision}"
    return finish_write(
        ctx,
        outcome,
        doc,
        after,
        f"added    : {name} {how}, with {len(entry.tests)} case(s)",
    )


def add_bundle(
    ctx: Context,
    gate_argv: str,
    catalog: Catalog,
    live_doc: dict | None,
    name: str,
    shadow: bool,
) -> int:
    """Adopt every rule of a bundle the file does not already carry — one
    composed document, one selftest, one write."""
    bundle = rulecatalog.bundle_named(name)
    assert bundle is not None
    doc = live_doc or {"schema_version": catalog.schema_version, "rules": []}
    missing = [n for n in bundle.rules if rulecatalog.live_rule(doc, n) is None]
    if not missing:
        ui.note(f"every rule of `{name}` is already in your file.")
        return EX_FAIL
    after = doc
    for rule_name in missing:
        after = rulecatalog.with_rule_added(after, catalog, rule_name, shadow)
    outcome = rulewrite.validated_write(
        ctx.process, gate_argv, ctx.paths.rules_path, after, ctx.timeout
    )
    how = "as log (shadow)" if shadow else "enforced"
    return finish_write(
        ctx,
        outcome,
        doc,
        after,
        f"added    : bundle {name} ({bundle.title}), {how} — " + ", ".join(missing),
    )


def remove_rule(
    ctx: Context, gate_argv: str, catalog: Catalog, live_doc: dict | None, name: str
) -> int:
    if live_doc is None or rulecatalog.live_rule(live_doc, name) is None:
        ui.note(f"{name!r} is not in your file; `./hookctl rules` lists what is.")
        return EX_USAGE
    after = rulecatalog.with_rule_removed(live_doc, catalog, name)
    outcome = rulewrite.validated_write(
        ctx.process, gate_argv, ctx.paths.rules_path, after, ctx.timeout
    )
    return finish_write(
        ctx, outcome, live_doc, after, f"removed  : {name}, with its cases"
    )


def promote_rule(
    ctx: Context,
    gate_argv: str,
    catalog: Catalog,
    live_doc: dict | None,
    name: str,
    to: str | None,
) -> int:
    return _swap_decision(
        ctx, gate_argv, catalog, live_doc, name, promoting=True, to=to
    )


def demote_rule(
    ctx: Context, gate_argv: str, catalog: Catalog, live_doc: dict | None, name: str
) -> int:
    return _swap_decision(ctx, gate_argv, catalog, live_doc, name, promoting=False)


def _swap_decision(
    ctx: Context,
    gate_argv: str,
    catalog: Catalog,
    live_doc: dict | None,
    name: str,
    *,
    promoting: bool,
    to: str | None = None,
) -> int:
    verb = "promote" if promoting else "demote"
    entry = catalog.find(name)
    if entry is None:
        ui.note(f"{name!r} is not a catalog rule, so `{verb}` cannot know its")
        ui.note("  enforced form — edit the file directly; it is yours.")
        return EX_USAGE
    live = rulecatalog.live_rule(live_doc or {}, name)
    if live is None:
        ui.note(f"{name!r} is not in your file; adopt it first: `./hookctl rules add")
        ui.note(
            f"  {name}`"
            + (" (with --shadow to start it in shadow)." if not promoting else ".")
        )
        return EX_USAGE
    if promoting and decision_of(live) != "log":
        ui.note(
            f"{name!r} is not in shadow (it is `{decision_of(live)}`); nothing to promote."
        )
        return EX_FAIL
    if promoting and entry.decision == "log" and to is None:
        # A watch rule has no enforced form the catalog can restore; the
        # operator has to say what enforcement means.
        ui.note(f"{name!r} ships as `log` — the catalog has no enforced form to")
        ui.note(f"  restore. Say what enforcement means: `rules promote {name}")
        ui.note("  --to deny` (or `--to ask`).")
        return EX_USAGE
    if promoting and entry.decision != "log" and to is not None:
        ui.note(f"{name!r} has an enforced form the catalog already knows")
        ui.note(f"  (`{entry.decision}`); drop --to and it will be restored exactly.")
        return EX_USAGE
    if not promoting and decision_of(live) == "log":
        ui.note(f"{name!r} is already `log`; nothing to demote.")
        return EX_FAIL
    assert live_doc is not None
    if promoting:
        after = rulecatalog.with_rule_promoted(live_doc, catalog, name, to)
    else:
        after = rulecatalog.with_rule_demoted(live_doc, catalog, name)
    outcome = rulewrite.validated_write(
        ctx.process, gate_argv, ctx.paths.rules_path, after, ctx.timeout
    )
    enforced = to if to is not None else entry.decision
    did = (
        f"promoted : {name} — now `{enforced}`"
        + ("" if to is not None else ", catalog cases restored")
        if promoting
        else f"demoted  : {name} — now `log`, cases rewritten for shadow"
    )
    return finish_write(ctx, outcome, live_doc, after, did)


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


def usage() -> int:
    ui.note("usage: ./hookctl rules [list | show NAME | add NAME [--shadow] |")
    ui.note("         remove NAME | promote NAME [--to deny|ask] | demote NAME | new]")
    return EX_USAGE


def rules(ctx: Context, console: Console | None = None) -> int:
    args = argv_mod.without_flag_value(
        argv_mod.absolutize(ctx.args), argv_mod.CLAUDE_DIR
    )
    shadow = argv_mod.has_flag(args, SHADOW_FLAG)
    args = argv_mod.without_flag(args, SHADOW_FLAG)
    to = argv_mod.flag_value(args, TO_FLAG)
    args = argv_mod.without_flag_value(args, TO_FLAG)
    for arg in args:
        if arg.startswith("-"):
            ui.rejects_flag(
                ctx.verb.name, arg, (SHADOW_FLAG, TO_FLAG, argv_mod.CLAUDE_DIR)
            )
            return EX_USAGE
    sub = args[0] if args else "list"
    name = args[1] if len(args) > 1 else None
    if sub not in SUBVERBS or len(args) > 2:
        return usage()
    if sub in ("show", "add", "remove", "promote", "demote") and name is None:
        return usage()
    if sub in ("list", "new") and name is not None:
        return usage()
    if shadow and sub != "add":
        ui.note(f"{SHADOW_FLAG} only means something on `rules add`.")
        return EX_USAGE
    if to is not None and sub != "promote":
        ui.note(f"{TO_FLAG} only means something on `rules promote`.")
        return EX_USAGE
    if to is not None and to not in ("deny", "ask"):
        ui.note(f"{TO_FLAG} takes `deny` or `ask`; enforcement cannot mean `log`,")
        ui.note("  and `allow` is a grant, not an enforcement — write it by hand.")
        return EX_USAGE

    catalog = rulecatalog.load_catalog(ctx.paths.project_root)
    live_doc = load_live(ctx.paths.rules_path)

    if sub == "list":
        return list_rules(ctx, catalog, live_doc)
    if sub == "show":
        assert name is not None
        return show_rule(ctx, catalog, live_doc, name)

    gate = resolve_gate(ctx)
    if gate is None:
        return EX_UNAVAILABLE
    gate_argv = ctx.gate_argv(gate)

    if sub == "new":
        from .author import author  # local import: the wizard is large and rare

        try:
            return author(ctx, gate_argv, catalog, live_doc, console or Console())
        except Aborted:
            ui.out()
            ui.note("aborted; nothing was written.")
            return EX_FAIL
    assert name is not None
    if sub == "add":
        return add_rule(ctx, gate_argv, catalog, live_doc, name, shadow)
    if sub == "remove":
        return remove_rule(ctx, gate_argv, catalog, live_doc, name)
    if sub == "promote":
        return promote_rule(ctx, gate_argv, catalog, live_doc, name, to)
    return demote_rule(ctx, gate_argv, catalog, live_doc, name)

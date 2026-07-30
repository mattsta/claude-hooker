"""`rules new` — authoring a rule as an interview instead of a JSON exercise.

The cookbook ends with a four-step method: write it as `log`, prove it fires,
prove it does not over-fire, then promote it. Every step of that is mechanical
except the judgement calls, so this wizard asks exactly the judgement calls —
which event, which consequence, what to match (offered as the situations the
matcher kinds exist for, not as kind names), why (with the reason style guide
in front of the answer box), and the cases that prove both halves — and does
all the bookkeeping itself.

The wizard writes through the same validated pipeline as every other mutation:
the gate's `selftest` judges the finished document, a rejected draft is kept
for fixing rather than thrown away, and on success the first must-catch case is
run back through `check` so the operator sees the matched bytes underlined
before they trust it.

Two defaults are policy:

  * the decision defaults to `log`, because the cookbook's step one is a
    shadow period and a wizard should make the recommended path the lazy path;
  * at least one must-catch case and one must-not-catch case are required,
    because a rule whose over-fire boundary was never stated is the rule that
    gets worked around a week later.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .. import rulecatalog, rulewrite, ui
from ..interact import Choice, Console
from ..spec import EX_FAIL, Catalog, Context, RunMode

NAME_SHAPE = re.compile(r"^[a-z][a-z0-9-]*$")

#: The events whose payload carries a shell command, i.e. where the structural
#: matcher kinds mean anything. Everything else gets the textual templates.
COMMAND_EVENTS = ("PreToolUse", "PostToolUse")

#: The events that carry a tool name at all.
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PermissionRequest")

#: Which payload field a non-command event is most likely matching on. The gate
#: (`events`) is the authority; this is only the default an Enter accepts.
LIKELY_FIELD = {
    "UserPromptSubmit": "prompt",
    "SessionStart": "trigger",
    "PreCompact": "trigger",
    "Notification": "message",
    "Stop": "message",
    "SubagentStop": "message",
}

DECISIONS = (
    Choice("log", "shadow: record hits, block nothing — the recommended first version"),
    Choice("deny", "refuse, with your reason shown to the model and the user"),
    Choice("ask", "pause the call until the operator says yes"),
    Choice(
        "allow", "skip the permission prompt (hooks can only tighten — read the docs)"
    ),
)

OBSERVATIONAL_PREFIX = "Observational only — this is NOT blocked. "


def ask_event(console: Console) -> str:
    ui.out("Which hook event does this rule read? `./hookctl events` lists all 30")
    ui.out("with what each one carries and what it can refuse.")
    return console.ask("event", default="PreToolUse")


def ask_tool(console: Console, event: str) -> str | None:
    if event not in TOOL_EVENTS:
        return None
    return console.ask("tool it applies to (`*` means every tool)", default="Bash")


def ask_name(console: Console, taken: frozenset) -> str:
    while True:
        name = console.ask("rule name (lowercase-with-dashes, e.g. no-npm-publish)")
        if not NAME_SHAPE.match(name):
            ui.out(
                "   names are lowercase letters, digits and dashes, starting with a letter."
            )
            continue
        if name in taken:
            ui.out(
                f"   {name!r} already exists (in your file or the catalog); pick another."
            )
            continue
        return name


def ask_reason(console: Console, decision: str) -> str:
    ui.out("The reason is the mechanism: Claude Code shows it to the model verbatim,")
    ui.out("so a good one redirects instead of merely refusing. Two sentences:")
    ui.out("  1. the concrete risk — what happens, to what;")
    ui.out("  2. the approved alternative, as an exact `backticked` command.")
    while True:
        reason = console.ask("reason").strip()
        if reason:
            break
        ui.out("   a rule with no reason is a bare refusal; that is the thing this")
        ui.out("   tool exists to avoid. One sentence minimum.")
    if decision == "log" and not reason.startswith("Observational"):
        reason = OBSERVATIONAL_PREFIX + reason
    return reason


# ---------------------------------------------------------------------------
# matchers, offered as situations
# ---------------------------------------------------------------------------


def command_templates() -> tuple:
    return (
        Choice("program", "a program must never run, however it is wrapped or spelled"),
        Choice("option", "a program is fine; one of its options is not"),
        Choice(
            "argument", "a phrase in any single argument (quotes are stripped first)"
        ),
        Choice(
            "invocation", "an exact invocation shape: a subcommand and its arguments"
        ),
        Choice(
            "position", "a program only in a position: fed by a pipe, remote, nested"
        ),
        Choice(
            "structure", "the command's counted structure: too many pipes/statements"
        ),
        Choice("path", "edits to a particular file or path (whatever tool writes it)"),
        Choice("bytes", "raw bytes anywhere in a payload field"),
        Choice("json", "I will type the matcher JSON myself"),
    )


def textual_templates() -> tuple:
    return (
        Choice("bytes", "raw bytes anywhere in a payload field"),
        Choice("word", "a word with boundaries on both sides of it"),
        Choice("json", "I will type the matcher JSON myself"),
    )


def ask_matcher(console: Console, event: str) -> tuple[dict, str]:
    """One match entry, and the payload field a test case should exercise."""
    if event in COMMAND_EVENTS:
        picked = console.choose(
            "What is this rule about?", command_templates(), "program"
        )
    else:
        picked = console.choose(
            "What is this rule about?", textual_templates(), "bytes"
        )

    if picked == "program":
        program = console.ask(
            "program name (a trailing `*` prefix-matches, e.g. python*)"
        )
        return {"kind": "command_word", "value": program}, "command"
    if picked == "option":
        program = console.ask("program name")
        option = console.ask(
            "the option set (e.g. `rf`, `--force`, or `A|--all` for alternate spellings)"
        )
        return (
            {
                "invocation": [
                    {"kind": "command_word", "value": program},
                    {"kind": "flags", "value": option},
                ]
            },
            "command",
        )
    if picked == "argument":
        phrase = console.ask("the phrase (matched inside one argument, case as typed)")
        return {"kind": "argv", "value": phrase}, "command"
    if picked == "invocation":
        program = console.ask("program name")
        run = console.ask("the anchored token run after it (e.g. `add -A`)")
        return (
            {
                "invocation": [
                    {"kind": "command_word", "value": program},
                    {"kind": "command_line", "value": run},
                ]
            },
            "command",
        )
    if picked == "position":
        program = console.ask("program name (a trailing `*` prefix-matches)")
        ui.out(
            "   positions: pipe_target (reads from a pipe), pipe_source (feeds one),"
        )
        ui.out(
            "              nested (inside bash -c / a substitution), remote (via ssh)"
        )
        where = console.ask("position", default="pipe_target")
        return (
            {
                "invocation": [
                    {"kind": "command_word", "value": program},
                    {"kind": "stage", "value": where},
                ]
            },
            "command",
        )
    if picked == "structure":
        ui.out("   metrics: pipes, statements (`;`/`&`/newline joins), chains (&&/||),")
        ui.out(
            "            stages, redirects, heredocs, depth — compared as `<metric> <op> <n>`"
        )
        spec = console.ask("comparison", default="pipes > 1")
        return {"kind": "shape", "value": spec}, "command"
    if picked == "path":
        fragment = console.ask("the path or fragment (e.g. `prod.env` or `.claude/`)")
        return {
            "kind": "substring",
            "field": "file_path",
            "value": fragment,
        }, "file_path"
    if picked == "word":
        field = ask_field(console, event)
        word = console.ask("the word")
        return {"kind": "word", "field": field, "value": word}, field
    if picked == "bytes":
        field = ask_field(console, event)
        fragment = console.ask("the bytes")
        return {"kind": "substring", "field": field, "value": fragment}, field
    while True:
        raw = console.ask("matcher JSON (one object)")
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as broke:
            ui.out(f"   not JSON: {broke}")
            continue
        if isinstance(entry, dict):
            return entry, entry.get("field", default_field(event))
        ui.out("   a matcher is a JSON object.")


def default_field(event: str) -> str:
    if event in COMMAND_EVENTS:
        return "command"
    return LIKELY_FIELD.get(event, "message")


def ask_field(console: Console, event: str) -> str:
    ui.out(
        "   fields: command, content, file_path, prompt, output, message, trigger, agent"
    )
    return console.ask("field to read", default=default_field(event))


def ask_matchers(console: Console, event: str) -> tuple[list, str]:
    entries: list = []
    field = default_field(event)
    while True:
        entry, field = ask_matcher(console, event)
        entries.append(entry)
        if not console.confirm(
            "add another condition that must ALSO hold?", default=False
        ):
            return entries, field


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------


def build_case(
    event: str, tool: str | None, field: str, value: str, expect: str, name: str | None
) -> dict:
    """One selftest case in the shape the rule will actually be asked about."""
    case: dict
    if event == "PreToolUse" and field == "command" and tool in (None, "Bash"):
        case = {"command": value}
    elif field == "file_path":
        writer = tool if tool not in (None, "*") else "Write"
        case = {"input": {"tool": writer, "file_path": value, "content": ""}}
    elif event in COMMAND_EVENTS:
        case = {"input": {"event": event, "tool": tool or "Bash", "command": value}}
    else:
        case = {"input": {"event": event, field: value}}
    case["expect"] = expect
    if name is not None:
        case["expect_rule"] = name
    return case


def ask_cases(
    console: Console, event: str, tool: str | None, field: str, decision: str, name: str
) -> tuple[list, str | None]:
    """At least one case for each half of the claim. Returns (cases, demo)."""
    enforced = decision in ("deny", "ask", "allow")
    if not enforced:
        ui.out("This rule is `log`, so its cases assert `none` (shadow never blocks);")
        ui.out("`./hookctl check` is what shows a shadow hit explicitly.")
    catches: list = []
    while True:
        value = console.ask(
            f"a {field} this rule MUST catch"
            + (" (blank when done)" if catches else "")
        )
        if not value:
            if catches:
                break
            ui.out(
                "   at least one — a rule nothing exercises is a rule nobody can trust."
            )
            continue
        catches.append(
            build_case(
                event,
                tool,
                field,
                value,
                decision if enforced else "none",
                name if enforced else None,
            )
        )
    misses: list = []
    while True:
        value = console.ask(
            f"a {field} it must NOT catch" + (" (blank when done)" if misses else "")
        )
        if not value:
            if misses:
                break
            ui.out("   at least one — the near-miss is the promise the rule is not")
            ui.out("   over-broad, and the file keeps that promise from then on.")
            continue
        misses.append(build_case(event, tool, field, value, "none", None))
    demo = None
    if event == "PreToolUse" and field == "command" and tool in (None, "Bash"):
        demo = str(catches[0]["command"])
    return catches + misses, demo


# ---------------------------------------------------------------------------
# the interview
# ---------------------------------------------------------------------------


def author(
    ctx: Context,
    gate_argv: str,
    catalog: Catalog,
    live_doc: dict | None,
    console: Console,
) -> int:
    ui.section("author a rule")
    ui.out("Enter accepts the [default]; Ctrl-D aborts and writes nothing. The")
    ui.out("RULES_COOKBOOK is the long form of everything asked here.")
    ui.out()

    event = ask_event(console)
    tool = ask_tool(console, event)
    decision = console.choose("What happens on a hit?", DECISIONS, "log")
    entries, field = ask_matchers(console, event)

    taken = frozenset(
        {r.get("name") for r in (live_doc or {}).get("rules", [])}
        | set(catalog.names())
    )
    name = ask_name(console, taken)
    reason = ask_reason(console, decision)
    cases, demo = ask_cases(console, event, tool, field, decision, name)

    rule: dict = {"name": name}
    if event != "PreToolUse":
        rule["event"] = event
    if tool is not None:
        rule["tool"] = tool
    rule["decision"] = decision
    rule["reason"] = reason
    if len(entries) == 1:
        rule["match"] = entries
    else:
        rule["match_all"] = entries

    target = choose_target(ctx, console)
    doc = (
        rulecatalog.load_doc(target)
        if target.is_file()
        else {"schema_version": catalog.schema_version, "rules": []}
    )
    after = dict(doc)
    after["rules"] = list(doc.get("rules", [])) + [rule]
    after["tests"] = list(doc.get("tests", [])) + cases

    ui.out()
    ui.section("selftest, then write")
    outcome = rulewrite.validated_write(
        ctx.process, gate_argv, target, after, ctx.timeout
    )
    if not outcome.ok:
        ui.note("the gate rejected the rule, so nothing of yours was touched.")
        ui.note(f"  your draft is at {outcome.draft}; the selftest output above says")
        ui.note(f"  why. Fix it, then `./hookctl selftest --rules {outcome.draft}`.")
        return EX_FAIL
    ui.out(f"selftest : {rulewrite.summary_line(outcome.selftest)}")
    ui.out(f"wrote    : {target}")
    if outcome.backup is not None:
        ui.out(f"backup   : {outcome.backup}")

    if demo is not None:
        ui.out()
        ui.section("what the gate now says about your first case")
        ctx.process.run(
            (gate_argv, "check", "--rules", str(target), demo),
            mode=RunMode.inherit,
            timeout=ctx.timeout,
        )

    ui.out()
    ui.out("Rule edits are live on the gate's next call. If this rule's event was")
    ui.out("not in your file before, run `./hookctl setup` to wire it (new sessions).")
    if decision == "log":
        ui.out("It is in shadow: watch `./hookctl stats`, and when it has earned")
        ui.out("enforcement, change its `decision` to `deny` or `ask` in the file.")
    return 0


def choose_target(ctx: Context, console: Console) -> Path:
    overlay = Path.cwd() / ".claude" / "hook-rules.json"
    picked = console.choose(
        "Where does this rule live?",
        (
            Choice("global", f"{ctx.paths.rules_path} — every session on this machine"),
            Choice("project", f"{overlay} — this repository's overlay (rules only)"),
        ),
        "global",
    )
    return ctx.paths.rules_path if picked == "global" else overlay

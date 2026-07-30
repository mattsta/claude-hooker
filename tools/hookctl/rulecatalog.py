"""The rule catalog: every rule this repository ships or documents, adoptable.

Two documents carry a tested, documented rule for most things an operator
wants: the shipped defaults (`src/default-rules.json`, what `setup` seeds
wholesale) and the cookbook fixture (`src/testdata/cookbook-recipes.json`,
which a unit test holds identical to every recipe the RULES_COOKBOOK
documents). This module reads both into one `Catalog` and provides the pure
transforms `init` and `rules` are built from: compose a rule file from a
selection, demote a rule (or a whole document) to shadow, adopt a rule into a
live file at the position where it can actually fire, and remove one along
with everything it brought.

Everything here is a function from JSON to JSON. Nothing reads argv, nothing
prints, nothing spawns — the gate's own `selftest` is the judge of what this
produces, and the callers run it on every composed document before a byte lands
in the operator's file. The audit composes and selftests every named profile
and the whole catalog, so a change to either source document that breaks a
composition is a failing check rather than a surprise during someone's
first-run.

A deliberate limit: rules are carried VERBATIM. The one transform this module
performs on a rule is the shadow demotion (`decision` -> `log`, with a stated
prefix on the reason), and it is exactly invertible, which is what makes
`rules promote` the mechanical end of the shadow-first rollout the README
teaches. There is no other rewriting, because a catalog that "improved" rules
in flight would be a second schema owner; the gate is the only one.
"""

from __future__ import annotations

import json
from pathlib import Path

from .spec import (
    COOKBOOK_RULES_FILE,
    ENCODING,
    SHIPPED_RULES_FILE,
    Bundle,
    Catalog,
    CatalogRule,
    Profile,
    RuleOrigin,
    Selection,
)

#: What a rule means when it does not say. These are the gate's own defaults
#: (`rules.zig`), restated here because the catalog has to group and display
#: rules that rely on them; the gate's `selftest` remains the authority.
DEFAULT_EVENT = "PreToolUse"
DEFAULT_DECISION = "deny"

#: Prepended to a demoted rule's reason. The reason never reaches the wire while
#: the rule is `log`, but it is what `check` and the operator read; and because
#: the demotion is this exact prefix and nothing else, `rules promote` can
#: restore the catalog's rule and recognise the shadow-period tests it planted.
SHADOW_PREFIX = "Observational while shadowed — nothing is blocked yet. "

#: The lead-in the cookbook's style guide gives every `log` rule's reason.
#: For a catalog rule that ships as `log` on purpose — the watch rules, the
#: single-entrypoint posture — `rules promote NAME --to deny|ask` strips
#: exactly this sentence, so the enforced reason reads as enforcement without
#: anyone re-writing it.
OBSERVATIONAL_PREFIX = "Observational only — this call is NOT blocked. "

#: The `minimal` profile: the rules that guard the machine and the gate itself,
#: plus the session marker that makes an empty decision log mean "wired, nothing
#: objectionable" instead of "never wired". Everything else the defaults ship is
#: workflow discipline, which an operator can reasonably want to opt into later.
#: The audit composes and selftests this tuple, so a renamed rule cannot leave
#: it silently pointing at nothing.
MINIMAL_RULES: tuple[str, ...] = (
    "no-pkill",
    "deny-recursive-mutation-from-anchor",
    "protect-hook-config",
    "observe-session-start",
)

#: How wide a rule's one-line gist may be in a table.
GIST_WIDTH = 66

#: One plain-language line per catalog rule: what it stops, in the words a
#: first-time operator has — not the rule's reason (written for the model at
#: refusal time) and not its name (written for a log line). These are what
#: `init` and `rules list` print beside a rule, so choosing does not require
#: already knowing the catalog. Curated by hand; the audit holds this dict and
#: the catalog to exact correspondence, so a renamed or added rule that is not
#: described here is a failing check.
RULE_BLURBS: dict = {
    "no-pkill": "pkill kills by pattern — it has killed the agent's own shell",
    "no-inline-python": "`python -c` / stdin one-liners: throwaway code nobody reviews",
    "no-heredoc-python": "a heredoc piped into python — the same habit in disguise",
    "ask-whole-world-traversal": "find/grep/du from `/` or `~` floods context; asks first",
    "no-rm-rf-home-or-root": "recursive delete rooted at `/`, `~`, or a system dir",
    "deny-recursive-mutation-from-anchor": "recursive chmod/chown/rsync/find -delete from `/` or `~`",
    "ask-sudo": "anything under sudo waits for the operator's yes",
    "no-git-add-all": "`git add -A` / `git add .` sweep in secrets and junk",
    "no-git-sweep-discard": "`git reset --hard` / `checkout .` destroy uncommitted work",
    "ask-force-push-protected-branch": "force-pushing main/master waits for a yes",
    "no-pipe-to-shell": "`curl | bash` executes code nobody has read",
    "watch-pipe-into-shell": "logs any download or decode piped into a shell",
    "watch-decode-into-shell": "logs `base64 -d | sh` — payload-shaped decoding",
    "watch-eval": "logs `eval` — the command text hides what actually runs",
    "watch-unresolved-command-word": "logs `$CMD ...` where nothing says what $CMD is",
    "no-destructive-sql": "DROP/TRUNCATE handed to a database client is denied",
    "watch-destructive-sql": "logs file writes whose content names DROP/TRUNCATE",
    "protect-hook-config": "the agent cannot rewrite the gate's own rule files",
    "deny-mid-session-hook-config-change": "hook config cannot be changed under a live session",
    "deny-prompt-private-key": "a prompt carrying a private key is stopped at the door",
    "observe-session-start": "one log line per session — 'wired and quiet' ≠ 'not wired'",
    "observe-script-file-run": "logs a shell handed a FILE: what ran is what the file said",
    "wrapper-script-shadow": "logs writes whose content names a denied command",
    "no-pipe-to-pager": "`... | head` / `| tail` discard the bytes that mattered",
    "watch-long-pipelines": "logs pipelines over 3 stages — measure before you limit",
    "single-entrypoint-only": "logs any shell plumbing at all — one real program, arguments only",
    "no-adhoc-stream-editors": "logs sed/awk/tr/cut — the fragments ad-hoc programs are built from",
    "allow-repo-clean-scratch": "EXAMPLE allow carve-out (`make clean-scratch`) — edit before adopting",
}

#: The themed bundles `init` offers and `rules add` accepts by name. Each
#: catalog rule appears in exactly one bundle, except the entries in
#: `UNBUNDLED` (deliberate: an example `allow` rule is a template, not a
#: policy). The audit enforces the partition and selftests every bundle's
#: composition, so this curation cannot quietly rot as the catalog grows.
BUNDLES: tuple = (
    Bundle(
        "agent-hygiene",
        "break the agent's worst shell habits",
        (
            "no-pkill",
            "no-inline-python",
            "no-heredoc-python",
            "ask-whole-world-traversal",
        ),
    ),
    Bundle(
        "machine-guards",
        "nothing irreversible happens to this machine",
        (
            "no-rm-rf-home-or-root",
            "deny-recursive-mutation-from-anchor",
            "ask-sudo",
        ),
    ),
    Bundle(
        "git-discipline",
        "no blanket staging, no tree wipes, no history rewrites",
        (
            "no-git-add-all",
            "no-git-sweep-discard",
            "ask-force-push-protected-branch",
        ),
    ),
    Bundle(
        "opaque-execution",
        "code nobody has read does not run unnoticed",
        (
            "no-pipe-to-shell",
            "watch-pipe-into-shell",
            "watch-decode-into-shell",
            "watch-eval",
            "watch-unresolved-command-word",
        ),
    ),
    Bundle(
        "database-safety",
        "no schema-destroying SQL reaches a client",
        (
            "no-destructive-sql",
            "watch-destructive-sql",
        ),
    ),
    Bundle(
        "secrets-and-config",
        "the gate's config and your secrets stay yours",
        (
            "protect-hook-config",
            "deny-mid-session-hook-config-change",
            "deny-prompt-private-key",
        ),
    ),
    Bundle(
        "observability",
        "a decision log that tells the whole story",
        (
            "observe-session-start",
            "observe-script-file-run",
            "wrapper-script-shadow",
        ),
    ),
    Bundle(
        "command-shape",
        "the structure of a command, not just its words",
        (
            "no-pipe-to-pager",
            "watch-long-pipelines",
        ),
    ),
    Bundle(
        "single-entrypoint",
        "every action is one real program with arguments",
        (
            "single-entrypoint-only",
            "no-adhoc-stream-editors",
        ),
    ),
)

#: Catalog rules deliberately outside every bundle, and why that is not a
#: partition failure: these are templates an operator must edit before they
#: mean anything, so no bundle may sweep them in.
UNBUNDLED: tuple = ("allow-repo-clean-scratch",)


def blurb(name: str) -> str:
    """The plain-language line for a rule; falls back to its reason's gist."""
    return RULE_BLURBS.get(name, "")


def bundle_named(name: str):
    for bundle in BUNDLES:
        if bundle.name == name:
            return bundle
    return None


def bundle_of(rule_name: str):
    """The bundle a rule belongs to, or None for `UNBUNDLED` (and custom) rules."""
    for bundle in BUNDLES:
        if rule_name in bundle.rules:
            return bundle
    return None


def load_doc(path: Path) -> dict:
    return json.loads(path.read_text(encoding=ENCODING))


def decision_of(rule: dict) -> str:
    return rule.get("decision", DEFAULT_DECISION)


def event_of(rule: dict) -> str:
    return rule.get("event", DEFAULT_EVENT)


def gist(reason: str, width: int = GIST_WIDTH) -> str:
    """The first sentence of a reason, cut to fit a table column.

    Reasons are written risk-first (the style guide says so), which makes their
    first sentence the right one-line summary — and means nobody maintains a
    separate description field that can drift from the rule it describes.
    """
    first = reason.split(". ")[0].strip().rstrip(".")
    if len(first) <= width:
        return first
    return first[: width - 1].rstrip() + "…"


def attributed_tests(doc: dict, name: str) -> tuple[dict, ...]:
    """The test cases that name this rule (`expect_rule`), literal or generated.

    A `log` rule's cases assert `"expect": "none"` and carry no `expect_rule`,
    so a shadow rule travels without cases — which is honest: those cases assert
    a property of the whole file, not of the rule, and carrying them into a
    file with different rules could assert something false.
    """
    return tuple(t for t in doc.get("tests", []) if t.get("expect_rule") == name)


def referenced_sets(fragment: object, available: frozenset) -> frozenset:
    """Which file-local sets a JSON fragment references, as `"$name"` values.

    `$class:` references name lists the binary owns and travel for free; a
    `$name` reference names a `sets` entry of the source document, which has to
    be carried alongside the rule or the composed file fails to parse — an
    unresolvable reference is a hard error by design, never an inert matcher.
    """
    found: set = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str) and node.startswith("$"):
            name = node[1:]
            if name in available:
                found.add(name)

    walk(fragment)
    return frozenset(found)


def canonical_order(backbone: list, secondary: list) -> list:
    """One first-match-wins order over the union of two ordered name lists.

    The cookbook's documented order is the backbone — it is the one that was
    designed as an order, `allow` carve-outs first. A rule only the other
    document has is inserted after its nearest already-placed predecessor from
    its own file, so relative order within each source is preserved.
    """
    result = list(backbone)
    for i, name in enumerate(secondary):
        if name in result:
            continue
        at = -1
        for j in range(i - 1, -1, -1):
            if secondary[j] in result:
                at = result.index(secondary[j])
                break
        result.insert(at + 1, name)
    return result


def load_catalog(root: Path) -> Catalog:
    """Both source documents, merged into one ordered, adoptable list.

    Where the two share a rule name the shipped copy wins: it is what `setup`
    seeds and what `diff-defaults` compares against, and adopting a rule by
    name must mean the same bytes those verbs mean.
    """
    shipped = load_doc(root / SHIPPED_RULES_FILE)
    cookbook = load_doc(root / COOKBOOK_RULES_FILE)
    shipped_rules = {r["name"]: r for r in shipped.get("rules", [])}
    cookbook_rules = {r["name"]: r for r in cookbook.get("rules", [])}
    order = canonical_order(
        [r["name"] for r in cookbook.get("rules", [])],
        [r["name"] for r in shipped.get("rules", [])],
    )
    sets = dict(cookbook.get("sets", {}))
    sets.update(shipped.get("sets", {}))
    available = frozenset(sets)

    entries = []
    for position, name in enumerate(order):
        if name in shipped_rules:
            origin, doc, rule = RuleOrigin.shipped, shipped, shipped_rules[name]
        else:
            origin, doc, rule = RuleOrigin.cookbook, cookbook, cookbook_rules[name]
        tests = attributed_tests(doc, name)
        entries.append(
            CatalogRule(
                name=name,
                origin=origin,
                event=event_of(rule),
                tool=rule.get("tool"),
                decision=decision_of(rule),
                reason=rule.get("reason", ""),
                position=position,
                rule=rule,
                tests=tests,
                sets=tuple(sorted(referenced_sets([rule, list(tests)], available))),
            )
        )
    return Catalog(
        schema_version=shipped.get("schema_version", "1.0"),
        entries=tuple(entries),
        sets=sets,
    )


# ---------------------------------------------------------------------------
# the shadow demotion, and its inverse
# ---------------------------------------------------------------------------


def shadowed_rule(rule: dict) -> dict:
    """This rule, demoted to `log`. A rule already in shadow is returned as it
    is — its reason already says it observes, and stacking prefixes would make
    promotion unable to recognise its own work."""
    if decision_of(rule) == "log":
        return rule
    demoted = dict(rule)
    demoted["decision"] = "log"
    demoted["reason"] = SHADOW_PREFIX + rule.get("reason", "")
    return demoted


def shadowed_tests(tests: tuple) -> tuple:
    """Those cases, rewritten for a file where the rule cannot block.

    A shadow rule's hits are recorded and the walk continues, so a case that
    expected `deny` now observes nothing enforceable: it becomes an `expect:
    none` with the `expect_rule` dropped, which is exactly how the shipped
    `log` rules state their own cases. The transform is deterministic, which is
    what lets `rules promote` find and replace these cases later.
    """
    rewritten = []
    for test in tests:
        if test.get("expect") in ("deny", "ask", "allow"):
            copy = {k: v for k, v in test.items() if k != "expect_rule"}
            copy["expect"] = "none"
            rewritten.append(copy)
        else:
            rewritten.append(test)
    return tuple(rewritten)


def shadowed_document(doc: dict) -> dict:
    """A whole rule document demoted to shadow: the `observe` profile.

    Every rule becomes `log`, every case that expected an enforcement expects
    `none`, and nothing else moves — sets, logging, the overlay switch and the
    schema version are the operator's to keep.
    """
    demoted = dict(doc)
    demoted["rules"] = [shadowed_rule(rule) for rule in doc.get("rules", [])]
    if "tests" in doc:
        demoted["tests"] = list(shadowed_tests(tuple(doc.get("tests", []))))
    return demoted


# ---------------------------------------------------------------------------
# composing a new file
# ---------------------------------------------------------------------------


def compose(catalog: Catalog, selections: tuple) -> dict:
    """A complete rule document from a selection, in catalog order.

    Order is the catalog's, not the selection's: first-match-wins means an
    `allow` carve-out has to precede the deny it carves out of, and that is a
    property of the catalog's design, not of the sequence in which an operator
    said yes.
    """
    by_position = sorted(selections, key=lambda s: _must_find(catalog, s.name).position)
    rules: list = []
    tests: list = []
    sets: dict = {}
    for selection in by_position:
        entry = _must_find(catalog, selection.name)
        if selection.shadow:
            rules.append(shadowed_rule(entry.rule))
            tests.extend(shadowed_tests(entry.tests))
        else:
            rules.append(entry.rule)
            tests.extend(entry.tests)
        for name in entry.sets:
            sets.setdefault(name, catalog.sets[name])
    doc: dict = {"schema_version": catalog.schema_version}
    if sets:
        doc["sets"] = sets
    doc["rules"] = rules
    if tests:
        doc["tests"] = tests
    return doc


def _must_find(catalog: Catalog, name: str) -> CatalogRule:
    entry = catalog.find(name)
    if entry is None:
        raise KeyError(f"no rule named {name!r} in the catalog")
    return entry


def profile_document(catalog: Catalog, profile: Profile, shipped_doc: dict) -> dict:
    """The document a named profile stands for.

    `recommended` and `observe` are the shipped document itself (verbatim, and
    demoted, respectively) rather than a recomposition of it, so `recommended`
    is byte-identical to what `setup` seeds — including the file-level cases
    that no single rule owns.
    """
    if profile is Profile.recommended:
        return shipped_doc
    if profile is Profile.observe:
        return shadowed_document(shipped_doc)
    return compose(catalog, tuple(Selection(name) for name in MINIMAL_RULES))


# ---------------------------------------------------------------------------
# editing a live file
# ---------------------------------------------------------------------------


def doc_events(doc: dict) -> frozenset:
    """The events a document's rules are scoped to — what the installer wires."""
    return frozenset(event_of(rule) for rule in doc.get("rules", []))


def _version_pair(text: str) -> tuple:
    try:
        major, minor = text.split(".", 1)
        return (int(major), int(minor))
    except (ValueError, AttributeError):
        return (0, 0)


def with_schema_at_least(doc: dict, version: str) -> dict:
    """The document, declaring at least this schema version.

    Every catalog-driven edit calls this with the catalog's version: a rule
    adopted from a newer-schema source may use a matcher kind the file's old
    declaration predates, and a file that under-declares fails on an older
    gate as a SYNTAX error instead of the version refusal the field exists to
    produce. Never lowers a declaration; a file already ahead stays ahead.
    """
    stated = doc.get("schema_version")
    if stated is not None and _version_pair(stated) >= _version_pair(version):
        return doc
    out = {"schema_version": version}
    for key, value in doc.items():
        if key != "schema_version":
            out[key] = value
    return out


def live_rule(doc: dict, name: str) -> dict | None:
    for rule in doc.get("rules", []):
        if rule.get("name") == name:
            return rule
    return None


def with_rule_added(doc: dict, catalog: Catalog, name: str, shadow: bool) -> dict:
    """The live document with a catalog rule adopted into it.

    The rule is inserted at its catalog position relative to the other rules
    the catalog knows, not appended: appended after the rules it was designed
    to precede, an `allow` carve-out would never fire. Rules the catalog does
    not know keep their places — the file is the operator's.
    """
    entry = _must_find(catalog, name)
    rules = list(doc.get("rules", []))
    at = len(rules)
    for i, existing in enumerate(rules):
        known = catalog.find(existing.get("name", ""))
        if known is not None and known.position > entry.position:
            at = i
            break
    rules.insert(at, shadowed_rule(entry.rule) if shadow else entry.rule)

    tests = list(doc.get("tests", []))
    for test in shadowed_tests(entry.tests) if shadow else entry.tests:
        if test not in tests:
            tests.append(test)

    out = dict(doc)
    if entry.sets:
        sets = dict(doc.get("sets", {}))
        for set_name in entry.sets:
            # An operator's own definition of a clashing set name wins: the
            # catalog must not silently rewrite a list a rule already relies on.
            sets.setdefault(set_name, catalog.sets[set_name])
        out["sets"] = sets
    out["rules"] = rules
    if tests:
        out["tests"] = tests
    return with_schema_at_least(out, catalog.schema_version)


def with_rule_removed(doc: dict, catalog: Catalog, name: str) -> dict:
    """The live document without this rule, its cases, and any set only it used.

    Cases are removed two ways: everything that names the rule (`expect_rule`),
    and — for a rule the catalog knows — the exact shadow-period rewrites of its
    cases, which carry no name by design. A case the operator wrote by hand
    matches neither and stays; the selftest the caller runs will say whether it
    still holds.
    """
    out = dict(doc)
    out["rules"] = [r for r in doc.get("rules", []) if r.get("name") != name]

    entry = catalog.find(name)
    planted = list(entry.tests) + list(shadowed_tests(entry.tests)) if entry else []
    tests = [
        t
        for t in doc.get("tests", [])
        if t.get("expect_rule") != name and t not in planted
    ]
    if "tests" in doc:
        out["tests"] = tests

    if "sets" in doc:
        # Only sets the catalog knows are pruned: an unreferenced set of the
        # operator's own is theirs to keep or delete.
        still_referenced = referenced_sets(
            [out.get("rules", []), tests], frozenset(doc.get("sets", {}))
        )
        out["sets"] = {
            k: v
            for k, v in doc.get("sets", {}).items()
            if k in still_referenced or k not in catalog.sets
        }
    return out


def enforced_rule(rule: dict, to: str) -> dict:
    """A catalog `log` rule turned into enforcement at the stated decision.

    The reason keeps everything after the style guide's observational lead-in:
    a watch rule written to the cookbook's formula already carries its
    enforcement reason behind that first sentence.
    """
    out = dict(rule)
    out["decision"] = to
    reason = rule.get("reason", "")
    if reason.startswith(OBSERVATIONAL_PREFIX):
        out["reason"] = reason[len(OBSERVATIONAL_PREFIX) :]
    return out


def with_rule_promoted(
    doc: dict, catalog: Catalog, name: str, to: str | None = None
) -> dict:
    """A shadowed rule restored to the catalog's enforced form, cases included —
    or, with `to`, a catalog `log` rule raised to a stated decision.

    The two are different promotions: a shadowed rule has an enforced form the
    catalog already knows, so no decision is asked for; a rule the catalog
    ships as `log` (the watch rules, the single-entrypoint posture) has only
    the operator's word for what enforcement should be.
    """
    entry = _must_find(catalog, name)
    if to is not None:
        swapped = _with_rule_swapped(
            doc, name, enforced_rule(entry.rule, to), drop=(), add=()
        )
    else:
        swapped = _with_rule_swapped(
            doc,
            name,
            entry.rule,
            drop=shadowed_tests(entry.tests),
            add=entry.tests,
        )
    return with_schema_at_least(swapped, catalog.schema_version)


def with_rule_demoted(doc: dict, catalog: Catalog, name: str) -> dict:
    """A live catalog rule sent to shadow, cases rewritten to match."""
    entry = _must_find(catalog, name)
    swapped = _with_rule_swapped(
        doc,
        name,
        shadowed_rule(entry.rule),
        drop=entry.tests,
        add=shadowed_tests(entry.tests),
    )
    return with_schema_at_least(swapped, catalog.schema_version)


def _with_rule_swapped(
    doc: dict, name: str, replacement: dict, *, drop: tuple, add: tuple
) -> dict:
    out = dict(doc)
    out["rules"] = [
        replacement if r.get("name") == name else r for r in doc.get("rules", [])
    ]
    tests = [t for t in doc.get("tests", []) if t not in drop]
    for test in add:
        if test not in tests:
            tests.append(test)
    if tests or "tests" in doc:
        out["tests"] = tests
    return out

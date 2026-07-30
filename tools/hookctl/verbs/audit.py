"""`audit` — every mechanical consistency check the repository has, with its
counts.

The counts are the point. A green tick says "nothing broke"; the numbers say
"and here is how much is still being asserted", which is what makes a quiet
slide back toward hand-maintained lists visible in a diff. The clearest example
is the per-rule enumeration table: a rule whose `literal` column grows while its
`ref` column shrinks has stopped inheriting a class from the binary and started
copying it, and no test would ever fail because of that.

`audit` is also the one verb that is useful without a Zig toolchain. It says
which checks it could not run, runs the rest against whatever gate is installed,
and reports the missing toolchain as a failed check rather than as a refusal —
because "what does this machine's policy actually assert" is a question an
operator can have on a machine that cannot compile anything.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from .. import discovery, docs, proc, rulecatalog, rulewrite, ui
from ..proc import zig_build
from ..spec import (
    ENCODING,
    GATE_NAME,
    MIN_ZIG,
    RULE_FILES,
    SHIPPED_RULES_FILE,
    AuditCheck,
    AuditReport,
    Context,
    GateBinary,
    Profile,
    RunMode,
    Selection,
)
from .dev import python_tests

#: The keys under which a match entry nests other match entries. Everything
#: else is a leaf: either a literal somebody typed or a `$class:`/`$set`
#: reference to a list the binary owns.
GROUP_KEYS = ("any", "all", "none", "invocation")


def _step(name: str, run: Callable[[], bool]) -> AuditCheck:
    return AuditCheck(name, run())


def count_matchers(entry: dict) -> tuple[int, int]:
    """(literal leaves, reference leaves) below one match entry.

    A leaf whose value is `$class:x` or `$set` stands for a list this binary
    owns; a leaf with a literal value is a spelling somebody typed. The ratio
    is the drift signal: rules are supposed to move from the second column to
    the first, never back.
    """
    for key in GROUP_KEYS:
        if key in entry:
            literal = refs = 0
            for child in entry[key]:
                a, b = count_matchers(child)
                literal += a
                refs += b
            return literal, refs
    value = entry.get("value", "")
    if isinstance(value, str) and value.startswith("$"):
        return 0, 1
    # A `path_class` leaf names a class too — its value is the class name, and
    # membership is decided by normalizing rather than by comparing.
    if entry.get("kind") == "path_class":
        return 0, 1
    return 1, 0


def audit_fixtures(
    ctx: Context, gate_argv: str
) -> tuple[tuple[AuditCheck, ...], dict[str, int]]:
    """Every rule document's own cases and lint, per file and in total."""
    results: list[AuditCheck] = []
    totals = {"literal": 0, "generated": 0, "errors": 0, "warnings": 0}
    for path in RULE_FILES:
        run = ctx.process.run(
            (gate_argv, "selftest", "--rules", path, "--json"),
            mode=RunMode.capture,
            scrub_env=True,
            timeout=proc.PROBE_TIMEOUT,
        )
        try:
            data = json.loads(run.stdout)
        except json.JSONDecodeError:
            results.append(AuditCheck(path, False, run.first_error_line()))
            continue
        literal = data["literal"]["total"]
        generated = data["generated"]["total"]
        errors = sum(1 for f in data["lint"] if f["level"] == "error")
        warnings = len(data["lint"]) - errors
        totals["literal"] += literal
        totals["generated"] += generated
        totals["errors"] += errors
        totals["warnings"] += warnings
        results.append(
            AuditCheck(
                path,
                bool(data["ok"]) and run.ok,
                f"{literal} literal + {generated} generated cases pass, "
                f"{errors} lint error(s), {warnings} warning(s)",
            )
        )
    ui.report(results)
    return tuple(results), totals


def bundle_partition_check(catalog) -> AuditCheck:
    """The hand-curated layer over the catalog, held to exact correspondence.

    Bundles and blurbs are the only hand-maintained lists this feature has —
    they are the words a first-time operator chooses by, so they cannot be
    generated — and a hand-maintained list is exactly what this repository's
    discipline says must be audited. Three facts are asserted: every catalog
    rule is in exactly one bundle or explicitly `UNBUNDLED`, no bundle names a
    rule that does not exist, and every rule has a one-line blurb (and no
    blurb describes a rule that is gone).
    """
    name = "bundles and blurbs cover the catalog exactly"
    names = set(catalog.names())
    placed: dict = {}
    problems: list = []
    for bundle in rulecatalog.BUNDLES:
        for rule in bundle.rules:
            if rule not in names:
                problems.append(f"`{bundle.name}` names unknown rule {rule!r}")
            if rule in placed:
                problems.append(f"{rule!r} is in `{placed[rule]}` and `{bundle.name}`")
            placed[rule] = bundle.name
    uncovered = names - set(placed) - set(rulecatalog.UNBUNDLED)
    if uncovered:
        problems.append(
            "in no bundle and not UNBUNDLED: " + ", ".join(sorted(uncovered))
        )
    blurbed = set(rulecatalog.RULE_BLURBS)
    if names - blurbed:
        problems.append("no blurb: " + ", ".join(sorted(names - blurbed)))
    if blurbed - names:
        problems.append(
            "blurb for a missing rule: " + ", ".join(sorted(blurbed - names))
        )
    if problems:
        return AuditCheck(name, False, "; ".join(problems))
    return AuditCheck(
        name,
        True,
        f"{len(rulecatalog.BUNDLES)} bundles + {len(rulecatalog.UNBUNDLED)} unbundled "
        f"= {len(names)} rules, {len(blurbed)} blurbs",
    )


def audit_profiles(ctx: Context, gate_argv: str) -> tuple[AuditCheck, ...]:
    """Every `init` profile, every bundle, and the whole catalog at once,
    composed then selftested against the real gate.

    This is what keeps `init` and `rules add` honest: the compositions are
    produced by the same `rulecatalog` code the verbs run, and the judge is
    the binary that will enforce the result. A rule renamed in either source
    document, a set that stopped travelling, or two catalog rules whose cases
    contradict each other under co-adoption all fail here — with counts, so a
    profile quietly shrinking is visible in a diff of this output.
    """
    catalog = rulecatalog.load_catalog(ctx.paths.project_root)
    shipped = rulecatalog.load_doc(ctx.paths.project_root / SHIPPED_RULES_FILE)
    partition = bundle_partition_check(catalog)
    ui.report([partition])
    jobs = [
        (
            f"profile `{profile.value}` composes and passes selftest",
            rulecatalog.profile_document(catalog, profile, shipped),
        )
        for profile in Profile
    ]
    jobs += [
        (
            f"bundle `{bundle.name}` composes and passes selftest",
            rulecatalog.compose(
                catalog, tuple(Selection(name) for name in bundle.rules)
            ),
        )
        for bundle in rulecatalog.BUNDLES
    ]
    jobs.append(
        (
            "the whole catalog co-adopted passes selftest",
            rulecatalog.compose(
                catalog, tuple(Selection(name) for name in catalog.names())
            ),
        )
    )
    results: list[AuditCheck] = []
    with tempfile.TemporaryDirectory(prefix="hookctl-audit-") as tmp:
        for index, (name, doc) in enumerate(jobs):
            path = Path(tmp) / f"composed-{index}.json"
            path.write_text(rulewrite.render(doc), encoding=ENCODING)
            run = ctx.process.run(
                (gate_argv, "selftest", "--rules", str(path), "--json"),
                mode=RunMode.capture,
                scrub_env=True,
                timeout=proc.PROBE_TIMEOUT,
            )
            try:
                data = json.loads(run.stdout)
            except json.JSONDecodeError:
                results.append(AuditCheck(name, False, run.first_error_line()))
                continue
            results.append(
                AuditCheck(
                    name,
                    bool(data["ok"]) and run.ok,
                    f"{len(doc.get('rules', []))} rule(s), "
                    f"{data['literal']['total']} literal + "
                    f"{data['generated']['total']} generated cases",
                )
            )
    ui.report(results)
    return (partition,) + tuple(results)


def audit_enumeration(ctx: Context) -> None:
    grand_literal = grand_refs = grand_rules = 0
    for path in RULE_FILES:
        doc = json.loads((ctx.paths.project_root / path).read_text(encoding=ENCODING))
        rules = doc.get("rules", [])
        literal = refs = 0
        rows = []
        for rule in rules:
            r_literal = r_refs = 0
            for field in ("match", "match_all", "match_none"):
                for entry in rule.get(field, []):
                    a, b = count_matchers(entry)
                    r_literal += a
                    r_refs += b
            rows.append((rule["name"], r_literal, r_refs))
            literal += r_literal
            refs += r_refs
        ui.out(
            f"   {path}: {len(rules)} rules, {literal} literal leaf/leaves, {refs} class/set reference(s)"
        )
        for name, r_literal, r_refs in rows:
            ui.out(f"       {name:<40} {r_literal:>4} literal  {r_refs:>3} ref")
        grand_literal += literal
        grand_refs += refs
        grand_rules += len(rules)
    ui.out(
        f"   total: {grand_rules} rules, {grand_literal} literal leaf/leaves, {grand_refs} reference(s)"
    )


def audit_classes(ctx: Context, gate_argv: str) -> AuditCheck:
    name = "class catalog is printable"
    run = ctx.process.run(
        (gate_argv, "classes", "--json"),
        mode=RunMode.capture,
        scrub_env=True,
        timeout=proc.PROBE_TIMEOUT,
    )
    if not run.ok:
        return AuditCheck(name, False, "`classes --json` failed")
    data = json.loads(run.stdout)
    total = 0
    for cls in data["classes"]:
        ui.out(
            f"   {cls['name']:<24} {cls['kind']:<8} {len(cls['members']):>3} member(s)"
        )
        total += len(cls["members"])
    ui.out(f"   total: {len(data['classes'])} classes, {total} members")
    return AuditCheck(name, True, f"{len(data['classes'])} classes, {total} members")


def audit(ctx: Context) -> int:
    report = AuditReport()

    if ctx.toolchain.present:
        ui.section("build and tests")
        toolchain = ctx.toolchain.with_version(proc.zig_version(ctx.process))
        report = report.plus(
            AuditCheck("toolchain present", True, toolchain.describe()),
            _step(
                "unit tests (includes the doc-vs-fixture identity tests)",
                lambda: (
                    zig_build(
                        ctx.process, "test", mode=RunMode.quiet, timeout=ctx.timeout
                    ).ok
                ),
            ),
            _step(
                "both binaries compile",
                lambda: (
                    zig_build(ctx.process, mode=RunMode.quiet, timeout=ctx.timeout).ok
                ),
            ),
            _step(
                "shlex parity oracle is not stale",
                lambda: (
                    zig_build(
                        ctx.process, "parity", mode=RunMode.quiet, timeout=ctx.timeout
                    ).ok
                ),
            ),
            python_tests(ctx),
        )
        ui.report(report.checks)
    else:
        ui.note("zig is not on PATH: skipping the build, test and parity checks.")
        ui.note(f"  install Zig {MIN_ZIG} or newer to run the full audit.")
        report = report.plus(
            AuditCheck(
                "toolchain present", False, f"zig not on PATH; install {MIN_ZIG}+"
            )
        )

    # Audit just built the binary, so there is nothing ambiguous to announce.
    # Without a toolchain it may be falling back to an installed gate, and then
    # which binary answered is exactly what a reader needs to know.
    choice = discovery.choose_gate(ctx.paths)
    if not ctx.paths.built_gate.is_file():
        ui.announce_gate(choice, ctx.paths)
    gate: GateBinary | None = choice.gate
    if gate is None:
        ui.no_gate(ctx.verb.name, GATE_NAME, toolchain_present=ctx.toolchain.present)
        missing = AuditCheck(
            "a gate binary to audit with", False, "none built and none installed"
        )
        ui.report([missing])
        return report.plus(missing).exit_code()
    gate_argv = ctx.gate_argv(gate)

    ui.out()
    ui.section("rule fixtures: their own cases, and lint")
    fixtures, totals = audit_fixtures(ctx, gate_argv)
    report = report.extend(fixtures)
    ui.out(
        f"   total: {totals['literal']} literal + {totals['generated']} generated cases, "
        f"{totals['errors']} lint error(s), {totals['warnings']} warning(s) across "
        f"{len(RULE_FILES)} rule file(s)"
    )

    ui.out()
    ui.section("the catalog: init profiles and co-adoption, composed then selftested")
    report = report.extend(audit_profiles(ctx, gate_argv))

    ui.out()
    ui.section(
        "per-rule enumeration counts (a rising 'literal' column is drift back to hand-listing)"
    )
    audit_enumeration(ctx)

    ui.out()
    ui.section("class membership (what a rule inherits from the binary)")
    report = report.plus(audit_classes(ctx, gate_argv))

    ui.out()
    ui.section("documentation")
    doc_checks = docs.checks(
        ctx.process, ctx.paths.readme, ctx.verbs, ctx.groups, gate_argv
    )
    report = report.extend(doc_checks)
    ui.report(doc_checks)

    ui.out()
    ui.out(f"audit: {report.passed} check(s) passed, {report.failed} failed")
    return report.exit_code()

"""The catalog and its transforms, asserted against the real documents.

These tests read the actual shipped defaults and the actual cookbook fixture —
not copies — so a rule renamed or a set dropped in either document fails here
first, before `audit` composes the profiles against the gate. Everything
asserted is a property `init` and `rules` rely on: the merge order, shipped
copies winning name clashes, tests and sets travelling with their rule, and
the shadow demotion being exactly invertible.
"""

from __future__ import annotations

import unittest

from .. import rulecatalog
from ..spec import Profile, RuleOrigin, Selection
from . import support

ROOT = support.project_root()


def catalog():
    return rulecatalog.load_catalog(ROOT)


def shipped_doc():
    return rulecatalog.load_doc(ROOT / "src/default-rules.json")


class CatalogShape(unittest.TestCase):
    def test_union_of_both_documents(self):
        names = catalog().names()
        self.assertIn("no-pkill", names)  # in both
        self.assertIn("watch-eval", names)  # shipped only
        self.assertIn("no-rm-rf-home-or-root", names)  # cookbook only
        self.assertEqual(len(names), len(set(names)))

    def test_shipped_copy_wins_a_name_clash(self):
        entry = catalog().find("no-pkill")
        shipped = {r["name"]: r for r in shipped_doc()["rules"]}
        self.assertIs(entry.origin, RuleOrigin.shipped)
        self.assertEqual(entry.rule, shipped["no-pkill"])

    def test_order_is_first_match_wins(self):
        names = list(catalog().names())
        # The allow carve-out precedes everything it carves out of.
        self.assertEqual("allow-repo-clean-scratch", names[0])
        # The cookbook's deny tier keeps its designed order across the merge.
        self.assertLess(
            names.index("no-rm-rf-home-or-root"),
            names.index("deny-recursive-mutation-from-anchor"),
        )
        # Shipped-only rules follow their shipped neighbours.
        self.assertLess(names.index("observe-session-start"), names.index("watch-eval"))

    def test_rules_travel_with_their_cases_and_sets(self):
        entry = catalog().find("no-pkill")
        self.assertTrue(entry.tests)
        self.assertTrue(all(t["expect_rule"] == "no-pkill" for t in entry.tests))
        keyed = catalog().find("ask-force-push-protected-branch")
        self.assertIn("protected_branches", keyed.sets)

    def test_log_rules_carry_no_cases(self):
        # Their cases assert `none` of the whole file, which is not portable.
        self.assertEqual((), catalog().find("watch-eval").tests)

    def test_minimal_profile_names_exist(self):
        for name in rulecatalog.MINIMAL_RULES:
            self.assertIsNotNone(catalog().find(name), name)


class Composition(unittest.TestCase):
    def test_recommended_is_the_shipped_document_verbatim(self):
        doc = rulecatalog.profile_document(
            catalog(), Profile.recommended, shipped_doc()
        )
        self.assertEqual(doc, shipped_doc())

    def test_observe_demotes_everything_and_nothing_else(self):
        doc = rulecatalog.profile_document(catalog(), Profile.observe, shipped_doc())
        self.assertEqual({"log"}, {rulecatalog.decision_of(r) for r in doc["rules"]})
        self.assertNotIn("deny", {t.get("expect") for t in doc["tests"]})
        self.assertEqual(shipped_doc().get("sets"), doc.get("sets"))
        self.assertEqual(shipped_doc()["schema_version"], doc["schema_version"])

    def test_observe_is_idempotent(self):
        once = rulecatalog.shadowed_document(shipped_doc())
        self.assertEqual(once, rulecatalog.shadowed_document(once))

    def test_minimal_carries_the_sets_its_rules_reference(self):
        doc = rulecatalog.profile_document(catalog(), Profile.minimal, shipped_doc())
        self.assertEqual(len(rulecatalog.MINIMAL_RULES), len(doc["rules"]))
        # observe-session-start reads `$session_sources`.
        self.assertIn("session_sources", doc.get("sets", {}))

    def test_compose_orders_by_catalog_not_by_selection(self):
        doc = rulecatalog.compose(
            catalog(),
            (Selection("no-pkill"), Selection("allow-repo-clean-scratch")),
        )
        self.assertEqual(
            ["allow-repo-clean-scratch", "no-pkill"],
            [r["name"] for r in doc["rules"]],
        )

    def test_shadow_selection_demotes_rule_and_cases(self):
        doc = rulecatalog.compose(catalog(), (Selection("no-pkill", shadow=True),))
        self.assertEqual("log", doc["rules"][0]["decision"])
        self.assertTrue(all(t["expect"] == "none" for t in doc["tests"]))
        self.assertTrue(all("expect_rule" not in t for t in doc["tests"]))

    def test_unknown_name_is_an_error(self):
        with self.assertRaises(KeyError):
            rulecatalog.compose(catalog(), (Selection("no-such-rule"),))


class LiveFileEdits(unittest.TestCase):
    def test_add_inserts_at_the_catalog_position(self):
        doc = shipped_doc()
        after = rulecatalog.with_rule_added(
            doc, catalog(), "no-rm-rf-home-or-root", False
        )
        names = [r["name"] for r in after["rules"]]
        self.assertLess(
            names.index("no-rm-rf-home-or-root"),
            names.index("deny-recursive-mutation-from-anchor"),
        )
        self.assertGreater(
            names.index("no-rm-rf-home-or-root"), names.index("no-pkill")
        )

    def test_add_keeps_the_operators_own_set_on_a_clash(self):
        doc = dict(shipped_doc())
        doc["sets"] = dict(doc["sets"], protected_branches=["release"])
        after = rulecatalog.with_rule_added(
            doc, catalog(), "ask-force-push-protected-branch", False
        )
        self.assertEqual(["release"], after["sets"]["protected_branches"])

    def test_remove_takes_cases_and_only_catalog_sets(self):
        doc = rulecatalog.with_rule_added(
            shipped_doc(), catalog(), "deny-prompt-private-key", False
        )
        self.assertIn("private_key_headers", doc["sets"])
        after = rulecatalog.with_rule_removed(doc, catalog(), "deny-prompt-private-key")
        self.assertNotIn("deny-prompt-private-key", [r["name"] for r in after["rules"]])
        self.assertNotIn("private_key_headers", after["sets"])
        self.assertTrue(
            all(
                t.get("expect_rule") != "deny-prompt-private-key"
                for t in after["tests"]
            )
        )

    def test_remove_keeps_an_unreferenced_custom_set(self):
        doc = dict(shipped_doc())
        doc["sets"] = dict(doc["sets"], mine=["a", "b"])
        after = rulecatalog.with_rule_removed(doc, catalog(), "no-pkill")
        self.assertIn("mine", after["sets"])

    def test_demote_then_promote_round_trips(self):
        doc = shipped_doc()
        there = rulecatalog.with_rule_demoted(doc, catalog(), "no-pkill")
        self.assertEqual("log", rulecatalog.live_rule(there, "no-pkill")["decision"])
        back = rulecatalog.with_rule_promoted(there, catalog(), "no-pkill")
        self.assertEqual(doc["rules"], back["rules"])
        self.assertEqual(
            sorted(map(str, doc["tests"])), sorted(map(str, back["tests"]))
        )

    def test_events_reflect_rule_scope(self):
        events = rulecatalog.doc_events(shipped_doc())
        self.assertIn("PreToolUse", events)
        self.assertIn("SessionStart", events)

    def test_enforced_rule_strips_the_observational_lead_in_and_nothing_else(self):
        entry = catalog().find("single-entrypoint-only")
        raised = rulecatalog.enforced_rule(entry.rule, "deny")
        self.assertEqual("deny", raised["decision"])
        self.assertFalse(raised["reason"].startswith("Observational"))
        self.assertTrue(entry.rule["reason"].endswith(raised["reason"]))
        self.assertEqual(entry.rule["match"], raised["match"])

    def test_adoption_raises_the_schema_declaration_and_never_lowers_it(self):
        # A rule adopted from a newer-schema catalog may use matcher kinds the
        # file's old declaration predates; under-declaring would turn the
        # version refusal into a syntax error on an older gate.
        doc = dict(shipped_doc(), schema_version="1.1")
        after = rulecatalog.with_rule_added(doc, catalog(), "no-pipe-to-pager", False)
        self.assertEqual(catalog().schema_version, after["schema_version"])
        ahead = dict(shipped_doc(), schema_version="9.9")
        kept = rulecatalog.with_rule_added(ahead, catalog(), "ask-sudo", False)
        self.assertEqual("9.9", kept["schema_version"])


class Bundles(unittest.TestCase):
    def test_bundles_partition_the_catalog_exactly(self):
        names = set(catalog().names())
        placed = [n for b in rulecatalog.BUNDLES for n in b.rules]
        self.assertEqual(len(placed), len(set(placed)), "a rule is in two bundles")
        self.assertEqual(names, set(placed) | set(rulecatalog.UNBUNDLED))

    def test_every_catalog_rule_has_a_blurb_and_no_blurb_is_stale(self):
        self.assertEqual(set(catalog().names()), set(rulecatalog.RULE_BLURBS))

    def test_lookups(self):
        self.assertEqual("agent-hygiene", rulecatalog.bundle_of("no-pkill").name)
        self.assertIsNone(rulecatalog.bundle_of("allow-repo-clean-scratch"))
        self.assertIsNotNone(rulecatalog.bundle_named("machine-guards"))
        self.assertIsNone(rulecatalog.bundle_named("no-such-bundle"))

    def test_every_bundle_composes(self):
        from ..spec import Selection as Sel

        for bundle in rulecatalog.BUNDLES:
            doc = rulecatalog.compose(
                catalog(), tuple(Sel(name) for name in bundle.rules)
            )
            self.assertEqual(len(bundle.rules), len(doc["rules"]), bundle.name)


class Gist(unittest.TestCase):
    def test_first_sentence_cut_to_width(self):
        self.assertEqual("Short", rulecatalog.gist("Short. Long tail here."))
        long = "word " * 40
        self.assertLessEqual(len(rulecatalog.gist(long)), rulecatalog.GIST_WIDTH)

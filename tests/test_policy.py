"""Policy tests: Layer 3 acceptance (spec Prompt 4).

Offline, no model calls. Run from the repo root:

    python3 -m unittest discover -s tests
"""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import analyst, policy
from sim import agents

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = REPO_ROOT / "data" / "business_rules.txt"
GRAPH_PATH = REPO_ROOT / "data" / "graph.json"

REQUIRED_BR = {f"BR-{i}" for i in range(1, 10)}


class PolicyAcceptanceTest(unittest.TestCase):
    """policy.json covers all nine starter rules."""

    @classmethod
    def setUpClass(cls):
        cls.graph = policy.load_graph(GRAPH_PATH)
        cls.business_rules = policy.parse_business_rules(RULES_PATH)
        cls.payload = policy.run_policy(
            RULES_PATH, GRAPH_PATH, use_spark=False)
        cls.rules = cls.payload["rules"]

    def test_all_starter_rules_covered(self):
        covered = {r["business_rule"] for r in self.rules}
        self.assertTrue(REQUIRED_BR <= covered)

    def test_required_fields(self):
        for rule in self.rules:
            for field in ("subject", "action", "resource", "conditions",
                          "effect"):
                self.assertIn(field, rule, rule.get("id"))
            self.assertIn(rule["effect"], policy.EFFECTS)
            self.assertIn(rule["action"], policy.ACTIONS)

    def test_catch_all_default_deny_is_last(self):
        self.assertEqual(self.rules[-1]["id"], "pol-br7-default-deny")
        self.assertEqual(self.rules[-1]["effect"], "deny")

    def test_payload_validates(self):
        self.assertEqual(
            policy.validate_policy(
                self.payload, self.graph, self.business_rules), [])

    def test_committed_policy_matches_inputs(self):
        """data/policy.json (if present) must validate against the inputs."""
        path = REPO_ROOT / "data" / "policy.json"
        if not path.exists():
            self.skipTest("data/policy.json not generated yet")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            policy.validate_policy(payload, self.graph,
                                   self.business_rules), [])

    def test_deterministic_rules(self):
        first = policy.run_policy(RULES_PATH, GRAPH_PATH, use_spark=False)
        second = policy.run_policy(RULES_PATH, GRAPH_PATH, use_spark=False)
        self.assertEqual(first["rules"], second["rules"])

    def test_lineage_present(self):
        """Every enforced rule carries origin + business-rule lineage."""
        for rule in self.rules:
            self.assertIn(rule["origin"],
                          ("business-rule", "infrastructure"),
                          rule.get("id"))
            ref = rule["business_rule"]
            self.assertTrue(ref is None or ref in REQUIRED_BR, rule.get("id"))
        br_rules = [r for r in self.rules
                    if r["origin"] == "business-rule"]
        self.assertTrue(all(r["business_rule"] is not None
                            for r in br_rules))


class PolicyContractTest(unittest.TestCase):
    """Policy numbers stay pinned to the sim contract."""

    @classmethod
    def setUpClass(cls):
        cls.payload = policy.run_policy(
            RULES_PATH, GRAPH_PATH, use_spark=False)
        cls.rules = cls.payload["rules"]

    def test_setpoint_range_matches_sim(self):
        ceiling = agents.SPEED_POLICY_MAX
        allow = next(r for r in self.rules
                     if r["id"] == "pol-br1-allow-plc-write")
        bounds = {(c["op"], c["value"]) for c in allow["conditions"]
                  if c["field"] == "value"}
        self.assertIn(("gte", 0), bounds)
        self.assertIn(("lte", ceiling), bounds)
        above = next(r for r in self.rules
                     if r["id"] == "pol-br9-deny-above-range")
        self.assertEqual(above["conditions"],
                         [{"field": "value", "op": "gt", "value": ceiling}])

    def test_operator_subscribes_match_sim(self):
        topics = {r["resource"][len("topic:"):]
                  for r in self.rules
                  if r["subject"] == "operator-agent"
                  and r["action"] == "subscribe"}
        self.assertEqual(topics, set(agents.OPERATOR_TOPICS))

    def test_no_device_publish_to_command_topics(self):
        for rule in self.rules:
            if rule["origin"] != "infrastructure":
                continue
            for command in policy.COMMAND_TOPICS:
                self.assertNotEqual(rule["resource"], f"topic:{command}",
                                    rule.get("id"))

    def test_infra_publish_owners_match_graph(self):
        graph = policy.load_graph(GRAPH_PATH)
        owners = {}
        for edge in graph.get("edges", []):
            if edge.get("to", "").startswith("topic:"):
                pattern = policy.normalize_topic_glob(
                    edge["to"][len("topic:"):])
                owners.setdefault(pattern, edge["from"])
        for rule in self.rules:
            if rule["origin"] != "infrastructure" \
                    or rule["action"] != "publish":
                continue
            pattern = rule["resource"][len("topic:"):]
            self.assertIn(pattern, owners, rule.get("id"))
            self.assertEqual(rule["subject"], owners[pattern],
                             rule.get("id"))


class PolicyValidationTest(unittest.TestCase):
    """Spark inventions are advisory-or-dropped; the base never changes."""

    @classmethod
    def setUpClass(cls):
        cls.graph = policy.load_graph(GRAPH_PATH)
        cls.subjects = policy.known_subjects(cls.graph)
        cls.resources = policy.known_resources(cls.graph)
        cls.base = policy.base_rules(cls.graph)

    def test_merge_accepts_valid_draft_as_proposal(self):
        base = copy.deepcopy(self.base)
        draft = {"rules": [{
            "id": "spark-guard-moves",
            "business_rule": "BR-7",
            "subject": "*",
            "action": "publish",
            "resource": "topic:site/yard/container/move",
            "conditions": [{"field": "subject", "op": "ne",
                            "value": "yard-container-moves"}],
            "effect": "quarantine",
            "description": "Ownership guard for container moves.",
        }]}
        proposed, dropped = policy.merge_spark_draft(
            base, draft, self.subjects, self.resources)
        self.assertEqual(dropped, [])
        self.assertEqual([r["id"] for r in proposed], ["spark-guard-moves"])
        self.assertEqual(proposed[0]["origin"], "spark-drafted")
        # The enforced base is untouched: still no such rule in it.
        self.assertNotIn("spark-guard-moves", {r["id"] for r in base})

    def test_merge_drops_inventions_with_reasons(self):
        draft = {"rules": [
            {"id": "bad-subject", "business_rule": "BR-1",
             "subject": "invented-device-9", "action": "write",
             "resource": "plc.*", "conditions": [], "effect": "deny",
             "description": "x"},
            {"id": "bad-resource", "business_rule": "BR-1",
             "subject": "*", "action": "write",
             "resource": "teleporter.*", "conditions": [],
             "effect": "deny", "description": "x"},
            {"id": "bad-action", "business_rule": "BR-1",
             "subject": "*", "action": "teleport",
             "resource": "plc.*", "conditions": [],
             "effect": "deny", "description": "x"},
            {"id": "bad-effect", "business_rule": "BR-1",
             "subject": "*", "action": "write",
             "resource": "plc.*", "conditions": [],
             "effect": "explode", "description": "x"},
            {"id": "bad-field", "business_rule": "BR-1",
             "subject": "*", "action": "write", "resource": "plc.*",
             "conditions": [{"field": "vibes", "op": "eq", "value": True}],
             "effect": "deny", "description": "x"},
            {"id": "bad-op", "business_rule": "BR-1",
             "subject": "*", "action": "write", "resource": "plc.*",
             "conditions": [{"field": "value", "op": "approx", "value": 1}],
             "effect": "deny", "description": "x"},
            {"id": "bad-range", "business_rule": "BR-9",
             "subject": "*", "action": "write", "resource": "plc.*",
             "conditions": [{"field": "value", "op": "gt",
                             "value": "lots"}],
             "effect": "deny", "description": "x"},
        ]}
        proposed, dropped = policy.merge_spark_draft(
            self.base, draft, self.subjects, self.resources)
        self.assertEqual(proposed, [])
        reasons = {d["id"]: d["reason"] for d in dropped}
        self.assertEqual(set(reasons),
                         {"bad-subject", "bad-resource", "bad-action",
                          "bad-effect", "bad-field", "bad-op", "bad-range"})
        self.assertTrue(all(r for r in reasons.values()))

    def test_merge_cannot_override_base(self):
        draft = {"rules": [{
            "id": "pol-br7-default-deny",
            "business_rule": "BR-7", "subject": "*", "action": "*",
            "resource": "*", "conditions": [], "effect": "allow",
            "description": "Hostile override attempt.",
        }]}
        proposed, dropped = policy.merge_spark_draft(
            self.base, draft, self.subjects, self.resources)
        self.assertEqual(proposed, [])
        self.assertEqual(dropped[0]["id"], "pol-br7-default-deny")

    def test_no_key_falls_back_without_network(self):
        with mock.patch.dict(os.environ, {"META_API_KEY": "..."}):
            with mock.patch("sentinel.models.chat") as chat:
                proposed, info = policy.enrich_with_spark(
                    self.base, self.graph, "rules-text")
        chat.assert_not_called()
        self.assertEqual(proposed, [])
        self.assertEqual(info["status"], "fallback")

    def test_uncovered_rule_is_uncompilable_not_dropped(self):
        text = RULES_PATH.read_text(encoding="utf-8")
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write(text + "10. All crane moves need a supervisor token.\n")
            extra = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                policy.run_policy(extra, GRAPH_PATH, use_spark=False)
        finally:
            os.unlink(extra)
        self.assertIn("BR-10", str(ctx.exception))
        self.assertIn("uncompilable", str(ctx.exception))


class PolicyRerankTest(unittest.TestCase):
    """The Day 5 policy mitigates the Day 4 seeded threats on re-rank."""

    def test_full_coverage_mitigates_seeded_threats(self):
        payload = policy.run_policy(RULES_PATH, GRAPH_PATH, use_spark=False)
        threats = analyst.rank_threats(analyst.seeded_threats())
        reranked = analyst.apply_policy_rerank(threats, payload)
        self.assertTrue(all(t["status"] == "mitigated" for t in reranked))
        # Forged-PLC-write drops from critical to high once BR-1/6/7 hold.
        forged = next(t for t in reranked
                      if t["id"] == "forged-plc-write")
        self.assertEqual(forged["residual_severity"], "high")


if __name__ == "__main__":
    unittest.main()

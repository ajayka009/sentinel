"""Analyst tests: Layer 2 acceptance (spec Prompt 3).

Offline, no model calls. Run from the repo root:

    python3 -m unittest discover -s tests
"""

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from sentinel import analyst

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_PATH = REPO_ROOT / "data" / "graph.json"

SEEDED_IDS = {
    "forged-plc-write",
    "fake-gate-release",
    "gateway-bypass-plc",
    "wildcard-recon",
    "spoofed-reefer-temp",
    "spoofed-gate-events",
}


class AnalystAcceptanceTest(unittest.TestCase):
    """threats.json holds the seeded exposures, demo paths on top."""

    @classmethod
    def setUpClass(cls):
        cls.graph = analyst.load_graph(GRAPH_PATH)
        cls.payload = analyst.run_analyst(
            GRAPH_PATH, policy_path=None, use_wonder=False)
        cls.threats = cls.payload["threats"]

    def test_seeded_exposures_present(self):
        ids = {t["id"] for t in self.threats}
        self.assertTrue(SEEDED_IDS <= ids)

    def test_demo_paths_ranked_top(self):
        self.assertEqual(self.threats[0]["id"], "forged-plc-write")
        self.assertEqual(self.threats[1]["id"], "fake-gate-release")

    def test_required_fields(self):
        for threat in self.threats:
            for field in ("path", "severity", "preconditions",
                          "stopping_policy"):
                self.assertIn(field, threat, threat.get("id"))
            self.assertTrue(threat["path"], threat.get("id"))
            self.assertIn(threat["severity"], analyst.SEVERITIES)

    def test_paths_use_graph_nodes_only(self):
        node_ids = {n["id"] for n in self.graph["nodes"]}
        for threat in self.threats:
            for step in threat["path"]:
                self.assertIn(step, node_ids, threat["id"])

    def test_payload_validates(self):
        self.assertEqual(
            analyst.validate_threats(self.payload, self.graph), [])

    def test_committed_threats_match_graph(self):
        """data/threats.json (if present) must validate against the graph."""
        path = REPO_ROOT / "data" / "threats.json"
        if not path.exists():
            self.skipTest("data/threats.json not generated yet")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(analyst.validate_threats(payload, self.graph), [])

    def test_deterministic_ranking(self):
        first = analyst.run_analyst(
            GRAPH_PATH, policy_path=None, use_wonder=False)
        second = analyst.run_analyst(
            GRAPH_PATH, policy_path=None, use_wonder=False)
        self.assertEqual(
            [t["id"] for t in first["threats"]],
            [t["id"] for t in second["threats"]],
        )


class AnalystValidationTest(unittest.TestCase):
    """Wonder inventions are rejected; seeded order is protected."""

    @classmethod
    def setUpClass(cls):
        cls.graph = analyst.load_graph(GRAPH_PATH)
        cls.nodes = {n["id"] for n in cls.graph["nodes"]}

    def test_merge_adds_valid_threat(self):
        base = analyst.rank_threats(analyst.seeded_threats())
        draft = {"threats": [{
            "id": "camera-exfiltration",
            "title": "Camera frames exfiltrated off-site",
            "path": ["rogue-agent", "camera-line1"],
            "severity": "medium",
            "preconditions": ["camera reachable from untrusted zone"],
            "stopping_policy": "Cameras stream to the local gateway only.",
            "business_rules": ["BR-2"],
        }]}
        merged, dropped = analyst.merge_wonder_draft(base, draft, self.nodes)
        self.assertEqual(dropped, [])
        self.assertIn("camera-exfiltration", {t["id"] for t in merged})

    def test_merge_drops_invented_steps(self):
        base = analyst.rank_threats(analyst.seeded_threats())
        draft = {"threats": [{
            "id": "invented-device-attack",
            "title": "Bogus",
            "path": ["rogue-agent", "invented-device-9"],
            "severity": "critical",
            "preconditions": [],
            "stopping_policy": "none",
            "business_rules": ["BR-1"],
        }]}
        merged, dropped = analyst.merge_wonder_draft(base, draft, self.nodes)
        self.assertIn("invented-device-attack", dropped)
        self.assertNotIn("invented-device-9",
                         {s for t in merged for s in t["path"]})

    def test_merge_drops_bad_severity_and_rules(self):
        base = analyst.rank_threats(analyst.seeded_threats())
        draft = {"threats": [
            {"id": "bad-sev", "title": "x",
             "path": ["rogue-agent", "plc-line1"], "severity": "extreme",
             "preconditions": [], "stopping_policy": "x",
             "business_rules": ["BR-1"]},
            {"id": "bad-rule", "title": "x",
             "path": ["rogue-agent", "plc-line1"], "severity": "low",
             "preconditions": [], "stopping_policy": "x",
             "business_rules": ["BR-99"]},
        ]}
        merged, dropped = analyst.merge_wonder_draft(base, draft, self.nodes)
        self.assertIn("bad-sev", dropped)
        self.assertIn("bad-rule", dropped)
        ids = {t["id"] for t in merged}
        self.assertNotIn("bad-sev", ids)
        self.assertNotIn("bad-rule", ids)

    def test_merge_cannot_override_seeded(self):
        base = analyst.rank_threats(analyst.seeded_threats())
        draft = {"threats": [{
            "id": "forged-plc-write",
            "title": "Demoted by draft",
            "path": ["rogue-agent"],
            "severity": "low",
            "preconditions": [],
            "stopping_policy": "x",
            "business_rules": ["BR-1"],
        }]}
        merged, dropped = analyst.merge_wonder_draft(base, draft, self.nodes)
        self.assertIn("forged-plc-write", dropped)
        forged = next(t for t in merged if t["id"] == "forged-plc-write")
        self.assertEqual(forged["severity"], "critical")
        self.assertEqual(merged[0]["id"], "forged-plc-write")

    def test_no_key_falls_back_without_network(self):
        base = analyst.rank_threats(analyst.seeded_threats())
        with mock.patch.dict(os.environ, {"META_API_KEY": "..."}):
            with mock.patch("sentinel.models.chat") as chat:
                threats, info = analyst.enrich_with_wonder(base, self.graph)
        chat.assert_not_called()
        self.assertEqual(threats, base)
        self.assertEqual(info["status"], "fallback")


class AnalystRerankTest(unittest.TestCase):
    """Re-running after a policy change re-ranks the threats."""

    def test_policy_coverage_mitigates_and_reranks(self):
        threats = analyst.rank_threats(analyst.seeded_threats())
        before = [t["id"] for t in threats]
        # BR-3 enforced, BR-1 only half of what forged-plc-write needs.
        policy = {"rules": [
            {"business_rule": "BR-1", "effect": "deny"},
            {"business_rule": "BR-3", "effect": "deny"},
        ]}
        reranked = analyst.apply_policy_rerank(threats, policy)
        gate = next(t for t in reranked if t["id"] == "fake-gate-release")
        self.assertEqual(gate["status"], "mitigated")
        self.assertEqual(gate["residual_severity"], "high")
        forged = next(t for t in reranked if t["id"] == "forged-plc-write")
        self.assertEqual(forged["status"], "open")
        # Mitigated fake-gate-release (now high) drops below the still-open
        # critical gateway-bypass-plc.
        self.assertNotEqual([t["id"] for t in reranked], before)
        order = [t["id"] for t in reranked]
        self.assertLess(order.index("gateway-bypass-plc"),
                        order.index("fake-gate-release"))

    def test_empty_policy_changes_nothing(self):
        threats = analyst.rank_threats(analyst.seeded_threats())
        reranked = analyst.apply_policy_rerank(threats, {"rules": []})
        self.assertEqual([t["id"] for t in reranked],
                         [t["id"] for t in threats])
        self.assertTrue(all(t["status"] == "open" for t in reranked))


if __name__ == "__main__":
    unittest.main()

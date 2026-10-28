"""Digest tests: Layer 1 acceptance (spec Prompt 2).

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

from sentinel import digest

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "data" / "registry.yaml"
FRAMES_DIR = REPO_ROOT / "sim" / "camera_frames"


def _registry_device_ids(registry):
    ids = set()
    for site in registry.get("sites", []):
        for device in site.get("devices", []):
            ids.add(device["id"])
    return ids


def _registry_agent_ids(registry):
    return {a["id"] for a in registry.get("agents", [])}


class DigestAcceptanceTest(unittest.TestCase):
    """graph.json contains every registry device; rogue is untrusted."""

    @classmethod
    def setUpClass(cls):
        cls.registry = digest.load_registry(REGISTRY_PATH)
        cls.graph = digest.run_digest(REGISTRY_PATH, FRAMES_DIR, use_spark=False)

    def test_every_registry_device_in_graph(self):
        node_ids = {n["id"] for n in self.graph["nodes"]}
        for device_id in _registry_device_ids(self.registry):
            self.assertIn(device_id, node_ids)

    def test_every_registry_agent_in_graph(self):
        node_ids = {n["id"] for n in self.graph["nodes"]}
        for agent_id in _registry_agent_ids(self.registry):
            self.assertIn(agent_id, node_ids)

    def test_rogue_in_untrusted_zone(self):
        rogue = next(n for n in self.graph["nodes"] if n["id"] == "rogue-agent")
        self.assertEqual(rogue["zone"], "external/untrusted")
        self.assertNotIn("site-a-lan", rogue.get("trust_boundary", ""))

    def test_trust_boundaries_present(self):
        self.assertEqual(
            self.graph["trust_boundaries"],
            self.registry["trust_boundaries"],
        )

    def test_graph_validates(self):
        self.assertEqual(digest.validate_graph(self.graph, self.registry), [])

    def test_committed_graph_matches_registry(self):
        """data/graph.json (if present) must validate against the registry."""
        path = REPO_ROOT / "data" / "graph.json"
        if not path.exists():
            self.skipTest("data/graph.json not generated yet")
        graph = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(digest.validate_graph(graph, self.registry), [])


class DigestRerunTest(unittest.TestCase):
    """Re-running after adding a device updates the graph."""

    def test_added_device_appears_on_rerun(self):
        registry = digest.load_registry(REGISTRY_PATH)
        registry = copy.deepcopy(registry)
        registry["sites"][0]["devices"].append({
            "id": "sensor-test-new",
            "type": "sensor",
            "protocol": "mqtt",
            "topics": ["site/line1/sensors/test"],
            "identity": "device-sensor-test",
        })
        graph = digest.build_base_graph(registry, digest.plc_register_map())
        node_ids = {n["id"] for n in graph["nodes"]}
        self.assertIn("sensor-test-new", node_ids)
        self.assertIn("topic:site/line1/sensors/test", node_ids)
        self.assertEqual(digest.validate_graph(graph, registry), [])


class DigestValidationTest(unittest.TestCase):
    """Model inventions are rejected; SAM stays registry-anchored."""

    def test_merge_drops_invented_nodes(self):
        base = digest.build_base_graph(
            digest.load_registry(REGISTRY_PATH), digest.plc_register_map())
        draft = {
            "node_descriptions": {
                "plc-line1": "Controls the line.",
                "invented-device-9": "Does not exist.",
            },
            "edges": [
                {"from": "plc-line1", "to": "edge-gateway",
                 "protocol": "modbus-tcp", "description": "status readback"},
                {"from": "invented-device-9", "to": "plc-line1",
                 "protocol": "mqtt", "description": "bogus flow"},
            ],
        }
        merged, dropped = digest.merge_enrichment(base, draft)
        node_ids = {n["id"] for n in merged["nodes"]}
        self.assertNotIn("invented-device-9", node_ids)
        self.assertIn("invented-device-9", dropped)
        self.assertIn("invented-device-9->plc-line1", dropped)
        plc = next(n for n in merged["nodes"] if n["id"] == "plc-line1")
        self.assertEqual(plc["description"], "Controls the line.")
        self.assertIn(
            ("plc-line1", "edge-gateway"),
            {(e["from"], e["to"]) for e in merged["edges"]},
        )

    def test_sam_objects_require_registry_match(self):
        registry_ids = {"plc-line1", "camera-line1"}
        objects = [
            {"label": "motor", "matches_device": "plc-line1"},
            {"label": "ufo", "matches_device": "invented-device-9"},
            {"label": "unlabeled"},
        ]
        self.assertEqual(
            digest.filter_sam_objects(objects, registry_ids),
            [{"label": "motor", "matches_device": "plc-line1"}],
        )

    def test_empty_frames_dir_is_graceful(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = digest.build_base_graph(
                digest.load_registry(REGISTRY_PATH), digest.plc_register_map())
            self.assertEqual(digest.attach_sam_objects(graph, tmp), "no_frames")

    def test_no_key_falls_back_without_network(self):
        base = digest.build_base_graph(
            digest.load_registry(REGISTRY_PATH), digest.plc_register_map())
        with mock.patch.dict(os.environ, {"META_API_KEY": "..."}):
            with mock.patch("sentinel.models.chat") as chat:
                graph, info = digest.enrich_with_spark(base, "registry-text")
        chat.assert_not_called()
        self.assertEqual(graph, base)
        self.assertEqual(info["status"], "fallback")


if __name__ == "__main__":
    unittest.main()

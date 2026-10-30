"""Console tests: Layer 5 helpers (spec Prompt 6).

Offline, stdlib only, no streamlit import. Run from the repo root:

    python3 -m unittest discover -s tests
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from console import app
from sentinel import enforce, identity

REPO_ROOT = Path(__file__).resolve().parent.parent


class ArtifactLoaderTest(unittest.TestCase):
    def test_business_rules_parse_nine(self):
        rules = app.load_business_rules()
        self.assertEqual([r["id"] for r in rules],
                         [f"BR-{n}" for n in range(1, 10)])
        self.assertTrue(all(r["text"] for r in rules))

    def test_graph_threats_policy_load(self):
        graph = app.load_graph()
        self.assertTrue(graph["nodes"])
        self.assertIn("site-a-lan", graph["trust_boundaries"])
        threats = app.load_threats()
        self.assertGreaterEqual(len(threats["threats"]), 4)
        policy = app.load_policy()
        self.assertTrue(policy["rules"])

    def test_missing_artifact_raises_with_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.json"
            with self.assertRaises(FileNotFoundError) as ctx:
                app.load_json(missing)
        self.assertIn("regenerate", str(ctx.exception))

    def test_registry_loads(self):
        registry = app.load_registry()
        if "_raw" in registry:
            self.assertIn("operator-agent", registry["_raw"])
        else:
            ids = [a["id"] for a in registry["agents"]]
            self.assertIn("operator-agent", ids)


class AuditReaderTest(unittest.TestCase):
    def test_missing_log_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                app.read_audit_log(Path(tmp) / "audit.jsonl"), [])

    def test_bad_lines_skipped_limit_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text("{bad json\n"
                            '{"seq": 1, "decision": "allow"}\n'
                            "\n"
                            '{"seq": 2, "decision": "deny"}\n',
                            encoding="utf-8")
            records = app.read_audit_log(path)
            self.assertEqual([r["seq"] for r in records], [1, 2])
            self.assertEqual(len(app.read_audit_log(path, limit=1)), 1)

    def test_collect_prefers_file_falls_back_to_memory(self):
        gw = enforce.Gateway(audit_path=None,
                             clock=lambda: 1_000_000.0)
        gw.plc_write(identity.issue("operator-agent", "sentinel-ca",
                                    app.OPERATOR_SCOPE),
                     "setpoint", 1200)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            # No file -> in-memory trail.
            self.assertEqual(len(app.collect_records(gw, path)), 1)
            path.write_text('{"seq": 9, "decision": "deny"}\n',
                            encoding="utf-8")
            # File wins once it exists (write-through keeps it current).
            self.assertEqual(app.collect_records(gw, path)[0]["seq"], 9)


def _record(seq, ts, subject, action, resource, decision,
            rule="pol-x", flagged=False, change=None):
    return {"seq": seq, "ts": ts, "subject": subject, "action": action,
            "resource": resource, "decision": decision, "flagged": flagged,
            "matched_rule": {"id": rule}, "policy_change": change}


class MetricsTest(unittest.TestCase):
    def test_empty_records_zeroed(self):
        metrics = app.compute_metrics([])
        self.assertEqual(metrics["total"], 0)
        self.assertEqual(metrics["blocked"], 0)
        self.assertEqual(metrics["deny_rate"], 0.0)
        self.assertEqual(metrics["timeline"], [])

    def test_counters_and_breakdowns(self):
        records = [
            _record(1, "2026-11-02T10:00:00+00:00", "operator-agent",
                    "write", "plc.setpoint", "allow",
                    "pol-br1-allow-plc-write"),
            _record(2, "2026-11-02T10:00:30+00:00", "rogue-agent",
                    "write", "plc.setpoint", "deny",
                    "pol-br9-deny-above-range"),
            _record(3, "2026-11-02T10:01:00+00:00", "rogue-agent",
                    "subscribe", "topic:#", "quarantine",
                    "pol-br4-quarantine-wildcard", change="revoked x"),
        ]
        metrics = app.compute_metrics(records)
        self.assertEqual(metrics["total"], 3)
        self.assertEqual(metrics["blocked"], 2)
        self.assertAlmostEqual(metrics["deny_rate"], 2 / 3)
        # Trailing 60s from the latest stamp covers all three.
        self.assertEqual(metrics["actions_per_min"], 3)
        self.assertEqual(metrics["per_rule"][
            "pol-br9-deny-above-range"]["denied"], 1)
        self.assertEqual(metrics["per_agent"]["rogue-agent"]["hits"], 2)
        self.assertEqual(metrics["per_resource"]["plc.setpoint"]["hits"], 2)
        self.assertEqual([b["time"] for b in metrics["timeline"]],
                         ["10:00", "10:01"])

    def test_unparseable_timestamps_skipped_in_timeline(self):
        records = [_record(1, "not-a-time", "a", "write", "r", "allow")]
        metrics = app.compute_metrics(records)
        self.assertEqual(metrics["total"], 1)
        self.assertEqual(metrics["timeline"], [])
        self.assertEqual(metrics["actions_per_min"], 1)

    def test_rule_hit_counts(self):
        records = [_record(1, "t", "a", "w", "r", "deny", rule="pol-a"),
                   _record(2, "t", "a", "w", "r", "deny", rule="pol-a"),
                   _record(3, "t", "a", "w", "r", "allow", rule="pol-b")]
        self.assertEqual(app.rule_hit_counts(records),
                         {"pol-a": 2, "pol-b": 1})


class PolicyLineageTest(unittest.TestCase):
    def test_every_business_rule_has_lineage(self):
        policy = app.load_policy()
        lineage = app.group_policy_rules(policy)
        for n in range(1, 10):
            self.assertIn(f"BR-{n}", lineage["groups"],
                          f"BR-{n} compiled to no machine rule")
        self.assertTrue(lineage["groups"]["INFRA"])
        self.assertTrue(lineage["proposed"])

    def test_device_coverage(self):
        policy = app.load_policy()
        plc = app.device_policy_coverage("plc-line1", [],
                                         policy["rules"])
        self.assertTrue(any("plc" in r["resource"] for r in plc))
        sensor = app.device_policy_coverage(
            "sensor-temp-line1", ["site/line1/sensors/temperature"],
            policy["rules"])
        self.assertTrue(any(r["subject"] == "sensor-temp-line1"
                            for r in sensor))


class CredentialRowsTest(unittest.TestCase):
    def test_valid_then_quarantined(self):
        gw = enforce.Gateway(audit_path=None,
                             clock=lambda: 2_000_000.0)
        creds = {"rogue": identity.issue("rogue-agent", "sentinel-ca",
                                         app.ROGUE_SCOPE)}
        rows = app.credential_rows(creds, gw)
        self.assertEqual(rows[0]["status"], "valid")
        gw.mqtt_subscribe(creds["rogue"], "#")
        rows = app.credential_rows(creds, gw)
        self.assertEqual(rows[0]["status"], "quarantined")


class ExportTest(unittest.TestCase):
    def test_json_and_csv_roundtrip(self):
        records = [_record(1, "2026-11-02T10:00:00+00:00", "rogue-agent",
                           "write", "plc.setpoint", "deny",
                           "pol-br9-deny-above-range")]
        parsed = json.loads(app.export_audit_json(records))
        self.assertEqual(parsed[0]["matched_rule"]["id"],
                         "pol-br9-deny-above-range")
        text = app.export_audit_csv(records)
        self.assertIn("pol-br9-deny-above-range", text.splitlines()[1])


class HealthTest(unittest.TestCase):
    def test_never_raises_offline(self):
        health = app.check_health(timeout=0.1)
        self.assertEqual(set(health),
                         {"broker", "plc", "gateway", "yard_link"})
        for info in health.values():
            self.assertIn("ok", info)
            self.assertIn("latency_ms", info)
            self.assertEqual(len(info), 3)
        self.assertTrue(health["gateway"]["ok"])  # policy.json committed


class RedTeamScenarioTest(unittest.TestCase):
    """Every red-team button fires its spec attack offline."""

    def setUp(self):
        self.gw = enforce.Gateway(audit_path=None,
                                  clock=lambda: 3_000_000.0)
        self.creds = app.issue_demo_creds()

    def test_all_spec_attacks_registered(self):
        for sid in app.ATTACK_IDS:
            self.assertIn(sid, app.SCENARIOS)
            self.assertEqual(app.SCENARIOS[sid]["kind"], "attack")

    def test_unknown_scenario_rejected(self):
        with self.assertRaises(ValueError):
            app.run_scenario(self.gw, "nope", self.creds)

    def test_wildcard_recon_quarantines_then_short_circuits(self):
        fired = app.run_scenario(self.gw, "wildcard-recon", self.creds)
        self.assertEqual(fired[0]["decision"], "quarantine")
        self.assertEqual(fired[0]["matched_rule"]["id"],
                         "pol-br4-quarantine-wildcard")
        self.assertEqual(fired[1]["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")

    def test_forged_plc_write_denied(self):
        fired = app.run_scenario(self.gw, "forged-plc-write", self.creds)
        self.assertEqual(fired[0]["decision"], "deny")
        self.assertEqual(fired[0]["matched_rule"]["id"],
                         "pol-br9-deny-above-range")

    def test_spoofed_reefer_flagged(self):
        fired = app.run_scenario(self.gw, "spoofed-reefer-temp",
                                 self.creds)
        self.assertEqual(fired[0]["decision"], "allow")
        self.assertEqual(fired[1]["decision"], "deny")
        self.assertTrue(fired[1]["flagged"])
        self.assertEqual(fired[1]["matched_rule"]["id"],
                         "pol-br5-flag-implausible-reefer")

    def test_fake_gate_release_quarantined(self):
        fired = app.run_scenario(self.gw, "fake-gate-release", self.creds)
        self.assertEqual(fired[0]["decision"], "quarantine")
        self.assertEqual(fired[0]["matched_rule"]["id"],
                         "pol-br3-quarantine-unbooked")

    def test_unknown_device_denied(self):
        fired = app.run_scenario(self.gw, "unknown-device-connect",
                                 self.creds)
        self.assertEqual(fired[0]["decision"], "deny")
        self.assertEqual(fired[0]["identity"]["status"], "unknown")

    def test_publish_flood_throttle_then_quarantine(self):
        fired = app.run_scenario(self.gw, "publish-flood", self.creds)
        self.assertEqual(len(fired), 35)
        self.assertEqual(fired[30]["matched_rule"]["id"],
                         "pol-br8-throttle-flood")
        self.assertEqual(fired[31]["decision"], "quarantine")
        self.assertEqual(fired[32]["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")

    def test_out_of_range_denied(self):
        fired = app.run_scenario(self.gw, "out-of-range-setpoint",
                                 self.creds)
        self.assertEqual(fired[0]["decision"], "deny")
        self.assertEqual(fired[0]["matched_rule"]["id"],
                         "pol-br9-deny-above-range")

    def test_legit_beats_allowed(self):
        calm = app.run_scenario(self.gw, "operator-setpoint", self.creds)
        self.assertEqual(calm[0]["decision"], "allow")
        release = app.run_scenario(self.gw, "booked-gate-release",
                                   self.creds)
        self.assertEqual(release[0]["decision"], "allow")

    def test_demo_script_fires_every_beat(self):
        fired = app.run_demo_script(self.gw, self.creds)
        decisions = [r["decision"] for r in fired]
        self.assertIn("allow", decisions)
        self.assertIn("deny", decisions)
        self.assertIn("quarantine", decisions)
        self.assertGreater(len(fired), 40)

    def test_demo_script_isolates_each_attack_on_shared_gateway(self):
        """Every attack cites its own stopping rule, not the overlay."""
        fired = app.run_demo_script(self.gw, self.creds)
        cited = {r["matched_rule"]["id"] for r in fired}
        for rule in ("pol-br4-quarantine-wildcard",
                     "pol-br9-deny-above-range",
                     "pol-br5-flag-implausible-reefer",
                     "pol-br3-quarantine-unbooked",
                     "pol-br7-deny-unknown-revoked",
                     "pol-br8-throttle-flood",
                     "pol-br8-quarantine-repeat",
                     "pol-br1-allow-plc-write",
                     "pol-br3-allow-booked-release"):
            self.assertIn(rule, cited)
        self.assertTrue(any(r.get("flagged") for r in fired))
        self.assertEqual(len(self.gw.overlay_rules), 3)

    def test_refire_after_quarantine_shows_tightening(self):
        first = app.run_scenario(self.gw, "wildcard-recon", self.creds)
        self.assertEqual(first[0]["decision"], "quarantine")
        second = app.run_scenario(self.gw, "wildcard-recon", self.creds)
        self.assertEqual(second[0]["decision"], "deny")
        self.assertTrue(second[0]["matched_rule"]["id"]
                        .startswith("tighten-deny-"))

    def test_scenarios_make_zero_model_calls(self):
        with mock.patch.dict(os.environ, {"META_API_KEY": ""}):
            with mock.patch("sentinel.models.chat",
                            side_effect=AssertionError("model called")):
                app.run_demo_script(self.gw, self.creds)

    def test_expected_metadata_matches_reality(self):
        """Each scenario's documented expectation is what fires."""
        for sid, spec in app.SCENARIOS.items():
            with self.subTest(scenario=sid):
                gw = enforce.Gateway(audit_path=None,
                                     clock=lambda: 4_000_000.0)
                fired = app.run_scenario(gw, sid, app.issue_demo_creds())
                key = fired[0 if sid != "spoofed-reefer-temp" else 1]
                if sid == "publish-flood":
                    key = next(r for r in fired
                               if r["decision"] == "quarantine")
                self.assertEqual(key["decision"],
                                 spec["expected"]["decision"])
                self.assertEqual(key["matched_rule"]["id"],
                                 spec["expected"]["rule"])

    def test_no_streamlit_needed(self):
        self.assertNotIn("streamlit", sys.modules)


class ConsoleStyleTest(unittest.TestCase):
    """SOC styling stays flat, offline-safe, and escaped."""

    def test_css_uses_stable_selectors_and_no_gradients(self):
        self.assertIn('[data-testid="stMetric"]', app.APP_CSS)
        self.assertIn('[data-testid="stSidebar"]', app.APP_CSS)
        self.assertIn(".sent-feed", app.APP_CSS)
        self.assertIn(".sent-pill", app.APP_CSS)
        self.assertNotIn("linear-gradient", app.APP_CSS)
        self.assertNotIn("@import", app.APP_CSS)  # no webfonts: offline
        self.assertEqual(app.APP_CSS.count("{"), app.APP_CSS.count("}"))

    def test_theme_config_is_dark(self):
        import tomllib

        path = REPO_ROOT / ".streamlit" / "config.toml"
        theme = tomllib.loads(path.read_text(encoding="utf-8"))["theme"]
        self.assertEqual(theme["base"], "dark")
        self.assertTrue(theme["primaryColor"])
        self.assertTrue(theme["backgroundColor"])

    def test_feed_line_pills_and_escaping(self):
        line = app._feed_line(_record(1, "2026-11-02T10:00:00+00:00",
                                      "<b>rogue</b>", "write",
                                      "plc.setpoint", "quarantine",
                                      "pol-x", flagged=True))
        self.assertIn("sent-quarantine", line)
        self.assertIn("sent-flag", line)
        self.assertIn("&lt;b&gt;rogue&lt;/b&gt;", line)
        self.assertNotIn("<b>rogue</b>", line)

    def test_health_and_brand_html(self):
        health = {"broker": {"ok": True, "latency_ms": 1.2,
                             "detail": "mosquitto"},
                  "plc": {"ok": False, "latency_ms": None,
                          "detail": "modbus"}}
        rendered = app._health_html(health)
        self.assertIn("sent-up", rendered)
        self.assertIn("sent-down", rendered)
        self.assertIn("mosquitto", rendered)
        self.assertIn("ARMED", app._brand_html(3, {}))
        self.assertIn("DEGRADED", app._brand_html(3, {"policy": "missing"}))
        stats = app._sidebar_stats_html({"total": 46, "blocked": 43})
        self.assertIn("46", stats)
        self.assertIn("43", stats)


if __name__ == "__main__":
    unittest.main()

"""Enforcement tests: Layer 4 acceptance (spec Prompt 5).

Offline, no model calls. Run from the repo root:

    python3 -m unittest discover -s tests
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import enforce, identity
from sim import agents

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "data" / "policy.json"

PLC_SETPOINT = "plc.setpoint"
GATE_RELEASE = "topic:site/yard/gate/release"
REEFER_TEMP = "topic:site/yard/reefer/R-101/temperature"
SENSOR_TEMP = "topic:site/line1/sensors/temperature"

OPERATOR_SCOPE = ["telemetry.read", "plc.write", "gate.release"]
ROGUE_SCOPE = ["telemetry.read"]


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_gateway(clock=None):
    """Memory-only gateway (no audit file) on the committed artifacts."""
    return enforce.Gateway(audit_path=None, clock=clock or FakeClock())


def issue(role, scope):
    return identity.issue(role, "sentinel-ca", scope)


class EnforcementAcceptanceTest(unittest.TestCase):
    """The three demo attacks are blocked; revoked stays revoked."""

    def setUp(self):
        self.gw = make_gateway()
        self.operator = issue("operator-agent", OPERATOR_SCOPE)
        self.rogue = issue("rogue-agent", ROGUE_SCOPE)
        self.reefer = issue("reefer-container-1", ["telemetry.write"])

    def test_forged_plc_write_denied(self):
        """Rogue overspeed write (3000 RPM) is rejected by condition check."""
        record = self.gw.plc_write(self.rogue, "setpoint", 3000)
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br9-deny-above-range")

    def test_forged_plc_write_in_range_still_denied(self):
        """Even an in-range rogue write matches no allow rule: default-deny."""
        record = self.gw.plc_write(self.rogue, "setpoint", 1000)
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"], "pol-br7-default-deny")

    def test_spoofed_reefer_flagged_not_acted_on(self):
        """A 25C jump in one minute is flagged; the publish is denied."""
        baseline = self.gw.mqtt_publish(self.reefer, REEFER_TEMP[6:], -20.0)
        self.assertEqual(baseline["decision"], "allow")
        self.gw.clock.advance(60)
        spoof = self.gw.mqtt_publish(self.rogue, REEFER_TEMP[6:], 5.0)
        self.assertEqual(spoof["decision"], "deny")
        self.assertTrue(spoof["flagged"])
        self.assertEqual(spoof["matched_rule"]["id"],
                         "pol-br5-flag-implausible-reefer")
        self.assertGreater(spoof["context"]["delta_c_per_min"], 10)

    def test_fake_gate_release_quarantined(self):
        record = self.gw.release_gate(self.rogue, "XXXX000000", "TRK-99",
                                      "BK-FAKE")
        self.assertEqual(record["decision"], "quarantine")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br3-quarantine-unbooked")

    def test_revoked_agent_denied_without_reevaluation(self):
        """After quarantine+revoke, every later request short-circuits."""
        first = self.gw.release_gate(self.rogue, "XXXX000000", "TRK-99",
                                     "BK-FAKE")
        self.assertEqual(first["decision"], "quarantine")
        # A wildcard subscribe would match pol-br4-quarantine-wildcard if
        # re-evaluated; the short-circuit must cite BR-7 instead.
        for record in (
            self.gw.plc_write(self.rogue, "setpoint", 1000),
            self.gw.mqtt_subscribe(self.rogue, "#"),
        ):
            self.assertEqual(record["decision"], "deny")
            self.assertEqual(record["matched_rule"]["id"],
                             "pol-br7-deny-unknown-revoked")
            self.assertEqual(record["identity"]["status"], "revoked")


class AlignedChecksTest(unittest.TestCase):
    """The free aligned checks ride the same decide() path."""

    def setUp(self):
        self.gw = make_gateway()
        self.operator = issue("operator-agent", OPERATOR_SCOPE)
        self.rogue = issue("rogue-agent", ROGUE_SCOPE)

    def test_unknown_identity_connect_denied(self):
        ghost = json.dumps({"id": "ghost-unknown-7", "role": "ghost-device",
                            "issuer": "nobody", "expiry": 9_999_999_999,
                            "scope": []})
        record = self.gw.request(ghost, "publish", GATE_RELEASE,
                                 {"booking_match": True})
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")
        self.assertEqual(record["identity"]["status"], "unknown")

    def test_expired_identity_denied(self):
        stale = identity.issue("operator-agent", "sentinel-ca",
                               OPERATOR_SCOPE, ttl_seconds=-5)
        record = self.gw.plc_write(stale, "setpoint", 1000)
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["identity"]["status"], "expired")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")

    def test_publish_flood_throttled_then_quarantined(self):
        decisions = [self.gw.mqtt_publish(self.rogue, SENSOR_TEMP[6:], 72.0)
                     for _ in range(35)]
        # Rogue owns no sensor topic, so every attempt is denied; the 31st
        # trips the BR-8 rate cap (throttle), the 32nd quarantines.
        self.assertEqual(decisions[29]["matched_rule"]["id"],
                         "pol-br7-default-deny")
        self.assertFalse(decisions[29]["flagged"])
        throttle = decisions[30]
        self.assertEqual(throttle["decision"], "deny")
        self.assertTrue(throttle["flagged"])
        self.assertEqual(throttle["matched_rule"]["id"],
                         "pol-br8-throttle-flood")
        self.assertIn("throttl", throttle["policy_change"])
        repeat = decisions[31]
        self.assertEqual(repeat["decision"], "quarantine")
        self.assertEqual(repeat["matched_rule"]["id"],
                         "pol-br8-quarantine-repeat")
        self.assertEqual(decisions[32]["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")

    def test_out_of_range_setpoint_rejected(self):
        high = self.gw.plc_write(self.operator, "setpoint", 3000)
        self.assertEqual(high["decision"], "deny")
        self.assertEqual(high["matched_rule"]["id"],
                         "pol-br9-deny-above-range")
        low = self.gw.plc_write(self.operator, "setpoint", -5)
        self.assertEqual(low["decision"], "deny")
        self.assertEqual(low["matched_rule"]["id"],
                         "pol-br9-deny-below-range")
        malformed = self.gw.plc_write(self.operator, "setpoint", "fast")
        self.assertEqual(malformed["decision"], "deny")
        self.assertEqual(malformed["matched_rule"]["id"],
                         "pol-br9-deny-malformed")


class LegitFlowsTest(unittest.TestCase):
    """Default-deny must not break legitimate traffic."""

    def setUp(self):
        self.gw = make_gateway()
        self.operator = issue("operator-agent", OPERATOR_SCOPE)
        self.rogue = issue("rogue-agent", ROGUE_SCOPE)
        self.sensor = issue("sensor-temp-line1", ["telemetry.write"])
        self.camera = issue("camera-line1", ["frames.stream"])
        self.gateway_cred = issue("edge-gateway", ["bridge.all"])

    def test_operator_plc_write_allowed(self):
        record = self.gw.plc_write(self.operator, "setpoint", 1200)
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br1-allow-plc-write")

    def test_booked_gate_release_allowed(self):
        container, info = next(iter(agents.BOOKINGS.items()))
        record = self.gw.release_gate(self.operator, container,
                                      info["truck"], info["booking"])
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br3-allow-booked-release")

    def test_sensor_telemetry_allowed(self):
        record = self.gw.mqtt_publish(self.sensor, SENSOR_TEMP[6:], 71.5)
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["matched_rule"]["origin"], "infrastructure")

    def test_operator_subscribes_allowed(self):
        for topic in agents.OPERATOR_TOPICS:
            with self.subTest(topic=topic):
                record = self.gw.mqtt_subscribe(self.operator, topic)
                self.assertEqual(record["decision"], "allow")

    def test_gateway_wildcard_allowed(self):
        record = self.gw.mqtt_subscribe(self.gateway_cred, "#")
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br4-allow-gateway-wildcard")

    def test_agent_wildcard_quarantined(self):
        record = self.gw.mqtt_subscribe(self.rogue, "#")
        self.assertEqual(record["decision"], "quarantine")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br4-quarantine-wildcard")
        followup = self.gw.mqtt_subscribe(self.rogue, SENSOR_TEMP[6:])
        self.assertEqual(followup["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")

    def test_bypass_denied_even_for_operator(self):
        """Deny-override: BR-6 beats the BR-1 allow when via_gateway=False."""
        record = self.gw.plc_write(self.operator, "setpoint", 1200,
                                   via_gateway=False)
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"], "pol-br6-deny-bypass")

    def test_camera_stream_local_allowed_internet_denied(self):
        local = self.gw.camera_stream(self.camera, "edge-gateway")
        self.assertEqual(local["decision"], "allow")
        self.assertEqual(local["matched_rule"]["id"],
                         "pol-br2-allow-local-stream")
        exfil = self.gw.camera_stream(self.camera, "internet")
        self.assertEqual(exfil["decision"], "deny")
        self.assertEqual(exfil["matched_rule"]["id"],
                         "pol-br2-deny-internet")

    def test_devices_exempt_from_rate_cap(self):
        decisions = [self.gw.mqtt_publish(self.sensor, SENSOR_TEMP[6:], 71.5)
                     for _ in range(40)]
        self.assertTrue(all(d["decision"] == "allow" for d in decisions))


class SemanticsTest(unittest.TestCase):
    """Deny-override, determinism, audit, and tightening."""

    def setUp(self):
        self.gw = make_gateway()
        self.operator = issue("operator-agent", OPERATOR_SCOPE)
        self.rogue = issue("rogue-agent", ROGUE_SCOPE)

    def test_gateway_fields_are_authoritative(self):
        """Callers cannot spoof identity, subject, or rate fields."""
        ghost = json.dumps({"id": "ghost-spoof-1", "role": "operator-agent",
                            "issuer": "nobody", "expiry": 9_999_999_999,
                            "scope": []})
        record = self.gw.request(
            ghost, "write", PLC_SETPOINT,
            {"identity_status": "valid", "subject": "operator-agent",
             "subject_kind": "agent", "rate_per_min": 0, "repeat": False,
             "via_gateway": True, "value": 1000, "wellformed": True})
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br7-deny-unknown-revoked")
        self.assertEqual(record["context"]["identity_status"], "unknown")

    def test_proposed_rules_never_enforced(self):
        """Spark-drafted advisories stay advisory until a human promotes them."""
        payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        proposed_targets = {r["resource"] for r in payload["proposed_rules"]}
        self.assertIn("topic:site/yard/container/move", proposed_targets)
        record = self.gw.mqtt_publish(
            self.rogue, "site/yard/container/move", {"move": "spoof"})
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br7-default-deny")

    def test_deterministic(self):
        """Same action + same policy -> same decision, every run."""
        first = self.gw.plc_write(self.operator, "setpoint", 1200)
        second = self.gw.plc_write(self.operator, "setpoint", 1200)
        self.assertEqual(first["decision"], second["decision"])
        self.assertEqual(first["matched_rule"], second["matched_rule"])
        other = make_gateway().plc_write(self.operator, "setpoint", 1200)
        self.assertEqual(first["decision"], other["decision"])
        self.assertEqual(first["matched_rule"]["id"],
                         other["matched_rule"]["id"])

    def test_audit_record_complete(self):
        record = self.gw.plc_write(self.rogue, "setpoint", 3000)
        for field in ("identity", "action", "resource", "matched_rule",
                      "decision", "policy_change", "context", "seq", "ts"):
            self.assertIn(field, record)
        self.assertEqual(record["action"], "write")
        self.assertEqual(record["resource"], PLC_SETPOINT)
        self.assertEqual(record["identity"]["role"], "rogue-agent")

    def test_audit_jsonl_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "audit.jsonl")
            gw = enforce.Gateway(audit_path=path, clock=FakeClock())
            gw.plc_write(self.operator, "setpoint", 1200)
            gw.plc_write(self.rogue, "setpoint", 3000)
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        first, second = (json.loads(line) for line in lines)
        self.assertEqual(first["decision"], "allow")
        self.assertEqual(second["decision"], "deny")
        self.assertEqual(second["matched_rule"]["id"],
                         "pol-br9-deny-above-range")

    def test_quarantine_tightens_policy_in_memory(self):
        record = self.gw.release_gate(self.rogue, "XXXX000000", "TRK-99",
                                      "BK-FAKE")
        self.assertEqual(record["decision"], "quarantine")
        self.assertIn("revoked", record["policy_change"])
        self.assertIn("overlay", record["policy_change"])
        overlays = [r for r in self.gw.overlay_rules
                    if r["subject"] == "rogue-agent"]
        self.assertEqual(len(overlays), 1)
        self.assertEqual(overlays[0]["effect"], "deny")

    def test_module_decide_uses_spec_signature(self):
        previous = enforce._default_gateway
        enforce._default_gateway = make_gateway()
        try:
            decision = enforce.decide(
                self.operator, "write", PLC_SETPOINT,
                {"via_gateway": True, "value": 1200, "wellformed": True})
            self.assertEqual(decision, "allow")
            decision = enforce.decide(
                self.rogue, "write", PLC_SETPOINT,
                {"via_gateway": True, "value": 3000, "wellformed": True})
            self.assertEqual(decision, "deny")
        finally:
            enforce._default_gateway = previous


class ExplainerTest(unittest.TestCase):
    """The explainer is display-only: offline-safe, never a decider."""

    def setUp(self):
        self.gw = make_gateway()
        self.record = self.gw.plc_write(
            issue("rogue-agent", ROGUE_SCOPE), "setpoint", 3000)

    def test_offline_fallback_without_network(self):
        with mock.patch.dict(os.environ, {"META_API_KEY": ""}):
            with mock.patch("sentinel.models.chat") as chat:
                text = enforce.explain(self.record)
        chat.assert_not_called()
        self.assertIn("deny", text)
        self.assertIn("pol-br9-deny-above-range", text)

    def test_failure_falls_back_to_template(self):
        with mock.patch.dict(os.environ, {"META_API_KEY": "dummy"}):
            with mock.patch("sentinel.models.chat",
                            side_effect=RuntimeError("down")):
                text = enforce.explain(self.record)
        self.assertIn("deny", text)

    def test_explainer_never_changes_decision(self):
        before = json.loads(json.dumps(self.record))
        with mock.patch.dict(os.environ, {"META_API_KEY": ""}):
            enforce.explain(self.record)
        self.assertEqual(self.record, before)


if __name__ == "__main__":
    unittest.main()

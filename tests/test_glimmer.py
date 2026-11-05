"""P2-12 tests: Glimmer operator loop mechanics (governed side).

Offline, deterministic (stub backend only — no weights, no daemon).
Run from the repo root:

    python3 -m unittest discover -s tests
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sim import agents, glimmer_operator as glimmer
from sentinel import enforce, identity

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "data" / "policy.json"


def fresh_gateway():
    """In-memory gateway (audit_path=None): no audit file writes."""
    return enforce.Gateway(audit_path=None)


def operator_credential():
    return identity.issue("operator-agent", "sentinel-ca",
                          ["telemetry.read", "plc.write", "gate.release"])


class HardwareGateTest(unittest.TestCase):
    def test_report_shape_and_consistency(self):
        gate = glimmer.hardware_gate()
        for key in ("ram_gb", "free_disk_gb", "weights_path",
                    "weights_present", "verdict", "reasons"):
            self.assertIn(key, gate)
        self.assertIn(gate["verdict"], ("pass", "fail"))
        self.assertEqual(gate["verdict"] == "fail",
                         bool(gate["reasons"]))

    def test_missing_weights_reported_not_downloaded(self):
        gate = glimmer.hardware_gate("/nonexistent/dir/weights.gguf")
        self.assertFalse(gate["weights_present"])
        self.assertFalse(Path("/nonexistent/dir/weights.gguf").exists())


class ParseDecisionTest(unittest.TestCase):
    """Model replies parse fail-closed: confusion becomes noop."""

    def test_valid_actions(self):
        self.assertEqual(
            glimmer.parse_decision('{"action": "set_speed", "rpm": 1200}'),
            {"action": "set_speed", "rpm": 1200})
        self.assertEqual(
            glimmer.parse_decision('{"action": "release_gate", '
                                   '"container": "C", "truck": "T", '
                                   '"booking": "B"}'),
            {"action": "release_gate", "container": "C", "truck": "T",
             "booking": "B"})
        self.assertEqual(glimmer.parse_decision('{"action": "noop"}'),
                         {"action": "noop"})

    def test_garbage_becomes_noop(self):
        for bad in ("not json", "[1, 2]", '"str"', "42", "",
                    '{"action": "rm_rf"}', '{"action": "set_speed"}',
                    '{"action": "set_speed", "rpm": true}',
                    '{"action": "set_speed", "rpm": "fast"}',
                    '{"action": "release_gate", "container": "C"}',
                    '{"rpm": 1200}'):
            with self.subTest(bad=bad):
                self.assertEqual(glimmer.parse_decision(bad)["action"],
                                 "noop")

    def test_prompt_carries_state_and_envelope(self):
        prompt = glimmer.build_prompt({"temperature": {"value": 85.0},
                                       "last_speed_rpm": 1000})
        self.assertIn("85.0", prompt)
        self.assertIn(str(glimmer.SPEED_POLICY_MAX), prompt)


class GovernedLoopTest(unittest.TestCase):
    """The gateway judges; the wire moves only on allow."""

    def test_in_policy_setpoint_allowed(self):
        backend = glimmer.StubBackend(
            ['{"action": "set_speed", "rpm": 1200}'])
        decision, record = glimmer.evaluate(
            backend, {}, fresh_gateway(), operator_credential())
        self.assertEqual(decision, {"action": "set_speed", "rpm": 1200})
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br1-allow-plc-write")

    def test_out_of_policy_setpoint_denied(self):
        backend = glimmer.StubBackend(
            ['{"action": "set_speed", "rpm": 3000}'])
        decision, record = glimmer.evaluate(
            backend, {}, fresh_gateway(), operator_credential())
        self.assertEqual(record["decision"], "deny")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br9-deny-above-range")

    def test_unbooked_release_quarantined(self):
        backend = glimmer.StubBackend(
            ['{"action": "release_gate", "container": "XXXX000000", '
             '"truck": "TRK-99", "booking": "BK-FAKE"}'])
        _, record = glimmer.evaluate(backend, {}, fresh_gateway(),
                                     operator_credential())
        self.assertEqual(record["decision"], "quarantine")
        self.assertEqual(record["matched_rule"]["id"],
                         "pol-br3-quarantine-unbooked")

    def test_wire_moves_only_on_allow(self):
        """Denied attempts are never executed on MQTT/Modbus."""
        calls = []

        class FakePlc:
            def write_register(self, *a, **k):
                calls.append(("plc", a))

        class FakeMqtt:
            def publish(self, *a, **k):
                calls.append(("mqtt", a))

        op = glimmer.GlimmerOperator.__new__(glimmer.GlimmerOperator)
        op.plc, op.mqtt = FakePlc(), FakeMqtt()
        op.state = {"last_speed_rpm": 1000}

        op._execute({"action": "set_speed", "rpm": 3000},
                    {"decision": "deny"})
        op._execute({"action": "release_gate", "container": "C",
                     "truck": "T", "booking": "B"},
                    {"decision": "quarantine"})
        self.assertEqual(calls, [])

        op._execute({"action": "set_speed", "rpm": 1200},
                    {"decision": "allow"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "plc")

    def test_ten_stub_cycles_log_jsonl_offline(self):
        """Acceptance mechanic: 10+ cycles, one JSONL line each."""
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "glimmer.jsonl"
            backend = glimmer.StubBackend(
                ['{"action": "noop"}'] * 12)
            gateway, cred = fresh_gateway(), operator_credential()
            for _ in range(12):
                decision, record = glimmer.evaluate(
                    backend, {"temperature": {"value": 72.0}},
                    gateway, cred)
                glimmer.log_cycle(log, backend.name,
                                  {"temperature": {"value": 72.0}},
                                  decision, record)
            lines = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 12)
            entry = json.loads(lines[0])
            for key in ("ts", "state", "decision", "verdict",
                        "matched_rule"):
                self.assertIn(key, entry)

    def test_policy_file_untouched_by_cycles(self):
        before = POLICY_PATH.read_bytes()
        backend = glimmer.StubBackend(
            ['{"action": "set_speed", "rpm": 3000}'])
        glimmer.evaluate(backend, {}, fresh_gateway(),
                         operator_credential())
        self.assertEqual(POLICY_PATH.read_bytes(), before)


class SeparationTest(unittest.TestCase):
    """Own process identity: own client ID, own credential."""

    def test_own_mqtt_client_id(self):
        self.assertEqual(glimmer.MQTT_CLIENT_ID,
                         "sentinel-glimmer-operator")
        self.assertNotEqual(glimmer.MQTT_CLIENT_ID, agents.MQTT_CLIENT_ID)

    def test_no_wildcard_subscribes(self):
        for topic in glimmer.SUBSCRIBE_TOPICS:
            self.assertNotIn("#", topic)
            self.assertNotIn("+", topic)

    def test_backends_are_local_only(self):
        self.assertEqual(glimmer.OllamaBackend("m").host,
                         "http://127.0.0.1:11434")

    def test_default_ollama_tag_is_official_glimmer(self):
        backend = glimmer.make_backend("ollama", None)
        self.assertEqual(backend.model, "muse-glimmer:30b")


class OllamaResilienceTest(unittest.TestCase):
    """One slow first load must not kill the operator (bounded retries)."""

    def _canned(self, text='{"action": "noop"}'):
        body = json.dumps({"response": text}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = body
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    def test_generate_retries_transient_timeout_then_succeeds(self):
        backend = glimmer.OllamaBackend("muse-glimmer:30b")
        with mock.patch("urllib.request.urlopen",
                        side_effect=[TimeoutError("timed out"),
                                     self._canned()]) as m_open, \
                mock.patch("time.sleep") as m_sleep:
            text = backend.generate('{"action": "noop"}')
        self.assertEqual(text, '{"action": "noop"}')
        self.assertEqual(m_open.call_count, 2)
        self.assertEqual(m_sleep.call_count, 1)
        sent = json.loads(m_open.call_args[0][0].data.decode())
        self.assertEqual(sent["model"], "muse-glimmer:30b")
        self.assertEqual(sent["keep_alive"], "30m")

    def test_generate_raises_after_retries_exhausted(self):
        backend = glimmer.OllamaBackend("muse-glimmer:30b", retries=1)
        with mock.patch("urllib.request.urlopen",
                        side_effect=TimeoutError("timed out")), \
                mock.patch("time.sleep"):
            with self.assertRaises(SystemExit):
                backend.generate("prompt")

    def test_generate_defaults_cover_slow_first_load(self):
        backend = glimmer.OllamaBackend("m")
        self.assertGreater(backend.timeout, 300)
        self.assertGreaterEqual(backend.retries, 1)
        self.assertEqual(backend.keep_alive, "30m")

    def test_ensure_log_touch_creates_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "sub" / "glimmer_operator.jsonl"
            glimmer._ensure_log(log)
            self.assertTrue(log.exists())
            self.assertEqual(log.stat().st_size, 0)
            log.write_text('{"a": 1}\n', encoding="utf-8")
            glimmer._ensure_log(log)
            self.assertEqual(log.read_text(encoding="utf-8"),
                             '{"a": 1}\n')


if __name__ == "__main__":
    unittest.main()

"""Glimmer-driven operator agent (P2-12). Runs in its own process.

The operator role, but driven by a local model on the edge node instead of
a script: every ~10s it perceives the latest sensor/telemetry state, asks
the local model for ONE operational action (setpoint adjustment, gate
release, or no-op), submits that action to the real gateway
(sentinel.enforce.Gateway — unchanged code, unchanged policy.json), and
only executes it on the wire (MQTT publish / Modbus write) when the
verdict is allow. Denied attempts are logged and never executed.

GOVERNED side, never governor: the model decides what the agent ATTEMPTS;
code-only decide() decides what is ALLOWED. No model output goes into
enforcement, policy, revocation, or audit. The scripted sim/agents.py is
untouched and remains the fallback demo.

Backends (all local, no API calls, no network beyond localhost):
  ollama            — `muse-glimmer:30b` pulled into the local Ollama
      daemon (official Ollama build, ~18GB). Easiest path: install
      Ollama, `ollama pull muse-glimmer:30b`, run with
      --backend ollama. Inference stays on localhost.
  llama.cpp (default) — GGUF weights in the gitignored models/ dir, e.g.
      models/glimmer-30b-q4.gguf (official:
      meta-models/Muse-Glimmer-30B-GGUF, file
      Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf, Apache 2.0).
      Needs ~24GB RAM headroom.

Hardware gate (P2-12 Step 0) runs before anything else:
    python3 sim/glimmer_operator.py --hardware-gate
On a machine that cannot hold the weights it reports FAIL and the
operator exits without downloading anything — scripted agents stay
the demo (spec fallback).

Every cycle appends one JSONL line (timestamp, perceived state summary,
model's decided action, gateway verdict, matched rule) to
data/glimmer_operator.jsonl (gitignored, console-readable) and prints a
one-line human-readable summary.

Run on capable hardware (example):
    ollama pull muse-glimmer:30b  # once, ~18GB into the local daemon
    python3 sim/glimmer_operator.py --backend ollama --cycles 0
Loop check without weights (deterministic stub, offline):
    python3 sim/glimmer_operator.py --backend stub --cycles 10
"""

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow `python3 sim/glimmer_operator.py` script runs to import sentinel.*.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = REPO_ROOT / "data" / "glimmer_operator.jsonl"
DEFAULT_WEIGHTS = REPO_ROOT / "models" / "glimmer-30b-q4.gguf"

# P2-12 Step 0 thresholds: 4-bit 30B weights need ~24GB headroom and
# ~17-20GB of weights on disk.
REQUIRED_RAM_GB = 24.0
REQUIRED_DISK_GB = 21.0

MQTT_CLIENT_ID = "sentinel-glimmer-operator"
CREDENTIAL_ROLE = "operator-agent"
CREDENTIAL_SCOPE = ["telemetry.read", "plc.write", "gate.release"]

# Explicit subscribes only (starter rule 4 forbids wildcard subscribes
# for non-gateway agents). Same topics as the scripted operator.
TOPIC_TEMPERATURE = "site/line1/sensors/temperature"
TOPIC_VIBRATION = "site/line1/sensors/vibration"
TOPIC_GATE_EVENT = "site/yard/gate/event"
TOPIC_GATE_RELEASE = "site/yard/gate/release"
SUBSCRIBE_TOPICS = (TOPIC_TEMPERATURE, TOPIC_VIBRATION, TOPIC_GATE_EVENT)

SPEED_POLICY_MAX = 1500  # operator's known in-policy envelope (RPM)
CYCLE_SECONDS = 10.0


# ---------------------------------------------------------------------------
# Step 0 — hardware gate (runs before any download or inference)
# ---------------------------------------------------------------------------

def _ram_gb():
    """Total physical RAM in GiB, or None if it cannot be determined."""
    try:
        import os
        if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names:
            pages = os.sysconf("SC_PHYS_PAGES")
            return pages * os.sysconf("SC_PAGE_SIZE") / 1024**3
    except (ValueError, OSError):
        pass
    return None


def hardware_gate(weights_path=None):
    """Check this machine can hold 4-bit Glimmer 30B weights.

    Returns a JSON-serializable dict with ram_gb, free_disk_gb,
    weights_present, verdict ("pass"|"fail") and reasons. Never
    downloads anything, never raises on missing /proc or sysconf.
    """
    weights = Path(weights_path or DEFAULT_WEIGHTS)
    ram = _ram_gb()
    try:
        free_disk = shutil.disk_usage(weights.parent
                                      if weights.parent.exists()
                                      else REPO_ROOT).free / 1024**3
    except OSError:
        free_disk = None
    reasons = []
    if ram is None:
        reasons.append("could not determine total RAM")
    elif ram < REQUIRED_RAM_GB:
        reasons.append(f"RAM {ram:.1f}GB < {REQUIRED_RAM_GB:.0f}GB headroom")
    if free_disk is None:
        reasons.append("could not determine free disk")
    elif free_disk < REQUIRED_DISK_GB:
        reasons.append(f"free disk {free_disk:.1f}GB < "
                       f"{REQUIRED_DISK_GB:.0f}GB for weights")
    weights_present = weights.exists()
    verdict = "pass" if not reasons else "fail"
    return {
        "ram_gb": None if ram is None else round(ram, 1),
        "free_disk_gb": None if free_disk is None else round(free_disk, 1),
        "required_ram_gb": REQUIRED_RAM_GB,
        "required_disk_gb": REQUIRED_DISK_GB,
        "weights_path": str(weights),
        "weights_present": weights_present,
        "verdict": verdict,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Local-model backends (governed side only)
# ---------------------------------------------------------------------------

class LlamaCppBackend:
    """llama.cpp inference over a local GGUF file (default backend)."""

    name = "llama.cpp"

    def __init__(self, weights_path):
        self.weights_path = str(weights_path)
        self._model = None

    def generate(self, prompt):
        if self._model is None:
            try:
                from llama_cpp import Llama
            except ImportError as exc:
                raise SystemExit(
                    "llama-cpp-python is not installed. On the compute "
                    "node: pip install llama-cpp-python "
                    "(Metal/CUDA build per that machine).") from exc
            if not Path(self.weights_path).exists():
                raise SystemExit(
                    f"weights not found: {self.weights_path} — download "
                    "the 4-bit Glimmer 30B GGUF into the gitignored "
                    "models/ dir first (never commit weights).")
            self._model = Llama(model_path=self.weights_path, n_ctx=4096,
                                verbose=False)
        out = self._model.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.2, max_tokens=256)
        return out["choices"][0]["message"]["content"]


class OllamaBackend:
    """Local Ollama daemon (localhost only, no API key, no cloud)."""

    name = "ollama"

    def __init__(self, model, host="http://127.0.0.1:11434"):
        self.model = model
        self.host = host

    def generate(self, prompt):
        import urllib.request
        body = json.dumps({"model": self.model, "prompt": prompt,
                           "stream": False,
                           "options": {"temperature": 0.2}}).encode()
        req = urllib.request.Request(
            self.host + "/api/generate", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                payload = json.loads(resp.read().decode())
        except Exception as exc:
            raise SystemExit(
                f"ollama daemon unreachable at {self.host} "
                f"(is `ollama serve` running? model `{self.model}` "
                f"pulled?): {exc}") from exc
        text = payload.get("response", "")
        if not isinstance(text, str) or not text.strip():
            raise SystemExit(f"ollama model `{self.model}` returned no "
                             "text — is it pulled?")
        return text


class StubBackend:
    """Deterministic stand-in for loop checks (tests, no weights)."""

    name = "stub"

    def __init__(self, script=None):
        self._script = list(script or [])
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        if self._script:
            return self._script.pop(0)
        return '{"action": "noop"}'


def make_backend(kind, model):
    """Build a local backend. `model` is a weights path (llama.cpp),
    an Ollama tag (ollama), or ignored (stub)."""
    if kind == "llama.cpp":
        return LlamaCppBackend(model or str(DEFAULT_WEIGHTS))
    if kind == "ollama":
        return OllamaBackend(model or "muse-glimmer:30b")
    if kind == "stub":
        return StubBackend()
    raise SystemExit(f"unknown backend: {kind!r} "
                     "(llama.cpp | ollama | stub)")


# ---------------------------------------------------------------------------
# Perceive → decide (pure helpers: prompt building + fail-closed parsing)
# ---------------------------------------------------------------------------

PROMPT_TEMPLATE = """You are the operator agent for a plant line and a truck
yard. Given the latest telemetry, output ONE operational action as JSON
only, no other text: {{"action": <name>, ...}}.
Allowed actions:
  {{"action": "set_speed", "rpm": <0-{speed_max}>}}
  {{"action": "release_gate", "container": <id>, "truck": <id>,
    "booking": <id>}}  (only when a gate event names all three)
  {{"action": "noop"}}  (when nothing needs doing — prefer this)
Rules: stay within 0-{speed_max} RPM; release only containers named by a
recent gate event; when in doubt, noop.
State:
{state}
JSON:"""


def summarize_state(state):
    """Compact the perceived state for the prompt and the JSONL log."""
    return {
        "temperature_c": (state.get("temperature") or {}).get("value"),
        "vibration_mm_s": (state.get("vibration") or {}).get("value"),
        "last_speed_rpm": state.get("last_speed_rpm"),
        "line_running": state.get("line_running"),
        "gate_event": state.get("gate_event"),
    }


def build_prompt(state):
    """Render the decide prompt from the perceived state (pure)."""
    return PROMPT_TEMPLATE.format(
        speed_max=SPEED_POLICY_MAX,
        state=json.dumps(summarize_state(state), sort_keys=True))


def parse_decision(text):
    """Parse the model's reply into an action dict (pure, fail-closed).

    Anything unparseable, unknown, or malformed becomes a noop — a
    confused governed agent holds still; it never acts raw.
    """
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return {"action": "noop", "parse_error": True}
    if not isinstance(payload, dict):
        return {"action": "noop", "parse_error": True}
    action = payload.get("action")
    if action == "noop":
        return {"action": "noop"}
    if action == "set_speed":
        rpm = payload.get("rpm")
        if isinstance(rpm, bool) or not isinstance(rpm, (int, float)):
            return {"action": "noop", "parse_error": True}
        return {"action": "set_speed", "rpm": int(rpm)}
    if action == "release_gate":
        container, truck, booking = (payload.get("container"),
                                     payload.get("truck"),
                                     payload.get("booking"))
        if not all(isinstance(v, str) and v for v in
                   (container, truck, booking)):
            return {"action": "noop", "parse_error": True}
        return {"action": "release_gate", "container": container,
                "truck": truck, "booking": booking}
    return {"action": "noop", "parse_error": True}


# ---------------------------------------------------------------------------
# Act → observe (gateway verdict first, wire action only on allow)
# ---------------------------------------------------------------------------

def evaluate(backend, state, gateway, credential):
    """One decide + govern step: returns (decision, record).

    The gateway is the unchanged sentinel.enforce.Gateway over the
    unchanged data/policy.json — the same code the console uses.
    """
    decision = parse_decision(backend.generate(build_prompt(state)))
    action = decision["action"]
    if action == "set_speed":
        record = gateway.plc_write(credential, "setpoint",
                                   decision["rpm"])
    elif action == "release_gate":
        record = gateway.release_gate(credential, decision["container"],
                                      decision["truck"],
                                      decision["booking"])
    else:
        # Noop attempts nothing, so there is nothing to judge — no
        # gateway request, no audit record, no metric pollution.
        record = {"decision": "noop", "matched_rule": {"id": None}}
    return decision, record


def log_cycle(log_path, backend_name, state, decision, record):
    """Append one JSONL line; return the one-line human summary."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "backend": backend_name,
        "state": summarize_state(state),
        "decision": decision,
        "verdict": record.get("decision"),
        "matched_rule": (record.get("matched_rule") or {}).get("id"),
    }
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    detail = ""
    if decision["action"] == "set_speed":
        detail = f" rpm={decision['rpm']}"
    elif decision["action"] == "release_gate":
        detail = f" {decision['container']}/{decision['truck']}"
    rule = entry["matched_rule"] or "no request"
    return (f"glimmer: {decision['action']}{detail} -> "
            f"{record.get('decision')} ({rule})")


class GlimmerOperator:
    """Own process, own MQTT client ID, own credential (like agents.py)."""

    def __init__(self, backend, mqtt_host, mqtt_port, plc_host, plc_port,
                 log_path=DEFAULT_LOG, gateway=None):
        import paho.mqtt.client as mqtt
        from pymodbus.client import ModbusTcpClient

        from sentinel import enforce, identity

        self.backend = backend
        self.log_path = Path(log_path)
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                client_id=MQTT_CLIENT_ID)
        self.mqtt.on_message = self.on_message
        self.mqtt_host, self.mqtt_port = mqtt_host, mqtt_port
        self.plc = ModbusTcpClient(plc_host, port=plc_port)
        self.gateway = gateway or enforce.Gateway()
        self.state = {"last_speed_rpm": 1000, "line_running": True,
                      "temperature": None, "vibration": None,
                      "gate_event": None}
        self.credential = identity.issue(CREDENTIAL_ROLE, "sentinel-ca",
                                         CREDENTIAL_SCOPE)
        self.credential_id = json.loads(self.credential)["id"]

    def on_message(self, _client, _userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
        except ValueError:
            return
        if msg.topic == TOPIC_TEMPERATURE:
            self.state["temperature"] = data
        elif msg.topic == TOPIC_VIBRATION:
            self.state["vibration"] = data
        elif msg.topic == TOPIC_GATE_EVENT:
            if data.get("event") == "truck_arrival":
                self.state["gate_event"] = data

    def _execute(self, decision, record):
        """Wire action, ONLY after an allow verdict (the choke point)."""
        if record.get("decision") != "allow":
            return
        if decision["action"] == "set_speed":
            rpm = max(0, min(SPEED_POLICY_MAX, decision["rpm"]))
            self.plc.write_register(1, rpm, device_id=1)
            self.state["last_speed_rpm"] = rpm
        elif decision["action"] == "release_gate":
            self.mqtt.publish(TOPIC_GATE_RELEASE, json.dumps({
                "container": decision["container"],
                "truck": decision["truck"],
                "booking": decision["booking"],
                "decision": "allow", "ts": time.time()}))

    def cycle(self):
        """Perceive → decide → govern → (maybe) act → log."""
        perceived = dict(self.state)
        decision, record = evaluate(self.backend, self.state,
                                    self.gateway, self.credential)
        self._execute(decision, record)
        line = log_cycle(self.log_path, self.backend.name, perceived,
                         decision, record)
        print(line, flush=True)
        return decision, record

    def run(self, cycles=0, interval=CYCLE_SECONDS):
        print(f"glimmer-operator: backend={self.backend.name} "
              f"credential id={self.credential_id} "
              f"role={CREDENTIAL_ROLE}", flush=True)
        self.plc.connect()
        self.mqtt.connect(self.mqtt_host, self.mqtt_port)
        for topic in SUBSCRIBE_TOPICS:
            self.mqtt.subscribe(topic)
        self.mqtt.loop_start()
        print(f"glimmer-operator: subscribed to "
              f"{', '.join(SUBSCRIBE_TOPICS)}", flush=True)
        done = 0
        try:
            while cycles <= 0 or done < cycles:
                time.sleep(interval)
                self.cycle()
                done += 1
        except KeyboardInterrupt:
            pass
        finally:
            self.mqtt.loop_stop()
            self.mqtt.disconnect()
            self.plc.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Glimmer-driven operator agent (P2-12, governed side).")
    parser.add_argument("--backend", default="llama.cpp",
                        choices=("llama.cpp", "ollama", "stub"))
    parser.add_argument("--model", default=None,
                        help="weights path (llama.cpp) or local tag "
                             "(ollama); ignored for stub")
    parser.add_argument("--cycles", type=int, default=0,
                        help="cycles to run (0 = forever)")
    parser.add_argument("--interval", type=float, default=CYCLE_SECONDS)
    parser.add_argument("--log", default=str(DEFAULT_LOG))
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--plc-host", default="127.0.0.1")
    parser.add_argument("--plc-port", type=int, default=5020)
    parser.add_argument("--hardware-gate", action="store_true",
                        help="print the Step 0 hardware report and exit")
    parser.add_argument("--skip-gate", action="store_true",
                        help="run despite a FAIL verdict (dev only: the "
                             "verdict is still printed and logged)")
    args = parser.parse_args()

    gate = hardware_gate(args.model if args.backend == "llama.cpp"
                         and args.model else None)
    if args.hardware_gate:
        print(json.dumps(gate, indent=2))
        raise SystemExit(0 if gate["verdict"] == "pass" else 1)
    print(f"hardware gate: {gate['verdict']} "
          f"(RAM {gate['ram_gb']}GB, free disk {gate['free_disk_gb']}GB)",
          flush=True)
    if gate["verdict"] == "fail" and not args.skip_gate:
        print("FAIL reasons: " + "; ".join(gate["reasons"]), flush=True)
        print("Local Glimmer 30B is not viable on this machine — not "
              "downloading weights. Scripted sim/agents.py remains the "
              "demo (spec fallback).", flush=True)
        raise SystemExit(2)

    backend = make_backend(args.backend, args.model)
    GlimmerOperator(backend, args.mqtt_host, args.mqtt_port,
                    args.plc_host, args.plc_port,
                    log_path=args.log).run(cycles=args.cycles,
                                           interval=args.interval)


if __name__ == "__main__":
    main()

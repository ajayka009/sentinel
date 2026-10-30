"""Layer 5 — Demo console (Streamlit).

The console IS the demo: anyone opening it can explore the whole system
without narration and can fire attacks themselves from the Red team tab.

Offline by construction: everything reads the committed cached artifacts
(data/graph.json, threats.json, policy.json) plus the local audit trail.
The live loop never calls a cloud model — API calls are needed only to
*regenerate* the artifacts, never to *run* the demo. The only model
allowed near runtime is the display-only explainer (sentinel.enforce.explain),
which can never change a decision and falls back to a template offline.

Run from the repo root:

    streamlit run console/app.py

Layout: pure helpers first (importable without streamlit, covered by
tests/test_console.py), Streamlit UI last (streamlit imported lazily
inside main() so the helpers stay stdlib-only and offline-testable).
"""

import csv
import fnmatch
import html
import io
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow `streamlit run console/app.py` from anywhere to import sentinel.*.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import enforce, identity  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
GRAPH_PATH = DATA_DIR / "graph.json"
THREATS_PATH = DATA_DIR / "threats.json"
POLICY_PATH = DATA_DIR / "policy.json"
BUSINESS_RULES_PATH = DATA_DIR / "business_rules.txt"
REGISTRY_PATH = DATA_DIR / "registry.yaml"
AUDIT_PATH = DATA_DIR / "audit.jsonl"

OPERATOR_SCOPE = ["telemetry.read", "plc.write", "gate.release"]
ROGUE_SCOPE = ["telemetry.read"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# The seven spec attacks the Red team tab must fire on demand.
ATTACK_IDS = (
    "wildcard-recon",
    "forged-plc-write",
    "spoofed-reefer-temp",
    "fake-gate-release",
    "unknown-device-connect",
    "publish-flood",
    "out-of-range-setpoint",
)


# ---------------------------------------------------------------------------
# Cached-artifact loaders (pure, offline, no model calls)
# ---------------------------------------------------------------------------

def load_json(path):
    """Parse a JSON artifact; raise FileNotFoundError with a regen hint."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing — regenerate it with its Layer script "
            f"(needs META_API_KEY); the console itself runs offline.")
    return json.loads(path.read_text(encoding="utf-8"))


def load_graph(path=None):
    return load_json(path or GRAPH_PATH)


def load_threats(path=None):
    return load_json(path or THREATS_PATH)


def load_policy(path=None):
    return load_json(path or POLICY_PATH)


def load_business_rules(path=None):
    """Parse data/business_rules.txt into [{id: 'BR-N', text: ...}]."""
    path = Path(path or BUSINESS_RULES_PATH)
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing.")
    rules = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        number, _, text = line.partition(".")
        number = number.strip()
        if number.isdigit() and text.strip():
            rules.append({"id": f"BR-{number}", "text": text.strip()})
    return rules


def load_registry(path=None):
    """Parse data/registry.yaml (stdlib fallback if pyyaml is missing)."""
    path = Path(path or REGISTRY_PATH)
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing.")
    try:
        import yaml
    except ImportError:
        return {"_raw": path.read_text(encoding="utf-8")}
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Audit trail + metrics (pure)
# ---------------------------------------------------------------------------

def read_audit_log(audit_path=None, limit=1000):
    """Tail the JSONL audit log; missing file -> [], bad lines skipped."""
    path = Path(audit_path or AUDIT_PATH)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    records = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def collect_records(gateway=None, audit_path=None, limit=1000):
    """File-first audit view: the log file is the source of truth.

    The console gateway writes through to the same file, so the tail
    already includes this session's records. When the file is missing
    or empty (fresh checkout, read-only dir), fall back to the
    gateway's in-memory trail so the feed never goes blank.
    """
    records = read_audit_log(audit_path, limit)
    if records:
        return records
    if gateway is not None:
        return list(gateway.audit_trail[-limit:])
    return []


def _parse_ts(value):
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def compute_metrics(records):
    """Roll audit records into dashboard counters (pure).

    Returns total/allowed/denied/quarantined/flagged/blocked counts,
    deny_rate, trailing-60s actions_per_min, per-rule/per-agent/
    per-resource breakdowns, and a per-minute timeline.
    """
    total = len(records)
    allowed = sum(1 for r in records if r.get("decision") == "allow")
    denied = sum(1 for r in records if r.get("decision") == "deny")
    quarantined = sum(1 for r in records if r.get("decision") == "quarantine")
    flagged = sum(1 for r in records if r.get("flagged"))
    blocked = denied + quarantined

    per_rule, per_agent, per_resource = {}, {}, {}
    for record in records:
        rule_id = record.get("matched_rule", {}).get("id", "unknown")
        slot = per_rule.setdefault(
            rule_id, {"hits": 0, "allowed": 0, "denied": 0})
        slot["hits"] += 1
        slot["allowed" if record.get("decision") == "allow"
             else "denied"] += 1
        for key, table in (("subject", per_agent),
                           ("resource", per_resource)):
            name = record.get(key, "unknown") or "unknown"
            slot = table.setdefault(
                name, {"hits": 0, "allowed": 0, "denied": 0})
            slot["hits"] += 1
            slot["allowed" if record.get("decision") == "allow"
                 else "denied"] += 1

    stamps = [(r, _parse_ts(r.get("ts"))) for r in records]
    stamps = [(r, ts) for r, ts in stamps if ts is not None]
    buckets = {}
    for record, ts in stamps:
        key = ts.strftime("%H:%M")
        slot = buckets.setdefault(key, {"allow": 0, "deny": 0,
                                        "quarantine": 0})
        decision = record.get("decision")
        if decision in slot:
            slot[decision] += 1
    timeline = [{"time": key, **buckets[key]}
                for key in sorted(buckets)[-30:]]

    if stamps:
        latest = max(ts for _, ts in stamps)
        actions_per_min = sum(
            1 for _, ts in stamps if (latest - ts).total_seconds() <= 60)
    else:
        actions_per_min = total

    return {
        "total": total,
        "allowed": allowed,
        "denied": denied,
        "quarantined": quarantined,
        "flagged": flagged,
        "blocked": blocked,
        "deny_rate": (blocked / total) if total else 0.0,
        "actions_per_min": actions_per_min,
        "per_rule": per_rule,
        "per_agent": per_agent,
        "per_resource": per_resource,
        "timeline": timeline,
    }


def rule_hit_counts(records):
    """Map matched-rule id -> hit count (for the Policies tab)."""
    counts = {}
    for record in records:
        rule_id = record.get("matched_rule", {}).get("id", "unknown")
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return counts


def group_policy_rules(policy):
    """Lineage: business-rule id -> machine rules, plus infra/proposed."""
    groups = {}
    for rule in policy.get("rules", []):
        key = rule.get("business_rule") or "INFRA"
        groups.setdefault(key, []).append(rule)
    proposed = list(policy.get("proposed_rules", []))
    return {"groups": groups, "proposed": proposed}


def device_policy_coverage(device_id, device_topics, policy_rules):
    """Machine rules governing a device.

    A rule covers the device when its subject names the device, when its
    resource glob matches one of the device's topics, or when its
    resource namespace matches the device family (plc.* -> plc-line1,
    camera.* -> camera-line1). Bare subject+resource wildcards (BR-7/BR-8
    identity and rate rules) govern agents, not devices, and are skipped.
    """
    tokens = set(device_id.split("-"))
    topics = [f"topic:{t}" for t in (device_topics or [])]
    covered = []
    for rule in policy_rules:
        subject, pattern = rule.get("subject"), rule.get("resource", "")
        if subject == device_id:
            covered.append(rule)
            continue
        if pattern == "*":
            continue
        if any(fnmatch.fnmatchcase(t, pattern) for t in topics):
            covered.append(rule)
            continue
        namespace = pattern.split(":")[-1].split(".")[0].split("/")[0]
        if namespace in tokens:
            covered.append(rule)
    return covered


def credential_rows(creds, gateway=None):
    """Demo credential table rows with live verify status.

    `creds` maps a display label -> credential JSON string. A revoked
    credential whose role also holds a tightening overlay reads as
    quarantined (quarantine = revoked + overlay deny).
    """
    quarantined_roles = set()
    if gateway is not None:
        for rule in gateway.overlay_rules:
            if rule.get("origin") == "enforcement-tightening":
                quarantined_roles.add(rule.get("subject"))
    rows = []
    for label, token in creds.items():
        payload, status = identity.verify_status(token)
        claimed = payload or identity._coerce(token) or {}
        if status == "revoked" and claimed.get("role") in quarantined_roles:
            status = "quarantined"
        rows.append({
            "label": label,
            "id": (claimed.get("id") or "?")[:12],
            "role": claimed.get("role", "?"),
            "scope": ", ".join(claimed.get("scope", []) or []),
            "status": status,
        })
    return rows


def export_audit_json(records):
    return json.dumps(records, indent=2)


def export_audit_csv(records):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["seq", "ts", "subject", "action", "resource",
                     "decision", "flagged", "rule_id", "business_rule",
                     "policy_change"])
    for record in records:
        matched = record.get("matched_rule", {})
        writer.writerow([record.get("seq"), record.get("ts"),
                         record.get("subject"), record.get("action"),
                         record.get("resource"), record.get("decision"),
                         record.get("flagged"), matched.get("id"),
                         matched.get("business_rule"),
                         record.get("policy_change") or ""])
    return buffer.getvalue()


def check_health(timeout=0.5):
    """Probe broker/PLC/gateway/yard-link; never raises, offline-safe."""
    def probe(host, port):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, (time.perf_counter() - start) * 1000.0
        except OSError:
            return False, None

    broker_ok, broker_ms = probe("127.0.0.1", 1883)
    plc_ok, plc_ms = probe("127.0.0.1", 5020)
    try:
        policy = load_policy()
        gateway_ok = bool(policy.get("rules"))
        detail = f"{len(policy.get('rules', []))} rules loaded"
    except (FileNotFoundError, ValueError):
        gateway_ok, detail = False, "policy.json missing"
    return {
        "broker": {"ok": broker_ok, "latency_ms": broker_ms,
                   "detail": "mosquitto 127.0.0.1:1883"},
        "plc": {"ok": plc_ok, "latency_ms": plc_ms,
                "detail": "modbus localhost:5020"},
        "gateway": {"ok": gateway_ok, "latency_ms": None, "detail": detail},
        "yard_link": {"ok": broker_ok, "latency_ms": broker_ms,
                      "detail": "simulated-constrained link via broker"},
    }


# ---------------------------------------------------------------------------
# Red-team scenarios (pure w.r.t. streamlit; deterministic, offline)
# ---------------------------------------------------------------------------

def _fresh(role, scope, tag, creds):
    """Issue a credential and register it in the demo creds dict."""
    token = identity.issue(role, "sentinel-ca", scope)
    label = f"{tag}-{identity._coerce(token)['id'][:6]}"
    creds[label] = token
    return token


def _revoked_followup(gateway, token):
    """Show the BR-7 short-circuit: a revoked cred stays revoked."""
    return gateway.mqtt_subscribe(token, "site/line1/sensors/temperature")


def _scenario_wildcard_recon(gateway, creds):
    rogue = _fresh("rogue-recon", ROGUE_SCOPE, "rogue-recon", creds)
    first = gateway.mqtt_subscribe(rogue, "#")
    return [first, _revoked_followup(gateway, rogue)]


def _scenario_forged_plc_write(gateway, creds):
    rogue = _fresh("rogue-plc", ROGUE_SCOPE, "rogue-plc", creds)
    return [gateway.plc_write(rogue, "setpoint", 3000)]


def _scenario_spoofed_reefer(gateway, creds):
    reefer = _fresh("reefer-container-1", ["telemetry.write"],
                    "reefer", creds)
    baseline = gateway.mqtt_publish(
        reefer, "site/yard/reefer/R-101/temperature", -20.0)
    rogue = _fresh("rogue-reefer", ROGUE_SCOPE, "rogue-reefer", creds)
    spoof = gateway.mqtt_publish(
        rogue, "site/yard/reefer/R-101/temperature", 5.0)
    return [baseline, spoof]


def _scenario_fake_gate_release(gateway, creds):
    rogue = _fresh("rogue-gate", ROGUE_SCOPE, "rogue-gate", creds)
    first = gateway.release_gate(rogue, "XXXX000000", "TRK-99", "BK-FAKE")
    return [first, _revoked_followup(gateway, rogue)]


def _scenario_unknown_device(gateway, creds):
    ghost = json.dumps({"id": "ghost-unknown-7", "role": "ghost-device",
                        "issuer": "nobody", "expiry": 9_999_999_999,
                        "scope": []})
    creds["ghost-unknown-7"] = ghost
    return [gateway.request(ghost, "publish",
                            "topic:site/yard/gate/release",
                            {"booking_match": True})]


def _scenario_publish_flood(gateway, creds):
    rogue = _fresh("rogue-flood", ROGUE_SCOPE, "rogue-flood", creds)
    return [gateway.mqtt_publish(rogue, "site/line1/sensors/temperature",
                                 72.0)
            for _ in range(35)]


def _scenario_out_of_range(gateway, creds):
    operator = _fresh("operator-agent", OPERATOR_SCOPE,
                      "operator-range", creds)
    return [gateway.plc_write(operator, "setpoint", 3000)]


def _scenario_operator_setpoint(gateway, creds):
    return [gateway.plc_write(creds["operator"], "setpoint", 1200)]


def _scenario_booked_release(gateway, creds):
    from sim import agents

    container, info = next(iter(agents.BOOKINGS.items()))
    return [gateway.release_gate(creds["operator"], container,
                                 info["truck"], info["booking"])]


SCENARIOS = {
    # The seven spec attacks (ATTACK_IDS), then the two legit calm beats.
    "wildcard-recon": {
        "label": "Wildcard recon (# subscribe)",
        "kind": "attack",
        "description": "Rogue subscribes to # to see every topic.",
        "expected": {"decision": "quarantine",
                     "rule": "pol-br4-quarantine-wildcard"},
        "run": _scenario_wildcard_recon,
    },
    "forged-plc-write": {
        "label": "Forged PLC write (3000 RPM)",
        "kind": "attack",
        "description": "Rogue forges a PLC setpoint above the safe range.",
        "expected": {"decision": "deny",
                     "rule": "pol-br9-deny-above-range"},
        "run": _scenario_forged_plc_write,
    },
    "spoofed-reefer-temp": {
        "label": "Spoofed reefer temp (+25C jump)",
        "kind": "attack",
        "description": "Rogue injects an implausible reefer temperature.",
        "expected": {"decision": "deny",
                     "rule": "pol-br5-flag-implausible-reefer"},
        "run": _scenario_spoofed_reefer,
    },
    "fake-gate-release": {
        "label": "Fake gate release (no booking)",
        "kind": "attack",
        "description": "Rogue requests a container release with no booking.",
        "expected": {"decision": "quarantine",
                     "rule": "pol-br3-quarantine-unbooked"},
        "run": _scenario_fake_gate_release,
    },
    "unknown-device-connect": {
        "label": "Unknown-device connect",
        "kind": "attack",
        "description": "A never-issued credential attempts a gate release.",
        "expected": {"decision": "deny",
                     "rule": "pol-br7-deny-unknown-revoked"},
        "run": _scenario_unknown_device,
    },
    "publish-flood": {
        "label": "Publish flood (35 rapid)",
        "kind": "attack",
        "description": "Rogue floods publishes to trip the BR-8 rate cap.",
        "expected": {"decision": "quarantine",
                     "rule": "pol-br8-quarantine-repeat"},
        "run": _scenario_publish_flood,
    },
    "out-of-range-setpoint": {
        "label": "Out-of-range setpoint",
        "kind": "attack",
        "description": "Out-of-range write rejected by condition check.",
        "expected": {"decision": "deny",
                     "rule": "pol-br9-deny-above-range"},
        "run": _scenario_out_of_range,
    },
    "operator-setpoint": {
        "label": "Operator setpoint 1200 (calm)",
        "kind": "legit",
        "description": "In-policy operator write; the Beat 0 baseline.",
        "expected": {"decision": "allow",
                     "rule": "pol-br1-allow-plc-write"},
        "run": _scenario_operator_setpoint,
    },
    "booked-gate-release": {
        "label": "Booked gate release (calm)",
        "kind": "legit",
        "description": "Release with matching container + truck + booking.",
        "expected": {"decision": "allow",
                     "rule": "pol-br3-allow-booked-release"},
        "run": _scenario_booked_release,
    },
}

# Demo-script order for "fire all": calm, recon, forged write, spoofed
# reefer, fake gate, then the rapid-fire aligned checks.
DEMO_SCRIPT_ORDER = (
    "operator-setpoint",
    "wildcard-recon",
    "forged-plc-write",
    "spoofed-reefer-temp",
    "fake-gate-release",
    "unknown-device-connect",
    "publish-flood",
    "out-of-range-setpoint",
    "booked-gate-release",
)


def issue_demo_creds():
    """Fresh session credentials (operator flow shares `operator`)."""
    return {
        "operator": identity.issue("operator-agent", "sentinel-ca",
                                   OPERATOR_SCOPE),
        "rogue": identity.issue("rogue-agent", "sentinel-ca", ROGUE_SCOPE),
        "sensor": identity.issue("sensor-temp-line1", "sentinel-ca",
                                 ["telemetry.write"]),
        "reefer": identity.issue("reefer-container-1", "sentinel-ca",
                                 ["telemetry.write"]),
        "camera": identity.issue("camera-line1", "sentinel-ca",
                                 ["frames.stream"]),
        "gateway": identity.issue("edge-gateway", "sentinel-ca",
                                  ["bridge.all"]),
    }


def run_scenario(gateway, scenario_id, creds):
    """Fire one red-team scenario; return its audit records.

    Each attack issues a fresh credential under its own rogue role
    (rogue-recon, rogue-plc, ...) so it demonstrates its own rule in
    isolation on the shared session gateway: a shared role would
    short-circuit to BR-7 or the tightening overlay after the first
    quarantine instead of showing each attack's stopping rule.
    Fresh creds are registered in `creds`. Quarantine scenarios append
    a revoked-retry followup proving the BR-7 short-circuit.
    Deterministic, offline, zero model calls.
    """
    try:
        scenario = SCENARIOS[scenario_id]
    except KeyError:
        raise ValueError(f"unknown scenario: {scenario_id!r}") from None
    return list(scenario["run"](gateway, creds))


def run_demo_script(gateway, creds):
    """Fire the full demo beats in order; return every audit record."""
    fired = []
    for scenario_id in DEMO_SCRIPT_ORDER:
        fired.extend(run_scenario(gateway, scenario_id, creds))
    return fired


# ---------------------------------------------------------------------------
# Streamlit UI (the only section that needs streamlit installed)
# ---------------------------------------------------------------------------

def _require_streamlit():
    try:
        import streamlit
    except ImportError:
        raise SystemExit(
            "streamlit is not installed. From the repo root:\n"
            "  pip install -r requirements.txt\n"
            "  streamlit run console/app.py") from None
    return streamlit


APP_CSS = """
/* Sentinel SOC console — flat dark ops panels. System fonts only
   (offline-safe). Severity colors: green allow, amber flag, red deny,
   solid red quarantine. Uses stable data-testid selectors; if one
   misses on a future Streamlit, that widget falls back to defaults. */
[data-testid="stMetric"] {
    background: #111922;
    border: 1px solid #223041;
    border-radius: 8px;
    padding: 10px 14px;
}
[data-testid="stMetricLabel"] {
    font-size: 0.78rem;
    color: #9aa7b1;
}
[data-testid="stMetricValue"] {
    font-variant-numeric: tabular-nums;
}
[data-testid="stSidebar"] {
    background: #090e13;
    border-right: 1px solid #1a2530;
}
[data-testid="stTable"], [data-testid="stDataFrame"] {
    font-size: 0.85rem;
    font-variant-numeric: tabular-nums;
}
[data-testid="stTabs"] button {
    font-size: 0.92rem;
}
code, .sent-mono {
    font-family: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas,
        monospace;
}
.sent-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 0 12px;
}
.sent-mark {
    width: 12px;
    height: 28px;
    background: #2dd4a8;
    border-radius: 2px;
}
.sent-name {
    font-size: 1.35rem;
    font-weight: 800;
    letter-spacing: 0.14em;
}
.sent-tag {
    font-size: 0.82rem;
    color: #9aa7b1;
}
.sent-brand .sent-pill {
    margin-left: auto;
}
.sent-feed {
    padding: 7px 10px;
    border: 1px solid #1f2c38;
    border-radius: 6px;
    margin-bottom: 6px;
    background: #0e151d;
    font-size: 0.85rem;
    line-height: 1.7;
}
.sent-pill {
    display: inline-block;
    min-width: 84px;
    text-align: center;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 2px 8px;
    margin-right: 8px;
    border-radius: 999px;
    border: 1px solid;
    white-space: nowrap;
}
.sent-allow { color: #3fb950; border-color: #3fb95066; background: #3fb95014; }
.sent-deny { color: #f85149; border-color: #f8514966; background: #f8514914; }
.sent-quarantine { color: #ffffff; background: #b62324; border-color: #b62324; }
.sent-flag { color: #d29922; border-color: #d2992266; background: #d2992214; }
.sent-info { color: #9aa7b1; border-color: #9aa7b166; background: #9aa7b114; }
.sent-ts { color: #8b949e; }
.sent-subj { font-weight: 600; }
.sent-rule { color: #8b949e; }
.sent-health {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 10px;
    border: 1px solid #1f2c38;
    border-radius: 6px;
    margin-bottom: 6px;
    background: #0e151d;
    font-size: 0.85rem;
}
.sent-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
    flex: none;
}
.sent-up { background: #3fb950; }
.sent-down { background: #f85149; }
.sent-comp { font-weight: 600; min-width: 90px; }
.sent-lat { margin-left: auto; color: #8b949e; }
.sent-stat {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    padding: 5px 0;
    border-bottom: 1px solid #1a2530;
    font-size: 0.85rem;
}
.sent-statnum {
    font-size: 1.1rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
}
"""

DECISION_PILL = {"allow": "allow", "deny": "deny", "quarantine": "quarantine"}

SEVERITY_PILL = {"critical": "quarantine", "high": "deny",
                 "medium": "flag", "low": "info"}


def _pill_html(text, kind):
    """Severity pill span; text is HTML-escaped."""
    return (f'<span class="sent-pill sent-{kind}">'
            f"{html.escape(str(text))}</span>")


def _brand_html(blocked, errors):
    """Console masthead: wordmark + tagline + armed/degraded status pill."""
    pill = (_pill_html(f"ARMED - {blocked} BLOCKED", "allow") if not errors
            else _pill_html("DEGRADED - ARTIFACT MISSING", "flag"))
    return (
        '<div class="sent-brand"><span class="sent-mark"></span>'
        "<div><div class=\"sent-name\">SENTINEL</div>"
        '<div class="sent-tag">Traditional firewalls inspect packets; '
        "Sentinel inspects intent.</div></div>"
        f"{pill}</div>")


def _health_html(health):
    """Compact status-dot rows for broker/PLC/gateway/yard-link."""
    rows = []
    for name, info in health.items():
        dot = ("sent-up" if info["ok"] else "sent-down")
        status = "up" if info["ok"] else "down"
        latency = (f"{info['latency_ms']:.1f} ms"
                   if info["latency_ms"] is not None else "-")
        rows.append(
            '<div class="sent-health">'
            f'<span class="sent-dot {dot}"></span>'
            f'<span class="sent-comp">{html.escape(name)}</span>'
            f"<span>{status} - {html.escape(info['detail'])}</span>"
            f'<span class="sent-lat sent-mono">{latency}</span></div>')
    return "\n".join(rows)


def _sidebar_stats_html(metrics):
    """Sidebar counters with tabular numerals."""
    return (
        '<div class="sent-stat"><span>Evaluated</span>'
        f"<span class=\"sent-statnum\">{metrics['total']}</span></div>"
        '<div class="sent-stat"><span>Blocked</span>'
        f"<span class=\"sent-statnum\">{metrics['blocked']}</span></div>")


def _init_session(st):
    if "gateway" not in st.session_state:
        st.session_state.gateway = enforce.Gateway(
            audit_path=str(AUDIT_PATH))
        st.session_state.creds = issue_demo_creds()
        st.session_state.last_fired = []
        st.session_state.latencies_ms = []
        st.session_state.live = True


def _reset_demo(st):
    try:
        AUDIT_PATH.write_text("", encoding="utf-8")
    except OSError:
        pass
    st.session_state.gateway = enforce.Gateway(audit_path=str(AUDIT_PATH))
    st.session_state.creds = issue_demo_creds()
    st.session_state.last_fired = []
    st.session_state.latencies_ms = []


def _feed_line(record):
    """One live-feed row: severity pill + mono identity/action/resource."""
    decision = record.get("decision", "?")
    pill = _pill_html(decision.upper(),
                      DECISION_PILL.get(decision, "info"))
    flag = (" " + _pill_html("FLAG", "flag") if record.get("flagged")
            else "")
    rule = record.get("matched_rule", {}).get("id", "?")
    ts = (record.get("ts") or "")[11:19]
    return (
        '<div class="sent-feed">'
        f"{pill}{flag}"
        f'<span class="sent-ts sent-mono">{html.escape(ts)}</span> '
        f"<span class=\"sent-subj\">"
        f"{html.escape(str(record.get('subject')))}</span> "
        f"<span class=\"sent-mono\">"
        f"{html.escape(str(record.get('action')))} "
        f"{html.escape(str(record.get('resource')))}</span> "
        f"<span class=\"sent-rule sent-mono\">"
        f"{html.escape(str(rule))}</span></div>")


def _render_feed(st, records, limit=15, key="feed"):
    st.subheader("Live feed")
    if not records:
        st.info("No decisions yet — fire an attack from the Red team tab.")
        return
    for record in records[-limit:][::-1]:
        st.markdown(_feed_line(record), unsafe_allow_html=True)
        if record.get("policy_change"):
            st.caption(f"Policy change: {record['policy_change']}")


def _chart_or_table(st, rows, x, y, title):
    st.write(f"**{title}**")
    if not rows:
        st.caption("No data yet.")
        return
    try:
        st.bar_chart(rows, x=x, y=y)
    except Exception:
        st.table(rows)


def _render_overview(st, data, records, metrics, health):
    blocked = metrics["blocked"]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Actions evaluated", metrics["total"])
    col2.metric("Blocked (deny + quarantine)", blocked,
                f"{metrics['quarantined']} quarantined",
                delta_color="inverse")
    col3.metric("Allowed", metrics["allowed"])
    col4.metric("Quarantined", metrics["quarantined"])
    graph = data.get("graph") or {}
    policy = data.get("policy") or {}
    nodes = graph.get("nodes", [])
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Actions/min (trailing 60s)", metrics["actions_per_min"])
    col2.metric("Deny rate", f"{metrics['deny_rate']:.0%}")
    col3.metric("Agents / devices",
                f"{sum(1 for n in nodes if n.get('kind') == 'agent')} / "
                f"{sum(1 for n in nodes if n.get('kind') == 'device')}")
    col4.metric("Machine rules", len(policy.get("rules", [])))
    latencies = st.session_state.get("latencies_ms", [])
    if latencies:
        st.caption(f"Decision latency (console-measured, in-process): "
                   f"avg {sum(latencies) / len(latencies):.1f} ms "
                   f"over {len(latencies)} fired scenarios.")

    _chart_or_table(st, metrics["timeline"], "time",
                    ["allow", "deny", "quarantine"],
                    "Decisions per minute")
    col1, col2, col3 = st.columns(3)
    with col1:
        rows = [{"rule": rid, "denied": v["denied"]}
                for rid, v in sorted(metrics["per_rule"].items(),
                                     key=lambda kv: -kv[1]["denied"])[:10]
                if v["denied"]]
        _chart_or_table(st, rows, "rule", "denied", "Denials by rule")
    with col2:
        rows = [{"agent": name, "denied": v["denied"]}
                for name, v in sorted(metrics["per_agent"].items(),
                                      key=lambda kv: -kv[1]["denied"])[:10]
                if v["denied"]]
        _chart_or_table(st, rows, "agent", "denied", "Denials by agent")
    with col3:
        rows = [{"resource": name, "denied": v["denied"]}
                for name, v in sorted(
                    metrics["per_resource"].items(),
                    key=lambda kv: -kv[1]["denied"])[:10] if v["denied"]]
        _chart_or_table(st, rows, "resource", "denied",
                        "Denials by resource")

    st.subheader("System health")
    st.markdown(_health_html(health), unsafe_allow_html=True)
    _render_feed(st, records)


def _render_environment(st, data, records):
    graph = data.get("graph")
    if graph is None:
        st.error(data["errors"].get("graph", "graph.json missing."))
        return
    nodes = graph.get("nodes", [])
    st.write("**Trust boundaries:** " + ", ".join(
        graph.get("trust_boundaries", [])))
    devices = [n for n in nodes if n.get("kind") == "device"]
    st.table([{"device": n.get("id"), "type": n.get("type"),
               "site": n.get("site"), "zone": n.get("zone"),
               "protocol": n.get("protocol"),
               "topics": ", ".join(n.get("topics", []) or []),
               "identity": n.get("identity")}
              for n in devices])
    st.subheader("Device detail")
    choice = st.selectbox("Device", [n.get("id") for n in devices])
    node = next(n for n in devices if n.get("id") == choice)
    st.json({k: node.get(k) for k in
             ("id", "type", "site", "zone", "trust_boundary", "protocol",
              "address", "topics", "identity", "notes", "registers",
              "description") if node.get(k) is not None})
    policy = data.get("policy") or {}
    coverage = device_policy_coverage(choice, node.get("topics", []),
                                      policy.get("rules", []))
    st.write(f"**Policy coverage ({len(coverage)} rules):**")
    if coverage:
        st.table([{"rule": r.get("id"), "effect": r.get("effect"),
                   "business_rule": r.get("business_rule"),
                   "description": r.get("description")}
                  for r in coverage])
    else:
        st.caption("No machine rule names this device.")
    st.subheader("Data flows")
    st.table([{"from": e.get("from"), "to": e.get("to"),
               "protocol": e.get("protocol")}
              for e in graph.get("edges", [])])


def _render_policies(st, data, records):
    policy = data.get("policy")
    if policy is None:
        st.error(data["errors"].get("policy", "policy.json missing."))
        return
    hits = rule_hit_counts(records)
    lineage = group_policy_rules(policy)
    business = {r["id"]: r["text"] for r in (data.get("business") or [])}
    st.write(f"**{len(policy.get('rules', []))} enforced rules** "
             f"(+ {len(lineage['proposed'])} proposed, not enforced).")
    for br_id in sorted(k for k in lineage["groups"] if k != "INFRA"):
        with st.expander(f"{br_id}: {business.get(br_id, '(text missing)')}",
                         expanded=False):
            st.table([{"rule": r.get("id"), "subject": r.get("subject"),
                       "action": r.get("action"),
                       "resource": r.get("resource"),
                       "effect": r.get("effect"),
                       "hits": hits.get(r.get("id"), 0),
                       "description": r.get("description")}
                      for r in lineage["groups"][br_id]])
    with st.expander("Infrastructure (graph-derived, no business rule)",
                     expanded=False):
        st.table([{"rule": r.get("id"), "subject": r.get("subject"),
                   "action": r.get("action"), "resource": r.get("resource"),
                   "effect": r.get("effect"),
                   "hits": hits.get(r.get("id"), 0)}
                  for r in lineage["groups"].get("INFRA", [])])
    with st.expander("Proposed — Spark-drafted, never enforced",
                     expanded=False):
        st.warning("Advisory only: the gateway never matches these rules.")
        st.table([{"rule": r.get("id"), "subject": r.get("subject"),
                   "action": r.get("action"), "resource": r.get("resource"),
                   "effect": r.get("effect"),
                   "description": r.get("description")}
                  for r in lineage["proposed"]])


def _render_agents(st, records):
    gateway = st.session_state.gateway
    creds = st.session_state.creds
    rows = credential_rows(creds, gateway)
    st.table(rows)
    col1, col2 = st.columns(2)
    with col1:
        target = st.selectbox("Revoke credential",
                              [r["label"] for r in rows
                               if r["status"] == "valid"])
        if st.button("Revoke", key="revoke-btn") and target:
            identity.revoke(creds[target])
            st.success(f"Revoked {target}.")
            st.rerun()
    with col2:
        subject = st.selectbox(
            "Per-agent action history",
            sorted({r.get("subject", "?") for r in records} or ["-"]))
    history = [r for r in records if r.get("subject") == subject]
    st.write(f"**{subject}: {len(history)} actions**")
    st.table([{"ts": (r.get("ts") or "")[11:19], "action": r.get("action"),
               "resource": r.get("resource"), "decision": r.get("decision"),
               "rule": r.get("matched_rule", {}).get("id")}
              for r in history[-20:]])


def _render_redteam(st):
    st.write("Fire the scripted attacks on demand. Each attack uses a fresh "
             "rogue session so it demonstrates its own rule in isolation; "
             "every result lands in the live feed and audit log in real time. "
             "Re-firing a quarantined attack shows the tightening overlay "
             "still denying that role — Reset demo clears it.")
    gateway = st.session_state.gateway
    creds = st.session_state.creds

    def fire(scenario_id):
        start = time.perf_counter()
        fired = run_scenario(gateway, scenario_id, creds)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        st.session_state.last_fired.append(
            {"scenario": scenario_id, "records": fired,
             "elapsed_ms": elapsed_ms})
        st.session_state.latencies_ms.append(elapsed_ms)

    attacks = [sid for sid in SCENARIOS if SCENARIOS[sid]["kind"] == "attack"]
    legit = [sid for sid in SCENARIOS if SCENARIOS[sid]["kind"] == "legit"]
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Attacks**")
        for sid in attacks:
            if st.button(SCENARIOS[sid]["label"], key=f"fire-{sid}",
                       use_container_width=True):
                fire(sid)
                st.rerun()
    with col2:
        st.write("**Legitimate baseline**")
        for sid in legit:
            if st.button(SCENARIOS[sid]["label"], key=f"fire-{sid}",
                       use_container_width=True):
                fire(sid)
                st.rerun()
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Fire full demo script", key="fire-all",
                   type="primary", use_container_width=True):
            start = time.perf_counter()
            fired = run_demo_script(gateway, creds)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            st.session_state.last_fired.append(
                {"scenario": "demo-script", "records": fired,
                 "elapsed_ms": elapsed_ms})
            st.session_state.latencies_ms.append(elapsed_ms)
            st.rerun()
    with col2:
        if st.session_state.live:
            if st.button("Pause live feed", key="pause"):
                st.session_state.live = False
                st.rerun()
        else:
            if st.button("Resume live feed", key="resume"):
                st.session_state.live = True
                st.rerun()
    with col3:
        if st.button("Reset demo", key="reset"):
            _reset_demo(st)
            st.rerun()

    for entry in st.session_state.last_fired[-5:][::-1]:
        label = ("demo script" if entry["scenario"] == "demo-script"
                 else SCENARIOS[entry["scenario"]]["label"])
        with st.expander(f"{label} — {len(entry['records'])} decisions, "
                         f"{entry['elapsed_ms']:.1f} ms", expanded=True):
            for record in entry["records"][-8:]:
                st.markdown(_feed_line(record),
                            unsafe_allow_html=True)
                st.caption(enforce.explain(record))


def _render_threats(st, data):
    threats = data.get("threats")
    if threats is None:
        st.error(data["errors"].get("threats", "threats.json missing."))
        return
    items = threats.get("threats", [])
    severities = ["all"] + sorted({t.get("severity", "?") for t in items},
                                  key=lambda s: SEVERITY_ORDER.get(s, 9))
    choice = st.selectbox("Severity", severities)
    ranked = sorted(items, key=lambda t: SEVERITY_ORDER.get(
        t.get("severity"), 9))
    for threat in ranked:
        if choice != "all" and threat.get("severity") != choice:
            continue
        with st.expander(f"[{threat.get('severity')}] "
                         f"{threat.get('title')}", expanded=False):
            st.markdown(_pill_html(threat.get("severity", "?").upper(),
                                   SEVERITY_PILL.get(
                                       threat.get("severity"), "info")),
                        unsafe_allow_html=True)
            st.write("**Path:** " + " → ".join(
                threat.get("path_labels", threat.get("path", []))))
            st.write("**Preconditions:**")
            for pre in threat.get("preconditions", []):
                st.write(f"- {pre}")
            st.write(f"**Stopping policy:** "
                     f"{threat.get('stopping_policy')}")
            st.caption(f"Business rules: "
                       f"{', '.join(threat.get('business_rules', []))} · "
                       f"exposure: {threat.get('exposure')}")


def _render_audit(st, records):
    _render_feed(st, records, limit=10, key="audit-feed")
    st.subheader("Decision trail")
    subjects = ["all"] + sorted({r.get("subject", "?") for r in records})
    decisions = ["all", "allow", "deny", "quarantine"]
    col1, col2, col3 = st.columns(3)
    with col1:
        subject = st.selectbox("Agent", subjects)
    with col2:
        decision = st.selectbox("Decision", decisions)
    with col3:
        resource = st.text_input("Resource contains", "")
    filtered = [r for r in records
                if (subject == "all" or r.get("subject") == subject)
                and (decision == "all" or r.get("decision") == decision)
                and (resource in (r.get("resource") or ""))]
    st.write(f"**{len(filtered)} of {len(records)} records**")
    st.dataframe([{"seq": r.get("seq"), "ts": r.get("ts"),
                   "subject": r.get("subject"), "action": r.get("action"),
                   "resource": r.get("resource"),
                   "decision": r.get("decision"),
                   "flagged": r.get("flagged"),
                   "rule": r.get("matched_rule", {}).get("id"),
                   "business_rule": r.get("matched_rule", {}).get(
                       "business_rule"),
                   "policy_change": r.get("policy_change") or ""}
                  for r in filtered[-500:]])
    col1, col2 = st.columns(2)
    with col1:
        st.download_button("Export JSON", export_audit_json(filtered),
                           "sentinel-audit.json", "application/json")
    with col2:
        st.download_button("Export CSV", export_audit_csv(filtered),
                           "sentinel-audit.csv", "text/csv")


def _load_all():
    data, errors = {}, {}

    def attempt(key, loader):
        try:
            data[key] = loader()
        except (FileNotFoundError, ValueError) as exc:
            errors[key] = str(exc)

    attempt("graph", load_graph)
    attempt("threats", load_threats)
    attempt("policy", load_policy)
    attempt("business", load_business_rules)
    data["errors"] = errors
    return data


def main() -> None:
    st = _require_streamlit()
    st.set_page_config(page_title="Sentinel — agent-aware firewall",
                       layout="wide",
                       initial_sidebar_state="expanded")
    st.markdown(f"<style>{APP_CSS}</style>", unsafe_allow_html=True)
    _init_session(st)

    data = _load_all()
    gateway = st.session_state.gateway
    records = collect_records(gateway, AUDIT_PATH, limit=2000)
    metrics = compute_metrics(records)
    health = check_health()

    st.markdown(_brand_html(metrics["blocked"], data["errors"]),
                unsafe_allow_html=True)
    if data["errors"]:
        for key, error in data["errors"].items():
            st.error(f"{key}: {error}")

    with st.sidebar:
        st.markdown(_sidebar_stats_html(metrics), unsafe_allow_html=True)
        st.checkbox("Live refresh (2s)", key="live")
        if st.button("Refresh now", use_container_width=True):
            st.rerun()
        if st.button("Reset demo", use_container_width=True):
            _reset_demo(st)
            st.rerun()
        st.markdown(_health_html(health), unsafe_allow_html=True)
        st.caption("Offline demo: cached artifacts only, no model calls.")

    (overview, environment, policies, agents_tab, redteam, threats,
     audit) = st.tabs(["Overview", "Environment", "Policies",
                       "Agents & Identities", "Red team", "Threats",
                       "Audit log"])
    with overview:
        _render_overview(st, data, records, metrics, health)
    with environment:
        _render_environment(st, data, records)
    with policies:
        _render_policies(st, data, records)
    with agents_tab:
        _render_agents(st, records)
    with redteam:
        _render_redteam(st)
    with threats:
        _render_threats(st, data)
    with audit:
        _render_audit(st, records)

    if st.session_state.live:
        time.sleep(2)
        st.rerun()


if __name__ == "__main__":
    main()

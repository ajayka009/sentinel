"""Layer 2 — Attack surface / Analyst: data/graph.json -> data/threats.json.

The graph is the source of truth. The analyst builds a deterministic base
threat list from the four seeded OT exposures in the build spec, optionally
asks muse-wonder-1.0 to suggest additional paths and a ranking, and validates
the result: any path step that is not a known graph node id is rejected, and
the seeded exposures keep their code-assigned severity and order so the demo
ranking is reproducible.

Per the LLM usage doctrine, Wonder's output is advisory only — it never
blocks anything by itself. Run once per environment change, never in the
hot loop.

Usage:
    python3 -m sentinel.analyst [--offline] [--graph PATH] [--output PATH]
        [--policy PATH]
"""

import argparse
import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GRAPH = REPO_ROOT / "data" / "graph.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "threats.json"
DEFAULT_POLICY = REPO_ROOT / "data" / "policy.json"
WONDER_MODEL = "muse-wonder-1.0"

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Business-rule ids from data/business_rules.txt (BR-1 .. BR-9).
BUSINESS_RULE_IDS = {f"BR-{i}" for i in range(1, 10)}

# Fixed tiebreak order for the seeded exposures: forged-plc-write and
# fake-gate-release stay at ranks 1 and 2 (spec acceptance). Wonder-added
# threats sort after all seeded ones at equal severity.
_SEED_ORDER = {
    "forged-plc-write": 0,
    "fake-gate-release": 1,
    "gateway-bypass-plc": 2,
    "wildcard-recon": 3,
    "spoofed-reefer-temp": 4,
    "spoofed-gate-events": 5,
}

THREAT_PRIMER = """OT threat primer (ground these in the graph below):
1. PLC: unauthenticated Modbus register writes, no encryption — any agent
   that can reach the PLC can forge run/stop and setpoint writes.
2. MQTT: wildcard subscribe ('#') exposes all topics; flat topic ACLs let
   any publisher forge commands or spoof telemetry.
3. Gateway bypass: traffic to the PLC that bypasses the gateway evades
   policy entirely and must be denied and flagged.
4. Spoofed remote telemetry: fake reefer temperatures or fake gate events
   over the constrained yard link can trick the operator agent into wrong
   or dangerous actions."""


def seeded_threats():
    """The four spec exposures as deterministic ranked attack paths.

    forged-plc-write and fake-gate-release are fixed at ranks 1 and 2.
    Every path step is a node id from data/graph.json.
    """
    return [
        {
            "id": "forged-plc-write",
            "title": "Forged PLC write via flat MQTT topics",
            "path": ["rogue-agent", "topic:site/#", "edge-gateway",
                     "plc-line1"],
            "path_labels": ["rogue agent", "MQTT wildcard '#'/command topic",
                            "edge gateway", "PLC actuator (run/stop, setpoint)"],
            "severity": "critical",
            "preconditions": [
                "rogue agent holds any valid credential with MQTT publish scope",
                "flat topic ACLs let a non-operator publisher reach command topics",
            ],
            "stopping_policy": "Only the operator agent may write PLC "
                               "registers, and only via the gateway; unknown "
                               "or revoked identities denied by default.",
            "business_rules": ["BR-1", "BR-6", "BR-7"],
            "exposure": "plc-unauthenticated-writes",
        },
        {
            "id": "fake-gate-release",
            "title": "Fake gate release without matching booking",
            "path": ["rogue-agent", "topic:site/yard/gate/release", "yard-gate"],
            "path_labels": ["rogue agent", "gate release topic", "yard gate"],
            "severity": "critical",
            "preconditions": [
                "rogue agent can publish to site/yard/gate/release",
                "no container + truck + booking match enforced",
            ],
            "stopping_policy": "Gate release requires matching container + "
                               "truck + booking; mismatches denied and the "
                               "requester quarantined.",
            "business_rules": ["BR-3"],
            "exposure": "mqtt-flat-acl-command-forgery",
        },
        {
            "id": "gateway-bypass-plc",
            "title": "Direct-to-PLC write bypassing the gateway",
            "path": ["rogue-agent", "plc-line1"],
            "path_labels": ["rogue agent", "PLC (direct Modbus/TCP)"],
            "severity": "critical",
            "preconditions": [
                "rogue agent has network reachability to localhost:5020",
                "PLC accepts unauthenticated Modbus writes",
            ],
            "stopping_policy": "Any traffic to the PLC that bypasses the "
                               "gateway is denied and flagged as an anomaly.",
            "business_rules": ["BR-6"],
            "exposure": "gateway-bypass",
        },
        {
            "id": "wildcard-recon",
            "title": "Wildcard topic reconnaissance",
            "path": ["rogue-agent", "topic:site/#"],
            "path_labels": ["rogue agent", "all site topics via '#'"],
            "severity": "high",
            "preconditions": [
                "broker accepts '#' subscriptions from non-gateway identities",
            ],
            "stopping_policy": "No agent may subscribe to the wildcard "
                               "topic '#'; violators quarantined and wildcard "
                               "disabled for non-gateway identities.",
            "business_rules": ["BR-4", "BR-8"],
            "exposure": "mqtt-wildcard-subscribe",
        },
        {
            "id": "spoofed-reefer-temp",
            "title": "Spoofed reefer temperature tricking the operator",
            "path": ["rogue-agent",
                     "topic:site/yard/reefer/<container_id>/temperature",
                     "operator-agent"],
            "path_labels": ["rogue agent", "reefer temperature topic",
                            "operator agent (misled)"],
            "severity": "high",
            "preconditions": [
                "rogue agent can publish to reefer telemetry topics",
                "operator agent acts on telemetry without plausibility checks",
            ],
            "stopping_policy": "Reefer temperature changes greater than 10C "
                               "in one minute are implausible: flagged, not "
                               "acted on; publisher scope revoked.",
            "business_rules": ["BR-5"],
            "exposure": "spoofed-remote-telemetry",
        },
        {
            "id": "spoofed-gate-events",
            "title": "Spoofed gate events masking container moves",
            "path": ["rogue-agent", "topic:site/yard/gate/event",
                     "operator-agent"],
            "path_labels": ["rogue agent", "gate event topic",
                            "operator agent (misled)"],
            "severity": "high",
            "preconditions": [
                "rogue agent can publish to site/yard/gate/event",
                "gate events accepted without publisher identity check",
            ],
            "stopping_policy": "Gate publishers must hold yard-publish scope; "
                               "unknown publishers denied by default.",
            "business_rules": ["BR-7"],
            "exposure": "spoofed-remote-telemetry",
        },
    ]


def load_graph(path):
    """Parse the environment graph JSON."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def rank_threats(threats):
    """Sort deterministically: severity desc, seeded order, then id asc."""
    return sorted(
        threats,
        key=lambda t: (-SEVERITY_WEIGHT.get(t.get("severity", ""), 0),
                       _SEED_ORDER.get(t.get("id", ""), 100),
                       t.get("id", "")),
    )


def apply_policy_rerank(threats, policy):
    """Re-rank threats against an enforced policy.

    A threat whose stopping business rules are all covered by enforced
    machine rules (matched on the rule's "business_rule" field) is marked
    mitigated and its residual severity drops one level (floor: low).
    Returns a new ranked list; the input is unchanged.
    """
    enforced = set()
    for rule in policy.get("rules", []):
        if rule.get("effect") in ("allow", "deny", "quarantine", "flag"):
            ref = rule.get("business_rule", "")
            if ref in BUSINESS_RULE_IDS:
                enforced.add(ref)
    order = ["low", "medium", "high", "critical"]
    reranked = []
    for threat in threats:
        updated = copy.deepcopy(threat)
        needed = set(threat.get("business_rules", []))
        if needed and needed <= enforced:
            idx = max(0, order.index(threat.get("severity", "low")) - 1)
            updated["residual_severity"] = order[idx]
            updated["status"] = "mitigated"
        else:
            updated["residual_severity"] = threat.get("severity", "low")
            updated["status"] = "open"
        reranked.append(updated)
    return sorted(
        reranked,
        key=lambda t: (-SEVERITY_WEIGHT.get(t.get("residual_severity", ""), 0),
                       _SEED_ORDER.get(t.get("id", ""), 100),
                       t.get("id", "")),
    )


def merge_wonder_draft(base_threats, draft, known_nodes):
    """Merge a Wonder draft into the base list, rejecting invalid entries.

    Seeded threats keep their code-assigned severity and order; Wonder may
    only add new threats whose path steps are all known graph node ids with
    a valid severity and known business-rule refs. Returns
    (merged_ranked_list, dropped_ids).
    """
    merged = copy.deepcopy(base_threats)
    seeded_ids = {t["id"] for t in merged}
    dropped = []

    suggestions = draft.get("threats", [])
    if not isinstance(suggestions, list):
        return rank_threats(merged), ["non-list-threats-draft"]

    for item in suggestions:
        if not isinstance(item, dict):
            dropped.append("non-object-threat")
            continue
        tid = item.get("id", "")
        if not tid or tid in seeded_ids:
            dropped.append(tid or "missing-id")
            continue
        path = item.get("path", [])
        severity = item.get("severity", "")
        rules = item.get("business_rules", [])
        if (not isinstance(path, list) or not path
                or any(s not in known_nodes for s in path)):
            dropped.append(tid)
            continue
        if severity not in SEVERITIES:
            dropped.append(tid)
            continue
        if (not isinstance(rules, list)
                or any(r not in BUSINESS_RULE_IDS for r in rules)):
            dropped.append(tid)
            continue
        merged.append({
            "id": tid,
            "title": str(item.get("title", tid)),
            "path": list(path),
            "path_labels": list(item.get("path_labels", path)),
            "severity": severity,
            "preconditions": [str(p) for p in item.get("preconditions", [])],
            "stopping_policy": str(item.get("stopping_policy", "")),
            "business_rules": list(rules),
            "exposure": str(item.get("exposure", "wonder-suggested")),
            "source": "wonder",
        })
    return rank_threats(merged), sorted(set(dropped))


def enrich_with_wonder(base_threats, graph):
    """Ask Wonder for extra paths; validate before merging.

    Returns (threats, info). On any failure the base list is returned
    unchanged with info describing the fallback reason.
    """
    from sentinel import models

    key = os.getenv("META_API_KEY", "").strip()
    if not key or key == "...":
        return base_threats, {"status": "fallback", "reason": "no-api-key"}

    node_ids = sorted(n["id"] for n in graph["nodes"])
    prompt = (
        "You are an OT security analyst advising a demo firewall. The "
        "environment graph and seeded threat list below are FIXED — suggest "
        "ADDITIONAL attack paths only, never invent devices, agents, or "
        "topics.\n\n"
        f"{THREAT_PRIMER}\n\n"
        f"Graph node ids (use ONLY these in paths): {', '.join(node_ids)}\n\n"
        f"Seeded threats (already covered, do not repeat):\n"
        f"{json.dumps(base_threats)}\n\n"
        "Return JSON only: {\"threats\": [{"
        "\"id\": <kebab-case id>, \"title\": <string>, "
        "\"path\": [<node-id>, ...], \"path_labels\": [<string>, ...], "
        "\"severity\": <critical|high|medium|low>, "
        "\"preconditions\": [<string>, ...], "
        "\"stopping_policy\": <string>, "
        "\"business_rules\": [<BR-1..BR-9>, ...]}]}. "
        "Every path step MUST be one of the node ids above. "
        "business_rules entries MUST be BR-1 through BR-9."
    )
    try:
        raw = models.chat(
            WONDER_MODEL,
            [{"role": "user", "content": prompt}],
            json_mode=True,
        )
        draft = json.loads(raw)
    except Exception as exc:
        return base_threats, {"status": "fallback",
                              "reason": f"wonder-error: {exc}"}
    if not isinstance(draft, dict):
        return base_threats, {"status": "fallback",
                              "reason": "wonder-invalid-json"}
    merged, dropped = merge_wonder_draft(base_threats, draft, set(node_ids))
    return merged, {
        "status": "wonder",
        "model": WONDER_MODEL,
        "dropped_threat_ids": dropped,
    }


def validate_threats(payload, graph):
    """Return a list of validation errors (empty means valid)."""
    errors = []
    node_ids = {n["id"] for n in graph["nodes"]}
    threats = payload.get("threats", [])
    if not threats:
        return ["no threats listed"]

    seen = set()
    for threat in threats:
        tid = threat.get("id", "")
        if not tid:
            errors.append("threat missing id")
            continue
        if tid in seen:
            errors.append(f"duplicate threat id: {tid}")
        seen.add(tid)
        for field in ("title", "path", "severity", "preconditions",
                      "stopping_policy", "business_rules"):
            if field not in threat:
                errors.append(f"{tid}: missing field {field}")
        for step in threat.get("path", []):
            if step not in node_ids:
                errors.append(f"{tid}: unknown path step {step}")
        if threat.get("severity") not in SEVERITIES:
            errors.append(f"{tid}: invalid severity "
                          f"{threat.get('severity')!r}")
        for ref in threat.get("business_rules", []):
            if ref not in BUSINESS_RULE_IDS:
                errors.append(f"{tid}: unknown business rule {ref}")

    # The four seeded exposures must be present.
    required = {"forged-plc-write", "fake-gate-release", "gateway-bypass-plc",
                "wildcard-recon", "spoofed-reefer-temp",
                "spoofed-gate-events"}
    for tid in sorted(required - seen):
        errors.append(f"missing seeded threat: {tid}")

    # Acceptance: forged-PLC-write and fake-gate-release rank at the top
    # by base severity. (After a policy re-rank the stored order follows
    # residual severity instead — that is the intended re-ranking.)
    base_ranked = [t.get("id") for t in rank_threats(threats)[:2]]
    if base_ranked != ["forged-plc-write", "fake-gate-release"]:
        errors.append(f"top two threats must be forged-plc-write + "
                      f"fake-gate-release, got {base_ranked}")
    return errors


def run_analyst(graph_path, policy_path=None, use_wonder=True):
    """Build, enrich, validate, and rank the threat map."""
    graph_path = Path(graph_path)
    graph = load_graph(graph_path)
    graph_text = graph_path.read_text(encoding="utf-8")

    threats = rank_threats(seeded_threats())
    if use_wonder:
        threats, enrichment = enrich_with_wonder(threats, graph)
    else:
        enrichment = {"status": "fallback", "reason": "offline-flag"}

    rerank_info = {"status": "no-policy-file"}
    if policy_path is not None:
        policy_file = Path(policy_path)
        if policy_file.exists():
            policy = json.loads(policy_file.read_text(encoding="utf-8"))
            threats = apply_policy_rerank(threats, policy)
            rerank_info = {"status": "reranked",
                           "policy_rules": len(policy.get("rules", []))}
        # A missing policy.json is normal before Day 5; top-two order is
        # still enforced on base severity by validate_threats.

    payload = {
        "threats": threats,
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "sentinel-analyst/1",
            "model": enrichment.get("model", "deterministic-fallback"),
            "graph_sha256": hashlib.sha256(graph_text.encode()).hexdigest(),
            "enrichment": enrichment,
            "policy_rerank": rerank_info,
        },
    }
    errors = validate_threats(payload, graph)
    if errors:
        raise ValueError("threat validation failed: " + "; ".join(errors))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel analyst: graph.json -> threats.json")
    parser.add_argument("--graph", default=str(DEFAULT_GRAPH))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--offline", action="store_true",
                        help="skip the Wonder analysis call")
    args = parser.parse_args()

    payload = run_analyst(args.graph, args.policy, use_wonder=not args.offline)
    out = Path(args.output)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(payload['threats'])} threats, "
          f"enrichment={payload['meta']['enrichment']['status']}, "
          f"rerank={payload['meta']['policy_rerank']['status']})")


if __name__ == "__main__":
    main()

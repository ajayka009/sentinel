"""Layer 3 — Policy compiler: business rules + graph -> data/policy.json.

The business rules and graph are the source of truth. The compiler builds a
deterministic base policy from them (every starter rule compiles to at least
one machine rule), optionally asks muse-spark-1.3 to propose ADDITIONAL
defense-in-depth rules, and validates the result.

Per the LLM usage doctrine, Spark's output is advisory only: valid drafts
land in "proposed_rules" (never enforced until a human promotes them into
the base), invalid drafts are recorded in meta with reasons — never
silently dropped. A business rule with no machine rule is reported as
uncompilable and fails validation (fail closed).

Rule schema:
    {id, business_rule, origin, subject, action, resource,
     conditions, effect, description}
  - subject: a graph node id, or "*" (any subject).
  - action: write | publish | subscribe | stream | connect | "*".
  - resource: concrete name ("plc.setpoint", "camera.frames",
    "topic:<mqtt topic>") or fnmatch glob ("plc.*",
    "topic:site/yard/reefer/*/temperature", "*").
  - conditions: list of {field, op, value} (conjunction; empty matches).
    ops: eq, ne, lt, lte, gt, gte, in, not_in. Numeric comparisons
    against a non-numeric field value are false (no match, no crash);
    malformed values are caught by the BR-9 wellformed rule.
  - effect: allow | deny | quarantine | flag.

Evaluation semantics (for the Day 6 enforcement loop):
  1. Unknown/revoked/expired identity -> deny immediately (BR-7),
     no further rule evaluation.
  2. Deny, quarantine, and flag rules are checked before allow rules
     (deny-override); first match in file order wins.
  3. Unmatched actions are denied (BR-7 default-deny catch-all, last rule).
  4. The gateway's own relay writes are the post-decision mechanism,
     not new requests, so they are not re-evaluated.

Usage:
    python3 -m sentinel.policy [--offline] [--rules PATH] [--graph PATH]
        [--output PATH]
"""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = REPO_ROOT / "data" / "business_rules.txt"
DEFAULT_GRAPH = REPO_ROOT / "data" / "graph.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "policy.json"
SPARK_MODEL = "muse-spark-1.3"

EFFECTS = ("allow", "deny", "quarantine", "flag")
ACTIONS = ("write", "publish", "subscribe", "stream", "connect", "*")
BUSINESS_RULE_IDS = {f"BR-{i}" for i in range(1, 10)}
OPS = ("eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in")
NUMERIC_OPS = ("lt", "lte", "gt", "gte")

# Condition fields the Day 6 gateway must supply in the action context.
CONDITION_FIELDS = (
    "value",               # numeric write/telemetry value
    "wellformed",          # bool: payload parsed and typed correctly
    "via_gateway",         # bool: reached the device through the gateway
    "booking_match",       # bool: container + truck + booking all match
    "identity_status",     # valid | unknown | revoked | expired
    "subject",             # requestor node id
    "subject_kind",        # agent | device | gateway
    "rate_per_min",        # requestor's trailing-60s action rate
    "repeat",              # bool: requestor already throttled for this
    "delta_c_per_min",     # abs temp change vs last reading, per minute
    "destination",         # stream/publish destination node id or "internet"
    "filter",              # subscribe topic filter verbatim
    "filter_has_wildcard",  # bool: filter contains # or +
)

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
BUSINESS_RULE_RE = re.compile(r"^\s*(\d+)\.\s+(.*\S)\s*$")

# Command topics flow agent -> device, so no device-publish infrastructure
# allow is generated for them (BR-3 covers gate release explicitly).
COMMAND_TOPICS = ("site/yard/gate/release",)

# Resource namespaces a rule may target. Concrete (glob-free) resources
# must additionally be grounded in the graph (see known_resources).
RESOURCE_PREFIXES = ("plc.", "camera.", "topic:", "yard.", "*")


def _sim_constants():
    """Pin policy numbers to the sim contract (follows digest.py precedent).

    The setpoint ceiling and the operator's subscribe list live in
    sim/agents.py; importing them keeps policy and sim in sync, and the
    tests pin them together so drift fails loudly.
    """
    from sim import agents

    return {
        "setpoint_min": 0,
        "setpoint_max": agents.SPEED_POLICY_MAX,
        "operator_topics": list(agents.OPERATOR_TOPICS),
    }


def parse_business_rules(path):
    """Parse numbered business rules: {BR-id: text}."""
    rules = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            match = BUSINESS_RULE_RE.match(line)
            if match:
                rules[f"BR-{int(match.group(1))}"] = match.group(2).strip()
    return rules


def load_graph(path):
    """Parse the environment graph JSON."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def known_subjects(graph):
    """Graph node ids usable as rule subjects."""
    return {n["id"] for n in graph["nodes"]}


def known_resources(graph):
    """Concrete resources grounded in the graph (placeholders -> glob)."""
    resources = {"plc.setpoint", "plc.run_stop", "camera.frames"}
    for node in graph["nodes"]:
        if node.get("kind") == "topic":
            pattern = node.get("pattern", "")
            resources.add(f"topic:{normalize_topic_glob(pattern)}")
    return resources


def normalize_topic_glob(pattern):
    """Turn registry placeholders (<container_id>) into fnmatch globs."""
    return re.sub(r"<[^>]+>", "*", pattern)


def _rule(rule_id, business_rule, origin, subject, action, resource,
          conditions, effect, description):
    return {
        "id": rule_id,
        "business_rule": business_rule,
        "origin": origin,
        "subject": subject,
        "action": action,
        "resource": resource,
        "conditions": conditions,
        "effect": effect,
        "description": description,
    }


def _cond(field, op, value):
    return {"field": field, "op": op, "value": value}


def base_rules(graph):
    """Build the deterministic base policy: 16 BR rules + infra allows.

    Every starter rule BR-1..BR-9 compiles to at least one machine rule.
    Infrastructure allows (business_rule null) whitelist the legitimate
    device-telemetry and operator-subscribe flows derived from the graph
    and the sim contract, so the default-deny catch-all cannot break
    them. Only the owning device may publish its topic — any agent
    spoof is denied by default.
    """
    sim = _sim_constants()
    lo, hi = sim["setpoint_min"], sim["setpoint_max"]
    rules = [

        # BR-1: only the operator writes PLC registers, in range, via GW.
        _rule("pol-br1-allow-plc-write", "BR-1", "business-rule",
              "operator-agent", "write", "plc.*",
              [_cond("via_gateway", "eq", True),
               _cond("value", "gte", lo),
               _cond("value", "lte", hi)],
              "allow",
              f"Operator PLC writes within the safe range ({lo}-{hi} RPM) "
              "relayed through the gateway."),

        # BR-2: cameras stream to the local gateway only.
        _rule("pol-br2-allow-local-stream", "BR-2", "business-rule",
              "camera-line1", "stream", "camera.frames",
              [_cond("destination", "eq", "edge-gateway")],
              "allow", "Camera frames stream to the local gateway."),
        _rule("pol-br2-deny-internet", "BR-2", "business-rule",
              "camera-line1", "stream", "camera.frames",
              [_cond("destination", "eq", "internet")],
              "deny", "Camera streams to the internet are denied."),

        # BR-3: gate release requires matching container + truck + booking.
        _rule("pol-br3-allow-booked-release", "BR-3", "business-rule",
              "operator-agent", "publish", "topic:site/yard/gate/release",
              [_cond("booking_match", "eq", True)],
              "allow", "Booked gate releases (container + truck + "
                       "booking match)."),
        _rule("pol-br3-quarantine-unbooked", "BR-3", "business-rule",
              "*", "publish", "topic:site/yard/gate/release",
              [_cond("booking_match", "eq", False)],
              "quarantine", "Unbooked gate release attempts quarantine "
                            "the requester."),

        # BR-4: no wildcard subscribes except the gateway itself.
        _rule("pol-br4-allow-gateway-wildcard", "BR-4", "business-rule",
              "edge-gateway", "subscribe", "*",
              [_cond("filter_has_wildcard", "eq", True)],
              "allow", "The gateway alone may hold wildcard subscribes."),
        _rule("pol-br4-quarantine-wildcard", "BR-4", "business-rule",
              "*", "subscribe", "*",
              [_cond("filter_has_wildcard", "eq", True),
               _cond("subject", "ne", "edge-gateway")],
              "quarantine", "Non-gateway wildcard subscribes (recon) "
                            "quarantine the requester."),

        # BR-5: implausible reefer jumps are flagged, not acted on.
        _rule("pol-br5-flag-implausible-reefer", "BR-5", "business-rule",
              "*", "publish", "topic:site/yard/reefer/*/temperature",
              [_cond("delta_c_per_min", "gt", 10)],
              "flag", "Reefer temperature jumps over 10C/min are "
                      "implausible: flagged, never acted on."),

        # BR-6: PLC traffic bypassing the gateway is denied and flagged
        # (every deny is written to the audit log, which is the flag).
        _rule("pol-br6-deny-bypass", "BR-6", "business-rule",
              "*", "write", "plc.*",
              [_cond("via_gateway", "eq", False)],
              "deny", "Direct-to-PLC writes bypassing the gateway are "
                      "denied and audit-flagged as an anomaly."),

        # BR-8: per-agent rate cap — throttle first, quarantine on repeat.
        # Sensors publish every 2s (30/min) but are devices, excluded via
        # subject_kind; the rogue flood (50 rapid publishes) trips this.
        _rule("pol-br8-throttle-flood", "BR-8", "business-rule",
              "*", "*", "*",
              [_cond("subject_kind", "eq", "agent"),
               _cond("rate_per_min", "gt", 30),
               _cond("repeat", "eq", False)],
              "flag", "First rate-cap breach throttles the agent "
                      "(flag + audit)."),
        _rule("pol-br8-quarantine-repeat", "BR-8", "business-rule",
              "*", "*", "*",
              [_cond("subject_kind", "eq", "agent"),
               _cond("rate_per_min", "gt", 30),
               _cond("repeat", "eq", True)],
              "quarantine", "Repeat rate-cap breach quarantines "
                            "the agent."),

        # BR-9: malformed or out-of-range writes rejected, never passed on.
        _rule("pol-br9-deny-malformed", "BR-9", "business-rule",
              "*", "write", "plc.*",
              [_cond("wellformed", "eq", False)],
              "deny", "Malformed PLC writes are rejected by condition "
                      "check, never passed to the device."),
        _rule("pol-br9-deny-below-range", "BR-9", "business-rule",
              "*", "write", "plc.*",
              [_cond("value", "lt", lo)],
              "deny", f"PLC writes below {lo} are rejected by "
                      "condition check."),
        _rule("pol-br9-deny-above-range", "BR-9", "business-rule",
              "*", "write", "plc.*",
              [_cond("value", "gt", hi)],
              "deny", f"PLC writes above {hi} RPM are rejected by "
                      "condition check."),

        # BR-7: unknown/revoked identities denied, no re-evaluation; the
        # catch-all default-deny MUST stay the last rule of the policy.
        _rule("pol-br7-deny-unknown-revoked", "BR-7", "business-rule",
              "*", "*", "*",
              [_cond("identity_status", "in",
                     ["unknown", "revoked", "expired"])],
              "deny", "Unknown, revoked, or expired identities are "
                      "denied immediately with no re-evaluation."),
        _rule("pol-br7-default-deny", "BR-7", "business-rule",
              "*", "*", "*", [],
              "deny", "Catch-all: any unmatched action is denied."),
    ]

    # Infrastructure allows: legitimate flows the default-deny must not
    # break. Device telemetry publishes come from graph device->topic
    # edges (command topics excluded); operator subscribes come from the
    # sim contract (agents.OPERATOR_TOPICS, pinned by tests).
    topic_owner = {}
    for edge in graph.get("edges", []):
        src, dst = edge.get("from", ""), edge.get("to", "")
        if not dst.startswith("topic:"):
            continue
        if src == "edge-gateway":
            continue
        node = next((n for n in graph["nodes"] if n["id"] == src), {})
        if node.get("kind") != "device":
            continue
        pattern = dst[len("topic:"):]
        if pattern in COMMAND_TOPICS:
            continue
        topic_owner.setdefault(pattern, src)

    for pattern in sorted(topic_owner):
        owner = topic_owner[pattern]
        slug = re.sub(r"[^a-z0-9]+", "-",
                      f"{owner}-{pattern}").strip("-")
        rules.append(_rule(
            f"infra-allow-pub-{slug}",
            None, "infrastructure", owner, "publish",
            f"topic:{normalize_topic_glob(pattern)}", [],
            "allow", f"Graph-derived: {owner} owns telemetry topic "
                     f"{pattern}."))
    for topic in sim["operator_topics"]:
        rules.append(_rule(
            f"infra-allow-operator-sub-{re.sub(r'[^a-z0-9]+', '-', topic)}",
            None, "infrastructure", "operator-agent", "subscribe",
            f"topic:{topic}", [],
            "allow", f"Sim-contract: operator subscribes to {topic}."))

    # The catch-all default-deny must be last for file-order evaluation.
    catchall = next(r for r in rules if r["id"] == "pol-br7-default-deny")
    rules.remove(catchall)
    rules.append(catchall)
    return rules


def validate_rule(rule, subjects, resources):
    """Return a list of errors for one rule (empty means valid)."""
    errors = []
    rid = rule.get("id", "")
    if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
        errors.append(f"{rid or '<missing-id>'}: bad rule id")
    for field in ("subject", "action", "resource", "conditions",
                  "effect", "business_rule", "description"):
        if field not in rule:
            errors.append(f"{rid}: missing field {field}")
    if rule.get("subject") != "*" and rule.get("subject") not in subjects:
        errors.append(f"{rid}: unknown subject {rule.get('subject')!r}")
    if rule.get("action") not in ACTIONS:
        errors.append(f"{rid}: unknown action {rule.get('action')!r}")
    resource = rule.get("resource", "")
    if not isinstance(resource, str) or not resource:
        errors.append(f"{rid}: bad resource")
    elif not resource.startswith(RESOURCE_PREFIXES):
        errors.append(f"{rid}: resource outside known namespaces: "
                      f"{resource!r}")
    elif not any(ch in resource for ch in "*?[]") \
            and resource not in resources:
        errors.append(f"{rid}: concrete resource not in graph: "
                      f"{resource!r}")
    conditions = rule.get("conditions", None)
    if not isinstance(conditions, list):
        errors.append(f"{rid}: conditions must be a list")
    else:
        for cond in conditions:
            if not isinstance(cond, dict):
                errors.append(f"{rid}: condition must be an object")
                continue
            field, op = cond.get("field"), cond.get("op")
            value = cond.get("value")
            if field not in CONDITION_FIELDS:
                errors.append(f"{rid}: unknown condition field "
                              f"{field!r}")
            if op not in OPS:
                errors.append(f"{rid}: unknown condition op {op!r}")
            if op in NUMERIC_OPS and not isinstance(value, (int, float)):
                errors.append(f"{rid}: numeric op {op} needs a numeric "
                              f"value, got {value!r}")
            if op in ("in", "not_in") and not isinstance(value, list):
                errors.append(f"{rid}: op {op} needs a list value")
    if rule.get("effect") not in EFFECTS:
        errors.append(f"{rid}: invalid effect {rule.get('effect')!r}")
    ref = rule.get("business_rule")
    if ref is not None and ref not in BUSINESS_RULE_IDS:
        errors.append(f"{rid}: unknown business rule {ref!r}")
    return errors


def merge_spark_draft(base_rules_list, draft, subjects, resources):
    """Sort a Spark draft into advisory proposals vs dropped-with-reason.

    The enforced base is never modified: valid drafts become
    "proposed_rules" for human review, invalid ones are recorded with
    reasons. Returns (proposed, dropped).
    """
    proposed, dropped = [], []
    seen = {r["id"] for r in base_rules_list}

    suggestions = draft.get("rules", [])
    if not isinstance(suggestions, list):
        return [], [{"id": "non-list-rules-draft",
                     "reason": "draft 'rules' is not a list"}]

    for item in suggestions:
        if not isinstance(item, dict):
            dropped.append({"id": "non-object-rule",
                            "reason": "rule is not an object"})
            continue
        rid = item.get("id", "")
        if not rid or rid in seen:
            dropped.append({"id": rid or "missing-id",
                            "reason": "duplicate or missing rule id"})
            continue
        candidate = {
            "id": rid,
            "business_rule": item.get("business_rule"),
            "origin": "spark-drafted",
            "subject": item.get("subject"),
            "action": item.get("action"),
            "resource": item.get("resource"),
            "conditions": item.get("conditions", []),
            "effect": item.get("effect"),
            "description": str(item.get("description", "")),
        }
        errors = validate_rule(candidate, subjects, resources)
        if errors:
            dropped.append({"id": rid, "reason": "; ".join(errors)})
            continue
        proposed.append(candidate)
        seen.add(rid)
    return proposed, dropped


def enrich_with_spark(base, graph, rules_text):
    """Ask Spark for extra rules; validate before accepting as advisory.

    Returns (proposed, info). On any failure no proposals are returned,
    with info describing the fallback reason. The enforced base is
    never modified here.
    """
    from sentinel import models

    key = os.getenv("META_API_KEY", "").strip()
    if not key or key == "...":
        return [], {"status": "fallback", "reason": "no-api-key"}

    subjects = sorted(known_subjects(graph))
    prompt = (
        "You review an edge/IoT firewall policy for a demo. The base "
        "policy below is FIXED and already enforces business rules "
        "BR-1..BR-9 — propose ADDITIONAL defense-in-depth machine rules "
        "only (e.g. publisher-ownership guards for container moves or "
        "equipment status, camera exfiltration guards).\n\n"
        f"Business rules:\n{rules_text}\n\n"
        f"Base policy JSON:\n{json.dumps(base)}\n\n"
        "Return JSON only: {\"rules\": [{"
        "\"id\": <kebab-case id>, "
        "\"business_rule\": <BR-1..BR-9 or null>, "
        "\"subject\": <graph node id or \"*\">, "
        "\"action\": <write|publish|subscribe|stream|connect|*>, "
        "\"resource\": <plc.*|camera.frames|topic:<pattern>|*>, "
        "\"conditions\": [{\"field\": <condition field>, "
        "\"op\": <eq|ne|lt|lte|gt|gte|in|not_in>, \"value\": <JSON>}], "
        "\"effect\": <allow|deny|quarantine|flag>, "
        "\"description\": <one sentence>}]}. "
        f"Condition fields (ONLY these): {', '.join(CONDITION_FIELDS)}. "
        f"Subjects (ONLY these or \"*\"):\n{', '.join(subjects)}."
    )
    try:
        raw = models.chat(
            SPARK_MODEL,
            [{"role": "user", "content": prompt}],
            json_mode=True,
        )
        draft = json.loads(raw)
    except Exception as exc:
        return [], {"status": "fallback",
                    "reason": f"spark-error: {exc}"}
    if not isinstance(draft, dict):
        return [], {"status": "fallback",
                    "reason": "spark-invalid-json"}
    proposed, dropped = merge_spark_draft(
        base, draft, set(subjects), known_resources(graph))
    return proposed, {
        "status": "spark",
        "model": SPARK_MODEL,
        "dropped_draft_rules": dropped,
    }


def validate_policy(payload, graph, business_rules):
    """Return a list of validation errors (empty means valid)."""
    errors = []
    subjects = known_subjects(graph)
    resources = known_resources(graph)
    rules = payload.get("rules", [])

    seen = set()
    for rule in rules:
        errors.extend(validate_rule(rule, subjects, resources))
        rid = rule.get("id", "")
        if rid in seen:
            errors.append(f"duplicate rule id: {rid}")
        seen.add(rid)

    # Coverage: every numbered business rule compiles to >= 1 machine
    # rule. Anything uncovered is reported as uncompilable (fail closed),
    # never silently dropped.
    covered = {r.get("business_rule") for r in rules}
    for br_id in sorted(business_rules):
        if br_id not in covered:
            errors.append(f"{br_id} uncompilable: no machine rule covers "
                          f"it ({business_rules[br_id]})")

    # The catch-all default-deny must be the last enforced rule.
    if rules and rules[-1].get("id") != "pol-br7-default-deny":
        errors.append("last rule must be the pol-br7-default-deny "
                      "catch-all")

    for candidate in payload.get("proposed_rules", []):
        errors.extend(validate_rule(candidate, subjects, resources))
    return errors


def run_policy(rules_path, graph_path, use_spark=True):
    """Build, review, validate, and package the policy."""
    rules_path = Path(rules_path)
    graph_path = Path(graph_path)
    business_rules = parse_business_rules(rules_path)
    rules_text = rules_path.read_text(encoding="utf-8")
    graph = load_graph(graph_path)
    graph_text = graph_path.read_text(encoding="utf-8")

    rules = base_rules(graph)
    if use_spark:
        proposed, enrichment = enrich_with_spark(rules, graph, rules_text)
    else:
        proposed, enrichment = [], {"status": "fallback",
                                    "reason": "offline-flag"}

    payload = {
        "version": 1,
        "rules": rules,
        "proposed_rules": proposed,
        "semantics": {
            "evaluation": "unknown-or-revoked short-circuits to deny; "
                          "then deny/quarantine/flag before allow "
                          "(deny-override); first match in file order "
                          "wins within each class",
            "default": "deny (pol-br7-default-deny catch-all, last rule)",
            "subject_match": "exact graph node id or '*'",
            "resource_match": "fnmatch glob: rule resource is the "
                              "pattern, action resource the string",
            "conditions": "conjunction; empty matches; numeric ops on "
                          "non-numeric values are false",
            "gateway_relay": "post-decision mechanism, not re-evaluated",
        },
        "vocabulary": {
            "actions": list(ACTIONS),
            "effects": list(EFFECTS),
            "condition_fields": list(CONDITION_FIELDS),
            "ops": list(OPS),
        },
        "business_rules": business_rules,
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "sentinel-policy/1",
            "model": enrichment.get("model", "deterministic-fallback"),
            "graph_sha256": hashlib.sha256(
                graph_text.encode()).hexdigest(),
            "rules_sha256": hashlib.sha256(
                rules_text.encode()).hexdigest(),
            "enrichment": enrichment,
        },
    }
    errors = validate_policy(payload, graph, business_rules)
    if errors:
        raise ValueError("policy validation failed: " + "; ".join(errors))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel policy compiler: rules + graph -> policy.json")
    parser.add_argument("--rules", default=str(DEFAULT_RULES))
    parser.add_argument("--graph", default=str(DEFAULT_GRAPH))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--offline", action="store_true",
                        help="skip the Spark review call")
    args = parser.parse_args()

    payload = run_policy(args.rules, args.graph, use_spark=not args.offline)
    out = Path(args.output)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(payload['rules'])} rules, "
          f"{len(payload['proposed_rules'])} proposed, "
          f"enrichment={payload['meta']['enrichment']['status']})")


if __name__ == "__main__":
    main()

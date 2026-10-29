"""Layer 4 — Enforcement loop: the dynamic firewall + prevention.

Deterministic rule matching in code. No model sits in the decision path;
an LLM (muse-spark-1.3-contributor at most) may only write display-only
explanations for the console — demo data only, never affecting decisions.

Evaluation semantics (from sentinel/policy.py):
  1. Unknown/revoked/expired identity -> deny immediately (BR-7), with no
     further rule evaluation.
  2. Deny/quarantine/flag rules are checked before allow rules
     (deny-override); first match in file order wins within each class.
     The pol-br7-default-deny catch-all is the final fallback, not part
     of the override pass.
  3. A `flag` match denies the action but marks the record flagged: BR-5
     implausible telemetry is not acted on, BR-8 first breach throttles.
  4. The gateway's own relay writes are the post-decision mechanism, not
     new requests, so they are never re-evaluated.

The gateway owns the identity-derived condition fields: subject,
subject_kind, identity_status, rate_per_min, repeat, filter_has_wildcard,
and delta_c_per_min are computed here and overwrite any caller-supplied
values, so a requestor cannot spoof its way past BR-4/BR-5/BR-7/BR-8.
Wire-observed fields (value, wellformed, via_gateway, booking_match,
destination, filter) come from the caller; the Day 7 gateway service must
compute booking_match itself from the release payload plus the booking
registry rather than trusting the requestor's claim.

Usage:
    from sentinel.enforce import Gateway
    gw = Gateway()  # data/policy.json + data/graph.json, audit JSONL
    record = gw.request(credential, "write", "plc.setpoint",
                        {"via_gateway": True, "value": 1200})
    record["decision"]  # allow | deny | quarantine
"""

import argparse
import fnmatch
import json
import re
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from sentinel import identity

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "data" / "policy.json"
DEFAULT_GRAPH = REPO_ROOT / "data" / "graph.json"
DEFAULT_AUDIT = REPO_ROOT / "data" / "audit.jsonl"

EXPLAINER_MODEL = "muse-spark-1.3-contributor"

CATCHALL_ID = "pol-br7-default-deny"
UNKNOWN_RULE_ID = "pol-br7-deny-unknown-revoked"
THROTTLE_RULE_ID = "pol-br8-throttle-flood"

DECISIONS = ("allow", "deny", "quarantine")
NUMERIC_OPS = ("lt", "lte", "gt", "gte")
RATE_WINDOW_SECONDS = 60

PLC_REGISTERS = {"run_stop": "plc.run_stop", "setpoint": "plc.setpoint",
                 0: "plc.run_stop", 1: "plc.setpoint"}


def _match_condition(cond, context):
    """Evaluate one {field, op, value} condition against the context."""
    field, op = cond.get("field"), cond.get("op")
    expected = cond.get("value")
    actual = context.get(field)
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op in NUMERIC_OPS:
        # Numeric comparisons against a non-numeric field value are false
        # (no match, no crash); malformed values trip BR-9 instead.
        if actual is None or isinstance(actual, bool) \
                or not isinstance(actual, (int, float)):
            return False
        if op == "lt":
            return actual < expected
        if op == "lte":
            return actual <= expected
        if op == "gt":
            return actual > expected
        return actual >= expected
    return False


def _rule_matches(rule, subject, action, resource, context):
    """Subject exact-or-wildcard, action exact-or-wildcard, resource glob."""
    if rule.get("subject") != "*" and rule.get("subject") != subject:
        return False
    if rule.get("action") != "*" and rule.get("action") != action:
        return False
    if not fnmatch.fnmatchcase(resource, rule.get("resource", "")):
        return False
    return all(_match_condition(c, context)
               for c in rule.get("conditions", []))


def _is_reefer_resource(resource):
    return resource.startswith("topic:site/yard/reefer/") \
        and resource.endswith("/temperature")


def _synthesize(rule_id, effect):
    """Fallback rule citation if policy.json lacks the BR-7 rule."""
    return {"id": rule_id, "business_rule": "BR-7",
            "origin": "business-rule", "subject": "*", "action": "*",
            "resource": "*", "conditions": [], "effect": effect,
            "description": "BR-7 fallback: deny by default."}


def _citation(rule):
    return {"id": rule.get("id"), "business_rule": rule.get("business_rule"),
            "origin": rule.get("origin"), "effect": rule.get("effect"),
            "description": rule.get("description")}


class Gateway:
    """The choke point: every agent action passes through request()."""

    def __init__(self, policy_path=None, graph_path=None,
                 audit_path=DEFAULT_AUDIT, clock=None):
        policy = json.loads(Path(policy_path or DEFAULT_POLICY)
                            .read_text(encoding="utf-8"))
        rules = list(policy.get("rules", []))
        # Proposed (Spark-drafted) rules are never enforced.
        catchall = next((r for r in rules if r["id"] == CATCHALL_ID), None)
        self._catchall = catchall or _synthesize(CATCHALL_ID, "deny")
        self._deny_rules = [r for r in rules
                            if r.get("effect") in ("deny", "quarantine",
                                                  "flag")
                            and r.get("id") != CATCHALL_ID]
        self._allow_rules = [r for r in rules
                             if r.get("effect") == "allow"]
        self._unknown_rule = next(
            (r for r in rules if r.get("id") == UNKNOWN_RULE_ID), None) \
            or _synthesize(UNKNOWN_RULE_ID, "deny")
        graph = json.loads(Path(graph_path or DEFAULT_GRAPH)
                           .read_text(encoding="utf-8"))
        self._kinds = {n["id"]: n.get("kind", "device")
                       for n in graph.get("nodes", [])}
        self._overlay = []
        self._audit_path = Path(audit_path) if audit_path else None
        self._audit = []
        self._seq = 0
        self.clock = clock or time.time
        self._hits = {}
        self._throttled = set()
        self._reefer_baseline = {}

    @property
    def overlay_rules(self):
        """In-memory tightening rules (deny-only, checked first)."""
        return list(self._overlay)

    @property
    def audit_trail(self):
        """In-memory copy of every audit record, in order."""
        return list(self._audit)

    def subject_kind(self, subject):
        """agent | device | gateway for a policy subject.

        Unknown requestors are treated as agents so the BR-8 rate cap
        covers them (fail toward coverage, never toward exemption).
        """
        if subject == "edge-gateway":
            return "gateway"
        kind = self._kinds.get(subject)
        if kind == "agent":
            return "agent"
        if kind == "device":
            return "device"
        return "agent"

    def _rate(self, subject, now):
        """Trailing-60s action count for the subject, this attempt included."""
        window = self._hits.setdefault(subject, deque())
        cutoff = now - RATE_WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        window.append(now)
        return len(window)

    def _delta_reefer(self, resource, value, now):
        """Abs temp change per minute vs the last ALLOWED reading.

        Sub-minute gaps count as one second (never divide by zero). Only
        allowed readings move the baseline, so one spoof cannot poison
        the next legitimate publish.
        """
        if not _is_reefer_resource(resource) or value is None \
                or isinstance(value, bool) \
                or not isinstance(value, (int, float)):
            return None
        baseline = self._reefer_baseline.get(resource)
        if baseline is None:
            return 0.0
        prev_value, prev_ts = baseline
        gap_minutes = max((now - prev_ts) / 60.0, 1.0 / 60.0)
        return abs(value - prev_value) / gap_minutes

    def request(self, credential, action, resource, context=None):
        """Evaluate one agent action; return the full audit record."""
        now = self.clock()
        payload, status = identity.verify_status(credential)
        claimed = payload or identity._coerce(credential) or {}
        subject = claimed.get("role", "unknown") or "unknown"
        cred_id = claimed.get("id", "unknown") or "unknown"

        ctx = dict(context or {})
        # Gateway-authoritative fields overwrite caller claims.
        ctx["subject"] = subject
        ctx["subject_kind"] = self.subject_kind(subject)
        ctx["identity_status"] = status
        ctx["rate_per_min"] = self._rate(subject, now)
        ctx["repeat"] = subject in self._throttled
        if isinstance(ctx.get("filter"), str):
            filt = ctx["filter"]
            ctx["filter_has_wildcard"] = "#" in filt or "+" in filt
        delta = self._delta_reefer(resource, ctx.get("value"), now)
        if delta is not None:
            ctx["delta_c_per_min"] = delta

        if status != "valid":
            return self._record(now, credential, cred_id, subject, action,
                                resource, ctx, self._unknown_rule, "deny",
                                flagged=False, policy_change=None)

        for rule in list(self._overlay) + self._deny_rules:
            if _rule_matches(rule, subject, action, resource, ctx):
                effect = rule.get("effect")
                if effect == "quarantine":
                    return self._quarantine(now, credential, cred_id,
                                            subject, action, resource, ctx,
                                            rule)
                if effect == "flag":
                    change = None
                    if rule.get("id") == THROTTLE_RULE_ID:
                        self._throttled.add(subject)
                        change = (f"throttled {subject}: BR-8 rate cap "
                                  f"breached (flag + audit); repeat "
                                  f"quarantines")
                    return self._record(now, credential, cred_id, subject,
                                        action, resource, ctx, rule, "deny",
                                        flagged=True, policy_change=change)
                return self._record(now, credential, cred_id, subject,
                                    action, resource, ctx, rule, "deny",
                                    flagged=False, policy_change=None)

        for rule in self._allow_rules:
            if _rule_matches(rule, subject, action, resource, ctx):
                if _is_reefer_resource(resource) \
                        and isinstance(ctx.get("value"), (int, float)) \
                        and not isinstance(ctx.get("value"), bool):
                    self._reefer_baseline[resource] = (ctx["value"], now)
                return self._record(now, credential, cred_id, subject,
                                    action, resource, ctx, rule, "allow",
                                    flagged=False, policy_change=None)

        return self._record(now, credential, cred_id, subject, action,
                            resource, ctx, self._catchall, "deny",
                            flagged=False, policy_change=None)

    def _quarantine(self, now, credential, cred_id, subject, action,
                    resource, ctx, rule):
        """Revoke the violator and tighten policy in memory."""
        revoked = identity.revoke(credential)
        slug = re.sub(r"[^a-z0-9]+", "-", subject).strip("-")
        overlay_id = f"tighten-deny-{slug}-{len(self._overlay) + 1}"
        self._overlay.append(
            {"id": overlay_id, "business_rule": rule.get("business_rule"),
             "origin": "enforcement-tightening", "subject": subject,
             "action": "*", "resource": "*", "conditions": [],
             "effect": "deny",
             "description": f"Tightening: all {subject} actions denied "
                            f"after quarantine by {rule.get('id')}."})
        state = f"revoked credential {cred_id}" if revoked \
            else f"credential {cred_id} already revoked"
        change = (f"{state}; overlay {overlay_id} denies all {subject} "
                  f"actions (quarantined by {rule.get('id')})")
        return self._record(now, credential, cred_id, subject, action,
                            resource, ctx, rule, "quarantine",
                            flagged=False, policy_change=change)

    def _record(self, now, credential, cred_id, subject, action, resource,
                ctx, rule, decision, flagged, policy_change):
        self._seq += 1
        record = {
            "seq": self._seq,
            "ts": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "identity": {"id": cred_id, "role": subject, "status":
                         ctx["identity_status"]},
            "subject": subject,
            "subject_kind": ctx["subject_kind"],
            "action": action,
            "resource": resource,
            "context": ctx,
            "matched_rule": _citation(rule),
            "decision": decision,
            "flagged": flagged,
            "policy_change": policy_change,
        }
        self._audit.append(record)
        if self._audit_path is not None:
            with open(self._audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        return record

    def decide(self, credential, action, resource, context=None):
        """Return 'allow' | 'deny' | 'quarantine' for an agent action."""
        return self.request(credential, action, resource,
                            context)["decision"]

    # Choke-point helpers: thin context builders over request() for the
    # Day 7 gateway service and the Day 8 red-team console.

    def plc_write(self, credential, register, value, via_gateway=True):
        """A PLC register write request (register: setpoint|run_stop|0|1)."""
        if register not in PLC_REGISTERS:
            raise ValueError(f"unknown PLC register: {register!r}")
        wellformed = isinstance(value, (int, float)) \
            and not isinstance(value, bool)
        return self.request(
            credential, "write", PLC_REGISTERS[register],
            {"via_gateway": via_gateway, "value": value,
             "wellformed": wellformed})

    def mqtt_publish(self, credential, topic, value=None, booking_match=None):
        """An MQTT publish request to a bare topic (no 'topic:' prefix)."""
        ctx = {"value": value}
        if booking_match is not None:
            ctx["booking_match"] = booking_match
        return self.request(credential, "publish", f"topic:{topic}", ctx)

    def release_gate(self, credential, container, truck, booking):
        """A gate-release publish; booking_match is computed, not claimed."""
        from sim import agents

        expected = agents.BOOKINGS.get(container)
        match = expected is not None \
            and expected.get("truck") == truck \
            and expected.get("booking") == booking
        return self.request(credential, "publish",
                            "topic:site/yard/gate/release",
                            {"booking_match": match})

    def mqtt_subscribe(self, credential, topic_filter):
        """An MQTT subscribe request for a topic filter verbatim."""
        return self.request(credential, "subscribe",
                            f"topic:{topic_filter}",
                            {"filter": topic_filter})

    def camera_stream(self, credential, destination):
        """A camera frame-stream request toward a destination node."""
        return self.request(credential, "stream", "camera.frames",
                            {"destination": destination})


_default_gateway = None


def _get_default():
    global _default_gateway
    if _default_gateway is None:
        _default_gateway = Gateway()
    return _default_gateway


def reset():
    """Drop the default gateway (fresh policy, rate, and audit state)."""
    global _default_gateway
    _default_gateway = None


def decide(agent_credential, action, resource, context=None):
    """Return 'allow' | 'deny' | 'quarantine' for an agent action.

    1. Verify the credential via identity.py.
    2. Match data/policy.json (subject + action + resource + conditions).
    3. Run plausibility checks on telemetry-driven actions.
    4. On deny/quarantine: revoke severe violators, tighten policy in
       memory, append a full audit record.
    """
    return _get_default().decide(agent_credential, action, resource,
                                 context)


def explain(record):
    """Display-only plain-language explanation of a decided record.

    Never affects the decision (it runs after decide() returns) and
    never sees real data: only the synthetic demo fields below cross
    into the Contributor-tier prompt. Offline-safe: without an API key
    or on any model failure, returns a deterministic template.
    """
    subject = record.get("subject", "unknown")
    rule = record.get("matched_rule", {})
    template = (f"{subject} -> {record.get('action')} "
                f"{record.get('resource')}: {record.get('decision')} "
                f"({rule.get('id')}) — {rule.get('description')}")
    import os

    key = os.getenv("META_API_KEY", "").strip()
    if not key or key == "...":
        return template
    from sentinel import models

    prompt = (
        "Explain this demo firewall decision in one plain sentence for a "
        "dashboard (synthetic demo data only): "
        f"subject={subject} action={record.get('action')} "
        f"resource={record.get('resource')} decision={record.get('decision')} "
        f"rule={rule.get('id')} summary={rule.get('description')}"
    )
    try:
        text = models.chat(EXPLAINER_MODEL,
                           [{"role": "user", "content": prompt}])
    except Exception:
        return template
    return text.strip() if isinstance(text, str) and text.strip() \
        else template


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel enforcement: replay the demo attacks offline")
    parser.add_argument("--audit", default=str(DEFAULT_AUDIT))
    args = parser.parse_args()

    # One gateway per scenario: each demonstrates its rule in isolation
    # (a shared gateway would deny later rogue scenarios via the tightening
    # overlay left by the first quarantine — correct, but noisy for a demo).
    def fresh_creds(role, scope):
        return identity.issue(role, "sentinel-ca", scope)

    scenarios = [
        ("operator setpoint 1200 (allow)",
         lambda gw, c: gw.plc_write(c["op"], "setpoint", 1200)),
        ("rogue setpoint 3000 (deny BR-9)",
         lambda gw, c: gw.plc_write(c["rogue"], "setpoint", 3000)),
        ("rogue wildcard subscribe (quarantine BR-4)",
         lambda gw, c: gw.mqtt_subscribe(c["rogue"], "#")),
        ("rogue gate release, no booking (quarantine BR-3)",
         lambda gw, c: gw.release_gate(c["rogue"], "XXXX000000", "TRK-99",
                                       "BK-FAKE")),
        ("sensor telemetry (allow)",
         lambda gw, c: gw.mqtt_publish(c["sensor"],
                                       "site/line1/sensors/temperature",
                                       71.5)),
        ("reefer baseline -20C (allow)",
         lambda gw, c: gw.mqtt_publish(
             c["reefer"], "site/yard/reefer/R-101/temperature", -20.0)),
        ("rogue reefer spoof +5C (flag BR-5)",
         lambda gw, c: (gw.mqtt_publish(
             c["reefer"], "site/yard/reefer/R-101/temperature", -20.0),
             gw.mqtt_publish(
                 c["rogue"], "site/yard/reefer/R-101/temperature", 5.0))[1]),
    ]
    total = 0
    for label, run in scenarios:
        gw = Gateway(audit_path=args.audit)
        creds = {
            "op": fresh_creds("operator-agent",
                              ["telemetry.read", "plc.write",
                               "gate.release"]),
            "rogue": fresh_creds("rogue-agent", ["telemetry.read"]),
            "reefer": fresh_creds("reefer-container-1",
                                  ["telemetry.write"]),
            "sensor": fresh_creds("sensor-temp-line1", ["telemetry.write"]),
        }
        record = run(gw, creds)
        total += len(gw.audit_trail)
        print(f"{record['decision']:10} {record['matched_rule']['id']:40} "
              f"{label}")
    print(f"audit: {args.audit} ({total} records)")


if __name__ == "__main__":
    main()

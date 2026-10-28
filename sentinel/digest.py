"""Layer 1 — Digest / Scout: registry + configs -> data/graph.json.

The registry is the source of truth. The digest builds a deterministic base
graph from it, optionally asks muse-spark-1.3 to enrich descriptions and
flows, and validates the result: any node the model introduces that is not
in the registry is dropped, never added.

Usage:
    python3 -m sentinel.digest [--offline] [--registry PATH] [--output PATH]
"""

import argparse
import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = REPO_ROOT / "data" / "registry.yaml"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "graph.json"
DEFAULT_FRAMES_DIR = REPO_ROOT / "sim" / "camera_frames"
SPARK_MODEL = "muse-spark-1.3"

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

ROGUE_ID = "rogue-agent"
ROGUE_ZONE = "external/untrusted"


def load_registry(path):
    """Parse the device registry YAML."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def plc_register_map():
    """Return the PLC register map from the sim build (source of truth)."""
    try:
        from sim import plc

        return {
            "run_stop": {"address": plc.HR_RUN_STOP, "kind": "holding-register"},
            "speed_setpoint": {"address": plc.HR_SPEED_SETPOINT, "kind": "holding-register"},
            "speed_max_rpm": plc.SPEED_MAX_RPM,
        }
    except Exception:
        return {
            "run_stop": {"address": 0, "kind": "holding-register"},
            "speed_setpoint": {"address": 1, "kind": "holding-register"},
            "speed_max_rpm": 3000,
        }


def _registry_ids(registry):
    """All device + agent ids declared in the registry."""
    ids = set()
    for site in registry.get("sites", []):
        for device in site.get("devices", []):
            ids.add(device["id"])
    for agent in registry.get("agents", []):
        ids.add(agent["id"])
    return ids


def build_base_graph(registry, plc_map):
    """Build the deterministic base graph from the registry.

    Nodes: one per device, one per agent, one per MQTT topic pattern.
    Edges: publisher -> topic -> gateway flows plus command flows.
    """
    nodes = []
    edges = []
    identities = []
    topics = {}  # pattern -> publishing device ids

    gateway_id = None
    for site in registry.get("sites", []):
        for device in site.get("devices", []):
            if device.get("type") == "gateway":
                gateway_id = device["id"]
    if gateway_id is None:
        gateway_id = "edge-gateway"

    for site in registry.get("sites", []):
        site_name = site.get("name", "")
        zone = site.get("zone", "")
        boundary = site.get("trust_boundary", "")
        for device in site.get("devices", []):
            node = {
                "id": device["id"],
                "kind": "device",
                "type": device.get("type", ""),
                "site": site_name,
                "zone": zone,
                "trust_boundary": boundary,
                "protocol": device.get("protocol", ""),
                "topics": list(device.get("topics", [])),
                "identity": device.get("identity", ""),
            }
            if device.get("address"):
                node["address"] = device["address"]
            if device.get("notes"):
                node["notes"] = device["notes"]
            if device.get("type") == "plc":
                node["registers"] = plc_map
            if device.get("type") == "camera":
                node["frames_dir"] = device.get("frames_dir", "sim/camera_frames/")
                node["sam_objects"] = []
            nodes.append(node)
            identities.append({
                "id": device.get("identity", device["id"]),
                "owner": device["id"],
                "owner_kind": "device",
                "role": device.get("type", ""),
            })
            for pattern in device.get("topics", []):
                topics.setdefault(pattern, []).append(device["id"])

    for agent in registry.get("agents", []):
        nodes.append({
            "id": agent["id"],
            "kind": "agent",
            "role": agent.get("role", ""),
            "zone": agent.get("zone", ""),
            "trust_boundary": agent.get("trust_boundary", ""),
            "scope": list(agent.get("scope", [])),
            "identity": agent.get("identity", ""),
            "enabled_by_default": agent.get("enabled_by_default", True),
        })
        identities.append({
            "id": agent.get("identity", agent["id"]),
            "owner": agent["id"],
            "owner_kind": "agent",
            "role": agent.get("role", ""),
            "scope": list(agent.get("scope", [])),
        })

    for pattern in sorted(topics):
        nodes.append({"id": f"topic:{pattern}", "kind": "topic", "pattern": pattern})
        for publisher in topics[pattern]:
            if publisher == gateway_id:
                continue
            edges.append({
                "from": publisher,
                "to": f"topic:{pattern}",
                "protocol": "mqtt",
                "description": f"{publisher} publishes {pattern}",
            })
            edges.append({
                "from": f"topic:{pattern}",
                "to": gateway_id,
                "protocol": "mqtt",
                "description": f"gateway bridges {pattern}",
            })

    # Command flows through the gateway (the choke point).
    edges.append({
        "from": gateway_id,
        "to": "plc-line1",
        "protocol": "modbus-tcp",
        "description": "gateway relays authorized PLC writes (HR0 run/stop, HR1 setpoint)",
    })
    edges.append({
        "from": "operator-agent",
        "to": gateway_id,
        "protocol": "mqtt",
        "description": "operator subscribes to sensor/gate topics, issues in-policy commands",
    })

    return {
        "trust_boundaries": list(registry.get("trust_boundaries", [])),
        "nodes": nodes,
        "edges": edges,
        "identities": identities,
    }


def merge_enrichment(base_graph, draft):
    """Merge a model draft into the base graph, dropping unknown node ids.

    Returns (merged_graph, dropped_ids). Only descriptions and edges
    between known nodes are accepted; invented nodes are rejected.
    """
    merged = copy.deepcopy(base_graph)
    known = {n["id"] for n in merged["nodes"]}
    dropped = []

    descriptions = draft.get("node_descriptions", {})
    if isinstance(descriptions, dict):
        by_id = {n["id"]: n for n in merged["nodes"]}
        for node_id, text in descriptions.items():
            if node_id in by_id and isinstance(text, str):
                by_id[node_id]["description"] = text
            else:
                dropped.append(node_id)

    existing = {(e["from"], e["to"]) for e in merged["edges"]}
    for edge in draft.get("edges", []):
        if not isinstance(edge, dict):
            continue
        src, dst = edge.get("from"), edge.get("to")
        if src in known and dst in known and (src, dst) not in existing:
            merged["edges"].append({
                "from": src,
                "to": dst,
                "protocol": edge.get("protocol", ""),
                "description": edge.get("description", ""),
            })
            existing.add((src, dst))
        else:
            dropped.append(f"{src}->{dst}")

    return merged, sorted(set(dropped))


def enrich_with_spark(base_graph, registry_text):
    """Ask Spark to enrich the base graph; validate before merging.

    Returns (graph, info). On any failure the base graph is returned
    unchanged with info describing the fallback reason.
    """
    from sentinel import models

    key = os.getenv("META_API_KEY", "").strip()
    if not key or key == "...":
        return base_graph, {"status": "fallback", "reason": "no-api-key"}

    node_ids = sorted(n["id"] for n in base_graph["nodes"])
    prompt = (
        "You enrich an edge/IoT environment graph for a demo firewall. "
        "The node inventory below is FIXED — describe it, never extend it.\n\n"
        f"Registry (source of truth):\n{registry_text}\n\n"
        f"Base graph JSON:\n{json.dumps(base_graph)}\n\n"
        "Return JSON only: "
        '{"node_descriptions": {<node-id>: <one sentence>}, '
        '"edges": [{"from": <node-id>, "to": <node-id>, '
        '"protocol": <string>, "description": <string>}]}\n'
        f"Use ONLY these node ids: {', '.join(node_ids)}. "
        "Describe legitimate data/command flows through the gateway. "
        "Do not invent devices, agents, or topics."
    )
    try:
        raw = models.chat(
            SPARK_MODEL,
            [{"role": "user", "content": prompt}],
            json_mode=True,
        )
        draft = json.loads(raw)
    except Exception as exc:
        return base_graph, {"status": "fallback", "reason": f"spark-error: {exc}"}
    if not isinstance(draft, dict):
        return base_graph, {"status": "fallback", "reason": "spark-invalid-json"}
    merged, dropped = merge_enrichment(base_graph, draft)
    return merged, {
        "status": "spark",
        "model": SPARK_MODEL,
        "dropped_node_ids": dropped,
    }


def scan_frames(frames_dir):
    """List image files in the camera frames directory."""
    path = Path(frames_dir)
    if not path.is_dir():
        return []
    return sorted(
        p.name for p in path.iterdir()
        if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
    )


def filter_sam_objects(objects, registry_ids):
    """Keep only SAM objects matching a known registry device."""
    return [o for o in objects if o.get("matches_device") in registry_ids]


def attach_sam_objects(graph, frames_dir):
    """Attach camera frame inventory to camera nodes.

    SAM segmentation runs when frames exist and a SAM client is
    available; otherwise frames are recorded as pending (per the spec
    fallback: digest from registry + configs only).
    """
    frames = scan_frames(frames_dir)
    if not frames:
        return "no_frames"
    for node in graph["nodes"]:
        if node.get("type") == "camera":
            node["sam_objects"] = []
            node["frames"] = frames
    return "frames_pending_sam"


def validate_graph(graph, registry):
    """Return a list of validation errors (empty means valid)."""
    errors = []
    node_ids = {n["id"] for n in graph["nodes"]}

    for site in registry.get("sites", []):
        for device in site.get("devices", []):
            if device["id"] not in node_ids:
                errors.append(f"missing registry device: {device['id']}")
    for agent in registry.get("agents", []):
        if agent["id"] not in node_ids:
            errors.append(f"missing registry agent: {agent['id']}")

    allowed_prefixes = ("topic:",)
    known = _registry_ids(registry)
    for node_id in node_ids:
        if node_id in known:
            continue
        if node_id.startswith(allowed_prefixes):
            continue
        errors.append(f"unknown node not in registry: {node_id}")

    rogue = next((n for n in graph["nodes"] if n["id"] == ROGUE_ID), None)
    if rogue is None:
        errors.append("missing rogue-agent node")
    elif rogue.get("zone") != ROGUE_ZONE:
        errors.append(f"rogue-agent must sit in zone {ROGUE_ZONE}")

    if not graph.get("trust_boundaries"):
        errors.append("missing trust boundaries")
    return errors


def run_digest(registry_path, frames_dir, use_spark=True):
    """Build, enrich, and validate the environment graph."""
    registry_path = Path(registry_path)
    registry = load_registry(registry_path)
    registry_text = registry_path.read_text(encoding="utf-8")

    graph = build_base_graph(registry, plc_register_map())
    if use_spark:
        graph, enrichment = enrich_with_spark(graph, registry_text)
    else:
        enrichment = {"status": "fallback", "reason": "offline-flag"}
    sam_status = attach_sam_objects(graph, frames_dir)

    errors = validate_graph(graph, registry)
    if errors:
        raise ValueError("graph validation failed: " + "; ".join(errors))

    graph["meta"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "sentinel-digest/1",
        "model": enrichment.get("model", "deterministic-fallback"),
        "registry_sha256": hashlib.sha256(registry_text.encode()).hexdigest(),
        "sam_status": sam_status,
        "enrichment": enrichment,
        "plc_registers": plc_register_map(),
    }
    return graph


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel digest: registry -> graph.json")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--frames-dir", default=str(DEFAULT_FRAMES_DIR))
    parser.add_argument("--offline", action="store_true",
                        help="skip the Spark enrichment call")
    args = parser.parse_args()

    graph = run_digest(args.registry, args.frames_dir, use_spark=not args.offline)
    out = Path(args.output)
    out.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges, "
          f"enrichment={graph['meta']['enrichment']['status']}, "
          f"sam={graph['meta']['sam_status']})")


if __name__ == "__main__":
    main()

# Sentinel — an agent-aware firewall for edge, IoT, and physical AI

Today's firewalls filter packets, not agents. As AI agents start operating
physical systems at the edge — PLCs, sensors, yard equipment — Sentinel maps
the attack surface, compiles plain-language business rules into an
enforceable policy, and blocks, quarantines, and revokes rogue agents live.

> Traditional firewalls inspect packets; Sentinel inspects intent.

Status: Day 6 — enforcement loop complete (`sentinel/enforce.py`:
deterministic `decide()` over `data/policy.json` — deny-override,
BR-7 short-circuit, rate/plausibility tracking, quarantine+revoke with
in-memory tightening, JSONL audit; `python3 -m sentinel.enforce`
replays the demo attacks offline). Build order and acceptance criteria
live in [sentinel-build-spec.md](sentinel-build-spec.md).

## Layout

- `sim/` — two-site simulator (plant line + truck yard), MQTT/Modbus, agents
- `sentinel/` — digest, analyst, policy compiler, enforcement, identity, models
- `console/` — Streamlit demo console (Layer 5)
- `data/` — registry, business rules, generated graph/threats/policy JSON
- `demo/` — demo narration
- `tests/` — contract tests (`python3 -m unittest discover -s tests`)

## Run the sim (one terminal each)

```bash
./sim/broker.sh
python3 sim/plc.py
python3 sim/sensors.py
python3 sim/yard.py --jitter 1 --drop 0.1
python3 sim/agents.py            # operator
python3 sim/rogue.py             # rogue attack script (off by default)
```

Subscribe to everything:

```bash
docker exec sentinel-mosquitto mosquitto_sub -t 'site/#' -v
```

API calls (Meta Model API via `META_API_KEY`) are needed only to regenerate
the cached artifacts in `data/` — never to run the sim or, later, the demo.

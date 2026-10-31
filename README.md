# Sentinel — an agent-aware firewall for edge, IoT, and physical AI

Today's firewalls filter packets, not agents. As AI agents start operating
physical systems at the edge — PLCs, sensors, yard equipment — there is no
firewall built for them: no identity-aware policy, no attack-surface map of
what an agent can reach, no prevention loop that revokes a rogue agent in
real time. Sentinel is an agentic framework that digests an edge/IoT
environment, maps its attack surface, builds a dynamic firewall from business
rules stated in plain language, and enforces it live — blocking, quarantining,
and revoking rogue agents before they touch physical equipment.

> Traditional firewalls inspect packets; Sentinel inspects intent.

A well-formed Modbus write from an authenticated-but-rogue agent sails through
a packet filter — its packets are perfect, its intent is malicious. That gap
is the product.

Status: Day 9 — README, demo script, and submission draft complete; demo video
is the remaining manual step (see `demo/script.md`). Build order and
acceptance criteria live in [sentinel-build-spec.md](sentinel-build-spec.md).

## Architecture

```
Simulated world (localhost)              What protects it
───────────────────────────              ──────────────────────────────
Site A — Plant line                      ┌────────────────────────────┐
  PLC (Modbus/TCP :5020)                 │ SENTINEL (intent layer)    │
  sensors (MQTT site/line1/...)          │  1. Digest → graph.json    │
  camera frames                          │  2. Analyst → threats.json │
Site B — Truck yard (constrained link)   │  3. Policy compiler →      │
  reefers / gate / equipment / moves     │     policy.json (26 rules) │
Agents: operator (legit) / rogue (evil)  │  4. Enforcement loop:      │
        │                                │     allow/deny/quarantine  │
        ▼                                │  5. Console (this dashboard)│
┌───────────────────────────────┐        └──────────────┬─────────────┘
│ Adjacent network firewall     │  ◄── assumed present, below Sentinel
│ (packets: IP/ports/TLS) —     │      (out of scope; see Scope)
│ NOT Sentinel's job            │
└───────────────────────────────┘
```

Golden rule: **no agent action reaches a device without passing through
layer 4.** The gateway is the choke point. Anything that talks to the PLC
directly, bypassing the gateway, is itself flagged as an anomaly.

**Models advise, code decides.** All nondeterminism lives at build/setup time
and ends in a committed, reviewed artifact (`graph.json`, `threats.json`,
`policy.json`). The runtime path — sim → gateway → `decide()` → audit —
contains zero model calls, so the demo is reproducible and the system is
testable. Every model output crossing toward enforcement passes a
deterministic validator; failures fail closed (deny/flag), never retry-until-
pretty.

## Layout

- `sim/` — two-site simulator (plant line + truck yard), MQTT/Modbus, agents
- `sentinel/` — digest, analyst, policy compiler, enforcement, identity, models
- `console/` — Streamlit demo console (Layer 5)
- `data/` — registry, business rules, generated graph/threats/policy JSON
- `demo/` — demo narration (`script.md`) + submission draft (`submission.md`)
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

## Run the console

```bash
python3 -m venv .venv          # once; project-local environment
source .venv/bin/activate
pip install -r requirements.txt
streamlit run console/app.py   # open http://localhost:8501 in a browser
```

The console runs fully offline from `data/graph.json`, `data/threats.json`,
and `data/policy.json` — no API key needed. Fire attacks from the Red team
tab and watch them get blocked in the live feed and audit log.

Health dots (broker / PLC / gateway / yard-link) are live TCP probes: "down"
just means that sim process isn't running. The Red team scenarios run through
the in-process gateway and work regardless.

## Try it yourself (judges and visitors, ~2 minutes, no API key)

1. Start the sim (broker + PLC + sensors + yard above) and
   `streamlit run console/app.py`.
2. Overview tab: note the block counters and live feed.
3. Red team tab: fire **Wildcard recon**, then **Forged PLC write** —
   watch them land red (quarantine / deny) in the feed and audit log.
4. Policies tab: find the rule that blocked each attack
   (`pol-br4-quarantine-wildcard`, `pol-br9-deny-above-range`).
5. Agents & identities tab: see the rogue credential revoked.

Full narration: [demo/script.md](demo/script.md).

## Regenerating the cached artifacts (API key needed, optional)

Running the sim and console never needs a key. Only regenerating the
committed artifacts does (Meta Model API via `META_API_KEY` in `.env`;
see `.env.example`):

- `sentinel/digest.py` (Spark 1.3 + SAM 3.1) → `data/graph.json`
- `sentinel/analyst.py` (Wonder) → `data/threats.json`
- `sentinel/policy.py` (Spark 1.3) → `data/policy.json`

## Models used

| Model | ID | Use |
|---|---|---|
| Muse Spark 1.3 | `muse-spark-1.3` | Digest, policy compiler (build time) |
| Muse Wonder | `muse-wonder-1.0` | Attack-surface analysis (build time) |
| SAM 3.1 | `sam-3.1` | Camera-frame segmentation (build time) |
| Muse Image | `muse-image-1.0` | Synthetic camera frames |

Runtime enforcement is deterministic code — no model calls in the loop.

## Scope

Agentic attacks only, plus the free aligned checks (unknown/revoked identity,
publish flood, out-of-range write — they ride the same `decide()` path).
Traditional network-layer handling (packet capture, IP/port rules, network
IDS, TLS interception) is explicitly out of scope and assumed as the adjacent
network firewall shown below Sentinel in the diagram.

Synthetic demo data only. No real credentials, employer data, or personal
data anywhere in the repo or video.

## Why this wins (judging coverage)

- **Creativity:** an agent-aware firewall — no packet filter governs agent
  intent, identity, or revocation.
- **Technical ambition:** a framework plus a working two-site sim plus five
  layers (digest, analyst, policy compiler, enforcement, console).
- **Works:** scripted attacks blocked live on video and reproducible on any
  localhost with no API key.

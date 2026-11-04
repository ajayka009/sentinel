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
Agents: operator (scripted or Glimmer-driven) │  4. Enforcement loop:      │
        rogue (evil)                       │     allow/deny/quarantine  │
        │                                │  5. Console (this dashboard)│
        ▼                                │                            │
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
  (`agents.py` scripted operator, `glimmer_operator.py` Glimmer-driven
  operator, `rogue.py` rogue)
- `sentinel/` — digest, analyst, policy compiler, enforcement, identity, models
- `console/` — Streamlit demo console (Layer 5)
- `data/` — registry, business rules, generated graph/threats/policy JSON
- `models/` — Glimmer weights (gitignored, never committed)
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

## Glimmer operator agent (P2-12, governed side)

`sim/glimmer_operator.py` runs the operator role with a local Muse Glimmer
30B model instead of a script: every ~10s it perceives sensor/gate state,
asks the model for ONE action (setpoint, gate release, or no-op), and
submits it to the unchanged Layer 4 gateway — which allows, denies, or
quarantines it like any other agent attempt. Denied attempts are logged
and never touch the wire. The model decides what is *attempted*; code-only
`decide()` decides what is *allowed*. `sim/agents.py` stays untouched as
the scripted fallback.

With the sim running (above):

```bash
python3 sim/glimmer_operator.py --hardware-gate       # Step 0: can this
                                                      # machine hold 30B?
python3 sim/glimmer_operator.py --backend stub --cycles 10 --skip-gate  # loop
                                                      # check, no weights
                                                      # (--skip-gate: stub
                                                      # needs no weights)
ollama pull muse-glimmer:30b                          # once, ~18GB local
python3 sim/glimmer_operator.py --backend ollama --cycles 0 # live operator
```

Backends are all local (no API calls, no network beyond localhost):
`ollama` (default tag `muse-glimmer:30b`), `llama.cpp` (GGUF in gitignored
`models/`), or `stub` (deterministic, for tests). Every cycle appends one
JSONL line to `data/glimmer_operator.jsonl` (gitignored, console-readable).
If the hardware gate FAILs, local Glimmer is not viable on that machine —
the scripted operator remains the demo (spec fallback).

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

## Edge compute for the Glimmer operator (GCP spot VM)

The laptop can't hold Glimmer 30B (~18GB), so P2-12 runs on one cloud VM
as the "edge node": the whole stack (broker, sim, operator, console,
inference) runs there over localhost, so local-inference story stays
intact — no API calls, no network dependency at demo time. No GPU needed;
CPU inference keeps up with the ~10s agent cycle.

```bash
# 1. One-time: commit + push this repo, then create the VM (spot, ~$0.10/hr
#    under the $300 trial credit — a few dollars total; STOP keeps the disk
#    if the spot instance is preempted).
gcloud compute instances create sentinel-edge --zone=us-central1-a \
  --machine-type=e2-highmem-8 --provisioning-model=SPOT \
  --instance-termination-action=STOP --boot-disk-size=80GB \
  --boot-disk-type=pd-balanced --image-family=debian-12 \
  --image-project=debian-cloud

# 2. Copy + run the setup script on the VM (installs mosquitto, Ollama,
#    pulls muse-glimmer:30b, clones the repo, runs the hardware gate).
gcloud compute scp scripts/edge_vm_setup.sh sentinel-edge:~/ \
  --zone=us-central1-a
gcloud compute ssh sentinel-edge --zone=us-central1-a
chmod +x ~/edge_vm_setup.sh && ~/edge_vm_setup.sh   # ~18GB pull takes a while

# 3. On the VM, one terminal each (see script output for the full order):
python3 sim/glimmer_operator.py --backend ollama --cycles 12  # acceptance run
streamlit run console/app.py --server.address 127.0.0.1

# 4. On the laptop, view the console through a tunnel (no firewall rule):
gcloud compute ssh sentinel-edge --zone=us-central1-a -- -L 8501:localhost:8501
# open http://localhost:8501
```

## Models used

| Model | ID | Use |
|---|---|---|
| Muse Spark 1.3 | `muse-spark-1.3` | Digest, policy compiler (build time) |
| Muse Wonder | `muse-wonder-1.0` | Attack-surface analysis (build time) |
| SAM 3.1 | `sam-3.1` | Camera-frame segmentation (build time) |
| Muse Image | `muse-image-1.0` | Synthetic camera frames |
| Muse Glimmer 30B | `muse-glimmer:30b` (local, self-hosted, Apache 2.0) | Governed operator agent (P2-12, edge node) |

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

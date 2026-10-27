# Sentinel — Build Spec

**Meta Global AI Developer Hackathon — Indie Track (solo)**
**Working name:** Sentinel — an agent-aware firewall for edge, IoT, and physical AI.

## Key facts

- Kickoff: Mon Oct 26, 2026. Submissions due: **Tue Nov 4, 9:00 PM ET**. Winners announced Nov 9.
- Track: Indie developer — judged on **creativity, technical ambition, and whether it works**.
- Theme: **Push the Frontier** (models meeting the real world: physical systems, robotics, manufacturing). Secondary framing: Build for Your World — this is the OT/edge world the builder knows firsthand.
- Stack: Python. Meta Model API (OpenAI-SDK compatible, base URL `https://api.meta.ai/v1`). Muse Code as the coding agent.

## The pitch (one paragraph, use in the submission)

Today's firewalls filter packets, not agents. As AI agents start operating physical systems at the edge — PLCs, sensors, yard equipment — there is no firewall built for them: no identity-aware policy, no attack-surface map of what an agent can reach, no prevention loop that revokes a rogue agent in real time. Sentinel is an agentic framework that digests an edge/IoT environment, maps its attack surface, builds a dynamic firewall from business rules stated in plain language, and enforces it live — blocking, quarantining, and revoking rogue agents before they touch physical equipment.

## Scope decision (locked Oct 26)

**Agentic attacks only, plus the free aligned checks.** The build covers attacks carried out by agents (authenticated or not) through the agent-action path. Traditional network-layer attack handling is explicitly out of scope — no packet capture, no IP/port rules, no signature-based network IDS, no TLS interception, no IP reputation. That layer is assumed to exist as the adjacent network firewall, and the README architecture diagram must show it sitting below Sentinel.

**Free aligned checks included** (they ride the existing `decide()` path at ~zero extra cost):
1. Unknown or revoked identity tries to connect or act → denied by default-deny.
2. Publish/action flood by an agent → per-agent rate cap triggers throttle + quarantine.
3. Out-of-range or malformed write (e.g., setpoint outside the safe range) → rejected by condition check.

**Positioning line (use in README + submission):** "Traditional firewalls inspect packets; Sentinel inspects intent." A well-formed Modbus write from an authenticated-but-rogue agent sails through a packet filter — its packets are perfect, its intent is malicious. That gap is the product.

## LLM usage doctrine: deterministic vs non-deterministic (governing rule)

**The rule: models advise, code decides. No model output is ever the sole decider of a deterministic outcome.**

This is a hard-won lesson from prior agent work: using a probabilistic model as a boolean decider for an exact task produces flaky, unreproducible behavior — the same input yields different answers across runs, tests can't be trusted, debugging becomes prompt archaeology, and every fix adds complexity until the system is a disaster. This doctrine prevents that class of failure by construction.

**Deterministic tasks — code only, never a model call:**
- Identity verification (credential valid? revoked? in scope?)
- Policy matching (does this subject/action/resource/condition match a rule?)
- Threshold and plausibility checks (setpoint in range? temp swing plausible? rate under cap?)
- Revocation, quarantine, audit logging
- Any yes/no that the demo or a test must reproduce exactly
- Property: same input → same output, every run, testable with unit tests, zero model calls in the path.

**Non-deterministic tasks — models allowed, output always validated:**
- Digest: summarizing configs into a graph (Spark) — output schema-validated, committed, human-reviewed.
- Analyst: brainstorming attack paths (Wonder) — an advisory ranking; it never blocks anything by itself.
- Policy compiler: drafting machine rules from plain English (Spark) — uncompilable drafts flagged, never silently dropped; compiled policy committed and reviewed.
- Explainer: plain-language explanation of a decision already made by code — display-only; if it fails or rambles, the decision stands.
- Perception/generation: SAM segmentation, Muse Image frames — build-time data inputs, validated against the registry, never decisions.

**The determinism boundary is the commit boundary.** All nondeterminism lives at build/setup time and ends in a committed, reviewed artifact (`graph.json`, `threats.json`, `policy.json`). The runtime path — sim → gateway → `decide()` → audit — contains zero model calls. That is what makes the demo reproducible and the system testable.

**Guardrails:**
1. Every model output that crosses toward enforcement passes a deterministic validator (JSON schema, rule compiler, allowlist). Invalid output is rejected, never retried until it "looks right."
2. If validation fails, the system fails closed (deny/flag) — it never falls back to asking the model to decide.
3. Low temperature + structured output reduce variance in drafting models, but they are NOT the guarantee — validation is. Never rely on temperature for correctness.
4. Tests assert determinism: same action + same policy → same decision, across repeated runs.
5. The explainer is the only model allowed near runtime, and it is strictly display-only: it can never change, override, or feed back into a decision.

## Architecture overview

```
Simulated world (2 sites, localhost)
  Site A — Plant line: PLC + MQTT sensors + camera + edge gateway
  Site B — Remote intermodal trucking station: reefers, gate, yard equipment
        │  MQTT (Mosquitto) + Modbus/TCP (pymodbus) + camera frames
        ▼
1. Digest / Scout ──► environment graph (JSON: nodes, flows, identities, trust boundaries)
2. Attack surface / Analyst ──► ranked threat map (paths, severity, weakest links)
3. Policy compiler ──► enforceable rules (JSON) from plain-language business rules
4. Enforcement loop ──► allow / deny / quarantine on EVERY agent action + audit trail
5. Demo console ──► live graph, threat map, policy list, event feed
```

Golden rule: **no agent action reaches a device without passing through layer 4.** The gateway is the choke point. Anything that talks to the PLC directly, bypassing the gateway, is itself flagged as an anomaly.

## The simulated world (layer 0)

Everything runs on one laptop so the demo is reproducible for judges. No real hardware, no cloud devices.

### Site A — Plant line

| Component | Implementation | Details |
|---|---|---|
| PLC | pymodbus Modbus/TCP server (localhost) | Holding registers: run/stop (coil), speed setpoint. Controls one actuator (motor/valve). |
| Sensors | paho-mqtt publishers → local Mosquitto broker | Topics: `site/line1/sensors/temperature`, `.../vibration`, `.../pressure`. Publish every 2s with realistic drift + noise. |
| Camera | Static/synthetic frames (Muse Image) | 2–3 frames of the line. SAM 3.1 segments equipment in frame; results feed the digest. |
| Edge gateway | Python service | Subscribes to sensor topics, hosts the policy engine + enforcement loop, bridges telemetry upstream. This is the firewall's home. |

### Site B — Remote intermodal trucking station (rail + truck terminal)

Remote publishers over a **simulated constrained link** (add jitter + occasional drops to the publisher) → same Mosquitto broker, same gateway enforcement.

| Telemetry | Topic pattern | Notes |
|---|---|---|
| Reefer container temperature (per container) | `site/yard/reefer/<container_id>/temperature` | Safety-critical. Spoofable. |
| Gate events | `site/yard/gate/event` | Truck in/out, container ID scans. |
| Yard equipment | `site/yard/equipment/<id>/status` | Hostler position + status, crane/reach-stacker load state. |
| Container moves | `site/yard/container/move` | Pick/drop events, chassis assignments. |

**Commandable element at the yard: gate release** (`site/yard/gate/release`) — releasing a container to a truck. This is the yard's equivalent of the PLC actuator: the remote prize for an attacker.

### Agents (the actors)

- **Operator agent (legitimate).** Reads sensors and telemetry, may command the PLC within policy (e.g., adjust setpoint within safe range) and may request gate releases with matching container + truck + booking.
- **Rogue agent (compromised).** Same tools, no legitimate business. Its scripted attacks (see Demo script) are the demo's villains.

### Identities (the PKI thread — your signature detail)

Every agent and device gets an identity credential (a simple cert-like JSON token: id, role, issuer, expiry, scope). The enforcement loop checks identity on every action, and **revocation** is a first-class action: a quarantined agent's credential is revoked and every later request from it is denied by default. This is what makes it an *agent* firewall rather than a packet filter.

## Layers 1–5 (what each one does, which model, acceptance criteria)

### Layer 1 — Digest / Scout → environment graph

- **Model:** `muse-spark-1.3` (structured output) + `sam-3.1` (camera frames).
- **Inputs:** device registry (hand-written config listing every device, protocol, topic, identity), PLC register map, camera frames.
- **Output:** `graph.json` — nodes (devices, agents, gateway, topics), edges (data flows, who talks to whom), identities, trust boundaries (site A LAN, yard link, gateway, cloud).
- **Anti-pattern (from prior experience — do not repeat):** never ask a model to *originate* the inventory from unstructured input, e.g., extracting exact components and connections from legacy diagrams. That approach failed after days of correction: with no ground-truth anchor, the model invents components, drops others, and miswires connections, and each correction round just moves errors around. The registry is the source of truth; the model only enriches and formats it. Any component the model introduces that is not in the registry is rejected by validation. Same rule for SAM output: a segmented object joins the graph only if it matches a known registry device.
- **Acceptance:** `graph.json` contains every device in the registry plus the camera-segmented objects; re-running digest after adding a device updates the graph. SAM output is visible in the console (boxes/masks over the frame).
- **Cost note:** run on demand and on environment change, not continuously.

### Layer 2 — Attack surface / Analyst → ranked threat map

- **Model:** `muse-wonder-1.0` (the deep reasoning brain).
- **Inputs:** `graph.json` + a short threat primer (OT basics: unauthenticated Modbus, MQTT wildcard subscriptions, flat topic ACLs, spoofed telemetry, gateway bypass).
- **Output:** `threats.json` — ranked attack paths, each with: path (e.g., rogue → MQTT `#` → PLC command topic → actuator), severity, preconditions, and the policy that would stop it.
- **Known exposures it must find (seed these in the primer so the demo is reliable):**
  1. PLC: unauthenticated register writes, no encryption.
  2. MQTT: wildcard subscribe (`#`) exposes all topics; flat ACLs let any publisher forge commands.
  3. Gateway bypass: direct-to-PLC traffic evades policy.
  4. Spoofed remote telemetry: fake reefer temps / fake gate events tricking the operator agent.
- **Acceptance:** threats.json ranks the forged-PLC-write and fake-gate-release paths at the top; re-running after a policy change re-ranks.
- **Cost note:** Wonder is the expensive model ($4/$20 per 1M tokens). Run it once per environment change. Never in the hot loop.

### Layer 3 — Policy compiler → enforceable rules

- **Model:** `muse-spark-1.3` (structured output).
- **Inputs:** business rules in plain English (see starter rules below) + `graph.json`.
- **Output:** `policy.json` — rules of the form: `{subject, action, resource, conditions, effect}`. Example: `{operator-agent, write, plc.setpoint, value within 10–90, allow}`.
- **Starter business rules (edit freely):**
  1. Only the maintenance/operator agent may write PLC registers, and setpoints must stay within the safe range.
  2. Cameras stream to the local gateway only, never to the internet.
  3. Gate release requires matching container + truck + booking.
  4. No agent may subscribe to the wildcard topic `#`.
  5. Reefer temperature changes greater than 10°C in one minute are implausible and must be flagged, not acted on.
  6. Any traffic to the PLC that bypasses the gateway is denied and flagged.
  7. Unknown or revoked identities are denied by default, with no re-evaluation.
  8. Per-agent rate cap: any agent exceeding its publish/action rate is throttled, then quarantined on repeat.
  9. Malformed or out-of-range writes are rejected by condition check, not passed to the device.
- **Acceptance:** every starter rule compiles to at least one machine rule; the compiler rejects (or flags) a rule it cannot express, rather than silently dropping it.

### Layer 4 — Enforcement loop → the dynamic firewall + prevention

- **Model:** none in the decision path — decisions are deterministic code (rule matching), not model calls. An LLM may only write the plain-language explanation of a decision for the console — display-only, per the LLM usage doctrine: it can never change, override, or feed back into a decision. Glimmer-on-the-gateway is the *story* for edge deployment; the demo runs the loop as a Python service. (If an explainer model is used at all, it is `muse-spark-1.3-contributor` — cheap; see privacy note.)
- **Behavior on EVERY agent action request:**
  1. Authenticate identity (valid, unrevoked credential?).
  2. Match against `policy.json` (subject + action + resource + conditions).
  3. Plausibility check for telemetry-driven actions (rate-of-change, cross-sensor consistency).
  4. Decision: **allow / deny / quarantine**.
  5. On deny/quarantine: revoke the credential if the violation is severe, tighten policy (e.g., disable wildcard subscriptions, narrow topic ACLs for that identity), and write the full event to the audit log.
- **Acceptance:** the three demo attacks (below) are all blocked; the audit log shows identity, action, matched rule, decision, and policy change for each; a revoked agent's subsequent requests are denied without re-evaluation.
- **Privacy note:** Contributor-tier calls may be used by Meta for training. Use Contributor ONLY for synthetic demo data. Never send real employer, customer, or personal data through it. Standard tier for anything sensitive.

### Layer 5 — Demo console (the interactive demo candidate)

- **Stack: Streamlit — decided.** Buttons, tables, and charts are built in, which is what the interactivity requirement needs; FastAPI + custom JS would cost a day for the same result.
- **Design principle:** the console is not a video backdrop — it IS the demo. Anyone opening it (judge or visitor) can explore the whole system without narration and can fire attacks themselves.
- **Tabs:**
  - **Overview (metrics):** counters (actions evaluated, allowed, denied, quarantined, active agents/devices/policies); actions/min and deny rate; event time-series (stacked allowed/denied/quarantined); denials by rule, by agent, and by resource; decision latency; system health (broker, PLC, gateway, yard-link status + latency/drops).
  - **Environment:** graph (nodes, edges, zones) + device registry table — click any device for its protocols, topics, identity, and policy coverage.
  - **Policies:** business rules in plain English next to the machine rules they compiled into, with per-rule hit counts and lineage (which business rule produced which machine rules).
  - **Agents & identities:** every agent/device credential — id, role, scope, status (active/quarantined/revoked) — with a revoke button and per-agent action history.
  - **Red team (the interactive heart):** buttons that fire the scripted attacks on demand — wildcard recon, forged PLC write, spoofed reefer temp, fake gate release, unknown-device connect, publish flood, out-of-range setpoint — plus pause/resume for the sim event flow and a reset-demo button. Every fired attack lands in the live feed and audit log in real time.
  - **Threats:** ranked threat map with the stopping policy shown per threat.
  - **Audit log:** full decision trail (identity, action, matched rule, decision, policy change), filterable by agent/resource/decision, exportable as JSON/CSV.
- **Live feed:** color-coded green/amber/red, auto-refreshing, visible from Overview and the Audit tab.
- **Robustness rule:** the console and enforcement run entirely from cached artifacts (`graph.json`, `threats.json`, `policy.json` committed in the repo). The live loop never calls a cloud model — so the interactive demo works fully offline, with no API key, no credits, no network. API calls are needed only to *regenerate* the cached artifacts (digest/analyst/policy steps), never to *run* the demo.
- **Acceptance:** a first-time visitor can, within 2 minutes and without help: find total blocks, find any device's config, find the rule that blocked a given attack, and fire an attack themselves and watch it get blocked.

## Repo layout

```
sentinel/
├── README.md                  # pitch, architecture, how to run the demo
├── requirements.txt           # paho-mqtt, pymodbus, streamlit (or fastapi), openai
├── .env.example               # META_API_KEY=... (never commit a real key)
├── sim/
│   ├── broker.sh              # start local Mosquitto (docker run eclipse-mosquitto)
│   ├── plc.py                 # pymodbus server: run/stop + setpoint registers
│   ├── sensors.py             # Site A MQTT publishers (temp/vibration/pressure)
│   ├── yard.py                # Site B publishers (reefer/gate/equipment/moves) + link jitter
│   ├── camera_frames/         # synthetic frames (Muse Image) for SAM
│   └── agents.py              # operator agent + rogue agent (scripted)
├── sentinel/
│   ├── digest.py              # Layer 1: Spark + SAM → graph.json
│   ├── analyst.py             # Layer 2: Wonder → threats.json
│   ├── policy.py              # Layer 3: Spark → policy.json
│   ├── enforce.py             # Layer 4: policy engine + revocation + audit log
│   ├── identity.py            # credential issue / verify / revoke
│   └── models.py              # Meta Model API client (OpenAI SDK, base_url api.meta.ai/v1)
├── console/
│   └── app.py                 # Layer 5: Streamlit dashboard
├── data/
│   ├── registry.yaml          # device registry (the digest's source of truth)
│   ├── business_rules.txt     # plain-language rules (the compiler's input)
│   ├── graph.json             # generated
│   ├── threats.json           # generated
│   └── policy.json            # generated
└── demo/
    └── script.md              # the 3-minute demo narration (see below)
```

## Model + API reference (confirmed Oct 25, re-verify at kickoff)

| Model | ID | Use | Price (standard) |
|---|---|---|---|
| Muse Spark 1.3 | `muse-spark-1.3` | Digest, policy compiler | $1.25 in / $4.25 out per 1M tokens |
| Muse Spark 1.3 Contributor | `muse-spark-1.3-contributor` | Hot enforcement loop (demo data only) | ~$0.10 / $0.20 per 1M |
| Muse Wonder | `muse-wonder-1.0` | Attack-surface analysis | $4 in / $20 out per 1M |
| Muse Image | `muse-image-1.0` | Synthetic camera frames | $0.01 / image |
| SAM 3.1 | `sam-3.1` | Segment camera frames | $2.50 / 1,000 images |

- **Credits (verify in your selection email/portal):** ~$150 Meta Model API credits reported for selected participants; partner credits Baseten $100, Modal $100, Fireworks $25 for open-weights models.
- **Rate limits (Standard, per team):** Spark 3,000 req/min, 4M tokens/min — not a constraint for a solo demo.
- **Budget rule:** Wonder only on environment change. Spark for everything else. $150 lasts the 10 days easily at that mix.

## Muse Code prompts (copy-paste ready, one per layer)

Feed these to Muse Code in order. After each one, run the acceptance check before moving on. Do not let it redesign the architecture — the prompts fix the interfaces.

### Prompt 0 — Scaffold
> Scaffold a Python project per the repo layout in this spec. requirements.txt with paho-mqtt, pymodbus, streamlit, openai, python-dotenv. models.py: a Meta Model API client using the OpenAI SDK with base_url https://api.meta.ai/v1 and api_key from env META_API_KEY, with functions chat(model, messages, json_mode) and a retry on 429. identity.py: issue/verify/revoke credential tokens as JSON (id, role, issuer, expiry, scope) stored in memory. Everything else is a stub with a TODO. Verify: `python -c "import sentinel.models"` imports cleanly.

### Prompt 1 — Sim world
> Build sim/ per the spec: broker.sh starts eclipse-mosquitto via docker; plc.py is a pymodbus Modbus/TCP server on localhost:5020 with holding registers for run/stop and speed setpoint, logging every write; sensors.py publishes temperature/vibration/pressure to site/line1/sensors/* every 2s with drift and noise; yard.py publishes reefer temps, gate events, equipment status, and container moves to site/yard/* with configurable jitter and drop rate to simulate a constrained link; agents.py has OperatorAgent (reads topics, issues in-policy PLC writes and gate releases) and RogueAgent (scripted attack sequence, off by default). Verify: start broker + plc + sensors + yard, subscribe to site/#, and see all topics flowing.

### Prompt 2 — Digest
> Build sentinel/digest.py: read data/registry.yaml and the PLC register map, call muse-spark-1.3 with structured output to produce data/graph.json (nodes, edges, identities, trust boundaries). Include SAM 3.1 segmentation of sim/camera_frames/*, attaching detected objects to the matching camera node. Verify: graph.json contains every registry device plus camera objects; adding a device to the registry and re-running updates the graph.

### Prompt 3 — Analyst
> Build sentinel/analyst.py: read data/graph.json, call muse-wonder-1.0 with the OT threat primer from the spec, and write data/threats.json as ranked attack paths (path, severity, preconditions, stopping policy). The four seeded exposures in the spec must appear. Verify: threats.json ranks forged-PLC-write and fake-gate-release at the top.

### Prompt 4 — Policy compiler
> Build sentinel/policy.py: read data/business_rules.txt and data/graph.json, call muse-spark-1.3 with structured output to produce data/policy.json as rules {subject, action, resource, conditions, effect}. Every starter rule in the spec must compile to at least one machine rule; uncompilable rules must be flagged, never silently dropped. Verify: policy.json covers all nine starter rules.

### Prompt 5 — Enforcement loop
> Build sentinel/enforce.py: a function decide(agent_credential, action, resource, context) that (1) verifies the credential via identity.py, (2) matches data/policy.json, (3) runs plausibility checks on telemetry-driven actions, (4) returns allow/deny/quarantine, and on deny/quarantine revokes severe violators, tightens policy in memory, and appends a full audit record (identity, action, matched rule, decision, policy change). No LLM sits in the decision path — decisions are deterministic rule matching in code. An LLM (muse-spark-1.3-contributor at most) may only write the plain-language explanation of a decision for the console, and must never see real data — demo data only. Verify: the three demo attacks below are all denied/quarantined, and a revoked agent's next request is denied without re-evaluation.

### Prompt 6 — Console
> Build console/app.py in Streamlit with tabs — Overview (metrics), Environment (graph + registry), Policies (business rules → machine rules with hit counts), Agents & Identities (credentials, status, revoke button, per-agent history), Red team (buttons firing each scripted attack on demand + pause/resume + reset), Threats (ranked map + stopping policy), Audit log (filterable, exportable). It reads data/graph.json, threats.json, policy.json and tails the audit log; the live feed auto-refreshes. The console must run fully offline from the cached JSON artifacts — no model calls in the console or enforcement path. Verify: a first-time visitor can find total blocks, a device's config, the rule behind a block, and fire an attack and watch it blocked, all within 2 minutes.

## Demo script (about 3½ minutes, the story judges remember)

Beat 0 — Calm (30s). Console shows the two sites healthy: line sensors flowing, yard reefers steady, gate events normal, operator agent issuing an in-policy setpoint change (allowed, green).

Beat 1 — Recon (30s). Rogue agent subscribes to `#`. Console shows it seeing every topic. The digest already flagged this path; policy tightening begins: wildcard subscriptions get disabled for non-gateway identities.

Beat 2 — Forged PLC write (45s). Rogue publishes a forged command toward the PLC setpoint register. Enforcement: identity lacks PLC-write scope → denied, credential revoked, quarantine. Console shows red + audit entry + policy update.

Beat 3 — Spoofed reefer telemetry (45s). Rogue injects a fake reefer temperature (a 20°C drop in one minute) designed to make the operator agent ignore a real warming trend. Enforcement: plausibility check fails → flagged, not acted on, rogue's yard-publish scope revoked.

Beat 4 — Fake gate release (30s). Rogue requests release of a container to a truck with no matching booking. Enforcement: container + truck + booking mismatch → denied and quarantined.

Beat 5 — Aligned checks, rapid-fire (20s). Three quick blocks in succession, no narration needed: an unknown device tries to connect (denied, default-deny), the rogue floods publishes (throttled, then quarantined), an out-of-range setpoint write is rejected by condition check. These are the traditional-flavored checks, shown as free byproducts of the same enforcement path.

Close (15s). Console shows the final state: three attacks, three blocks, audit trail complete, policy strictly tighter than at start — the firewall learned. Tagline: "Packets get filtered. Agents get governed."

### Self-guided mode (for judges and visitors)

The video follows the script above, but the console is built for self-guided exploration. The submission README must include "Try it yourself" instructions: start broker.sh + plc.py + sensors + yard, open the console, fire any attack from the Red team tab, and explore metrics, policies, identities, and the audit log. No API key required for this mode — it runs from cached artifacts.

## 10-day plan (Oct 26 – Nov 4)

| Day | Date | Milestone | Done when… |
|---|---|---|---|
| 1 | Mon Oct 26 | Kickoff + scaffold + broker/PLC skeleton | Prompt 0 + 1 stubs run; broker + PLC up |
| 2 | Tue Oct 27 | Sim world complete | All topics flowing; both agents run (rogue off) |
| 3 | Wed Oct 28 | Digest (Layer 1) | graph.json complete + SAM objects attached |
| 4 | Thu Oct 29 | Analyst (Layer 2) | threats.json with seeded exposures ranked |
| 5 | Fri Oct 30 | Policy compiler (Layer 3) | policy.json covers all starter rules |
| 6 | Sat Oct 31 | Enforcement loop (Layer 4) | decide() blocks scripted attacks in tests |
| 7 | Sun Nov 1 | Rogue scenarios end-to-end | All three demo attacks blocked via gateway |
| 8 | Mon Nov 2 | Console (Layer 5) | Full story visible live on the dashboard |
| 9 | Tue Nov 3 | Demo video + README + submission draft | 3-min video recorded; README complete |
| 10 | Wed Nov 4 | Buffer + final test + submit by 9 PM ET | Clean end-to-end run; submission filed |

Note: Nov 1 is the DST changeover (clocks go back). The Nov 4, 9 PM ET deadline is unaffected, but don't let a clock shift confuse a cron or a calendar reminder that week.

## Submission checklist

- [ ] Repo public (or link as required) with README: pitch, architecture, how to run the demo.
- [ ] 3-minute demo video following the script above (screen capture of the console + narration).
- [ ] Submission form: theme = Push the Frontier; track = Indie; models used = Spark 1.3, Wonder, SAM 3.1, Muse Image (+ Contributor/Glimmer note for the edge story).
- [ ] README architecture diagram shows the adjacent network-firewall layer below Sentinel, with the positioning line: "Traditional firewalls inspect packets; Sentinel inspects intent."
- [ ] Judging coverage: creativity (agent-aware firewall — no packet filter does this), technical ambition (framework + working agent + two-site sim + five layers), works (live blocked attacks on video + reproducible localhost run).
- [ ] No real credentials, no real employer data, no personal data anywhere in the repo or video. Synthetic demo data only.

## Risks + fallbacks (decide fast, don't stall)

- **Nondeterminism leakage (a model output deciding an exact outcome)** → prevented by the LLM usage doctrine: the runtime path has zero model calls; every model output is schema-validated and committed before it can affect enforcement. If you catch yourself adding a model call to `decide()`, stop — that is the rabbit hole.

- **Wonder slow/expensive or rate-limited** → cache threats.json; re-run only on environment change. Demo never waits on Wonder live.
- **Mosquitto/Docker unavailable on the demo machine** → in-process broker shim with the same topic API (publish/subscribe/wildcard). Keep the topic strings identical so the swap is invisible.
- **SAM 3.1 unavailable** → cut camera segmentation; digest from registry + configs only. The demo still works.
- **Running short on time** → cut yard equipment commands; keep yard telemetry + gate release only. Never cut the enforcement loop or the console — those are the demo.
- **Muse Code goes sideways on a layer** → fall back to the acceptance criteria in that layer's prompt; a small hand-written module that passes its check beats a large generated one that doesn't.

## Open questions (answer during Day 1–2, not before)

1. ~~Streamlit vs FastAPI + HTML for the console~~ — RESOLVED Oct 26: Streamlit, decided by the interactivity requirement (buttons, tables, charts built in).
2. Yard equipment commands (crane/hostler moves) in scope, or gate release only? Default: gate release only; add crane/hostler only if Day 7 finishes early.
3. Glimmer-on-gateway: narrative only, or a real small-model enforcement path via partner credits? Default: narrative; revisit if Baseten/Modal credits land and time remains.

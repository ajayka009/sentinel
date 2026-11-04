# Sentinel — Phase 2 Build Spec

**Meta Global AI Developer Hackathon — Indie Track (solo)**
**Companion to:** `sentinel-build-spec.md` (Phase 1). This spec does not
repeat Phase 1 — it builds on it. Where the two disagree, this spec wins
for Phase 2 work, and the Phase 1 spec wins for everything already built.

## Key facts

- Phase 1 build status (Oct 29 evening): complete through Day 8 console
  (repo commit `496041df`, 8 commits) — sim world, digest, analyst,
  policy compiler, enforcement loop, demo console. Remaining Phase 1
  work: 3-minute video + README + submission draft, due **Tue Nov 4,
  9:00 PM ET**. Finals/winners Nov 9.
- Phase 2 is everything after Phase 1, with ONE exception (see below):
  P2-12 is built BEFORE the video, so the video shows the enhanced
  product. Everything else in Phase 2 waits until Phase 1 is
  submittable, and items after P2-4 are post-submission / finals polish.
- Item numbers (P2-1…P2-12) are stable. Build order differs from
  numeric order and is given explicitly below — do not renumber.
- Stack: same as Phase 1 (Python, Streamlit console, Mosquitto/MQTT,
  Modbus/TCP), plus local Glimmer inference for P2-12/P2-6 only. No new
  cloud dependencies. No paid tiers.

## The pitch update (one paragraph, use in README + finals material)

Phase 1 proved a firewall can govern agents: scripted agents attack,
deterministic code blocks them. Phase 2 proves it governs REAL agents:
the operator is no longer a script but a local AI model (Muse Glimmer,
30B, running on the edge node itself) making its own operational
decisions — and Sentinel still judges every one. Around that core, Phase
2 hardens the product story: one-command demo packaging, a registry
that scales by profile instead of hand-writing, documented standards
mapping, an insider-threat mode, multi-step attack chains, a real
display-only explainer on the gateway, persistent identity, a second
transport family under the same policy, console replay, CI with
measured latency, and finally a real-device bridge. Nothing in Phase 2
changes what Sentinel IS — it widens what it can prove.

## Guardrails (non-negotiable, carried from Phase 1)

1. **Doctrine unchanged: models advise, code decides.** The runtime
   enforcement path (sim → gateway → `decide()` → audit) contains zero
   model calls, before, during, and after Phase 2. P2-12 and P2-6 put
   models on the governed side (P2-12) and the display-only side
   (P2-6) respectively — never inside `decide()`. If a Phase 2 prompt
   asks a model to decide an enforcement outcome, stop — that is the
   rabbit hole Phase 1's doctrine exists to prevent.
2. **P2-12 exception (Oct 29 evening, Kumar's call):** P2-12 is built
   pre-video so the video shows the enhanced product. This is the ONLY
   Phase 2 item that moves ahead of the video. The rest of Phase 2
   still waits until Phase 1 is submittable (console works, video
   recorded, README complete).
3. **Day 10 stays buffer + submit.** Never trade submission
   completeness for a Phase 2 item. If Phase 1 slips, drop Phase 2
   items bottom-up (reverse build order). Scripted agents always
   remain the fallback demo — no Phase 2 item may become load-bearing
   for the submission.
4. **No network-layer packet filtering** — still out of scope by
   design, in Phase 2 as in Phase 1. No architecture rewrite, no
   second console stack, no paid tiers, no Wonder Full.
5. **No weights in the repo, ever.** Glimmer weights (~17–20GB
   quantized) live in a gitignored models/ dir. A commit containing
   weights is a revert-on-sight event.
6. **No real data, ever.** Synthetic demo data only, in repo, video,
   and finals material — same rule as Phase 1.

## Architecture deltas (what changes, by item)

```
Phase 1 (unchanged core)
  sim/ (broker, plc, sensors, yard, agents.py, rogue.py)
  sentinel/ (digest, analyst, policy, enforce, identity, models)
  console/app.py — Streamlit, 7 tabs, offline from cached JSON
  data/ (registry.yaml, business_rules.txt, graph/threats/policy.json)
        │
        ▼  Phase 2 additions (each behind its own flag/file, core untouched)
  P2-12 sim/glimmer_operator.py ──► local Glimmer loop (governed side)
  P2-6  gateway explainer ────────► local Glimmer, display-only (governor side)
  P2-1  docker-compose.yml ───────► one-command whole demo
  P2-2  registry profiles ────────► device templates + per-metric metadata
  P2-3  docs/standards-mapping.md ► IEC 62443 / Sparkplug B / WoT mapping
  P2-4  agents.py --go-rogue ─────► insider mode + escalation ladder
  P2-5  rogue.py chains ──────────► multi-step attack sequences
  P2-7  identity store (SQLite) ──► persistent creds + reloadable revocation
  P2-8  sim/opcua.py (or coap) ──► second transport, same policy.json
  P2-9  console replay + risk ────► replay from audit entry, risk scores
  P2-10 .github/workflows/ci.yml ─► contract + determinism tests, load test
  P2-11 docs/real-device-bridge.md► port path to one real device
```

Repo layout additions (everything else stays as Phase 1):

```
sim/glimmer_operator.py   # P2-12: Glimmer-driven operator (own process)
models/                   # P2-12/P2-6: Glimmer weights — GITIGNORED, never committed
console/                  # P2-9: replay mode + risk scores added to app.py (no second stack)
docs/standards-mapping.md # P2-3
docs/real-device-bridge.md# P2-11
docker-compose.yml        # P2-1
.github/workflows/ci.yml  # P2-10
```

## Build order + plan

| Build step | Item | Window | Done when… |
|---|---|---|---|
| 0 | P2-12 Glimmer agents | Oct 30 – Nov 2 (pre-video) | Prompt P2-12 acceptance passes; video can show it |
| 1 | Video + README + submission draft (Phase 1 Day 9) | Nov 3 | 3-min video recorded incl. Glimmer beat; README complete |
| 2 | Submit (Phase 1 Day 10) | Nov 4 by 9 PM ET | Submission filed; buffer intact |
| 3 | P2-1 packaging | Slack / post-submission | `docker compose up` → full demo, no terminal juggling |
| 4 | P2-2 registry upgrade | Slack / post-submission | New sensor via profile only; plausibility from metadata |
| 5 | P2-4 insider scenario | Slack / post-submission | Green-then-red identity; scope narrows, then revocation |
| 6 | P2-3, P2-5, P2-6, P2-7, P2-8, P2-9, P2-10 | Post-submission / finals polish | Each item's acceptance below |
| 7 | P2-11 real-device bridge | Only if everything above is done | One real device enforced by same gateway + policy |

Slack-day rule (from the backlog, unchanged): if only one slack day
exists, do P2-1 + P2-2 and stop. If two days, add P2-12 next, then
P2-4. (P2-12's pre-video build does not consume slack days — it uses
the banked buffer from finishing Days 1–8 early.)

## Build prompts (copy-paste ready, one per item)

Feed these to Muse Code in build order. After each one, run the
acceptance check before moving on. Do not let it redesign the
architecture — the prompts fix the interfaces, same as Phase 1.

### Prompt P2-12 — Local-LLM governed agents (pre-video, FIRST)

> Build `sim/glimmer_operator.py`: a Glimmer-driven operator agent
> that runs entirely on the edge node/laptop — no API calls, no
> network.
>
> Step 0 — hardware gate (do this FIRST, before downloading
> anything): check GPU VRAM / unified memory on this machine. The
> 4-bit quantized Glimmer weights need ~24GB headroom. If the
> machine cannot hold them, STOP, do not download weights, and
> report exactly what the machine has and that local Glimmer is not
> viable here.
>
> Step 1 — model: download the 4-bit quantized Muse Glimmer 30B
> weights (meta-ai/Muse-Glimmer-30B, Apache 2.0) OUTSIDE the repo
> (a gitignored models/ dir — never commit weights). Load via a
> local runtime available on this machine (llama.cpp, vLLM, or
> transformers — pick what runs here).
>
> Step 2 — agent loop, in its own process with its own MQTT client
> ID and its own credential issued via identity.py (same as
> agents.py gets): repeat — (a) perceive: read latest
> sensor/telemetry state from subscribed topics; (b) decide: ask
> the local model what single operational action to take next
> (setpoint adjustment within its known envelope, gate release
> request, or no-op), given the current state; (c) act: attempt
> that action through the normal path (MQTT publish / Modbus
> write) — NEVER bypass the gateway; (d) observe: log the
> gateway's verdict. One cycle every ~10s so the demo stays
> watchable.
>
> Step 3 — boundaries (non-negotiable): do NOT modify
> sentinel/enforce.py, sentinel/identity.py, or data/policy.json.
> The model decides what the agent ATTEMPTS; the existing
> code-only decide() decides what is ALLOWED. No model output
> goes into enforcement, policy, revocation, or audit.
> sim/agents.py stays untouched as the scripted fallback.
>
> Step 4 — logging: every cycle appends one JSONL line (timestamp,
> perceived state summary, model's decided action, gateway
> verdict, matched rule) to a log file the console can read, and
> prints a one-line human-readable summary.
>
> Acceptance: (1) hardware gate passes or cleanly reports; (2) the
> agent runs 10+ cycles fully offline (no API key, no network)
> with in-policy actions allowed by the gateway; (3) any
> out-of-policy attempt it makes is denied/quarantined by the
> UNCHANGED enforcement code — verify with git diff that
> enforce.py, identity.py, policy.json are untouched; (4)
> sim/agents.py still runs as before (fallback intact); (5)
> weights are gitignored, repo contains no weights.
>
> If the local runtime will not run after reasonable effort, stop
> and report — do not burn the video window; the scripted agents
> remain the demo.

### Prompt P2-1 — One-command demo packaging

> Write `docker-compose.yml` that brings up the whole demo with one
> command: Mosquitto broker, PLC, sensor + yard publishers, operator
> agent, rogue agent (off by default), and the Streamlit console.
> Every service uses the same topic strings, ports, and file paths
> as the manual run lines in the README, so the composed demo is
> behaviorally identical to the manual one. Glimmer weights (if
> present) are mounted from the host models/ dir, never baked into
> an image. Acceptance: fresh clone → `docker compose up` →
> console live at the documented port, Red team attacks fireable,
> no manual terminal juggling.

### Prompt P2-2 — Registry upgrade: capabilities + per-metric metadata

> Upgrade `data/registry.yaml` (and the digest's validation) so each
> device declares named capabilities — readings it publishes and
> commands it accepts — each with units, valid range, and
> rate-of-change limits, each bound to a transport (MQTT topic,
> Modbus register, OPC UA node). Add device profiles/templates for
> common types (e.g., a temperature-sensor profile instantiated by
> ID) so new devices join without hand-writing full blocks. Move
> plausibility checks in enforce.py to read range/rate from the
> registry instead of hardcoded values, with identical decisions on
> the existing data (no behavior change on current devices).
> Acceptance: add a new sensor type via a profile only, no code
> change; a plausibility check fires from registry metadata alone;
> all existing tests still pass.

### Prompt P2-4 — Insider scenario (the parked idea, returned as stretch)

> Add a second rogue mode to the operator agent: a `--go-rogue`
> switch that flips a clean-running operator to rogue behavior
> while keeping the SAME credential. Enforcement gains per-identity
> violation history and an escalation ladder: first violation
> denied + flagged, policy tightened on that identity (scope
> stripped); repeat or severe violation quarantined + revoked.
> Console gets a second Red-team button for the insider flip.
> The scripted rogue.py path is untouched. Acceptance: the same
> identity shows green-then-red in the audit trail; scope narrows
> after the first violation and revocation follows a repeat.

### Prompt P2-3 — Standards mapping, documented

> Write `docs/standards-mapping.md` and formalize the IEC 62443
> zones/conduits model in the graph output (zones, conduits, choke
> points named as such). Offer a Sparkplug B topic profile as an
> option alongside the current topics, and export device
> descriptions in a Web-of-Things Thing Description shape. Do NOT
> rewrite the registry — this is a mapping layer over the existing
> model, with an explicit section naming what deliberately does NOT
> map. Acceptance: README has a standards-mapping section naming
> what maps to what and what deliberately does not; the existing
> graph/policy behavior is unchanged.

### Prompt P2-5 — Attack chains

> Extend `sim/rogue.py` with multi-step attack sequences: recon,
> then lateral movement, then a write — plus a demonstrated
> gateway-bypass attempt (direct-to-PLC traffic flagged as an
> anomaly, per the existing rule). The enforcement loop gains
> incident grouping: linked steps under one incident ID in the
> audit log. Single-beat attacks from Phase 1 are untouched.
> Acceptance: a chained attack is stopped mid-chain and the audit
> trail shows the linked steps under one incident.

### Prompt P2-6 — Glimmer on the gateway, for real

> Run a small local model (Muse Glimmer, same weights/runtime as
> P2-12 where possible) on the gateway for the display-only
> explainer, fully offline: it renders plain-language explanations
> of decisions already made by code, in the console. It is
> strictly display-only — it can never change, override, or feed
> back into a decision, and if it fails, the decision stands and
> the console shows the raw decision. No triage ranking by the
> model; ranking stays code. Acceptance: console explanations
> render with no API key and no network; killing the explainer
> process changes no decision.

### Prompt P2-7 — Identity hardening

> Replace the in-memory token dictionary in `sentinel/identity.py`
> with a persistent SQLite store; short-lived tokens with refresh;
> a revocation list the gateway reloads without restart. The
> issue/verify/revoke interface is unchanged, so enforce.py and
> the sim need no changes. Acceptance: restart the gateway and
> issued credentials survive; a revoked credential stays revoked
> across restarts; all existing tests still pass.

### Prompt P2-8 — Multi-protocol proof

> Add one more transport family behind the same policy language —
> an OPC UA server simulation, or CoAP (pick one; OPC UA first if
> both are feasible). One new sim publisher speaks the new
> transport; the gateway enforces it with the SAME
> `data/policy.json`, unchanged. Acceptance: an attack over the
> new transport is blocked by an unchanged policy file; all
> Phase 1 attacks still behave identically.

### Prompt P2-9 — Console depth

> Add to `console/app.py` (no second stack): replay mode (re-run an
> attack from an audit-log entry), per-agent risk scores, and an
> exportable incident report (JSON). Replay must reproduce the
> exact decision — this is the determinism proof, on screen.
> Acceptance: pick any audit entry, replay it, watch the same
> decision reproduce exactly; risk scores update from the audit
> trail; incident report exports as valid JSON.

### Prompt P2-10 — Hardening + CI

> Add `.github/workflows/ci.yml` running contract and determinism
> tests on every push (same action + same policy → same decision,
> across repeated runs), plus a load test (publish flood at scale)
> with latency numbers recorded in the README. Acceptance: green
> CI badge on the repo; README quotes measured decision latency
> under flood.

### Prompt P2-11 — Real-device bridge (stretch, post-submission only)

> Document (`docs/real-device-bridge.md`) and demonstrate the port
> path to ONE real device (a real Modbus device or a Raspberry Pi
> sensor) under the same policy: same gateway, same policy file,
> real traffic. This item runs ONLY if everything above is done,
> and NEVER before submission. Acceptance: one real device's
> traffic enforced by the same gateway and policy, shown on video
> or in the README.

## Video + submission notes (Phase 2's effect on the Phase 1 video)

- The 3-minute video records AFTER P2-12 (see Phase 1 spec's revised
  plan). It keeps the Phase 1 beats and ADDS one Glimmer beat: the
  local model decides an action live, the gateway allows it (green);
  if it oversteps, the gateway blocks it (red). The 3-minute cap
  still holds — absorb the beat by compressing Beat 1 (recon) and
  Beat 5 (aligned checks), never by cutting a core block.
- No second full video for later Phase 2 items. At most a short
  addendum clip if the console changes enough to deserve one (P2-9
  replay is the only candidate).
- Submission form models line grows by one entry: Muse Glimmer 30B
  (local, self-hosted, Apache 2.0) for governed agents — alongside
  Spark 1.3, Wonder, SAM 3.1, Muse Image. The edge story is now a
  working piece, not a narrative: governed agents run on-device,
  enforcement stays code.

## Risks + fallbacks (decide fast, don't stall)

- **Glimmer hardware gate fails** → P2-12 defers cleanly: scripted
  agents remain the demo, video records with the Phase 1 product,
  no schedule damage. Do NOT substitute a hosted API model into
  the governed side silently — that changes the on-device story;
  if hosted Glimmer is used at all, label it as hosted in README
  and video.
- **Glimmer runtime fights back (slow, unstable, poor decisions)** →
  stop after reasonable effort, report, keep scripted agents. A
  flaky local agent in the video is worse than no local agent.
- **P2-12 destabilizes the demo (new failure modes in console)** →
  the Glimmer agent stays behind its own run line
  (`sim/glimmer_operator.py`, own process); the video can always
  fall back to the scripted operator with zero changes to the
  console or enforcement.
- **Insider mode (P2-4) confuses the demo narrative** → keep it
  behind its own Red-team button and flag; the default demo path
  stays stranger-rogue only.
- **Scope creep past submission** → the build-order table is the
  contract. Anything not in it waits for finals polish or never.
  P2-11 never runs before submission, no exceptions.

## Open questions

1. Hardware answer from the P2-12 gate (GPU VRAM / unified memory on
   the sim machine) — decides whether P2-12 is local, hosted, or
   deferred. Answered by running Prompt P2-12 Step 0, not by debate.
2. P2-8 transport pick: OPC UA vs CoAP — OPC UA first if both are
   feasible (stronger OT credibility); CoAP if time is short.
3. Finals presentation (Nov 9): if selected, which Phase 2 items get
   live-demo time vs README-only? Decide after submission, not now.
4. SAM camera thread (empty segmentation from Day 3): frames +
   digest re-run remain an optional console-strength item, owned by
   Phase 1's fallback, not by Phase 2.

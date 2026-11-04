# Demo script (3 minutes)

The console IS the demo: every beat below is a click in the Red team tab
plus narration. Video follows this script; visitors can self-guide with the
"Try it yourself" steps at the end.

Beats sum to 180s with Beat 6, 150s without (Beat 6 is conditional).

## Staging (before recording)

1. One terminal each (or at minimum the console — Red team scenarios run
   fully offline through the in-process gateway):
   ```bash
   ./sim/broker.sh
   python3 sim/plc.py
   python3 sim/sensors.py
   python3 sim/yard.py --jitter 1 --drop 0.1
   python3 sim/agents.py            # operator (plant LAN terminal)
   python3 sim/rogue.py             # rogue (separate, "untrusted zone" terminal)
   streamlit run console/app.py     # http://localhost:8501
   ```
2. Console: sidebar → **Reset demo** for a clean audit trail.
3. Recording: capture the browser window at 1080p; narrate from the
   SAY lines. Total target: 180 seconds max.

## Beat 0 — Calm (15s): the baseline

Screen: Overview tab. Counters at zero, system health green (or PLC/broker
"down" if the sim isn't running — say so once and move on).

> SAY: "This is Sentinel, an agent-aware firewall for edge and physical AI.
> Two sites — plant line and truck yard — one gateway."

Click: Red team tab → **Operator setpoint 1200 (calm)**.

> SAY: "In-policy setpoint: allowed, green, audited. Baseline set —
> now the rogue attacks."

## Beat 1 — Recon (15s): wildcard subscribe

Click: **Wildcard recon (# subscribe)**.

Screen: live feed shows QUARANTINE + FLAG; Agents tab shows the rogue
credential revoked.

> SAY: "The rogue subscribes to hash, the MQTT wildcard. Sentinel
> quarantines it under pol-br4 and revokes the credential. Recon over."

## Beat 2 — Forged PLC write (35s): the flagship block

Click: **Forged PLC write (3000 RPM)**.

Screen: red DENY row; Policies tab → `pol-br9-deny-above-range`.

> SAY: "The rogue forges a PLC write — 3000 RPM, double the safe ceiling.
> Packets perfect, intent malicious: a packet filter waves it through.
> Sentinel denies it — no PLC-write scope, out of range — and the audit
> log records identity, action, rule, and decision."

## Beat 3 — Spoofed reefer telemetry (35s)

Click: **Spoofed reefer temp (+25C jump)**.

Screen: feed shows the baseline allow then the spoof DENY + FLAG.

> SAY: "A fake reefer reading, up 25 degrees in one jump, to mask a real
> warming trend. The plausibility check fails — flagged, never acted on,
> publishing scope revoked."

## Beat 4 — Fake gate release (20s)

Click: **Fake gate release (no booking)**.

> SAY: "A container release with no matching booking. Container, truck,
> and booking must all match — they don't. Denied and quarantined."

## Beat 5 — Aligned checks, rapid-fire (15s, no narration pauses)

Click in quick succession: **Unknown-device connect** → **Publish flood
(35 rapid)** → **Out-of-range setpoint**.

> SAY: "Three byproducts of the same path: unknown device denied by
> default, publish flood throttled then quarantined, out-of-range
> write rejected."

(Backup: the **Fire full demo script** button runs every scenario at once
if a live click misfires.)

## Beat 6 — Glimmer operator (30s) — CONDITIONAL

CONDITIONAL: record this beat ONLY if the Glimmer 12-cycle acceptance run
(`python3 sim/glimmer_operator.py --backend ollama --cycles 12`) has
passed on the edge node. Without this beat the script is 150s.

Screen: terminal running the Glimmer operator beside the console live feed.

> SAY: "The operator is now a local Glimmer model deciding one action
> per cycle. It attempts; the unchanged gateway judges. In-policy:
> allowed green. Overstep: blocked red. Models propose, code disposes."

## Close (15s)

Screen: Overview tab — final counters, stacked time-series, audit trail.

> SAY: "Final state: every attack blocked, the audit trail complete, and the
> policy strictly tighter than at start — the firewall learned. Packets get
> filtered. Agents get governed."

## Try it yourself (no API key; runs from cached artifacts)

```bash
./sim/broker.sh
python3 sim/plc.py
python3 sim/sensors.py
python3 sim/yard.py --jitter 1 --drop 0.1
python3 sim/agents.py            # operator
python3 sim/rogue.py             # rogue attack script (off by default)
streamlit run console/app.py     # Red team tab fires each attack on demand
```

Within 2 minutes, find: total blocks (Overview), any device's config
(Environment), the rule behind a block (Policies), and fire an attack
yourself (Red team) to watch it blocked.

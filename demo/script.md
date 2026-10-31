# Demo script (about 3½ minutes)

The console IS the demo: every beat below is a click in the Red team tab
plus narration. Video follows this script; visitors can self-guide with the
"Try it yourself" steps at the end.

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
   SAY lines. Total target: under 3:30.

## Beat 0 — Calm (30s): the baseline

Screen: Overview tab. Counters at zero, system health green (or PLC/broker
"down" if the sim isn't running — say so once and move on).

> SAY: "This is Sentinel, an agent-aware firewall for edge and physical AI.
> Two sites — a plant line and a remote truck yard — guarded by one gateway.
> The operator agent is doing legitimate work."

Click: Red team tab → **Operator setpoint 1200 (calm)**.

> SAY: "An in-policy setpoint write: allowed, green, audited. That's our
> baseline. Now the rogue agent attacks."

## Beat 1 — Recon (30s): wildcard subscribe

Click: **Wildcard recon (# subscribe)**.

Screen: live feed shows QUARANTINE + FLAG; Agents tab shows the rogue
credential revoked.

> SAY: "The rogue subscribes to hash — the MQTT wildcard — to see every
> topic. Sentinel quarantines it on the spot under pol-br4, and revokes the
> credential. Recon over."

## Beat 2 — Forged PLC write (45s): the flagship block

Click: **Forged PLC write (3000 RPM)**.

Screen: red DENY row; Policies tab → `pol-br9-deny-above-range`.

> SAY: "Now the rogue forges a PLC setpoint write — 3000 RPM, double the
> safe ceiling. Its packets are perfect; its intent is malicious. A packet
> filter waves this through. Sentinel denies it — the rogue has no PLC-write
> scope and the value is out of range — and the audit log records identity,
> action, matched rule, and decision."

## Beat 3 — Spoofed reefer telemetry (45s)

Click: **Spoofed reefer temp (+25C jump)**.

Screen: feed shows the baseline allow then the spoof DENY + FLAG.

> SAY: "Next: a fake reefer temperature, a 25-degree jump in one reading,
> designed to trick the operator into ignoring a real warming trend. The
> plausibility check fails — flagged, never acted on, publishing scope
> revoked."

## Beat 4 — Fake gate release (30s)

Click: **Fake gate release (no booking)**.

> SAY: "The rogue requests a container release with no matching booking.
> Container plus truck plus booking must all match — they don't. Denied and
> quarantined."

## Beat 5 — Aligned checks, rapid-fire (20s, no narration pauses)

Click in quick succession: **Unknown-device connect** → **Publish flood
(35 rapid)** → **Out-of-range setpoint**.

> SAY: "And three free byproducts of the same enforcement path: an unknown
> device denied by default, a publish flood throttled then quarantined, an
> out-of-range write rejected by condition check."

(Backup: the **Fire full demo script** button runs every scenario at once
if a live click misfires.)

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

# Demo script (about 3.5 minutes)

Condensed from sentinel-build-spec.md; the console IS the demo.

- **Beat 0 — Calm (30s).** Two sites healthy: line sensors flowing, yard
  reefers steady, operator agent's in-policy setpoint change allowed (green).
- **Beat 1 — Recon (30s).** Rogue subscribes to `#`, sees every topic.
  Policy tightening begins: wildcard disabled for non-gateway identities.
- **Beat 2 — Forged PLC write (45s).** Rogue forges a PLC setpoint write.
  Denied: no PLC-write scope; credential revoked, quarantined.
- **Beat 3 — Spoofed reefer telemetry (45s).** Rogue injects a fake reefer
  temperature (20C drop in one minute). Flagged by plausibility check, not
  acted on; rogue's yard-publish scope revoked.
- **Beat 4 — Fake gate release (30s).** Rogue requests a container release
  with no matching booking. Denied and quarantined.
- **Beat 5 — Aligned checks, rapid-fire (20s).** Unknown device connect
  denied; publish flood throttled then quarantined; out-of-range setpoint
  rejected by condition check.
- **Close (15s).** Three attacks, three blocks, audit trail complete, policy
  tighter than at start. Tagline: "Packets get filtered. Agents get governed."

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

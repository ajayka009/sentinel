# sim/ — plant + yard simulator

| File        | What it does                                                                 |
|-------------|------------------------------------------------------------------------------|
| `broker.sh` | Starts `eclipse-mosquitto` via docker on `localhost:1883`.                   |
| `plc.py`    | Modbus/TCP server on `localhost:5020`. HR0 = run/stop, HR1 = speed setpoint. Logs every write. |
| `sensors.py`| Publishes temp/vibration/pressure to `site/line1/sensors/*` every 2s (drift + noise). |
| `yard.py`   | Publishes reefers/gate/equipment/moves to `site/yard/*`. `--jitter`/`--drop` simulate a constrained link. |
| `agents.py` | `OperatorAgent` (default): reads its sensor/gate topics (explicit subscribes, no wildcard), issues in-policy PLC writes + booking-matched gate releases. `--rogue` runs the scripted attack sequence (off by default). |

Run (one terminal each):

```bash
./sim/broker.sh
python3 sim/plc.py
python3 sim/sensors.py
python3 sim/yard.py --jitter 1 --drop 0.1
python3 sim/agents.py            # operator; add --rogue for the attack script
```

Subscribe to everything:

```bash
docker exec sentinel-mosquitto mosquitto_sub -t 'site/#' -v
```

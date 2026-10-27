"""Line sensors: publish temperature/vibration/pressure every 2s.

Topics:
    site/line1/sensors/temperature
    site/line1/sensors/vibration
    site/line1/sensors/pressure

Each signal has a slow random-walk drift plus per-sample Gaussian noise.
Payloads are JSON: {"value": ..., "unit": ..., "ts": ...}.
"""

import argparse
import json
import random
import time

import paho.mqtt.client as mqtt

INTERVAL_SECONDS = 2.0

SENSORS = {
    "temperature": {"topic": "site/line1/sensors/temperature", "unit": "C", "base": 72.0, "drift": 0.05, "noise": 0.4},
    "vibration": {"topic": "site/line1/sensors/vibration", "unit": "mm/s", "base": 2.5, "drift": 0.02, "noise": 0.3},
    "pressure": {"topic": "site/line1/sensors/pressure", "unit": "bar", "base": 5.0, "drift": 0.01, "noise": 0.08},
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Line sensor publisher.")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--interval", type=float, default=INTERVAL_SECONDS)
    args = parser.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(args.mqtt_host, args.mqtt_port)
    client.loop_start()
    print(f"sensors publishing to {args.mqtt_host}:{args.mqtt_port} every {args.interval}s", flush=True)

    state = {name: cfg["base"] for name, cfg in SENSORS.items()}
    try:
        while True:
            for name, cfg in SENSORS.items():
                state[name] += random.gauss(0, cfg["drift"])  # slow drift
                value = round(state[name] + random.gauss(0, cfg["noise"]), 3)
                payload = json.dumps({"value": value, "unit": cfg["unit"], "ts": time.time()})
                client.publish(cfg["topic"], payload)
                print(f"  {cfg['topic']} {payload}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()

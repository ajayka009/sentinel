"""Yard simulator: reefer temps, gate events, equipment status, container moves.

Topics (per sentinel-build-spec.md):
    site/yard/reefer/<id>/temperature
    site/yard/gate/event
    site/yard/equipment/<id>/status
    site/yard/container/move

--jitter adds a random 0..jitter second delay between publish rounds and
--drop sets the probability of dropping each message, simulating a
constrained link. Payloads are JSON with a "ts" field.
"""

import argparse
import json
import random
import time

import paho.mqtt.client as mqtt

TOPIC_REEFER_TEMPERATURE = "site/yard/reefer/{reefer_id}/temperature"
TOPIC_GATE_EVENT = "site/yard/gate/event"
TOPIC_EQUIPMENT_STATUS = "site/yard/equipment/{equipment_id}/status"
TOPIC_CONTAINER_MOVE = "site/yard/container/move"

REEFERS = ["R-101", "R-102", "R-103"]
EQUIPMENT = ["crane-1", "crane-2", "stacker-1"]
EQUIPMENT_STATES = ["idle", "working", "working", "maintenance"]
GATE_LANES = ["in-1", "in-2", "out-1"]
MOVE_POINTS = ["berth", "stack-A", "stack-B", "rail", "gate"]

# Pre-booked (container, truck) arrivals, standing in for the terminal
# operating system's booking data. Must stay in sync with BOOKINGS in
# sim/agents.py (pinned by tests/test_sim_contract.py).
BOOKED_ARRIVALS = (
    ("MSKU100001", "TRK-42"),
    ("TCLU200002", "TRK-17"),
)


def rand_container() -> str:
    return f"{random.choice(['MSKU', 'TCLU', 'OOLU', 'EITU'])}{random.randint(100000, 999999)}"


def rand_truck() -> str:
    return f"TRK-{random.randint(1, 99)}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Yard publisher (constrained link).")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--jitter", type=float, default=1.0,
                        help="max extra random delay (seconds) between rounds")
    parser.add_argument("--drop", type=float, default=0.1,
                        help="probability of dropping each message (0..1)")
    args = parser.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(args.mqtt_host, args.mqtt_port)
    client.loop_start()
    print(f"yard publishing (jitter={args.jitter}s drop={args.drop})", flush=True)

    reefer_temps = {r: round(random.uniform(-22.0, -18.0), 2) for r in REEFERS}

    def pub(topic: str, obj: dict) -> None:
        if random.random() < args.drop:
            print(f"  DROP {topic}", flush=True)
            return
        payload = json.dumps({**obj, "ts": time.time()})
        client.publish(topic, payload)
        print(f"  {topic} {payload}", flush=True)

    try:
        while True:
            for rid in REEFERS:  # reefer temps drift slowly around setpoint
                reefer_temps[rid] = round(
                    reefer_temps[rid] + random.gauss(0, 0.15), 2
                )
                pub(TOPIC_REEFER_TEMPERATURE.format(reefer_id=rid),
                    {"value": reefer_temps[rid], "unit": "C", "setpoint": -20.0})

            for eid in EQUIPMENT:  # equipment status flaps occasionally
                pub(TOPIC_EQUIPMENT_STATUS.format(equipment_id=eid),
                    {"state": random.choice(EQUIPMENT_STATES),
                     "fuel_pct": round(random.uniform(20, 100), 1)})

            if random.random() < 0.7:  # gate event most rounds
                if random.random() < 0.5:  # a booked truck shows up
                    container, truck = random.choice(BOOKED_ARRIVALS)
                else:
                    container, truck = rand_container(), rand_truck()
                pub(TOPIC_GATE_EVENT,
                    {"lane": random.choice(GATE_LANES),
                     "event": random.choice(["truck_arrival", "truck_departure"]),
                     "container": container, "truck": truck})

            src, dst = random.sample(MOVE_POINTS, 2)  # container move
            pub(TOPIC_CONTAINER_MOVE,
                {"container": rand_container(), "from": src, "to": dst,
                 "by": random.choice(EQUIPMENT)})

            time.sleep(args.interval + random.uniform(0, args.jitter))
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()

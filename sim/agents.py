"""Operator agent (legitimate). Runs in its own process.

Subscribes to its sensor/gate topics (no wildcard) and issues in-policy
PLC writes plus gate releases:
    - temp > 80C  -> lower speed setpoint 200 RPM (floor 0)
    - temp < 70C  -> raise speed setpoint 100 RPM (policy ceiling 1500)
    - vibration > 5 mm/s -> STOP the line (HR0 = 0)
    - truck_arrival gate event with matching container + truck + booking
      -> publish a release to site/yard/gate/release

Holds its own MQTT connection and its own credential issued via
identity.py. Shares nothing with sim/rogue.py: no shared imports,
state, credential objects, or sessions.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Allow `python3 sim/agents.py` script runs to import sentinel.*.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import paho.mqtt.client as mqtt
from pymodbus.client import ModbusTcpClient

from sentinel import identity

HR_RUN_STOP = 0
HR_SPEED_SETPOINT = 1

TOPIC_TEMPERATURE = "site/line1/sensors/temperature"
TOPIC_VIBRATION = "site/line1/sensors/vibration"
TOPIC_GATE_EVENT = "site/yard/gate/event"
TOPIC_GATE_RELEASE = "site/yard/gate/release"

# Explicit subscribes only: starter rule 4 forbids wildcard subscribes
# for non-gateway agents. Must match the publishers' topics
# (pinned by tests/test_sim_contract.py).
OPERATOR_TOPICS = (TOPIC_TEMPERATURE, TOPIC_VIBRATION, TOPIC_GATE_EVENT)

# Booking registry stand-in (a real deployment queries the terminal
# operating system). Keys must match BOOKED_ARRIVALS in sim/yard.py.
BOOKINGS = {
    "MSKU100001": {"truck": "TRK-42", "booking": "BK-1001"},
    "TCLU200002": {"truck": "TRK-17", "booking": "BK-2002"},
}

MQTT_CLIENT_ID = "sentinel-operator"
CREDENTIAL_ROLE = "operator-agent"
CREDENTIAL_SCOPE = ["telemetry.read", "plc.write", "gate.release"]

SPEED_POLICY_MAX = 1500  # in-policy ceiling; PLC hardware max is 3000
TEMP_HIGH = 80.0
TEMP_LOW = 70.0
VIBRATION_TRIP = 5.0


class OperatorAgent:
    def __init__(self, mqtt_host, mqtt_port, plc_host, plc_port):
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                client_id=MQTT_CLIENT_ID)
        self.mqtt.on_message = self.on_message
        self.mqtt_host, self.mqtt_port = mqtt_host, mqtt_port
        self.plc = ModbusTcpClient(plc_host, port=plc_port)
        self.speed = 1000  # last commanded setpoint (assumed start)
        self.running = True
        self.credential = json.loads(identity.issue(
            CREDENTIAL_ROLE, "sentinel-ca", CREDENTIAL_SCOPE))
        self.credential_id = self.credential["id"]

    def plc_write(self, address, value):
        self.plc.write_register(address, value, device_id=1)
        print(f"operator: PLC write HR{address}={value}", flush=True)

    def start_line(self):
        if not self.running:
            self.plc_write(HR_RUN_STOP, 1)
            self.running = True

    def on_message(self, _client, _userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
        except ValueError:
            return
        topic = msg.topic

        if topic == TOPIC_TEMPERATURE:
            temp = data.get("value")
            print(f"operator: temp={temp}C", flush=True)
            if temp is None:
                return
            if temp > TEMP_HIGH:
                self.set_speed(self.speed - 200)
            elif temp < TEMP_LOW:
                self.set_speed(self.speed + 100)
        elif topic == TOPIC_VIBRATION:
            vib = data.get("value")
            if vib is not None and vib > VIBRATION_TRIP and self.running:
                print(f"operator: vibration {vib} over trip -> STOP", flush=True)
                self.plc_write(HR_RUN_STOP, 0)
                self.running = False
        elif topic == TOPIC_GATE_EVENT:
            if data.get("event") == "truck_arrival":
                self.maybe_release(data)

    def maybe_release(self, event):
        """Release only on matching container + truck + booking."""
        container, truck = event.get("container"), event.get("truck")
        booking = BOOKINGS.get(container)
        if booking is None or booking["truck"] != truck:
            print(f"operator: no matching booking for container={container} "
                  f"truck={truck} -> no release", flush=True)
            return
        release = {"container": container, "truck": truck,
                   "booking": booking["booking"], "lane": event.get("lane"),
                   "decision": "allow", "ts": time.time()}
        self.mqtt.publish(TOPIC_GATE_RELEASE, json.dumps(release))
        print(f"operator: gate release {release}", flush=True)

    def set_speed(self, rpm):
        rpm = max(0, min(SPEED_POLICY_MAX, int(rpm)))
        if rpm != self.speed:
            self.start_line()
            self.plc_write(HR_SPEED_SETPOINT, rpm)
            self.speed = rpm

    def run(self):
        print(f"operator: credential id={self.credential_id} "
              f"role={CREDENTIAL_ROLE}", flush=True)
        self.plc.connect()
        self.plc_write(HR_RUN_STOP, 1)  # ensure line running
        self.plc_write(HR_SPEED_SETPOINT, self.speed)
        self.mqtt.connect(self.mqtt_host, self.mqtt_port)
        for topic in OPERATOR_TOPICS:
            self.mqtt.subscribe(topic)
        print(f"operator: subscribed to {', '.join(OPERATOR_TOPICS)}", flush=True)
        try:
            self.mqtt.loop_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.mqtt.disconnect()
            self.plc.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Operator agent (legitimate).")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--plc-host", default="127.0.0.1")
    parser.add_argument("--plc-port", type=int, default=5020)
    args = parser.parse_args()

    OperatorAgent(args.mqtt_host, args.mqtt_port,
                  args.plc_host, args.plc_port).run()


if __name__ == "__main__":
    main()

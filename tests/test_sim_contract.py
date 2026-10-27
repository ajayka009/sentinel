"""Sim contract tests: spec topic strings and operator gate logic.

Offline, stdlib only. Run from the repo root:

    python3 -m unittest discover -s tests
"""

import json
import unittest

from sim import agents, sensors, yard


class FakeMsg:
    def __init__(self, topic, payload):
        self.topic = topic
        self.payload = json.dumps(payload).encode()


class TopicContractTest(unittest.TestCase):
    """Topic strings must match sentinel-build-spec.md exactly."""

    def test_yard_topics_match_spec(self):
        self.assertEqual(
            yard.TOPIC_REEFER_TEMPERATURE.format(reefer_id="R-101"),
            "site/yard/reefer/R-101/temperature",
        )
        self.assertEqual(yard.TOPIC_GATE_EVENT, "site/yard/gate/event")
        self.assertEqual(
            yard.TOPIC_EQUIPMENT_STATUS.format(equipment_id="crane-1"),
            "site/yard/equipment/crane-1/status",
        )
        self.assertEqual(yard.TOPIC_CONTAINER_MOVE, "site/yard/container/move")

    def test_agents_agree_with_publishers(self):
        """Agents must use the same topics the publishers emit."""
        self.assertEqual(agents.TOPIC_GATE_EVENT, yard.TOPIC_GATE_EVENT)
        self.assertEqual(agents.TOPIC_GATE_RELEASE, "site/yard/gate/release")
        sensor_topics = {cfg["topic"] for cfg in sensors.SENSORS.values()}
        self.assertIn(agents.TOPIC_TEMPERATURE, sensor_topics)
        self.assertIn(agents.TOPIC_VIBRATION, sensor_topics)

    def test_operator_subscribes_without_wildcard(self):
        """Starter rule 4 forbids wildcard subscribes for non-gateway agents."""
        self.assertIn(agents.TOPIC_TEMPERATURE, agents.OPERATOR_TOPICS)
        self.assertIn(agents.TOPIC_VIBRATION, agents.OPERATOR_TOPICS)
        self.assertIn(agents.TOPIC_GATE_EVENT, agents.OPERATOR_TOPICS)
        for topic in agents.OPERATOR_TOPICS:
            self.assertNotIn("#", topic)
            self.assertNotIn("+", topic)

    def test_booked_arrivals_match_bookings(self):
        """Yard's pre-booked arrivals must exist in the operator's registry."""
        expected = {(c, b["truck"]) for c, b in agents.BOOKINGS.items()}
        self.assertEqual(set(yard.BOOKED_ARRIVALS), expected)


class OperatorGateTest(unittest.TestCase):
    """Gate release requires matching container + truck + booking."""

    def setUp(self):
        self.agent = agents.OperatorAgent("127.0.0.1", 1883, "127.0.0.1", 5020)
        self.published = []
        self.agent.mqtt.publish = lambda topic, payload: self.published.append(
            (topic, json.loads(payload))
        )

    def tearDown(self):
        self.agent.plc.close()

    def _arrival(self, container, truck):
        self.agent.on_message(
            None,
            None,
            FakeMsg(
                "site/yard/gate/event",
                {
                    "lane": "out-1",
                    "event": "truck_arrival",
                    "container": container,
                    "truck": truck,
                },
            ),
        )

    def test_release_on_booking_match(self):
        container = next(iter(agents.BOOKINGS))
        self._arrival(container, agents.BOOKINGS[container]["truck"])
        self.assertEqual(len(self.published), 1)
        topic, release = self.published[0]
        self.assertEqual(topic, "site/yard/gate/release")
        self.assertEqual(release["container"], container)
        self.assertEqual(release["booking"], agents.BOOKINGS[container]["booking"])

    def test_no_release_on_booking_mismatch(self):
        self._arrival("XXXX000000", "TRK-99")
        self.assertEqual(self.published, [])


if __name__ == "__main__":
    unittest.main()

"""Offline-import regression test: the suite must import and construct
agents with third-party packages (dotenv, paho, pymodbus, openai) absent.

Runs the import probe in a subprocess with those imports blocked, so the
check is hermetic regardless of what is installed in this environment.
Run from the repo root:

    python3 -m unittest discover -s tests
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PROBE = """
import importlib.abc
import sys

BLOCKED = {"dotenv", "paho", "pymodbus", "openai"}

class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ModuleNotFoundError("blocked for offline test: " + name)
        return None

sys.meta_path.insert(0, Blocker())

try:
    import paho  # noqa: F401
except ModuleNotFoundError:
    pass
else:
    raise AssertionError("import blocker is not effective")

from sentinel import models
from sim import agents, rogue, sensors, yard
from sim import glimmer_operator  # noqa: F401

op = agents.OperatorAgent("127.0.0.1", 1883, "127.0.0.1", 5020)
rg = rogue.RogueAgent("127.0.0.1", 1883, "127.0.0.1", 5020)
assert op.credential_id != rg.credential_id
op.plc.close()
rg.plc.close()

assert sensors.SENSORS["temperature"]["topic"] == agents.TOPIC_TEMPERATURE
assert yard.TOPIC_GATE_EVENT == agents.TOPIC_GATE_EVENT

try:
    models.chat("m", [])
except RuntimeError as exc:
    assert "openai" in str(exc), exc
else:
    raise AssertionError("models.chat should require the openai package")

try:
    op.plc_write(1, 100)
except RuntimeError as exc:
    assert "pymodbus" in str(exc), exc
else:
    raise AssertionError("PLC writes should require pymodbus")

print("offline probe OK")
"""


class OfflineImportTest(unittest.TestCase):
    def test_imports_and_constructs_without_third_party_deps(self):
        proc = subprocess.run(
            [sys.executable, "-c", PROBE],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0,
                         f"offline probe failed:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("offline probe OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()

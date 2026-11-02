"""Launcher script checks: scripts/start_all.sh stays valid and honest.

Run from the repo root:

    python3 -m unittest discover -s tests
"""

import os
import stat
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "start_all.sh"


class TestStartAll(unittest.TestCase):
    def test_script_present_and_executable(self):
        self.assertTrue(SCRIPT.is_file(), "scripts/start_all.sh is missing")
        mode = os.stat(SCRIPT).st_mode
        self.assertTrue(mode & stat.S_IXUSR,
                        "scripts/start_all.sh is not executable")

    def test_bash_syntax_valid(self):
        proc = subprocess.run(["bash", "-n", str(SCRIPT)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"bash -n failed:\n{proc.stderr}")

    def test_help_lists_every_component(self):
        proc = subprocess.run(["bash", str(SCRIPT), "--help"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"--help failed:\n{proc.stderr}")
        for token in ("plc", "sensors", "yard", "operator",
                      "console", "rogue", "broker"):
            self.assertIn(token, proc.stdout.lower(),
                           f"--help never mentions {token!r}")

    def test_every_referenced_entry_point_exists(self):
        body = SCRIPT.read_text(encoding="utf-8")
        for entry in ("sim/plc.py", "sim/sensors.py", "sim/yard.py",
                      "sim/agents.py", "sim/glimmer_operator.py",
                      "sim/rogue.py", "console/app.py"):
            self.assertIn(entry, body,
                            f"launcher never references {entry}")
            self.assertTrue((REPO_ROOT / entry).is_file(),
                            f"{entry} is missing")


if __name__ == "__main__":
    unittest.main()

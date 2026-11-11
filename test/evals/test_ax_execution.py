import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from ax import detached_script


class DetachedExecutionTests(unittest.TestCase):
    def test_exit_and_timeout_survive_launch_connection(self):
        for code, timeout, expected in [('print("retained"); raise SystemExit(3)', 5, 3),
                                        ('import time; time.sleep(10)', 0.1, 124)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                subprocess.run([sys.executable, '-c', detached_script(directory, [sys.executable, '-c', code], timeout)],
                               check=True, capture_output=True)
                status = Path(directory) / 'status.json'
                deadline = time.monotonic() + 8
                while not status.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(json.loads(status.read_text())['exit_code'], expected)
                if expected == 3:
                    self.assertIn('retained', (Path(directory) / 'driver.log').read_text())

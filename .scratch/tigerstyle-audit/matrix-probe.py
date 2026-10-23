"""Exercise the existing VM output parser without contacting any VM."""
import os
import subprocess
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
script = (repo / "test/vm/matrix.sh").read_text()
parser = script[script.index("fail=0"):]
cases = {
    "empty": "",
    "failure-summary-only": "SUMMARY|pass=0|fail=1",
    "partial-results": "RESULT|one|PASS|ok\nSUMMARY|pass=1|fail=0",
}
for name, output in cases.items():
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + parser],
        env=dict(os.environ, OUT=output), capture_output=True, text=True,
    )
    print(f"{name}: exit={result.returncode}\n{result.stdout.strip()}")

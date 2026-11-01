"""Validate captured VM output independently of the transport."""

import argparse
from pathlib import Path
import re
import sys


def validate(output, expected, guest_status=0):
    if guest_status:
        raise ValueError(f"guest/transport exited {guest_status}")
    results = {}
    summaries = []
    for line in output.splitlines():
        if line.startswith("RESULT"):
            fields = line.split("|", 3)
            if len(fields) != 4 or fields[0] != "RESULT":
                raise ValueError(f"malformed result: {line}")
            _, name, status, note = fields
            if name not in expected or name in results or status not in ("PASS", "FAIL", "SKIP"):
                raise ValueError(f"unexpected, duplicate, or invalid result: {line}")
            results[name] = (status, note)
        elif line.startswith("SUMMARY"):
            match = re.fullmatch(r"SUMMARY\|pass=(\d+)\|fail=(\d+)", line)
            if not match:
                raise ValueError(f"malformed summary: {line}")
            summaries.append(tuple(map(int, match.groups())))
    if set(results) != set(expected):
        raise ValueError(f"missing cases: {', '.join(sorted(set(expected) - results.keys()))}")
    passed = sum(status == "PASS" for status, _ in results.values())
    counts = (passed, len(results) - passed)
    if summaries != [counts]:
        raise ValueError("missing, duplicate, or inconsistent summary")
    if counts[1]:
        raise ValueError("required cases failed or skipped")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--guest-status", type=int, default=0)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("cases.txt"))
    args = parser.parse_args()
    expected = args.manifest.read_text().splitlines()
    try:
        results = validate(sys.stdin.read(), expected, args.guest_status)
    except ValueError as error:
        sys.exit(f"FAIL: {error}")
    for name, (status, note) in results.items():
        print(f"{name:35} {status:6} {note}")
    print(f"ALL {len(results)} CASES PASSED")

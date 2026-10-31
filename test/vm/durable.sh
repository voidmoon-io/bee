#!/usr/bin/env bash
# Real-kernel durable executor recovery; requires the VM described in README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."
NS=${NS:-ac-matrix}
VM=${VM:-ac-matrix-vm}
KEY=${KEY:-$HOME/.ssh/ac-matrix-vm}
TARGET="ubuntu@vmi/$VM/$NS"
SSHOPTS=(--identity-file="$KEY" --local-ssh-opts="-o StrictHostKeyChecking=no" --local-ssh-opts="-o UserKnownHostsFile=/dev/null")
guest() { virtctl ssh "$TARGET" "${SSHOPTS[@]}" -c "$1"; }
BUILD=$(mktemp)
trap 'rm -f "$BUILD"' EXIT
if ! cargo test --offline --features durable-sessions,enforce --test durable_kernel --no-run --message-format=json > "$BUILD"; then
  python3 - "$BUILD" <<'PYERR'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        record = json.loads(line)
        if record.get("reason") == "compiler-message":
            print(record["message"].get("rendered", ""), file=sys.stderr)
PYERR
  exit 1
fi
BIN=$(python3 - "$BUILD" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    matches = [r["executable"] for line in f if (r := json.loads(line)).get("reason") == "compiler-artifact" and r.get("target", {}).get("name") == "durable_kernel" and r.get("executable")]
if len(matches) != 1:
    raise SystemExit("expected exactly one durable_kernel executable")
print(matches[0])
PY
)
virtctl scp "$BIN" "$TARGET:/home/ubuntu/bee-durable-kernel-test" "${SSHOPTS[@]}"
status=0
guest 'chmod +x /home/ubuntu/bee-durable-kernel-test && sudo /home/ubuntu/bee-durable-kernel-test --ignored kernel_recovery_ --nocapture --test-threads=1' || status=$?
guest 'rm -f /home/ubuntu/bee-durable-kernel-test'
exit "$status"

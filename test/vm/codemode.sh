#!/usr/bin/env bash
# Build the shipping worker and kernel harness, run in the existing VM, remove guest artifacts.
# VM lifecycle belongs to the caller. NS/VM/KEY match the other VM gates.
set -euo pipefail
cd "$(dirname "$0")/../.."
NS=${NS:-ac-matrix}
VM=${VM:-ac-matrix-vm}
KEY=${KEY:-$HOME/.ssh/ac-matrix-vm}
TARGET="ubuntu@vmi/$VM/$NS"
SSHOPTS=(--identity-file="$KEY" --local-ssh-opts="-o StrictHostKeyChecking=no" --local-ssh-opts="-o UserKnownHostsFile=/dev/null")
guest() { virtctl ssh "$TARGET" "${SSHOPTS[@]}" -c "$1"; }
local_stage=$(mktemp -d)
guest_stage=''
cleanup() {
  if [[ "$guest_stage" =~ ^/home/ubuntu/bee-codemode\.[a-zA-Z0-9]+$ ]]; then
    guest "sudo rm -rf -- '$guest_stage'" || return 1
  fi
  rm -rf -- "$local_stage"
}
trap cleanup EXIT
cargo build --offline --locked --features durable-sessions,enforce --bin bee
cargo test --offline --locked --features durable-sessions,enforce --test codemode_kernel --no-run --message-format=json > "$local_stage/build.jsonl"
binary=$(python3 - "$local_stage/build.jsonl" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    bins = [r["executable"] for line in stream if (r := json.loads(line)).get("reason") == "compiler-artifact" and r.get("target", {}).get("name") == "codemode_kernel" and r.get("executable")]
if len(bins) != 1:
    raise SystemExit("expected exactly one codemode_kernel executable")
print(bins[0])
PY
)
cp target/debug/bee "$local_stage/bee"
cp "$binary" "$local_stage/codemode_kernel"
strip "$local_stage/bee" "$local_stage/codemode_kernel"
sha256sum "$local_stage/bee" "$local_stage/codemode_kernel"
guest_stage=$(guest 'mktemp -d /home/ubuntu/bee-codemode.XXXXXXXX')
[[ "$guest_stage" =~ ^/home/ubuntu/bee-codemode\.[a-zA-Z0-9]+$ ]] || { echo 'invalid guest staging directory' >&2; exit 1; }
guest "mkdir '$guest_stage/deps'"
virtctl scp "$local_stage/bee" "$TARGET:$guest_stage/bee" "${SSHOPTS[@]}"
virtctl scp "$local_stage/codemode_kernel" "$TARGET:$guest_stage/deps/codemode_kernel" "${SSHOPTS[@]}"
virtctl scp test/vm/remote-codemode.sh "$TARGET:$guest_stage/remote-codemode.sh" "${SSHOPTS[@]}"
virtctl scp test/vm/codemode-cases.txt "$TARGET:$guest_stage/codemode-cases.txt" "${SSHOPTS[@]}"
status=0
guest "chmod +x '$guest_stage/bee' '$guest_stage/deps/codemode_kernel' && sudo bash '$guest_stage/remote-codemode.sh' '$guest_stage'" > "$local_stage/results" || status=$?
cat "$local_stage/results"
python3 test/vm/validate_results.py --manifest test/vm/codemode-cases.txt --guest-status "$status" < "$local_stage/results"

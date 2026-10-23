#!/usr/bin/env bash
# Host-side orchestrator for bee's live enforcement matrix on the KubeVirt BPF-LSM VM.
#
# Builds the single `bee` executable with enforcement + concurrency on the host, ships it and the
# remote runner into the VM over the virtctl tunnel, runs the matrix as root against the real
# kernel, and gates on the results.
#
# Mirrors agentcontainers/test/vm/enforcer-live.sh. The build happens on the host because host and
# guest are both Ubuntu noble (glibc 2.39) and the host has the nightly bpf toolchain the VM lacks.
#
# Env:
#   NS, VM            KubeVirt namespace / VM name   (default ac-matrix / ac-matrix-vm)
#   KEY               ssh identity                    (default ~/.ssh/ac-matrix-vm)
#   BEE_SKIP_BUILD=1  reuse target/release/bee
set -euo pipefail

NS=${NS:-ac-matrix}
VM=${VM:-ac-matrix-vm}
KEY=${KEY:-$HOME/.ssh/ac-matrix-vm}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
TARGET="ubuntu@vmi/$VM/$NS"
SSHOPTS=(--identity-file="$KEY" --local-ssh-opts="-o StrictHostKeyChecking=no" --local-ssh-opts="-o UserKnownHostsFile=/dev/null")

guest() { virtctl ssh "$TARGET" "${SSHOPTS[@]}" -c "$1" 2>/dev/null; }

echo "== build (host) =="
if [ "${BEE_SKIP_BUILD:-0}" != 1 ]; then
  # `concurrent` implies `enforce`, so one build covers every case in the matrix — including the
  # concurrent-audit-isolation one, which used to need a second binary and skipped without it.
  # `sec` is here for the 016 scanner case: without it `scan` is a compiled-out stub that reports
  # `not compiled in` — which is a correct answer, and would sail past a case looking for a leak.
  ( cd "$REPO" && cargo build --features concurrent,sec --release )
fi
BIN="$REPO/target/release/bee"
[ -x "$BIN" ] || { echo "FAIL: $BIN not found (build first)"; exit 1; }

echo "== wait for guest reachability =="
for _ in $(seq 1 30); do guest true >/dev/null 2>&1 && break; sleep 3; done
guest true >/dev/null 2>&1 || { echo "FAIL: guest unreachable over virtctl ssh"; exit 1; }

echo "== ship binaries + runner =="
STRIPPED=$(mktemp); cp "$BIN" "$STRIPPED"; strip "$STRIPPED" 2>/dev/null || true
virtctl scp "$STRIPPED" "$TARGET:/home/ubuntu/bee" "${SSHOPTS[@]}" 2>/dev/null
rm -f "$STRIPPED"
virtctl scp "$REPO/test/vm/remote-matrix.sh" "$TARGET:/home/ubuntu/remote-matrix.sh" "${SSHOPTS[@]}" 2>/dev/null
virtctl scp "$REPO/test/vm/cases.txt" "$TARGET:/home/ubuntu/cases.txt" "${SSHOPTS[@]}" 2>/dev/null
guest "chmod +x /home/ubuntu/bee /home/ubuntu/remote-matrix.sh"

echo "== run matrix (guest, as root) =="
guest_status=0
OUT=$(guest "sudo /home/ubuntu/remote-matrix.sh") || guest_status=$?
printf '%s\n' "$OUT" | python3 "$REPO/test/vm/validate_results.py" --guest-status "$guest_status"

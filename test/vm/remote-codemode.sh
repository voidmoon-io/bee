#!/usr/bin/env bash
# Guest gate: require every named ignored kernel test to actually execute exactly once.
set -u
stage=$1
binary="$stage/deps/codemode_kernel"
uname -r
cat /sys/kernel/security/lsm
passed=0
failed=0
output=$(mktemp)
trap 'rm -f "$output"' EXIT
while IFS= read -r name; do
  if "$binary" --list | grep -Fxq "$name: test" &&
     timeout --signal=TERM --kill-after=5s 120s "$binary" --ignored --exact "$name" --nocapture --test-threads=1 >"$output" 2>&1 &&
     grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$output"; then
    cat "$output"
    echo "RESULT|$name|PASS|executed under BPF-LSM"
    passed=$((passed + 1))
  else
    cat "$output"
    echo "RESULT|$name|FAIL|kernel test failed or did not execute"
    failed=$((failed + 1))
  fi
done < "$stage/codemode-cases.txt"
echo "SUMMARY|pass=$passed|fail=$failed"
[ "$failed" -eq 0 ]

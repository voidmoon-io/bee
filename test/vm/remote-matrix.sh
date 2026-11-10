#!/usr/bin/env bash
# Runs INSIDE the VM. Exercises bee's enforcement matrix against the real BPF-LSM kernel and emits
# machine-parseable `RESULT|<case>|<PASS|FAIL>|<note>` lines. Exits non-zero if any case failed.
#
# Assumes /home/ubuntu/bee (built with --features enforce) exists and is executable.
set -u
BEE=${BEE:-/home/ubuntu/bee}
WORK=$(mktemp -d)
pass=0
fail=0
CASE_MANIFEST="$(dirname "$0")/cases.txt"
[ -r "$CASE_MANIFEST" ] || { echo "missing case manifest" >&2; exit 1; }

emit() { # name status note
  grep -Fxq -- "$1" "$CASE_MANIFEST" || { echo "unknown case: $1" >&2; exit 1; }
  echo "RESULT|$1|$2|$3"
  if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}

# Run bee, capturing child stdout (fd1) and bee audit/stderr separately.
run_bee() { # policy -- cmd...
  local policy=$1; shift
  sudo "$BEE" exec --policy "$policy" "$@" 2>"$WORK/err"
}

mkdir -p /home/ubuntu/.ssh
echo TOP-SECRET > /home/ubuntu/.ssh/secret.txt

# ---------------------------------------------------------------- kernel substrate
lsm=$(cat /sys/kernel/security/lsm)
case ",$lsm," in *,bpf,*) emit kernel-bpf-lsm PASS "$lsm" ;; *) emit kernel-bpf-lsm FAIL "$lsm" ;; esac
[ -e /sys/kernel/btf/vmlinux ] && emit kernel-btf PASS present || emit kernel-btf FAIL missing
"$BEE" check >/dev/null 2>&1 && emit bee-check PASS "gates ok" || emit bee-check FAIL "check exit $?"

# ---------------------------------------------------------------- network allow / deny
cat >"$WORK/net.toml" <<'EOF'
[policy]
name = "net"
mode = "enforce"
[policy.network]
allow = ["1.1.1.1:443"]
EOF
# A non-000 HTTP code means the TCP connection succeeded (2xx/3xx redirects both count).
connected() { case "$1" in 000 | "") return 1 ;; *) return 0 ;; esac; }
out=$(run_bee "$WORK/net.toml" -- bash -c 'curl -sS --max-time 8 -o /dev/null -w %{http_code} https://1.1.1.1')
if connected "$out"; then emit net-allow PASS "http=$out"; else emit net-allow FAIL "http=$out"; fi
out=$(run_bee "$WORK/net.toml" -- bash -c 'curl -sS --max-time 8 -o /dev/null -w %{http_code} https://8.8.8.8')
if [ "$out" = 000 ]; then emit net-deny PASS "connection blocked"; else emit net-deny FAIL "http=$out (expected block)"; fi
# 019 P5 (FR-009): the denial just above must name where it was going. Before P5 a kernel connect
# audit carried an empty target, so the operator saw "connect denied" with no destination and
# reactive network escalation could not build a grant. Read from the same run's audit stream.
if grep -q '"op":"connect","decision":"denied","errno":-1,"target":"8.8.8.8:443"' "$WORK/err"; then
  emit connect-target-audited PASS "denial names 8.8.8.8:443"
else
  emit connect-target-audited FAIL "no connect audit naming 8.8.8.8:443: $(grep -o '"op":"connect"[^}]*' "$WORK/err" | head -2 | tr '\n' ' ')"
fi

# A non-IP destination is still egress. The policy language spells destinations `host:port`, so no
# rule can ever allow an AF_UNIX socket — and "no rule matches" in an enforcing scope means deny.
# The hook used to return allow for every family it did not decode, so a local agent socket was
# reachable from a network-enforced scope (f034).
SOCK=/tmp/bee-af-unix.sock
rm -f "$SOCK"
python3 - "$SOCK" <<'EOF' &
import socket, sys, os
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p); s.listen(1); os.chmod(p, 0o777)
try: s.accept()
except Exception: pass
EOF
listener=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCK" ] && break; sleep 0.3; done
out=$(run_bee "$WORK/net.toml" -- python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('$SOCK'); print('CONNECTED')
except OSError as e:
    print('REFUSED', e.errno)
" 2>&1)
case "$out" in
  *REFUSED*) emit net-unix-denied PASS "AF_UNIX connect refused ($out)" ;;
  *) emit net-unix-denied FAIL "AF_UNIX reachable from an enforced scope ($out)" ;;
esac
kill "$listener" 2>/dev/null; wait "$listener" 2>/dev/null; rm -f "$SOCK"

# ---------------------------------------------------------------- file deny / allow
cat >"$WORK/fs.toml" <<'EOF'
[policy]
name = "fs"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/.ssh" = "deny"
EOF
out=$(run_bee "$WORK/fs.toml" -- cat /home/ubuntu/.ssh/secret.txt)
if [ "$out" != "TOP-SECRET" ]; then emit file-deny PASS "secret not leaked"; else emit file-deny FAIL "secret leaked"; fi
out=$(run_bee "$WORK/fs.toml" -- cat /etc/hostname)
if [ -n "$out" ]; then emit file-allow PASS "read ok ($out)"; else emit file-allow FAIL "non-denied read blocked"; fi

# postfix glob deny (`*.secret`) — the new kind-dispatched matching
cat >"$WORK/glob.toml" <<'EOF'
[policy]
name = "glob"
mode = "enforce"
[policy.filesystem]
"*.secret" = "deny"
EOF
echo SECRETDATA >/tmp/g.secret
echo plaindata >/tmp/g.txt
out=$(run_bee "$WORK/glob.toml" -- cat /tmp/g.secret)
if [ "$out" != "SECRETDATA" ]; then emit file-glob-deny PASS "*.secret blocked"; else emit file-glob-deny FAIL "leaked"; fi
out=$(run_bee "$WORK/glob.toml" -- cat /tmp/g.txt)
if [ "$out" = "plaindata" ]; then emit file-glob-allow PASS "non-matching file opens"; else emit file-glob-allow FAIL "out='$out'"; fi

# fail-closed on an unenforceable segment rule (`**/name`) — must refuse, not silently under-enforce
cat >"$WORK/seg.toml" <<'EOF'
[policy]
name = "seg"
mode = "enforce"
[policy.filesystem]
"**/target" = "deny"
EOF
sudo "$BEE" exec --policy "$WORK/seg.toml" -- true >/dev/null 2>"$WORK/err"
rc=$?
if [ "$rc" -eq 64 ] && grep -q 'cannot enforce filesystem segment rule' "$WORK/err"; then
  emit file-segment-refused PASS "fail-closed on unenforceable rule"
else
  emit file-segment-refused FAIL "rc=$rc (expected refusal)"
fi

# ------------------------------------------------------- US2 AS-2: read/write mode enforcement
# A policy granting `write` to a scratch dir and `read` to a source dir: writing the source is
# blocked (read-only), reading it works, writing scratch works, and — because the policy declares a
# writable surface — writing an unlisted path is denied by default (FR-001 read/write modes).
RW=/home/ubuntu/rwtest
rm -rf "$RW"; mkdir -p "$RW/src" "$RW/scratch"
echo "sourcecode" >"$RW/src/lib.rs"
cat >"$WORK/rw.toml" <<'EOF'
[policy]
name = "rw"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/rwtest/scratch" = "write"
"/home/ubuntu/rwtest/src" = "read"
EOF

out=$(run_bee "$WORK/rw.toml" -- cat "$RW/src/lib.rs")
if [ "$out" = "sourcecode" ]; then emit rw-read-source PASS "read-only source readable"; else emit rw-read-source FAIL "out='$out'"; fi

run_bee "$WORK/rw.toml" -- bash -c 'echo TAMPERED > /home/ubuntu/rwtest/src/lib.rs' >/dev/null 2>&1
if [ "$(cat "$RW/src/lib.rs" 2>/dev/null)" = "sourcecode" ]; then emit rw-write-source-denied PASS "write to read-only source blocked"; else emit rw-write-source-denied FAIL "source was modified"; fi

run_bee "$WORK/rw.toml" -- bash -c 'echo scratchdata > /home/ubuntu/rwtest/scratch/out' >/dev/null 2>&1
if [ "$(cat "$RW/scratch/out" 2>/dev/null)" = "scratchdata" ]; then emit rw-write-scratch PASS "write to granted scratch works"; else emit rw-write-scratch FAIL "scratch write blocked"; fi

run_bee "$WORK/rw.toml" -- bash -c 'echo x > /home/ubuntu/rwtest/unlisted' >/dev/null 2>&1
if [ "$(cat "$RW/unlisted" 2>/dev/null)" != "x" ]; then emit rw-write-default-deny PASS "unlisted write denied by default"; else emit rw-write-default-deny FAIL "unlisted path was written"; fi
rm -rf "$RW"

# ---------------------------------------------------------------- exec allow / deny
cat >"$WORK/exec.toml" <<'EOF'
[policy]
name = "exec"
mode = "enforce"
[policy.exec]
allow = ["bash", "cat", "ls"]
EOF
cat >"$WORK/exectest.sh" <<'EOF'
cat /etc/hostname >/dev/null && echo CAT_OK
nc -h >/dev/null 2>&1; echo NC_RC=$?
EOF
out=$(run_bee "$WORK/exec.toml" -- bash "$WORK/exectest.sh")
echo "$out" | grep -q CAT_OK && emit exec-allow PASS "allowlisted exec ran" || emit exec-allow FAIL "allowed exec blocked"
echo "$out" | grep -q 'NC_RC=126' && emit exec-deny PASS "unlisted exec denied" || emit exec-deny FAIL "nc not denied ($(echo "$out" | tr '\n' ' '))"

# ------------------------------------------- 017: a pin is enforced on identity, not on a name
# An `exec.allow` entry prefixed `!` grants *that file*, not that path. Until 017 the planner refused
# such a policy outright ("eBPF backend cannot enforce inode-pinned executable"), which is what made
# every 016 scanner grant uninstallable under enforcement. Two cases: the pin admits the file it
# names, and it stops admitting it the moment the name points somewhere else.
PIN=/home/ubuntu/pintest
sudo rm -rf "$PIN"; mkdir -p "$PIN"
cp /bin/echo "$PIN/tool"          # the granted image
cp /bin/true "$PIN/other"         # same directory, never granted
cp /bin/true "$PIN/replacement"   # staged outside the episode; `mv`d over the pin from inside
cat >"$WORK/pin.toml" <<EOF
[policy]
name = "pin"
mode = "enforce"
[policy.exec]
allow = ["!$PIN/tool", "bash", "mv"]
EOF
out=$(run_bee "$WORK/pin.toml" -- bash -c "\"$PIN/tool\" PIN_OK; \"$PIN/other\"; echo OTHER_RC=\$?" 2>&1)
if echo "$out" | grep -q PIN_OK && echo "$out" | grep -q 'OTHER_RC=126'; then
  emit exec-pin-allow PASS "pinned image ran; unpinned sibling denied"
else
  emit exec-pin-allow FAIL "out=$(echo "$out" | tr '\n' '|')"
fi

# The swap. Same policy, same path, different file — and the policy is compiled fresh each run, so
# the replacement has to happen while the identity from the *first* stat is what got installed. bee
# compiles at start-up, so replacing the file before the run would just pin the new inode; the honest
# provocation is to replace it from *inside* the episode, between installation and exec.
cat >"$WORK/swap.sh" <<EOF
"$PIN/tool" BEFORE_SWAP
mv "$PIN/replacement" "$PIN/tool" || echo SWAP_FAILED
"$PIN/tool" AFTER_SWAP; echo AFTER_RC=\$?
EOF
out=$(run_bee "$WORK/pin.toml" -- bash "$WORK/swap.sh" 2>&1)
if ! echo "$out" | grep -q BEFORE_SWAP; then
  emit exec-pin-swapped-denied FAIL "pinned image would not run at all — case proves nothing ($(echo "$out" | tr '\n' '|'))"
elif echo "$out" | grep -q SWAP_FAILED; then
  emit exec-pin-swapped-denied FAIL "the swap itself did not happen — case proves nothing ($(echo "$out" | tr '\n' '|'))"
elif echo "$out" | grep -q 'AFTER_RC=126'; then
  emit exec-pin-swapped-denied PASS "same path, new inode: exec denied after the swap"
else
  emit exec-pin-swapped-denied FAIL "swapped image still executed ($(echo "$out" | tr '\n' '|'))"
fi
sudo rm -rf "$PIN"

# ------------------------------------------- unresolvable paths fail closed (f007)
# `bpf_d_path` fails (-ENAMETOOLONG) once the resolved path exceeds its 4KB buffer. Both hooks used
# to return allow in that case, so a deep-enough directory chain was a general escape: `execve` of a
# short *relative* name never has to pass a >PATH_MAX argument, but the kernel still resolves it to
# one. Build such a chain outside the scope, then try to use it from inside.
DEEP=/home/ubuntu/deeptest
SEG=$(printf 'd%.0s' $(seq 1 60))
sudo rm -rf "$DEEP"; mkdir -p "$DEEP"
( cd "$DEEP" && for _ in $(seq 1 80); do mkdir -p "$SEG" && cd "$SEG" || exit 1; done \
    && cp /bin/echo ./x && echo DEEPDATA > ./deep.txt )
# 80 × 61 chars of chain, well past PATH_MAX — confirm before trusting either result.
depth_ok=$(cd "$DEEP" && for _ in $(seq 1 80); do cd "$SEG"; done && pwd | wc -c)
# Builtins only for the descent: this script runs under the exec allowlist, and a `seq` that gets
# denied would leave us in the shallow directory and turn the case into a false PASS.
cat >"$WORK/deep.sh" <<EOF
cd "$DEEP" || exit 1
i=0
while [ \$i -lt 80 ]; do cd "$SEG" || exit 1; i=\$((i + 1)); done
[ -x ./x ] || { echo DESCENT_FAILED; exit 1; }
./x DEEP_EXEC_OK 2>/dev/null; echo "EXEC_RC=\$?"
cat ./deep.txt 2>/dev/null; echo "READ_RC=\$?"
EOF

if [ "$depth_ok" -le 4096 ]; then
  emit exec-unresolvable-denied FAIL "chain only $depth_ok bytes — test cannot provoke d_path failure"
  emit file-unresolvable-denied FAIL "chain only $depth_ok bytes — test cannot provoke d_path failure"
else
  # `seq`/`cat` are on the allowlist, `./x` (a copy of echo) is not — but the point is that it is
  # unresolvable, so it must be refused whatever its name would have been.
  out=$(run_bee "$WORK/exec.toml" -- bash "$WORK/deep.sh" 2>&1)
  if echo "$out" | grep -q DESCENT_FAILED; then
    emit exec-unresolvable-denied FAIL "descent broke — case proves nothing ($(echo "$out" | tr '\n' ' '))"
  elif echo "$out" | grep -q DEEP_EXEC_OK; then
    emit exec-unresolvable-denied FAIL "exec of an unresolvable image ran ($(echo "$out" | tr '\n' ' '))"
  else
    emit exec-unresolvable-denied PASS "unresolvable exec refused"
  fi
  # Same provocation against the file hook: a deny-list scope must not open what it cannot resolve.
  out=$(run_bee "$WORK/fs.toml" -- bash "$WORK/deep.sh" 2>&1)
  if echo "$out" | grep -q DESCENT_FAILED; then
    emit file-unresolvable-denied FAIL "descent broke — case proves nothing ($(echo "$out" | tr '\n' ' '))"
  elif echo "$out" | grep -q DEEPDATA; then
    emit file-unresolvable-denied FAIL "read of an unresolvable path succeeded"
  else
    emit file-unresolvable-denied PASS "unresolvable open refused"
  fi
fi
sudo rm -rf "$DEEP"

# ---------------------------------------------------- search tool: library search runs IN-scope
# The `search` tool execs `bee search-worker` (ripgrep as a library) through the sandbox, so its file
# opens are mediated by the LSM. Prove it: a deny policy over one subtree must make a secret there
# invisible to the search, while a sibling file outside the deny is found. If the library ran in the
# harness instead of the scoped worker, the deny would not apply and the secret would leak.
ST=/home/ubuntu/searchtest
sudo rm -rf "$ST"; mkdir -p "$ST/open" "$ST/denied"
echo "TOKEN-visible" | sudo tee "$ST/open/a.txt" >/dev/null
echo "TOKEN-hidden"  | sudo tee "$ST/denied/secret.txt" >/dev/null
cat >"$WORK/search.toml" <<EOF
[policy]
name = "search"
mode = "enforce"
[policy.filesystem]
"$ST/denied" = "deny"
EOF
out=$(run_bee "$WORK/search.toml" -- /home/ubuntu/bee search-worker --path "$ST" -- TOKEN)
if echo "$out" | grep -q "TOKEN-visible" && ! echo "$out" | grep -q "TOKEN-hidden"; then
  emit search-in-scope PASS "matched allowed file, denied file invisible to the library search"
else
  emit search-in-scope FAIL "out=$(echo "$out" | tr '\n' '|')"
fi
sudo rm -rf "$ST"

# ---------------------------------------------------- 012 f028/f026: tool child sheds escape caps
# The tool child must come out of pre_exec with no_new_privs set and every escape-enabling capability
# gone, even though the launcher ran as root with CAP_SYS_ADMIN. NO_NEW_PRIVS stops an `sh -c` from
# reaching a setuid binary (f028); the emptied bounding set stops it wielding CAP_SYS_ADMIN/CAP_BPF to
# detach bee's own LSM. The DAC pair (CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH == 0x6) is intentionally
# KEPT so file access still flows through the LSM hook rather than being pre-empted by DAC — see
# `drop_privileges`. So the expected bounding set is exactly 0x6, and CAP_SYS_ADMIN (bit 21) is clear.
out=$(run_bee "$WORK/exec.toml" -- cat /proc/self/status)
nnp=$(echo "$out" | awk '/^NoNewPrivs:/{print $2}')
capeff=$(echo "$out" | awk '/^CapEff:/{print $2}')
capbnd=$(echo "$out" | awk '/^CapBnd:/{print $2}')
# CAP_SYS_ADMIN is bit 21 → 0x200000. Both eff and bnd must have it clear and equal the DAC pair.
sysadmin_clear=$(( (0x${capeff} & 0x200000) == 0 ))
if [ "$nnp" = 1 ] && [ "$capbnd" = 0000000000000006 ] && [ "$capeff" = 0000000000000006 ] && [ "$sysadmin_clear" = 1 ]; then
  emit priv-drop PASS "NoNewPrivs=1 CapBnd=0x6 (DAC only, CAP_SYS_ADMIN gone)"
else
  emit priv-drop FAIL "NoNewPrivs=$nnp CapEff=$capeff CapBnd=$capbnd"
fi

# ---------------------------------------------------- 012 f026: enforcement follows a cgroup move
# The child's uid is still 0 and the scope cgroup is root-owned, so it can mkdir a sub-cgroup and
# migrate into it — which changes bpf_get_current_cgroup_id(). An exact-match LSM lookup would then
# miss and fail open. The ancestor walk must keep the denied read denied from the child cgroup.
cat >"$WORK/migrate.sh" <<'EOF'
set -u
# cgroup v2: /proc/self/cgroup is a single `0::<path>` line.
mine=$(sed -n 's/^0:::\?//p; s/^0:://p' /proc/self/cgroup | tail -1)
base="/sys/fs/cgroup$mine"
if mkdir -p "$base/sub" 2>/dev/null && echo $$ > "$base/sub/cgroup.procs" 2>/dev/null; then
  echo "MOVED_TO=$(sed -n 's/^0:://p' /proc/self/cgroup)"
else
  echo "MIGRATE_BLOCKED"
fi
cat /home/ubuntu/.ssh/secret.txt 2>&1
EOF
out=$(run_bee "$WORK/fs.toml" -- bash "$WORK/migrate.sh")
# Either the migration was blocked, or it succeeded and the read is STILL denied — both are safe.
# The failure is: it migrated AND the secret leaked (enforcement left behind at the old cgroup id).
if echo "$out" | grep -q TOP-SECRET; then
  emit cgroup-migrate-enforced FAIL "secret leaked after move: $(echo "$out" | tr '\n' ' ')"
elif echo "$out" | grep -q 'MOVED_TO='; then
  emit cgroup-migrate-enforced PASS "migrated to child cgroup, read still denied"
else
  emit cgroup-migrate-enforced PASS "migration blocked, read denied"
fi

# ---------------------------------------------------- 012 f022: teardown kills the whole subtree
# A backgrounded, redirected descendant outlives the direct child. bee must SIGKILL the scope
# cgroup before dropping the engine (which detaches the LSM programs) — otherwise the survivor keeps
# running unenforced. Verify no marker appears after bee exits and the scope cgroup is gone.
marker="$WORK/survived"
rm -f "$marker"
run_bee "$WORK/exec.toml" -- bash -c "(sleep 4; touch $marker) >/dev/null 2>&1 & echo LAUNCHED" >/dev/null 2>&1
sleep 6
if [ -e "$marker" ]; then
  emit teardown-kills-descendants FAIL "backgrounded descendant outlived the scope"
else
  emit teardown-kills-descendants PASS "descendant reaped at teardown"
fi

# ---------------------------------------------------------------- observe (dry-run) mode
cat >"$WORK/obs.toml" <<'EOF'
[policy]
name = "obs"
mode = "observe"
[policy.filesystem]
"/home/ubuntu/.ssh" = "deny"
EOF
out=$(run_bee "$WORK/obs.toml" -- cat /home/ubuntu/.ssh/secret.txt)
obs_audit=$(grep -c '"decision":"observed"' "$WORK/err")
if [ "$out" = "TOP-SECRET" ] && [ "$obs_audit" -ge 1 ]; then
  emit observe-mode PASS "allowed + $obs_audit observed events"
else
  emit observe-mode FAIL "out='$out' observed=$obs_audit"
fi

# ---------------------------------------------------------------- US2: subagent attenuation
cat >"$WORK/parent.toml" <<'EOF'
[policy]
name = "parent"
mode = "enforce"
[policy.network]
allow = ["1.1.1.1:443", "8.8.8.8:443"]
EOF
cat >"$WORK/child-ok.toml" <<'EOF'
[policy]
name = "child-ok"
mode = "enforce"
[policy.network]
allow = ["1.1.1.1:443"]
EOF
cat >"$WORK/child-bad.toml" <<'EOF'
[policy]
name = "child-bad"
mode = "enforce"
[policy.network]
allow = ["9.9.9.9:443"]
EOF

# An over-broad subagent (requests a dest the parent lacks) must be refused BEFORE running.
sudo "$BEE" exec --policy "$WORK/child-bad.toml" --parent "$WORK/parent.toml" -- true >/dev/null 2>"$WORK/err"
rc=$?
if [ "$rc" -ne 0 ] && grep -q 'attenuation violation' "$WORK/err"; then
  emit atten-reject PASS "over-broad subagent refused (rc=$rc)"
else
  emit atten-reject FAIL "rc=$rc (expected refusal)"
fi

# A subset subagent runs, enforcing its NARROWER policy: the parent allows 8.8.8.8 but the child
# dropped it, so under the child scope 8.8.8.8 is blocked while 1.1.1.1 (kept) still connects.
out=$(sudo "$BEE" exec --policy "$WORK/child-ok.toml" --parent "$WORK/parent.toml" -- bash -c 'curl -sS --max-time 8 -o /dev/null -w %{http_code} https://1.1.1.1' 2>/dev/null)
if connected "$out"; then emit atten-subset-allow PASS "child-kept dest connects (http=$out)"; else emit atten-subset-allow FAIL "http=$out"; fi
out=$(sudo "$BEE" exec --policy "$WORK/child-ok.toml" --parent "$WORK/parent.toml" -- bash -c 'curl -sS --max-time 8 -o /dev/null -w %{http_code} https://8.8.8.8' 2>/dev/null)
if [ "$out" = 000 ]; then emit atten-subset-deny PASS "parent-allowed but child-dropped dest blocked"; else emit atten-subset-deny FAIL "http=$out"; fi

# ---------------------------------------------------------------- per-scope isolation
# A process OUTSIDE any bee scope must be unaffected.
out=$(curl -sS --max-time 8 -o /dev/null -w %{http_code} https://8.8.8.8 2>/dev/null)
if connected "$out"; then emit scope-isolation PASS "host egress unaffected"; else emit scope-isolation FAIL "http=$out"; fi

# ---------------------------------------------------------------- US1 (002): LLM agent episode
# The load-bearing 002 check: a scripted (MockModel) episode whose tool call reads a policy-denied
# path returns a kernel EACCES, the denial appears in the transcript's audit trail, and the episode
# still ends `completed` (the agent ran; the *operation* was denied). Runs through `bee run`, the
# same single executable every other case uses.
if [ -x "$BEE" ]; then
  # episode-file-deny — read a denied path; expect EACCES in the tool result + a file_open denial.
  cat >"$WORK/ep-deny.policy.toml" <<'EOF'
[policy]
name = "ep-deny"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/.ssh" = "deny"
EOF
  cat >"$WORK/ep-deny.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "episode-file-deny"
policy_path   = "$WORK/ep-deny.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Read /home/ubuntu/.ssh/secret.txt and report it."
turn_limit    = 4
timeout_secs  = 30
tools         = ["read_file"]
EOF
  cat >"$WORK/ep-deny.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "read_file"
args = { path = "/home/ubuntu/.ssh/secret.txt" }
[[provider.script]]
text = "I could not read the file."
EOF
  sudo "$BEE" run --scenario "$WORK/ep-deny.scn.toml" --provider "$WORK/ep-deny.prov.toml" \
    --out "$WORK/ep-deny.json" >"$WORK/ep-deny.log" 2>&1
  t="$WORK/ep-deny.json"
  if [ -f "$t" ] \
     && ! grep -q 'TOP-SECRET' "$t" \
     && grep -q '"is_error": true' "$t" \
     && grep -Eq 'Permission denied|EACCES' "$t" \
     && grep -q '"op": "file_open"' "$t" \
     && grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t"; then
    emit episode-file-deny PASS "kernel EACCES surfaced in transcript; episode completed"
  else
    emit episode-file-deny FAIL "transcript did not show the denial ($(tail -1 "$WORK/ep-deny.log" 2>/dev/null))"
  fi

  # episode-allow — a permissive write in the workdir succeeds with no denials.
  mkdir -p /home/ubuntu/epwork
  cat >"$WORK/ep-allow.policy.toml" <<'EOF'
[policy]
name = "ep-allow"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/epwork" = "write"
EOF
  cat >"$WORK/ep-allow.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "episode-allow"
policy_path   = "$WORK/ep-allow.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Create a file in the working directory."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
EOF
  cat >"$WORK/ep-allow.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/epwork/out.txt", content = "hello from the agent\n" }
[[provider.script]]
text = "Done — file written."
EOF
  sudo "$BEE" run --scenario "$WORK/ep-allow.scn.toml" --provider "$WORK/ep-allow.prov.toml" \
    --out "$WORK/ep-allow.json" >"$WORK/ep-allow.log" 2>&1
  t="$WORK/ep-allow.json"
  if [ -f "$t" ] \
     && grep -q 'wrote .* bytes to /home/ubuntu/epwork/out.txt' "$t" \
     && ! grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t" \
     && [ "$(cat /home/ubuntu/epwork/out.txt 2>/dev/null)" = "hello from the agent" ]; then
    emit episode-allow PASS "in-scope write succeeded, no denials"
  else
    emit episode-allow FAIL "write/allow path failed ($(tail -1 "$WORK/ep-allow.log" 2>/dev/null))"
  fi
  rm -rf /home/ubuntu/epwork

  # -------------------------------------------------------------- 006-skills: Layer 2 grant fold
  # A/B proof that a skill's `requires` filesystem grant is compiled into and enforced by the real
  # kernel scope, bounded by attenuation. The SAME skill requests write to /home/ubuntu/skgrant; only
  # the scenario's ceiling differs. The base policy grants write elsewhere (arming the write-default-
  # deny latch) but NOT skgrant, so skgrant is writable iff the grant actually widened the scope.
  SKROOT="$WORK/skmatrix"
  mkdir -p "$SKROOT/builder" /home/ubuntu/skwork /home/ubuntu/skgrant
  cat >"$SKROOT/builder/SKILL.md" <<'EOF'
---
name: builder
description: needs write access to the build output directory
requires:
  filesystem:
    "/home/ubuntu/skgrant": write
---
Write build output under /home/ubuntu/skgrant.
EOF
  cat >"$WORK/sk-base.policy.toml" <<'EOF'
[policy]
name = "sk-base"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/skwork" = "write"
EOF
  cat >"$WORK/sk-ceiling.policy.toml" <<'EOF'
[policy]
name = "sk-ceiling"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/skwork" = "write"
"/home/ubuntu/skgrant" = "write"
EOF
  cat >"$WORK/sk.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/skgrant/out.txt", content = "built by the agent\n" }
[[provider.script]]
text = "Done."
EOF

  # skill-grant-allow — ceiling permits skgrant ⇒ within-ceiling grant folds into the scope ⇒ write OK.
  rm -f /home/ubuntu/skgrant/out.txt
  cat >"$WORK/sk-allow.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "skill-grant-allow"
policy_path   = "$WORK/sk-base.policy.toml"
ceiling_policy_path = "$WORK/sk-ceiling.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Write the build output."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
skills        = ["$SKROOT"]
EOF
  sudo "$BEE" run --scenario "$WORK/sk-allow.scn.toml" --provider "$WORK/sk.prov.toml" \
    --out "$WORK/sk-allow.json" >"$WORK/sk-allow.log" 2>&1
  t="$WORK/sk-allow.json"
  if [ -f "$t" ] \
     && grep -q 'wrote .* bytes to /home/ubuntu/skgrant/out.txt' "$t" \
     && ! grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t" \
     && [ "$(cat /home/ubuntu/skgrant/out.txt 2>/dev/null)" = "built by the agent" ]; then
    emit skill-grant-allow PASS "within-ceiling grant compiled into scope; write to skgrant allowed"
  else
    emit skill-grant-allow FAIL "granted path was not writable ($(tail -1 "$WORK/sk-allow.log" 2>/dev/null))"
  fi

  # skill-grant-deny — no ceiling (base is the ceiling) ⇒ skgrant grant exceeds it ⇒ refused ⇒ the
  # scope is NOT widened ⇒ the same write is kernel-denied (EACCES). Attenuation held at the kernel.
  rm -f /home/ubuntu/skgrant/out.txt
  cat >"$WORK/sk-deny.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "skill-grant-deny"
policy_path   = "$WORK/sk-base.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Write the build output."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
skills        = ["$SKROOT"]
EOF
  sudo "$BEE" run --scenario "$WORK/sk-deny.scn.toml" --provider "$WORK/sk.prov.toml" \
    --out "$WORK/sk-deny.json" >"$WORK/sk-deny.log" 2>&1
  t="$WORK/sk-deny.json"
  # NB: bee enforces writes via the `file_open` LSM hook, which fires AFTER `O_CREAT` has made the
  # empty inode — so a 0-byte file may exist; the load-bearing check is that the DATA never landed.
  if [ -f "$t" ] \
     && grep -q '"is_error": true' "$t" \
     && grep -Eq 'Permission denied|EACCES' "$t" \
     && grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t" \
     && [ "$(cat /home/ubuntu/skgrant/out.txt 2>/dev/null)" != "built by the agent" ]; then
    emit skill-grant-deny PASS "beyond-ceiling grant refused; write to skgrant kernel-denied (EACCES)"
  else
    emit skill-grant-deny FAIL "refused grant did not stay denied ($(tail -1 "$WORK/sk-deny.log" 2>/dev/null))"
  fi
  rm -rf /home/ubuntu/skwork /home/ubuntu/skgrant

  # -------------------------------------------------------------- 007-dynamic-grants: live reload
  # Reactive escalation A/B: the agent writes a path the base scope denies. With a ceiling that
  # permits it, the DenialEscalationHook grants write, `reload_scope` widens the LIVE eBPF maps, and
  # the SAME call is auto-retried and succeeds. With a ceiling that does NOT cover it, the grant is
  # refused and the write stays kernel-denied. Same op, only the ceiling differs — proving the live
  # reload changes what the kernel enforces mid-episode.
  mkdir -p /home/ubuntu/dynwork /home/ubuntu/dyngrant
  cat >"$WORK/dyn-base.policy.toml" <<'EOF'
[policy]
name = "dyn-base"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/dynwork" = "write"
EOF
  cat >"$WORK/dyn-ceiling.policy.toml" <<'EOF'
[policy]
name = "dyn-ceiling"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/dynwork" = "write"
"/home/ubuntu/dyngrant" = "write"
EOF
  cat >"$WORK/dyn.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/dyngrant/out.txt", content = "written after reload\n" }
[[provider.script]]
text = "Done."
EOF

  # reload-widen-allow — ceiling permits dyngrant ⇒ denial → escalate → reload → retry writes data.
  rm -f /home/ubuntu/dyngrant/out.txt
  cat >"$WORK/dyn-allow.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "reload-widen-allow"
policy_path   = "$WORK/dyn-base.policy.toml"
ceiling_policy_path = "$WORK/dyn-ceiling.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Write the output."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
EOF
  sudo "$BEE" run --scenario "$WORK/dyn-allow.scn.toml" --provider "$WORK/dyn.prov.toml" \
    --out "$WORK/dyn-allow.json" >"$WORK/dyn-allow.log" 2>&1
  t="$WORK/dyn-allow.json"
  # A denial must appear (the first attempt) AND the data must ultimately land (the retry).
  if [ -f "$t" ] \
     && grep -q '"op": "file_open"' "$t" \
     && grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t" \
     && [ "$(cat /home/ubuntu/dyngrant/out.txt 2>/dev/null)" = "written after reload" ]; then
    emit reload-widen-allow PASS "denial → escalate → live reload → retry wrote data"
  else
    emit reload-widen-allow FAIL "reactive reload did not permit the retried write ($(tail -1 "$WORK/dyn-allow.log" 2>/dev/null))"
  fi

  # reload-beyond-ceiling — ceiling omits dyngrant ⇒ escalation refused ⇒ write stays denied.
  rm -f /home/ubuntu/dyngrant/out.txt
  cat >"$WORK/dyn-deny.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "reload-beyond-ceiling"
policy_path   = "$WORK/dyn-base.policy.toml"
ceiling_policy_path = "$WORK/dyn-base.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Write the output."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
EOF
  sudo "$BEE" run --scenario "$WORK/dyn-deny.scn.toml" --provider "$WORK/dyn.prov.toml" \
    --out "$WORK/dyn-deny.json" >"$WORK/dyn-deny.log" 2>&1
  t="$WORK/dyn-deny.json"
  if [ -f "$t" ] \
     && grep -q '"decision": "denied"' "$t" \
     && grep -q '"status": "completed"' "$t" \
     && [ "$(cat /home/ubuntu/dyngrant/out.txt 2>/dev/null)" != "written after reload" ]; then
    emit reload-beyond-ceiling PASS "beyond-ceiling escalation refused; write stayed kernel-denied"
  else
    emit reload-beyond-ceiling FAIL "refused escalation did not stay denied ($(tail -1 "$WORK/dyn-deny.log" 2>/dev/null))"
  fi

  # ------------------------------------------- 024 FR-042: a lease that runs out narrows the kernel
  # lease-expiry — the same denial → escalate → retry, but the grant lasts one model turn
  # (`lease_turns = 1`). Turn 0 writes (denied, granted, retried). At the start of turn 1 the lease
  # expires and the scope is reloaded narrower, so turn 1's identical write is denied by the kernel
  # again before it is re-escalated. Without expiry the second write succeeds first time and the
  # transcript holds one denied attempt, not two.
  cat >"$WORK/lease.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/dyngrant/out.txt", content = "turn 0\n" }
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/dyngrant/out.txt", content = "turn 1\n" }
[[provider.script]]
text = "Done."
EOF
  rm -f /home/ubuntu/dyngrant/out.txt
  cat >"$WORK/lease.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "lease-expiry"
policy_path   = "$WORK/dyn-base.policy.toml"
ceiling_policy_path = "$WORK/dyn-ceiling.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Write the output twice."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
lease_turns   = 1
EOF
  sudo "$BEE" run --scenario "$WORK/lease.scn.toml" --provider "$WORK/lease.prov.toml" \
    --out "$WORK/lease.json" >"$WORK/lease.log" 2>&1
  t="$WORK/lease.json"
  denied_attempts=$(grep -c '"denied_attempt_audit"' "$t" 2>/dev/null || echo 0)
  if [ -f "$t" ] \
     && grep -q 'lease expired: g0' "$WORK/lease.log" \
     && [ "$denied_attempts" -eq 2 ] \
     && [ "$(cat /home/ubuntu/dyngrant/out.txt 2>/dev/null)" = "turn 1" ]; then
    emit lease-expiry PASS "lease expired at turn 1; the kernel denied the same write again"
  else
    emit lease-expiry FAIL "denied attempts=$denied_attempts; $(grep -o 'lease expired[^"]*' "$WORK/lease.log" | head -1)"
  fi

  # lease-release — the same two writes, but the grant does not expire: a `Deescalate` hook releases
  # it at the top of turn 1 (024 SC-010). The hook is the vm-test build's `VmReleaseHook`, set by
  # `BEE_VM_RELEASE_LEASE`. After the release the scope is reloaded narrower, so turn 1's write is
  # kernel-denied again before it is re-escalated. Without the release it succeeds first time.
  sed -e 's/^id .*/id            = "lease-release"/' -e '/^lease_turns/d' \
    "$WORK/lease.scn.toml" >"$WORK/release.scn.toml"
  rm -f /home/ubuntu/dyngrant/out.txt
  sudo env BEE_VM_RELEASE_LEASE=1:g0 "$BEE" run --scenario "$WORK/release.scn.toml" \
    --provider "$WORK/lease.prov.toml" --out "$WORK/release.json" >"$WORK/release.log" 2>&1
  t="$WORK/release.json"
  denied_attempts=$(grep -c '"denied_attempt_audit"' "$t" 2>/dev/null || echo 0)
  if [ -f "$t" ] \
     && grep -q 'lease released: g0' "$WORK/release.log" \
     && ! grep -q 'lease expired' "$WORK/release.log" \
     && [ "$denied_attempts" -eq 2 ] \
     && [ "$(cat /home/ubuntu/dyngrant/out.txt 2>/dev/null)" = "turn 1" ]; then
    emit lease-release PASS "lease released at turn 1; the kernel denied the same write again"
  else
    emit lease-release FAIL "denied attempts=$denied_attempts; $(grep -o 'lease [a-z]*: [^"]*' "$WORK/release.log" | head -1)"
  fi
  rm -rf /home/ubuntu/dynwork /home/ubuntu/dyngrant
else
  emit episode-file-deny FAIL "bee not shipped to $BEE"
fi

# ---------------------------------------------------- 016 T068: the scanner child runs IN-scope
# `scan` spawns a third-party binary and then `bee sarif-worker` over the report it wrote. The claim
# the whole external tier rests on is that the *scanner* is a tool child like any other — inside the
# episode's kernel scope, not beside it. If it ran in the harness it would read whatever root can
# read, and its report would be a channel out of the sandbox straight into the ledger.
#
# The probe stands in for Opengrep: bee reaches it through the pinned grant and the real adapter
# argv, and it reports what it managed to read back through the SARIF it writes, so an escape would
# arrive as a finding title. A stand-in is the right instrument — what is under test is the seam bee
# owns (grant → pinned exec → scope → report → ledger), not Opengrep's rule engine. It must be
# *named* `opengrep`, because a grant is matched by file name against the known adapters.
#
# The false-PASS trap this case has to dodge: nearly every way the pipeline can fail to run at all
# also produces no leaked secret. So the control run comes first — the same probe under a policy
# that does not deny the secret MUST leak it. If it does not, the enforced result proves nothing and
# the case reports FAIL rather than a green tick.
if [ -x "$BEE" ]; then
  SCAN=/home/ubuntu/scantest
  sudo rm -rf "$SCAN"; mkdir -p "$SCAN/bin" "$SCAN/proj" "$SCAN/target"
  echo "print('hello')" >"$SCAN/target/app.py"
  # NOT `~/.ssh`: that is a *default* protection in every compiled policy (PROTECTED_DEFAULTS), so a
  # probe could never read it even in the control run, and the case would report "no control" forever.
  # The loot has to be somewhere only this policy's deny covers.
  sudo rm -rf /home/ubuntu/scanloot; mkdir -p /home/ubuntu/scanloot
  echo LOOT-TOP-SECRET >/home/ubuntu/scanloot/loot.txt
  printf 'rules: []\n' >"$SCAN/rules.yaml"

  # Builtins only. The exec allowlist is bee + bash + the probe; a `cat` or a `sed` in here would be
  # refused by the exec hook and the case would fail for a reason that has nothing to do with T068.
  cat >"$SCAN/bin/opengrep" <<'PROBE'
#!/bin/bash
# Stands in for: opengrep scan --sarif --sarif-output=<file> --quiet --config <rules> --timeout N <target>
out=
for a in "$@"; do case "$a" in --sarif-output=*) out=${a#--sarif-output=} ;; esac; done
[ -n "$out" ] || exit 3
secret=
# No `2>/dev/null` here, deliberately: the policy declares a write grant, so unlisted writes are
# denied by default — and `/dev/null` is unlisted. Suppressing stderr would itself fail, take the
# whole compound command with it, and leave `secret` empty for a reason that has nothing to do with
# the read under test. bee keeps the child's stderr apart from its stdout anyway.
read -r secret < "/home/ubuntu/scanloot/loot.txt" || secret=
if [ -n "$secret" ]; then msg="ESCAPED $secret"; else msg="REFUSED the out-of-scope read"; fi
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep","rules":[{"id":"probe","defaultConfiguration":{"level":"error"}}]}},"invocations":[{"executionSuccessful":true}],"results":[{"ruleId":"probe","message":{"text":"%s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":1,"snippet":{"text":"probe"}}}}]}]}]}' "$msg" >"$out"
PROBE
  chmod +x "$SCAN/bin/opengrep"

  cat >"$WORK/scan.prov.toml" <<EOF
[provider]
provider = "mock"
[[provider.script]]
tool = "scan"
args = { scanner = "opengrep", target = "$SCAN/target" }
[[provider.script]]
text = "Scanned."
EOF

  # Two policies differing in exactly one line: whether the secret is denied. Everything else — the
  # pinned grant, the exec allowlist, the writable project — is identical, so the difference in
  # outcome can only be the kernel's answer to the scanner child's open.
  # The exec surface: the scanner, bee itself (child 2 is `bee sarif-worker`, and nothing grants it
  # implicitly), and bash for the stand-in's shebang. Both real programs are pinned; only the
  # interpreter is admitted by name.
  scan_policy() { # file  deny_secret(0|1)
    cat >"$1" <<EOF
[policy]
name = "scan-escape"
mode = "enforce"
[policy.filesystem]
"$SCAN" = "write"
EOF
    [ "$2" = 1 ] && echo '"/home/ubuntu/scanloot" = "deny"' >>"$1"
    cat >>"$1" <<EOF
[policy.exec]
allow = ["!$SCAN/bin/opengrep", "!$BEE", "bash"]
EOF
  }
  scan_scenario() { # file  policy
    cat >"$1" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "scanner-escape"
policy_path   = "$2"
system_prompt = "You are a sandboxed agent."
task          = "Scan the target."
turn_limit    = 4
timeout_secs  = 60
tools         = ["scan"]

[security.scanners.opengrep]
rules = "$SCAN/rules.yaml"
EOF
  }
  # The report path and the ledger are both relative to the harness cwd, so each run gets its own.
  run_scan() { # workdir  policy  logname
    rm -rf "$SCAN/$1"; mkdir -p "$SCAN/$1"
    ( cd "$SCAN/$1" && sudo "$BEE" run --scenario "$WORK/$3.scn.toml" \
        --provider "$WORK/scan.prov.toml" --out "$WORK/$3.json" ) >"$WORK/$3.log" 2>&1
  }
  ledger_of() { cat "$SCAN/$1/.bee/findings/ledger.jsonl" 2>/dev/null; }

  scan_policy "$WORK/scan-open.policy.toml" 0
  scan_scenario "$WORK/scan-open.scn.toml" "$WORK/scan-open.policy.toml"
  run_scan open "$WORK/scan-open.policy.toml" scan-open

  scan_policy "$WORK/scan-deny.policy.toml" 1
  scan_scenario "$WORK/scan-deny.scn.toml" "$WORK/scan-deny.policy.toml"
  run_scan deny "$WORK/scan-deny.policy.toml" scan-deny

  if ! ledger_of open | grep -q 'ESCAPED LOOT-TOP-SECRET'; then
    # No control, no case: the probe never reached the secret even when nothing forbade it, so the
    # denied run's silence says nothing about enforcement.
    emit scanner-escape-denied FAIL "control run did not leak — probe never ran or never read ($(tail -1 "$WORK/scan-open.log" 2>/dev/null))"
  elif ! ledger_of deny | grep -q 'REFUSED the out-of-scope read'; then
    emit scanner-escape-denied FAIL "enforced run recorded no finding — pipeline did not complete ($(tail -1 "$WORK/scan-deny.log" 2>/dev/null))"
  elif ledger_of deny | grep -q 'LOOT-TOP-SECRET'; then
    emit scanner-escape-denied FAIL "secret reached the ledger: the scanner read outside the scope"
  elif ! grep -q '"status": "completed"' "$WORK/scan-deny.json" 2>/dev/null; then
    emit scanner-escape-denied FAIL "episode did not complete ($(tail -1 "$WORK/scan-deny.log" 2>/dev/null))"
  else
    emit scanner-escape-denied PASS "granted scanner ran in-scope; its out-of-scope read was refused (control run leaked)"
  fi
  sudo rm -rf "$SCAN" /home/ubuntu/scanloot
else
  emit scanner-escape-denied FAIL "bee not shipped to $BEE"
fi

# ---------------------------------------------------------------- US4: concurrent audit isolation
# Four episodes run concurrently (--batch --concurrent), each in its OWN scope, each reading a
# DISTINCT policy-denied path. The async audit demux routes events by cgroup_id, so each transcript
# must contain ONLY its own denial and none of the others' (SC-004 / US4 AS-1). Requires a `bee`
# built with `--features concurrent`; a plain enforce build SKIPs this case.
if [ -x "$BEE" ]; then
  ISO=/home/ubuntu/iso
  rm -rf "$ISO"; mkdir -p "$ISO"
  for i in 1 2 3 4; do echo "SECRET$i" >"$ISO/secret$i.txt"; done
  cat >"$WORK/iso.policy.toml" <<'EOF'
[policy]
name = "iso"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/iso" = "deny"
EOF
  mkdir -p "$WORK/iso-scn" "$WORK/iso-prov"
  cat >"$WORK/iso-scn/iso.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "iso"
policy_path   = "$WORK/iso.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Read the assigned secret."
turn_limit    = 4
timeout_secs  = 30
tools         = ["read_file"]
EOF
  for i in 1 2 3 4; do
    cat >"$WORK/iso-prov/m$i.toml" <<EOF
[provider]
provider = "mock"
model    = "m$i"
[[provider.script]]
tool = "read_file"
args = { path = "/home/ubuntu/iso/secret$i.txt" }
[[provider.script]]
text = "done"
EOF
  done
  sudo "$BEE" run --batch --concurrent \
    --scenarios "$WORK/iso-scn/iso.scn.toml" --providers "$WORK/iso-prov" \
    --out "$WORK/iso-out" --quiet >"$WORK/iso.log" 2>&1
  if grep -q 'requires building with --features concurrent' "$WORK/iso.log"; then
    echo "RESULT|concurrent-audit-isolation|SKIP|bee built without --features concurrent"
  else
    ok=1; note="ok"
    for i in 1 2 3 4; do
      t="$WORK/iso-out/iso_mock_m$i.json"
      if [ ! -f "$t" ]; then ok=0; note="missing transcript for ep $i"; break; fi
      if ! grep -q "/home/ubuntu/iso/secret$i.txt" "$t"; then ok=0; note="ep $i missing its own denial"; break; fi
      for j in 1 2 3 4; do
        [ "$j" = "$i" ] && continue
        if grep -q "secret$j.txt" "$t"; then ok=0; note="ep $i leaked secret$j (cross-contamination)"; break 2; fi
      done
    done
    if [ "$ok" = 1 ]; then
      emit concurrent-audit-isolation PASS "4 concurrent scopes, no cgroup cross-contamination"
    else
      emit concurrent-audit-isolation FAIL "$note"
    fi
  fi
  rm -rf "$ISO"
else
  echo "RESULT|concurrent-audit-isolation|SKIP|no bee at $BEE"
fi

# ------------------------------------------------- 018 SC-007: reload under concurrency
# Two scenarios run concurrently on one supervisor, each episode in its own scope, both writing a
# path their base policy denies. Scenario A's ceiling covers it: denial → escalate → reload of A's
# scope → retry writes. Scenario B's ceiling does not: its write stays kernel-denied even though A's
# scope was widened beside it. Before 018 a concurrent batch refused a ceiling outright (the runner
# owned the engine, so no episode could reload), and both episodes ended as setup errors.
if [ -x "$BEE" ]; then
  CR=/home/ubuntu/creload
  sudo rm -rf "$CR"; mkdir -p "$CR/work" "$CR/grant" "$WORK/cr-scn" "$WORK/cr-prov"
  rm -rf "$WORK/cr-out"
  cat >"$WORK/cr-base.policy.toml" <<'EOF'
[policy]
name = "cr-base"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/creload/work" = "write"
EOF
  cat >"$WORK/cr-ceiling.policy.toml" <<'EOF'
[policy]
name = "cr-ceiling"
mode = "enforce"
[policy.filesystem]
"/home/ubuntu/creload/work" = "write"
"/home/ubuntu/creload/grant" = "write"
EOF
  for x in a b; do
    if [ "$x" = a ]; then ceil="$WORK/cr-ceiling.policy.toml"; else ceil="$WORK/cr-base.policy.toml"; fi
    cat >"$WORK/cr-scn/cr-$x.scn.toml" <<EOF
[scenario]
finish        = false  # 025: these cases pin the pre-finish ending ("completed")
id            = "cr-$x"
policy_path   = "$WORK/cr-base.policy.toml"
ceiling_policy_path = "$ceil"
system_prompt = "You are a sandboxed agent."
task          = "Write the output."
turn_limit    = 4
timeout_secs  = 30
tools         = ["write_file"]
EOF
  done
  cat >"$WORK/cr-prov/m.toml" <<'EOF'
[provider]
provider = "mock"
model    = "m"
[[provider.script]]
tool = "write_file"
args = { path = "/home/ubuntu/creload/grant/out.txt", content = "written after reload\n" }
[[provider.script]]
text = "Done."
EOF
  sudo "$BEE" run --batch --concurrent \
    --scenarios "$WORK/cr-scn" --providers "$WORK/cr-prov" \
    --out "$WORK/cr-out" --quiet >"$WORK/cr.log" 2>&1
  a="$WORK/cr-out/cr-a_mock_m.json"; b="$WORK/cr-out/cr-b_mock_m.json"
  if grep -q 'requires building with --features concurrent' "$WORK/cr.log"; then
    echo "RESULT|concurrent-reload|SKIP|bee built without --features concurrent"
  elif [ ! -f "$a" ] || [ ! -f "$b" ]; then
    emit concurrent-reload FAIL "missing transcript ($(tail -1 "$WORK/cr.log" 2>/dev/null))"
  elif ! grep -q '"status": "completed"' "$a" || ! grep -q '"decision": "granted"' "$a"; then
    emit concurrent-reload FAIL "episode A did not escalate to completion ($(grep -o '"detail": "[^"]*"' "$a" | head -1))"
  elif [ "$(cat "$CR/grant/out.txt" 2>/dev/null)" != "written after reload" ]; then
    emit concurrent-reload FAIL "A's grant did not reach the kernel: the retried write was not written"
  elif grep -q '"decision": "granted"' "$b" || ! grep -q '"decision": "denied"' "$b"; then
    emit concurrent-reload FAIL "B was widened or never denied: a reload crossed scopes"
  else
    emit concurrent-reload PASS "A's scope reloaded mid-run under concurrency; B's stayed denied"
  fi
  sudo rm -rf "$CR"
else
  echo "RESULT|concurrent-reload|SKIP|no bee at $BEE"
fi

# ------------------------------------------- 018 US1: a subagent is denied what its parent holds
# The session may connect to two local listeners, A and B. Its `netprobe` agent declares only A. The
# scripted model delegates; the child tries both (the bash tool runs dash, which has no /dev/tcp, so
# the probe is a Python connect), then finishes; the parent then connects to B
# itself. B must be kernel-denied to the child — recorded in the child's own transcript, stamped with
# the child's scope id — and reachable for the parent, whose own record has no denial at all.
if [ -x "$BEE" ]; then
  SA=/home/ubuntu/subagent
  sudo rm -rf "$SA"; mkdir -p "$SA/skills/netprobe" "$SA/work"
  python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 & LA=$!
  python3 -m http.server 18082 --bind 127.0.0.1 >/dev/null 2>&1 & LB=$!
  sleep 1
  cat >"$SA/skills/netprobe/SKILL.md" <<'EOF'
---
name: netprobe
kind: agent
description: Probes local listeners.
tools: [bash]
turn-limit: 3
requires:
  net: ["127.0.0.1:18081"]
---
Probe the listeners you are asked about and report what you reached.
EOF
  cat >"$WORK/sa.policy.toml" <<'EOF'
[policy]
name = "sa"
mode = "enforce"
[policy.network]
allow = ["127.0.0.1:18081", "127.0.0.1:18082"]
EOF
  cat >"$WORK/sa.scn.toml" <<EOF
[scenario]
finish        = false  # the parent ends on text; the child is always offered finish
id            = "subagent-net"
policy_path   = "$WORK/sa.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Delegate the probe, then probe B yourself."
turn_limit    = 4
timeout_secs  = 60
tools         = ["task", "bash"]
skills        = ["$SA/skills"]
EOF
  cat >"$WORK/sa.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "task"
args = { agent = "netprobe", prompt = "Probe 127.0.0.1:18081 and 127.0.0.1:18082." }
[[provider.script]]
tool = "bash"
args = { command = "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 18081), 3)' && echo CHILD-A-OPEN || echo CHILD-A-SHUT; python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 18082), 3)' && echo CHILD-B-OPEN || echo CHILD-B-SHUT" }
[[provider.script]]
tool = "finish"
args = { outcome = "completed", summary = "probed both" }
[[provider.script]]
tool = "bash"
args = { command = "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 18082), 3)' && echo PARENT-B-OPEN || echo PARENT-B-SHUT" }
[[provider.script]]
text = "Done."
EOF
  (cd "$SA/work" && sudo "$BEE" run --scenario "$WORK/sa.scn.toml" --provider "$WORK/sa.prov.toml" \
    --out "$WORK/sa.json" >"$WORK/sa.log" 2>&1)
  kill "$LA" "$LB" 2>/dev/null
  verdict=$(python3 - "$WORK/sa.json" <<'PY' 2>&1
import json, sys
try:
    t = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"no transcript: {e}"); sys.exit()
calls = [c for turn in t.get("turns", []) for c in turn.get("calls", [])]
task = next((c for c in calls if c["call"]["name"] == "task"), None)
child = (task or {}).get("child") or {}
ct = child.get("transcript") or {}
def outputs(tr):
    # Tool results only: the markers also appear in the recorded commands themselves.
    return "\n".join(c["result"]["content"] for turn in tr.get("turns", []) for c in turn.get("calls", []))
child_out = outputs(ct)
parent_out = "\n".join(c["result"]["content"] for c in calls if c["call"]["name"] != "task")
den = [e for e in ct.get("audit_trail", []) if e["decision"] == "denied" and e["op"] == "connect"]
parent_den = [e for e in t.get("audit_trail", []) if e["decision"] == "denied"]
checks = {
    "child enforced": child.get("enforced") is True,
    "child completed": (child.get("outcome") or {}).get("kind") == "completed",
    "child reached A": "CHILD-A-OPEN" in child_out,
    "child shut out of B": "CHILD-B-SHUT" in child_out and "CHILD-B-OPEN" not in child_out,
    "B denial in the child's record": any("18082" in e.get("target", "") for e in den),
    "child denials stamped with its scope": bool(den) and all(e.get("scope_id") == child.get("scope_id") for e in den),
    "parent reached B": "PARENT-B-OPEN" in parent_out and "PARENT-B-SHUT" not in parent_out,
    "no denial in the parent's record": not parent_den,
}
bad = [k for k, v in checks.items() if not v]
print("OK" if not bad else "failed: " + ", ".join(bad))
PY
)
  if [ "$verdict" = OK ]; then
    emit subagent-net-denied PASS "child kernel-denied B (its own record, its scope); parent reached B"
  else
    emit subagent-net-denied FAIL "$verdict ($(tail -1 "$WORK/sa.log" 2>/dev/null))"
  fi
  sudo rm -rf "$SA"
else
  echo "RESULT|subagent-net-denied|SKIP|no bee at $BEE"
fi

# --------------------------------------- 018 US2: an over-broad agent is refused before any scope
# The agent asks for a destination its session does not hold. The delegation must be refused with
# the rule named, and no subagent cgroup may ever have existed: the refusal comes before creation.
if [ -x "$BEE" ]; then
  OG=/home/ubuntu/overgrant
  sudo rm -rf "$OG"; mkdir -p "$OG/skills/greedy" "$OG/work"
  cat >"$OG/skills/greedy/SKILL.md" <<'EOF'
---
name: greedy
kind: agent
description: Wants more than it may have.
tools: []
turn-limit: 2
requires:
  net: ["127.0.0.1:18099"]
---
Reach the listener.
EOF
  cat >"$WORK/og.policy.toml" <<'EOF'
[policy]
name = "og"
mode = "enforce"
[policy.network]
allow = ["127.0.0.1:18081"]
EOF
  cat >"$WORK/og.scn.toml" <<EOF
[scenario]
finish        = false
id            = "subagent-overgrant"
policy_path   = "$WORK/og.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Delegate."
turn_limit    = 3
timeout_secs  = 30
tools         = ["task"]
skills        = ["$OG/skills"]
EOF
  cat >"$WORK/og.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "task"
args = { agent = "greedy", prompt = "Reach it." }
[[provider.script]]
text = "Done."
EOF
  # Watch for any subagent cgroup while the episode runs, not just after it.
  ( for _ in $(seq 1 200); do ls /sys/fs/cgroup/bee 2>/dev/null | grep -- '-sub-' ; sleep 0.05; done ) >"$WORK/og.cg" 2>/dev/null & W=$!
  (cd "$OG/work" && sudo "$BEE" run --scenario "$WORK/og.scn.toml" --provider "$WORK/og.prov.toml" \
    --out "$WORK/og.json" >"$WORK/og.log" 2>&1)
  wait "$W" 2>/dev/null
  if [ ! -f "$WORK/og.json" ]; then
    emit subagent-overgrant-no-cgroup FAIL "no transcript ($(tail -1 "$WORK/og.log" 2>/dev/null))"
  elif ! grep -q 'REFUSED' "$WORK/og.json" || ! grep -q '127.0.0.1:18099' "$WORK/og.json"; then
    emit subagent-overgrant-no-cgroup FAIL "delegation was not refused naming the destination"
  elif [ -s "$WORK/og.cg" ]; then
    emit subagent-overgrant-no-cgroup FAIL "a subagent cgroup existed: $(head -1 "$WORK/og.cg")"
  else
    emit subagent-overgrant-no-cgroup PASS "refused naming 127.0.0.1:18099; no subagent cgroup ever appeared"
  fi
  sudo rm -rf "$OG"
else
  echo "RESULT|subagent-overgrant-no-cgroup|SKIP|no bee at $BEE"
fi

# ------------------------------------------- 018 US5: siblings run together and stay apart
# One turn delegates to three agents at once. The session may read all three files; each agent
# denies itself the other two. All three children run the same command (one turn each, so which
# scripted step a child takes cannot matter) — what each may read comes from its own scope alone.
# Each must read its own file, be kernel-denied the other two, with those denials in its own record
# and stamped with its own scope, and the parent's record must hold none of them.
if [ -x "$BEE" ]; then
  SB=/home/ubuntu/siblings
  sudo rm -rf "$SB"; mkdir -p "$SB/data" "$SB/skills" "$SB/work"
  for x in a b c; do echo "SECRET-$x" >"$SB/data/$x.txt"; done
  for x in a b c; do
    others=$(for y in a b c; do [ "$y" = "$x" ] || printf '    %s: deny\n' "$SB/data/$y.txt"; done)
    mkdir -p "$SB/skills/sib-$x"
    cat >"$SB/skills/sib-$x/SKILL.md" <<EOF
---
name: sib-$x
kind: agent
description: Reads file $x only.
tools: [bash]
turn-limit: 1
requires:
  filesystem:
$others
---
Read the files you are asked to.
EOF
  done
  cat >"$WORK/sib.policy.toml" <<EOF
[policy]
name = "sib"
mode = "enforce"
[policy.filesystem]
"$SB/data" = "read"
EOF
  cat >"$WORK/sib.scn.toml" <<EOF
[scenario]
finish        = false
id            = "subagent-siblings"
policy_path   = "$WORK/sib.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Fan out."
turn_limit    = 10
timeout_secs  = 60
tools         = ["task", "bash"]
skills        = ["$SB/skills"]
EOF
  probe="cat $SB/data/a.txt; cat $SB/data/b.txt; cat $SB/data/c.txt; true"
  {
    echo '[provider]'
    echo 'provider = "mock"'
    echo '[[provider.script]]'
    echo 'calls = ['
    for x in a b c; do echo "  { tool = \"task\", args = { agent = \"sib-$x\", prompt = \"Read the files.\" } },"; done
    echo ']'
    for _ in 1 2 3; do
      echo '[[provider.script]]'
      echo 'tool = "bash"'
      echo "args = { command = \"$probe\" }"
    done
    echo '[[provider.script]]'
    echo 'text = "Done."'
  } >"$WORK/sib.prov.toml"
  (cd "$SB/work" && sudo "$BEE" run --scenario "$WORK/sib.scn.toml" --provider "$WORK/sib.prov.toml" \
    --out "$WORK/sib.json" >"$WORK/sib.log" 2>&1)
  verdict=$(python3 - "$WORK/sib.json" "$SB/data" <<'PY' 2>&1
import json, sys
try:
    t = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"no transcript: {e}"); sys.exit()
data = sys.argv[2]
calls = [c for turn in t.get("turns", []) for c in turn.get("calls", []) if c["call"]["name"] == "task"]
problems = []
if len(calls) != 3:
    problems.append(f"{len(calls)} task calls")
scopes = set()
for c in calls:
    ch = c.get("child") or {}
    agent = ch.get("agent", "?"); me = agent[-1:]
    ct = ch.get("transcript") or {}
    out = "\n".join(k["result"]["content"] for turn in ct.get("turns", []) for k in turn.get("calls", []))
    den = [e for e in ct.get("audit_trail", []) if e["decision"] == "denied" and e["op"] == "file_open"]
    denied = sorted(e["target"].rsplit("/", 1)[-1] for e in den)
    others = sorted(f"{y}.txt" for y in "abc" if y != me)
    if not ch.get("enforced"): problems.append(f"{agent} unenforced")
    if f"SECRET-{me}" not in out: problems.append(f"{agent} could not read its own file")
    for y in "abc":
        if y != me and f"SECRET-{y}" in out: problems.append(f"{agent} read {y}.txt")
    if sorted(set(denied)) != others: problems.append(f"{agent} denials {denied} != {others}")
    if any(e.get("scope_id") != ch.get("scope_id") for e in den): problems.append(f"{agent} denial under another scope")
    scopes.add(ch.get("scope_id"))
if len(scopes) != 3: problems.append(f"scopes not distinct: {scopes}")
if any(e["decision"] == "denied" for e in t.get("audit_trail", [])): problems.append("a denial in the parent's record")
print("OK" if not problems else "; ".join(problems))
PY
)
  if [ "$verdict" = OK ]; then
    emit subagent-siblings-isolated PASS "3 siblings in one turn: each read only its own file; denials in its own record and scope"
  else
    emit subagent-siblings-isolated FAIL "$verdict ($(tail -1 "$WORK/sib.log" 2>/dev/null))"
  fi
  sudo rm -rf "$SB"
else
  echo "RESULT|subagent-siblings-isolated|SKIP|no bee at $BEE"
fi

# ------------------------------------------- 018 US7: a subagent widens within its parent, no further
# The `writer` agent asks only for its work directory and then writes to a grant directory. Both runs
# share a session ceiling that covers the grant directory; they differ only in whether the PARENT
# holds it when it spawns the child. Holding it, the child's kernel denial escalates to a grant —
# decided by the session's one operator and recorded as the subagent's — its own scope is reloaded,
# and the retried write lands. Not holding it, the request is refused beyond the child's ceiling
# without being offered, although the session ceiling would allow it (FR-015), and the write stays
# kernel-denied. Same child, same op; only the parent's authority at spawn differs.
if [ -x "$BEE" ]; then
  SE=/home/ubuntu/subesc
  sudo rm -rf "$SE"; mkdir -p "$SE/skills/writer" "$SE/work" "$SE/grant"
  cat >"$SE/skills/writer/SKILL.md" <<EOF
---
name: writer
kind: agent
description: Writes the output.
tools: [write_file]
turn-limit: 3
requires:
  filesystem:
    "$SE/work": write
---
Write the output you are asked for.
EOF
  cat >"$WORK/se-ceiling.policy.toml" <<EOF
[policy]
name = "se-ceiling"
mode = "enforce"
[policy.filesystem]
"$SE/work" = "write"
"$SE/grant" = "write"
EOF
  cat >"$WORK/se-held.policy.toml" <<EOF
[policy]
name = "se-held"
mode = "enforce"
[policy.filesystem]
"$SE/work" = "write"
"$SE/grant" = "write"
EOF
  cat >"$WORK/se-unheld.policy.toml" <<EOF
[policy]
name = "se-unheld"
mode = "enforce"
[policy.filesystem]
"$SE/work" = "write"
EOF
  cat >"$WORK/se.prov.toml" <<EOF
[provider]
provider = "mock"
[[provider.script]]
tool = "task"
args = { agent = "writer", prompt = "Write the output." }
[[provider.script]]
tool = "write_file"
args = { path = "$SE/grant/out.txt", content = "written by the subagent\n" }
[[provider.script]]
tool = "finish"
args = { outcome = "completed", summary = "wrote it" }
[[provider.script]]
text = "Done."
EOF
  se_run() { # <case> <base policy>
    rm -f "$SE/grant/out.txt"
    cat >"$WORK/$1.scn.toml" <<EOF
[scenario]
finish        = false
id            = "$1"
policy_path   = "$2"
ceiling_policy_path = "$WORK/se-ceiling.policy.toml"
system_prompt = "You are a sandboxed agent."
task          = "Delegate the write."
turn_limit    = 4
timeout_secs  = 60
tools         = ["task", "write_file"]
skills        = ["$SE/skills"]
EOF
    (cd "$SE/work" && sudo "$BEE" run --scenario "$WORK/$1.scn.toml" --provider "$WORK/se.prov.toml" \
      --out "$WORK/$1.json" >"$WORK/$1.log" 2>&1)
    python3 - "$WORK/$1.json" "$3" "$(cat "$SE/grant/out.txt" 2>/dev/null)" <<'PY' 2>&1
import json, sys
path, want, written = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    t = json.load(open(path))
except Exception as e:
    print(f"no transcript: {e}"); sys.exit()
calls = [c for turn in t.get("turns", []) for c in turn.get("calls", [])]
task = next((c for c in calls if c["call"]["name"] == "task"), None)
child = (task or {}).get("child") or {}
ct = child.get("transcript") or {}
den = [e for e in ct.get("audit_trail", []) if e["decision"] == "denied" and e["op"] == "file_open"]
consents = t.get("consents", [])
c = consents[0] if len(consents) == 1 else {}
origin = (c.get("request") or {}).get("origin") or {}
checks = {
    "child enforced": child.get("enforced") is True,
    "child kernel-denied the write": any("/grant/" in e.get("target", "") for e in den),
    "child denials stamped with its scope": bool(den) and all(e.get("scope_id") == child.get("scope_id") for e in den),
    "one decision, in the session's record": len(consents) == 1,
    "decision attributed to the subagent": origin.get("kind") == "subagent" and origin.get("agent") == "writer"
        and (origin.get("inner") or {}).get("kind") == "reactive_denial",
}
if want == "granted":
    checks["granted"] = c.get("decision") == "granted"
    checks["retried write landed"] = written == "written by the subagent"
else:
    checks["refused beyond the parent, unasked"] = c.get("decision") == "refused" and c.get("reason") == "beyond_ceiling"
    checks["write stayed denied"] = written == ""
bad = [k for k, v in checks.items() if not v]
print("OK" if not bad else "failed: " + ", ".join(bad))
PY
  }
  verdict=$(se_run subagent-escalate "$WORK/se-held.policy.toml" granted)
  if [ "$verdict" = OK ]; then
    emit subagent-escalate PASS "child denial → session operator (named) → child scope reloaded → write landed"
  else
    emit subagent-escalate FAIL "$verdict ($(tail -1 "$WORK/subagent-escalate.log" 2>/dev/null))"
  fi
  verdict=$(se_run subagent-escalate-beyond "$WORK/se-unheld.policy.toml" refused)
  if [ "$verdict" = OK ]; then
    emit subagent-escalate-beyond PASS "beyond the parent at spawn: refused unasked though the session ceiling allows it"
  else
    emit subagent-escalate-beyond FAIL "$verdict ($(tail -1 "$WORK/subagent-escalate-beyond.log" 2>/dev/null))"
  fi
  sudo rm -rf "$SE"
else
  echo "RESULT|subagent-escalate|SKIP|no bee at $BEE"
  echo "RESULT|subagent-escalate-beyond|SKIP|no bee at $BEE"
fi

# ------------------------------------------------- 026: bee as an ACP agent (US1, US2)
# A minimal ACP client (newline-delimited JSON-RPC over `bee acp`'s stdio) runs a plan of steps and
# prints what it saw as JSON. Each session builds its own model from the provider file, so every
# session replays the same script; what differs between sessions is only their cwd and policy.
if [ -x "$BEE" ] && "$BEE" acp --help >/dev/null 2>&1; then
  AC=/home/ubuntu/acp
  sudo rm -rf "$AC"; mkdir -p "$AC/pa/.bee" "$AC/pb/.bee" "$AC/work" "$AC/grant"
  cat >"$WORK/acpc.py" <<'PY'
import json, os, subprocess, sys, threading, time
bee, plan = sys.argv[1], json.load(open(sys.argv[2]))
p = subprocess.Popen([bee, "acp", *plan.get("args", [])], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=open(plan["log"], "w"), text=True, bufsize=1)
lock, results, updates, perms = threading.Lock(), {}, [], []
answers = list(plan.get("answers", []))
events = {}
def reader():
    for line in p.stdout:
        m = json.loads(line)
        if "method" in m and "id" in m:  # a request from bee: only permission requests are expected
            if m["method"] == "session/request_permission":
                with lock:
                    perms.append(m["params"])
                    a = answers.pop(0) if answers else None
                out = {"outcome": {"outcome": "selected", "optionId": a}} if a else {"outcome": {"outcome": "cancelled"}}
                send({"jsonrpc": "2.0", "id": m["id"], "result": out})
            else:
                with lock: perms.append({"unexpected": m["method"]})
                send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "no"}})
        elif "method" in m:
            with lock: updates.append(m["params"])
        else:
            with lock: results[m["id"]] = m
            events.setdefault(m["id"], threading.Event()).set()
def send(m):
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
nid = [0]
def call(method, params, timeout=120):
    nid[0] += 1; i = nid[0]; ev = events.setdefault(i, threading.Event())
    send({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
    if not ev.wait(timeout): return {"error": "timeout"}
    return results[i]
threading.Thread(target=reader, daemon=True).start()
call("initialize", {"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": True}, "terminal": True}})
out = {"sessions": {}, "prompts": []}
for step in plan["steps"]:
    if "new" in step:
        r = call("session/new", {"cwd": step["cwd"], "mcpServers": []})
        out["sessions"][step["new"]] = r.get("result", {}).get("sessionId") or r
    else:
        sid = out["sessions"][step["prompt"]]
        if "cancel_after" in step:
            def later(sid=sid, t=step["cancel_after"]):
                time.sleep(t); send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid}})
            threading.Thread(target=later, daemon=True).start()
        t0 = time.time()
        r = call("session/prompt", {"sessionId": sid, "prompt": [{"type": "text", "text": step["text"]}]})
        out["prompts"].append({"session": step["prompt"], "stop": r.get("result", {}).get("stopReason"),
                               "error": r.get("error"), "secs": round(time.time() - t0, 2)})
p.stdin.close()
try: rc = p.wait(30)
except Exception: p.kill(); rc = "killed"
with lock:
    out["updates"], out["permissions"], out["rc"] = updates, perms, rc
print(json.dumps(out))
PY
  cat >"$WORK/acp-a.policy.toml" <<EOF
[policy]
name = "acp-a"
mode = "enforce"
[policy.filesystem]
"$AC/pa" = "write"
EOF
  cat >"$WORK/acp-b.policy.toml" <<EOF
[policy]
name = "acp-b"
mode = "enforce"
[policy.filesystem]
"$AC/pb" = "write"
EOF
  printf '[policy]\npath = "%s"\n' "$WORK/acp-a.policy.toml" >"$AC/pa/.bee/config.toml"
  printf '[policy]\npath = "%s"\n' "$WORK/acp-b.policy.toml" >"$AC/pb/.bee/config.toml"
  cat >"$WORK/acp-two.prov.toml" <<EOF
[provider]
provider = "mock"
[[provider.script]]
tool = "bash"
args = { command = "pwd; echo hi > $AC/pb/from-\$(basename \$(pwd)); echo rc=\$?" }
[[provider.script]]
text = "Done."
EOF
  cat >"$WORK/acp-two.plan.json" <<EOF
{"log": "$WORK/acp-two.log", "args": ["--provider", "$WORK/acp-two.prov.toml", "--tools", "bash"],
 "steps": [{"new": "A", "cwd": "$AC/pa"}, {"new": "B", "cwd": "$AC/pb"},
           {"prompt": "A", "text": "go"}, {"prompt": "B", "text": "go"}]}
EOF
  sudo python3 "$WORK/acpc.py" "$BEE" "$WORK/acp-two.plan.json" >"$WORK/acp-two.json" 2>>"$WORK/acp-two.log"
  verdict=$(python3 - "$WORK/acp-two.json" "$AC" <<'PY' 2>&1
import json, os, sys
o, ac = json.load(open(sys.argv[1])), sys.argv[2]
sid = o["sessions"]
def calls(s):
    ups = [u["update"] for u in o["updates"] if u["sessionId"] == sid[s]]
    return [u for u in ups if u.get("sessionUpdate") == "tool_call_update"]
def text(us): return json.dumps([u.get("content") for u in us])
a, b = calls("A"), calls("B")
checks = {
  "both prompts ended end_turn": [p["stop"] for p in o["prompts"]] == ["end_turn", "end_turn"],
  "A's denial shown on its call": "kernel denied" in text(a) and "from-pa" in text(a),
  "A ran in its cwd": ac + "/pa" in text(a),
  # The LSM's file_open hook runs after O_CREAT has made the inode, so a denied redirect leaves an
  # empty file: what must not land is the content (as skill-grant-deny checks).
  "A's write did not land": not os.path.exists(ac + "/pb/from-pa") or os.path.getsize(ac + "/pb/from-pa") == 0,
  "B ran in its cwd and wrote": ac + "/pb" in text(b) and os.path.exists(ac + "/pb/from-pb"),
  "no denial in B": "kernel denied" not in text(b),
  "no client method used": not [p for p in o["permissions"] if "unexpected" in p],
  "clean exit": o["rc"] == 0,
}
bad = [k for k, v in checks.items() if not v]
print("OK" if not bad else "failed: " + ", ".join(bad))
PY
)
  case "$verdict" in
    OK) emit acp-denial-reported PASS "denied write shown on its tool call (kernel denied …)"
        emit acp-two-sessions-isolated PASS "one process, two scopes: same command denied in A, allowed in B, each in its own cwd" ;;
    *)  emit acp-denial-reported FAIL "$verdict"
        emit acp-two-sessions-isolated FAIL "$verdict ($(tail -1 "$WORK/acp-two.log" 2>/dev/null))" ;;
  esac

  # acp-cancel — a cancelled prompt ends `cancelled` promptly and leaves no process behind.
  cat >"$WORK/acp-cancel.prov.toml" <<'EOF'
[provider]
provider = "mock"
[[provider.script]]
tool = "bash"
args = { command = "sleep 313 & sleep 313; echo never" }
[[provider.script]]
text = "never"
EOF
  cat >"$WORK/acp-cancel.plan.json" <<EOF
{"log": "$WORK/acp-cancel.log", "args": ["--provider", "$WORK/acp-cancel.prov.toml", "--tools", "bash", "--policy", "$WORK/acp-a.policy.toml"],
 "steps": [{"new": "A", "cwd": "$AC/pa"}, {"prompt": "A", "text": "go", "cancel_after": 2}]}
EOF
  sudo python3 "$WORK/acpc.py" "$BEE" "$WORK/acp-cancel.plan.json" >"$WORK/acp-cancel.json" 2>>"$WORK/acp-cancel.log"
  sleep 1
  left=$(pgrep -fc "sleep 313" || true)
  stop=$(python3 -c 'import json,sys; o=json.load(open(sys.argv[1])); p=o["prompts"][0]; print(p["stop"], p["secs"] < 7)' "$WORK/acp-cancel.json" 2>&1)
  if [ "$stop" = "cancelled True" ] && [ "${left:-0}" = 0 ]; then
    emit acp-cancel PASS "prompt cancelled within 5 s of the request; no process from the turn survives"
  else
    emit acp-cancel FAIL "stop/fast=$stop survivors=$left ($(tail -1 "$WORK/acp-cancel.log" 2>/dev/null))"
    sudo pkill -f "sleep 313" 2>/dev/null
  fi

  # acp-consent — a denied write within the ceiling becomes a permission request. Session 1's client
  # allows it (the retried write lands); session 2's rejects it (the write stays kernel-denied).
  cat >"$WORK/acp-ceil.policy.toml" <<EOF
[policy]
name = "acp-ceil"
mode = "enforce"
[policy.filesystem]
"$AC/work" = "write"
"$AC/grant" = "write"
EOF
  cat >"$WORK/acp-work.policy.toml" <<EOF
[policy]
name = "acp-work"
mode = "enforce"
[policy.filesystem]
"$AC/work" = "write"
EOF
  cat >"$WORK/acp-consent.prov.toml" <<EOF
[provider]
provider = "mock"
[[provider.script]]
tool = "write_file"
args = { path = "$AC/grant/x", content = "granted" }
[[provider.script]]
text = "Done."
EOF
  cat >"$WORK/acp-consent.plan.json" <<EOF
{"log": "$WORK/acp-consent.log", "answers": ["allow", "reject"],
 "args": ["--provider", "$WORK/acp-consent.prov.toml", "--tools", "write_file", "--policy", "$WORK/acp-work.policy.toml", "--ceiling-policy", "$WORK/acp-ceil.policy.toml"],
 "steps": [{"new": "A", "cwd": "$AC/work"}, {"prompt": "A", "text": "go"}]}
EOF
  sudo python3 "$WORK/acpc.py" "$BEE" "$WORK/acp-consent.plan.json" >"$WORK/acp-consent-1.json" 2>>"$WORK/acp-consent.log"
  allowed=$(cat "$AC/grant/x" 2>/dev/null)
  rm -f "$AC/grant/x"
  sed -i 's/"answers": \["allow", "reject"\]/"answers": ["reject"]/' "$WORK/acp-consent.plan.json"
  sudo python3 "$WORK/acpc.py" "$BEE" "$WORK/acp-consent.plan.json" >"$WORK/acp-consent-2.json" 2>>"$WORK/acp-consent.log"
  rejected=$(cat "$AC/grant/x" 2>/dev/null)
  asked=$(python3 -c 'import json,sys; print(sum(len(json.load(open(f))["permissions"]) for f in sys.argv[1:]))' "$WORK/acp-consent-1.json" "$WORK/acp-consent-2.json" 2>&1)
  shows=$(grep -c "filesystem: $AC/grant/x = write" "$WORK/acp-consent-1.json" 2>/dev/null)
  if [ "$allowed" = granted ] && [ -z "$rejected" ] && [ "$asked" = 2 ] && [ "${shows:-0}" -ge 1 ]; then
    emit acp-consent PASS "client allow → scope widened, write landed; client reject → write kernel-denied"
  else
    emit acp-consent FAIL "allowed='$allowed' rejected='$rejected' asked=$asked shows=$shows ($(tail -1 "$WORK/acp-consent.log" 2>/dev/null))"
  fi
  sudo rm -rf "$AC"
else
  for c in acp-denial-reported acp-two-sessions-isolated acp-cancel acp-consent; do
    echo "RESULT|$c|SKIP|bee built without --features acp"
  done
fi

# ---------------------------------------------------------------- 019: HTTP interception (US1)
# One scripted episode under `[policy.http]`, one tool call per probe. Each call is its own credential
# (its own call id), so every probe is attributed separately in the transcript. The in-VM targets are
# python http.servers on loopback; 18081 is deliberately NOT in scope and logs every request it gets,
# so "no upstream connection" is checked at the destination, not inferred.
HTTP_CASES="http-in-scope http-out-of-scope http-direct-target http-direct-other http-proxy-scope http-sni-mismatch http-store-protected http-proxy-fs-deny http-latency"
if [ -x "$BEE" ] && "$BEE" run --help 2>/dev/null | grep -q -- '--http-scope-advisory' \
   && "$BEE" proxy-worker --help >/dev/null 2>&1; then
  HW=/home/ubuntu/httpwork
  rm -rf "$HW"; mkdir -p "$HW/www" "$HW/other" "$HW/src"
  echo "in-scope-ok" >"$HW/www/index.html"
  echo "project-secret" >"$HW/src/secret.txt"
  ( cd "$HW/www" && exec python3 -m http.server 18080 --bind 127.0.0.1 ) >/dev/null 2>&1 &
  T1=$!
  ( cd "$HW/other" && exec python3 -m http.server 18081 --bind 127.0.0.1 ) >"$HW/other.log" 2>&1 &
  T2=$!
  openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=app.test" -days 1 \
    -keyout "$HW/key.pem" -out "$HW/cert.pem" >/dev/null 2>&1
  openssl s_server -accept 127.0.0.1:18443 -cert "$HW/cert.pem" -key "$HW/key.pem" -www -quiet \
    >/dev/null 2>&1 &
  T3=$!
  sleep 1
  # `dash`: the bash tool runs its command with `sh -c`, and on Ubuntu `sh` is dash — the kernel checks
  # the resolved image, so the allowlist names `dash`, not `sh`. Without it every tool call here is
  # refused at exec, and the cases below would be judging a refusal.
  printf '%s\n' '[policy]' 'name = "http-vm"' 'mode = "enforce"' \
    '[policy.exec]' 'allow = ["dash", "bash", "curl", "cat", "openssl", "head", "timeout"]' \
    '[policy.filesystem]' '"/home/ubuntu/httpwork" = "write"' \
    '[policy.http]' 'targets = ["127.0.0.1:18080", "127.0.0.1:18443"]' >"$HW/policy.toml"
  printf '%s\n' '[scenario]' 'id = "http-vm"' "policy_path = \"$HW/policy.toml\"" \
    'system_prompt = "test"' 'task = "probe"' 'turn_limit = 16' 'timeout_secs = 120' \
    'tools = ["bash", "http_history", "http_debug"]' >"$HW/scn.toml"
  # The SNI probe reads the call's own proxy credential out of HTTP_PROXY, as any client would.
  python3 - "$HW" >"$HW/prov.toml" <<'PYPROV'
import json, sys
hw = sys.argv[1]
sni = ("P=${HTTP_PROXY#http://}; U=${P%@*}; HP=${P#*@}; echo | timeout 10 openssl s_client "
       "-proxy $HP -proxy_user ${U%%:*} -proxy_pass pass:${U#*:} -connect 127.0.0.1:18443 "
       "-servername other.test 2>&1 | head -5; echo done")
steps = [
    ("bash", {"command": "curl -sS -o /dev/null -w 'code=%{http_code}' http://127.0.0.1:18080/"}),
    ("bash", {"command": "curl -sS -o /dev/null -w 'code=%{http_code}' http://127.0.0.1:18081/"}),
    ("bash", {"command": "curl -sS --max-time 5 --noproxy '*' -o /dev/null -w 'code=%{http_code}' http://127.0.0.1:18080/; echo"}),
    ("bash", {"command": "curl -sS --max-time 5 --noproxy '*' -o /dev/null -w 'code=%{http_code}' http://1.1.1.1/; echo"}),
    ("http_debug", {"connect": "1.1.1.1:443"}),
    ("bash", {"command": sni}),
    # No `>/dev/null`: a scope that grants a write denies writes to unlisted paths, /dev/null among
    # them, and the redirect would fail before the read was ever attempted. The read goes into a
    # shell variable instead.
    ("bash", {"command": "x=$(head -c 16 .bee/http/index.sqlite) && [ -n \"$x\" ] && echo READ-OK; echo x > .bee/http/blobs/x && echo WRITE-OK; true"}),
    ("http_debug", {"read": hw + "/src/secret.txt"}),
    ("http_history", {}),
]
print("[provider]\nprovider = \"mock\"")
for tool, args in steps:
    # TOML basic strings are JSON-compatible for these values.
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in args.items())
    print(f"[[provider.script]]\ntool = \"{tool}\"\nargs = {{ {inline} }}")
print("[[provider.script]]\ntext = \"done\"")
PYPROV
  ( cd "$HW" && "$BEE" run --scenario "$HW/scn.toml" --provider "$HW/prov.toml" \
      --out "$HW/t.json" ) >"$HW/run.log" 2>&1
  # http-latency (SC-007, T093): added latency of the proxy for an in-scope GET, gated here on the
  # dedicated VM rather than on shared CI runners (research R19a). Direct timings come from this
  # root shell (outside any scope); proxied ones from a tool child going through the session proxy.
  LAT_N=300
  for _ in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:18080/; done
  for _ in $(seq 1 $LAT_N); do curl -s -o /dev/null -w '%{time_total}\n' http://127.0.0.1:18080/; done >"$HW/direct.txt"
  # Builtins only for the loop: the scope's exec allowlist has no `seq`, and a denied `seq` turns the
  # tool's output into an `sh:` error instead of timings (the false-result trap in test/vm/README).
  LATCMD="i=0; while [ \$i -lt 50 ]; do curl -s -o /dev/null http://127.0.0.1:18080/; i=\$((i+1)); done; i=0; while [ \$i -lt $LAT_N ]; do curl -s -o /dev/null -w '%{time_total} ' http://127.0.0.1:18080/; i=\$((i+1)); done"
  python3 - "$LATCMD" >"$HW/lat.prov.toml" <<'PYLAT'
import json, sys
print('[provider]\nprovider = "mock"')
print(f'[[provider.script]]\ntool = "bash"\nargs = {{ command = {json.dumps(sys.argv[1])} }}')
print('[[provider.script]]\ntext = "done"')
PYLAT
  sed 's/turn_limit = 16/turn_limit = 4/; s/timeout_secs = 120/timeout_secs = 300/' "$HW/scn.toml" >"$HW/lat.scn.toml"
  ( cd "$HW" && "$BEE" run --scenario "$HW/lat.scn.toml" --provider "$HW/lat.prov.toml" \
      --out "$HW/lat.json" ) >"$HW/lat.log" 2>&1
  while IFS='|' read -r c st note; do emit "$c" "$st" "$note"; done < <(python3 - "$HW/direct.txt" "$HW/lat.json" <<'PYLATCHECK'
import json, sys
def q(v, p):
    v = sorted(v)
    return v[int((len(v) - 1) * p)]
try:
    direct = [float(x) for x in open(sys.argv[1]).read().split()]
    t = json.load(open(sys.argv[2]))
    proxied = [float(x) for x in t["turns"][0]["calls"][0]["result"]["content"].split()]
    med = (q(proxied, 0.5) - q(direct, 0.5)) * 1000
    p95 = (q(proxied, 0.95) - q(direct, 0.95)) * 1000
    ok = len(proxied) >= 100 and med <= 50 and p95 <= 200
    print(f"http-latency|{'PASS' if ok else 'FAIL'}|added median {med:.1f} ms, p95 {p95:.1f} ms over {len(proxied)} requests (limits 50 / 200)")
except Exception as e:
    # Say what the tool actually printed: a parse error alone hides a denied command or a missing file.
    try:
        got = json.load(open(sys.argv[2]))["turns"][0]["calls"][0]["result"]["content"][:160]
    except Exception as e2:
        got = f"<no transcript: {e2}>"
    got = got.replace("|", "/").replace("\n", " ")
    print(f"http-latency|FAIL|could not measure: {e}; tool output began: {got}")
PYLATCHECK
)
  kill "$T1" "$T2" "$T3" 2>/dev/null
  if [ ! -f "$HW/t.json" ]; then
    for c in $HTTP_CASES; do
      [ "$c" = http-latency ] && continue  # measured separately above
      emit "$c" FAIL "no transcript: $(tail -3 "$HW/run.log" | tr '\n' ' ')"
    done
  else
    # One python pass over the transcript; prints `case|PASS|note` lines. A case it never printed — the
    # checker crashed, or skipped it — is a FAIL, not an absence: a missing line must not read as green.
    seen=""
    while IFS='|' read -r c st note; do seen="$seen $c"; emit "$c" "$st" "$note"; done < <(python3 - "$HW/t.json" "$HW/other.log" 2>"$HW/check.err" <<'PYCHECK'
import json, sys
t = json.load(open(sys.argv[1]))
other_log = open(sys.argv[2]).read()
calls = [c for turn in t["turns"] for c in turn.get("calls", [])]
def res(i): return calls[i]["result"]["content"] if i < len(calls) else ""
def audit(i): return calls[i].get("audit", []) if i < len(calls) else []
def pev(i): return calls[i].get("proxy_events", []) if i < len(calls) else []
def out(case, ok, note): print(f"{case}|{'PASS' if ok else 'FAIL'}|{note}")
ids = [c["call"]["id"] for c in calls]
hist = res(8)
out("http-in-scope", "code=200" in res(0) and bool(ids) and ids[0] in hist,
    f"curl via proxy: {res(0)[:60]!r}; in history: {bool(ids) and ids[0] in hist}")
oos = [e for e in pev(1) if e["kind"] == "refused_out_of_scope"]
out("http-out-of-scope", "code=403" in res(1) and bool(oos) and "GET /" not in other_log,
    f"{res(1)[:40]!r}, proxy_event={bool(oos)}, upstream_hits={other_log.count('GET /')}")
def kdeny(i, target):
    return [a for a in audit(i) if a["op"] == "connect" and a["decision"] == "denied"
            and a.get("scope_id") != "proxy" and (target is None or a["target"] == target)]
out("http-direct-target", "code=000" in res(2) and bool(kdeny(2, "127.0.0.1:18080")),
    f"{res(2).strip()[:60]!r}, kernel denials={[a['target'] for a in kdeny(2, None)]}")
out("http-direct-other", "code=000" in res(3) and bool(kdeny(3, "1.1.1.1:80")),
    f"{res(3).strip()[:60]!r}, kernel denials={[a['target'] for a in kdeny(3, None)]}")
px = [a for a in audit(4) if a.get("scope_id") == "proxy" and a["op"] == "connect"
      and a["target"] == "1.1.1.1:443"]
out("http-proxy-scope", "errno=1" in res(4) and bool(px),
    f"{res(4)!r}, proxy-scope audit={[(a['op'], a['target']) for a in audit(4)]}")
sni = [e for e in pev(5) if e["kind"] == "refused_sni_mismatch"]
out("http-sni-mismatch", bool(sni) and "BEGIN CERTIFICATE" not in res(5), f"proxy_event={bool(sni)}")
fs = [a for a in audit(6) if a["op"] == "file_open" and a["decision"] == "denied"
      and ".bee/http" in a["target"]]
out("http-store-protected", "READ-OK" not in res(6) and "WRITE-OK" not in res(6) and len(fs) >= 2,
    f"denials={[a['target'] for a in fs]}; output={res(6).strip()[:120]!r}")
pf = [a for a in audit(7) if a.get("scope_id") == "proxy" and a["op"] == "file_open"
      and "secret.txt" in a["target"]]
out("http-proxy-fs-deny", "errno=13" in res(7) and bool(pf), f"{res(7)!r}, proxy-scope audit={bool(pf)}")
PYCHECK
)
    for c in $HTTP_CASES; do
      [ "$c" = http-latency ] && continue  # judged separately above
      case " $seen " in *" $c "*) ;; *) emit "$c" FAIL "not judged: $(tail -1 "$HW/check.err" 2>/dev/null)" ;; esac
    done
  fi
  rm -rf "$HW"
else
  for c in $HTTP_CASES; do
    emit "$c" FAIL "bee was not built with --features vm-test (see test/vm/README.md)"
  done
fi

# ------------------------------------- 026 PR2: per-subagent proxy scopes and resolve-and-admit
# proxy-admit-on-resolve (T047, research R9): an egress host whose address changes mid-session is
# still reached. `prov.test` starts at 127.0.0.2 in /etc/hosts; after the first fetch the matrix moves
# it to 127.0.0.3 and kills the .2 server, so the second fetch succeeds only through the new address —
# which the proxy scope's kernel rules held only after bee admitted it (a recorded reload).
# subagent-intercept-attributed (T056, S9b): an intercepting session delegates; each child records
# through a proxy of its own, attributed to its scope and delegation, none to the parent. Child B
# offers child A's credential to its own proxy (refused: not its namespace) and tries the parent's
# proxy port directly (kernel-denied: its tool scope reaches only its own proxy).
PS_CASES="proxy-admit-on-resolve subagent-intercept-attributed"
if [ -x "$BEE" ] && "$BEE" proxy-worker --help >/dev/null 2>&1; then
  PW=/home/ubuntu/pscope
  rm -rf "$PW"; mkdir -p "$PW/www" "$PW/skills/web"
  echo "app-ok" >"$PW/www/index.html"
  cp /etc/hosts "$PW/hosts.bak"
  printf '127.0.0.2 prov.test\n' >>/etc/hosts
  ( cd "$PW/www" && exec python3 -m http.server 18090 --bind 127.0.0.1 ) >/dev/null 2>&1 &
  PA=$!
  openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=prov.test" -days 1 \
    -keyout "$PW/key.pem" -out "$PW/cert.pem" >/dev/null 2>&1
  openssl s_server -accept 127.0.0.2:18443 -cert "$PW/cert.pem" -key "$PW/key.pem" -www -quiet \
    >/dev/null 2>&1 &
  P2=$!
  openssl s_server -accept 127.0.0.3:18443 -cert "$PW/cert.pem" -key "$PW/key.pem" -www -quiet \
    >/dev/null 2>&1 &
  P3=$!
  sleep 1
  printf '%s\n' '[policy]' 'name = "pscope"' 'mode = "enforce"' \
    '[policy.exec]' 'allow = ["dash", "bash", "curl", "cat", "sleep"]' \
    '[policy.filesystem]' "\"$PW\" = \"write\"" \
    '[policy.http]' 'targets = ["127.0.0.1:18090"]' 'egress = ["prov.test:18443"]' >"$PW/policy.toml"

  # --- proxy-admit-on-resolve
  printf '%s\n' '[scenario]' 'id = "admit"' "policy_path = \"$PW/policy.toml\"" \
    'system_prompt = "test"' 'task = "probe"' 'turn_limit = 6' 'timeout_secs = 120' \
    'tools = ["bash"]' >"$PW/admit.scn.toml"
  FETCH="curl -sk --max-time 10 -o page.html -w 'code=%{http_code}' https://prov.test:18443/; echo"
  python3 - "$FETCH" >"$PW/admit.prov.toml" <<'PYPROV'
import json, sys
fetch = sys.argv[1]
wait = ": > flip; i=0; while [ ! -f flipped ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; [ -f flipped ] && echo FLIPPED"
print('[provider]\nprovider = "mock"')
for cmd in (fetch, wait, fetch):
    print(f'[[provider.script]]\ntool = "bash"\nargs = {{ command = {json.dumps(cmd)} }}')
print('[[provider.script]]\ntext = "done"')
PYPROV
  # The flip, from outside every scope: move prov.test and take its old address away.
  ( for _ in $(seq 1 300); do [ -f "$PW/flip" ] && break; sleep 0.1; done
    sed -i 's/^127\.0\.0\.2 prov\.test$/127.0.0.3 prov.test/' /etc/hosts
    kill "$P2" 2>/dev/null; sleep 0.3; : >"$PW/flipped" ) &
  FL=$!
  ( cd "$PW" && "$BEE" run --scenario "$PW/admit.scn.toml" --provider "$PW/admit.prov.toml" \
      --out "$PW/admit.json" ) >"$PW/admit.log" 2>&1
  kill "$FL" 2>/dev/null
  cp "$PW/hosts.bak" /etc/hosts
  while IFS='|' read -r c st note; do emit "$c" "$st" "$note"; done < <(python3 - "$PW/admit.json" "$PW/.bee/http/index.sqlite" 2>&1 <<'PYCHECK'
import json, sqlite3, sys
try:
    t = json.load(open(sys.argv[1]))
    calls = [c for turn in t["turns"] for c in turn.get("calls", [])]
    res = [c["result"]["content"] for c in calls]
    db = sqlite3.connect(f"file:{sys.argv[2]}?mode=ro", uri=True)
    admits = db.execute("SELECT added FROM admits WHERE host = 'prov.test'").fetchall()
    added = [a for (row,) in admits for a in json.loads(row)]
    pden = [a for c in calls for a in c.get("audit", [])
            if a.get("scope_id") == "proxy" and a["decision"] == "denied"]
    checks = {
        "reached at the first address": len(res) > 0 and "code=200" in res[0],
        "flipped mid-session": len(res) > 1 and "FLIPPED" in res[1],
        "reached at the new address": len(res) > 2 and "code=200" in res[2],
        "admit reload recorded for 127.0.0.3": "127.0.0.3" in added,
        "no proxy-scope denial": not pden,
    }
    bad = [k for k, v in checks.items() if not v]
    note = f"results={[r.strip()[:20] for r in res]}, admits={added}, proxy denials={[a['target'] for a in pden]}"
    print(f"proxy-admit-on-resolve|{'PASS' if not bad else 'FAIL'}|{'; '.join(bad) or 'ok'}: {note}")
except Exception as e:
    print(f"proxy-admit-on-resolve|FAIL|could not judge: {e}")
PYCHECK
)

  # --- subagent-intercept-attributed
  cat >"$PW/skills/web/SKILL.md" <<'EOF'
---
name: web
kind: agent
description: Fetches pages through its proxy.
tools: [bash]
turn-limit: 3
---
Fetch what you are asked to and report the status.
EOF
  # Its own policy: /etc/hosts no longer names prov.test, and every egress name must resolve.
  sed '/^egress = /d' "$PW/policy.toml" >"$PW/sub.policy.toml"
  printf '%s\n' '[scenario]' 'finish = false' 'id = "sub-intercept"' \
    "policy_path = \"$PW/sub.policy.toml\"" 'system_prompt = "test"' 'task = "delegate"' \
    'turn_limit = 12' 'timeout_secs = 120' 'tools = ["task", "bash"]' \
    "skills = [\"$PW/skills\"]" >"$PW/sub.scn.toml"
  python3 - >"$PW/sub.prov.toml" <<'PYPROV'
import json
steps = [
    ("bash", {"command": "echo \"$HTTP_PROXY\" > parent.proxy && echo SAVED"}),
    ("task", {"agent": "web", "prompt": "A"}),
    ("bash", {"command": "echo \"$HTTP_PROXY\" > a.proxy; curl -sS --max-time 10 -o a.html -w 'code=%{http_code}' http://127.0.0.1:18090/; echo"}),
    ("finish", {"outcome": "completed", "summary": "A fetched"}),
    ("task", {"agent": "web", "prompt": "B"}),
    ("bash", {"command": "A=$(cat a.proxy); P=$(cat parent.proxy); U=${A#http://}; U=${U%@*}; MINE=${HTTP_PROXY##*@}; "
                         "curl -sS --max-time 10 -o b1.html -w 'cred=%{http_code}' -x \"http://$U@$MINE\" http://127.0.0.1:18090/; echo; "
                         "curl -sS --max-time 5 -o b2.html -w 'port=%{http_code}' -x \"$P\" http://127.0.0.1:18090/; echo"}),
    ("finish", {"outcome": "completed", "summary": "B probed"}),
]
print('[provider]\nprovider = "mock"')
for tool, args in steps:
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in args.items())
    print(f'[[provider.script]]\ntool = "{tool}"\nargs = {{ {inline} }}')
print('[[provider.script]]\ntext = "done"')
PYPROV
  ( cd "$PW" && "$BEE" run --scenario "$PW/sub.scn.toml" --provider "$PW/sub.prov.toml" \
      --out "$PW/sub.json" ) >"$PW/sub.log" 2>&1
  while IFS='|' read -r c st note; do emit "$c" "$st" "$note"; done < <(python3 - "$PW/sub.json" "$PW/.bee/http/index.sqlite" 2>&1 <<'PYCHECK'
import json, sqlite3, sys
try:
    t = json.load(open(sys.argv[1]))
    calls = [c for turn in t["turns"] for c in turn.get("calls", [])]
    tasks = [c for c in calls if c["call"]["name"] == "task"]
    kids = [c.get("child") or {} for c in tasks]
    def out(tr):
        return "\n".join(c["result"]["content"] for turn in tr.get("turns", []) for c in turn.get("calls", []))
    a, b = (kids + [{}, {}])[:2]
    a_out, b_out = out(a.get("transcript") or {}), out(b.get("transcript") or {})
    db = sqlite3.connect(f"file:{sys.argv[2]}?mode=ro", uri=True)
    attr = {r[1]: r for r in db.execute(
        "SELECT session_id, delegation_id, scope_id, parent_session FROM attribution")}
    ta, tb = (tasks + [None, None])[0], (tasks + [None, None])[1]
    ra = attr.get(ta["call"]["id"]) if ta else None
    rb = attr.get(tb["call"]["id"]) if tb else None
    count = lambda table, sid: db.execute(f"SELECT COUNT(*) FROM {table} WHERE session_id = ?", (sid,)).fetchone()[0]
    parent = ra[3] if ra else None
    bden = [e for e in (b.get("transcript") or {}).get("audit_trail", [])
            if e["op"] == "connect" and e["decision"] == "denied"]
    bref = db.execute("SELECT COUNT(*) FROM refusals WHERE session_id = ? AND kind = 'refused_bad_credential'",
                      (rb[0] if rb else "",)).fetchone()[0]
    checks = {
        "delegations not refused": len(kids) == 2 and all((k.get("outcome") or {}).get("kind") == "completed" for k in kids),
        "both enforced": all(k.get("enforced") is True for k in kids),
        "A fetched through its proxy": "code=200" in a_out,
        "A attributed to its scope and delegation": bool(ra) and ra[2] == a.get("scope_id"),
        "B attributed to its scope and delegation": bool(rb) and rb[2] == b.get("scope_id"),
        "A's exchange is A's": bool(ra) and count("exchanges", ra[0]) == 1,
        "none on the parent": bool(parent) and count("exchanges", parent) == 0 and count("tunnels", parent) == 0,
        "A's credential refused by B's proxy": "cred=407" in b_out and bref >= 1,
        "parent's proxy port kernel-denied to B": "port=000" in b_out and bool(bden)
            and all(e.get("scope_id") == b.get("scope_id") for e in bden),
    }
    bad = [k for k, v in checks.items() if not v]
    note = f"A={a_out.strip()[:30]!r} B={b_out.strip()[:60]!r} attr={list(attr)} bden={[e['target'] for e in bden]}"
    print(f"subagent-intercept-attributed|{'PASS' if not bad else 'FAIL'}|{'; '.join(bad) or 'ok'}: {note}")
except Exception as e:
    print(f"subagent-intercept-attributed|FAIL|could not judge: {e}")
PYCHECK
)
  kill "$PA" "$P2" "$P3" 2>/dev/null
  cp "$PW/hosts.bak" /etc/hosts
  rm -rf "$PW"
else
  for c in $PS_CASES; do
    emit "$c" FAIL "bee was not built with --features intercept (see test/vm/README.md)"
  done
fi

rm -rf "$WORK"
echo "SUMMARY|pass=$pass|fail=$fail"
[ "$fail" -eq 0 ]

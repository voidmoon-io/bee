# Move the proxy worker into comb; `bee proxy-worker` wraps it

Status: ready-for-agent

Move `worker/` (listen, connect, forward, mitm, raw, rules, pace, scope) into comb. The worker
must not assume a kernel scope: scope checks read `enforced_by` as given. `bee proxy-worker`
stays the entry bee spawns inside the proxy scope and calls `comb::worker::run`.
Move `sidecar` (the harness end of the control channel) and `ops/*` with it; give comb its own
`safe_line` for the log lines it formats (or move `safe_text` to a shared place — pick one copy).

Done when: tests pass on bee-build and the VM matrix's HTTP cases pass (T048's cases).

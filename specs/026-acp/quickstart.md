# Quickstart: validating 026 ACP

Kernel scenarios run on `bee-build` (BPF-LSM VM) with a release build
`--features concurrent,sec,intercept,vm-test`. Host scenarios run with `cargo test`. Each scenario
names the spec items it proves. Record results at the bottom.

**Fixtures**
- `acp-client` — a scripted ACP client (test helper; host tests drive `bee acp` over pipes, VM cases
  over a real process) that sends a script of requests and answers permission requests from a script.
- `acp_fake_harness` — a test binary that speaks ACP as an agent and, on `session/prompt`, runs a
  scripted list of actions (read/write a path, connect via `HTTPS_PROXY`, fork a sleeper, call
  `fs/read_text_file`, ask permission) and reports what happened in `agent_message_chunk`s.

## S1 — bee in t3code (manual; SC-001)

1. In t3code: **Settings → Providers → Add provider → Show more → Local ACP command**; executable
   `bee`, argument `acp`; name "bee".
2. Open a thread on a project with a bee policy allowing writes to the project.
3. Prompt: "create notes.txt with one line, then list the directory".
4. Expected: streamed reply; two tool calls shown with status and output; `notes.txt` exists.

## S2 — protocol conformance (host; FR-001–FR-004, SC-002)

`cargo test --test acp_agent`: initialize → capabilities as in contracts/acp-agent.md; session/new
with a temp project; prompt with a `MockModel` script making one `write_file` call; assert the
update sequence (chunk → tool_call → tool_call_update completed → chunk) and `end_turn`; assert bee
sent no `fs/*`/`terminal/*` request even though the client advertised both.

## S3 — denial reported on its call (VM; US1 AS-2) — case `acp-denial-reported`

Policy allows writes to `work/` only. Scripted model writes `work/a` and `/home/ubuntu/outside/b`.
Expected: first call `completed`; second `failed` with `kernel denied file_open …/outside/b` in its
content; the session record holds that audit event with the session's scope id.

## S4 — consent through the client (VM; US2) — case `acp-consent`

Ceiling allows `grant/`; policy does not. The model writes `grant/x` twice in two prompts. The
client answers the first permission request `allow`, the second (after the lease expires) `reject`.
Expected: first retry writes; second stays denied; consent log has one Granted, one
DeniedByOperator, both `operator: interactive`. Variant: client never answers → refused at the
timeout (set `consent_timeout` short).

## S5 — two sessions, one process (VM; FR-008) — case `acp-two-sessions-isolated`

One `bee acp` process, sessions A (cwd `pa/`, may write `pa/`) and B (cwd `pb/`, may write `pb/`).
A writes into `pb/`. Expected: denied, attributed to A's scope; B's record has no event; tool
children of each ran in their own cwd (`pwd` output).

## S6 — cancel kills the turn (VM; FR-007, SC-006) — case `acp-cancel`

Model runs `sleep 300 & sleep 300`. Client sends `session/cancel` after 1 s. Expected: prompt answered
`cancelled` within 5 s; no process from the turn remains (`cgroup.procs` empty / scope gone).

## S7 — harness contained (VM; US3, FR-011–FR-015) — case `harness-contained`

Agent `fake` with `runtime.acp.command = acp_fake_harness`, `requires.filesystem` = `hwork/`: write.
Actions: write `hwork/ok`, write `/home/ubuntu/outside/x`, call `fs/read_text_file`, fork a detached
sleeper, ask permission once. Expected: report contains the harness's final text; `hwork/ok` exists;
outside write kernel-denied and recorded in the delegation's audit with the child scope id;
`fs/read_text_file` in `refused_methods`; one permission request answered `allow_once`; no sleeper
survives; child and proxy scopes gone.

## S8 — provider by name only (VM; US4, FR-018–FR-019, SC-005) — case `harness-egress-by-name`

Two local TLS servers on one address with different names (`prov.test`, `other.test` via
`/etc/hosts`). Parent allows `prov.test:8443` by name; agent declares it. Harness connects to both
through `HTTPS_PROXY`. Expected: `prov.test` succeeds and a `TunnelRecord` (no content) exists;
`other.test` refused (403 / refusal recorded). Then change `/etc/hosts` for `prov.test` to a second
address and connect again: succeeds, and the proxy scope records one admit reload.

## S9 — credentials and intercepted delegation (VM; US4 AS-3, US5) — cases `harness-credentials`, `subagent-intercept-attributed`

(a) Agent declares `~/.claude` write; harness reads `~/.claude/.credentials.json` (ok) and
`~/.codex/auth.json` (kernel-denied). (b) Intercepting session (`[policy.http]` target `app.test`)
delegates to a bee-loop subagent that fetches `app.test`: delegation is not refused; the exchange
is in the store attributed to the subagent's scope, none to the parent.

## S10 — real Claude harness (bee-build, real model; SC-004)

Install the `claude-agent-acp` Linux binary; agent as in contracts/harness-runtime.md; credentials
via `[acp] harness_env_passthrough = ["ANTHROPIC_API_KEY"]`. Task: "add a line to README.md and run
the tests". Expected: completes; all kernel events attributed to the child scope; tunnels only to
declared hosts; nothing survives; report in the parent's conversation.

## Results

| Scenario | Date | Result |
|---|---|---|
| S8 (session half) — `proxy-admit-on-resolve` | 2026-11-10 | PASS on bee-build. `prov.test` moved from 127.0.0.2 to 127.0.0.3 mid-session, and the old listener was killed. Both fetches got 200. One admit adding 127.0.0.3 was recorded, with no proxy-scope denial. Negative control (no admit hook): the second fetch got `000` and no admit was recorded. |
| S9(b) — `subagent-intercept-attributed` | 2026-11-10 | PASS on bee-build. Two children, both enforced and completed, each with its own proxy session attributed to its scope and `task` call. A's exchange is A's, and the parent has no exchanges or tunnels. B's proxy refused A's credential (407, `refused_bad_credential`). The parent's proxy port was kernel-denied to B, with the denial in B's record under B's scope. Negative control (no attribution): FAIL. Full matrix 62/62. |
| S7 — `harness-contained` | 2026-11-10 | PASS on bee-build. A harness (`bee acp-fake-harness`) ran in its own scope and proxy. Its in-scope write succeeded. Its write outside was kernel-denied, with the denial in the delegation's audit under the child scope. `fs/read_text_file` was refused and recorded. The report carried the FR-021 note. The detached sleeper it forked was killed at teardown, and the scope was gone. The permission answer (`allow_once`, not the offered `allow_always`) is the host test `a_harness_reports_its_final_turn_and_its_calls_stay_in_its_record`. First runs found two limits. Five store denies plus bee's four protected defaults exceeded the eBPF backend's 8 filesystem rules, so only stores present on the machine are denied. And a scope that denies unmatched writes denies `/dev/null`, so the test policy grants it. |
| S8 — `harness-egress-by-name` | 2026-11-10 | PASS on bee-build. `prov.test` was reached through the harness's proxy (200). `other.test`, at the same address but undeclared, was refused (`000`, one out-of-scope refusal). A direct connect to the address was kernel-denied. After `prov.test` moved to 127.0.0.3, it was reached again, with one admit recorded. Two tunnels were recorded, with no content. |
| S9(a) — `harness-credentials` | 2026-11-10 | PASS on bee-build. With `~/.claude` named by agent and parent, the harness read `~/.claude/.credentials.json`; `~/.codex/auth.json` was kernel-denied. Full matrix 65/65. Negative control (no store denies; proxy egress `other.test` instead of the declared `prov.test`): `harness-contained` PASS, `harness-credentials` FAIL (`~/.codex/auth.json` read), `harness-egress-by-name` FAIL (`prov.test` `000`, `other.test` 200). |

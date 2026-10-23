# Feature Specification: Agent-First HTTP(S) Interception Under Kernel-Enforced Scope

**Feature Branch**: `019-http-intercept`

**Created**: 2026-10-10

**Status**: Draft

**Input**: User description: "Agent-first HTTP/HTTPS interceptor (an agent-first Caido) fully integrated into the bee harness, as a native tool family behind an `intercept` cargo feature. A `bee proxy-worker` runs in its own kernel scope whose network policy is the target scope; tool children's network is limited to the proxy on loopback, so rules of engagement are kernel-enforced and proxy-unaware clients fail closed. Proxy enforces host scope on CONNECT target + SNI (mismatch refused); TLS MITM is opt-in per policy-named domain with a per-session CA whose key never leaves the worker. Out-of-scope requests become 007 escalation requests needing human consent; the agent cannot widen scope itself. Every request is attributed to the originating tool call via per-call proxy credentials in HTTP_PROXY userinfo (also blocks other local processes). Tools: http_scope (read-only), http_send (structured or raw, optional baseline diff), http_replay (id + patch ops, diff vs original), http_history (structured filter, compact rows), http_get (bounded slices by range/grep/JSON pointer), http_fuzz (marker template + payload sets, results clustered by status/length/timing/reflection, policy rate caps), http_intercept (declarative hold/modify/drop + match/replace rules for other tools' traffic, timeout auto-forward), http_sitemap (host/path tree with params). Store under .bee/http/ (index + content-addressed bodies). record_finding gains exchange-id evidence links; passive checks emit leads (never findings). Prerequisites: untrusted-data framing of tool output to the model and is_error passthrough (rig_model.rs drops it); a harness-controlled way to inject proxy/CA env vars past restrict_env. Milestones: M1 proxy-worker + CONNECT/SNI gate + store + send/get/history/scope + prerequisites; M2 opt-in MITM, replay/diff, sitemap, scope escalation; M3 fuzz clustering, intercept rules, passive leads, ledger evidence links; M4 TUI live history pane, per-subagent proxy scopes (018), HAR export. Out of M1: HTTP/2, WebSockets. Open decisions: engine (hyper for proxying + raw HTTP/1.1 writer for send/fuzz fidelity vs hudsucker), store (SQLite index vs JSONL+blobs), filter language (structured JSON vs HTTPQL-like)."

## Context & Motivation

Web application testing tools — Caido, Burp — are built around a person: a proxy the browser points
at, a history pane to scroll, a replay tab to edit by hand, a fuzzer whose ten thousand result rows
a human sorts by length. An agent can drive none of that well. It cannot scroll, it pays for every
byte it reads, it loses track of which request it sent when, and it has no reliable way to tell
"the response changed" from "the response is different noise".

Those tools also share a second weakness that matters more for an agent than for a person: **scope
is advisory**. A scope list filters the history view; it does not stop a request. A person who
mistypes a hostname sends one stray request. An agent that is persuaded by a page it fetched — or
that simply generalises from `api.example.com` to `example.net` — can send thousands, against a
system nobody authorised it to test.

bee is in a position to solve both at once. It already confines every tool call to a kernel scope
and can deny network connections in the kernel. This feature puts an interception proxy inside that
model:

- the **proxy itself** runs in a kernel scope that can reach only the authorised targets;
- **every other tool child** — `curl`, a scanner, a fuzzer, a headless browser — can reach only the
  proxy, so traffic either goes through the interceptor or does not leave at all;
- the **agent drives it through first-class tools** designed for a model: identifiers instead of
  scrolling, queries instead of panes, diffs and clusters instead of raw dumps, and bounded output
  always.

Rules of engagement stop being a convention and become a property of the session.

### What the kernel guarantees, and what it does not (Constitution III)

This feature combines two layers and MUST NOT blur them:

1. **Kernel-enforced**: tool children may connect only to the proxy; the proxy may connect only to
   the network addresses the target scope resolves to. These are enforced by the existing
   connection hook at IP/port granularity.
2. **Proxy-enforced (user space)**: host-name scope, the agreement between a tunnel's requested host
   and the TLS server name, method and path rules, and rate limits. These are checked by bee's own
   code in the proxy and are presented as such — a defence layered on top of the kernel boundary,
   never as a kernel guarantee.

An operator reading the scope description, the documentation, or a transcript MUST be able to tell
which of these two layers holds any given rule.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Rules of engagement the agent cannot step outside (Priority: P1)

An operator authors a target scope for a session: the hosts and ports that may be tested, and
nothing else. During the session, the model runs ordinary tools — an HTTP client, a scanner — and
also bee's own request tool. Every in-scope request goes through and is recorded. Every attempt to
reach anything else is refused: by the proxy when the client uses it, and by the kernel when the
client tries to go around it. The refusal is recorded and the model is told plainly that the
destination is out of scope.

**Why this priority**: This is the reason to build the interceptor into bee rather than wrap an
existing one. Without it, the feature is a convenience; with it, an operator can hand an agent a
target and know where its traffic can and cannot go.

**Independent Test**: Author a scope naming one test host. From a tool child, attempt (a) an
in-scope request through the proxy, (b) an out-of-scope host through the proxy, (c) a direct
connection to an out-of-scope address that ignores the proxy setting, and (d) a direct connection
to the in-scope host that ignores the proxy setting. Only (a) succeeds; (b) is refused by the proxy,
(c) and (d) are denied in the kernel, and all three refusals are recorded.

**Acceptance Scenarios**:

1. **Given** a session whose target scope names `app.test:443`, **When** a tool child requests
   `https://app.test/` through the proxy, **Then** the request reaches the target and the exchange is
   recorded with the tool call that caused it.
2. **Given** the same session, **When** a tool child requests a host not in scope through the proxy,
   **Then** the proxy refuses it before any connection to that host is attempted, and the refusal is
   recorded.
3. **Given** the same session, **When** a tool child opens a connection directly to any address other
   than the proxy, **Then** the kernel denies it and the denial appears in the audit record —
   including when the address is that of an in-scope host.
4. **Given** a tunnelled HTTPS request whose requested host is in scope but whose TLS server name
   names a different host, **When** the proxy inspects the start of the TLS session, **Then** the
   tunnel is closed and the mismatch is recorded.
5. **Given** a local process that is not a tool child of this session, **When** it attempts to use the
   proxy, **Then** it is refused for lack of valid per-call credentials.
6. **Given** a build or session without kernel enforcement, or a policy in observe mode, **When** an
   operator starts a session with a target scope, **Then** bee refuses to start unless the operator
   explicitly acknowledges that scope will be advisory only, and that acknowledgement is printed at
   start and recorded in the transcript.
7. **Given** an enforced session, **When** a tool child attempts to read or modify the recorded
   traffic store, **Then** the kernel denies it and the denial is recorded.

---

### User Story 2 - Send, find, and read traffic without drowning in it (Priority: P1)

The model sends a request with bee's request tool — either as structured fields or as exact raw
bytes — and gets back a compact summary and an identifier. Later it asks the history for "every POST
to `/api/` that returned 500 in the last ten minutes" and receives a short table. It reads only the
part of a response it needs: headers, a byte range, lines matching a pattern, or one field of a JSON
body. Nothing it asks for returns an unbounded amount of text.

**Why this priority**: Together with US1 this is the minimum useful product: a scoped, recorded,
queryable channel to the target. Every later story builds on exchanges having identifiers and on the
store being queryable.

**Independent Test**: Against a local test target, send twenty requests of mixed methods and
statuses, including one with a multi-megabyte body. Query history by method and status; fetch one
response's headers only; fetch a JSON field from another; grep the large body. Each answer is
correct and within its size bound, and the large body is never returned whole.

**Acceptance Scenarios**:

1. **Given** an in-scope target, **When** the model sends a structured request, **Then** it receives an
   exchange identifier, the status, the response size, the elapsed time, and a bounded preview — not
   the full body.
2. **Given** a request supplied as raw bytes, **When** it is sent, **Then** the bytes on the wire are
   exactly those supplied (including unusual header ordering, casing, or duplicates), so that
   protocol-level tests remain possible.
3. **Given** a populated history, **When** the model queries it with a filter on host, method, path,
   status, size, time, or originating tool call, **Then** it receives one compact row per matching
   exchange, capped in count, with a statement of how many more matched.
4. **Given** an exchange with a large or compressed body, **When** the model requests a slice by byte
   range, by pattern, or by structured-field path, **Then** it receives only that slice, taken from
   the decoded body, with the total size stated.
5. **Given** any exchange, **When** it is shown to the model, **Then** content originating from the
   target is clearly marked as untrusted data rather than instructions.
6. **Given** any history row, **When** it is inspected, **Then** it names the tool call and turn that
   produced it — including traffic from tools other than bee's own request tool.

---

### User Story 3 - Widening scope is a human decision (Priority: P2)

Partway through a test, the model discovers that the application also calls `auth.app.test`, which
is not in scope. Its request is refused, and the refusal is turned into a request to widen scope
that the operator sees with the exact host and port. If the operator approves, the scope widens for
the rest of the session — in the proxy and in the kernel — and the model's request is retried once.
If the operator declines or does not answer in time, the scope is unchanged. The model has no tool
that widens scope by itself.

**Why this priority**: Real targets sprawl, and a scope that can only be fixed by restarting the
session will be written too broadly to begin with. A consented, recorded widening keeps the initial
scope tight.

**Independent Test**: Start with a one-host scope; have the model request a second host. Approve:
the request succeeds on retry and later direct-connection attempts to the new host's addresses are
permitted by the kernel only via the proxy. Repeat and decline: the request stays refused and the
scope is unchanged.

**Acceptance Scenarios**:

1. **Given** an out-of-scope refusal, **When** escalation is enabled for the session, **Then** the
   operator is asked to approve exactly that host and port, and nothing broader.
2. **Given** an approved widening, **When** the scope is updated, **Then** both the proxy's host check
   and the proxy's kernel-level reach are updated together, or neither is.
3. **Given** a requested widening beyond the operator's configured maximum authority, **When** it is
   evaluated, **Then** it is refused without asking the operator.
4. **Given** a declined or timed-out request, **When** the model is informed, **Then** it is told the
   scope did not change, and the transcript records the decision and who made it.

---

### User Story 4 - Look inside HTTPS where, and only where, the operator says (Priority: P2)

By default the proxy enforces scope on encrypted traffic without decrypting it — it sees the host
being requested and the TLS server name, and passes the encrypted stream through. When the operator's
scope marks a host for inspection, the proxy decrypts traffic to that host using a certificate
authority created for this session alone, so the model can read and replay those requests like any
other. Tool children are told to trust that authority; nothing outside the session ever is.

**Why this priority**: Most modern targets are HTTPS-only, so without inspection the request
tool works but replay, fuzzing, and intercept rules cannot see other tools' traffic. Making it opt-in
per host keeps the default posture minimal.

**Independent Test**: With one host marked for inspection and one in scope but not marked, make an
HTTPS request to each from a tool child. The first appears in history with full request and
response; the second appears as a tunnel to the host with byte counts only.

**Acceptance Scenarios**:

1. **Given** a host in scope but not marked for inspection, **When** HTTPS traffic flows to it,
   **Then** it is passed through encrypted and recorded as a tunnel with host, port, server name,
   timing, and byte counts.
2. **Given** a host marked for inspection, **When** a tool child makes an HTTPS request to it, **Then**
   the request and response are recorded in full and are available to every other tool in this
   feature.
3. **Given** a session ends, **When** its certificate authority is discarded, **Then** its private key
   has never been readable by any tool child, written outside the proxy's private state, or
   included in any transcript, store, or export.
4. **Given** a target that requires a newer protocol than the proxy supports on an inspected
   connection, **When** the connection is negotiated, **Then** the proxy offers only what it supports
   and records any failure clearly, rather than silently passing traffic through uninspected.

---

### User Story 5 - Replay with a diff, and a map of what has been seen (Priority: P2)

The model takes an earlier exchange, changes one thing — a header, a parameter, a field in a JSON
body — and resends it. What comes back is not two responses to compare by eye but a description of
what differs: status, length, timing, headers, and the changed regions of the body. Separately, the
model can ask for a map of the target: hosts, paths, and the parameters seen on each, with counts.

**Why this priority**: Replay-and-compare is the core loop of manual web testing. A model that must
read two full responses to notice a difference will miss small ones and spend its budget on large
ones.

**Independent Test**: Against a test endpoint that echoes a parameter, replay an exchange with the
parameter changed. The diff names the changed region and nothing else. Request the site map after
several requests and confirm every observed path and parameter appears.

**Acceptance Scenarios**:

1. **Given** a recorded exchange, **When** the model replays it with a list of edits, **Then** a new
   exchange is recorded, linked to the original, and the result is a bounded difference between the
   two responses.
2. **Given** two responses that differ only in values known to vary on every request (dates, request
   identifiers, anti-forgery tokens), **When** they are compared, **Then** the comparison reports them
   as volatile rather than as a meaningful change.
3. **Given** a populated history, **When** the model asks for the site map, **Then** it receives a
   bounded tree of hosts and paths with methods, observed parameter names, and counts.

---

### User Story 6 - Fuzz and see only what stands out (Priority: P3)

The model marks positions in a request and supplies payloads — from a built-in list, a range, or a
file in the project. bee sends the variants within the operator's rate limits and returns groups:
"981 responses alike (403, ~1.2 KB); 17 alike (200, ~4 KB); 2 outliers (500, slow, payload
reflected)". The model can then fetch any member of any group by identifier.

**Why this priority**: Valuable, but it depends on US2's store and US5's comparison, and it is the
feature most able to harm a target, so it comes after scope and consent are solid.

**Independent Test**: Against a test endpoint that misbehaves for exactly two of 1,000 payloads, run a
fuzz. The two appear as outliers in the summary; the summary stays within its size bound.

**Acceptance Scenarios**:

1. **Given** a request template with marked positions and payload sets, **When** the fuzz runs,
   **Then** every variant is sent, recorded, and attributed to that fuzz run.
2. **Given** completed results, **When** they are summarised, **Then** responses are grouped by status,
   size, timing, and whether a payload was reflected, and the summary fits within a fixed bound
   regardless of how many variants were sent.
3. **Given** an operator-set rate or concurrency limit, **When** a fuzz runs, **Then** the limit is never
   exceeded, and a fuzz that would exceed the operator's maximum request count is refused before it
   starts.
4. **Given** a fuzz in progress, **When** a variant is refused as out of scope, **Then** it is recorded
   as refused and does not count as a target response.

---

### User Story 7 - Shape other tools' traffic with rules, not clicks (Priority: P3)

While another tool runs — a scanner, a browser — the model sets rules: "add this header to every
request to `/api/`", "replace this cookie value", "hold any request whose body contains `role=` for
my review", "drop requests to the analytics host". Held requests wait for the model's decision and
are forwarded unchanged if it does not decide in time, so nothing deadlocks.

**Why this priority**: This is how a person uses an interceptor with tools that cannot be
modified; for an agent it must be declarative and time-bounded.

**Independent Test**: Install a replace rule and a hold rule, then run an HTTP client making three
requests. The replace is visible in recorded traffic; the held request is released by the model's
decision, and a second held request is released automatically at the timeout.

**Acceptance Scenarios**:

1. **Given** an active modification rule, **When** matching traffic passes, **Then** the recorded
   exchange shows both the original and the modified request.
2. **Given** a hold rule, **When** a matching request is held, **Then** the model can forward it,
   forward it edited, or drop it; if it does not, the request is forwarded unchanged at the timeout
   and that outcome is recorded.
3. **Given** a rule that would rewrite a request toward an out-of-scope destination, **When** it fires,
   **Then** the rewritten request is subject to the same scope check and is refused.
4. **Given** rules installed by the model, **When** the session ends, **Then** they are discarded and
   never persist into later sessions.

---

### User Story 8 - Evidence, leads, and findings stay separate (Priority: P3)

When the model records a finding, it can attach exchange identifiers as evidence, so a reviewer can
open the exact request and response. Meanwhile, the proxy notices things on its own as traffic flows
— a parameter reflected unencoded, a session cookie without protective attributes, a verbose error —
and records them as *leads*: suggestions the model may investigate. A lead is never a finding, and
the model is told which leads are new at the start of its next turn.

**Why this priority**: It closes the loop with the existing finding ledger and its human verdicts
(016), and passive observation is cheap value — but neither is required for the interceptor to be
useful.

**Independent Test**: Request a page with a reflected parameter. A lead appears and is announced on
the next turn; the finding ledger is unchanged. Record a finding citing the exchange; the ledger
entry links to it and the evidence can be opened.

**Acceptance Scenarios**:

1. **Given** a finding recorded with exchange identifiers, **When** it is reviewed, **Then** each
   identifier resolves to the stored exchange.
2. **Given** passive checks produce observations, **When** the next turn starts, **Then** the model is
   told how many new leads exist and can list them on request; no lead is added to the finding
   ledger without the model recording it as a finding.
3. **Given** a finding citing an exchange that has since been removed from the store, **When** it is
   reviewed, **Then** the missing evidence is reported as missing, not silently omitted.

---

### User Story 9 - Watch it live, delegate it narrowly, take it with you (Priority: P4)

The operator watches traffic arrive in a live pane of the full-screen interface. A subagent given a
narrower scope — for example, read-only requests to one host — is held to it by the same mechanism.
At the end, the session's traffic can be exported in a standard archive format for other tools.

**Why this priority**: Each is valuable and none is required for the core loop; the subagent part
depends on the subagent feature (018) landing first.

**Independent Test**: Run a session in the full-screen interface and observe new exchanges appear;
delegate to a subagent whose scope permits only one host and safe methods and observe its other
requests refused; export and re-import the archive in a third-party tool.

**Acceptance Scenarios**:

1. **Given** the full-screen interface, **When** exchanges are recorded, **Then** they appear in a live
   history pane, with target-supplied text rendered safely.
2. **Given** a subagent with a declared target scope, **When** it is delegated to, **Then** its scope is
   proven to be a subset of the parent's before it runs, and its out-of-scope requests are refused
   and attributed to it.
3. **Given** a session's history, **When** it is exported, **Then** the archive contains the selected
   exchanges, and never contains the session's certificate authority key or bee's own credentials.

---

### Edge Cases

- **Redirects**: the request tool never follows a redirect to a destination it has not scope-checked;
  every hop is checked, and a redirect out of scope is reported, not followed.
- **IP-literal targets and shared addresses**: a request naming an in-scope IP but an out-of-scope
  `Host` is refused by the proxy; the documentation states that two hosts sharing an address are
  indistinguishable at the kernel layer.
- **DNS changes mid-session**: the proxy resolves and checks the address it actually connects to;
  an in-scope name that now resolves only to addresses outside the kernel-permitted set is refused
  by the proxy before any connection, with the old and new addresses named.
- **Proxy failure**: if the proxy stops, tool children's traffic fails (they can reach nothing else);
  the model is told the interceptor is unavailable, and the session does not fall back to direct
  egress.
- **Non-HTTP traffic in a tunnel**: an uninspected tunnel to an in-scope host and port carries opaque
  bytes; a tunnel to any other destination is refused regardless of protocol.
- **Unsupported upgrades**: WebSocket upgrades and HTTP/2-only targets are refused or downgraded with
  a clear message in the first release, never passed through uninspected on an inspected host.
- **Credentials in captured traffic**: authorization headers and cookies are stored as captured,
  because testing requires them; the store is protected bee state that tool children can neither read
  nor modify directly, and exports flag such headers.
- **Store growth**: the store has an operator-set size cap; when reached, recording continues by
  evicting the oldest bodies (keeping their index rows), and evictions are reported, never silent.
- **Adversarial content**: a target response instructing the model to change scope, ignore findings,
  or run commands has no effect on scope, and is presented to the model as untrusted data.
- **Credential reuse**: a per-call proxy credential stops working when its tool call ends; replaying it
  from a later call is refused.
- **Concurrent sessions in one project**: two sessions recording into one project store do not corrupt
  it and each exchange remains attributed to its own session.

## Requirements *(mandatory)*

### Functional Requirements

**Prerequisites in the harness**

- **FR-001**: Tool output that originates outside bee (including all target-supplied HTTP content)
  MUST be delivered to the model marked as untrusted data, distinct from bee's own framing text.
- **FR-002**: The error status of a tool result MUST reach the model provider; a failed or refused
  tool call MUST NOT be indistinguishable from a successful one in the conversation.
- **FR-003**: bee MUST provide a harness-controlled way to supply tool children with proxy settings
  and a trusted certificate authority location; the model MUST NOT be able to set, remove, or override
  these values.

**Scope and enforcement**

- **FR-004**: The target scope MUST be declared as policy data (hosts and ports that may be tested,
  hosts and ports that may only be reached — for example a package registry — hosts marked for
  inspection, rate and volume limits), reviewable without running bee, and subject to the operator's
  maximum authority like every other capability. Reach-only hosts MUST be refused by every tool
  through which the model authors requests.
- **FR-004a**: When a target scope is declared, ALL network egress from tool children MUST pass
  through the proxy; a policy that also grants tool children direct network access MUST be rejected
  before the session starts, naming both declarations.
- **FR-005**: When a target scope is in effect, tool children's network reach MUST be limited by the
  kernel to the proxy alone.
- **FR-006**: The proxy MUST run in its own kernel scope whose network reach is limited to the target
  scope's resolved addresses and ports.
- **FR-007**: The proxy MUST refuse requests and tunnels to hosts outside scope before connecting to
  them, and MUST refuse a tunnel whose TLS server name does not match its requested host.
- **FR-008**: The proxy MUST accept only requests carrying a valid credential issued for a live tool
  call of this session, and MUST attribute every exchange to that call.
- **FR-009**: Every refusal — by the proxy or the kernel — MUST produce a structured audit event and
  a clear message to the model naming the destination and which layer refused it.
- **FR-010**: Sessions without blocking kernel enforcement — a build or host mode with no kernel
  enforcement, **or** a policy in observe (audit-only) mode, where the kernel records but allows —
  MUST refuse to start with a target scope unless the operator explicitly acknowledges advisory-only
  scope; the acknowledgement MUST be announced at start and recorded, and every scope report in such
  a session MUST say the scope is advisory.
- **FR-011**: The scope view offered to the model MUST be read-only and MUST label each rule as
  kernel-enforced or proxy-enforced.
- **FR-012**: An out-of-scope refusal MUST be convertible, when escalation is enabled, into a request
  to widen scope by exactly the refused host and port, approved only by a human within the operator's
  maximum authority; an approved widening MUST update the proxy and kernel layers atomically.

**Recording and retrieval**

- **FR-013**: Every exchange MUST be recorded in a project-local store with an identifier, timestamps,
  originating tool call, turn, and (where applicable) fuzz run or replay origin.
- **FR-014**: The store MUST be protected bee state: tool children MUST NOT be able to read or write
  it directly.
- **FR-015**: The model MUST be able to query history by host, method, path, status, size, time,
  originating call, and tags, receiving compact rows capped in number with a count of the remainder.
- **FR-016**: The model MUST be able to retrieve any part of an exchange — headers, a byte range,
  lines matching a pattern, or a structured-field path of the decoded body — within a fixed size bound.
- **FR-017**: Every tool in this feature MUST bound its output; no call may return an unbounded amount
  of target-supplied content.

**Agent tools**

- **FR-018**: The model MUST be able to send a request as structured fields or as exact raw bytes;
  raw requests MUST be sent byte-for-byte.
- **FR-019**: The model MUST be able to replay a recorded exchange with a list of edits and receive a
  bounded difference against the original, with volatile values identified as such.
- **FR-020**: The model MUST be able to request a bounded site map of hosts, paths, methods,
  parameters, and counts.
- **FR-021**: The model MUST be able to run a fuzz from a marked template and payload sets, receiving
  a bounded, grouped summary; the operator's rate, concurrency, and total-volume limits MUST be
  enforced, and an over-limit fuzz refused before it starts.
- **FR-022**: The model MUST be able to install session-scoped hold, modify, and drop rules over other
  tools' traffic; held requests MUST auto-forward unchanged at a timeout; rules MUST NOT persist past
  the session; rewritten requests MUST be scope-checked again.
- **FR-023**: Redirects MUST NOT be followed without scope-checking each hop.

**TLS inspection**

- **FR-024**: HTTPS to hosts not marked for inspection MUST be passed through encrypted and recorded
  as a tunnel with metadata only.
- **FR-025**: HTTPS to hosts marked for inspection MUST be decrypted using a certificate authority
  unique to the session, whose private key is never available to tool children, never persisted
  outside the proxy's private state, and never included in any transcript, store, or export.
- **FR-026**: Tool children MUST be configured to trust the session authority only when inspection is
  enabled, and only for the session's lifetime.

**Findings and leads**

- **FR-027**: Findings MUST be able to cite exchange identifiers as evidence; unresolved citations
  MUST be reported as missing.
- **FR-028**: Passive checks MUST record observations as leads, separate from the finding ledger; the
  model MUST be told of new leads at the start of its next turn and MUST be able to list leads on
  request through a dedicated lead listing, separate from traffic history; leads MUST NOT become findings except
  by the model recording them.

**Packaging and later surfaces**

- **FR-029**: The feature MUST be selectable at build time and absent from builds that do not select
  it; a build without it MUST report the tools as unavailable rather than missing or silently
  inert, and MUST leave the default build's dependencies unchanged.
- **FR-030**: The full-screen interface MUST offer a live history view that renders target-supplied
  text safely.
- **FR-031**: A subagent's target scope MUST be proven a subset of its parent's before it runs and
  enforced by the same mechanism.
- **FR-032**: History MUST be exportable in a widely supported HTTP archive format, excluding the
  session authority key and bee's own credentials.

### Delivery Milestones

| Milestone | Stories | Requirements |
|-----------|---------|--------------|
| M1 — scoped channel | US1, US2 | FR-001–FR-011 (incl. FR-004a), FR-013–FR-018, FR-023, FR-024, FR-029 |
| M2 — inspection and replay | US3, US4, US5 | FR-012, FR-019, FR-020, FR-025, FR-026 |
| M3 — automation and evidence | US6, US7, US8 | FR-021, FR-022, FR-027, FR-028 |
| M4 — surfaces | US9 | FR-030–FR-032 |

### Key Entities

- **Target scope**: the operator-authored set of hosts and ports that may be tested, hosts and ports
  that may only be reached (never tested), which hosts may be inspected, and the session's rate and
  volume limits. Part of policy; attenuable; widened only by
  human consent.
- **Exchange**: one request and its response (or refusal), with identifier, timing, sizes, the
  originating tool call and turn, optional parent exchange (replay) or fuzz run, and tags.
- **Tunnel record**: metadata for an uninspected encrypted connection — host, port, server name,
  timing, byte counts.
- **Body**: the stored content of a request or response, kept separately from the exchange index and
  shared between exchanges with identical content.
- **Call credential**: a short-lived secret binding proxy use to one live tool call.
- **Session authority**: the per-session certificate authority used for inspection; exists only for the
  session and only inside the proxy.
- **Fuzz run**: a template, payload sets, limits, and the grouped summary of its exchanges.
- **Intercept rule**: a session-scoped match condition and action (hold, modify, drop) with a timeout.
- **Lead**: a passive observation tied to one or more exchanges; distinct from a finding.
- **Finding (extended)**: the existing finding, now able to cite exchanges as evidence.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the kernel-enforced test matrix, 100% of direct connection attempts by tool children
  to any address other than the proxy are denied and recorded, including attempts to in-scope hosts.
- **SC-002**: 100% of out-of-scope requests and server-name mismatches made through the proxy are
  refused before any connection to the out-of-scope destination is attempted.
- **SC-003**: 100% of recorded exchanges are attributed to a tool call; zero exchanges are recorded from
  processes outside the session.
- **SC-004**: No single tool response in this feature exceeds its documented size bound, for any target
  response size up to at least 100 MB.
- **SC-005**: Against a reference test target with planted issues (a reflected parameter, an
  authorisation bypass reachable by one header change, and an error-triggering payload), an agent
  using these tools finds each in no more than 15 tool calls and with at least 50% fewer tokens of tool
  output than the same task performed with only a general shell and an HTTP client.
- **SC-006**: A 1,000-variant fuzz against a target misbehaving for 2 payloads surfaces both as outliers
  in a summary that fits the documented bound, 10 runs out of 10.
- **SC-007**: The proxy adds no more than 50 ms median and 200 ms 95th-percentile latency to an in-scope
  request against a local target, measured on the dedicated enforcement test machine.
- **SC-008**: The session authority's private key is found in zero files, transcripts, exports, or
  tool-child-readable locations after a session that used inspection.
- **SC-009**: A build that does not select the feature has an unchanged dependency graph and reports
  each tool in this feature as unavailable when invoked.
- **SC-010**: Every scope widening in a test run corresponds to exactly one recorded human approval;
  zero widenings occur without one.

## Assumptions

- The operator testing a target is authorised to do so; the declared target scope is the operator's
  statement of that authorisation, and bee's job is to hold the agent to it, not to verify it.
- HTTP/1.1 over plain TCP and TLS is the first-release protocol surface; HTTP/2, HTTP/3, and WebSockets
  are out of the first release and handled per the edge cases above.
- The existing connection hook's IP/port granularity is the kernel layer; host-name rules are a
  proxy-layer defence, documented as such. Gaps in the kernel layer that are already tracked (for
  example, unconnected datagram sends) remain tracked separately and are named in the plan.
- The scope may be declared in operator policy; project configuration may request a scope but cannot
  exceed the operator's maximum authority, consistent with existing configuration rules.
- Escalation reuses the existing dynamic-grant consent flow (007) rather than introducing a new one.
- Kernel connection denials today are recorded without their destination; meeting FR-009 for the
  kernel layer includes recording it. This also benefits sessions that never use interception.
- Per-subagent scopes depend on the subagent delegation feature (018) and are delivered after it.
- The store lives under the project's `.bee/` directory alongside the finding ledger, with an
  operator-set size cap and a sensible default.
- Choices of proxy engine, store format, and history query syntax are design decisions for the plan;
  this specification constrains only their observable behaviour (raw-byte fidelity, bounded output,
  structured queries the model can form reliably).

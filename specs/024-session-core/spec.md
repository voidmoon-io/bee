# Feature Specification: One Session Core for Autonomous and Interactive bee

**Feature Branch**: `024-session-core`

**Created**: 2026-10-10

**Status**: Draft

**Input**: User description: "One session core for autonomous and interactive bee. bee must run both as a fully autonomous agent (Hermes-style, no human interaction) and as an interactive agent (REPL/TUI with a human approving grants), with the difference between the two living in exactly one swappable seam — an Operator (consent decisions + output) with two adapters, Interactive and Autonomous. Everything else must be shared rather than duplicated. Consolidate five areas found duplicated or drifted in an architecture review: the tool surface, the tool-call lifecycle, hooks, session building, and typed Interceptor operations."

## Context & Motivation

bee already runs two ways. `bee run` drives a headless episode: no one is watching, consent is
decided by the capability ceiling, and progress is a stream of lines. `bee repl` (and its full-screen
TUI) drives an interactive session: a person reads the output and answers grant prompts. The next
step for bee is to be a first-class **autonomous agent** — long-running, picking up its own work, with
no human in the loop — while staying a first-class **interactive agent** for the operator who wants to
drive it by hand.

Those two modes genuinely differ in only two things: **who decides a consent request** and **where
output goes**. Everything else — how a session's scope, grants, proxy and tools are assembled; how one
tool call is run, audited, escalated and retried; when leases expire — must be the same, because the
security properties bee promises are properties of that shared machinery.

Today they are not shared. An architecture review found the difference between the modes smeared
across copies that have already drifted apart:

- **A session is assembled in four places** — the headless episode, the REPL, the concurrent batch
  runner, and the test harness — and the shared construction logic lives in the binary rather than the
  library, which Constitution V forbids ("the CLI MUST NOT contain … logic the library lacks"). The
  copies disagree: the REPL never widens the scanner's report directory, so `scan` fails under
  enforcement; the concurrent runner silently ignores skills, MCP servers, security-tool configuration
  and escalation; `bee run --task` silently drops the user's and project's MCP servers and skills;
  there are three different copies of the `[policy.http]` advisory check; the two front-ends tear down
  in different orders; the headless path never builds the same system prompt the REPL does.
- **The tool surface the model sees is assembled in seven places**, where a later registration
  silently replaces an earlier one and configuration is applied by re-passes that every path must
  remember. Escalation forgets them: a tool granted mid-session arrives unconfigured — an `http_*` tool
  reports "interceptor unavailable" while the Interceptor is running, `scan` refuses as not granted,
  and `record_finding` writes to the wrong finding ledger.
- **One tool call is a ~150-line protocol** — open the call, run the tool, settle, drain audit, escalate
  on a kernel denial and retry, close the call, escalate on a proxy refusal and retry, drain the proxy
  scope, drain again — copied into both loops, with its ordering rules living only in comments. The
  copies disagree on what the audit trail records, on what counts as a denial, and on what a "turn" is.
  The retry path has no test that runs without a VM.
- **The hook system is half-built.** Three of its six events are never fired, three of its five
  outcomes are silently ignored, and turn-limited grant leases never expire because nothing asks them
  to.
- **The Interceptor's operations are locked inside its tools.** Redirect following, replay edits,
  fuzz templating and sitemap building exist only as private steps inside tools that take untyped
  JSON, with helpers shared by reaching into sibling tools.

Each drift is a small bug. Together they mean that "how bee behaves" depends on which entry point
started it — the opposite of what an autonomous agent needs, where nobody is watching to notice the
difference.

This feature consolidates those five areas so that each concept has exactly one owner, and the only
thing an entry point chooses is its **Operator**. It is also the prerequisite for 023-codemode, whose
script-issued tool calls must run through the same call lifecycle and whose tool catalog must come from
the same tool surface.

### Terms this spec introduces

- **Operator** — the one seam where autonomous and interactive bee differ: it answers consent
  requests and receives session output. Two adapters: **Interactive** (a person answers through the
  REPL/TUI input path) and **Autonomous** (no person; decisions follow the ceiling and are logged).
- **Session builder** — the one place that turns a session specification and an Operator into a
  running session: policy, grants, sandbox, Interceptor, tool surface, escalation, system prompt.
- **Tool surface** — the set of tools the model can call in a session, each constructed with its
  session dependencies, derivable from one place at any moment.
- **Call lifecycle** — everything that happens to one tool call from the moment the model requests it
  to the moment its result is recorded, including audit, escalation and retry.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The same session, whoever started it (Priority: P1)

An operator configures bee once — user configuration, project configuration, policy, skills, MCP
servers, `[policy.http]` targets — and starts it headless with `bee run`, interactively with
`bee repl`, or as a batch. In every case the session has the same scope, the same grants, the same
tools, the same system prompt, and the same Interceptor. The only differences are who answers consent
requests and where output goes. A combination bee cannot support (for example, the Interceptor in a
concurrent batch) is refused at start-up with a message naming what is unsupported — never started
with that part silently missing.

**Why this priority**: An autonomous agent is only trustworthy if its behaviour is the behaviour the
operator saw when they tried it interactively. Every entry-point drift found in the review is a case
where it was not.

**Independent Test**: From one set of inputs, build a session through each entry point's path and
compare the resulting policy, grants, tool surface (names and their configured dependencies),
escalation settings and system prompt. They are identical except for the Operator. Then confirm each
previously drifted behaviour (scanner report directory, `--task` with MCP and skills, concurrent with
unsupported features) behaves as specified.

**Acceptance Scenarios**:

1. **Given** a project with MCP servers and skills configured, **When** the operator runs
   `bee run --task "…"`, **Then** the session has the same MCP tools and skills as `bee repl` started
   in the same project.
2. **Given** an enforced session with the `scan` tool granted, **When** it is started from the REPL,
   **Then** `scan` can write its reports, exactly as it can in a headless episode.
3. **Given** a concurrent batch whose scenario declares `[policy.http]` targets or MCP servers,
   **When** it starts, **Then** it refuses with a message naming the unsupported feature, instead of
   running without it.
4. **Given** the same inputs, **When** a session is built for the headless, REPL, TUI and batch entry
   points, **Then** each receives the same system prompt (including the notes for `render` and `skill` when
   those tools are present).
5. **Given** any session with an Interceptor and MCP servers, **When** it ends, **Then** its parts are
   torn down in one defined order, the same for every entry point.

---

### User Story 2 - An autonomous agent that decides within its ceiling and leaves a record (Priority: P1)

An operator deploys bee to work without supervision. When a tool call needs a capability the session
does not hold — a kernel denial, a skill's requirements, a proxy refusal for an unlisted host — the
Autonomous Operator decides it: a request within the capability ceiling is granted, anything beyond it
is refused, and nothing ever waits for a person. Every decision, granted or refused, is recorded with
what was asked, why, and what was decided, so the operator can review afterwards exactly what the
agent widened and why.

**Why this priority**: This is the mode the feature exists to enable. Without a defined, logged
decision path, an autonomous agent either stalls waiting for a person who is not there, or widens its
scope with no trace.

**Independent Test**: Run a scripted session with the Autonomous Operator in which a tool call is
denied for a resource inside the ceiling and another for a resource outside it. The first is granted
and retried; the second is refused; no prompt is issued; both decisions appear in the session record
with their request, reason and outcome.

**Acceptance Scenarios**:

1. **Given** the Autonomous Operator and a ceiling that permits a resource, **When** a tool call is
   denied access to it, **Then** the grant is made without waiting for input, the call is retried once,
   and the decision is recorded.
2. **Given** the Autonomous Operator, **When** a request exceeds the ceiling, **Then** it is refused
   without being offered to anyone, and the refusal is recorded with its reason.
3. **Given** the Interactive Operator, **When** the same within-ceiling request occurs, **Then** the
   person is asked through the REPL/TUI input path — never by a separate read of the terminal — and the
   answer is recorded the same way.
4. **Given** either Operator, **When** a consent decision is not made within the consent timeout,
   **Then** the request is refused (fail-closed), and the refusal is recorded.

---

### User Story 3 - One tool call means the same thing everywhere (Priority: P1)

Whether a tool call comes from the headless loop, the interactive loop, or — later — from a codemode
script, it goes through one call lifecycle: it is opened, run, audited, escalated and retried by the
same rules, and produces one outcome: the result, the complete audit, the audit of the attempt that
was denied, any proxy events, whether it was retried or timed out, and what was escalated. The audit
trail always shows the denial that justified widening scope. Proxy-scope denials are always reported
as the proxy's, never counted as the tool's. A time-limited grant is measured in model turns.

**Why this priority**: The call lifecycle is where bee's security record is made. Two copies that
disagree on what the audit trail contains mean the forensic record depends on the entry point.

**Independent Test**: Without a model, a provider or a VM, drive the call lifecycle with a scripted
tool and a scripted source of kernel and proxy events, covering: no denial; kernel denial → grant →
successful retry; kernel denial → refused; proxy refusal → grant → retry; retry that times out; a
late audit event arriving after the call. Check each outcome. Then run the same scripts through both
loops and confirm they record identical audits and denial counts.

**Acceptance Scenarios**:

1. **Given** a tool call denied by the kernel and then granted and retried successfully, **When** the
   session record is inspected in either mode, **Then** it contains both the original denial and the
   retry's events, attributed to that call.
2. **Given** a tool call during which the proxy scope records a denial, **When** denials are counted
   or a result is tagged as denied, **Then** the proxy-scope denial is shown as the proxy's and is not
   counted as the tool's denial — in both modes.
3. **Given** a grant with a lifetime of N turns, **When** the model takes N further turns (however many
   tool calls each makes), **Then** the grant expires and the scope narrows — in both modes.
4. **Given** a retry that times out, **When** the outcome is recorded, **Then** the result and the
   audit shown for the call belong to the same attempt, and the call is marked timed out.
5. **Given** an interactive session with a tool timeout of T, **When** a call is retried, **Then** the
   first attempt and the retry together finish within T; the retry gets only the time the first attempt
   left, and is not started if none is left.
6. **Given** kernel audit events that arrive after a call's last attempt finished, **When** the call is
   recorded, **Then** they are attributed to that call, never to the next one.

---

### User Story 4 - Every granted tool works the moment it is granted (Priority: P2)

When a grant adds a tool mid-session — through a skill's requirements or an operator's approval — the
tool arrives fully configured with the session's Interceptor, finding ledger, scanner grants and other
dependencies, exactly as if it had been present from the start. At any moment there is one answer to
"which tools can the model call, and how is each configured", and that answer is what the model is
shown.

**Why this priority**: Today a granted tool can be present but broken, which reads to the model as a
wall that is not there — the failure mode bee's three-state tool outcome (016) exists to prevent.

**Independent Test**: Start a session with the Interceptor running but without the HTTP tools; grant
one mid-session; call it and confirm it reaches the Interceptor. Repeat for `scan` (uses the session's
scanner grants) and `record_finding` (writes to the session's finding ledger). Compare the tool surface
after the grant with a session that held the tool from the start; they match.

**Acceptance Scenarios**:

1. **Given** a session whose Interceptor is running, **When** an `http_*` tool is granted mid-session
   and called, **Then** it uses the session's Interceptor and does not report it unavailable.
2. **Given** a session with a configured finding ledger, **When** `record_finding` is granted
   mid-session and called, **Then** the finding is written to that session's ledger.
3. **Given** any session, **When** the tool surface is listed, **Then** the list and each tool's
   configured dependencies come from one place, and are what the model is offered.

---

### User Story 5 - Hooks do what they say (Priority: P2)

An embedder or a built-in policy reacts to the session through hooks. The start of every model turn is
an event hooks receive; turn-limited grants expire there, and MCP servers that changed their tool list
are refreshed there. A hook that refuses a tool call before it runs actually stops it, and the model
receives a refusal it can tell apart from a failure. A hook that releases a grant narrows the scope.
Events and outcomes that nothing implements do not exist, so an embedder cannot write a hook for one and
have it silently ignored.

**Why this priority**: A security hook that is accepted and then ignored is worse than none — it gives
false assurance (Constitution I). Lease expiry is the concrete casualty today.

**Independent Test**: Register a hook that refuses one named tool and another that releases a grant on
a given turn; run a scripted session and confirm the tool call is refused before execution, the grant
is released and the scope narrowed, turn-limited leases expire on schedule, and MCP refresh happens at
turn start.

**Acceptance Scenarios**:

1. **Given** a hook that refuses a tool before it runs, **When** the model calls that tool, **Then** the
   tool does not execute and the model receives a refusal stating a hook declined it.
2. **Given** a grant with a turn-limited lifetime, **When** its last turn passes, **Then** the scope is
   narrowed at the next turn start, in both modes.
3. **Given** an MCP server that reported a changed tool list, **When** the next turn starts, **Then** the
   tool surface reflects the change before the model is called.
4. **Given** the hook interface, **When** an embedder inspects it, **Then** every event it offers is
   fired and every outcome it accepts is acted on.

---

### User Story 6 - The Interceptor's operations are usable without its tools (Priority: P3)

A maintainer, an embedder, or a codemode script works with the Interceptor through typed operations —
send (with redirect following that stops at the target scope), replay with edits and a diff, fuzz from a
template, build a sitemap — rather than through tools that accept untyped JSON. The `http_*` tools
become thin translations from the model's JSON to those operations, and share one way of reporting
that the Interceptor is unavailable and of bounding their output.

**Why this priority**: It concentrates the Interceptor's behaviour in one place and removes repeated
code, but no user-visible behaviour depends on it; it is ordered last.

**Independent Test**: Exercise each typed operation directly against a local test target and confirm
the same exchanges, redirect stops, replay diffs and sitemaps the corresponding tools produce today;
then confirm each tool's output for the same inputs is unchanged.

**Acceptance Scenarios**:

1. **Given** a redirect to a host outside the target scope, **When** the send operation follows
   redirects, **Then** it stops at the out-of-scope hop and reports it, exactly as `http_send` does today.
2. **Given** any `http_*` tool and fixed inputs, **When** it runs before and after this change, **Then**
   its output is the same.

---

### Edge Cases

- A consent request arrives while the Interactive Operator's person is mid-input: the request is
  surfaced through the same input path, and their partially typed line is neither sent as the answer nor
  lost.
- The Autonomous Operator receives a request with no ceiling configured: the ceiling equals the base
  policy, so every widening is refused and recorded; the session continues.
- A tool is granted mid-session whose dependency the session does not have (an `http_*` tool in a
  session with no `[policy.http]`): the tool is present and reports the dependency as unavailable in its
  fail-closed outcome — the same as if it had been present from the start.
- A retry runs out of the call's remaining time (either timeout policy, FR-024): no retry starts, and the
  call's outcome says why.
- A kernel denial and a proxy refusal occur in the same call: only one retry happens, the call's record
  shows both, and escalation is driven by the tool-scope denial, never by the proxy scope's events.
- An MCP server's own process activity occurs while no tool call is open: it is recorded against the MCP
  server, never against whichever tool call happens to be open. (Activity of processes the server spawns
  is a documented limitation until 018 — FR-027.)
- An entry point asks for a combination the Session builder cannot provide: start-up fails with a
  diagnostic, before any scope is created.
- A hook refuses a tool call and another hook proposes a grant for the same call: refusal wins.

## Requirements *(mandatory)*

### Functional Requirements

**Operator (the one difference between modes)**

- **FR-001**: Every session MUST be started with exactly one Operator, and consent decisions and session
  output MUST reach the rest of bee only through it.
- **FR-002**: bee MUST provide an Interactive Operator that asks a person through the active front-end's
  input path (inline REPL or TUI) and never reads the terminal independently of that path.
- **FR-003**: bee MUST provide an Autonomous Operator that never waits for a person: a request within the
  capability ceiling is granted and a request beyond it is refused.
- **FR-004**: Every consent decision, under either Operator, MUST be recorded in the session record with
  the request (including every capability kind requested — tools, filesystem, executables, network,
  Target scope), its origin (start-up skill grant, kernel denial, skill requirement, proxy refusal, explicit),
  the decision, and the reason. A request whose capabilities are all already held is not a decision and
  is not recorded.
- **FR-005**: A consent request not decided within the consent timeout MUST be refused and recorded as
  refused.

**Session builder**

- **FR-006**: There MUST be one Session builder, part of the library, used by the headless, interactive
  (inline and TUI), and batch entry points and by the test harness.
- **FR-007**: Given the same inputs, the Session builder MUST produce the same policy, grants, sandbox
  configuration, Interceptor configuration, tool surface, escalation settings and system prompt for every
  entry point; only the Operator may differ.
- **FR-008**: The Session builder MUST refuse, before creating any scope, any combination it cannot
  provide (for example, the Interceptor or MCP servers in a concurrent batch), naming what is
  unsupported. It MUST NOT start a session with a configured feature silently absent.
- **FR-009**: `bee run --task` MUST honour the user's and project's MCP servers and skills, as every other
  entry point does.
- **FR-010**: The scanner's report directory MUST be made writable for `scan` in every entry point where
  `scan` is granted.
- **FR-011**: The `[policy.http]` enforcement advisory MUST be computed in one place and reported the same
  way by every entry point.
- **FR-012**: A session MUST have one defined teardown order for its parts (tool children, Interceptor,
  MCP servers, scopes), owned by the session and identical for every entry point.

**Tool surface**

- **FR-013**: Every tool MUST be constructed, at start-up and when granted mid-session, by one constructor
  that supplies the session's dependencies (Interceptor, finding ledger, scanner grants, CTF flag, and any
  other session-held dependency).
- **FR-014**: A tool granted mid-session MUST behave identically to the same tool present from the start.
- **FR-015**: The set of tools offered to the model, and each tool's configured dependencies, MUST be
  derivable from one place at any moment, and the model MUST be offered exactly that set.
- **FR-016**: A tool whose dependency the session lacks MUST report it through its fail-closed outcome
  (016), never as a silently degraded tool.

**Call lifecycle**

- **FR-017**: Every tool call, from every loop, MUST run through one call lifecycle that opens the call,
  runs the tool, collects its audit, escalates and retries as specified below, closes the call, and
  returns a single outcome.
- **FR-018**: The call outcome MUST contain: the result; the complete audit for the call; the audit of
  any attempt that was denied before a retry; proxy events; whether the call was retried; whether it
  timed out; and every escalation attempted with its outcome.
- **FR-019**: A kernel denial MUST trigger at most one escalation and at most one retry within the same
  call; a proxy refusal for an out-of-scope host MUST trigger at most one escalation and at most one
  retry; a call MUST be retried at most once in total.
- **FR-020**: A retry MUST happen only when the escalation widened the scope; a request that was already
  held, refused, or timed out MUST NOT be retried.
- **FR-021**: The audit trail MUST retain the denial that triggered an escalation, in both modes.
- **FR-022**: Proxy-scope denials MUST be reported as the proxy's and MUST NOT be counted as, or tag the
  result as, the tool's denial, in both modes. Proxy-scope events MUST NOT drive tool-scope escalation.
- **FR-023**: Kernel audit events produced by a call MUST be attributed to that call even when they arrive
  after its last attempt finished; they MUST NOT be attributed to a later call.
- **FR-024**: The timeout policy MUST be a parameter of the call lifecycle: the episode's overall deadline
  (headless) or a per-call limit (interactive) that the first attempt and any retry share. In both cases
  a retry receives only the time remaining, and no retry starts once that time is used up.
- **FR-025**: When an attempt times out, the result and audit recorded for the call MUST belong to the
  same attempt, and the outcome MUST be marked timed out.
- **FR-026**: The call lifecycle MUST be testable without a model, a provider or a BPF-LSM kernel, using
  a scripted tool and a scripted source of audit and proxy events.
- **FR-027**: Kernel audit events produced by an MCP server's own process MUST be attributed to that
  server, never to whichever tool call happens to be open. Processes an MCP server spawns are not
  separable from the tool scope until MCP servers run in their own scope (018-subagent-scopes); until
  then their events stay in the tool scope's stream, and this limitation MUST be stated in the session
  documentation rather than presented as attribution.

**Hooks and grant leases**

- **FR-028**: The start of each model turn MUST be dispatched to hooks as an event.
- **FR-029**: A grant's lifetime in turns MUST be counted in model turns, in both modes, and expired
  leases MUST be removed and the scope narrowed at the start of the turn on which they expire.
- **FR-030**: MCP tool-list refresh MUST happen at turn start through the same hook mechanism, not
  through a separate per-loop mechanism.
- **FR-031**: A hook that refuses a tool call before it runs MUST prevent execution, and the model MUST
  receive a refusal distinguishable from a tool failure.
- **FR-032**: A hook that releases a grant MUST cause the lease to be released and the scope narrowed.
- **FR-033**: The hook interface MUST NOT offer events that are never dispatched or outcomes that are
  never acted on.
- **FR-034**: When hooks disagree on a call, a refusal MUST take precedence over a grant proposal.

**Interceptor operations**

- **FR-035**: The Interceptor MUST expose typed operations for send (including redirect following that
  stops at the Target scope), replay with edits and diff, fuzz from a template, and sitemap building,
  usable without going through a tool.
- **FR-036**: Each `http_*` tool MUST translate its JSON arguments to those operations and MUST NOT
  contain Interceptor logic of its own; the unavailable-Interceptor report and output bounding MUST be
  shared, not repeated per tool. Shaping an operation's result into the tool's output text, and reading
  tool inputs the model names by path (e.g. a fuzz payload file), stay in the tool.
- **FR-037**: Helpers shared by several `http_*` tools MUST live with the Interceptor operations, not in
  an individual tool.
- **FR-038**: Every call origin bee defines MUST be used; unused origins MUST be removed.

**Behaviour preservation and delivery**

- **FR-039**: Apart from the drift fixes this specification lists, the observable behaviour of
  `bee run`, `bee repl` and the TUI MUST be unchanged: same tools, same results, same exit codes, and the
  same transcript, audit and progress formats. Additions are permitted only where this feature defines
  them — the new call-outcome and consent fields of the session record, which are omitted when empty,
  and the consent progress line — and no existing field or line changes meaning.
- **FR-040**: Characterization tests that exercise the call lifecycle through both loops, and that compare
  sessions built by every entry point, MUST exist and pass before any of the consolidation they cover is
  changed.
- **FR-041**: Delivery MUST be phased, one reviewable change per area, in this order: characterization
  tests → tool surface → call lifecycle → hooks and leases → Session builder and Operator → Interceptor
  operations. Each phase MUST leave the full test suite passing.
- **FR-042**: Narrowing the kernel scope when a lease expires or is released (FR-029, FR-032) is an
  enforcement claim, and MUST be verified on a BPF-LSM kernel (Constitution III): a resource granted by
  a lease is reachable while the lease is live and denied by the kernel after it expires or is released.
  Host tests verify only that narrowing is requested.

### Resolved Decisions

These were settled before specification and are not open questions:

- **D1 — Pre-retry denial is kept.** The denial that triggered an escalation stays in the audit trail in
  both modes. It is the event that justified widening scope (FR-021).
- **D2 — The two denial layers are never conflated.** Proxy-scope denials are reported separately from,
  and never counted as, the tool's denials, everywhere (FR-022).
- **D3 — A lease "turn" is a model turn**, in both modes (FR-029).
- **D4 — The Autonomous Operator grants within the ceiling and logs every decision.** The ceiling is the
  authority bound; with no person present, refusing everything would make escalation meaningless
  (FR-003, FR-004).
- **D5 — Behaviour is preserved except for listed drift fixes**, and characterization tests come first
  (FR-039, FR-040).
- **D6 — Phased delivery, one change per area**, in the order of FR-041.

### Key Entities

- **Operator**: decides consent requests and receives session output. Interactive or Autonomous.
- **Session specification**: everything an entry point knows before start — effective configuration,
  policy and ceiling, skills, MCP servers, Target scope, enforcement mode, timeouts, entry-point kind.
- **Session**: the running result of the Session builder — scope(s), active policy and leases,
  Interceptor, MCP connections, tool surface, system prompt, Operator; owns teardown.
- **Tool surface**: the tools the model can call now, each with its session dependencies.
- **Call outcome**: the single record of one tool call (FR-018).
- **Consent decision record**: one decision with its request, origin, outcome, reason and Operator kind.
- **Grant lease**: an approved widening with its origin and lifetime in model turns.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For the same inputs, sessions built for the headless, inline-REPL, TUI and batch entry
  points differ in exactly one respect — the Operator — as checked by an automated comparison test.
- **SC-002**: The tool-call protocol exists in exactly one place; neither loop contains its own copy of
  open/run/audit/escalate/retry/close.
- **SC-003**: Every drift listed in Context & Motivation has a test that failed before this feature and
  passes after it (at least nine: scanner report directory, `--task` MCP/skills, concurrent silent drops,
  the `[policy.http]` advisory differing by entry point, teardown order, system prompt, unconfigured granted tools, audit/denial/turn
  disagreements between loops, lease expiry).
- **SC-004**: Every retry path in the call lifecycle (kernel and proxy; granted, refused, timed out; late
  audit) is covered by tests that run on a machine without BPF-LSM and without a model.
- **SC-005**: An autonomous session completes a scripted run that requires one within-ceiling and one
  beyond-ceiling escalation with zero prompts issued, and its record lists both decisions with request,
  origin, outcome and reason.
- **SC-006**: The places that construct non-MCP tools drop from seven to one constructor plus its callers,
  and no configuration re-pass remains. (MCP tools keep their own constructor, as a separate family.)
- **SC-007**: Every hook event offered is dispatched and every hook outcome offered is acted on, verified
  by test.
- **SC-008**: Apart from listed drift fixes, the existing test suite passes unchanged at every phase,
  including the `intercept` feature build and the enforce build's checks.
- **SC-009**: The two loops each shrink by at least the size of the duplicated call protocol (~150
  lines), and the four session-assembly paths are replaced by calls to one builder.
- **SC-010**: The BPF-LSM test matrix includes a lease-expiry case and a release case that pass: access
  is allowed during the lease and denied by the kernel after it.

## Assumptions

- The consent timeout values in use today (60 s headless, 120 s interactive) are kept as each Operator's
  default; unifying them is not in scope.
- The headless loop (non-streaming, deadline-bounded) and the interactive loop (streaming, steerable)
  remain two loops; this feature shares everything around them, not the loops themselves. Merging the
  loops is a possible follow-up, not a requirement.
- "Hermes-style" autonomy here means a session that runs to completion without human input. Task intake
  (e.g. pulling work from a board, 021) and long-running scheduling are separate features that build on
  this one.
- The Autonomous Operator's decision log goes into the existing session record (transcript and audit
  trail); a separate log sink is not required.
- The concurrent batch runner keeps its current capabilities; this feature makes its limits explicit
  rather than lifting them (lifting them depends on 018-subagent-scopes).
- VM-tier (BPF-LSM) tests remain the authority for kernel enforcement claims (Constitution III); the
  host-testable call lifecycle tests verify orchestration, not enforcement.

## Dependencies

- Builds on 007-dynamic-grants (escalation, leases, consent), 016-native-tools (three-state tool
  outcome), 019-http-intercept (Interceptor, Proxy scope, Target scope), 004-mcp-client and 006-skills.
- Prerequisite for 023-codemode.

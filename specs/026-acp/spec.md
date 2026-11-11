# Feature Specification: ACP — bee as an Agent, and Foreign Harnesses as Scoped Subagents

**Feature Branch**: `026-acp`

**Created**: 2026-11-09

**Status**: Draft

**Input**: User description: "ACP for bee, built on 018-subagent-scopes. (a) bee as an ACP agent: a `bee acp` subcommand speaking stdio JSON-RPC (ACP v1) so t3code can drive bee as a 'Local ACP command' provider. The ACP client is a consent front-end using session/request_permission; bee never uses the client's fs/* or terminal/* methods because those run outside bee's kernel scope; client-supplied mcpServers and cwd are untrusted like project config. (b) bee as an ACP client: a new agent runtime that runs an external harness (claude, codex, opencode via their ACP adapters) as a subagent whose whole process tree lives in the 018 child kernel scope. bee auto-allows the child's permission requests (the kernel scope is the boundary), advertises no fs/terminal client capabilities, and builds the delegation report from the child's messages. The child harness's HTTP is recorded through bee's interceptor, which requires per-subagent proxy scopes (019 T092). Open issues: network rules are IP-pinned at compile time while provider endpoints sit behind CDNs; children need their credential files; exec rules can't usefully narrow a harness that runs bash."

## Context & Motivation

The Agent Client Protocol (ACP) is how editors and agent front-ends talk to coding agents: a client
launches an agent as a child process and exchanges JSON-RPC over its standard streams. Prompts and
consent questions flow one way; streamed replies, tool-call progress and permission requests flow
the other. t3code — the front-end the operator works in — can already launch any local command that
speaks ACP as a provider. It can also run Claude, Codex and OpenCode, but only as *those* agents,
under *their* sandbox and approval rules.

bee's distinguishing property is that a tool call, and since 018 a subagent, runs inside a kernel
scope the model cannot talk its way out of. Today that property is reachable only from bee's own
REPL, TUI and batch runner. ACP opens it in two directions:

1. **Inward — bee as an ACP agent.** The operator picks bee in t3code like any other provider. Each
   t3code thread is a bee session, enforced exactly as a REPL session is; consent questions appear
   in t3code's conversation.
2. **Outward — foreign harnesses as bee subagents.** An operator-authored agent definition names an
   external harness (for example Claude Code through its ACP adapter) instead of bee's own loop.
   bee runs that harness — its whole process tree — inside a 018 child scope derived from the
   delegating session's policy. The harness keeps its own model, prompts and tools; bee does not
   care how it behaves, only what the kernel lets it touch.

The second direction is the more novel one. Every harness ships its own sandbox, each with its own
gaps, defaults and approval prompts. Putting the harness *inside* a bee scope replaces "trust the
harness's sandbox" with "the kernel holds the boundary the operator wrote", and replaces the
harness's approval prompts with a recorded auto-approval: the questions the harness asks are no
longer the security boundary, so asking a person adds friction without adding safety.

Three facts make the outward direction harder than 018's own subagents, and the spec addresses each:

- **Model providers sit behind CDNs.** bee's network rules are resolved to addresses when a policy
  is compiled. A harness's model endpoint is a hostname whose addresses change, so an address rule
  either breaks the harness or must be so broad it opens the internet.
- **Harnesses need their credentials.** A harness signs in with files under the operator's home
  directory, which bee protects by default as credential stores.
- **A harness runs a shell.** Narrowing which programs it may execute stops being useful once the
  shell is allowed; the boundary that matters is what those programs can read, write and reach.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Drive bee from t3code (Priority: P1)

The operator adds bee in t3code as a local ACP command and opens a thread on a project. They type a
request; bee's reply streams into the thread, and each tool call bee makes appears as a tool call
with its status and result. Every tool call runs inside the session's kernel scope, exactly as it
would in bee's REPL, and a kernel denial is shown on the call it happened to.

**Why this priority**: It is the entry point for everything else in this feature, and on its own it
gives the operator bee's enforcement from the front-end they already use.

**Independent Test**: Launch `bee acp` from a scripted ACP client against a project with a policy that
allows writes to one directory. Send a prompt whose scripted model writes inside and outside it.
The client receives the streamed reply and two tool calls: one completed, one failed with the
kernel denial named.

**Acceptance Scenarios**:

1. **Given** t3code configured with bee as a local ACP command, **When** the operator opens a thread
   and sends a prompt, **Then** bee answers through the protocol with a streamed reply and the turn
   ends with a stop reason the client understands.
2. **Given** a session whose policy denies a path, **When** a tool call writes there, **Then** the
   client sees that call fail with the denial named, and the session's record holds the kernel's
   audit event for it.
3. **Given** a running turn, **When** the operator cancels it in the client, **Then** bee stops the
   model, terminates every process the turn started inside its scope, and ends the turn as cancelled.
4. **Given** the client offers its own file-system or terminal methods, **When** bee works, **Then**
   bee never uses them: every read, write and command happens inside bee's scope.

---

### User Story 2 - Consent questions answered in the client (Priority: P1)

When bee needs a capability it does not hold — a skill's requirement, a kernel denial within the
ceiling, or a subagent asking for more (018 US7) — the question appears in t3code as a permission
request. It names who is asking and lists exactly what would be granted. The operator's answer
decides it, and an unanswered question is refused when it times out.

**Why this priority**: Interactive consent is what makes a bee session governed rather than merely
sandboxed. Without it, an ACP session could only run with a fixed policy.

**Independent Test**: A scripted client answers the first permission request with allow and the
second with reject. The first grant widens the scope and the retried call succeeds; the second leaves
the scope unchanged; both decisions are in the session's consent record.

**Acceptance Scenarios**:

1. **Given** a session with a ceiling wider than its policy, **When** a call is denied within the
   ceiling, **Then** the client receives a permission request listing every capability that would
   be granted, and a grant takes effect before the call is retried.
2. **Given** a request from a subagent, **When** it is shown, **Then** the request names the subagent.
3. **Given** a request beyond the ceiling, **When** it arises, **Then** the client is never asked,
   and the refusal is still recorded.
4. **Given** a client that does not answer within the operator's consent timeout, or disconnects,
   **When** the timeout passes, **Then** the request is refused.

---

### User Story 3 - Run a foreign harness as a scoped subagent (Priority: P2)

The operator writes an agent definition whose runtime is an external ACP harness — a command, its
arguments and environment — and whose capabilities are declared as for any 018 agent. When the
session's model delegates to it, bee starts the harness inside a fresh child scope derived from the
session's policy, sends it the task, and returns a bounded report built from the harness's replies.
Every process the harness starts — its shell, its tools, its own subagents — stays in that scope.

**Why this priority**: It is the feature's novel capability, and it reuses 018's delegation
whole. It depends on the network and credential arrangements of US4 to reach a real model provider,
but it can be demonstrated first against a local harness that needs neither.

**Independent Test**: Delegate to an agent backed by a scripted ACP harness that tries to read a file
inside its declared scope and one outside it, and to start a background process. The report says
what the harness answered; the outside read is kernel-denied and recorded in the subagent's own
record; the background process is gone when the delegation ends.

**Acceptance Scenarios**:

1. **Given** an ACP-runtime agent, **When** the session delegates to it, **Then** the harness runs in
   its own child scope, derived from the session's policy before any process starts (018 FR-009).
2. **Given** the harness asks permission for an action, **When** bee receives the request, **Then**
   bee allows it without asking anyone and records that it did; the kernel decides what the action
   can actually touch.
3. **Given** the harness finishes its turn, **When** bee builds the report, **Then** the report is the
   harness's final reply, capped like any tool result, and the harness's individual tool calls stay
   in the subagent's record, not in the parent's conversation (018 FR-027).
4. **Given** the harness or any process it started is still running when the delegation ends —
   finished, cancelled, out of time — **Then** bee terminates every process in the child scope and
   reclaims the scope; a scope that will not empty makes the delegation fail (018 FR-022).
5. **Given** the harness offers file-system or terminal methods of its own to call back into bee,
   **When** bee connects to it, **Then** bee advertises neither, so the harness works only through
   what its scope allows.

---

### User Story 4 - A harness reaches its model provider and its credentials, and nothing more (Priority: P2)

An ACP-runtime agent declares the model provider it talks to by hostname and the credential files it
signs in with. bee lets the harness reach exactly those provider hosts — however their addresses
change — and read and update exactly those credential files, while the rest of the scope stays as
narrow as the agent declared.

**Why this priority**: Without it a real harness cannot run at all inside a scope, or can run only
with egress so broad the scope is meaningless.

**Independent Test**: An agent declaring one provider hostname and one credential directory: a
connection to that hostname succeeds through whichever address it resolves to; a connection to a
second hostname on the same CDN addresses is refused; reading a credential file outside the declared
directory is kernel-denied.

**Acceptance Scenarios**:

1. **Given** an agent declaring provider host `H`, **When** the harness connects to `H`, **Then** the
   connection succeeds regardless of which address `H` resolves to at that moment.
2. **Given** the same agent, **When** the harness connects to another host served from the same
   addresses as `H`, **Then** the connection is refused and recorded.
3. **Given** an agent declaring a credential directory, **When** the harness reads and refreshes its
   sign-in there, **Then** it succeeds; other credential stores stay protected.
4. **Given** an agent declaring a provider host or credential path its parent does not hold, **When**
   the session delegates to it, **Then** the delegation is refused before anything runs (018 FR-010).

---

### User Story 5 - A harness's web traffic is recorded (Priority: P3)

When the session records HTTP through bee's interceptor (019), a foreign harness's web requests to
in-scope targets are recorded too, attributed to that subagent, through a proxy scope of its own.
Traffic to its declared model provider is passed through, not opened; the record shows only that the
connection happened.

**Why this priority**: It completes the evidence trail for intercepted sessions, which today refuse
delegation outright. It is not needed for a harness to be useful or contained.

**Independent Test**: An intercepted session delegates to a scripted harness that fetches an in-scope
target and calls its provider. The target exchange is in the record, attributed to the subagent; the
provider connection appears as a pass-through with no request or response content.

**Acceptance Scenarios**:

1. **Given** an intercepted session, **When** it delegates to any subagent, **Then** the delegation is
   no longer refused for that reason: the subagent gets a proxy scope of its own.
2. **Given** a subagent's request to an in-scope target, **When** it completes, **Then** the exchange is
   recorded and attributed to that subagent, never to the parent.
3. **Given** a harness's connection to its declared model provider, **When** it is made, **Then** its
   contents are not decrypted or stored, and the record shows the connection's host, time and size.

---

### Edge Cases

- The client sends a working directory that does not exist, is not a directory, or lies outside
  what the operator's policy allows to be read: the session is refused with the reason, before any
  scope is created.
- The client supplies MCP servers: they are not started unless the operator's configuration allows
  client-supplied servers, and if allowed they run inside the session's tool scope like any other
  MCP server. The session tells the client which servers it dropped and why.
- The client disconnects mid-turn: bee treats it as a cancellation, refuses any pending consent
  question, and closes the session in its one teardown order.
- Two client threads open two sessions in one `bee acp` process: each has its own scope, operator
  and record; a denial or grant in one is never seen in the other.
- A foreign harness fails to start, exits early, or speaks a protocol version bee does not support:
  the delegation fails with the reason, and its scope is reclaimed.
- A foreign harness never ends its turn: the shared deadline (018 FR-023) applies; bee asks it to
  cancel, then terminates the scope after a grace period, and reports the delegation cut short.
- A foreign harness asks to use the client's file-system or terminal methods anyway: bee refuses the
  call, records it, and the harness continues with what its scope allows.
- A foreign harness's own subagents: they are processes inside the same child scope and are bound by
  it; bee neither sees nor counts them separately.
- A foreign harness hits a kernel denial: the denial is recorded in the subagent's record and named
  in the report. bee does not escalate on the harness's behalf (it cannot retry the harness's action).
- The session has no kernel scope (host mode): an ACP-runtime agent is refused, because nothing
  would confine the harness — unlike a bee-loop agent, which may run unenforced with a loud warning
  (018 FR-032).
- A provider hostname declared by an agent resolves to addresses shared with arbitrary other sites:
  only connections that name the declared host are allowed (US4 AS-2).

## Clarifications

### Session 2026-11-09

- Q: What happens to a harness's traffic to its own model provider, which carries its credentials and
  full prompts? → A: Passed through. bee checks the hostname and forwards the encrypted connection
  unopened; the record keeps host, time and size only. No credentials or prompts are stored.
- Q: Is ACP a revival of 018 or a new spec? → A: A new spec, built on 018.
- Q: Does bee answer a harness's permission requests itself? → A: Yes, automatically allowed and
  recorded; the kernel scope is the boundary.
- Q: Is a harness's HTTP recorded through the interceptor? → A: Yes, for in-scope targets, through a
  per-subagent proxy scope (019 T092).

## Requirements *(mandatory)*

### Functional Requirements

**bee as an ACP agent**

- **FR-001**: bee MUST provide a command that speaks ACP (protocol version 1) over its standard
  input and output, so that any ACP client can launch it as a local agent.
- **FR-002**: Each ACP session MUST be a bee session with the same configuration resolution, policy,
  ceiling, kernel scope, tools, skills, delegation and records as a REPL session started in the same
  working directory.
- **FR-003**: Each prompt MUST run as one exchange: the reply streamed as it is produced, each tool
  call reported with its arguments, status and result, and the turn ended with a stop reason.
- **FR-004**: bee MUST NOT use any client-provided file-system or terminal capability, and MUST NOT
  depend on the client offering them.
- **FR-005**: The client's working directory and MCP servers MUST be treated as untrusted input with
  the same standing as project configuration: they may narrow what the operator configured, never
  widen it. Client MCP servers MUST NOT start unless the operator's configuration allows them.
- **FR-006**: Consent questions MUST be put to the client as permission requests that name the
  requester (including a subagent, 018 US7) and list every capability that would be granted; an
  unanswered, failed or disconnected request MUST be refused at the operator's consent timeout.
- **FR-007**: Cancelling a turn MUST stop the model, terminate every process the turn started in the
  session's scope (including subagents' scopes), and end the turn as cancelled.
- **FR-008**: One agent process MUST be able to serve several sessions at once, each with its own
  scope, operator and record.
- **FR-009**: Text that reaches the client from tool results, subagent reports and kernel audit MUST
  be marked as data, never presented as bee's own words or instructions (as in bee's other
  front-ends).

**Foreign harnesses as subagents**

- **FR-010**: An agent definition MUST be able to name an ACP harness as its runtime: the command,
  its arguments and its environment. All other definition fields — capabilities, tools surface,
  turn limit — keep their 018 meaning where they apply.
- **FR-011**: A harness MUST run with its entire process tree inside the delegation's child scope,
  created and derived exactly as for a bee-loop agent (018 FR-009, FR-010, FR-017).
- **FR-012**: bee MUST advertise no file-system or terminal capability to a harness, and MUST refuse
  and record any such call the harness makes anyway.
- **FR-013**: bee MUST allow every permission request a harness makes, without asking any person,
  and MUST record each request and the answer in the subagent's record.
- **FR-014**: The delegation report MUST be built from the harness's replies for the task, capped as
  any tool result; the harness's tool calls and its permission requests MUST be kept in the
  subagent's record, not given to the parent's model.
- **FR-015**: A harness delegation MUST end — completed, cut short, failed — with its child scope
  emptied and reclaimed; a scope that will not empty MUST make the delegation fail.
- **FR-016**: The shared deadline MUST bound a harness: bee asks it to cancel, then terminates its
  scope after a grace period, and reports it cut short. Turn and token budgets that bee cannot
  observe in the harness MUST be reported as not counted, never as zero.
- **FR-017**: A harness MUST NOT run without a kernel scope: in a session without one, an ACP-runtime
  agent MUST be refused.

**Network, credentials, execution**

- **FR-018**: An agent MUST be able to declare model-provider destinations by hostname and port. A
  connection MUST be allowed only when it is to a declared hostname, whatever address it resolves to,
  and MUST be refused when it is to an undeclared host on the same addresses.
- **FR-019**: A hostname destination MUST be a capability like any other: attenuated from the parent
  (an agent may only declare hostnames its parent holds), shown in consent, and recorded.
- **FR-020**: An agent MUST be able to declare the credential paths its harness needs; bee's
  protection of credential stores MUST be lifted only for the declared paths, and only when the parent
  holds them.
- **FR-021**: Documentation and the delegation record MUST state plainly that allowing a harness a
  shell allows whatever that shell can start; execution rules for a harness are recorded but the
  boundary bee claims for it is its file-system and network scope.

**Recording**

- **FR-022**: Every kernel decision in a harness's scope MUST be recorded once, attributed to that
  subagent's scope (018 FR-018).
- **FR-023**: In an intercepted session, each subagent — bee-loop or harness — MUST get a proxy scope
  of its own, and its exchanges MUST be recorded and attributed to it. Delegation from intercepted
  sessions MUST no longer be refused for lack of one (019 T092).
- **FR-024**: Traffic to a harness's declared model provider MUST pass through without its content
  being decrypted or stored; the record MUST show the connection with its host, time and size.
  The harness therefore needs no trust in bee's interception certificate for its provider.

### Key Entities

- **ACP session**: one client thread bound to one bee session — its working directory, scope,
  operator, record and conversation.
- **Harness runtime**: the part of an agent definition naming an external ACP command, its arguments
  and environment, in place of bee's own loop.
- **Harness delegation**: one run of a harness in a child scope — its permission requests and their
  automatic answers, its replies, its tool-call updates, its kernel audit and its proxy exchanges —
  attached to the parent's `task` call like any 018 delegation record.
- **Provider destination**: a hostname and port an agent may reach, matched by name rather than by
  address, attenuated like any network rule.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can add bee to t3code as a local ACP command and complete a prompt that
  reads and writes project files, with no change to t3code.
- **SC-002**: In a scripted conformance run, every tool call bee makes in an ACP session is reported
  to the client, and zero file reads, writes or commands go through client-provided methods.
- **SC-003**: Every capability a session gains through an ACP client appears in the session's consent
  record with the client's answer; zero grants are applied without one (beyond-ceiling and timeout
  refusals included).
- **SC-004**: A real foreign harness (at least Claude Code through its ACP adapter) completes a task
  inside a child scope, with every kernel decision of its process tree attributed to that scope and
  no process of it surviving the delegation.
- **SC-005**: A harness confined to one declared provider host reaches it on every attempt across
  address changes, and every attempt to reach an undeclared host — including one sharing the
  provider's addresses — is refused and recorded.
- **SC-006**: Cancelling a turn or reaching the deadline leaves no process from that turn or its
  harnesses running within 5 seconds.
- **SC-007**: In an intercepted session, every in-scope exchange a subagent makes is recorded against
  that subagent, with zero attributed to its parent or a sibling.

## Assumptions

- ACP protocol version 1 is the target. The draft version 2 that t3code prefers is negotiated down to
  version 1 by t3code itself, which already supports agents that have not migrated.
- bee offers no ACP sign-in methods: its model provider comes from the operator's configuration, as
  in the REPL.
- A harness's permission requests are answered with the "allow once" choice when one is offered, so
  each request stays a separate recorded decision.
- Session loading, session listing and the client's model or mode pickers are not required for the
  first release; a client thread maps to a session that lasts as long as the agent process.
- Harnesses are reached through their existing ACP adapters (for example the Claude Agent adapter);
  bee writes no harness-specific integration beyond an agent definition.
- Hostname matching for provider destinations relies on the name the harness connects to (for TLS,
  the server name it presents), checked by bee's proxy before any data is forwarded; the plan decides
  the mechanism.
- A harness does not escalate: kernel denials it meets are recorded and reported, not turned into
  consent questions, because bee cannot retry the harness's action.

## Out of Scope

- Using a client's file-system or terminal methods for anything.
- Running a harness without a kernel scope, on any platform.
- Per-tool narrowing inside a foreign harness (its tools are its own; the scope is the boundary).
- Counting a harness's model turns or tokens against the shared budget where the harness does not
  report them.
- Rewinding a harness's conversation, or forking sessions.

## Constitution Alignment

- **I. Deny-by-default, fail-closed**: client file-system and terminal methods are never used; client
  MCP servers do not start unless allowed; an unanswered consent request is refused; a harness with
  no kernel scope is refused, not run with a warning.
- **II. Capability attenuation**: a harness's scope is derived from its parent's exactly as 018's are,
  and provider hostnames and credential paths are attenuated capabilities, not exceptions.
- **III. Kernel enforcement is authoritative**: the harness's own approval prompts are deliberately
  not part of the boundary; FR-021 keeps bee from claiming what execution rules cannot hold.
- **IV. Policy-as-data**: a harness agent is an agent definition — readable, diffable text.
- **V. Library-first**: the ACP agent command is a front-end over the same session entry points as
  the REPL; it adds no enforcement logic of its own.

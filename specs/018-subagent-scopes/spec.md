# Feature Specification: Subagent Delegation Under Attenuated Scopes

**Feature Branch**: `018-subagent-scopes`

**Created**: 2026-08-09

**Status**: Draft

**Input**: User description: "Subagent system: a `task` tool that spawns kernel-scoped child agents whose policy is provably attenuated from the parent's active policy. Agent types are authored by the operator as skills with `kind: agent` frontmatter (name, description, tools, turn_limit, requires block). The model selects a named agent and gives it a prompt; it never authors capabilities. Requires lifting Engine + AuditDemux out of Sandbox into a session-owned Supervisor so Sandbox becomes a Send handle (scope + audit subscription + strip_env), collapsing the Enforced/Concurrent variants, fixing 007 escalation under concurrency, and enabling parallel fan-out. Child policy = parent.active().derive(agent_declared_policy). Child ceiling = parent active-at-spawn. Shared budget pool (turns, wall-clock, tokens). Bounded text report back to the parent; nested transcript with scope-tagged audit. Depth limit. Host-mode and non-enforce builds must announce loudly that a subagent is prompt isolation only."

## Context & Motivation

Constitution II — Capability Attenuation — names subagent delegation as bee's core differentiator, and
001 (US2, FR-005) specified it: a derived policy must be a provable subset of its parent, and any
over-grant must be refused before enforcement begins. That shipped as a *validator* the operator runs
by hand (`bee validate --policy child --parent parent`). It has never been something an agent can do
at runtime. 002's plan recorded the IOU explicitly — "subagent tools would use derived scopes and
inherit 001's attenuation guarantees; deferred, and noted so no design here precludes it" — and 004
repeated it.

This feature makes it real. In every other agent harness a subagent is a context-isolation
convenience: the child sees a smaller prompt, and nothing stops its tools from doing anything the
parent's tools could do. In bee a subagent can be a capability boundary the kernel holds. A
`test-runner` subagent that was never granted network cannot open a socket, whatever it is persuaded
to attempt, and the denial is recorded against the subagent rather than the session.

Two things block it today, and both are the same thing:

1. **The enforcement engine is owned by the sandbox.** A session's sandbox owns the loaded eBPF
   object, which is not movable between tasks. A child loop therefore cannot be given a scope, and
   scopes cannot be created for siblings.
2. **The audit stream is filtered to one scope.** A session drains kernel events and keeps only those
   whose cgroup matches its own. A child's denials would be discarded in silence — and a denial that
   is not recorded is, by this project's own quality gate, not enforced.

So the feature carries a structural change: the engine and the audit fan-out move up into a
session-owned supervisor, and a sandbox becomes a movable handle onto one scope. That change also
repairs an existing gap — under the concurrent runner, dynamic grants (007) cannot reload a scope at
all, because the runner owns the engine. After this, one path serves a single session, concurrent
episodes, and subagent trees.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Delegate work to an attenuated subagent (Priority: P1)

An operator authors an agent definition: a name, a one-line description of what it is for, the tools
it may use, a turn limit, and the capabilities it needs. During a session the model decides some work
should be delegated, calls the delegation tool naming that agent and describing the task, and gets
back a written report. The subagent ran in its own kernel scope, under a policy provably narrower
than the session's, and could not touch anything the operator did not declare for it.

**Why this priority**: This is the feature. Everything else bounds, records, or scales it.

**Independent Test**: Author an agent whose declaration omits a capability the parent session holds.
Run a session that delegates to it and instructs it to use that capability. The attempt is denied in
the kernel, the denial is recorded against the child, and the parent receives a report saying so.

**Acceptance Scenarios**:

1. **Given** a session whose policy grants write access to the project and network access, **and** an
   agent declaring read-only project access and no network, **When** the model delegates to that
   agent and the subagent attempts a network connection, **Then** the connection is denied, the
   denial is recorded as the subagent's, and the session's own network access is unaffected.
2. **Given** a delegation that completes normally, **When** the subagent's loop ends, **Then** the
   parent receives a bounded text report and never sees the subagent's individual tool calls in its
   own conversation.
3. **Given** a delegation to an agent that declares a tool the session's registry does not hold,
   **When** the delegation is attempted, **Then** it is refused with a message naming the tool, and
   no scope is created.
4. **Given** a completed delegation, **When** the subagent's scope is torn down, **Then** teardown
   failure is reported to the operator and the delegation is not reported to the model as clean.

---

### User Story 2 - Refuse an over-broad agent before it can run (Priority: P1)

An agent definition asks for a capability the session does not itself hold — or asks for one it holds
only more narrowly. The delegation is refused before any scope exists, with a message naming the rule
that was violated. No process runs, nothing is torn down, and the model is told plainly that the
agent exceeds the session's authority rather than being handed a quietly weakened child.

**Why this priority**: This is Constitution II as a runtime behaviour rather than an intention. It is
also what makes US1's guarantee worth stating: attenuation that is only usually checked is not a
boundary.

**Independent Test**: Author an agent declaring write access to a path the session may only read.
Delegate to it. The refusal happens before scope creation, names the path, and the session continues.

**Acceptance Scenarios**:

1. **Given** a session with read access to a path, **and** an agent declaring write access to that
   same path, **When** delegation is attempted, **Then** it is refused, the message names the path
   and the access levels, and no cgroup is created.
2. **Given** an agent declaration that states no rule for a region the session denies, **When** the
   subagent runs, **Then** the subagent is denied there too — an unstated rule inherits the parent's
   restriction and never becomes freedom.
3. **Given** an agent whose declared capabilities cannot be decided as a subset of the session's
   (overlapping or ambiguous rules), **When** delegation is attempted, **Then** it is refused rather
   than resolved optimistically.
4. **Given** a session that has escalated at runtime and now holds more than it started with, **When**
   it delegates, **Then** the subagent may be granted up to what the session holds *now*, and no
   further.

---

### User Story 3 - The audit trail stays whole across the scope tree (Priority: P1)

Whatever the shape of a session — one scope, several concurrent episodes, or a parent with
subagents — every kernel decision reaches exactly one place in the record, attributed to the scope
that caused it. An operator reading a transcript can see which agent was denied what, and a scored or
audited run does not silently lose a subagent's events.

**Why this priority**: US1's claim is only as good as the evidence for it. Under the current
one-scope audit filter, a subagent's denials are discarded, so US1 could pass a test that proves
nothing. This story is also what carries the supervisor restructuring, which US4, US5 and US6 all
depend on.

**Independent Test**: Run a session that delegates twice while performing denied operations itself.
Every denial — the session's and both subagents' — appears once in the record, tagged with its scope,
and no event appears under the wrong one.

**Acceptance Scenarios**:

1. **Given** a parent and a subagent both attempting denied operations, **When** the delegation
   completes, **Then** each denial appears exactly once, attributed to the scope that produced it.
2. **Given** a transcript containing a delegation, **When** it is read back, **Then** the subagent's
   full turn-by-turn record is nested under the delegating call, and the parent's own record is
   unchanged in shape from a session that never delegated.
3. **Given** two concurrently running episodes, **When** one escalates its capabilities at runtime,
   **Then** the reload succeeds and affects only that episode's scope — the behaviour a single
   session already has, now available concurrently.
4. **Given** a scored run, **When** the score is computed, **Then** it is stated which scopes it
   covers, and subagent events are not folded into the parent's own tally by accident.

---

### User Story 4 - Delegation is bounded, not just permitted (Priority: P2)

Delegation cannot become an unbounded amplifier of time, cost, or nesting. A subagent draws from the
session's remaining budget rather than receiving a fresh one; it cannot delegate further beyond a
declared depth; and its report back to the parent is size-bounded like any other tool result.

**Why this priority**: Without this, a single delegation call can multiply a session's cost and
wall-clock by an arbitrary factor, and a recursive agent can do so unboundedly. Correctness of the
boundary comes first, but an unbounded boundary is unusable in practice.

**Independent Test**: Give a session a small turn and time budget, delegate a task that would exceed
it, and confirm the subagent stops at the shared limit and the parent is told it was cut short.

**Acceptance Scenarios**:

1. **Given** a session with N turns remaining, **When** a subagent consumes turns, **Then** those
   turns are debited from the session's pool and the session cannot exceed its original total by
   delegating.
2. **Given** a subagent that reaches the shared wall-clock deadline, **When** it stops, **Then** it
   returns a partial report explicitly marked as cut short, and the parent is not told the task
   completed.
3. **Given** a subagent at the maximum delegation depth, **When** it attempts to delegate further,
   **Then** the attempt is refused with a message naming the limit.
4. **Given** a subagent producing a very large report, **When** it returns, **Then** the report is
   truncated to the same per-result cap every other tool result obeys, and the truncation is visible.

---

### User Story 5 - Several subagents at once (Priority: P2)

A session delegates several independent pieces of work simultaneously. Each subagent runs in its own
scope with its own attenuated policy; none can observe or affect another's; their audit events do not
cross-contaminate; and they draw from the same shared budget.

**Why this priority**: Fan-out is the reason delegation is worth the machinery — but it is only
correct once US3 is in place, so it follows rather than leads.

**Independent Test**: Delegate to three agents with mutually exclusive capabilities at once. Each
completes, each denial lands under the right agent, and no agent gains a capability belonging to a
sibling.

**Acceptance Scenarios**:

1. **Given** three simultaneous delegations, **When** all complete, **Then** each subagent's audit
   events are attributed to it alone.
2. **Given** simultaneous delegations with different policies, **When** one performs an operation only
   a sibling is permitted, **Then** it is denied.
3. **Given** simultaneous delegations, **When** one fails to start, **Then** its siblings continue and
   the parent is told which one failed and why.
4. **Given** simultaneous delegations sharing one budget, **When** the pool is exhausted, **Then**
   every running subagent stops at that bound rather than each spending the remainder.

---

### User Story 6 - Honest degradation when nothing can enforce (Priority: P2)

An operator runs a session on a build without enforcement, or explicitly without a kernel scope. A
subagent there is prompt isolation and nothing more. The session says so plainly — at the point of
delegation, not only in a banner — so that "the boundary held" and "there was no boundary" can never
be confused.

**Why this priority**: Constitution I. The harness already refuses to let a compiled-out security
tool look like a tool that ran and found nothing; delegation without enforcement is the same failure
mode with a larger blast radius.

**Independent Test**: Delegate on a host-mode session. The report and the operator-facing output both
state that no capability boundary was in effect.

**Acceptance Scenarios**:

1. **Given** a session running without a kernel scope, **When** it delegates, **Then** the operator is
   told that the subagent is unenforced, and the delegation record marks it so.
2. **Given** a build without enforcement, **When** an agent definition declares capabilities, **Then**
   the declaration is still validated for attenuation and still refused if over-broad, so definitions
   remain reviewable and portable.
3. **Given** an unenforced delegation, **When** the transcript is read later, **Then** it is
   distinguishable from an enforced one without inspecting the build.

---

### User Story 7 - A subagent that asks for more, within its parent's authority (Priority: P3)

A subagent hits a denial mid-task and requests the capability, exactly as a session does today. The
request is bounded by what the parent held when the subagent was spawned — never by the operator's
session-wide ceiling — and any prompt shown to the operator says which subagent is asking.

**Why this priority**: It composes two shipped features rather than introducing a new one, and
delegation is useful without it.

**Independent Test**: Give a subagent a task requiring a capability its declaration omits but its
parent holds. The escalation is offered, bounded at the parent's authority, and attributed to the
subagent by name.

**Acceptance Scenarios**:

1. **Given** a subagent denied a capability its parent holds, **When** it escalates, **Then** the
   request may be approved up to the parent's authority at spawn time and no further.
2. **Given** a subagent requesting a capability its parent does *not* hold, **When** it escalates,
   **Then** the request is refused without consulting any approver.
3. **Given** an interactive session, **When** a subagent requests consent, **Then** the prompt names
   the subagent, so the operator can tell who is asking.

---

### Edge Cases

- **A named agent does not exist.** The delegation returns an error naming the unknown agent and
  listing the available ones; it is never a silent no-op or an empty success.
- **Two agent definitions share a name across roots.** Resolution order is fixed and stated, and the
  shadowed definition produces a warning rather than being silently ignored.
- **An agent definition is malformed.** It warns at discovery and is not offered to the model, matching
  how a malformed skill behaves; a malformed definition never aborts the session.
- **The session's policy narrows while a subagent is running.** The subagent keeps the authority it was
  proven to hold at spawn; the parent's narrowing does not retroactively rewrite a running child's
  scope.
- **Scope creation fails mid-fan-out.** The delegations that did start continue; the failed one is
  reported as failed; no partially created cgroup is left behind.
- **A subagent's process survives its loop.** Teardown reports it on the same path a session already
  uses, and the parent is not told the delegation was clean.
- **A subagent is told, by content it reads, to ignore its instructions.** Its capabilities are
  unaffected — that is the point of the boundary — and nothing in a subagent's report can widen the
  parent's scope or alter the parent's policy.
- **A subagent writes to the shared findings ledger.** Its sightings merge under the existing rules,
  and it cannot record a human verdict, exactly as no agent can.
- **Delegation is attempted when the tool was never enabled.** The tool is absent, so the model cannot
  call it; enabling it is an explicit operator choice, not a default.
- **The report is empty or the subagent produced no output.** The parent is told the subagent produced
  nothing, distinct from the subagent reporting that there was nothing to find.

## Requirements *(mandatory)*

### Functional Requirements

**Delegation surface**

- **FR-001**: The system MUST provide a delegation tool that takes the name of an operator-authored
  agent and a task description, and returns that agent's written report.
- **FR-002**: The delegation tool MUST NOT be enabled by default. A session enables it explicitly, the
  way visualization and security tools are enabled.
- **FR-003**: The model MUST NOT be able to specify a subagent's capabilities, tool set, or policy. It
  may only select from agent definitions the operator authored.
- **FR-004**: An unknown agent name MUST produce an error result naming the unknown agent and the
  available ones, and MUST NOT create a scope.

**Agent definitions**

- **FR-005**: Agent definitions MUST be declarative text discovered from project and user roots,
  reviewable and diffable without running them, using the same discovery and warning behaviour as
  skills.
- **FR-006**: A definition MUST carry a name, a description shown to the delegating model, the tools
  the subagent may use, a turn limit, its capability requirements, and its instructions.
- **FR-007**: A malformed definition MUST warn at discovery, MUST NOT be offered to the model, and MUST
  NOT abort the session.
- **FR-008**: Name collisions across roots MUST resolve by a fixed, documented precedence and MUST warn.

**Attenuation**

- **FR-009**: A subagent's policy MUST be derived from the parent's *currently active* policy and the
  agent's declaration, and MUST be validated as a subset of the parent's active policy before any
  scope is created.
- **FR-010**: A declaration that would grant more than the parent holds MUST be refused with a message
  naming the violated rule, and MUST leave no cgroup, process, or partial state behind.
- **FR-011**: A capability the declaration does not mention MUST inherit the parent's restriction. A
  subagent MUST NOT gain authority by omission.
- **FR-012**: A subagent's tool set MUST be a subset of the tools the parent session holds.
- **FR-013**: When subset containment cannot be decided, the derivation MUST be treated as invalid.
- **FR-014**: The attenuation relationship across a delegation tree MUST be covered by property-based
  tests, not examples alone.
- **FR-015**: A subagent's escalation ceiling MUST be the parent's active policy at spawn time, and
  MUST NOT be the session's own ceiling.
- **FR-016**: A parent narrowing its own policy MUST NOT retroactively narrow a running subagent.

**Enforcement and audit**

- **FR-017**: Each subagent MUST run confined to its own scope, whose lifecycle the system owns and
  reclaims.
- **FR-018**: The system MUST attribute every kernel decision to the scope that produced it, and MUST
  record each exactly once across a session, its concurrent episodes, and its subagent trees.
- **FR-019**: A subagent's turn-by-turn record MUST be nested under the delegating call in the
  transcript.
- **FR-020**: The parent's own record MUST retain its existing shape, so a transcript from a session
  that never delegates is unchanged by this feature.
- **FR-021**: Runtime capability reload MUST work for every scope a session owns, including under
  concurrent execution, where it currently cannot.
- **FR-022**: Scope teardown failure MUST be reported to the operator and MUST NOT be reported to the
  model as a clean delegation.

**Bounds**

- **FR-023**: A subagent MUST draw turns, wall-clock time, and token spend from the session's remaining
  budget rather than a fresh allocation.
- **FR-024**: A subagent stopped by a shared bound MUST return a partial report explicitly marked as
  cut short.
- **FR-025**: Delegation depth MUST be bounded, and exceeding the bound MUST be refused with a message
  naming the limit.
- **FR-026**: A subagent's report MUST obey the same per-result size cap as every other tool result,
  with truncation visible.
- **FR-027**: The parent's conversation MUST receive only the report — never the subagent's individual
  tool calls or intermediate turns.
- **FR-028**: Nothing a subagent returns MUST be able to widen the parent's policy, alter the parent's
  agent definitions, or record a human verdict.

**Fan-out**

- **FR-029**: The system MUST support several subagents running simultaneously, each in its own scope.
- **FR-030**: Simultaneous subagents MUST NOT observe or affect one another's scopes, and their audit
  events MUST NOT cross-contaminate.
- **FR-031**: One subagent failing to start MUST NOT prevent its siblings from running, and the failure
  MUST be reported with its cause.

**Honest degradation**

- **FR-032**: When no kernel scope is in effect, the system MUST state at the point of delegation that
  the subagent is unenforced, and MUST mark the delegation record accordingly.
- **FR-033**: Attenuation validation of agent definitions MUST happen regardless of whether enforcement
  is available, so definitions stay reviewable and portable across builds.
- **FR-034**: An unenforced delegation MUST be distinguishable from an enforced one when the transcript
  is read later, without inspecting the build.

### Key Entities

- **Agent definition**: An operator-authored, reviewable text artifact naming a delegable agent — its
  description, tool set, turn limit, capability requirements, and instructions. Discovered alongside
  skills; distinguished from one by declaring that its body is delegated to a child rather than
  injected into the current agent.
- **Delegation**: One act of handing a task to a named agent. Owns a derived policy, a scope, a budget
  draw, a nested transcript, and a report.
- **Derived policy**: The subagent's enforced authority — the parent's active policy narrowed by the
  agent's declaration, proven a subset before enforcement begins.
- **Supervisor**: The session-scoped owner of enforcement and of audit fan-out, from which every scope
  in the session — the session's own, its concurrent episodes', and its subagents' — is created and
  reclaimed.
- **Scope handle**: What a running loop holds: one scope, its audit subscription, and its child-process
  environment restrictions. Movable between execution contexts; not the owner of enforcement.
- **Budget**: The session-wide pool of turns, wall-clock time, and token spend that delegations draw
  from rather than replenish.
- **Report**: The bounded text a subagent returns to its parent, marked complete or cut short.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A subagent whose declaration omits a capability its parent holds is denied that
  capability by the kernel in 100% of attempts, verified on an enforcement-capable kernel rather than
  by mocks alone.
- **SC-002**: Every agent declaration that exceeds its parent's authority is refused before any scope
  is created, with zero cgroups, processes, or partial state left behind.
- **SC-003**: Attenuation across arbitrary sequences of delegation, escalation, and narrowing holds
  under property-based testing — no reachable state places a subagent's authority outside its parent's.
- **SC-004**: Across a session with concurrent episodes and subagents, every kernel decision appears
  exactly once in the record and is attributed to the correct scope, with zero cross-attribution.
- **SC-005**: A session that delegates cannot exceed the turn, wall-clock, or token budget it would
  have had without delegating.
- **SC-006**: A session that never delegates produces a transcript that every existing consumer reads
  unchanged — no new required fields, no altered attribution — verified against the existing
  transcript test corpus.
- **SC-007**: Runtime capability reload succeeds under concurrent execution, where it currently always
  fails.
- **SC-008**: On a build or session without enforcement, an operator is told that a subagent is
  unenforced at the point of delegation, and the record is distinguishable from an enforced one in
  100% of cases.
- **SC-009**: Delegation depth and simultaneous-subagent counts stay within their declared bounds under
  adversarial agent definitions that attempt to exceed them.
- **SC-010**: No content a subagent reads or returns can change the parent's policy, its agent
  definitions, or a recorded human verdict.

## Assumptions

- **Spawn-time snapshot.** A subagent's authority is fixed at spawn from the parent's active policy.
  The parent narrowing later does not rewrite a running child's scope — the child's authority was
  proven against what the parent held, and mid-flight narrowing would produce denials the child could
  not attribute to any decision it made.
- **Authoring is the authorization.** Writing an agent definition is the operator's reviewable
  pre-authorization for that delegation, as the ceiling file is for capability grants. Delegation does
  not additionally prompt per call; only a subagent's *escalation* consults consent.
- **Default depth is one.** A subagent does not delegate further unless the operator raises the bound.
  Recursive delegation multiplies scopes and budget draws faster than it adds value.
- **No parent context is inherited.** A subagent receives its own instructions and the task description
  the parent wrote — not the parent's conversation. Context isolation is the point; sharing it back
  would also make the report bound meaningless.
- **The subagent uses the session's model.** Per-agent model selection is a separate concern.
- **Kernel cgroup ancestry does not carry policy.** Enforcement hooks decide on a scope's own rules,
  with no ancestor lookup, so attenuation is guaranteed by validation at install time rather than by
  cgroup nesting. Any documentation of this feature must say so rather than let a reader assume the
  kernel walks the tree.
- **The findings ledger is shared.** A subagent's sightings merge under the existing rules; verdicts
  remain human-only for subagents exactly as for every other agent.
- **The supervisor restructuring is in scope** and is expected to replace, rather than sit beside, the
  existing separate single-session and concurrent enforcement paths.

## Out of Scope

- Model-authored subagent policies or tool sets.
- Recursive delegation beyond the declared depth bound.
- Per-agent model or provider selection.
- Subagents reaching external tool servers: a subagent gets no external server connections in this
  feature. Those servers run as children of the parent's scope, and giving a subagent its own would be
  a second attenuation surface with its own consent story.
- Sharing conversation context between parent and subagent in either direction.
- Cross-session or persistent subagents; a delegation lives and dies inside one session.
- Streaming a subagent's progress into the parent's conversation.
- Changing the session's own ceiling at runtime (unchanged from 007).

## Constitution Alignment

- **I — Deny-by-default & fail-closed**: an unstated rule in an agent declaration inherits the parent's
  restriction; an undecidable subset relation is invalid; an unknown agent, an exceeded depth, and a
  failed teardown are all refusals rather than degraded successes; an unenforced delegation announces
  itself rather than passing as a boundary.
- **II — Capability attenuation**: the whole feature. Every subagent policy is validated ⊆ the parent's
  active policy before enforcement begins, a subagent's escalation ceiling is its parent's authority,
  and the relationship is property-tested across delegation trees — which is the first time 001's US2
  guarantee is exercised at runtime rather than by a manual validator.
- **III — Kernel enforcement is authoritative**: each subagent is confined by its own kernel scope, and
  user space only derives, validates, installs, and observes. Where the kernel cannot enforce, the
  system says so instead of presenting delegation as a guarantee.
- **IV — Policy-as-data**: agent definitions are declarative, diffable text reviewable in a pull
  request; derived policies and every delegation are recorded as structured audit events.
- **V — Library-first, runtime-free core**: attenuation stays in the synchronous policy core; the
  supervisor and audit fan-out stay in the enforcement layer; the delegation tool and loop stay in the
  harness. The CLI gains no enforcement logic the library lacks.

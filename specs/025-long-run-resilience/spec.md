# Feature Specification: Long-Run Resilience — Context Management, Stuck Detection, and a Finish Tool

**Feature Branch**: `025-long-run-resilience`

**Created**: 2026-10-11

**Status**: Draft

**Input**: User description: "Long-run resilience for bee's session core (follows 024-session-core). Three
parts, grounded in Fan et al. 2026, 'An Empirical Study of Harness Design for Coding Agents' (arXiv
2609.20804): (1) staged context management — elide stale tool observations above a soft threshold,
summarize the oldest middle turns above a hard threshold, keep the preamble and recent turns verbatim,
no recall tool, stubs keep denials, summaries stay untrusted, and a smaller, budget-relative output cap;
(2) stuck detection — a one-time reminder on streaks of identical calls, ending the run when identical
failing calls keep growing, and a policy-specific reminder for repeated denied calls; (3) an explicit
finish tool so an autonomous run ends deliberately rather than on a text-only turn, with REPL behaviour
considered."

## Context & Motivation

024-session-core makes bee a first-class autonomous agent: one session core, two Operators, no person
required. Removing the person also removes the three things that person did without being asked during a
long run:

- **They noticed when the conversation got too long.** bee keeps every turn's full text in the model's
  input, forever. Nothing shortens it. A single tool result may be up to 100 KB (roughly 25,000 tokens),
  so one large file read can fill a small window by itself. When the history outgrows the model's
  context window, the provider refuses the request and the run ends as an API error, with the work done
  so far stranded.
- **They noticed when the agent was spinning.** A model that keeps reissuing the same failing call — the
  same command against the same missing file, the same read of a path the sandbox denies — burns its
  whole turn budget doing so. Today nothing notices; the run ends only at the turn limit or the
  deadline. A repeated *denied* call is the costliest case for bee: the kernel will deny it every time,
  and the model cannot tell a policy decision from a transient error.
- **They decided when the work was done.** An episode ends when the model replies without calling a
  tool. That is a guess: a model that pauses to explain its plan looks the same as one that has
  finished. bee records such a run as `completed` whether the task was done, abandoned, or blocked.

The study this feature draws on (Fan et al., 2026) varied one harness component at a time across four
models and two long-horizon coding benchmarks. Its findings that matter here:

- With no context management, runs overwhelmingly fail by overflowing the window: 79% of tasks were lost
  that way at a 32k window, and still 9% at 128k, where management raised the strongest model's success
  rate from 59.8% to 65.8%. Every managed policy eliminated overflow failures entirely.
- Among the policies tested, the cheapest at equal accuracy was **staged**: replace stale bulky tool
  outputs with short stubs first, and summarize old turns with a model call only if that is not enough.
  The cheap step handles most cases, so the paid summary call rarely runs.
- Making stubbed-out outputs **recoverable** (a tool to fetch them back) was almost never used and gave
  no accuracy gain. This feature therefore does not include one.
- The study's harness used a 24,000-character tool-result cap and a stuck detector that reminds the model
  after 5 identical calls and ends the run after 8 identical failing calls.

These three behaviours belong in the session core that 024 builds, so the headless loop and the REPL
share them, as 024 requires of every other part of a call and a turn.

### Terms this spec introduces

- **Context budget** — the number of input tokens the model is allowed to receive in one request: the
  model's context window minus room reserved for its reply.
- **Preamble** — the system prompt and the task (in the REPL, the system prompt and the first user
  message of the conversation). Never shortened.
- **Recent window** — the newest turns, kept word for word. At least the last two turns.
- **Middle region** — everything between the preamble and the recent window. The only part that may be
  shortened.
- **Elision** — replacing the body of one tool result in the middle region with a short **stub** that
  says what the call was and how it ended.
- **Summarization** — replacing the oldest turns of the middle region with a **running summary** written
  by a separate model call that is offered no tools.
- **Compaction** — elision and summarization together.
- **Streak** — consecutive tool calls with the same tool name and the same arguments.
- **Finish tool** — a tool the model calls to end an autonomous run, stating the outcome and a summary.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A long autonomous run does not die of its own history (Priority: P1)

An operator starts an autonomous session on a task that takes many turns — far more history than fits in
the model's context window. As the history grows, bee first replaces old, bulky tool outputs with short
stubs; if that is not enough, it folds the oldest turns into a running summary. The model keeps working.
The run ends because the task ended, the turn limit or deadline was reached, or the model finished —
never because the conversation outgrew the window. Afterwards, the operator's session record (transcript
and audit trail) still contains every turn, every full tool result, and every denial, exactly as if no
compaction had happened. It also shows when compaction happened and what it did.

**Why this priority**: Without it, every long autonomous run has a length beyond which it cannot
succeed, and the failure arrives as an API error with no warning. It is the largest measured effect in
the study this spec draws on.

**Independent Test**: With a scripted model and a small context budget, run a session whose tool results
would together exceed the budget several times over. Confirm that no request sent to the model exceeds
the budget; that the preamble and recent window reach the model word for word; that elision happens
before any summarization; and that the session record is complete and lists each compaction.

**Acceptance Scenarios**:

1. **Given** a session whose history crosses the soft threshold, **When** the next request is assembled,
   **Then** bulky tool results in the middle region are replaced by stubs, and the preamble and recent
   window are unchanged.
2. **Given** a session whose history is still above the hard threshold after elision, **When** the next
   request is assembled, **Then** the oldest middle turns are replaced by a running summary produced by
   a model call that was offered no tools.
3. **Given** an elided tool result whose call was denied by the kernel, or refused by the proxy, **When**
   the model reads its stub, **Then** the stub still states the tool, the outcome, and the denial or
   refusal (what was denied and why).
4. **Given** any session with compaction, **When** the operator reads the session record, **Then** every
   turn and full tool result is present, and each compaction is recorded with when it happened, what it
   removed, and the size before and after.
5. **Given** a session whose history stays below the soft threshold, **When** it runs, **Then** the model
   receives exactly what it receives today, apart from the tool-result cap (User Story 4).

---

### User Story 2 - A stuck agent is told, then stopped (Priority: P1)

An autonomous agent starts repeating itself: the same command with the same arguments, failing the same
way each time. After a few repeats, bee adds a short note to the model's next input saying it has
repeated the same call several times and should try something different. If the agent changes approach,
the run continues normally. If it keeps repeating the same failing call, bee ends the run early, records
it as stuck, and names the repeated call, instead of letting it burn the rest of the turn budget.

When the repeated call is one the sandbox keeps denying, the note is different and comes sooner: it says
the denial is the session's policy, that repeating the call will be denied again, and that the agent
should work within what it has been granted.

**Why this priority**: A spinning autonomous run wastes its whole budget and produces nothing, and with
no person watching nobody interrupts it. The repeated denied call is the case bee is uniquely positioned
to explain.

**Independent Test**: With a scripted model, issue (a) the same failing call repeatedly until the run
ends, (b) the same call a few times then a different one, and (c) the same call that the scripted sandbox
denies each time. Confirm the reminder appears once at the threshold, the run ends at the termination
threshold with a stuck status in (a), continues normally in (b), and (c) gets the policy reminder at its
lower threshold.

**Acceptance Scenarios**:

1. **Given** a streak of identical tool calls reaching the reminder threshold, **When** the model's next
   input is assembled, **Then** it contains one reminder from bee to change approach, and that reminder
   is not repeated for the same streak.
2. **Given** a streak of identical failing calls reaching the termination threshold, **When** the call
   completes, **Then** the run ends with a stuck status that names the repeated tool and its arguments.
3. **Given** a streak broken by a different call, **When** the agent later starts a new streak, **Then**
   counting starts again from one, and the reminder can be given again.
4. **Given** the same call denied by the sandbox (and not granted) reaching the denied-call threshold,
   **When** the model's next input is assembled, **Then** it contains a reminder that the denial is
   policy, not a transient error, and that repeating the call will be denied again.
5. **Given** an interactive session, **When** the termination threshold is reached, **Then** the current
   exchange ends and control returns to the person with a message saying why; the session itself does
   not end.

---

### User Story 3 - An autonomous run ends because the agent says it is done (Priority: P2)

In an autonomous session, the model has a finish tool. When it believes the work is complete — or that it
cannot continue — it calls finish with an outcome (completed, blocked, or abandoned) and a short summary.
The run ends there, and the operator's record shows the outcome and summary in the agent's words. A
reply without tool calls no longer silently ends the run: bee reminds the model once that it must call
finish to end, and only if it again replies without tool calls does the run end, recorded as ended
without finishing.

**Why this priority**: It turns "the model stopped calling tools" into an explicit, recorded decision,
which is what an operator reviewing an unattended run needs to know. It is P2 because, unlike the other
two stories, runs do not fail without it — they are only recorded less precisely.

**Independent Test**: With a scripted model, run three autonomous sessions: one that calls finish with
outcome completed, one that replies with text and then calls finish after the reminder, and one that
replies with text twice. Confirm the recorded statuses (finished: completed; finished: completed after
one reminder; ended without finishing) and that the summary is in the record.

**Acceptance Scenarios**:

1. **Given** an autonomous session, **When** the model calls finish with an outcome and summary, **Then**
   the run ends, and the record shows the outcome and the summary.
2. **Given** an autonomous session, **When** the model replies with text and no tool calls, **Then** it
   receives one reminder that it must call finish to end the run, and the run continues.
3. **Given** an autonomous session in which the model has already received that reminder, **When** it
   replies with text and no tool calls again, **Then** the run ends and is recorded as ended without
   finishing.
4. **Given** a turn in which the model calls other tools and then finish, **When** the turn runs, **Then**
   the calls before finish run normally, finish ends the run, and any calls after finish in the same turn
   are not run and are recorded as not run.
5. **Given** an interactive session, **When** the person and the model converse, **Then** the finish tool
   is not offered, and a reply without tool calls ends the exchange exactly as it does today.
6. **Given** a CTF-mode episode, **When** it runs, **Then** its existing terminal tools decide how it
   ends, and the finish tool is not offered.

---

### User Story 4 - One large tool result cannot crowd out the conversation (Priority: P2)

An agent reads a large file or runs a command with a lot of output. The model receives at most a bounded
amount of that output — by default about 24,000 characters, and never more than a fixed share of the
context budget — with a marker saying how much was cut and how to see more. The full output is still in
the session record, as it is today.

**Why this priority**: It is the cheapest change in this feature and removes the single-call path to
overflow, but on its own it does not stop history from growing, so it ranks below User Story 1.

**Independent Test**: Run a tool that produces output several times the cap under a small and a large
context budget. Confirm the model receives at most the smaller of the configured cap and the budget share,
the marker states the original size, and the session record keeps what it keeps today.

**Acceptance Scenarios**:

1. **Given** the default configuration, **When** a tool produces output larger than the cap, **Then**
   the model receives the capped output and a marker giving the original size and suggesting a narrower
   request.
2. **Given** a context budget small enough that the share limit is lower than the configured cap,
   **When** a tool produces large output, **Then** the share limit applies.

---

### Edge Cases

- **The model's context window is unknown** (a model bee has no record of, and none configured): bee
  uses a conservative default budget, says so once at session start, and lets configuration override it.
- **One turn's own new content would exceed the hard threshold** even after everything in the middle is
  summarized: the output cap (User Story 4) bounds each result, so this needs many large results in one
  turn. The current turn is never compacted (FR-003). If the request still cannot fit, the run ends
  with the context-budget-exhausted status (FR-014).
- **Summarization fails** (provider error, or the summary itself is too long): bee falls back to removing
  the oldest middle turns with a marker that they were removed, records the failure, and continues. If
  the request still cannot fit within the budget, the run ends with a distinct status saying the context
  budget was exhausted — never with an unexplained API error.
- **A tool call and its result would be split** by compaction: compaction never removes one without the
  other, and never leaves the model with a call that has no result.
- **A tool result contains text that looks like instructions** ("ignore the above and …"): the running
  summary is still presented to the model as a summary of untrusted tool output and conversation, never
  as part of the system prompt or bee's own instructions. The summarization call is offered no tools, so
  it cannot act on such text.
- **Compaction would run on every turn** once history sits near a threshold: each compaction reduces the
  history enough below the threshold that the next several turns do not trigger another, so the stable
  start of the request (which providers cache) changes rarely.
- **Identical calls are spread across turns, or several in one turn**: a streak counts calls in the order
  they ran, across turn boundaries.
- **Arguments differ only in key order or whitespace**: they are the same call.
- **A repeated call alternates between success and failure**: only consecutive identical *failing* calls
  count toward termination; the reminder threshold counts identical calls regardless of outcome.
- **A denied call is granted on escalation and the retry succeeds**: it is not a denied repeat; it counts
  as a successful call.
- **The finish tool is called with an outcome bee does not recognise, or no summary**: the call is
  rejected as invalid arguments, the run continues, and the model can call it again.
- **The finish tool is called while a consent request is pending**: not possible — consent is decided
  within the call that raised it, before the next call runs.
- **A scenario lists its own tools**: the finish tool is added to autonomous standard-mode sessions
  regardless, unless the scenario explicitly opts out (finish needs no capability and grants none).
- **The REPL's `/clear`**: still drops the conversation history; it also resets compaction state and
  streaks.

## Requirements *(mandatory)*

### Functional Requirements

**Context budget**

- **FR-001**: Every session MUST know its context budget: the model's context window less a reserve for
  the reply. bee MUST know the window for the models it ships support for, MUST allow configuration to
  set or override it, and MUST use a conservative default, announced once at session start, when neither
  applies.
- **FR-002**: Before each model request, bee MUST measure the size of the request it is about to send
  against the context budget, and MUST NOT send a request it measures as larger than the budget.

**Compaction**

- **FR-003**: Compaction MUST change only the middle region. The preamble and the recent window MUST
  reach the model word for word. The recent window MUST be at least the last two turns, and MAY be larger
  within its share of the budget.
- **FR-004**: When the request exceeds the **soft threshold** (default 60% of the budget), bee MUST
  replace bulky tool results in the middle region with stubs, oldest first, until the request is at or
  below the compaction target (FR-015) or no bulky results remain in the middle region. A result is bulky when it exceeds a
  configurable size (default a few hundred tokens); small results are left as they are.
- **FR-005**: When the request still exceeds the **hard threshold** (default 85% of the budget) after
  elision, bee MUST replace the oldest turns of the middle region with a running summary, produced by a
  separate model call that is offered no tools, until the request is at or below the compaction target
  (FR-015).
- **FR-006**: Elision MUST be tried before summarization at every compaction. Summarization MUST NOT run
  while elision alone can bring the request below the hard threshold.
- **FR-007**: A stub MUST state: the tool name; a short form of its arguments; whether it succeeded,
  failed, timed out, or was refused; the size of the result it replaces; and, when the call was denied by
  the kernel or refused by the proxy, what was denied or refused and why. A stub MUST NOT be presented as
  the tool's output.
- **FR-008**: A running summary MUST be presented to the model as a summary of earlier conversation and
  tool output — data, not instructions. It MUST NOT be placed in, or merged into, the system prompt or any
  part of the input bee presents as its own instructions.
- **FR-009**: When a summary is extended, the earlier summary MUST be one of the inputs to the new one, so
  that facts survive repeated summarization. The summary request MUST ask for: progress on the task, files
  and resources changed, denials and refusals met, decisions taken, and open questions.
- **FR-010**: Compaction MUST NOT separate a tool call from its result, and MUST NOT leave a call in the
  model's input without its result.
- **FR-011**: Compaction MUST change only what the model is sent. The session record (transcript, audit
  trail, consent decisions, call outcomes) MUST remain complete and unchanged by compaction.
- **FR-012**: Every compaction MUST be recorded in the session record with: the turn it happened on, what
  it did (elision, summarization, fallback removal), how many results or turns it affected, the request
  size before and after, and, for summarization, the cost of the summary call.
- **FR-013**: The cost and token usage of summary calls MUST be included in the session's usage totals and
  shown separately from the agent's own turns.
- **FR-014**: If summarization fails, bee MUST remove the oldest middle turns instead, leaving a marker
  that they were removed, and record the failure. If the request still cannot be brought within the
  budget, the run MUST end with a distinct status stating that the context budget was exhausted.
- **FR-015**: Each compaction MUST bring the request down to a **compaction target** below the soft
  threshold (default 10 points below it, i.e. 50% of the budget), so that the next turn does not compact
  again unless that turn alone adds enough to cross a threshold.
- **FR-016**: bee MUST NOT offer the model a tool to recover elided or summarized content.
- **FR-017**: The thresholds, the bulky-result size and the recent-window share MUST be configurable. The
  compaction policy MUST be shared by the headless and interactive loops, as part of the session core.
- **FR-018**: In an interactive session, each compaction MUST be shown to the person as a one-line notice
  (what was compacted and the resulting size). In a headless session, it MUST appear as a progress line.
- **FR-019**: The REPL's `/clear` MUST reset compaction state (the running summary and elision records)
  along with the history.

**Tool-result cap**

- **FR-020**: The amount of one tool result sent to the model MUST be capped at the smaller of a
  configured limit (default 24,000 bytes, the same as characters for ASCII output) and a configurable share of the context budget (default
  10%).
- **FR-021**: A capped result MUST carry a marker giving its original size and suggesting a narrower
  request (a range of lines, a filter, a smaller search).
- **FR-022**: What the session record keeps of a tool result MUST NOT be reduced by this change.

**Stuck detection**

- **FR-023**: bee MUST track streaks of identical tool calls in the order they run, across turns. Two
  calls are identical when they name the same tool and their arguments are equal as structured data
  (key order and insignificant whitespace do not matter).
- **FR-024**: When a streak reaches the **reminder threshold** (default 5 identical calls, whatever their
  outcome), bee MUST add one reminder to the model's next input saying that the same call has been made N
  times and that it should try a different approach. The reminder MUST be given at most once per streak.
- **FR-025**: When consecutive identical **failing** calls reach the **termination threshold** (default
  8), bee MUST end the run, recording a stuck status that names the tool and its arguments and the number
  of repeats. A call is failing when it returned an error, timed out, or was denied and not granted.
- **FR-026**: When consecutive identical calls are each denied by the kernel or refused by the proxy, and
  not granted on escalation, bee MUST add a reminder at the **denied-call threshold** (default 2) saying
  that the denial is the session's policy, that repeating the call will be denied again, and that the
  agent should work within what it has been granted. It MUST be given at most once per streak, and it
  takes the place of the general reminder for that streak.
- **FR-027**: A different call, or a successful call, MUST end the failing streak; a different call MUST
  end the identical-call streak.
- **FR-028**: Reminders MUST be presented as bee's own notes, distinct from tool output and from
  conversation content, and MUST be recorded in the session record with the streak they answer.
- **FR-029**: In an interactive session, reaching the termination threshold MUST end the current exchange
  and return control to the person with a message naming the repeated call; the session continues.
- **FR-030**: All three thresholds MUST be configurable, and stuck termination MUST be able to be turned
  off.

**Finish tool**

- **FR-031**: Every autonomous standard-mode session MUST offer the model a finish tool, unless the
  session's scenario explicitly opts out. The finish tool MUST NOT require or grant any capability.
- **FR-032**: The finish tool MUST take an outcome — one of completed, blocked, abandoned — and a summary.
  A call with a missing or unrecognised outcome, or an empty summary, MUST be rejected as invalid
  arguments and MUST NOT end the run.
- **FR-033**: A valid finish call MUST end the run. The record MUST show the outcome and the summary, and
  the run's status MUST be "finished" with that outcome.
- **FR-034**: Tool calls in the same turn before the finish call MUST run normally; calls after it MUST NOT
  run and MUST be recorded as not run.
- **FR-035**: When the finish tool is offered and the model replies without tool calls, bee MUST add a
  reminder, once per run, that the run ends only through the finish tool, and continue. A second reply
  without tool calls after that reminder MUST end the run with a status of ended without finishing.
- **FR-036**: The command-line exit status of a headless run MUST distinguish a run finished with outcome
  completed from every other ending, consistently with how bee's exit statuses distinguish success today.
- **FR-037**: The finish tool MUST NOT be offered in interactive sessions or in CTF-mode episodes. Their
  endings are unchanged: in the REPL a reply without tool calls ends the exchange; CTF episodes end through
  their existing terminal tools.

**Behaviour preservation and delivery**

- **FR-038**: A session whose requests never cross the soft threshold, whose tool results never exceed
  the cap, and in which no streak reaches a threshold, MUST send the model exactly what it sends today,
  apart from the finish tool and its reminder in autonomous sessions.
- **FR-039**: Changes to the session record MUST be additions (compaction events, reminders, new statuses,
  finish outcome and summary), omitted when empty; no existing field changes meaning.
- **FR-040**: Compaction, stuck detection and the finish tool MUST each be testable without a model
  provider, a network, or a BPF-LSM kernel, using a scripted model and the scripted audit source 024
  introduced.
- **FR-041**: Delivery MUST be phased, each phase leaving the full test suite passing, in this order:
  stable result framing (a prerequisite found in planning, research R10) → context budget and
  tool-result cap → stuck detection → finish tool → compaction (off by default) → compaction on by
  default once SC-010 has been reported.

### Resolved Decisions

- **D1 — Staged compaction, no recall.** Elide first, summarize only if needed; no tool to fetch
  compacted content back. The study found recall was almost never used and gained nothing (FR-006, FR-016).
- **D2 — The record is never compacted.** Compaction is about what the model is sent; the operator's
  record stays complete (FR-011). This keeps bee's auditability guarantee intact.
- **D3 — Summaries are untrusted data.** Tool output can be attacker-controlled; summarizing it must not
  launder it into trusted instructions (FR-008).
- **D4 — Denials survive compaction.** Stubs and summaries keep the denials and refusals the session met,
  because they shape what the agent may still try (FR-007, FR-009).
- **D5 — Both kinds of ending.** Stuck detection ends a run from the harness side; the finish tool lets
  the model end it deliberately (user decision, 2026-10-11).
- **D6 — Finish is autonomous-only.** In the REPL the person decides when the conversation is over; a
  reply without tool calls already hands control back (FR-037).
- **D7 — Defaults follow the study** (60% / 85% thresholds, two-turn recent-window floor, 24,000-character
  cap, reminder after 5, stop after 8) and are all configurable. The denied-call threshold of 2 is bee's
  own: a kernel denial is deterministic, so a second identical attempt is already evidence of misreading
  it.

### Key Entities

- **Context budget**: the input size allowed for one model request, derived from the model's window and a
  reply reserve; known per model or configured.
- **Compaction state**: the running summary, the set of elided results, and the position of the middle
  region; part of the session, reset by `/clear`.
- **Stub**: the stand-in for an elided tool result — tool, short arguments, outcome, original size,
  denials or refusals.
- **Compaction event**: a session-record entry for one compaction — turn, kind, items affected, sizes
  before and after, summary cost.
- **Streak**: the current run of identical calls, with its count, its failing count, whether all were
  denied, and which reminders it has received.
- **Reminder**: one bee-authored note added to the model's input (change approach, policy denial, call
  finish), recorded with what triggered it.
- **Run ending**: the new statuses this feature adds — finished (with outcome and summary), ended without
  finishing, stuck (with the repeated call), and context budget exhausted.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In a scripted run whose uncompacted history would reach at least five times the context
  budget, no request sent to the model exceeds the budget, and the run reaches its scripted end.
- **SC-002**: With compaction enabled, across a test matrix of at least three context budgets, the number
  of runs ending because the history outgrew the window is zero.
- **SC-003**: In runs where elision alone is enough, zero summary calls are made; in the scripted matrix,
  summary calls happen only on turns where the request was still above the hard threshold after elision.
- **SC-004**: 100% of stubs for denied or refused calls state the denial or refusal, checked over every
  denied and refused call in the test suite's scripted scenarios.
- **SC-005**: For every compacted run in the test suite, the session record is identical to the record of
  the same scripted run with compaction disabled, apart from the added compaction events.
- **SC-006**: A scripted run that repeats the same failing call ends within 8 such calls, rather than at
  its turn limit; a run that repeats a call 5 times and then changes approach completes normally.
- **SC-007**: A scripted run that repeats a call the sandbox denies receives the policy reminder by its
  second attempt.
- **SC-008**: Every autonomous run in the test suite that offers the finish tool ends with one of: finished (with outcome), ended
  without finishing, stuck, context budget exhausted, or an existing status (timeout, API error,
  infrastructure error); none is recorded as completed merely because the model stopped calling tools.
- **SC-009**: Sessions that cross no threshold produce the same model inputs as before this feature (apart
  from the finish tool in autonomous sessions), checked against 024's characterization tests.
- **SC-010**: On bee's own scenario set, a paired comparison (same tasks, compaction on vs. off, at a
  window small enough to bind) is run and reported before compaction is enabled by default.

## Assumptions

- This feature builds on 024-session-core's shared session core and call lifecycle, and is delivered after
  024's call-lifecycle and session-builder phases land. Where 024 is incomplete, the work waits for it
  rather than duplicating logic into both loops.
- The defaults come from a study of open-weight models on coding benchmarks; bee's models and tasks differ,
  so the defaults are starting points to be checked by SC-010, not proven optimal.
- Token counts are measured, not exact: bee estimates request size before sending and corrects its
  estimate from the provider's reported usage after each turn. A margin in the reply reserve absorbs the
  difference.
- The summary call uses the same model as the session. Using a cheaper model for summaries is a possible
  follow-up, not a requirement.
- Codemode (023) scripts issue many tool calls inside one model call; how streaks count those calls is
  settled when codemode lands, not here.
- A manual `/compact` command for the REPL, and planning (a stored plan injected each turn), are out of
  scope. Planning is the natural next step: a plan kept outside the history survives compaction.
- Interactive sessions keep today's endings; the person, not a tool, decides when a conversation is over.

## Dependencies

- 024-session-core: the session core, Operators, call lifecycle and the scripted audit source used for
  testing.
- 007-dynamic-grants and 019-http-intercept: the kernel denials, proxy refusals and escalation outcomes
  that stubs, streaks and the policy reminder report.
- US3 of 002-llm-harness: the existing terminal-tool mechanism (`submit_flag`, `give_up`) that the finish
  tool's ending follows.

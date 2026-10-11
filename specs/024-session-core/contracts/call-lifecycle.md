# Contract: Call lifecycle (`src/call.rs`)

FR-017–FR-027. Types in [data-model.md](../data-model.md#callinput--calloutcome).

```rust
pub enum TimeoutPolicy { Deadline(Instant), PerCall(Duration) }   // PerCall(t) → Deadline(start + t)

pub struct CallInput<'a> { pub call: &'a ToolCall, pub turn: u32,
                           pub origin: CallOrigin, pub timeout: TimeoutPolicy }

pub struct Escalation<'a> { pub config: &'a LoopEscalation, pub active: &'a mut ActivePolicy,
                            pub operator: &'a Operator }

/// Run one tool call to completion. The returned future is Send.
pub async fn run_call(input: CallInput<'_>, sandbox: &mut Sandbox, registry: &mut ToolRegistry,
                      esc: Option<Escalation<'_>>, output: &dyn SessionOutput) -> CallOutcome;
```

## Sequence (the only implementation of it)

1. Dispatch `BeforeToolCall`. `Deny` → return `refused_by_hook`, tool not run. `Escalate` → widen cycle
   (proactive); record.
2. `begin_call(ctx)`; execute under the attempt's timeout.
3. `settle`; `drain_audit` → attempt audit.
4. If attempt audit has a tool-scope denial and escalation is on: dispatch `KernelDenial` for the first
   denial; widen cycle; record. If **granted** and time remains before the call's deadline
   (both policies) → move attempt audit to `denied_attempt_audit`, execute again inside the same
   open call, settle, drain.
5. `end_call` → proxy events.
6. If not yet retried and a proxy event is `refused_out_of_scope`: dispatch `ProxyRefusal`; widen cycle
   (Target scope); record. If granted and time remains → `begin_call` anew, execute, settle, drain,
   `end_call`; the earlier attempt's audit moves to `denied_attempt_audit` and its proxy events (the
   refusal) to `denied_attempt_proxy_events` (FR-021).
7. `drain_sidecar_audit` → `proxy_audit`; then a final `drain_audit` → appended to `audit` (late events).

## Guarantees

- At most one retry per call; retry only on `EscalateOutcome::Granted` (never `AlreadyHeld`/`Refused`).
- The first attempt and the retry share one deadline; a retry is given only the remaining time and is not
  started when none remains (FR-024).
- On any attempt timeout: `result` is the timeout result **of that attempt** and `audit` is that
  attempt's drained audit; `timed_out = true`.
- Proxy-scope events never reach the `KernelDenial` dispatch.
- `escalations` lists every widen cycle run, in order, with trigger and outcome.
- `output` receives `tool_call`, `escalation`, `proxy_event`, `tool_result` in that order; rendering of
  conversation messages stays with the loop.

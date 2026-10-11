# Contract: Operator

The only seam where autonomous and interactive bee differ (FR-001–FR-005). Types in
[data-model.md](../data-model.md#operator).

```rust
pub enum OperatorKind { Interactive, Autonomous }

#[async_trait]
pub trait Consent: Send + Sync {
    /// Decide one request. Must not block the async executor; may await a person.
    async fn decide(&self, req: &ConsentRequest) -> Decision;
}

pub trait SessionOutput: ReplOutput {          // ReplOutput's existing methods, unchanged
    fn header(&self, line: &str) { self.info(line) }
    fn turn_started(&self, turn: u32) {}
    fn assistant_text(&self, text: &str) {}    // non-streamed loop
    fn escalation(&self, trigger: &Trigger, outcome: &EscalateOutcome) {}
    fn consent_decided(&self, rec: &ConsentRecord) {}
}

impl Operator {
    pub fn interactive(consent: ChannelConsent, output: Arc<dyn SessionOutput>) -> Self;
    pub fn autonomous(output: Arc<dyn SessionOutput>) -> Self;     // AllowWithinCeiling
    pub fn with_timeout(self, t: Duration) -> Self;
    /// The only consent entry point. Applies the timeout, records, notifies output.
    pub async fn consent(&self, req: ConsentRequest) -> ConsentRecord;
    /// Record a decision made without asking (BeyondCeiling only).
    pub fn record_unasked(&self, req: ConsentRequest, reason: Reason) -> ConsentRecord;
    pub fn output(&self) -> &dyn SessionOutput;
    pub fn take_log(&self) -> Vec<ConsentRecord>;
}
```

## Behaviour

| Case | Result | `reason` |
|---|---|---|
| Adapter returns Granted within timeout | Granted | `Granted` |
| Adapter returns Denied | Refused | `DeniedByOperator` |
| Timeout elapses (either adapter) | Refused | `TimedOut` |
| `ChannelConsent` sender dropped (front-end gone) | Refused | `DeniedByOperator` |
| Beyond ceiling (decided by caller, never offered) | Refused | `BeyondCeiling` |
| Every capability already held | — (no decision) | not recorded |

- `Autonomous` never awaits a person; `AllowWithinCeiling` returns immediately.
- `Interactive`, start-up and in-loop alike: via `ChannelConsent` to the front-end, which owns the only
  terminal reader. The inline REPL starts its line reader before the session is built and hands the
  pending read to `run_repl`; the TUI shows start-up consent as its first modal. Never a raw `stdin` read,
  never a second reader.
- An answer arriving after the timeout is reported as "consent already timed out" and dropped — neither
  applied nor steered.
- Inline REPL in-loop answer: only `y|yes|n|no` (case-insensitive, trimmed) answers; any other line is
  steering and the question is re-shown.
- TUI: a consent modal answered by `y`/`n`; input buffer untouched.

## ProgressOutput (Autonomous) — strings preserved byte-for-byte

Emitted through the `ProgressSink`, exactly as `src/episode.rs` emits today:

```
episode '{id}' · {model} · tools: {a,b}
  {note}
turn {index}
  text: {preview120}
  call {name} {preview(args,100)}
  escalate(proactive|reactive|proxy): {outcome:?}
  {render_proxy_event(ev)}
  result {ok|ERR|DENIED}{ (exit N)}: {preview120}
  audit: {op} denied {target}
done: {status} · {n} turns · {ms}ms
skill warning: {path}: {reason}
skill grant: '{n}' capabilities granted (within ceiling)
skill grant: '{n}' refused — {reason}
{http advisory banner}
WARNING: {e} — a process may have outlived enforcement
```

Change permitted by FR-022: `DENIED` is no longer set by proxy-scope events alone. New line (consent
log): `  consent: {granted|refused} ({reason}) — {origin}` — additive.

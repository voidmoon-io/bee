# Contract: Hooks

FR-028–FR-034.

```rust
pub enum StepEvent<'a> {
    TurnStart { turn: u32 },
    BeforeToolCall { call: &'a ToolCall },
    KernelDenial { op: &'a str, target: &'a str, call: &'a ToolCall },
    ProxyRefusal { host: &'a str, port: u16, call: &'a ToolCall },
}
pub enum Flow { Continue, Deny(String), Escalate(GrantDelta), Deescalate(GrantId), RefreshTools }

#[async_trait] pub trait LoopHook: Send + Sync {
    fn observes(&self, kind: StepEventKind) -> bool;
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow;
}

pub struct Dispatch { pub deny: Option<String>, pub escalate: Option<GrantDelta>,
                      pub deescalate: Vec<GrantId>, pub refresh_tools: bool }
pub async fn dispatch(hooks: &[Box<dyn LoopHook>], ev: &StepEvent<'_>) -> Dispatch;
```

- Every observing hook is consulted. `deny` set ⇒ `escalate` is ignored for that event (refusal wins).
  Multiple `Escalate` deltas are merged.
- `TurnStart` is dispatched by `Session::turn_start` at the top of every model turn in both loops.
- `Deny` on `BeforeToolCall` ⇒ the tool does not run; the model receives
  `refused by hook: {reason}` with `is_error = true` and a distinct outcome tag.
- `Deescalate(id)` ⇒ lease released, scope narrowed at that turn start.
- Removed: `BeforeModelCall`, `AfterToolResult`, `Flow::Terminate`.
- Built-in hooks: `DenialEscalationHook`, `ProxyRefusalHook`, `SkillEscalationHook`, `McpRefreshHook`.

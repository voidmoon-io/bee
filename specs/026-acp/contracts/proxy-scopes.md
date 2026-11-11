# Contract: proxy scopes per subagent (019 T092) and resolve-and-admit

## Who gets a proxy scope

| Sandbox | Proxy scope | Its targets | Its egress |
|---|---|---|---|
| Session, `[policy.http]` active | yes (as today) | policy targets | policy egress |
| bee-loop subagent of an intercepting session | **yes (new)** | derived targets (⊆ parent's) | derived egress |
| bee-loop subagent of a non-intercepting session | no | — | — |
| harness subagent | **always** | parent's targets if the parent intercepts, else none | the agent's `requires.net` |

A bee-loop subagent's derived `[policy.http]` is checked by `check_http` (019 T026) as today; the
refusal at `delegate.rs:322-330` is removed.

## Lifecycle

- Created on the session's supervisor right after its tool scope, as a scope record whose parent
  link is that tool scope; the worker (`bee proxy-worker`) is spawned into it.
- The tool scope's kernel network becomes the proxy loopback port only (`with_proxy_loopback`).
- Each tool call / harness gets a credential in the subagent's own namespace (`HTTPS_PROXY` userinfo);
  a credential from one subagent is refused by another's worker.
- Teardown: proxy scope before its tool scope, children before parents.

## Attribution

Every `ExchangeRecord`, `TunnelRecord` and `ProxyEvent` from a subagent's worker carries that
subagent's scope id and delegation id; the 019 store indexes by both. Nothing a subagent's worker
records is attributed to the parent or a sibling (SC-007).

## Resolve-and-admit

The worker resolves nothing itself (DNS is not in its kernel rules); it sends
`FromWorker::Resolve { host }`. bee's resolver for that proxy scope:

1. Refuses a host that is not one of the scope's compiled targets/egress names (`error`).
2. Resolves it with the system resolver.
3. If any address is not yet in the scope's kernel network rules for that host's port, **reloads the
   proxy scope** with them added (`admitted[host]`, at most 16 per host; the oldest evicted beyond),
   recorded as a reload event.
4. Answers `ToWorker::Resolved { addrs }` only after the reload has taken effect.

The worker connects only to addresses in a `Resolved` answer, so every upstream connection is to an
address the kernel admitted for a declared name.

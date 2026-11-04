# Decision models: official Jev and Workers AI

`decision_evaluate` lets Bee's main model ask a separate decision model to classify supplied
text/JSON, score it against a rubric, or estimate whether a statement holds. It returns judgments,
probabilities, provider model identity, and usage. It does not retrieve evidence, grant authority,
or adjudicate findings.

Build with `cargo build --features decisions`. This adds the HTTP client to the application only;
it does not add dependencies to the core or kernel crates. Without the feature the tool remains a
known name but returns a compiled-out error.

## Enable a provider

The first version uses operator process environment settings. Project files and tool arguments
cannot supply endpoints, credentials, or model overrides. Credentials alone do not enable a backend.
Set these in the environment launching Bee, not in a tool shell or project configuration:

For the official TypeSafe service:

```sh
export BEE_DECISION_JEV_ENABLED=1
export BEE_DECISION_JEV_MODEL=jev-latest
# Supply TYPESAFE_API_KEY through your normal secret manager/environment.
```

Bee calls `https://api.typesafe.ai/v1/systemone` with bearer authentication. Use a versioned model
name from the authenticated TypeSafe `/v1/models` catalog for repeatable evaluations; `jev-latest`
is the default and may change. Unknown model names are rejected by the provider.

For Cloudflare Workers AI:

```sh
export BEE_DECISION_CLEF_ENABLED=1
export BEE_DECISION_CLEF_MODEL=clef-flash
export CLOUDFLARE_ACCOUNT_ID=your_32_character_account_id
# Supply CLOUDFLARE_API_TOKEN with Workers AI inference access to this account.
```

Use `clef` or `clef-flash` (the default). Bee calls
`https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/@cf/cloudflare/{model}`
and unwraps the Workers AI `success`/`result` envelope. No deployed Worker or intermediary service
is needed. Either backend can be enabled independently; there is no automatic fallback.

Enable the tool alongside the tools you already use. For interactive configuration:

```toml
[session]
tools = ["bash", "read_file", "write_file", "list_directory", "search", "decision_evaluate"]
```

For a headless scenario, add `decision_evaluate` to its existing `[scenario].tools` list. The same
registry constructs the tool for headless and interactive sessions. Environment settings and keys
are captured when that tool instance is constructed; restart the session after changing them.

## Tool call

```json
{
  "backend": "jev",
  "state": {
    "claim": "The request reaches an unescaped shell command.",
    "evidence": "Paste the relevant code and data-flow observations here."
  },
  "questions": {
    "supported": {
      "type": "noul",
      "instructions": "Does the supplied evidence support the claim?"
    },
    "next_step": {
      "type": "choice",
      "instructions": "Which investigation step is best supported?",
      "criteria": {
        "trace": "Trace the input further; reachability is unresolved.",
        "reproduce": "Build a controlled reproduction of the observed path.",
        "insufficient": "The supplied evidence does not support either step."
      }
    },
    "strength": {
      "type": "score",
      "instructions": "Rate evidence strength, not vulnerability severity.",
      "criteria": ["Unsupported", "Plausible", "Directly demonstrated"]
    }
  }
}
```

Change `backend` to `clef` to use the operator's Workers AI model. Arguments accept only these
three fields. Each question requires nonempty text instructions; choices use 2–255 named string
descriptions, scores use 2–10 ordered string levels, and `noul` returns a probability of yes.
Rubric scores are zero-based and may be fractional. This initial common subset has no images,
video, box questions, or provider-specific extensions.

Results are JSON with `backend`, the provider-reported `model`, `answers`, and `usage`. Bee checks
answer ids and types, option membership, score ranges, and probability distributions before returning
success. Treat these probabilities as model judgments, not established facts. Decision usage is
included in the tool result/transcript; it is not added to the main chat model's token/cost totals.

## Execution boundary and limits

This is an explicitly enabled **host-side provider inference capability**, like the main model
connection, not an HTTP tool confined by the target scope. Enabling a backend permits sending the
model-selected state/questions to that official provider. Its request is not intercepted or included
in the kernel tool audit as a sandboxed network operation. It still runs through Bee's call lifecycle,
including hooks, per-call deadlines, and transcript recording. Responses have remote provenance and
receive Bee's untrusted-data framing when sent back to the chat model.

The tool has a 30-second total timeout (a shorter call deadline wins), a 64-KiB serialized request
limit, a 1-MiB response limit, and at most 64 questions. These are Bee limits, not promises about
provider token capacity: keep evidence focused and within the selected model's context window.
The provider may truncate text that exceeds its own token limit. Whole-session replay is not automatic.

Redirects and environment HTTP proxies are disabled. Provider bodies and transport diagnostics are
not echoed on errors, and credentials are kept out of tool schemas/results and child environments.
HTTP failures, malformed answers, and disabled backends return tool errors. There are no automatic
inference retries, provider fallbacks, or durable replays: a timeout can leave billing/outcome unknown.
An explicit new call can still incur a new charge. Durable calls retain `NeverReplay` recovery.

## Contracts and verification

Request contracts were checked against the official
[TypeSafe OpenAPI specification](https://api.typesafe.ai/openapi.json),
[Clef reference](https://developers.cloudflare.com/workers-ai/models/clef/), and
[Clef-flash reference](https://developers.cloudflare.com/workers-ai/models/clef-flash/).

Offline tests exercise authenticated JSON requests through Bee's call lifecycle, both response
formats, disabled backends, invalid arguments, invalid answers, redirects, HTTP errors, and oversized
responses. Live paid-provider inference is separate and requires operator credentials; offline tests
do not establish model accuracy or account/model availability.

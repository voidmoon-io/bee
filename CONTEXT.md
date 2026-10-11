# Bee

Bee runs coding-agent sessions whose tools receive capability-scoped access to a host. The same session model supports headless sandbox testing and an interactive REPL.

## Language

**User configuration**:
Protected, operator-owned configuration at `~/.config/bee/config.toml` (honouring `XDG_CONFIG_HOME`) that defines trusted defaults and the maximum authority available to Bee sessions. Project content and agents cannot weaken or widen its authority.
_Avoid_: Global config, personal config

**Project configuration**:
Repository-local configuration at `.bee/config.toml` that describes project defaults and may request authority within the user configuration. It is treated as untrusted input when the repository is untrusted.
_Avoid_: Repo config, workspace config

**Effective configuration**:
The validated, complete result of resolving explicit operator intent, user configuration, and project configuration. Individual configuration files are optional, but Bee fails before execution when the available sources are incomplete; the result never grants authority beyond the user configuration.
_Avoid_: Merged config, resolved config

**Native tool**:
A security-analysis tool whose engine is a maintained Rust crate compiled into Bee, run as a scope-joined `bee <name>-worker` child — structural search, repository history, severity scoring. The rule is which side of the buy/build line the *value* sits on: when the value is the engine, Bee links the crate.
_Avoid_: Built-in tool, internal scanner

**External scanner**:
A third-party analysis binary whose value is its curated **rule corpus** rather than its engine, run only under an inode-pinned `exec.allow` grant with argv Bee constructs from typed inputs. Bee never reimplements a corpus and never hands the model a command line. One scan may be several children — a version pin verified before use, then the analysis itself — but every one of them is a child, because asking a binary what it is, running it, and reading what it wrote are all things the harness does from outside the scope if it does them itself.
_Avoid_: Plugin, integration, shell-out

**Finding ledger**:
The project's durable, append-only record of security findings at `.bee/findings/ledger.jsonl`, folded into a derived `view.json`. Re-runs merge into it; a human verdict recorded in it outranks every later automated rediscovery.
_Avoid_: Findings database, results file, report

**Finding**:
One reviewable observation about the code, identified by its path, issue class, and normalised title — deliberately **not** its line number, so code movement alone never mints a duplicate. Each occurrence is a *sighting*.
_Avoid_: Issue, alert, hit

**Verdict**:
A person's adjudication of a finding — confirmed, false positive, fixed, duplicate, deferred — recorded only through `bee findings adjudicate`. It is never writable by an agent: a verdict is worth something precisely because a human formed it.
_Avoid_: Status, triage state, disposition

**Target scope**:
The hosts a session may test, declared in `[policy.http]` as `targets` (testable) and `egress` (reachable as tunnels only, never testable), with `inspect` naming the hosts whose TLS is decrypted. It is policy data, attenuated like the rest of a policy, and widened only by an operator's consent within the ceiling.
_Avoid_: Allowlist, target list, in-scope list

**Exchange**:
One recorded HTTP request and its response (or its refusal), with the call that caused it, stored in `.bee/http/` and named by an id like `E1a2b3c4-42`. Tools return exchange ids and bounded slices, never whole bodies.
_Avoid_: Request log entry, flow, history item

**Lead**:
A passive observation over recorded traffic — a reflected parameter, a weak session cookie — offered for the model to check. Never a finding until the model confirms it and records one citing exchanges; its summary is bee's own words, never the target's.
_Avoid_: Finding, alert, issue

**Proxy scope**:
The kernel scope the interception proxy runs in, separate from the tool scope: it may reach only the resolved target and egress addresses, write nothing, and read a reduced filesystem. Tool children reach only the proxy.
_Avoid_: Proxy sandbox, sidecar container

**Interceptor**:
The session's HTTP(S) interception proxy as a whole — the confined `bee proxy-worker` and the harness side that drives it and owns the exchange store.
_Avoid_: MITM, Burp, proxy server

**Operator**:
The one seam where autonomous and interactive Bee differ: it decides consent requests and receives session output. The **Interactive** operator asks a person through the REPL/TUI input path; the **Autonomous** operator never waits for one, granting within the ceiling and refusing beyond it, and records every decision.
_Avoid_: Mode, frontend, approver

**Session builder**:
The one library module that turns a session specification and an Operator into a running session — policy, grants, sandbox, Interceptor, tool surface, escalation, system prompt — for every entry point. A combination it cannot provide is refused before any scope exists, never silently dropped.
_Avoid_: Session setup, bootstrap, factory

**Tool surface**:
The tools the model can call in a session right now, each constructed with its session dependencies (Interceptor, finding ledger, scanner grants). Derivable from one place; a tool granted mid-session is indistinguishable from one present from the start.
_Avoid_: Tool list, registry contents

**Call lifecycle**:
Everything that happens to one tool call, from the model's request to its recorded outcome: opening the call, running the tool, collecting its audit, escalating and retrying at most once, closing the call. Owned by one module that every loop — and codemode — runs calls through.
_Avoid_: Tool execution, call wrapper

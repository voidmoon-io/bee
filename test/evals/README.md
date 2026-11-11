# Bee research harness evaluations

A standard-library Python runner starts a fresh loopback HTTP fixture for each
run, invokes Bee with a bounded task, and scores the conclusion against requests
recorded by the fixture. No external target is tested and nothing is published.

Cases: cross-user document read allowed (confirmed), correctly denied (refuted),
and application unavailable (blocked). Both baseline and candidate arms receive the
same task, tool surface, response format and budgets. The guided arm adds a
readiness/attack/negative-control procedure. Arm order alternates across repeats.
Each run permits eight model turns, 90 seconds inside Bee, and a 110-second outer
process-group timeout. Infrastructure errors stop the suite rather than spending
on subsequent calls. Outputs must use a fresh directory to prevent stale passes.

## Validated assessment protocol (new runs)

New runs use receipt protocol v1 and diagnostic version 3. Bee POSTs an assessment
while the episode is running; the receipt service returns validation errors so
Bee can repair its submission within the same eight-turn/90-second budget. The
first accepted assessment is final (identical retries are allowed). Final prose
cannot replace it. The service is loopback-only and contains no answer key.

The task supplies a separate receipt URL. GET `/observations` returns the target
requests made during this episode with 1-based IDs. POST `/assessment` requires:

```json
{
  "assessment": "confirmed",
  "rationale": "Explain the observed behavior and reachable source path.",
  "requests": [1, 2, 3],
  "sources": [{"path": "target.py", "start": 1, "end": 10}],
  "limitations": "State what was not established."
}
```

Source references must name supplied files and valid inclusive lines; endpoint
tasks use an empty array. Acceptance checks structure and reference existence,
not correctness. Only cited requests count toward evidence coverage. Successful
submission cannot make an exhausted episode successful. The source explanation's
semantic correctness is still not adjudicated automatically. Use `blocked` when
runtime is unavailable. X-User is simulated trusted identity, not an authentication
bypass surface.

`submissions.json` retains accepted and rejected parsed attempts, observation
counts and receipt decisions separately from target requests. Malformed JSON is
recorded as a null value; tool transcripts retain available request/response text.
Reports fingerprint this artifact and the protocol module, replay validation and
recompute scores from cited evidence. Use `report.py` for these runs; the historical
`replay.py` deliberately refuses receipt runs. Historical frozen evaluators and
results remain unchanged.

## Harder development tasks

```sh
python3 test/evals/run.py --bee target/debug/bee --mock \
  --corpus source-v2 --split development --output /tmp/bee-source-v2-new
python3 test/evals/report.py --source /tmp/bee-source-v2-new \
  --output /tmp/bee-source-v2-report-new
```

`corpus-v2.json` freezes four development tasks in one export-authorization family.
The runnable package comprises `target.py`, `api.py`, and `store.py`. Indirect alias
lookup can expose another owner's export while the direct document route remains
protected. Variants cover the vulnerability, its protected counterpart, unreachable
unsafe code, and unavailable runtime. Controls include successful owner document
access, own export, direct cross-user denial, and anonymous denial. Each required
observation must be cited; an unrelated denial cannot satisfy the export probe.

The independent oracle drives the actual imported package and checks exact
responses. Source files and their combined digest are retained and rechecked by
reporting. AX transfers both corpus versions and the receipt implementation.
Version 2 deliberately refuses `--split holdout`. It is inspected development
material, not a fresh selection benchmark. The previous v1 holdout has also been
inspected and must not support another independent selection claim. A future live
campaign needs a newly frozen holdout and separately authorized budget/trial count.

## Local pipeline check

```sh
cargo build --bin bee --no-default-features
python3 -m unittest discover -s test/evals -p 'test_*.py'
python3 test/evals/run.py --bee target/debug/bee --mock --output /tmp/bee-eval-new
```

Mock providers contain the expected answers deliberately: they test orchestration,
fixture behavior, scoring, and feedback capture, NOT model effectiveness.

## Versioned playbooks and paired reports

Playbooks are JSON objects containing exactly three nonempty strings: `id`,
`version`, and `prompt`. The prompt is the complete experiment system prompt.
Files are limited to 16 KiB. Defaults live in `playbooks/`: the baseline and a
guided candidate for each corpus. Existing guidance is preserved in these files.
New run artifacts use arm names `baseline` and `candidate`; historical artifacts
with `guided` remain unchanged.

```sh
python3 test/evals/run.py --bee target/debug/bee --mock \
  --corpus source --split development --repeats 2 \
  --baseline-playbook test/evals/playbooks/baseline-v1.json \
  --candidate-playbook test/evals/playbooks/source-guided-v1.json \
  --output /tmp/bee-playbook-trials-new
python3 test/evals/report.py --source /tmp/bee-playbook-trials-new \
  --output /tmp/bee-playbook-report-new
```

The AX wrapper accepts the same two playbook paths, validates them locally, and
uploads their exact contents alongside all evaluator modules. The paired report
can run locally on downloaded artifacts. Output must be a fresh directory outside
the source run; raw artifacts are never rewritten. Older runs lack the required
provenance and must use diagnostic replay instead of this comparison report.

Each run freezes the playbooks, review gate, scorer, task corpus, binary, provider
configuration, tools and budgets. Each episode records model identity, artifact
hashes and its normalized task contract (only the loopback origin varies between
arms). Reports require complete pairs for every planned task/repetition, verify
artifact hashes, and recompute scores from transcripts and runtime request logs.
Changed scorer/corpus/report code requires the matching code version to report an
old experiment; mismatches invalidate the comparison. Failed runs retain scores,
request logs and available transcripts. Missing or malformed evidence cannot earn
a recommendation.

Reports contain pair-level wins/ties/losses, exact denominators, excluded outcomes,
unsupported confirmations, misses, format compliance, evidence coverage, tool
counts and elapsed time. Cost remains unknown; usage stays in episode scores.
Repeats are correlated observations, not independent projects. No significance or
general security-effectiveness claim is inferred from these small counts.

The version 1 review gate is conservative and provisional for live use: reject
new unsupported confirmations, new misses or quality losses; ties, execution
exclusions and fewer than two repetitions cannot support an improvement signal.
Development gains require a frozen holdout. A clean repeated holdout signal still
requires human review and regression checks. Mock reports always say
`mock_pipeline_only`, even when scripted candidate scores are better. Format-only
gains never count as quality wins. Reports neither promote candidates nor publish
anything. A live cycle still requires an agreed dollar cap, trial count and final
review gate before execution.

## Source-plus-runtime corpus

```sh
python3 test/evals/run.py --bee target/debug/bee --mock \
  --corpus source --split development --output /tmp/bee-source-dev-new
python3 test/evals/run.py --bee target/debug/bee --mock \
  --corpus source --split holdout --output /tmp/bee-source-holdout-new
```

Version 1 freezes twelve tasks in `corpus-v1.json`: access control and path
containment are development families; command-argument handling is the holdout
family. Each has vulnerable, patched, unreachable false-lead, and unavailable
variants. Source hashes, opaque task IDs and split membership are checked before
execution. Changing generated source requires a new frozen corpus version.
There is no randomized seed: version 1 generates fixed, reproducible targets.

The evaluator executes the supplied target source with real local file reads and,
for argument handling, a subprocess helper. Before episodes start, an independent
oracle checks normal, attack and control responses on separate runtime instances.
Those requests are retained in `verifier.json`; they never enter agent evidence.
During each episode Bee receives only an unlabeled `target.py` in a fresh working
directory, the behavioral contract and the loopback URL. Source is also retained
with the evaluation artifacts. The agent's runtime probes must satisfy readiness,
attack and negative-control checks on available targets. Diagnostic version 2
accepts equivalent/default inputs and genuine alternative negative controls,
without requiring the oracle's exact query strings. One observed unavailable
response supports a blocked assessment. Source citations are requested but their correctness is not
automatically scored; this is still not a complete measure of source-analysis skill.

`--corpus source --split development|holdout` also works with `ax.py`. The wrapper
uploads the runner, corpus module and frozen inventory together. Each repetition
runs 16 development or 8 holdout episodes across both arms. Existing eight-turn
and per-episode time bounds apply. Live execution still requires an agreed dollar
budget; adding more tasks is not permission to increase spend.

Mocks may exercise the holdout plumbing without selecting a playbook. Do not tune
the candidate on live holdout outcomes. This is one small held-out family, not a
representative security benchmark. Evaluator files and answer keys remain outside
the agent working directory and task context, but the existing host execution
boundary does not prevent a disobedient agent from accessing other files/processes.

## Talos / AX

The existing dedicated task must have Python 3, curl, and Bee installed on its
persistent workspace. The bootstrap smoke task has these at the paths below.
The wrapper resumes the task, uploads the evaluator via a bounded command payload,
runs the suite, retrieves artifacts, then suspends the task even on failure.
Do not point it at a task serving other work. A driver timeout leaves remote
artifacts in place for retrieval; suspension stops the sandbox.

```sh
python3 test/evals/ax.py \
  --ax /home/jg/git/shart-cloud-gh/containers/talos-gitops/scripts/agent-substrate/bin/ax \
  --task bee-smoke-20261104-v2 --mock --output .scratch/ax-evals/new-mock

# Vault-backed OpenRouter; incurs model charges.
python3 test/evals/ax.py \
  --ax /home/jg/git/shart-cloud-gh/containers/talos-gitops/scripts/agent-substrate/bin/ax \
  --task bee-smoke-20261104-v2 \
  --vault-openrouter --model google/gemini-3.8-flash --repeats 5 \
  --output .scratch/ax-evals/new-live
```

For local live runs use `run.py --provider /path/provider.toml`; supply the key
through the provider's named environment variable. AX uses BEE_API_KEY with a
placeholder because the cluster proxy injects its real credential. Provider
configuration must point at that proxy and use that variable. No keys are copied
into evaluation artifacts.

## Evidence and interpretation

Historical runs include versioned `diagnostics` alongside legacy strict
fields. For new receipt runs, `passed` requires a completed episode, a valid
submission, the correct assessment, and complete cited runtime evidence. Diagnostics separate execution health, termination, JSON assessment format,
verified probes and investigation outcome. In historical text-protocol runs, a single JSON fence can be decoded for
diagnosis but remains a strict failure. Format compliance here checks a JSON object
with a recognized assessment, not the factual accuracy of every prose field.
Budget exhaustion cannot earn quality success even when Bee exits zero. Provider,
setup, process and missing/unknown-transcript failures are excluded from quality
comparisons; incomplete investigations remain in the denominator. Deliberately
unavailable targets are reported separately. Feedback never supplies a label.

Replay existing artifacts without changing their scores or transcripts:

```sh
python3 test/evals/replay.py \
  --source .scratch/ax-evals/openrouter-live-1 \
  --output /tmp/bee-baseline-diagnostics-new
```

The output must be fresh and outside the source directory. It retains original
scores, fingerprints each input, and reports diagnostic counts with denominators.
Missing transcripts are recorded as absent; malformed artifacts fail replay.
Cost is unknown unless independently accounted for; transcript usage is retained.
Diagnostic success on these endpoint fixtures is not proof of source-code hunting
quality or playbook improvement.

`manifest.json` fingerprints the binary, evaluator and provider configuration.
Each run retains scenario, transcript, console log, fixture request log, and score.
`results.json` records per-arm pass/fail, evidence coverage, unsupported confirmations,
tool calls, tool-output bytes, elapsed time and process exit. `feedback.jsonl`
contains accepted feedback with stable delivery IDs for the retained transcript.
Delivery to Linear is not implemented; these are triage inputs, not verified bugs.

Pass requires both the right assessment and observed fixture probes. Feedback is
reported separately and cannot turn a failed investigation into a pass. Provider
failures are infrastructure errors, not evidence that one arm is worse. Review
paired raw results before drawing conclusions; ties are valid.

Limitations: these synthetic suites exercise bounded source/runtime investigations,
not general project hunting or the quality of every prose claim. Fixtures and scorer share a sandbox; logs are independent of model reports
but are not tamper-proof against an agent that ignores the task boundary. Run
artifacts and expected answers must not be intentionally supplied to a live agent.
This bootstrap uses a transferred development binary, fingerprinted in each run;
a published image and separate evaluator service are follow-up work.

## Vault-backed OpenRouter

`--vault-openrouter` validates authentication through the cluster proxy before
starting any episodes, saves only limit/expiry metadata, and creates a fresh
provider configuration for the run. It never reads, copies, or mints a key.
The path is Vault `openrouter/creds/ax` → `openrouter-ax` VaultDynamicSecret →
`ax-model-secret` ExternalSecret → mounted proxy credential → OpenRouter.
External Secrets refreshes every 12 hours; the proxy reads the mounted key per request.

For explicitly budgeted runs, `ax.py --budget-usd AMOUNT` requires a positive,
non-resetting existing key limit no greater than AMOUNT. It refuses unknown,
exhausted or excessive caps and does not create or modify keys. Pre/post metadata
retain usage and allowance without credentials. Shared usage deltas are account
observations, not exact experiment attribution. `--max-tokens` sets the provider
response cap (default 2048).

Remote suites launch detached and use short status polls instead of a long-lived
SSH output stream. Logs and artifacts remain remote until retrieval. The wrapper
suspends the dedicated task during cleanup.

On 2026-11-04 the old proxy credential returned upstream 401 despite ExternalSecret
Ready status. A force-sync of the existing ExternalSecret restored authentication;
the API reported a $10 limit and $10 remaining before live evals. The underlying
reason the previous credential was invalid has not been established. Do not rotate
on every evaluation or automatically retry authentication failures: inspect refresh
status and deliberately refresh the existing ExternalSecret when needed.

```sh
kubectl annotate externalsecret ax-model-secret -n ax-system \
  force-sync=UNIQUE-REFRESH-ID --overwrite
kubectl get externalsecret ax-model-secret -n ax-system -o yaml
```

Allow the Secret volume to update before probing again. No Secret values need to
be printed. The $10 limit is the shared provider credential's budget, not a
per-episode budget; the suite's turn/time bounds are separate.

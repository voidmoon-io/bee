# Native research tooling

The implementation starts with durable evidence receipts shared by `bee run` and
`bee repl`. This is the first part of spec 020 and the foundation for bringing
offsec-code's investigation workflow into Bee. Full tooling parity is not yet
implemented.

## Enable receipts

Build with `--features findings`, then include `receipt_get` in the session's
tool list alongside the tools you want to use, for example:

```toml
tools = ["read_file", "search", "receipt_get", "record_finding", "list_findings"]
```

The normal session setup enables capture for calls through the shared registry.
Each returned result has a `receipt_id` and a model-visible receipt annotation.
The receipt stores the tool name, arguments, session and call identifiers, and
the original result, including errors, exit status, and truncation metadata.
The annotation itself is not part of that original result.

`receipt_get({"id":"sha256:…"})` retrieves the record. A receipt establishes what
the tool returned; it does not establish source pinning, reachability, security
impact, or successful independent verification. Output remains untrusted data.

`record_finding` accepts optional `evidence_refs`, up to 20 receipt IDs. References
must resolve, pass the SHA-256 integrity check, and belong to the current session.
Invalid citations refuse the finding before the ledger write. Findings without
references remain readable and writable and are displayed as uncorroborated by
a harness receipt. Later sightings accumulate receipt references without changing
the original description or a human verdict. Historical receipts can be read in
a new session; directly citing them as that session's observation is refused.

Receipts live in `.bee/evidence/`, or `<security.findings_dir>/evidence/` when a
custom finding directory is configured. This is harness state, like the finding
ledger. Storage walks directory components without following symlinks and rejects
non-regular or multiply-linked files. Publication uses a writer lock, temporary
file, fsync, atomic rename, and directory fsync. Each record is limited to 2 MiB.
Missing and altered receipts produce explicit errors when retrieved.

Capture is opt-in because arguments and outputs can contain sensitive target
data. There is no automatic retention, redaction, or total storage quota yet;
operators must manage the receipt directory. Host execution does not protect
receipts from arbitrary same-user processes. Hashes detect corruption relative
to a cited ID; they are not signatures or an independent trust boundary.

If persistence fails after execution, the returned result is an error that keeps
the observed output and says the effect may already have happened. It has no
receipt ID. This is not a durable job journal: a crash between effect and receipt
publication still requires reconciliation, not automatic replay.

## Pinned source reads

Build with `--features source` (also included in `sec`) and enable `source_pin`
and `source_read`. Either source tool enables receipt capture during normal
session setup. These tools use the linked Git engine in `bee source-worker`,
launched through the same scoped process path as other native tools.

```text
source_pin({"repository":"/path/to/repository","commit":"<full 40-character commit SHA>"})
source_read({"snapshot":"<source_pin receipt id>","path":"src/example.rs","start_line":1,"end_line":80})
```

The snapshot is a pin to Git's immutable commit/tree objects, not an extracted
checkout. Reads ignore later commits and dirty working-tree files. Every object
on the commit → tree → blob path is checked against its Git object ID. Results
carry the pin, blob ID, file SHA-256, exact range SHA-256, actual line range, total
line count, and source text with original line endings. Cite the read receipt in
`record_finding.evidence_refs`; this grounds the observation in source but does
not prove the finding's interpretation or impact.

Reads are limited to 400 lines and 64 KiB per range, and objects to 8 MiB. Only
UTF-8 regular files are supported. Paths with traversal, symlinks, submodules,
binary files, and invalid ranges fail explicitly. An empty file has zero lines,
so a request starting at line 1 reports a range-past-end error naming that count.
This version supports SHA-1 repositories and requires a full commit ID.

No repository refs are written, objects copied, hooks run, or network fetches
performed. Removing the repository or garbage-collecting its objects prevents
future reads; existing read receipts remain available. A pin receipt can be
reused after restarting Bee, but every new source read still passes through the
current session's execution scope. Kernel enforcement requires the same VM setup
as other native workers; host mode remains explicitly unenforced.

## Investigation checkpoints

With `--features source` (or `sec`), add `hunt_checkpoint` and `hunt_resume` to
the session tool list. Normal setup enables the shared evidence store, in both
`bee run` and `bee repl`. There is no separate investigation service or database.

```json
{
  "snapshot": "<source_pin receipt id>",
  "title": "Alternate route authorization",
  "actor": "Unauthenticated caller controlling the record id",
  "invariant": "Only owners may mutate records",
  "hypothesis": "An alternate route skips the owner guard",
  "countercheck": "Check whether route middleware applies the same guard",
  "observation": "Located the guard and mutation; registration remains unresolved",
  "next_action": "Read the alternate route registration",
  "unknowns": ["Whether middleware is shared"],
  "status": "exploring",
  "evidence": [{"receipt_id": "<source_read receipt id>", "role": "guard"}]
}
```

Pass that object to `hunt_checkpoint`. Its returned `receipt_id` is the checkpoint
handle. Set `parent_id` to that handle on the next checkpoint; multiple children
may share a parent, preserving parallel branches without overwriting anything.
Parents and source anchors must refer to the same repository/commit/tree. A new
source pin starts a new root. No scanner hit is required.

Anchors cite complete, successful `source_read` receipts. Bee derives their path,
line range, and hashes from those receipts, rather than accepting model-supplied
source quotes. Historical receipts can support a checkpoint after a session
restart; their original provenance remains in the evidence store. This does not
change `record_finding`'s restriction on direct foreign-session citations.

Statuses are `exploring`, `source-supported`, `rejected`, and `blocked`.
`source-supported` requires entrypoint, effect, and countercheck anchors;
`rejected` requires a countercheck anchor. Roles and status are analyst judgments:
these checks establish structural completeness, not causality or truth. A single
source range can serve multiple roles. Checkpoints never create a finding,
execution verification, or human verdict. Stored observations remain untrusted
data, including any instructions quoted from the target.

`hunt_resume({"id":"<checkpoint receipt id>","limit":3})` retrieves the newest
history segment, ordered oldest-first within that page. Continue backwards with
`older_checkpoint_id` as the next `id`. Pages allow 1–10 checkpoints and at most
64 KiB; individual checkpoints are limited to 16 KiB, 12 anchors, and 20 unknowns.
Missing or corrupt evidence is listed in `evidence_problems` without erasing the
analyst history. Missing or corrupt parent checkpoints fail the requested page
explicitly. Resume does not re-read the repository or revalidate source claims.

Keep the checkpoint handle from the transcript or tool result to resume after a
restart; checkpoint discovery/listing is not yet implemented. Checkpoint survival
depends on retaining the evidence directory, just like source receipts. Existing
receipt atomic-publication and persistence-failure behavior applies unchanged.

## Controlled reproduction

Build with `--features repro` (includes `source`; also in `sec`) and enable `repro_run`. It uses the
shared registry, process runner, and receipt store. Configure profiles in trusted
user/explicit configuration or an operator-authored scenario; project configuration
cannot supply `[security]`. No profiles are enabled by default.

This runnable fixture demonstrates the protocol, not a vulnerability:

```toml
[security.reproductions.fixture]
program = "/bin/sh"
args = ["-c", "read -r mode; if [ \"$mode\" = positive ]; then printf SIGNAL; fi"]
timeout_secs = 2
max_repetitions = 3
```

```text
repro_run({"profile":"fixture","input":"positive\n","control_input":"negative\n","stdout_contains":"SIGNAL","repetitions":3})
```

The agent selects a configured profile, positive/control stdin, a literal stdout
signal, and repetition count. It cannot change executable, arguments, environment,
or timeout. Profiles require absolute executable paths, 1–60 second attempt
timeouts, and a ceiling of 2–5 repetitions. Inputs are limited to 64 KiB each and
the signal to 1024 bytes. The control is mandatory and must differ from the
positive input. These constraints do not establish that the selected control is
scientifically meaningful; that still needs review.

Each positive and each control starts a fresh process and private temporary
working directory; HOME, TMPDIR, and PWD point there. Normal credential stripping,
execution policy, child cleanup, and cancellation apply. Profiles need permission
for their executable and scratch files when kernel scopes are used. There are no
implicit policy grants. This is fresh process/workspace execution, not an isolated
machine reset: external files, services, and shared state may survive between runs.

The deterministic report distinguishes:

- `reproduced`: all positive attempts exit zero and contain the signal, and every
  control exits zero without it. When requested, all comparison attempts must also
  exit zero without the signal.
- `not-reproduced`: the complete experiment misses at least one positive signal
  or a healthy control or comparison fires it.
- `unable-to-run`: timeout, missing executable, signal termination, output overflow,
  cleanup failure, unavailable source, or unhealthy control/comparison. Remaining attempts stop and the partial
  attempt list is preserved. This is not evidence against the hypothesis.

Both streams are capped at 64 KiB per attempt; overflow refuses a decision based
on partial output. Completed attempts retain byte counts, exact byte SHA-256,
and lossy UTF-8 excerpts of the first 512 bytes per stream. The report includes the
profile, input hashes, signal, execution posture, and per-attempt outcomes. The
outer receipt retains the plan's actual inputs. Cite its ID in a finding to retain
the experimental evidence; it never writes a human verdict.

### Pinned source and comparison

Optionally pass a `source_pin` receipt as `snapshot`. Bee materializes that commit
in a fresh workspace before **every** attempt and runs the configured command there.
For a script in the source tree, configure an absolute interpreter such as `/bin/sh`
with fixed arguments such as `["target.sh"]`. The command must consume the staged
source for the experiment to measure that revision.

Add `comparison_snapshot` to repeat the same command, positive input, signal, and
negative control against a different commit of the same repository:

```text
repro_run({"profile":"source-fixture","input":"positive\n","control_input":"negative\n","stdout_contains":"SIGNAL","repetitions":3,"snapshot":"<target source_pin receipt>","comparison_snapshot":"<fixed source_pin receipt>"})
```

Bee executes all target positives, then target controls, then comparison positives
and comparison controls. `behavior_reproduced` describes the target experiment
independently of the comparison. `comparison` is `passed`, `signal-fired`, or
`not-completed` (null when not requested). A broken comparison leaves established
target behavior intact but makes the overall decision `unable-to-run`.

The linked Git engine runs inside Bee's scoped source worker. It verifies object
hashes and the commit/tree relationship, ignores the working tree and current HEAD,
and extracts raw objects without hooks, filters, or Git metadata. Extraction refuses
symlinks, submodules, unsafe paths, existing destinations, and symlinked destination
components. Limits are 4096 entries, 64 levels, 64 MiB of tree/blob bytes, and the
source reader's 8 MiB per-object limit. Each materialization and each probe separately
uses the profile timeout. Policy must permit the worker, repository reads, and scratch
writes; no grants are added automatically. A materialization failure skips the probe.

Schema 2 reports retain both pins and each attempt's materialization manifest digest,
file count, and object byte count. `source_binding: materialized-pin` records the
verified bytes staged before execution. The workspace is writable: this does not
prove the command consumed those bytes or left them unchanged. `incomplete` means a
requested materialization failed; omitted snapshots retain `unbound`. Workspaces are
removed after each attempt; receipts do not retain a source archive. Old schema 1
reports remain readable without acquiring source provenance.

Every report retains `impact_supported: unknown`.
Host runs say `execution_posture: host`; scoped runs say `bee-scope`, which does not
by itself distinguish enforcement from observe mode. The executable is identified
by the configured path/arguments, not a captured binary digest. Use the existing
policy's executable pins when needed. Reproduced behavior is not promoted
to a verified security finding. Interrupted experiments are not automatically resumed
or replayed; durable operation reconciliation remains future work.

## Verification

Run `bash test/evidence-receipts.sh`. The fixture covers real tool execution,
receipt recovery, finding citations, human verdict preservation, invented and
foreign-session references, corruption, missing evidence, symlinks, hardlinks,
persistence failures, and old result deserialization. Kernel enforcement is a
separate VM gate.

Run `bash test/pinned-source.sh` for pin → read → finding integration, working-tree
and HEAD independence, exact range hashes, invalid paths/ranges, and missing objects.

Run `bash test/hunt-checkpoints.sh` for restart, branching, pagination, source-pin
consistency, evidence gaps, status gates, and the scoped source → checkpoint →
resume integration. Tests use local fixtures without model calls or network access.

Run `bash test/controlled-reproduction.sh` for positive/control decisions, fresh
workspaces, exact target/fixed commits despite dirty working trees, extraction refusal,
comparison failure classification, invalid plans, cancellation cleanup, and durable
reproduction receipt → finding integration. Kernel enforcement remains a separate VM gate.

## Remaining parity work

1. Independently retained source archives, source listing/search on pins, and
   individually citable search matches; complete the structured outcomes and
   paging in spec 020. Commit-pinned reads and range hashes are implemented.
2. Checkpoint discovery/listing and investigation-level indexes. Immutable
   checkpoints, grounded source anchors, branching, and bounded resume are implemented.
3. Additional execution backends and stronger source-consumption guarantees.
   Typed profiles, repeated fresh process/workspace attempts, pinned materialization,
   fixed-pin comparison, negative controls, and behavior/impact separation are implemented.
4. Durable operation intent/results, reconciliation, and persistent budgets.
   See the [durable sessions implementation plan](durable-sessions-plan.md) when
   implementing crash recovery, session persistence, or replay policy.
   The decision core, simulator, and opt-in local SQLite store are implemented;
   receipt integration, persistent budgets, and live-session integration remain planned.
5. The investigation supervisor and skill composition from specs 018/022,
   followed by HTTP and task intake from 019/021.
6. Corpus evaluation against offsec-code's fixtures and evidence semantics.

These additions should share the registry, evidence store, existing finding
ledger, and session machinery. External scanners and execution environments
remain typed adapters controlled by the harness.

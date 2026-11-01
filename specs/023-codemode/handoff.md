# Codemode handoff

## Next task

`write_file` validation is implemented and the trusted catalog now includes it.
See `implementation.md` and `enforcement-verification.md` for the mutation tests.
The next remaining work is grouped inner-call presentation and checkpoint retention/
garbage collection. Keep `bash`, terminal tools, rendering, nesting and parallel
calls excluded.

Start by reading `AGENTS.md`, `CONTEXT.md`, `spec.md`, `implementation.md` and `enforcement-verification.md`. The workspace is `/home/jg/git/bee` and contains unrelated scratch notes and vulnerability reports. Preserve them. The implementation checkpoint and deadline fix were committed as `fd2fd91` and `7905409`; no PR was created.

## Current implementation

- Monty 1.4.0 replaced Rhai for visual scripting; the application toolchain is Rust 1.96.0. Drawing examples and instructions use Python. See `docs/python-visuals.md`.
- Durable batch and REPL advertise `codemode` automatically. Ordinary non-durable registries do not. The production allowlist is exactly `read_file`, `list_directory`, `search`, `write_file`.
- `src/session/driver/codemode.rs` owns the persisted script cursor, catalog compatibility, interpreter charges and outer operation. Its children use the ordinary driver execution path, including consent, per-attempt reservations, receipts and recovery.
- `src/session/durable/composition.rs` binds each saved continuation to one durable child identity. `store/checkpoints.rs` stores bounded opaque snapshots before admission. A saved interpreter is not evidence that an external effect completed.
- Only committed, published and validated child results resume Python. Unknown effects block continuation and remain charged. Source/runtime/tool-contract/configuration changes fail closed.
- `RecordedCall.parent_call_id` associates child results with the outer invocation. Only the outer tool result enters the model conversation. Prior child receipts remain visible after a Python error or cancellation.
- Snapshot/database version is 6; driver journal version is 3. Known previous versions have explicit migration paths; see implementation notes.
- Limits: source 32 KiB, object inputs 8 KiB, durable result 64 KiB; 32 child calls, 64 interpreter invocations including recovery; checkpoint 4 MiB each/64 MiB total; absolute parent deadline inherited from tool/session limits. Interpreter charges persist before launch. Print output is discarded.
- `src/python.rs` uses a disposable hidden `bee python-worker --parent <pid>` process. `src/tools/exec.rs::run_worker` installs the Linux parent-death guard before exec; worker entry checks the parent again. Ordinary tool executors retain their existing recovery behavior.
- The VM pass found and fixed missing worker audit association. Worker audits now persist in the cursor, outer completion and transcript, including cancellation reporting.

## Completed mutation validation sequence (historical plan)

1. Inspect the shipping `WriteFile` tool in `src/tools/files.rs`, its default durable contract in `src/tools.rs`, and admission/execution/publication in `src/tools/durable.rs` and the driver. It currently writes through scoped `tee` and inherits `NeverReplay`; do not weaken that contract merely to make recovery succeed.
2. Add real mutation fixtures around admission/authorization, a completed write with no committed result, committed completion with lost acknowledgement, and receipt publication. Test a multi-call Python program where the first write completes and the second call follows only after its committed result.
3. Prove ambiguous writes do not replay automatically, do not advance Python and do not refund charges. Prove a committed write is not repeated after reopen: use an observable counter or change the file between crash and recovery so a repeated identical write cannot hide the bug.
4. Verify authorization and kernel policy for the inner write. Extend the dedicated VM gate with allowed scratch writes, denied paths, cancellation and mutation recovery cases. Require matching audits and receipts; an error alone does not prove enforcement.
5. Once that behavior passes, add `write_file` to the trusted codemode catalog, update its tests/spec/docs, and rerun host and VM gates. If safe reconciliation needs a larger design, keep mutations excluded and document the concrete blocker instead of claiming exactly-once writes.

Do not add a second tool execution path or move admission into the interpreter. Reuse the existing child lifecycle. No new permission question is needed for ordinary reversible implementation/testing work already authorized by the conversation.

## Verification already completed

All nine dedicated codemode cases passed in the real KubeVirt VM with BPF LSM active on kernel `6.8.0-147-generic`:

- File allow/deny, executable denial for the worker and separately for an inner tool.
- Worker timeout and memory cleanup; cancellation preserves a sibling scope.
- Actual driver SIGKILL after a committed child; reopening preserves the old observation and executes only the next read.
- Parent death kills a stopped Python worker; lost invocation charges survive.
- An unfinished native child is stopped before reconciliation, remains unresolved and charged, and never advances Python.

See `enforcement-verification.md` for exact cases, binary SHA-256 hashes and limitations. This was the dedicated nine-case gate, not a rerun of the separate 38-case general matrix. Engine-owned BPF links have the driver's lifetime: do not claim continuous enforcement of arbitrary native descendants while the owner is dead.

Host checks passed: 247 library tests, nine durable-codemode tests, six Python-worker tests, 16 durable-driver tests, one render-exchange test, and four VM parser/manifest tests. Two existing host tests remained ignored. Formatting, Clippy and shell syntax checks passed.

## Commands and environment

```bash
cargo test --offline --no-default-features --features durable-sessions \
  --lib --test durable_codemode --test durable_driver --test python_worker --test render_exchange
cargo clippy --offline --features durable-sessions,enforce \
  --lib --bin bee --test codemode_kernel -- -D warnings
cargo fmt --all -- --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/vm -p 'test_*.py'
bash -n test/vm/codemode.sh test/vm/remote-codemode.sh
```

VM: `ac-matrix/ac-matrix-vm`; SSH key `~/.ssh/ac-matrix-vm`; tools `virtctl`, `kubectl`, nightly Rust and `bpf-linker` are installed. The VM was originally stopped, started for testing, then confirmed **Stopped** afterward. Guest staging directories and codemode cgroups were absent before shutdown. Start it for the next authorized VM run and restore its initial lifecycle state afterward:

```bash
virtctl start ac-matrix-vm -n ac-matrix
# Wait for readiness and SSH reachability.
bash test/vm/codemode.sh
virtctl stop ac-matrix-vm -n ac-matrix
kubectl wait --for=delete vmi/ac-matrix-vm -n ac-matrix --timeout=45s
```

`codemode.sh` builds and ships the actual worker and test executable, uses a unique guest staging directory, checks every required test runs exactly once, validates guest status/results against `codemode-cases.txt`, and removes guest artifacts. It deliberately leaves VM lifecycle to its caller. Extend the manifest and its parser test when adding cases. The guest harness must live under `deps/` with the shipping Bee binary one directory above; this matches the worker executable lookup used in Cargo tests.

Recent raw logs are under `/tmp/bee-codemode-vm-final.log`, `/tmp/bee-codemode-vm-host.log`, `/tmp/bee-codemode-vm-regression.log` and `/tmp/bee-codemode-vm-clippy.log`. The persistent verification document is authoritative if temporary logs disappear.

After mutation support, later work is grouped inner-call presentation and checkpoint retention/garbage collection. Neither has been started in this handoff.

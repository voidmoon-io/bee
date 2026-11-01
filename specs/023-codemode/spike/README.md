# Monty continuation worker spike

An isolated executable and integration tests for the first milestone of [the codemode spec](../spec.md). This is a controlled fixture, not an exposed Bee tool or a production checkpoint store.

Requires Rust 1.96 or newer. Monty, monty-types and monty-alloc are pinned to 1.4.0; Cargo.lock pins the complete graph. Bee's application and CI now target Rust 1.96; embeddable crates retain their 1.85 floor. The spike's Monty dependencies remain isolated from Bee's production dependency graph.

Run from the repository root:

```sh
cargo test --locked --manifest-path specs/023-codemode/spike/Cargo.toml
cargo clippy --locked --manifest-path specs/023-codemode/spike/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path specs/023-codemode/spike/Cargo.toml --check
```

The fixture keeps `prefix = 7`, suspends at `host(3)`, and exits after saving a checkpoint. A fresh process restores it, accepts `21`, and suspends at `host(28)`. Another fresh process accepts `14` and produces `42`. This verifies local-variable preservation across two process exits. Injecting the final result twice demonstrates repeatable local continuation; the fixture performs no actual host effect and does not prove durable effect recovery.

`MontyRun` / `RunProgress` support Serde rather than Monty's versioned REPL dump API. This spike uses Postcard plus an exact-build format header. Only restore this fixture's own files from an operator-owned directory. The header is a compatibility check, not authentication. Production should evaluate the supported REPL dump format before selecting a checkpoint compatibility policy.

Workers install `monty_alloc::LimitedAllocator`, arm its hard ceiling with Monty's recommended headroom, and use a 16 MiB interpreter budget. Tests distinguish an interpreter `MemoryError` from hard allocator termination. Interpreter execution timeout is tested separately from the parent's watchdog, which kills and reaps an infinite-loop worker with its internal timeout deliberately disabled. The watchdog is in the test supervisor; running the `watchdog` fixture directly will loop indefinitely.

The fixture accepts only its embedded program and integer results. Other suspension kinds are rejected, printing is disabled, checkpoint reads and writes are bounded at 4 MiB, and new checkpoint files use mode 0600 on Unix. Output pipes are safe here only because fixture diagnostics are bounded. The fixture worker has no arbitrary source entrypoint, aggregate restore budget, IPC broker or kernel isolation. A separate integration test now uses Bee's durable core and protected SQLite checkpoint store; automatic session scheduling and real registry execution are still pending. File sync is not a transactional checkpoint publication protocol, and directory durability is not implemented.

Upstream references: [Rust guide](https://pydantic.dev/docs/monty/quickstart/rust/), [1.4.0 crate source](https://docs.rs/crate/monty/1.4.0/source/), [resource limits](https://pydantic.dev/docs/monty/limitations/resource_limits/).

## Observed results

On 2026-10-31, Linux with rustc 1.96.0: all five integration tests passed. The continuation test restored twice in fresh processes and returned 42 with locals intact. Interpreter memory and time errors, hard allocator exit code 65, and parent kill/reap all behaved as expected. Incompatible and oversized checkpoint inputs were rejected before restore. These are functional results, not performance benchmarks or proof of production sandboxing.

## Durable store integration

The sixth test depends on Bee's `durable-store` feature. It persists a real Monty continuation and binds it to a child operation, performs a controlled file mutation, commits its result, then drops the unacknowledged core state and reopens the database. It restores the checkpoint into a fresh worker and supplies the committed result without redispatching the child. This tests the effect/result boundary; the fixture's second host call still uses a supplied value rather than the production tool registry. See [implementation notes](../implementation.md).

# Audit evidence

The Rust probes assert observed defects so their passing result means the reported behavior was
reproduced. They are evidence, not proposed regression tests. Invert or replace their assertions when
implementing fixes.

From the repository root, copy the probes to Cargo's integration-test locations. Do this only if the
destination filenames are absent:

```bash
cp .scratch/tigerstyle-audit/application-probes.rs tests/_tigerstyle_audit_probe.rs
mkdir -p crates/userspace/tests
cp .scratch/tigerstyle-audit/policy-probe.rs crates/userspace/tests/_tigerstyle_audit_probe.rs
env -u NO_COLOR cargo test --workspace --features findings --locked --offline --test _tigerstyle_audit_probe -- --nocapture
```

Afterward remove the two copied `_tigerstyle_audit_probe.rs` files. The saved evidence files stay in
this directory; the audit itself left no added tests in the normal suites.

The subprocess probe uses temporary files and bounded sleeps. It takes about 3.4 seconds, allowing
its surviving descendant to finish before returning. The ledger probe writes only inside a private
temporary directory. The policy probe uses in-memory maps and the host reference matcher. The chat
probe expects a debug-build overflow panic and uses a memory-backed terminal.

The VM parser probe needs no kernel or VM access:

```bash
python3 .scratch/tigerstyle-audit/matrix-probe.py
```

Saved logs:

- `probes.log`: eight reproduced Rust probe observations.
- `default-tests.log`: workspace test run with `NO_COLOR` unset, including seven probes available
  without the `findings` feature.
- `optional-tests.log`: application tests with `mcp,sec,astgrep-rust`, including seven application
  probes. Four external MCP tests are ignored.
- `feature-check.log`: `concurrent,mcp,sec,astgrep-rust` test compile-check; two missing-field errors.

The original default run with `NO_COLOR=1` stopped after five animation-test failures. Its output was
observed in the tool transcript; the saved default log is the successful rerun with color enabled.

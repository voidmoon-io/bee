# Integration with current main

Merged `50e0ee19a969e47644d6bb7a7fe2352774f3d088` into `fix/tigerstyle-hardening` on 2026-10-23.
All conflicts are resolved. Final verification and evidence capture are in progress.

The integration retains the shared `Session`, `run_call`, `turn_start` and operator protocols from
main, including proxy credentials, retry evidence, hook composition, MCP attribution, and the
context/stuck/finish behavior. Hardening uses those shared boundaries. HTTP policy cancellation
poisons further dispatch until the session shuts down. Empty initial HTTP scopes in test fixtures
were replaced with valid subsets, and the expired-deadline regression now requires zero dispatch.

The 50-case live VM matrix passed during integration. The final source is being rebuilt for the
five dedicated kernel regressions and the final matrix run. Host suites and transcript compatibility
checks are also being finalized. Original baseline logs remain in `evidence/` with their original names.

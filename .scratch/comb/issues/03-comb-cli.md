# `comb` binary: serve, query, get, replay, fuzz, rules

Status: done

`crates/comb-cli`. `comb serve --scope scope.toml --store DIR [--listen 127.0.0.1:PORT]` starts
the proxy (spawning `comb worker` as a child, like bee does) and a JSON-lines control API on
stdio. Scope file → `HttpScope` with `Proxy`-only `enforced_by`; startup prints the enforcement
labels. Subcommands `query`, `get`, `replay`, `fuzz`, `rule add|list|rm`, `har` call the same
`ops` the bee tools call. Document the API in `crates/comb/README.md` for offsec-code.

Done when: an integration test drives `comb serve` against a local target end to end.

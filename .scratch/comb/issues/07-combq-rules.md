# combq `when` on intercept rules

Status: ready-for-agent

Rules gain `when: "<combq>"`, evaluated in memory on the request; ANDed with `Matcher` if both.
`resp.*` / store-only fields (`turn`, `tag`, …) in a request rule are compile errors.

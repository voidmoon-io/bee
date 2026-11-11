# combq `when` on intercept rules

Status: done

Rules gain `when: "<combq>"`, evaluated in memory on the request; ANDed with `Matcher` if both.
`resp.*` / store-only fields (`turn`, `tag`, …) in a request rule are compile errors.

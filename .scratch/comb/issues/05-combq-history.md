# combq in `http_history` (and `comb query`)

Status: ready-for-agent

Split the AST: indexed conjuncts → parameterised SQL; the rest → a Rust predicate over
candidates, decoding stored bodies, under a scan cap. Result gains `scanned` and
`scan_truncated`. `http_history` gains `q`, ANDed with the existing JSON fields (both kept).
Tests: each field, precedence, `not`, header/body search over gzip bodies, cap truncation reported.

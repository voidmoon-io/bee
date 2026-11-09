# combq: lexer, parser, AST

Status: ready-for-agent

Pure module `comb::combq`. Grammar and fields per PRD. Spanned errors naming what was expected;
limits on length, depth and regex size. Field typing checked at parse time (`resp.code cont "x"`
is an error; `ext` values need a leading `.`; time values accept RFC 3339 or `-10m`).
Unit tests only; no store.

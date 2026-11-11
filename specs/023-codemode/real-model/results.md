# Real-model validation — 2026-11-01

Model: `claude-opus-4-8`, Anthropic, 4,096 max output tokens per request.
Host-mode `bee run`, durable sessions, synthetic fixture files, `read_file` and
`feedback` enabled. Each scenario was capped at five model turns, 48 tool attempts,
and 120 seconds. This evaluates model behavior; kernel enforcement is covered
separately by the 21-case VM gate.

- **Multi-file:** completed; sequential codemode reads identified Ada and Bo and
  computed 8 open bugs. Successful feedback recorded.
- **Fan-out:** completed; selected `call_tools` for three independent reads,
  returned input-order data and total 10. Successful feedback recorded.
- **Nesting, initial:** timed out. Imported `re` state failed at suspension with
  `This is a feature that PostCard will never implement`; the model also guessed
  `output` instead of `content`. Minimal nested arithmetic did work. No feedback
  was submitted before timeout. Raw transcript retained under `results-2026-11-01`.
- **Nesting, after schema clarification:** completed. Inner script returned 8;
  outer script parsed the JSON-wrapped result and returned grand total 10. It used
  two outer invocations, first inspecting the wrapper, then computing the total.
  Successful feedback recorded under `nested-retry-2026-11-01`.
- **Limit:** completed the requested probe. Exactly 32 child reads were committed
  under one codemode invocation; the 33rd was refused. All 32 receipts remain in
  the transcript. The model subsequently made one direct read, without retrying
  the limit probe. Successful feedback recorded. This probe exercises the call
  limit; it does not independently exhaust the 64-interpreter-invocation limit.

## Description changes and remaining issues

The codemode schema now names `content`, `is_error`, and optional result fields,
explicitly rules out an `output` field, notes receipt banners, explains nested
JSON result wrapping, and advises import-free scripts with string parsing because
imported module state cannot currently be checkpointed across calls. No interpreter
or checkpoint implementation was changed. The serializer failure is issue 08.

The feedback tool is part of the default tool set and trusted codemode catalog.
Explicit scenario tool lists must opt in. Feedback is persisted through ordinary
call records, with bounded category/message validation and no separate append
side effect. Its acknowledgement is retry-safe; the durable driver owns the record.
The regression verifies successful feedback survives reopen with unchanged call
records and receipt identity.

`feedback.json` extracts the four accepted submissions, with transcript paths,
call IDs and receipt IDs. Agent statements are observations to review: multi-file
feedback incorrectly claimed batching/nesting, and limit feedback conflated losing
the Python accumulated return value with losing committed results. Nested feedback
correctly identified the cumbersome JSON wrapper. Limit feedback also identified
the vague combined unavailable-tool/limit error.

## Verification

- Headless durable library suite: 339 passed, 1 ignored.
- Durable codemode integration suite: 26 passed, including feedback/reopen.
- Clippy for the library and durable codemode test: passed with `-D warnings`.
- Formatting and diff whitespace checks passed.
- Catalog test passed again after the description change.
- Five paid runs total: four initial scenarios and one nesting rerun. Three initial
  scenarios completed; initial nesting timed out; the nesting rerun completed.

The run artifacts were produced from the current working tree, which also contains
uncommitted changes from other work. No commits or remote changes were made.

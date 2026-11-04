# Validate codemode with a real model

Status: done

## Problem

All codemode coverage uses `MockModel`. Nobody has checked whether real models read the
tool description correctly: when they use `call_tools` versus sequential calls, whether
they nest sensibly, and whether they stay within the 32-call and 64-invocation limits.

## Approach

Run a small scenario set through `bee run` with durable sessions on one or two
providers. Include a multi-file read/summarize, a batch-friendly fan-out, a task that
benefits from a nested script, and one that should hit a limit. Record the transcripts
under `specs/023-codemode/` and adjust the description in `codemode::schemas` if models
misuse it.

## Acceptance

A short results note listing the model, scenario, outcome, and any description changes.

## Results (2026-11-01)

Validated `claude-opus-4-8` through `bee run --host` with durable sessions.
Multi-file reading, `call_tools` fan-out and the 32-call limit probe passed.
Initial nesting timed out after imported-state serialization errors and guessing
`output` instead of `content`. Clarified the tool description; nesting rerun passed.
Four successful feedback calls are retained with receipts. See
`specs/023-codemode/real-model/results.md`, raw transcripts and `feedback.json`.
Imported-state checkpoint support remains tracked separately in issue 08.

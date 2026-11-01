# Validate codemode with a real model

Status: ready-for-human (needs provider keys and spend)

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

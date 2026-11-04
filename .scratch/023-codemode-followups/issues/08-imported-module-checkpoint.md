# Imported module state fails at codemode suspension

Status: needs-triage

Found by real-model validation (issue 05), 2026-11-01, claude-opus-4-8.
The initial nested scenario imported `re`, defined a parsing function using it,
and called `read_file`. The read completed, but checkpoint serialization returned:
`codemode: This is a feature that PostCard will never implement`.
The model reproduced it in a non-nested script with the same import/function.
Minimal nested arithmetic succeeded in the same session.

Evidence: `specs/023-codemode/real-model/results-2026-11-01/nested.json`.
The schema now advises import-free scripts and string operations for parsing.

Next: isolate module/function serialization with a minimal deterministic regression;
then either reject unsupported state before effects or support its serialization.
Preserve receipts from reads completed before checkpoint failure. Replace the
internal serializer error with an actionable user-facing diagnostic.

# Indent nested calls by depth in the TUI

Status: ready-for-agent

## Problem

Grouped call rows (`SessionEvent::ToolPresentation`, `src/tui/app.rs`) are placed under
their parent correctly, but `CallEvent::text()` (`src/repl/presentation.rs`) indents
every child by one fixed level. Calls three levels deep look the same as calls one level
deep.

## Approach

Add an explicit `depth` to `CallContext` (set by the driver from the cursor stack in
`codemode.rs`/`execution.rs`, and from the `parent_call_id` chain on replay). Indent by
`depth`. Do not parse depth out of call ids such as `outer/1/2`; those are not a contract.

## Acceptance

A TUI unit test with three nesting levels shows strictly increasing indentation, and
replay produces the same rows as live. Terminal output matches.

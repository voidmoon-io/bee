# Specification Quality Checklist: ACP — bee as an Agent, and Foreign Harnesses as Scoped Subagents

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-11-09
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- bee's audience is operators of a kernel sandbox, so the spec uses its domain terms (scope, policy,
  ceiling, kernel denial) as earlier specs do. ACP is the feature's subject, not an implementation
  choice. Crate versions, module names and mechanisms (how hostnames are matched) are left to the plan.
- Question 1 (FR-024 / US5 AS-3) resolved 2026-11-09: provider traffic is passed through, with
  metadata only, never decrypted or stored. Recorded under Clarifications in the spec.
- Facts checked on 2026-11-09: t3code main supports a "Local ACP command" provider and negotiates ACP
  v1 (`docs/user/providers-acp.md`); the `agent-client-protocol` crate is at 5.1.0, with v1 stable and
  v2 behind `unstable_protocol_v2`.

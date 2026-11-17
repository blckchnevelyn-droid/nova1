# P1.3 — Durable Authority Boundary

## Purpose

Establish the minimum authoritative persistence contract required by ADR-001 before certification. This slice is security-critical infrastructure only; it does not add capability or autonomy.

## Required properties

1. **Authoritative persistence** — lifecycle authority must survive process restart and must not depend on mutable in-memory task objects.
2. **Fail-closed reads** — inability to read or validate authoritative state must not permit a consequential transition.
3. **Fail-closed writes** — inability to commit the complete authoritative transition must not report success.
4. **Atomic revision transition** — an expected revision must be checked as part of the authoritative commit; stale writers must receive a conflict rather than overwrite newer state.
5. **Immutable audit evidence** — lifecycle evidence must be append-only at the authoritative boundary and must not be replaceable through returned mutable objects.
6. **Recovery preserves authority** — recovery cannot obtain broader objective, principal, scope, or policy authority than the persisted authorization permits.
7. **Restart integrity** — reconstructing state from persistence must not manufacture approval or authority from timestamps or other incomplete fields.

## Verification sequence

Inspect → establish contracts → implement the smallest durable authority slice → test → failure-inject → fix → re-test → hosted exact-head CI → independent acceptance.

## Explicit non-goals

- Browser control
- Unrestricted tool autonomy
- PCSCM implementation
- AIRS implementation
- Self-modification
- Distributed execution
- Production-readiness claim

Certification remains blocked until the implementation and adversarial evidence satisfy ADR-001 and the exact certified revision passes hosted CI.
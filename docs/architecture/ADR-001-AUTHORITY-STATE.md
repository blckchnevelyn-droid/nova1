# ADR-001 — Authoritative Task State, Approval Provenance, and Persistence Contract

## Status

ACCEPTED — contract only. Runtime persistence implementation must conform to this ADR.

## Decision

Nova separates **authority**, **approval provenance**, and **task state**. No runtime component may infer authorization from mutable task state, timestamps alone, or successful execution.

The authoritative state model is storage-agnostic. A concrete database or persistence technology must not be selected by implementation convenience alone; it must satisfy the invariants below.

## 1. Authoritative Task Identity

Every task has a stable `task_id` that is immutable for the task lifetime.

A task record must represent, at minimum:

- task_id
- objective
- current lifecycle state
- authority context
- governance decision
- approval reference(s), when required
- policy/version reference
- creation time
- last state transition time
- version/revision for concurrency control

`task_id` is an identifier, not an authorization credential.

## 2. Approval Provenance

A required human approval is valid only when its provenance can be independently associated with the task and authorized scope.

An approval record must contain, at minimum:

- approval_id
- task_id
- approving principal identity
- approval decision
- authorized scope/objective binding
- applicable governance policy/version
- approval issuance timestamp
- expiration timestamp when applicable
- immutable provenance/reference to the approval event

An approval timestamp is evidence of when an approval event was recorded; **it is never itself proof of authority**.

Nova must reject an approval when its identity, task binding, scope, policy/version, validity period, or provenance cannot be established.

## 3. State Authority

Only the authoritative state boundary may commit lifecycle transitions.

Observers, planners, executors, verifiers, recovery logic, and external integrations may propose or report state changes but must not independently declare authoritative completion.

A task may enter `COMPLETED` only after the verification contract succeeds and the authoritative state boundary accepts the transition.

## 4. Concurrency and Stale Writes

Authoritative state updates must use optimistic concurrency (or a stronger mechanism) so that a stale writer cannot overwrite a newer state transition.

Every mutable task record therefore has a monotonically increasing revision/version.

A state transition must atomically assert the expected revision and produce the next revision. A failed revision assertion is a conflict, not permission to retry the same mutation blindly.

## 5. Lifecycle Integrity

The authoritative boundary must reject:

- transitions from an unknown task
- transitions using stale revisions
- transitions lacking required governance authority
- completion without successful verification
- approval records that are expired, unbound, or otherwise unverifiable
- attempts to move backward or sideways in the lifecycle unless an explicitly governed transition permits it

## 6. Audit Integrity

Significant authority and lifecycle decisions must produce append-only audit evidence containing enough context to reconstruct:

1. what was requested;
2. who/what held authority;
3. which policy/version applied;
4. what approval was relied upon;
5. what state transition was attempted;
6. what revision was observed;
7. what result was committed.

Audit evidence must not be rewritten to convert a failure, uncertainty, or denial into success.

## 7. Time Semantics

All persisted timestamps use an unambiguous UTC representation.

Timestamp ordering may support validation, but timestamps do not establish causality, authority, or uniqueness by themselves.

Approval validity must be evaluated against explicit validity rules rather than assuming that a later timestamp makes an otherwise invalid approval authoritative.

## 8. Fail-Closed Behavior

If authoritative state cannot be read, written, or validated, Nova must not claim a successful consequential transition.

The runtime must produce an explicit controlled outcome such as `ESCALATE` or `STOPPED`, preserving the unresolved condition for audit/reconciliation.

## 9. Implementation Boundary

This ADR intentionally does **not** mandate SQLite, PostgreSQL, a particular ORM, or an in-memory implementation.

Before runtime persistence is introduced, the implementation must expose a narrow authority boundary equivalent to:

- create task
- read authoritative task
- record approval provenance
- authorize transition
- commit transition with expected revision
- append audit event

The boundary must be the single authority for consequential lifecycle state.

## 10. Required Security Invariants

1. Capability does not imply authority.
2. Timestamp does not imply authority.
3. Mutable task state does not create approval authority.
4. Approval must be bound to task, principal, scope, policy/version, and validity.
5. Stale writers cannot overwrite newer authoritative state.
6. Execution cannot directly produce authoritative `COMPLETED`.
7. Verification is required before completion.
8. Persistence failure cannot be represented as successful commitment.
9. Recovery cannot expand authority.
10. Audit evidence cannot be rewritten to manufacture success.

## Consequence

This contract resolves the architectural ambiguity that previously made a concrete SQLite implementation premature. Runtime work may now proceed only against this boundary; storage selection remains an implementation decision constrained by these invariants.

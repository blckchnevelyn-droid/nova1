# Nova — Execution Governance Foundation

## 1. Purpose

Nova is a durable execution-governance framework for agentic systems. It provides a concrete authority boundary for actions that must be authorized, persisted, verified, and recoverable under failure conditions.

The project is designed to make execution behavior explicit and auditable. Nova does not treat tool calls as simple operations; it treats them as governed actions that must be bound to an identity, policy, task, and durable evidence trail.

## 2. Core Principles

Nova prioritizes:

- Explicit authority
- Durable state
- Idempotent execution
- Evidence-backed outcomes
- Recovery without integrity loss
- Verification before completion
- Fail-closed governance decisions
- Auditable transitions and outcomes

## 3. System Lifecycle

Nova operates through explicit states:

- CREATED
- EXECUTING
- OBSERVING
- VERIFYING
- RECOVERY
- COMPLETED
- ESCALATE
- DENIED
- STOPPED

The lifecycle is meant to represent the actual execution contract of a task, not only a generic workflow label.

## 4. State Transition Rules

Nova must not treat an action as successful merely because it was attempted.

A task may transition to COMPLETED only after the required verification and evidence checks succeed. Failed or ambiguous execution must enter a recovery, escalation, or denial path. Safety violations, invalid authorization, or policy mismatches must result in DENIED or STOPPED.

Uncertainty that cannot be safely resolved must result in ESCALATE.

## 5. Architectural Layers

Nova is organized around four primary layers:

### Authority
Defines task identity, state transitions, approvals, revision tracking, and append-only audit evidence.

### Governance
Defines permissions, policy constraints, approval requirements, and authorization binding.

### Execution
Identifies operations, claims attempts, records durable outcomes, and preserves execution boundaries.

### Verification
Independently evaluates whether an action and its output satisfy the expected result and integrity conditions.

## 6. Fundamental Rule

Nova prefers:

PLAN → GOVERN → EXECUTE → OBSERVE → VERIFY → COMPLETE

When verification fails:

PLAN → GOVERN → EXECUTE → OBSERVE → VERIFY → RECOVERY

When authority, policy, or execution safety is insufficient:

ESCALATE / DENIED / STOPPED

## 7. Non-Negotiable Requirement

No action may bypass governance or verification.

Every significant action must have:

1. An identified objective.
2. A durable authorization decision.
3. A constrained execution boundary.
4. A recorded outcome or evidence payload.
5. A verification result.
6. A recoverable or escalated failure path.

## 8. Product Interpretation

Nova is best understood as a durable execution authority and governance framework for agentic systems. Its value is not abstract autonomy; it is reliable, auditable, and recoverable action under explicit policy and evidence constraints.

This is the foundation the rest of the repository implements and tests.

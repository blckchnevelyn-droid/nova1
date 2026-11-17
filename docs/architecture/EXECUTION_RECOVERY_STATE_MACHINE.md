# Nova Execution / Recovery State Machine

## Mandatory lifecycle

`PLAN → GOVERN → EXECUTING → OBSERVING → VERIFYING → COMPLETED`

Failure and ambiguity branches are explicit:

- execution failure/unknown → `RECOVERY`
- insufficient authority or unresolved ambiguity → `ESCALATE`
- unsafe/emergency condition → `STOPPED`
- policy/authorization denial → `DENIED`

## Safety semantics

### RECOVERY
Recovery is a decision boundary. It may authorize a bounded rollback/retry path, but it never grants new scope and never proves success.

### ROLLBACK
Rollback must remain inside the original authorization boundary and must carry the original task/operation/scope/policy binding. A rollback decision cannot substitute for verification.

### STOPPED
`STOPPED` is terminal. No implicit retry or resume is permitted.

### ESCALATE
`ESCALATE` is a handoff state, not a resume instruction. A later transition requires a fresh authoritative governance decision and applicable authorization.

### COMPLETED
`COMPLETED` requires an independently verified, cryptographically bound completion proof. A plain `verification="VERIFIED"` field is not evidence.

## Failure-injection requirements

The certification suite must inject stale revisions, expired authorization, revoked identity, altered scope, altered operation hash, forged evidence, duplicate/conflicting recovery decisions, missing recovery binding, and attempts to resume terminal states.

Every injected fault must result in a deterministic fail-closed outcome and must leave an auditable record.

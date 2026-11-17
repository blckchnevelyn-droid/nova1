# Nova — Recovery Specification

## 1. Purpose

Recovery defines how Nova responds when execution fails, verification fails, evidence is insufficient, or an unexpected condition occurs.

Recovery must restore safe and controlled operation without bypassing governance.

## 2. Recovery Principles

Nova recovery must be:

- Safe
- Controlled
- Governed
- Observable
- Auditable
- Reversible where practical
- Idempotent where practical
- Proportional to the failure
- Explicit about uncertainty

Recovery must never become a mechanism for bypassing authorization or safety controls.

## 3. Recovery Triggers

Recovery may be triggered by:

- Execution failure
- Verification failure
- Unexpected system state
- Partial completion
- Timeout
- Dependency failure
- Resource failure
- Policy conflict discovered during execution
- Safety condition
- Inconsistent or corrupted state
- Repeated execution failure
- Uncertain outcome requiring controlled resolution

## 4. Recovery Classification

### LOW
Local, reversible correction with minimal impact.

### MODERATE
Correction affecting multiple components or requiring additional validation.

### HIGH
Potentially significant operational or data impact. Requires stronger verification and may require human oversight.

### CRITICAL
Potential for serious safety, security, financial, operational, or irreversible impact. Recovery must stop unsafe activity and escalate to the appropriate authority.

## 5. Recovery Flow

The standard recovery flow is:

FAILED / UNCERTAIN
→ CONTAIN
→ ASSESS
→ RECOVERY AUTHORITY
→ RECOVER
→ OBSERVE
→ VERIFY

If recovery cannot safely proceed:

RECOVERY
→ ESCALATE

If continued operation is unsafe:

RECOVERY
→ STOPPED

## 6. Containment

When a failure is detected, Nova must first prevent uncontrolled continuation.

Containment may include:

- Pausing execution
- Preventing repeated actions
- Restricting affected scope
- Preserving relevant state
- Cancelling unsafe pending actions
- Preventing cascading failures
- Preserving evidence for investigation

Containment must not destroy evidence required for verification or audit unless necessary to prevent greater harm.

## 7. Recovery Assessment

Before attempting recovery, Nova should determine:

1. What failed?
2. What state currently exists?
3. What actions were actually performed?
4. What actions may have partially completed?
5. What evidence is available?
6. What risks exist if recovery continues?
7. What recovery actions are authorized?
8. What verification is required afterward?

Nova must not assume that a failed action had no effect.

## 8. UNKNOWN Is a Safety Boundary

`UNKNOWN` means the authoritative execution boundary cannot establish whether the external operation produced its intended effect. It is not equivalent to failure and is not permission to retry.

For an `UNKNOWN` attempt, Nova must preserve the original attempt, operation identity, fence, evidence, and audit trail. The attempt must not be rewritten to `FAILED`, `NOT_EXECUTED`, or `SUCCEEDED` merely to enable recovery.

A second consequential attempt is prohibited until authoritative reconciliation or an explicitly governed compensating/idempotent strategy permits it.

## 9. Recovery Authority Decision

A recovery decision is a separate authoritative artifact. It must be created only while the task is in `RECOVERY` and current governance/approval authority remains valid.

The decision is immutably bound to:

- Task identity
- Original operation identity
- Original attempt identity
- Execution fence
- Operation hash
- Exact action and scope
- Recovery strategy
- Actor/authority
- Policy version
- Authoritative task revision
- Reconciliation evidence
- Rationale
- Issuance and optional expiry
- Integrity hash

Recovery authority cannot expand the task's scope, action, resources, actor, or policy authority. A recovery decision is not an authorization credential for unrelated work.

The durable recovery decision store is append-only. Integrity verification must fail closed if the decision is altered.

## 10. Recovery Decision Strategies

Supported strategy classifications are:

- `RECONCILE` — establish authoritative external state before any further consequential action.
- `COMPENSATE` — perform an explicitly authorized compensating action.
- `RETRY_IDEMPOTENT` — permit a retry only where the operation's idempotency semantics make duplicate effect safe and current authority is independently revalidated.
- `ESCALATE` — preserve the unresolved state and request authorized intervention.
- `STOP` — cease further autonomous action pending an authorized resolution.

Creating a recovery decision does not itself execute any strategy.

## 11. Authorized Recovery

Recovery actions remain subject to governance.

Nova must not:

- Grant itself new authority
- Expand execution scope
- Disable safety controls
- Bypass approval requirements
- Conceal failures
- Rewrite evidence to indicate success
- Treat recovery attempts as successful outcomes
- Convert `UNKNOWN` into `SUCCEEDED` without independent authoritative evidence

If the required recovery action is outside existing authorization, Nova must escalate rather than self-authorize.

## 12. Recovery Strategies

Depending on the failure, authorized recovery may include:

- Retry
- Rollback
- Compensating action
- State restoration
- Alternative execution path
- Dependency restoration
- Additional observation
- Additional verification
- Human intervention

The selected strategy must be appropriate to the actual system state and risk.

## 13. Retry Controls

Retries must be controlled.

Nova should define:

- Maximum retry count
- Retry conditions
- Backoff strategy where appropriate
- Idempotency requirements
- Stop conditions
- Escalation conditions

A recovery decision cannot itself create a new execution attempt. The execution boundary must separately enforce operation identity, fencing, current authority, and claim rules.

## 14. Rollback and Compensation

Where rollback is technically possible, Nova should prefer a verified rollback when appropriate.

When rollback is impossible, Nova may use an authorized compensating action to restore the intended safe state.

Rollback or compensation must itself be governed and verified.

## 15. Partial Completion

If an action partially completed, Nova must determine the actual state before retrying.

The system must avoid blindly repeating actions that may already have taken effect.

Partial completion must remain explicitly represented until the resulting state is verified.

## 16. Recovery Verification

Every recovery action that changes system state must be followed by appropriate observation and verification.

Recovery is not complete merely because the recovery action executed successfully.

The required sequence is:

RECOVER
→ OBSERVE
→ VERIFY

Only successful verification may establish that the intended safe state has been restored.

Recovery never establishes `COMPLETED` directly.

## 17. Escalation

Nova must escalate when:

- Recovery is unauthorized
- Recovery is unsafe
- Evidence is insufficient
- The system state is ambiguous
- Required dependencies are unavailable
- Repeated recovery attempts fail
- A high or critical risk condition exists
- Human approval is required
- The intended safe state cannot be verified

Escalation must preserve relevant context, evidence, actions taken, and unresolved conditions.

## 18. Stop Conditions

Nova must stop recovery when continued action could increase risk beyond the authorized boundary.

`STOPPED` means Nova has intentionally ceased further autonomous action pending an authorized resolution.

Stopping must not be represented as successful completion.

## 19. Recovery Audit Record

Recovery events should record, where applicable:

- Original objective
- Governance decision
- Failure trigger
- Observed state
- Actions already performed
- Recovery classification
- Recovery decision identity
- Authorization basis
- Operation/attempt identity
- Fence
- Recovery actions
- Observed recovery result
- Verification result
- Escalation decision
- Final state

## 20. Recovery Invariants

1. Recovery cannot grant authority.
2. Recovery cannot bypass governance.
3. Failed execution must not be assumed harmless.
4. `UNKNOWN` must never be silently reclassified.
5. Partial completion must be explicitly handled.
6. Repeated actions must be controlled.
7. Recovery actions require appropriate authorization.
8. Recovery decisions are bound to the exact unresolved operation and attempt.
9. Recovery cannot broaden scope or policy authority.
10. Recovery must be observable.
11. Recovery must be verified.
12. Unsafe recovery must stop and escalate.
13. Recovery must never create false completion.

## 21. Final Recovery Decision

Recovery may transition to normal operation only when:

1. The failure condition has been addressed.
2. The resulting system state is observable.
3. Required verification succeeds.
4. No unresolved mandatory safety or governance condition remains.

Otherwise Nova must remain in an explicitly controlled state such as:

ESCALATE

or

STOPPED.

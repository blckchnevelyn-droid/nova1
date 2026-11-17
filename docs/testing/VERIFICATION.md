# Nova — Verification Specification

## 1. Purpose

Verification determines whether Nova's intended objective and required outcome were actually achieved.

Execution completion alone must never be treated as proof of success.

## 2. Verification Contract

Every significant task must define:

1. Intended objective
2. Expected outcome
3. Observable evidence
4. Verification criteria
5. Verification method
6. Verification result
7. Failure handling

## 3. Verification Gate

After execution:

EXECUTE → OBSERVE → VERIFY

Verification must evaluate the observed result against the intended objective and defined acceptance criteria.

Only a successful verification may transition a task to:

COMPLETED

## 4. Evidence

Verification should rely on observable evidence appropriate to the task.

Evidence may include:

- Returned values
- System state
- File state
- Test results
- Validation results
- External confirmations
- Policy checks
- Other independently observable signals

Nova must not treat an assumption, intention, or attempted action as evidence of success.

## 5. Verification Outcomes

Verification must produce an explicit outcome:

### VERIFIED

Required criteria have been satisfied by sufficient evidence.

### FAILED

Required criteria have not been satisfied.

### INCONCLUSIVE

Available evidence is insufficient to determine whether the objective was achieved.

### BLOCKED

Verification cannot proceed because a required dependency, permission, system, or evidence source is unavailable.

## 6. Failure Handling

When verification returns FAILED:

VERIFY → RECOVERY

Nova must not silently mark the task as completed.

When verification returns INCONCLUSIVE or BLOCKED:

VERIFY → ESCALATE

unless an explicitly authorized recovery or additional verification path exists.

## 7. Independence

Where practical, verification should be logically independent from the action that produced the result.

The component that performs an action should not be the sole source of evidence that the action succeeded when stronger independent evidence is available.

## 8. Verification Requirements

Verification should check, where applicable:

- Correctness
- Completeness
- Policy compliance
- Safety
- Expected state
- Absence of unintended side effects
- Required output quality

## 9. No False Completion

Nova must never claim:

COMPLETED

when required verification has:

- Failed
- Not occurred
- Produced insufficient evidence
- Been bypassed
- Been overridden without authorized governance

## 10. Verification Invariants

1. Execution does not prove success.
2. Evidence must support the verification decision.
3. Required verification cannot be skipped.
4. Failed verification cannot produce COMPLETED.
5. Uncertain verification must remain explicitly uncertain.
6. Verification failures must have a controlled recovery or escalation path.
7. Verification must not grant authority to execute an otherwise unauthorized action.

## 11. Final Decision

A task may transition to COMPLETED only when:

1. Execution occurred within authorized scope.
2. Observable evidence was collected.
3. Required verification criteria were evaluated.
4. The evidence satisfies the acceptance criteria.
5. No unresolved mandatory safety or governance condition remains.

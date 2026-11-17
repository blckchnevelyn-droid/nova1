# Nova — Execution Specification

## 1. Purpose

Execution is responsible for carrying out actions that have already passed Nova's governance requirements.

Execution must not independently authorize actions.

## 2. Execution Contract

Every executable task must contain:

1. Objective
2. Authorized scope
3. Governance decision
4. Action plan
5. Execution boundary
6. Expected result
7. Verification requirement
8. Failure and recovery strategy

## 3. Execution Gate

Execution may begin only when Governance returns:

ALLOW

The following outcomes must prevent execution:

- DENIED
- ESCALATE
- STOPPED

Execution must never reinterpret a governance decision to obtain permission.

## 4. Planning

Before execution, Nova should:

1. Understand the objective.
2. Determine the required actions.
3. Identify dependencies.
4. Identify potential failure conditions.
5. Establish execution boundaries.
6. Confirm the governance decision.
7. Define how the result will be verified.

## 5. Controlled Execution

Actions must remain within their authorized scope.

Nova must not:

- Expand the requested scope without authorization.
- Grant itself additional permissions.
- Bypass governance.
- Disable required safety controls.
- Conceal execution failures.
- Treat an attempted action as a successful result.

## 6. Observation

During execution, Nova should record observable outcomes relevant to the task.

Observation should provide sufficient information to determine:

- What action occurred.
- Whether it completed.
- What result was produced.
- Whether an unexpected condition occurred.
- Whether execution remains within its authorized boundary.

## 7. Completion

Execution does not determine final success by itself.

After execution:

EXECUTE → OBSERVE → VERIFY

Only successful verification may produce:

COMPLETED

## 8. Failure Handling

When execution fails:

1. Stop unsafe continuation.
2. Preserve relevant execution state.
3. Record the failure.
4. Determine whether recovery is authorized.
5. Enter RECOVERY when appropriate.
6. Escalate when autonomous recovery is insufficient.

## 9. Idempotency and Repetition

Before repeating an action, Nova should determine whether repetition could:

- Duplicate an operation.
- Produce additional side effects.
- Change the intended outcome.
- Increase risk.

Where practical, actions should be designed to be idempotent or have explicit safeguards against unintended repetition.

## 10. Execution Invariants

1. Governance precedes execution.
2. Authorization precedes action.
3. Execution remains within authorized scope.
4. Execution cannot grant itself authority.
5. Execution cannot declare an unverified result successful.
6. Unsafe continuation must stop.
7. Significant failures must be observable and recoverable.

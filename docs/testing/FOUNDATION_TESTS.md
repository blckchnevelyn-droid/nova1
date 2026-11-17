# Nova — Foundation Test Specification

## 1. Purpose

These tests validate that Nova's foundational safety, governance, execution, verification, recovery, authority, provenance, and concurrency rules cannot be bypassed.

The foundation tests are mandatory before autonomous implementation is expanded.

## 2. Test Principle

Nova must fail safely.

A test passes only when Nova:

- Performs an authorized action within scope.
- Rejects unauthorized actions.
- Does not execute when governance denies execution.
- Does not claim completion without successful verification.
- Handles failed or uncertain outcomes through controlled recovery or escalation.
- Stops when continued autonomous action would violate safety or governance boundaries.
- Rejects stale authoritative writes.
- Rejects unverifiable approval provenance.
- Never treats a timestamp alone as authority.

## 3. Governance Tests

### GOV-001 — Authorized Action

**Given:**
- A clearly defined objective.
- An authorized requester.
- Permitted scope.
- Required approvals.
- Satisfied safety and policy conditions.

**Expected:**

Governance returns:

ALLOW

Execution may proceed.

### GOV-002 — Unauthorized Action

**Given:**
- An action outside the requester's authority.

**Expected:**

Governance returns:

DENIED

Execution must not occur.

### GOV-003 — Scope Violation

**Given:**
- An action exceeds the authorized scope.

**Expected:**

The action is denied or escalated.

Nova must not expand its own authority.

### GOV-004 — Human Approval Required

**Given:**
- An action requiring human approval.

**Expected:**

Nova must escalate and wait for the required authorization.

Simulated or assumed approval is invalid.

## 4. Authority and Persistence Tests

### AUTH-001 — Stable Task Identity

A task must have a stable `task_id` that does not change during its lifetime.

### AUTH-002 — Approval Provenance Completeness

A required approval is invalid unless its principal, task binding, scope/objective binding, policy/version, decision, validity, and provenance are established.

### AUTH-003 — Timestamp Is Not Authority

A valid-looking or later timestamp must not convert an otherwise unauthorized approval into an authorized one.

### AUTH-004 — Expired Approval

An approval outside its explicit validity period must not authorize execution.

### AUTH-005 — Policy Binding

An approval bound to a different or unverifiable governance policy/version must not authorize the task.

### AUTH-006 — Stale Revision Rejection

An authoritative state update using an obsolete revision must be rejected and must not overwrite newer state.

### AUTH-007 — Completion Authority

Execution, observation, or recovery components cannot independently commit authoritative `COMPLETED`.

### AUTH-008 — Persistence Failure Is Not Success

If authoritative state cannot be durably committed or validated, Nova must not report the consequential transition as successfully committed.

### AUTH-009 — Audit Integrity

Authority and lifecycle evidence must preserve the attempted transition and must not be rewritten to manufacture success.

## 5. Execution Tests

### EXE-001 — Allow Gate

**Given:**
- Governance decision is ALLOW.

**Expected:**

Execution may proceed only within the authorized scope.

### EXE-002 — Denied Gate

**Given:**
- Governance decision is DENIED.

**Expected:**

Execution does not occur.

### EXE-003 — Escalation Gate

**Given:**
- Governance decision is ESCALATE.

**Expected:**

Execution does not occur until the required authorization is obtained.

### EXE-004 — Scope Preservation

**Given:**
- An authorized execution scope.

**Expected:**

Execution cannot silently expand beyond that scope.

### EXE-005 — No Safety Bypass

**Given:**
- An execution path that would require disabling a mandatory safety control.

**Expected:**

Nova refuses the bypass and enters a controlled state.

## 6. Verification Tests

### VER-001 — Completion Requires Verification

**Given:**
- Execution completed.

**Expected:**

Nova does not transition to COMPLETED until required verification succeeds.

### VER-002 — Failed Verification

**Given:**
- Execution occurred.
- Verification returns FAILED.

**Expected:**

Nova does not claim COMPLETED.

The task enters controlled recovery.

### VER-003 — Inconclusive Verification

**Given:**
- Available evidence is insufficient.

**Expected:**

Nova reports INCONCLUSIVE and escalates unless an explicitly authorized verification or recovery path exists.

### VER-004 — Blocked Verification

**Given:**
- Required verification cannot proceed.

**Expected:**

Nova reports BLOCKED and escalates unless an authorized alternative exists.

### VER-005 — False Completion Prevention

**Given:**
- An action was attempted but objective success cannot be established.

**Expected:**

Nova must not represent the task as completed.

## 7. Recovery Tests

### REC-001 — Execution Failure

**Given:**
- Execution fails.

**Expected:**

Nova enters recovery rather than falsely completing the task.

### REC-002 — Partial Completion

**Given:**
- An action may have partially completed.

**Expected:**

Nova determines actual state before retrying.

Blind repetition is prohibited.

### REC-003 — Controlled Retry

**Given:**
- A retry is authorized and safe.

**Expected:**

Retry limits, conditions, and stop criteria are respected.

### REC-004 — Unauthorized Recovery

**Given:**
- Recovery requires authority not currently granted.

**Expected:**

Nova escalates rather than self-authorizing.

### REC-005 — Unsafe Recovery

**Given:**
- Continued recovery could increase risk beyond the authorized boundary.

**Expected:**

Nova stops recovery and enters:

STOPPED

### REC-006 — Recovery Verification

**Given:**
- Recovery changes system state.

**Expected:**

Nova observes and verifies the resulting state before considering recovery successful.

## 8. Escalation and Stop Tests

### ESC-001 — Ambiguous State

**Given:**
- Nova cannot determine the actual system state with sufficient confidence.

**Expected:**

Nova does not guess.

Nova escalates or stops according to the applicable governance rule.

### ESC-002 — Critical Risk

**Given:**
- A critical safety, security, financial, operational, or irreversible risk is detected.

**Expected:**

Nova stops unsafe activity and escalates to the appropriate authority.

### ESC-003 — Repeated Failure

**Given:**
- Recovery repeatedly fails.

**Expected:**

Nova reaches a defined stop or escalation condition.

Unlimited autonomous retries are prohibited.

## 9. End-to-End Foundation Test

### E2E-001 — Governed Autonomous Task Lifecycle

Validate the complete lifecycle:

PLAN
→ GOVERN
→ EXECUTE
→ OBSERVE
→ VERIFY
→ COMPLETE

Failure path:

PLAN
→ GOVERN
→ EXECUTE
→ OBSERVE
→ VERIFY
→ RECOVERY

Unsafe or unauthorized path:

PLAN
→ GOVERN
→ ESCALATE / DENIED / STOPPED

**Expected:**

No state transition bypasses governance.

No task reaches COMPLETED without successful verification.

No recovery action bypasses governance.

No unsafe condition is silently ignored.

## 10. Foundation Invariants

The following invariants must remain true:

1. Capability does not imply authority.
2. Governance controls execution.
3. DENIED prevents execution.
4. ESCALATE prevents unauthorized execution.
5. Execution does not prove success.
6. Verification is required for completion.
7. Failed verification cannot produce COMPLETED.
8. Uncertain outcomes remain explicitly uncertain.
9. Recovery cannot grant authority.
10. Recovery cannot bypass safety controls.
11. Unsafe continuation must stop.
12. Human approval cannot be simulated.
13. Nova must not create false completion.
14. All significant actions require observable evidence.
15. Safety and governance take priority over task completion.
16. Approval timestamps do not create authority.
17. Approval provenance must be bound to task, principal, scope, policy/version, and validity.
18. Stale revisions cannot overwrite authoritative state.
19. Persistence failure cannot become false success.
20. Authoritative completion belongs to the state authority boundary.

## 11. Authority Contract Source

The normative authority/state/persistence contract is defined by:

`docs/architecture/ADR-001-AUTHORITY-STATE.md`

Runtime implementation must conform to that contract before consequential autonomous execution or recovery is enabled.

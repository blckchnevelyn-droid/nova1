# Nova Recovery Certification Plan

## Gate objective

Prove that recovery is a governed state transition, not an execution bypass.

## Required invariants

1. Recovery may begin only from an eligible failure/ambiguous state.
2. Every recovery decision is bound to task, operation, attempt, fence, operation hash, scope, policy version, authorization, and authoritative revision.
3. Recovery cannot expand the authorized scope or tool set.
4. Expired, revoked, mismatched, or unverifiable authorization fails closed.
5. Recovery cannot manufacture successful completion.
6. Rollback, retry, stop, and escalation are distinct outcomes with explicit lifecycle transitions.
7. STOPPED and DENIED are terminal and cannot silently resume.
8. ESCALATE requires an explicit subsequent authorized transition; it is not an implicit resume.
9. Failure injection must prove the invariants under stale revisions, forged evidence, tampered bindings, duplicate decisions, expired authorization, and conflicting provenance.
10. Certification requires reproducible automated test evidence; documentation or manual PASS statements are insufficient.

## Certification sequence

RECOVERY CONTRACT → ROLLBACK/STOP/ESCALATE → FAULT INJECTION → REGRESSION → SECURITY → AUDIT

A failed prerequisite blocks the next gate until the defect is fixed and a regression test is added.

# Nova — Recovery Authority Contract

## Status

ADOPTED contract for the first recovery-security implementation slice.

## Security boundary

An execution attempt in `UNKNOWN` is unresolved evidence, not failure and not permission to retry. The recovery authority boundary may record a decision, but it must never itself execute a consequential action or convert `UNKNOWN` into success.

## Required bindings

Every recovery decision is bound to the exact task, operation, attempt, fence, operation hash, action, scope, actor, policy version, authoritative task revision, reconciliation evidence, strategy, rationale, issuance/expiry, and integrity digest.

## Preconditions

A recovery decision may be authorized only when:

1. the referenced attempt exists;
2. the attempt is exactly `UNKNOWN`;
3. the operation belongs to the task;
4. the operation scope equals the authoritative task objective;
5. the task is currently `RECOVERY`;
6. governance currently permits recovery;
7. required approval is current, provenance-bearing, task-bound, scope-bound, and policy-version-bound;
8. rationale and reconciliation evidence are present;
9. the decision expiry, when present, is in the future.

## Non-escalation invariant

A recovery decision cannot change the operation's action, scope, operation hash, attempt identity, or fence. It cannot create authority that the task does not already possess.

## Strategy semantics

- `RECONCILE`: determine authoritative external state before consequential retry.
- `COMPENSATE`: authorize a separately governed compensating operation.
- `RETRY_IDEMPOTENT`: permit consideration of retry only when provider/operation idempotency is established and current authority is revalidated by the execution boundary.
- `ESCALATE`: preserve unresolved state for authorized intervention.
- `STOP`: cease autonomous recovery.

## Consumption rule

The recovery decision is not an execution credential. A future retry/compensation consumer must re-read authoritative task and attempt state, verify decision integrity and freshness, revalidate authority, and acquire a fresh execution claim before any consequential side effect.

## Terminal-state rule

Creating or consuming a recovery decision must never directly establish `SUCCEEDED` or `COMPLETED`. Successful completion remains subject to execution evidence, observation, independent verification, and the authoritative lifecycle rules.

## Durability and integrity

Recovery decisions are durable, unique per unresolved attempt, append-only, and protected by an integrity digest. Mutation or deletion must fail closed at the persistence boundary; detected digest mismatch must fail closed on read.

## Out of scope for this gate

This contract does not implement autonomous retry, external side-effect reconciliation, compensating execution, provider APIs, secrets, or real-world action. Those remain separate governed boundaries.

# P0 — Precision, Evidence & Semantic Verification Foundation Audit

**Status:** AUDIT BASELINE — implementation intentionally deferred
**Security posture:** fail-closed; no existing authority or verification invariant is weakened by this document.

## 1. Objective

Define the minimum contract Nova must satisfy before it may claim that a task result is not merely executed and cryptographically verified, but sufficiently evidenced against the original objective.

Core rule:

> Successful execution is not successful verification, and successful verification is not proof of semantic truth.

## 2. Current verified boundary

### Governance

Authorization currently binds authorizer, agent, task, objective, action, scope, allowed tools, limits, policy version, time window, provenance, proof, and an integrity hash. Execution checks the ledgered authorization and durable governed attempt binding before consequential execution. This remains a security-critical boundary and must not be weakened.

### Execution

Operations are canonically represented and hashed. Attempts are fenced and bound to operation/task/worker identity. Successful outcomes require result evidence, and evidence is hashed with task/operation/attempt/fence/state context. Durable execution records and relevant audit records have immutability controls.

### Completion verification

Completion proofs cryptographically bind task, expected revision, operation, attempt, evidence hash, decision, verifier identity, and issuance time. Trusted verifier keys have validity/revocation controls, and conflicting provenance for the same attempt is rejected.

## 3. Confirmed precision gap

The current completion contract establishes:

`Objective/Task → Authorized Action → Execution Attempt → Evidence → Evidence Hash → Signed VERIFIED Proof`

It does **not yet define a machine-verifiable contract that establishes whether the evidence is sufficient to demonstrate that the expected semantic result was achieved.**

The missing layer is:

`Objective → Expected Result Contract → Action → Evidence → Provenance → Evidence Sufficiency → Independent Verification → VERIFIED`

A signature authenticates what a trusted verifier asserted. It does not independently establish that the assertion is semantically correct.

## 4. Required Result Contract

Every consequential task that can reach COMPLETE should eventually bind, at minimum:

1. **Objective** — immutable task objective.
2. **Expected result** — explicit acceptance criteria derived from the objective.
3. **Result type** — structured result category/schema where applicable.
4. **Evidence requirements** — what evidence is necessary and sufficient.
5. **Evidence provenance** — source, producer, acquisition time, and binding to the attempt.
6. **Verification method** — deterministic test, independent verifier, comparison, invariant check, or explicitly bounded human verification.
7. **Failure semantics** — FAILED, INCONCLUSIVE, CONFLICTED, UNSAFE, or ESCALATE conditions.
8. **Uncertainty/confidence semantics** — only where measurable and never treated as authorization.
9. **Recovery path** — what happens when acceptance criteria are not met.

## 5. Required result states

Recommended semantic result vocabulary:

- `SUCCESS` — execution completed without an execution error.
- `VERIFIED` — required evidence and verification checks passed.
- `CORRECT` — independently established against the declared acceptance contract.
- `INCONCLUSIVE` — evidence is insufficient or verification cannot establish the claim.
- `CONFLICTED` — authoritative evidence sources disagree.
- `UNSAFE` — safety/security conditions prohibit acceptance.
- `ESCALATE` — human or higher-authority decision is required.

`VERIFIED` must not implicitly mean `CORRECT` unless the verification contract explicitly establishes correctness for that task class.

## 6. Adversarial test matrix

Before implementation is considered complete, tests should cover at least:

| Attack / failure | Required behavior |
|---|---|
| Valid evidence, wrong semantic result | Reject completion/correctness claim |
| Evidence hash valid but evidence source is wrong | Reject or mark INCONCLUSIVE |
| Evidence omitted for a criterion | Reject successful verification |
| Partial evidence presented as complete evidence | Reject |
| Stale evidence from another attempt | Reject binding |
| Evidence replay from another task | Reject binding |
| Conflicting independent evidence | CONFLICTED / ESCALATE |
| Verifier signs an unsupported claim | Contract must prevent acceptance |
| Tampered acceptance criteria | Reject integrity/binding |
| Objective changes after authorization | Require new governed revision |
| Unknown evidence provenance | Reject or INCONCLUSIVE |
| Verification method unavailable | INCONCLUSIVE / ESCALATE, never VERIFIED |
| High confidence but failed deterministic check | Deterministic failure wins |
| Successful execution with semantic failure | Must not COMPLETE |
| Verification proof valid but evidence unavailable | Must not infer correctness |

## 7. Implementation boundary

Do **not** redesign `nova/execution.py` or `nova/verification.py` broadly as part of this audit. First introduce the smallest explicit contract that can be independently tested and bound to the existing immutable task/operation/attempt identities.

The implementation must preserve:

- human authority;
- fail-closed authorization;
- governed execution bindings;
- evidence hashing;
- signed verifier provenance;
- existing immutability controls;
- recovery/STOP/ESCALATE semantics;
- append-only audit guarantees.

No semantic result may authorize an action by itself.

## 8. CI acceptance criteria

The P0 milestone is not complete until hosted CI demonstrates:

1. all existing regression/security/adversarial tests remain green;
2. new semantic-result contract tests are green;
3. forged, stale, incomplete, conflicting, and cross-task evidence attacks are rejected;
4. execution success cannot bypass semantic verification where the task contract requires it;
5. `VERIFIED` cannot be upgraded to `CORRECT` without the declared correctness contract;
6. no workflow permission expansion is introduced;
7. evidence identifies the exact commit, test suite, and result artifacts.

## 9. Relationship to audit-chain trust Issue #1

This audit does not close or weaken the independent audit-chain trust finding. Issue #1 remains open until external-anchor custody/claim-boundary requirements and real evidence are satisfied.

## 10. Next implementation slice

**P0.1 — Define immutable `ExpectedResultContract` and `EvidenceRequirement` primitives plus adversarial tests only.**

Do not connect them to completion state transitions until the contract itself is reviewed and its failure semantics are locked by tests.

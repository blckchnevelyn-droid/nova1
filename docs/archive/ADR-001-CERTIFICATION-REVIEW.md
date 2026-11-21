> **Status: aspirational, not completed.** This document describes a certification process that was planned but never finished. It is not evidence that Nova is certified. The project is a prototype (see README.md).

# ADR-001 Authority Contract Certification Review

## Status

P1.3 certification evidence review for PR #12. This document records objective coverage and does not by itself declare certification or lock.

## Certified candidate revision

The current certification candidate is the exact PR head revision recorded below.

`6817e2f78b2f97bcb85da8f29be74fcd63053bfa`

Base: `876e0f22ce39e01ff32305417063e9878b2694ec`

## Invariant matrix

| # | ADR-001 invariant | Objective evidence on candidate revision | Status |
|---|---|---|---|
| 1 | Capability does not imply authority | Existing governed-execution and adversarial boundary suites; exact-head hosted run | COVERED |
| 2 | Timestamp does not imply authority | Durable approval immutability attack rejects persisted `issued_at`/provenance substitution; restart/reconstruction coverage remains in adversarial suite | COVERED |
| 3 | Mutable task state does not create approval authority | Durable task identity immutability rejects objective/principal substitution | COVERED |
| 4 | Approval is bound to task, principal, scope, policy/version, and validity | Existing approval-binding/expiry/provenance tests plus durable approval persistence/immutability | COVERED |
| 5 | Stale writers cannot overwrite newer state | Two durable store instances plus revision conflict attack | COVERED |
| 6 | Execution cannot directly produce authoritative COMPLETED | API rejects durable completion; database trigger rejects direct persisted COMPLETED state | COVERED |
| 7 | Verification is required before completion | Existing authority/adversarial verification gates; durable completion remains blocked without independent completion contract | COVERED |
| 8 | Persistence failure cannot be represented as successful commitment | Authoritative read failure, transition write failure, commit failure, audit-write partial-commit failure, and rollback failure injection | COVERED |
| 9 | Recovery cannot expand authority | Durable recovery tests reject persisted objective/principal substitution; approval binding remains immutable | COVERED |
| 10 | Audit evidence cannot be rewritten to manufacture success | Append-only UPDATE/DELETE triggers plus failure-to-success rewrite attack and persisted audit integrity checks | COVERED |

## Hosted exact-head evidence

- Nova governed execution run: `35465092330` (#142), success, executed against candidate SHA `6817e2f78b2f97bcb85da8f29be74fcd63053bfa`.
- Nova authority boundary run: `35465092331` (#141), success, executed against candidate SHA `6817e2f78b2f97bcb85da8f29be74fcd63053bfa`.
- Both hosted workflows performed exact-revision verification successfully.
- Hosted runner: GitHub-hosted Ubuntu 24.04.5, runner 2.337.0.
- Governed execution verification artifact: `nova-governed-execution-verification-35465092330-1`.
- Governed artifact SHA-256: `6c530d09bde7475daa41148bebc89fc05a92512116914a2ee56f13fa4ffe29a4`.
- Local verification before this documentation synchronization: targeted P1.3 durability tests 17/17 passed; full regression 208/208 passed.

## Acceptance gate

Implementation and hosted evidence for the candidate revision are green. This review is not an independent acceptance review; P1.3 remains UNLOCKED until an independent acceptance review confirms the matrix against ADR-001 and the hosted evidence, the documentation synchronization commit itself passes exact-head hosted verification, and PR #12 receives an explicit human merge decision.

## Non-goals

No browser control, unrestricted tool autonomy, PCSCM, AIRS, self-modification, distributed execution, or production-readiness claim is authorized by this review.

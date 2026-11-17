# Nova Security Gap Register

## Current gate

Nova's governed execution path consumes cryptographic authorizer identity. The durable authority layer has per-task cryptographic audit chaining and completion is proof-bound at the authoritative transition. Hosted CI now provides reproducible execution evidence for the current `main` revision. P1.1 certification remains gated on formal final audit/acceptance against ADR-001 and exact evidence mapping.

## SG-001 — Authorizer authentication at consequential execution boundary

**Severity:** Critical for production authorization

### Remediation status

**CLOSED at the governed execution boundary.**

`nova/identity.py` provides a fail-closed Ed25519 verification boundary with trusted-key registration, principal/key binding, algorithm enforcement, validity/revocation checks, exact canonical-envelope signature verification, replay detection, and deterministic signed-envelope hashing. `nova/governed_execution.py` requires an `IdentityGate` and verifies the authorization proof before operation binding, attempt creation, claim, and outcome recording.

## SG-002 — Durable authoritative lifecycle and recovery certification

**Severity:** High

The SQLite authority store, execution boundary, recovery boundary, fencing, immutable terminal attempts, and recovery decision integrity checks are implemented. Hosted CI has now exercised the durable lifecycle, recovery, concurrency, adversarial, and regression boundaries on the current `main` revision.

**Status: REMEDIATED — formal P1.1 audit/acceptance pending.**

## SG-003 — Cryptographically chained tamper-evident audit

**Severity:** Critical for production auditability

Durable authority audit events carry `previous_hash` and `event_hash` values. Each event is canonically serialized and SHA-256 chained from a deterministic genesis value per task. The chain is verified on audit reads, and schema migration backfills existing v1 audit records. Adversarial durability coverage exercises privileged tampering detection.

This is tamper-evident, not an absolute claim against an attacker who can rewrite the entire database and independently replace every digest. Production hardening should add an externally anchored/signed audit root before treating the audit as resilient to full database compromise.

**Status: REMEDIATED — formal certification evidence pending; external-root hardening remains a production-security enhancement.**

## SG-004 — Independent completion proof enforcement

**Severity:** Critical for production completion authority

`nova/verification.py` provides an independent Ed25519 verifier trust root and completion proof bound to task, authoritative revision, operation, attempt, evidence digest, verifier identity, decision, and timestamp. The durable authority transition rejects plain `verification="VERIFIED"`, requires a `CompletionProof` plus `VerificationGate`, verifies the proof inside the authoritative transaction, validates operation/attempt/evidence binding, requires a `SUCCEEDED` attempt, persists an immutable proof record, and records the proof digest in the transition audit detail. The in-memory reference authority also rejects string-only completion.

Adversarial completion tests cover plain-string bypass, forged signature/evidence, stale revision, tampered execution evidence, revoked verifier, and proof reuse.

**Status: REMEDIATED — formal certification evidence pending.**

## SG-005 — CI execution evidence

**Severity:** Critical for certification integrity

The governed-execution and authority-boundary workflows run on pushes to `main` and execute the governed boundary tests, Gate-2 durability/verification tests, recovery/adversarial invariants, full regression, and Python compilation checks, with verification logs uploaded as an artifact.

Latest hosted evidence:
- commit: `639cfb2452dcc7014392f04f03005c0c3b8fcc2c`
- governed-execution run: `34984776685`
- governed-execution job: `104433945456`
- authority-boundary run: `34984776823`
- authority-boundary job: `104433945785`
- governed-execution full regression: `150 passed`
- authority-boundary suite: `150 passed`
- Python `compileall`: passed
- governed verification artifact: `nova-governed-execution-verification-34984776685-1`, artifact ID `10402793222`
- hosted runner: GitHub-hosted Ubuntu 24.04.5, runner `2.337.0`

The hosted logs also prove the governed workflow checked out the exact current SHA before executing the matrix.

**Status: REMEDIATED — operational evidence established on current revision.**

## Gate rule

Nova must not be declared production-ready or unrestricted-autonomy capable merely because the P1.1 verification matrix passes. P1.1 certification requires formal final audit/acceptance against ADR-001, confirmation that the durable authority contract is preserved, failure-closed persistence semantics remain intact, recovery cannot expand authority, and the evidence mapping is complete and auditable.

## SG-006 — File-write pilot (sandboxed, governed, single action class)

**Status: PILOT IMPLEMENTED on Linux, with open gaps.** See `docs/security/FILE_WRITE_PILOT.md`, "Implementation status".

Closed:
- A grant binds an exact path and content digest through the signed scope.
- Sandbox traversal and symlink escape are refused at open time, and a directory swap after open does not redirect the write.
- Crash rows recover without a second effect. Concurrent processes cannot double-write or credit a foreign write.
- Evidence hashes are keyed and the execution audit is hash-chained, both with a key outside the database. Tampering is detected on read and by chain verification.
- Completion requires an independently signed proof checked by the trusted gate. The executor holds no verifier key.
- The lifecycle is model-checked (TLC, 150 states, five invariants). Two planted bugs are caught.

Open:
- Recovery decisions for `UNKNOWN` attempts are not implemented. Escalation is a refusal.
- In-process enforcement is impossible in Python. The publish capability and attempt creation are restricted only by convention. Real restriction needs process isolation controlled by the host.
- Migration of pre-chain databases is implemented and tested. It has not been run against any real production database.
- Symlink-replacement races are tested at one swap point only. Case behavior, macOS, and other filesystems are untested.
- The model is abstract (one operation, one path, bounded attempts). It does not model the Python implementation directly.

## SG-007 — Draft host (first host, human-approved drafts)

**Status: BUILT and tested locally. Not run live. Model call untested against the real API.** See `docs/hosts/draft-host.md`.

Closed:
- Trust is established once, at setup, by writing public keys into the database. `approve` and `verify` refuse unregistered and revoked keys. Forged-key and revoked-key tests cover this, and a mutation that removes the check fails three tests.
- Approval is bound to exact path and digest. Changed content is refused before any write.
- Execution holds no verifier key. Completion is a separate step.
- The kill switch stops `run` before each effect.

Open:
- Approval is key possession, not an identity check.
- Key separation is an operator duty. The default setup co-locates keys with the agent. Do not use the default.
- The model adapter has not run against the live API. This sandbox has no API key.
- Review result records are not hash-chained.
- Nothing has run on the GitHub runners yet.

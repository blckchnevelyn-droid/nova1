# Gate 4 — Recovery, Fault Injection, and Failure Semantics

## Exit criteria

- [ ] Recovery uses only the governed execution boundary.
- [ ] Recovery decisions are durable and immutable.
- [ ] Rollback cannot broaden task/objective/scope/tool authorization.
- [ ] STOPPED and DENIED cannot resume.
- [ ] ESCALATE cannot implicitly resume.
- [ ] Expired/revoked/mismatched authorization is rejected.
- [ ] Stale revisions are rejected.
- [ ] Forged/altered evidence is rejected.
- [ ] Conflicting provenance is rejected.
- [ ] Completion cannot be produced by a recovery decision.
- [ ] Cryptographic audit chaining is verified independently.
- [ ] Completion proof is enforced by the authoritative state transition.
- [ ] Full unit, integration, security, fault-injection, regression, and benchmark suites execute successfully.

## Certification rule

Gate 4 is **NOT CERTIFIED** while any required item is unchecked. CI infrastructure failure is recorded as an infrastructure blocker, not converted into a test PASS.

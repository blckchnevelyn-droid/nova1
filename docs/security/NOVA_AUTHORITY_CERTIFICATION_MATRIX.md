# NOVA Authority Certification Matrix

## Purpose

P1.3 certification artifact for proving the Nova authority boundary before runtime security expansion.

Certification rule:

> No authority claim without implementation evidence, adversarial verification, and reproducible artifacts.

## Authority Invariants

| Invariant | Implementation | Test Evidence | Status |
|---|---|---|---|
| Single authoritative permission path | Pending verification | Pending adversarial run | OPEN |
| Model cannot self-authorize | Pending mapping | Pending attack evidence | OPEN |
| Approval is required before execution | Authority contract / durable authority path | Approval rejection tests | OPEN |
| Identity is bound to authority decision | Pending mapping | Identity mismatch attack | OPEN |
| Capability/tool binding is enforced | Pending mapping | Tool substitution attack | OPEN |
| Completion requires valid proof | Completion integrity boundary | Modified proof attack | OPEN |
| Audit events are integrity protected | Audit implementation | Tamper test | OPEN |

## Required Attack Coverage

- [ ] Fake approval
- [ ] Modified completion proof
- [ ] Identity mismatch
- [ ] Capability replay
- [ ] Tool substitution
- [ ] Unauthorized completion claim

## Evidence Requirements

Every completed item must record:

- Exact commit SHA
- Environment information
- Test command
- Test result
- Artifact location

## Exit Gate

P1.3 is complete only when:

- Authority path is singular and verified
- Unauthorized execution fails closed
- Attack tests execute against the real authorization path
- Evidence is reproducible
- No unresolved authority split remains

Next phase after approval:

P2.1 Runtime Security Foundation

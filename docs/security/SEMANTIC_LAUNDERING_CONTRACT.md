# Semantic-Laundering Security Contract

## Status

This document defines the security contract for cumulative-action authorization. It does not grant any new capability.

## Threat

A sequence of individually permitted operations may collectively produce an effect outside the authorized objective, scope, capability set, or resource boundary. Per-operation allow decisions are therefore insufficient as the sole control.

## Required invariants

1. Canonical objective binding: every operation belongs to one immutable task/objective identity.
2. Authorization continuity: every operation and attempt remains bound to the durable authorization identity, integrity hash, agent identity, tool, scope, and policy version that authorized the task.
3. Capability attenuation: later operations cannot acquire authority absent from the original authorization.
4. Cumulative accounting: the control plane accounts for cumulative operations and, when applicable, resources, data-flow/provenance, and consequential effects.
5. Composition control: policy can deny a sequence whose combined effect is prohibited even when atomic operations are individually allowed.
6. Consequential approval: crossing a separately defined authority boundary stops execution pending required human approval, bound to the canonical task and exact consequential scope.
7. Independent post-condition verification: completion depends on observed resulting state/evidence, not solely on executor claims.
8. Fail-closed ambiguity: missing, stale, contradictory, or unverifiable cumulative context is not permission.
9. Audit continuity: cumulative decisions and approvals are attributable to task, authorization, operation/attempt, policy version, and evidence.
10. No privilege laundering through decomposition: splitting a prohibited effect into benign-looking calls cannot bypass the authority boundary.

## Policy inputs

Deterministic policy evaluation must have access to the canonical task/objective, authorization identity and integrity hash, authorized scope and allowed tools/actions, policy version, cumulative counters, relevant data-flow/provenance, prior consequential decisions/approvals, normalized requested operation semantics, and observed state/evidence needed to evaluate resulting effect.

The model/agent may propose operations but cannot define, relax, or attest its own cumulative authorization.

## Required adversarial tests

At minimum:
- an ordinary multi-step workflow remains allowed within its authorized aggregate effect;
- a semantic-laundering sequence is denied before the forbidden aggregate effect occurs;
- capability accumulation is denied;
- objective/scope/policy context changes mid-sequence are denied;
- consequential approval cannot be replayed for another task, operation, scope, or authorization;
- incomplete cumulative context fails closed;
- forged/altered post-condition evidence cannot establish completion.

## Implementation boundary

Do not invent a universal numeric risk score. Tool-specific effect schemas and composition rules must be explicitly defined before enforcement for those tools.

This contract does not authorize browser control, external connectors, AIRS, broad orchestration, or higher autonomy.

## Closure evidence

A future implementation must provide the exact commit SHA, positive/negative regression counts, authoritative CI run/job IDs and logs, exact-head checkout verification, proof that the laundering sequence is denied before the prohibited effect, proof that ordinary authorized composition works, and zero unresolved critical/high attack findings.

# Nova Authorization Binding Contract

## Status

**Authorization-record contract and consequential execution enforcement are implemented. Gate 2 remains OPEN until the complete regression/adversarial suite is verified green.**

## Non-negotiable rule

Nova must never infer authorization from a timestamp, mutable task state, agent assertion, successful execution result, or a generic `ALLOW` value alone.

A consequential authorization record must bind:

- authorizer identity
- agent identity
- task identity
- objective / intent
- exact action
- exact scope
- allowed tools
- explicit limits
- policy version
- issuance time
- expiration time
- provenance
- authorization proof/reference
- integrity hash

## Integrity model

`AuthorizationRecord.issue()` canonicalizes the complete authorization envelope and computes a SHA-256 integrity hash. `verify_integrity()` reconstructs the canonical representation and rejects any mutation.

The hash is an integrity mechanism, **not** proof of authorizer authenticity. Cryptographic identity/signature and key lifecycle belong to the identity/security gate.

## Fail-closed checks

The binding contract rejects:

- missing authorizer, agent, action, scope, policy, provenance, or proof
- missing allowed tools
- invalid expiration
- modified authorization records
- unknown authorization IDs
- duplicate authorization IDs
- revoked authorization
- expired/not-yet-valid authorization
- wrong agent
- wrong action
- wrong scope
- unauthorized tool

## Execution enforcement

The durable execution implementation is internal-only. Its constructor requires an internal capability and an authorization ledger; it is not exported as the public execution API.

`GovernedSQLiteExecutionAuthority` is the sole public consequential execution facade. It requires an `AuthorizationRecord` and tool for operation identification, claim, and outcome recording. It additionally persists immutable authorization ID/hash/tool bindings for operations and attempts and rechecks the exact binding before consequential transitions.

The facade does not expose the raw durable execution object, preventing callers from bypassing the durable governed binding through an internal escape hatch.

## Gate 2 completion condition

Gate 2 is PASS only after:

1. the authorization contract is implemented;
2. consequential execution cannot proceed without a current authorization record;
3. the exact authorization identity/hash/tool is durably bound to the operation and attempt;
4. tampering, wrong-agent/tool/action/scope, expiry, revocation, replay, and direct-bypass tests pass;
5. the full regression and adversarial CI suite is verified green.

Until those conditions are verified, unrestricted runtime execution remains disabled.

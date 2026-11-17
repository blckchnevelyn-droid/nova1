# Nova Audit Anchor Trust Boundary

## Security claim

Nova's local audit chain is **tamper-evident within the database trust domain**. A signed checkpoint strengthens this by binding a verified chain head and event count to an independently managed signing key.

This does **not** by itself defeat an attacker who controls both the audit database and the checkpoint-signing key. To make privileged rewrite detectable, checkpoint evidence must be retained by a custody system that the database operator cannot rewrite or delete.

## Trust domains

1. **Nova database domain** — mutable application/database state, local audit rows, local triggers, and local chain verification.
2. **Signing domain** — private checkpoint key custody. The private key must not be recoverable from the audit database.
3. **External custody domain** — immutable or append-only checkpoint evidence held under separate administrative control.
4. **Independent verifier** — consumes the checkpoint, pinned public key(s), and external anchor evidence without treating database-supplied trust material as authoritative.

A production-grade claim requires at least domains 1–3 to be independently controlled. Putting the anchor in the same database, account, or administrator boundary does not satisfy the external-anchor requirement.

## Required anchor properties

- Write-once / append-only semantics for published checkpoint evidence.
- Independent custody credentials and administrative boundary.
- Stable anchor identifier and checkpoint digest.
- Public-key provenance outside the mutable database.
- Key rotation with explicit successor continuity and retained historical verification keys.
- Offline or independently executable verification.
- Failure is fail-closed: missing, substituted, stale, or mismatched anchor evidence cannot be treated as verified history.
- Anchor publication must not contain business payloads; checkpoint metadata and cryptographic commitments are sufficient.

## Exposure window

History after the latest successful external anchor remains covered by the signed local checkpoint but is not yet protected against an attacker who controls both the database and signing service. The deployment must define an anchor cadence and explicitly report the unanchored interval.

## Required adversarial validation before closing Issue #1

- Drop local audit triggers, rewrite all historical rows, recompute the local chain, and verify the old external checkpoint rejects the history.
- Truncate history and forge a continuation; verify the anchored event count/head rejects it.
- Substitute a chain head while retaining the old signature; reject.
- Substitute or forge the checkpoint signature; reject.
- Substitute the anchor digest; reject.
- Substitute the custody domain or an unknown anchor identifier; reject.
- Rotate signing keys and prove old and new checkpoints remain verifiable with explicit continuity.
- Attempt to place the anchor inside the mutable database trust domain; treat this as insufficient evidence rather than certification.

## Certification boundary

Issue #1 remains open until a concrete external custody adapter is exercised against a real independently controlled anchor and the complete attack suite passes on the hosted CI runner. The current repository contract intentionally stops short of claiming that an in-database implementation is an external immutable anchor.

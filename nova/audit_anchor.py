"""External audit-checkpoint anchoring contracts for Nova Trust Foundation.

An anchor is evidence held outside the database trust domain. This module deliberately
contains only the protocol and fail-closed verification boundary; concrete custody
providers must satisfy the contract without allowing the application database to
rewrite or delete previously published anchors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from nova.audit_checkpoint import AuditCheckpointVerifier, CheckpointError, SignedAuditCheckpoint


class AuditAnchorError(ValueError):
    """Raised when external anchor evidence cannot be trusted."""


@dataclass(frozen=True)
class ExternalAnchor:
    """Immutable evidence receipt obtained from an independently controlled anchor."""

    anchor_id: str
    checkpoint_digest: str
    anchored_at: str
    custody_domain: str

    def __post_init__(self) -> None:
        if not self.anchor_id or not self.custody_domain:
            raise AuditAnchorError("anchor identity and custody domain are required")
        if len(self.checkpoint_digest) != 64:
            raise AuditAnchorError("anchor checkpoint digest is invalid")


class ExternalAnchorReader(Protocol):
    """Read-only contract for a custody system outside Nova's database trust domain."""

    def read_anchor(self, anchor_id: str) -> ExternalAnchor:
        ...


class ExternalAnchorWriter(Protocol):
    """Write-once contract for publishing checkpoint evidence to external custody."""

    def publish(self, checkpoint: SignedAuditCheckpoint) -> ExternalAnchor:
        ...


def verify_external_anchor(
    checkpoint: SignedAuditCheckpoint,
    anchor: ExternalAnchor,
    verifier: AuditCheckpointVerifier,
    *,
    trusted_custody_domains: Mapping[str, str],
) -> None:
    """Verify a checkpoint against separately supplied external anchor evidence.

    The custody-domain mapping is supplied independently of the mutable audit database.
    A missing or mismatched domain, checkpoint digest, or checkpoint signature fails closed.
    """
    expected_domain = trusted_custody_domains.get(anchor.anchor_id)
    if expected_domain is None:
        raise AuditAnchorError("anchor is not trusted")
    if anchor.custody_domain != expected_domain:
        raise AuditAnchorError("anchor custody domain mismatch")
    try:
        digest = verifier.verify(checkpoint)
    except CheckpointError as exc:
        raise AuditAnchorError("checkpoint verification failed") from exc
    if digest != anchor.checkpoint_digest:
        raise AuditAnchorError("external anchor checkpoint mismatch")

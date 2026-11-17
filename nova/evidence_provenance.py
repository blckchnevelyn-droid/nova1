"""Fail-closed evidence identity and provenance boundary for Nova P0.2."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .result_contract import ExpectedResultContract, ResultContractError


class EvidenceProvenanceError(ValueError):
    """Raised when evidence identity or provenance cannot be established."""


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceProvenanceError(f"{field} is required")
    return value.strip()


@dataclass(frozen=True)
class EvidenceIdentity:
    """Immutable identity binding evidence to one task, operation, attempt and contract."""

    task_id: str
    operation_id: str
    attempt_id: str
    fence: int
    evidence_hash: str
    contract_hash: str
    provenance_id: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.task_id, "task_id"),
            (self.operation_id, "operation_id"),
            (self.attempt_id, "attempt_id"),
            (self.evidence_hash, "evidence_hash"),
            (self.contract_hash, "contract_hash"),
            (self.provenance_id, "provenance_id"),
        ):
            _text(value, field)
        if not isinstance(self.fence, int) or isinstance(self.fence, bool) or self.fence < 1:
            raise EvidenceProvenanceError("fence must be a positive integer")
        for value, field in ((self.evidence_hash, "evidence_hash"), (self.contract_hash, "contract_hash")):
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise EvidenceProvenanceError(f"{field} must be a lowercase SHA-256 hex digest")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "attempt_id": self.attempt_id,
            "fence": self.fence,
            "evidence_hash": self.evidence_hash,
            "contract_hash": self.contract_hash,
            "provenance_id": self.provenance_id,
        }

    def digest(self) -> str:
        encoded = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable evidence plus its independently computed identity binding."""

    identity: EvidenceIdentity
    evidence: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, str) or not self.evidence:
            raise EvidenceProvenanceError("evidence is required")


class EvidenceProvenanceGate:
    """Fail-closed checker for cross-task, stale, forged and conflicting evidence."""

    def __init__(self) -> None:
        self._accepted: dict[str, str] = {}

    def _build_identity(
        self,
        *,
        task_id: str,
        operation_id: str,
        attempt_id: str,
        fence: int,
        evidence_hash: str,
        contract: ExpectedResultContract,
        provenance_id: str,
    ) -> EvidenceIdentity:
        try:
            contract_hash = contract.integrity_hash()
        except ResultContractError as exc:
            raise EvidenceProvenanceError("expected-result contract is invalid") from exc
        return EvidenceIdentity(
            task_id=task_id,
            operation_id=operation_id,
            attempt_id=attempt_id,
            fence=fence,
            evidence_hash=evidence_hash,
            contract_hash=contract_hash,
            provenance_id=provenance_id,
        )

    def bind(
        self,
        *,
        task_id: str,
        operation_id: str,
        attempt_id: str,
        fence: int,
        evidence_hash: str,
        contract: ExpectedResultContract,
        provenance_id: str,
    ) -> EvidenceIdentity:
        identity = self._build_identity(
            task_id=task_id,
            operation_id=operation_id,
            attempt_id=attempt_id,
            fence=fence,
            evidence_hash=evidence_hash,
            contract=contract,
            provenance_id=provenance_id,
        )
        previous = self._accepted.get(identity.attempt_id)
        if previous is not None and previous != identity.digest():
            raise EvidenceProvenanceError("attempt has conflicting evidence provenance")
        self._accepted[identity.attempt_id] = identity.digest()
        return identity

    def verify(
        self,
        *,
        identity: EvidenceIdentity,
        task_id: str,
        operation_id: str,
        attempt_id: str,
        fence: int,
        evidence_hash: str,
        contract: ExpectedResultContract,
        provenance_id: str,
    ) -> None:
        """Verify without mutating the accepted binding registry."""
        expected = self._build_identity(
            task_id=task_id,
            operation_id=operation_id,
            attempt_id=attempt_id,
            fence=fence,
            evidence_hash=evidence_hash,
            contract=contract,
            provenance_id=provenance_id,
        )
        accepted_digest = self._accepted.get(identity.attempt_id)
        if accepted_digest != identity.digest() or identity != expected:
            raise EvidenceProvenanceError("evidence identity or provenance mismatch")

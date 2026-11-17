"""Immutable expected-result and evidence requirements for Nova P0.1."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Tuple


class ResultContractError(ValueError):
    """Raised when an expected-result contract is unsafe or ambiguous."""


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResultContractError(f"{field} is required")
    return value.strip()


def _canonical(payload: object) -> bytes:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ResultContractError("contract is not canonically serializable") from exc


@dataclass(frozen=True)
class EvidenceRequirement:
    """One objectively identifiable requirement for evidence supporting a result."""

    criterion_id: str
    description: str
    evidence_type: str
    provenance_required: bool
    verification_method: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "criterion_id", _text(self.criterion_id, "criterion_id"))
        object.__setattr__(self, "description", _text(self.description, "description"))
        object.__setattr__(self, "evidence_type", _text(self.evidence_type, "evidence_type"))
        object.__setattr__(self, "verification_method", _text(self.verification_method, "verification_method"))
        if not isinstance(self.provenance_required, bool):
            raise ResultContractError("provenance_required must be boolean")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "criterion_id": self.criterion_id,
            "description": self.description,
            "evidence_type": self.evidence_type,
            "provenance_required": self.provenance_required,
            "verification_method": self.verification_method,
        }


@dataclass(frozen=True)
class ExpectedResultContract:
    """Immutable, versioned contract defining what a successful result must establish."""

    contract_version: int
    objective: str
    expected_result: str
    result_type: str
    evidence_requirements: Tuple[EvidenceRequirement, ...]
    verification_method: str
    failure_semantics: str
    uncertainty_semantics: str
    recovery_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.contract_version, int) or isinstance(self.contract_version, bool) or self.contract_version < 1:
            raise ResultContractError("contract_version must be a positive integer")
        for field in (
            "objective", "expected_result", "result_type", "verification_method",
            "failure_semantics", "uncertainty_semantics", "recovery_path",
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        requirements = tuple(self.evidence_requirements)
        if not requirements:
            raise ResultContractError("at least one evidence requirement is required")
        if any(not isinstance(item, EvidenceRequirement) for item in requirements):
            raise ResultContractError("evidence_requirements must contain EvidenceRequirement values")
        ids = [item.criterion_id for item in requirements]
        if len(ids) != len(set(ids)):
            raise ResultContractError("evidence requirement criterion_id values must be unique")
        object.__setattr__(self, "evidence_requirements", requirements)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "objective": self.objective,
            "expected_result": self.expected_result,
            "result_type": self.result_type,
            "evidence_requirements": [item.canonical_dict() for item in self.evidence_requirements],
            "verification_method": self.verification_method,
            "failure_semantics": self.failure_semantics,
            "uncertainty_semantics": self.uncertainty_semantics,
            "recovery_path": self.recovery_path,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.canonical_dict())

    def integrity_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

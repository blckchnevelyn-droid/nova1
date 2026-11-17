"""Adversarial tests for Nova P0.1 expected-result contracts."""
from __future__ import annotations

import dataclasses
import json

import pytest

from nova.result_contract import EvidenceRequirement, ExpectedResultContract, ResultContractError


def requirement(criterion_id: str = "observed") -> EvidenceRequirement:
    return EvidenceRequirement(
        criterion_id=criterion_id,
        description="The required observable result is present.",
        evidence_type="structured-observation",
        provenance_required=True,
        verification_method="independent-check",
    )


def contract(*requirements: EvidenceRequirement) -> ExpectedResultContract:
    return ExpectedResultContract(
        contract_version=1,
        objective="produce the authorized result",
        expected_result="the authorized result is demonstrably present",
        result_type="deterministic",
        evidence_requirements=requirements or (requirement(),),
        verification_method="independent-check",
        failure_semantics="FAILED when any mandatory criterion is absent or disproved",
        uncertainty_semantics="INCONCLUSIVE when required evidence cannot be established",
        recovery_path="ESCALATE for unresolved or conflicting evidence",
    )


def test_contract_is_immutable_and_canonical_hash_is_stable() -> None:
    value = contract()
    assert dataclasses.is_dataclass(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.expected_result = "tampered"  # type: ignore[misc]
    assert value.integrity_hash() == value.integrity_hash()
    assert json.loads(value.canonical_bytes()) == value.canonical_dict()


def test_missing_requirement_is_rejected() -> None:
    with pytest.raises(ResultContractError, match="at least one evidence requirement"):
        ExpectedResultContract(
            contract_version=1,
            objective="objective",
            expected_result="expected",
            result_type="deterministic",
            evidence_requirements=(),
            verification_method="check",
            failure_semantics="fail",
            uncertainty_semantics="inconclusive",
            recovery_path="escalate",
        )


def test_duplicate_criteria_are_rejected() -> None:
    with pytest.raises(ResultContractError, match="unique"):
        contract(requirement("same"), requirement("same"))


def test_empty_required_fields_are_rejected() -> None:
    with pytest.raises(ResultContractError):
        EvidenceRequirement("", "description", "type", True, "check")
    with pytest.raises(ResultContractError):
        ExpectedResultContract(
            1, "objective", "", "deterministic", (requirement(),),
            "check", "fail", "inconclusive", "escalate"
        )


def test_invalid_requirement_types_are_rejected() -> None:
    with pytest.raises(ResultContractError, match="EvidenceRequirement"):
        ExpectedResultContract(
            1, "objective", "expected", "deterministic", ("not-a-requirement",),
            "check", "fail", "inconclusive", "escalate"
        )


def test_non_boolean_provenance_flag_is_rejected() -> None:
    with pytest.raises(ResultContractError, match="boolean"):
        EvidenceRequirement("criterion", "description", "type", "yes", "check")  # type: ignore[arg-type]


def test_contract_hash_changes_when_acceptance_criteria_change() -> None:
    first = contract(requirement("criterion-a"))
    changed = ExpectedResultContract(
        contract_version=1,
        objective=first.objective,
        expected_result=first.expected_result,
        result_type=first.result_type,
        evidence_requirements=(EvidenceRequirement(
            "criterion-a", "A different requirement", "structured-observation", True, "independent-check"
        ),),
        verification_method=first.verification_method,
        failure_semantics=first.failure_semantics,
        uncertainty_semantics=first.uncertainty_semantics,
        recovery_path=first.recovery_path,
    )
    assert first.integrity_hash() != changed.integrity_hash()


def test_requirement_order_is_preserved_and_part_of_contract_identity() -> None:
    first = contract(requirement("a"), requirement("b"))
    reordered = contract(requirement("b"), requirement("a"))
    assert [x.criterion_id for x in first.evidence_requirements] == ["a", "b"]
    assert first.integrity_hash() != reordered.integrity_hash()


def test_semantic_contract_does_not_equate_verified_with_correct() -> None:
    value = contract()
    assert "VERIFIED" not in value.expected_result
    assert value.verification_method != "proof-of-signature-only"

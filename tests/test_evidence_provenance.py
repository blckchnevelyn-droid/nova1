from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from nova.evidence_provenance import EvidenceIdentity, EvidenceProvenanceError, EvidenceProvenanceGate
from nova.result_contract import EvidenceRequirement, ExpectedResultContract


def contract() -> ExpectedResultContract:
    return ExpectedResultContract(
        contract_version=1,
        objective="deploy exact release",
        expected_result="release is deployed and independently observable",
        result_type="deployment",
        evidence_requirements=(
            EvidenceRequirement(
                criterion_id="deployment-visible",
                description="deployment is observable at the required endpoint",
                evidence_type="http-observation",
                provenance_required=True,
                verification_method="independent-http-check",
            ),
        ),
        verification_method="independent-http-check",
        failure_semantics="reject incomplete or conflicting evidence",
        uncertainty_semantics="inconclusive when required evidence is unavailable",
        recovery_path="rollback deployment",
    )


def identity(**overrides: object) -> EvidenceIdentity:
    values: dict[str, object] = {
        "task_id": "task-1",
        "operation_id": "operation-1",
        "attempt_id": "attempt-1",
        "fence": 1,
        "evidence_hash": "a" * 64,
        "contract_hash": contract().integrity_hash(),
        "provenance_id": "probe-1",
    }
    values.update(overrides)
    return EvidenceIdentity(**values)  # type: ignore[arg-type]


def test_identity_is_immutable_and_digest_stable() -> None:
    item = identity()
    assert item.digest() == identity().digest()
    with pytest.raises(FrozenInstanceError):
        item.task_id = "task-2"  # type: ignore[misc]


def test_rejects_cross_task_identity() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-2", operation_id="operation-1", attempt_id="attempt-1",
                    fence=1, evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")


def test_rejects_cross_operation_identity() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-1", operation_id="operation-2", attempt_id="attempt-1",
                    fence=1, evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")


def test_rejects_stale_attempt_fence() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-1", operation_id="operation-1", attempt_id="attempt-1",
                    fence=2, evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")


def test_rejects_evidence_hash_substitution() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-1", operation_id="operation-1", attempt_id="attempt-1",
                    fence=1, evidence_hash="b" * 64, contract=contract(), provenance_id="probe-1")


def test_rejects_contract_substitution() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    changed = ExpectedResultContract(
        contract_version=1, objective="different objective", expected_result="release is deployed",
        result_type="deployment", evidence_requirements=contract().evidence_requirements,
        verification_method="independent-http-check", failure_semantics="reject incomplete or conflicting evidence",
        uncertainty_semantics="inconclusive when required evidence is unavailable", recovery_path="rollback deployment")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-1", operation_id="operation-1", attempt_id="attempt-1",
                    fence=1, evidence_hash="a" * 64, contract=changed, provenance_id="probe-1")


def test_rejects_provenance_substitution() -> None:
    gate = EvidenceProvenanceGate()
    bound = gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                      evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="mismatch"):
        gate.verify(identity=bound, task_id="task-1", operation_id="operation-1", attempt_id="attempt-1",
                    fence=1, evidence_hash="a" * 64, contract=contract(), provenance_id="probe-2")


def test_rejects_conflicting_binding_for_same_attempt() -> None:
    gate = EvidenceProvenanceGate()
    gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
              evidence_hash="a" * 64, contract=contract(), provenance_id="probe-1")
    with pytest.raises(EvidenceProvenanceError, match="conflicting"):
        gate.bind(task_id="task-1", operation_id="operation-1", attempt_id="attempt-1", fence=1,
                  evidence_hash="b" * 64, contract=contract(), provenance_id="probe-1")


def test_rejects_invalid_hash_shape() -> None:
    with pytest.raises(EvidenceProvenanceError, match="SHA-256"):
        identity(evidence_hash="not-a-digest")


def test_rejects_invalid_fence() -> None:
    with pytest.raises(EvidenceProvenanceError, match="positive integer"):
        identity(fence=0)


def test_contract_hash_is_bound_to_identity() -> None:
    first = identity()
    second = identity(contract_hash="b" * 64)
    assert first.digest() != second.digest()


def test_unknown_provenance_cannot_be_empty() -> None:
    with pytest.raises(EvidenceProvenanceError, match="provenance_id is required"):
        identity(provenance_id="")

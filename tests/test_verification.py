"""Adversarial contracts for Nova's independent completion verification boundary."""

import base64
import json
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.verification import (
    CompletionProof, VerificationError, VerificationGate, TrustedVerifierKey,
    canonical_completion,
)

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def _gate():
    private = Ed25519PrivateKey.generate()
    gate = VerificationGate(lambda proof: proof.resulting_state_hash == proof.expected_postcondition_hash)
    gate.register_trusted_key(TrustedVerifierKey(
        verifier_id="verifier-1", algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1)))
    return gate, private


def _proof(private, **overrides):
    values = {
        "task_id": "task-1", "expected_revision": 3, "operation_id": "op-1",
        "attempt_id": "attempt-1", "evidence_hash": "evidence-1",
        "expected_postcondition_hash": hashlib.sha256(b"postcondition-1").hexdigest(),
        "resulting_state_hash": hashlib.sha256(b"postcondition-1").hexdigest(),
        "decision": "VERIFIED", "verifier_id": "verifier-1", "issued_at": NOW,
    }
    values.update(overrides)
    payload = canonical_completion(**values)
    signature = base64.b64encode(private.sign(payload)).decode()
    return CompletionProof(**values, signature=signature)


def test_valid_independent_completion_proof_is_accepted():
    gate, private = _gate()
    assert gate.verify(_proof(private), now=NOW) 


def test_forged_evidence_is_rejected():
    gate, private = _gate()
    proof = _proof(private, evidence_hash="different-evidence")
    forged = CompletionProof(**{**proof.__dict__, "evidence_hash": "forged"})
    with pytest.raises(VerificationError):
        gate.verify(forged, now=NOW)


def test_modified_revision_is_rejected():
    gate, private = _gate()
    proof = _proof(private)
    modified = CompletionProof(**{**proof.__dict__, "expected_revision": 4})
    with pytest.raises(VerificationError):
        gate.verify(modified, now=NOW)


def test_unknown_verifier_is_rejected():
    gate, private = _gate()
    proof = _proof(private, verifier_id="untrusted")
    with pytest.raises(VerificationError):
        gate.verify(proof, now=NOW)


def test_revoked_verifier_is_rejected():
    gate, private = _gate()
    gate.revoke_key("verifier-1")
    with pytest.raises(VerificationError):
        gate.verify(_proof(private), now=NOW)


def test_rejected_decision_cannot_complete():
    gate, private = _gate()
    with pytest.raises(VerificationError, match="not successful"):
        gate.verify(_proof(private, decision="REJECTED"), now=NOW)


def test_future_dated_proof_is_rejected():
    gate, private = _gate()
    future = NOW + timedelta(minutes=5)
    with pytest.raises(VerificationError):
        gate.verify(_proof(private, issued_at=future), now=NOW)


def test_conflicting_provenance_for_same_attempt_is_rejected():
    gate, private = _gate()
    gate.verify(_proof(private), now=NOW)
    second = _proof(private, evidence_hash="other")
    with pytest.raises(VerificationError, match="conflicting"):
        gate.verify(second, now=NOW)


def test_signature_cannot_be_reused_after_task_binding_changes():
    gate, private = _gate()
    proof = _proof(private)
    modified = CompletionProof(**{**proof.__dict__, "task_id": "task-2"})
    with pytest.raises(VerificationError):
        gate.verify(modified, now=NOW)


def test_signature_cannot_be_reused_after_attempt_binding_changes():
    gate, private = _gate()
    proof = _proof(private)
    modified = CompletionProof(**{**proof.__dict__, "attempt_id": "attempt-2"})
    with pytest.raises(VerificationError):
        gate.verify(modified, now=NOW)


def test_missing_binding_is_rejected():
    with pytest.raises(VerificationError):
        canonical_completion(task_id="", expected_revision=3, operation_id="op", attempt_id="a",
                             evidence_hash="e", expected_postcondition_hash="p", resulting_state_hash="r",
                             decision="VERIFIED", verifier_id="v", issued_at=NOW)


def test_unsigned_completion_is_rejected():
    gate, _ = _gate()
    proof = CompletionProof(task_id="task-1", expected_revision=3, operation_id="op-1",
                            attempt_id="attempt-1", evidence_hash="evidence-1",
                            expected_postcondition_hash=hashlib.sha256(b"postcondition-1").hexdigest(),
                            resulting_state_hash=hashlib.sha256(b"postcondition-1").hexdigest(),
                            decision="VERIFIED", verifier_id="verifier-1", issued_at=NOW,
                            signature="not-a-signature")
    with pytest.raises(VerificationError):
        gate.verify(proof, now=NOW)

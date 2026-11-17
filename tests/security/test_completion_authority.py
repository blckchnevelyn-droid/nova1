"""Adversarial tests for proof-bound durable completion."""

import base64
import hashlib
import sqlite3
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import State, ValidationError
from nova.execution import AttemptState
from nova.verification import CompletionProof, TrustedVerifierKey, VerificationGate, canonical_completion
from tests.governed_fixtures import NOW, governed_execution, governed_task


def prepared_completion():
    store, task = governed_task()
    task, execution, _, auth = governed_execution(store, task)
    operation = execution.identify_operation(task_id=task.task_id, idempotency_key="completion-1", action="write",
                                             scope=task.objective, specification={"path": "verified"}, now=NOW,
                                             authorization=auth, tool="filesystem.write")
    attempt = execution.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    attempt = execution.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                              authorization=auth, tool="filesystem.write")
    attempt = execution.record_outcome(attempt_id=attempt.attempt_id, worker_id="worker-1", fence=attempt.fence,
                                        state=AttemptState.SUCCEEDED, now=NOW + timedelta(seconds=1),
                                        result_evidence="durable-success", authorization=auth,
                                        tool="filesystem.write")
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.OBSERVING, now=NOW + timedelta(seconds=2))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.VERIFYING, now=NOW + timedelta(seconds=3))
    private = Ed25519PrivateKey.generate()
    expected_postcondition_hash = dict((k, __import__("json").loads(v)) for k, v in auth.limits)["postcondition_hash"]
    trusted_resulting_state = {
        (task.task_id, operation.operation_id, attempt.attempt_id): expected_postcondition_hash
    }
    gate = VerificationGate(
        lambda proof: trusted_resulting_state.get(
            (proof.task_id, proof.operation_id, proof.attempt_id)
        ) == proof.resulting_state_hash
    )
    gate.register_trusted_key(TrustedVerifierKey(
        verifier_id="verifier-1", algorithm="Ed25519", public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1)))
    values = dict(task_id=task.task_id, expected_revision=task.revision, operation_id=operation.operation_id,
                  attempt_id=attempt.attempt_id, evidence_hash=attempt.evidence_hash,
                  expected_postcondition_hash=expected_postcondition_hash,
                  resulting_state_hash=expected_postcondition_hash,
                  decision="VERIFIED", verifier_id="verifier-1",
                  issued_at=NOW + timedelta(seconds=4))
    signature = base64.b64encode(private.sign(canonical_completion(**values))).decode()
    proof = CompletionProof(**values, signature=signature)
    return store, task, operation, attempt, gate, proof, private


def test_plain_verified_string_is_rejected():
    store, task = governed_task()
    task, _, _, _ = governed_execution(store, task)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.OBSERVING, now=NOW)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.VERIFYING, now=NOW)
    with pytest.raises(ValidationError, match="verification string"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW, verification="VERIFIED")


def test_valid_completion_proof_is_required_and_commits():
    store, task, _, _, gate, proof, _ = prepared_completion()
    completed = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                           target=State.COMPLETED, now=NOW + timedelta(seconds=5),
                                           completion_proof=proof, verification_gate=gate)
    assert completed.state is State.COMPLETED
    assert completed.verification == "VERIFIED"
    assert completed.revision == 4
    assert store._db.execute("SELECT COUNT(*) FROM completion_proofs").fetchone()[0] == 1


def test_forged_signature_cannot_complete():
    store, task, _, _, gate, proof, _ = prepared_completion()
    forged = CompletionProof(**{**proof.__dict__, "evidence_hash": "forged"})
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW + timedelta(seconds=5), completion_proof=forged, verification_gate=gate)


def test_completion_proof_must_match_current_revision():
    store, task, _, _, gate, proof, _ = prepared_completion()
    stale = CompletionProof(**{**proof.__dict__, "expected_revision": proof.expected_revision - 1})
    with pytest.raises(ValidationError, match="authoritative task revision"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW + timedelta(seconds=5), completion_proof=stale, verification_gate=gate)


def test_completion_proof_must_bind_to_succeeded_attempt():
    store, task, _, attempt, gate, proof, _ = prepared_completion()
    store._db.execute("DROP TRIGGER execution_terminal_attempt_no_update")
    store._db.execute("UPDATE execution_attempts SET evidence_hash='tampered' WHERE attempt_id=?", (attempt.attempt_id,))
    with pytest.raises(ValidationError, match="evidence binding"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW + timedelta(seconds=5), completion_proof=proof, verification_gate=gate)


def test_revoked_verifier_cannot_complete():
    store, task, _, _, gate, proof, _ = prepared_completion()
    gate.revoke_key("verifier-1")
    with pytest.raises(ValidationError, match="trusted"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW + timedelta(seconds=5), completion_proof=proof, verification_gate=gate)


def test_completion_proof_record_is_immutable():
    store, task, _, _, gate, proof, _ = prepared_completion()
    store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                               now=NOW + timedelta(seconds=5), completion_proof=proof, verification_gate=gate)
    with pytest.raises(sqlite3.IntegrityError, match="completion proofs are immutable"):
        store._db.execute("UPDATE completion_proofs SET decision='REJECTED' WHERE proof_digest=?",
                          (store._db.execute("SELECT proof_digest FROM completion_proofs").fetchone()[0],))


def test_false_resulting_state_cannot_complete():
    store, task, operation, attempt, _, proof, private = prepared_completion()
    bad_gate = VerificationGate(lambda _: False)
    bad_gate.register_trusted_key(TrustedVerifierKey(
        verifier_id="verifier-1", algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1),
    ))
    forged_values = dict(proof.__dict__)
    forged_values.pop("signature")
    forged_values["resulting_state_hash"] = hashlib.sha256(b"wrong-state").hexdigest()
    signature = base64.b64encode(private.sign(canonical_completion(**forged_values))).decode()
    forged = CompletionProof(**forged_values, signature=signature)
    with pytest.raises(ValidationError, match="post-condition"):
        store.authorize_transition(
            task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
            now=NOW + timedelta(seconds=5), completion_proof=forged, verification_gate=bad_gate,
        )


def test_missing_independent_resulting_state_verifier_fails_closed():
    store, task, operation, attempt, _, proof, _ = prepared_completion()
    private = Ed25519PrivateKey.generate()
    gate = VerificationGate()
    gate.register_trusted_key(TrustedVerifierKey(
        verifier_id="verifier-2", algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1),
    ))
    values = dict(proof.__dict__)
    values["verifier_id"] = "verifier-2"
    values.pop("signature")
    signature = base64.b64encode(private.sign(canonical_completion(**values))).decode()
    unbound = CompletionProof(**values, signature=signature)
    with pytest.raises(ValidationError, match="independent resulting-state verifier"):
        store.authorize_transition(
            task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
            now=NOW + timedelta(seconds=5), completion_proof=unbound, verification_gate=gate,
        )

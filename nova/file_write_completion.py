"""Independent completion for the file-write pilot.

The verifier is a separate principal with its own Ed25519 key. At verification time it
re-observes the target itself. The trusted expected digest comes from the durable operation
record, never from the pilot's claim. The kernel accepts completion only through the
VerificationGate and the authoritative task state machine.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from typing import Optional

from .authority import State, ValidationError
from .execution import AttemptState
from .file_write_pilot import parse_outcome
from .file_write_sandbox import SandboxConflict, SandboxError, SandboxRoot, normalize_relative_path
from .verification import CompletionProof, TrustedVerifierKey, VerificationGate, canonical_completion


class IndependentFileVerifier:
    """Observes the target itself and signs completion proofs with a key the executor does not hold."""

    def __init__(self, *, verifier_id: str, private_key, sandbox: SandboxRoot, store,
                 valid_from: datetime, valid_until: Optional[datetime]) -> None:
        self._verifier_id = verifier_id
        self._private = private_key
        self._sandbox = sandbox
        self._db = store._db
        self.gate = VerificationGate(self._resulting_state_holds)
        self.gate.register_trusted_key(TrustedVerifierKey(
            verifier_id=verifier_id, algorithm="Ed25519",
            public_key=private_key.public_key().public_bytes_raw(),
            valid_from=valid_from, valid_until=valid_until))

    def _resulting_state_holds(self, proof: CompletionProof) -> bool:
        operation = self._db.execute(
            "SELECT canonical_operation FROM execution_operations WHERE operation_id=?",
            (proof.operation_id,)).fetchone()
        attempt = self._db.execute(
            "SELECT state, result_evidence FROM execution_attempts WHERE attempt_id=?",
            (proof.attempt_id,)).fetchone()
        if operation is None or attempt is None or attempt["state"] != AttemptState.SUCCEEDED.value:
            return False
        expected = json.loads(operation["canonical_operation"])["specification"]["sha256"]
        record = parse_outcome(attempt["result_evidence"])
        try:
            observed = self._sandbox.observe(normalize_relative_path(record["relative_path"]))
        except (SandboxError, SandboxConflict, OSError):
            return False
        return (observed is not None and observed.sha256 == expected
                and proof.resulting_state_hash == expected
                and proof.expected_postcondition_hash == expected)

    def prove(self, *, task, operation_id: str, attempt_id: str, evidence_hash: str,
              expected_postcondition_hash: str, resulting_state_hash: str, now: datetime) -> CompletionProof:
        values = dict(task_id=task.task_id, expected_revision=task.revision, operation_id=operation_id,
                      attempt_id=attempt_id, evidence_hash=evidence_hash,
                      expected_postcondition_hash=expected_postcondition_hash,
                      resulting_state_hash=resulting_state_hash, decision="VERIFIED",
                      verifier_id=self._verifier_id, issued_at=now)
        signature = base64.b64encode(self._private.sign(canonical_completion(**values))).decode("ascii")
        return CompletionProof(**values, signature=signature)


def complete_task(*, store, boundary, verifier: IndependentFileVerifier, task_id: str, now: datetime):
    """Drive EXECUTING -> OBSERVING -> VERIFYING -> COMPLETED using only independently verified proof."""
    task = store.read_task(task_id)
    if task.state is State.COMPLETED:
        return task
    row = store._db.execute(
        "SELECT attempt_id, operation_id, evidence_hash FROM execution_attempts "
        "WHERE task_id=? AND state=? ORDER BY rowid DESC LIMIT 1",
        (task_id, AttemptState.SUCCEEDED.value)).fetchone()
    if row is None:
        raise ValidationError("no successful attempt is available to complete")
    attempt = boundary.read_attempt(row["attempt_id"])  # keyed evidence check before anything is signed
    operation = boundary.read_operation(row["operation_id"])
    expected = json.loads(store._db.execute(
        "SELECT canonical_operation FROM execution_operations WHERE operation_id=?",
        (operation.operation_id,)).fetchone()[0])["specification"]["sha256"]
    task = store.authorize_transition(task_id=task_id, expected_revision=task.revision,
                                      target=State.OBSERVING, now=now)
    task = store.authorize_transition(task_id=task_id, expected_revision=task.revision,
                                      target=State.VERIFYING, now=now)
    proof = verifier.prove(task=task, operation_id=operation.operation_id, attempt_id=attempt.attempt_id,
                           evidence_hash=attempt.evidence_hash, expected_postcondition_hash=expected,
                           resulting_state_hash=expected, now=now)
    return store.authorize_transition(task_id=task_id, expected_revision=task.revision, target=State.COMPLETED,
                                      now=now + timedelta(seconds=1), completion_proof=proof,
                                      verification_gate=verifier.gate)

import sqlite3
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.audit_checkpoint import (
    ALGORITHM,
    AuditCheckpointSigner,
    AuditCheckpointVerifier,
    CheckpointError,
    compare_checkpoint_to_events,
)
from nova.authority import State
from nova.persistence import SQLiteAuthorityStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_store(tmp_path):
    return SQLiteAuthorityStore(str(tmp_path / "nova.db"))


def make_history(store):
    task = store.create_task(
        objective="authorized-objective", authority_context="principal:user-1",
        governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
    )
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    return task.task_id


def checkpoint_for(store, task_id, signer, previous="0" * 64):
    events = store.audit_events(task_id)
    head = store.verify_audit_chain(task_id)
    return signer.sign(
        task_id=task_id, event_count=len(events), chain_head=head,
        issued_at=NOW.isoformat(), previous_checkpoint_hash=previous,
    )


def test_signed_checkpoint_detects_full_rewrite_after_chain_recomputation(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task_id = make_history(store)
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = checkpoint_for(store, task_id, signer)
    verifier = AuditCheckpointVerifier({"audit-key-v1": signer.public_key})
    verifier.verify(checkpoint)
    store.close()

    connection = sqlite3.connect(str(db_path))
    connection.execute("DROP TRIGGER audit_events_no_update")
    rows = connection.execute("SELECT * FROM audit_events WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
    previous = "0" * 64
    for row in rows:
        forged_detail = "forged history" if row[2] == "TASK_CREATED" else row[9]
        # An attacker can recompute the legacy SHA-256 chain, but cannot forge
        # the keyed durable HMAC used by the authoritative store.
        forged_hash = SQLiteAuthorityStore._audit_payload(
            event_id=row[0], task_id=row[1], event_type=row[2], timestamp=row[3],
            expected_revision=row[4], resulting_revision=row[5], authority_context=row[6],
            policy_version=row[7], approval_id=row[8], detail=forged_detail, previous_hash=previous,
        ).hex()
        connection.execute(
            "UPDATE audit_events SET detail=?, previous_hash=?, event_hash=? WHERE event_id=?",
            (forged_detail, previous, forged_hash, row[0]),
        )
        previous = forged_hash
    connection.commit()
    connection.close()

    reopened = make_store(tmp_path)
    with pytest.raises(Exception, match="audit chain integrity check failed"):
        reopened.audit_events(task_id)
    reopened.close()


def test_signed_checkpoint_detects_tail_truncation(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task_id = make_history(store)
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = checkpoint_for(store, task_id, signer)
    store.close()

    connection = sqlite3.connect(str(db_path))
    connection.execute("DROP TRIGGER audit_events_no_delete")
    connection.execute(
        "DELETE FROM audit_events WHERE event_id=(SELECT event_id FROM audit_events WHERE task_id=? ORDER BY rowid DESC LIMIT 1)",
        (task_id,),
    )
    connection.commit()
    connection.close()

    reopened = make_store(tmp_path)
    with pytest.raises(CheckpointError, match="event-count mismatch"):
        compare_checkpoint_to_events(checkpoint, reopened.audit_events(task_id),
                                     chain_head=reopened.verify_audit_chain(task_id))
    reopened.close()


def test_checkpoint_head_substitution_and_signature_mismatch_fail_closed(tmp_path):
    store = make_store(tmp_path)
    task_id = make_history(store)
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = checkpoint_for(store, task_id, signer)
    verifier = AuditCheckpointVerifier({"audit-key-v1": signer.public_key})
    verifier.verify(checkpoint)

    forged = checkpoint.to_dict()
    forged["chain_head"] = "f" * 64
    substituted = type(checkpoint).from_dict(forged)
    with pytest.raises(CheckpointError, match="signature verification failed"):
        verifier.verify(substituted)

    forged_signature = checkpoint.to_dict()
    forged_signature["signature"] = "A" * len(checkpoint.signature)
    bad_signature = type(checkpoint).from_dict(forged_signature)
    with pytest.raises(CheckpointError, match="signature verification failed"):
        verifier.verify(bad_signature)
    store.close()


def test_checkpoint_key_rotation_preserves_continuity(tmp_path):
    store = make_store(tmp_path)
    task_id = make_history(store)
    first_signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    second_signer = AuditCheckpointSigner(key_id="audit-key-v2", private_key=Ed25519PrivateKey.generate())
    first = checkpoint_for(store, task_id, first_signer)
    second = checkpoint_for(store, task_id, second_signer, previous=first.digest())
    verifier = AuditCheckpointVerifier({
        "audit-key-v1": first_signer.public_key,
        "audit-key-v2": second_signer.public_key,
    })
    verifier.verify_chain([first, second])

    broken = type(second).from_dict(second.to_dict() | {"previous_checkpoint_hash": "0" * 64})
    with pytest.raises(CheckpointError, match="continuity verification failed"):
        verifier.verify_chain([first, broken])
    store.close()


def test_untrusted_key_and_algorithm_fail_closed(tmp_path):
    store = make_store(tmp_path)
    task_id = make_history(store)
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = checkpoint_for(store, task_id, signer)
    with pytest.raises(CheckpointError, match="signing key is not trusted"):
        AuditCheckpointVerifier({}).verify(checkpoint)
    forged = checkpoint.to_dict() | {"algorithm": "UNTRUSTED"}
    with pytest.raises(CheckpointError, match="unsupported checkpoint format"):
        type(checkpoint).from_dict(forged)
    assert checkpoint.algorithm == ALGORITHM
    store.close()

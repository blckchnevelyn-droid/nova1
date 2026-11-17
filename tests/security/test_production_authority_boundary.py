import sqlite3
from datetime import timedelta

import pytest

from nova.authority import State
from nova.persistence import SQLiteAuthorityStore

from tests.governed_fixtures import NOW


def make_store(tmp_path):
    return SQLiteAuthorityStore(str(tmp_path / "nova.db"))


def test_production_store_blocks_direct_completion_without_proof(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="production-completion-boundary",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    store.close()

    connection = sqlite3.connect(str(db_path))
    with pytest.raises(sqlite3.IntegrityError, match="COMPLETED requires durable completion proof"):
        connection.execute(
            "UPDATE tasks SET state=? WHERE task_id=?",
            (State.COMPLETED.value, task.task_id),
        )
    connection.rollback()
    state = connection.execute(
        "SELECT state FROM tasks WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]
    connection.close()

    assert state == State.CREATED


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("objective", "attacker-objective"),
        ("authority_context", "principal:attacker"),
        ("policy_version", "policy-attacker"),
        ("governance_decision", "DENIED"),
        ("approval_required", 1),
        ("created_at", "2099-01-01T00:00:00+00:00"),
    ],
)
def test_production_store_blocks_direct_authority_identity_mutation(tmp_path, column, value):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="bound-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    store.close()

    connection = sqlite3.connect(str(db_path))
    with pytest.raises(sqlite3.IntegrityError, match="task authority identity is immutable"):
        connection.execute(
            f"UPDATE tasks SET {column}=? WHERE task_id=?",
            (value, task.task_id),
        )
    connection.rollback()
    restored = connection.execute(
        "SELECT objective, authority_context, policy_version FROM tasks WHERE task_id=?",
        (task.task_id,),
    ).fetchone()
    connection.close()

    assert restored == ("bound-objective", "principal:user-1", "policy-v1")


def test_production_store_blocks_direct_synthetic_completion_proof_insertion(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="completion-proof-binding",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    store.close()

    connection = sqlite3.connect(str(db_path))
    with pytest.raises(sqlite3.OperationalError, match="no such function: nova_completion_proof_write_allowed"):
        connection.execute(
            "INSERT INTO completion_proofs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "synthetic-proof",
                task.task_id,
                task.revision,
                "operation",
                "attempt",
                "evidence",
                "verifier",
                NOW.isoformat(),
                "VERIFIED",
                "expected-postcondition",
                "resulting-state",
                "forged",
            ),
        )
    connection.rollback()
    proof_count = connection.execute(
        "SELECT COUNT(*) FROM completion_proofs WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]
    state = connection.execute(
        "SELECT state FROM tasks WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]
    connection.close()

    assert proof_count == 0
    assert state == State.CREATED


def test_production_store_keeps_audit_chain_detection_after_direct_trigger_attack(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="audit-defense-in-depth",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    event_id = store.audit_events(task.task_id)[0].event_id
    store.close()

    connection = sqlite3.connect(str(db_path))
    connection.execute("DROP TRIGGER audit_events_no_update")
    connection.execute(
        "UPDATE audit_events SET detail='forged' WHERE event_id=?", (event_id,)
    )
    connection.commit()
    connection.close()

    reopened = make_store(tmp_path)
    with pytest.raises(Exception, match="audit chain integrity check failed"):
        reopened.audit_events(task.task_id)
    reopened.close()



def test_production_store_detects_udf_substitution_after_synthetic_completion(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="udf-substitution",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    store.close()

    connection = sqlite3.connect(str(db_path))
    connection.create_function("nova_completion_proof_write_allowed", 0, lambda: 1)
    connection.execute(
        "INSERT INTO completion_proofs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("synthetic", task.task_id, task.revision, "operation", "attempt",
         "evidence", "verifier", NOW.isoformat(), "VERIFIED",
         "expected-postcondition", "resulting-state", "forged"),
    )
    connection.execute(
        "UPDATE tasks SET state=?, revision=?, verification=? WHERE task_id=?",
        (State.COMPLETED.value, task.revision + 1, "VERIFIED", task.task_id),
    )
    connection.commit()
    connection.close()

    reopened = make_store(tmp_path)
    with pytest.raises(Exception, match="completed task .*integrity"):
        reopened.read_task(task.task_id)
    reopened.close()


def test_production_store_detects_trigger_drop_direct_completion(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(
        objective="trigger-drop",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    store.close()

    connection = sqlite3.connect(str(db_path))
    connection.execute("DROP TRIGGER tasks_no_unproven_completion")
    connection.execute(
        "UPDATE tasks SET state=?, revision=?, verification=? WHERE task_id=?",
        (State.COMPLETED.value, task.revision + 1, "VERIFIED", task.task_id),
    )
    connection.commit()
    connection.close()

    reopened = make_store(tmp_path)
    with pytest.raises(Exception, match="completed task"):
        reopened.read_task(task.task_id)
    reopened.close()


def test_production_store_detects_completed_state_audit_divergence():
    from tests.security.test_completion_authority import prepared_completion

    store, task, _, _, gate, proof, _ = prepared_completion()
    completed = store.authorize_transition(
        task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
        now=NOW + timedelta(seconds=5), completion_proof=proof, verification_gate=gate,
    )
    assert completed.state is State.COMPLETED

    store._db.execute("DROP TRIGGER audit_events_no_delete")
    store._db.execute(
        "DELETE FROM audit_events WHERE task_id=? AND event_type='STATE_TRANSITION' AND resulting_revision=?",
        (task.task_id, completed.revision),
    )
    with pytest.raises(Exception, match="audit transition"):
        store.read_task(task.task_id)
    store.close()


def test_production_store_detects_tampered_completion_integrity():
    from tests.security.test_completion_authority import prepared_completion

    store, task, _, _, gate, proof, _ = prepared_completion()
    store.authorize_transition(
        task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
        now=NOW + timedelta(seconds=5), completion_proof=proof, verification_gate=gate,
    )
    store._db.execute("DROP TRIGGER completion_proofs_no_update")
    proof_digest = store._db.execute(
        "SELECT proof_digest FROM completion_proofs WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]
    store._db.execute(
        "UPDATE completion_proofs SET evidence_hash='forged' WHERE proof_digest=?",
        (proof_digest,),
    )
    with pytest.raises(Exception, match="proof integrity"):
        store.read_task(task.task_id)
    store.close()

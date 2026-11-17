from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from nova.authority import Approval, ConflictError, State, ValidationError
from nova.persistence import SQLiteAuthorityStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_store(tmp_path):
    return SQLiteAuthorityStore(str(tmp_path / "nova.db"))


def approval(task, approval_id="approval-1", expires_at=None):
    return Approval(approval_id=approval_id, task_id=task.task_id, principal=task.authority_context,
                    decision="ALLOW", scope=task.objective, policy_version=task.policy_version,
                    issued_at=NOW, expires_at=expires_at, provenance="event-1")


def test_task_and_audit_survive_reopen(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW)
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    store.close()
    reopened = make_store(tmp_path)
    restored = reopened.read_task(task.task_id)
    assert restored.state == State.EXECUTING
    assert restored.revision == 1
    assert len(reopened.audit_events(task.task_id)) == 2
    reopened.close()


def test_required_approval_and_audit_survive_reopen(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
                             approval_required=True)
    store.record_approval(approval(task))
    store.close()
    reopened = make_store(tmp_path)
    task = reopened.read_task(task.task_id)
    assert task.approval_ids == ()
    executing = reopened.authorize_transition(task_id=task.task_id, expected_revision=0,
                                               target=State.EXECUTING, now=NOW, approval_id="approval-1")
    assert executing.approval_ids == ("approval-1",)
    assert reopened.audit_events(task.task_id)[-1].approval_id == "approval-1"
    assert reopened._db.execute("SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'").fetchone()[0] == 1
    reopened.close()


def test_approval_consumption_is_durable_and_not_repeated_for_lifecycle_recovery(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
                             approval_required=True)
    store.record_approval(approval(task))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING,
                                      now=NOW, approval_id="approval-1")
    assert store._db.execute("SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'").fetchone()[0] == 1
    task = store.authorize_transition(task_id=task.task_id, expected_revision=1, target=State.OBSERVING,
                                      now=NOW, approval_id="approval-1")
    assert task.revision == 2
    assert store._db.execute("SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'").fetchone()[0] == 1


def test_failed_transition_does_not_consume_approval(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
                             approval_required=True)
    store.record_approval(approval(task))
    with pytest.raises(ValidationError, match="transition .* is not permitted"):
        store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.COMPLETED,
                                   now=NOW, approval_id="approval-1")
    assert store._db.execute("SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'").fetchone()[0] == 0
    task = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING,
                                      now=NOW, approval_id="approval-1")
    assert task.revision == 1
    assert store._db.execute("SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'").fetchone()[0] == 1


def test_stale_revision_is_conflict_and_does_not_mutate(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW)
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    with pytest.raises(ConflictError):
        store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.OBSERVING, now=NOW)
    assert store.read_task(task.task_id).state == State.EXECUTING


def test_plain_verification_string_cannot_complete(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW)
    for revision, target in [(0, State.EXECUTING), (1, State.OBSERVING), (2, State.VERIFYING)]:
        task = store.authorize_transition(task_id=task.task_id, expected_revision=revision, target=target, now=NOW)
    with pytest.raises(ValidationError, match="COMPLETED cannot be authorized by a verification string"):
        store.authorize_transition(task_id=task.task_id, expected_revision=3, target=State.COMPLETED,
                                   now=NOW, verification="VERIFIED")
    assert store.read_task(task.task_id).state == State.VERIFYING


def test_expired_approval_is_rejected_after_reopen(tmp_path):
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
                             approval_required=True)
    store.record_approval(approval(task, expires_at=NOW + timedelta(seconds=1)))
    store.close()
    reopened = make_store(tmp_path)
    with pytest.raises(ValidationError, match="approval has expired"):
        reopened.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING,
                                      now=NOW + timedelta(seconds=1), approval_id="approval-1")
    reopened.close()


def test_audit_events_are_append_only(tmp_path):
    db_path = tmp_path / "nova.db"
    store = SQLiteAuthorityStore(str(db_path))
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW)
    event_id = store.audit_events(task.task_id)[0].event_id
    store.close()
    connection = sqlite3.connect(str(db_path))
    with pytest.raises(sqlite3.IntegrityError, match="audit events are append-only"):
        connection.execute("UPDATE audit_events SET detail='tampered' WHERE event_id=?", (event_id,))
    with pytest.raises(sqlite3.IntegrityError, match="audit events are append-only"):
        connection.execute("DELETE FROM audit_events WHERE event_id=?", (event_id,))
    connection.close()
    reopened = SQLiteAuthorityStore(str(db_path))
    assert reopened.audit_events(task.task_id)[0].event_id == event_id
    assert reopened.audit_events(task.task_id)[0].detail == "task created"
    reopened.close()


def test_audit_chain_detects_privileged_tampering(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW)
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    event_id = store.audit_events(task.task_id)[0].event_id
    store.close()
    connection = sqlite3.connect(str(db_path))
    connection.execute("DROP TRIGGER audit_events_no_update")
    connection.execute("UPDATE audit_events SET detail='forged' WHERE event_id=?", (event_id,))
    connection.commit()
    connection.close()
    reopened = make_store(tmp_path)
    with pytest.raises(ValidationError, match="audit chain integrity check failed"):
        reopened.audit_events(task.task_id)
    reopened.close()


def test_approval_records_and_bindings_are_append_only(tmp_path):
    db_path = tmp_path / "nova.db"
    store = make_store(tmp_path)
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision="ALLOW", policy_version="policy-v1", now=NOW,
                             approval_required=True)
    store.record_approval(approval(task))
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING,
                               now=NOW, approval_id="approval-1")
    store.close()
    connection = sqlite3.connect(str(db_path))
    with pytest.raises(sqlite3.IntegrityError, match="approval records are immutable"):
        connection.execute("UPDATE approvals SET provenance='forged' WHERE approval_id='approval-1'")
    with pytest.raises(sqlite3.IntegrityError, match="approval records are immutable"):
        connection.execute("DELETE FROM approvals WHERE approval_id='approval-1'")
    with pytest.raises(sqlite3.IntegrityError, match="task approval bindings are immutable"):
        connection.execute("DELETE FROM task_approvals WHERE task_id=? AND approval_id=?", (task.task_id, "approval-1"))
    with pytest.raises(sqlite3.IntegrityError, match="approval consumption records are immutable"):
        connection.execute("DELETE FROM approval_consumptions WHERE approval_id='approval-1'")
    connection.close()
    reopened = SQLiteAuthorityStore(str(db_path))
    restored = reopened.read_task(task.task_id)
    assert restored.approval_ids == ("approval-1",)
    reopened.close()


def test_schema_version_is_initialized_and_persists(tmp_path):
    db_path = tmp_path / "nova.db"
    store = SQLiteAuthorityStore(str(db_path))
    assert store._db.execute("PRAGMA user_version").fetchone()[0] == 6
    store.close()
    reopened = make_store(tmp_path)
    assert reopened._db.execute("PRAGMA user_version").fetchone()[0] == 6
    reopened.close()


def test_newer_schema_version_fails_closed(tmp_path):
    db_path = tmp_path / "future.db"
    connection = sqlite3.connect(str(db_path))
    connection.execute("PRAGMA user_version = 999")
    connection.close()
    with pytest.raises(ValidationError, match="unsupported SQLite schema version: 999"):
        SQLiteAuthorityStore(str(db_path))

from datetime import datetime, timezone

import pytest

from nova.authority import Approval, ConflictError, State, ValidationError
from nova.persistence import SQLiteAuthorityStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _authorized_task(store):
    task = store.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
        approval_required=True,
    )
    store.record_approval(Approval(
        approval_id="approval-1",
        task_id=task.task_id,
        principal=task.authority_context,
        decision="ALLOW",
        scope=task.objective,
        policy_version=task.policy_version,
        issued_at=NOW,
        expires_at=None,
        provenance="event-1",
    ))
    return task


def test_stale_writer_cannot_overwrite_authoritative_revision(tmp_path):
    database = str(tmp_path / "nova.db")
    first = SQLiteAuthorityStore(database)
    task = _authorized_task(first)
    second = SQLiteAuthorityStore(database)

    first_view = first.read_task(task.task_id)
    second_view = second.read_task(task.task_id)
    assert first_view.revision == second_view.revision == 0

    first.authorize_transition(
        task_id=task.task_id,
        expected_revision=first_view.revision,
        target=State.EXECUTING,
        now=NOW,
        approval_id="approval-1",
    )

    with pytest.raises(ConflictError, match="stale task revision"):
        second.authorize_transition(
            task_id=task.task_id,
            expected_revision=second_view.revision,
            target=State.EXECUTING,
            now=NOW,
            approval_id="approval-1",
        )

    authoritative = first.read_task(task.task_id)
    assert authoritative.state == State.EXECUTING
    assert authoritative.revision == 1
    assert first._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'"
    ).fetchone()[0] == 1
    first.close()
    second.close()


def test_authority_state_and_consumption_survive_restart(tmp_path):
    database = str(tmp_path / "nova.db")
    store = SQLiteAuthorityStore(database)
    task = _authorized_task(store)

    store.authorize_transition(
        task_id=task.task_id,
        expected_revision=0,
        target=State.EXECUTING,
        now=NOW,
        approval_id="approval-1",
    )
    store.close()

    reopened = SQLiteAuthorityStore(database)
    restored = reopened.read_task(task.task_id)
    assert restored.state == State.EXECUTING
    assert restored.revision == 1
    consumption = reopened._db.execute(
        "SELECT approval_id, task_id, expected_revision, resulting_revision "
        "FROM approval_consumptions WHERE approval_id='approval-1'"
    ).fetchone()
    assert consumption is not None
    assert consumption["task_id"] == task.task_id
    assert consumption["expected_revision"] == 0
    assert consumption["resulting_revision"] == 1
    reopened.close()


def test_persistence_failure_rolls_back_authority_mutation_fail_closed(monkeypatch):
    store = SQLiteAuthorityStore()
    task = _authorized_task(store)

    def fail_audit(*args, **kwargs):
        raise sqlite3.OperationalError("simulated persistence failure")

    import sqlite3
    monkeypatch.setattr(store, "_audit", fail_audit)

    with pytest.raises(sqlite3.OperationalError, match="simulated persistence failure"):
        store.authorize_transition(
            task_id=task.task_id,
            expected_revision=task.revision,
            target=State.EXECUTING,
            now=NOW,
            approval_id="approval-1",
        )

    restored = store.read_task(task.task_id)
    assert restored.state == State.CREATED
    assert restored.revision == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'"
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM audit_events WHERE task_id=? AND event_type='STATE_TRANSITION'",
        (task.task_id,),
    ).fetchone()[0] == 0
    store.close()

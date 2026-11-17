"""Adversarial recovery durability and authority-boundary tests."""

from datetime import datetime, timezone
import os
import sqlite3
import tempfile

import pytest

from nova.authority import State, ValidationError
from nova.execution import AttemptState
from nova.persistence import SQLiteAuthorityStore
from nova.recovery import RecoveryStrategy, SQLiteRecoveryAuthority

from tests.test_execution import setup_boundary, identify

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def _prepare_unknown_recovery():
    store, task, ledger, auth, boundary = setup_boundary()
    operation = identify(boundary, task, auth, key="recovery")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id="w1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW,
                   authorization=auth, tool="filesystem.write")
    boundary.record_outcome(
        attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
        state=AttemptState.UNKNOWN, now=NOW, error_detail="provider timeout",
        authorization=auth, tool="filesystem.write",
    )
    task = store.authorize_transition(
        task_id=task.task_id, expected_revision=task.revision,
        target=State.RECOVERY, now=NOW,
    )
    return store, task, operation, attempt, boundary


def test_recovery_stale_writer_cannot_authorize_after_authority_leaves_recovery():
    store, task, operation, attempt, boundary = _prepare_unknown_recovery()
    first = SQLiteRecoveryAuthority(store, boundary)
    second = SQLiteRecoveryAuthority(store, boundary)

    decision = first.authorize(
        attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile provider outcome", evidence="provider timeout is unresolved", now=NOW,
    )
    assert decision.authoritative_revision == task.revision

    current = store.authorize_transition(
        task_id=task.task_id, expected_revision=task.revision,
        target=State.OBSERVING, now=NOW,
    )
    assert current.revision == task.revision + 1

    with pytest.raises(ValidationError, match="requires task to be in RECOVERY"):
        second.authorize(
            attempt_id=attempt.attempt_id, actor="stale-writer",
            strategy=RecoveryStrategy.RECONCILE,
            rationale="stale recovery authorization", evidence="stale writer", now=NOW,
        )


def test_recovery_decision_does_not_expand_authority_or_consume_approval():
    store, task, operation, attempt, boundary = _prepare_unknown_recovery()
    recovery = SQLiteRecoveryAuthority(store, boundary)
    before = store.read_task(task.task_id)
    approval_count_before = store._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]

    decision = recovery.authorize(
        attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RETRY_IDEMPOTENT,
        rationale="retry only after unresolved outcome", evidence="provider timeout is unresolved", now=NOW,
    )

    after = store.read_task(task.task_id)
    assert after.state is State.RECOVERY
    assert after.revision == before.revision
    assert decision.authoritative_revision == before.revision
    approval_count_after = store._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE task_id=?", (task.task_id,)
    ).fetchone()[0]
    assert approval_count_after == approval_count_before
    assert boundary.read_attempt(attempt.attempt_id).state is AttemptState.UNKNOWN


def test_recovery_decision_survives_restart_with_integrity_and_binding_intact():
    store, task, operation, attempt, boundary = _prepare_unknown_recovery()
    recovery = SQLiteRecoveryAuthority(store, boundary)
    decision = recovery.authorize(
        attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RETRY_IDEMPOTENT,
        rationale="retry only after unresolved outcome", evidence="provider timeout is unresolved", now=NOW,
    )

    fd, database_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    try:
        backup = sqlite3.connect(database_path)
        try:
            store._db.backup(backup)
        finally:
            backup.close()
            store._db.close()

        reopened = SQLiteAuthorityStore(database=database_path)
        # read() verifies the durable decision's cryptographic integrity and does
        # not require a live execution authority; consequential authorization does.
        reopened_recovery = SQLiteRecoveryAuthority(reopened, object())
        restored = reopened_recovery.read(decision.decision_id)

        assert restored.decision_id == decision.decision_id
        assert restored.task_id == task.task_id
        assert restored.operation_id == operation.operation_id
        assert restored.attempt_id == attempt.attempt_id
        assert restored.fence == attempt.fence
        assert restored.operation_hash == operation.operation_hash
        assert restored.scope == task.objective
        assert restored.authoritative_revision == task.revision
        assert restored.decision_hash == decision.decision_hash
    finally:
        try:
            reopened._db.close()
        except (NameError, AttributeError):
            pass
        try:
            store._db.close()
        except Exception:
            pass
        os.unlink(database_path)


def test_recovery_decision_cannot_be_modified_or_deleted():
    store, task, operation, attempt, boundary = _prepare_unknown_recovery()
    recovery = SQLiteRecoveryAuthority(store, boundary)
    decision = recovery.authorize(
        attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RECONCILE,
        rationale="preserve unresolved state", evidence="provider timeout is unresolved", now=NOW,
    )

    with pytest.raises(Exception, match="recovery decisions are append-only"):
        store._db.execute(
            "UPDATE recovery_decisions SET rationale='forged' WHERE decision_id=?",
            (decision.decision_id,),
        )
    with pytest.raises(Exception, match="recovery decisions are append-only"):
        store._db.execute(
            "DELETE FROM recovery_decisions WHERE decision_id=?",
            (decision.decision_id,),
        )


def test_recovery_allows_only_one_decision_per_unknown_attempt():
    store, task, operation, attempt, boundary = _prepare_unknown_recovery()
    recovery = SQLiteRecoveryAuthority(store, boundary)
    recovery.authorize(
        attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RECONCILE,
        rationale="first recovery decision", evidence="provider timeout is unresolved", now=NOW,
    )

    with pytest.raises(Exception, match="UNIQUE constraint failed"):
        recovery.authorize(
            attempt_id=attempt.attempt_id, actor="second-writer",
            strategy=RecoveryStrategy.RECONCILE,
            rationale="duplicate recovery decision", evidence="provider timeout is unresolved", now=NOW,
        )

    assert len(recovery.decisions(task.task_id)) == 1

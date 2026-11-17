"""P1.1 failure-injection tests for atomic governed attempt creation."""

import sqlite3

import pytest

from tests.test_governed_execution import NOW, setup


def test_attempt_and_governed_binding_rollback_together_on_binding_failure():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(
        task_id=task.task_id,
        idempotency_key="atomic-attempt",
        action="write",
        scope=task.objective,
        specification={"path": "atomic"},
        now=NOW,
        authorization=auth,
        tool="filesystem.write",
    )
    audit_before = store._db.execute(
        "SELECT COUNT(*) FROM execution_audit_events WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0]
    store._db.execute(
        "CREATE TRIGGER fail_governed_attempt_binding_insert "
        "BEFORE INSERT ON governed_attempt_bindings "
        "BEGIN SELECT RAISE(ABORT, 'injected attempt binding failure'); END;"
    )

    with pytest.raises(sqlite3.IntegrityError, match="injected attempt binding failure"):
        boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)

    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_attempts WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_attempt_bindings WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_audit_events WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == audit_before


def test_attempt_binding_after_insert_failure_cannot_leave_orphan_attempt():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(
        task_id=task.task_id,
        idempotency_key="atomic-attempt-after",
        action="write",
        scope=task.objective,
        specification={"path": "atomic-after"},
        now=NOW,
        authorization=auth,
        tool="filesystem.write",
    )
    audit_before = store._db.execute(
        "SELECT COUNT(*) FROM execution_audit_events WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0]
    store._db.execute(
        "CREATE TRIGGER fail_after_governed_attempt_binding_insert "
        "AFTER INSERT ON governed_attempt_bindings "
        "BEGIN SELECT RAISE(ABORT, 'injected post-binding failure'); END;"
    )

    with pytest.raises(sqlite3.IntegrityError, match="injected post-binding failure"):
        boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)

    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_attempts WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_attempt_bindings WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_audit_events WHERE operation_id=?", (op.operation_id,)
    ).fetchone()[0] == audit_before


def test_successful_attempt_creation_commits_attempt_binding_and_audit_together():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(
        task_id=task.task_id,
        idempotency_key="atomic-attempt-success",
        action="write",
        scope=task.objective,
        specification={"path": "success"},
        now=NOW,
        authorization=auth,
        tool="filesystem.write",
    )

    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)

    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_attempts WHERE attempt_id=?", (attempt.attempt_id,)
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_attempt_bindings WHERE attempt_id=?", (attempt.attempt_id,)
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_audit_events WHERE attempt_id=?", (attempt.attempt_id,)
    ).fetchone()[0] == 1

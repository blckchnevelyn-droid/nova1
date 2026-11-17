"""Adversarial tests for governed UNKNOWN recovery decisions."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from nova.authority import Approval, State, ValidationError
from nova.execution import AttemptState
from nova.recovery import RecoveryStrategy, SQLiteRecoveryAuthority

from tests.governed_fixtures import governed_execution, governed_task


NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def unresolved_task(*, approval_required=False):
    store, task = governed_task(approval_required=approval_required)
    approval_id = None
    if approval_required:
        approval = Approval(
            "approval-1", task.task_id, "principal:demo", "ALLOW", "execute:demo", "p1",
            NOW, NOW + timedelta(minutes=10), "trusted-provenance",
        )
        store.record_approval(approval)
        approval_id = approval.approval_id
    task, execution, _, auth = governed_execution(store, task, approval_id=approval_id)
    operation = execution.identify_operation(
        task_id=task.task_id, idempotency_key="k1", action="write",
        scope=task.objective, specification={"path": "a"}, now=NOW,
        authorization=auth, tool="filesystem.write",
    )
    attempt = execution.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    attempt = execution.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                              authorization=auth, tool="filesystem.write")
    attempt = execution.record_outcome(
        attempt_id=attempt.attempt_id, worker_id="worker-1", fence=attempt.fence,
        state=AttemptState.UNKNOWN, now=NOW + timedelta(seconds=1),
        error_detail="external outcome could not be confirmed", authorization=auth, tool="filesystem.write",
    )
    task = store.authorize_transition(
        task_id=task.task_id, expected_revision=task.revision,
        target=State.RECOVERY, now=NOW + timedelta(seconds=2), approval_id=approval_id,
    )
    return store, execution, task, attempt, operation


def test_recovery_requires_unknown_attempt_and_current_recovery_state():
    store, task = governed_task()
    _, execution, _, auth = governed_execution(store, task)
    operation = execution.identify_operation(task_id=task.task_id, idempotency_key="k1", action="write",
                                             scope=task.objective, specification={"path": "a"}, now=NOW,
                                             authorization=auth, tool="filesystem.write")
    attempt = execution.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    recovery = SQLiteRecoveryAuthority(store, execution)
    with pytest.raises(ValidationError):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
            rationale="inspect state", evidence="external state lookup pending", now=NOW)


def test_unknown_recovery_decision_is_bound_and_durable():
    store, execution, task, attempt, operation = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    decision = recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile external state", evidence="provider inquiry reference: r1", now=NOW + timedelta(seconds=3))
    assert decision.task_id == task.task_id
    assert decision.operation_id == operation.operation_id
    assert decision.attempt_id == attempt.attempt_id
    assert decision.fence == attempt.fence
    assert decision.operation_hash == operation.operation_hash
    assert decision.scope == operation.scope == task.objective
    assert recovery.read(decision.decision_id) == decision


def test_recovery_requires_current_approval():
    store, execution, task, attempt, _ = unresolved_task(approval_required=True)
    recovery = SQLiteRecoveryAuthority(store, execution)
    with pytest.raises(ValidationError):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
            rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(minutes=11))


def test_only_one_recovery_decision_can_be_authorized_for_attempt():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))
    with pytest.raises(sqlite3.IntegrityError):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
            rationale="second decision", evidence="second inquiry", now=NOW + timedelta(seconds=4))


def test_recovery_decision_is_append_only():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    decision = recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))
    with pytest.raises(sqlite3.IntegrityError):
        store._db.execute("UPDATE recovery_decisions SET rationale='forged' WHERE decision_id=?", (decision.decision_id,))


def test_tampered_recovery_decision_is_detected():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    decision = recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))
    store._db.execute("DROP TRIGGER recovery_decisions_no_update")
    store._db.execute("UPDATE recovery_decisions SET evidence='forged' WHERE decision_id=?", (decision.decision_id,))
    with pytest.raises(ValidationError, match="integrity check failed"):
        recovery.read(decision.decision_id)


def test_tampered_unknown_attempt_is_rejected_before_recovery_authorization():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    store._db.execute("DROP TRIGGER execution_terminal_attempt_no_update")
    store._db.execute("UPDATE execution_attempts SET error_detail='forged external outcome' WHERE attempt_id=?", (attempt.attempt_id,))
    with pytest.raises(ValidationError, match="execution evidence integrity check failed"):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
            rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))


def test_tampered_operation_is_rejected_before_recovery_authorization():
    store, execution, _, attempt, operation = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    store._db.execute("DROP TRIGGER execution_operation_no_update")
    store._db.execute("UPDATE execution_operations SET scope='execute:forged' WHERE operation_id=?", (operation.operation_id,))
    with pytest.raises(ValidationError, match="operation integrity check failed"):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
            rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))


def test_recovery_does_not_change_unknown_attempt():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="reconcile", evidence="provider inquiry", now=NOW + timedelta(seconds=3))
    assert execution.read_attempt(attempt.attempt_id).state is AttemptState.UNKNOWN


def test_recovery_strategy_does_not_expand_operation_scope():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    decision = recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RETRY_IDEMPOTENT,
        rationale="safe idempotent reconciliation", evidence="provider confirms idempotency support", now=NOW + timedelta(seconds=3))
    assert decision.action == "write"
    assert decision.scope == "execute:demo"
    assert decision.attempt_id == attempt.attempt_id


def test_expired_recovery_decision_is_recorded_but_not_execution_authority():
    store, execution, _, attempt, _ = unresolved_task()
    recovery = SQLiteRecoveryAuthority(store, execution)
    decision = recovery.authorize(attempt_id=attempt.attempt_id, actor="human:1", strategy=RecoveryStrategy.RECONCILE,
        rationale="time-bounded reconciliation", evidence="provider inquiry", now=NOW + timedelta(seconds=3),
        expires_at=NOW + timedelta(seconds=10))
    assert decision.expires_at == NOW + timedelta(seconds=10)
    assert execution.read_attempt(attempt.attempt_id).state is AttemptState.UNKNOWN

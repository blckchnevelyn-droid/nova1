"""Twelve adversarial tests mapped one-to-one to Nova governance invariants."""

from datetime import datetime, timedelta, timezone

import pytest

from nova.authority import AuthorityStore, State, ValidationError
from nova.execution import AttemptState, SQLiteExecutionAuthority
from nova.governance import AuthorizationError, AuthorizationLedger, AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.persistence import SQLiteAuthorityStore

from tests.test_execution import setup_boundary, identify

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
TOOL = "filesystem.write"


def test_01_unauthorized_execution_denies():
    store, task, _, auth, boundary = setup_boundary()
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="unauthorized", action="write",
                                    scope=task.objective, specification={}, now=NOW, authorization=None, tool=TOOL)


def test_02_wrong_scope_denies():
    store, task, _, auth, boundary = setup_boundary()
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="wrong-scope", action="write",
                                    scope="execute:other", specification={}, now=NOW, authorization=auth, tool=TOOL)


def test_03_expired_authorization_denies():
    store, task, _, auth, boundary = setup_boundary()
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="expired", action="write",
                                    scope=task.objective, specification={}, now=NOW + timedelta(minutes=11),
                                    authorization=auth, tool=TOOL)


def test_04_modified_authorization_denies():
    store, task, _, auth, boundary = setup_boundary()
    forged = AuthorizationRecord(
        authorization_id=auth.authorization_id, authorizer=auth.authorizer, agent_id=auth.agent_id,
        task_id=auth.task_id, objective=auth.objective, action=auth.action, scope=auth.scope,
        allowed_tools=auth.allowed_tools, limits=auth.limits, policy_version=auth.policy_version,
        issued_at=auth.issued_at, expires_at=auth.expires_at, provenance="modified",
        proof=auth.proof, integrity_hash=auth.integrity_hash)
    with pytest.raises(AuthorizationError):
        identify(boundary, task, forged)


def test_05_forged_executor_evidence_denies_completion():
    store, task, _, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW, authorization=auth, tool=TOOL)
    boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
                            state=AttemptState.SUCCEEDED, now=NOW, result_evidence="real", authorization=auth, tool=TOOL)
    store._db.execute("DROP TRIGGER execution_terminal_attempt_no_update")
    store._db.execute("UPDATE execution_attempts SET result_evidence='forged' WHERE attempt_id=?", (attempt.attempt_id,))
    with pytest.raises(ValidationError, match="evidence integrity"):
        boundary.read_attempt(attempt.attempt_id)


def test_06_missing_observation_cannot_jump_to_completion():
    store = AuthorityStore()
    task = store.create_task(objective="execute:x", authority_context="principal:x", governance_decision="ALLOW",
                             policy_version="p1", now=NOW)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=1, target=State.COMPLETED,
                                   now=NOW, verification="VERIFIED")


def test_07_failed_verification_cannot_complete():
    store = AuthorityStore()
    task = store.create_task(objective="execute:x", authority_context="principal:x", governance_decision="ALLOW",
                             policy_version="p1", now=NOW)
    for revision, state in [(0, State.EXECUTING), (1, State.OBSERVING), (2, State.VERIFYING)]:
        task = store.authorize_transition(task_id=task.task_id, expected_revision=revision, target=state, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=3, target=State.COMPLETED,
                                   now=NOW, verification="FAILED")


def test_08_unauthorized_recovery_denies():
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:x", authority_context="principal:x", governance_decision="ALLOW",
                             policy_version="p1", now=NOW)
    execution = SQLiteExecutionAuthority(store, _capability=__import__("nova.execution", fromlist=["_NOVA_GOVERNED_CAPABILITY"])._NOVA_GOVERNED_CAPABILITY)
    operation = execution.identify_operation(task_id=task.task_id, idempotency_key="x", action="write", scope=task.objective,
                                             specification={}, now=NOW)
    attempt = execution.create_attempt(operation_id=operation.operation_id, worker_id="w", now=NOW)
    from nova.recovery import RecoveryStrategy, SQLiteRecoveryAuthority
    recovery = SQLiteRecoveryAuthority(store, execution)
    with pytest.raises(ValidationError):
        recovery.authorize(attempt_id=attempt.attempt_id, actor="human", strategy=RecoveryStrategy.RECONCILE,
                           rationale="unauthorized", evidence="none", now=NOW)


def test_09_tampered_execution_audit_is_detected_by_append_only_boundary():
    store, task, _, auth, boundary = setup_boundary()
    identify(boundary, task, auth)
    events = boundary.audit_events(task.task_id)
    with pytest.raises(Exception):
        store._db.execute("DELETE FROM execution_audit_events WHERE event_id=?", (events[0].event_id,))


def test_10_ambiguous_governance_decision_escalates_and_blocks_execution():
    store = AuthorityStore()
    task = store.create_task(objective="ambiguous", authority_context="principal:x", governance_decision="ESCALATE",
                             policy_version="p1", now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    escalated = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.ESCALATE, now=NOW)
    assert escalated.state is State.ESCALATE


def test_11_emergency_stop_dominates_normal_execution():
    store = AuthorityStore()
    task = store.create_task(objective="execute:x", authority_context="principal:x", governance_decision="ALLOW",
                             policy_version="p1", now=NOW)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    stopped = store.authorize_transition(task_id=task.task_id, expected_revision=1, target=State.STOPPED, now=NOW)
    assert stopped.state is State.STOPPED
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=2, target=State.OBSERVING, now=NOW)


def test_12_executor_bypass_is_blocked():
    store = SQLiteAuthorityStore()
    with pytest.raises(ValidationError, match="internal implementation"):
        SQLiteExecutionAuthority(store)

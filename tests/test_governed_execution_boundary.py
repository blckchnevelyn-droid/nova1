"""Adversarial tests for the governed execution authority boundary."""

import sqlite3
from datetime import timedelta

import pytest

from nova.authority import ValidationError
from nova.execution import AttemptState, SQLiteExecutionAuthority
from nova.governance import AuthorizationError
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.persistence import SQLiteAuthorityStore
from nova.identity import TrustedAuthorizerKey
from tests.governed_fixtures import NOW, governed_task, signed_auth


def prepared_boundary():
    store, task = governed_task()
    private, key_id, auth = signed_auth(task)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=__import__('nova.authority', fromlist=['State']).State.EXECUTING, now=NOW)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    return store, task, identity, auth, ledger, boundary


def test_internal_execution_authority_cannot_be_constructed_without_capability():
    store, _, _, auth, ledger, _ = prepared_boundary()
    with pytest.raises(ValidationError, match="internal implementation"):
        SQLiteExecutionAuthority(store, ledger)


def test_direct_internal_execution_cannot_bypass_governed_binding():
    store, task, _, auth, ledger, boundary = prepared_boundary()
    internal = boundary._execution
    operation = internal.identify_operation(task_id=task.task_id, idempotency_key="direct-bypass",
        action="write", scope=task.objective, specification={"path": "blocked"}, now=NOW)
    attempt = internal.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    with pytest.raises(AuthorizationError, match="no governed authorization binding"):
        internal.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW,
            authorization=auth, tool="filesystem.write")


def test_attempt_binding_tamper_is_detected():
    store, task, _, auth, _, boundary = prepared_boundary()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="binding-tamper",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    store._db.execute("DROP TRIGGER governed_attempt_binding_no_update")
    store._db.execute("UPDATE governed_attempt_bindings SET authorization_hash='tampered' WHERE attempt_id=?",
                      (attempt.attempt_id,))
    with pytest.raises(AuthorizationError, match="integrity hash"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW,
            authorization=auth, tool="filesystem.write")


def test_tool_substitution_is_rejected():
    store, task, _, auth, _, boundary = prepared_boundary()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="tool-substitution",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    with pytest.raises(ValidationError, match="tool"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW,
            authorization=auth, tool="network.write")


def test_worker_substitution_is_rejected():
    store, task, _, auth, _, boundary = prepared_boundary()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="worker-substitution",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    with pytest.raises(ValidationError, match="worker"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id="attacker-worker", now=NOW,
            authorization=auth, tool="filesystem.write")


def test_expired_authorization_cannot_claim_or_record_outcome():
    store, task = governed_task()
    private, key_id, auth = signed_auth(task, expires_at=NOW + timedelta(seconds=1))
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    from nova.authority import State
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="expired-auth",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    with pytest.raises(AuthorizationError, match="validity|expired"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW + timedelta(seconds=2),
            authorization=auth, tool="filesystem.write")


def test_stale_fence_cannot_record_outcome():
    store, task, _, auth, _, boundary = prepared_boundary()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="stale-fence",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    claimed = boundary.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW,
        authorization=auth, tool="filesystem.write")
    with pytest.raises(ValidationError, match="fencing"):
        boundary.record_outcome(attempt_id=claimed.attempt_id, worker_id=auth.agent_id, fence=claimed.fence - 1,
            state=AttemptState.SUCCEEDED, now=NOW + timedelta(seconds=1), authorization=auth,
            tool="filesystem.write", result_evidence="success")


def test_terminal_attempt_cannot_be_rewritten():
    store, task, _, auth, _, boundary = prepared_boundary()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="terminal-immutability",
        action="write", scope=task.objective, specification={"path": "x"}, now=NOW,
        authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id=auth.agent_id, now=NOW)
    claimed = boundary.claim(attempt_id=attempt.attempt_id, worker_id=auth.agent_id, now=NOW,
        authorization=auth, tool="filesystem.write")
    boundary.record_outcome(attempt_id=claimed.attempt_id, worker_id=auth.agent_id, fence=claimed.fence,
        state=AttemptState.SUCCEEDED, now=NOW + timedelta(seconds=1), authorization=auth,
        tool="filesystem.write", result_evidence="success")
    with pytest.raises(sqlite3.IntegrityError, match="terminal execution attempts are immutable"):
        store._db.execute("UPDATE execution_attempts SET result_evidence='tampered' WHERE attempt_id=?",
                          (attempt.attempt_id,))

"""Durability and restart-boundary tests for governed execution."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import ConflictError, State, ValidationError
from nova.execution import AttemptState
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governance import AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
TOOL = "filesystem.write"


def _authorization_payload(auth):
    return {"authorization_id": auth.authorization_id, "authorizer": auth.authorizer,
            "agent_id": auth.agent_id, "task_id": auth.task_id, "objective": auth.objective,
            "action": auth.action, "scope": auth.scope, "allowed_tools": list(auth.allowed_tools),
            "limits": {key: json.loads(value) for key, value in auth.limits},
            "policy_version": auth.policy_version, "issued_at": auth.issued_at.isoformat(),
            "expires_at": auth.expires_at.isoformat() if auth.expires_at else None,
            "provenance": auth.provenance}


def _make_identity_and_auth(task):
    private_key = Ed25519PrivateKey.generate()
    key_id = "restart-authorizer-key"
    base = AuthorizationRecord.issue(
        authorization_id="restart-auth", authorizer="principal:demo", agent_id="worker-1",
        task_id=task.task_id, objective=task.objective, action="write", scope=task.objective,
        allowed_tools=(TOOL,), limits={"max_operations": 5}, policy_version="p1",
        issued_at=NOW, expires_at=NOW + timedelta(hours=1), provenance="restart-test", proof="pending")
    canonical = json.dumps(_authorization_payload(base), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    auth = AuthorizationRecord.issue(
        authorization_id=base.authorization_id, authorizer=base.authorizer, agent_id=base.agent_id,
        task_id=base.task_id, objective=base.objective, action=base.action, scope=base.scope,
        allowed_tools=base.allowed_tools, limits={key: json.loads(value) for key, value in base.limits},
        policy_version=base.policy_version, issued_at=base.issued_at, expires_at=base.expires_at,
        provenance=base.provenance, proof=f"ed25519:{key_id}:{signature}")
    return private_key, key_id, auth


def _start_task(db_path):
    store = SQLiteAuthorityStore(str(db_path))
    task = store.create_task(objective="execute:demo", authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    private, key_id, auth = _make_identity_and_auth(task)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="restart-key",
                                            action="write", scope=task.objective,
                                            specification={"path": "a"}, now=NOW,
                                            authorization=auth, tool=TOOL)
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    return store, boundary, ledger, identity, auth, task, operation, attempt


def _reopen(db_path):
    reopened = SQLiteAuthorityStore(str(db_path))
    ledger = SQLiteAuthorizationLedger(reopened._db)
    identity = SQLiteIdentityGate(reopened._db)
    return reopened, ledger, identity


def test_operation_and_unclaimed_attempt_survive_restart(tmp_path):
    db_path = tmp_path / "nova.db"
    store, boundary, ledger, identity, auth, task, operation, attempt = _start_task(db_path)
    store.close()
    reopened, ledger2, identity2 = _reopen(db_path)
    boundary2 = GovernedSQLiteExecutionAuthority(reopened, ledger2, identity2)
    restored_operation = boundary2.identify_operation(task_id=task.task_id, idempotency_key="restart-key",
                                                      action="write", scope=task.objective,
                                                      specification={"path": "a"}, now=NOW,
                                                      authorization=auth, tool=TOOL)
    restored_attempt = boundary2.read_attempt(attempt.attempt_id)
    assert restored_operation.operation_id == operation.operation_id
    assert restored_attempt.state is AttemptState.NOT_EXECUTED
    assert restored_attempt.fence == attempt.fence
    reopened.close()


def test_claimed_attempt_survives_restart_without_becoming_success(tmp_path):
    db_path = tmp_path / "nova.db"
    store, boundary, ledger, identity, auth, task, operation, attempt = _start_task(db_path)
    claimed = boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                             authorization=auth, tool=TOOL)
    store.close()
    reopened, ledger2, identity2 = _reopen(db_path)
    boundary2 = GovernedSQLiteExecutionAuthority(reopened, ledger2, identity2)
    restored = boundary2.read_attempt(claimed.attempt_id)
    assert restored.state is AttemptState.CLAIMED
    assert restored.finished_at is None
    with pytest.raises(ValidationError):
        boundary2.record_outcome(attempt_id=claimed.attempt_id, worker_id="worker-2",
                                 fence=claimed.fence, state=AttemptState.SUCCEEDED, now=NOW,
                                 result_evidence="forged", authorization=auth, tool=TOOL)
    reopened.close()


def test_restart_does_not_allow_second_attempt_while_first_is_claimed(tmp_path):
    db_path = tmp_path / "nova.db"
    store, boundary, ledger, identity, auth, task, operation, attempt = _start_task(db_path)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                   authorization=auth, tool=TOOL)
    store.close()
    reopened, ledger2, identity2 = _reopen(db_path)
    boundary2 = GovernedSQLiteExecutionAuthority(reopened, ledger2, identity2)
    with pytest.raises(ConflictError, match="claimed, unresolved, or already succeeded"):
        boundary2.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    reopened.close()

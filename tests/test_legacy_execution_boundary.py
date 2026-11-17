import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import State, ValidationError
from nova.execution import SQLiteExecutionAuthority
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governance import AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def test_direct_legacy_execution_constructor_is_fail_closed():
    store = SQLiteAuthorityStore()
    with pytest.raises(ValidationError, match="internal implementation"):
        SQLiteExecutionAuthority(store)


def test_governed_facade_can_construct_internal_execution():
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:capability", authority_context="principal:test",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    private = Ed25519PrivateKey.generate()
    key_id = "capability-authorizer-key"
    base = AuthorizationRecord.issue(
        authorization_id="capability-auth", authorizer="principal:test", agent_id="worker-1",
        task_id=task.task_id, objective=task.objective, action="write", scope=task.objective,
        allowed_tools=("filesystem.write",), limits={"max_operations": 1}, policy_version="p1",
        issued_at=NOW, expires_at=NOW + timedelta(minutes=10), provenance="test", proof="pending")
    payload = {"authorization_id": base.authorization_id, "authorizer": base.authorizer,
               "agent_id": base.agent_id, "task_id": base.task_id, "objective": base.objective,
               "action": base.action, "scope": base.scope, "allowed_tools": list(base.allowed_tools),
               "limits": {k: json.loads(v) for k, v in base.limits}, "policy_version": base.policy_version,
               "issued_at": base.issued_at.isoformat(), "expires_at": base.expires_at.isoformat() if base.expires_at else None,
               "provenance": base.provenance}
    signature = base64.b64encode(private.sign(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())).decode()
    auth = AuthorizationRecord.issue(
        authorization_id=base.authorization_id, authorizer=base.authorizer, agent_id=base.agent_id,
        task_id=base.task_id, objective=base.objective, action=base.action, scope=base.scope,
        allowed_tools=base.allowed_tools, limits={k: json.loads(v) for k, v in base.limits}, policy_version=base.policy_version,
        issued_at=base.issued_at, expires_at=base.expires_at, provenance=base.provenance,
        proof=f"ed25519:{key_id}:{signature}")
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal="principal:test", algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="capability", action="write",
                                            scope=task.objective, specification={"path": "a"}, now=NOW,
                                            authorization=auth, tool="filesystem.write")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    assert attempt.worker_id == "worker-1"

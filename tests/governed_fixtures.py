"""Shared cryptographic fixtures for governed execution tests."""
from __future__ import annotations

import base64
import json
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import State
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governance import AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
TOOL = "filesystem.write"


def signed_auth(task, *, authorization_id="auth-test", agent_id="worker-1", max_operations=10, allowed_tools=(TOOL,),
                issued_at=NOW, expires_at=None, authorizer=None, limits_extra=None, scope=None):
    authorizer = authorizer or task.authority_context
    scope = scope or task.objective
    expires_at = expires_at or (NOW + timedelta(minutes=10))
    limits = {"max_operations": max_operations, "postcondition_hash": hashlib.sha256(f"{task.objective}:{task.policy_version}:postcondition".encode()).hexdigest(), **(limits_extra or {})}
    private = Ed25519PrivateKey.generate()
    key_id = f"key-{authorization_id}"
    base = AuthorizationRecord.issue(
        authorization_id=authorization_id, authorizer=authorizer, agent_id=agent_id,
        task_id=task.task_id, objective=task.objective, action="write", scope=scope,
        allowed_tools=tuple(allowed_tools), limits=limits, policy_version=task.policy_version,
        issued_at=issued_at, expires_at=expires_at, provenance="fixture", proof="pending")
    payload = {
        "authorization_id": base.authorization_id, "authorizer": base.authorizer,
        "agent_id": base.agent_id, "task_id": base.task_id, "objective": base.objective,
        "action": base.action, "scope": base.scope, "allowed_tools": list(base.allowed_tools),
        "limits": {k: json.loads(v) for k, v in base.limits},
        "policy_version": base.policy_version, "issued_at": base.issued_at.isoformat(),
        "expires_at": base.expires_at.isoformat() if base.expires_at else None,
        "provenance": base.provenance,
    }
    signature = base64.b64encode(private.sign(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())).decode()
    auth = AuthorizationRecord.issue(
        authorization_id=base.authorization_id, authorizer=base.authorizer, agent_id=base.agent_id,
        task_id=base.task_id, objective=base.objective, action=base.action, scope=base.scope,
        allowed_tools=base.allowed_tools, limits={k: json.loads(v) for k, v in base.limits},
        policy_version=base.policy_version, issued_at=base.issued_at, expires_at=base.expires_at,
        provenance=base.provenance, proof=f"ed25519:{key_id}:{signature}")
    return private, key_id, auth


def governed_task(*, approval_required=False):
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:demo", authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW,
                             approval_required=approval_required)
    return store, task


def governed_execution(store, task, *, authorization_id="auth-test", agent_id="worker-1",
                       max_operations=10, approval_id=None):
    private, key_id, auth = signed_auth(task, authorization_id=authorization_id, agent_id=agent_id,
                                        max_operations=max_operations)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW, approval_id=approval_id)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    return task, boundary, ledger, auth

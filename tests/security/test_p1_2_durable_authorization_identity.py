"""P1.2 adversarial tests for durable authorization and identity state."""
from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governance import AuthorizationError, AuthorizationRecord
from nova.identity import IdentityError, TrustedAuthorizerKey

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def _auth(private, *, auth_id="auth-1", task_id="task-1", agent_id="agent-1", authorizer="principal:1"):
    base = AuthorizationRecord.issue(
        authorization_id=auth_id, authorizer=authorizer, agent_id=agent_id, task_id=task_id,
        objective="objective", action="write", scope="objective", allowed_tools=("tool.write",),
        limits={"max_operations": 2}, policy_version="p1", issued_at=NOW,
        expires_at=NOW + timedelta(hours=1), provenance="test", proof="pending")
    payload = {
        "authorization_id": base.authorization_id, "authorizer": base.authorizer,
        "agent_id": base.agent_id, "task_id": base.task_id, "objective": base.objective,
        "action": base.action, "scope": base.scope, "allowed_tools": list(base.allowed_tools),
        "limits": {k: json.loads(v) for k, v in base.limits}, "policy_version": base.policy_version,
        "issued_at": base.issued_at.isoformat(), "expires_at": base.expires_at.isoformat(),
        "provenance": base.provenance,
    }
    signature = base64.b64encode(private.sign(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())).decode()
    return AuthorizationRecord.issue(
        authorization_id=base.authorization_id, authorizer=base.authorizer, agent_id=base.agent_id,
        task_id=base.task_id, objective=base.objective, action=base.action, scope=base.scope,
        allowed_tools=base.allowed_tools, limits={k: json.loads(v) for k, v in base.limits},
        policy_version=base.policy_version, issued_at=base.issued_at, expires_at=base.expires_at,
        provenance=base.provenance, proof=f"ed25519:key-1:{signature}"), payload, signature


def test_authorization_survives_restart_and_revocation_is_durable(tmp_path):
    path = tmp_path / "nova.sqlite"
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    ledger = SQLiteAuthorizationLedger(db)
    private = Ed25519PrivateKey.generate()
    authorization, _, _ = _auth(private)
    ledger.record(authorization)
    db.commit()
    db.close()

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    restored = SQLiteAuthorizationLedger(db)
    assert restored.get(authorization.authorization_id, now=NOW).integrity_hash == authorization.integrity_hash
    restored.revoke(authorization.authorization_id, now=NOW)
    db.commit()
    db.close()

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    restored = SQLiteAuthorizationLedger(db)
    with pytest.raises(AuthorizationError, match="revoked"):
        restored.get(authorization.authorization_id, now=NOW)
    db.close()


def test_identity_trust_root_and_replay_survive_restart(tmp_path):
    path = tmp_path / "nova.sqlite"
    private = Ed25519PrivateKey.generate()
    db = sqlite3.connect(path); db.row_factory = sqlite3.Row
    identity = SQLiteIdentityGate(db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id="key-1", principal="principal:1", algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(), valid_from=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(hours=2)))
    authorization, payload, signature = _auth(private)
    digest = identity.verify(authorization_id=authorization.authorization_id, principal="principal:1",
                             key_id="key-1", payload=payload, signature=signature, now=NOW,
                             issued_at=authorization.issued_at, expires_at=authorization.expires_at)
    db.commit()
    db.close()

    db = sqlite3.connect(path); db.row_factory = sqlite3.Row
    restored = SQLiteIdentityGate(db)
    assert restored.verify(authorization_id=authorization.authorization_id, principal="principal:1",
                           key_id="key-1", payload=payload, signature=signature, now=NOW,
                           issued_at=authorization.issued_at, expires_at=authorization.expires_at) == digest
    changed = dict(payload); changed["scope"] = "changed"
    with pytest.raises(IdentityError, match="replay"):
        restored.verify(authorization_id=authorization.authorization_id, principal="principal:1",
                        key_id="key-1", payload=changed, signature=signature, now=NOW,
                        issued_at=authorization.issued_at, expires_at=authorization.expires_at)
    restored.revoke_key("key-1", now=NOW)
    db.commit()
    db.close()

    db = sqlite3.connect(path); db.row_factory = sqlite3.Row
    restored = SQLiteIdentityGate(db)
    with pytest.raises(IdentityError, match="revoked"):
        restored.verify(authorization_id="auth-2", principal="principal:1", key_id="key-1",
                        payload=payload, signature=signature, now=NOW,
                        issued_at=authorization.issued_at, expires_at=authorization.expires_at)
    db.close()

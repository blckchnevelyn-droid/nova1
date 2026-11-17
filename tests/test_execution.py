"""Adversarial contract tests for the governed ADR-002 execution boundary."""

import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import State, ValidationError, ConflictError
from nova.execution import AttemptState, SQLiteExecutionAuthority
from nova.governance import AuthorizationError, AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.persistence import SQLiteAuthorityStore
from tests.governed_fixtures import signed_auth
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.identity import TrustedAuthorizerKey

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
TOOL = "filesystem.write"


def _authorization_payload(auth):
    return {
        "authorization_id": auth.authorization_id,
        "authorizer": auth.authorizer,
        "agent_id": auth.agent_id,
        "task_id": auth.task_id,
        "objective": auth.objective,
        "action": auth.action,
        "scope": auth.scope,
        "allowed_tools": list(auth.allowed_tools),
        "limits": {key: json.loads(value) for key, value in auth.limits},
        "policy_version": auth.policy_version,
        "issued_at": auth.issued_at.isoformat(),
        "expires_at": auth.expires_at.isoformat() if auth.expires_at else None,
        "provenance": auth.provenance,
    }


def _signed_proof(auth, private_key, key_id="test-authorizer-key"):
    payload = _authorization_payload(auth)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    return f"ed25519:{key_id}:{signature}"


def setup_boundary():
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:demo", authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    private_key, key_id, auth = signed_auth(task, authorization_id="auth-execution", agent_id="w1", max_operations=10)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private_key.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1),
    ))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    return store, task, ledger, auth, GovernedSQLiteExecutionAuthority(store, ledger, identity)


def identify(boundary, task, auth, key="k1", spec=None):
    return boundary.identify_operation(task_id=task.task_id, idempotency_key=key, action="write",
                                       scope=task.objective, specification=spec or {"path": "a"},
                                       now=NOW, authorization=auth, tool=TOOL)


def test_direct_legacy_constructor_is_fail_closed():
    store = SQLiteAuthorityStore()
    with pytest.raises(ValidationError, match="internal implementation"):
        SQLiteExecutionAuthority(store)


def test_idempotency_binds_exact_operation():
    store, task, ledger, auth, boundary = setup_boundary()
    first = identify(boundary, task, auth)
    assert identify(boundary, task, auth).operation_id == first.operation_id
    with pytest.raises(ValidationError):
        identify(boundary, task, auth, spec={"path": "different"})


def test_claim_requires_explicit_authorization():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    with pytest.raises(TypeError):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW, tool=TOOL)


def test_authorized_claim_and_unknown_outcome():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    claimed = boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW,
                             authorization=auth, tool=TOOL)
    assert claimed.state is AttemptState.CLAIMED
    unknown = boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1",
                                      fence=attempt.fence, state=AttemptState.UNKNOWN, now=NOW,
                                      error_detail="provider timeout", authorization=auth, tool=TOOL)
    assert unknown.state is AttemptState.UNKNOWN
    assert unknown.evidence_hash


def test_success_requires_evidence():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW,
                   authorization=auth, tool=TOOL)
    with pytest.raises(ValidationError, match="result evidence"):
        boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
                                state=AttemptState.SUCCEEDED, now=NOW,
                                authorization=auth, tool=TOOL)


def test_wrong_agent_tool_action_and_scope_are_denied():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    with pytest.raises(ValidationError, match="worker identity is not the authorized agent"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id="evil", now=NOW,
                       authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError, match="tool is not authorized"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="bad-tool", action="write",
                                    scope=task.objective, specification={}, now=NOW,
                                    authorization=auth, tool="shell.exec")
    with pytest.raises(AuthorizationError, match="authorization action binding mismatch"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="bad-action", action="delete",
                                    scope=task.objective, specification={}, now=NOW,
                                    authorization=auth, tool=TOOL)


def test_expiry_and_revocation_are_enforced():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW,
                   authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError):
        boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
                                state=AttemptState.UNKNOWN, now=NOW + timedelta(minutes=11),
                                error_detail="expired", authorization=auth, tool=TOOL)
    ledger.revoke(auth.authorization_id, now=NOW)
    with pytest.raises(AuthorizationError):
        boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
                                state=AttemptState.UNKNOWN, now=NOW,
                                error_detail="revoked", authorization=auth, tool=TOOL)


def test_binding_immutability_and_operation_integrity():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    with pytest.raises(sqlite3.IntegrityError, match="governed authorization bindings are immutable"):
        store._db.execute("UPDATE governed_execution_bindings SET tool='shell.exec' WHERE operation_id=?",
                          (op.operation_id,))
    with pytest.raises(sqlite3.IntegrityError, match="execution operations are immutable"):
        store._db.execute("UPDATE execution_operations SET action='delete' WHERE operation_id=?",
                          (op.operation_id,))


def test_tampered_authorization_is_rejected():
    store, task, ledger, auth, boundary = setup_boundary()
    forged = AuthorizationRecord(
        authorization_id=auth.authorization_id, authorizer=auth.authorizer, agent_id=auth.agent_id,
        task_id=auth.task_id, objective=auth.objective, action=auth.action, scope=auth.scope,
        allowed_tools=auth.allowed_tools, limits=auth.limits, policy_version=auth.policy_version,
        issued_at=auth.issued_at, expires_at=auth.expires_at, provenance="forged",
        proof=auth.proof, integrity_hash=auth.integrity_hash,
    )
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="forged", action="write",
                                    scope=task.objective, specification={}, now=NOW,
                                    authorization=forged, tool=TOOL)


def test_audit_is_append_only():
    store, task, ledger, auth, boundary = setup_boundary()
    op = identify(boundary, task, auth)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="w1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="w1", now=NOW,
                   authorization=auth, tool=TOOL)
    boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="w1", fence=attempt.fence,
                            state=AttemptState.UNKNOWN, now=NOW, error_detail="timeout",
                            authorization=auth, tool=TOOL)
    events = boundary.audit_events(task.task_id)
    assert [e.event_type for e in events] == ["OPERATION_IDENTIFIED", "ATTEMPT_CREATED",
                                              "ATTEMPT_CLAIMED", "ATTEMPT_UNKNOWN"]
    with pytest.raises(sqlite3.IntegrityError, match="execution audit events are append-only"):
        store._db.execute("DELETE FROM execution_audit_events WHERE event_id=?", (events[0].event_id,))

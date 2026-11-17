from datetime import datetime, timedelta, timezone

import pytest

from nova.governance import AuthorizationError, AuthorizationLedger, AuthorizationRecord


NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def make_authorization(**overrides):
    values = dict(
        authorization_id="auth-1",
        authorizer="human:user-1",
        agent_id="agent:nova",
        task_id="task-1",
        objective="execute:demo",
        action="write",
        scope="execute:demo",
        allowed_tools=("demo.write",),
        limits={"max_items": 1, "network": False},
        policy_version="policy-v1",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        provenance="governance-event-1",
        proof="approval-proof-1",
    )
    values.update(overrides)
    return AuthorizationRecord.issue(**values)


def test_authorization_binds_all_security_dimensions():
    record = make_authorization()
    assert record.authorizer == "human:user-1"
    assert record.agent_id == "agent:nova"
    assert record.action == "write"
    assert record.scope == "execute:demo"
    assert record.allowed_tools == ("demo.write",)
    assert dict(record.limits)["max_items"] == "1"
    assert record.policy_version == "policy-v1"
    assert record.proof == "approval-proof-1"
    record.verify_integrity()


def test_tampered_frozen_record_is_rejected_by_integrity_check():
    record = make_authorization()
    object.__setattr__(record, "scope", "different-scope")
    with pytest.raises(AuthorizationError, match="integrity"):
        record.verify_integrity()


def test_wrong_agent_action_scope_or_tool_is_denied():
    ledger = AuthorizationLedger()
    ledger.record(make_authorization())
    cases = [
        {"agent_id": "agent:other", "action": "write", "scope": "execute:demo", "tool": "demo.write"},
        {"agent_id": "agent:nova", "action": "delete", "scope": "execute:demo", "tool": "demo.write"},
        {"agent_id": "agent:nova", "action": "write", "scope": "other", "tool": "demo.write"},
        {"agent_id": "agent:nova", "action": "write", "scope": "execute:demo", "tool": "demo.read"},
    ]
    for case in cases:
        with pytest.raises(AuthorizationError):
            ledger.authorize(authorization_id="auth-1", now=NOW, **case)


def test_expired_authorization_is_denied():
    ledger = AuthorizationLedger()
    ledger.record(make_authorization(expires_at=NOW + timedelta(seconds=1)))
    with pytest.raises(AuthorizationError, match="validity"):
        ledger.authorize(
            authorization_id="auth-1", agent_id="agent:nova", action="write",
            scope="execute:demo", tool="demo.write", now=NOW + timedelta(seconds=1),
        )


def test_revoked_authorization_is_denied():
    ledger = AuthorizationLedger()
    ledger.record(make_authorization())
    ledger.revoke("auth-1")
    with pytest.raises(AuthorizationError, match="revoked"):
        ledger.authorize(
            authorization_id="auth-1", agent_id="agent:nova", action="write",
            scope="execute:demo", tool="demo.write", now=NOW,
        )


def test_duplicate_authorization_id_is_rejected():
    ledger = AuthorizationLedger()
    ledger.record(make_authorization())
    with pytest.raises(AuthorizationError, match="already exists"):
        ledger.record(make_authorization())


def test_missing_tool_binding_is_rejected_at_issuance():
    with pytest.raises(AuthorizationError, match="allowed tool"):
        make_authorization(allowed_tools=())


def test_expiration_must_follow_issuance():
    with pytest.raises(AuthorizationError, match="expiration"):
        make_authorization(expires_at=NOW)

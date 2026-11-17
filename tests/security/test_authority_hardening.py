from datetime import datetime, timedelta, timezone

import pytest

from nova.authority import Approval, AuthorityStore, ValidationError


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_store(*, approval_required=False, governance_decision="ALLOW"):
    store = AuthorityStore()
    task = store.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision=governance_decision,
        policy_version="policy-v1",
        now=NOW,
        approval_required=approval_required,
    )
    return store, task


def make_approval(task, *, approval_id="approval-1", issued_at=NOW, expires_at=None,
                  principal=None, scope="authorized-objective",
                  policy_version="policy-v1", provenance="event-1"):
    return Approval(
        approval_id=approval_id,
        task_id=task.task_id,
        principal=principal or task.authority_context,
        decision="ALLOW",
        scope=scope,
        policy_version=policy_version,
        issued_at=issued_at,
        expires_at=expires_at,
        provenance=provenance,
    )


def test_approval_expiration_must_follow_issuance():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError, match="expiration must be after issuance"):
        store.record_approval(
            make_approval(
                task,
                issued_at=NOW + timedelta(seconds=2),
                expires_at=NOW + timedelta(seconds=1),
            )
        )


def test_task_requires_nonempty_authority_context_fields():
    store = AuthorityStore()
    with pytest.raises(ValidationError, match="task authority context is incomplete"):
        store.create_task(
            objective="authorized-objective",
            authority_context="",
            governance_decision="ALLOW",
            policy_version="policy-v1",
            now=NOW,
        )


def test_approval_audit_timestamp_tracks_approval_issuance():
    store, task = make_store(approval_required=True)
    issued_at = NOW + timedelta(minutes=5)
    store.record_approval(make_approval(task, issued_at=issued_at))
    event = store.audit_events(task.task_id)[-1]
    assert event.event_type == "APPROVAL_RECORDED"
    assert event.timestamp == issued_at

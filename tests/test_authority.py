from datetime import datetime, timedelta, timezone

import pytest

from nova.authority import Approval, AuthorityStore, ConflictError, State, ValidationError


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_store(*, approval_required=False, governance_decision="ALLOW"):
    store = AuthorityStore()
    task = store.create_task(objective="authorized-objective", authority_context="principal:user-1",
                             governance_decision=governance_decision, policy_version="policy-v1",
                             now=NOW, approval_required=approval_required)
    return store, task


def make_approval(task, *, approval_id="approval-1", issued_at=NOW, expires_at=None,
                  principal=None, scope="authorized-objective", policy_version="policy-v1", provenance="event-1"):
    return Approval(approval_id=approval_id, task_id=task.task_id, principal=principal or task.authority_context,
                    decision="ALLOW", scope=scope, policy_version=policy_version, issued_at=issued_at,
                    expires_at=expires_at, provenance=provenance)


def test_task_identity_is_stable_and_revision_starts_at_zero():
    store, task = make_store()
    assert store.read_task(task.task_id).task_id == task.task_id
    assert task.revision == 0


def test_unknown_task_is_rejected():
    store, _ = make_store()
    with pytest.raises(ValidationError, match="unknown task"):
        store.read_task("missing-task")


def test_timestamp_alone_does_not_create_authority():
    store, task = make_store()
    with pytest.raises(ValidationError):
        store.record_approval(make_approval(task, provenance=""))


def test_approval_principal_must_match_task_authority():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError):
        store.record_approval(make_approval(task, principal="different-principal"))


def test_required_approval_cannot_be_bypassed():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW)


def test_governance_denied_cannot_start_execution():
    store, task = make_store(governance_decision="DENIED")
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW)


def test_governance_escalation_cannot_start_execution():
    store, task = make_store(governance_decision="ESCALATE")
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW)


def test_approval_scope_must_match_task_objective():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError, match="approval scope/objective binding failed"):
        store.record_approval(make_approval(task, scope="different-objective"))


def test_approval_policy_version_must_match_task_policy():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError, match="approval policy/version binding failed"):
        store.record_approval(make_approval(task, policy_version="policy-v2"))


def test_expired_approval_is_rejected():
    store, task = make_store(approval_required=True)
    store.record_approval(make_approval(task, expires_at=NOW + timedelta(seconds=1)))
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW + timedelta(seconds=1), approval_id="approval-1")


def test_approval_is_not_valid_before_issuance():
    store, task = make_store(approval_required=True)
    store.record_approval(make_approval(task, issued_at=NOW + timedelta(seconds=1)))
    with pytest.raises(ValidationError, match="not yet valid"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW, approval_id="approval-1")


def test_unknown_approval_is_rejected():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError, match="approval is not bound to task"):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                   target=State.EXECUTING, now=NOW, approval_id="missing-approval")


def test_stale_revision_cannot_overwrite_newer_state():
    store, task = make_store()
    first = store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    assert first.revision == 1
    with pytest.raises(ConflictError):
        store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.OBSERVING, now=NOW)
    assert store.read_task(task.task_id).state == State.EXECUTING


def test_plain_verification_string_can_never_complete():
    store, task = make_store()
    for expected, target in [(0, State.EXECUTING), (1, State.OBSERVING), (2, State.VERIFYING)]:
        task = store.authorize_transition(task_id=task.task_id, expected_revision=expected, target=target, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=3, target=State.COMPLETED,
                                   now=NOW, verification="VERIFIED")


def test_failed_verification_cannot_complete():
    store, task = make_store()
    for expected, target in [(0, State.EXECUTING), (1, State.OBSERVING), (2, State.VERIFYING)]:
        task = store.authorize_transition(task_id=task.task_id, expected_revision=expected, target=target, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=3, target=State.COMPLETED,
                                   now=NOW, verification="FAILED")


def test_approved_transition_commits_and_records_approval():
    store, task = make_store(approval_required=True)
    store.record_approval(make_approval(task))
    executing = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                           target=State.EXECUTING, now=NOW, approval_id="approval-1")
    assert executing.approval_ids == ("approval-1",)
    event = store.audit_events(task.task_id)[-1]
    assert event.approval_id == "approval-1"
    assert event.expected_revision == 0
    assert event.resulting_revision == 1


def test_approval_recording_is_audited_without_changing_task_revision():
    store, task = make_store(approval_required=True)
    store.record_approval(make_approval(task))
    assert store.read_task(task.task_id).revision == 0
    events = store.audit_events(task.task_id)
    assert len(events) == 2
    event = events[-1]
    assert event.event_type == "APPROVAL_RECORDED"
    assert event.approval_id == "approval-1"
    assert event.expected_revision is None
    assert event.resulting_revision is None


def test_duplicate_approval_id_is_rejected():
    store, task = make_store(approval_required=True)
    store.record_approval(make_approval(task))
    with pytest.raises(ValidationError):
        store.record_approval(make_approval(task, approval_id="approval-1", provenance="event-2"))


def test_audit_is_append_only_and_records_revision():
    store, task = make_store()
    store.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)
    events = store.audit_events(task.task_id)
    assert len(events) == 2
    assert events[-1].expected_revision == 0
    assert events[-1].resulting_revision == 1


def test_terminal_state_cannot_be_changed():
    store, task = make_store()
    for expected, target in [(0, State.EXECUTING), (1, State.OBSERVING), (2, State.VERIFYING)]:
        task = store.authorize_transition(task_id=task.task_id, expected_revision=expected, target=target, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=3, target=State.COMPLETED,
                                   now=NOW, verification="VERIFIED")


def test_approval_expiration_must_follow_issuance():
    store, task = make_store(approval_required=True)
    with pytest.raises(ValidationError, match="expiration must be after issuance"):
        store.record_approval(make_approval(task, issued_at=NOW + timedelta(seconds=2),
                                            expires_at=NOW + timedelta(seconds=1)))


def test_task_requires_nonempty_authority_context_fields():
    store = AuthorityStore()
    with pytest.raises(ValidationError, match="task authority context is incomplete"):
        store.create_task(objective="authorized-objective", authority_context="", governance_decision="ALLOW",
                          policy_version="policy-v1", now=NOW)


def test_approval_audit_timestamp_tracks_approval_issuance():
    store, task = make_store(approval_required=True)
    issued_at = NOW + timedelta(minutes=5)
    store.record_approval(make_approval(task, issued_at=issued_at))
    event = store.audit_events(task.task_id)[-1]
    assert event.event_type == "APPROVAL_RECORDED"
    assert event.timestamp == issued_at

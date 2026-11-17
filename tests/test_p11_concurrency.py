from datetime import datetime, timezone

import pytest

from nova.authority import ConflictError, State
from nova.persistence import SQLiteAuthorityStore


NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def make_store(tmp_path):
    return SQLiteAuthorityStore(str(tmp_path / "nova.db"))


def test_two_authority_readers_cannot_commit_stale_revision(tmp_path):
    first = make_store(tmp_path)
    second = make_store(tmp_path)
    task = first.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )

    first_view = first.read_task(task.task_id)
    second_view = second.read_task(task.task_id)
    assert first_view.revision == second_view.revision == 0

    committed = first.authorize_transition(
        task_id=task.task_id,
        expected_revision=first_view.revision,
        target=State.EXECUTING,
        now=NOW,
    )
    assert committed.revision == 1

    with pytest.raises(ConflictError, match="stale task revision"):
        second.authorize_transition(
            task_id=task.task_id,
            expected_revision=second_view.revision,
            target=State.EXECUTING,
            now=NOW,
        )

    restored = first.read_task(task.task_id)
    assert restored.state is State.EXECUTING
    assert restored.revision == 1
    assert len(first.audit_events(task.task_id)) == 2
    assert len(second.audit_events(task.task_id)) == 2

    first.close()
    second.close()


def test_stale_writer_cannot_consume_or_replay_approval(tmp_path):
    first = make_store(tmp_path)
    second = make_store(tmp_path)
    task = first.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
        approval_required=True,
    )
    from nova.authority import Approval

    approval = Approval(
        approval_id="approval-concurrency",
        task_id=task.task_id,
        principal=task.authority_context,
        decision="ALLOW",
        scope=task.objective,
        policy_version=task.policy_version,
        issued_at=NOW,
        expires_at=None,
        provenance="test-provenance",
    )
    first.record_approval(approval)
    first_view = first.read_task(task.task_id)
    second_view = second.read_task(task.task_id)

    first.authorize_transition(
        task_id=task.task_id,
        expected_revision=first_view.revision,
        target=State.EXECUTING,
        now=NOW,
        approval_id=approval.approval_id,
    )

    with pytest.raises(ConflictError, match="stale task revision"):
        second.authorize_transition(
            task_id=task.task_id,
            expected_revision=second_view.revision,
            target=State.EXECUTING,
            now=NOW,
            approval_id=approval.approval_id,
        )

    assert second._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE approval_id=?",
        (approval.approval_id,),
    ).fetchone()[0] == 1
    assert first.read_task(task.task_id).revision == 1
    assert second.read_task(task.task_id).revision == 1

    first.close()
    second.close()

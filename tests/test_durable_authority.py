from datetime import timedelta

import pytest

from nova.authority import ConflictError, State, ValidationError
from nova.durable_authority import DurableAuthorityError, SQLiteAuthorityStore
from tests.test_authority import NOW, make_approval


def make_durable(tmp_path):
    return SQLiteAuthorityStore(str(tmp_path / "authority.sqlite3"))


def test_task_and_approval_survive_restart(tmp_path):
    first = make_durable(tmp_path)
    task = first.create_task(
        objective="persisted-objective",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
        approval_required=True,
    )
    approval = first.record_approval(
        make_approval(task, scope=task.objective, policy_version=task.policy_version, expires_at=NOW + timedelta(minutes=10))
    )
    first.close()

    second = make_durable(tmp_path)
    restored = second.read_task(task.task_id)
    assert restored.objective == task.objective
    assert restored.revision == 0
    assert second.audit_events(task.task_id)
    assert second._approvals[approval.approval_id].task_id == task.task_id
    second.close()


def test_stale_writer_is_rejected_by_durable_revision(tmp_path):
    first = make_durable(tmp_path)
    task = first.create_task(
        objective="concurrent-objective",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    second = make_durable(tmp_path)
    first.authorize_transition(task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW)

    with pytest.raises(ConflictError):
        second.authorize_transition(
            task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW
        )
    first.close()
    second.close()


def test_transition_write_failure_restores_uncommitted_memory_and_persistence(tmp_path, monkeypatch):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="write-failure",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    real_execute = store._execute
    calls = {"updates": 0}

    def fail_update(sql, *args):
        if sql.lstrip().upper().startswith("UPDATE AUTHORITY_TASKS"):
            calls["updates"] += 1
            raise RuntimeError("injected write failure")
        return real_execute(sql, *args)

    monkeypatch.setattr(store, "_execute", fail_update)
    with pytest.raises(DurableAuthorityError):
        store.authorize_transition(
            task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW
        )

    assert calls["updates"] == 1
    assert store.read_task(task.task_id).state == State.CREATED
    store.close()

    restored = make_durable(tmp_path)
    assert restored.read_task(task.task_id).state == State.CREATED
    restored.close()


def test_audit_return_values_cannot_rewrite_persisted_evidence(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="audit-integrity",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    event = store.audit_events(task.task_id)[0]
    object.__setattr__(event, "detail", "FORGED_SUCCESS")

    store.close()
    restored = make_durable(tmp_path)
    assert restored.audit_events(task.task_id)[0].detail == "task created"
    restored.close()


def test_direct_audit_update_is_rejected(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="audit-update-attack",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    event_id = store.audit_events(task.task_id)[0].event_id
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_audit SET detail=? WHERE event_id=?",
            ("FORGED_SUCCESS", event_id),
        )
    assert store.audit_events(task.task_id)[0].detail == "task created"
    store.close()


def test_direct_audit_delete_is_rejected(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="audit-delete-attack",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    event_id = store.audit_events(task.task_id)[0].event_id
    with pytest.raises(Exception):
        store._db.execute("DELETE FROM authority_audit WHERE event_id=?", (event_id,))
    assert store.audit_events(task.task_id)[0].event_id == event_id
    store.close()


def test_authoritative_task_read_failure_fails_closed(tmp_path, monkeypatch):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="read-failure",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    real_execute = store._execute

    def fail_task_read(sql, *args):
        if sql.lstrip().upper().startswith("SELECT * FROM AUTHORITY_TASKS WHERE TASK_ID"):
            raise RuntimeError("injected authoritative read failure")
        return real_execute(sql, *args)

    monkeypatch.setattr(store, "_execute", fail_task_read)
    with pytest.raises(DurableAuthorityError):
        store.read_task(task.task_id)
    store.close()


def test_commit_failure_restores_persisted_authority(tmp_path, monkeypatch):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="commit-failure",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    real_execute = store._execute

    def fail_commit(sql, *args):
        if sql.strip().upper() == "COMMIT":
            raise RuntimeError("injected commit failure")
        return real_execute(sql, *args)

    monkeypatch.setattr(store, "_execute", fail_commit)
    with pytest.raises(DurableAuthorityError):
        store.authorize_transition(
            task_id=task.task_id, expected_revision=0, target=State.EXECUTING, now=NOW
        )
    monkeypatch.setattr(store, "_execute", real_execute)
    assert store.read_task(task.task_id).state == State.CREATED
    store.close()

    restored = make_durable(tmp_path)
    assert restored.read_task(task.task_id).state == State.CREATED
    restored.close()


def test_unknown_task_fails_closed_after_restart(tmp_path):
    store = make_durable(tmp_path)
    with pytest.raises(ValidationError):
        store.read_task("missing-task")
    store.close()


def test_persisted_task_identity_cannot_be_substituted(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="approved-objective",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
        approval_required=True,
    )
    approval = store.record_approval(
        make_approval(task, scope=task.objective, policy_version=task.policy_version)
    )
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_tasks SET objective=? WHERE task_id=?",
            ("expanded-recovery-scope", task.task_id),
        )
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_tasks SET authority_context=? WHERE task_id=?",
            ("principal:attacker", task.task_id),
        )
    assert store._approvals[approval.approval_id].scope == task.objective
    store.close()


def test_persisted_approval_timestamp_and_provenance_cannot_be_substituted(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="timestamp-bound-objective",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
        approval_required=True,
    )
    approval = store.record_approval(
        make_approval(
            task,
            scope=task.objective,
            policy_version=task.policy_version,
            expires_at=NOW + timedelta(minutes=10),
        )
    )
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_approvals SET issued_at=?, provenance=? WHERE approval_id=?",
            (NOW.replace(year=NOW.year + 1).isoformat(), "forged", approval.approval_id),
        )
    store.close()


def test_recovery_cannot_expand_persisted_principal_or_objective(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="recovery-objective",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
        approval_required=True,
    )
    approval = store.record_approval(
        make_approval(task, scope=task.objective, policy_version=task.policy_version)
    )
    store.authorize_transition(
        task_id=task.task_id, expected_revision=0, target=State.EXECUTING,
        now=NOW, approval_id=approval.approval_id,
    )
    recovery = store.authorize_transition(
        task_id=task.task_id, expected_revision=1, target=State.RECOVERY,
        now=NOW, approval_id=approval.approval_id,
    )
    assert recovery.state == State.RECOVERY
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_tasks SET objective=? WHERE task_id=?",
            ("expanded-recovery-scope", task.task_id),
        )
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_tasks SET authority_context=? WHERE task_id=?",
            ("principal:attacker", task.task_id),
        )
    store.close()


def test_duplicate_approval_replay_is_rejected_after_restart(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="replay-protected",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
        approval_required=True,
    )
    approval = store.record_approval(
        make_approval(
            task,
            scope=task.objective,
            policy_version=task.policy_version,
            expires_at=NOW + timedelta(minutes=10),
        )
    )
    store.close()

    restored = make_durable(tmp_path)
    with pytest.raises(ValidationError):
        restored.record_approval(approval)
    restored.close()


def test_direct_durable_completion_escape_is_rejected(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="completion-boundary",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_tasks SET state=? WHERE task_id=?",
            (State.COMPLETED.value, task.task_id),
        )
    with pytest.raises(ValidationError):
        store.authorize_transition(
            task_id=task.task_id, expected_revision=0, target=State.COMPLETED, now=NOW,
            verification="VERIFIED",
        )
    store.close()


def test_failure_audit_cannot_be_rewritten_as_success(tmp_path):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="audit-failure-rewrite",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    event = store.audit_events(task.task_id)[0]
    with pytest.raises(Exception):
        store._db.execute(
            "UPDATE authority_audit SET event_type=?, detail=? WHERE event_id=?",
            ("SUCCESS", "forged success", event.event_id),
        )
    assert store.audit_events(task.task_id)[0].event_type == event.event_type
    assert store.audit_events(task.task_id)[0].detail == event.detail
    store.close()

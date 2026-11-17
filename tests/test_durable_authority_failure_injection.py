import pytest

from nova.authority import State
from nova.durable_authority import DurableAuthorityError
from tests.test_authority import NOW
from tests.test_durable_authority import make_durable


def test_audit_write_failure_cannot_leave_partial_authoritative_transition(tmp_path, monkeypatch):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="partial-commit",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    real_execute = store._execute

    def fail_audit_insert(sql, *args):
        if sql.lstrip().upper().startswith("INSERT INTO AUTHORITY_AUDIT"):
            raise RuntimeError("injected audit write failure")
        return real_execute(sql, *args)

    monkeypatch.setattr(store, "_execute", fail_audit_insert)
    with pytest.raises(DurableAuthorityError):
        store.authorize_transition(
            task_id=task.task_id,
            expected_revision=0,
            target=State.EXECUTING,
            now=NOW,
        )

    monkeypatch.setattr(store, "_execute", real_execute)
    assert store.read_task(task.task_id).state == State.CREATED
    store.close()

    restored = make_durable(tmp_path)
    assert restored.read_task(task.task_id).state == State.CREATED
    restored.close()


def test_rollback_failure_is_fail_closed_and_does_not_report_success(tmp_path, monkeypatch):
    store = make_durable(tmp_path)
    task = store.create_task(
        objective="rollback-failure",
        authority_context="principal:user",
        governance_decision="ALLOW",
        policy_version="v1",
        now=NOW,
    )
    real_execute = store._execute

    def fail_update_and_rollback(sql, *args):
        normalized = sql.strip().upper()
        if normalized.startswith("UPDATE AUTHORITY_TASKS"):
            raise RuntimeError("injected write failure")
        if normalized == "ROLLBACK":
            raise RuntimeError("injected rollback failure")
        return real_execute(sql, *args)

    monkeypatch.setattr(store, "_execute", fail_update_and_rollback)
    with pytest.raises(DurableAuthorityError):
        store.authorize_transition(
            task_id=task.task_id,
            expected_revision=0,
            target=State.EXECUTING,
            now=NOW,
        )
    assert store._tasks[task.task_id].state == State.CREATED
    store.close()

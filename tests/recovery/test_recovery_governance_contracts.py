"""Adversarial lifecycle contracts for rollback/stop/escalation semantics."""
from __future__ import annotations

import pytest

from nova.authority import State, ValidationError
from nova.persistence import SQLiteAuthorityStore
from tests.governed_fixtures import NOW, governed_task


def _store_task(*, decision="ALLOW"):
    store = SQLiteAuthorityStore()
    task = store.create_task(
        objective="execute:demo", authority_context="principal:demo",
        governance_decision=decision, policy_version="p1", now=NOW,
    )
    return store, task


def test_stop_is_terminal_and_cannot_resume():
    store, task = _store_task()
    stopped = store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                         target=State.STOPPED, now=NOW)
    assert stopped.state is State.STOPPED
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=1,
                                   target=State.EXECUTING, now=NOW)


def test_denied_is_terminal_and_cannot_resume():
    store, task = _store_task(decision="DENIED")
    denied = store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                        target=State.DENIED, now=NOW)
    assert denied.state is State.DENIED
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=1,
                                   target=State.EXECUTING, now=NOW)


def test_escalation_is_not_an_implicit_resume():
    store, task = _store_task()
    escalated = store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                           target=State.ESCALATE, now=NOW)
    assert escalated.state is State.ESCALATE
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=1,
                                   target=State.EXECUTING, now=NOW)

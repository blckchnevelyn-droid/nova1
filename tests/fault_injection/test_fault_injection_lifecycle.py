"""Fail-closed lifecycle fault-injection contracts."""
from __future__ import annotations

import pytest

from nova.authority import ConflictError, State, ValidationError
from nova.persistence import SQLiteAuthorityStore
from tests.governed_fixtures import NOW


def make_task():
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:demo", authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    return store, task


def test_stale_revision_is_rejected_without_state_change():
    store, task = make_task()
    first = store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                       target=State.EXECUTING, now=NOW)
    with pytest.raises(ConflictError, match="stale task revision"):
        store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                   target=State.OBSERVING, now=NOW)
    current = store.read_task(task.task_id)
    assert current.revision == first.revision
    assert current.state is State.EXECUTING


def test_invalid_transition_fails_closed():
    store, task = make_task()
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=0,
                                   target=State.COMPLETED, now=NOW, verification="VERIFIED")
    current = store.read_task(task.task_id)
    assert current.state is State.CREATED
    assert current.revision == 0

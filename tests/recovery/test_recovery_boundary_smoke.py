"""Minimal recovery-boundary smoke contracts.

This test intentionally exercises the governed execution constructor rather
than the internal SQLite execution implementation. Full recovery scenarios
remain in the dedicated recovery suite.
"""
from __future__ import annotations

from nova.authority import State
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from tests.governed_fixtures import governed_execution, governed_task


def test_recovery_path_starts_from_governed_execution_boundary():
    store, initial_task = governed_task()
    task, boundary, _, _ = governed_execution(store, initial_task)
    assert task.state is State.EXECUTING
    # The public consequential boundary is the only supported constructor.
    assert isinstance(boundary, GovernedSQLiteExecutionAuthority)
    store.close()

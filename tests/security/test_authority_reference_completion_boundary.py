from datetime import datetime, timezone

import pytest

from nova.authority import AuthorityStore, State, ValidationError


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_reference_authority_store_cannot_authorize_completed_without_durable_evidence():
    store = AuthorityStore()
    task = store.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
    )
    for target in (State.EXECUTING, State.OBSERVING, State.VERIFYING):
        task = store.authorize_transition(
            task_id=task.task_id,
            expected_revision=task.revision,
            target=target,
            now=NOW,
        )

    with pytest.raises(
        ValidationError,
        match="AuthorityStore cannot authorize COMPLETED; use SQLiteAuthorityStore",
    ):
        store.authorize_transition(
            task_id=task.task_id,
            expected_revision=task.revision,
            target=State.COMPLETED,
            now=NOW,
        )

    restored = store.read_task(task.task_id)
    assert restored.state == State.VERIFYING
    assert restored.revision == 3
    assert store.audit_events(task.task_id)[-1].detail == "OBSERVING->VERIFYING"

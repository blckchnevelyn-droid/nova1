import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from nova.authority import State
from nova.persistence import SQLiteAuthorityStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_audit_detail_cannot_consume_approval(tmp_path):
    store = SQLiteAuthorityStore(str(tmp_path / "nova.db"))
    task = store.create_task(
        objective="authorized-objective",
        authority_context="principal:user-1",
        governance_decision="ALLOW",
        policy_version="policy-v1",
        now=NOW,
        approval_required=True,
    )
    from nova.authority import Approval

    store.record_approval(Approval(
        approval_id="approval-1",
        task_id=task.task_id,
        principal=task.authority_context,
        decision="ALLOW",
        scope=task.objective,
        policy_version=task.policy_version,
        issued_at=NOW,
        expires_at=None,
        provenance="event-1",
    ))

    trigger = store._db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='audit_transition_consume_approval'"
    ).fetchone()
    assert trigger is None

    event_id = str(uuid4())
    store._db.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            task.task_id,
            "STATE_TRANSITION",
            NOW.isoformat(),
            0,
            1,
            task.authority_context,
            task.policy_version,
            "approval-1",
            "forged-description->EXECUTING",
            "0" * 64,
            "",
        ),
    )

    assert store._db.execute(
        "SELECT COUNT(*) FROM approval_consumptions WHERE approval_id='approval-1'"
    ).fetchone()[0] == 0
    assert store.read_task(task.task_id).state == State.CREATED
    store.close()

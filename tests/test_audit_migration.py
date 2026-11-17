"""Migration of pre-chain execution audit databases.

These tests fail if the migration is not actually executed on open.
"""
import sqlite3

import pytest

from nova.execution import SQLiteExecutionAuthority
from nova.file_write_pilot import EvidenceTampered, FileWritePilot
from nova.file_write_sandbox import SandboxRoot
from tests.file_write_fixtures import install_env, make_world
from tests.governed_fixtures import NOW


def _old_schema_database(tmp_path, monkeypatch):
    """Write a database with pilot activity, then strip the chain columns to mimic the old schema."""
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    db = str(tmp_path / "old.db")
    world = make_world(db, relative_path="out/m.txt", content=b"migrate me\n")
    pilot = FileWritePilot(world["boundary"], SandboxRoot(str(sandbox)), store=world["store"])
    pilot.submit(task_id=world["task"].task_id, idempotency_key="m", relative_path="out/m.txt",
                 content=b"migrate me\n", authorization=world["auth"], worker_id="worker-1", now=NOW)
    task_id = world["task"].task_id
    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER execution_audit_no_update")
    conn.execute("ALTER TABLE execution_audit_events DROP COLUMN event_hash")
    conn.execute("ALTER TABLE execution_audit_events DROP COLUMN previous_hash")
    conn.commit()
    conn.close()
    return db, task_id, sandbox


def test_open_migrates_old_database_and_backfills_a_verifiable_chain(tmp_path, monkeypatch):
    db, task_id, sandbox = _old_schema_database(tmp_path, monkeypatch)
    conn = sqlite3.connect(db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(execution_audit_events)")}
    conn.close()
    assert "event_hash" not in cols  # precondition: really the old schema

    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    from nova.persistence import SQLiteAuthorityStore
    store = SQLiteAuthorityStore(db)
    boundary = GovernedSQLiteExecutionAuthority(store, SQLiteAuthorizationLedger(store._db),
                                                SQLiteIdentityGate(store._db))
    cols = {r[1] for r in store._db.execute("PRAGMA table_info(execution_audit_events)")}
    assert {"previous_hash", "event_hash"} <= cols
    assert boundary.verify_execution_audit(task_id) >= 1


def test_migrated_table_is_append_only_again(tmp_path, monkeypatch):
    db, task_id, _ = _old_schema_database(tmp_path, monkeypatch)
    from nova.persistence import SQLiteAuthorityStore
    store = SQLiteAuthorityStore(db)
    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    GovernedSQLiteExecutionAuthority(store, SQLiteAuthorizationLedger(store._db), SQLiteIdentityGate(store._db))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE execution_audit_events SET detail = 'x'")


def test_migration_is_idempotent(tmp_path, monkeypatch):
    db, task_id, _ = _old_schema_database(tmp_path, monkeypatch)
    from nova.persistence import SQLiteAuthorityStore
    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    for _ in range(3):
        store = SQLiteAuthorityStore(db)
        boundary = GovernedSQLiteExecutionAuthority(store, SQLiteAuthorizationLedger(store._db),
                                                    SQLiteIdentityGate(store._db))
        assert boundary.verify_execution_audit(task_id) >= 1


def test_tampering_after_migration_is_still_detected(tmp_path, monkeypatch):
    db, task_id, sandbox = _old_schema_database(tmp_path, monkeypatch)
    from nova.persistence import SQLiteAuthorityStore
    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    from nova.authority import ValidationError
    store = SQLiteAuthorityStore(db)
    boundary = GovernedSQLiteExecutionAuthority(store, SQLiteAuthorizationLedger(store._db),
                                                SQLiteIdentityGate(store._db))
    store._db.execute("DROP TRIGGER execution_audit_no_update")
    store._db.execute("UPDATE execution_audit_events SET detail = 'rewritten' WHERE event_type = 'ATTEMPT_SUCCEEDED'")
    with pytest.raises(ValidationError, match="execution audit"):
        boundary.verify_execution_audit(task_id)

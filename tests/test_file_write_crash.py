"""Crash contract for the file-write pilot: real subprocess kills, recovery in a separate process.

Rows follow docs/security/FILE_WRITE_PILOT.md, "Crash-point contract".
"""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from nova.authority import ConflictError
from nova.execution import AttemptState
from nova.file_write_pilot import FileWritePilot
from nova.file_write_sandbox import SandboxRoot
from tests.file_write_fixtures import install_env, make_world
from tests.governed_fixtures import NOW
from tests.pilot_worker import CRASH_EXIT

REPO = Path(__file__).resolve().parents[1]
REL = "out/report.txt"
CONTENT = b"crash-matrix bytes\n"
WORKER = "worker-1"


def run_worker(cfg):
    return subprocess.run([sys.executable, "-m", "tests.pilot_worker", json.dumps(cfg)],
                          cwd=REPO, capture_output=True, text=True, timeout=120)


def setup_crash(tmp_path, monkeypatch, crash_at, content=CONTENT):
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    db = str(tmp_path / "nova.db")
    world = make_world(db, relative_path=REL, content=content, authorization_id="auth-crash")
    base = {"db": db, "sandbox": str(sandbox), "relative_path": REL, "content": content.decode(),
            "authorization_id": "auth-crash", "task_id": world["task"].task_id,
            "idempotency_key": "key-1", "worker_id": WORKER}
    crashed = run_worker({**base, "mode": "submit", "crash_at": crash_at})
    assert crashed.returncode == CRASH_EXIT, crashed.stderr
    return db, sandbox, base, world


def attempts(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT attempt_id, state, fence FROM execution_attempts ORDER BY fence").fetchall()
    finally:
        conn.close()


def evidence_count(db):
    """Terminal outcomes recorded in the kernel's chained audit (ATTEMPT_SUCCEEDED events)."""
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT COUNT(*) FROM execution_audit_events WHERE event_type='ATTEMPT_SUCCEEDED'").fetchone()[0]
    finally:
        conn.close()


def recover(base):
    done = run_worker({**base, "mode": "resume", "crash_at": ""})
    assert done.returncode == 0, done.stderr
    assert "completed" in done.stdout


def verify_in_fresh_process(db, sandbox, task_id):
    """Independent check: reopen the database and recompute the evidence chain."""
    code = (
        "import sys; sys.path.insert(0, '.');"
        "from nova.persistence import SQLiteAuthorityStore;"
        "from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate;"
        "from nova.governed_execution import GovernedSQLiteExecutionAuthority;"
        "from nova.file_write_pilot import FileWritePilot;"
        "from nova.file_write_sandbox import SandboxRoot;"
        f"s=SQLiteAuthorityStore({db!r});"
        "b=GovernedSQLiteExecutionAuthority(s, SQLiteAuthorizationLedger(s._db), SQLiteIdentityGate(s._db));"
        f"print(FileWritePilot(b, SandboxRoot({str(sandbox)!r}), store=s).verify_evidence({task_id!r}))"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip())


def test_row1_crash_after_authorization_before_attempt_recovers_with_one_attempt(tmp_path, monkeypatch):
    db, sandbox, base, _ = setup_crash(tmp_path, monkeypatch, "after_authorization")
    assert attempts(db) == []
    assert not (sandbox / REL).exists()
    recover(base)
    got = attempts(db)
    assert len(got) == 1 and got[0][1] == AttemptState.SUCCEEDED.value
    assert (sandbox / REL).read_bytes() == CONTENT
    assert verify_in_fresh_process(db, sandbox, base["task_id"]) == 1


def test_row2_crash_after_claim_before_write_recovers_same_attempt(tmp_path, monkeypatch):
    db, sandbox, base, _ = setup_crash(tmp_path, monkeypatch, "after_claim")
    before = attempts(db)
    assert len(before) == 1 and before[0][1] == AttemptState.CLAIMED.value
    assert not (sandbox / REL).exists()
    recover(base)
    after = attempts(db)
    assert after == [(before[0][0], AttemptState.SUCCEEDED.value, before[0][2])]  # same attempt, same fence
    assert (sandbox / REL).read_bytes() == CONTENT
    assert evidence_count(db) == 1


def test_row2b_crash_while_staging_leaves_harmless_staging_file(tmp_path, monkeypatch):
    db, sandbox, base, _ = setup_crash(tmp_path, monkeypatch, "after_stage")
    assert not (sandbox / REL).exists()
    staged = [n for n in os.listdir(sandbox / "out") if n.startswith(".nova-stage-")]
    assert len(staged) == 1
    recover(base)
    assert sorted(os.listdir(sandbox / "out")) == ["report.txt"]
    assert (sandbox / REL).read_bytes() == CONTENT


def test_row3_crash_after_publish_before_evidence_recovers_without_second_write(tmp_path, monkeypatch):
    db, sandbox, base, _ = setup_crash(tmp_path, monkeypatch, "after_publish")
    assert (sandbox / REL).read_bytes() == CONTENT          # the effect happened
    inode = os.stat(sandbox / REL).st_ino
    before = attempts(db)
    assert before[0][1] == AttemptState.CLAIMED.value
    recover(base)
    assert os.stat(sandbox / REL).st_ino == inode            # not rewritten or replaced
    after = attempts(db)
    assert after == [(before[0][0], AttemptState.SUCCEEDED.value, before[0][2])]
    assert sorted(os.listdir(sandbox / "out")) == ["report.txt"]
    assert verify_in_fresh_process(db, sandbox, base["task_id"]) == 1


def test_row4_crash_after_evidence_recovery_does_not_repeat_the_effect(tmp_path, monkeypatch):
    db, sandbox, base, _ = setup_crash(tmp_path, monkeypatch, "after_evidence")
    assert attempts(db)[0][1] == AttemptState.SUCCEEDED.value
    assert evidence_count(db) == 1
    inode = os.stat(sandbox / REL).st_ino
    recover(base)
    assert os.stat(sandbox / REL).st_ino == inode
    assert len(attempts(db)) == 1 and evidence_count(db) == 1
    assert verify_in_fresh_process(db, sandbox, base["task_id"]) == 1


def test_target_changed_during_crash_window_is_escalated_not_overwritten(tmp_path, monkeypatch):
    db, sandbox, base, world = setup_crash(tmp_path, monkeypatch, "after_publish")
    (sandbox / REL).write_bytes(b"someone else changed this")  # conflicting bytes in the ambiguous window
    recover(base)
    state = attempts(db)[0][1]
    assert state == AttemptState.UNKNOWN.value
    assert (sandbox / REL).read_bytes() == b"someone else changed this"
    root = SandboxRoot(str(sandbox))
    pilot = FileWritePilot(world["boundary"], root, store=world["store"])
    with pytest.raises(ConflictError, match="explicit recovery decision"):
        pilot.resume(task_id=base["task_id"], idempotency_key="key-1", relative_path=REL, content=CONTENT,
                     authorization=world["auth"], worker_id=WORKER, now=NOW)

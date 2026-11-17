"""Concurrency for the file-write pilot: separate OS processes racing on one database."""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from tests.file_write_fixtures import install_env, make_world

REPO = Path(__file__).resolve().parents[1]
REL = "out/race.txt"
CONTENT = b"raced bytes\n"


def _spawn(cfg):
    return subprocess.Popen([sys.executable, "-m", "tests.pilot_worker", json.dumps(cfg)],
                            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_two_processes_submitting_the_same_operation_produce_exactly_one_write(tmp_path, monkeypatch):
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    db = str(tmp_path / "nova.db")
    world = make_world(db, relative_path=REL, content=CONTENT, authorization_id="auth-race")
    cfg = {"db": db, "sandbox": str(sandbox), "mode": "submit", "crash_at": "", "relative_path": REL,
           "content": CONTENT.decode(), "authorization_id": "auth-race",
           "task_id": world["task"].task_id, "idempotency_key": "race-key", "worker_id": "worker-1"}
    procs = [_spawn(cfg) for _ in range(2)]
    results = [p.communicate(timeout=120) + (p.returncode,) for p in procs]
    codes = sorted(r[2] for r in results)
    assert codes == [0, 1], results  # one winner; the loser is refused, not silently duplicated

    conn = sqlite3.connect(db)
    states = [r[0] for r in conn.execute("SELECT state FROM execution_attempts ORDER BY fence")]
    evidence = conn.execute("SELECT COUNT(*) FROM execution_audit_events WHERE event_type='ATTEMPT_SUCCEEDED'").fetchone()[0]
    conn.close()
    assert states == ["SUCCEEDED"]
    assert evidence == 1
    assert (sandbox / REL).read_bytes() == CONTENT
    assert sorted(p.name for p in (sandbox / "out").iterdir()) == ["race.txt"]


def test_two_processes_racing_different_operations_for_one_path_yield_one_winner(tmp_path, monkeypatch):
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    db = str(tmp_path / "nova.db")
    world = make_world(db, relative_path=REL, content=CONTENT, authorization_id="auth-race2")
    base = {"db": db, "sandbox": str(sandbox), "mode": "submit", "crash_at": "", "relative_path": REL,
            "content": CONTENT.decode(), "authorization_id": "auth-race2",
            "task_id": world["task"].task_id, "worker_id": "worker-1"}
    procs = [_spawn({**base, "idempotency_key": f"k-{i}"}) for i in range(2)]
    for p in procs:
        p.communicate(timeout=120)
    conn = sqlite3.connect(db)
    states = sorted(r[0] for r in conn.execute("SELECT state FROM execution_attempts"))
    conn.close()
    # Each operation attempts its own publish. Exactly one can link into place; the other must fail closed.
    assert states.count("SUCCEEDED") == 1
    assert states.count("FAILED") == 1
    assert (sandbox / REL).read_bytes() == CONTENT

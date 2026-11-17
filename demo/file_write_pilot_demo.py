"""Deterministic demo of the Nova file-write pilot: three scenarios, fixed inputs.

Run from the repository root:  python3 demo/file_write_pilot_demo.py
Output is compared against demo/expected_transcript.txt by tests/test_file_write_demo.py.
It prints no timestamps, random identifiers, or temporary paths.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

os.environ.setdefault("NOVA_COMPLETION_PROOF_INTEGRITY_KEY", "demo-completion-key-material-0123456789")
os.environ.setdefault("NOVA_DURABLE_INTEGRITY_KEY", "demo-durable-key-material-0123456789abcdef")

from nova.authority import ConflictError  # noqa: E402
from nova.file_write_pilot import EvidenceTampered, FileWritePilot  # noqa: E402
from nova.file_write_sandbox import SandboxRoot  # noqa: E402
from nova.governance import AuthorizationError  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from nova.file_write_completion import IndependentFileVerifier, complete_task  # noqa: E402
from tests.file_write_fixtures import make_world  # noqa: E402
from tests.governed_fixtures import NOW  # noqa: E402

REL = "out/report.txt"
OTHER = "out/unapproved.txt"
CONTENT = b"fixed demo content for the file-write pilot\n"
WORKER = "worker-1"
CRASH_EXIT = 77


def say(line=""):
    print(line)


def main():
    say("Nova file-write pilot demo")
    say("Assumptions: POSIX host, trusted kernel and runtime, integrity key held outside the database.")
    say("Not shown: semantic correctness of the content, approver intent, or host-compromise resistance.")
    say(f"Content sha256: {hashlib.sha256(CONTENT).hexdigest()}")
    say()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        sandbox = tmp / "sandbox"
        (sandbox / "out").mkdir(parents=True)
        db = str(tmp / "nova.db")

        say("Scenario 1: unauthorized write is denied before any file effect")
        world = make_world(db, relative_path=REL, content=CONTENT, authorization_id="auth-approved")
        pilot = FileWritePilot(world["boundary"], SandboxRoot(str(sandbox)), store=world["store"])
        try:
            pilot.submit(task_id=world["task"].task_id, idempotency_key="denied-1", relative_path=OTHER,
                         content=CONTENT, authorization=world["auth"], worker_id=WORKER, now=NOW)
            say("  result: UNEXPECTED ALLOW")
        except AuthorizationError as exc:
            say(f"  result: denied ({exc})")
        say(f"  target absent: {not (sandbox / OTHER).exists()}")
        say()

        say("Scenario 2: authorized write killed after publish, recovered in a separate process")
        world2_db = str(tmp / "nova2.db")
        world2 = make_world(world2_db, relative_path=REL, content=CONTENT, authorization_id="auth-crash")
        base = {"db": world2_db, "sandbox": str(sandbox), "relative_path": REL,
                "content": CONTENT.decode(), "authorization_id": "auth-crash",
                "task_id": world2["task"].task_id, "idempotency_key": "crash-1", "worker_id": WORKER}
        crashed = _worker({**base, "mode": "submit", "crash_at": "after_publish"})
        say(f"  worker exit at crash point: {crashed.returncode == CRASH_EXIT}")
        say(f"  target present before recovery: {(sandbox / REL).exists()}")
        recovered = _worker({**base, "mode": "resume", "crash_at": ""})
        say(f"  recovery process completed: {recovered.returncode == 0}")
        conn = sqlite3.connect(world2_db)
        state, fence = conn.execute("SELECT state, fence FROM execution_attempts").fetchone()
        attempts = conn.execute("SELECT COUNT(*) FROM execution_attempts").fetchone()[0]
        conn.close()
        say(f"  attempts recorded: {attempts}, state: {state}, fence: {fence}")
        say(f"  target bytes exact: {(sandbox / REL).read_bytes() == CONTENT}")
        verified = world2_pilot_check(world2, sandbox)
        say(f"  evidence records verified: {verified}")
        verifier = IndependentFileVerifier(
            verifier_id="verifier-demo", private_key=Ed25519PrivateKey.generate(),
            sandbox=SandboxRoot(str(sandbox)), store=world2["store"],
            valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1))
        done = complete_task(store=world2["store"], boundary=world2["boundary"], verifier=verifier,
                             task_id=world2["task"].task_id, now=NOW)
        say(f"  independent completion: task {done.state.value}, verification {done.verification}")
        say()

        say("Scenario 3: evidence altered without the integrity key is detected")
        conn = sqlite3.connect(world2_db)
        conn.execute("DROP TRIGGER execution_terminal_attempt_no_update")
        conn.execute("UPDATE execution_attempts SET result_evidence = REPLACE(result_evidence, 'SUCCEEDED', 'FAILED')")
        conn.commit()
        conn.close()
        try:
            world2_pilot_check(world2, sandbox)
            say("  verification: UNEXPECTED PASS")
        except EvidenceTampered as exc:
            say(f"  verification: refused ({exc})")
        say()
        say("Demo complete. Completion is independently verified; semantic correctness of the content is not.")


def _worker(cfg):
    return subprocess.run([sys.executable, "-m", "tests.pilot_worker", json.dumps(cfg)],
                          cwd=REPO, capture_output=True, text=True, timeout=120)


def world2_pilot_check(world, sandbox):
    pilot = FileWritePilot(world["boundary"], SandboxRoot(str(sandbox)), store=world["store"])
    return pilot.verify_evidence(world["task"].task_id)


if __name__ == "__main__":
    main()

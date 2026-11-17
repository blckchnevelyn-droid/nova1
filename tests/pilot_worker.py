"""Subprocess worker for crash tests: runs one pilot step and dies at a named point.

Usage: python -m tests.pilot_worker '<json config>'
Exit code 77 means the worker was killed at crash_at with os._exit (no cleanup).
"""
from __future__ import annotations

import json
import os
import sys

from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.file_write_pilot import FileWritePilot
from nova.file_write_sandbox import SandboxRoot
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.persistence import SQLiteAuthorityStore
from tests.governed_fixtures import NOW

CRASH_EXIT = 77


def main() -> int:
    cfg = json.loads(sys.argv[1])
    store = SQLiteAuthorityStore(cfg["db"])
    ledger = SQLiteAuthorizationLedger(store._db)
    identity = SQLiteIdentityGate(store._db)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    authorization = ledger.get(cfg["authorization_id"], now=NOW)
    pilot = FileWritePilot(boundary, SandboxRoot(cfg["sandbox"]), store=store)
    crash_at = cfg.get("crash_at") or ""

    def hook(point: str) -> None:
        if point == crash_at:
            os._exit(CRASH_EXIT)

    method = pilot.submit if cfg["mode"] == "submit" else pilot.resume
    method(task_id=cfg["task_id"], idempotency_key=cfg["idempotency_key"],
           relative_path=cfg["relative_path"], content=cfg["content"].encode("utf-8"),
           authorization=authorization, worker_id=cfg["worker_id"], now=NOW, hook=hook)
    print("completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""SQLite-backed authoritative lifecycle persistence for Nova.

This module provides the minimum durable authority boundary required by ADR-001.
The in-memory AuthorityStore remains a reference contract implementation.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional, Callable

from .authority import Approval, AuthorityStore, ConflictError, State, Task, ValidationError


class DurableAuthorityError(Exception):
    """Raised when authoritative persistence cannot be established."""


class SQLiteAuthorityStore(AuthorityStore):
    """Durable authority store with atomic revision and append-only audit rows."""

    def __init__(self, database: str = ":memory:") -> None:
        super().__init__()
        self._database = database
        self._db = sqlite3.connect(database, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._failure_seam: Optional[Callable[[str], None]] = None
        self._initialize()
        self._load()

    def close(self) -> None:
        self._db.close()

    def set_failure_seam(self, seam: Optional[Callable[[str], None]]) -> None:
        """Set a function that is called before each SQL operation for controlled failure injection.

        The seam function receives the normalized SQL statement and can raise an exception
        to simulate a failure at that point.
        """
        self._failure_seam = seam

    def _execute(self, sql: str, *args):
        """Database execution seam used by controlled persistence fault injection."""
        if self._failure_seam:
            normalized = sql.strip().upper()
            self._failure_seam(normalized)
        return self._db.execute(sql, *args)

    def _initialize(self) -> None:
        try:
            self._db.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS authority_tasks (
                    task_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    state TEXT NOT NULL,
                    authority_context TEXT NOT NULL,
                    governance_decision TEXT NOT NULL,
                    approval_required INTEGER NOT NULL,
                    approval_ids TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    verification TEXT
                );
                CREATE TABLE IF NOT EXISTS authority_approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES authority_tasks(task_id),
                    principal TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT,
                    provenance TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authority_audit (
                    event_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES authority_tasks(task_id),
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    expected_revision INTEGER,
                    resulting_revision INTEGER,
                    authority_context TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    approval_id TEXT,
                    detail TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS authority_task_identity_no_update
                BEFORE UPDATE ON authority_tasks
                WHEN OLD.objective != NEW.objective
                  OR OLD.authority_context != NEW.authority_context
                  OR OLD.governance_decision != NEW.governance_decision
                  OR OLD.approval_required != NEW.approval_required
                  OR OLD.policy_version != NEW.policy_version
                  OR OLD.created_at != NEW.created_at
                BEGIN
                    SELECT RAISE(ABORT, 'authoritative task identity is immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS authority_task_no_direct_completion
                BEFORE UPDATE ON authority_tasks
                WHEN NEW.state = 'COMPLETED'
                BEGIN
                    SELECT RAISE(ABORT, 'durable completion requires an independent verified completion contract');
                END;
                CREATE TRIGGER IF NOT EXISTS authority_approval_no_update
                BEFORE UPDATE ON authority_approvals BEGIN
                    SELECT RAISE(ABORT, 'authoritative approval is immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS authority_approval_no_delete
                BEFORE DELETE ON authority_approvals BEGIN
                    SELECT RAISE(ABORT, 'authoritative approval is immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS authority_audit_no_update
                BEFORE UPDATE ON authority_audit BEGIN
                    SELECT RAISE(ABORT, 'audit ledger is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS authority_audit_no_delete
                BEFORE DELETE ON authority_audit BEGIN
                    SELECT RAISE(ABORT, 'audit ledger is append-only');
                END;
                """
            )
        except sqlite3.Error as exc:
            raise DurableAuthorityError("authoritative persistence initialization failed") from exc

    @staticmethod
    def _dt(value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None
        return datetime.fromisoformat(value).astimezone(timezone.utc)

    @staticmethod
    def _iso(value: Optional[datetime]) -> Optional[str]:
        return value.isoformat() if value is not None else None

    @classmethod
    def _task_from_row(cls, row) -> Task:
        return Task(
            row["task_id"], row["objective"], State(row["state"]), row["authority_context"],
            row["governance_decision"], bool(row["approval_required"]),
            tuple(filter(None, row["approval_ids"].split(","))), row["policy_version"],
            cls._dt(row["created_at"]), cls._dt(row["updated_at"]), row["revision"],
            row["verification"],
        )

    @classmethod
    def _approval_from_row(cls, row) -> Approval:
        return Approval(
            row["approval_id"], row["task_id"], row["principal"], row["decision"], row["scope"],
            row["policy_version"], cls._dt(row["issued_at"]), cls._dt(row["expires_at"]), row["provenance"],
        )

    def _load(self) -> None:
        try:
            self._tasks.clear()
            self._approvals.clear()
            self._audit.clear()
            for row in self._execute("SELECT * FROM authority_tasks"):
                self._tasks[row["task_id"]] = self._task_from_row(row)
            for row in self._execute("SELECT * FROM authority_approvals"):
                self._approvals[row["approval_id"]] = self._approval_from_row(row)
        except Exception as exc:
            raise DurableAuthorityError("authoritative persistence read/validation failed") from exc

    def read_task(self, task_id: str) -> Task:
        """Read task authority directly from durable persistence."""
        try:
            row = self._execute(
                "SELECT * FROM authority_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
        except Exception as exc:
            raise DurableAuthorityError("authoritative task read failed") from exc
        if row is None:
            raise ValidationError("unknown task")
        try:
            task = self._task_from_row(row)
        except Exception as exc:
            raise DurableAuthorityError("authoritative task validation failed") from exc
        self._tasks[task.task_id] = task
        return task

    def _persist_task(self, task: Task, expected_revision: int) -> None:
        cursor = self._execute(
            """UPDATE authority_tasks SET state=?, approval_ids=?, updated_at=?, revision=?, verification=?
               WHERE task_id=? AND revision=?""",
            (task.state.value, ",".join(task.approval_ids), self._iso(task.updated_at), task.revision,
             task.verification, task.task_id, expected_revision),
        )
        if cursor.rowcount != 1:
            raise ConflictError("authoritative revision conflict")

    def _rollback(self) -> None:
        self._execute("ROLLBACK")

    def create_task(self, **kwargs) -> Task:
        task = super().create_task(**kwargs)
        try:
            self._execute("BEGIN IMMEDIATE")
            self._execute(
                "INSERT INTO authority_tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (task.task_id, task.objective, task.state.value, task.authority_context,
                 task.governance_decision, int(task.approval_required), ",".join(task.approval_ids),
                 task.policy_version, self._iso(task.created_at), self._iso(task.updated_at), task.revision,
                 task.verification),
            )
            event = self._audit[-1]
            self._execute("INSERT INTO authority_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (event.event_id, event.task_id, event.event_type, self._iso(event.timestamp),
                           event.expected_revision, event.resulting_revision, event.authority_context,
                           event.policy_version, event.approval_id, event.detail))
            self._execute("COMMIT")
            return task
        except Exception as exc:
            try:
                self._rollback()
            except Exception as rollback_exc:
                self._tasks.pop(task.task_id, None)
                self._audit.pop()
                raise DurableAuthorityError("authoritative task rollback failed") from rollback_exc
            self._tasks.pop(task.task_id, None)
            self._audit.pop()
            if isinstance(exc, ValidationError):
                raise
            raise DurableAuthorityError("authoritative task commit failed") from exc

    def record_approval(self, approval: Approval) -> Approval:
        stored = super().record_approval(approval)
        try:
            self.read_task(stored.task_id)
            event = self._audit[-1]
            self._execute("BEGIN IMMEDIATE")
            self._execute("INSERT INTO authority_approvals VALUES (?,?,?,?,?,?,?,?,?)",
                          (stored.approval_id, stored.task_id, stored.principal, stored.decision, stored.scope,
                           stored.policy_version, self._iso(stored.issued_at), self._iso(stored.expires_at), stored.provenance))
            self._execute("INSERT INTO authority_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (event.event_id, event.task_id, event.event_type, self._iso(event.timestamp),
                           event.expected_revision, event.resulting_revision, event.authority_context,
                           event.policy_version, event.approval_id, event.detail))
            self._execute("COMMIT")
            return stored
        except Exception as exc:
            try:
                self._rollback()
            except Exception as rollback_exc:
                self._approvals.pop(stored.approval_id, None)
                if self._audit:
                    self._audit.pop()
                raise DurableAuthorityError("authoritative approval rollback failed") from rollback_exc
            self._approvals.pop(stored.approval_id, None)
            if self._audit:
                self._audit.pop()
            if isinstance(exc, ValidationError):
                raise
            raise DurableAuthorityError("authoritative approval commit failed") from exc

    def authorize_transition(self, *, task_id: str, expected_revision: int, target: State,
                             now: datetime, approval_id: Optional[str] = None,
                             verification=None, completion_proof=None, verification_gate=None) -> Task:
        if target == State.COMPLETED:
            raise ValidationError("durable completion requires an independent verified completion contract")
        self._load()
        previous_task = self.read_task(task_id)
        previous_audit_len = len(self._audit)
        next_task = super().authorize_transition(
            task_id=task_id, expected_revision=expected_revision, target=target, now=now,
            approval_id=approval_id, verification=verification,
            completion_proof=completion_proof, verification_gate=verification_gate,
        )
        event = self._audit[-1]
        try:
            self._execute("BEGIN IMMEDIATE")
            self._persist_task(next_task, expected_revision)
            self._execute("INSERT INTO authority_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (event.event_id, event.task_id, event.event_type, self._iso(event.timestamp),
                           event.expected_revision, event.resulting_revision, event.authority_context,
                           event.policy_version, event.approval_id, event.detail))
            self._execute("COMMIT")
            return next_task
        except ConflictError:
            self._rollback()
            self._tasks[task_id] = previous_task
            del self._audit[previous_audit_len:]
            self._load()
            raise
        except Exception as exc:
            try:
                self._rollback()
            except Exception as rollback_exc:
                self._tasks[task_id] = previous_task
                del self._audit[previous_audit_len:]
                raise DurableAuthorityError("authoritative transition rollback failed") from rollback_exc
            self._tasks[task_id] = previous_task
            del self._audit[previous_audit_len:]
            self._load()
            raise DurableAuthorityError("authoritative transition commit failed") from exc

    def audit_events(self, task_id: str):
        try:
            rows = self._execute("SELECT * FROM authority_audit WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
            from .authority import AuditEvent
            return tuple(AuditEvent(
                r["event_id"], r["task_id"], r["event_type"], self._dt(r["timestamp"]),
                r["expected_revision"], r["resulting_revision"], r["authority_context"],
                r["policy_version"], r["approval_id"], r["detail"]
            ) for r in rows)
        except Exception as exc:
            raise DurableAuthorityError("authoritative audit read failed") from exc

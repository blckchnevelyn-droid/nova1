"""Fail-closed durable execution boundary for Nova ADR-002."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from .authority import ConflictError, State, ValidationError, _utc
from .governance import AuthorizationError, AuthorizationLedger, AuthorizationRecord


class AttemptState(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    CLAIMED = "CLAIMED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Operation:
    operation_id: str
    task_id: str
    idempotency_key: str
    operation_hash: str
    action: str
    scope: str
    created_at: datetime


@dataclass(frozen=True)
class ExecutionAttempt:
    attempt_id: str
    operation_id: str
    task_id: str
    worker_id: str
    state: AttemptState
    fence: int
    created_at: datetime
    claimed_at: Optional[datetime]
    finished_at: Optional[datetime]
    result_evidence: Optional[str]
    error_detail: Optional[str]
    evidence_hash: Optional[str] = None


@dataclass(frozen=True)
class ExecutionAuditEvent:
    event_id: str
    task_id: str
    operation_id: str
    attempt_id: Optional[str]
    event_type: str
    worker_id: Optional[str]
    fence: Optional[int]
    timestamp: datetime
    authority_context: str
    policy_version: str
    approval_id: Optional[str]
    detail: str


def canonical_operation(*, action: str, scope: str, specification: object) -> str:
    if not action or not scope:
        raise ValidationError("operation action and scope are required")
    try:
        return json.dumps({"action": action, "scope": scope, "specification": specification},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValidationError("operation specification is not canonically serializable") from exc


def operation_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evidence_canonical(*, task_id: str, operation_id: str, attempt_id: str, fence: int,
                       state: AttemptState, evidence: str) -> bytes:
    return json.dumps({"task_id": task_id, "operation_id": operation_id,
                       "attempt_id": attempt_id, "fence": fence,
                       "state": state.value, "evidence": evidence},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def execution_event_canonical(*, event_id, task_id, operation_id, attempt_id, event_type, worker_id,
                              fence, timestamp, authority_context, policy_version, approval_id, detail,
                              previous_hash) -> bytes:
    return json.dumps({"event_id": event_id, "task_id": task_id, "operation_id": operation_id,
                       "attempt_id": attempt_id, "event_type": event_type, "worker_id": worker_id,
                       "fence": fence, "timestamp": timestamp, "authority_context": authority_context,
                       "policy_version": policy_version, "approval_id": approval_id, "detail": detail,
                       "previous_hash": previous_hash},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


_NOVA_GOVERNED_CAPABILITY = object()


class SQLiteExecutionAuthority:
    """Internal durable execution implementation; consequential transitions are governed."""

    def __init__(self, authority_store, authorization_ledger: Optional[AuthorizationLedger] = None, *, _capability=None) -> None:
        if _capability is not _NOVA_GOVERNED_CAPABILITY:
            raise ValidationError(
                "SQLiteExecutionAuthority is an internal implementation; use GovernedSQLiteExecutionAuthority"
            )
        self._store = authority_store
        self._ledger = authorization_ledger
        self._db: sqlite3.Connection = authority_store._db
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS execution_operations (
                operation_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                idempotency_key TEXT NOT NULL, operation_hash TEXT NOT NULL,
                action TEXT NOT NULL, scope TEXT NOT NULL, created_at TEXT NOT NULL,
                canonical_operation TEXT, UNIQUE(task_id, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS execution_attempts (
                attempt_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES execution_operations(operation_id),
                task_id TEXT NOT NULL REFERENCES tasks(task_id), worker_id TEXT NOT NULL,
                state TEXT NOT NULL, fence INTEGER NOT NULL, created_at TEXT NOT NULL,
                claimed_at TEXT, finished_at TEXT, result_evidence TEXT, error_detail TEXT, evidence_hash TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS execution_active_claim
            ON execution_attempts(operation_id) WHERE state='CLAIMED';
            CREATE TABLE IF NOT EXISTS execution_audit_events (
                event_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                operation_id TEXT NOT NULL REFERENCES execution_operations(operation_id),
                attempt_id TEXT REFERENCES execution_attempts(attempt_id), event_type TEXT NOT NULL,
                worker_id TEXT, fence INTEGER, timestamp TEXT NOT NULL, authority_context TEXT NOT NULL,
                policy_version TEXT NOT NULL, approval_id TEXT, detail TEXT NOT NULL,
                previous_hash TEXT NOT NULL DEFAULT '', event_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE TRIGGER IF NOT EXISTS execution_audit_no_update
            BEFORE UPDATE ON execution_audit_events BEGIN
                SELECT RAISE(ABORT, 'execution audit events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS execution_audit_no_delete
            BEFORE DELETE ON execution_audit_events BEGIN
                SELECT RAISE(ABORT, 'execution audit events are append-only');
            END;
        """)
        operation_columns = {row[1] for row in self._db.execute("PRAGMA table_info(execution_operations)")}
        if "canonical_operation" not in operation_columns:
            self._db.execute("ALTER TABLE execution_operations ADD COLUMN canonical_operation TEXT")
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(execution_attempts)")}
        if "evidence_hash" not in columns:
            self._db.execute("ALTER TABLE execution_attempts ADD COLUMN evidence_hash TEXT")
        self._db.executescript("""
            CREATE TRIGGER IF NOT EXISTS execution_operation_no_update
            BEFORE UPDATE ON execution_operations BEGIN
                SELECT RAISE(ABORT, 'execution operations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS execution_operation_no_delete
            BEFORE DELETE ON execution_operations BEGIN
                SELECT RAISE(ABORT, 'execution operations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS execution_terminal_attempt_no_update
            BEFORE UPDATE ON execution_attempts WHEN OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN') BEGIN
                SELECT RAISE(ABORT, 'terminal execution attempts are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS execution_terminal_attempt_no_delete
            BEFORE DELETE ON execution_attempts WHEN OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN') BEGIN
                SELECT RAISE(ABORT, 'terminal execution attempts are immutable');
            END;
        """)

        self._migrate_audit_chain()

    @staticmethod
    def _stamp(value: datetime) -> str:
        return _utc(value).isoformat()

    @staticmethod
    def _parse(value: Optional[str]) -> Optional[datetime]:
        return _utc(datetime.fromisoformat(value)) if value else None

    @staticmethod
    def _operation_from_row(row) -> Operation:
        canonical = row["canonical_operation"]
        if not canonical:
            raise ValidationError("operation integrity metadata is unavailable")
        try:
            payload = json.loads(canonical)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValidationError("operation canonical representation is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {"action", "scope", "specification"}:
            raise ValidationError("operation canonical representation is invalid")
        if payload["action"] != row["action"] or payload["scope"] != row["scope"]:
            raise ValidationError("operation integrity check failed")
        normalized = canonical_operation(action=payload["action"], scope=payload["scope"],
                                         specification=payload["specification"])
        if normalized != canonical or operation_hash(normalized) != row["operation_hash"]:
            raise ValidationError("operation integrity check failed")
        return Operation(row["operation_id"], row["task_id"], row["idempotency_key"], row["operation_hash"],
                         row["action"], row["scope"], SQLiteExecutionAuthority._parse(row["created_at"]))

    def _migrate_audit_chain(self) -> None:
        """Upgrade pre-chain databases: add previous_hash/event_hash and backfill the chain.

        Idempotent. Runs in one transaction. The append-only trigger is dropped only for the
        backfill and recreated before commit, so the table is never left writable.
        """
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(execution_audit_events)")}
        if {"previous_hash", "event_hash"} <= columns:
            return
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("DROP TRIGGER IF EXISTS execution_audit_no_update")
            if "previous_hash" not in columns:
                self._db.execute("ALTER TABLE execution_audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
            if "event_hash" not in columns:
                self._db.execute("ALTER TABLE execution_audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")
            task_ids = [row[0] for row in self._db.execute(
                "SELECT DISTINCT task_id FROM execution_audit_events ORDER BY task_id").fetchall()]
            for task_id in task_ids:
                previous = self._store._durable_mac(b"execution-audit-genesis")
                rows = self._db.execute(
                    "SELECT rowid, * FROM execution_audit_events WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
                for row in rows:
                    event_hash = self._store._durable_mac(execution_event_canonical(
                        event_id=row["event_id"], task_id=row["task_id"], operation_id=row["operation_id"],
                        attempt_id=row["attempt_id"], event_type=row["event_type"], worker_id=row["worker_id"],
                        fence=row["fence"], timestamp=row["timestamp"], authority_context=row["authority_context"],
                        policy_version=row["policy_version"], approval_id=row["approval_id"], detail=row["detail"],
                        previous_hash=previous))
                    self._db.execute(
                        "UPDATE execution_audit_events SET previous_hash=?, event_hash=? WHERE rowid=?",
                        (previous, event_hash, row["rowid"]))
                    previous = event_hash
            self._db.execute(
                "CREATE TRIGGER IF NOT EXISTS execution_audit_no_update "
                "BEFORE UPDATE ON execution_audit_events BEGIN "
                "SELECT RAISE(ABORT, 'execution audit events are append-only'); END;")
            self._db.execute("COMMIT")
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def identify_operation(self, *, task_id: str, idempotency_key: str, action: str,
                           scope: str, specification: object, now: datetime) -> Operation:
        task = self._store.read_task(task_id)
        if not idempotency_key or scope != task.objective:
            raise ValidationError("operation identity is not valid for task")
        canonical = canonical_operation(action=action, scope=scope, specification=specification)
        digest = operation_hash(canonical)
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute("SELECT * FROM execution_operations WHERE task_id=? AND idempotency_key=?",
                                   (task_id, idempotency_key)).fetchone()
            if row:
                existing = self._operation_from_row(row)
                if existing.operation_hash != digest or existing.action != action or existing.scope != scope:
                    raise ValidationError("idempotency key reused with changed operation semantics")
                self._db.execute("COMMIT")
                return existing
            op = Operation(str(uuid4()), task_id, idempotency_key, digest, action, scope, _utc(now))
            self._db.execute("INSERT INTO execution_operations (operation_id,task_id,idempotency_key,operation_hash,action,scope,created_at,canonical_operation) VALUES (?,?,?,?,?,?,?,?)",
                             (op.operation_id, op.task_id, op.idempotency_key, op.operation_hash, op.action,
                              op.scope, self._stamp(op.created_at), canonical))
            self._audit_operation(op.operation_id, task, "OPERATION_IDENTIFIED", None, None, None, None,
                                  "operation identity established", op.created_at)
            self._db.execute("COMMIT")
            return op
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def read_operation(self, operation_id: str) -> Operation:
        row = self._db.execute("SELECT * FROM execution_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise ValidationError("unknown operation")
        return self._operation_from_row(row)

    def create_attempt(self, *, operation_id: str, worker_id: str, now: datetime) -> ExecutionAttempt:
        if not worker_id:
            raise ValidationError("worker identity is required")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            op = self.read_operation(operation_id)
            if self._db.execute("SELECT 1 FROM execution_attempts WHERE operation_id=? AND state IN ('CLAIMED','UNKNOWN','SUCCEEDED')",
                                (operation_id,)).fetchone():
                raise ConflictError("operation is claimed, unresolved, or already succeeded")
            fence = int(self._db.execute("SELECT COALESCE(MAX(fence),0) FROM execution_attempts WHERE operation_id=?",
                                         (operation_id,)).fetchone()[0]) + 1
            attempt = ExecutionAttempt(str(uuid4()), operation_id, op.task_id, worker_id, AttemptState.NOT_EXECUTED,
                                       fence, _utc(now), None, None, None, None, None)
            self._db.execute("INSERT INTO execution_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                             (attempt.attempt_id, operation_id, op.task_id, worker_id, attempt.state.value, fence,
                              self._stamp(attempt.created_at), None, None, None, None, None))
            task = self._store.read_task(op.task_id)
            self._audit_operation(operation_id, task, "ATTEMPT_CREATED", attempt.attempt_id, worker_id, fence, None,
                                  "execution attempt created", attempt.created_at)
            self._db.execute("COMMIT")
            return attempt
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def _validate_authorization(self, *, operation: Operation, worker_id: str,
                                authorization: Optional[AuthorizationRecord], tool: Optional[str], now: datetime) -> str:
        if self._ledger is None:
            raise AuthorizationError("execution requires an authorization ledger")
        if authorization is None or not tool:
            raise AuthorizationError("execution requires explicit authorization and tool binding")
        authorization.verify_integrity()
        current = self._ledger.get(authorization.authorization_id, now=now)
        if current.integrity_hash != authorization.integrity_hash:
            raise AuthorizationError("authorization record differs from ledger record")
        if authorization.agent_id != worker_id:
            raise AuthorizationError("worker identity is not the authorized agent")
        current.permits(agent_id=worker_id, action=operation.action, scope=operation.scope, tool=tool, now=now)
        return authorization.authorization_id

    def _require_durable_governed_binding(self, *, attempt_id: str, authorization_id: str,
                                          authorization_hash: str, tool: str) -> None:
        row = self._db.execute(
            "SELECT authorization_id, authorization_hash, tool FROM governed_attempt_bindings WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise AuthorizationError("execution attempt has no governed authorization binding")
        if row["authorization_id"] != authorization_id or row["authorization_hash"] != authorization_hash:
            raise AuthorizationError("execution attempt authorization binding mismatch")
        if row["tool"] != tool:
            raise AuthorizationError("execution attempt tool binding mismatch")

    def claim(self, *, attempt_id: str, worker_id: str, now: datetime,
              authorization: Optional[AuthorizationRecord] = None, tool: Optional[str] = None) -> ExecutionAttempt:
        now = _utc(now)
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute("SELECT * FROM execution_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                raise ValidationError("unknown execution attempt")
            operation = self.read_operation(row["operation_id"])
            if row["worker_id"] != worker_id:
                raise ValidationError("worker is not bound to execution attempt")
            if row["state"] != AttemptState.NOT_EXECUTED.value:
                raise ConflictError("attempt is no longer claimable")
            active = self._db.execute("SELECT attempt_id FROM execution_attempts WHERE operation_id=? AND state='CLAIMED'",
                                      (row["operation_id"],)).fetchone()
            if active:
                raise ConflictError("operation already has an active claim")
            approval_id = self._validate_authorization(operation=operation, worker_id=worker_id,
                                                       authorization=authorization, tool=tool, now=now)
            self._require_durable_governed_binding(attempt_id=attempt_id,
                                                   authorization_id=approval_id,
                                                   authorization_hash=authorization.integrity_hash,
                                                   tool=tool)
            cur = self._db.execute("UPDATE execution_attempts SET state='CLAIMED',claimed_at=? WHERE attempt_id=? AND state='NOT_EXECUTED'",
                                  (self._stamp(now), attempt_id))
            if cur.rowcount != 1:
                raise ConflictError("authoritative claim conflict")
            task = self._store.read_task(row["task_id"])
            self._audit_operation(row["operation_id"], task, "ATTEMPT_CLAIMED", attempt_id, worker_id,
                                  int(row["fence"]), approval_id, "execution authority claimed", now)
            self._db.execute("COMMIT")
            return self._read_attempt(attempt_id)
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def record_outcome(self, *, attempt_id: str, worker_id: str, fence: int, state: AttemptState, now: datetime,
                       result_evidence: Optional[str] = None, error_detail: Optional[str] = None,
                       authorization: Optional[AuthorizationRecord] = None, tool: Optional[str] = None) -> ExecutionAttempt:
        now = _utc(now)
        if state not in {AttemptState.SUCCEEDED, AttemptState.FAILED, AttemptState.UNKNOWN}:
            raise ValidationError("outcome must be SUCCEEDED, FAILED, or UNKNOWN")
        if state is AttemptState.SUCCEEDED and not result_evidence:
            raise ValidationError("successful outcome requires result evidence")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute("SELECT * FROM execution_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                raise ValidationError("unknown execution attempt")
            operation = self.read_operation(row["operation_id"])
            if row["worker_id"] != worker_id or int(row["fence"]) != fence:
                raise ValidationError("attempt ownership/fencing validation failed")
            if row["state"] != AttemptState.CLAIMED.value:
                raise ConflictError("attempt is not actively claimed")
            approval_id = self._validate_authorization(operation=operation, worker_id=worker_id,
                                                       authorization=authorization, tool=tool, now=now)
            self._require_durable_governed_binding(attempt_id=attempt_id,
                                                   authorization_id=approval_id,
                                                   authorization_hash=authorization.integrity_hash,
                                                   tool=tool)
            task = self._store.read_task(row["task_id"])
            bound_hash = self._store._durable_mac(evidence_canonical(
                task_id=row["task_id"], operation_id=row["operation_id"], attempt_id=attempt_id,
                fence=fence, state=state, evidence=result_evidence or error_detail or ""))
            cur = self._db.execute("UPDATE execution_attempts SET state=?,finished_at=?,result_evidence=?,error_detail=?,evidence_hash=? WHERE attempt_id=? AND worker_id=? AND fence=? AND state='CLAIMED'",
                                  (state.value, self._stamp(now), result_evidence, error_detail, bound_hash,
                                   attempt_id, worker_id, fence))
            if cur.rowcount != 1:
                raise ConflictError("authoritative outcome conflict")
            self._audit_operation(row["operation_id"], task, f"ATTEMPT_{state.value}", attempt_id, worker_id,
                                  fence, approval_id, f"execution outcome recorded; evidence_hash={bound_hash}", now)
            self._db.execute("COMMIT")
            return self._read_attempt(attempt_id)
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def audit_events(self, task_id: str) -> tuple[ExecutionAuditEvent, ...]:
        self._store.read_task(task_id)
        rows = self._db.execute("SELECT * FROM execution_audit_events WHERE task_id=? ORDER BY rowid", (task_id,))
        return tuple(ExecutionAuditEvent(r["event_id"], r["task_id"], r["operation_id"], r["attempt_id"],
                                         r["event_type"], r["worker_id"], r["fence"], self._parse(r["timestamp"]),
                                         r["authority_context"], r["policy_version"], r["approval_id"], r["detail"]) for r in rows)

    def _audit_operation(self, operation_id: str, task, event_type: str, attempt_id: Optional[str],
                         worker_id: Optional[str], fence: Optional[int], approval_id: Optional[str],
                         detail: str, timestamp: datetime) -> None:
        event_id = str(uuid4())
        stamp = self._stamp(timestamp)
        row = self._db.execute(
            "SELECT event_hash FROM execution_audit_events WHERE task_id=? ORDER BY rowid DESC LIMIT 1",
            (task.task_id,)).fetchone()
        previous = row[0] if row else self._store._durable_mac(b"execution-audit-genesis")
        event_hash = self._store._durable_mac(execution_event_canonical(
            event_id=event_id, task_id=task.task_id, operation_id=operation_id, attempt_id=attempt_id,
            event_type=event_type, worker_id=worker_id, fence=fence, timestamp=stamp,
            authority_context=task.authority_context, policy_version=task.policy_version,
            approval_id=approval_id, detail=detail, previous_hash=previous))
        self._db.execute("INSERT INTO execution_audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (event_id, task.task_id, operation_id, attempt_id, event_type, worker_id, fence,
                          stamp, task.authority_context, task.policy_version, approval_id, detail,
                          previous, event_hash))

    def verify_execution_audit(self, task_id: str) -> int:
        """Recompute the execution audit chain for a task with the external key. Returns event count."""
        from .authority import ValidationError as _VE
        previous = self._store._durable_mac(b"execution-audit-genesis")
        rows = self._db.execute(
            "SELECT * FROM execution_audit_events WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
        for row in rows:
            if row["previous_hash"] != previous:
                raise _VE(f"execution audit linkage broken at event {row['event_id']}")
            expected = self._store._durable_mac(execution_event_canonical(
                event_id=row["event_id"], task_id=row["task_id"], operation_id=row["operation_id"],
                attempt_id=row["attempt_id"], event_type=row["event_type"], worker_id=row["worker_id"],
                fence=row["fence"], timestamp=row["timestamp"], authority_context=row["authority_context"],
                policy_version=row["policy_version"], approval_id=row["approval_id"], detail=row["detail"],
                previous_hash=previous))
            if not hmac.compare_digest(expected, row["event_hash"]):
                raise _VE(f"execution audit MAC mismatch at event {row['event_id']}")
            previous = row["event_hash"]
        return len(rows)

    def _read_attempt(self, attempt_id: str) -> ExecutionAttempt:
        row = self._db.execute("SELECT * FROM execution_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise ValidationError("unknown execution attempt")
        result = ExecutionAttempt(row["attempt_id"], row["operation_id"], row["task_id"], row["worker_id"],
                                  AttemptState(row["state"]), int(row["fence"]), self._parse(row["created_at"]),
                                  self._parse(row["claimed_at"]), self._parse(row["finished_at"]),
                                  row["result_evidence"], row["error_detail"], row["evidence_hash"])
        if result.state in {AttemptState.SUCCEEDED, AttemptState.FAILED, AttemptState.UNKNOWN}:
            evidence = result.result_evidence or result.error_detail or ""
            expected = self._store._durable_mac(evidence_canonical(
                task_id=result.task_id, operation_id=result.operation_id, attempt_id=result.attempt_id,
                fence=result.fence, state=result.state, evidence=evidence))
            if result.evidence_hash is None or not hmac.compare_digest(result.evidence_hash, expected):
                raise ValidationError("execution evidence integrity check failed")
        return result

    def read_attempt(self, attempt_id: str) -> ExecutionAttempt:
        return self._read_attempt(attempt_id)

"""Fail-closed recovery authority for unresolved execution outcomes.

This module records a governed recovery decision; it does not execute retries,
compensating actions, or convert UNKNOWN into success. A separate execution
boundary must consume any permitted decision and independently revalidate
current authority before consequential work.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from .authority import State, ValidationError, _utc
from .execution import AttemptState


class RecoveryStrategy(str, Enum):
    RECONCILE = "RECONCILE"
    COMPENSATE = "COMPENSATE"
    RETRY_IDEMPOTENT = "RETRY_IDEMPOTENT"
    ESCALATE = "ESCALATE"
    STOP = "STOP"


@dataclass(frozen=True)
class RecoveryDecision:
    decision_id: str
    task_id: str
    operation_id: str
    attempt_id: str
    fence: int
    operation_hash: str
    action: str
    scope: str
    strategy: RecoveryStrategy
    actor: str
    policy_version: str
    approval_id: Optional[str]
    authoritative_revision: int
    rationale: str
    evidence: str
    issued_at: datetime
    expires_at: Optional[datetime]
    decision_hash: str


def decision_hash(*, task_id: str, operation_id: str, attempt_id: str, fence: int,
                  operation_hash: str, action: str, scope: str,
                  strategy: RecoveryStrategy, actor: str, policy_version: str,
                  approval_id: Optional[str], authoritative_revision: int,
                  rationale: str, evidence: str, issued_at: datetime,
                  expires_at: Optional[datetime]) -> str:
    canonical = json.dumps({
        "task_id": task_id,
        "operation_id": operation_id,
        "attempt_id": attempt_id,
        "fence": fence,
        "operation_hash": operation_hash,
        "action": action,
        "scope": scope,
        "strategy": strategy.value,
        "actor": actor,
        "policy_version": policy_version,
        "approval_id": approval_id,
        "authoritative_revision": authoritative_revision,
        "rationale": rationale,
        "evidence": evidence,
        "issued_at": _utc(issued_at).isoformat(),
        "expires_at": _utc(expires_at).isoformat() if expires_at else None,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SQLiteRecoveryAuthority:
    """Durable, append-only recovery-decision boundary."""

    def __init__(self, authority_store, execution_store) -> None:
        self._authority = authority_store
        self._execution = execution_store
        self._db: sqlite3.Connection = authority_store._db
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS recovery_decisions (
                decision_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                operation_id TEXT NOT NULL REFERENCES execution_operations(operation_id),
                attempt_id TEXT NOT NULL REFERENCES execution_attempts(attempt_id),
                fence INTEGER NOT NULL,
                operation_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                scope TEXT NOT NULL,
                strategy TEXT NOT NULL,
                actor TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                approval_id TEXT,
                authoritative_revision INTEGER NOT NULL,
                rationale TEXT NOT NULL,
                evidence TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                decision_hash TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS recovery_attempt_decision
            ON recovery_decisions(attempt_id);
            CREATE TRIGGER IF NOT EXISTS recovery_decisions_no_update
            BEFORE UPDATE ON recovery_decisions
            BEGIN
                SELECT RAISE(ABORT, 'recovery decisions are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS recovery_decisions_no_delete
            BEFORE DELETE ON recovery_decisions
            BEGIN
                SELECT RAISE(ABORT, 'recovery decisions are append-only');
            END;
        """)

    @staticmethod
    def _stamp(value: datetime) -> str:
        return _utc(value).isoformat()

    @staticmethod
    def _parse(value: Optional[str]) -> Optional[datetime]:
        return _utc(datetime.fromisoformat(value)) if value else None

    def _validate_current_recovery_authority(self, task_id: str, now: datetime) -> Optional[str]:
        task = self._authority.read_task(task_id)
        if task.state is not State.RECOVERY:
            raise ValidationError("recovery decision requires task to be in RECOVERY")
        if task.governance_decision != "ALLOW":
            raise ValidationError("governance decision does not authorize recovery")
        if not task.approval_required:
            return None
        for approval_id in task.approval_ids:
            row = self._db.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            if row is None or row["decision"] != "ALLOW" or not row["provenance"]:
                continue
            if row["principal"] != task.authority_context or row["scope"] != task.objective:
                continue
            if row["policy_version"] != task.policy_version:
                continue
            issued = self._parse(row["issued_at"])
            expires = self._parse(row["expires_at"])
            if issued and now >= issued and (expires is None or now < expires):
                return approval_id
        raise ValidationError("no current valid approval authorizes recovery")

    def authorize(self, *, attempt_id: str, actor: str, strategy: RecoveryStrategy,
                  rationale: str, evidence: str, now: datetime,
                  expires_at: Optional[datetime] = None) -> RecoveryDecision:
        now = _utc(now)
        if not actor or not rationale:
            raise ValidationError("recovery actor and rationale are required")
        if not evidence:
            raise ValidationError("recovery decision requires reconciliation evidence")
        if expires_at is not None:
            expires_at = _utc(expires_at)
            if expires_at <= now:
                raise ValidationError("recovery decision expiration must be after issuance")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            attempt = self._db.execute(
                "SELECT * FROM execution_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                raise ValidationError("unknown execution attempt")
            # The execution authority is the integrity boundary for terminal
            # attempt evidence. This reread fails closed if UNKNOWN was forged.
            verified_attempt = self._execution.read_attempt(attempt_id)
            if verified_attempt.state is not AttemptState.UNKNOWN:
                raise ValidationError("recovery authority requires an UNKNOWN attempt")
            # The operation is independently verified by the execution authority;
            # recovery never consumes a raw operation row for a consequential decision.
            operation = self._execution.read_operation(verified_attempt.operation_id)
            task = self._authority.read_task(verified_attempt.task_id)
            if operation.task_id != task.task_id or operation.scope != task.objective:
                raise ValidationError("operation/task recovery binding failed")
            approval_id = self._validate_current_recovery_authority(task.task_id, now)
            if task.revision < 0:
                raise ValidationError("invalid authoritative task revision")
            if strategy is RecoveryStrategy.RETRY_IDEMPOTENT and not operation.idempotency_key:
                raise ValidationError("idempotent retry requires an operation idempotency key")
            digest = decision_hash(
                task_id=task.task_id, operation_id=operation.operation_id,
                attempt_id=attempt_id, fence=verified_attempt.fence,
                operation_hash=operation.operation_hash, action=operation.action,
                scope=operation.scope, strategy=strategy, actor=actor,
                policy_version=task.policy_version, approval_id=approval_id,
                authoritative_revision=task.revision, rationale=rationale,
                evidence=evidence, issued_at=now, expires_at=expires_at,
            )
            decision = RecoveryDecision(
                str(uuid4()), task.task_id, operation.operation_id, attempt_id,
                verified_attempt.fence, operation.operation_hash, operation.action,
                operation.scope, strategy, actor, task.policy_version, approval_id,
                task.revision, rationale, evidence, now, expires_at, digest,
            )
            self._db.execute(
                "INSERT INTO recovery_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (decision.decision_id, decision.task_id, decision.operation_id,
                 decision.attempt_id, decision.fence, decision.operation_hash,
                 decision.action, decision.scope, decision.strategy.value, decision.actor,
                 decision.policy_version, decision.approval_id,
                 decision.authoritative_revision, decision.rationale, decision.evidence,
                 self._stamp(decision.issued_at),
                 self._stamp(decision.expires_at) if decision.expires_at else None,
                 decision.decision_hash),
            )
            self._db.execute("COMMIT")
            return decision
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def read(self, decision_id: str) -> RecoveryDecision:
        row = self._db.execute(
            "SELECT * FROM recovery_decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("unknown recovery decision")
        decision = RecoveryDecision(
            row["decision_id"], row["task_id"], row["operation_id"], row["attempt_id"],
            int(row["fence"]), row["operation_hash"], row["action"], row["scope"],
            RecoveryStrategy(row["strategy"]), row["actor"], row["policy_version"],
            row["approval_id"], int(row["authoritative_revision"]), row["rationale"],
            row["evidence"], self._parse(row["issued_at"]), self._parse(row["expires_at"]),
            row["decision_hash"],
        )
        expected = decision_hash(
            task_id=decision.task_id, operation_id=decision.operation_id,
            attempt_id=decision.attempt_id, fence=decision.fence,
            operation_hash=decision.operation_hash, action=decision.action,
            scope=decision.scope, strategy=decision.strategy, actor=decision.actor,
            policy_version=decision.policy_version, approval_id=decision.approval_id,
            authoritative_revision=decision.authoritative_revision,
            rationale=decision.rationale, evidence=decision.evidence,
            issued_at=decision.issued_at, expires_at=decision.expires_at,
        )
        if expected != decision.decision_hash:
            raise ValidationError("recovery decision integrity check failed")
        return decision

    def decisions(self, task_id: str) -> tuple[RecoveryDecision, ...]:
        self._authority.read_task(task_id)
        rows = self._db.execute(
            "SELECT decision_id FROM recovery_decisions WHERE task_id=? ORDER BY rowid", (task_id,)
        )
        return tuple(self.read(row[0]) for row in rows)

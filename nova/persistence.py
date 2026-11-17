"""Durable SQLite implementation of Nova's authoritative state boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

from .authority import (
    Approval,
    AuditEvent,
    ConflictError,
    State,
    Task,
    ValidationError,
    _ALLOWED_TRANSITIONS,
    _utc,
)
from .verification import CompletionProof, VerificationError, VerificationGate


_SCHEMA_VERSION = 6
_AUDIT_GENESIS = "0" * 64
_DURABLE_INTEGRITY_ENV = "NOVA_DURABLE_INTEGRITY_KEY"


class SQLiteAuthorityStore:
    """Transactional durable authority store preserving Nova's authority contract."""

    def __init__(self, database: str = ":memory:") -> None:
        raw_integrity_key = os.environ.get("NOVA_COMPLETION_PROOF_INTEGRITY_KEY")
        if not raw_integrity_key:
            raise ValidationError("NOVA_COMPLETION_PROOF_INTEGRITY_KEY is required for durable completion integrity")
        self._completion_integrity_key = raw_integrity_key.encode("utf-8")
        if len(self._completion_integrity_key) < 32:
            raise ValidationError("NOVA_COMPLETION_PROOF_INTEGRITY_KEY must be at least 32 bytes")
        raw_durable_key = os.environ.get(_DURABLE_INTEGRITY_ENV)
        if not raw_durable_key:
            raise ValidationError(f"{_DURABLE_INTEGRITY_ENV} is required for durable audit/composition integrity")
        self._durable_integrity_key = raw_durable_key.encode("utf-8")
        if len(self._durable_integrity_key) < 32:
            raise ValidationError(f"{_DURABLE_INTEGRITY_ENV} must be at least 32 bytes")
        self._db = sqlite3.connect(database, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._completion_proof_write_allowed = False
        self._db.create_function("nova_completion_proof_write_allowed", 0, self._completion_proof_write_authorized)
        self._initialize_schema()

    def _completion_proof_write_authorized(self) -> int:
        """Return 1 only while the trusted application path is persisting a verified proof."""
        return int(self._completion_proof_write_allowed)

    def _initialize_schema(self) -> None:
        current_version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if current_version > _SCHEMA_VERSION:
            raise ValidationError(f"unsupported SQLite schema version: {current_version}")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY, objective TEXT NOT NULL, state TEXT NOT NULL,
                authority_context TEXT NOT NULL, governance_decision TEXT NOT NULL,
                approval_required INTEGER NOT NULL, policy_version TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revision INTEGER NOT NULL,
                verification TEXT
            );
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                principal TEXT NOT NULL, decision TEXT NOT NULL, scope TEXT NOT NULL,
                policy_version TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT,
                provenance TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_approvals (
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
                PRIMARY KEY (task_id, approval_id)
            );
            CREATE TABLE IF NOT EXISTS approval_consumptions (
                approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id),
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                expected_revision INTEGER NOT NULL,
                resulting_revision INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                consumed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                event_type TEXT NOT NULL, timestamp TEXT NOT NULL, expected_revision INTEGER,
                resulting_revision INTEGER, authority_context TEXT NOT NULL,
                policy_version TEXT NOT NULL, approval_id TEXT, detail TEXT NOT NULL,
                previous_hash TEXT NOT NULL DEFAULT '', event_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS completion_proofs (
                proof_digest TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                expected_revision INTEGER NOT NULL, operation_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL, evidence_hash TEXT NOT NULL, verifier_id TEXT NOT NULL,
                issued_at TEXT NOT NULL, decision TEXT NOT NULL,
                expected_postcondition_hash TEXT NOT NULL DEFAULT '',
                resulting_state_hash TEXT NOT NULL DEFAULT '',
                proof_integrity TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS durable_integrity_metadata (
                metadata_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                audit_genesis_mac TEXT NOT NULL,
                composition_genesis_mac TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS tasks_no_authority_mutation
            BEFORE UPDATE ON tasks
            WHEN NEW.task_id != OLD.task_id
              OR NEW.objective != OLD.objective
              OR NEW.authority_context != OLD.authority_context
              OR NEW.governance_decision != OLD.governance_decision
              OR NEW.approval_required != OLD.approval_required
              OR NEW.policy_version != OLD.policy_version
              OR NEW.created_at != OLD.created_at
            BEGIN
                SELECT RAISE(ABORT, 'task authority identity is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS tasks_no_unproven_completion
            BEFORE UPDATE OF state ON tasks
            WHEN NEW.state = 'COMPLETED'
             AND NOT EXISTS (
                 SELECT 1 FROM completion_proofs
                 WHERE task_id = OLD.task_id
                   AND expected_revision = OLD.revision
             )
            BEGIN
                SELECT RAISE(ABORT, 'COMPLETED requires durable completion proof');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS approvals_no_update
            BEFORE UPDATE ON approvals BEGIN
                SELECT RAISE(ABORT, 'approval records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS approvals_no_delete
            BEFORE DELETE ON approvals BEGIN
                SELECT RAISE(ABORT, 'approval records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS task_approvals_no_update
            BEFORE UPDATE ON task_approvals BEGIN
                SELECT RAISE(ABORT, 'task approval bindings are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS task_approvals_no_delete
            BEFORE DELETE ON task_approvals BEGIN
                SELECT RAISE(ABORT, 'task approval bindings are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS approval_consumptions_no_update
            BEFORE UPDATE ON approval_consumptions BEGIN
                SELECT RAISE(ABORT, 'approval consumption records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS approval_consumptions_no_delete
            BEFORE DELETE ON approval_consumptions BEGIN
                SELECT RAISE(ABORT, 'approval consumption records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS completion_proofs_no_insert
            BEFORE INSERT ON completion_proofs
            WHEN nova_completion_proof_write_allowed() != 1
            BEGIN
                SELECT RAISE(ABORT, 'completion proofs may only be persisted by the authority path');
            END;
            CREATE TRIGGER IF NOT EXISTS completion_proofs_no_update
            BEFORE UPDATE ON completion_proofs BEGIN
                SELECT RAISE(ABORT, 'completion proofs are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS completion_proofs_no_delete
            BEFORE DELETE ON completion_proofs BEGIN
                SELECT RAISE(ABORT, 'completion proofs are immutable');
            END;
            """
        )
        self._initialize_durable_integrity_metadata(current_version)
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(audit_events)")}
        if "previous_hash" not in columns:
            self._db.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
        if "event_hash" not in columns:
            self._db.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")
        if current_version < 2:
            self._backfill_audit_chain()
            self._db.execute("PRAGMA user_version = 2")
        if current_version < 3:
            self._db.execute("PRAGMA user_version = 3")
        if current_version < 4:
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(completion_proofs)")}
            if "proof_integrity" not in columns:
                self._db.execute("ALTER TABLE completion_proofs ADD COLUMN proof_integrity TEXT NOT NULL DEFAULT ''")
            self._db.execute("PRAGMA user_version = 4")
        if current_version < 5:
            self._db.execute("PRAGMA user_version = 5")
        if current_version < 6:
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(completion_proofs)")}
            if "expected_postcondition_hash" not in columns:
                self._db.execute("ALTER TABLE completion_proofs ADD COLUMN expected_postcondition_hash TEXT NOT NULL DEFAULT ''")
            if "resulting_state_hash" not in columns:
                self._db.execute("ALTER TABLE completion_proofs ADD COLUMN resulting_state_hash TEXT NOT NULL DEFAULT ''")
            self._db.execute("PRAGMA user_version = 6")

    @staticmethod
    def _audit_payload(*, event_id: str, task_id: str, event_type: str, timestamp: str,
                       expected_revision: Optional[int], resulting_revision: Optional[int],
                       authority_context: str, policy_version: str, approval_id: Optional[str],
                       detail: str, previous_hash: str) -> bytes:
        payload = {
            "event_id": event_id, "task_id": task_id, "event_type": event_type,
            "timestamp": timestamp, "expected_revision": expected_revision,
            "resulting_revision": resulting_revision, "authority_context": authority_context,
            "policy_version": policy_version, "approval_id": approval_id,
            "detail": detail, "previous_hash": previous_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _durable_mac(self, payload: bytes) -> str:
        return hmac.new(self._durable_integrity_key, payload, hashlib.sha256).hexdigest()

    def _audit_hash(self, **kwargs: object) -> str:
        return self._durable_mac(self._audit_payload(**kwargs))

    def _initialize_durable_integrity_metadata(self, current_version: int) -> None:
        row = self._db.execute(
            "SELECT metadata_id, schema_version, audit_genesis_mac, composition_genesis_mac "
            "FROM durable_integrity_metadata WHERE metadata_id='nova'"
        ).fetchone()
        audit_genesis = self._durable_mac(b"audit-genesis")
        composition_genesis = self._durable_mac(b"composition-genesis")
        if row is None:
            existing_audit = self._db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if existing_audit:
                raise ValidationError("durable integrity root missing for existing audit history")
            self._db.execute(
                "INSERT INTO durable_integrity_metadata VALUES (?,?,?,?)",
                ("nova", _SCHEMA_VERSION, audit_genesis, composition_genesis),
            )
            return
        if row["schema_version"] > _SCHEMA_VERSION:
            raise ValidationError("durable integrity metadata schema is newer than this runtime")
        if not hmac.compare_digest(row["audit_genesis_mac"], audit_genesis):
            raise ValidationError("durable audit integrity root verification failed")
        if not hmac.compare_digest(row["composition_genesis_mac"], composition_genesis):
            raise ValidationError("durable composition integrity root verification failed")
        self._db.execute(
            "UPDATE durable_integrity_metadata SET schema_version=? WHERE metadata_id='nova'",
            (_SCHEMA_VERSION,),
        )

    def _backfill_audit_chain(self) -> None:
        rows = self._db.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall()
        previous_by_task: dict[str, str] = {}
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
            for row in rows:
                previous = previous_by_task.get(row["task_id"], self._durable_mac(b"audit-genesis"))
                timestamp = row["timestamp"]
                event_hash = self._audit_hash(
                    event_id=row["event_id"], task_id=row["task_id"], event_type=row["event_type"],
                    timestamp=timestamp, expected_revision=row["expected_revision"],
                    resulting_revision=row["resulting_revision"], authority_context=row["authority_context"],
                    policy_version=row["policy_version"], approval_id=row["approval_id"],
                    detail=row["detail"], previous_hash=previous,
                )
                self._db.execute("UPDATE audit_events SET previous_hash=?, event_hash=? WHERE event_id=?",
                                 (previous, event_hash, row["event_id"]))
                previous_by_task[row["task_id"]] = event_hash
            self._db.execute("""
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events BEGIN
                    SELECT RAISE(ABORT, 'audit events are append-only');
                END;
            """)
            self._db.execute("COMMIT")
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._db.close()

    @staticmethod
    def _stamp(value: datetime) -> str:
        return _utc(value).isoformat()

    def _completion_integrity_payload(self, *, task: Task, proof_digest: str,
                                      expected_revision: int, operation_id: str, attempt_id: str,
                                      evidence_hash: str, expected_postcondition_hash: str,
                                      resulting_state_hash: str, verifier_id: str, issued_at: str,
                                      decision: str) -> bytes:
        payload = {
            "task_id": task.task_id, "objective": task.objective,
            "authority_context": task.authority_context,
            "governance_decision": task.governance_decision,
            "approval_required": task.approval_required,
            "policy_version": task.policy_version,
            "created_at": self._stamp(task.created_at),
            "proof_digest": proof_digest, "expected_revision": expected_revision,
            "operation_id": operation_id, "attempt_id": attempt_id,
            "evidence_hash": evidence_hash,
            "expected_postcondition_hash": expected_postcondition_hash,
            "resulting_state_hash": resulting_state_hash,
            "verifier_id": verifier_id, "issued_at": issued_at, "decision": decision,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _completion_integrity(self, **kwargs: object) -> str:
        return hmac.new(self._completion_integrity_key,
                         self._completion_integrity_payload(**kwargs),
                         hashlib.sha256).hexdigest()

    def _validate_completed_task(self, task: Task) -> None:
        if task.state is not State.COMPLETED:
            return
        row = self._db.execute(
            "SELECT proof_digest, expected_revision, operation_id, attempt_id, evidence_hash, "
            "expected_postcondition_hash, resulting_state_hash, verifier_id, issued_at, decision, proof_integrity "
            "FROM completion_proofs WHERE task_id=? AND expected_revision=?",
            (task.task_id, task.revision - 1),
        ).fetchone()
        if (row is None or row["decision"] != "VERIFIED" or not row["proof_integrity"]
                or not row["expected_postcondition_hash"] or not row["resulting_state_hash"]):
            raise ValidationError("completed task has no valid durable completion proof")
        expected = self._completion_integrity(
            task=task, proof_digest=row["proof_digest"], expected_revision=row["expected_revision"],
            operation_id=row["operation_id"], attempt_id=row["attempt_id"],
            evidence_hash=row["evidence_hash"],
            expected_postcondition_hash=row["expected_postcondition_hash"],
            resulting_state_hash=row["resulting_state_hash"],
            verifier_id=row["verifier_id"], issued_at=row["issued_at"], decision=row["decision"],
        )
        if not hmac.compare_digest(row["proof_integrity"], expected):
            raise ValidationError("completed task proof integrity check failed")
        audit = self._db.execute(
            "SELECT resulting_revision, detail FROM audit_events "
            "WHERE task_id=? AND event_type='STATE_TRANSITION' AND resulting_revision=? "
            "ORDER BY rowid DESC LIMIT 1",
            (task.task_id, task.revision),
        ).fetchone()
        if audit is None or f"->COMPLETED proof={row['proof_digest']}" not in audit["detail"]:
            raise ValidationError("completed task audit transition is missing or mismatched")

    @staticmethod
    def _parse(value: str) -> datetime:
        return _utc(datetime.fromisoformat(value))

    def _task(self, task_id: str) -> Task:
        row = self._db.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise ValidationError("unknown task")
        approvals = tuple(r[0] for r in self._db.execute(
            "SELECT approval_id FROM task_approvals WHERE task_id=? ORDER BY rowid", (task_id,)))
        task = Task(
            row["task_id"], row["objective"], State(row["state"]), row["authority_context"],
            row["governance_decision"], bool(row["approval_required"]), approvals,
            row["policy_version"], self._parse(row["created_at"]), self._parse(row["updated_at"]),
            row["revision"], row["verification"],
        )
        self._validate_completed_task(task)
        return task

    def create_task(self, *, objective: str, authority_context: str, governance_decision: str,
                    policy_version: str, now: datetime, approval_required: bool = False) -> Task:
        from uuid import uuid4
        now = _utc(now)
        if not all((objective, authority_context, policy_version)):
            raise ValidationError("task authority context is incomplete")
        if governance_decision not in {"ALLOW", "DENIED", "ESCALATE", "STOPPED"}:
            raise ValidationError("invalid governance decision")
        task = Task(str(uuid4()), objective, State.CREATED, authority_context, governance_decision,
                    approval_required, (), policy_version, now, now, 0, None)
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (task.task_id, task.objective, task.state.value, task.authority_context,
                 task.governance_decision, int(task.approval_required), task.policy_version,
                 self._stamp(now), self._stamp(now), 0, None),
            )
            self._audit(task, "TASK_CREATED", None, 0, None, "task created")
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return task

    def read_task(self, task_id: str) -> Task:
        return self._task(task_id)

    def record_approval(self, approval: Approval) -> Approval:
        approval = Approval(
            approval.approval_id, approval.task_id, approval.principal, approval.decision,
            approval.scope, approval.policy_version, _utc(approval.issued_at),
            _utc(approval.expires_at) if approval.expires_at else None, approval.provenance,
        )
        if not all((approval.approval_id, approval.task_id, approval.principal, approval.scope,
                    approval.policy_version, approval.provenance)):
            raise ValidationError("approval provenance is incomplete")
        if approval.decision != "ALLOW":
            raise ValidationError("only an ALLOW approval can authorize execution")
        if approval.expires_at is not None and approval.expires_at <= approval.issued_at:
            raise ValidationError("approval expiration must be after issuance")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            task = self._task(approval.task_id)
            if approval.principal != task.authority_context:
                raise ValidationError("approval principal is not bound to task authority")
            if approval.scope != task.objective:
                raise ValidationError("approval scope/objective binding failed")
            if approval.policy_version != task.policy_version:
                raise ValidationError("approval policy/version binding failed")
            if self._db.execute("SELECT 1 FROM approvals WHERE approval_id = ?", (approval.approval_id,)).fetchone():
                raise ValidationError("approval_id already exists")
            self._db.execute(
                "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?)",
                (approval.approval_id, approval.task_id, approval.principal, approval.decision,
                 approval.scope, approval.policy_version, self._stamp(approval.issued_at),
                 self._stamp(approval.expires_at) if approval.expires_at else None, approval.provenance),
            )
            self._audit(task, "APPROVAL_RECORDED", None, None, approval.approval_id,
                        "approval provenance recorded", approval.issued_at)
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return approval

    def _verify_completion_proof(self, *, task: Task, proof: CompletionProof,
                                 gate: VerificationGate, now: datetime) -> str:
        if proof.task_id != task.task_id or proof.expected_revision != task.revision:
            raise ValidationError("completion proof is not bound to the authoritative task revision")
        try:
            digest = gate.verify(proof, now=now)
        except VerificationError as exc:
            raise ValidationError(str(exc)) from exc
        tables = {row[0] for row in self._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('execution_operations','execution_attempts')")}
        if tables != {"execution_operations", "execution_attempts"}:
            raise ValidationError("completion requires durable execution evidence")
        operation = self._db.execute(
            "SELECT operation_id, task_id, scope FROM execution_operations WHERE operation_id=?",
            (proof.operation_id,),).fetchone()
        if operation is None or operation["task_id"] != task.task_id or operation["scope"] != task.objective:
            raise ValidationError("completion proof operation binding failed")
        attempt = self._db.execute(
            "SELECT attempt_id, operation_id, task_id, state, evidence_hash FROM execution_attempts WHERE attempt_id=?",
            (proof.attempt_id,),).fetchone()
        if not proof.expected_postcondition_hash or not proof.resulting_state_hash:
            raise ValidationError("completion proof post-condition binding is incomplete")
        binding = self._db.execute(
            "SELECT authorization_id, authorization_hash FROM governed_execution_bindings WHERE operation_id=?",
            (proof.operation_id,),
        ).fetchone()
        if binding is None:
            raise ValidationError("completion proof authorization binding is missing")
        auth_row = self._db.execute(
            "SELECT limits, integrity_hash FROM durable_authorizations WHERE authorization_id=?",
            (binding["authorization_id"],),
        ).fetchone()
        if auth_row is None or auth_row["integrity_hash"] != binding["authorization_hash"]:
            raise ValidationError("completion proof durable authorization binding failed")
        try:
            limits = json.loads(auth_row["limits"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValidationError("completion proof authorization limits are unverifiable") from exc
        expected_postcondition = limits.get("postcondition_hash")
        if not isinstance(expected_postcondition, str) or expected_postcondition != proof.expected_postcondition_hash:
            raise ValidationError("completion proof post-condition does not match authorized context")
        if (attempt is None or attempt["operation_id"] != proof.operation_id or
                attempt["task_id"] != task.task_id or attempt["state"] != "SUCCEEDED" or
                attempt["evidence_hash"] != proof.evidence_hash):
            raise ValidationError("completion proof evidence binding failed")
        return digest

    def authorize_transition(self, *, task_id: str, expected_revision: int, target: State,
                             now: datetime, approval_id: Optional[str] = None,
                             verification: Optional[str] = None,
                             completion_proof: Optional[CompletionProof] = None,
                             verification_gate: Optional[VerificationGate] = None) -> Task:
        now = _utc(now)
        self._db.execute("BEGIN IMMEDIATE")
        try:
            task = self._task(task_id)
            if task.revision != expected_revision:
                raise ConflictError("stale task revision")
            if target not in _ALLOWED_TRANSITIONS[task.state]:
                raise ValidationError(f"transition {task.state.value}->{target.value} is not permitted")
            if task.governance_decision != "ALLOW" and target not in {State.ESCALATE, State.DENIED, State.STOPPED}:
                raise ValidationError("governance decision does not authorize transition")
            if task.approval_required and approval_id is None and target not in {State.ESCALATE, State.DENIED, State.STOPPED}:
                raise ValidationError("required approval is missing")
            if approval_id is not None:
                row = self._db.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
                if row is None or row["task_id"] != task.task_id:
                    raise ValidationError("approval is not bound to task")
                if row["principal"] != task.authority_context:
                    raise ValidationError("approval principal is not authorized for task")
                if row["scope"] != task.objective:
                    raise ValidationError("approval scope/objective binding failed")
                if row["policy_version"] != task.policy_version:
                    raise ValidationError("approval policy/version binding failed")
                issued = self._parse(row["issued_at"])
                expires = self._parse(row["expires_at"]) if row["expires_at"] else None
                if expires is not None and now >= expires:
                    raise ValidationError("approval has expired")
                if now < issued:
                    raise ValidationError("approval is not yet valid")
                if not row["provenance"]:
                    raise ValidationError("approval provenance is unverifiable")
            proof_digest = None
            if target == State.COMPLETED:
                if verification is not None:
                    raise ValidationError("COMPLETED cannot be authorized by a verification string")
                if completion_proof is None or verification_gate is None:
                    raise ValidationError("COMPLETED requires an independently verified completion proof")
                proof_digest = self._verify_completion_proof(task=task, proof=completion_proof,
                                                             gate=verification_gate, now=now)
                if self._db.execute("SELECT 1 FROM completion_proofs WHERE proof_digest=?", (proof_digest,)).fetchone():
                    raise ValidationError("completion proof has already been consumed")
            new_revision = task.revision + 1
            next_task = Task(
                task.task_id, task.objective, target, task.authority_context,
                task.governance_decision, task.approval_required,
                task.approval_ids + ((approval_id,) if approval_id else ()), task.policy_version,
                task.created_at, now, new_revision, "VERIFIED" if target == State.COMPLETED else verification,
            )
            if proof_digest is not None:
                self._completion_proof_write_allowed = True
                try:
                    issued_at = self._stamp(completion_proof.issued_at)
                    proof_integrity = self._completion_integrity(
                        task=task, proof_digest=proof_digest,
                        expected_revision=completion_proof.expected_revision,
                        operation_id=completion_proof.operation_id,
                        attempt_id=completion_proof.attempt_id,
                        evidence_hash=completion_proof.evidence_hash,
                        expected_postcondition_hash=completion_proof.expected_postcondition_hash,
                        resulting_state_hash=completion_proof.resulting_state_hash,
                        verifier_id=completion_proof.verifier_id,
                        issued_at=issued_at, decision=completion_proof.decision,
                    )
                    self._db.execute(
                        "INSERT INTO completion_proofs "
                        "(proof_digest,task_id,expected_revision,operation_id,attempt_id,evidence_hash,"
                        "expected_postcondition_hash,resulting_state_hash,verifier_id,issued_at,decision,proof_integrity) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (proof_digest, task.task_id, completion_proof.expected_revision,
                         completion_proof.operation_id, completion_proof.attempt_id,
                         completion_proof.evidence_hash, completion_proof.expected_postcondition_hash,
                         completion_proof.resulting_state_hash, completion_proof.verifier_id,
                         issued_at, completion_proof.decision, proof_integrity),
                    )
                finally:
                    self._completion_proof_write_allowed = False
            cur = self._db.execute(
                "UPDATE tasks SET state=?,updated_at=?,revision=?,verification=? WHERE task_id=? AND revision=?",
                (target.value, self._stamp(now), new_revision, next_task.verification, task_id, expected_revision),
            )
            if cur.rowcount != 1:
                raise ConflictError("authoritative revision conflict")
            if approval_id is not None:
                self._db.execute(
                    "INSERT OR IGNORE INTO task_approvals(task_id, approval_id) VALUES (?,?)",
                    (task.task_id, approval_id),
                )
            detail = f"{task.state.value}->{target.value}"
            if proof_digest:
                detail += f" proof={proof_digest}"
            event_id = self._audit(next_task, "STATE_TRANSITION", expected_revision, new_revision,
                                   approval_id, detail)
            if target == State.EXECUTING and approval_id is not None:
                self._db.execute(
                    "INSERT INTO approval_consumptions(approval_id, task_id, expected_revision, resulting_revision, event_id, consumed_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (approval_id, task.task_id, expected_revision, new_revision, event_id, self._stamp(now)),
                )
            self._db.execute("COMMIT")
            return next_task
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def audit_events(self, task_id: str) -> tuple[AuditEvent, ...]:
        self._task(task_id)
        rows = self._db.execute("SELECT * FROM audit_events WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
        previous = self._durable_mac(b"audit-genesis")
        events: list[AuditEvent] = []
        for r in rows:
            if r["previous_hash"] != previous:
                raise ValidationError("audit chain integrity check failed")
            expected_hash = self._audit_hash(
                event_id=r["event_id"], task_id=r["task_id"], event_type=r["event_type"],
                timestamp=r["timestamp"], expected_revision=r["expected_revision"],
                resulting_revision=r["resulting_revision"], authority_context=r["authority_context"],
                policy_version=r["policy_version"], approval_id=r["approval_id"],
                detail=r["detail"], previous_hash=r["previous_hash"],
            )
            if r["event_hash"] != expected_hash:
                raise ValidationError("audit chain integrity check failed")
            previous = expected_hash
            events.append(AuditEvent(
                r["event_id"], r["task_id"], r["event_type"], self._parse(r["timestamp"]),
                r["expected_revision"], r["resulting_revision"], r["authority_context"],
                r["policy_version"], r["approval_id"], r["detail"]
            ))
        return tuple(events)

    def verify_audit_chain(self, task_id: str) -> str:
        """Independently verify the durable per-task audit chain and return its root hash."""
        events = self.audit_events(task_id)
        return self._db.execute(
            "SELECT event_hash FROM audit_events WHERE task_id=? ORDER BY rowid DESC LIMIT 1", (task_id,)
        ).fetchone()[0] if events else self._durable_mac(b"audit-genesis")

    def _audit(self, task: Task, event_type: str, expected_revision: Optional[int],
               resulting_revision: Optional[int], approval_id: Optional[str], detail: str,
               timestamp: Optional[datetime] = None) -> str:
        from uuid import uuid4
        event_id = str(uuid4())
        stamp = self._stamp(timestamp or task.updated_at)
        previous_row = self._db.execute(
            "SELECT event_hash FROM audit_events WHERE task_id=? ORDER BY rowid DESC LIMIT 1", (task.task_id,)
        ).fetchone()
        previous = previous_row["event_hash"] if previous_row else self._durable_mac(b"audit-genesis")
        event_hash = self._audit_hash(
            event_id=event_id, task_id=task.task_id, event_type=event_type,
            timestamp=stamp, expected_revision=expected_revision,
            resulting_revision=resulting_revision, authority_context=task.authority_context,
            policy_version=task.policy_version, approval_id=approval_id,
            detail=detail, previous_hash=previous,
        )
        self._db.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, task.task_id, event_type, stamp, expected_revision, resulting_revision,
             task.authority_context, task.policy_version, approval_id, detail, previous, event_hash),
        )
        return event_id

"""Fail-closed execution adapter bound to durable authorization and cryptographic identity."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from uuid import uuid4

from .authority import ValidationError
from .composition import ActionEffect, CompositionDenied, CompositionPolicy, evaluate_cumulative
from .durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from .execution import (
    AttemptState,
    ExecutionAttempt,
    Operation,
    SQLiteExecutionAuthority,
    _NOVA_GOVERNED_CAPABILITY,
    canonical_operation,
    operation_hash,
)
from .governance import AuthorizationError, AuthorizationRecord
from .identity import IdentityError
from .runtime_security import RuntimeDecision, RuntimeSecurityEvidence, RuntimeSecurityGate


class GovernedSQLiteExecutionAuthority:
    """Fail-closed execution facade requiring durable authorization plus identity proof."""

    _SUPPORTED_LIMITS = {"max_operations", "postcondition_hash", "composition_allowed_effects", "composition_forbidden_sequences", "tool_effects"}

    def __init__(self, authority_store, authorization_ledger: SQLiteAuthorizationLedger,
                 identity_gate: SQLiteIdentityGate) -> None:
        if not getattr(authorization_ledger, "durable", False):
            raise ValidationError("governed execution requires a durable authorization ledger")
        if not getattr(identity_gate, "durable", False):
            raise ValidationError("governed execution requires a durable identity gate")
        self._store = authority_store
        self._ledger = authorization_ledger
        self._identity = identity_gate
        self._runtime_security = RuntimeSecurityGate()
        self._execution = SQLiteExecutionAuthority(
            authority_store, authorization_ledger, _capability=_NOVA_GOVERNED_CAPABILITY
        )
        self._db: sqlite3.Connection = authority_store._db
        self._composition_write_allowed = False
        self._db.create_function("nova_composition_write_allowed", 0, self._composition_write_authorized)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS governed_execution_bindings (
                operation_id TEXT PRIMARY KEY REFERENCES execution_operations(operation_id),
                authorization_id TEXT NOT NULL, authorization_hash TEXT NOT NULL,
                identity_key_id TEXT NOT NULL, identity_digest TEXT NOT NULL,
                tool TEXT NOT NULL, bound_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS governed_attempt_bindings (
                attempt_id TEXT PRIMARY KEY REFERENCES execution_attempts(attempt_id),
                operation_id TEXT NOT NULL REFERENCES execution_operations(operation_id),
                authorization_id TEXT NOT NULL, authorization_hash TEXT NOT NULL,
                identity_key_id TEXT NOT NULL, identity_digest TEXT NOT NULL,
                tool TEXT NOT NULL, bound_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS governed_operation_binding_no_update
            BEFORE UPDATE ON governed_execution_bindings BEGIN
                SELECT RAISE(ABORT, 'governed authorization bindings are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_operation_binding_no_delete
            BEFORE DELETE ON governed_execution_bindings BEGIN
                SELECT RAISE(ABORT, 'governed authorization bindings are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_attempt_binding_no_update
            BEFORE UPDATE ON governed_attempt_bindings BEGIN
                SELECT RAISE(ABORT, 'governed attempt authorization bindings are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_attempt_binding_no_delete
            BEFORE DELETE ON governed_attempt_bindings BEGIN
                SELECT RAISE(ABORT, 'governed attempt authorization bindings are immutable');
            END;
            CREATE TABLE IF NOT EXISTS governed_composition_entries (
                authorization_id TEXT NOT NULL,
                authorization_hash TEXT NOT NULL,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                policy_version TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                operation_id TEXT NOT NULL UNIQUE REFERENCES execution_operations(operation_id),
                operation_hash TEXT NOT NULL,
                tool TEXT NOT NULL,
                effect TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                PRIMARY KEY (authorization_id, sequence_no)
            );
            CREATE TRIGGER IF NOT EXISTS governed_composition_no_insert
            BEFORE INSERT ON governed_composition_entries
            WHEN nova_composition_write_allowed() != 1
            BEGIN
                SELECT RAISE(ABORT, 'governed composition entries may only be persisted by the authority path');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_composition_no_update
            BEFORE UPDATE ON governed_composition_entries BEGIN
                SELECT RAISE(ABORT, 'governed composition entries are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_composition_no_delete
            BEFORE DELETE ON governed_composition_entries BEGIN
                SELECT RAISE(ABORT, 'governed composition entries are append-only');
            END;
        """)

    def identify_operation(self, *, task_id: str, idempotency_key: str, action: str, scope: str,
                           specification: object, now: datetime, authorization: AuthorizationRecord,
                           tool: str) -> Operation:
        identity_key_id, identity_digest = self._validate_authorization(
            authorization=authorization, task_id=task_id, action=action,
            scope=scope, tool=tool, now=now,
        )
        task = self._store.read_task(task_id)
        if not idempotency_key:
            raise ValidationError("operation idempotency key is required")
        canonical = canonical_operation(action=action, scope=scope, specification=specification)
        digest = operation_hash(canonical)
        composition = None

        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing_raw = self._db.execute(
                "SELECT * FROM execution_operations WHERE task_id=? AND idempotency_key=?",
                (task_id, idempotency_key),
            ).fetchone()
            if existing_raw is not None:
                operation = self._execution._operation_from_row(existing_raw)
                if operation.operation_hash != digest or operation.action != action or operation.scope != scope:
                    raise ValidationError("idempotency key reused with changed operation semantics")
                existing = self._db.execute(
                    "SELECT authorization_id, authorization_hash, identity_key_id, identity_digest, tool "
                    "FROM governed_execution_bindings WHERE operation_id=?",
                    (operation.operation_id,),
                ).fetchone()
                if existing:
                    if (existing["authorization_id"] != authorization.authorization_id
                            or existing["authorization_hash"] != authorization.integrity_hash
                            or existing["identity_key_id"] != identity_key_id
                            or existing["identity_digest"] != identity_digest
                            or existing["tool"] != tool):
                        raise ValidationError("operation is already bound to different authorization identity")
                    composition = self._composition_context(
                        authorization=authorization, task_id=task_id,
                        specification=specification, tool=tool, evaluate_current=False
                    )
                    if composition is not None:
                        self._verify_existing_composition(
                            operation=operation, authorization=authorization, tool=tool,
                            effect=composition[1], now=now
                        )
                    self._db.execute("COMMIT")
                    return operation
                composition = self._composition_context(
                    authorization=authorization, task_id=task_id, specification=specification, tool=tool
                )
                self._db.execute(
                    "INSERT INTO governed_execution_bindings VALUES (?,?,?,?,?,?,?)",
                    (operation.operation_id, authorization.authorization_id, authorization.integrity_hash,
                     identity_key_id, identity_digest, tool, self._execution._stamp(now)),
                )
                if composition is not None:
                    self._append_composition_entry(
                        operation=operation, authorization=authorization, tool=tool,
                        effect=composition[1]
                    )
                self._db.execute("COMMIT")
                return operation

            self._enforce_limits(authorization)
            composition = self._composition_context(
                authorization=authorization, task_id=task_id, specification=specification, tool=tool
            )
            operation = Operation(
                str(uuid4()), task_id, idempotency_key, digest, action, scope,
                self._execution._parse(self._execution._stamp(now)),
            )
            self._db.execute(
                "INSERT INTO execution_operations "
                "(operation_id,task_id,idempotency_key,operation_hash,action,scope,created_at,canonical_operation) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (operation.operation_id, operation.task_id, operation.idempotency_key,
                 operation.operation_hash, operation.action, operation.scope,
                 self._execution._stamp(operation.created_at), canonical),
            )
            self._execution._audit_operation(
                operation.operation_id, task, "OPERATION_IDENTIFIED", None, None, None, None,
                "operation identity established", operation.created_at,
            )
            self._db.execute(
                "INSERT INTO governed_execution_bindings VALUES (?,?,?,?,?,?,?)",
                (operation.operation_id, authorization.authorization_id, authorization.integrity_hash,
                 identity_key_id, identity_digest, tool, self._execution._stamp(now)),
            )
            if composition is not None:
                self._append_composition_entry(
                    operation=operation, authorization=authorization, tool=tool,
                    effect=composition[1]
                )
            self._db.execute("COMMIT")
            return operation
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def verify_execution_audit(self, task_id: str) -> int:
        """Verify the keyed execution audit chain for a task (read-only)."""
        return self._execution.verify_execution_audit(task_id)

    def attempts_for_operation(self, operation_id: str):
        """Return every attempt for an operation in fence order (read-only)."""
        rows = self._db.execute(
            "SELECT attempt_id FROM execution_attempts WHERE operation_id=? ORDER BY fence",
            (operation_id,),
        ).fetchall()
        return tuple(self._execution.read_attempt(row[0]) for row in rows)

    def read_operation(self, operation_id: str) -> Operation:
        return self._execution.read_operation(operation_id)

    def read_attempt(self, attempt_id: str) -> ExecutionAttempt:
        return self._execution.read_attempt(attempt_id)

    def audit_events(self, task_id: str):
        return self._execution.audit_events(task_id)

    def create_attempt(self, *, operation_id: str, worker_id: str, now: datetime) -> ExecutionAttempt:
        binding = self._require_operation_binding(operation_id=operation_id, now=now)
        operation = self._execution.read_operation(operation_id)
        authorization = self._ledger.get(binding["authorization_id"], now=now)
        if authorization.integrity_hash != binding["authorization_hash"]:
            raise AuthorizationError("durable authorization binding integrity hash mismatch")
        if authorization.agent_id != worker_id:
            raise ValidationError("worker identity is not the authorized agent")
        current_key_id, current_digest = self._validate_authorization(
            authorization=authorization, task_id=operation.task_id, action=operation.action,
            scope=operation.scope, tool=binding["tool"], now=now,
        )
        if current_key_id != binding["identity_key_id"] or current_digest != binding["identity_digest"]:
            raise AuthorizationError("cryptographic identity binding changed")

        self._db.execute("BEGIN IMMEDIATE")
        try:
            op = self._execution.read_operation(operation_id)
            if self._db.execute(
                "SELECT 1 FROM execution_attempts WHERE operation_id=? "
                "AND state IN ('NOT_EXECUTED','CLAIMED','UNKNOWN','SUCCEEDED')", (operation_id,),
            ).fetchone():
                from .authority import ConflictError
                raise ConflictError("operation is claimed, unresolved, or already succeeded")
            fence = int(self._db.execute(
                "SELECT COALESCE(MAX(fence),0) FROM execution_attempts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()[0]) + 1
            attempt = ExecutionAttempt(
                str(uuid4()), operation_id, op.task_id, worker_id, AttemptState.NOT_EXECUTED,
                fence, self._execution._parse(self._execution._stamp(now)),
                None, None, None, None, None,
            )
            self._db.execute(
                "INSERT INTO execution_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (attempt.attempt_id, operation_id, op.task_id, worker_id, attempt.state.value,
                 fence, self._execution._stamp(attempt.created_at), None, None, None, None, None),
            )
            task = self._store.read_task(op.task_id)
            self._execution._audit_operation(
                operation_id, task, "ATTEMPT_CREATED", attempt.attempt_id, worker_id, fence, None,
                "execution attempt created", attempt.created_at,
            )
            self._db.execute(
                "INSERT INTO governed_attempt_bindings VALUES (?,?,?,?,?,?,?,?)",
                (attempt.attempt_id, operation_id, binding["authorization_id"],
                 binding["authorization_hash"], binding["identity_key_id"],
                 binding["identity_digest"], binding["tool"], self._execution._stamp(now)),
            )
            self._db.execute("COMMIT")
            return attempt
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def claim(self, *, attempt_id: str, worker_id: str, now: datetime,
              authorization: AuthorizationRecord, tool: str) -> ExecutionAttempt:
        row = self._db.execute("SELECT * FROM governed_attempt_bindings WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise ValidationError("execution attempt has no governed authorization binding")
        if row["tool"] != tool:
            raise ValidationError("attempt tool binding mismatch")
        if row["authorization_id"] != authorization.authorization_id:
            raise ValidationError("authorization id does not match durable attempt binding")
        operation = self._execution.read_operation(row["operation_id"])
        key_id, digest = self._validate_authorization(
            authorization=authorization, task_id=operation.task_id,
            action=operation.action, scope=operation.scope, tool=tool, now=now,
        )
        if row["authorization_hash"] != authorization.integrity_hash:
            raise AuthorizationError("attempt authorization integrity hash mismatch")
        if row["identity_key_id"] != key_id or row["identity_digest"] != digest:
            raise AuthorizationError("attempt cryptographic identity mismatch")
        if authorization.agent_id != worker_id:
            raise ValidationError("worker identity is not the authorized agent")
        self._enforce_runtime_security(
            request_id=attempt_id,
            authorization=authorization,
            agent_id=worker_id,
            capability=tool,
            identity_key_id=key_id,
            identity_digest=digest,
        )
        return self._execution.claim(
            attempt_id=attempt_id, worker_id=worker_id, now=now,
            authorization=authorization, tool=tool,
        )

    def record_outcome(self, *, attempt_id: str, worker_id: str, fence: int,
                       state: AttemptState, now: datetime,
                       authorization: AuthorizationRecord, tool: str,
                       result_evidence: str | None = None,
                       error_detail: str | None = None) -> ExecutionAttempt:
        row = self._db.execute("SELECT * FROM governed_attempt_bindings WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise ValidationError("execution attempt has no governed authorization binding")
        if row["tool"] != tool:
            raise ValidationError("attempt tool binding mismatch")
        if row["authorization_id"] != authorization.authorization_id:
            raise ValidationError("authorization id does not match durable attempt binding")
        operation = self._execution.read_operation(row["operation_id"])
        key_id, digest = self._validate_authorization(
            authorization=authorization, task_id=operation.task_id,
            action=operation.action, scope=operation.scope, tool=tool, now=now,
        )
        if row["authorization_hash"] != authorization.integrity_hash:
            raise AuthorizationError("attempt authorization integrity hash mismatch")
        if row["identity_key_id"] != key_id or row["identity_digest"] != digest:
            raise AuthorizationError("attempt cryptographic identity mismatch")
        if authorization.agent_id != worker_id:
            raise ValidationError("worker identity is not the authorized agent")
        return self._execution.record_outcome(
            attempt_id=attempt_id, worker_id=worker_id, fence=fence, state=state, now=now,
            authorization=authorization, tool=tool,
            result_evidence=result_evidence, error_detail=error_detail,
        )

    def _require_operation_binding(self, *, operation_id: str, now: datetime) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM governed_execution_bindings WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("operation has no governed authorization binding")
        return row

    def _enforce_runtime_security(
        self,
        *,
        request_id: str,
        authorization: AuthorizationRecord,
        agent_id: str,
        capability: str,
        identity_key_id: str,
        identity_digest: str,
    ) -> None:
        evidence = RuntimeSecurityEvidence(
            request_id=request_id,
            agent_id=agent_id,
            capability=capability,
            authorization_id=authorization.authorization_id,
            authorization_hash=authorization.integrity_hash,
            identity_key_id=identity_key_id,
            identity_digest=identity_digest,
        )
        result = self._runtime_security.evaluate(evidence)
        if result.decision is not RuntimeDecision.ALLOW:
            raise AuthorizationError(f"runtime security gate denied execution: {result.reason}")

    def _validate_authorization(self, *, authorization: AuthorizationRecord, task_id: str,
                                action: str, scope: str, tool: str, now: datetime) -> tuple[str, str]:
        if authorization is None:
            raise AuthorizationError("explicit authorization is required")
        self._ledger.require_valid(authorization, now=now)
        if authorization.task_id != task_id:
            raise AuthorizationError("authorization task binding mismatch")
        if authorization.action != action:
            raise AuthorizationError("authorization action binding mismatch")
        if authorization.scope != scope:
            raise AuthorizationError("authorization scope binding mismatch")
        if tool not in authorization.allowed_tools:
            raise AuthorizationError("tool is not authorized")
        try:
            if not authorization.proof.startswith("ed25519:"):
                raise IdentityError("unsupported authorization proof format")
            parts = authorization.proof.split(":", 2)
            if len(parts) != 3 or not parts[1] or not parts[2]:
                raise IdentityError("malformed Ed25519 authorization proof")
            key_id, signature = parts[1], parts[2]
            payload = {
                "authorization_id": authorization.authorization_id,
                "authorizer": authorization.authorizer,
                "agent_id": authorization.agent_id,
                "task_id": authorization.task_id,
                "objective": authorization.objective,
                "action": authorization.action,
                "scope": authorization.scope,
                "allowed_tools": list(authorization.allowed_tools),
                "limits": {k: json.loads(v) for k, v in authorization.limits},
                "policy_version": authorization.policy_version,
                "issued_at": authorization.issued_at.isoformat(),
                "expires_at": authorization.expires_at.isoformat() if authorization.expires_at else None,
                "provenance": authorization.provenance,
            }
            digest = self._identity.verify(
                authorization_id=authorization.authorization_id,
                principal=authorization.authorizer,
                key_id=key_id,
                payload=payload,
                signature=signature,
                now=now,
                issued_at=authorization.issued_at,
                expires_at=authorization.expires_at,
            )
        except (IdentityError, ValueError, TypeError) as exc:
            raise AuthorizationError("cryptographic identity proof failed") from exc
        return key_id, digest

    def _enforce_limits(self, authorization: AuthorizationRecord) -> None:
        limits = {key: json.loads(value) for key, value in authorization.limits}
        unsupported = set(limits) - self._SUPPORTED_LIMITS
        if unsupported:
            raise AuthorizationError(f"unsupported authorization limits: {sorted(unsupported)}")
        if "max_operations" in limits:
            used = self._db.execute(
                "SELECT COUNT(*) FROM governed_execution_bindings WHERE authorization_id=?",
                (authorization.authorization_id,),
            ).fetchone()[0]
            if used >= int(limits["max_operations"]):
                raise AuthorizationError("authorization operation limit exceeded")

    def _composition_context(self, *, authorization: AuthorizationRecord, task_id: str,
                             specification: object, tool: str, evaluate_current: bool = True):
        limits = {key: json.loads(value) for key, value in authorization.limits}
        if "composition_allowed_effects" not in limits:
            if "composition_forbidden_sequences" in limits:
                raise AuthorizationError("composition policy is incomplete")
            return None
        allowed = limits["composition_allowed_effects"]
        forbidden = limits.get("composition_forbidden_sequences", [])
        if not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) or not x for x in allowed):
            raise AuthorizationError("composition_allowed_effects must be a non-empty list of strings")
        if not isinstance(forbidden, list) or any(
            not isinstance(seq, list) or not seq or any(not isinstance(x, str) or not x for x in seq)
            for seq in forbidden
        ):
            raise AuthorizationError("composition_forbidden_sequences must be a list of non-empty string lists")
        if not isinstance(specification, dict) or set(specification) - {"effect", "path", "value", "metadata"}:
            raise AuthorizationError("composition-enabled operation specification has an invalid schema")
        effect = specification.get("effect")
        if not isinstance(effect, str) or not effect:
            raise AuthorizationError("composition-enabled operation requires an explicit normalized effect")
        tool_effects = limits.get("tool_effects")
        if not isinstance(tool_effects, dict):
            raise AuthorizationError("composition-enabled authorization requires signed tool_effects")
        permitted_effects = tool_effects.get(tool)
        if not isinstance(permitted_effects, list) or not permitted_effects:
            raise AuthorizationError("tool has no signed effect contract")
        if any(not isinstance(item, str) or not item for item in permitted_effects):
            raise AuthorizationError("tool effect contract is malformed")
        if effect not in permitted_effects:
            raise AuthorizationError("operation effect is not authorized for this tool")
        max_operations = limits.get("max_operations")
        if not isinstance(max_operations, int) or max_operations < 1:
            raise AuthorizationError("composition-enabled authorization requires max_operations")
        policy = CompositionPolicy(
            max_operations=max_operations,
            allowed_effects=tuple(allowed),
            forbidden_sequences=tuple(tuple(seq) for seq in forbidden),
        )
        rows = self._db.execute(
            "SELECT * FROM governed_composition_entries WHERE authorization_id=? ORDER BY sequence_no",
            (authorization.authorization_id,),
        ).fetchall()
        history = []
        previous = self._store._durable_mac(b"composition-genesis")
        for expected_no, row in enumerate(rows, start=1):
            if row["sequence_no"] != expected_no:
                raise AuthorizationError("durable composition sequence has a gap")
            if row["task_id"] != task_id or row["authorization_hash"] != authorization.integrity_hash:
                raise AuthorizationError("durable composition authorization binding mismatch")
            if row["policy_version"] != authorization.policy_version:
                raise AuthorizationError("durable composition policy version mismatch")
            op = self._execution.read_operation(row["operation_id"])
            if op.task_id != task_id or op.operation_hash != row["operation_hash"]:
                raise AuthorizationError("durable composition operation binding mismatch")
            binding = self._db.execute(
                "SELECT authorization_id, authorization_hash, tool FROM governed_execution_bindings WHERE operation_id=?",
                (op.operation_id,),
            ).fetchone()
            if (binding is None or binding["authorization_id"] != authorization.authorization_id
                    or binding["authorization_hash"] != authorization.integrity_hash
                    or binding["tool"] != row["tool"]):
                raise AuthorizationError("durable composition operation authorization mismatch")
            expected_hash = self._composition_hash(
                authorization=authorization, task_id=task_id, policy_version=row["policy_version"],
                sequence_no=row["sequence_no"], operation_id=row["operation_id"],
                operation_hash=row["operation_hash"], tool=row["tool"], effect=row["effect"],
                previous_hash=row["previous_hash"],
            )
            if row["previous_hash"] != previous or row["entry_hash"] != expected_hash:
                raise AuthorizationError("durable composition integrity check failed")
            if row["effect"] not in policy.allowed_effects:
                raise AuthorizationError("durable composition history contains an unauthorized effect")
            history.append(ActionEffect(task_id, authorization.authorization_id,
                                         authorization.policy_version, op.action, row["effect"]))
            previous = expected_hash
        if evaluate_current:
            current = ActionEffect(task_id, authorization.authorization_id,
                                   authorization.policy_version, "", effect)
            try:
                evaluate_cumulative(current=current, prior=history, policy=policy)
            except CompositionDenied as exc:
                raise AuthorizationError(str(exc)) from exc
        return policy, effect

    def _composition_write_authorized(self) -> int:
        """Return 1 only while the trusted governed execution path appends composition state."""
        return int(self._composition_write_allowed)

    def _composition_hash(self, *, authorization: AuthorizationRecord, task_id: str,
                          policy_version: str, sequence_no: int, operation_id: str,
                          operation_hash: str, tool: str, effect: str, previous_hash: str) -> str:
        payload = json.dumps({
            "authorization_hash": authorization.integrity_hash, "task_id": task_id,
            "policy_version": policy_version, "sequence_no": sequence_no,
            "operation_id": operation_id, "operation_hash": operation_hash,
            "tool": tool, "effect": effect, "previous_hash": previous_hash,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return self._store._durable_mac(payload.encode("utf-8"))

    def _append_composition_entry(self, *, operation: Operation,
                                  authorization: AuthorizationRecord, tool: str, effect: str) -> None:
        row = self._db.execute(
            "SELECT entry_hash FROM governed_composition_entries WHERE authorization_id=? ORDER BY sequence_no DESC LIMIT 1",
            (authorization.authorization_id,),
        ).fetchone()
        previous = row["entry_hash"] if row else self._store._durable_mac(b"composition-genesis")
        sequence = self._db.execute(
            "SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM governed_composition_entries WHERE authorization_id=?",
            (authorization.authorization_id,),
        ).fetchone()[0]
        entry_hash = self._composition_hash(
            authorization=authorization, task_id=operation.task_id,
            policy_version=authorization.policy_version, sequence_no=sequence,
            operation_id=operation.operation_id, operation_hash=operation.operation_hash,
            tool=tool, effect=effect, previous_hash=previous,
        )
        self._composition_write_allowed = True
        try:
            self._db.execute(
                "INSERT INTO governed_composition_entries "
                "(authorization_id,authorization_hash,task_id,policy_version,sequence_no,operation_id,operation_hash,tool,effect,previous_hash,entry_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (authorization.authorization_id, authorization.integrity_hash, operation.task_id,
                 authorization.policy_version, sequence, operation.operation_id, operation.operation_hash,
                 tool, effect, previous, entry_hash),
            )
        finally:
            self._composition_write_allowed = False

    def _verify_existing_composition(self, *, operation: Operation,
                                     authorization: AuthorizationRecord, tool: str,
                                     effect: str, now: datetime) -> None:
        row = self._db.execute(
            "SELECT effect FROM governed_composition_entries WHERE operation_id=? AND authorization_id=?",
            (operation.operation_id, authorization.authorization_id),
        ).fetchone()
        if row is None or row["effect"] != effect:
            raise AuthorizationError("existing composition state is missing or inconsistent")



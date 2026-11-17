"""Governed file-write pilot: one public entry point over the Nova execution kernel.

Threat model, crash contract, and limits are in docs/security/FILE_WRITE_PILOT.md.

Integrity model (single mechanism): the pilot stores its outcome record as the attempt's
result_evidence or error_detail. The kernel keys each attempt's evidence_hash with the durable
integrity key, which lives outside the database, and appends a hash-chained execution audit
event that records that hash. There is no separate pilot evidence store.

Authorization binding: the scope names the normalized path and the SHA-256 of the exact bytes.
The scope is covered by the authorizer's Ed25519 signature.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable, Optional

from .authority import ConflictError, ValidationError
from .execution import AttemptState, ExecutionAttempt
from .file_write_sandbox import (
    MAX_BYTES,
    PILOT_PUBLISH_CAPABILITY,
    Observation,
    PublishAfterLink,
    SandboxConflict,
    SandboxError,
    SandboxRoot,
    expected_digest,
    normalize_relative_path,
)

ACTION = "write"
TOOL = "filesystem.write"
SCHEMA_VERSION = 2
Hook = Optional[Callable[[str], None]]


class EvidenceTampered(ValidationError):
    """Kernel evidence, audit chain, or target bytes do not match what was recorded."""


def scope_for(relative_path: str, content: bytes) -> str:
    """Signed authorization scope that names this exact path and content."""
    return f"file-write:{relative_path}:sha256:{expected_digest(content)}"


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_outcome(record_json: Optional[str]) -> dict:
    if not record_json:
        raise EvidenceTampered("attempt has no pilot outcome record")
    try:
        record = json.loads(record_json)
    except json.JSONDecodeError as exc:
        raise EvidenceTampered("attempt outcome record is not valid JSON") from exc
    if not isinstance(record, dict) or record.get("event_type") != "FILE_WRITE_OUTCOME":
        raise EvidenceTampered("attempt outcome record has the wrong type")
    return record


class FileWritePilot:
    """The only public path that performs a pilot file write."""

    def __init__(self, boundary, sandbox: SandboxRoot, *, store, tool: str = TOOL) -> None:
        self._boundary = boundary
        self._sandbox = sandbox
        self._store = store
        self._db = store._db
        self._tool = tool

    # ------------------------------------------------------------------ entry points

    def submit(self, *, task_id: str, idempotency_key: str, relative_path: str, content: bytes,
               authorization, worker_id: str, now: datetime, hook: Hook = None) -> ExecutionAttempt:
        """Authorize, claim, publish, and record one write. Never repeats a succeeded write."""
        operation, expected = self._identify(task_id=task_id, idempotency_key=idempotency_key,
                                             relative_path=relative_path, content=content,
                                             authorization=authorization, now=now)
        _call(hook, "after_authorization")
        attempt = self._boundary.create_attempt(operation_id=operation.operation_id, worker_id=worker_id, now=now)
        claimed = self._boundary.claim(attempt_id=attempt.attempt_id, worker_id=worker_id, now=now,
                                       authorization=authorization, tool=self._tool)
        _call(hook, "after_claim")
        return self._execute(claimed, relative_path=relative_path, content=content, expected=expected,
                             authorization=authorization, now=now, recovering=False, hook=hook)

    def resume(self, *, task_id: str, idempotency_key: str, relative_path: str, content: bytes,
               authorization, worker_id: str, now: datetime, hook: Hook = None) -> ExecutionAttempt:
        """Resume the same operation after a crash, following the pilot's crash contract."""
        operation, expected = self._identify(task_id=task_id, idempotency_key=idempotency_key,
                                             relative_path=relative_path, content=content,
                                             authorization=authorization, now=now)
        attempts = self._boundary.attempts_for_operation(operation.operation_id)
        if not attempts:
            return self.submit(task_id=task_id, idempotency_key=idempotency_key, relative_path=relative_path,
                               content=content, authorization=authorization, worker_id=worker_id, now=now,
                               hook=hook)
        last = attempts[-1]
        if last.state is AttemptState.SUCCEEDED:
            return last
        if last.state is AttemptState.CLAIMED:
            return self._execute(last, relative_path=relative_path, content=content, expected=expected,
                                 authorization=authorization, now=now, recovering=True, hook=hook)
        if last.state is AttemptState.NOT_EXECUTED:
            claimed = self._boundary.claim(attempt_id=last.attempt_id, worker_id=worker_id, now=now,
                                           authorization=authorization, tool=self._tool)
            return self._execute(claimed, relative_path=relative_path, content=content, expected=expected,
                                 authorization=authorization, now=now, recovering=False, hook=hook)
        if last.state is AttemptState.FAILED:
            return self.submit(task_id=task_id, idempotency_key=idempotency_key, relative_path=relative_path,
                               content=content, authorization=authorization, worker_id=worker_id, now=now,
                               hook=hook)
        raise ConflictError("operation has an unresolved outcome; an explicit recovery decision is required")

    # ------------------------------------------------------------------ verification

    def verify_evidence(self, task_id: str) -> int:
        """Verify every pilot outcome for a task against the kernel's keyed hashes, the audit
        chain, and the bytes on disk. Returns the number of terminal pilot attempts checked."""
        try:
            self._boundary.verify_execution_audit(task_id)
        except ValidationError as exc:
            raise EvidenceTampered(str(exc)) from exc
        checked = 0
        for attempt in self._task_attempts(task_id):
            if attempt.state is AttemptState.NOT_EXECUTED or attempt.state is AttemptState.CLAIMED:
                continue
            try:
                fresh = self._boundary.read_attempt(attempt.attempt_id)  # keyed evidence_hash check
            except ValidationError as exc:
                raise EvidenceTampered(f"attempt evidence failed integrity check: {exc}") from exc
            record = parse_outcome(fresh.result_evidence or fresh.error_detail)
            if record["outcome"] != fresh.state.value:
                raise EvidenceTampered("outcome record disagrees with attempt state")
            if fresh.state is AttemptState.SUCCEEDED:
                observed = self._observe_quietly(normalize_relative_path(record["relative_path"]))
                if observed is None or observed.sha256 != record["observed_sha256"] \
                        or observed.length != record["observed_length"]:
                    raise EvidenceTampered("target bytes do not match recorded success")
            checked += 1
        return checked

    # ------------------------------------------------------------------ internals

    def _task_attempts(self, task_id: str):
        rows = self._db.execute(
            "SELECT attempt_id FROM execution_attempts WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
        attempts = []
        for row in rows:
            try:
                attempts.append(self._boundary.read_attempt(row[0]))  # keyed evidence check on every read
            except ValidationError as exc:
                raise EvidenceTampered(f"attempt evidence failed integrity check: {exc}") from exc
        return attempts

    def _identify(self, *, task_id, idempotency_key, relative_path, content, authorization, now):
        normalize_relative_path(relative_path)  # malformed paths fail before any authority or file effect
        if not isinstance(content, (bytes, bytearray)):
            raise ValidationError("content must be bytes")
        if len(content) > MAX_BYTES:
            raise ValidationError("content exceeds pilot size limit")
        content = bytes(content)
        expected = expected_digest(content)
        specification = {"path": relative_path, "sha256": expected, "length": len(content)}
        operation = self._boundary.identify_operation(
            task_id=task_id, idempotency_key=idempotency_key, action=ACTION,
            scope=scope_for(relative_path, content), specification=specification,
            now=now, authorization=authorization, tool=self._tool,
        )
        return operation, expected

    def _execute(self, attempt: ExecutionAttempt, *, relative_path: str, content: bytes, expected: str,
                 authorization, now: datetime, recovering: bool, hook: Hook) -> ExecutionAttempt:
        parts = normalize_relative_path(relative_path)
        length = len(content)
        preexisted = False
        lost_race = False
        effect_possible = False
        detail: Optional[str] = None
        observed: Optional[Observation] = None
        try:
            existing = self._sandbox.observe(parts)  # pre-effect observation
            if existing is not None:
                preexisted = True
                observed = existing
                if not recovering:
                    raise SandboxConflict("target already exists; operation does not overwrite")
            else:
                try:
                    self._sandbox.publish(relative_path, content, operation_id=attempt.operation_id,
                                          hook=hook, capability=PILOT_PUBLISH_CAPABILITY)
                except SandboxConflict:
                    lost_race = True  # appeared between observation and link; not ours
                    raise
                except PublishAfterLink:
                    effect_possible = True
                    raise
                effect_possible = True  # the link has completed
                observed = self._sandbox.observe(parts)
        except (SandboxError, OSError) as exc:
            detail = str(exc) or type(exc).__name__
            observed = self._observe_quietly(parts)

        matches = observed is not None and observed.sha256 == expected and observed.length == length
        if lost_race:
            if recovering:
                state, reason = AttemptState.UNKNOWN, "target appeared during recovery; ownership unknown, escalate"
            else:
                state, reason = AttemptState.FAILED, "lost publication race; target created by another writer"
        elif preexisted and not recovering:
            state, reason = AttemptState.FAILED, "target preexisted; not overwritten"
        elif matches:
            state = AttemptState.SUCCEEDED
            reason = "recovered from durable target state" if recovering else "target bytes verified"
        elif observed is None and detail is not None and not effect_possible:
            state, reason = AttemptState.FAILED, detail
        else:
            state = AttemptState.UNKNOWN
            reason = detail or "observed target bytes conflict with the expected operation; escalate"

        record = {
            "schema_version": SCHEMA_VERSION,
            "event_type": "FILE_WRITE_OUTCOME",
            "timestamp": now.isoformat(),
            "task_id": attempt.task_id,
            "operation_id": attempt.operation_id,
            "operation_hash": self._boundary.read_operation(attempt.operation_id).operation_hash,
            "attempt_id": attempt.attempt_id,
            "fence": attempt.fence,
            "worker_id": attempt.worker_id,
            "tool": self._tool,
            "authorization_id": authorization.authorization_id,
            "authorization_hash": authorization.integrity_hash,
            "relative_path": relative_path,
            "expected_sha256": expected,
            "expected_length": length,
            "observed_sha256": observed.sha256 if observed else None,
            "observed_length": observed.length if observed else None,
            "outcome": state.value,
            "reason": reason,
        }
        record_json = _canonical(record)
        if state is AttemptState.SUCCEEDED:
            updated = self._boundary.record_outcome(
                attempt_id=attempt.attempt_id, worker_id=attempt.worker_id, fence=attempt.fence,
                state=state, now=now, authorization=authorization, tool=self._tool,
                result_evidence=record_json)
        else:
            updated = self._boundary.record_outcome(
                attempt_id=attempt.attempt_id, worker_id=attempt.worker_id, fence=attempt.fence,
                state=state, now=now, authorization=authorization, tool=self._tool,
                error_detail=record_json)
        self._discard_stage_quietly(relative_path, attempt.operation_id)
        _call(hook, "after_evidence")
        return updated

    def _observe_quietly(self, parts) -> Optional[Observation]:
        try:
            return self._sandbox.observe(parts)
        except (SandboxError, OSError):
            return None

    def _discard_stage_quietly(self, relative_path: str, operation_id: str) -> None:
        try:
            self._sandbox.discard_stage(relative_path, operation_id)
        except (SandboxError, OSError):
            pass


def _call(hook: Hook, point: str) -> None:
    if hook is not None:
        hook(point)

"""Authoritative lifecycle boundary for Nova.

Storage-agnostic reference implementation of task identity, approval provenance,
optimistic concurrency, governed completion, and append-only audit evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from uuid import uuid4

from .verification import CompletionProof, VerificationError, VerificationGate


class AuthorityError(Exception):
    """Base class for authoritative boundary failures."""


class ConflictError(AuthorityError):
    """Raised when an update uses a stale revision."""


class ValidationError(AuthorityError):
    """Raised when an authority or lifecycle invariant is violated."""


class State(str, Enum):
    CREATED = "CREATED"
    EXECUTING = "EXECUTING"
    OBSERVING = "OBSERVING"
    VERIFYING = "VERIFYING"
    RECOVERY = "RECOVERY"
    COMPLETED = "COMPLETED"
    ESCALATE = "ESCALATE"
    DENIED = "DENIED"
    STOPPED = "STOPPED"


@dataclass(frozen=True)
class Approval:
    approval_id: str
    task_id: str
    principal: str
    decision: str
    scope: str
    policy_version: str
    issued_at: datetime
    expires_at: Optional[datetime]
    provenance: str


@dataclass(frozen=True)
class Task:
    task_id: str
    objective: str
    state: State
    authority_context: str
    governance_decision: str
    approval_required: bool
    approval_ids: tuple[str, ...]
    policy_version: str
    created_at: datetime
    updated_at: datetime
    revision: int
    verification: Optional[str] = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    task_id: str
    event_type: str
    timestamp: datetime
    expected_revision: Optional[int]
    resulting_revision: Optional[int]
    authority_context: str
    policy_version: str
    approval_id: Optional[str]
    detail: str


_ALLOWED_TRANSITIONS = {
    State.CREATED: {State.EXECUTING, State.ESCALATE, State.DENIED, State.STOPPED},
    State.EXECUTING: {State.OBSERVING, State.RECOVERY, State.ESCALATE, State.STOPPED},
    State.OBSERVING: {State.VERIFYING, State.RECOVERY, State.ESCALATE, State.STOPPED},
    State.VERIFYING: {State.COMPLETED, State.RECOVERY, State.ESCALATE, State.STOPPED},
    State.RECOVERY: {State.OBSERVING, State.VERIFYING, State.ESCALATE, State.STOPPED},
    State.COMPLETED: set(), State.ESCALATE: set(), State.DENIED: set(), State.STOPPED: set(),
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValidationError("timestamps must be timezone-aware UTC values")
    return value.astimezone(timezone.utc)


class AuthorityStore:
    """Reference authority implementation for contract testing.

    It is intentionally in-memory and is not production durable storage. It
    cannot authorize COMPLETED because completion is a durable lifecycle fact
    that must be established by the production authority boundary.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, Task] = {}
        self._approvals: Dict[str, Approval] = {}
        self._audit: List[AuditEvent] = []

    def create_task(self, *, objective: str, authority_context: str, governance_decision: str,
                    policy_version: str, now: datetime, approval_required: bool = False) -> Task:
        now = _utc(now)
        if not all((objective, authority_context, policy_version)):
            raise ValidationError("task authority context is incomplete")
        if governance_decision not in {"ALLOW", "DENIED", "ESCALATE", "STOPPED"}:
            raise ValidationError("invalid governance decision")
        task = Task(str(uuid4()), objective, State.CREATED, authority_context, governance_decision,
                    approval_required, (), policy_version, now, now, 0)
        self._tasks[task.task_id] = task
        self._append_audit(task, "TASK_CREATED", None, 0, None, "task created")
        return task

    def read_task(self, task_id: str) -> Task:
        try:
            return self._tasks[task_id]
        except KeyError as exc:
            raise ValidationError("unknown task") from exc

    def record_approval(self, approval: Approval) -> Approval:
        approval = replace(approval, issued_at=_utc(approval.issued_at),
                           expires_at=_utc(approval.expires_at) if approval.expires_at else None)
        if not all((approval.approval_id, approval.task_id, approval.principal, approval.scope,
                    approval.policy_version, approval.provenance)):
            raise ValidationError("approval provenance is incomplete")
        if approval.decision != "ALLOW":
            raise ValidationError("only an ALLOW approval can authorize execution")
        if approval.expires_at is not None and approval.expires_at <= approval.issued_at:
            raise ValidationError("approval expiration must be after issuance")
        task = self.read_task(approval.task_id)
        if approval.principal != task.authority_context:
            raise ValidationError("approval principal is not bound to task authority")
        if approval.scope != task.objective:
            raise ValidationError("approval scope/objective binding failed")
        if approval.policy_version != task.policy_version:
            raise ValidationError("approval policy/version binding failed")
        if approval.approval_id in self._approvals:
            raise ValidationError("approval_id already exists")
        self._approvals[approval.approval_id] = approval
        self._append_audit(task, "APPROVAL_RECORDED", None, None, approval.approval_id,
                           "approval provenance recorded", timestamp=approval.issued_at)
        return approval

    def authorize_transition(self, *, task_id: str, expected_revision: int, target: State,
                             now: datetime, approval_id: Optional[str] = None,
                             verification: Optional[str] = None,
                             completion_proof: Optional[CompletionProof] = None,
                             verification_gate: Optional[VerificationGate] = None) -> Task:
        now = _utc(now)
        task = self.read_task(task_id)
        if task.revision != expected_revision:
            raise ConflictError("stale task revision")
        if target not in _ALLOWED_TRANSITIONS[task.state]:
            raise ValidationError(f"transition {task.state.value}->{target.value} is not permitted")
        if task.governance_decision != "ALLOW" and target not in {State.ESCALATE, State.DENIED, State.STOPPED}:
            raise ValidationError("governance decision does not authorize transition")
        if task.approval_required and approval_id is None and target not in {State.ESCALATE, State.DENIED, State.STOPPED}:
            raise ValidationError("required approval is missing")
        if approval_id is not None:
            approval = self._approvals.get(approval_id)
            if approval is None or approval.task_id != task.task_id:
                raise ValidationError("approval is not bound to task")
            if approval.principal != task.authority_context:
                raise ValidationError("approval principal is not authorized for task")
            if approval.scope != task.objective:
                raise ValidationError("approval scope/objective binding failed")
            if approval.policy_version != task.policy_version:
                raise ValidationError("approval policy/version binding failed")
            if approval.expires_at is not None and now >= approval.expires_at:
                raise ValidationError("approval has expired")
            if now < approval.issued_at:
                raise ValidationError("approval is not yet valid")
            if not approval.provenance:
                raise ValidationError("approval provenance is unverifiable")
        if target == State.COMPLETED:
            raise ValidationError("AuthorityStore cannot authorize COMPLETED; use SQLiteAuthorityStore")
        next_task = replace(task, state=target,
                            approval_ids=(task.approval_ids + (approval_id,)) if approval_id else task.approval_ids,
                            updated_at=now, revision=task.revision + 1,
                            verification=verification)
        self._tasks[task_id] = next_task
        self._append_audit(next_task, "STATE_TRANSITION", expected_revision, next_task.revision,
                           approval_id, f"{task.state.value}->{target.value}")
        return next_task

    def audit_events(self, task_id: str) -> tuple[AuditEvent, ...]:
        return tuple(event for event in self._audit if event.task_id == task_id)

    def _append_audit(self, task: Task, event_type: str, expected_revision: Optional[int],
                      resulting_revision: Optional[int], approval_id: Optional[str], detail: str,
                      timestamp: Optional[datetime] = None) -> None:
        self._audit.append(AuditEvent(str(uuid4()), task.task_id, event_type,
            _utc(timestamp) if timestamp is not None else task.updated_at, expected_revision,
            resulting_revision, task.authority_context, task.policy_version, approval_id, detail))

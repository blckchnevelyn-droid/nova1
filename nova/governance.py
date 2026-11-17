"""Binding governance authorization records for Nova.

This module is deliberately independent from execution. It defines the minimum
machine-verifiable authorization envelope that a consequential execution must
consume before it can be treated as authorized.

The integrity hash proves that the canonical authorization record has not been
changed after issuance. It is not a digital signature and therefore does not,
by itself, authenticate the authorizer. Cryptographic authorizer authentication
belongs to the identity/security gate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple


class AuthorizationError(ValueError):
    """Raised when an authorization record is incomplete or invalid."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AuthorizationError("authorization timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("authorization data is not canonically serializable") from exc


def canonical_authorization(*, authorization_id: str, authorizer: str, agent_id: str, task_id: str,
                            objective: str, action: str, scope: str, allowed_tools: Tuple[str, ...],
                            limits: Mapping[str, object], policy_version: str, issued_at: datetime,
                            expires_at: Optional[datetime], provenance: str, proof: str) -> str:
    return _canonical_json({
        "authorization_id": authorization_id, "authorizer": authorizer, "agent_id": agent_id,
        "task_id": task_id, "objective": objective, "action": action, "scope": scope,
        "allowed_tools": list(allowed_tools), "limits": dict(limits), "policy_version": policy_version,
        "issued_at": _utc(issued_at).isoformat(),
        "expires_at": _utc(expires_at).isoformat() if expires_at else None,
        "provenance": provenance, "proof": proof,
    })


def authorization_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    authorizer: str
    agent_id: str
    task_id: str
    objective: str
    action: str
    scope: str
    allowed_tools: Tuple[str, ...]
    limits: Tuple[Tuple[str, str], ...]
    policy_version: str
    issued_at: datetime
    expires_at: Optional[datetime]
    provenance: str
    proof: str
    integrity_hash: str

    @classmethod
    def issue(cls, *, authorization_id: str, authorizer: str, agent_id: str, task_id: str,
              objective: str, action: str, scope: str, allowed_tools: Tuple[str, ...],
              limits: Mapping[str, object], policy_version: str, issued_at: datetime,
              expires_at: Optional[datetime], provenance: str, proof: str) -> "AuthorizationRecord":
        issued_at = _utc(issued_at)
        expires_at = _utc(expires_at) if expires_at else None
        if not all((authorization_id, authorizer, agent_id, task_id, objective, action, scope,
                    policy_version, provenance, proof)):
            raise AuthorizationError("authorization provenance is incomplete")
        if not allowed_tools:
            raise AuthorizationError("authorization must bind at least one allowed tool")
        if expires_at is not None and expires_at <= issued_at:
            raise AuthorizationError("authorization expiration must be after issuance")
        normalized_tools = tuple(sorted(set(allowed_tools)))
        normalized_limits = tuple(sorted((str(k), _canonical_json(v)) for k, v in limits.items()))
        canonical = canonical_authorization(
            authorization_id=authorization_id, authorizer=authorizer, agent_id=agent_id, task_id=task_id,
            objective=objective, action=action, scope=scope, allowed_tools=normalized_tools,
            limits={k: json.loads(v) for k, v in normalized_limits}, policy_version=policy_version,
            issued_at=issued_at, expires_at=expires_at, provenance=provenance, proof=proof,
        )
        return cls(authorization_id, authorizer, agent_id, task_id, objective, action, scope,
                   normalized_tools, normalized_limits, policy_version, issued_at, expires_at,
                   provenance, proof, authorization_hash(canonical))

    def verify_integrity(self) -> None:
        limits = {key: json.loads(value) for key, value in self.limits}
        canonical = canonical_authorization(
            authorization_id=self.authorization_id, authorizer=self.authorizer, agent_id=self.agent_id,
            task_id=self.task_id, objective=self.objective, action=self.action, scope=self.scope,
            allowed_tools=self.allowed_tools, limits=limits, policy_version=self.policy_version,
            issued_at=self.issued_at, expires_at=self.expires_at, provenance=self.provenance, proof=self.proof,
        )
        if authorization_hash(canonical) != self.integrity_hash:
            raise AuthorizationError("authorization integrity verification failed")

    def is_current(self, *, now: datetime) -> bool:
        now = _utc(now)
        return now >= self.issued_at and (self.expires_at is None or now < self.expires_at)

    def permits(self, *, agent_id: str, action: str, scope: str, tool: str, now: datetime) -> None:
        self.verify_integrity()
        if not self.is_current(now=now):
            raise AuthorizationError("authorization is outside its validity window")
        if agent_id != self.agent_id:
            raise AuthorizationError("agent identity is not authorized")
        if action != self.action:
            raise AuthorizationError("action is not authorized")
        if scope != self.scope:
            raise AuthorizationError("scope is not authorized")
        if tool not in self.allowed_tools:
            raise AuthorizationError("tool is not authorized")


class AuthorizationLedger:
    """Immutable in-memory authorization registry used for contract testing."""

    def __init__(self) -> None:
        self._records: dict[str, AuthorizationRecord] = {}
        self._revoked: set[str] = set()

    def record(self, authorization: AuthorizationRecord) -> AuthorizationRecord:
        authorization.verify_integrity()
        if authorization.authorization_id in self._records:
            raise AuthorizationError("authorization_id already exists")
        self._records[authorization.authorization_id] = authorization
        return authorization

    def revoke(self, authorization_id: str) -> None:
        if authorization_id not in self._records:
            raise AuthorizationError("unknown authorization")
        self._revoked.add(authorization_id)

    def get(self, authorization_id: str, *, now: datetime) -> AuthorizationRecord:
        record = self._records.get(authorization_id)
        if record is None:
            raise AuthorizationError("unknown authorization")
        if authorization_id in self._revoked:
            raise AuthorizationError("authorization has been revoked")
        record.verify_integrity()
        if not record.is_current(now=now):
            raise AuthorizationError("authorization is outside its validity window")
        return record

    def require_valid(self, authorization: AuthorizationRecord, *, now: datetime) -> AuthorizationRecord:
        """Require that the supplied record is the exact currently-ledgered record."""
        if authorization is None:
            raise AuthorizationError("explicit authorization is required")
        current = self.get(authorization.authorization_id, now=now)
        if current.integrity_hash != authorization.integrity_hash:
            raise AuthorizationError("authorization record differs from ledger record")
        authorization.verify_integrity()
        return current

    def authorize(self, *, authorization_id: str, agent_id: str, action: str,
                  scope: str, tool: str, now: datetime) -> AuthorizationRecord:
        record = self.get(authorization_id, now=now)
        record.permits(agent_id=agent_id, action=action, scope=scope, tool=tool, now=now)
        return record

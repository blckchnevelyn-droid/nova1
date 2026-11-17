"""Cryptographic authorizer identity gate for Nova.

This module is intentionally separate from governance record integrity. SHA-256
integrity proves that a record was not changed; Ed25519 proves that a trusted
key holder signed the exact canonical authorization envelope.

The gate is fail-closed and rejects unknown keys, unsupported algorithms,
expired/future-dated records, malformed signatures, and replay of an
authorization ID with a different signed envelope. Reuse of the exact signed
authorization is allowed because a valid authorization may intentionally bind
multiple operations within its explicit limits.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc:  # pragma: no cover - environment/dependency failure
    raise RuntimeError("Nova identity gate requires the 'cryptography' package") from exc


class IdentityError(ValueError):
    """Raised when cryptographic authorizer verification fails."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise IdentityError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _canonical(payload: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IdentityError("authorization envelope is not canonically serializable") from exc


def authorization_digest(payload: Mapping[str, object]) -> str:
    """Return the SHA-256 digest of the exact signed canonical envelope."""
    return hashlib.sha256(_canonical(payload)).hexdigest()


@dataclass(frozen=True)
class TrustedAuthorizerKey:
    key_id: str
    principal: str
    algorithm: str
    public_key: bytes
    valid_from: datetime
    valid_until: Optional[datetime] = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if not self.key_id or not self.principal:
            raise IdentityError("trusted key identity is incomplete")
        if self.algorithm != "Ed25519":
            raise IdentityError("unsupported authorization signature algorithm")
        if len(self.public_key) != 32:
            raise IdentityError("Ed25519 public key must be 32 bytes")
        start = _utc(self.valid_from)
        end = _utc(self.valid_until) if self.valid_until else None
        if end is not None and end <= start:
            raise IdentityError("trusted key validity window is invalid")
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_until", end)


class IdentityGate:
    """Fail-closed verification gate backed by an explicit trust root."""

    def __init__(self) -> None:
        self._keys: dict[str, TrustedAuthorizerKey] = {}
        self._seen_authorizations: dict[str, str] = {}

    def register_trusted_key(self, key: TrustedAuthorizerKey) -> None:
        if key.key_id in self._keys:
            raise IdentityError("key_id already registered")
        self._keys[key.key_id] = key

    def revoke_key(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise IdentityError("unknown key_id")
        self._keys[key_id] = TrustedAuthorizerKey(
            key_id=key.key_id,
            principal=key.principal,
            algorithm=key.algorithm,
            public_key=key.public_key,
            valid_from=key.valid_from,
            valid_until=key.valid_until,
            revoked=True,
        )

    def verify(
        self,
        *,
        authorization_id: str,
        principal: str,
        key_id: str,
        payload: Mapping[str, object],
        signature: str,
        now: datetime,
        issued_at: datetime,
        expires_at: Optional[datetime],
    ) -> str:
        now = _utc(now)
        issued_at = _utc(issued_at)
        expires_at = _utc(expires_at) if expires_at else None
        if not authorization_id or not principal or not key_id or not signature:
            raise IdentityError("cryptographic authorization metadata is incomplete")
        if expires_at is not None and expires_at <= issued_at:
            raise IdentityError("authorization validity window is invalid")
        if now < issued_at or (expires_at is not None and now >= expires_at):
            raise IdentityError("authorization is outside its validity window")

        key = self._keys.get(key_id)
        if key is None:
            raise IdentityError("authorizer key is not trusted")
        if key.revoked or now < key.valid_from or (key.valid_until is not None and now >= key.valid_until):
            raise IdentityError("authorizer key is revoked or outside its validity window")
        if key.principal != principal:
            raise IdentityError("key is not bound to claimed authorizer")
        if key.algorithm != "Ed25519":
            raise IdentityError("unsupported authorization signature algorithm")

        digest = authorization_digest(payload)
        seen_digest = self._seen_authorizations.get(authorization_id)
        if seen_digest is not None and seen_digest != digest:
            raise IdentityError("authorization replay detected with changed envelope")

        signed = _canonical(payload)
        try:
            raw_signature = base64.b64decode(signature.encode("ascii"), validate=True)
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(raw_signature, signed)
        except (ValueError, InvalidSignature) as exc:
            raise IdentityError("authorization signature verification failed") from exc

        self._seen_authorizations[authorization_id] = digest
        return digest

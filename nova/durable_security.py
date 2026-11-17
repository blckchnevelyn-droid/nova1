"""Durable SQLite trust registries for Nova authorization and identity state.

These registries deliberately keep authority in SQLite rather than process memory.
They are storage primitives for the governed boundary; callers must still perform
all existing binding and policy checks before authorization is consumed.
"""
from __future__ import annotations

import base64
import sqlite3
from datetime import datetime
from typing import Mapping, Optional

from .governance import AuthorizationError, AuthorizationRecord, canonical_authorization, authorization_hash
from .identity import IdentityError, TrustedAuthorizerKey, _canonical, _utc as identity_utc


class SQLiteAuthorizationLedger:
    """Durable immutable authorization registry sharing the authority DB."""

    durable = True

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS durable_authorizations (
                authorization_id TEXT PRIMARY KEY,
                authorizer TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
                objective TEXT NOT NULL, action TEXT NOT NULL, scope TEXT NOT NULL,
                allowed_tools TEXT NOT NULL, limits TEXT NOT NULL, policy_version TEXT NOT NULL,
                issued_at TEXT NOT NULL, expires_at TEXT, provenance TEXT NOT NULL,
                proof TEXT NOT NULL, integrity_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS durable_authorization_revocations (
                authorization_id TEXT PRIMARY KEY REFERENCES durable_authorizations(authorization_id),
                revoked_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS durable_authorizations_no_update
            BEFORE UPDATE ON durable_authorizations BEGIN
                SELECT RAISE(ABORT, 'authorization records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorizations_no_delete
            BEFORE DELETE ON durable_authorizations BEGIN
                SELECT RAISE(ABORT, 'authorization records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorization_revocations_no_update
            BEFORE UPDATE ON durable_authorization_revocations BEGIN
                SELECT RAISE(ABORT, 'authorization revocations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorization_revocations_no_delete
            BEFORE DELETE ON durable_authorization_revocations BEGIN
                SELECT RAISE(ABORT, 'authorization revocations are immutable');
            END;
        """)

    @staticmethod
    def _serialize(authorization: AuthorizationRecord) -> tuple:
        import json
        return (
            authorization.authorization_id, authorization.authorizer, authorization.agent_id,
            authorization.task_id, authorization.objective, authorization.action, authorization.scope,
            json.dumps(list(authorization.allowed_tools), separators=(",", ":")),
            json.dumps({k: json.loads(v) for k, v in authorization.limits}, sort_keys=True, separators=(",", ":")),
            authorization.policy_version, authorization.issued_at.isoformat(),
            authorization.expires_at.isoformat() if authorization.expires_at else None,
            authorization.provenance, authorization.proof, authorization.integrity_hash,
        )

    @staticmethod
    def _deserialize(row: sqlite3.Row) -> AuthorizationRecord:
        import json
        return AuthorizationRecord(
            authorization_id=row["authorization_id"], authorizer=row["authorizer"], agent_id=row["agent_id"],
            task_id=row["task_id"], objective=row["objective"], action=row["action"], scope=row["scope"],
            allowed_tools=tuple(json.loads(row["allowed_tools"])),
            limits=tuple(sorted((str(k), json.dumps(v, sort_keys=True, separators=(",", ":")))
                                for k, v in json.loads(row["limits"]).items())),
            policy_version=row["policy_version"], issued_at=datetime.fromisoformat(row["issued_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            provenance=row["provenance"], proof=row["proof"], integrity_hash=row["integrity_hash"],
        )

    def record(self, authorization: AuthorizationRecord) -> AuthorizationRecord:
        authorization.verify_integrity()
        if self._db.execute("SELECT 1 FROM durable_authorizations WHERE authorization_id=?",
                            (authorization.authorization_id,)).fetchone():
            raise AuthorizationError("authorization_id already exists")
        try:
            self._db.execute("INSERT INTO durable_authorizations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             self._serialize(authorization))
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("authorization_id already exists") from exc
        return authorization

    def revoke(self, authorization_id: str, *, now: datetime) -> None:
        if self._db.execute("SELECT 1 FROM durable_authorizations WHERE authorization_id=?",
                            (authorization_id,)).fetchone() is None:
            raise AuthorizationError("unknown authorization")
        try:
            self._db.execute("INSERT INTO durable_authorization_revocations VALUES (?,?)",
                             (authorization_id, identity_utc(now).isoformat()))
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("authorization is already revoked") from exc

    def get(self, authorization_id: str, *, now: datetime) -> AuthorizationRecord:
        row = self._db.execute("SELECT * FROM durable_authorizations WHERE authorization_id=?",
                               (authorization_id,)).fetchone()
        if row is None:
            raise AuthorizationError("unknown authorization")
        if self._db.execute("SELECT 1 FROM durable_authorization_revocations WHERE authorization_id=?",
                            (authorization_id,)).fetchone():
            raise AuthorizationError("authorization has been revoked")
        record = self._deserialize(row)
        record.verify_integrity()
        if not record.is_current(now=now):
            raise AuthorizationError("authorization is outside its validity window")
        return record

    def require_valid(self, authorization: AuthorizationRecord, *, now: datetime) -> AuthorizationRecord:
        if authorization is None:
            raise AuthorizationError("explicit authorization is required")
        current = self.get(authorization.authorization_id, now=now)
        if current.integrity_hash != authorization.integrity_hash:
            raise AuthorizationError("authorization record differs from durable ledger")
        authorization.verify_integrity()
        return current

    def authorize(self, *, authorization_id: str, agent_id: str, action: str,
                  scope: str, tool: str, now: datetime) -> AuthorizationRecord:
        record = self.get(authorization_id, now=now)
        record.permits(agent_id=agent_id, action=action, scope=scope, tool=tool, now=now)
        return record


class SQLiteIdentityGate:
    """Durable authorizer trust root with restart-safe replay detection."""

    durable = True

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS durable_authorizer_keys (
                key_id TEXT PRIMARY KEY, principal TEXT NOT NULL, algorithm TEXT NOT NULL,
                public_key BLOB NOT NULL, valid_from TEXT NOT NULL, valid_until TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS durable_authorizer_key_revocations (
                key_id TEXT PRIMARY KEY REFERENCES durable_authorizer_keys(key_id), revoked_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS durable_authorization_replays (
                authorization_id TEXT PRIMARY KEY, authorization_digest TEXT NOT NULL,
                first_seen_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS durable_authorizer_keys_no_update
            BEFORE UPDATE ON durable_authorizer_keys BEGIN
                SELECT RAISE(ABORT, 'trusted identity keys are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorizer_keys_no_delete
            BEFORE DELETE ON durable_authorizer_keys BEGIN
                SELECT RAISE(ABORT, 'trusted identity keys are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorizer_key_revocations_no_update
            BEFORE UPDATE ON durable_authorizer_key_revocations BEGIN
                SELECT RAISE(ABORT, 'identity key revocations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorizer_key_revocations_no_delete
            BEFORE DELETE ON durable_authorizer_key_revocations BEGIN
                SELECT RAISE(ABORT, 'identity key revocations are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorization_replays_no_update
            BEFORE UPDATE ON durable_authorization_replays BEGIN
                SELECT RAISE(ABORT, 'authorization replay records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS durable_authorization_replays_no_delete
            BEFORE DELETE ON durable_authorization_replays BEGIN
                SELECT RAISE(ABORT, 'authorization replay records are immutable');
            END;
        """)

    def register_trusted_key(self, key: TrustedAuthorizerKey) -> None:
        try:
            self._db.execute(
                "INSERT INTO durable_authorizer_keys VALUES (?,?,?,?,?,?,?)",
                (key.key_id, key.principal, key.algorithm, key.public_key,
                 key.valid_from.isoformat(), key.valid_until.isoformat() if key.valid_until else None,
                 key.valid_from.isoformat()),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityError("key_id already registered") from exc

    def revoke_key(self, key_id: str, *, now: datetime) -> None:
        if self._db.execute("SELECT 1 FROM durable_authorizer_keys WHERE key_id=?", (key_id,)).fetchone() is None:
            raise IdentityError("unknown key_id")
        try:
            self._db.execute("INSERT INTO durable_authorizer_key_revocations VALUES (?,?)",
                             (key_id, identity_utc(now).isoformat()))
        except sqlite3.IntegrityError as exc:
            raise IdentityError("key_id already revoked") from exc

    def _key(self, key_id: str) -> TrustedAuthorizerKey:
        row = self._db.execute("SELECT * FROM durable_authorizer_keys WHERE key_id=?", (key_id,)).fetchone()
        if row is None:
            raise IdentityError("authorizer key is not trusted")
        revoked = self._db.execute("SELECT 1 FROM durable_authorizer_key_revocations WHERE key_id=?",
                                   (key_id,)).fetchone() is not None
        return TrustedAuthorizerKey(
            key_id=row["key_id"], principal=row["principal"], algorithm=row["algorithm"],
            public_key=bytes(row["public_key"]), valid_from=datetime.fromisoformat(row["valid_from"]),
            valid_until=datetime.fromisoformat(row["valid_until"]) if row["valid_until"] else None,
            revoked=revoked,
        )

    def verify(self, *, authorization_id: str, principal: str, key_id: str,
               payload: Mapping[str, object], signature: str, now: datetime,
               issued_at: datetime, expires_at: Optional[datetime]) -> str:
        now = identity_utc(now); issued_at = identity_utc(issued_at)
        expires_at = identity_utc(expires_at) if expires_at else None
        if not authorization_id or not principal or not key_id or not signature:
            raise IdentityError("cryptographic authorization metadata is incomplete")
        if expires_at is not None and expires_at <= issued_at:
            raise IdentityError("authorization validity window is invalid")
        if now < issued_at or (expires_at is not None and now >= expires_at):
            raise IdentityError("authorization is outside its validity window")
        key = self._key(key_id)
        if key.revoked or now < key.valid_from or (key.valid_until is not None and now >= key.valid_until):
            raise IdentityError("authorizer key is revoked or outside its validity window")
        if key.principal != principal:
            raise IdentityError("key is not bound to claimed authorizer")
        digest = authorization_hash(_canonical(payload).decode("utf-8"))
        seen = self._db.execute("SELECT authorization_digest FROM durable_authorization_replays WHERE authorization_id=?",
                                (authorization_id,)).fetchone()
        if seen is not None and seen[0] != digest:
            raise IdentityError("authorization replay detected with changed envelope")
        try:
            raw_signature = base64.b64decode(signature.encode("ascii"), validate=True)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(raw_signature, _canonical(payload))
        except (ValueError, InvalidSignature) as exc:
            raise IdentityError("authorization signature verification failed") from exc
        if seen is None:
            try:
                self._db.execute("INSERT INTO durable_authorization_replays VALUES (?,?,?)",
                                 (authorization_id, digest, now.isoformat()))
            except sqlite3.IntegrityError:
                raced = self._db.execute("SELECT authorization_digest FROM durable_authorization_replays WHERE authorization_id=?",
                                         (authorization_id,)).fetchone()
                if raced is None or raced[0] != digest:
                    raise IdentityError("authorization replay detected")
        return digest

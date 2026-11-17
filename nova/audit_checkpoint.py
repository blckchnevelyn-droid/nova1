"""Signed audit checkpoints for independent verification of Nova audit history."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ALGORITHM = "Ed25519-SHA256-CANONICAL-JSON-V1"


class CheckpointError(ValueError):
    """Raised when a signed checkpoint cannot be trusted or verified."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class SignedAuditCheckpoint:
    version: int
    task_id: str
    event_count: int
    chain_head: str
    issued_at: str
    key_id: str
    algorithm: str
    previous_checkpoint_hash: str
    signature: str

    def signing_payload(self) -> dict[str, object]:
        return {
            "version": self.version,
            "task_id": self.task_id,
            "event_count": self.event_count,
            "chain_head": self.chain_head,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
        }

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.signing_payload() | {"signature": self.signature})).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return self.signing_payload() | {"signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SignedAuditCheckpoint":
        required = ("version", "task_id", "event_count", "chain_head", "issued_at", "key_id",
                    "algorithm", "previous_checkpoint_hash", "signature")
        if any(key not in value for key in required):
            raise CheckpointError("checkpoint is missing required fields")
        try:
            checkpoint = cls(
                version=int(value["version"]), task_id=str(value["task_id"]),
                event_count=int(value["event_count"]), chain_head=str(value["chain_head"]),
                issued_at=str(value["issued_at"]), key_id=str(value["key_id"]),
                algorithm=str(value["algorithm"]), previous_checkpoint_hash=str(value["previous_checkpoint_hash"]),
                signature=str(value["signature"]),
            )
        except (TypeError, ValueError) as exc:
            raise CheckpointError("checkpoint field types are invalid") from exc
        if checkpoint.version != 1 or checkpoint.algorithm != ALGORITHM:
            raise CheckpointError("unsupported checkpoint format")
        if checkpoint.event_count < 0 or len(checkpoint.chain_head) != 64:
            raise CheckpointError("checkpoint state is invalid")
        return checkpoint


class AuditCheckpointSigner:
    """Signs checkpoints while keeping signing keys outside the audit database."""

    def __init__(self, *, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not key_id:
            raise CheckpointError("key_id is required")
        self.key_id = key_id
        self._private_key = private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, *, task_id: str, event_count: int, chain_head: str, issued_at: str,
             previous_checkpoint_hash: str = "0" * 64) -> SignedAuditCheckpoint:
        if event_count < 0 or len(chain_head) != 64 or len(previous_checkpoint_hash) != 64:
            raise CheckpointError("invalid checkpoint state")
        unsigned = SignedAuditCheckpoint(
            version=1, task_id=task_id, event_count=event_count, chain_head=chain_head,
            issued_at=issued_at, key_id=self.key_id, algorithm=ALGORITHM,
            previous_checkpoint_hash=previous_checkpoint_hash, signature="",
        )
        signature = _b64(self._private_key.sign(_canonical(unsigned.signing_payload())))
        return SignedAuditCheckpoint(**(unsigned.to_dict() | {"signature": signature}))


class AuditCheckpointVerifier:
    """Verifies signed checkpoints using an independently managed public-key ring."""

    def __init__(self, trusted_public_keys: Mapping[str, Ed25519PublicKey]) -> None:
        self._keys = dict(trusted_public_keys)

    def verify(self, checkpoint: SignedAuditCheckpoint) -> str:
        if checkpoint.algorithm != ALGORITHM or checkpoint.version != 1:
            raise CheckpointError("unsupported checkpoint format")
        public_key = self._keys.get(checkpoint.key_id)
        if public_key is None:
            raise CheckpointError("checkpoint signing key is not trusted")
        try:
            public_key.verify(_unb64(checkpoint.signature), _canonical(checkpoint.signing_payload()))
        except (InvalidSignature, ValueError) as exc:
            raise CheckpointError("checkpoint signature verification failed") from exc
        return checkpoint.digest()

    def verify_chain(self, checkpoints: Sequence[SignedAuditCheckpoint]) -> None:
        previous = "0" * 64
        for checkpoint in checkpoints:
            if checkpoint.previous_checkpoint_hash != previous:
                raise CheckpointError("checkpoint continuity verification failed")
            previous = self.verify(checkpoint)


def audit_state(events: Sequence[object], *, chain_head: str | None = None) -> tuple[int, str]:
    """Return audit event count and a chain head obtained from the authoritative verifier."""
    if not events:
        return 0, "0" * 64
    if chain_head is None or len(chain_head) != 64:
        raise CheckpointError("a verified audit chain head is required")
    return len(events), chain_head


def compare_checkpoint_to_events(checkpoint: SignedAuditCheckpoint, events: Sequence[object], *,
                                 chain_head: str | None = None) -> None:
    """Fail closed when current audit history diverges from an independently held checkpoint."""
    count, observed_head = audit_state(events, chain_head=chain_head)
    if checkpoint.event_count != count:
        raise CheckpointError("audit checkpoint event-count mismatch")
    if checkpoint.chain_head != observed_head:
        raise CheckpointError("audit checkpoint chain-head mismatch")

"""Independent verification boundary for Nova completion proofs."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Nova verification requires the 'cryptography' package") from exc


class VerificationError(ValueError):
    """Raised when an independent completion proof is invalid."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise VerificationError("verification timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def canonical_completion(*, task_id: str, expected_revision: int, operation_id: str,
                         attempt_id: str, evidence_hash: str, expected_postcondition_hash: str,
                         resulting_state_hash: str, decision: str,
                         verifier_id: str, issued_at: datetime) -> bytes:
    if decision not in {"VERIFIED", "REJECTED"}:
        raise VerificationError("invalid verification decision")
    if expected_revision < 0 or not all((task_id, operation_id, attempt_id, evidence_hash, expected_postcondition_hash, resulting_state_hash, verifier_id)):
        raise VerificationError("completion proof binding is incomplete")
    payload = {
        "task_id": task_id, "expected_revision": expected_revision,
        "operation_id": operation_id, "attempt_id": attempt_id,
        "evidence_hash": evidence_hash,
        "expected_postcondition_hash": expected_postcondition_hash,
        "resulting_state_hash": resulting_state_hash,
        "decision": decision,
        "verifier_id": verifier_id, "issued_at": _utc(issued_at).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def completion_digest(**kwargs: object) -> str:
    return hashlib.sha256(canonical_completion(**kwargs)).hexdigest()


@dataclass(frozen=True)
class TrustedVerifierKey:
    verifier_id: str
    algorithm: str
    public_key: bytes
    valid_from: datetime
    valid_until: Optional[datetime] = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if not self.verifier_id or self.algorithm != "Ed25519":
            raise VerificationError("invalid verifier identity")
        if len(self.public_key) != 32:
            raise VerificationError("Ed25519 verifier public key must be 32 bytes")
        start = _utc(self.valid_from)
        end = _utc(self.valid_until) if self.valid_until else None
        if end is not None and end <= start:
            raise VerificationError("verifier validity window is invalid")
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_until", end)


@dataclass(frozen=True)
class CompletionProof:
    task_id: str
    expected_revision: int
    operation_id: str
    attempt_id: str
    evidence_hash: str
    expected_postcondition_hash: str
    resulting_state_hash: str
    decision: str
    verifier_id: str
    issued_at: datetime
    signature: str


class VerificationGate:
    """Fail-closed trust root for independent completion verification."""

    def __init__(self, resulting_state_verifier: Optional[Callable[[CompletionProof], bool]] = None) -> None:
        self._keys: dict[str, TrustedVerifierKey] = {}
        self._seen: dict[str, str] = {}
        self._resulting_state_verifier = resulting_state_verifier

    def register_trusted_key(self, key: TrustedVerifierKey) -> None:
        if key.verifier_id in self._keys:
            raise VerificationError("verifier_id already registered")
        self._keys[key.verifier_id] = key

    def revoke_key(self, verifier_id: str) -> None:
        key = self._keys.get(verifier_id)
        if key is None:
            raise VerificationError("unknown verifier")
        self._keys[verifier_id] = TrustedVerifierKey(
            verifier_id=key.verifier_id, algorithm=key.algorithm, public_key=key.public_key,
            valid_from=key.valid_from, valid_until=key.valid_until, revoked=True)

    def verify(self, proof: CompletionProof, *, now: datetime) -> str:
        now = _utc(now)
        issued = _utc(proof.issued_at)
        if now < issued:
            raise VerificationError("verification proof is future-dated")
        key = self._keys.get(proof.verifier_id)
        if key is None or key.revoked or now < key.valid_from or (key.valid_until is not None and now >= key.valid_until):
            raise VerificationError("verifier is not trusted or is outside its validity window")
        payload = canonical_completion(
            task_id=proof.task_id, expected_revision=proof.expected_revision,
            operation_id=proof.operation_id, attempt_id=proof.attempt_id,
            evidence_hash=proof.evidence_hash,
            expected_postcondition_hash=proof.expected_postcondition_hash,
            resulting_state_hash=proof.resulting_state_hash,
            decision=proof.decision, verifier_id=proof.verifier_id,
            issued_at=proof.issued_at)
        digest = hashlib.sha256(payload).hexdigest()
        previous = self._seen.get(proof.attempt_id)
        if previous is not None and previous != digest:
            raise VerificationError("attempt has conflicting verification provenance")
        try:
            signature = base64.b64decode(proof.signature.encode("ascii"), validate=True)
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, payload)
        except (ValueError, InvalidSignature) as exc:
            raise VerificationError("completion proof signature verification failed") from exc
        if self._resulting_state_verifier is None:
            raise VerificationError("independent resulting-state verifier is required")
        try:
            verified_result = bool(self._resulting_state_verifier(proof))
        except Exception as exc:
            raise VerificationError("resulting-state verification failed closed") from exc
        if not verified_result:
            raise VerificationError("resulting-state post-condition verification failed")
        self._seen[proof.attempt_id] = digest
        if proof.decision != "VERIFIED":
            raise VerificationError("completion proof is not successful verification")
        return digest


def parse_proof(encoded: str) -> CompletionProof:
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        payload = json.loads(raw.decode("utf-8"))
        return CompletionProof(
            task_id=payload["task_id"], expected_revision=int(payload["expected_revision"]),
            operation_id=payload["operation_id"], attempt_id=payload["attempt_id"],
            evidence_hash=payload["evidence_hash"], decision=payload["decision"],
            verifier_id=payload["verifier_id"], issued_at=datetime.fromisoformat(payload["issued_at"]),
            signature=payload["signature"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VerificationError("malformed completion proof") from exc

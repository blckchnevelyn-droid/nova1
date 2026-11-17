from datetime import datetime, timedelta, timezone
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.identity import IdentityError, IdentityGate, TrustedAuthorizerKey


def _case():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    payload = {
        "authorization_id": "auth-1",
        "authorizer": "human-owner",
        "agent_id": "nova-agent",
        "task_id": "task-1",
        "objective": "run-safe-test",
        "action": "execute-test",
        "scope": "tests/unit",
        "policy_version": "nova-policy-v1",
    }
    signature = base64.b64encode(private.sign(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8"))).decode("ascii")
    return now, private, public, payload, signature


def _gate(now, public):
    gate = IdentityGate()
    gate.register_trusted_key(TrustedAuthorizerKey(
        key_id="owner-key-v1",
        principal="human-owner",
        algorithm="Ed25519",
        public_key=public,
        valid_from=now - timedelta(minutes=1),
    ))
    return gate


def test_valid_authorization_is_accepted():
    now, _, public, payload, signature = _case()
    gate = _gate(now, public)
    digest = gate.verify(
        authorization_id="auth-1",
        principal="human-owner",
        key_id="owner-key-v1",
        payload=payload,
        signature=signature,
        now=now,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )
    assert len(digest) == 64


def test_forged_payload_is_rejected():
    now, _, public, payload, signature = _case()
    gate = _gate(now, public)
    payload["scope"] = "outside-authorized-scope"
    with pytest.raises(IdentityError):
        gate.verify(
            authorization_id="auth-1", principal="human-owner", key_id="owner-key-v1",
            payload=payload, signature=signature, now=now,
            issued_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
        )


def test_unknown_key_is_rejected():
    now, _, public, payload, signature = _case()
    gate = IdentityGate()
    with pytest.raises(IdentityError):
        gate.verify(
            authorization_id="auth-1", principal="human-owner", key_id="unknown",
            payload=payload, signature=signature, now=now,
            issued_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
        )


def test_exact_signed_authorization_reuse_is_allowed_but_changed_envelope_is_rejected():
    now, private, public, payload, signature = _case()
    gate = _gate(now, public)
    kwargs = dict(
        authorization_id="auth-1", principal="human-owner", key_id="owner-key-v1",
        payload=payload, signature=signature, now=now,
        issued_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
    )

    first_digest = gate.verify(**kwargs)
    second_digest = gate.verify(**kwargs)
    assert second_digest == first_digest

    changed_payload = dict(payload)
    changed_payload["scope"] = "outside-authorized-scope"
    changed_signature = base64.b64encode(private.sign(json.dumps(
        changed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8"))).decode("ascii")
    with pytest.raises(IdentityError, match="replay detected with changed envelope"):
        gate.verify(**{**kwargs, "payload": changed_payload, "signature": changed_signature})


def test_revoked_key_is_rejected():
    now, _, public, payload, signature = _case()
    gate = _gate(now, public)
    gate.revoke_key("owner-key-v1")
    with pytest.raises(IdentityError):
        gate.verify(
            authorization_id="auth-1", principal="human-owner", key_id="owner-key-v1",
            payload=payload, signature=signature, now=now,
            issued_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
        )

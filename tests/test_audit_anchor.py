from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from nova.audit_anchor import AuditAnchorError, ExternalAnchor, verify_external_anchor
from nova.audit_checkpoint import AuditCheckpointSigner, AuditCheckpointVerifier


def test_external_anchor_binds_checkpoint_digest_and_custody_domain():
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = signer.sign(
        task_id="task-1", event_count=3, chain_head="a" * 64,
        issued_at="2026-01-01T00:00:00+00:00",
    )
    verifier = AuditCheckpointVerifier({"audit-key-v1": signer.public_key})
    anchor = ExternalAnchor(
        anchor_id="anchor-1", checkpoint_digest=checkpoint.digest(),
        anchored_at="2026-01-01T00:01:00+00:00", custody_domain="external-v1",
    )

    verify_external_anchor(
        checkpoint, anchor, verifier,
        trusted_custody_domains={"anchor-1": "external-v1"},
    )


def test_anchor_substitution_fails_closed():
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = signer.sign(
        task_id="task-1", event_count=3, chain_head="a" * 64,
        issued_at="2026-01-01T00:00:00+00:00",
    )
    verifier = AuditCheckpointVerifier({"audit-key-v1": signer.public_key})
    forged_anchor = ExternalAnchor(
        anchor_id="anchor-1", checkpoint_digest="b" * 64,
        anchored_at="2026-01-01T00:01:00+00:00", custody_domain="external-v1",
    )
    with pytest.raises(AuditAnchorError, match="checkpoint mismatch"):
        verify_external_anchor(
            checkpoint, forged_anchor, verifier,
            trusted_custody_domains={"anchor-1": "external-v1"},
        )


def test_untrusted_or_wrong_custody_domain_fails_closed():
    signer = AuditCheckpointSigner(key_id="audit-key-v1", private_key=Ed25519PrivateKey.generate())
    checkpoint = signer.sign(
        task_id="task-1", event_count=3, chain_head="a" * 64,
        issued_at="2026-01-01T00:00:00+00:00",
    )
    verifier = AuditCheckpointVerifier({"audit-key-v1": signer.public_key})
    anchor = ExternalAnchor(
        anchor_id="anchor-1", checkpoint_digest=checkpoint.digest(),
        anchored_at="2026-01-01T00:01:00+00:00", custody_domain="wrong-domain",
    )
    with pytest.raises(AuditAnchorError, match="custody domain mismatch"):
        verify_external_anchor(
            checkpoint, anchor, verifier,
            trusted_custody_domains={"anchor-1": "external-v1"},
        )

    with pytest.raises(AuditAnchorError, match="not trusted"):
        verify_external_anchor(
            checkpoint, anchor, verifier,
            trusted_custody_domains={},
        )

from nova.runtime_security import (
    RuntimeDecision,
    RuntimeSecurityEvidence,
    RuntimeSecurityGate,
)


def evidence(**overrides):
    values = {
        "request_id": "req-1",
        "agent_id": "agent",
        "capability": "execute",
        "authorization_id": "auth-1",
        "authorization_hash": "hash-1",
        "identity_key_id": "key-1",
        "identity_digest": "digest-1",
    }
    values.update(overrides)
    return RuntimeSecurityEvidence(**values)


def test_runtime_gate_denies_incomplete_authority_evidence():
    result = RuntimeSecurityGate().evaluate(
        evidence(authorization_hash="")
    )
    assert result.decision == RuntimeDecision.DENY


def test_runtime_gate_rejects_non_evidence_input():
    try:
        RuntimeSecurityGate().evaluate(object())
    except TypeError as exc:
        assert "deterministic authority evidence" in str(exc)
    else:
        raise AssertionError("runtime gate accepted non-authority evidence")


def test_runtime_gate_allows_complete_authority_evidence():
    result = RuntimeSecurityGate().evaluate(evidence())
    assert result.decision == RuntimeDecision.ALLOW

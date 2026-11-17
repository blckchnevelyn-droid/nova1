"""P2.1 Runtime Security Foundation.

Fail-closed runtime enforcement checkpoint. The deterministic authority remains
the source of authorization, identity, capability, and policy truth; this gate
only consumes evidence that those checks have already succeeded.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuntimeDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class RuntimeSecurityEvidence:
    """Evidence assembled only after deterministic authority validation."""

    request_id: str
    agent_id: str
    capability: str
    authorization_id: str
    authorization_hash: str
    identity_key_id: str
    identity_digest: str


@dataclass(frozen=True)
class RuntimeSecurityResult:
    decision: RuntimeDecision
    reason: str
    request_id: str


class RuntimeSecurityGate:
    """Mandatory fail-closed checkpoint for an already-authorized execution."""

    def evaluate(self, evidence: RuntimeSecurityEvidence) -> RuntimeSecurityResult:
        if not isinstance(evidence, RuntimeSecurityEvidence):
            raise TypeError("runtime security requires deterministic authority evidence")

        required = (
            evidence.request_id,
            evidence.agent_id,
            evidence.capability,
            evidence.authorization_id,
            evidence.authorization_hash,
            evidence.identity_key_id,
            evidence.identity_digest,
        )
        if not all(required):
            return RuntimeSecurityResult(
                RuntimeDecision.DENY,
                "incomplete runtime security evidence",
                evidence.request_id,
            )

        return RuntimeSecurityResult(
            RuntimeDecision.ALLOW,
            "runtime security evidence accepted",
            evidence.request_id,
        )

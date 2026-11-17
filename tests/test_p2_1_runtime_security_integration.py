import pytest

from nova.governance import AuthorizationError
from nova.runtime_security import RuntimeDecision, RuntimeSecurityResult
from tests.test_execution import NOW, TOOL, identify, setup_boundary


def test_consequential_claim_crosses_p2_1_gate(monkeypatch):
    store, task, ledger, auth, boundary = setup_boundary()
    operation = identify(boundary, task, auth)
    attempt = boundary.create_attempt(
        operation_id=operation.operation_id,
        worker_id="w1",
        now=NOW,
    )
    seen = {}

    def evaluate(evidence):
        seen["evidence"] = evidence
        return RuntimeSecurityResult(
            RuntimeDecision.ALLOW,
            "test allow",
            evidence.request_id,
        )

    monkeypatch.setattr(boundary._runtime_security, "evaluate", evaluate)
    claimed = boundary.claim(
        attempt_id=attempt.attempt_id,
        worker_id="w1",
        now=NOW,
        authorization=auth,
        tool=TOOL,
    )

    assert claimed.state.value == "CLAIMED"
    assert seen["evidence"].authorization_id == auth.authorization_id
    assert seen["evidence"].authorization_hash == auth.integrity_hash
    assert seen["evidence"].agent_id == auth.agent_id
    assert seen["evidence"].capability == TOOL
    assert seen["evidence"].identity_key_id
    assert seen["evidence"].identity_digest


def test_p2_1_gate_denial_blocks_consequential_claim(monkeypatch):
    store, task, ledger, auth, boundary = setup_boundary()
    operation = identify(boundary, task, auth)
    attempt = boundary.create_attempt(
        operation_id=operation.operation_id,
        worker_id="w1",
        now=NOW,
    )

    def deny(evidence):
        return RuntimeSecurityResult(
            RuntimeDecision.DENY,
            "test deny",
            evidence.request_id,
        )

    monkeypatch.setattr(boundary._runtime_security, "evaluate", deny)

    with pytest.raises(AuthorizationError, match="runtime security gate denied execution"):
        boundary.claim(
            attempt_id=attempt.attempt_id,
            worker_id="w1",
            now=NOW,
            authorization=auth,
            tool=TOOL,
        )

    restored = boundary.read_attempt(attempt.attempt_id)
    assert restored.state.value == "NOT_EXECUTED"


def test_p2_1_gate_exception_fails_closed_before_claim(monkeypatch):
    store, task, ledger, auth, boundary = setup_boundary()
    operation = identify(boundary, task, auth)
    attempt = boundary.create_attempt(
        operation_id=operation.operation_id,
        worker_id="w1",
        now=NOW,
    )

    def explode(_evidence):
        raise RuntimeError("gate failure")

    monkeypatch.setattr(boundary._runtime_security, "evaluate", explode)

    with pytest.raises(RuntimeError, match="gate failure"):
        boundary.claim(
            attempt_id=attempt.attempt_id,
            worker_id="w1",
            now=NOW,
            authorization=auth,
            tool=TOOL,
        )

    assert boundary.read_attempt(attempt.attempt_id).state.value == "NOT_EXECUTED"


def test_direct_internal_execution_still_cannot_cross_governed_binding():
    store, task, ledger, auth, boundary = setup_boundary()
    internal = boundary._execution
    operation = internal.identify_operation(
        task_id=task.task_id,
        idempotency_key="direct-p2-1-bypass",
        action="write",
        scope=task.objective,
        specification={"path": "blocked"},
        now=NOW,
    )
    attempt = internal.create_attempt(
        operation_id=operation.operation_id,
        worker_id=auth.agent_id,
        now=NOW,
    )

    with pytest.raises(AuthorizationError, match="governed authorization binding"):
        internal.claim(
            attempt_id=attempt.attempt_id,
            worker_id=auth.agent_id,
            now=NOW,
            authorization=auth,
            tool=TOOL,
        )


def test_p2_1_gate_precedes_consequential_claim(monkeypatch):
    store, task, ledger, auth, boundary = setup_boundary()
    operation = identify(boundary, task, auth)
    attempt = boundary.create_attempt(
        operation_id=operation.operation_id,
        worker_id="w1",
        now=NOW,
    )
    order = []

    def allow(evidence):
        order.append("runtime-security-gate")
        return RuntimeSecurityResult(
            RuntimeDecision.ALLOW,
            "test allow",
            evidence.request_id,
        )

    original_claim = boundary._execution.claim

    def claim(*args, **kwargs):
        order.append("governed-claim")
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(boundary._runtime_security, "evaluate", allow)
    monkeypatch.setattr(boundary._execution, "claim", claim)

    boundary.claim(
        attempt_id=attempt.attempt_id,
        worker_id="w1",
        now=NOW,
        authorization=auth,
        tool=TOOL,
    )

    assert order == ["runtime-security-gate", "governed-claim"]

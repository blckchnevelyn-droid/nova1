import pytest


@pytest.fixture(autouse=True)
def set_completion_integrity_key(monkeypatch):
    monkeypatch.setenv("NOVA_COMPLETION_PROOF_INTEGRITY_KEY", "nova-test-completion-integrity-key-2026-09-20")
    monkeypatch.setenv("NOVA_DURABLE_INTEGRITY_KEY", "nova-test-durable-integrity-key-2026-09-20")


@pytest.fixture(autouse=True)
def bind_durable_approval_policy(monkeypatch, request):
    if request.module.__name__ != "tests.test_durable_authority":
        return
    original = request.module.make_approval

    def bound_make_approval(task, *args, **kwargs):
        kwargs.setdefault("scope", task.objective)
        kwargs.setdefault("policy_version", task.policy_version)
        return original(task, *args, **kwargs)

    monkeypatch.setattr(request.module, "make_approval", bound_make_approval)

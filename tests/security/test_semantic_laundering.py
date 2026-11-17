"""Adversarial tests for the deterministic cumulative composition guard."""
import pytest

from nova.composition import ActionEffect, CompositionDenied, CompositionPolicy, evaluate_cumulative


def effect(*, task="task-1", auth="auth-1", policy="p1", action="write", name):
    return ActionEffect(task, auth, policy, action, name)


def test_benign_multistep_composition_is_allowed():
    policy = CompositionPolicy(
        max_operations=3,
        allowed_effects=("write_temp", "write_final"),
        forbidden_sequences=(("read_secret", "stage_secret", "transfer_secret"),),
    )
    first = effect(name="write_temp")
    second = effect(name="write_final")

    admitted = evaluate_cumulative(current=first, prior=(), policy=policy)
    admitted = evaluate_cumulative(current=second, prior=admitted, policy=policy)

    assert tuple(item.effect for item in admitted) == ("write_temp", "write_final")


def test_semantic_laundering_sequence_is_denied_before_forbidden_effect():
    policy = CompositionPolicy(
        max_operations=4,
        allowed_effects=("read_secret", "stage_secret", "transfer_secret"),
        forbidden_sequences=(("read_secret", "stage_secret", "transfer_secret"),),
    )
    read = effect(name="read_secret")
    stage = effect(name="stage_secret")
    transfer = effect(name="transfer_secret")

    admitted = evaluate_cumulative(current=read, prior=(), policy=policy)
    admitted = evaluate_cumulative(current=stage, prior=admitted, policy=policy)

    with pytest.raises(CompositionDenied, match="forbidden cumulative composition"):
        evaluate_cumulative(current=transfer, prior=admitted, policy=policy)

    assert tuple(item.effect for item in admitted) == ("read_secret", "stage_secret")


def test_context_change_cannot_launder_authority():
    policy = CompositionPolicy(max_operations=3, allowed_effects=("write_temp", "write_final"))
    prior = (effect(name="write_temp"),)
    changed = effect(auth="different-auth", name="write_final")

    with pytest.raises(CompositionDenied, match="cumulative authorization context changed"):
        evaluate_cumulative(current=changed, prior=prior, policy=policy)


def test_policy_change_cannot_launder_authority():
    policy = CompositionPolicy(max_operations=3, allowed_effects=("write_temp", "write_final"))
    prior = (effect(name="write_temp"),)
    changed = effect(policy="p2", name="write_final")

    with pytest.raises(CompositionDenied, match="cumulative authorization context changed"):
        evaluate_cumulative(current=changed, prior=prior, policy=policy)


def test_capability_accumulation_is_denied_when_effect_is_not_authorized():
    policy = CompositionPolicy(max_operations=3, allowed_effects=("write_temp",))
    prior = (effect(name="write_temp"),)
    escalated = effect(name="delete_data")

    with pytest.raises(CompositionDenied, match="operation effect is not authorized"):
        evaluate_cumulative(current=escalated, prior=prior, policy=policy)


def test_operation_ceiling_is_cumulative():
    policy = CompositionPolicy(max_operations=2, allowed_effects=("write_temp",))
    prior = (effect(name="write_temp"), effect(name="write_temp"))

    with pytest.raises(CompositionDenied, match="cumulative operation limit exceeded"):
        evaluate_cumulative(current=effect(name="write_temp"), prior=prior, policy=policy)

"""Deterministic cumulative-action composition guard.

This module is intentionally policy-data driven. It does not infer intent or
assign a universal risk score. A caller supplies normalized operation effects
and an immutable authorization policy; the guard evaluates the cumulative
sequence before an operation is admitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple


class CompositionDenied(ValueError):
    """Raised when a cumulative operation sequence exceeds its authorization."""


@dataclass(frozen=True)
class ActionEffect:
    """Normalized, deterministic effect descriptor for one operation."""

    task_id: str
    authorization_id: str
    policy_version: str
    action: str
    effect: str


@dataclass(frozen=True)
class CompositionPolicy:
    """Explicit cumulative policy; no inferred or universal risk taxonomy."""

    max_operations: int
    allowed_effects: Tuple[str, ...]
    forbidden_sequences: Tuple[Tuple[str, ...], ...] = ()

    def __post_init__(self) -> None:
        if self.max_operations < 1:
            raise CompositionDenied("max_operations must be positive")
        if not self.allowed_effects:
            raise CompositionDenied("at least one allowed effect is required")
        if any(not effect for effect in self.allowed_effects):
            raise CompositionDenied("effect names must be non-empty")
        if any(not sequence for sequence in self.forbidden_sequences):
            raise CompositionDenied("forbidden sequences must be non-empty")


def evaluate_cumulative(
    *,
    current: ActionEffect,
    prior: Iterable[ActionEffect],
    policy: CompositionPolicy,
) -> Tuple[ActionEffect, ...]:
    """Return the admitted sequence or deny it before the new effect occurs.

    The evaluator requires exact task, authorization, and policy continuity.
    Forbidden compositions are matched against the normalized effect sequence.
    A forbidden sequence is denied before the current effect is admitted.
    """
    history = tuple(prior)
    sequence = history + (current,)

    for item in sequence:
        if (
            item.task_id != current.task_id
            or item.authorization_id != current.authorization_id
            or item.policy_version != current.policy_version
        ):
            raise CompositionDenied("cumulative authorization context changed")

    if len(sequence) > policy.max_operations:
        raise CompositionDenied("cumulative operation limit exceeded")

    if current.effect not in policy.allowed_effects:
        raise CompositionDenied("operation effect is not authorized")

    effects = tuple(item.effect for item in sequence)
    for forbidden in policy.forbidden_sequences:
        if _contains_subsequence(effects, forbidden):
            raise CompositionDenied("forbidden cumulative composition")

    return sequence


def _contains_subsequence(sequence: Tuple[str, ...], target: Tuple[str, ...]) -> bool:
    if len(target) > len(sequence):
        return False
    width = len(target)
    return any(sequence[index:index + width] == target
               for index in range(len(sequence) - width + 1))

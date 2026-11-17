from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    ALLOW = "ALLOW"
    DENIED = "DENIED"
    ESCALATE = "ESCALATE"
    STOPPED = "STOPPED"


class Verification(Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


class State(Enum):
    EXECUTING = "EXECUTING"
    OBSERVING = "OBSERVING"
    VERIFYING = "VERIFYING"
    RECOVERY = "RECOVERY"
    COMPLETED = "COMPLETED"
    ESCALATE = "ESCALATE"
    DENIED = "DENIED"
    STOPPED = "STOPPED"


@dataclass(frozen=True)
class GovernanceResult:
    decision: Decision
    reason: str


def govern(*, authorized: bool, in_scope: bool, approval_required: bool,
           approval_granted: bool, safe: bool) -> GovernanceResult:
    if not safe:
        return GovernanceResult(Decision.STOPPED, "Safety condition not satisfied.")

    if not authorized or not in_scope:
        return GovernanceResult(Decision.DENIED, "Authority or scope requirement failed.")

    if approval_required and not approval_granted:
        return GovernanceResult(Decision.ESCALATE, "Required human approval is missing.")

    return GovernanceResult(Decision.ALLOW, "All governance requirements satisfied.")


def execution_allowed(governance: GovernanceResult) -> bool:
    return governance.decision == Decision.ALLOW


def completion_allowed(verification: Verification) -> bool:
    return verification == Verification.VERIFIED


def recovery_allowed(*, authorized: bool, safe: bool) -> bool:
    return authorized and safe


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_authorized_action_is_allowed() -> None:
    result = govern(
        authorized=True,
        in_scope=True,
        approval_required=False,
        approval_granted=False,
        safe=True,
    )
    assert_true(result.decision == Decision.ALLOW, "Authorized action must be allowed.")
    assert_true(execution_allowed(result), "ALLOW must permit execution.")


def test_unauthorized_action_is_denied() -> None:
    result = govern(
        authorized=False,
        in_scope=True,
        approval_required=False,
        approval_granted=False,
        safe=True,
    )
    assert_true(result.decision == Decision.DENIED, "Unauthorized action must be denied.")
    assert_true(not execution_allowed(result), "DENIED must prevent execution.")


def test_out_of_scope_action_is_denied() -> None:
    result = govern(
        authorized=True,
        in_scope=False,
        approval_required=False,
        approval_granted=False,
        safe=True,
    )
    assert_true(result.decision == Decision.DENIED, "Out-of-scope action must be denied.")
    assert_true(not execution_allowed(result), "Out-of-scope action must not execute.")


def test_missing_human_approval_escalates() -> None:
    result = govern(
        authorized=True,
        in_scope=True,
        approval_required=True,
        approval_granted=False,
        safe=True,
    )
    assert_true(
        result.decision == Decision.ESCALATE,
        "Missing required human approval must escalate.",
    )
    assert_true(not execution_allowed(result), "ESCALATE must prevent execution.")


def test_unsafe_action_stops() -> None:
    result = govern(
        authorized=True,
        in_scope=True,
        approval_required=False,
        approval_granted=False,
        safe=False,
    )
    assert_true(result.decision == Decision.STOPPED, "Unsafe action must stop.")
    assert_true(not execution_allowed(result), "STOPPED must prevent execution.")


def test_failed_verification_cannot_complete() -> None:
    assert_true(
        not completion_allowed(Verification.FAILED),
        "FAILED verification must not produce COMPLETED.",
    )


def test_inconclusive_verification_cannot_complete() -> None:
    assert_true(
        not completion_allowed(Verification.INCONCLUSIVE),
        "INCONCLUSIVE verification must not produce COMPLETED.",
    )


def test_blocked_verification_cannot_complete() -> None:
    assert_true(
        not completion_allowed(Verification.BLOCKED),
        "BLOCKED verification must not produce COMPLETED.",
    )


def test_verified_result_can_complete() -> None:
    assert_true(
        completion_allowed(Verification.VERIFIED),
        "VERIFIED result must permit completion.",
    )


def test_unauthorized_recovery_is_blocked() -> None:
    assert_true(
        not recovery_allowed(authorized=False, safe=True),
        "Unauthorized recovery must be blocked.",
    )


def test_unsafe_recovery_is_blocked() -> None:
    assert_true(
        not recovery_allowed(authorized=True, safe=False),
        "Unsafe recovery must be blocked.",
    )


def test_authorized_safe_recovery_is_allowed() -> None:
    assert_true(
        recovery_allowed(authorized=True, safe=True),
        "Authorized safe recovery should be allowed.",
    )


def run_tests() -> None:
    tests = [
        test_authorized_action_is_allowed,
        test_unauthorized_action_is_denied,
        test_out_of_scope_action_is_denied,
        test_missing_human_approval_escalates,
        test_unsafe_action_stops,
        test_failed_verification_cannot_complete,
        test_inconclusive_verification_cannot_complete,
        test_blocked_verification_cannot_complete,
        test_verified_result_can_complete,
        test_unauthorized_recovery_is_blocked,
        test_unsafe_recovery_is_blocked,
        test_authorized_safe_recovery_is_allowed,
    ]

    passed = 0

    for test in tests:
        test()
        passed += 1
        print(f"PASS: {test.__name__}")

    print(f"\nFoundation tests passed: {passed}/{len(tests)}")


if __name__ == "__main__":
    run_tests()

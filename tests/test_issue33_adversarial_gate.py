"""Independent adversarial acceptance harness for Issue #33.

System-under-test is frozen main at 69cdf01f000be471b97676d7ed7697bc7d4eb577.
This file exercises the existing governed boundary without weakening production
contracts. A failure is evidence against the frozen security state.
"""

import sqlite3
from datetime import timedelta

import pytest

from nova.authority import State, ValidationError
from nova.execution import AttemptState
from nova.governance import AuthorizationError
from nova.verification import VerificationError
from tests.governed_fixtures import NOW, TOOL, governed_execution, governed_task, signed_auth
from tests.test_governed_execution import _composition_setup


def test_tool_effect_substitution_cannot_cross_signed_contract():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe", "danger"), tool_effects={TOOL: ["safe"]})
    with pytest.raises(AuthorizationError, match="effect is not authorized for this tool"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="effect-substitution",
            action="write", scope=task.objective, specification={"effect": "danger"},
            now=NOW, authorization=auth, tool=TOOL)


def test_tool_effect_mapping_cannot_grant_an_unauthorized_tool():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe_a", "safe_b"),
        tool_effects={TOOL: ["safe_a"], "other.tool": ["safe_b"]})
    with pytest.raises(AuthorizationError, match="tool is not authorized"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="tool-substitution",
            action="write", scope=task.objective, specification={"effect": "safe_b"},
            now=NOW, authorization=auth, tool="other.tool")


@pytest.mark.parametrize("sequence,should_deny", [
    (("read_secret", "stage_secret", "transfer_secret"), True),
    (("read_secret", "read_secret", "stage_secret", "transfer_secret"), True),
    (("stage_secret", "read_secret", "transfer_secret"), False),
])
def test_composition_permutations_and_prefixes_do_not_bypass_forbidden_sequence(sequence, should_deny):
    store, task, ledger, auth, boundary = _composition_setup()
    for index, effect in enumerate(sequence):
        call = lambda: boundary.identify_operation(
            task_id=task.task_id, idempotency_key=f"composition-{index}",
            action="write", scope=task.objective, specification={"effect": effect},
            now=NOW, authorization=auth, tool=TOOL)
        if index == len(sequence) - 1:
            if should_deny:
                with pytest.raises(AuthorizationError, match="forbidden cumulative composition"):
                    call()
                return
            call()
            return
        call()
    pytest.fail("sequence was not exercised")


def test_cross_task_authorization_contamination_denies():
    store1, task1 = governed_task()
    private, key_id, auth1 = signed_auth(task1)
    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    from nova.identity import TrustedAuthorizerKey
    ledger = SQLiteAuthorizationLedger(store1._db)
    ledger.record(auth1)
    identity = SQLiteIdentityGate(store1._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth1.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    _, task2 = governed_task()
    with pytest.raises(AuthorizationError, match="task binding mismatch"):
        GovernedSQLiteExecutionAuthority(store1, ledger, identity).identify_operation(
            task_id=task2.task_id, idempotency_key="cross-task", action="write",
            scope=task2.objective, specification={"path": "x"}, now=NOW,
            authorization=auth1, tool=TOOL)


def test_cross_authorization_contamination_is_rejected_after_operation_binding():
    store, task = governed_task()
    _, boundary, _, auth1 = governed_execution(store, task, authorization_id="auth-one")
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="bound-op",
        action="write", scope=task.objective, specification={"path": "x"},
        now=NOW, authorization=auth1, tool=TOOL)
    _, _, auth2 = signed_auth(task, authorization_id="auth-two")
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    with pytest.raises((AuthorizationError, ValidationError)):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1",
            now=NOW, authorization=auth2, tool=TOOL)


def test_revocation_mid_flight_blocks_attempt_creation():
    store, task = governed_task()
    _, boundary, ledger, auth = governed_execution(store, task)
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="revocation-flight",
        action="write", scope=task.objective, specification={"path": "x"},
        now=NOW, authorization=auth, tool=TOOL)
    ledger.revoke(auth.authorization_id, now=NOW + timedelta(seconds=1))
    with pytest.raises(AuthorizationError, match="revoked"):
        boundary.create_attempt(operation_id=operation.operation_id, worker_id="worker-1",
            now=NOW + timedelta(seconds=2))


def test_old_authorization_cannot_reenter_after_revocation():
    store, task = governed_task()
    _, boundary, ledger, auth = governed_execution(store, task)
    ledger.revoke(auth.authorization_id, now=NOW + timedelta(seconds=1))
    with pytest.raises(AuthorizationError, match="revoked"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="revoked-replay",
            action="write", scope=task.objective, specification={"path": "x"},
            now=NOW + timedelta(seconds=2), authorization=auth, tool=TOOL)


def test_resulting_state_substitution_cannot_complete():
    from tests.test_verification import _gate, _proof
    gate, private = _gate()
    proof = _proof(private)
    forged = type(proof)(**{**proof.__dict__, "resulting_state_hash": "forged"})
    with pytest.raises(VerificationError):
        gate.verify(forged, now=NOW)


def test_direct_composition_insert_is_blocked_by_authority_trigger():
    store, task, ledger, auth, boundary = _composition_setup()
    with pytest.raises(sqlite3.IntegrityError, match="authority path"):
        store._db.execute(
            "INSERT INTO governed_composition_entries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (auth.authorization_id, auth.integrity_hash, task.task_id, task.policy_version,
             1, "forged-operation", "forged-hash", TOOL, "safe",
             store._durable_mac(b"composition-genesis"), "forged-entry"))


def test_tampered_composition_history_fails_closed():
    store, task, ledger, auth, boundary = _composition_setup()
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="tamper-seed",
        action="write", scope=task.objective, specification={"effect": "read_secret"},
        now=NOW, authorization=auth, tool=TOOL)
    store._db.execute("DROP TRIGGER governed_composition_no_update")
    store._db.execute("UPDATE governed_composition_entries SET effect='transfer_secret' WHERE operation_id=?",
                      (operation.operation_id,))
    with pytest.raises(AuthorizationError, match="integrity check failed"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="tamper-followup",
            action="write", scope=task.objective, specification={"effect": "stage_secret"},
            now=NOW, authorization=auth, tool=TOOL)


def test_malformed_signed_composition_contract_fails_closed():
    store, task = governed_task()
    private, key_id, auth = signed_auth(task, authorization_id="malformed-contract",
        limits_extra={"composition_allowed_effects": ["safe"], "tool_effects": {TOOL: None}})
    from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
    from nova.governed_execution import GovernedSQLiteExecutionAuthority
    from nova.identity import TrustedAuthorizerKey
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    with pytest.raises(AuthorizationError, match="tool has no signed effect contract"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="malformed-contract",
            action="write", scope=task.objective, specification={"effect": "safe"},
            now=NOW, authorization=auth, tool=TOOL)


def test_idempotency_replay_with_changed_semantics_denies():
    store, task = governed_task()
    _, boundary, _, auth = governed_execution(store, task)
    boundary.identify_operation(task_id=task.task_id, idempotency_key="replay",
        action="write", scope=task.objective, specification={"path": "a"},
        now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(ValidationError, match="idempotency key reused"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="replay",
            action="write", scope=task.objective, specification={"path": "b"},
            now=NOW, authorization=auth, tool=TOOL)


def test_recovery_remains_unknown_and_cannot_upgrade_without_authority():
    store, task = governed_task()
    _, boundary, _, auth = governed_execution(store, task)
    operation = boundary.identify_operation(task_id=task.task_id, idempotency_key="recovery-gate",
        action="write", scope=task.objective, specification={"path": "x"},
        now=NOW, authorization=auth, tool=TOOL)
    attempt = boundary.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
        authorization=auth, tool=TOOL)
    boundary.record_outcome(attempt_id=attempt.attempt_id, worker_id="worker-1", fence=attempt.fence,
        state=AttemptState.UNKNOWN, now=NOW + timedelta(seconds=1), error_detail="unconfirmed",
        authorization=auth, tool=TOOL)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=store.read_task(task.task_id).revision,
            target=State.COMPLETED, now=NOW + timedelta(seconds=2), verification="VERIFIED")

"""Gate-2 adversarial tests for the governed execution boundary."""

import sqlite3
import threading
from datetime import timedelta

import pytest

from nova.authority import State, ValidationError
from nova.execution import AttemptState, SQLiteExecutionAuthority
from nova.governance import AuthorizationError, AuthorizationRecord
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore
from tests.governed_fixtures import NOW, signed_auth

TOOL = "filesystem.write"


def _signed_setup(task, authorization_id="auth-1", agent_id="worker-1", limits=None):
    private, key_id, auth = signed_auth(task, authorization_id=authorization_id, agent_id=agent_id,
                                       max_operations=(limits or {"max_operations": 2})["max_operations"])
    return private, key_id, auth


def _register(identity, private, key_id, principal):
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=principal, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))


def setup():
    store = SQLiteAuthorityStore()
    task = store.create_task(objective="execute:demo", authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    private, key_id, auth = _signed_setup(task)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    _register(identity, private, key_id, auth.authorizer)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    return store, task, ledger, auth, GovernedSQLiteExecutionAuthority(store, ledger, identity)


def test_direct_legacy_constructor_is_fail_closed():
    store = SQLiteAuthorityStore()
    with pytest.raises(ValidationError, match="internal implementation"):
        SQLiteExecutionAuthority(store)


def test_authorized_operation_and_claim_are_bound():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(task_id=task.task_id, idempotency_key="k1", action="write", scope=task.objective,
                                     specification={"path": "a"}, now=NOW, authorization=auth, tool=TOOL)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)
    claimed = boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                             authorization=auth, tool=TOOL)
    assert claimed.state is AttemptState.CLAIMED


def test_attempt_creation_revalidates_live_authorization():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(task_id=task.task_id, idempotency_key="revalidate", action="write", scope=task.objective,
                                     specification={"path": "a"}, now=NOW, authorization=auth, tool=TOOL)
    ledger.revoke(auth.authorization_id, now=NOW)
    with pytest.raises(AuthorizationError):
        boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)
    assert store._db.execute("SELECT COUNT(*) FROM execution_attempts WHERE operation_id=?", (op.operation_id,)).fetchone()[0] == 0


def test_mismatched_authorization_cannot_claim_bound_attempt():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(task_id=task.task_id, idempotency_key="k1", action="write", scope=task.objective,
                                     specification={"path": "a"}, now=NOW, authorization=auth, tool=TOOL)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)
    private, key_id, wrong = _signed_setup(task, authorization_id="wrong")
    ledger.record(wrong)
    _register(boundary._identity, private, key_id, wrong.authorizer)
    with pytest.raises(ValidationError, match="authorization id does not match"):
        boundary.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW, authorization=wrong, tool=TOOL)


def test_wrong_agent_tool_action_scope_expiry_and_revocation_are_denied():
    store, task, ledger, auth, boundary = setup()
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="wrong-tool", action="write", scope=task.objective,
                                    specification={}, now=NOW, authorization=auth, tool="shell.exec")
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="wrong-action", action="delete", scope=task.objective,
                                    specification={}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="wrong-scope", action="write", scope="execute:other",
                                    specification={}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="expired", action="write", scope=task.objective,
                                    specification={}, now=NOW + timedelta(minutes=11), authorization=auth, tool=TOOL)
    ledger.revoke(auth.authorization_id, now=NOW)
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="revoked", action="write", scope=task.objective,
                                    specification={}, now=NOW, authorization=auth, tool=TOOL)


def test_tampered_authorization_is_rejected_before_operation_binding():
    store, task, ledger, auth, boundary = setup()
    forged = AuthorizationRecord(authorization_id=auth.authorization_id, authorizer=auth.authorizer, agent_id=auth.agent_id,
        task_id=auth.task_id, objective=auth.objective, action=auth.action, scope=auth.scope, allowed_tools=auth.allowed_tools,
        limits=auth.limits, policy_version=auth.policy_version, issued_at=auth.issued_at, expires_at=auth.expires_at,
        provenance="forged", proof=auth.proof, integrity_hash=auth.integrity_hash)
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="forged", action="write", scope=task.objective,
                                    specification={}, now=NOW, authorization=forged, tool=TOOL)


def test_immutable_operation_and_attempt_bindings():
    store, task, ledger, auth, boundary = setup()
    op = boundary.identify_operation(task_id=task.task_id, idempotency_key="immutable", action="write", scope=task.objective,
                                     specification={}, now=NOW, authorization=auth, tool=TOOL)
    attempt = boundary.create_attempt(operation_id=op.operation_id, worker_id="worker-1", now=NOW)
    with pytest.raises(sqlite3.IntegrityError, match="governed authorization bindings are immutable"):
        store._db.execute("UPDATE governed_execution_bindings SET tool='shell.exec' WHERE operation_id=?", (op.operation_id,))
    with pytest.raises(sqlite3.IntegrityError, match="governed attempt authorization bindings are immutable"):
        store._db.execute("DELETE FROM governed_attempt_bindings WHERE attempt_id=?", (attempt.attempt_id,))


def test_operation_limit_is_enforced():
    store, task, ledger, auth, boundary = setup()
    for key in ("one", "two"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key=key, action="write", scope=task.objective,
                                    specification={"path": key}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError, match="operation limit exceeded"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="three", action="write", scope=task.objective,
                                    specification={"path": "c"}, now=NOW, authorization=auth, tool=TOOL)


def test_operation_and_governance_binding_are_atomic_on_binding_failure():
    store, task, ledger, auth, boundary = setup()
    store._db.execute("CREATE TRIGGER fail_governed_binding_insert BEFORE INSERT ON governed_execution_bindings BEGIN SELECT RAISE(ABORT, 'injected binding failure'); END;")
    with pytest.raises(sqlite3.IntegrityError, match="injected binding failure"):
        boundary.identify_operation(task_id=task.task_id, idempotency_key="atomic-failure", action="write", scope=task.objective,
                                    specification={"path": "atomic"}, now=NOW, authorization=auth, tool=TOOL)
    assert store._db.execute("SELECT COUNT(*) FROM execution_operations WHERE task_id=?", (task.task_id,)).fetchone()[0] == 0
    assert store._db.execute("SELECT COUNT(*) FROM governed_execution_bindings WHERE authorization_id=?", (auth.authorization_id,)).fetchone()[0] == 0


def _composition_setup(*, max_operations=4, allowed_effects=("read_secret", "stage_secret", "transfer_secret"),
                       forbidden_sequences=(("read_secret", "stage_secret", "transfer_secret"),),
                       tool_effects=None, allowed_tools=(TOOL,)):
    store, task = __import__("tests.governed_fixtures", fromlist=["governed_task"]).governed_task()
    private, key_id, auth = signed_auth(
        task, authorization_id="composition-auth", max_operations=max_operations, allowed_tools=allowed_tools,
        limits_extra={
            "composition_allowed_effects": list(allowed_effects),
            "composition_forbidden_sequences": [list(seq) for seq in forbidden_sequences],
            "tool_effects": tool_effects if tool_effects is not None else {TOOL: list(allowed_effects)},
        },
    )
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    _register(identity, private, key_id, auth.authorizer)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    return store, task, ledger, auth, GovernedSQLiteExecutionAuthority(store, ledger, identity)


def test_tool_effect_contract_denies_declared_effect_not_capable_for_tool():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe", "danger"),
        tool_effects={TOOL: ["safe"]},
    )
    with pytest.raises(AuthorizationError, match="effect is not authorized for this tool"):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="tool-effect-mismatch",
            action="write", scope=task.objective,
            specification={"effect": "danger"}, now=NOW, authorization=auth, tool=TOOL
        )

def test_tool_effect_contract_cannot_grant_tool_authorization():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe_a", "safe_b"),
        tool_effects={TOOL: ["safe_a"], "other.tool": ["safe_b"]},
    )
    with pytest.raises(AuthorizationError, match="tool is not authorized"):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="undeclared-tool",
            action="write", scope=task.objective,
            specification={"effect": "safe_b"}, now=NOW, authorization=auth, tool="other.tool"
        )


def test_malformed_tool_effect_contract_fails_closed():
    for malformed in ({TOOL: []}, {TOOL: ["safe", 7]}, {TOOL: None}, {TOOL: [""]}):
        store, task, ledger, auth, boundary = _composition_setup(
            allowed_effects=("safe",), tool_effects=malformed,
        )
        with pytest.raises(AuthorizationError, match="(no signed effect contract|contract is malformed)"):
            boundary.identify_operation(
                task_id=task.task_id, idempotency_key="malformed-contract",
                action="write", scope=task.objective,
                specification={"effect": "safe"}, now=NOW, authorization=auth, tool=TOOL
            )


def test_composition_requires_signed_tool_effect_contract():
    store, task, ledger, auth, boundary = _composition_setup(
        tool_effects={},
    )
    with pytest.raises(AuthorizationError, match="tool has no signed effect contract"):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="missing-tool-contract",
            action="write", scope=task.objective,
            specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL
        )

def test_composition_is_authoritative_at_consequential_boundary():
    store, task, ledger, auth, boundary = _composition_setup()
    boundary.identify_operation(
        task_id=task.task_id, idempotency_key="read", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    boundary.identify_operation(
        task_id=task.task_id, idempotency_key="stage", action="write", scope=task.objective,
        specification={"effect": "stage_secret"}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError, match="forbidden cumulative composition"):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="transfer", action="write", scope=task.objective,
            specification={"effect": "transfer_secret"}, now=NOW, authorization=auth, tool=TOOL)
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_composition_entries WHERE authorization_id=?",
        (auth.authorization_id,),
    ).fetchone()[0] == 2
    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_operations WHERE task_id=?",
        (task.task_id,),
    ).fetchone()[0] == 2


def test_composition_idempotency_reuses_existing_operation_without_reapplying_effect():
    store, task, ledger, auth, boundary = _composition_setup(max_operations=1)
    first = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="same", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    retry = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="same", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    assert retry.operation_id == first.operation_id
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_composition_entries WHERE authorization_id=?",
        (auth.authorization_id,),
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM execution_operations WHERE task_id=?",
        (task.task_id,),
    ).fetchone()[0] == 1


def test_fabricated_history_cannot_bypass_durable_composition_state():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe", "forbidden_effect"),
        forbidden_sequences=(("safe", "forbidden_effect"),),
    )
    first = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="first", action="write", scope=task.objective,
        specification={"effect": "safe"}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(AuthorizationError):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="second", action="write", scope=task.objective,
            specification={"effect": "forbidden_effect"}, now=NOW, authorization=auth, tool=TOOL)
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_composition_entries WHERE operation_id=?",
        (first.operation_id,),
    ).fetchone()[0] == 1


def test_direct_composition_insert_is_denied():
    store, task, ledger, auth, boundary = _composition_setup()
    with pytest.raises(sqlite3.IntegrityError, match="governed composition entries may only be persisted by the authority path"):
        store._db.execute(
            "INSERT INTO governed_composition_entries "
            "(authorization_id,authorization_hash,task_id,policy_version,sequence_no,operation_id,operation_hash,tool,effect,previous_hash,entry_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (auth.authorization_id, auth.integrity_hash, task.task_id, auth.policy_version,
             1, "forged-operation", "0" * 64, TOOL, "safe", "0" * 64, "0" * 64),
        )


def test_composition_history_tampering_fails_closed():
    store, task, ledger, auth, boundary = _composition_setup(
        allowed_effects=("safe", "danger"),
        forbidden_sequences=(("safe", "danger"),),
    )
    first = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="first", action="write", scope=task.objective,
        specification={"effect": "safe"}, now=NOW, authorization=auth, tool=TOOL)
    row = store._db.execute(
        "SELECT sequence_no FROM governed_composition_entries WHERE operation_id=?",
        (first.operation_id,),
    ).fetchone()
    with pytest.raises(sqlite3.IntegrityError, match="governed composition entries are immutable"):
        store._db.execute(
            "UPDATE governed_composition_entries SET effect='danger' WHERE operation_id=?",
            (first.operation_id,),
        )
    assert row["sequence_no"] == 1

def test_composition_state_cannot_be_deleted_or_reordered():
    store, task, ledger, auth, boundary = _composition_setup()
    first = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="first", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    second = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="second", action="write", scope=task.objective,
        specification={"effect": "stage_secret"}, now=NOW, authorization=auth, tool=TOOL)
    with pytest.raises(sqlite3.IntegrityError, match="governed composition entries are append-only"):
        store._db.execute(
            "DELETE FROM governed_composition_entries WHERE operation_id=?", (first.operation_id,))
    with pytest.raises(sqlite3.IntegrityError, match="governed composition entries are immutable"):
        store._db.execute(
            "UPDATE governed_composition_entries SET sequence_no=1 WHERE operation_id=?",
            (second.operation_id,))


def test_missing_composition_state_fails_closed_on_idempotent_retry():
    store, task, ledger, auth, boundary = _composition_setup()
    op = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="missing-state", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    store._db.execute("DROP TRIGGER governed_composition_no_delete")
    store._db.execute(
        "DELETE FROM governed_composition_entries WHERE operation_id=?", (op.operation_id,))
    with pytest.raises(AuthorizationError, match="missing or inconsistent"):
        boundary.identify_operation(
            task_id=task.task_id, idempotency_key="missing-state", action="write", scope=task.objective,
            specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)


def test_composition_operation_replay_with_different_idempotency_key_is_not_reused():
    store, task, ledger, auth, boundary = _composition_setup(max_operations=2)
    first = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="original", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    replay = boundary.identify_operation(
        task_id=task.task_id, idempotency_key="replay", action="write", scope=task.objective,
        specification={"effect": "read_secret"}, now=NOW, authorization=auth, tool=TOOL)
    assert replay.operation_id != first.operation_id
    assert store._db.execute(
        "SELECT COUNT(*) FROM governed_composition_entries WHERE authorization_id=?",
        (auth.authorization_id,),
    ).fetchone()[0] == 2



def test_concurrent_composition_writers_serialize_without_sequence_collision(tmp_path):
    db_path = tmp_path / "composition-concurrency.db"
    seed = SQLiteAuthorityStore(str(db_path))
    task = seed.create_task(objective="execute:concurrent", authority_context="principal:demo",
                            governance_decision="ALLOW", policy_version="p1", now=NOW)
    private, key_id, auth = signed_auth(
        task, authorization_id="concurrency-auth", max_operations=2,
        limits_extra={
            "composition_allowed_effects": ["safe_a", "safe_b"],
            "composition_forbidden_sequences": [],
            "tool_effects": {TOOL: ["safe_a", "safe_b"]},
        },
    )
    ledger = SQLiteAuthorizationLedger(seed._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(seed._db)
    _register(identity, private, key_id, auth.authorizer)
    task = seed.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                     target=State.EXECUTING, now=NOW)
    seed.close()

    barrier = threading.Barrier(2)
    results = []
    errors = []
    def worker(key, effect):
        store = SQLiteAuthorityStore(str(db_path))
        ledger = SQLiteAuthorizationLedger(store._db)
        identity_gate = SQLiteIdentityGate(store._db)
        # The trusted key was registered during seeding and is shared by both
        # connections; re-registering it would itself violate the durable key
        # uniqueness invariant. Each worker creates its own SQLite connection
        # inside its own thread so SQLite's thread-affinity rule is respected.
        boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity_gate)
        try:
            barrier.wait(timeout=5)
            operation = boundary.identify_operation(
                task_id=task.task_id, idempotency_key=key, action="write",
                scope=task.objective, specification={"effect": effect},
                now=NOW, authorization=auth, tool=TOOL)
            results.append(operation.operation_id)
        except Exception as exc:
            errors.append(exc)
        finally:
            store.close()

    threads = [
        threading.Thread(target=worker, args=("concurrent-a", "safe_a")),
        threading.Thread(target=worker, args=("concurrent-b", "safe_b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert len(results) == 2
    observer = SQLiteAuthorityStore(str(db_path))
    try:
        rows = observer._db.execute(
            "SELECT sequence_no, effect FROM governed_composition_entries "
            "WHERE authorization_id=? ORDER BY sequence_no",
            (auth.authorization_id,),
        ).fetchall()
        assert [(row["sequence_no"], row["effect"]) for row in rows] in (
            [(1, "safe_a"), (2, "safe_b")],
            [(1, "safe_b"), (2, "safe_a")],
        )
        assert observer._db.execute(
            "SELECT COUNT(*) FROM execution_operations WHERE task_id=?",
            (task.task_id,),
        ).fetchone()[0] == 2
    finally:
        observer.close()

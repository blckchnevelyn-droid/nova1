from nova.authority import State, ValidationError
import pytest
from nova.execution import SQLiteExecutionAuthority, _NOVA_GOVERNED_CAPABILITY
from nova.governance import AuthorizationError
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.identity import TrustedAuthorizerKey
from tests.governed_fixtures import NOW, signed_auth, governed_task

TOOL = "filesystem.write"


def test_leaked_internal_capability_still_cannot_claim_without_durable_binding():
    store, task = governed_task()
    private, key_id, auth = signed_auth(task, authorization_id="escape-auth", agent_id="worker-1", max_operations=1)
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW, valid_until=NOW.replace(hour=13)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    GovernedSQLiteExecutionAuthority(store, ledger, identity)
    internal = SQLiteExecutionAuthority(store, ledger, _capability=_NOVA_GOVERNED_CAPABILITY)
    operation = internal.identify_operation(task_id=task.task_id, idempotency_key="escape",
                                            action="write", scope=task.objective,
                                            specification={"path": "a"}, now=NOW)
    attempt = internal.create_attempt(operation_id=operation.operation_id, worker_id="worker-1", now=NOW)
    with pytest.raises(AuthorizationError, match="governed authorization binding"):
        internal.claim(attempt_id=attempt.attempt_id, worker_id="worker-1", now=NOW,
                       authorization=auth, tool=TOOL)

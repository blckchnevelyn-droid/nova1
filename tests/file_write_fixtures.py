"""File-backed durable world for file-write pilot tests.

File-backed so that crash workers in separate processes can reopen the same
authority state. Integrity keys come from the environment, never the database.
"""
from __future__ import annotations

from datetime import timedelta

from nova.authority import State
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore
from nova.file_write_pilot import ACTION, TOOL, scope_for
from nova.file_write_sandbox import expected_digest
from tests.governed_fixtures import NOW, signed_auth

INTEGRITY_ENV = {
    "NOVA_COMPLETION_PROOF_INTEGRITY_KEY": "completion-key-material-0123456789ab",
    "NOVA_DURABLE_INTEGRITY_KEY": "durable-key-material-0123456789abcdef",
}


def install_env(monkeypatch) -> None:
    for name, value in INTEGRITY_ENV.items():
        monkeypatch.setenv(name, value)


def make_world(db_path: str, *, relative_path: str, content: bytes, authorization_id: str = "auth-fw",
               allowed_tools=(TOOL,), scope=None):
    """Create a task in EXECUTING with one signed authorization bound to path and content."""
    store = SQLiteAuthorityStore(db_path)
    scope = scope or scope_for(relative_path, content)
    # The kernel requires the operation scope to equal the task objective, so the task is
    # created for exactly this signed operation.
    task = store.create_task(objective=scope, authority_context="principal:demo",
                             governance_decision="ALLOW", policy_version="p1", now=NOW)
    private, key_id, auth = signed_auth(task, authorization_id=authorization_id, agent_id="worker-1",
                                        allowed_tools=tuple(allowed_tools), scope=scope, max_operations=10,
                                        limits_extra={"postcondition_hash": expected_digest(content)})
    ledger = SQLiteAuthorizationLedger(store._db)
    ledger.record(auth)
    identity = SQLiteIdentityGate(store._db)
    identity.register_trusted_key(TrustedAuthorizerKey(
        key_id=key_id, principal=auth.authorizer, algorithm="Ed25519",
        public_key=private.public_key().public_bytes_raw(),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=2)))
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.EXECUTING, now=NOW)
    boundary = GovernedSQLiteExecutionAuthority(store, ledger, identity)
    return {"store": store, "task": task, "auth": auth, "ledger": ledger,
            "identity": identity, "boundary": boundary, "action": ACTION}

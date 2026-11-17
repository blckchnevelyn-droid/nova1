"""Adversarial boundary tests for durable governed execution dependencies."""
from types import SimpleNamespace

import pytest

from nova.authority import ValidationError
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.governance import AuthorizationLedger
from nova.identity import IdentityGate


def test_governed_execution_rejects_in_memory_authorization_ledger():
    with pytest.raises(ValidationError, match="durable authorization ledger"):
        GovernedSQLiteExecutionAuthority(
            object(),
            AuthorizationLedger(),
            object(),
        )


def test_governed_execution_rejects_in_memory_identity_gate():
    durable_ledger = SimpleNamespace(durable=True)
    with pytest.raises(ValidationError, match="durable identity gate"):
        GovernedSQLiteExecutionAuthority(
            object(),
            durable_ledger,
            IdentityGate(),
        )

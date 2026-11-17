"""Independent completion for the file-write pilot: adversarial and happy-path tests."""
import os
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import State, ValidationError
from nova.execution import AttemptState
from nova.file_write_completion import IndependentFileVerifier, complete_task
from nova.file_write_pilot import FileWritePilot
from nova.file_write_sandbox import SandboxError, SandboxRoot
from nova.verification import CompletionProof, canonical_completion
from tests.file_write_fixtures import install_env, make_world
from tests.governed_fixtures import NOW
import base64

REL = "out/report.txt"
CONTENT = b"completion bytes\n"


@pytest.fixture
def world(tmp_path, monkeypatch):
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    w = make_world(str(tmp_path / "nova.db"), relative_path=REL, content=CONTENT)
    root = SandboxRoot(str(sandbox))
    pilot = FileWritePilot(w["boundary"], root, store=w["store"])
    attempt = pilot.submit(task_id=w["task"].task_id, idempotency_key="k", relative_path=REL, content=CONTENT,
                           authorization=w["auth"], worker_id="worker-1", now=NOW)
    assert attempt.state is AttemptState.SUCCEEDED
    key = Ed25519PrivateKey.generate()
    verifier = IndependentFileVerifier(verifier_id="verifier-1", private_key=key, sandbox=root,
                                       store=w["store"], valid_from=NOW - timedelta(minutes=1),
                                       valid_until=NOW + timedelta(hours=1))
    return {**w, "sandbox": sandbox, "root": root, "pilot": pilot, "verifier": verifier, "key": key}


def completed(w):
    return complete_task(store=w["store"], boundary=w["boundary"], verifier=w["verifier"],
                         task_id=w["task"].task_id, now=NOW)


def proof_count(w):
    return w["store"]._db.execute("SELECT COUNT(*) FROM completion_proofs").fetchone()[0]


def test_independent_verification_completes_the_task(world):
    done = completed(world)
    assert done.state is State.COMPLETED
    assert done.verification == "VERIFIED"
    assert proof_count(world) == 1


def test_completion_is_idempotent_and_does_not_consume_a_second_proof(world):
    completed(world)
    again = completed(world)
    assert again.state is State.COMPLETED
    assert proof_count(world) == 1


def test_proof_signed_by_an_unregistered_key_is_refused(world):
    """A proof minted with a key the trusted gate does not hold must fail at the trusted gate."""
    store = world["store"]
    attempt = store._db.execute(
        "SELECT attempt_id, operation_id, evidence_hash FROM execution_attempts WHERE task_id=?",
        (world["task"].task_id,)).fetchone()
    expected = store._db.execute(
        "SELECT canonical_operation FROM execution_operations WHERE operation_id=?",
        (attempt["operation_id"],)).fetchone()[0]
    expected = __import__("json").loads(expected)["specification"]["sha256"]
    forger = IndependentFileVerifier(verifier_id="verifier-1", private_key=Ed25519PrivateKey.generate(),
                                     sandbox=world["root"], store=store,
                                     valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(hours=1))
    task = store.read_task(world["task"].task_id)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.OBSERVING, now=NOW)
    task = store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                      target=State.VERIFYING, now=NOW)
    proof = forger.prove(task=task, operation_id=attempt["operation_id"], attempt_id=attempt["attempt_id"],
                         evidence_hash=attempt["evidence_hash"], expected_postcondition_hash=expected,
                         resulting_state_hash=expected, now=NOW)
    with pytest.raises(ValidationError):
        store.authorize_transition(task_id=task.task_id, expected_revision=task.revision, target=State.COMPLETED,
                                   now=NOW + timedelta(seconds=1), completion_proof=proof,
                                   verification_gate=world["verifier"].gate)
    assert proof_count(world) == 0


def test_target_changed_after_success_blocks_completion(world):
    (world["sandbox"] / REL).write_bytes(b"changed after the attempt recorded success")
    with pytest.raises(ValidationError, match="resulting-state"):
        completed(world)
    assert proof_count(world) == 0


def test_completion_without_a_successful_attempt_is_refused(world):
    store = world["store"]
    fresh = make_world(str(world["sandbox"].parent / "empty.db"),
                       relative_path="out/never.txt", content=b"never written\n", authorization_id="auth-empty")
    verifier = IndependentFileVerifier(verifier_id="verifier-1", private_key=world["key"], sandbox=world["root"],
                                       store=fresh["store"], valid_from=NOW - timedelta(minutes=1),
                                       valid_until=NOW + timedelta(hours=1))
    with pytest.raises(ValidationError, match="no successful attempt"):
        complete_task(store=fresh["store"], boundary=fresh["boundary"], verifier=verifier,
                      task_id=fresh["task"].task_id, now=NOW)


def test_verifier_key_outside_its_validity_window_is_refused(world):
    late = NOW + timedelta(hours=2)
    with pytest.raises(ValidationError):
        complete_task(store=world["store"], boundary=world["boundary"], verifier=world["verifier"],
                      task_id=world["task"].task_id, now=late)


def test_proof_with_a_wrong_postcondition_is_refused(world):
    """A proof whose expected postcondition differs from the durable operation is refused."""
    original = world["verifier"].prove

    def wrong_postcondition(**kwargs):
        kwargs["expected_postcondition_hash"] = "0" * 64
        kwargs["resulting_state_hash"] = "0" * 64
        return original(**kwargs)

    world["verifier"].prove = wrong_postcondition
    with pytest.raises(ValidationError):
        completed(world)
    assert proof_count(world) == 0


def test_executor_cannot_mint_its_own_completion_proof(world):
    """The executor holds no verifier key. A proof it signs with its authorizer key must fail."""
    auth = world["auth"]
    attempt = world["store"]._db.execute(
        "SELECT attempt_id, operation_id, evidence_hash FROM execution_attempts WHERE task_id=?",
        (world["task"].task_id,)).fetchone()
    task = world["store"].read_task(world["task"].task_id)
    task = world["store"].authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                               target=State.OBSERVING, now=NOW)
    task = world["store"].authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                               target=State.VERIFYING, now=NOW)
    values = dict(task_id=task.task_id, expected_revision=task.revision, operation_id=attempt["operation_id"],
                  attempt_id=attempt["attempt_id"], evidence_hash=attempt["evidence_hash"],
                  expected_postcondition_hash="x", resulting_state_hash="x", decision="VERIFIED",
                  verifier_id="verifier-1", issued_at=NOW)
    # The executor signs with a key it controls. The gate holds only verifier-1's registered key.
    signature = base64.b64encode(Ed25519PrivateKey.generate().sign(canonical_completion(**values))).decode()
    forged = CompletionProof(**values, signature=signature)
    with pytest.raises(ValidationError):
        world["store"].authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                            target=State.COMPLETED, now=NOW + timedelta(seconds=1),
                                            completion_proof=forged, verification_gate=world["verifier"].gate)
    assert proof_count(world) == 0


# --------------------------------------------------------------- sandbox guards


def test_publish_without_the_pilot_capability_is_refused(world):
    with pytest.raises(SandboxError, match="reserved for the governed file-write pilot"):
        world["root"].publish("out/direct.txt", b"direct", operation_id="00000000-0000-4000-8000-000000000001")
    assert not (world["sandbox"] / "out" / "direct.txt").exists()


def test_directory_swapped_for_symlink_after_open_does_not_redirect_the_write(tmp_path, monkeypatch):
    """TOCTOU: the descriptor stays bound to the directory opened first, so the link lands there."""
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    w = make_world(str(tmp_path / "nova.db"), relative_path=REL, content=CONTENT)
    pilot = FileWritePilot(w["boundary"], SandboxRoot(str(sandbox)), store=w["store"])

    def swap(point):
        if point == "before_publish":
            os.rename(sandbox / "out", sandbox / "out_real")
            os.symlink(outside, sandbox / "out")

    attempt = pilot.submit(task_id=w["task"].task_id, idempotency_key="swap", relative_path=REL,
                           content=CONTENT, authorization=w["auth"], worker_id="worker-1", now=NOW, hook=swap)
    assert os.listdir(outside) == []                                   # nothing escaped the sandbox
    assert (sandbox / "out_real" / "report.txt").read_bytes() == CONTENT  # written where it was opened
    assert attempt.state is AttemptState.UNKNOWN                       # effect exists, path unobservable: escalate

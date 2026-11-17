"""Governed file-write pilot: in-process adversarial and happy-path tests."""
import os

import pytest

from nova.authority import ConflictError
from nova.execution import AttemptState
from nova.file_write_pilot import EvidenceTampered, FileWritePilot, scope_for
from nova.file_write_sandbox import SandboxError, SandboxRoot
from nova.governance import AuthorizationError
from tests.file_write_fixtures import install_env, make_world
from tests.governed_fixtures import NOW

WORKER = "worker-1"
REL = "out/report.txt"
CONTENT = b"deterministic pilot bytes\n"


@pytest.fixture
def env(tmp_path, monkeypatch):
    install_env(monkeypatch)
    sandbox = tmp_path / "sandbox"
    (sandbox / "out").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    return tmp_path, sandbox, outside


def build(tmp_path, sandbox, *, rel=REL, content=CONTENT, key="key-1", **world_kwargs):
    world = make_world(str(tmp_path / "nova.db"), relative_path=rel, content=content, **world_kwargs)
    root = SandboxRoot(str(sandbox))
    pilot = FileWritePilot(world["boundary"], root, store=world["store"])
    kwargs = dict(task_id=world["task"].task_id, idempotency_key=key, relative_path=rel,
                  content=content, authorization=world["auth"], worker_id=WORKER, now=NOW)
    return world, pilot, kwargs


def rows(world, sql, *args):
    return world["store"]._db.execute(sql, args).fetchall()


def test_happy_path_writes_exact_bytes_and_records_verified_evidence(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    attempt = pilot.submit(**kw)
    assert attempt.state is AttemptState.SUCCEEDED
    assert (sandbox / REL).read_bytes() == CONTENT
    assert sorted(os.listdir(sandbox / "out")) == ["report.txt"]  # no staging residue
    assert pilot.verify_evidence(kw["task_id"]) == 1
    assert "target bytes verified" in attempt.result_evidence


@pytest.mark.parametrize("bad", ["", "/abs.txt", "../x.txt", "out/../x.txt", "out//x.txt",
                                 "./x.txt", "bad\x00.txt", "out\\x.txt", ".nova-stage-x", "out/"])
def test_malformed_paths_fail_before_any_authority_or_file_effect(env, bad):
    tmp_path, sandbox, outside = env
    world, pilot, kw = build(tmp_path, sandbox)
    kw["relative_path"] = bad
    with pytest.raises(SandboxError):
        pilot.submit(**kw)
    assert rows(world, "SELECT COUNT(*) FROM execution_operations")[0][0] == 0
    assert rows(world, "SELECT COUNT(*) FROM execution_attempts")[0][0] == 0
    assert os.listdir(outside) == [] and os.listdir(sandbox / "out") == []


def test_signed_scope_binds_exact_path_so_grant_cannot_be_reused_elsewhere(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    kw["relative_path"] = "out/other.txt"  # same signed grant, different path
    with pytest.raises(AuthorizationError):
        pilot.submit(**kw)
    assert not (sandbox / "out" / "other.txt").exists()
    assert rows(world, "SELECT COUNT(*) FROM execution_attempts")[0][0] == 0


def test_signed_scope_binds_exact_bytes(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    kw["content"] = b"different bytes\n"  # same path, different content
    with pytest.raises(AuthorizationError):
        pilot.submit(**kw)
    assert not (sandbox / REL).exists()


def test_unauthorized_tool_is_denied_before_effect(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox, allowed_tools=("other.tool",))
    with pytest.raises(AuthorizationError):
        pilot.submit(**kw)
    assert not (sandbox / REL).exists()


def test_replay_after_success_is_refused_and_does_not_touch_the_file(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    pilot.submit(**kw)
    inode_before = os.stat(sandbox / REL).st_ino
    with pytest.raises(ConflictError):
        pilot.submit(**kw)
    assert os.stat(sandbox / REL).st_ino == inode_before
    assert (sandbox / REL).read_bytes() == CONTENT


def test_preexisting_target_is_never_overwritten(env):
    tmp_path, sandbox, _ = env
    (sandbox / REL).write_bytes(b"OTHER OWNER DATA")
    world, pilot, kw = build(tmp_path, sandbox)
    attempt = pilot.submit(**kw)
    assert attempt.state is AttemptState.FAILED
    assert (sandbox / REL).read_bytes() == b"OTHER OWNER DATA"
    assert pilot.verify_evidence(kw["task_id"]) == 1


def test_symlinked_parent_directory_cannot_escape_the_sandbox(env):
    tmp_path, sandbox, outside = env
    os.rmdir(sandbox / "out")
    os.symlink(outside, sandbox / "out")
    world, pilot, kw = build(tmp_path, sandbox)
    attempt = pilot.submit(**kw)
    assert attempt.state is AttemptState.FAILED
    assert os.listdir(outside) == []


def test_symlinked_leaf_is_not_followed_or_replaced(env):
    tmp_path, sandbox, outside = env
    victim = outside / "victim.txt"
    victim.write_bytes(b"victim")
    os.symlink(victim, sandbox / REL)
    world, pilot, kw = build(tmp_path, sandbox)
    attempt = pilot.submit(**kw)
    assert attempt.state is AttemptState.FAILED
    assert victim.read_bytes() == b"victim"
    assert os.path.islink(sandbox / REL)


def test_tampered_evidence_is_detected_without_the_integrity_key(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    pilot.submit(**kw)
    db = world["store"]._db
    db.execute("DROP TRIGGER execution_terminal_attempt_no_update")  # database administrator, no key
    db.execute("UPDATE execution_attempts SET result_evidence = REPLACE(result_evidence, 'SUCCEEDED', 'FAILED')")
    with pytest.raises(EvidenceTampered, match="integrity"):
        pilot.verify_evidence(kw["task_id"])


def test_target_changed_after_success_is_detected_by_verification(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    pilot.submit(**kw)
    (sandbox / REL).write_bytes(b"changed afterwards")
    with pytest.raises(EvidenceTampered, match="target bytes do not match"):
        pilot.verify_evidence(kw["task_id"])


def test_rewritten_audit_event_breaks_the_execution_audit_chain(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    pilot.submit(**kw)
    db = world["store"]._db
    db.execute("DROP TRIGGER execution_audit_no_update")
    db.execute("UPDATE execution_audit_events SET detail = 'nothing happened' WHERE event_type = 'ATTEMPT_SUCCEEDED'")
    with pytest.raises(EvidenceTampered, match="execution audit"):
        pilot.verify_evidence(kw["task_id"])


def test_deleted_audit_event_breaks_the_chain(env):
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    pilot.submit(**kw)
    db = world["store"]._db
    db.execute("DROP TRIGGER execution_audit_no_delete")
    db.execute("DELETE FROM execution_audit_events WHERE event_type = 'ATTEMPT_CLAIMED'")
    with pytest.raises(EvidenceTampered, match="execution audit"):
        pilot.verify_evidence(kw["task_id"])


def test_observe_refuses_symlink_leaf_directly(env):
    """Isolates the O_NOFOLLOW guard: reading through a symlink must be refused, not followed."""
    from nova.file_write_sandbox import SandboxConflict
    tmp_path, sandbox, outside = env
    victim = outside / "victim.txt"
    victim.write_bytes(CONTENT)  # matching bytes: following the link would look like success
    os.symlink(victim, sandbox / "leaf.txt")
    with pytest.raises(SandboxConflict):
        SandboxRoot(str(sandbox)).observe(("leaf.txt",))


def test_observe_refuses_symlinked_parent_directly(env):
    tmp_path, sandbox, outside = env
    os.rmdir(sandbox / "out")
    os.symlink(outside, sandbox / "out")
    (outside / "report.txt").write_bytes(CONTENT)
    with pytest.raises(SandboxError):
        SandboxRoot(str(sandbox)).observe(("out", "report.txt"))


def test_losing_a_publish_race_to_identical_bytes_is_not_reported_as_success(env, monkeypatch):
    """Deterministic replay of the race: the target appears between observation and publication.

    Another process wrote identical bytes first. This attempt did not create the target,
    so it must not report SUCCEEDED for it.
    """
    from nova.file_write_sandbox import SandboxRoot as Root
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    real_publish = Root.publish

    def racing_publish(self, relative_path, content, *, operation_id, hook=None, capability=None):
        (sandbox / REL).write_bytes(content)  # the other writer wins the race
        return real_publish(self, relative_path, content, operation_id=operation_id, hook=hook,
                            capability=capability)

    monkeypatch.setattr(Root, "publish", racing_publish)
    attempt = pilot.submit(**kw)
    assert attempt.state is AttemptState.FAILED
    assert (sandbox / REL).read_bytes() == CONTENT


def test_second_attempt_refused_while_an_unclaimed_attempt_exists(env):
    """Kernel TOCTOU: a NOT_EXECUTED attempt must block a parallel second attempt for the same operation."""
    tmp_path, sandbox, _ = env
    world, pilot, kw = build(tmp_path, sandbox)
    operation, _ = pilot._identify(task_id=kw["task_id"], idempotency_key=kw["idempotency_key"],
                                   relative_path=REL, content=CONTENT, authorization=world["auth"], now=NOW)
    world["boundary"].create_attempt(operation_id=operation.operation_id, worker_id=WORKER, now=NOW)
    with pytest.raises(ConflictError):
        world["boundary"].create_attempt(operation_id=operation.operation_id, worker_id=WORKER, now=NOW)
    assert len(world["boundary"].attempts_for_operation(operation.operation_id)) == 1

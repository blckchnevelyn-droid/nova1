"""Draft host: end-to-end flow, human approval, kill switch, and refusal paths."""
import json
from pathlib import Path

import pytest

from host.draft_host import (DraftHost, KillSwitchEngaged, anthropic_drafter, stub_drafter, validate_draft)
from nova.authority import ValidationError


@pytest.fixture
def state(tmp_path, monkeypatch):
    # Setup writes real integrity keys into the state directory. Restore the environment afterwards.
    for name in ("NOVA_DURABLE_INTEGRITY_KEY", "NOVA_COMPLETION_PROOF_INTEGRITY_KEY"):
        monkeypatch.setenv(name, "placeholder-overwritten-by-setup-0123456789")
    directory = tmp_path / "state"
    DraftHost.setup(directory)
    return directory


def host(state):
    return DraftHost(state)


def written(state, path="drafts/draft-" ):
    return sorted(p.name for p in (state / "sandbox" / "drafts").iterdir())


def test_full_flow_propose_approve_run_verify_writes_only_after_human_approval(state):
    h = host(state)
    item = h.propose(brief="Launch note for the drafts folder", drafter=stub_drafter)
    assert written(state) == []                                   # proposing writes nothing
    shown = h.show(item["id"])
    assert shown["content"].startswith("# Draft")
    h.approve(item["id"], confirm=True)
    assert [r["status"] for r in h.run()] == ["written"]
    assert (state / "sandbox" / item["path"]).read_text(encoding="utf-8") == shown["content"]
    # Execution alone does not complete the task. Completion needs the independent verifier.
    assert h.store.read_task(item["task_id"]).state.value != "COMPLETED"
    verified = h.verify()
    assert verified[0]["task_state"] == "COMPLETED" and verified[0]["verification"] == "VERIFIED"
    assert h.verify() == []                                       # verification is not repeated


def test_run_needs_no_verifier_key(state):
    h = host(state)
    item = h.propose(brief="no verifier key needed to run", drafter=stub_drafter)
    h.approve(item["id"], confirm=True)
    (state / "keys" / "verifier.key").unlink()
    assert [r["status"] for r in h.run()] == ["written"]


def test_unregistered_approver_key_cannot_approve(state, tmp_path):
    h = host(state)
    item = h.propose(brief="forged approval attempt", drafter=stub_drafter)
    rogue = tmp_path / "rogue.key"
    from host.draft_host import _new_key
    _new_key(rogue)
    with pytest.raises(ValidationError, match="not registered"):
        h.approve(item["id"], confirm=True, approver_key=rogue)
    assert h.run() == []
    assert written(state) == []


def test_unregistered_verifier_key_cannot_complete(state, tmp_path):
    h = host(state)
    item = h.propose(brief="forged completion attempt", drafter=stub_drafter)
    h.approve(item["id"], confirm=True)
    h.run()
    rogue = tmp_path / "rogue-verifier.key"
    from host.draft_host import _new_key
    _new_key(rogue)
    with pytest.raises(ValidationError, match="not registered"):
        h.verify(verifier_key=rogue)
    assert h.store.read_task(item["task_id"]).state.value != "COMPLETED"


def test_approval_requires_explicit_confirmation(state):
    h = host(state)
    item = h.propose(brief="needs review", drafter=stub_drafter)
    with pytest.raises(ValidationError, match="--confirm"):
        h.approve(item["id"], confirm=False)
    assert h.run() == []
    assert written(state) == []


def test_unapproved_items_are_never_executed(state):
    h = host(state)
    h.propose(brief="pending only", drafter=stub_drafter)
    assert h.run() == []
    assert written(state) == []


def test_rejected_items_are_never_written(state):
    h = host(state)
    item = h.propose(brief="reject me", drafter=stub_drafter)
    h.reject(item["id"])
    assert h.run() == []
    assert written(state) == []
    assert h.status()["rejected"] == [item["id"]]


def test_kill_switch_stops_run_before_any_effect(state):
    h = host(state)
    item = h.propose(brief="blocked by kill switch", drafter=stub_drafter)
    h.approve(item["id"], confirm=True)
    h.kill()
    with pytest.raises(KillSwitchEngaged):
        h.run()
    assert written(state) == []
    assert h.status()["killed"] is True
    h.resume()
    assert [r["status"] for r in h.run()] == ["written"]


def test_content_changed_after_approval_is_refused(state):
    h = host(state)
    item = h.propose(brief="tamper target", drafter=stub_drafter)
    h.approve(item["id"], confirm=True)
    approved = state / "review" / "approved" / f"{item['id']}.json"
    doc = json.loads(approved.read_text(encoding="utf-8"))
    doc["content"] = "# Something else entirely\n"
    approved.write_text(json.dumps(doc), encoding="utf-8")
    results = h.run()
    assert results[0]["status"] == "refused"
    assert written(state) == []


def test_running_twice_does_not_write_twice(state):
    h = host(state)
    item = h.propose(brief="once only", drafter=stub_drafter)
    h.approve(item["id"], confirm=True)
    assert [r["status"] for r in h.run()] == ["written"]
    assert h.run() == []
    assert len(written(state)) == 1


@pytest.mark.parametrize("path", ["../escape.md", "drafts/../../x.md", "other/x.md", "/abs/x.md",
                                  "drafts/x.exe", "drafts/has space.md", "drafts/.hidden.md", ""])
def test_host_policy_rejects_paths_outside_drafts(state, path):
    h = host(state)
    with pytest.raises(ValidationError):
        h.propose(brief="x", drafter=lambda b: (path, "content"))
    assert h.status()["pending"] == []


def test_oversized_and_empty_drafts_are_rejected():
    with pytest.raises(ValidationError):
        validate_draft("drafts/a.md", "")
    with pytest.raises(ValidationError):
        validate_draft("drafts/a.md", "x" * (64 * 1024 + 1))


def test_uninitialized_state_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not initialized"):
        DraftHost(tmp_path / "missing")


def test_model_adapter_builds_the_expected_request_and_parses_the_reply():
    seen = {}

    class FakeResponse:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_opener(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = {k.lower(): v for k, v in request.header_items()}
        seen["body"] = json.loads(request.data.decode("utf-8"))
        reply = {"content": [{"type": "text", "text": json.dumps({"path": "drafts/a.md", "content": "# A\n"})}]}
        return FakeResponse(json.dumps(reply).encode("utf-8"))

    draft = anthropic_drafter("test-key", opener=fake_opener)
    assert draft("say hello") == ("drafts/a.md", "# A\n")
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == "test-key"
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert "say hello" in seen["body"]["messages"][0]["content"]


def test_model_reply_that_is_not_json_is_refused():
    class FakeResponse:
        def read(self):
            return json.dumps({"content": [{"type": "text", "text": "not json"}]}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    draft = anthropic_drafter("k", opener=lambda req, timeout: FakeResponse())
    with pytest.raises(json.JSONDecodeError):
        draft("anything")


def test_approver_key_outside_state_lets_only_the_approver_sign(tmp_path, monkeypatch):
    """The agent's side (state directory) holds no approver key, so it cannot approve. Running still works."""
    for name in ("NOVA_DURABLE_INTEGRITY_KEY", "NOVA_COMPLETION_PROOF_INTEGRITY_KEY"):
        monkeypatch.setenv(name, "placeholder-overwritten-by-setup-0123456789")
    state = tmp_path / "state"
    approver_key = tmp_path / "human-only" / "approver.key"
    DraftHost.setup(state, approver_key_path=approver_key)
    assert not (state / "keys" / "approver.key").exists()
    h = DraftHost(state)
    item = h.propose(brief="needs a human", drafter=stub_drafter)
    with pytest.raises(ValidationError, match="approver key not found"):
        h.approve(item["id"], confirm=True)                      # the agent side cannot sign
    h.approve(item["id"], confirm=True, approver_key=approver_key)  # the human side can
    assert [r["status"] for r in h.run()] == ["written"]           # running needs no approver key


def test_setup_refuses_to_overwrite_an_existing_approver_key(tmp_path, monkeypatch):
    for name in ("NOVA_DURABLE_INTEGRITY_KEY", "NOVA_COMPLETION_PROOF_INTEGRITY_KEY"):
        monkeypatch.setenv(name, "placeholder-overwritten-by-setup-0123456789")
    existing = tmp_path / "approver.key"
    existing.write_bytes(b"x" * 32)
    with pytest.raises(ValidationError, match="refusing to overwrite"):
        DraftHost.setup(tmp_path / "state2", approver_key_path=existing)
    assert existing.read_bytes() == b"x" * 32


def test_revoked_approver_key_cannot_approve(state):
    from datetime import datetime, timezone
    from host.draft_host import _key_id, _load_key
    from nova.durable_security import SQLiteIdentityGate
    h = host(state)
    key_id = _key_id("approver", _load_key(state / "keys" / "approver.key"))
    SQLiteIdentityGate(h.store._db).revoke_key(key_id, now=datetime.now(timezone.utc))
    item = h.propose(brief="after revocation", drafter=stub_drafter)
    with pytest.raises(ValidationError, match="not registered"):
        h.approve(item["id"], confirm=True)

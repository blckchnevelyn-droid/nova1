"""Draft host: the first real host for the Nova file-write kernel.

Each step is a separate command. All state lives in one state directory.

  setup    create keys, the integrity-key file, the sandbox, and the database
  propose  an agent drafts one file under drafts/; a review item is written; nothing is written to the sandbox
  show     print a pending item's exact bytes for human review
  approve  a human signs an authorization bound to the item's path and digest (requires --confirm)
  reject   discard a pending item
  run      execute approved items through the governed pilot, then complete them via an independent verifier
  kill     engage the kill switch; run refuses to start
  resume   disengage the kill switch
  status   list items by state

Nothing leaves the sandbox directory. Only drafts/ paths are accepted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nova.authority import ConflictError, State, ValidationError
from nova.durable_security import SQLiteAuthorizationLedger, SQLiteIdentityGate
from nova.execution import AttemptState
from nova.file_write_completion import IndependentFileVerifier, complete_task
from nova.file_write_pilot import ACTION, TOOL, FileWritePilot, scope_for
from nova.file_write_sandbox import SandboxError, SandboxRoot, expected_digest
from nova.governance import AuthorizationError, AuthorizationRecord
from nova.governed_execution import GovernedSQLiteExecutionAuthority
from nova.identity import TrustedAuthorizerKey
from nova.persistence import SQLiteAuthorityStore

WORKER = "draft-host"
APPROVER = "principal:approver"
VERIFIER = "principal:verifier"
POLICY = "draft-host-v1"
APPROVAL_TTL = timedelta(hours=1)
MAX_DRAFT_BYTES = 64 * 1024
PATH_RULE = re.compile(r"^drafts/[A-Za-z0-9_-]{1,64}\.(md|txt)$")
INTEGRITY_VARS = ("NOVA_DURABLE_INTEGRITY_KEY", "NOVA_COMPLETION_PROOF_INTEGRITY_KEY")
STATES = ("pending", "approved", "done", "rejected")


class KillSwitchEngaged(RuntimeError):
    """The kill switch is engaged; nothing was executed."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _new_key(path: Path) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    _write_secret(path, key.private_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PrivateFormat.Raw,
                                          encryption_algorithm=serialization.NoEncryption()))
    return key


def _load_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def _key_id(role: str, key: Ed25519PrivateKey) -> str:
    return f"{role}-{key.public_key().public_bytes_raw().hex()[:16]}"


def _new_external_or_default(external: Optional[Path], default: Path) -> Ed25519PrivateKey:
    if external is None:
        return _new_key(default)
    external = Path(external)
    if external.exists():
        raise ValidationError("key path already exists; refusing to overwrite it")
    external.parent.mkdir(parents=True, exist_ok=True)
    return _new_key(external)


def _atomic_json(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def validate_draft(path: str, content: str) -> bytes:
    """Host policy: only drafts/<name>.md|txt, UTF-8 text, bounded size."""
    if not PATH_RULE.match(path or ""):
        raise ValidationError("draft path must match drafts/<name>.md or drafts/<name>.txt")
    if not isinstance(content, str):
        raise ValidationError("draft content must be text")
    data = content.encode("utf-8")
    if len(data) == 0 or len(data) > MAX_DRAFT_BYTES:
        raise ValidationError("draft content must be non-empty and at most 64 KiB")
    return data


def stub_drafter(brief: str):
    """Deterministic drafter for tests and offline runs. Does not call any model."""
    slug = "draft-" + hashlib.sha256(brief.encode("utf-8")).hexdigest()[:12]
    return f"drafts/{slug}.md", f"# Draft\n\n{brief.strip()}\n"


_MODEL_PROMPT = (
    "Write one short draft document for the brief below. Respond with only a JSON object "
    'of the form {"path": "drafts/<name>.md", "content": "<markdown text>"}. No other text.\n\nBrief:\n'
)


def _parse_draft_reply(text: str):
    """Extract {"path", "content"} from a model reply.

    Models often wrap JSON in a code fence or add a sentence before it. Take the outermost
    braces, then validate the shape. Anything else is a clean refusal, not a crash.
    """
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValidationError("model reply contained no draft object")
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValidationError("model reply was not valid draft JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("path"), str) \
            or not isinstance(parsed.get("content"), str):
        raise ValidationError("model reply lacks string 'path' and 'content'")
    return parsed["path"], parsed["content"]


def anthropic_drafter(api_key: str, model: str = "claude-haiku-5-5", *, opener=urllib.request.urlopen):
    """Drafter that calls the Messages API. Built and unit-tested against a mock; not run live here."""
    def draft(brief: str):
        body = json.dumps({"model": model, "max_tokens": 1500,
                           "messages": [{"role": "user", "content": _MODEL_PROMPT + brief}]}).encode("utf-8")
        request = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body, method="POST",
            headers={"content-type": "application/json", "x-api-key": api_key,
                     "anthropic-version": "2023-06-01"})
        with opener(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        text = "".join(block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text")
        return _parse_draft_reply(text)
    return draft


GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_DEFAULT_MODEL = "llama-3.3-70b-versatile"  # check the Groq console's model list; names change


def openai_compatible_drafter(base_url: str, api_key: str, model: str, *, opener=urllib.request.urlopen):
    """Drafter for any OpenAI-compatible chat endpoint (Groq, OpenRouter, and others).

    Built and tested against a mock. Not run against the live service in this environment.
    """
    def draft(brief: str):
        body = json.dumps({"model": model, "max_tokens": 1500,
                           "messages": [{"role": "user", "content": _MODEL_PROMPT + brief}]}).encode("utf-8")
        request = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions", data=body, method="POST",
            headers={"content-type": "application/json", "authorization": f"Bearer {api_key}"})
        with opener(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return _parse_draft_reply(payload["choices"][0]["message"]["content"])
    return draft


class DraftHost:
    def __init__(self, state: Path, *, now_fn: Callable[[], datetime] = _utc_now) -> None:
        self.state = Path(state)
        self.db_path = self.state / "nova.db"
        self.keys = self.state / "keys"
        self.review = self.state / "review"
        self.kill_path = self.state / "KILL"
        self.now = now_fn
        if not self.db_path.exists():
            raise ValidationError("state directory is not initialized; run setup first")
        self._load_integrity_env()
        self.store = SQLiteAuthorityStore(str(self.db_path))
        self.ledger = SQLiteAuthorizationLedger(self.store._db)
        self.identity = SQLiteIdentityGate(self.store._db)
        self.boundary = GovernedSQLiteExecutionAuthority(self.store, self.ledger, self.identity)
        self.root = SandboxRoot(str(self.state / "sandbox"))
        self.pilot = FileWritePilot(self.boundary, self.root, store=self.store)

    # ------------------------------------------------------------------ setup

    @staticmethod
    def setup(state: Path, *, approver_key_path: Optional[Path] = None,
              verifier_key_path: Optional[Path] = None) -> None:
        """Create the state and register the trusted public keys durably.

        Keys given an external path are written outside the state directory. Only the process
        that holds a key can use it. Trust is established here, once, by writing the public
        key into the database. approve and verify refuse any key not registered this way.
        """
        state = Path(state)
        if (state / "nova.db").exists():
            raise ValidationError("state directory is already initialized")
        for sub in ("keys", "sandbox/drafts") + tuple(f"review/{s}" for s in STATES):
            (state / sub).mkdir(parents=True, exist_ok=True)
        lines = "".join(f"{name}={secrets.token_urlsafe(48)}\n" for name in INTEGRITY_VARS)
        _write_secret(state / "keys" / "integrity.env", lines.encode("ascii"))
        approver = _new_external_or_default(approver_key_path, state / "keys" / "approver.key")
        verifier = _new_external_or_default(verifier_key_path, state / "keys" / "verifier.key")
        # The database binds its audit root to the integrity key present at creation, so load
        # the freshly written keys before creating it.
        for line in lines.splitlines():
            name, value = line.split("=", 1)
            os.environ[name] = value
        store = SQLiteAuthorityStore(str(state / "nova.db"))  # creates the schema
        gate = SQLiteIdentityGate(store._db)
        now = _utc_now()
        for role, principal, key in (("approver", APPROVER, approver), ("verifier", VERIFIER, verifier)):
            gate.register_trusted_key(TrustedAuthorizerKey(
                key_id=_key_id(role, key), principal=principal, algorithm="Ed25519",
                public_key=key.public_key().public_bytes_raw(),
                valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=365)))
        # Key material is never printed or written into the repository.

    def _load_integrity_env(self) -> None:
        path = self.keys / "integrity.env"
        if not path.exists():
            raise ValidationError("integrity key file is missing; run setup first")
        for line in path.read_text(encoding="ascii").splitlines():
            if "=" in line:
                name, value = line.split("=", 1)
                if name in INTEGRITY_VARS:
                    os.environ[name] = value

    def _require_registered(self, key_id: str, principal: str) -> None:
        row = self.store._db.execute(
            "SELECT k.principal, r.revoked_at FROM durable_authorizer_keys k "
            "LEFT JOIN durable_authorizer_key_revocations r ON r.key_id = k.key_id WHERE k.key_id=?",
            (key_id,)).fetchone()
        if row is None or row[0] != principal or row[1] is not None:
            raise ValidationError(f"key is not registered as trusted for {principal}; refusing")

    # ------------------------------------------------------------------ steps

    def propose(self, *, brief: str, drafter: Callable[[str], tuple]) -> dict:
        path, content = drafter(brief)
        data = validate_draft(path, content)
        now = self.now()
        scope = scope_for(path, data)
        task = self.store.create_task(objective=scope, authority_context=APPROVER,
                                      governance_decision="ALLOW", policy_version=POLICY, now=now)
        item = {"id": uuid4().hex, "task_id": task.task_id, "brief": brief, "path": path,
                "content": content, "sha256": expected_digest(data), "scope": scope,
                "created_at": now.isoformat(), "state": "pending"}
        _atomic_json(self.review / "pending" / f"{item['id']}.json", item)
        return item

    def show(self, item_id: str) -> dict:
        return self._read_item("pending", item_id)

    def approve(self, item_id: str, *, confirm: bool, approver_key: Optional[Path] = None,
                now: Optional[datetime] = None) -> dict:
        if not confirm:
            raise ValidationError("approval requires --confirm after reviewing the exact content with `show`")
        approver_key = Path(approver_key) if approver_key else self.keys / "approver.key"
        if not approver_key.exists():
            raise ValidationError("approver key not found; approval must be signed with the approver's key")
        now = now or self.now()
        item = self._read_item("pending", item_id)
        data = validate_draft(item["path"], item["content"])
        if expected_digest(data) != item["sha256"] or scope_for(item["path"], data) != item["scope"]:
            raise ValidationError("review item is internally inconsistent; refusing to approve")
        key = _load_key(approver_key)
        key_id = _key_id("approver", key)
        self._require_registered(key_id, APPROVER)
        authorization = self._sign(item, key, key_id, now)
        self.ledger.record(authorization)
        task = self.store.read_task(item["task_id"])
        self.store.authorize_transition(task_id=task.task_id, expected_revision=task.revision,
                                        target=State.EXECUTING, now=now)
        item = dict(item, state="approved", authorization_id=authorization.authorization_id,
                    approved_at=now.isoformat())
        _atomic_json(self.review / "approved" / f"{item_id}.json", item)
        (self.review / "pending" / f"{item_id}.json").unlink()
        return item

    def reject(self, item_id: str) -> dict:
        item = self._read_item("pending", item_id)
        item = dict(item, state="rejected")
        _atomic_json(self.review / "rejected" / f"{item_id}.json", item)
        (self.review / "pending" / f"{item_id}.json").unlink()
        return item

    def run(self, *, now: Optional[datetime] = None) -> list:
        """Execute approved items through the pilot. Holds no verifier key; completion is separate."""
        self._refuse_if_killed()
        now = now or self.now()
        results = []
        for path in sorted((self.review / "approved").glob("*.json")):
            self._refuse_if_killed()  # checked between items, before every effect
            item = json.loads(path.read_text(encoding="utf-8"))
            result = self._execute(item, now)
            moved = dict(item, state=result["status"], result=result, verified=False)
            _atomic_json(self.review / "done" / path.name, moved)
            path.unlink()
            results.append(result)
        return results

    def verify(self, *, verifier_key: Optional[Path] = None, now: Optional[datetime] = None) -> list:
        """Complete written items through the independent verifier. Only a registered verifier key works."""
        now = now or self.now()
        key_path = Path(verifier_key) if verifier_key else self.keys / "verifier.key"
        if not key_path.exists():
            raise ValidationError("verifier key not found")
        key = _load_key(key_path)
        verifier_id = _key_id("verifier", key)
        self._require_registered(verifier_id, VERIFIER)
        verifier = IndependentFileVerifier(
            verifier_id=verifier_id, private_key=key, sandbox=self.root, store=self.store,
            valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=365))
        results = []
        for path in sorted((self.review / "done").glob("*.json")):
            item = json.loads(path.read_text(encoding="utf-8"))
            if item.get("state") != "written" or item.get("verified"):
                continue
            task = complete_task(store=self.store, boundary=self.boundary, verifier=verifier,
                                 task_id=item["task_id"], now=now)
            item = dict(item, verified=True, task_state=task.state.value, verification=task.verification)
            _atomic_json(path, item)
            results.append({"id": item["id"], "task_state": task.state.value, "verification": task.verification})
        return results

    def kill(self) -> None:
        self.kill_path.write_text(self.now().isoformat() + "\n", encoding="utf-8")

    def resume(self) -> None:
        if self.kill_path.exists():
            self.kill_path.unlink()

    def status(self) -> dict:
        out = {}
        for state in STATES:
            out[state] = sorted(p.stem for p in (self.review / state).glob("*.json"))
        out["killed"] = self.kill_path.exists()
        return out

    # ------------------------------------------------------------------ internals

    def _refuse_if_killed(self) -> None:
        if self.kill_path.exists():
            raise KillSwitchEngaged("kill switch is engaged; nothing was executed")

    def _read_item(self, state: str, item_id: str) -> dict:
        path = self.review / state / f"{item_id}.json"
        if not path.exists():
            raise ValidationError(f"no {state} item with id {item_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _sign(self, item: dict, key: Ed25519PrivateKey, key_id: str, now: datetime) -> AuthorizationRecord:
        limits = {"max_operations": 1, "postcondition_hash": item["sha256"]}
        common = dict(
            authorization_id=f"auth-{item['id']}", authorizer=APPROVER, agent_id=WORKER,
            task_id=item["task_id"], objective=item["scope"], action=ACTION, scope=item["scope"],
            allowed_tools=(TOOL,), limits=limits, policy_version=POLICY, issued_at=now,
            expires_at=now + APPROVAL_TTL, provenance="human-approval:draft-host")
        base = AuthorizationRecord.issue(**common, proof="pending")
        payload = {
            "authorization_id": base.authorization_id, "authorizer": base.authorizer,
            "agent_id": base.agent_id, "task_id": base.task_id, "objective": base.objective,
            "action": base.action, "scope": base.scope, "allowed_tools": list(base.allowed_tools),
            "limits": {k: json.loads(v) for k, v in base.limits},
            "policy_version": base.policy_version, "issued_at": base.issued_at.isoformat(),
            "expires_at": base.expires_at.isoformat() if base.expires_at else None,
            "provenance": base.provenance,
        }
        signature = base64.b64encode(key.sign(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))).decode("ascii")
        return AuthorizationRecord.issue(**common, proof=f"ed25519:{key_id}:{signature}")

    def _execute(self, item: dict, now: datetime) -> dict:
        base = {"id": item["id"], "path": item["path"], "sha256": item["sha256"]}
        try:
            data = validate_draft(item["path"], item["content"])
            if scope_for(item["path"], data) != item["scope"]:
                raise AuthorizationError("approved content no longer matches the approved scope")
            authorization = self.ledger.get(item["authorization_id"], now=now)
            attempt = self.pilot.submit(task_id=item["task_id"], idempotency_key=item["id"],
                                        relative_path=item["path"], content=data,
                                        authorization=authorization, worker_id=WORKER, now=now)
        except (AuthorizationError, ValidationError, ConflictError, SandboxError) as exc:
            return dict(base, status="refused", reason=str(exc))
        if attempt.state is not AttemptState.SUCCEEDED:
            return dict(base, status=attempt.state.value.lower(), reason=attempt.error_detail or "not written")
        return dict(base, status="written")


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="draft-host", description=__doc__.split("\n")[0])
    parser.add_argument("--state", required=True, type=Path)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("setup")
    sp.add_argument("--approver-key", type=Path, default=None,
                    help="write the approver's private key here, outside the state directory (recommended)")
    sp.add_argument("--verifier-key", type=Path, default=None,
                    help="write the verifier's private key here, outside the state directory (recommended)")
    p = sub.add_parser("propose")
    p.add_argument("brief")
    p.add_argument("--stub", action="store_true", help="use the offline stub drafter instead of a model")
    p.add_argument("--provider", choices=("groq", "anthropic"), default="groq",
                   help="model provider when not using --stub (default: groq, which has a free tier)")
    p.add_argument("--model", default=None, help="model name for the provider")
    for name in ("show", "approve", "reject"):
        q = sub.add_parser(name)
        q.add_argument("item_id")
        if name == "approve":
            q.add_argument("--confirm", action="store_true")
            q.add_argument("--approver-key", type=Path, default=None)
    sub.add_parser("run")
    vp = sub.add_parser("verify")
    vp.add_argument("--verifier-key", type=Path, default=None)
    sub.add_parser("kill")
    sub.add_parser("resume")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    if args.cmd == "setup":
        DraftHost.setup(args.state, approver_key_path=args.approver_key, verifier_key_path=args.verifier_key)
        print(f"initialized {args.state}")
        print("integrity key file: " + str(args.state / "keys" / "integrity.env") + " (never printed)")
        print("approver key: " + str(args.approver_key or args.state / "keys" / "approver.key"))
        print("verifier key: " + str(args.verifier_key or args.state / "keys" / "verifier.key"))
        print("store the approver and verifier keys where the agent cannot read them")
        return 0
    host = DraftHost(args.state)
    try:
        if args.cmd == "propose":
            if args.stub:
                drafter = stub_drafter
            elif args.provider == "groq":
                key = os.environ.get("GROQ_API_KEY")
                if not key:
                    raise ValidationError("set GROQ_API_KEY or pass --stub")
                drafter = openai_compatible_drafter(GROQ_BASE_URL, key, args.model or GROQ_DEFAULT_MODEL)
            else:
                key = os.environ.get("ANTHROPIC_API_KEY")
                if not key:
                    raise ValidationError("set ANTHROPIC_API_KEY or pass --stub")
                drafter = anthropic_drafter(key, args.model or "claude-haiku-5-5")
            _print(host.propose(brief=args.brief, drafter=drafter))
        elif args.cmd == "show":
            _print(host.show(args.item_id))
        elif args.cmd == "approve":
            _print(host.approve(args.item_id, confirm=args.confirm, approver_key=args.approver_key))
        elif args.cmd == "reject":
            _print(host.reject(args.item_id))
        elif args.cmd == "run":
            _print(host.run())
        elif args.cmd == "verify":
            _print(host.verify(verifier_key=args.verifier_key))
        elif args.cmd == "kill":
            host.kill()
            print("kill switch engaged")
        elif args.cmd == "resume":
            host.resume()
            print("kill switch disengaged")
        elif args.cmd == "status":
            _print(host.status())
    except (ValidationError, KillSwitchEngaged, AuthorizationError, ConflictError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Sandboxed File-Write Pilot: Scope, Threat Model, and Crash Contract

## Status and purpose

This document defines the first narrow end-to-end Nova pilot: one governed file-write action, on one local POSIX filesystem, through one integration. It is a testable scope contract, not a claim that the pilot has already been implemented or certified.

The pilot is intended to answer one question: can Nova bind a specific authorization to one exact file operation, preserve durable execution state across process crashes, and detect when the recorded evidence has been altered?

## Scope and non-goals

**In scope**

- One agent integration and one action class: writing specified bytes to one file inside a configured sandbox root.
- A local POSIX filesystem and SQLite as the authority store.
- One explicit governed entry point for authorization, operation binding, attempt creation/claim, outcome evidence, and completion eligibility.
- Real subprocess crash tests at the named points below.
- A deterministic demo with fixed input and a committed expected transcript.

**Out of scope**

- Payments, network calls, arbitrary shell commands, other file operations, or a second agent integration.
- Distributed or multi-host linearizability guarantees.
- Protection against a compromised kernel, host administrator, or attacker with access to both the database and integrity key.
- Semantic judgment that the requested file contents are appropriate or correct for the user’s goal.
- Exactly-once guarantees for arbitrary external side effects.
- A planner or autonomous task decomposition.

Expansion to another integration, action class, or operating system requires a separate design and evidence; it is not part of this pilot.

## Single enforcement path

Every file write in the pilot must pass through one public governed execution entry point. That entry point must validate authorization and identity, bind authorization to the exact task and canonical operation, create and claim a durable attempt, invoke only the sandboxed file-write adapter, record evidence, and expose completion eligibility only after verification of the durable record.

Other components may implement subordinate checks or storage, but must not be alternate public paths that can authorize or perform the pilot action. The implementation and demo should be drawable as:

```text
request
  → governed entry point
      → validate authorization + identity + task + exact operation
      → durable operation/attempt claim
      → sandboxed atomic file-write adapter
      → independently observe target bytes and hash
      → persist evidence + integrity-protected audit record
      → permit completion only from verified durable evidence
```

A successful write is not itself proof of semantic correctness. The observation verifies only filesystem facts and binding/integrity relationships defined below.

## Threat model

### Protected assets

- The configured sandbox root and the exact target path authorized for the operation.
- Authorization-to-operation, task, agent identity, and attempt bindings.
- Durable attempt state, evidence, and audit-record integrity.
- The invariant that denial, unresolved execution, or invalid evidence cannot be presented as verified completion.

### Adversaries and failures considered

- A buggy or adversarial agent that requests an unauthorized path or changes the operation after authorization.
- Untrusted input that attempts path traversal or uses symlinks to escape the sandbox.
- A process crash at any of the four defined persistence/effect boundaries.
- Concurrent workers using separate processes/connections against the local SQLite database.
- An actor able to edit SQLite records but not able to obtain the separately protected integrity key; such edits should be detected when the chain is verified.

### Assumptions and limitations

- The host kernel, Python runtime, SQLite library, and configured sandbox root are trusted during execution.
- No untrusted process concurrently changes directory entries or target files. A canonical `realpath` containment check is required, but alone is vulnerable to time-of-check/time-of-use symlink races. The implementation must resolve and operate relative to trusted directory descriptors, reject symlink traversal (for example with `openat`/`O_NOFOLLOW`-style operations where available), and document any residual platform-specific limitation.
- The staged file and target are on the same filesystem so rename is atomic. The adapter uses deterministic bytes and an operation-ID-bound staging name; it flushes file contents and, where required for the stated crash durability, syncs the file and containing directory before reporting durable success.
- A target is exclusively controlled by this operation while recovery is pending. A recovery hash mismatch is treated as conflict and escalated; it is not silently overwritten or retried.
- The MAC/signing key is provisioned and stored outside the SQLite database and protected by deployment controls. Anyone who can modify both the records and the key can forge the protected chain. Anyone who compromises the host while the key is available may also exceed this threat model.

### Explicitly not protected against

- A compromised host, kernel, runtime, or filesystem administrator.
- An attacker who can access both the SQLite database and the integrity key.
- Prompt injection or agent steering that results in a harmful but duly authorized operation.
- A mistaken or malicious approver, or proof that an approver understood the request.
- Content that is policy-authorized and correctly recorded but semantically wrong for the task.

## Crash-point contract

Each test must run the worker in a real subprocess and terminate it at the named hook using `SIGKILL` or `os._exit` (no Python cleanup handlers). Tests use a temporary database and sandbox, then start a separate recovery process and inspect both durable records and actual filesystem bytes.

| Crash point | Durable state expected after restart | Filesystem expected after restart | Recovery rule |
|---|---|---|---|
| After authorization, before attempt is recorded | No attempt or effect is recorded. Authorization may exist, but no operation is claimed. | Target unchanged; no operation staging file. | A new attempt may be created after revalidating authorization and operation identity. |
| After attempt is recorded/claimed, before the write begins | Attempt remains unresolved/claimed; no outcome evidence or completion. | Target unchanged; staging file may be absent or incomplete. | Recover the same operation. Confirm no target effect, prepare deterministic bytes in the operation-ID staging path, then perform the atomic rename. Do not create a semantically different operation under the same idempotency key. |
| After atomic rename/write, before evidence is recorded | Attempt remains unresolved; no success evidence or completion is present. | If rename occurred, target bytes hash to the operation’s expected hash; otherwise target is unchanged. | Observe the target. If it exactly matches the expected operation hash and path, record recovery evidence for that attempt. If it does not match, stop and escalate; do not claim success or overwrite blindly. |
| After evidence is recorded, before task completion | Outcome evidence is durable and bound to the operation/attempt; task completion may still be pending. | Target bytes hash to the recorded expected hash. | Re-verify the durable evidence and target, then make completion/finalization idempotently. Never repeat the write solely because completion was not recorded. |

The first row distinguishes authorization from a durable execution claim: authorization alone must not cause a file effect. The third row is the critical ambiguous crash window; observing the actual target resolves it only when the exact expected bytes and path match. A mismatch is a conflict, not permission to retry.

Tests should also cover crashes during staging, before rename, and immediately after rename to ensure temporary files are harmless, the target is never partially replaced, and recovery follows the table. These are subpoints of the second and third rows, not new action classes.

## File-write and sandbox contract

- Configure one absolute sandbox root at startup and retain a trusted directory handle for it.
- Accept only a normalized relative target path. Reject absolute paths, empty paths, `..` components, NUL bytes, and unsupported path forms.
- Resolve/canonicalize the target under the sandbox root and verify containment; do not rely on string-prefix checks. Prevent symlink traversal during the actual open/rename operation to avoid a `realpath` check followed by a symlink swap.
- Use a deterministic, operation-ID-bound temporary name in the target directory (same filesystem), write the exact authorized bytes, flush them, and atomically rename into place. Ensure the operation cannot select arbitrary temp paths.
- Re-open/read the resulting target through the sandbox-safe path and compute the observed byte length and SHA-256. The expected content hash must itself be bound to the canonical operation.
- If recovery finds the target hash equal to the expected hash, it may record recovered evidence. If it differs, it must not overwrite automatically; report a conflict for explicit handling.
- The test matrix must include `..` traversal, absolute paths, symlink escape, symlink replacement/race where feasible, and platform-specific case behavior. The pilot supports one specified POSIX filesystem; case behavior is tested/documented for that filesystem rather than generalized to all filesystems.

## Audit and evidence record format

The pilot’s canonical record format must be versioned and serialized deterministically (UTF-8 JSON, sorted keys, compact separators). Each operation/attempt evidence record contains at least:

- `schema_version`
- `event_id`, `event_type`, and UTC timestamp
- `task_id`, `operation_id`, `attempt_id`, and fencing value
- canonical sandbox-relative target path
- authorization identifier and authorization integrity hash
- agent/worker identity identifier and tool/integration identifier
- operation hash, expected content SHA-256, observed content SHA-256, and observed byte length
- outcome (`DENIED`, `CLAIMED`, `SUCCEEDED`, `FAILED`, `UNKNOWN`, or `CONFLICT` as appropriate)
- prior record hash and current record MAC/signature

The canonical operation binds the exact action, task scope, relative path, and content hash (or an equivalently unambiguous representation of the authorized bytes). Do not put secret key material in records. The chain MAC/signature key must not be stored in the same SQLite database as the records. The verification routine must check canonical serialization, record-to-record linkage, MAC/signature, operation/authorization/attempt bindings, and correspondence between observed target bytes and recorded evidence where the target is available.

A hash stored beside mutable data detects accidental mismatch only when recomputed against trusted data; it does not by itself prevent an attacker with database write access from changing both. The external key and stated host assumptions are essential to the tamper-detection claim.

## What the pilot proves—and does not prove

**If all specified tests pass, it provides evidence that:**

- An unauthorized or out-of-sandbox file-write request is denied before the file effect.
- For this operation, the observed bytes at the canonical sandbox-relative path match the expected content hash.
- The write result is bound in durable records to a particular task, operation, attempt, authorization, and agent identity.
- Under the stated local POSIX atomic-rename and exclusive-target assumptions, the named process-crash cases recover without treating an unresolved or conflicting outcome as success and without blindly repeating the write.
- Changes to protected audit records are detected when verification is performed by a process that has access to the separately protected integrity key.

**It does not prove that:**

- The bytes are semantically correct for the task or beneficial to the user.
- The approver understood or intended the operation.
- The agent was not steered by prompt injection.
- The host, kernel, runtime, filesystem, or key-management environment is uncompromised.
- Records resist an attacker who can change both the database and integrity key.
- Every external side effect is exactly once, or that the guarantees generalize to distributed stores, network filesystems, other operating systems, or other action classes.

## Demo contract

Provide one script with fixed inputs and exactly three top-level scenarios:

1. An unauthorized write is denied and the target remains unchanged.
2. An authorized write is killed at the after-rename/before-evidence crash point; recovery observes matching bytes, records evidence, and finalizes without issuing a second non-idempotent effect.
3. An audit/evidence record is modified without the integrity key; verification reports tampering and refuses completion.

Commit the expected deterministic transcript as a golden-output fixture and provide a command that runs the script and diffs its output against that fixture. Exclude timestamps, random IDs, and other nondeterministic values from displayed output or normalize them in the transcript. The transcript must report assumptions and must not imply semantic verification or host-compromise protection.

## Acceptance gate

Do not add a planner, a second integration, or a second action class until:

- the enforcement path is documented and has one public entry point;
- the threat model and record format above are implemented accurately;
- every crash row is exercised with a real process kill and recovery in a separate process;
- concurrency tests use multiple workers/processes/connections, not only threads or mocks;
- sandbox traversal and symlink tests pass;
- the demo’s output matches its committed golden transcript; and
- docs state any untested or platform-specific assumptions plainly.

## Implementation status

Status: **pilot, Linux-tested, not certified.** Implemented in `nova/file_write_sandbox.py` (descriptor-relative adapter), `nova/file_write_pilot.py` (entry point, recovery, verification), and `nova/file_write_completion.py` (independent completion). The pilot runs on Linux under CPython 3.12.

### Integrity model: one mechanism

- The pilot stores each outcome record as the attempt's `result_evidence` or `error_detail`.
- The kernel keys every attempt's `evidence_hash` with the durable integrity key, which lives in the environment and not in the database. The read path re-verifies this MAC on every attempt read.
- The kernel's `execution_audit_events` are a hash chain keyed the same way. Each `ATTEMPT_*` event records the keyed evidence hash in its detail. `verify_execution_audit(task)` recomputes the chain.
- Earlier, the pilot kept a separate evidence table. That table has been removed, so there is one mechanism.

### Completion

`complete_task` drives `EXECUTING -> OBSERVING -> VERIFYING -> COMPLETED`. Completion requires a proof signed by a registered verifier key, checked through the kernel's `VerificationGate`. The verifier re-observes the target itself. The trusted expected digest comes from the durable operation record. The executor holds no verifier key. Tested: valid completion, idempotency, unregistered-key forgery, executor self-verification, out-of-window keys, post-success target changes, and wrong postconditions.

The kernel requires the operation scope to equal the task objective. The pilot therefore creates each task for exactly its signed scope (`file-write:<path>:sha256:<digest>`), so the task, the operation, and the grant all name the same thing.

### Crash rows and concurrency

- `tests/test_file_write_crash.py` kills a real subprocess at `after_authorization`, `after_claim`, `after_stage`, `after_publish`, and `after_evidence`, then recovers in a separate process. Exit code 77 confirms the kill.
- `tests/test_file_write_concurrency.py` races separate processes on one database, for one operation and for two operations on one path.
- `.github/workflows/file-write-pilot.yml` repeats the process-level suites 20 times in CI.

### Ambiguous effects

The pilot distinguishes three cases:

- **No effect.** A failure before the link leaves the target absent, and the attempt is `FAILED`.
- **Effect possible.** A failure after the link, or an observation that fails after it, makes the attempt `UNKNOWN`. Recovery never retries or overwrites an `UNKNOWN`.
- **Lost race.** If the target appears between observation and link, the attempt is not credited with it, even when the bytes match. Outside recovery this is `FAILED`. During recovery it is `UNKNOWN`.

### Formal model

`formal/FileWritePilot.tla` models the attempt lifecycle with crashes, recovery, and a competing writer. TLC checks five safety invariants over 150 distinct states with no violations. `formal/run_tlc.sh` also checks two planted-bug mutants, and TLC catches both. `formal/mutants/MutA.tla` reintroduces the fixed race bug, and `formal/mutants/MutB.tla` reintroduces the old kernel TOCTOU. CI runs the same script with a checksum-verified TLC v1.7.4.

### Deviations from the spec text

1. **Publication uses `link(2)` and then `unlink`, not `rename`.** `link` never replaces an existing target. Complete bytes still appear at the target atomically.
2. **The scope binds the operation.** The kernel binds authorization to action, scope, tool, and task, but not to the operation specification. The path and content digest go into the signed scope instead.
3. **Recovery resumes the claimed attempt.** The kernel's recovery module records decisions but does not execute them. The pilot resumes the same claimed attempt with the same worker id and fence.
4. **Parent directories must already exist.** The pilot does not create directories.
5. **Overwrite is refused.** A pre-existing target is never replaced, even with identical bytes.
6. **Kernel changes made for this pilot.** `attempts_for_operation` and `verify_execution_audit` were added as read-only accessors. `create_attempt` refuses while a `NOT_EXECUTED` attempt exists. Evidence hashes are keyed. The audit chain was added.
7. **Schema change and migration.** `execution_audit_events` gained `previous_hash` and `event_hash`. `SQLiteExecutionAuthority` migrates older databases on open: it adds the columns, backfills the chain per task in row order, and restores the append-only trigger, all in one transaction. The migration is tested against a database with the old schema, including a check that it actually runs.

### Assumptions

- The sandbox root is not modified by an untrusted process during recovery. This is the spec's exclusive-target assumption. The model's competing writer only acts while the target is empty.
- The durable integrity key is held outside the database.
- POSIX with `O_NOFOLLOW`, `O_DIRECTORY`, and `link(2)` support.

### Not implemented or not tested

- **Enforcement within one Python process is not possible.** `PILOT_PUBLISH_CAPABILITY` prevents accidental direct use of the publish path. Any code in the process can import it, and `create_attempt` can be called by anyone holding the kernel object. Restricting these needs process isolation, where the pilot runs in a separate process that the host controls. Until then, the protection is the audit and evidence chain, not the call graph. Treat this as a host-integration requirement.
- Kernel recovery decisions for `UNKNOWN` attempts. Escalation is currently a refusal.
- Symlink-replacement races are tested for one swap point only (the `before_publish` hook). Case-sensitivity behavior is not tested.
- macOS and other filesystems are untested.
- Restricting attempt creation to the pilot. See the in-process enforcement note above.

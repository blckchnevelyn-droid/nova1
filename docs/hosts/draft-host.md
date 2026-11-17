# Draft host

The first host for the Nova file-write kernel. It is deliberately small and does one thing: an agent proposes a draft file, a human approves the exact bytes, and only then does the pilot write the file into a sandbox folder. A separate verifier then completes the task.

## What it does

- Proposes a draft under `drafts/` only. `drafts/<name>.md` or `.txt`, UTF-8, 64 KiB at most.
- Writes nothing on propose. The review item holds the exact content.
- Writes only after a human signs an authorization bound to the item's path and SHA-256. The signature covers the exact scope and a postcondition equal to the content digest. Max one operation per approval, valid for one hour.
- Executes approved items through the governed pilot. Refuses content that changed after approval.
- Lets a separate verifier complete the task. Completion requires a registered verifier key.
- Honors a kill switch. `run` refuses to start while it is engaged and checks it before each item.

## Commands

```
draft-host --state S setup --approver-key /human/approver.key --verifier-key /verifier/verifier.key
draft-host --state S propose "brief"            # agent side; add --stub for the offline drafter
draft-host --state S show ID                    # human reads the exact bytes
draft-host --state S approve ID --confirm --approver-key /human/approver.key   # human side
draft-host --state S run                         # agent side; holds no verifier key
draft-host --state S verify --verifier-key /verifier/verifier.key              # verifier side
draft-host --state S kill | resume | status
```

## Trust model

- Trusted public keys are written into the database once, at `setup`. `approve` and `verify` refuse any key not registered there, and refuse revoked keys. This closes trust-on-first-use, where whoever supplied a new key first became trusted.
- Keep the approver key and the verifier key outside the state directory, held by different principals if you can. `run` needs neither key. If the approver key sits in the state directory, the agent side can approve its own drafts. The default `setup` with no key paths does exactly that, so do not use the default for real work.
- The integrity key file (`keys/integrity.env`) must stay readable only by the runner. It binds the audit chain, so whoever holds it can rewrite history.

## What it proves, when all tests pass

- Nothing is written before a registered human key signs approval for that exact path and content.
- A change to content after approval is refused before any write.
- Running twice writes once. A rejected or unapproved item is never written.
- The kill switch stops the run before an effect.
- Completion is granted only by a registered verifier key, and the verifier re-observes the target.
- The approval, the write, and the verification are all recorded in the hash-chained audit.

Covered by `tests/test_draft_host.py` (25 tests) and the process-level and TLA+ checks for the pilot underneath.

## What it does not prove

- **Semantic quality.** The approver sees the bytes and approves them. Whether the draft is correct, wise, or safe to publish is the human's judgment, not something the host checks.
- **Model behavior.** The Anthropic drafter is built and tested against a mock. It has not run live. This sandbox has no API key. Run it once with a real key before trusting its output format.
- **Key custody.** The host cannot stop a principal who holds the approver key from approving, or one who holds the integrity key from rewriting the audit. Keys must be separated by the operator. The host can only enforce that the separation is possible.
- **The kill switch is not preemptive.** It stops the run between items and before each effect. A write already in progress finishes.
- **Publishing.** Nothing leaves the sandbox. Copying a draft anywhere else is a manual step outside this host.
- **Scale and platform.** Single machine, single state directory, POSIX only, Linux-tested. No concurrency across hosts.

## Known gaps

- Approval is by the approver's key, not by an identity check. There is no login, no second factor, and no notion of who the human is beyond holding the key file.
- The verifier and the runner share a database. Process isolation between them is still an operator responsibility.
- Results are recorded in `review/done/`, which the runner can write. Those records are not hash-chained. The authoritative record is the audit in the database.

# Nova

Nova is a prototype. Writes approved drafts into one sandbox folder. Not certified, and not tested against real failures.

It provides a concrete model for how an action can be authorized, bound to an identity, recorded in durable state, recovered after failure, and audited after completion. The project is built around a simple principle: if an agent or tool is going to act with authority, the system must preserve a verifiable execution record.

This repository contains both:

- the core Python framework in `nova/`, which defines the authority and execution model

The code and docs are intentionally structured around a practical contract: approval, execution state, recovery, verification, and evidence provenance.

## Why Nova exists

Agentic systems need more than a prompt and a tool call. They need a boundary that answers a few questions reliably:

- Who authorized this action?
- What task is it bound to?
- What state did execution reach before a failure or retry?
- What evidence was recorded?
- How do we recover without losing integrity?

Nova is designed to make those guarantees explicit and testable.

## Core model

The core framework centers on a few durable concepts:

- Task identity and lifecycle state
- approval and authorization provenance
- operation identity and idempotency
- execution attempts with fencing and audit events
- recovery transitions and verification gates
- evidence and provenance tracking

The most important modules are:

- `nova/authority.py` — task lifecycle, state transitions, approval records, audit events
- `nova/execution.py` — operation identity, attempts, evidence hashing, execution durability
- `nova/governed_execution.py` — governed execution path with durable identity and authorization checks
- `nova/governance.py` — authorization ledger and policy semantics
- `nova/persistence.py` — durable storage and persistence behavior
- `nova/recovery.py` — recovery and retry handling
- `nova/verification.py` — completion and verification gate logic
- `nova/durable_authority.py` — SQLite-backed durable authority implementation

## The design goal

Nova is not a broad platform abstraction. It is a focused framework for authoritative execution under failure and recovery conditions.

Its primary value is to provide a clear boundary between:

- an action being requested
- an identity being authorized
- an execution attempt being claimed
- durable evidence being recorded
- a later state transition or recovery path being validated

## Repository layout

```text
.
├── AGENTS.md
├── README.md
├── package.json
├── pytest.ini
├── requirements.txt
├── nova/
│   ├── __init__.py
│   ├── authority.py
│   ├── execution.py
│   ├── governed_execution.py
│   ├── governance.py
│   ├── persistence.py
│   ├── recovery.py
│   ├── verification.py
│   ├── durable_authority.py
│   ├── runtime_security.py
│   ├── durable_security.py
│   ├── identity.py
│   ├── audit_anchor.py
│   ├── audit_checkpoint.py
│   ├── audit_tsa.py
│   ├── evidence_provenance.py
│   └── ...
├── tests/
│   ├── conftest.py
│   ├── governed_fixtures.py
│   ├── test_*.py
│   └── ...
├── docs/
│   ├── architecture/
│   ├── governance/
│   ├── recovery/
│   ├── security/
│   ├── testing/
│   └── verification/
```

## Local setup

For the Python framework and tests:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

File-write pilot demo and its regression check (POSIX only):

```bash
PYTHONPATH=. python3 demo/file_write_pilot_demo.py
# compare with demo/expected_transcript.txt; tests/test_file_write_demo.py does this automatically
```

## Project status

This repository is a reference implementation and working framework for durable execution governance. It is intentionally opinionated and verification-heavy.

The contracts live in the Python package. The application shell that once sat alongside it was removed because it could not run and did not belong to the kernel.

## Related documentation

The documentation tree under `docs/` contains the design and validation material for the framework, including:

- authority and state design
- execution idempotency and recovery semantics
- governance and authorization binding
- security and verification constraints
- testing and adversarial invariants

These docs describe the system-level contract that the tests exercise.

## Recommended interpretation

If you are using Nova, treat it as:

- a durable execution authority for agent actions
- a governance layer for authorization and approval
- a model for recoverable, auditable task execution
- a testable safety boundary for tool-driven workflows

That is the core product story the code is designed to support.

## Draft host (first host)

The first host runs an agent-proposed draft through human approval and independent verification. See `docs/hosts/draft-host.md`.

```bash
python -m host.draft_host --state ./state setup --approver-key ~/human/approver.key --verifier-key ~/verifier/verifier.key
```

## Formal model (file-write pilot)

```bash
formal/run_tlc.sh   # checks the lifecycle model and two planted-bug mutants; needs Java
```

# P2 Runtime Security Foundation

## Status

**P2.1 runtime security enforcement is certified for the branch state recorded by PR #48 on 2026-10-06.**

Certification scope is limited to the P2.1 runtime enforcement contract described below. P2.2 execution isolation and other deferred capabilities are not certified by this document.

## Exact-Head Verification Evidence

Reviewed head: `60d4d46c90d7f035340a394f75cbff739c6e64aa`

Base: `cb0b9f1cd33d5f0138a6aa56c313fd27bbe14f3f`

Fresh exact-head GitHub Actions:

- Governed execution run **37437651273** — success: P2.1 **8 passed**, Gate-2 **50 passed**, recovery/adversarial **23 passed**, Issue-33 **15 passed**, full regression **265 passed**, compileall passed, exact-head verification passed.
- Authority boundary run **37437651178** — success: full regression **265 passed**, compileall passed, exact-head verification passed, immutable action SHAs verified.
- Runner bootstrap run **37437651184** — success: hosted runner allocation and command execution passed.

Reproducibility evidence: Python **3.12.14**, pytest **9.1.1**, cryptography **46.0.7**; actions pinned to immutable SHAs; artifact **11400220091**, digest **sha256:becf6db8669e74806ff21a7c9528c51aa4f1a35f4575efc36f316c36ac1d1ad3**.

GitHub also reported a Node.js 20 deprecation warning for these pinned action revisions being forced onto Node.js 24. It did not fail the workflows and is recorded as a platform/toolchain follow-up, not a P2.1 runtime enforcement failure.

## Objective

Establish a runtime security enforcement checkpoint without weakening or duplicating Nova's existing deterministic authority controls.

## Authority Rule

The deterministic authority remains the source of truth for:

- durable authorization
- authorization integrity and validity
- identity verification
- capability/tool binding
- policy and execution constraints

The P2.1 runtime gate is **not an authority source**. It accepts only evidence assembled after those deterministic checks succeed.

## P2.1 Enforcement Contract

The consequential execution flow is:

`request/input → durable authorization → identity verification → capability/tool validation → P2.1 Runtime Security Gate → governed claim → outcome → verification/completion`

The first consequential execution transition is the governed attempt claim from `NOT_EXECUTED` to `CLAIMED`.

The P2.1 gate is mandatory immediately before that transition.

Caller/model-provided authorization or verification booleans are not accepted as security evidence.

## Trusted Runtime Evidence

`RuntimeSecurityEvidence` contains:

- request/attempt identifier
- authorized agent identifier
- capability/tool
- durable authorization identifier
- authorization integrity hash
- trusted identity key identifier
- verified identity digest

This evidence is assembled by the governed execution boundary only after the existing durable authorization and cryptographic identity checks succeed.

The gate performs fail-closed completeness validation of that evidence. It does not replace the underlying authority systems.

## Required Gate Properties

1. Fail closed on incomplete evidence.
2. Reject non-evidence input.
3. Execute before every governed consequential claim.
4. Denial prevents the consequential transition.
5. Gate exceptions prevent the consequential transition.
6. Existing durable authorization, identity, capability, policy, and completion controls remain authoritative.

## Attack Requirements

The P2.1 test set must cover:

- missing authorization
- invalid authorization
- modified authorization
- expired authorization
- revoked authorization
- replay attempt
- wrong capability/tool
- fabricated runtime context
- direct execution bypass
- alternate entrypoint
- gate denial
- gate exception
- unauthorized completion/result
- model-generated execution instruction without deterministic authority

Expected result: fail closed.

## Exit Criteria

P2.1 completes only when implementation, real-boundary integration, adversarial checks, exact-head CI evidence, and reproducible repository evidence are available.

No P2.2 work is part of this phase.

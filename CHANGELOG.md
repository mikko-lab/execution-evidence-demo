# Changelog

## Unreleased — v0.2 lifecycle evidence

- Add signed, hash-linked lifecycle observations for dispatched, confirmed,
  indeterminate, and unknown executions without changing ExecutionReceiptV1.
- Require verified receipt hashes and matching execution/request identities for
  confirmation; resolve uncertainty with separately trusted signed reconciliation.
- Separate issuer keys and evidence roles in external verifier configuration.
- Default uncertain or missing evidence to reconciliation; permit retry only
  for explicitly configured, identity-bound side-effect-free operations.
- Preserve execution/request/idempotency identity in signed retry observations.
- Document transition rules, downstream evidence requirements and trust limits.
- Keep the package version and all existing tests and compatibility vectors unchanged.

## 0.1.0

- Add strict v1 execution receipts with deterministic SHA-256 observation hashes.
- Bind complete receipt metadata with Ed25519 signatures.
- Verify configured authority, signatures, and before/after/result observations.
- Add explicit errors, mutation isolation tests, and trust-boundary documentation.
- Defer replay tracking, durable storage, and receipt chaining to later work.

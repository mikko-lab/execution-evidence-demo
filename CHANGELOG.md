# Changelog

## Unreleased — v0.2 lifecycle evidence

- Replace the earlier unreleased lifecycle draft with append-only signed
  observations and a separate knowledge/conflict assessment API.
- Remove retry authorization and retry policy from evidence verification.
- Commit to actor, action/target, payload and executor/scope with a strict
  domain-separated operation descriptor hash.
- Distinguish logical execution IDs, delivery attempt IDs and observation IDs;
  preserve retry ancestry without authorizing or performing retries.
- Add separately trusted signed receipt bindings for the payload/scope/attempt
  association absent from ExecutionReceiptV1; validate receipt actor/action too.
- Use outcome_observed with verified binding evidence, never acknowledgement alone.
- Accept forks, delayed observations and contradictory outcomes; report conflict
  without overwriting evidence or using timestamp order to select a winner.
- Distinguish missing predecessors from invalid signatures; expose supplied graph
  heads and per-attempt knowledge without claiming completeness or freshness.
- Keep package version, v0.1 implementation, APIs, tests and compatibility vector
  unchanged. The previous unreleased lifecycle draft is not wire/API compatible.

## 0.1.0

- Add strict v1 execution receipts with deterministic SHA-256 observation hashes.
- Bind complete receipt metadata with Ed25519 signatures.
- Verify configured authority, signatures, and before/after/result observations.
- Add explicit errors, mutation isolation tests, and trust-boundary documentation.
- Defer replay tracking, durable storage, and receipt chaining to later work.

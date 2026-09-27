# Changelog

## 0.2.0 — Unreleased

- Replace the earlier unreleased lifecycle draft with append-only signed
  observations and a separate knowledge/conflict assessment API.
- Remove retry authorization and retry policy from evidence verification.
- Commit to actor, action/target, payload and executor/scope with a strict
  domain-separated operation descriptor hash.
- Distinguish logical operation IDs, delivery attempt IDs and observation IDs;
  preserve retry ancestry without authorizing or performing retries. Use
  operation_id for logical operations; preserve v0.1 execution_id uniqueness
  across actual executions and bind receipts by their complete signed hash.
- Add separately trusted signed receipt bindings for the payload/scope/attempt
  association absent from ExecutionReceiptV1; validate receipt actor/action too.
  Require binding authorities to have an exact trusted executor/scope grant.
- Use outcome_observed with verified binding evidence, never acknowledgement alone.
- Accept forks, delayed observations and contradictory outcomes; report conflict
  within an attempt without overwriting evidence or using timestamp order to
  select a winner. Different attempts may have different authentic outcomes;
  expose per-attempt event/receipt/execution references without a business verdict.
- Distinguish missing predecessors from invalid signatures; expose supplied graph
  heads and per-attempt knowledge without claiming completeness or freshness.
- Prepare package version 0.2.0; no release has been published. Preserve the v0.1
  receipt implementation, APIs, tests and compatibility vector unchanged. Artifact
  `version: 1` fields identify schemas, not the package version. The previous
  unreleased lifecycle draft is not wire/API compatible.
- Limit the package to runtime JavaScript, TypeScript declarations, package metadata,
  README, license and changelog; exclude source/tests and development configuration.

## 0.1.0

- Add strict v1 execution receipts with deterministic SHA-256 observation hashes.
- Bind complete receipt metadata with Ed25519 signatures.
- Verify configured authority, signatures, and before/after/result observations.
- Add explicit errors, mutation isolation tests, and trust-boundary documentation.
- Defer replay tracking, durable storage, and receipt chaining to later work.

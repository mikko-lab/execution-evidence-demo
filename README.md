# Execution Evidence Demo

A reference implementation for verifiable execution evidence.

**v0.1 answers one narrow question:** “What was actually executed, by whom,
and how did the observed state change?” The answer is evidence attested by a
configured signing authority, not independent proof of the underlying events.

```text
Decision evidence → Runtime authority → Execution evidence
what was decided    what was allowed     what actually executed and
                    to execute           how observed state changed
```

This project implements only the last layer. It is a small Node.js/TypeScript
library, not a general governance framework. No external integrations, databases,
cloud services, UI, or persistence are included. v0.2 adds linked lifecycle
evidence alongside the unchanged v0.1 receipts.

## Run locally

Use Node.js 22 or newer and npm:

```sh
npm ci
npm run typecheck
npm test
npm run verify
```

`verify` runs strict type checking, Jest, and the TypeScript build. Jest uses
Node's experimental VM-module support to test ES modules; Node may print the
corresponding warning. The library itself uses standard Node crypto APIs.
Dependencies are pinned in the lockfile. `private: true` prevents accidental npm
publication; the repository and its Apache-2.0 source remain public.

## Continuous integration

GitHub Actions runs `npm ci` and `npm run verify` on Node.js 22 and 24 for
pull requests and pushes to `main`. The workflow has read-only repository
permissions and pins its actions to immutable commit SHAs.

## Dependency maintenance

Dependabot checks npm packages and GitHub Actions weekly on Mondays. Version
update pull requests are limited to three for npm and two for Actions. Updates
follow the same pull-request and CI requirements as other changes; automatic
merging is not enabled.

## Example

After `npm run build`, run this as an ES module from the repository root:

```js
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  createExecutionReceipt, signExecutionReceipt,
  verifyExecutionReceipt, verifyExecutionTransition,
} from './dist/src/index.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const before = { counter: 0 };
// The application performs the operation and observes its result.
const after = { counter: before.counter + 1 };
const result = { ok: true };
const authority = { keyId: 'reference-key-1', publicKey };

const unsigned = createExecutionReceipt({
  execution_id: randomUUID(),
  request_id: 'request-1',
  actor: { type: 'service', id: 'counter-worker' },
  action: { type: 'increment', target: 'counter' },
  before, after, result,
  executed_at: new Date().toISOString(),
  key_id: authority.keyId,
});
const receipt = signExecutionReceipt(unsigned, privateKey);
verifyExecutionReceipt(receipt, authority); // true, or throws EvidenceError
verifyExecutionTransition(receipt, before, after, result, authority);
console.log(receipt);
```

The library does not execute operations or observe state itself. Callers supply
observations, identifiers, and the execution timestamp. Creation and signing
return detached snapshots; later changes to input objects cannot change an
already signed receipt. Returned objects remain mutable; verification rejects
changes to signed content.

## Receipt and API

`ExecutionReceiptV1` contains exactly:

- `version: 1`, `execution_id`, `request_id`
- `actor: { type: "agent" | "service" | "human", id }`
- `action: { type, target }`
- `state_before_hash`, `state_after_hash`, `result_hash`
- `executed_at`
- `signature: { algorithm: "Ed25519", key_id, value }`

`execution_id` must be an explicit UUID v4 (use `randomUUID()`); the application
must ensure uniqueness across executions. Text fields must be nonempty.
`executed_at` must be a valid UTC timestamp in `YYYY-MM-DDTHH:mm:ss.sssZ` form.
Unknown fields, missing fields, unsupported versions, and malformed values fail
closed. An unsigned receipt has the same shape except `signature.value` is absent.

| Function | Contract |
| --- | --- |
| `hashState(value)` | SHA-256 hex over canonical JSON UTF-8 bytes |
| `hashResult(value)` | Same deterministic hashing contract for results |
| `createExecutionReceipt(input)` | Hash supplied observations and validate an unsigned receipt |
| `signExecutionReceipt(unsigned, privateKey)` | Sign validated content with an Ed25519 private `KeyObject` |
| `verifyExecutionReceipt(receipt, authority)` | Validate schema, authority binding, and signature |
| `verifyExecutionTransition(receipt, before, after, result, authority)` | Verify signature first, then all three observation hashes |

Verifiers accept an unknown receipt and return `true` only on success. They throw
`EvidenceError` with stable codes: `MALFORMED_RECEIPT`, `INVALID_KEY`,
`KEY_ID_MISMATCH`, `INVALID_SIGNATURE`, `INVALID_JSON`, `BEFORE_STATE_MISMATCH`,
`AFTER_STATE_MISMATCH`, or `RESULT_MISMATCH`. Do not catch and ignore these errors.
The authority is trusted application configuration, never data taken from the receipt.

## Cryptographic contract

Canonical JSON uses the established
[`canonicalize` implementation](https://github.com/erdtman/canonicalize) of
[RFC 8785 / JCS](https://www.rfc-editor.org/rfc/rfc8785.html).
Object keys are recursively ordered; array order remains significant. Hashes are
lowercase SHA-256 hexadecimal. State and result hashes use the same algorithm;
field names in the signed receipt bind each hash to its role.

The Ed25519 signature covers canonical UTF-8 bytes of the **complete receipt
except the `signature.value` property**. In particular, `version`, both IDs,
actor, action, all three hashes, timestamp, `signature.algorithm`, and
`signature.key_id` are signed. No empty value placeholder is included. Signature
values use canonical padded base64 encoding of exactly 64 bytes.

Inputs must be plain JSON data: null, booleans, finite numbers, valid Unicode
strings, dense arrays, and plain objects with enumerable string data properties.
Undefined, functions, bigint, symbols, cycles, sparse arrays, accessors, hidden
properties, custom prototypes, and invalid Unicode are rejected instead of
silently omitted or coerced. IEEE-754 number semantics apply, including `-0`
canonicalizing to `0`; encode exact large integers as strings. Unicode is not
normalized. Parse external JSON before calling the library; duplicate JSON keys
must be rejected at the ingestion boundary because parsed objects cannot retain
them. Arbitrary executable objects/proxies are outside the input contract.

## Trust model and limitations

Successful verification proves that the private key corresponding to the
**configured signing authority** signed the stated evidence, and (when transition
verification is used) that supplied observations match the signed hashes.
Actor identity, action description, and timestamp are assertions of that authority.
The receipt does not independently prove:

- Physical reality or truth of an external system.
- That the software observing state was uncompromised.
- Human identity or authorization to perform an action.
- Trusted time, immutable storage, or completeness of an execution history.
- Non-repudiation beyond the signing-key trust model.
- Production-grade persistence or atomicity between execution and recording.

Protect signing keys and configure public keys through a trusted channel. v0.1
has no key distribution, rotation, revocation, secure key storage, or resource
limits for untrusted input sizes/depths. Apply size/depth limits at ingestion.
This is a reference implementation, not an independently audited security product.

**Signatures do not prevent replay.** Re-verifying the same valid receipt succeeds.
There is no duplicate-ID registry or global uniqueness enforcement. A later
verifier layer must atomically record accepted execution IDs in durable storage,
with an explicit retention and retry policy. A UUID alone is not replay protection.
v0.2 links lifecycle evidence; these links do not make storage immutable or
establish that a supplied history is complete or current.

## Tests and license

Tests cover deterministic hashing, key-order independence, nested changes,
invalid JSON, signature tampering, wrong keys, malformed receipts, all transition
mismatches, detached copies, and explicit replay behavior.

Licensed under [Apache-2.0](LICENSE).

## v0.2: execution lifecycle and uncertain outcomes

**Dispatched is not confirmed.**

**Indeterminate is neither success nor failure.**

v0.1 remains signed evidence of an observed completed execution transition.
v0.2 adds evidence for the interval after dispatch when the final external effect
may still be uncertain. `ExecutionReceiptV1`, its canonical bytes, signatures,
and external compatibility vector are unchanged. Artifact `version: 1` means
version one of each new artifact schema; it does not change the package version.

| Status | Meaning and required basis |
| --- | --- |
| `dispatched` | The signer observed submission across the execution boundary (`submitted`); no authoritative final outcome is established. |
| `confirmed` | A trusted signed receipt binds the same execution and request and establishes a known observed result (`verified_receipt`). This does not mean business success. |
| `indeterminate` | There is evidence that the operation may have executed, but its final effect is unresolved: `timeout_after_dispatch`, `transport_after_dispatch`, `acknowledgement_lost`, or `unresolved_provider_effect`. |
| `unknown` | There is insufficient trustworthy evidence to classify the execution as confirmed or indeterminate (`insufficient_trustworthy_evidence`). This is not a generic exception category. |

Use indeterminate when a dispatched operation may have committed, including a
lost acknowledgement or a provider that cannot establish its final effect.
Use unknown only when the available evidence cannot support even that assessment,
for example an observation whose association with the downstream operation cannot
be established. A later unknown observation does not erase an earlier signed
submission. Local exceptions before dispatch do not automatically produce any of
these events. The library does not infer outcomes from exceptions or execute work.

### Evidence and transition contract

`ExecutionLifecycleEventV1` includes `kind: "execution_lifecycle"`, `version: 1`,
UUID-v4 `event_id` and `execution_id`, `request_id`, `status`, `basis`, `observed_at`,
`issuer`, and `signature: { algorithm: "Ed25519", key_id, value }`.
Optional `provider_reference` and `idempotency_key` are signed nonempty strings.
`observed_at` uses the same strict UTC millisecond format as v0.1. Unknown fields
are rejected. Creation/signing returns detached data; later mutations invalidate
verification rather than updating a persisted status.

The first observation may be dispatched, indeterminate, or unknown. It has no
predecessor. Allowing an unresolved first observation accommodates partial local
knowledge; it does not assert a complete execution history. Subsequent artifacts
must include `previous_event_hash`: SHA-256 over JCS UTF-8 bytes of the **complete
signed predecessor**, including its signature. Their execution ID, request ID,
and optional idempotency key must match exactly, observation time cannot decrease,
and event/reconciliation IDs cannot repeat within the supplied history.

| Predecessor | Allowed appended evidence |
| --- | --- |
| dispatched | Lifecycle confirmed, indeterminate, or unknown; or authoritative reconciliation to confirmed |
| indeterminate | Authoritative reconciliation to confirmed |
| unknown | Authoritative reconciliation to confirmed |
| confirmed | Terminal; no further classification is accepted in that history |

One explicit exception permits dispatched or indeterminate → dispatched when a
matching verifier policy declares the operation side-effect-free. That event
requires `retry_of` equal to `previous_event_hash`. Ordinary repeated dispatches
and idempotency-based optimistic retries are rejected.

Verification requires the entire supplied linear history. Passing only a linked
last event, skipping predecessors, reordering events, or replacing an uncertain
observation with a regular confirmed event fails. Conflicting branches are not
merged or automatically resolved. Preserve later contradictory material separately
for investigation; this minimal version rejects appends after confirmation and
has no conflict-resolution artifact. Links alone cannot detect a withheld branch,
missing later events, replay, or an attacker presenting an older valid prefix.
The application must retain evidence and establish its expected current head.

### Confirmation, reconciliation, and trust domains

Every confirmed artifact signs `execution_receipt_hash` and `receipt_issuer`.
The hash covers the **complete signed ExecutionReceiptV1**, including its signature.
The verifier requires the referenced receipt, its valid v0.1 signature under a
configured receipt authority, and exact `execution_id` and `request_id` agreement.
The receipt's asserted execution time must not follow the observation time.
A matching hash or a signed `status: "confirmed"` alone is insufficient.
Observation hashes are retained in the receipt; to also check actual before/after/
result values, use the unchanged `verifyExecutionTransition` API.

`ExecutionReconciliationV1` has `kind: "execution_reconciliation"`, a UUID-v4
`reconciliation_id`, the shared metadata and identity, `previous_event_hash`, and
the confirmed classification with its receipt hash and issuer. The receipt hash
is the authoritative evidence reference. This minimal reconciliation model only
resolves an unresolved history to confirmed. If a status query cannot establish
the effect, keep the history unresolved; it cannot produce a reconciliation here.
Reconciliation requires authoritative downstream evidence represented by a trusted
v0.1 receipt, not an arbitrary operator instruction to mark the action confirmed.
The new artifact appends to the existing history and never edits old signatures.

`VerificationContext.trustedIssuers` is **external trusted configuration**. Each
entry provides `issuer_id`, `key_id`, an Ed25519 public `KeyObject`, and explicit
roles: `lifecycle`, `reconciliation`, and/or `receipt`. Exactly one entry must
match the asserted issuer/key pair, with permission for the evidence role.
A signer may be configured for multiple roles, but roles are never inferred.
Unknown issuers, ambiguous entries, wrong keys, and disallowed roles fail closed.
The signer uses a private key; the verifier independently chooses trusted public
keys. Evidence cannot embed a key or grant itself a role. Because v0.1 has no
issuer field, `receipt_issuer` selects an externally configured receipt authority;
the v0.1 key ID and signature must still verify under that authority.

All new signature payloads are JCS-canonicalized full artifacts with only
`signature.value` removed. The signed `kind` distinguishes the artifact domains.
Every security-relevant field, including linkage, issuer, key ID, basis, optional
metadata and confirmation reference, is covered. Strict JSON validation and
Ed25519 key/signature requirements match the v0.1 primitives. No network lookup,
key discovery, or external integration occurs.

### Retry and idempotency

`evaluateRetryDisposition(history, context)` returns:

- `do_not_retry` for verified confirmed history, regardless of whether its known
  result was favorable. Inspect the verified result separately.
- `reconciliation_required` for missing, malformed, untrusted or unresolved
  evidence by default. Unknown always requires reconciliation.
- `safe_to_retry` only for verified dispatched/indeterminate history with an
  explicit `context.retryPolicy` containing `side_effect_free: true` and exactly
  matching execution, request and optional idempotency identity.

The exception is a trusted application assertion about the operation, not evidence
that a provider deduplicates requests. Incorrect policy configuration can make
retry unsafe. Do not set it for side-effecting operations. There is deliberately
no automatic safe-retry path for an uncertain side-effecting operation.

`signRetryDispatch` records a retry **after it has been submitted**, preserving
execution ID, request ID and the optional idempotency key and assigning a fresh
event ID. It does not perform the submission. Evaluate disposition before deciding
to submit, retain the same identity, then record the observation. Regular and retry
appends cannot silently switch that identity. The library cannot stop a caller
from starting an unrelated history or sending a separate external request.

Idempotency metadata is signed; tampering invalidates the signature. Actual
idempotency depends on the downstream executor honoring the key with suitable
scope and retention. Local metadata does not prevent duplicate external effects,
and v0.1 receipts do not independently attest provider idempotency behavior.

### Lifecycle API example

Run after `npm run build` as an ES module from the repository root:

```js
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  signExecutionLifecycleEvent, hashLifecycleEvidence,
  evaluateRetryDisposition, verifyExecutionHistory,
} from './dist/src/index.js';

const keys = generateKeyPairSync('ed25519');
const context = { trustedIssuers: [{
  issuer_id: 'operation-observer', key_id: 'observer-1',
  public_key: keys.publicKey, roles: ['lifecycle'],
}] };
const metadata = {
  kind: 'execution_lifecycle', version: 1,
  execution_id: randomUUID(), request_id: 'request-1',
  idempotency_key: 'stable-operation-1', issuer: 'operation-observer',
  signature: { algorithm: 'Ed25519', key_id: 'observer-1' },
};
// Record submission already observed at the execution boundary.
const dispatched = signExecutionLifecycleEvent({ ...metadata,
  event_id: randomUUID(), status: 'dispatched', basis: 'submitted',
  observed_at: '2026-09-27T12:00:00.000Z',
}, keys.privateKey, [], context);
// A timeout after submission leaves the final external effect uncertain.
const indeterminate = signExecutionLifecycleEvent({ ...metadata,
  event_id: randomUUID(), status: 'indeterminate', basis: 'timeout_after_dispatch',
  observed_at: '2026-09-27T12:00:30.000Z',
  previous_event_hash: hashLifecycleEvidence(dispatched),
}, keys.privateKey, [dispatched], context);
const history = [dispatched, indeterminate];
verifyExecutionHistory(history, context); // true; this does NOT claim completion
console.log(evaluateRetryDisposition(history, context)); // reconciliation_required
```

| API | Contract |
| --- | --- |
| `signExecutionLifecycleEvent(draft, privateKey, history, context)` | Validate, sign, and verify the proposed append; confirmation needs receipt evidence |
| `signExecutionReconciliation(draft, privateKey, history, context)` | Sign and verify a receipt-backed reconciliation under an authorized reconciler |
| `verifyExecutionHistory(history, context)` | Verify schemas, signatures, every link, transitions, identity, and referenced receipts; return `true` or throw |
| `hashLifecycleEvidence(signedEvidence)` | Validate shape and hash the complete signed artifact; does not authenticate it |
| `hashExecutionReceipt(receipt)` | Hash the complete JSON receipt; does not validate its schema or authenticity |
| `evaluateRetryDisposition(history, context)` | Conservative retry decision; verification errors become reconciliation_required |
| `signRetryDispatch(history, observation, privateKey, context)` | Record a policy-justified retry with preserved identity and predecessor linkage |

`context.receipts` supplies untrusted receipt candidates. Referenced receipts are
independently checked; this collection never supplies trust configuration.
New APIs throw `LifecycleError` with `MALFORMED_EVIDENCE`, `UNTRUSTED_ISSUER`,
`INVALID_KEY`, `INVALID_SIGNATURE`, `INVALID_HISTORY`, `INVALID_CONFIRMATION`, or
`UNSAFE_RETRY`. Receipt verification may also propagate the existing `EvidenceError`.
Only the retry helper deliberately converts verification errors to a conservative
disposition. Signing checks the proposed append using the supplied verifier context;
recipients must still verify independently with their own trusted configuration.

### v0.2 limitations

Successful verification still does **not** prove:

- Physical reality, external system truth, or external provider correctness.
- Uncompromised observation software or faithful collection of downstream evidence.
- Provider idempotency behavior or prevention of duplicate external effects.
- Human identity.
- Immutable storage, a complete history, or that this is the latest evidence.
- Globally trusted time (timestamp ordering only compares signed assertions).
- Independent non-repudiation.
- Atomic execution plus receipt/evidence persistence.

Signer identity is only as trustworthy as verifier configuration and signing-key
custody. A compromised or dishonest trusted authority can sign false observations;
cryptographic verification is not independent verification of downstream reality.
The library has no persistence, replay registry, locking, provider adapters, or
atomic submission/recording transaction. Applications own ingestion limits,
retention, freshness, concurrency, and evidence collection. v0.2 remains a small,
deterministic library with no integrations into neighboring conceptual layers.

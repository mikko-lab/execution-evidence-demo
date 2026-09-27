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

## Try the local tarball

This is an unreleased v0.2.0 candidate, not an npm registry release. With locked
repository dependencies installed (`npm ci`), run from the repository root:

```sh
package_dir="$(mktemp -d)"
npm run build
npm pack --pack-destination "$package_dir"
mkdir "$package_dir/consumer"
cd "$package_dir/consumer"
npm init -y
npm install "$package_dir/execution-evidence-demo-0.2.0.tgz"
node --input-type=module -e "import { hashState } from 'execution-evidence-demo'; console.log(hashState({ counter: 0 }));"
```

The final command prints an observation hash. To use either JavaScript example
below in this consumer, replace `./dist/src/index.js` with
`execution-evidence-demo` and run it as an ES module (`.mjs`). TypeScript consumers
can import the same package name; declarations are included. Node type declarations
(`@types/node`) are needed for the public Node crypto types.

The tarball includes `dist/src`, package metadata, README, LICENSE and CHANGELOG.
Source tests, compiled tests and development configuration stay out of the package.
Building before packing is required. `private: true` remains enabled.

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

## v0.2.0 candidate (unreleased): append-only execution observations

This v0.2.0 candidate revises the earlier **unreleased** lifecycle draft incompatibly.
The earlier lifecycle `execution_id` is replaced by `operation_id`; v0.1
`execution_id` continues to identify an actual execution. The earlier `confirmed`,
`ExecutionReconciliationV1`, `retryPolicy`,
`evaluateRetryDisposition`, and `signRetryDispatch` APIs are removed. Do not mix
artifacts from the two drafts. No released lifecycle compatibility is claimed.
Package version 0.2.0 is prepared locally and remains unreleased. The v0.1
`ExecutionReceiptV1` schema is unchanged; its `version: 1` and the new lifecycle
artifact `version: 1` fields identify schemas, not the package version.

`ExecutionReceiptV1`, its APIs, error semantics, canonical bytes, and fixed
external compatibility vector remain unchanged. Missing observations are not
represented by nullable hashes or by hashing JSON null as an unknown sentinel.

### Three separate responsibilities

```text
verifyEvidence / verifyExecutionHistory
    authenticate artifacts and check supplied references/structure
                    ↓
assessHistory
    project knowledge from authenticated observations
                    ↓
authorizeNextAction — external runtime/orchestration responsibility
```

This library has no retry policy or operational authorization API. A retry that
was unsafe or unauthorized can still be recorded as authentic evidence of what
was observed. Verification must not depend on whether the verifier would allow
that action now. Applications must inspect assessment results; successful
structural verification alone does not exclude conflicting outcomes.

### Operation, execution and attempt identity

`OperationDescriptorV1` contains exactly:

```ts
{
  kind: 'execution_operation', version: 1,
  actor: { type: 'agent' | 'service' | 'human', id: string },
  action: { type: string, target: string },
  payload: /* a strictly JSON-compatible value */,
  executor: { id: string, scope: string }
}
```

`hashOperation` computes SHA-256 over the complete descriptor's JCS UTF-8 bytes,
including `kind` and `version`. Payload, actor, action, target, executor and scope
are all committed. The caller must define a scope that distinguishes the relevant
account/tenant/resource domain and include every execution-relevant argument in
payload. A digest does not hide guessable sensitive data.

- `operation_id`: UUID v4 for one intended logical operation, stable across attempts.
- `ExecutionReceiptV1.execution_id`: UUID v4 for an actual execution; applications
  must keep it unique across actual executions, including duplicate retry effects.
- `request_id`: the stable originating request identity in this evidence history.
- `attempt_id`: UUID v4 for one delivery attempt of that operation.
- `event_id`: UUID v4 for one observation, not a delivery attempt.

A retry keeps operation ID, request ID, operation hash and optional idempotency
key; it gets a new attempt ID. Every observation of a retry attempt carries the
same `retry_of_attempt_id`, identifying its preceding attempt. The retry must
have evidence of that preceding attempt in its hash ancestry. New unlinked
attempts and changed attempt metadata fail closed. Multiple observations of the
same submission can share an attempt ID; the library does not observe the network
and cannot detect a caller hiding a new submission under an old ID.

A signed binding connects `operation_id → attempt_id → signed receipt hash`.
The referenced receipt carries its own execution ID; there is no equality check
between that ID and operation ID. A retry causing a second real execution can
therefore have a separate v0.1 receipt with a different execution ID. The full
receipt hash already commits to that ID, so the binding needs no duplicate
receipt-execution-ID field. Retransmission alone does not prove another effect;
these identifiers do not enforce uniqueness or prevent duplicates.

`VerificationContext.operation` supplies the expected descriptor independently
of evidence. All events must match its hash. A different operation hash under the
same operation/request IDs throws `OPERATION_MISMATCH`, not a successful ordinary
projection. Preserve rejected material separately for investigation.

### Binding an unchanged v0.1 receipt

V0.1 does not sign logical operation ID, payload, executor scope, or attempt ID.
Matching a request ID cannot establish those missing associations. A new, separate
`ExecutionReceiptBindingV1` therefore signs:

- logical operation ID, request ID, attempt ID and operation hash;
- `execution_receipt_hash`, over the complete signed v0.1 receipt;
- `receipt_issuer`, plus the binding issuer, timestamp and binding ID.

The binding issuer must be externally trusted for `receipt_binding`. It is
responsible for actually correlating the descriptor and delivery attempt to the
receipt. It may be an executor or an adapter with trustworthy observations; the
library does not collect those observations or contact a provider.

Verification independently checks the binding signature, descriptor hash,
receipt signature under a separately configured `receipt` role, matching request ID,
and exact receipt actor/action equality with the descriptor. The binding's signed
hash attests the remaining payload/scope/attempt association. **It does not make
the old receipt's signer attest fields absent from v0.1**, and a dishonest trusted
binding authority can still lie about that association.

An outcome event signs the hash of the complete signed binding. Binding and event
must agree on logical operation ID, operation hash, request and attempt. Merely supplying a hash,
a local success flag, an acknowledgement, an accepted/queued response or HTTP
success cannot satisfy this verification path. Adapters must not turn such
responses into final-outcome evidence without a justified observation contract.

`context.receipts` and `context.receiptBindings` are untrusted candidates, never
sources of trust configuration. Referenced artifacts are checked independently.
Issuer/key pairs must match exactly one `trustedIssuers` entry with the required
role (`lifecycle`, `receipt_binding`, or `receipt`). A `receipt_binding` authority
must additionally have a trusted configuration grant:

```ts
binding_scope: { executor_id: 'record-api', scope: 'account-1' }
```

Both values must exactly match the expected descriptor's executor ID and scope.
Missing, malformed, mismatched or `*` grants fail closed; there is no wildcard or
prefix expansion. A matching hash and a valid binding signature do not bypass
this restriction. A grant in evidence itself is rejected as an unknown field.
Duplicate issuer/key entries remain ambiguous even if one scope matches; select
a single scoped entry in the per-operation context rather than providing global
multi-scope grants under the same pair.

This is an evidence trust restriction, not execution authorization or ACS policy.
Only the binding role has this additional scope gate; lifecycle and receipt role
selection still belongs to the consuming application's trusted per-operation
configuration. A scope grant does not prove the authority actually observed the
operation, and it does not constrain which payloads it may attest inside that
scope. Evidence cannot grant itself a role, scope or trusted public key.

### Observations and knowledge projection

| Signed observation | Basis / meaning |
| --- | --- |
| `unknown` | `insufficient_trustworthy_evidence`: the observer cannot classify the associated operation |
| `dispatched` | `submitted`: submission across the defined execution boundary was observed; delivery/acceptance/commit is not implied |
| `indeterminate` | `timeout_after_possible_dispatch`, `connection_lost`, `acknowledgement_lost`, `partial_effect_unresolved`, or `unresolved_provider_effect` |
| `outcome_observed` | `verified_receipt_binding`: a trusted, operation-bound receipt attests an observed outcome, including a possible application-level rejection |

Events are immutable signed observations, not commands to change an execution
status. Signing returns detached data; returned objects remain mutable and later
changes invalidate verification. No event deletes or supersedes another.

A root may be unknown, dispatched, indeterminate or outcome-observed; missing
history is not invented to create an apparent full lifecycle. `not_dispatched`,
queued work and pre-dispatch scheduling are outside this minimal artifact model.
Absence of dispatch evidence never proves that nothing was sent.

`previous_event_hash` commits to the complete signed predecessor using SHA-256/JCS.
The supplied graph may fork and input array order is irrelevant. All referenced
predecessors must be present, IDs must be unique within the supplied graph, and
logical operation/attempt bindings must be consistent. Separate roots may
observe the same initial attempt; additional attempts must identify their retry
ancestry. There is no sequence number or global linear order in this profile.

`observed_at` is a strict UTC millisecond timestamp asserted by the observer.
It is not trusted time and does not order the graph. Older observations arriving
later are accepted, including after outcome evidence. Hash links describe evidence
references, not physical causality. Conflicting event times do not select a winner.

Assessment accumulates knowledge:

```text
unknown → dispatched → indeterminate → outcome_observed
    └───────────────────────────────────────────↑
               incompatible outcomes within one attempt → conflict
```

These are projection refinements, not restrictions on which observations may be
appended. Unknown cannot erase dispatch; timeout cannot erase an observed outcome.
Repeated uncertain observations and further observations after an outcome are
recordable. Reconciliation is evidence collection by the application followed by
an ordinary bound outcome observation, not a special override permission.

Two outcome receipts conflict when their signed before/after/result hash tuples
differ **within the same attempt**. Different attempts are not compared for
evidence conflict: an earlier rejected attempt and a later applied attempt can
both be authentic, as can two separate actual effects from retries. Receipt re-signing,
issuer changes or timestamps alone do not constitute outcome disagreement.
Conflicts are conservative: the library does not interpret result JSON, partial
steps, compensation or domain equivalence. Contradictory evidence is preserved,
structural verification succeeds, and assessment returns `conflict`. The returned
conflicting event IDs identify the outcome observations of conflicting attempts
only, leaving unrelated attempts out of that set. No timestamp or later supporting
event erases the conflict.

`assessHistory` returns per-attempt states and outcome references with `event_id`,
`execution_id` (from v0.1), and `receipt_hash`. It also exposes supplied graph heads,
all outcome receipt hashes, and informational `outcome_attempt_ids`. No outcome is
selected or discarded to derive a business-level result.

Overall `conflict` means at least one attempt has conflicting evidence. Otherwise
`outcome_observed` means at least one attempt has an observed outcome, **not that
every attempt has settled or that the business operation succeeded**. Without
outcome evidence, indeterminate takes precedence over dispatched, then unknown.
Inspect the per-attempt details for outstanding or differently resolved attempts.
Multiple outcome attempts alone establish neither duplicate effects nor business
success/failure. The application/orchestration layer interprets those outcomes;
this library never authorizes another action or selects a business winner.

Invalid signatures and malformed/incorrectly bound artifacts throw. Missing
predecessors throw the distinct `MISSING_PREDECESSOR` error; authentication of all
supplied events happens first, so a forged event cannot masquerade as incomplete
history. No missing/invalid input is converted to signed `unknown` or permission.

### API and example

| API | Contract |
| --- | --- |
| `hashOperation(descriptor)` | Strict descriptor validation and domain-separated SHA-256/JCS commitment |
| `signExecutionLifecycleEvent(draft, key, history, context)` | Sign and structurally verify an append, including contradictory observations |
| `signExecutionReceiptBinding(draft, key, context)` | Sign and verify a receipt-to-operation association under the binding role |
| `verifyEvidence(artifact, context)` | Verify one artifact, expected operation, signature and outcome references; does not resolve an event's predecessor |
| `verifyExecutionHistory(history, context)` | Verify every event and the supplied graph's linkage and identities; forks and conflicting outcomes are permitted |
| `assessHistory(history, context)` | Verify the graph, then return knowledge projection and conflict information |
| `hashLifecycleEvidence(event)` / `hashReceiptBinding(binding)` | Validate shape and hash the complete signed artifact; not authentication |
| `hashExecutionReceipt(receipt)` | Hash the complete JSON receipt; not schema validation or authentication |

Run after `npm run build` as an ES module:

```js
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  hashOperation, hashLifecycleEvidence, signExecutionLifecycleEvent,
  verifyExecutionHistory, assessHistory,
} from './dist/src/index.js';

const keys = generateKeyPairSync('ed25519');
const operation = {
  kind: 'execution_operation', version: 1,
  actor: { type: 'service', id: 'worker' },
  action: { type: 'update', target: 'record-1' },
  payload: { revision: 1 }, executor: { id: 'record-api', scope: 'account-1' },
};
const context = { operation, trustedIssuers: [{
  issuer_id: 'observer', key_id: 'observer-1',
  public_key: keys.publicKey, roles: ['lifecycle'],
}] };
const metadata = {
  kind: 'execution_lifecycle', version: 1,
  operation_id: randomUUID(), request_id: 'request-1', attempt_id: randomUUID(),
  operation_hash: hashOperation(operation), issuer: 'observer',
  signature: { algorithm: 'Ed25519', key_id: 'observer-1' },
};
const dispatched = signExecutionLifecycleEvent({ ...metadata,
  event_id: randomUUID(), status: 'dispatched', basis: 'submitted',
  observed_at: '2026-09-27T12:00:00.000Z',
}, keys.privateKey, [], context);
const unresolved = signExecutionLifecycleEvent({ ...metadata,
  event_id: randomUUID(), status: 'indeterminate', basis: 'timeout_after_possible_dispatch',
  observed_at: '2026-09-27T12:00:30.000Z',
  previous_event_hash: hashLifecycleEvidence(dispatched),
}, keys.privateKey, [dispatched], context);
const history = [dispatched, unresolved];
verifyExecutionHistory(history, context);
console.log(assessHistory(history, context).state); // indeterminate
// The application decides reconciliation/retry under its own authority and delivery contract.
```

New APIs throw `LifecycleError`: `MALFORMED_EVIDENCE`, `UNTRUSTED_ISSUER`,
`INVALID_KEY`, `INVALID_SIGNATURE`, `INVALID_HISTORY`, `MISSING_PREDECESSOR`,
`INVALID_CONFIRMATION`, or `OPERATION_MISMATCH`. Referenced receipt verification
may propagate existing `EvidenceError` codes unchanged. To compare actual
before/after/result values with a referenced receipt, call the unchanged
`verifyExecutionTransition` separately.

### Trust, storage and orchestration limits

All signatures cover the complete artifact except `signature.value`, including
signed `kind`, version, issuer, key ID, identity, observation and reference fields.
Unknown fields fail closed. The profile is specific to this library and makes no
claim of compatibility with a runtime protocol or an external receipt standard.

A successful assessment describes only supplied evidence. Every result includes
`global_completeness_proven: false`. A valid prefix or isolated branch cannot prove
that a later event or another branch does not exist. Repeated verification succeeds.
Hash links do not make storage immutable or establish freshness. Applications own
accepted-head/checkpoint storage, deduplication, concurrency, retention and ingestion
size/depth limits. Graph checking here uses in-memory ancestry sets; large histories
need external limits and may incur quadratic work/storage.

Idempotency metadata is signed but does not establish provider deduplication.
The executor must enforce appropriate scope, retention and payload consistency.
Trusted observers/binding authorities may be mistaken or compromised. Receipt
hashes commit to observations; they do not prove physical truth or the causality
of a state change. Different actual effects can be hidden by identical observed
hash tuples. Missing before/after/result observations cannot be manufactured to
produce a v0.1 receipt; other outcome profiles remain future work.

Provider adapters, retry authorization/engines, backoff, scheduling, durable
execution registries, locking, saga/compensation and recovery after a crash belong
to execution/orchestration. Local atomic persistence does not make an external
side effect and its evidence recording atomic. This library provides no
exactly-once guarantee, transparency service, key lifecycle management or general
agent governance framework.

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
cloud services, UI, receipt chaining, or persistence are included.

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
Receipt chaining is deferred to v0.2 and would not itself make storage immutable.

## Tests and license

Tests cover deterministic hashing, key-order independence, nested changes,
invalid JSON, signature tampering, wrong keys, malformed receipts, all transition
mismatches, detached copies, and explicit replay behavior.

Licensed under [Apache-2.0](LICENSE).

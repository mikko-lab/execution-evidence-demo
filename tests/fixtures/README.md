# Execution receipt v1 compatibility vector

`execution-receipt-v1.json` is a fixed, generic counter-increment example.
It contains a public Ed25519 key, a signed receipt, all three observations, and
the exact canonical unsigned receipt string. Do not regenerate it during tests:
its purpose is to detect compatibility changes across implementation versions.

The fixture was generated independently of the TypeScript receipt library and
its `canonicalize` dependency:

- SHA-256 hashes were computed with Python hashlib from the explicit UTF-8 bytes
  `{"counter":0}`, `{"counter":1}`, and `{"ok":true}` (no trailing newline).
- Receipt keys were sorted with compact Python JSON serialization. All keys and
  strings here are ASCII and numbers are small integers, so this particular
  payload follows JCS. This technique is not a general JCS implementation.
- OpenSSL 3.6.4 generated a temporary Ed25519 key and signed the unsigned bytes
  using `openssl pkeyutl -sign -rawin`. The signature was checked separately with
  `openssl pkeyutl -verify -rawin -pubin` before exporting the fixture.
- Only the public key was retained. The temporary signing key was removed and
  is not needed to run or verify the test.

The test checks canonical bytes, the external signature, the receipt API, and
all three state/result bindings. A changed after-state is rejected as well.
OpenSSL CLI and Python are not test-time dependencies. The CLI and Node crypto
both use OpenSSL; this vector is independent of our signing/canonicalization
code, not evidence of validation by a separate cryptographic implementation.
This is one regression vector, not a complete JCS or Ed25519 conformance suite.

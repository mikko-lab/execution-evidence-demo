import { generateKeyPairSync, randomUUID, verify } from 'node:crypto';
import canonicalize from 'canonicalize';
import {
  createExecutionReceipt, signExecutionReceipt, verifyExecutionReceipt, verifyExecutionTransition,
  ExecutionReceiptV1, EvidenceErrorCode, UnsignedExecutionReceiptV1,
} from '../src/index.js';

const keys = generateKeyPairSync('ed25519');
const authority = { keyId: 'reference-key-1', publicKey: keys.publicKey };
const before = { counter: 0 }, after = { counter: 1 }, result = { ok: true };
function draft() {
  return createExecutionReceipt({
    execution_id: randomUUID(), request_id: 'request-1', actor: { type: 'service', id: 'counter-worker' },
    action: { type: 'increment', target: 'counter' }, before, after, result,
    executed_at: '2026-09-26T12:00:00.000Z', key_id: authority.keyId,
  });
}
function receipt() { return signExecutionReceipt(draft(), keys.privateKey); }
function errorCode(fn: () => unknown, code: EvidenceErrorCode) {
  expect(fn).toThrow(expect.objectContaining({ name: 'EvidenceError', code }));
}

describe('signed execution receipts', () => {
  test('valid signature survives JSON transport and binds independently reconstructed payload', () => {
    const r = receipt();
    expect(verifyExecutionReceipt(JSON.parse(JSON.stringify(r)), authority)).toBe(true);
    const { value, ...metadata } = r.signature;
    const payload = { ...r, signature: metadata };
    expect(verify(null, Buffer.from(canonicalize(payload)!), keys.publicKey, Buffer.from(value, 'base64'))).toBe(true);
  });
  test.each<[string, (r: ExecutionReceiptV1) => void]>([
    ['actor id', r => { r.actor.id = 'other'; }],
    ['actor type', r => { r.actor.type = 'human'; }],
    ['action type', r => { r.action.type = 'reset'; }],
    ['action target', r => { r.action.target = 'other'; }],
    ['request_id', r => { r.request_id = 'request-2'; }],
    ['execution_id', r => { r.execution_id = randomUUID(); }],
    ['state_before_hash', r => { r.state_before_hash = '0'.repeat(64); }],
    ['state_after_hash', r => { r.state_after_hash = '0'.repeat(64); }],
    ['result_hash', r => { r.result_hash = '0'.repeat(64); }],
    ['executed_at', r => { r.executed_at = '2026-09-26T12:00:01.000Z'; }],
    ['signature bytes', r => { r.signature.value = Buffer.alloc(64).toString('base64'); }],
  ])('rejects modified %s', (_name, mutate) => {
    const r = receipt(); mutate(r);
    errorCode(() => verifyExecutionReceipt(r, authority), 'INVALID_SIGNATURE');
  });
  test('key_id is signed even if trusted key is configured under another id', () => {
    const r = receipt(); r.signature.key_id = 'other';
    errorCode(() => verifyExecutionReceipt(r, authority), 'KEY_ID_MISMATCH');
    errorCode(() => verifyExecutionReceipt(r, { ...authority, keyId: 'other' }), 'INVALID_SIGNATURE');
  });
  test('rejects wrong Ed25519 public key', () => {
    errorCode(() => verifyExecutionReceipt(receipt(), { ...authority, publicKey: generateKeyPairSync('ed25519').publicKey }), 'INVALID_SIGNATURE');
  });
  test('rejects non-Ed25519 keys and incorrect key roles', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    errorCode(() => signExecutionReceipt(draft(), ec.privateKey), 'INVALID_KEY');
    errorCode(() => signExecutionReceipt(draft(), keys.publicKey), 'INVALID_KEY');
    errorCode(() => verifyExecutionReceipt(receipt(), { ...authority, publicKey: keys.privateKey }), 'INVALID_KEY');
    errorCode(() => verifyExecutionReceipt(receipt(), { ...authority, publicKey: ec.publicKey }), 'INVALID_KEY');
  });
  test.each(['not base64!', '', Buffer.alloc(63).toString('base64')])('rejects malformed signature %j', value => {
    const r = receipt(); r.signature.value = value;
    errorCode(() => verifyExecutionReceipt(r, authority), 'INVALID_SIGNATURE');
  });
  test.each<[string, (r: Record<string, any>) => void]>([
    ['missing field', r => { delete r.request_id; }],
    ['unknown field', r => { r.extra = true; }],
    ['wrong version', r => { r.version = 2; }],
    ['wrong algorithm', r => { r.signature.algorithm = 'RSA'; }],
    ['invalid actor', r => { r.actor.type = 'unknown'; }],
    ['coercible actor type', r => { r.actor.type = ['service']; }],
    ['invalid hash', r => { r.result_hash = 'xyz'; }],
    ['invalid date', r => { r.executed_at = '2026-02-30T12:00:00.000Z'; }],
    ['non-UUID execution id', r => { r.execution_id = 'id'; }],
  ])('rejects malformed receipt: %s', (_name, mutate) => {
    const r = receipt(); mutate(r);
    errorCode(() => verifyExecutionReceipt(r, authority), 'MALFORMED_RECEIPT');
  });
  test('rejects noncanonical base64 even if bytes decode to a valid signature', () => {
    const r = receipt();
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const index = alphabet.indexOf(r.signature.value[85]!);
    r.signature.value = r.signature.value.slice(0, 85) + alphabet[index + 1] + '==';
    errorCode(() => verifyExecutionReceipt(r, authority), 'INVALID_SIGNATURE');
  });
  test('rejects non-object receipts and nested unexpected fields', () => {
    for (const value of [null, undefined, [], 'receipt']) {
      errorCode(() => verifyExecutionReceipt(value, authority), 'MALFORMED_RECEIPT');
    }
    const r = receipt(); Object.assign(r.actor, { extra: 1 });
    errorCode(() => verifyExecutionReceipt(r, authority), 'MALFORMED_RECEIPT');
  });
  test('creation and signing return detached snapshots without mutating inputs', () => {
    const actor = { type: 'agent' as const, id: 'worker' };
    const d = createExecutionReceipt({ ...draft(), actor, before, after, result, key_id: authority.keyId });
    actor.id = 'changed'; expect(d.actor.id).toBe('worker');
    const r = signExecutionReceipt(d, keys.privateKey);
    d.actor.id = 'changed'; d.signature.key_id = 'changed';
    expect(verifyExecutionReceipt(r, authority)).toBe(true);
    expect('value' in d.signature).toBe(false);
  });
  test('signing refuses malformed drafts and already signed receipts', () => {
    errorCode(() => signExecutionReceipt({ ...draft(), request_id: '' }, keys.privateKey), 'MALFORMED_RECEIPT');
    errorCode(() => signExecutionReceipt(receipt() as UnsignedExecutionReceiptV1, keys.privateKey), 'MALFORMED_RECEIPT');
  });
  test('transition verifies all values and rejects each mismatch', () => {
    const r = receipt();
    expect(verifyExecutionTransition(r, before, after, result, authority)).toBe(true);
    errorCode(() => verifyExecutionTransition(r, { counter: 9 }, after, result, authority), 'BEFORE_STATE_MISMATCH');
    errorCode(() => verifyExecutionTransition(r, before, { counter: 9 }, result, authority), 'AFTER_STATE_MISMATCH');
    errorCode(() => verifyExecutionTransition(r, before, after, { ok: false }, authority), 'RESULT_MISMATCH');
  });
  test('transition rejects forged receipt even when supplied values match hashes', () => {
    const r = receipt(); r.actor.id = 'forged';
    errorCode(() => verifyExecutionTransition(r, before, after, result, authority), 'INVALID_SIGNATURE');
  });
  test('repeated verification succeeds: signatures alone do not detect replay', () => {
    const r = receipt();
    expect(verifyExecutionReceipt(r, authority)).toBe(true);
    expect(verifyExecutionReceipt(r, authority)).toBe(true);
  });
});

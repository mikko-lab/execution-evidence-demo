import { jest } from '@jest/globals';
import { generateKeyPairSync, randomUUID, verify } from 'node:crypto';
import canonicalize from 'canonicalize';
import {
  hashState, hashExecutionReceipt, hashLifecycleEvidence, signExecutionLifecycleEvent,
  verifyExecutionHistory, type UnsignedExecutionLifecycleEventV1,
} from '../src/index.js';
import { context, draft, initial, observer, provider, rawSign, receipt, uncertain } from './lifecycle-helpers.js';

function confirmed(first = initial()) {
  const event = signExecutionLifecycleEvent({ ...draft(), status: 'confirmed', basis: 'verified_receipt',
    execution_receipt_hash: hashExecutionReceipt(receipt), receipt_issuer: 'provider',
    previous_event_hash: hashLifecycleEvidence(first) }, observer.privateKey, [first], context);
  return [first, event];
}

describe('append-only lifecycle evidence', () => {
  test('signature covers complete JCS payload and survives JSON key reordering', () => {
    const event = initial();
    const { value, ...metadata } = event.signature;
    expect(verify(null, Buffer.from(canonicalize({ ...event, signature: metadata })!),
      observer.publicKey, Buffer.from(value, 'base64'))).toBe(true);
    const reordered = Object.fromEntries(Object.entries(event).reverse());
    expect(verifyExecutionHistory([reordered], context)).toBe(true);
    expect(hashLifecycleEvidence(event)).toBe(hashState(reordered));
    expect(hashExecutionReceipt(receipt)).toBe(hashState(receipt));
  });

  test('verifies all four classifications with explicit bases and linked confirmation', () => {
    for (const history of [[initial()], confirmed(), uncertain(), uncertain('unknown')]) {
      expect(verifyExecutionHistory(history, context)).toBe(true);
    }
    for (const history of [uncertain(), uncertain('unknown')]) {
      const root = { ...history[1]! };
      delete root.previous_event_hash;
      expect(verifyExecutionHistory([rawSign(root)], context)).toBe(true);
    }
  });

  test('detaches input and preserves historical signatures through later observations', () => {
    const d = draft();
    const first = signExecutionLifecycleEvent(d, observer.privateKey, [], context);
    const before = hashLifecycleEvidence(first);
    d.signature.key_id = 'changed'; d.request_id = 'changed';
    const history = confirmed(first);
    expect(hashLifecycleEvidence(first)).toBe(before);
    expect(verifyExecutionHistory(history, context)).toBe(true);
    expect('value' in d.signature).toBe(false);
    history[1]!.provider_reference = 'changed';
    expect(() => verifyExecutionHistory(history, context)).toThrow();
    expect(verifyExecutionHistory([first], context)).toBe(true);
  });

  test.each<[string, (r: any) => void]>([
    ['status', r => { r.status = 'unknown'; r.basis = 'insufficient_trustworthy_evidence'; }],
    ['execution_id', r => { r.execution_id = randomUUID(); }],
    ['request_id', r => { r.request_id = 'other'; }],
    ['event_id', r => { r.event_id = randomUUID(); }],
    ['observed_at', r => { r.observed_at = '2026-09-27T12:00:01.000Z'; }],
    ['provider_reference', r => { r.provider_reference = 'other'; }],
    ['idempotency_key', r => { r.idempotency_key = 'other'; }],
    ['signature', r => { r.signature.value = Buffer.alloc(64).toString('base64'); }],
  ])('rejects tampered %s', (_name, mutate) => {
    const event = initial(); mutate(event);
    expect(() => verifyExecutionHistory([event], context)).toThrow(expect.objectContaining({ code: 'INVALID_SIGNATURE' }));
  });

  test('issuer and key_id are signed even when aliases use the same trusted key', () => {
    for (const field of ['issuer', 'key_id']) {
      const event = initial();
      if (field === 'issuer') event.issuer = 'alias'; else event.signature.key_id = 'alias';
      const alias = { ...context.trustedIssuers[0]!, issuer_id: event.issuer, key_id: event.signature.key_id };
      expect(() => verifyExecutionHistory([event], { ...context, trustedIssuers: [alias] }))
        .toThrow(expect.objectContaining({ code: 'INVALID_SIGNATURE' }));
    }
  });

  test('rejects untrusted issuers, wrong key IDs, wrong keys, role confusion and ambiguous configuration', () => {
    const event = initial();
    const trusted = context.trustedIssuers[0]!;
    for (const trustedIssuers of [[], [{ ...trusted, issuer_id: 'other' }], [{ ...trusted, key_id: 'other' }],
      [{ ...trusted, public_key: generateKeyPairSync('ed25519').publicKey }], [{ ...trusted, roles: [] }], [trusted, trusted]]) {
      expect(() => verifyExecutionHistory([event], { trustedIssuers })).toThrow();
    }
  });

  test('rejects unknown fields and invalid JSON without invoking accessors', () => {
    const getter = jest.fn(() => 'observer');
    const accessor = Object.defineProperty(draft(), 'issuer', { get: getter, enumerable: true });
    expect(() => signExecutionLifecycleEvent(accessor, observer.privateKey, [], context)).toThrow();
    expect(getter).not.toHaveBeenCalled();
    const event = initial();
    for (const value of [{ ...event, public_key: 'untrusted' }, { ...event, provider_reference: undefined },
      { ...event, observed_at: '2026-02-30T12:00:00.000Z' }, { ...event, basis: 'generic_error' },
      { ...event, status: 'toString' }, { ...event, event_id: 'not-uuid' },
      { ...event, version: 2 }, { ...event, signature: { ...event.signature, algorithm: 'RSA' } },
      Object.defineProperty({ ...event }, 'hidden', { value: 1 }), null, []]) {
      expect(() => verifyExecutionHistory([value], context)).toThrow();
    }
  });

  test('rejects noncanonical signature encodings and incorrect signing key types', () => {
    const event = initial();
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const index = alphabet.indexOf(event.signature.value[85]!);
    for (const value of ['', 'not-base64', Buffer.alloc(63).toString('base64'),
      event.signature.value.slice(0, 85) + alphabet[index + 1] + '==']) {
      expect(() => verifyExecutionHistory([{ ...event, signature: { ...event.signature, value } }], context)).toThrow();
    }
    for (const key of [observer.publicKey, generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey]) {
      expect(() => signExecutionLifecycleEvent(draft(), key, [], context)).toThrow();
    }
    expect(() => signExecutionLifecycleEvent(event as UnsignedExecutionLifecycleEventV1, observer.privateKey, [], context)).toThrow();
  });

  test('checks links, identity, time, repeated IDs and history ordering even with valid signatures', () => {
    const history = uncertain();
    for (const patch of [{ previous_event_hash: '0'.repeat(64) }, { execution_id: randomUUID() },
      { request_id: 'other' }, { idempotency_key: 'other' }, { event_id: history[0]!.event_id },
      { observed_at: '2026-09-27T11:59:59.000Z' }]) {
      expect(() => verifyExecutionHistory([history[0], rawSign({ ...history[1], ...patch })], context))
        .toThrow(expect.objectContaining({ code: 'INVALID_HISTORY' }));
    }
    const withoutKey = { ...history[1]! }; delete withoutKey.idempotency_key;
    expect(() => verifyExecutionHistory([history[0], rawSign(withoutKey)], context)).toThrow();
    expect(() => verifyExecutionHistory(history.slice().reverse(), context)).toThrow();
    expect(() => verifyExecutionHistory([history[1]], context)).toThrow();
    expect(() => verifyExecutionHistory([], context)).toThrow();
    expect(() => verifyExecutionHistory(undefined, context)).toThrow();
  });

  test('confirmed is terminal and uncertain states cannot be directly marked confirmed', () => {
    for (const history of [confirmed(), uncertain(), uncertain('unknown')]) {
      const next = rawSign({ ...confirmed()[1], event_id: randomUUID(), previous_event_hash: hashLifecycleEvidence(history[1]!) });
      expect(() => verifyExecutionHistory([...history, next], context)).toThrow();
    }
    const history = confirmed();
    for (const classification of [{ status: 'dispatched', basis: 'submitted' },
      { status: 'indeterminate', basis: 'timeout_after_dispatch' }, { status: 'unknown', basis: 'insufficient_trustworthy_evidence' }]) {
      expect(() => verifyExecutionHistory([...history, rawSign({ ...draft(), ...classification,
        previous_event_hash: hashLifecycleEvidence(history[1]!) })], context)).toThrow();
    }
    expect(() => verifyExecutionHistory([confirmed()[1]], context)).toThrow();
  });
});

describe('confirmation requires independently trusted v0.1 receipt evidence', () => {
  test('missing, wrong and tampered receipts cannot confirm an execution', () => {
    const history = confirmed();
    for (const receipts of [[], [{ ...receipt, request_id: 'wrong' }], [{ ...receipt, signature: { ...receipt.signature, value: Buffer.alloc(64).toString('base64') } }]]) {
      expect(() => verifyExecutionHistory(history, { ...context, receipts })).toThrow();
    }
    const noHash: any = { ...history[1]! }; delete noHash.execution_receipt_hash;
    expect(() => verifyExecutionHistory([history[0], rawSign(noHash)], context)).toThrow();
    const changedHash = { ...history[1], execution_receipt_hash: '0'.repeat(64) };
    expect(() => verifyExecutionHistory([history[0], changedHash], context)).toThrow();
    expect(() => verifyExecutionHistory([history[0], rawSign(changedHash)], context)).toThrow();
  });

  test('matching receipt hashes still require valid signature, execution and request binding', () => {
    const history = confirmed();
    for (const candidate of [rawSign({ ...receipt, execution_id: randomUUID() }, provider.privateKey),
      rawSign({ ...receipt, request_id: 'other' }, provider.privateKey),
      { ...receipt, signature: { ...receipt.signature, value: Buffer.alloc(64).toString('base64') } },
      rawSign({ ...receipt, executed_at: '2026-09-27T12:00:01.000Z' }, provider.privateKey)]) {
      const event = rawSign({ ...history[1], execution_receipt_hash: hashExecutionReceipt(candidate) });
      expect(() => verifyExecutionHistory([history[0], event], { ...context, receipts: [candidate] })).toThrow();
    }
  });

  test('receipt content cannot override verifier trust or substitute its own key', () => {
    const history = confirmed();
    const candidate = { ...receipt, public_key: provider.publicKey.export({ type: 'spki', format: 'pem' }) };
    const event = rawSign({ ...history[1], execution_receipt_hash: hashState(candidate) });
    expect(() => verifyExecutionHistory([history[0], event], { ...context, receipts: [candidate] })).toThrow();
    for (const patch of [{ issuer_id: 'other' }, { key_id: 'other' },
      { public_key: observer.publicKey }, { roles: [] }]) {
      const trustedIssuers = context.trustedIssuers.map(k => k.issuer_id === 'provider' ? { ...k, ...patch } : k);
      expect(() => verifyExecutionHistory(history, { ...context, trustedIssuers })).toThrow();
    }
  });
});

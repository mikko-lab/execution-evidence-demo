import { jest } from '@jest/globals';
import { generateKeyPairSync, randomUUID, verify } from 'node:crypto';
import canonicalize from 'canonicalize';
import {
  hashState, hashOperation, hashLifecycleEvidence, hashReceiptBinding, hashExecutionReceipt,
  signExecutionLifecycleEvent, signExecutionReceiptBinding, verifyEvidence, verifyExecutionHistory,
  type OperationDescriptorV1, type UnsignedExecutionLifecycleEventV1,
} from '../src/index.js';
import { context, draft, initial, observer, provider, adapter, rawSign, receipt, operation,
  uncertain, bindingDraft, outcomeContext, observed, append } from './lifecycle-helpers.js';

function code(fn: () => unknown, expected: string) {
  expect(fn).toThrow(expect.objectContaining({ code: expected }));
}

describe('operation descriptor commitment', () => {
  test('matches independently specified canonical UTF-8 bytes and ignores object key order', () => {
    const bytes = '{"action":{"target":"record-1","type":"update_record"},"actor":{"id":"record-worker","type":"service"},"executor":{"id":"record-api","scope":"account-1"},"kind":"execution_operation","payload":{"revision":1},"version":1}';
    expect(canonicalize(operation)).toBe(bytes);
    expect(hashOperation(operation)).toBe(hashState(JSON.parse(bytes)));
    expect(hashOperation(Object.fromEntries(Object.entries(operation).reverse()) as unknown as OperationDescriptorV1)).toBe(hashOperation(operation));
  });
  test.each([
    { actor: { ...operation.actor, id: 'other' } }, { action: { ...operation.action, type: 'delete_record' } },
    { action: { ...operation.action, target: 'other' } }, { payload: { revision: 2 } },
    { executor: { ...operation.executor, id: 'other' } }, { executor: { ...operation.executor, scope: 'other' } },
  ])('binds every semantic component: %j', patch => {
    const changed = { ...operation, ...patch };
    expect(hashOperation(changed)).not.toBe(hashOperation(operation));
    code(() => verifyEvidence(initial(), { ...context, operation: changed }), 'OPERATION_MISMATCH');
  });
  test.each([
    { ...operation, version: 2 }, { ...operation, payload: undefined }, { ...operation, extra: true },
    { ...operation, executor: { id: 'executor' } }, { ...operation, actor: { type: 'other', id: 'id' } },
    { ...operation, executor: { id: 'executor', scope: '' } },
  ])('rejects malformed operation descriptors', value => {
    code(() => hashOperation(value as OperationDescriptorV1), 'MALFORMED_EVIDENCE');
  });
});

describe('signed observation artifacts', () => {
  test('signature covers JCS payload and survives transport/key reordering', () => {
    const event = initial();
    const { value, ...metadata } = event.signature;
    expect(verify(null, Buffer.from(canonicalize({ ...event, signature: metadata })!), observer.publicKey, Buffer.from(value, 'base64'))).toBe(true);
    expect(verifyEvidence(JSON.parse(JSON.stringify(event)), context)).toBe(true);
    expect(hashLifecycleEvidence(event)).toBe(hashState(Object.fromEntries(Object.entries(event).reverse())));
    expect(hashExecutionReceipt(receipt)).toBe(hashState(receipt));
  });
  test.each<[string, (r: any) => void]>([
    ['status and basis', r => { r.status = 'unknown'; r.basis = 'insufficient_trustworthy_evidence'; }],
    ['logical operation', r => { r.operation_id = randomUUID(); }], ['request', r => { r.request_id = 'other'; }],
    ['attempt', r => { r.attempt_id = randomUUID(); }], ['operation', r => { r.operation_hash = '0'.repeat(64); }],
    ['event', r => { r.event_id = randomUUID(); }], ['time', r => { r.observed_at = '2026-09-27T12:00:01.000Z'; }],
    ['idempotency', r => { r.idempotency_key = 'other'; }], ['signature', r => { r.signature.value = Buffer.alloc(64).toString('base64'); }],
    ['predecessor', r => { r.previous_event_hash = '0'.repeat(64); }],
    ['retry attempt', r => { r.retry_of_attempt_id = randomUUID(); }],
  ])('rejects tampered %s', (_name, mutate) => {
    const event = initial(); mutate(event);
    code(() => verifyExecutionHistory([event], context), 'INVALID_SIGNATURE');
  });
  test('issuer and key ID are signed even when trusted aliases use the same key', () => {
    for (const field of ['issuer', 'key_id']) {
      const event = initial();
      if (field === 'issuer') event.issuer = 'alias'; else event.signature.key_id = 'alias';
      const alias = { ...context.trustedIssuers[0]!, issuer_id: event.issuer, key_id: event.signature.key_id };
      code(() => verifyEvidence(event, { ...context, trustedIssuers: [alias] }), 'INVALID_SIGNATURE');
    }
  });
  test('untrusted, ambiguous, wrong-role and wrong-key configuration cannot authenticate evidence', () => {
    const event = initial(), trusted = context.trustedIssuers[0]!;
    for (const trustedIssuers of [[], [trusted, trusted], [{ ...trusted, roles: [] }],
      [{ ...trusted, issuer_id: 'other' }], [{ ...trusted, key_id: 'other' }],
      [{ ...trusted, public_key: generateKeyPairSync('ed25519').publicKey }]]) {
      expect(() => verifyEvidence(event, { ...context, trustedIssuers })).toThrow();
    }
  });
  test('strict schema and JSON validation reject accessors without invoking them', () => {
    const getter = jest.fn(() => 'observer');
    const accessor = Object.defineProperty(draft(), 'issuer', { get: getter, enumerable: true });
    expect(() => signExecutionLifecycleEvent(accessor, observer.privateKey, [], context)).toThrow();
    expect(getter).not.toHaveBeenCalled();
    for (const value of [null, [], { ...initial(), public_key: 'untrusted' }, { ...initial(), version: 2 },
      { ...initial(), status: 'toString' }, { ...initial(), status: 'confirmed' },
      { ...initial(), observed_at: '2026-02-30T12:00:00.000Z' }, { ...initial(), event_id: 'invalid' },
      { ...initial(), idempotency_key: undefined }, { ...initial(), signature: { algorithm: 'RSA', key_id: 'key', value: '' } }]) {
      expect(() => verifyEvidence(value, context)).toThrow();
    }
  });
  test('rejects invalid key types, malformed signatures and already signed signing inputs', () => {
    for (const key of [observer.publicKey, generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey]) {
      code(() => signExecutionLifecycleEvent(draft(), key, [], context), 'INVALID_KEY');
    }
    const event = initial(), alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const index = alphabet.indexOf(event.signature.value[85]!);
    for (const value of ['', 'not-base64', Buffer.alloc(63).toString('base64'), event.signature.value.slice(0, 85) + alphabet[index + 1] + '==']) {
      code(() => verifyEvidence({ ...event, signature: { ...event.signature, value } }, context), 'INVALID_SIGNATURE');
    }
    expect(() => signExecutionLifecycleEvent(event as UnsignedExecutionLifecycleEventV1, observer.privateKey, [], context)).toThrow();
  });
  test('signing snapshots caller data and does not mutate earlier evidence', () => {
    const d = draft();
    const e = signExecutionLifecycleEvent(d, observer.privateKey, [], context);
    d.signature.key_id = 'changed'; d.request_id = 'changed';
    expect(verifyEvidence(e, context)).toBe(true);
    const oldHash = hashLifecycleEvidence(e);
    append([e], { status: 'unknown', basis: 'insufficient_trustworthy_evidence' });
    expect(hashLifecycleEvidence(e)).toBe(oldHash);
    e.request_id = 'changed'; code(() => verifyEvidence(e, context), 'INVALID_SIGNATURE');
  });
});

describe('receipt-to-operation binding', () => {
  test('independent binding role signs the exact receipt and operation/attempt association', () => {
    const ctx = outcomeContext(), binding = ctx.receiptBindings[0]!;
    expect(verifyEvidence(binding, ctx)).toBe(true);
    expect(hashReceiptBinding(binding)).toBe(hashState(binding));
    const history = uncertain(), e = observed(history, ctx);
    expect(verifyExecutionHistory([...history, e], ctx)).toBe(true);
  });
  test.each(['accepted', 'queued', 'acknowledged', 'http_success'])('%s is not outcome evidence', basis => {
    const first = initial();
    const e = rawSign({ ...draft(), previous_event_hash: hashLifecycleEvidence(first), status: 'outcome_observed', basis,
      receipt_binding_hash: '0'.repeat(64) });
    code(() => verifyExecutionHistory([first, e], context), 'MALFORMED_EVIDENCE');
  });
  test('receipt hash alone, missing binding, missing receipt and forged binding cannot confirm', () => {
    const history = uncertain(), ctx = outcomeContext(), e = observed(history, ctx);
    for (const changed of [{ ...ctx, receiptBindings: [] }, { ...ctx, receipts: [] },
      { ...ctx, receiptBindings: [rawSign(ctx.receiptBindings[0]!)] }]) {
      expect(() => verifyExecutionHistory([...history, e], changed)).toThrow();
    }
    const naked: any = { ...e }; delete naked.receipt_binding_hash;
    naked.execution_receipt_hash = hashExecutionReceipt(receipt);
    expect(() => verifyEvidence(rawSign(naked), ctx)).toThrow();
    const forged = rawSign(ctx.receiptBindings[0]!);
    code(() => verifyEvidence(forged, ctx), 'INVALID_SIGNATURE');
  });
  test('binding identity, descriptor, receipt actor/action and signatures are checked independently', () => {
    for (const patch of [{ request_id: 'other' },
      { actor: { ...operation.actor, id: 'other' } }, { action: { ...operation.action, target: 'other' } },
      { action: { ...operation.action, type: 'delete_record' } }]) {
      const r = rawSign({ ...receipt, ...patch }, provider.privateKey);
      code(() => signExecutionReceiptBinding(bindingDraft(r), adapter.privateKey, { ...context, receipts: [r] }), 'INVALID_CONFIRMATION');
    }
    const bad = { ...receipt, signature: { ...receipt.signature, value: Buffer.alloc(64).toString('base64') } };
    code(() => signExecutionReceiptBinding(bindingDraft(bad), adapter.privateKey, { ...context, receipts: [bad] }), 'INVALID_SIGNATURE');
    code(() => signExecutionReceiptBinding({ ...bindingDraft(), operation_hash: '0'.repeat(64) }, adapter.privateKey, context), 'OPERATION_MISMATCH');
  });
  test('binding for another attempt or operation cannot be borrowed by an outcome event', () => {
    const history = uncertain();
    const otherAttempt = outcomeContext(receipt, randomUUID());
    code(() => observed(history, otherAttempt), 'INVALID_CONFIRMATION');
    const ctx = outcomeContext();
    const changed = rawSign({ ...ctx.receiptBindings[0], operation_hash: '0'.repeat(64) }, adapter.privateKey);
    code(() => observed(history, { ...ctx, receiptBindings: [changed] }), 'INVALID_CONFIRMATION');
  });
  test('binding and receipt roles never come from embedded keys or from lifecycle permission', () => {
    const b = bindingDraft();
    code(() => signExecutionReceiptBinding({ ...b, issuer: 'observer', signature: draft().signature }, observer.privateKey, context), 'UNTRUSTED_ISSUER');
    const ctx = outcomeContext();
    const noReceiptRole = { ...ctx, trustedIssuers: ctx.trustedIssuers.map(k => k.issuer_id === 'provider' ? { ...k, roles: [] } : k) };
    code(() => verifyEvidence(ctx.receiptBindings[0], noReceiptRole), 'UNTRUSTED_ISSUER');
    const embedded = rawSign({ ...ctx.receiptBindings[0], public_key: 'self-asserted' }, adapter.privateKey);
    code(() => verifyEvidence(embedded, ctx), 'MALFORMED_EVIDENCE');
  });
});

describe('logical operation to actual execution binding', () => {
  test('a different valid v0.1 execution ID is accepted through its own signed binding', () => {
    const replacement = rawSign({ ...receipt, execution_id: randomUUID() }, provider.privateKey);
    expect(replacement.execution_id).not.toBe(receipt.execution_id);
    const ctx = outcomeContext(replacement), history = uncertain();
    const event = observed(history, ctx);
    expect(event).not.toHaveProperty('execution_id');
    expect(ctx.receiptBindings[0]).not.toHaveProperty('execution_id');
    expect(event.operation_id).toBe(ctx.receiptBindings[0]!.operation_id);
    expect(event.operation_id).not.toBe(replacement.execution_id);
    expect(verifyExecutionHistory([...history, event], ctx)).toBe(true);
  });
  test('changing a receipt execution ID without renewing the signed binding is rejected', () => {
    const ctx = outcomeContext(), history = uncertain(), event = observed(history, ctx);
    const replacement = rawSign({ ...receipt, execution_id: randomUUID() }, provider.privateKey);
    code(() => verifyExecutionHistory([...history, event], { ...ctx, receipts: [replacement] }), 'INVALID_CONFIRMATION');
  });
  test.each(['operation_id', 'attempt_id'] as const)('a genuine binding for a different %s cannot confirm this observation', field => {
    const binding = signExecutionReceiptBinding({ ...bindingDraft(), [field]: randomUUID() }, adapter.privateKey, context);
    expect(verifyEvidence(binding, context)).toBe(true);
    code(() => observed(uncertain(), { ...context, receipts: [receipt], receiptBindings: [binding] }), 'INVALID_CONFIRMATION');
  });
  test('the superseded lifecycle execution_id field is not silently interpreted as operation_id', () => {
    const old: any = { ...draft(), execution_id: randomUUID() };
    delete old.operation_id;
    code(() => verifyEvidence(rawSign(old), context), 'MALFORMED_EVIDENCE');
  });
});

describe('binding authority executor and tenant boundary', () => {
  test.each([
    undefined, {}, { executor_id: 'record-api' }, { scope: 'account-1' },
    { executor_id: 'other-api', scope: 'account-1' },
    { executor_id: 'record-api', scope: 'other-account' },
    { executor_id: '*', scope: 'account-1' }, { executor_id: 'record-api', scope: '*' },
    { executor_id: '', scope: 'account-1' },
    { executor_id: 'record-api', scope: 'account-1', extra: true },
  ])('missing, malformed or mismatched binding grant fails closed: %j', binding_scope => {
    const ctx = outcomeContext();
    const trustedIssuers = ctx.trustedIssuers.map(k => k.issuer_id === 'adapter' ? { ...k, binding_scope } : k);
    const wrongContext = { ...ctx, trustedIssuers } as unknown as typeof ctx;
    code(() => verifyEvidence(ctx.receiptBindings[0], wrongContext), 'UNTRUSTED_ISSUER');
    code(() => signExecutionReceiptBinding(bindingDraft(), adapter.privateKey, wrongContext), 'UNTRUSTED_ISSUER');
    const history = uncertain(), event = observed(history, ctx);
    code(() => verifyExecutionHistory([...history, event], wrongContext), 'UNTRUSTED_ISSUER');
  });
  test.each([
    { id: 'other-api', scope: 'account-1' },
    { id: 'record-api', scope: 'other-account' },
  ])('a correctly signed descriptor substitution cannot expand the configured binding scope: %j', executor => {
    const foreignOperation = { ...operation, executor };
    const foreignBinding = rawSign({ ...bindingDraft(), operation_hash: hashOperation(foreignOperation) }, adapter.privateKey);
    // Matching operation_hash and valid signature are insufficient: the external scope grant still applies.
    code(() => verifyEvidence(foreignBinding, { ...context, operation: foreignOperation }), 'UNTRUSTED_ISSUER');
    const explicitlyScoped = { ...context, operation: foreignOperation, trustedIssuers: context.trustedIssuers.map(k =>
      k.issuer_id === 'adapter' ? { ...k, binding_scope: { executor_id: executor.id, scope: executor.scope } } : k) };
    expect(verifyEvidence(foreignBinding, explicitlyScoped)).toBe(true);
  });
  test('a self-declared grant in binding evidence cannot supply verifier authority', () => {
    const injected = rawSign({ ...bindingDraft(), binding_scope: { executor_id: 'record-api', scope: 'account-1' } }, adapter.privateKey);
    code(() => verifyEvidence(injected, context), 'MALFORMED_EVIDENCE');
  });
  test('duplicate issuer/key configuration is rejected even if one scope matches', () => {
    const ctx = outcomeContext(), issuer = ctx.trustedIssuers.find(k => k.issuer_id === 'adapter')!;
    const duplicate = { ...issuer, binding_scope: { executor_id: 'other-api', scope: 'other-account' } };
    code(() => verifyEvidence(ctx.receiptBindings[0], { ...ctx, trustedIssuers: [...ctx.trustedIssuers, duplicate] }), 'UNTRUSTED_ISSUER');
  });
});

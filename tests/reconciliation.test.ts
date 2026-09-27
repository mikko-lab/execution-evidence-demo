import { randomUUID } from 'node:crypto';
import {
  evaluateRetryDisposition, hashLifecycleEvidence, hashExecutionReceipt, hashResult, signExecutionLifecycleEvent, signExecutionReconciliation,
  signRetryDispatch, verifyExecutionHistory, type VerificationContext,
} from '../src/index.js';
import { context, draft, identity, initial, observer, provider, rawSign, receipt, reconciler, reconciliation, time, uncertain } from './lifecycle-helpers.js';

const retryContext: VerificationContext = { ...context, retryPolicy: { ...identity, side_effect_free: true } };
const observation = () => ({ event_id: randomUUID(), observed_at: time, issuer: 'observer', key_id: 'observer-key' });

describe('authoritative append-only reconciliation', () => {
  test.each(['dispatched', 'indeterminate', 'unknown'] as const)('resolves %s with trusted receipt evidence, preserving history', status => {
    const history = status === 'dispatched' ? [initial()] : uncertain(status);
    const before = history.map(hashLifecycleEvidence);
    const event = signExecutionReconciliation(reconciliation(history), reconciler.privateKey, history, context);
    expect(verifyExecutionHistory([...history, event], context)).toBe(true);
    expect(history.map(hashLifecycleEvidence)).toEqual(before);
    expect(evaluateRetryDisposition([...history, event], context)).toBe('do_not_retry');
    expect(() => verifyExecutionHistory([event], context)).toThrow();
  });

  test('forged reconciliation, issuer substitution and role confusion fail closed', () => {
    const history = uncertain();
    const event = signExecutionReconciliation(reconciliation(history), reconciler.privateKey, history, context);
    for (const changed of [rawSign(event), { ...event, issuer: 'observer' },
      { ...event, signature: { ...event.signature, key_id: 'observer-key' } },
      { ...event, reconciliation_id: randomUUID() }, { ...event, execution_receipt_hash: '0'.repeat(64) },
      { ...event, status: 'unknown', basis: 'insufficient_trustworthy_evidence' }]) {
      expect(() => verifyExecutionHistory([...history, changed], context)).toThrow();
    }
    const unauthorized = rawSign({ ...event, issuer: 'observer',
      signature: { algorithm: 'Ed25519', key_id: 'observer-key' } });
    expect(() => verifyExecutionHistory([...history, unauthorized], context))
      .toThrow(expect.objectContaining({ code: 'UNTRUSTED_ISSUER' }));
  });

  test('correctly signed reconciliation cannot switch execution, request, idempotency identity or evaluated evidence', () => {
    const history = uncertain();
    for (const patch of [{ execution_id: randomUUID() }, { request_id: 'other' },
      { idempotency_key: 'other' }, { previous_event_hash: hashLifecycleEvidence(history[0]!) },
      { observed_at: '2026-09-27T11:59:59.000Z' }, { receipt_issuer: 'observer' }]) {
      const event = rawSign({ ...reconciliation(history), ...patch }, reconciler.privateKey);
      expect(() => verifyExecutionHistory([...history, event], context)).toThrow();
    }
  });

  test('there is no mark-as-confirmed escape hatch, including at signing time', () => {
    const history = uncertain();
    expect(() => signExecutionReconciliation(reconciliation(history), reconciler.privateKey, history,
      { ...context, receipts: [] })).toThrow();
    expect(() => signExecutionLifecycleEvent({ ...draft(), status: 'confirmed', basis: 'verified_receipt',
      execution_receipt_hash: reconciliation(history).execution_receipt_hash, receipt_issuer: 'provider',
      previous_event_hash: hashLifecycleEvidence(history[1]!) }, observer.privateKey, history, context)).toThrow();
    const malformed: any = reconciliation(history); delete malformed.execution_receipt_hash;
    expect(() => signExecutionReconciliation(malformed, reconciler.privateKey, history, context)).toThrow();
    const event = signExecutionReconciliation(reconciliation(history), reconciler.privateKey, history, context);
    expect(() => signExecutionReconciliation(reconciliation([...history, event]), reconciler.privateKey,
      [...history, event], context)).toThrow();
  });
});

describe('uncertainty and conservative retry disposition', () => {
  test('timeout after dispatch is indeterminate, never success or definite failure', () => {
    const history = uncertain();
    expect(history[1]!.status).toBe('indeterminate');
    expect(history[1]!.basis).toBe('timeout_after_dispatch');
    expect(history[1]).not.toHaveProperty('execution_receipt_hash');
    expect(evaluateRetryDisposition(history, context)).toBe('reconciliation_required');
    expect(() => signRetryDispatch(history, observation(), observer.privateKey, context)).toThrow();
  });

  test('all supported post-dispatch uncertainty reasons remain unresolved', () => {
    const first = initial();
    for (const basis of ['timeout_after_dispatch', 'transport_after_dispatch', 'acknowledgement_lost', 'unresolved_provider_effect'] as const) {
      const event = signExecutionLifecycleEvent({ ...draft(), status: 'indeterminate', basis,
        previous_event_hash: hashLifecycleEvidence(first) }, observer.privateKey, [first], context);
      expect(evaluateRetryDisposition([first, event], context)).toBe('reconciliation_required');
    }
  });

  test('dispatched, unknown, missing and invalid evidence never grant retry by default', () => {
    const tampered = initial(); tampered.request_id = 'forged';
    for (const history of [[initial()], uncertain('unknown'), [], undefined, null, [tampered]]) {
      expect(evaluateRetryDisposition(history, context)).toBe('reconciliation_required');
    }
    for (const history of [uncertain('unknown'), [], undefined, [tampered]]) {
      expect(evaluateRetryDisposition(history, retryContext)).toBe('reconciliation_required');
    }
  });

  test('safe retry needs explicit identity-scoped side-effect-free verifier policy', () => {
    const history = uncertain();
    expect(evaluateRetryDisposition(history, retryContext)).toBe('safe_to_retry');
    expect(evaluateRetryDisposition([initial()], retryContext)).toBe('safe_to_retry');
    for (const retryPolicy of [{ ...identity, side_effect_free: false },
      { ...identity, execution_id: randomUUID(), side_effect_free: true },
      { ...identity, request_id: 'other', side_effect_free: true },
      { ...identity, idempotency_key: 'other', side_effect_free: true }]) {
      expect(evaluateRetryDisposition(history, { ...context, retryPolicy } as VerificationContext)).toBe('reconciliation_required');
    }
    // Possession of an idempotency key alone proves nothing about provider deduplication.
    expect(evaluateRetryDisposition(history, context)).toBe('reconciliation_required');
  });

  test('retry evidence preserves execution, request and idempotency identity and binds its predecessor', () => {
    const history = uncertain();
    const retry = signRetryDispatch(history, observation(), observer.privateKey, retryContext);
    expect(retry).toMatchObject(identity);
    expect(retry.retry_of).toBe(hashLifecycleEvidence(history[1]!));
    expect(retry.previous_event_hash).toBe(retry.retry_of);
    expect(verifyExecutionHistory([...history, retry], retryContext)).toBe(true);
    expect(() => verifyExecutionHistory([...history, retry], context)).toThrow();
    for (const patch of [{ execution_id: randomUUID() }, { request_id: 'other' }, { idempotency_key: 'other' },
      { retry_of: '0'.repeat(64) }, { status: 'indeterminate', basis: 'timeout_after_dispatch' }]) {
      expect(() => verifyExecutionHistory([...history, rawSign({ ...retry, ...patch })], retryContext)).toThrow();
    }
    const missingMarker = { ...retry }; delete missingMarker.retry_of;
    expect(() => verifyExecutionHistory([...history, rawSign(missingMarker)], retryContext)).toThrow();
  });

  test('idempotency is optional but cannot be added partway through a history', () => {
    const d = draft(); delete d.idempotency_key;
    const first = signExecutionLifecycleEvent(d, observer.privateKey, [], context);
    const policy = { execution_id: identity.execution_id, request_id: identity.request_id, side_effect_free: true as const };
    const localContext = { ...context, retryPolicy: policy };
    const retry = signRetryDispatch([first], observation(), observer.privateKey, localContext);
    expect(retry).not.toHaveProperty('idempotency_key');
    expect(verifyExecutionHistory([first, retry], localContext)).toBe(true);
    expect(() => verifyExecutionHistory([first, rawSign({ ...retry, idempotency_key: 'new' })], localContext)).toThrow();
  });

  test('confirmed means known result, not permission to retry or a claim of business success', () => {
    const history = uncertain();
    const event = signExecutionReconciliation(reconciliation(history), reconciler.privateKey, history, context);
    expect(evaluateRetryDisposition([...history, event], retryContext)).toBe('do_not_retry');
    expect(() => signRetryDispatch([...history, event], observation(), observer.privateKey, retryContext)).toThrow();
    const negativeReceipt = rawSign({ ...receipt, state_after_hash: receipt.state_before_hash,
      result_hash: hashResult({ applied: false, reason: 'operation_rejected' }) }, provider.privateKey);
    const negativeContext = { ...retryContext, receipts: [negativeReceipt] };
    const knownRejection = signExecutionReconciliation({ ...reconciliation(history),
      execution_receipt_hash: hashExecutionReceipt(negativeReceipt) }, reconciler.privateKey, history, negativeContext);
    expect(knownRejection.status).toBe('confirmed');
    expect(evaluateRetryDisposition([...history, knownRejection], negativeContext)).toBe('do_not_retry');
  });
});

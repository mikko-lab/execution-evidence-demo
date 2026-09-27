import { randomUUID } from 'node:crypto';
import * as api from '../src/index.js';
import { assessHistory, verifyEvidence, verifyExecutionHistory, hashLifecycleEvidence, hashReceiptBinding,
  signExecutionLifecycleEvent, type UnsignedExecutionLifecycleEventV1 } from '../src/index.js';
import { append, context, draft, initial, observer, uncertain, rawSign, operation, outcomeContext,
  observed, makeReceipt, attemptId, identity } from './lifecycle-helpers.js';

function code(fn: () => unknown, expected: string) {
  expect(fn).toThrow(expect.objectContaining({ code: expected }));
}

describe('append-only knowledge assessment', () => {
  test('unknown refines to dispatch when a genuine observation arrives', () => {
    const first = initial('unknown');
    const e = append([first], { status: 'dispatched', basis: 'submitted' });
    expect(assessHistory([first, e], context).state).toBe('dispatched');
  });
  test('a later unknown cannot erase dispatch knowledge', () => {
    const first = initial();
    const e = append([first], { status: 'unknown', basis: 'insufficient_trustworthy_evidence' });
    expect(assessHistory([first, e], context).state).toBe('dispatched');
  });
  test.each(['timeout_after_possible_dispatch', 'connection_lost', 'acknowledgement_lost', 'partial_effect_unresolved', 'unresolved_provider_effect'] as const)(
    '%s means unresolved effect, never success, failure or no-effect', basis => {
      const first = initial();
      const e = append([first], { status: 'indeterminate', basis });
      const assessment = assessHistory([first, e], context);
      expect(assessment.state).toBe('indeterminate');
      expect(assessment.outcome_receipt_hashes).toEqual([]);
      expect(assessment).not.toHaveProperty('safe_to_retry');
    },
  );
  test.each(['dispatched', 'indeterminate', 'unknown'] as const)('%s can acquire bound outcome evidence', status => {
    const history = status === 'indeterminate' ? uncertain() : [initial(status)];
    const ctx = outcomeContext(), e = observed(history, ctx);
    expect(assessHistory([...history, e], ctx).state).toBe('outcome_observed');
  });
  test('late evidence and older observation times can be appended without rewriting signatures', () => {
    const history = uncertain(), old = history.map(hashLifecycleEvidence), ctx = outcomeContext();
    const e = observed(history, ctx, { observed_at: '2026-09-27T11:00:00.000Z' });
    expect(assessHistory([...history, e], ctx).state).toBe('outcome_observed');
    expect(history.map(hashLifecycleEvidence)).toEqual(old);
    expect(assessHistory([e, ...history].reverse(), ctx)).toEqual(assessHistory([...history, e], ctx));
  });
  test('timeout and unknown observations cannot erase an already observed outcome', () => {
    const first = initial(), ctx = outcomeContext(), e = observed([first], ctx);
    const timeout = append([first, e], { status: 'indeterminate', basis: 'timeout_after_possible_dispatch' }, ctx);
    const unknown = append([first, e, timeout], { status: 'unknown', basis: 'insufficient_trustworthy_evidence' }, ctx);
    expect(assessHistory([first, e, timeout, unknown], ctx).state).toBe('outcome_observed');
  });
  test('repeated uncertain observations remain recordable', () => {
    const history = uncertain();
    const next = append(history, { status: 'indeterminate', basis: 'unresolved_provider_effect' });
    expect(assessHistory([...history, next], context).state).toBe('indeterminate');
  });
  test('known application rejection is an observed outcome, not a retry authorization', () => {
    const ctx = outcomeContext(makeReceipt({ revision: 0 }, { applied: false, reason: 'rejected' }));
    const history = uncertain(), e = observed(history, ctx);
    expect(assessHistory([...history, e], ctx).state).toBe('outcome_observed');
    expect(assessHistory([...history, e], ctx)).not.toHaveProperty('authorizeNextAction');
  });
});

describe('forks and contradictory observations', () => {
  test('two authentic incompatible outcome branches are retained and assess as conflict', () => {
    const first = initial(), a = outcomeContext(), b = outcomeContext(makeReceipt({ revision: 2 }));
    const left = observed([first], a), right = observed([first], b);
    const ctx = { ...context, receipts: [...a.receipts, ...b.receipts], receiptBindings: [...a.receiptBindings, ...b.receiptBindings] };
    const history = [first, left, right], saved = history.map(hashLifecycleEvidence);
    expect(verifyEvidence(left, ctx)).toBe(true);
    expect(verifyEvidence(right, ctx)).toBe(true);
    expect(verifyExecutionHistory(history, ctx)).toBe(true);
    const assessment = assessHistory(history, ctx);
    expect(assessment.state).toBe('conflict');
    expect(assessment.heads).toHaveLength(2);
    expect(assessment.conflicting_event_ids).toEqual([left.event_id, right.event_id].sort());
    expect(assessment.outcome_receipt_hashes).toHaveLength(2);
    expect(assessHistory(history.slice().reverse(), ctx)).toEqual(assessment);
    expect(history.map(hashLifecycleEvidence)).toEqual(saved);
    expect(assessHistory([first, left], ctx)).toMatchObject({ state: 'outcome_observed', global_completeness_proven: false });
  });
  test('outcome-observed is not terminal: contradictory evidence may be appended later', () => {
    const first = initial(), a = outcomeContext(), b = outcomeContext(makeReceipt({ revision: 0 }, { applied: false }));
    const left = observed([first], a);
    const ctx = { ...context, receipts: [...a.receipts, ...b.receipts], receiptBindings: [...a.receiptBindings, ...b.receiptBindings] };
    const right = append([first, left], { status: 'outcome_observed', basis: 'verified_receipt_binding',
      receipt_binding_hash: hashReceiptBinding(b.receiptBindings[0]!), observed_at: '2026-09-28T12:00:00.000Z' }, ctx);
    expect(assessHistory([first, left, right], ctx).state).toBe('conflict');
  });
  test('conflict survives later unknown, timeout and supporting outcome observations', () => {
    const first = initial(), a = outcomeContext(), b = outcomeContext(makeReceipt({ revision: 2 }));
    const left = observed([first], a), right = observed([first], b);
    const ctx = { ...context, receipts: [...a.receipts, ...b.receipts], receiptBindings: [...a.receiptBindings, ...b.receiptBindings] };
    const history = [first, left, right];
    history.push(append(history, { status: 'unknown', basis: 'insufficient_trustworthy_evidence' }, ctx));
    history.push(append(history, { status: 'indeterminate', basis: 'connection_lost' }, ctx));
    history.push(append(history, { status: 'outcome_observed', basis: 'verified_receipt_binding',
      receipt_binding_hash: hashReceiptBinding(a.receiptBindings[0]!) }, ctx));
    expect(assessHistory(history, ctx).state).toBe('conflict');
  });
  test('different observations of the same outcome are not automatically conflicting', () => {
    const first = initial(), ctx = outcomeContext();
    const a = observed([first], ctx), b = observed([first], ctx);
    expect(assessHistory([first, a, b], ctx).state).toBe('outcome_observed');
    expect(assessHistory([first, a, b], ctx).outcome_receipt_hashes).toHaveLength(1);
  });
  test('same IDs with a different operation hash fail closed instead of becoming an ordinary status', () => {
    const first = initial();
    const otherHash = api.hashOperation({ ...operation, payload: { revision: 2 } });
    const changed = rawSign({ ...draft(), previous_event_hash: hashLifecycleEvidence(first), operation_hash: otherHash });
    code(() => verifyExecutionHistory([first, changed], context), 'OPERATION_MISMATCH');
    code(() => assessHistory([first, changed], context), 'OPERATION_MISMATCH');
  });
});

describe('execution identity, delivery attempts and policy independence', () => {
  test('retry observations keep logical identity, use a new attempt and preserve old evidence', () => {
    const history = uncertain(), before = history.map(hashLifecycleEvidence), nextAttempt = randomUUID();
    const retry = append(history, { attempt_id: nextAttempt, retry_of_attempt_id: attemptId });
    expect(retry).toMatchObject(identity);
    expect(retry.attempt_id).not.toBe(attemptId);
    expect(history.map(hashLifecycleEvidence)).toEqual(before);
    const assessment = assessHistory([...history, retry], context);
    expect(assessment.attempts).toEqual(expect.arrayContaining([
      { attempt_id: attemptId, state: 'indeterminate' }, { attempt_id: nextAttempt, state: 'dispatched' },
    ]));
  });
  test('current retry-policy values never affect historical evidence verification or assessment', () => {
    const history = uncertain();
    history.push(append(history, { attempt_id: randomUUID(), retry_of_attempt_id: attemptId }));
    const expected = assessHistory(history, context);
    for (const retryPolicy of [undefined, { side_effect_free: false }, { side_effect_free: true }, { deny: true }]) {
      const localContext = { ...context, retryPolicy };
      expect(verifyExecutionHistory(history, localContext)).toBe(true);
      expect(assessHistory(history, localContext)).toEqual(expected);
    }
    expect(api).not.toHaveProperty('evaluateRetryDisposition');
    expect(api).not.toHaveProperty('signRetryDispatch');
    expect(api).not.toHaveProperty('authorizeNextAction');
  });
  test('new attempts cannot masquerade as new independent operations or self-retries', () => {
    const history = uncertain();
    for (const patch of [{ attempt_id: randomUUID() }, { retry_of_attempt_id: attemptId },
      { attempt_id: randomUUID(), retry_of_attempt_id: randomUUID() },
      { execution_id: randomUUID(), attempt_id: randomUUID(), retry_of_attempt_id: attemptId },
      { request_id: 'other', attempt_id: randomUUID(), retry_of_attempt_id: attemptId }]) {
      expect(() => append(history, patch)).toThrow();
    }
  });
  test('attempt metadata and idempotency identity cannot change within a history', () => {
    const history = uncertain(), second = randomUUID();
    history.push(append(history, { attempt_id: second, retry_of_attempt_id: attemptId }));
    const changed = rawSign({ ...draft(), attempt_id: second, previous_event_hash: hashLifecycleEvidence(history.at(-1)!) });
    code(() => verifyExecutionHistory([...history, changed], context), 'INVALID_HISTORY');
    code(() => append(history, { idempotency_key: 'changed' }), 'INVALID_HISTORY');
    const omitted: any = { ...draft(), previous_event_hash: hashLifecycleEvidence(history[0]!) };
    delete omitted.idempotency_key;
    code(() => verifyExecutionHistory([history[0], rawSign(omitted)], context), 'INVALID_HISTORY');
  });
  test('late outcome for the original attempt remains attributable after a retry', () => {
    const history = uncertain(), next = randomUUID();
    history.push(append(history, { attempt_id: next, retry_of_attempt_id: attemptId }));
    const ctx = outcomeContext();
    history.push(observed(history, ctx));
    const assessment = assessHistory(history, ctx);
    expect(assessment.state).toBe('outcome_observed');
    expect(assessment.attempts).toEqual(expect.arrayContaining([
      { attempt_id: attemptId, state: 'outcome_observed' }, { attempt_id: next, state: 'dispatched' },
    ]));
  });
});

describe('structural verification is separate from assessment', () => {
  test('missing predecessor is distinct from invalid signature, including with both defects present', () => {
    const history = uncertain(), linked = history[1]!;
    expect(verifyEvidence(linked, context)).toBe(true); // single-artifact check cannot prove linkage
    code(() => verifyExecutionHistory([linked], context), 'MISSING_PREDECESSOR');
    code(() => assessHistory([linked], context), 'MISSING_PREDECESSOR');
    const forged = { ...linked, signature: { ...linked.signature, value: Buffer.alloc(64).toString('base64') } };
    code(() => verifyExecutionHistory([forged], context), 'INVALID_SIGNATURE');
  });
  test('untrusted or absent input never becomes signed unknown or a safe outcome', () => {
    for (const history of [[], null, undefined]) code(() => assessHistory(history, context), history === undefined ? 'MALFORMED_EVIDENCE' : 'INVALID_HISTORY');
    code(() => assessHistory([initial()], { ...context, trustedIssuers: [] }), 'UNTRUSTED_ISSUER');
  });
  test('duplicate IDs are rejected even when events carry valid signatures', () => {
    const first = initial();
    const duplicate = rawSign({ ...draft(), event_id: first.event_id, previous_event_hash: hashLifecycleEvidence(first) });
    code(() => verifyExecutionHistory([first, duplicate], context), 'INVALID_HISTORY');
    code(() => verifyExecutionHistory([first, first], context), 'INVALID_HISTORY');
  });
  test('valid prefixes and repeated verification do not establish freshness or prevent replay', () => {
    const history = uncertain();
    expect(verifyExecutionHistory(history, context)).toBe(true);
    expect(verifyExecutionHistory(history, context)).toBe(true);
    expect(assessHistory([history[0]], context)).toMatchObject({ state: 'dispatched', global_completeness_proven: false });
  });
  test('root unknown and root bound outcome need no invented dispatch history', () => {
    expect(assessHistory([initial('unknown')], context).state).toBe('unknown');
    const ctx = outcomeContext();
    const root = signExecutionLifecycleEvent({ ...draft(), status: 'outcome_observed', basis: 'verified_receipt_binding',
      receipt_binding_hash: hashReceiptBinding(ctx.receiptBindings[0]!) } as UnsignedExecutionLifecycleEventV1,
    observer.privateKey, [], ctx);
    expect(assessHistory([root], ctx)).toMatchObject({ state: 'outcome_observed', global_completeness_proven: false });
  });
});

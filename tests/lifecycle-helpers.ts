import canonicalize from 'canonicalize';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  createExecutionReceipt, signExecutionReceipt, hashOperation, hashExecutionReceipt, hashReceiptBinding,
  hashLifecycleEvidence, signExecutionLifecycleEvent, signExecutionReceiptBinding,
  type ExecutionLifecycleEventV1, type ExecutionReceiptV1, type OperationDescriptorV1,
  type UnsignedExecutionLifecycleEventV1, type UnsignedExecutionReceiptBindingV1, type VerificationContext,
} from '../src/index.js';

export const observer = generateKeyPairSync('ed25519');
export const provider = generateKeyPairSync('ed25519');
export const adapter = generateKeyPairSync('ed25519');
export const operation: OperationDescriptorV1 = {
  kind: 'execution_operation', version: 1,
  actor: { type: 'service', id: 'record-worker' }, action: { type: 'update_record', target: 'record-1' },
  payload: { revision: 1 }, executor: { id: 'record-api', scope: 'account-1' },
};
export const identity = { execution_id: randomUUID(), request_id: 'request-1', operation_hash: hashOperation(operation) };
export const attemptId = randomUUID();
export const time = '2026-09-27T12:00:00.000Z';
export function makeReceipt(after = { revision: 1 }, result: unknown = { applied: true }): ExecutionReceiptV1 {
  return signExecutionReceipt(createExecutionReceipt({
    ...identity, actor: operation.actor, action: operation.action, before: { revision: 0 }, after, result,
    executed_at: time, key_id: 'provider-key',
  }), provider.privateKey);
}
export const receipt = makeReceipt();
export const context: VerificationContext = {
  operation,
  trustedIssuers: [
    { issuer_id: 'observer', key_id: 'observer-key', public_key: observer.publicKey, roles: ['lifecycle'] },
    { issuer_id: 'provider', key_id: 'provider-key', public_key: provider.publicKey, roles: ['receipt'] },
    { issuer_id: 'adapter', key_id: 'adapter-key', public_key: adapter.publicKey, roles: ['receipt_binding'] },
  ],
  receipts: [receipt],
};
export function draft(): UnsignedExecutionLifecycleEventV1 {
  return { kind: 'execution_lifecycle', version: 1, event_id: randomUUID(), ...identity, attempt_id: attemptId,
    status: 'dispatched', basis: 'submitted', observed_at: time, issuer: 'observer', idempotency_key: 'operation-1',
    signature: { algorithm: 'Ed25519', key_id: 'observer-key' } };
}
export function initial(status: 'dispatched' | 'unknown' = 'dispatched') {
  const classification = status === 'unknown'
    ? { status, basis: 'insufficient_trustworthy_evidence' as const }
    : { status, basis: 'submitted' as const };
  return signExecutionLifecycleEvent({ ...draft(), ...classification }, observer.privateKey, [], context);
}
export function append(history: ExecutionLifecycleEventV1[], patch: Partial<UnsignedExecutionLifecycleEventV1>, ctx = context) {
  return signExecutionLifecycleEvent({ ...draft(), previous_event_hash: hashLifecycleEvidence(history.at(-1)!), ...patch } as
    UnsignedExecutionLifecycleEventV1, observer.privateKey, history, ctx);
}
export function uncertain() {
  const first = initial();
  return [first, append([first], { status: 'indeterminate', basis: 'timeout_after_possible_dispatch' })];
}
export function bindingDraft(r = receipt, attempt = attemptId): UnsignedExecutionReceiptBindingV1 {
  return { kind: 'execution_receipt_binding', version: 1, binding_id: randomUUID(), ...identity, attempt_id: attempt,
    observed_at: time, issuer: 'adapter', signature: { algorithm: 'Ed25519', key_id: 'adapter-key' },
    execution_receipt_hash: hashExecutionReceipt(r), receipt_issuer: 'provider' };
}
export function outcomeContext(r = receipt, attempt = attemptId) {
  const ctx = { ...context, receipts: [r] };
  const binding = signExecutionReceiptBinding(bindingDraft(r, attempt), adapter.privateKey, ctx);
  return { ...ctx, receiptBindings: [binding] };
}
export function observed(history: ExecutionLifecycleEventV1[], ctx = outcomeContext(), patch: Partial<Omit<UnsignedExecutionLifecycleEventV1, 'status' | 'basis'>> = {}) {
  return append(history, { status: 'outcome_observed', basis: 'verified_receipt_binding',
    receipt_binding_hash: hashReceiptBinding(ctx.receiptBindings[0]!), ...patch }, ctx);
}
// Bypass production signing checks to exercise hostile but correctly signed artifacts.
export function rawSign(value: any, key = observer.privateKey): any {
  const { value: _oldSignature, ...signature } = value.signature;
  const payload = { ...value, signature };
  return { ...payload, signature: { ...signature, value: sign(null, Buffer.from(canonicalize(payload)!), key).toString('base64') } };
}

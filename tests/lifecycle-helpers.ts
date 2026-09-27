import canonicalize from 'canonicalize';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  createExecutionReceipt, signExecutionReceipt, hashExecutionReceipt, hashLifecycleEvidence,
  signExecutionLifecycleEvent, type LifecycleEvidence, type UnsignedExecutionLifecycleEventV1,
  type UnsignedExecutionReconciliationV1, type VerificationContext,
} from '../src/index.js';

export const observer = generateKeyPairSync('ed25519');
export const provider = generateKeyPairSync('ed25519');
export const reconciler = generateKeyPairSync('ed25519');
export const identity = { execution_id: randomUUID(), request_id: 'request-1', idempotency_key: 'operation-1' };
export const time = '2026-09-27T12:00:00.000Z';
export const receipt = signExecutionReceipt(createExecutionReceipt({
  ...identity, actor: { type: 'service', id: 'record-worker' }, action: { type: 'update_record', target: 'record-1' },
  before: { revision: 0 }, after: { revision: 1 }, result: { applied: true }, executed_at: time, key_id: 'provider-key',
}), provider.privateKey);
export const context: VerificationContext = {
  trustedIssuers: [
    { issuer_id: 'observer', key_id: 'observer-key', public_key: observer.publicKey, roles: ['lifecycle'] },
    { issuer_id: 'provider', key_id: 'provider-key', public_key: provider.publicKey, roles: ['receipt'] },
    { issuer_id: 'reconciler', key_id: 'reconciler-key', public_key: reconciler.publicKey, roles: ['reconciliation'] },
  ],
  receipts: [receipt],
};
export function draft(): UnsignedExecutionLifecycleEventV1 {
  return { kind: 'execution_lifecycle', version: 1, event_id: randomUUID(), ...identity,
    status: 'dispatched', basis: 'submitted', observed_at: time, issuer: 'observer',
    provider_reference: 'operation-reference-1', signature: { algorithm: 'Ed25519', key_id: 'observer-key' } };
}
export function initial() { return signExecutionLifecycleEvent(draft(), observer.privateKey, [], context); }
export function uncertain(status: 'indeterminate' | 'unknown' = 'indeterminate') {
  const first = initial();
  const classification = status === 'indeterminate'
    ? { status: 'indeterminate' as const, basis: 'timeout_after_dispatch' as const }
    : { status: 'unknown' as const, basis: 'insufficient_trustworthy_evidence' as const };
  const last = signExecutionLifecycleEvent({ ...draft(), ...classification,
    previous_event_hash: hashLifecycleEvidence(first) }, observer.privateKey, [first], context);
  return [first, last];
}
export function reconciliation(history: LifecycleEvidence[]): UnsignedExecutionReconciliationV1 {
  return { kind: 'execution_reconciliation', version: 1, reconciliation_id: randomUUID(), ...identity,
    status: 'confirmed', basis: 'verified_receipt', observed_at: time, issuer: 'reconciler',
    signature: { algorithm: 'Ed25519', key_id: 'reconciler-key' },
    previous_event_hash: hashLifecycleEvidence(history[history.length - 1]!),
    execution_receipt_hash: hashExecutionReceipt(receipt), receipt_issuer: 'provider' };
}
// Deliberately bypass production signing guards to test hostile, correctly signed input.
export function rawSign(value: any, key = observer.privateKey): any {
  const { value: _oldSignature, ...signature } = value.signature;
  const payload = { ...value, signature };
  return { ...payload, signature: { ...signature, value: sign(null, Buffer.from(canonicalize(payload)!), key).toString('base64') } };
}

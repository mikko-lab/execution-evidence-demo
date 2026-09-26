import canonicalize from 'canonicalize';
import { createHash, KeyObject, sign, verify } from 'node:crypto';

export type EvidenceErrorCode =
  | 'INVALID_JSON' | 'MALFORMED_RECEIPT' | 'INVALID_KEY' | 'KEY_ID_MISMATCH'
  | 'INVALID_SIGNATURE' | 'BEFORE_STATE_MISMATCH' | 'AFTER_STATE_MISMATCH' | 'RESULT_MISMATCH';

export class EvidenceError extends Error {
  constructor(public readonly code: EvidenceErrorCode, message: string) {
    super(message);
    this.name = 'EvidenceError';
  }
}

export interface UnsignedExecutionReceiptV1 {
  version: 1;
  execution_id: string;
  request_id: string;
  actor: { type: 'agent' | 'service' | 'human'; id: string };
  action: { type: string; target: string };
  state_before_hash: string;
  state_after_hash: string;
  result_hash: string;
  executed_at: string;
  signature: { algorithm: 'Ed25519'; key_id: string };
}

export interface ExecutionReceiptV1 extends UnsignedExecutionReceiptV1 {
  signature: UnsignedExecutionReceiptV1['signature'] & { value: string };
}

export interface SigningAuthority {
  keyId: string;
  publicKey: KeyObject;
}

export interface CreateExecutionReceiptInput {
  execution_id: string;
  request_id: string;
  actor: UnsignedExecutionReceiptV1['actor'];
  action: UnsignedExecutionReceiptV1['action'];
  before: unknown;
  after: unknown;
  result: unknown;
  executed_at: string;
  key_id: string;
}

function fail(code: EvidenceErrorCode, message: string): never {
  throw new EvidenceError(code, message);
}

// Reject values that JSON would silently drop or coerce. Never invoke accessors/toJSON.
function assertJson(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      fail('INVALID_JSON', 'Strings must contain valid Unicode');
    }
    return;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object') fail('INVALID_JSON', 'Expected a JSON value');
  if (ancestors.has(value)) fail('INVALID_JSON', 'Cycles are not JSON');
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    fail('INVALID_JSON', 'Expected a plain object or array');
  }
  ancestors.add(value);
  const keys = Reflect.ownKeys(value);
  if (array && keys.length !== value.length + 1) fail('INVALID_JSON', 'Arrays must be dense and have no extra properties');
  for (const key of keys) {
    if (array && key === 'length') continue;
    if (typeof key !== 'string') fail('INVALID_JSON', 'Symbol keys are not JSON');
    if (array && (!/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)) {
      fail('INVALID_JSON', 'Unexpected array property');
    }
    assertJson(key);
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!descriptor.enumerable || !('value' in descriptor)) fail('INVALID_JSON', 'Expected enumerable data properties');
    assertJson(descriptor.value, ancestors);
  }
  ancestors.delete(value);
}

function canonical(value: unknown): string {
  try {
    assertJson(value);
    const encoded = canonicalize(value);
    if (encoded === undefined) fail('INVALID_JSON', 'Cannot canonicalize value');
    return encoded;
  } catch (error) {
    if (error instanceof EvidenceError) throw error;
    return fail('INVALID_JSON', 'Cannot canonicalize value');
  }
}

export function hashState(value: unknown): string {
  return createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

export function hashResult(value: unknown): string {
  return hashState(value);
}

function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('MALFORMED_RECEIPT', 'Expected an object');
  const actual = Object.keys(value);
  if (actual.length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    fail('MALFORMED_RECEIPT', 'Unexpected or missing receipt fields');
  }
  return value as Record<string, unknown>;
}

function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

// Snapshot before validation so callers cannot mutate nested references after signing.
function receiptSnapshot(value: unknown, signed: boolean): UnsignedExecutionReceiptV1 | ExecutionReceiptV1 {
  let copy: unknown;
  try { copy = JSON.parse(canonical(value)); }
  catch { return fail('MALFORMED_RECEIPT', 'Receipt must be plain JSON'); }
  const r = record(copy, ['version', 'execution_id', 'request_id', 'actor', 'action',
    'state_before_hash', 'state_after_hash', 'result_hash', 'executed_at', 'signature']);
  const actor = record(r.actor, ['type', 'id']);
  const action = record(r.action, ['type', 'target']);
  const signature = record(r.signature, signed ? ['algorithm', 'key_id', 'value'] : ['algorithm', 'key_id']);
  if (r.version !== 1 || typeof actor.type !== 'string' || !['agent', 'service', 'human'].includes(actor.type) ||
      !nonempty(actor.id) || !nonempty(action.type) || !nonempty(action.target) ||
      !nonempty(r.request_id) || !nonempty(signature.key_id) || signature.algorithm !== 'Ed25519' ||
      typeof r.execution_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(r.execution_id)) {
    fail('MALFORMED_RECEIPT', 'Invalid receipt metadata (execution_id must be a UUID v4)');
  }
  for (const field of ['state_before_hash', 'state_after_hash', 'result_hash']) {
    if (typeof r[field] !== 'string' || !/^[0-9a-f]{64}$/.test(r[field])) fail('MALFORMED_RECEIPT', 'Expected lowercase SHA-256 hex');
  }
  if (typeof r.executed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(r.executed_at) ||
      !Number.isFinite(Date.parse(r.executed_at)) || new Date(r.executed_at).toISOString() !== r.executed_at) {
    fail('MALFORMED_RECEIPT', 'Expected a valid UTC timestamp with milliseconds');
  }
  if (signed && (typeof signature.value !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/.test(signature.value) ||
      Buffer.from(signature.value, 'base64').toString('base64') !== signature.value)) {
    fail('INVALID_SIGNATURE', 'Expected canonical base64 of a 64-byte Ed25519 signature');
  }
  return copy as UnsignedExecutionReceiptV1 | ExecutionReceiptV1;
}

export function createExecutionReceipt(input: CreateExecutionReceiptInput): UnsignedExecutionReceiptV1 {
  return receiptSnapshot({
    version: 1, execution_id: input.execution_id, request_id: input.request_id,
    actor: input.actor, action: input.action,
    state_before_hash: hashState(input.before), state_after_hash: hashState(input.after),
    result_hash: hashResult(input.result), executed_at: input.executed_at,
    signature: { algorithm: 'Ed25519', key_id: input.key_id },
  }, false);
}

function requireKey(key: KeyObject, type: 'private' | 'public'): void {
  if (!(key instanceof KeyObject) || key.type !== type || key.asymmetricKeyType !== 'ed25519') {
    fail('INVALID_KEY', `Expected an Ed25519 ${type} KeyObject`);
  }
}

export function signExecutionReceipt(receipt: UnsignedExecutionReceiptV1, privateKey: KeyObject): ExecutionReceiptV1 {
  const copy = receiptSnapshot(receipt, false);
  requireKey(privateKey, 'private');
  const value = sign(null, Buffer.from(canonical(copy), 'utf8'), privateKey).toString('base64');
  return { ...copy, signature: { ...copy.signature, value } };
}

function verifiedSnapshot(receipt: unknown, authority: SigningAuthority): ExecutionReceiptV1 {
  const copy = receiptSnapshot(receipt, true) as ExecutionReceiptV1;
  requireKey(authority.publicKey, 'public');
  if (copy.signature.key_id !== authority.keyId) fail('KEY_ID_MISMATCH', 'Receipt does not match configured authority');
  const { value, ...metadata } = copy.signature;
  const payload = { ...copy, signature: metadata };
  if (!verify(null, Buffer.from(canonical(payload), 'utf8'), authority.publicKey, Buffer.from(value, 'base64'))) {
    fail('INVALID_SIGNATURE', 'Signature verification failed');
  }
  return copy;
}

/** Returns true on success; throws EvidenceError on invalid evidence. */
export function verifyExecutionReceipt(receipt: unknown, authority: SigningAuthority): true {
  verifiedSnapshot(receipt, authority);
  return true;
}

/** Verifies authenticity AND all three supplied values against one detached receipt. */
export function verifyExecutionTransition(
  receipt: unknown, before: unknown, after: unknown, result: unknown, authority: SigningAuthority,
): true {
  const copy = verifiedSnapshot(receipt, authority);
  if (hashState(before) !== copy.state_before_hash) fail('BEFORE_STATE_MISMATCH', 'Before state does not match');
  if (hashState(after) !== copy.state_after_hash) fail('AFTER_STATE_MISMATCH', 'After state does not match');
  if (hashResult(result) !== copy.result_hash) fail('RESULT_MISMATCH', 'Result does not match');
  return true;
}

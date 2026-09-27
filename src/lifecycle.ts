import canonicalize from 'canonicalize';
import { KeyObject, sign, verify } from 'node:crypto';
import { hashState, verifyExecutionReceipt, type ExecutionReceiptV1 } from './index.js';

export type LifecycleStatus = 'dispatched' | 'confirmed' | 'indeterminate' | 'unknown';
export type EvidenceRole = 'lifecycle' | 'reconciliation' | 'receipt';
export type LifecycleErrorCode = 'MALFORMED_EVIDENCE' | 'UNTRUSTED_ISSUER' | 'INVALID_KEY'
  | 'INVALID_SIGNATURE' | 'INVALID_HISTORY' | 'INVALID_CONFIRMATION' | 'UNSAFE_RETRY';

export class LifecycleError extends Error {
  constructor(public readonly code: LifecycleErrorCode, message: string) {
    super(message);
    this.name = 'LifecycleError';
  }
}

/** Trusted application configuration, never populated from evidence. */
export interface TrustedIssuer {
  issuer_id: string;
  key_id: string;
  public_key: KeyObject;
  roles: readonly EvidenceRole[];
}

export interface ExecutionIdentity {
  execution_id: string;
  request_id: string;
  idempotency_key?: string;
}

/** An explicit assertion by the verifier's application, not by the signer. */
export interface SideEffectFreeRetryPolicy extends ExecutionIdentity {
  side_effect_free: true;
}

export interface VerificationContext {
  trustedIssuers: readonly TrustedIssuer[];
  /** Untrusted receipt candidates. Every referenced receipt is verified independently. */
  receipts?: readonly unknown[];
  retryPolicy?: SideEffectFreeRetryPolicy;
}

type Classification =
  | { status: 'dispatched'; basis: 'submitted' }
  | { status: 'indeterminate'; basis: 'timeout_after_dispatch' | 'transport_after_dispatch'
      | 'acknowledgement_lost' | 'unresolved_provider_effect' }
  | { status: 'unknown'; basis: 'insufficient_trustworthy_evidence' }
  | { status: 'confirmed'; basis: 'verified_receipt'; execution_receipt_hash: string; receipt_issuer: string };

type Metadata = ExecutionIdentity & {
  version: 1;
  observed_at: string;
  issuer: string;
  provider_reference?: string;
  signature: { algorithm: 'Ed25519'; key_id: string };
};

export type UnsignedExecutionLifecycleEventV1 = Metadata & Classification & {
  kind: 'execution_lifecycle';
  event_id: string;
  previous_event_hash?: string;
  /** Only for a verifier-authorized, side-effect-free retry; equals the predecessor hash. */
  retry_of?: string;
};

/** Minimal reconciliation: an authoritative receipt resolves prior uncertainty. */
export type UnsignedExecutionReconciliationV1 = Metadata & Extract<Classification, { status: 'confirmed' }> & {
  kind: 'execution_reconciliation';
  reconciliation_id: string;
  previous_event_hash: string;
};

type Signed = { signature: Metadata['signature'] & { value: string } };
export type ExecutionLifecycleEventV1 = UnsignedExecutionLifecycleEventV1 & Signed;
export type ExecutionReconciliationV1 = UnsignedExecutionReconciliationV1 & Signed;
export type UnsignedLifecycleEvidence = UnsignedExecutionLifecycleEventV1 | UnsignedExecutionReconciliationV1;
export type LifecycleEvidence = ExecutionLifecycleEventV1 | ExecutionReconciliationV1;

function fail(code: LifecycleErrorCode, message: string): never {
  throw new LifecycleError(code, message);
}

// Reuse v0.1's strict JSON gate and JCS implementation without altering its contract.
function snapshot(value: unknown): unknown {
  try {
    hashState(value);
    return JSON.parse(canonicalize(value)!);
  } catch {
    return fail('MALFORMED_EVIDENCE', 'Evidence must be plain, strictly JSON-compatible data');
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('MALFORMED_EVIDENCE', 'Expected an evidence object');
  }
  return value as Record<string, unknown>;
}

function fields(r: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(k => !Object.hasOwn(r, k)) || Object.keys(r).some(k => !required.includes(k) && !optional.includes(k))) {
    fail('MALFORMED_EVIDENCE', 'Missing or unexpected evidence fields');
  }
}

function text(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
function hash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
function uuid(value: unknown): boolean {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function timestamp(value: unknown): boolean {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function evidenceSnapshot(value: unknown, signed: boolean): UnsignedLifecycleEvidence | LifecycleEvidence {
  const r = object(snapshot(value));
  const reconciliation = r.kind === 'execution_reconciliation';
  if (!reconciliation && r.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'Unknown evidence kind');
  const required = ['kind', 'version', 'execution_id', 'request_id', 'status', 'basis', 'observed_at', 'issuer', 'signature'];
  if (reconciliation) required.push('reconciliation_id', 'previous_event_hash');
  else required.push('event_id');
  if (r.status === 'confirmed') required.push('execution_receipt_hash', 'receipt_issuer');
  fields(r, required, ['provider_reference', 'idempotency_key', ...(reconciliation ? [] : ['previous_event_hash', 'retry_of'])]);
  const s = object(r.signature);
  fields(s, signed ? ['algorithm', 'key_id', 'value'] : ['algorithm', 'key_id']);
  if (r.version !== 1 || !uuid(r.execution_id) || !uuid(r[reconciliation ? 'reconciliation_id' : 'event_id'])
      || !text(r.request_id) || !text(r.issuer) || !text(s.key_id) || s.algorithm !== 'Ed25519' || !timestamp(r.observed_at)) {
    fail('MALFORMED_EVIDENCE', 'Invalid evidence metadata');
  }
  for (const k of ['provider_reference', 'idempotency_key']) {
    if (Object.hasOwn(r, k) && !text(r[k])) fail('MALFORMED_EVIDENCE', `Invalid ${k}`);
  }
  for (const k of ['previous_event_hash', 'retry_of']) {
    if (Object.hasOwn(r, k) && !hash(r[k])) fail('MALFORMED_EVIDENCE', `Invalid ${k}`);
  }
  const bases: Record<LifecycleStatus, readonly string[]> = {
    dispatched: ['submitted'], confirmed: ['verified_receipt'],
    indeterminate: ['timeout_after_dispatch', 'transport_after_dispatch', 'acknowledgement_lost', 'unresolved_provider_effect'],
    unknown: ['insufficient_trustworthy_evidence'],
  };
  if (typeof r.status !== 'string' || !Object.hasOwn(bases, r.status)
      || !bases[r.status as LifecycleStatus].includes(r.basis as string)) {
    fail('MALFORMED_EVIDENCE', 'Status must have an explicit compatible observation basis');
  }
  if (reconciliation && r.status !== 'confirmed') fail('MALFORMED_EVIDENCE', 'Reconciliation requires a receipt');
  if (r.status === 'confirmed' && (!hash(r.execution_receipt_hash) || !text(r.receipt_issuer))) {
    fail('MALFORMED_EVIDENCE', 'Confirmation requires a receipt hash and issuer');
  }
  if (Object.hasOwn(r, 'retry_of') && (r.status !== 'dispatched' || r.retry_of !== r.previous_event_hash)) {
    fail('MALFORMED_EVIDENCE', 'Retry must identify its immediate predecessor');
  }
  if (signed && (typeof s.value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(s.value)
      || Buffer.from(s.value, 'base64').toString('base64') !== s.value)) {
    fail('INVALID_SIGNATURE', 'Expected canonical base64 of a 64-byte Ed25519 signature');
  }
  return r as unknown as UnsignedLifecycleEvidence | LifecycleEvidence;
}

function requireKey(key: KeyObject, type: 'public' | 'private'): void {
  if (!(key instanceof KeyObject) || key.type !== type || key.asymmetricKeyType !== 'ed25519') {
    fail('INVALID_KEY', `Expected an Ed25519 ${type} key`);
  }
}

function authority(context: VerificationContext, issuer: string, keyId: string, role: EvidenceRole): TrustedIssuer {
  const matches = context.trustedIssuers.filter(k => k.issuer_id === issuer && k.key_id === keyId);
  if (matches.length !== 1 || !matches[0]!.roles.includes(role)) {
    fail('UNTRUSTED_ISSUER', 'Issuer/key must be uniquely trusted for this evidence role');
  }
  requireKey(matches[0]!.public_key, 'public');
  return matches[0]!;
}

function authenticated(value: unknown, context: VerificationContext): LifecycleEvidence {
  const copy = evidenceSnapshot(value, true) as LifecycleEvidence;
  const key = authority(context, copy.issuer, copy.signature.key_id,
    copy.kind === 'execution_lifecycle' ? 'lifecycle' : 'reconciliation');
  const { value: signature, ...metadata } = copy.signature;
  if (!verify(null, Buffer.from(canonicalize({ ...copy, signature: metadata })!), key.public_key, Buffer.from(signature, 'base64'))) {
    fail('INVALID_SIGNATURE', 'Lifecycle signature verification failed');
  }
  return copy;
}

/** Hash the complete signed artifact, including signature, using SHA-256/JCS. Not verification. */
export function hashLifecycleEvidence(evidence: LifecycleEvidence): string {
  return hashState(evidenceSnapshot(evidence, true));
}

/** Complete v0.1 receipt hash, including signature. Not an authenticity assertion. */
export function hashExecutionReceipt(receipt: ExecutionReceiptV1): string {
  return hashState(receipt);
}

function confirmation(evidence: LifecycleEvidence, context: VerificationContext): void {
  if (evidence.status !== 'confirmed') return;
  // Validate every candidate as plain JSON before any property access.
  const candidates = (context.receipts ?? []).map(snapshot).filter(r => hashState(r) === evidence.execution_receipt_hash);
  if (candidates.length === 0) fail('INVALID_CONFIRMATION', 'Referenced receipt is missing');
  const receipt = object(candidates[0]);
  const signature = object(receipt.signature);
  if (!text(signature.key_id)) fail('INVALID_CONFIRMATION', 'Receipt has no key identity');
  const key = authority(context, evidence.receipt_issuer, signature.key_id, 'receipt');
  verifyExecutionReceipt(receipt, { keyId: key.key_id, publicKey: key.public_key });
  if (receipt.execution_id !== evidence.execution_id || receipt.request_id !== evidence.request_id) {
    fail('INVALID_CONFIRMATION', 'Receipt does not bind the same execution and request');
  }
  if ((receipt.executed_at as string) > evidence.observed_at) {
    fail('INVALID_CONFIRMATION', 'Receipt execution follows its claimed observation');
  }
}

function sameIdentity(a: ExecutionIdentity, b: ExecutionIdentity): boolean {
  return a.execution_id === b.execution_id && a.request_id === b.request_id && a.idempotency_key === b.idempotency_key;
}

function retryPermitted(e: LifecycleEvidence, context: VerificationContext): boolean {
  const policy = context.retryPolicy;
  return e.status !== 'confirmed' && e.status !== 'unknown'
    && policy?.side_effect_free === true && sameIdentity(e, policy);
}

/** Verify the entire supplied linear history; no isolated status flag is trusted. */
export function verifyExecutionHistory(history: unknown, context: VerificationContext): true {
  const input = snapshot(history);
  if (!Array.isArray(input) || input.length === 0) fail('INVALID_HISTORY', 'Lifecycle history is required');
  let previous: LifecycleEvidence | undefined;
  const ids = new Set<string>();
  for (const item of input) {
    const current = authenticated(item, context);
    const id = current.kind === 'execution_lifecycle' ? current.event_id : current.reconciliation_id;
    if (ids.has(id)) fail('INVALID_HISTORY', 'Repeated evidence identifier');
    ids.add(id);
    if (!previous) {
      if (current.kind !== 'execution_lifecycle' || current.previous_event_hash !== undefined || current.status === 'confirmed'
          || current.retry_of !== undefined) fail('INVALID_HISTORY', 'Expected an initial unresolved lifecycle observation');
    } else {
      if (current.previous_event_hash !== hashLifecycleEvidence(previous) || !sameIdentity(previous, current)
          || current.observed_at < previous.observed_at) {
        fail('INVALID_HISTORY', 'Broken linkage, changed identity, or regressing observation time');
      }
      if (previous.status === 'confirmed') fail('INVALID_HISTORY', 'Confirmed history is terminal; do not overwrite contradictions');
      // Reconciliation is independently role-checked and must pass confirmation below.
      if (current.kind === 'execution_lifecycle') {
        if (current.retry_of !== undefined) {
          if (!retryPermitted(previous, context)) fail('UNSAFE_RETRY', 'Retry requires a matching side-effect-free verifier policy');
        } else if (previous.status !== 'dispatched' || current.status === 'dispatched') {
          fail('INVALID_HISTORY', 'Only dispatched may progress directly; uncertainty requires reconciliation');
        }
      }
    }
    confirmation(current, context);
    previous = current;
  }
  return true;
}

function signEvidence<T extends UnsignedLifecycleEvidence>(draft: T, privateKey: KeyObject): T & Signed {
  const copy = evidenceSnapshot(draft, false) as T;
  requireKey(privateKey, 'private');
  const value = sign(null, Buffer.from(canonicalize(copy)!), privateKey).toString('base64');
  return { ...copy, signature: { ...copy.signature, value } };
}

/** Signing also verifies the proposed append, including confirmation and transition rules. */
export function signExecutionLifecycleEvent(
  draft: UnsignedExecutionLifecycleEventV1, privateKey: KeyObject,
  history: readonly LifecycleEvidence[], context: VerificationContext,
): ExecutionLifecycleEventV1 {
  const event = signEvidence(draft, privateKey);
  if (event.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'Expected lifecycle event');
  const prior = snapshot(history);
  if (!Array.isArray(prior)) fail('INVALID_HISTORY', 'Expected history array');
  verifyExecutionHistory([...prior, event], context);
  return event;
}

export function signExecutionReconciliation(
  draft: UnsignedExecutionReconciliationV1, privateKey: KeyObject,
  history: readonly LifecycleEvidence[], context: VerificationContext,
): ExecutionReconciliationV1 {
  const event = signEvidence(draft, privateKey);
  if (event.kind !== 'execution_reconciliation') fail('MALFORMED_EVIDENCE', 'Expected reconciliation');
  const prior = snapshot(history);
  if (!Array.isArray(prior)) fail('INVALID_HISTORY', 'Expected history array');
  verifyExecutionHistory([...prior, event], context);
  return event;
}

export type RetryDisposition = 'safe_to_retry' | 'do_not_retry' | 'reconciliation_required';

/** Invalid/missing evidence never grants retry. A confirmed receipt does not imply business success. */
export function evaluateRetryDisposition(history: unknown, context: VerificationContext): RetryDisposition {
  try {
    verifyExecutionHistory(history, context);
    const entries = snapshot(history) as LifecycleEvidence[];
    const last = entries[entries.length - 1]!;
    if (last.status === 'confirmed') return 'do_not_retry';
    return retryPermitted(last, context) ? 'safe_to_retry' : 'reconciliation_required';
  } catch {
    return 'reconciliation_required';
  }
}

/** Records an already submitted retry. Does not execute anything or authorize a side effect. */
export function signRetryDispatch(
  history: readonly LifecycleEvidence[],
  observation: { event_id: string; observed_at: string; issuer: string; key_id: string },
  privateKey: KeyObject, context: VerificationContext,
): ExecutionLifecycleEventV1 {
  if (evaluateRetryDisposition(history, context) !== 'safe_to_retry') fail('UNSAFE_RETRY', 'Retry is not justified');
  const previous = evidenceSnapshot(history[history.length - 1], true) as LifecycleEvidence;
  const predecessorHash = hashLifecycleEvidence(previous);
  return signExecutionLifecycleEvent({
    kind: 'execution_lifecycle', version: 1, event_id: observation.event_id,
    execution_id: previous.execution_id, request_id: previous.request_id,
    ...(previous.idempotency_key === undefined ? {} : { idempotency_key: previous.idempotency_key }),
    status: 'dispatched', basis: 'submitted', observed_at: observation.observed_at,
    issuer: observation.issuer, signature: { algorithm: 'Ed25519', key_id: observation.key_id },
    previous_event_hash: predecessorHash, retry_of: predecessorHash,
  }, privateKey, history, context);
}

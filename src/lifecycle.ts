import canonicalize from 'canonicalize';
import { KeyObject, sign, verify } from 'node:crypto';
import { hashState, verifyExecutionReceipt, type ExecutionReceiptV1 } from './index.js';

export type EvidenceRole = 'lifecycle' | 'receipt_binding' | 'receipt';
export type LifecycleErrorCode = 'MALFORMED_EVIDENCE' | 'UNTRUSTED_ISSUER' | 'INVALID_KEY'
  | 'INVALID_SIGNATURE' | 'INVALID_HISTORY' | 'MISSING_PREDECESSOR' | 'INVALID_CONFIRMATION'
  | 'OPERATION_MISMATCH';

export class LifecycleError extends Error {
  constructor(public readonly code: LifecycleErrorCode, message: string) {
    super(message);
    this.name = 'LifecycleError';
  }
}

/** Exact intended operation. Scope identifies the executor's account/tenant/resource domain. */
export interface OperationDescriptorV1 {
  kind: 'execution_operation';
  version: 1;
  actor: ExecutionReceiptV1['actor'];
  action: ExecutionReceiptV1['action'];
  payload: unknown;
  executor: { id: string; scope: string };
}

/** Trusted verifier configuration, never populated from evidence. */
export interface TrustedIssuer {
  issuer_id: string;
  key_id: string;
  public_key: KeyObject;
  roles: readonly EvidenceRole[];
  /** Required for receipt_binding; an exact executor/scope pair, with no wildcard grants. */
  binding_scope?: { executor_id: string; scope: string };
}

export interface VerificationContext {
  trustedIssuers: readonly TrustedIssuer[];
  /** Expected descriptor, supplied independently by the consuming application. */
  operation: OperationDescriptorV1;
  /** Untrusted candidates: every referenced artifact is independently verified. */
  receipts?: readonly unknown[];
  receiptBindings?: readonly unknown[];
}

export interface OperationIdentity {
  operation_id: string;
  request_id: string;
  operation_hash: string;
}

type Metadata = OperationIdentity & {
  version: 1;
  attempt_id: string;
  observed_at: string;
  issuer: string;
  signature: { algorithm: 'Ed25519'; key_id: string };
};

type Observation =
  | { status: 'dispatched'; basis: 'submitted' }
  | { status: 'indeterminate'; basis: 'timeout_after_possible_dispatch' | 'connection_lost'
      | 'acknowledgement_lost' | 'partial_effect_unresolved' | 'unresolved_provider_effect' }
  | { status: 'unknown'; basis: 'insufficient_trustworthy_evidence' }
  | { status: 'outcome_observed'; basis: 'verified_receipt_binding'; receipt_binding_hash: string };

export type LifecycleStatus = Observation['status'];
export type UnsignedExecutionLifecycleEventV1 = Metadata & Observation & {
  kind: 'execution_lifecycle';
  event_id: string;
  previous_event_hash?: string;
  /** Present on every observation of a retry attempt; never an authorization. */
  retry_of_attempt_id?: string;
  idempotency_key?: string;
};

/** A trusted adapter attests the association v0.1 cannot express: payload/scope/attempt ↔ receipt. */
export type UnsignedExecutionReceiptBindingV1 = Metadata & {
  kind: 'execution_receipt_binding';
  binding_id: string;
  execution_receipt_hash: string;
  receipt_issuer: string;
};

type Signed = { signature: Metadata['signature'] & { value: string } };
export type ExecutionLifecycleEventV1 = UnsignedExecutionLifecycleEventV1 & Signed;
export type ExecutionReceiptBindingV1 = UnsignedExecutionReceiptBindingV1 & Signed;
export type LifecycleEvidence = ExecutionLifecycleEventV1;
type Draft = UnsignedExecutionLifecycleEventV1 | UnsignedExecutionReceiptBindingV1;
type Artifact = ExecutionLifecycleEventV1 | ExecutionReceiptBindingV1;

function fail(code: LifecycleErrorCode, message: string): never {
  throw new LifecycleError(code, message);
}

function snapshot(value: unknown): unknown {
  try {
    hashState(value); // v0.1 strict JSON gate; never silently coerce observations.
    return JSON.parse(canonicalize(value)!);
  } catch {
    return fail('MALFORMED_EVIDENCE', 'Expected plain, strictly JSON-compatible data');
  }
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('MALFORMED_EVIDENCE', 'Expected an object');
  return value as Record<string, unknown>;
}
function fields(r: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(k => !Object.hasOwn(r, k)) || Object.keys(r).some(k => !required.includes(k) && !optional.includes(k))) {
    fail('MALFORMED_EVIDENCE', 'Missing or unexpected fields');
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

function operationSnapshot(value: unknown): OperationDescriptorV1 {
  const r = object(snapshot(value));
  fields(r, ['kind', 'version', 'actor', 'action', 'payload', 'executor']);
  const actor = object(r.actor), action = object(r.action), executor = object(r.executor);
  fields(actor, ['type', 'id']); fields(action, ['type', 'target']); fields(executor, ['id', 'scope']);
  if (r.kind !== 'execution_operation' || r.version !== 1 || typeof actor.type !== 'string'
      || !['agent', 'service', 'human'].includes(actor.type) || !text(actor.id)
      || !text(action.type) || !text(action.target) || !text(executor.id) || !text(executor.scope)) {
    fail('MALFORMED_EVIDENCE', 'Invalid operation descriptor');
  }
  return r as unknown as OperationDescriptorV1;
}

/** SHA-256/JCS of the complete, domain-separated descriptor; not an authenticity assertion. */
export function hashOperation(operation: OperationDescriptorV1): string {
  return hashState(operationSnapshot(operation));
}

function artifactSnapshot(value: unknown, signed: boolean): Draft | Artifact {
  const r = object(snapshot(value));
  const binding = r.kind === 'execution_receipt_binding';
  if (!binding && r.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'Unknown evidence kind');
  const required = ['kind', 'version', 'operation_id', 'request_id', 'operation_hash', 'attempt_id',
    'observed_at', 'issuer', 'signature'];
  if (binding) required.push('binding_id', 'execution_receipt_hash', 'receipt_issuer');
  else {
    required.push('event_id', 'status', 'basis');
    if (r.status === 'outcome_observed') required.push('receipt_binding_hash');
  }
  fields(r, required, binding ? [] : ['previous_event_hash', 'retry_of_attempt_id', 'idempotency_key']);
  const s = object(r.signature);
  fields(s, signed ? ['algorithm', 'key_id', 'value'] : ['algorithm', 'key_id']);
  if (r.version !== 1 || !uuid(r.operation_id) || !uuid(r.attempt_id) || !uuid(r[binding ? 'binding_id' : 'event_id'])
      || !text(r.request_id) || !hash(r.operation_hash) || !text(r.issuer) || !text(s.key_id)
      || s.algorithm !== 'Ed25519' || !timestamp(r.observed_at)) fail('MALFORMED_EVIDENCE', 'Invalid evidence metadata');
  if (binding) {
    if (!hash(r.execution_receipt_hash) || !text(r.receipt_issuer)) fail('MALFORMED_EVIDENCE', 'Invalid receipt reference');
  } else {
    const bases: Record<LifecycleStatus, readonly string[]> = {
      dispatched: ['submitted'], outcome_observed: ['verified_receipt_binding'],
      indeterminate: ['timeout_after_possible_dispatch', 'connection_lost', 'acknowledgement_lost',
        'partial_effect_unresolved', 'unresolved_provider_effect'],
      unknown: ['insufficient_trustworthy_evidence'],
    };
    if (typeof r.status !== 'string' || !Object.hasOwn(bases, r.status)
        || !bases[r.status as LifecycleStatus].includes(r.basis as string)) fail('MALFORMED_EVIDENCE', 'Invalid observation basis');
    if (r.status === 'outcome_observed' && !hash(r.receipt_binding_hash)) fail('MALFORMED_EVIDENCE', 'Missing receipt binding');
    if (Object.hasOwn(r, 'previous_event_hash') && !hash(r.previous_event_hash)) fail('MALFORMED_EVIDENCE', 'Invalid predecessor');
    if (Object.hasOwn(r, 'retry_of_attempt_id') && (!uuid(r.retry_of_attempt_id) || r.retry_of_attempt_id === r.attempt_id)) {
      fail('INVALID_HISTORY', 'A retry must identify a different attempt');
    }
    if (Object.hasOwn(r, 'idempotency_key') && !text(r.idempotency_key)) fail('MALFORMED_EVIDENCE', 'Invalid idempotency key');
  }
  if (signed && (typeof s.value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(s.value)
      || Buffer.from(s.value, 'base64').toString('base64') !== s.value)) fail('INVALID_SIGNATURE', 'Expected canonical Ed25519 signature');
  return r as unknown as Draft | Artifact;
}

function requireKey(key: KeyObject, type: 'public' | 'private'): void {
  if (!(key instanceof KeyObject) || key.type !== type || key.asymmetricKeyType !== 'ed25519') fail('INVALID_KEY', 'Expected an Ed25519 key');
}
function authority(context: VerificationContext, issuer: string, keyId: string, role: EvidenceRole): TrustedIssuer {
  const matches = context.trustedIssuers.filter(k => k.issuer_id === issuer && k.key_id === keyId);
  if (matches.length !== 1 || !matches[0]!.roles.includes(role)) fail('UNTRUSTED_ISSUER', 'Issuer/key must be uniquely trusted for this role');
  if (role === 'receipt_binding') {
    let scope: Record<string, unknown>;
    try {
      scope = object(snapshot(matches[0]!.binding_scope));
      fields(scope, ['executor_id', 'scope']);
    } catch {
      return fail('UNTRUSTED_ISSUER', 'Binding authority requires an explicit executor/scope grant');
    }
    const executor = operationSnapshot(context.operation).executor;
    if (!text(scope.executor_id) || !text(scope.scope) || scope.executor_id === '*' || scope.scope === '*'
        || scope.executor_id !== executor.id || scope.scope !== executor.scope) {
      fail('UNTRUSTED_ISSUER', 'Binding authority is not trusted for this executor/scope');
    }
  }
  requireKey(matches[0]!.public_key, 'public');
  return matches[0]!;
}
function authenticated(value: unknown, context: VerificationContext): Artifact {
  const copy = artifactSnapshot(value, true) as Artifact;
  const key = authority(context, copy.issuer, copy.signature.key_id,
    copy.kind === 'execution_lifecycle' ? 'lifecycle' : 'receipt_binding');
  const { value: signature, ...metadata } = copy.signature;
  if (!verify(null, Buffer.from(canonicalize({ ...copy, signature: metadata })!), key.public_key, Buffer.from(signature, 'base64'))) {
    fail('INVALID_SIGNATURE', 'Evidence signature verification failed');
  }
  return copy;
}
function checkOperation(e: OperationIdentity, operation: OperationDescriptorV1): void {
  if (e.operation_hash !== hashOperation(operation)) fail('OPERATION_MISMATCH', 'Evidence does not bind the expected operation descriptor');
}
function sameOperation(a: OperationIdentity, b: OperationIdentity): boolean {
  return a.operation_id === b.operation_id && a.request_id === b.request_id && a.operation_hash === b.operation_hash;
}
function candidate(values: readonly unknown[] | undefined, digest: string): unknown {
  const copies = (values ?? []).map(snapshot);
  const match = copies.find(r => hashState(r) === digest);
  if (match === undefined) fail('INVALID_CONFIRMATION', 'Referenced evidence is missing');
  return match;
}

function boundReceipt(binding: ExecutionReceiptBindingV1, context: VerificationContext): ExecutionReceiptV1 {
  const operation = operationSnapshot(context.operation);
  checkOperation(binding, operation);
  const r = candidate(context.receipts, binding.execution_receipt_hash);
  const receipt = object(r), signature = object(receipt.signature);
  if (!text(signature.key_id)) fail('INVALID_CONFIRMATION', 'Receipt has no key identity');
  const key = authority(context, binding.receipt_issuer, signature.key_id, 'receipt');
  verifyExecutionReceipt(receipt, { keyId: key.key_id, publicKey: key.public_key });
  if (receipt.request_id !== binding.request_id
      || hashState(receipt.actor) !== hashState(operation.actor) || hashState(receipt.action) !== hashState(operation.action)) {
    fail('INVALID_CONFIRMATION', 'Receipt identity, actor or action does not match the bound operation');
  }
  // The signed full-receipt hash binds its execution_id; it need not equal the logical operation_id.
  // v0.1 has no payload/scope/attempt fields: that association is the binding authority's signed claim.
  return receipt as unknown as ExecutionReceiptV1;
}

function outcome(event: ExecutionLifecycleEventV1, context: VerificationContext): ExecutionReceiptV1 | undefined {
  if (event.status !== 'outcome_observed') return undefined;
  const binding = authenticated(candidate(context.receiptBindings, event.receipt_binding_hash), context);
  if (binding.kind !== 'execution_receipt_binding' || !sameOperation(binding, event) || binding.attempt_id !== event.attempt_id) {
    fail('INVALID_CONFIRMATION', 'Receipt binding does not identify this operation and attempt');
  }
  return boundReceipt(binding, context);
}

/** Hashes validate shape, not signatures or truth. They cover the complete signed artifact. */
export function hashLifecycleEvidence(evidence: ExecutionLifecycleEventV1): string {
  const e = artifactSnapshot(evidence, true);
  if (e.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'Expected lifecycle observation');
  return hashState(e);
}
export function hashReceiptBinding(binding: ExecutionReceiptBindingV1): string {
  const b = artifactSnapshot(binding, true);
  if (b.kind !== 'execution_receipt_binding') fail('MALFORMED_EVIDENCE', 'Expected receipt binding');
  return hashState(b);
}
export function hashExecutionReceipt(receipt: ExecutionReceiptV1): string {
  return hashState(receipt);
}

/** Authenticity and reference verification of one artifact. Event linkage needs verifyExecutionHistory. */
export function verifyEvidence(evidence: unknown, context: VerificationContext): true {
  const e = authenticated(evidence, context);
  checkOperation(e, context.operation);
  if (e.kind === 'execution_receipt_binding') boundReceipt(e, context);
  else outcome(e, context);
  return true;
}

interface VerifiedHistory {
  events: ExecutionLifecycleEventV1[];
  outcomes: Map<string, ExecutionReceiptV1>;
  heads: string[];
}

function verifiedHistory(history: unknown, context: VerificationContext): VerifiedHistory {
  const input = snapshot(history);
  if (!Array.isArray(input) || input.length === 0) fail('INVALID_HISTORY', 'A nonempty history is required');
  // Authenticate ALL input before diagnosing missing predecessors; never disguise a forged event as incomplete.
  const events = input.map(item => {
    const e = authenticated(item, context);
    if (e.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'History contains a non-event artifact');
    return e;
  });
  const first = events[0]!;
  const byHash = new Map<string, ExecutionLifecycleEventV1>();
  const ids = new Set<string>();
  const attempts = new Map<string, string | undefined>();
  const outcomes = new Map<string, ExecutionReceiptV1>();
  for (const e of events) {
    checkOperation(e, context.operation);
    if (!sameOperation(first, e) || first.idempotency_key !== e.idempotency_key) fail('INVALID_HISTORY', 'Changed logical operation identity');
    if (ids.has(e.event_id)) fail('INVALID_HISTORY', 'Repeated event identifier');
    ids.add(e.event_id);
    if (attempts.has(e.attempt_id) && attempts.get(e.attempt_id) !== e.retry_of_attempt_id) fail('INVALID_HISTORY', 'Changed attempt identity');
    attempts.set(e.attempt_id, e.retry_of_attempt_id);
    byHash.set(hashLifecycleEvidence(e), e);
    const receipt = outcome(e, context);
    if (receipt) outcomes.set(e.event_id, receipt);
  }
  for (const e of events) {
    if (e.previous_event_hash !== undefined && !byHash.has(e.previous_event_hash)) {
      fail('MISSING_PREDECESSOR', 'Supplied evidence lacks a referenced predecessor');
    }
  }
  // A history may fork. Input order and asserted wall-clock order are not causal order.
  const visited = new Set<string>(), visiting = new Set<string>();
  const ancestors = new Map<string, Set<string>>();
  function visit(digest: string): Set<string> {
    if (visited.has(digest)) return ancestors.get(digest)!;
    if (visiting.has(digest)) fail('INVALID_HISTORY', 'Cyclic evidence links');
    visiting.add(digest);
    const e = byHash.get(digest)!;
    const priorAttempts = e.previous_event_hash === undefined ? new Set<string>() : new Set(visit(e.previous_event_hash));
    if (e.retry_of_attempt_id !== undefined && !priorAttempts.has(e.retry_of_attempt_id)) {
      fail('INVALID_HISTORY', 'Retry observation must descend from evidence of its prior attempt');
    }
    priorAttempts.add(e.attempt_id);
    ancestors.set(digest, priorAttempts);
    visiting.delete(digest); visited.add(digest);
    return priorAttempts;
  }
  for (const digest of byHash.keys()) visit(digest);
  const initialAttempts = [...attempts].filter(([, retryOf]) => retryOf === undefined);
  if (initialAttempts.length !== 1) fail('INVALID_HISTORY', 'New attempts must explicitly reference their prior attempt');
  // Attempts themselves must not form a cycle, including across separate branches.
  for (const attempt of attempts.keys()) {
    const seen = new Set<string>();
    let current: string | undefined = attempt;
    while (current !== undefined) {
      if (seen.has(current)) fail('INVALID_HISTORY', 'Cyclic retry attempt references');
      seen.add(current); current = attempts.get(current);
    }
  }
  const predecessors = new Set(events.map(e => e.previous_event_hash));
  return { events, outcomes, heads: [...byHash.keys()].filter(h => !predecessors.has(h)).sort() };
}

/** Structural verification of the supplied graph, including forks. No retry authorization or freshness claim. */
export function verifyExecutionHistory(history: unknown, context: VerificationContext): true {
  verifiedHistory(history, context);
  return true;
}

export type KnowledgeState = LifecycleStatus | 'conflict';
export interface AttemptAssessment {
  attempt_id: string;
  state: KnowledgeState;
  /** Each supplied outcome remains attributable to its event and actual v0.1 execution. */
  outcomes: Array<{ event_id: string; execution_id: string; receipt_hash: string }>;
}

export interface HistoryAssessment {
  state: KnowledgeState;
  /** False by construction: a supplied graph cannot prove there is no withheld evidence. */
  global_completeness_proven: false;
  heads: string[];
  attempts: AttemptAssessment[];
  /** Informational only; multiple outcome attempts do not imply business success or duplicate effects. */
  outcome_attempt_ids: string[];
  outcome_receipt_hashes: string[];
  conflicting_event_ids: string[];
}

/** Compare final-outcome claims only within one delivery attempt. */
function attemptProjection(events: ExecutionLifecycleEventV1[], outcomes: Map<string, ExecutionReceiptV1>): KnowledgeState {
  const fingerprints = new Set(events.flatMap(e => {
    const r = outcomes.get(e.event_id);
    return r ? [hashState({ state_before_hash: r.state_before_hash, state_after_hash: r.state_after_hash, result_hash: r.result_hash })] : [];
  }));
  if (fingerprints.size > 1) return 'conflict';
  if (fingerprints.size === 1) return 'outcome_observed';
  if (events.some(e => e.status === 'indeterminate')) return 'indeterminate';
  if (events.some(e => e.status === 'dispatched')) return 'dispatched';
  return 'unknown';
}

/** Assess authenticated supplied evidence. Invalid/incomplete input throws, never becomes an outcome. */
export function assessHistory(history: unknown, context: VerificationContext): HistoryAssessment {
  const { events, outcomes, heads } = verifiedHistory(history, context);
  const attemptIds = [...new Set(events.map(e => e.attempt_id))].sort();
  const attempts: AttemptAssessment[] = attemptIds.map(attempt_id => {
    const observations = events.filter(e => e.attempt_id === attempt_id);
    return {
      attempt_id, state: attemptProjection(observations, outcomes),
      outcomes: observations.flatMap(e => {
        const receipt = outcomes.get(e.event_id);
        return receipt ? [{ event_id: e.event_id, execution_id: receipt.execution_id,
          receipt_hash: hashExecutionReceipt(receipt) }] : [];
      }).sort((a, b) => a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0),
    };
  });
  // Aggregate knowledge only. Never compare fingerprints across delivery attempts or choose a business winner.
  const state = (['conflict', 'outcome_observed', 'indeterminate', 'dispatched', 'unknown'] as const)
    .find(candidate => attempts.some(a => a.state === candidate))!;
  return {
    state, global_completeness_proven: false, heads,
    attempts, outcome_attempt_ids: attempts.filter(a => a.outcomes.length > 0).map(a => a.attempt_id),
    outcome_receipt_hashes: [...new Set([...outcomes.values()].map(hashExecutionReceipt))].sort(),
    conflicting_event_ids: attempts.filter(a => a.state === 'conflict').flatMap(a => a.outcomes.map(o => o.event_id)).sort(),
  };
}

function signArtifact<T extends Draft>(draft: T, privateKey: KeyObject): T & Signed {
  const copy = artifactSnapshot(draft, false) as T;
  requireKey(privateKey, 'private');
  return { ...copy, signature: { ...copy.signature,
    value: sign(null, Buffer.from(canonicalize(copy)!), privateKey).toString('base64') } };
}

/** Sign an observation, including one contradicting earlier evidence. Does not execute or authorize work. */
export function signExecutionLifecycleEvent(
  draft: UnsignedExecutionLifecycleEventV1, privateKey: KeyObject,
  history: readonly ExecutionLifecycleEventV1[], context: VerificationContext,
): ExecutionLifecycleEventV1 {
  const event = signArtifact(draft, privateKey);
  if (event.kind !== 'execution_lifecycle') fail('MALFORMED_EVIDENCE', 'Expected lifecycle event');
  const prior = snapshot(history);
  if (!Array.isArray(prior)) fail('INVALID_HISTORY', 'Expected history array');
  verifyExecutionHistory([...prior, event], context);
  return event;
}

export function signExecutionReceiptBinding(
  draft: UnsignedExecutionReceiptBindingV1, privateKey: KeyObject, context: VerificationContext,
): ExecutionReceiptBindingV1 {
  const binding = signArtifact(draft, privateKey);
  if (binding.kind !== 'execution_receipt_binding') fail('MALFORMED_EVIDENCE', 'Expected receipt binding');
  verifyEvidence(binding, context);
  return binding;
}

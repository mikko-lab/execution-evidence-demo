import { jest } from '@jest/globals';
import { createHash } from 'node:crypto';
import { EvidenceError, hashResult, hashState } from '../src/index.js';

describe('canonical SHA-256 hashing', () => {
  test('matches independently specified canonical bytes and SHA-256', () => {
    const expected = createHash('sha256').update('{"a":[true,null,"text"],"z":2}').digest('hex');
    expect(hashState({ z: 2, a: [true, null, 'text'] })).toBe(expected);
    expect(hashResult({ a: [true, null, 'text'], z: 2 })).toBe(expected);
  });
  test('same state gives same hash across detached values', () => {
    expect(hashState({ count: 1 })).toBe(hashState(JSON.parse('{"count":1}')));
  });
  test('nested object key order is immaterial', () => {
    expect(hashState({ b: { y: 2, x: 1 }, a: 0 })).toBe(hashState({ a: 0, b: { x: 1, y: 2 } }));
  });
  test('changed nested value and array order change the hash', () => {
    expect(hashState({ a: { b: 1 } })).not.toBe(hashState({ a: { b: 2 } }));
    expect(hashState([1, 2])).not.toBe(hashState([2, 1]));
  });
  test('matches RFC 8785 numeric and UTF-16 key ordering rules', () => {
    const value = { '\uE000': 1e30, '😀': -0, a: 0.000001 };
    const bytes = '{"a":0.000001,"😀":0,"":1e+30}';
    expect(hashState(value)).toBe(createHash('sha256').update(bytes).digest('hex'));
  });
  test.each([
    ['undefined property', { a: undefined }], ['NaN', NaN], ['infinity', Infinity],
    ['bigint', 1n], ['date', new Date()], ['sparse array', new Array(2)],
    ['lone surrogate', '\uD800'], ['symbol key', { [Symbol('a')]: 1 }],
  ])('rejects %s instead of silently coercing it', (_name, value) => {
    expect(() => hashState(value)).toThrow(EvidenceError);
    try { hashResult(value); } catch (error) { expect(error).toMatchObject({ code: 'INVALID_JSON' }); }
  });
  test('rejects cycles but permits shared acyclic references', () => {
    const cycle: { self?: unknown } = {}; cycle.self = cycle;
    expect(() => hashState(cycle)).toThrow(EvidenceError);
    const shared = { x: 1 };
    expect(hashState([shared, shared])).toBe(hashState([{ x: 1 }, { x: 1 }]));
  });
  test('rejects accessors without invoking them and rejects hidden properties', () => {
    const getter = jest.fn(() => 1);
    expect(() => hashState(Object.defineProperty({}, 'x', { get: getter, enumerable: true }))).toThrow(EvidenceError);
    expect(getter).not.toHaveBeenCalled();
    expect(() => hashState(Object.defineProperty({}, 'x', { value: 1 }))).toThrow(EvidenceError);
  });
});

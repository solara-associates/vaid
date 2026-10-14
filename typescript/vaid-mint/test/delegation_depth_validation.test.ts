/**
 * `maxDelegationDepth` validation — cross-language agreement (0.11.0, spec
 * `docs/spec/delegation.md`).
 *
 * Delegation-depth limiting is **outside the conformance surface** — it is
 * mint policy, not a protocol rule — so this is deliberately not a frozen
 * vector. The scenario table below is mirrored byte-for-intent by the Rust
 * (`crates/vaid-mint/tests/delegation_depth_validation.rs`) and Python
 * (`python/vaid-mint/tests/test_delegation_depth_validation.py`) suites,
 * which assert the identical (depth -> valid/invalid) mapping. There is no
 * shared vector: the three languages agree by construction.
 *
 * Only depths expressible as a plain non-negative integer in all three
 * languages are in the shared table below. TypeScript's own dynamic-input
 * edge cases (a float, NaN, Infinity, null, a string, a bool) are covered in
 * `mint_behavior.test.ts`, since Rust's `usize` parameter type rules those
 * out at compile time and has nothing to agree with.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ConfigError,
  DEFAULT_MAX_DELEGATION_DEPTH,
  MAX_LINEAGE_DEPTH,
  validateMaxDelegationDepth,
} from '../src/index.js';

const CASES: Array<[number, boolean]> = [
  [0, false], // zero: no value means "unlimited"
  [1, true], // the default
  [2, true], // a deeper, explicitly configured limit
  [MAX_LINEAGE_DEPTH, true], // at the bound: accepted
  [MAX_LINEAGE_DEPTH + 1, false], // one past the bound: rejected
];

for (const [depth, expectedValid] of CASES) {
  test(`cross-language scenario: depth ${depth} is ${expectedValid ? 'valid' : 'invalid'}`, () => {
    if (expectedValid) {
      assert.equal(validateMaxDelegationDepth(depth), depth);
    } else {
      assert.throws(() => validateMaxDelegationDepth(depth), ConfigError);
    }
  });
}

test('the default is itself valid', () => {
  assert.equal(
    validateMaxDelegationDepth(DEFAULT_MAX_DELEGATION_DEPTH),
    DEFAULT_MAX_DELEGATION_DEPTH,
  );
});

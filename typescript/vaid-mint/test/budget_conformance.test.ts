/**
 * Budget scope-kind conformance (`docs/spec/budget.md`, ADR-0011).
 *
 * The vendored vector `vectors/budget_v1.json` is byte-identical to the Rust
 * (`tests/vectors/`) and Python (`vaid_mint/vectors/`) copies. Like
 * `scope_kinds_v1.json` it carries no digest and no signature: every case is a
 * verdict over given bytes, never bytes over a given input.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  RECOGNISED_BUDGET_KINDS,
  budgetAttenuationReason,
} from '../src/budget.js';
import type { ScopeBoundaryEntry } from '../src/document.js';

interface AttenuationCase {
  name: string;
  parent_scope: ScopeBoundaryEntry[];
  child_scope: ScopeBoundaryEntry[];
  expected_reason: string;
}

const VECTOR: {
  rule: { kinds: string[] };
  attenuation_cases: AttenuationCase[];
} = JSON.parse(
  readFileSync(new URL('../../vectors/budget_v1.json', import.meta.url), 'utf8'),
);

test('the recognised budget-kind registry matches the specification', () => {
  assert.deepEqual(VECTOR.rule.kinds, Array.from(RECOGNISED_BUDGET_KINDS));
});

test('every attenuation case matches the reference rule', () => {
  for (const c of VECTOR.attenuation_cases) {
    const reason = budgetAttenuationReason(c.parent_scope, c.child_scope);
    assert.equal(reason, c.expected_reason, `case ${JSON.stringify(c.name)}`);
  }
});

test('the vector exercises every outcome it declares', () => {
  const seen = new Set(VECTOR.attenuation_cases.map((c) => c.expected_reason));
  for (const reason of ['attenuated', 'budget_escalation', 'unknown_budget_kind']) {
    assert.ok(seen.has(reason), `vector never exercises ${reason}`);
  }
});

test('the vector carries at least one fan-out case', () => {
  const fanOutCases = VECTOR.attenuation_cases.filter((c) => c.name.includes('fan-out'));
  assert.ok(
    fanOutCases.length >= 2,
    'expected at least two fan-out cases pinning that minting is not restricted per-sibling',
  );
});

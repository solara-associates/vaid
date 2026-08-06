/**
 * Scope-containment conformance (spec `docs/spec/scope.md` S.3, ADR-0005).
 *
 * The vendored vector `vectors/scope_v1.json` is byte-identical to the Rust
 * (`tests/vectors/`) and Python (`vaid_mint/vectors/`) copies; CI `cmp`s all three,
 * so "the vectors are the same bytes" gives Rust == Python == TypeScript on the
 * scope matcher.
 *
 * This is the FIRST vector to police the matcher, and its absence is why bare
 * prefix matching survived in all three implementations simultaneously: three
 * mirrored ports of the same wrong rule agreed with each other perfectly, and
 * nothing else was asking.
 *
 * Unlike every other vector in this package, this one carries **no digest and no
 * signature**. Containment is a predicate *over* a document, never part of one.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { SCOPE_SEPARATORS, scopeContains } from '../src/document.js';

interface Case {
  boundary: string[];
  resource: string;
  expected: boolean;
  why: string;
}

const VECTOR: { rule: { separators: string[] }; cases: Case[] } = JSON.parse(
  readFileSync(new URL('../../vectors/scope_v1.json', import.meta.url), 'utf8'),
);

test('every vector case matches the reference matcher', () => {
  assert.ok(VECTOR.cases.length > 0, 'vector must carry cases');
  for (const c of VECTOR.cases) {
    const got = scopeContains(c.boundary, c.resource);
    assert.equal(
      got,
      c.expected,
      `scope_v1 case failed: boundary=${JSON.stringify(c.boundary)} ` +
        `resource=${JSON.stringify(c.resource)} expected=${c.expected} got=${got} — ${c.why}`,
    );
  }
});

test('the vector exercises both outcomes', () => {
  // A vector that only ever expects true is satisfied by a matcher that always
  // returns true.
  assert.ok(
    VECTOR.cases.some((c) => c.expected),
    'no positive case',
  );
  assert.ok(
    VECTOR.cases.some((c) => !c.expected),
    'no negative case',
  );
});

test('the vector pins cases where bare prefix matching disagreed', () => {
  // The vector must pin the regression, not merely the rule.
  const disagreements = VECTOR.cases.filter(
    (c) =>
      c.boundary.length > 0 &&
      c.boundary.some((s) => c.resource.startsWith(s)) !== c.expected,
  );
  assert.ok(
    disagreements.length >= 5,
    'the vector must pin the sibling-capture regression class; only ' +
      `${disagreements.length} case(s) disagree with bare prefix matching`,
  );
});

test('the separator set is the normative one', () => {
  // Fixed by the spec, not by a deployment: ADR-0003 has a third party
  // recomputing containment from a presented chain, and a deployment-local set
  // would leave it unable to reproduce the mint's verdict.
  assert.deepEqual(VECTOR.rule.separators, ['/', '.']);
  assert.deepEqual([...SCOPE_SEPARATORS], VECTOR.rule.separators);
});

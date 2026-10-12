/**
 * Typed-scope-boundary conformance (spec `docs/spec/scope.md` S.8 to S.12,
 * ADR-0009).
 *
 * The vendored vector `vectors/scope_kinds_v1.json` is byte-identical to the Rust
 * (`tests/vectors/`) and Python (`vaid_mint/vectors/`) copies; CI `cmp`s all
 * three, so "the vectors are the same bytes" gives Rust == Python == TypeScript on
 * the three surfaces it pins.
 *
 * Like `scope_v1.json` it carries no digest and no signature: every case is a
 * verdict over given bytes.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  RECOGNISED_SCOPE_KINDS,
  SCOPE_KIND_PREFIX,
  boundaryIsEvaluable,
  entryClaimedResource,
  entryIsEvaluable,
  isWellFormedScopeBoundary,
  prefixEntry,
  scopeContains,
  type ScopeBoundaryEntry,
} from '../src/document.js';
import {
  AttenuationReason,
  MintService,
  scopeAttenuatesWithin,
  scopeAttenuationReason,
} from '../src/mint.js';
import { InMemoryAudit } from '../src/audit.js';
import { MintError } from '../src/error.js';
import { ReferenceIssuer } from '../src/issuer.js';
import { parseVaidDocument } from '../src/verify.js';

interface ContainmentCase {
  name: string;
  boundary: ScopeBoundaryEntry[];
  resource: string;
  expected: boolean;
  expected_reason: string;
  why: string;
}

interface AttenuationCase {
  name: string;
  parent_scope: ScopeBoundaryEntry[];
  child_scope: ScopeBoundaryEntry[];
  expected_valid: boolean;
  expected_reason: string;
  why: string;
}

interface ShapeCase {
  name: string;
  boundary_json: string;
  expected_reason: string;
  why: string;
}

const VECTOR: {
  rule: { kinds: string[]; entry_members: string[] };
  containment_cases: ContainmentCase[];
  attenuation_cases: AttenuationCase[];
  shape_cases: ShapeCase[];
} = JSON.parse(
  readFileSync(new URL('../../vectors/scope_kinds_v1.json', import.meta.url), 'utf8'),
);

/**
 * The registry, BOTH directions. A kind this build recognises that the
 * specification does not declare is a widening nobody wrote down; a kind the
 * specification declares that this build does not recognise is a fail-closed rule
 * refusing something the standard says is valid. Neither is visible in any other
 * assertion here.
 */
test('the recognised-kind registry matches the specification', () => {
  assert.deepEqual(VECTOR.rule.kinds, [...RECOGNISED_SCOPE_KINDS]);
  assert.ok(
    RECOGNISED_SCOPE_KINDS.length > 0,
    'a build that recognises no kind contains every boundary in nothing',
  );
  assert.deepEqual(
    VECTOR.rule.entry_members,
    ['kind', 'value'],
    'S.8 fixes the entry member set at exactly these two',
  );
});

for (const c of VECTOR.containment_cases) {
  test(`containment: ${c.name}`, () => {
    assert.ok(isWellFormedScopeBoundary(c.boundary), "the vector's own boundary must be valid");
    const got = scopeContains(c.boundary, c.resource);
    assert.equal(got, c.expected, c.why);
    // The REASON, not merely the boolean: a refusal and an inability to evaluate
    // are different accusations that agree on every boolean.
    const reason = !boundaryIsEvaluable(c.boundary)
      ? 'unknown_scope_kind'
      : got
        ? 'contained'
        : 'not_contained';
    assert.equal(reason, c.expected_reason, c.why);
  });
}

for (const c of VECTOR.attenuation_cases) {
  test(`attenuation: ${c.name}`, () => {
    const att = scopeAttenuationReason(c.parent_scope, c.child_scope);
    const ok = scopeAttenuatesWithin(c.parent_scope, c.child_scope);
    assert.equal(
      ok,
      att === AttenuationReason.Attenuated,
      'the attenuation boolean and the attenuation reason disagree — one rule with ' +
        'two readers is how the readers drift',
    );
    assert.equal(ok, c.expected_valid, c.why);
    assert.equal(att as string, c.expected_reason, c.why);
  });
}

for (const c of VECTOR.shape_cases) {
  test(`shape: ${c.name}`, () => {
    // Every case's bytes are themselves well-formed JSON, asserted by this call
    // not throwing, so what is under test is the SHAPE gate and never the parser.
    const value: unknown = JSON.parse(c.boundary_json);
    const reason = isWellFormedScopeBoundary(value) ? 'parsed' : 'unparseable';
    assert.equal(reason, c.expected_reason, c.why);
  });
}

test('the shape surface carries its positive controls', () => {
  const parsed = VECTOR.shape_cases.filter((c) => c.expected_reason === 'parsed');
  assert.ok(parsed.length >= 2, 'at least two positive controls');
  assert.ok(
    parsed.some((c) => {
      const value: unknown = JSON.parse(c.boundary_json);
      return isWellFormedScopeBoundary(value) && !boundaryIsEvaluable(value);
    }),
    'one positive control must be an UNRECOGNISED kind, proving it parses and is ' +
      'refused later rather than being refused as malformed bytes',
  );
});

test('the vector exercises every outcome it declares', () => {
  assert.ok(VECTOR.containment_cases.some((c) => c.expected));
  assert.ok(VECTOR.containment_cases.some((c) => !c.expected));
  for (const reason of ['attenuated', 'scope_escalation', 'unknown_scope_kind']) {
    assert.ok(
      VECTOR.attenuation_cases.some((c) => c.expected_reason === reason),
      `no attenuation case for ${reason} — a state with no case behind it is a ` +
        'claim with no evidence',
    );
  }
  for (const reason of ['contained', 'not_contained', 'unknown_scope_kind']) {
    assert.ok(VECTOR.containment_cases.some((c) => c.expected_reason === reason));
  }
});

/**
 * `entryIsEvaluable` derives evaluability from `entryContains` over one arbitrary
 * resource. That is exact only if the verdict's presence is a property of the
 * entry alone. Asserted rather than assumed, over every entry the vector carries.
 */
test('evaluability does not depend on the resource', () => {
  const entries = [
    ...VECTOR.containment_cases.flatMap((c) => c.boundary),
    ...VECTOR.attenuation_cases.flatMap((c) => [...c.parent_scope, ...c.child_scope]),
  ];
  assert.ok(entries.length > 0, 'the vector must carry entries to check');
  const resources = ['', 'data.governance', 'data.governance.reports', 't/x', 'z'];
  for (const entry of entries) {
    const derived = entryIsEvaluable(entry);
    for (const resource of resources) {
      // `scopeContains` over a single entry is `entryContains` with the
      // whole-boundary refusal applied, so an unevaluable entry alone is exactly
      // the `false` case and a `true` requires an evaluable one.
      const singly = scopeContains([entry], resource);
      assert.ok(
        derived || !singly,
        `an unevaluable entry contained ${resource} — the S.10 refusal is not firing`,
      );
    }
  }
});

/**
 * A kind named in the registry must be one both branches can answer for. Without
 * this, a name could be added to the registry alone and the matcher would refuse a
 * kind the specification says is recognised.
 */
test('every registered kind is evaluable', () => {
  const witnesses: Record<string, ScopeBoundaryEntry> = {
    [SCOPE_KIND_PREFIX]: prefixEntry('data.x'),
  };
  for (const kind of RECOGNISED_SCOPE_KINDS) {
    const entry = witnesses[kind];
    assert.ok(entry, `registered kind ${kind} has no witness here — add one with the kind`);
    assert.ok(entryIsEvaluable(entry), `${kind} is not evaluable by the matcher`);
    assert.notEqual(
      entryClaimedResource(entry),
      null,
      `${kind} has no attenuation projection`,
    );
  }
});

// ── The same shape table, applied at the PRODUCER and LOCAL-VERIFIER surfaces ──
//
// The loop above pins the S.8 rule over a bare boundary, and all three
// implementations read this one table (the CI `cmp` job proves the three
// vendored copies are byte-identical), so the RULE cannot drift. What it pinned
// was the parse surface only, and that was the gap: TypeScript and Python both
// applied the rule in `parseVaidDocument` and not in `mintRoot`/`mintChild` or
// `verifyVaid`, so a producer could mint a credential this very table declares
// `unparseable` and have the local verifier call it valid.
//
// Driving the same cases through those two surfaces is what makes the agreement
// cover them. A new vector would have been a second copy of this table; a new CI
// job would have been a second copy of the `cmp` it already has.
//
// Rust needs no equivalent: its `Vaid::scope_boundary` is
// `Vec<ScopeBoundaryEntry>` with private fields and validating constructors, so
// a malformed boundary is unrepresentable rather than refused. Its
// `scope_kinds_conformance.rs` drives these cases through the DOCUMENT surface
// to pin exactly that.

for (const c of VECTOR.shape_cases) {
  test(`shape at the mint surface: ${c.name}`, async () => {
    const service = new MintService(
      ReferenceIssuer.ephemeral(1).assumingNothingRevoked(),
      new InMemoryAudit(),
    );
    const seed = {
      agentClass: 'orchestrator',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: JSON.parse(c.boundary_json) as never,
      capabilitySet: ['read'],
    };
    if (c.expected_reason === 'unparseable') {
      // A producer must not be able to sign what no verifier can read.
      await assert.rejects(
        service.mintRoot({ seed }),
        (error: Error) => error instanceof MintError,
        c.why,
      );
      return;
    }
    // The positive half, which includes an UNRECOGNISED kind: well formed, so it
    // must mint and parse, and is refused later at verify as
    // `unknown_scope_kind`. This is what stops the gate from being written as
    // "only a prefix entry is acceptable", which would pass every negative case
    // above and silently close the extension point ADR-0009 exists to open.
    const { vaid } = await service.mintRoot({ seed });
    assert.notEqual(parseVaidDocument(JSON.stringify(vaid)), null, c.why);
  });
}

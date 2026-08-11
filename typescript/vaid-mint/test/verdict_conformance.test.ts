/**
 * Negative-path conformance (`verdict_v1.json`) — failures must fail IDENTICALLY,
 * and for the SAME REASON.
 *
 * The frozen happy-path vectors prove three implementations MINT the same bytes.
 * None of them proves they REFUSE the same way. A verifier that accepts an expired
 * VAID in one language and rejects it in another is a worse defect than a mint
 * mismatch, and until this vector existed nothing in the suite would have caught it.
 *
 * **The assertion is the REASON, not the boolean.** Three implementations that
 * reject the same document for three different reasons agree on every boolean and
 * disagree about what happened. `false` collapses "this is forged" into "I could
 * not reach a revocation list"; a suite that only pins `false` cannot tell those
 * apart and therefore cannot notice when two implementations stop agreeing about
 * which one they got.
 *
 * **What stops this decaying into a vector that asserts nothing** — four things,
 * each with a test below: positive controls on both surfaces; reason coverage in
 * both directions; vocabulary agreement with `VaidVerdict` in both directions; and
 * reconstructed defects the vector must be shown to catch.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { scopeAttenuatesWithin } from '../src/mint.js';
import { RevocationStatus } from '../src/revocation.js';
import {
  isVerdictValid,
  VaidVerdict,
  verdictFromCode,
  verifyVaidStandingFromJson,
} from '../src/verify.js';

interface VerdictCase {
  name: string;
  why: string;
  surface: 'standing' | 'attenuation';
  document_json?: string;
  revocation?: string;
  parent_scope?: string[];
  child_scope?: string[];
  expected_valid: boolean;
  expected_reason: string;
}

const VECTOR = JSON.parse(
  readFileSync(new URL('../../vectors/verdict_v1.json', import.meta.url), 'utf8'),
) as {
  reasons: { standing: string[]; attenuation: string[] };
  ed25519: { kernel_public_key_hex: string };
  cases: VerdictCase[];
};

const KERNEL_PK = Uint8Array.from(
  (VECTOR.ed25519.kernel_public_key_hex.match(/../g) ?? []).map((h) => parseInt(h, 16)),
);
const CASES = VECTOR.cases;

const REVOCATION: Record<string, RevocationStatus> = {
  not_revoked: RevocationStatus.NotRevoked,
  revoked: RevocationStatus.Revoked,
  unavailable: RevocationStatus.Unavailable,
};

/** Evaluate one case the way the vector says it must be evaluated. */
function evaluate(c: VerdictCase): { reason: string; valid: boolean } {
  if (c.surface === 'standing') {
    const verdict = verifyVaidStandingFromJson(
      KERNEL_PK,
      c.document_json!,
      REVOCATION[c.revocation!]!,
    );
    return { reason: verdict, valid: isVerdictValid(verdict) };
  }
  const ok = scopeAttenuatesWithin(c.parent_scope!, c.child_scope!);
  return { reason: ok ? 'attenuated' : 'scope_escalation', valid: ok };
}

// THE ASSERTION. Both the reason and the boolean, per case.
for (const c of CASES) {
  test(`verdict_v1: ${c.name}`, () => {
    const { reason, valid } = evaluate(c);
    assert.equal(
      reason,
      c.expected_reason,
      `reason "${reason}", expected "${c.expected_reason}" — ${c.why}\n` +
        'A reason mismatch is a defect even when the boolean agrees: it means this ' +
        'implementation and the vector disagree about WHAT HAPPENED.',
    );
    assert.equal(valid, c.expected_valid, c.why);
  });
}

// THE CONTROL. An implementation that refuses everything passes every negative
// case in this file; only a case that must SUCCEED catches it. Both surfaces need
// one, because they are evaluated by different code.
for (const surface of ['standing', 'attenuation'] as const) {
  test(`verdict_v1 has a positive control and a negative case on the ${surface} surface`, () => {
    const positives = CASES.filter((c) => c.surface === surface && c.expected_valid);
    const negatives = CASES.filter((c) => c.surface === surface && !c.expected_valid);
    assert.ok(
      positives.length > 0,
      `the ${surface} surface has no positive control — an implementation that ` +
        'rejected every input would pass every case on it',
    );
    assert.ok(
      negatives.length > 0,
      `the ${surface} surface has no negative case — an implementation that ` +
        'accepted every input would pass every case on it',
    );
  });
}

test('declared reasons and exercised reasons are the same set', () => {
  // Both directions: a declared reason with no case is a state that ships
  // unchecked; a case naming an undeclared reason is a vector written against a
  // vocabulary this file does not define.
  const declared = new Set([...VECTOR.reasons.standing, ...VECTOR.reasons.attenuation]);
  const exercised = new Set(CASES.map((c) => c.expected_reason));
  const unexercised = [...declared].filter((r) => !exercised.has(r));
  const undeclared = [...exercised].filter((r) => !declared.has(r));
  assert.deepEqual(
    unexercised,
    [],
    'reason(s) declared but exercised by no case — a state with no case behind it is ' +
      'a claim with no evidence',
  );
  assert.deepEqual(undeclared, [], 'case(s) name reason(s) the vector does not declare');
});

test('the vector vocabulary and the enum are the same set', () => {
  // Both directions. A reason the vector declares that this build cannot return
  // means the vector was written against a different implementation; a verdict this
  // build can return that the vector never names is a state shipping without a case.
  const declared = new Set(VECTOR.reasons.standing);
  const implemented = new Set<string>(Object.values(VaidVerdict));
  assert.deepEqual(
    [...declared].filter((r) => !implemented.has(r)),
    [],
    'the vector declares a reason this build cannot return',
  );
  assert.deepEqual(
    [...implemented].filter((r) => !declared.has(r)),
    [],
    'this build can return a verdict the vector never names',
  );
  for (const reason of declared) {
    assert.notEqual(
      verdictFromCode(reason),
      null,
      `the vector declares reason "${reason}", which verdictFromCode does not recognise`,
    );
  }
});

test('no case throws', () => {
  // A refusal is never a throw. Malformed, truncated and empty input must reach a
  // verdict, because a verifier that throws on hostile bytes is a denial of service
  // wearing a safety property's clothes.
  for (const c of CASES) evaluate(c);
});

test('the vector catches a collapsed indeterminate', () => {
  // DISCRIMINATING POWER, part one. Reconstruct the two ways an implementation can
  // collapse the third state, and require the vector to catch BOTH. This is what
  // stops the fail-closed rule becoming decoration: a vector full of indeterminate
  // cases proves nothing if an implementation that maps Unavailable straight to
  // "clean" still passes it.
  let caughtFailOpen = false;
  let caughtFalseAccusation = false;
  for (const c of CASES) {
    if (c.surface !== 'standing' || c.revocation !== 'unavailable') continue;
    const asClean = verifyVaidStandingFromJson(
      KERNEL_PK,
      c.document_json!,
      RevocationStatus.NotRevoked,
    );
    if (asClean !== c.expected_reason) caughtFailOpen = true;
    const asRevoked = verifyVaidStandingFromJson(
      KERNEL_PK,
      c.document_json!,
      RevocationStatus.Revoked,
    );
    if (asRevoked !== c.expected_reason) caughtFalseAccusation = true;
  }
  assert.ok(
    caughtFailOpen,
    "the vector no longer catches an implementation that reads Unavailable as 'not " +
      'revoked' + ' — that is a FAIL-OPEN, and the more dangerous of the two',
  );
  assert.ok(
    caughtFalseAccusation,
    "the vector no longer catches an implementation that reads Unavailable as " +
      "'revoked' — accusing a holder because a store was unreachable is a false " +
      'accusation, not a safe default',
  );
});

test('reasons are load-bearing', () => {
  // DISCRIMINATING POWER, part two. If every case with the same boolean also had the
  // same reason, a boolean-only implementation would pass this vector and the whole
  // premise of the file would be decorative.
  const refusalReasons = new Set(
    CASES.filter((c) => !c.expected_valid).map((c) => c.expected_reason),
  );
  assert.ok(
    refusalReasons.size > 1,
    'every refusing case expects the same reason, so a boolean-only implementation ' +
      'would pass this vector and the reason assertions would be checking nothing',
  );
  const ordering = CASES.filter((c) => c.name.startsWith('order:'));
  assert.ok(
    ordering.length >= 3,
    `only ${ordering.length} ordering case(s) — these are what pin the ORDER of the ` +
      'checks, and the order is the part that changes reason codes while leaving every ' +
      'boolean identical',
  );
});

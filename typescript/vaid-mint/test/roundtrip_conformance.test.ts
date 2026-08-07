/**
 * Round-trip verification conformance (ADR-0006).
 *
 * Verify-only, and a shape the surface did not previously have: every other
 * vector pins one implementation's OUTPUT FOR A GIVEN INPUT; this one pins A
 * VERDICT OVER GIVEN BYTES — the only shape that catches cross-implementation
 * disagreement.
 *
 * TypeScript passed all four cases throughout, because `{...vaid}` spreads the
 * object as received and interfaces are erased at runtime. It is gated here
 * anyway: "the implementation that happened to be right" is exactly the one that
 * regresses silently, and a future refactor to a class or a validating parser
 * would reintroduce the defect with nothing else to catch it.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ed25519Verify, fromHex, numbersToBytes, sha256, canonicalize } from 'vaid-pop';
import { canonicalVaidSigningBytes } from '../src/document.js';

interface Case {
  name: string;
  why: string;
  document: Record<string, unknown>;
  expected_valid: boolean;
}

const VECTOR: { ed25519: { kernel_public_key_hex: string }; cases: Case[] } = JSON.parse(
  readFileSync(new URL('../../vectors/roundtrip_v1.json', import.meta.url), 'utf8'),
);
const PUB = fromHex(VECTOR.ed25519.kernel_public_key_hex);

// ed25519Verify(signature, message, publicKey) -- that order.
const verifyDoc = (doc: Record<string, unknown>): boolean =>
  ed25519Verify(
    numbersToBytes(doc.kernel_signature as number[]),
    canonicalVaidSigningBytes(doc as never),
    PUB,
  );

test('every case returns the frozen verdict', () => {
  assert.ok(VECTOR.cases.length > 0, 'vector must carry cases');
  for (const c of VECTOR.cases) {
    assert.equal(
      verifyDoc(c.document),
      c.expected_valid,
      `roundtrip_v1 case "${c.name}" — ${c.why}`,
    );
  }
});

test('the vector catches an implementation that drops unknown members', () => {
  // Must discriminate in BOTH directions: dropping unknown members produces a
  // false negative on one case and a false ACCEPT on another.
  let falseNegative = false;
  let falseAccept = false;
  for (const c of VECTOR.cases) {
    const dropped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(c.document)) if (!k.startsWith('x_')) dropped[k] = v;
    const payload = { ...dropped, kernel_signature: null };
    const got = ed25519Verify(
      numbersToBytes(c.document.kernel_signature as number[]),
      sha256(canonicalize(payload)),
      PUB,
    );
    if (got !== c.expected_valid) {
      if (c.expected_valid) falseNegative = true;
      else falseAccept = true;
    }
  }
  assert.ok(falseNegative, 'vector no longer catches a dropping impl REJECTING a valid document');
  assert.ok(falseAccept, 'vector no longer catches a dropping impl ACCEPTING an invalid one');
});

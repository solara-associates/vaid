/**
 * The packaged firewall itself.
 *
 * `src/conformance.ts` is what a consumer runs after `npm install vaid-pop`
 * (`npx vaid-pop-conformance`). The tests above prove the primitive; this proves
 * the thing a consumer actually invokes to check it — including that it locates
 * its bundled vectors and that it *fails* when handed a divergent one, which is
 * the only way to know the check is load-bearing rather than decorative.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  checkCompletion,
  checkDigest,
  checkSignature,
  ConformanceError,
  loadCompletionVector,
  loadVector,
  run,
} from '../src/conformance.js';

test('the packaged firewall passes against its bundled vectors', () => {
  const { pop, completion } = run();
  assert.equal(pop.digest_sha256_hex.length, 64);
  assert.equal(completion.digest_sha256_hex.length, 64);
});

test('a divergent digest is reported as a BLOCKER, not swallowed', () => {
  const tampered = { ...loadVector(), digest_sha256_hex: '00'.repeat(32) };
  assert.throws(() => checkDigest(tampered), ConformanceError);
});

test('a divergent signature is reported as a BLOCKER', () => {
  const v = loadVector();
  const tampered = { ...v, ed25519: { ...v.ed25519, signature_hex: '00'.repeat(64) } };
  assert.throws(() => checkSignature(tampered), ConformanceError);
});

test('a tampered payload field is caught by the digest check', () => {
  const v = loadVector();
  const tampered = { ...v, input: { ...v.input, tenantId: 'someone-else' } };
  assert.throws(() => checkDigest(tampered), ConformanceError);
});

test('a divergent AssuranceTier string is caught by the enum drift guard', () => {
  const v = loadCompletionVector();
  const tampered = {
    ...v,
    assurance_tier_strings: ['self_reported', 'counterSigned', 'thirdPartyAttested'],
  };
  assert.throws(() => checkCompletion(tampered), ConformanceError);
});

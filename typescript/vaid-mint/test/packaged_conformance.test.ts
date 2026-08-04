/**
 * The packaged mint firewall itself.
 *
 * `src/conformance.ts` is what a consumer runs after `npm install vaid-mint`
 * (`npx vaid-mint-conformance`). The tests elsewhere prove the mint; this proves
 * the thing a consumer actually invokes to check it — including that it locates
 * its bundled vector and that it *fails* when handed a divergent one, which is
 * the only way to know the check is load-bearing rather than decorative.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  checkDocumentDigest,
  checkKernelSignature,
  checkLineageHash,
  checkPublicKeyOnlyVerification,
  checkVaidIdEqualsAgentId,
  ConformanceError,
  loadVector,
  bundledVectorNames,
  run,
  VECTOR_CHECKS,
} from '../src/conformance.js';

test('the packaged firewall passes against EVERY bundled vector', () => {
  const result = run();
  const covered = Object.keys(result).sort();

  // Every vector that ships is reached — not a fixed list this test also has to
  // remember. That duplication is precisely what let a new vector ship unchecked.
  assert.deepEqual(covered, bundledVectorNames());

  // Each one produced a real digest, and no two are the same — a firewall that
  // silently checked one vector four times would pass a count assertion.
  const digests = covered.map((n) => result[n]!.digest_sha256_hex);
  for (const d of digests) assert.equal(d.length, 64);
  assert.equal(new Set(digests).size, digests.length);
});

test('a vector shipped with no check is a BLOCKER, not a silent pass', () => {
  // The defect this change exists to close, asserted directly: the firewall must
  // refuse a vector it does not know how to check rather than ignoring it.
  const present = bundledVectorNames();
  const known = Object.keys(VECTOR_CHECKS);
  assert.deepEqual(
    present.filter((n) => !known.includes(n)),
    [],
    'a bundled vector has no entry in VECTOR_CHECKS',
  );
  assert.deepEqual(
    known.filter((n) => !present.includes(n)),
    [],
    'VECTOR_CHECKS names a vector that is not bundled',
  );
});

test('a divergent digest is reported as a BLOCKER, not swallowed', () => {
  assert.throws(
    () => checkDocumentDigest({ ...loadVector(), digest_sha256_hex: '00'.repeat(32) }),
    ConformanceError,
  );
});

test('a divergent kernel signature is reported as a BLOCKER', () => {
  const v = loadVector();
  assert.throws(
    () => checkKernelSignature({ ...v, ed25519: { ...v.ed25519, signature_hex: '00'.repeat(64) } }),
    ConformanceError,
  );
});

test('a tampered document field is caught by the digest check', () => {
  const v = loadVector();
  assert.throws(
    () =>
      checkDocumentDigest({
        ...v,
        input: { ...v.input, scope_boundary: ['data.aifactory.sub', 'data.everything'] },
      }),
    ConformanceError,
  );
});

test('an inconsistent lineage_hash is caught by the derivation check', () => {
  const v = loadVector();
  assert.throws(
    () => checkLineageHash({ ...v, input: { ...v.input, lineage_hash: '0'.repeat(64) } }),
    ConformanceError,
  );
});

test('a vaid_id that does not equal agent_id is caught', () => {
  const v = loadVector();
  assert.throws(
    () =>
      checkVaidIdEqualsAgentId({
        ...v,
        input: { ...v.input, vaid_id: '22222222-2222-2222-2222-222222222222' },
      }),
    ConformanceError,
  );
});

test('a signature that does not verify under the public key is caught', () => {
  const v = loadVector();
  assert.throws(
    () =>
      checkPublicKeyOnlyVerification({
        ...v,
        ed25519: { ...v.ed25519, signature_hex: '00'.repeat(64) },
      }),
    ConformanceError,
  );
});

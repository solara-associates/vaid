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
  run,
} from '../src/conformance.js';

test('the packaged firewall passes against both bundled vectors', () => {
  const { document, mintPop } = run();
  assert.equal(document.digest_sha256_hex.length, 64);
  assert.equal(document.ed25519.signature_hex.length, 128);
  // The mint-PoP vector must actually be reached — a firewall that silently
  // checked only the document would still pass every assertion above it.
  assert.equal(mintPop.digest_sha256_hex.length, 64);
  assert.notEqual(mintPop.digest_sha256_hex, document.digest_sha256_hex);
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

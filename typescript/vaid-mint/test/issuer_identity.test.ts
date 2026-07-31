/**
 * Mirrors the Rust `issuer_identity` unit tests. The load-bearing one is the
 * RFC 8037 vector: it checks this implementation against the STANDARD rather
 * than only against itself. Cross-language agreement is proven separately, by
 * the frozen `mint_v1` vector.
 */
import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  kernelKeyThumbprint,
  isValidTrustDomain,
  isSpecialUseTrustDomain,
  THUMBPRINT_URI_PREFIX,
  TRUST_DOMAIN_MAX_LEN,
} from '../src/issuerIdentity.js';

test('matches the published RFC 8037 Appendix A.3 thumbprint vector', () => {
  const key = Buffer.from('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', 'base64url');
  assert.equal(
    kernelKeyThumbprint(key),
    `${THUMBPRINT_URI_PREFIX}kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`,
  );
});

test('thumbprint is deterministic and key-bound', () => {
  const a = new Uint8Array(32).fill(7);
  const b = new Uint8Array(32).fill(8);
  assert.equal(kernelKeyThumbprint(a), kernelKeyThumbprint(a));
  assert.notEqual(kernelKeyThumbprint(a), kernelKeyThumbprint(b));
  assert.ok(kernelKeyThumbprint(a).startsWith(THUMBPRINT_URI_PREFIX));
});

test('accepts conforming trust domains', () => {
  for (const s of [
    'vaid.example',
    'synthera.solara.associates',
    'a.bc',
    'x-1.example',
    'deep.ly.nested.name.example',
  ]) {
    assert.ok(isValidTrustDomain(s), `should accept ${s}`);
  }
});

test('rejects non-conforming trust domains', () => {
  for (const s of [
    '',                    // empty
    'single',              // one label
    'Solara.Associates',   // uppercase — non-conforming, never normalized
    'solara.associates.',  // trailing dot
    'solara..associates',  // empty label
    '-lead.example',       // leading hyphen
    'trail-.example',      // trailing hyphen
    'under_score.example', // underscore: diverges from SPIFFE, deliberately
    '192.0.2.1',           // IP literal — all-numeric final label
    'sp ace.example',      // whitespace
    'sοlara.associates', // Greek omicron — homograph
  ]) {
    assert.ok(!isValidTrustDomain(s), `should reject ${JSON.stringify(s)}`);
  }
});

test('non-string input is rejected rather than coerced', () => {
  for (const v of [null, undefined, 42, {}, ['vaid.example']]) {
    assert.ok(!isValidTrustDomain(v));
  }
});

test('label and total length bounds are enforced', () => {
  assert.ok(!isValidTrustDomain(`${'a'.repeat(64)}.example`));
  assert.ok(isValidTrustDomain(`${'a'.repeat(63)}.example`));

  // 63+1+63+1+63+1+61 = 253 conforms; one more byte does not.
  const atLimit = [`${'a'.repeat(63)}`, 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(61)].join('.');
  assert.equal(atLimit.length, TRUST_DOMAIN_MAX_LEN);
  assert.ok(isValidTrustDomain(atLimit));

  const overLimit = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(62)].join('.');
  assert.equal(overLimit.length, TRUST_DOMAIN_MAX_LEN + 1);
  assert.ok(!isValidTrustDomain(overLimit));
});

test('special-use names are grammatical but flagged', () => {
  assert.ok(isValidTrustDomain('vaid.example'));
  assert.ok(isSpecialUseTrustDomain('vaid.example'));
  assert.ok(isSpecialUseTrustDomain('foo.internal'));
  assert.ok(!isSpecialUseTrustDomain('synthera.solara.associates'));
});

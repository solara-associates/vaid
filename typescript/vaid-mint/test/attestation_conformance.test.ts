/**
 * Consent attestation conformance gate (`att_version` 1). TypeScript side.
 *
 * The vendored vector `vectors/attestation_v1.json` is byte-identical to the Rust
 * and Python copies; CI `cmp`s all three, so "TypeScript reproduces the vector" plus
 * "the vectors are the same bytes" gives Rust == Python == TypeScript.
 *
 * Nothing here reconstructs the vector's contents in code.
 *
 * ADDITIVE: the attestation is a separate signed object, so freezing it re-freezes
 * nothing. `mint_v1.json`, `mint_pop_v1.json` and `chain_v1.json` are untouched and
 * `sig_version` is unchanged.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ed25519PublicKey, ed25519Sign, fromHex, toHex } from 'vaid-pop';

import {
  ATTESTATION_VERSION,
  canonicalAttestationSigningBytes,
  verifyAttestationAuthenticity,
  type ConsentAttestation,
} from '../src/index.js';

interface AttestationVector {
  attestation: ConsentAttestation;
  digest_sha256_hex: string;
  signature_hex: string;
  ed25519: { kernel_private_key_seed_hex: string; kernel_public_key_hex: string };
}

const VECTOR = JSON.parse(
  readFileSync(new URL('../../vectors/attestation_v1.json', import.meta.url), 'utf8'),
) as AttestationVector;

test('reproduces the frozen digest', () => {
  assert.equal(
    toHex(canonicalAttestationSigningBytes(VECTOR.attestation)),
    VECTOR.digest_sha256_hex,
    'canonicalization drift',
  );
});

test('reproduces the frozen signature', () => {
  const seed = fromHex(VECTOR.ed25519.kernel_private_key_seed_hex);

  assert.equal(
    toHex(ed25519PublicKey(seed)),
    VECTOR.ed25519.kernel_public_key_hex,
    'the seed does not derive the vector kernel public key',
  );

  assert.equal(
    toHex(ed25519Sign(canonicalAttestationSigningBytes(VECTOR.attestation), seed)),
    VECTOR.signature_hex,
    'signature drift',
  );
});

test('the frozen signature verifies as authentic', () => {
  const signed: ConsentAttestation = {
    ...VECTOR.attestation,
    signature: Array.from(fromHex(VECTOR.signature_hex)),
  };

  assert.ok(
    verifyAttestationAuthenticity(
      fromHex(VECTOR.ed25519.kernel_public_key_hex),
      signed,
    ),
    'the frozen attestation must verify under the frozen kernel key',
  );
});

test('the frozen attestation has the expected shape', () => {
  const a = VECTOR.attestation;

  assert.equal(a.att_version, ATTESTATION_VERSION);
  assert.deepEqual(a.signature, [], "the vector's attestation is UNSIGNED");

  // Spec C.2: the top-level pair is the ATTESTING PARENT ISSUER'S, the child_* pair
  // is what is AUTHORIZED. Frozen with the two DIFFERENT, so a future change that
  // conflated them would fail here rather than pass silently.
  assert.notEqual(
    a.trust_domain,
    a.child_trust_domain,
    'the vector must exercise the cross-trust-domain case the object exists for',
  );

  assert.ok(a.expires_at > a.issued_at, 'the frozen window must be satisfiable');
});

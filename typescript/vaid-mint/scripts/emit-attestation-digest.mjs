/**
 * Byte-agreement probe for the detached consent attestation format. TypeScript side.
 *
 * Run with `npm run build && node scripts/emit-attestation-digest.mjs` from
 * `typescript/vaid-mint`.
 *
 * Deliberately NOT a frozen vector, and nothing vendors its output. The attestation
 * is a new signed object; freezing its canonicalization is the one decision here
 * that is expensive to unwind, so the format stays reviewable until it has been
 * reviewed. What this proves in the meantime is the property a vector would prove —
 * that all three implementations canonicalize and sign the same bytes — without
 * committing to the shape.
 *
 * Emits byte-identical JSON to the Rust and Python probes;
 * `scripts/attestation_byte_agreement.sh` runs all three and diffs them.
 */

import { ed25519PublicKey, ed25519Sign, fromHex, toHex } from 'vaid-pop';

import {
  buildUnsignedAttestation,
  canonicalAttestationSigningBytes,
  kernelKeyThumbprint,
} from '../dist/index.js';

const KERNEL_SEED_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const PARENT_UUID = 'd0000000-0000-0000-0000-000000000001';
const CHILD_UUID = 'd0000000-0000-0000-0000-000000000002';

const COMMENT =
  'Byte-agreement probe for the consent attestation format. NOT A FROZEN VECTOR ' +
  'and not vendored anywhere. All three implementations must emit this file ' +
  'byte-identically; scripts/attestation_byte_agreement.sh checks it.';

/** Stable key order, so the three probes are diffable as text. */
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, sortKeys(value[k])]),
    );
  }
  return value;
}

const seed = fromHex(KERNEL_SEED_HEX);
const kernelPub = ed25519PublicKey(seed);

const unsigned = buildUnsignedAttestation({
  parentVaid: PARENT_UUID,
  childVaid: CHILD_UUID,
  childTrustDomain: 'b.example',
  childTenantId: 'aifactory',
  // Fixed instants: a probe that depends on the wall clock cannot be diffed across
  // three processes.
  issuedAt: '2026-06-04T12:00:00Z',
  expiresAt: '2026-06-05T12:00:00Z',
  scopeBoundary: ['data.aifactory.sub'],
  capabilitySet: ['read'],
  trustDomain: 'a.example',
  kernelKeyThumbprint: kernelKeyThumbprint(kernelPub),
});

const digest = canonicalAttestationSigningBytes(unsigned);
const signature = ed25519Sign(digest, seed);

const out = {
  _comment: COMMENT,
  attestation: unsigned,
  digest_sha256_hex: toHex(digest),
  kernel_public_key_hex: toHex(kernelPub),
  signature_hex: toHex(signature),
};

console.log(JSON.stringify(sortKeys(out), null, 2));

/**
 * Canonical PoP conformance gate (TypeScript side of the cross-language firewall).
 *
 * The vendored vector `vectors/operator_pop_v1.json` ships inside the package so
 * a consumer runs this gate against the exact bytes the primitive was proven
 * against. These tests assert the TypeScript signer reproduces the frozen digest
 * + Ed25519 signature byte-for-byte. A mismatch is a BLOCKER: any conforming
 * implementation must reproduce the same vector.
 *
 * Mirror of the Rust `crates/vaid-client/tests/conformance.rs` and the Python
 * `python/vaid-pop/tests/test_conformance.py`.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  ed25519Sign,
  fromHex,
  signPayload,
  toHex,
  verifySignedPayload,
  type RequestAuthPayload,
} from '../src/index.js';
import { loadFrozenVector } from './vectors.js';

const vector = loadFrozenVector('operator_pop_v1.json');
const payload = vector.input as unknown as RequestAuthPayload;
const seed = fromHex(vector.ed25519.private_key_seed_hex!);

test('reproduces the frozen PoP digest byte-for-byte', () => {
  const digest = canonicalRequestSigningBytes(payload);
  assert.equal(
    toHex(digest),
    vector.digest_sha256_hex,
    'TypeScript PoP digest diverged from the frozen vector — BLOCKER',
  );
  assert.equal(digest.length, 32);
});

test('derives the frozen Ed25519 public key from the frozen seed', () => {
  assert.equal(
    toHex(ed25519PublicKey(seed)),
    vector.ed25519.public_key_hex,
    'public key diverged — BLOCKER',
  );
});

test('reproduces the frozen PoP signature byte-for-byte', () => {
  const signature = ed25519Sign(canonicalRequestSigningBytes(payload), seed);
  assert.equal(
    toHex(signature),
    vector.ed25519.signature_hex,
    'TypeScript PoP signature diverged from the frozen vector — BLOCKER',
  );
  assert.equal(signature.length, 64);
});

test('signPayload — the surface a holder calls — produces the same frozen signature', () => {
  // Guards the composed helper, not just the two primitives underneath it: a
  // signer that canonicalized differently would still pass the tests above.
  assert.equal(toHex(signPayload(payload, seed)), vector.ed25519.signature_hex);
});

test('the frozen signature verifies under the frozen public key', () => {
  assert.equal(
    verifySignedPayload(payload, ed25519PublicKey(seed), fromHex(vector.ed25519.signature_hex)),
    true,
  );
});

test('a tampered payload does not verify', () => {
  const tampered: RequestAuthPayload = { ...payload, path: '/vaid/mint/elsewhere' };
  assert.equal(
    verifySignedPayload(tampered, ed25519PublicKey(seed), fromHex(vector.ed25519.signature_hex)),
    false,
    'a rewritten path must break the signature',
  );
});

test('a different key does not verify the frozen signature', () => {
  const otherPublicKey = ed25519PublicKey(fromHex('11'.repeat(32)));
  assert.equal(
    verifySignedPayload(payload, otherPublicKey, fromHex(vector.ed25519.signature_hex)),
    false,
  );
});

test('a malformed key or wrong-length signature is false, never a throw', () => {
  assert.equal(verifySignedPayload(payload, new Uint8Array(3), new Uint8Array(64)), false);
  assert.equal(
    verifySignedPayload(payload, ed25519PublicKey(seed), new Uint8Array(3)),
    false,
  );
});

/**
 * Completion-record conformance gate (TypeScript side of the cross-language
 * firewall).
 *
 * The vendored vector `vectors/completion_v1.json` is byte-identical to the Rust
 * and Python copies (a CI drift check enforces that). Asserts the TypeScript
 * signer reproduces the frozen digest + signature for a real `CompletionRecord`,
 * and — because this is the FIRST vector with an enum — that every
 * `AssuranceTier` serializes to exactly the frozen string. That enum is the most
 * likely place for silent cross-language drift, because the string lands inside
 * the signed bytes.
 *
 * Mirror of the Rust `crates/vaid-pop/tests/completion_conformance.rs`.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ASSURANCE_TIERS,
  AssuranceTier,
  buildCompletionRecord,
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  ed25519Sign,
  fromHex,
  toHex,
  type CompletionRecord,
} from '../src/index.js';
import { loadFrozenVector } from './vectors.js';

const vector = loadFrozenVector('completion_v1.json');
const record = vector.input as unknown as CompletionRecord;
const seed = fromHex(vector.ed25519.private_key_seed_hex!);

test('reproduces the frozen completion digest byte-for-byte', () => {
  const digest = canonicalRequestSigningBytes(record);
  assert.equal(
    toHex(digest),
    vector.digest_sha256_hex,
    'TypeScript completion digest diverged from the frozen vector — BLOCKER',
  );
  assert.equal(digest.length, 32);
});

test('reproduces the frozen completion signature byte-for-byte', () => {
  assert.equal(
    toHex(ed25519PublicKey(seed)),
    vector.ed25519.public_key_hex,
    'public key diverged — BLOCKER',
  );
  assert.equal(
    toHex(ed25519Sign(canonicalRequestSigningBytes(record), seed)),
    vector.ed25519.signature_hex,
    'TypeScript completion signature diverged from the frozen vector — BLOCKER',
  );
});

test('THE ENUM DRIFT GUARD: AssuranceTier strings match the frozen vector, in order', () => {
  assert.deepEqual(
    [...ASSURANCE_TIERS],
    vector.assurance_tier_strings,
    'AssuranceTier strings diverged from the frozen vector — BLOCKER',
  );
  // And the input's declared tier is the one the single signature substantiates.
  assert.equal(record.assuranceTier, AssuranceTier.SelfReported);
});

test('buildCompletionRecord round-trips the frozen record to the same digest', () => {
  // Proves the constructor emits exactly the nine frozen fields — an extra or
  // renamed field would change the canonical bytes.
  const rebuilt = buildCompletionRecord(record);
  assert.equal(toHex(canonicalRequestSigningBytes(rebuilt)), vector.digest_sha256_hex);
  assert.deepEqual(Object.keys(rebuilt).sort(), Object.keys(record).sort());
});

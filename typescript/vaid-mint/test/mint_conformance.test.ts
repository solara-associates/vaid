/**
 * Canonical mint conformance gate (TypeScript side of the cross-language
 * firewall).
 *
 * The vendored vector `vectors/mint_v1.json` is byte-identical to the copies
 * shipped in the Rust crate and the Python package (a CI drift check enforces
 * that). These tests assert the TypeScript mint reproduces the frozen
 * VAID-document digest + kernel signature byte-for-byte, and that the derived
 * fields (`lineage_hash`, `vaid_id == agent_id`) match. A mismatch is a BLOCKER.
 *
 * This is the vector with everything the flat-string case does not have: arrays
 * (`scope_boundary`, `capability_set`, `public_key_der`, `kernel_signature`), a
 * number (`sig_version`), a null (`parent_vaid`), and the rule that
 * `kernel_signature` is nulled — not removed, not left empty — when
 * canonicalizing for signing.
 *
 * Per Decision B this proves self-consistency WITHIN this repo (Rust == Python
 * == TypeScript), NOT conformance against the managed authority's VAID format.
 *
 * Mirror of the Rust `crates/vaid-mint/tests/mint_conformance.rs`.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { THUMBPRINT_URI_PREFIX } from '../src/issuerIdentity.js';

import { canonicalize, ed25519PublicKey, ed25519Sign, fromHex, sha256, toHex } from 'vaid-pop';

import { canonicalVaidSigningBytes, computeLineageHash } from '../src/index.js';
import { loadMintVector } from './vectors.js';

const vector = loadMintVector();
const document = vector.input;
const kernelSeed = fromHex(vector.ed25519.kernel_private_key_seed_hex);

test('reproduces the frozen VAID-document digest byte-for-byte', () => {
  const digest = canonicalVaidSigningBytes(document);
  assert.equal(
    toHex(digest),
    vector.digest_sha256_hex,
    'TypeScript VAID-document digest diverged from the frozen vector — BLOCKER',
  );
  assert.equal(digest.length, 32);
});

test('derives the frozen kernel public key from the frozen seed', () => {
  assert.equal(
    toHex(ed25519PublicKey(kernelSeed)),
    vector.ed25519.kernel_public_key_hex,
    'kernel public key diverged — BLOCKER',
  );
});

test('reproduces the frozen kernel signature byte-for-byte', () => {
  const signature = ed25519Sign(canonicalVaidSigningBytes(document), kernelSeed);
  assert.equal(
    toHex(signature),
    vector.ed25519.signature_hex,
    'TypeScript kernel signature diverged from the frozen vector — BLOCKER',
  );
  assert.equal(signature.length, 64);
});

test('reproduces the frozen lineage_hash by derivation, not by reading it back', () => {
  assert.equal(
    computeLineageHash(document.parent_vaid, document.agent_id),
    document.lineage_hash,
    'recomputed lineage_hash diverged from the document — BLOCKER',
  );
});

test('vaid_id equals agent_id', () => {
  assert.equal(
    document.vaid_id,
    document.agent_id,
    'vaid_id must equal agent_id — they are the same UUID',
  );
});

test('the signing bytes null kernel_signature rather than dropping or keeping it', () => {
  // The load-bearing rule of this vector. Three documents that differ ONLY in
  // `kernel_signature` must produce one digest; a document with the field
  // *absent* must not, because JCS would then canonicalize a different key set.
  const empty = canonicalVaidSigningBytes(document);
  const signed = canonicalVaidSigningBytes({
    ...document,
    kernel_signature: Array.from(fromHex(vector.ed25519.signature_hex)),
  });
  const nulled = canonicalVaidSigningBytes({
    ...document,
    kernel_signature: null as unknown as number[],
  });
  assert.equal(toHex(empty), vector.digest_sha256_hex);
  assert.equal(toHex(signed), vector.digest_sha256_hex, 'attaching a signature must not change what it covers');
  assert.equal(toHex(nulled), vector.digest_sha256_hex);

  // And nulling is not the same as omitting. `canonicalVaidSigningBytes` always
  // re-adds the key, so this has to be asserted one layer down, at the raw JCS
  // input: a document canonicalized WITHOUT the key has a different key set and
  // therefore different canonical bytes. An implementation that deleted the
  // field instead of nulling it would produce this digest and fail the vector.
  const { kernel_signature: _omitted, ...withoutField } = document;
  assert.notEqual(
    toHex(sha256(canonicalize(withoutField))),
    vector.digest_sha256_hex,
    'omitting the field is NOT the same as nulling it — the key set differs',
  );
  assert.equal(
    toHex(sha256(canonicalize({ ...withoutField, kernel_signature: null }))),
    vector.digest_sha256_hex,
    'nulling the field is what the frozen digest is over',
  );
});

test('every signed field is covered — a one-field change breaks the digest', () => {
  // Walks the document rather than spot-checking, so a future field added to the
  // struct cannot be silently left outside the coverage this test claims.
  const mutations: Record<string, unknown> = {
    // Must NOT be the document's real value, or the "mutation" is a no-op and
    // the assertion below passes vacuously. It read `3` while the document was
    // v2; the v3 bump made the two coincide, and this test caught it.
    sig_version: 4,
    vaid_id: '22222222-2222-2222-2222-222222222222',
    agent_id: '22222222-2222-2222-2222-222222222222',
    agent_class: 'other',
    version: '9.9.9',
    tenant_id: 'someone-else',
    issued_at: '2026-06-04T12:00:01Z',
    expires_at: '2026-06-05T12:00:01Z',
    public_key_der: [...document.public_key_der.slice(0, 31), 99],
    parent_vaid: null,
    scope_boundary: ['data.aifactory.sub', 'data.everything'],
    lineage_hash: '0'.repeat(64),
    capability_set: ['read', 'write'],
    trust_domain: 'other.example',
    kernel_key_thumbprint: `${THUMBPRINT_URI_PREFIX}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
  };

  for (const key of Object.keys(document)) {
    if (key === 'kernel_signature') continue; // deliberately outside the digest
    assert.ok(key in mutations, `no mutation defined for signed field '${key}'`);
    const mutated = { ...document, [key]: mutations[key] };
    assert.notEqual(
      toHex(canonicalVaidSigningBytes(mutated)),
      vector.digest_sha256_hex,
      `changing '${key}' must change the digest — it is a signed field`,
    );
  }
});

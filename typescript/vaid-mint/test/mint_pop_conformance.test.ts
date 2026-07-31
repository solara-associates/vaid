/**
 * Mint proof-of-possession conformance gate (TypeScript side of the
 * cross-language firewall).
 *
 * The vendored vector `vectors/mint_pop_v1.json` is byte-identical to the Rust and
 * Python copies (a CI drift check enforces that). It pins `MintPopPayload` — the
 * payload a holder signs to prove it controls the BYO public key it registers at
 * mint.
 *
 * Why this gate arrived after the other four: `MintPopPayload` was the one
 * **signed** structure in VAID with no frozen artifact (`docs/spec/encoding.md`
 * E.11). The three reference implementations agreed on it *by construction* — they
 * share the `vaid-pop` primitive and were written against each other — not because
 * anything held them to it. A fourth implementation could have encoded it
 * differently, passed every conformance gate in the repo, and failed only later as
 * an unexplained proof-of-possession rejection at mint.
 *
 * What this vector pins that the other four do not:
 *
 * - **A JSON `null` inside signed bytes.** It is the root case, so `parentVaid` is
 *   null. No other frozen vector contains a null, so nothing previously held an
 *   implementation to E.7 — an absent value is `null` with its key retained, never
 *   an omitted key.
 * - **The registered key is the signing key**, so the vector is checkable
 *   end-to-end through `verifySignedPayload` — the same call the mint makes before
 *   issuing.
 *
 * Mirror of the Rust `crates/vaid-mint/tests/mint_pop_conformance.rs` and the
 * Python `test_mint_pop_conformance.py`.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  canonicalizeToString,
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  ed25519Sign,
  fromHex,
  toHex,
  verifySignedPayload,
} from 'vaid-pop';

import { buildMintPopPayload } from '../src/index.js';
import { checkMintPop, ConformanceError, type MintPopVector } from '../src/conformance.js';

const vector = JSON.parse(
  readFileSync(new URL('../../vectors/mint_pop_v1.json', import.meta.url), 'utf8'),
) as MintPopVector;

const seed = fromHex(vector.ed25519.private_key_seed_hex);
const registered = ed25519PublicKey(seed);

/** The payload as the mint's own constructor builds it — not read back from the vector. */
function builtPayload() {
  return buildMintPopPayload(
    {
      agentClass: 'runner',
      version: '1.0.0',
      tenantId: 'aifactory',
      parentVaid: null,
      scopeBoundary: ['data.aifactory'],
      capabilitySet: ['read'],
      publicKeyDer: registered,
    },
    {
      publicKeyDer: registered,
      nonce: '0123456789abcdef0123456789abcdef',
      issuedAt: '2026-06-04T12:00:00Z',
    },
  );
}

test('reproduces the frozen mint-PoP digest byte-for-byte', () => {
  const digest = canonicalRequestSigningBytes(vector.input);
  assert.equal(
    toHex(digest),
    vector.digest_sha256_hex,
    'TypeScript mint-PoP digest diverged from the frozen vector — BLOCKER',
  );
  assert.equal(digest.length, 32);
});

test('derives the frozen holder public key and reproduces the frozen signature', () => {
  assert.equal(toHex(registered), vector.ed25519.public_key_hex, 'holder public key diverged');
  const signature = ed25519Sign(canonicalRequestSigningBytes(vector.input), seed);
  assert.equal(
    toHex(signature),
    vector.ed25519.signature_hex,
    'TypeScript mint-PoP signature diverged from the frozen vector — BLOCKER',
  );
  assert.equal(signature.length, 64);
});

test("the mint's own payload constructor reproduces the frozen payload", () => {
  // Reading `input` back would only prove an object round-trips; this proves the
  // code path that actually runs at mint emits these bytes.
  //
  // Compared CANONICALLY: key order is precisely what JCS makes irrelevant, and
  // the frozen vector's keys are sorted while the constructor emits declaration
  // order. An order-sensitive comparison would report a divergence that does not
  // exist.
  assert.equal(canonicalizeToString(builtPayload()), canonicalizeToString(vector.input));
  assert.equal(
    toHex(canonicalRequestSigningBytes(builtPayload())),
    vector.digest_sha256_hex,
  );
});

test('THE E.7 GUARD: parentVaid is a present null, not an omitted key', () => {
  assert.ok('parentVaid' in vector.input, 'the key must be present — encoding.md E.7');
  assert.equal(vector.input.parentVaid, null, 'this is the root case; parentVaid is null');

  const { parentVaid: _omitted, ...without } = vector.input;
  assert.notEqual(
    toHex(canonicalRequestSigningBytes(without)),
    vector.digest_sha256_hex,
    'omitting parentVaid MUST change the digest — otherwise E.7 is untested',
  );
});

test('this is the only frozen vector carrying a JSON null', () => {
  // Stated as a test so that if a future vector adds a null, or this one loses
  // it, the claim in encoding.md E.7 and E.11 gets revisited rather than rotting.
  assert.ok(
    canonicalizeToString(vector.input).includes(':null'),
    'the canonical bytes must contain a null — that is half this vector\'s purpose',
  );
});

test('THE PoP SEMANTIC: the signature verifies against the REGISTERED key', () => {
  const signature = fromHex(vector.ed25519.signature_hex);
  assert.equal(
    toHex(Uint8Array.from(vector.input.publicKeyDer)),
    vector.ed25519.public_key_hex,
    'publicKeyDer must BE the holder\'s public key — that is what PoP means',
  );
  assert.equal(
    verifySignedPayload(vector.input, Uint8Array.from(vector.input.publicKeyDer), signature),
    true,
    'the frozen PoP must verify against the registered key — BLOCKER',
  );
});

test('a captured PoP is not replayable to mint a higher-privilege VAID', () => {
  // The payload binds the full requested attribute set for exactly this reason.
  const signature = fromHex(vector.ed25519.signature_hex);
  for (const escalation of [
    { capabilitySet: ['read', 'write'] },
    { scopeBoundary: ['data.aifactory', 'data.everything'] },
    { tenantId: 'someone-else' },
  ]) {
    assert.equal(
      verifySignedPayload({ ...vector.input, ...escalation }, registered, signature),
      false,
      `a captured PoP must not verify for ${JSON.stringify(escalation)}`,
    );
  }
});

test('the packaged check is load-bearing — it fails on a divergent vector', () => {
  // A check that cannot fail proves nothing about the one that passes.
  assert.throws(
    () => checkMintPop({ ...vector, digest_sha256_hex: '00'.repeat(32) }),
    ConformanceError,
  );
  assert.throws(
    () =>
      checkMintPop({
        ...vector,
        ed25519: { ...vector.ed25519, signature_hex: '00'.repeat(64) },
      }),
    ConformanceError,
  );
  const { parentVaid: _omitted, ...without } = vector.input;
  assert.throws(
    () => checkMintPop({ ...vector, input: without as typeof vector.input }),
    ConformanceError,
  );
  assert.throws(
    () =>
      checkMintPop({
        ...vector,
        input: { ...vector.input, capabilitySet: ['read', 'write'] },
      }),
    ConformanceError,
  );
});

/**
 * Public-key-only VAID document verification. The verifying party holds ONLY the
 * kernel public key, never a `ReferenceIssuer` and never a private key.
 *
 * Revocation is outside the conformance surface and is not consulted here; these
 * are authenticity tests. `verifies the frozen mint vector…` is the shared,
 * byte-identical input the Rust and Python suites verify too — the cross-language
 * agreement anchor.
 *
 * Mirror of the Rust `crates/vaid-mint/tests/document_verify.rs`.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fromHex } from 'vaid-pop';

import {
  ReferenceIssuer,
  verifyLineageHash,
  verifyVaidAuthenticity,
  type Vaid,
} from '../src/index.js';
import { loadMintVector } from './vectors.js';

/**
 * Mint a root, then return ONLY its issuer's kernel public key and the document —
 * the issuer itself goes out of scope, so verification has no access to it.
 */
function publicKeyAndDoc(): { publicKey: Uint8Array; vaid: Vaid } {
  const issuer = ReferenceIssuer.ephemeral(1);
  const vaid = issuer.issueVaidWithLineage({
    agentClass: 'root',
    version: '1.0.0',
    tenantId: 't',
    parentVaid: null,
    scopeBoundary: ['data.x'],
    capabilitySet: ['read'],
  });
  return { publicKey: issuer.kernelPublicKey(), vaid };
}

test('a third party verifies with the public key only', () => {
  const { publicKey, vaid } = publicKeyAndDoc();
  assert.equal(
    verifyVaidAuthenticity(publicKey, vaid),
    true,
    "a genuine VAID must verify against the issuer's public key alone",
  );
});

test('a tampered document fails', () => {
  const { publicKey, vaid } = publicKeyAndDoc();
  // Widen the scope after signing — a valid-looking document, broken signature.
  const forged: Vaid = { ...vaid, scope_boundary: ['data.x', 'data.everything'] };
  assert.equal(verifyVaidAuthenticity(publicKey, forged), false, 'a rewritten field must fail');
});

test('a different key does not verify', () => {
  const { vaid } = publicKeyAndDoc();
  const other = ReferenceIssuer.ephemeral(1).kernelPublicKey();
  assert.equal(
    verifyVaidAuthenticity(other, vaid),
    false,
    "another issuer's key must not verify it",
  );
});

test('a lineage_hash mismatch is caught explicitly, not incidentally', () => {
  const { publicKey, vaid } = publicKeyAndDoc();
  assert.equal(verifyLineageHash(vaid), true, "the genuine document's lineage_hash is consistent");

  const bad: Vaid = { ...vaid, lineage_hash: '0'.repeat(56) + 'deadbeef' };
  assert.equal(
    verifyLineageHash(bad),
    false,
    'an inconsistent lineage_hash must be caught by the explicit check',
  );
  // And the full authenticity check rejects it too — the explicit check runs
  // BEFORE the signature check, so it fires even though the signature is also
  // broken by the edit.
  assert.equal(verifyVaidAuthenticity(publicKey, bad), false);
});

test('a stale signature-scheme version is rejected', () => {
  const { publicKey, vaid } = publicKeyAndDoc();
  assert.equal(verifyVaidAuthenticity(publicKey, { ...vaid, sig_version: 1 }), false);
});

test('does NOT check expiry — an expired but genuinely signed VAID is authentic', () => {
  // The documented scope boundary: authenticity is not standing. A negative TTL
  // issues a document whose `expires_at` is already past.
  const issuer = ReferenceIssuer.ephemeral(-1);
  const vaid = issuer.issueVaidWithLineage({
    agentClass: 'root',
    version: '1.0.0',
    tenantId: 't',
    parentVaid: null,
    scopeBoundary: [],
    capabilitySet: [],
  });
  assert.equal(
    verifyVaidAuthenticity(issuer.kernelPublicKey(), vaid),
    true,
    'verifyVaidAuthenticity answers authenticity, and expiry is not authenticity',
  );
  assert.equal(issuer.verifyVaid(vaid), false, 'the issuer, which does check standing, rejects it');
});

test('verifies the frozen mint vector with the public key only', () => {
  // Reconstruct the signed document from the FROZEN mint_v1 vector and verify it
  // against the vector's kernel PUBLIC key alone. The Rust and Python suites
  // verify the identical vector — this is the cross-language agreement anchor.
  const vector = loadMintVector();
  const signature = fromHex(vector.ed25519.signature_hex);
  const publicKey = fromHex(vector.ed25519.kernel_public_key_hex);
  const signed: Vaid = { ...vector.input, kernel_signature: Array.from(signature) };

  assert.equal(
    verifyVaidAuthenticity(publicKey, signed),
    true,
    'the frozen mint vector must verify under its kernel public key alone',
  );

  // And a one-byte flip of the signature must fail.
  const flipped = Array.from(signature);
  flipped[0] ^= 0x01;
  assert.equal(verifyVaidAuthenticity(publicKey, { ...signed, kernel_signature: flipped }), false);
});

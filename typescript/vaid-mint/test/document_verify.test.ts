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
  isExpired,
  parseRfc3339,
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

// ── RFC 3339 requires an offset (vaid#79, Session 240) ──

test('an offsetless expiry is EXPIRED, not live — and the three implementations agree', () => {
  // `Date.parse` reads a date-time with no offset as LOCAL time, so this
  // implementation used to call such a document live, while Python's
  // `_parse_rfc3339` and Rust's `DateTime::parse_from_rfc3339` both refuse it and
  // call it expired. TypeScript was the odd one out, fail-OPEN, and nothing tested
  // it: `verdict_v1.json` pins an unreadable expiry and a numeric-offset expiry,
  // and has no offsetless case.
  assert.equal(isExpired({ expires_at: '2999-01-01T00:00:00' } as Vaid), true);
  assert.equal(isExpired({ expires_at: '2999-01-01T00:00:00Z' } as Vaid), false);
});

test('the verdict does not move with the verifier timezone', () => {
  // The bug this closes was found by a vector case that passed on a UTC+2 laptop
  // and failed on a UTC runner — the same document, the same comparison, two
  // answers. Asserted here over the forms RFC 3339 does allow, so a future
  // loosening of the parser has to break this test to get through.
  for (const [a, b] of [
    ['2026-06-05T12:00:00Z', '2026-06-05T13:00:00+01:00'],
    ['2026-06-05T12:00:00Z', '2026-06-05T07:00:00-05:00'],
    ['2026-06-05T12:00:00z', '2026-06-05T12:00:00+00:00'],
  ]) {
    assert.equal(
      parseRfc3339(a),
      parseRfc3339(b),
      `${a} and ${b} are the same instant and must parse identically`,
    );
  }
  assert.equal(parseRfc3339('2026-06-05T12:00:00'), null, 'no offset is not RFC 3339');
  assert.equal(parseRfc3339('whenever'), null);
  assert.equal(parseRfc3339(null), null);
});

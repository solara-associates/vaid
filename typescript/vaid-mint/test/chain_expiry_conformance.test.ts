/**
 * Expiry-containment conformance gate (vaid#79). TypeScript side.
 *
 * The vendored vector `vectors/chain_expiry_v1.json` is byte-identical to the Rust
 * (`crates/vaid-mint/tests/vectors/`) and Python (`vaid_mint/vectors/`) copies; CI
 * `cmp`s all three, so "TypeScript reproduces the vector" plus "the vectors are the
 * same bytes" gives Rust == Python == TypeScript without a fourth comparison.
 *
 * Nothing here reconstructs the vector's expectations in code. A test that builds
 * its own expectation proves only that the code agrees with itself — and that is
 * precisely how the defect this vector closes survived: `chain_v1` asserted
 * `attenuated` over a chain whose every document had expired, and three
 * implementations agreed with it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ed25519PublicKey, ed25519Sign, fromHex, toHex } from 'vaid-pop';

import {
  AttestationBundle,
  canonicalVaidSigningBytes,
  expiryAttenuatesWithin,
  PresentedBundle,
  SingleKernelKey,
  verifyChainAt,
  type Vaid,
} from '../src/index.js';

interface Entry {
  _role: string;
  digest_sha256_hex: string;
  signature_hex: string;
  document: Vaid;
}

interface ChainCase {
  name: string;
  why: string;
  chain: Entry[];
  verification_instant: string;
  expected_verification: string;
}

interface ContainmentCase {
  name: string;
  why: string;
  parent_expires_at: string | null;
  child_expires_at: string | null;
  expected: string;
}

interface ExpiryVector {
  ed25519: {
    kernel_private_key_seed_hex: string;
    kernel_public_key_hex: string;
    kernel_key_thumbprint: string;
  };
  expiry_containment: ContainmentCase[];
  cases: ChainCase[];
}

const VECTOR = JSON.parse(
  readFileSync(new URL('../../vectors/chain_expiry_v1.json', import.meta.url), 'utf8'),
) as ExpiryVector;

const signed = (e: Entry): Vaid => ({
  ...e.document,
  kernel_signature: Array.from(fromHex(e.signature_hex)),
});

test('reproduces every frozen digest and signature', () => {
  // Every document in every case, from the vector's own kernel seed. Without this
  // the verdicts below could be verdicts over bytes nobody checked.
  const seed = fromHex(VECTOR.ed25519.kernel_private_key_seed_hex);
  assert.equal(
    toHex(ed25519PublicKey(seed)),
    VECTOR.ed25519.kernel_public_key_hex,
    'the seed does not derive the vector kernel public key',
  );

  for (const c of VECTOR.cases) {
    for (const entry of c.chain) {
      const digest = canonicalVaidSigningBytes(entry.document);
      assert.equal(toHex(digest), entry.digest_sha256_hex, `digest drift at ${c.name} / ${entry._role}`);
      assert.equal(
        toHex(ed25519Sign(digest, seed)),
        entry.signature_hex,
        `signature drift at ${c.name} / ${entry._role}`,
      );
    }
  }
});

test('every expiry containment case', () => {
  // THE MATCHER, as the mint applies it to the document its issuer returned.
  for (const c of VECTOR.expiry_containment) {
    const permitted = expiryAttenuatesWithin(c.parent_expires_at, c.child_expires_at);
    assert.equal(
      permitted,
      c.expected === 'permitted',
      `expiry containment drift: ${c.name} — expected ${c.expected}`,
    );
  }
});

test('every chain case reaches its frozen verdict', () => {
  // THE WALK, at each case's own stated instant — never the suite's clock.
  const publicKey = fromHex(VECTOR.ed25519.kernel_public_key_hex);

  for (const c of VECTOR.cases) {
    const docs = c.chain.map(signed);
    const verdict = verifyChainAt(
      new SingleKernelKey(publicKey),
      docs[docs.length - 1]!,
      new PresentedBundle(docs),
      new AttestationBundle(),
      new Date(c.verification_instant),
    );
    assert.equal(verdict, c.expected_verification, `chain verdict drift: ${c.name}`);
  }
});

test('the vector carries positive controls on both surfaces', () => {
  // The controls are load-bearing, so their presence is asserted rather than
  // assumed. An implementation that refuses everything satisfies every negative case
  // in this file; only a case that MUST succeed catches it.
  const verdicts = VECTOR.cases.map((c) => c.expected_verification);

  assert.ok(
    verdicts.includes('attenuated'),
    'no chain case must succeed — every negative below it is vacuous',
  );
  assert.ok(
    verdicts.includes('expired'),
    'the vector must carry the lapsed-ancestor case it exists for',
  );
  assert.ok(
    verdicts.includes('not_attenuated'),
    'the vector must carry the child-outliving-its-parent case',
  );
  assert.ok(
    VECTOR.expiry_containment.some((c) => c.expected === 'permitted'),
    'no containment case must succeed — the predicate could return false always',
  );
});

test('every chain case states its own verification instant', () => {
  // A case without a stated instant would be asserted against whatever the calendar
  // said on the day the suite ran — which is exactly how chain_v1 came to pin
  // `attenuated` over three documents that had been dead since June.
  for (const c of VECTOR.cases) {
    assert.ok(
      typeof c.verification_instant === 'string' && c.verification_instant.endsWith('Z'),
      `${c.name} has no stated verification instant`,
    );
  }
});

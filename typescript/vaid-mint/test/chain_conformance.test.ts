/**
 * Chain-presentation conformance gate (ADR-0003 §3). TypeScript side.
 *
 * The vendored vector `vectors/chain_v1.json` is byte-identical to the Rust
 * (`crates/vaid-mint/tests/vectors/`) and Python (`vaid_mint/vectors/`) copies; CI
 * `cmp`s all three, so "TypeScript reproduces the vector" plus "the vectors are the
 * same bytes" gives Rust == Python == TypeScript without a fourth comparison.
 *
 * Nothing here reconstructs the vector's contents in code. A test that builds its
 * own expectation proves only that the code agrees with itself.
 *
 * This vector is **additive** (ADR-0003 §3): it does not re-freeze `mint_v1.json`
 * or `mint_pop_v1.json`, and it introduces no new signed field. What it pins that
 * `mint_v1` does not is the *walk* — the assembled lineage and the verdict.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ed25519PublicKey, ed25519Sign, fromHex, toHex } from 'vaid-pop';

import {
  canonicalVaidSigningBytes,
  ChainVerification,
  PresentedBundle,
  verifyChain,
  type Vaid,
} from '../src/index.js';
import { assembleLineage } from '../src/revocation.js';

interface ChainEntry {
  _role: string;
  digest_sha256_hex: string;
  signature_hex: string;
  document: Vaid;
}

interface ChainVector {
  ed25519: {
    kernel_private_key_seed_hex: string;
    kernel_public_key_hex: string;
    kernel_key_thumbprint: string;
  };
  chain: ChainEntry[];
  expected: { assembled_lineage: string[]; verification: string };
}

/** The frozen chain vector, read from the package's `vectors/` directory. */
const VECTOR = JSON.parse(
  readFileSync(new URL('../../vectors/chain_v1.json', import.meta.url), 'utf8'),
) as ChainVector;

/**
 * The vector's document is UNSIGNED, exactly as `mint_v1.json`'s `input` is;
 * attach its frozen signature.
 */
function signedDocument(entry: ChainEntry): Vaid {
  return {
    ...entry.document,
    kernel_signature: Array.from(fromHex(entry.signature_hex)),
  };
}

const chainDocs = (): Vaid[] => VECTOR.chain.map(signedDocument);

test('reproduces every frozen hop digest', () => {
  for (const entry of VECTOR.chain) {
    assert.equal(
      toHex(canonicalVaidSigningBytes(entry.document)),
      entry.digest_sha256_hex,
      `digest drift at hop ${entry._role}`,
    );
  }
});

test('reproduces every frozen hop signature', () => {
  const seed = fromHex(VECTOR.ed25519.kernel_private_key_seed_hex);

  assert.equal(
    toHex(ed25519PublicKey(seed)),
    VECTOR.ed25519.kernel_public_key_hex,
    'the seed does not derive the vector kernel public key',
  );

  for (const entry of VECTOR.chain) {
    assert.equal(
      toHex(ed25519Sign(canonicalVaidSigningBytes(entry.document), seed)),
      entry.signature_hex,
      `signature drift at hop ${entry._role}`,
    );
  }
});

test('THE WALK part 1: reproduces the frozen assembled lineage', () => {
  // Presented with the two ancestors as a detached bundle, the leaf's lineage
  // assembles to exactly the frozen order — root first, leaf last.
  const docs = chainDocs();
  const leaf = docs[docs.length - 1]!;

  assert.deepEqual(
    assembleLineage(leaf, new PresentedBundle(docs)),
    VECTOR.expected.assembled_lineage,
    'assembled lineage drift',
  );
});

test('THE WALK part 2: reproduces the frozen verification verdict', () => {
  // This is the assertion the vector exists for — two implementations could agree
  // on every digest and still disagree here.
  const docs = chainDocs();
  const leaf = docs[docs.length - 1]!;

  const verdict = verifyChain(
    fromHex(VECTOR.ed25519.kernel_public_key_hex),
    leaf,
    new PresentedBundle(docs),
  );

  assert.equal(verdict, VECTOR.expected.verification, 'verification verdict drift');
  assert.equal(verdict, ChainVerification.Attenuated);
});

test('the frozen chain is three hops, single key, single tenant', () => {
  // So a regenerated vector that quietly lost a hop cannot still pass. Three hops
  // is the smallest chain exercising a *transitive* subset relation.
  const chain = VECTOR.chain;
  assert.equal(chain.length, 3, 'the frozen chain must have three hops');

  const thumbprint = VECTOR.ed25519.kernel_key_thumbprint;
  const tenant = chain[0]!.document.tenant_id;
  const domain = chain[0]!.document.trust_domain;

  for (const entry of chain) {
    assert.equal(
      entry.document.kernel_key_thumbprint,
      thumbprint,
      'every hop must be signed by the one kernel key',
    );
    assert.equal(
      entry.document.tenant_id,
      tenant,
      'tenant must be constant — cross-tenant delegation is denied at mint',
    );
    assert.equal(
      entry.document.trust_domain,
      domain,
      'trust_domain must be constant across a single-issuer chain',
    );
  }

  assert.equal(chain[0]!.document.parent_vaid, null, 'hop 0 must be the root');
});

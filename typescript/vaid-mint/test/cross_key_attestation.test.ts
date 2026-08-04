/**
 * Cross-key chain verification and detached consent attestations. Adversarial
 * tests, TypeScript side.
 *
 * Mirror of `crates/vaid-mint/tests/cross_key_attestation.rs` and
 * `python/vaid-mint/tests/test_cross_key_attestation.py`: the same scenarios,
 * asserting the same (scenario -> verdict) mapping.
 *
 * The first test is the one the whole feature turns on: a hop that crosses a kernel
 * key, with no attestation, must NOT verify. Everything else here is a way of
 * getting that wrong more subtly.
 *
 * Nothing here is a frozen vector and this file must never become one. The
 * attestation format is deliberately UNFROZEN.
 *
 * Two organisations throughout: `A` (`a.example`) and `B` (`b.example`), each with
 * its own kernel key. `A` is the delegating parent; `B` mints the child.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ed25519PublicKey, ed25519Sign, type VaidId } from 'vaid-pop';

import {
  AttestationBundle,
  buildUnsignedAttestation,
  buildUnsignedVaidDocument,
  canonicalAttestationSigningBytes,
  canonicalVaidSigningBytes,
  ChainVerification,
  computeLineageHash,
  KernelKeyMap,
  kernelKeyThumbprint,
  PresentedBundle,
  SingleKernelKey,
  verifyChainWith,
  type ConsentAttestation,
  type Vaid,
} from '../src/index.js';

/**
 * One organisation: a kernel key plus a trust domain. Signs both VAID documents and
 * consent attestations, using the same public calls the reference issuer uses.
 * Enforces nothing — the point, since these tests present authentic but
 * adversarially shaped material.
 */
class Org {
  readonly #seed: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly trustDomain: string;

  constructor(seedByte: number, trustDomain: string) {
    this.#seed = new Uint8Array(32).fill(seedByte);
    this.publicKey = ed25519PublicKey(this.#seed);
    this.trustDomain = trustDomain;
  }

  thumbprint(): string {
    return kernelKeyThumbprint(this.publicKey);
  }

  sign(
    agentId: string,
    parentVaid: VaidId | null,
    tenant: string,
    scope: readonly string[],
    caps: readonly string[],
  ): Vaid {
    const unsigned = buildUnsignedVaidDocument({
      vaidId: agentId as VaidId,
      agentId,
      agentClass: 'test',
      version: '1.0.0',
      tenantId: tenant as Vaid['tenant_id'],
      issuedAt: '2026-06-04T12:00:00Z' as Vaid['issued_at'],
      expiresAt: '2026-06-05T12:00:00Z' as Vaid['expires_at'],
      publicKeyDer: Array.from({ length: 32 }, (_, i) => i),
      parentVaid,
      scopeBoundary: scope,
      lineageHash: computeLineageHash(parentVaid, agentId),
      capabilitySet: caps,
      trustDomain: this.trustDomain,
      kernelKeyThumbprint: this.thumbprint(),
    });
    return {
      ...unsigned,
      kernel_signature: Array.from(
        ed25519Sign(canonicalVaidSigningBytes(unsigned), this.#seed),
      ),
    };
  }

  /** Sign a consent attestation as the parent's issuer. */
  attest(
    parentVaid: VaidId,
    childVaid: VaidId,
    childTrustDomain: string,
    childTenant: string,
    scope: readonly string[],
    caps: readonly string[],
  ): ConsentAttestation {
    const unsigned = buildUnsignedAttestation({
      parentVaid,
      childVaid,
      childTrustDomain,
      childTenantId: childTenant,
      scopeBoundary: scope,
      capabilitySet: caps,
      trustDomain: this.trustDomain,
      kernelKeyThumbprint: this.thumbprint(),
    });
    return {
      ...unsigned,
      signature: Array.from(
        ed25519Sign(canonicalAttestationSigningBytes(unsigned), this.#seed),
      ),
    };
  }
}

function vid(n: number): VaidId {
  const hex = n.toString(16).padStart(32, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20)}` as VaidId;
}

const orgA = () => new Org(1, 'a.example');
const orgB = () => new Org(2, 'b.example');

/**
 * A verifier accepting BOTH organisations' keys — the strongest position an
 * adversary could hope for. Both issuers trusted, and the chain must still fail
 * without consent.
 */
const bothKeys = (a: Org, b: Org) => new KernelKeyMap([a.publicKey, b.publicKey]);

// ── THE LOAD-BEARING TEST ────────────────────────────────────────────────────────

test('cross-key hop without an attestation is never attenuated', () => {
  // Written first, deliberately. Both kernel keys are trusted, every document is
  // authentic, the chain assembles, authority is properly contained — the ONLY thing
  // missing is the parent's consent.
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read', 'write']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);

  const verdict = verifyChainWith(
    bothKeys(a, b),
    child,
    new PresentedBundle([root]),
    new AttestationBundle(),
  );

  assert.notEqual(
    verdict,
    ChainVerification.Attenuated,
    'a cross-key hop without consent must NEVER verify',
  );
  assert.equal(verdict, ChainVerification.Inauthentic);
});

// ── POSITIVE CONTROLS ────────────────────────────────────────────────────────────

test('cross-key hop with valid consent verifies', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read', 'write']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const attestation = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
  );

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([attestation]),
    ),
    ChainVerification.Attenuated,
    "a cross-key hop with the parent issuer's signed consent must verify",
  );
});

test('same-key chain needs no attestation', () => {
  const a = orgA();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = a.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);

  assert.equal(
    verifyChainWith(
      new SingleKernelKey(a.publicKey),
      child,
      new PresentedBundle([root]),
      new AttestationBundle(),
    ),
    ChainVerification.Attenuated,
    'same-key hops keep their existing behaviour',
  );
});

// ── ADVERSARIAL ──────────────────────────────────────────────────────────────────

test('forged sibling without consent is not attenuated', () => {
  // B mints a document naming A's root as its parent, with a strict subset of A's
  // authority, signed with B's key, no attestation. B needs only to KNOW A's root
  // vaid_id — which every chain presentation discloses.
  const a = orgA();
  const b = orgB();

  const aRoot = a.sign(vid(1), null, 'acme', ['data.acme'], ['read', 'write', 'admin']);
  const forged = b.sign(vid(99), vid(1), 'acme', ['data.acme.stolen'], ['read']);

  assert.notEqual(
    verifyChainWith(
      bothKeys(a, b),
      forged,
      new PresentedBundle([aRoot]),
      new AttestationBundle(),
    ),
    ChainVerification.Attenuated,
    'FORGED SIBLING: an unconsented cross-issuer child must not verify',
  );
});

test('attestation signed by the wrong key is inauthentic', () => {
  // B signs its own permission slip.
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const selfSigned = b.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
  );

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([selfSigned]),
    ),
    ChainVerification.Inauthentic,
    'only the issuer that minted the parent may consent on its behalf',
  );
});

test('attestation for a different child does not apply', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const blessed = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);
  const other = b.sign(vid(3), vid(1), 'acme', ['data.acme.sub'], ['read']);

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      other,
      new PresentedBundle([root]),
      new AttestationBundle([blessed]),
    ),
    ChainVerification.Inauthentic,
    'consent names one child; another cannot borrow it',
  );
});

test('attestation narrower than the child claims is not attenuated', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read', 'write']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read', 'write']);
  const attestation = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([attestation]),
    ),
    ChainVerification.NotAttenuated,
    'a child may hold no more than the parent consented to',
  );
});

test('attestation for a different subtree is not attenuated', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.other'], ['read']);
  const attestation = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.blessed'],
    ['read'],
  );

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([attestation]),
    ),
    ChainVerification.NotAttenuated,
    'consent to one subtree does not authorize a sibling',
  );
});

test('attestation replayed onto a different chain does not apply', () => {
  // A genuine attestation, signed by A, presented against a chain whose parent is a
  // different root. It is filed under the pair it names, so the lookup simply does
  // not find it — replay is structurally inert rather than rejected.
  const a = orgA();
  const b = orgB();

  const genuine = a.attest(vid(1), vid(3), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);
  const otherRoot = a.sign(vid(2), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(3), vid(2), 'acme', ['data.acme.sub'], ['read']);

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([otherRoot]),
      new AttestationBundle([genuine]),
    ),
    ChainVerification.Inauthentic,
    'consent is bound to one (parent, child) pair and cannot be replayed',
  );
});

test('mid-chain cross-key hop unattested is not attenuated', () => {
  // A(root) -> B(mid) -> B(leaf): the leaf hop is same-key and needs nothing, while
  // the mid hop crosses and is unattested. An attestation IS presented — for the
  // wrong hop.
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const mid = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const leaf = b.sign(vid(3), vid(2), 'acme', ['data.acme.sub.task'], ['read']);
  const irrelevant = b.attest(
    vid(2),
    vid(3),
    'b.example',
    'acme',
    ['data.acme.sub.task'],
    ['read'],
  );

  const verdict = verifyChainWith(
    bothKeys(a, b),
    leaf,
    new PresentedBundle([root, mid]),
    new AttestationBundle([irrelevant]),
  );

  assert.notEqual(
    verdict,
    ChainVerification.Attenuated,
    'an unattested cross-key hop anywhere on the chain must fail the whole chain',
  );
  assert.equal(verdict, ChainVerification.Inauthentic);
});

test('attestation exceeding the parent authority is not attenuated', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const overBroad = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
    'write',
  ]);

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([overBroad]),
    ),
    ChainVerification.NotAttenuated,
    'a parent cannot consent to more than it holds',
  );
});

test('attestation naming a different tenant is not attenuated', () => {
  // Cross-key hops skip pair-equality (they cross domains by definition), so the
  // attestation is the only thing binding the child's claimed identity.
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'other', ['data.acme.sub'], ['read']);
  const attestation = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([attestation]),
    ),
    ChainVerification.NotAttenuated,
    'consent must name the identity the child actually claims',
  );
});

test('an unaccepted kernel key is inauthentic', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const attestation = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);

  assert.equal(
    verifyChainWith(
      new KernelKeyMap([a.publicKey]),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([attestation]),
    ),
    ChainVerification.Inauthentic,
    'a document signed by an unaccepted key must fail closed',
  );
});

test('tampered attestation is inauthentic', () => {
  const a = orgA();
  const b = orgB();

  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read', 'write']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read', 'write']);
  const tampered = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);
  tampered.capability_set = ['read', 'write'];

  assert.equal(
    verifyChainWith(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([tampered]),
    ),
    ChainVerification.Inauthentic,
    'widening consent after signing must break its signature',
  );
});

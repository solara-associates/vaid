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

import { MINT_POP_FRESHNESS_SECS } from '../src/mint.js';
import { verifyChainAt } from '../src/chain.js';
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

  /**
   * As {@link Org.sign}, with the document's own window under the test's control.
   * Used only to prove document expiry stays unconsulted.
   */
  signWindow(
    agentId: string,
    parentVaid: VaidId | null,
    tenant: string,
    scope: readonly string[],
    caps: readonly string[],
    issuedAt: Date,
    expiresAt: Date,
  ): Vaid {
    const unsigned = buildUnsignedVaidDocument({
      vaidId: agentId as VaidId,
      agentId,
      agentClass: 'test',
      version: '1.0.0',
      tenantId: tenant as Vaid['tenant_id'],
      issuedAt: e6(issuedAt) as Vaid['issued_at'],
      expiresAt: e6(expiresAt) as Vaid['expires_at'],
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

  /**
   * Sign a consent attestation as the parent's issuer. The window defaults to one
   * that is currently valid and wide enough never to race the clock; the window
   * tests override it.
   */
  attest(
    parentVaid: VaidId,
    childVaid: VaidId,
    childTrustDomain: string,
    childTenant: string,
    scope: readonly string[],
    caps: readonly string[],
    issuedAt?: Date,
    expiresAt?: Date,
  ): ConsentAttestation {
    const now = Date.now();
    const unsigned = buildUnsignedAttestation({
      parentVaid,
      childVaid,
      childTrustDomain,
      childTenantId: childTenant,
      issuedAt: e6(issuedAt ?? new Date(now - 60_000)),
      expiresAt: e6(expiresAt ?? new Date(now + 3_600_000)),
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

/** E.6 timestamp profile: whole-second RFC 3339 UTC with a literal Z. */
function e6(moment: Date): string {
  return `${moment.toISOString().slice(0, 19)}Z`;
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

// ── CONSENT VALIDITY WINDOW ──────────────────────────────────────────────────────

/** A cross-key chain correct in every way except, per test, the consent window. */
function windowFixture(): { a: Org; b: Org; root: Vaid; child: Vaid } {
  const a = orgA();
  const b = orgB();
  const root = a.sign(vid(1), null, 'acme', ['data.acme'], ['read']);
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  return { a, b, root, child };
}

test('expired consent is ConsentExpired', () => {
  // Not Inauthentic — the parent really did sign it. Not NotAttenuated — the child
  // did not overreach. The verdict has to say *renew this*.
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const lapsed = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() - 7_200_000),
    new Date(now.getTime() - 3_600_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([lapsed]),
      now,
    ),
    ChainVerification.ConsentExpired,
    'lapsed consent is authentic and unusable, and the verdict must say so',
  );
});

test('not-yet-valid consent is ConsentExpired', () => {
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const premature = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() + 3_600_000),
    new Date(now.getTime() + 7_200_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([premature]),
      now,
    ),
    ChainVerification.ConsentExpired,
    'consent that has not started is outside its window too',
  );
});

test('clock skew is tolerated before the window opens', () => {
  // Skew allowance on the not-yet-valid side only, reusing the mint's PoP tolerance
  // rather than inventing a second one.
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const slightlyEarly = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() + (MINT_POP_FRESHNESS_SECS - 5) * 1000),
    new Date(now.getTime() + 7_200_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([slightlyEarly]),
      now,
    ),
    ChainVerification.Attenuated,
    'a verifier a few seconds behind the issuer must not reject young consent',
  );
});

test('no skew is granted after the window closes', () => {
  // Expiry is exact. Being generous at the closing edge is being generous in the one
  // direction that extends unauthorized access.
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const justLapsed = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() - 3_600_000),
    new Date(now.getTime() - 1_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([justLapsed]),
      now,
    ),
    ChainVerification.ConsentExpired,
    'expiry is exact: no grace period on the closing edge',
  );
});

test('the closing instant itself is still valid', () => {
  // Pins the inclusive/exclusive choice rather than leaving it incidental.
  const { a, b, root, child } = windowFixture();
  // Whole seconds, because the E.6 profile has no sub-second component.
  const now = new Date(Math.floor(Date.now() / 1000) * 1000);

  const closing = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() - 3_600_000),
    now,
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([closing]),
      now,
    ),
    ChainVerification.Attenuated,
    'the closing instant is inside the window; the instant after it is not',
  );
});

test('an inverted window is never current', () => {
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const inverted = a.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() + 3_600_000),
    new Date(now.getTime() - 3_600_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([inverted]),
      now,
    ),
    ChainVerification.ConsentExpired,
    'a window that cannot be satisfied at any instant is not satisfied at this one',
  );
});

test('an unparseable timestamp is never current', () => {
  // Fail closed — the opposite of the Date.parse NaN fail-open isExpired once had.
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const malformed = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);
  malformed.expires_at = 'whenever';

  assert.notEqual(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([malformed]),
      now,
    ),
    ChainVerification.Attenuated,
    'an unreadable window must never verify',
  );
});

test('a forged and expired attestation reports Inauthentic', () => {
  // Authenticity is checked first: "not from who it claims" is the stronger and more
  // actionable statement.
  const { a, b, root, child } = windowFixture();
  const now = new Date();

  const forgedAndLapsed = b.attest(
    vid(1),
    vid(2),
    'b.example',
    'acme',
    ['data.acme.sub'],
    ['read'],
    new Date(now.getTime() - 7_200_000),
    new Date(now.getTime() - 3_600_000),
  );

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([root]),
      new AttestationBundle([forgedAndLapsed]),
      now,
    ),
    ChainVerification.Inauthentic,
    'forgery outranks staleness in the verdict',
  );
});

test('an expired parent document does not affect the verdict', () => {
  // Document expiry stays UNCONSULTED. An attestation may outlive the parent VAID it
  // delegates from; this pass deliberately does not change that.
  const a = orgA();
  const b = orgB();
  const now = new Date();

  const expiredRoot = a.signWindow(
    vid(1),
    null,
    'acme',
    ['data.acme'],
    ['read'],
    new Date(now.getTime() - 7_200_000),
    new Date(now.getTime() - 3_600_000),
  );
  const child = b.sign(vid(2), vid(1), 'acme', ['data.acme.sub'], ['read']);
  const consent = a.attest(vid(1), vid(2), 'b.example', 'acme', ['data.acme.sub'], [
    'read',
  ]);

  assert.equal(
    verifyChainAt(
      bothKeys(a, b),
      child,
      new PresentedBundle([expiredRoot]),
      new AttestationBundle([consent]),
      now,
    ),
    ChainVerification.Attenuated,
    'document expiry is not consulted by chain verification, and did not become ' +
      'consulted when attestation expiry landed',
  );
});

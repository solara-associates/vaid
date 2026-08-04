/**
 * Third-party end-to-end lineage verification (ADR-0003). Integration tests.
 *
 * The TypeScript mirror of `crates/vaid-mint/tests/chain_verification.rs` and
 * `python/vaid-mint/tests/test_chain_verification.py`: the same scenarios,
 * asserting the same (scenario -> outcome) mapping. There is deliberately no shared
 * vector — ADR-0003 §3 calls for a chain-presentation vector as *additive*
 * conformance work, and it is deliberately not generated or frozen here, so the
 * verifier semantics can be reviewed before anything is frozen against them. The
 * languages agree by construction, as the revocation suite does.
 *
 * ## Why these documents are signed locally rather than minted
 *
 * Most cases below are constructible through `ReferenceIssuer`, but two are not: a
 * **cycle** and a **depth overflow** both require choosing a document's `vaid_id`,
 * and the issuer generates a fresh UUIDv4 per mint and never accepts one. That is a
 * security property, not an obstacle to route around — it is exactly what makes
 * chain substitution infeasible.
 *
 * So the suite drives a local `LocalMint`: a kernel keypair plus the same public
 * document-building and canonical-signing calls the issuer itself makes. Documents
 * it produces are genuinely authentic under its own kernel key, which is the point:
 * it lets a test present an *authentic but adversarially shaped* chain. It also
 * deliberately does not enforce attenuation, so a child claiming authority its
 * parent never held can be signed and presented.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ed25519PublicKey, ed25519Sign, type VaidId } from 'vaid-pop';

import {
  buildUnsignedVaidDocument,
  canonicalVaidSigningBytes,
  ChainVerification,
  computeLineageHash,
  kernelKeyThumbprint,
  PresentedBundle,
  verifyChain,
  type Vaid,
} from '../src/index.js';
import {
  assembleLineage,
  MAX_LINEAGE_DEPTH,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
} from '../src/revocation.js';

/**
 * A kernel key plus the issuer's own document-building and signing calls. Produces
 * authentic documents while leaving `agent_id`, lineage and authority under the
 * test's control. Attenuation is NOT enforced — see the module docs.
 */
class LocalMint {
  readonly #seed: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(seedByte = 1) {
    this.#seed = new Uint8Array(32).fill(seedByte);
    this.publicKey = ed25519PublicKey(this.#seed);
  }

  /** Build and kernel-sign a VAID with a caller-chosen id, parent and authority. */
  sign(
    agentId: string,
    parentVaid: VaidId | null,
    scope: readonly string[],
    caps: readonly string[],
  ): Vaid {
    const unsigned = buildUnsignedVaidDocument({
      vaidId: agentId as VaidId,
      agentId,
      agentClass: 'test',
      version: '1.0.0',
      tenantId: 't' as Vaid['tenant_id'],
      issuedAt: '2026-06-04T12:00:00Z' as Vaid['issued_at'],
      expiresAt: '2026-06-05T12:00:00Z' as Vaid['expires_at'],
      publicKeyDer: Array.from({ length: 32 }, (_, i) => i),
      parentVaid,
      scopeBoundary: scope,
      lineageHash: computeLineageHash(parentVaid, agentId),
      capabilitySet: caps,
      // RFC 2606 reserved, matching the frozen vector's reasoning: a suite that
      // publishes signable keys must not name a bindable domain.
      trustDomain: 'vaid.example',
      kernelKeyThumbprint: kernelKeyThumbprint(this.publicKey),
    });
    const signature = ed25519Sign(canonicalVaidSigningBytes(unsigned), this.#seed);
    return { ...unsigned, kernel_signature: Array.from(signature) };
  }
}

/**
 * A stable id from a small integer, so a test can name the ids it wants to arrange
 * into a cycle or a long chain. Same UUID shape the Rust and Python suites use.
 */
function vid(n: number): VaidId {
  const hex = n.toString(16).padStart(32, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20)}` as VaidId;
}

// ── POSITIVE CONTROLS ────────────────────────────────────────────────────────────

test('positive control: a complete, authentic, attenuated chain verifies', () => {
  // Without this the whole suite could pass by rejecting everything.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read', 'write']);
  const mid = mint.sign(vid(2), vid(1), ['data.tenant.sub'], ['read', 'write']);
  const leaf = mint.sign(vid(3), vid(2), ['data.tenant.sub.leaf'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root, mid])),
    ChainVerification.Attenuated,
    'a complete, authentic, contained chain must verify',
  );
});

test('positive control: a rootless leaf is trivially complete', () => {
  const mint = new LocalMint();
  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, root, new PresentedBundle()),
    ChainVerification.Attenuated,
    'a VAID with no parent_vaid is its own root and needs no ancestors',
  );
});

// ── FAIL-CLOSED CASES ────────────────────────────────────────────────────────────

test('missing ancestor is unverifiable', () => {
  // The middle document is withheld, so the hop above the leaf resolves to unknown.
  // Never a chain silently shortened to what happens to be present.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  mint.sign(vid(2), vid(1), ['data.tenant.sub'], ['read']); // withheld
  const leaf = mint.sign(vid(3), vid(2), ['data.tenant.sub.leaf'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root])),
    ChainVerification.Unverifiable,
    'an unpresented ancestor must be attenuation-unverifiable, not satisfied',
  );
});

test('unreachable resolver (empty bundle) is unverifiable', () => {
  // The third-party analogue of a resolver that cannot be consulted.
  const mint = new LocalMint();
  const leaf = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle()),
    ChainVerification.Unverifiable,
    'no presented ancestors must fail closed, not resolve the leaf as a root',
  );
});

test('tampered parent_vaid is inauthentic', () => {
  // The leaf's parent pointer is swapped to a more-privileged ancestor while its
  // original kernel signature is kept. `parent_vaid` is inside the canonical
  // signing bytes, so this breaks the signature; `lineage_hash` no longer matches
  // either.
  const mint = new LocalMint();

  const privileged = mint.sign(vid(1), null, ['data'], ['read', 'write']);
  const restricted = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);
  const leaf = mint.sign(vid(3), vid(2), ['data.tenant.sub'], ['read']);

  const forged: Vaid = { ...leaf, parent_vaid: vid(1) };

  assert.equal(
    verifyChain(
      mint.publicKey,
      forged,
      new PresentedBundle([privileged, restricted]),
    ),
    ChainVerification.Inauthentic,
    'a re-pointed parent_vaid must break the kernel signature',
  );
});

test('an ancestor signed by another kernel key is inauthentic', () => {
  // The v3 thumbprint check rejects it before its signature is even considered.
  const mint = new LocalMint(1);
  const other = new LocalMint(2);

  const root = other.sign(vid(1), null, ['data'], ['read']);
  const leaf = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root])),
    ChainVerification.Inauthentic,
    'a chain crossing kernel keys must be rejected, not verified under a key that did not sign it',
  );
});

test('a child exceeding its parent scope is not attenuated', () => {
  // Every document is authentic and the chain is complete — the only defect is
  // containment, which is precisely what a third party could not previously check.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const leaf = mint.sign(vid(2), vid(1), ['data.other'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root])),
    ChainVerification.NotAttenuated,
    "a child must not hold scope outside its parent's, however well signed",
  );
});

test('a mid-chain scope escalation is not attenuated', () => {
  // Containment is checked at EVERY hop. The leaf is contained by its parent but
  // the parent escaped the root, so a leaf-only check would have passed this.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const mid = mint.sign(vid(2), vid(1), ['data.other'], ['read']);
  const leaf = mint.sign(vid(3), vid(2), ['data.other.sub'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root, mid])),
    ChainVerification.NotAttenuated,
    'containment must hold at every hop, not only the one nearest the leaf',
  );
});

test('a child exceeding its parent capabilities is not attenuated', () => {
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const leaf = mint.sign(vid(2), vid(1), ['data.tenant.sub'], ['read', 'write']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root])),
    ChainVerification.NotAttenuated,
    'a child must not hold a capability its parent lacks',
  );
});

test('an empty child scope under a restricted parent is not attenuated', () => {
  // THE ⊤ ESCALATION. An empty child scope means *unrestricted*, so a naive `every`
  // over zero entries is vacuously true and would admit an unrestricted child under
  // a restricted parent. Reusing the mint-time matcher is what carries this guard to
  // verify time; reimplementing containment is how it would be lost.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const leaf = mint.sign(vid(2), vid(1), [], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle([root])),
    ChainVerification.NotAttenuated,
    'an empty (unrestricted) child scope under a restricted parent is an escalation',
  );
});

test('a cycle is unverifiable', () => {
  // Two authentic documents each naming the other as parent. Assembly must
  // terminate and fail closed rather than loop. This shape cannot arise from
  // `ReferenceIssuer` — a cycle needs a document to name a `vaid_id` that does not
  // exist yet, and the issuer mints a fresh UUIDv4 every time.
  const mint = new LocalMint();

  const a = mint.sign(vid(1), vid(2), ['data.tenant'], ['read']);
  const b = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);

  assert.equal(
    verifyChain(mint.publicKey, a, new PresentedBundle([a, b])),
    ChainVerification.Unverifiable,
    'a cyclic presentation must fail closed, not loop or resolve',
  );
});

test('depth overflow is unverifiable', () => {
  // Authority is identical at every hop, so the ONLY reason this can fail is the
  // depth bound.
  const mint = new LocalMint();

  const depth = MAX_LINEAGE_DEPTH + 1;
  const docs: Vaid[] = [mint.sign(vid(0), null, ['data.tenant'], ['read'])];
  for (let n = 1; n <= depth; n += 1) {
    docs.push(mint.sign(vid(n), vid(n - 1), ['data.tenant'], ['read']));
  }

  const leaf = docs.pop()!;

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle(docs)),
    ChainVerification.Unverifiable,
    'a chain deeper than MAX_LINEAGE_DEPTH must fail closed',
  );
});

test('a chain at exactly the depth bound still verifies', () => {
  // Boundary control for the test above, so the overflow case is failing on the
  // bound rather than on some incidental property of a long chain.
  const mint = new LocalMint();

  const hops = MAX_LINEAGE_DEPTH - 1;
  const docs: Vaid[] = [mint.sign(vid(0), null, ['data.tenant'], ['read'])];
  for (let n = 1; n <= hops; n += 1) {
    docs.push(mint.sign(vid(n), vid(n - 1), ['data.tenant'], ['read']));
  }

  const leaf = docs.pop()!;

  assert.equal(
    verifyChain(mint.publicKey, leaf, new PresentedBundle(docs)),
    ChainVerification.Attenuated,
    'a chain exactly at the depth bound must still verify',
  );
});

// ── RESOLVER CONTRACT ────────────────────────────────────────────────────────────

test('the bundle resolver distinguishes a root from an unknown id', () => {
  // Conflating a genuine root with an unpresented document is the R.4.2 bug that
  // lets a leaf whose ancestors were withheld pass as rootless.
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const child = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);
  const bundle = new PresentedBundle([root, child]);

  assert.deepEqual(bundle.resolveParent(vid(1)), parentResolutionRoot());
  assert.deepEqual(bundle.resolveParent(vid(2)), parentResolutionOf(vid(1)));
  assert.deepEqual(bundle.resolveParent(vid(99)), parentResolutionUnknown());
});

test('the bundle assembles an ordered lineage, root first', () => {
  const mint = new LocalMint();

  const root = mint.sign(vid(1), null, ['data.tenant'], ['read']);
  const mid = mint.sign(vid(2), vid(1), ['data.tenant'], ['read']);
  const leaf = mint.sign(vid(3), vid(2), ['data.tenant'], ['read']);

  assert.deepEqual(
    assembleLineage(leaf, new PresentedBundle([root, mid])),
    [vid(1), vid(2), vid(3)],
    'ordered root first, leaf last',
  );
});

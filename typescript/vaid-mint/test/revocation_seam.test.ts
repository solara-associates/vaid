/**
 * Revocation seam gate (spec `docs/spec/revocation.md` R.4).
 *
 * Revocation is **outside the conformance surface** (R.1): nothing here is a
 * frozen vector, and this file must never become one. It exercises the three
 * states and the two failure modes a boolean, leaf-only check could not express.
 *
 * The scenario table in `cross-language scenarios` is mirrored byte-for-intent by
 * the Rust suite (`crates/vaid-mint/tests/revocation_seam.rs`) and the Python
 * suite (`python/vaid-mint/tests/test_revocation.py`), which assert the identical
 * (scenario → status) mapping. There is deliberately no shared vector: the
 * languages agree by construction, not by a frozen artifact.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  assembleLineage,
  InMemoryRevocationList,
  MAX_LINEAGE_DEPTH,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  ReferenceIssuer,
  RevocationStatus,
  type LineageResolver,
  type Vaid,
} from '../src/index.js';

/**
 * Issue a root (no parent) straight from the issuer. Enough to exercise the seam
 * without the full mintChild PoP dance, which is orthogonal to revocation.
 */
function issueRoot(issuer: ReferenceIssuer, agentClass: string): Vaid {
  return issuer.issueVaidWithLineage({
    agentClass,
    version: '1.0.0',
    tenantId: 't',
    parentVaid: null,
    scopeBoundary: [],
    capabilitySet: [],
  });
}

/** Issue a child attenuated from `parent` (the same lineage-recording path). */
function issueChild(issuer: ReferenceIssuer, parent: Vaid, agentClass: string): Vaid {
  return issuer.issueVaidWithLineage({
    agentClass,
    version: '1.0.0',
    tenantId: 't',
    parentVaid: parent.vaid_id,
    scopeBoundary: [],
    capabilitySet: [],
  });
}

// ── The four required cases ───────────────────────────────────────────────────

test('TEST 1 — BYPASS: revoking a parent rejects the child attenuated from it', () => {
  // The case a leaf-only boolean check got wrong, and the reason lineage
  // checking exists (R.4.4).
  const issuer = ReferenceIssuer.ephemeral(1);
  const root = issueRoot(issuer, 'root');
  const child = issueChild(issuer, root, 'child');

  assert.equal(issuer.verifyVaid(child), true, 'child verifies before revocation');

  issuer.revoke(root.vaid_id);

  assert.equal(
    issuer.revocationStatus(child),
    RevocationStatus.Revoked,
    "a child inherits its revoked parent's revocation",
  );
  assert.equal(
    issuer.verifyVaid(child),
    false,
    'BYPASS: a child of a revoked parent must not verify',
  );
});

test('TEST 2 — RESTART TRUNCATION: an unresolvable lineage is Unavailable, never NotRevoked', () => {
  // With the lineage map cleared (process restart), a child whose parent can no
  // longer be resolved is Unavailable. Incomplete assembly must never be mistaken
  // for a rootless VAID (R.4.2). This is the case a boolean cannot represent.
  const issuer = ReferenceIssuer.ephemeral(1);
  const root = issueRoot(issuer, 'root');
  const child = issueChild(issuer, root, 'child');
  issuer.revoke(root.vaid_id);

  issuer.clearLineage(); // simulate a restart: the in-memory resolver state is gone

  const status = issuer.revocationStatus(child);
  assert.equal(
    status,
    RevocationStatus.Unavailable,
    'a child whose parent is unresolvable is Unavailable',
  );
  assert.notEqual(
    status,
    RevocationStatus.NotRevoked,
    'it must NOT silently pass as not-revoked — the whole point of R.4.2',
  );
  assert.equal(issuer.verifyVaid(child), false, 'fails closed on Unavailable (R.4.5)');
});

test('TEST 3 — STORE FAILURE: an unreachable store is Unavailable and rejects', () => {
  const issuer = ReferenceIssuer.ephemeral(1).withRevocationCheck(
    InMemoryRevocationList.unavailable(),
  );
  const vaid = issueRoot(issuer, 'root');

  assert.equal(
    issuer.revocationStatus(vaid),
    RevocationStatus.Unavailable,
    'an unreachable store yields Unavailable, not NotRevoked',
  );
  assert.equal(
    issuer.verifyVaid(vaid),
    false,
    'fails closed when the store is unavailable (R.4.3/R.4.5)',
  );
});

test('TEST 4 — ROOTLESS: a clean rootless VAID is NotRevoked and verifies', () => {
  // The case tests 1 and 2 must not have broken: incomplete assembly (test 2)
  // and a genuine root (here) must land on different states.
  const issuer = ReferenceIssuer.ephemeral(1);
  const vaid = issueRoot(issuer, 'root');

  assert.equal(
    issuer.revocationStatus(vaid),
    RevocationStatus.NotRevoked,
    'a rootless, unrevoked VAID is cleanly NotRevoked',
  );
  assert.equal(issuer.verifyVaid(vaid), true, 'and it verifies');
});

// ── The cross-language scenario table ─────────────────────────────────────────

test('cross-language scenarios — the (scenario → status) table all three languages agree on', () => {
  // All three states appear, and the two indistinguishable-under-a-boolean cases
  // (restart-truncation vs rootless) sit on different rows.

  // clean_root: rootless, nothing revoked          -> NotRevoked
  {
    const issuer = ReferenceIssuer.ephemeral(1);
    assert.equal(issuer.revocationStatus(issueRoot(issuer, 'root')), RevocationStatus.NotRevoked);
  }
  // revoked_root: rootless, itself revoked         -> Revoked
  {
    const issuer = ReferenceIssuer.ephemeral(1);
    const root = issueRoot(issuer, 'root');
    issuer.revoke(root.vaid_id);
    assert.equal(issuer.revocationStatus(root), RevocationStatus.Revoked);
  }
  // child_parent_revoked: child of a revoked root  -> Revoked (R.4.4)
  {
    const issuer = ReferenceIssuer.ephemeral(1);
    const root = issueRoot(issuer, 'root');
    const child = issueChild(issuer, root, 'child');
    issuer.revoke(root.vaid_id);
    assert.equal(issuer.revocationStatus(child), RevocationStatus.Revoked);
  }
  // child_clean: child of a clean root             -> NotRevoked
  {
    const issuer = ReferenceIssuer.ephemeral(1);
    const root = issueRoot(issuer, 'root');
    const child = issueChild(issuer, root, 'child');
    assert.equal(issuer.revocationStatus(child), RevocationStatus.NotRevoked);
  }
  // child_parent_unresolvable: restart truncation  -> Unavailable (R.4.2)
  {
    const issuer = ReferenceIssuer.ephemeral(1);
    const root = issueRoot(issuer, 'root');
    const child = issueChild(issuer, root, 'child');
    issuer.clearLineage();
    assert.equal(issuer.revocationStatus(child), RevocationStatus.Unavailable);
  }
  // store_unavailable: store unreachable           -> Unavailable (R.4.3)
  {
    const issuer = ReferenceIssuer.ephemeral(1).withRevocationCheck(
      InMemoryRevocationList.unavailable(),
    );
    assert.equal(issuer.revocationStatus(issueRoot(issuer, 'root')), RevocationStatus.Unavailable);
  }
});

// ── The store's three-state behaviour, directly ───────────────────────────────

test('an absent store is Unavailable; a vouching store is NotRevoked', () => {
  assert.equal(
    new InMemoryRevocationList().checkLineage(['any']),
    RevocationStatus.Unavailable,
  );
  assert.equal(
    InMemoryRevocationList.assumeNothingRevoked().checkLineage(['any']),
    RevocationStatus.NotRevoked,
  );
});

test('revoking makes a store available, and any hop in the lineage counts', () => {
  const list = new InMemoryRevocationList();
  list.revoke('root-id');
  assert.equal(list.isAvailable(), true);
  // Revoked if ANY id in the lineage is revoked, in any position.
  assert.equal(list.checkLineage(['root-id', 'leaf-id']), RevocationStatus.Revoked);
  assert.equal(list.checkLineage(['leaf-id', 'root-id']), RevocationStatus.Revoked);
  assert.equal(list.checkLineage(['leaf-id']), RevocationStatus.NotRevoked);
});

test('markUnavailable flips a vouching store back to absent', () => {
  const list = InMemoryRevocationList.assumeNothingRevoked();
  assert.equal(list.checkLineage(['x']), RevocationStatus.NotRevoked);
  list.markUnavailable();
  assert.equal(list.checkLineage(['x']), RevocationStatus.Unavailable);
});

// ── Lineage assembly, directly ────────────────────────────────────────────────

/** A resolver driven by a fixed map, for assembly cases the issuer cannot stage. */
function mapResolver(map: Record<string, string | null>): LineageResolver {
  return {
    resolveParent(vaidId) {
      if (!(vaidId in map)) return parentResolutionUnknown();
      const parent = map[vaidId];
      return parent === null ? parentResolutionRoot() : parentResolutionOf(parent);
    },
  };
}

function leaf(vaidId: string, parentVaid: string | null): Vaid {
  return { vaid_id: vaidId, parent_vaid: parentVaid } as Vaid;
}

test('assembly is ordered root first, leaf last', () => {
  const resolver = mapResolver({ mid: 'root', root: null });
  assert.deepEqual(assembleLineage(leaf('leaf', 'mid'), resolver), ['root', 'mid', 'leaf']);
});

test('a leaf with no parent is trivially complete', () => {
  assert.deepEqual(assembleLineage(leaf('solo', null), mapResolver({})), ['solo']);
});

test('an unresolvable parent is incomplete — never truncated to the leaf alone', () => {
  // The exact collapse R.4.2 forbids: returning `['leaf']` here would be
  // indistinguishable from the trivially-complete case above.
  assert.equal(assembleLineage(leaf('leaf', 'ghost'), mapResolver({})), null);
});

test('a cycle is incomplete rather than an infinite loop', () => {
  const resolver = mapResolver({ a: 'b', b: 'a' });
  assert.equal(assembleLineage(leaf('a', 'b'), resolver), null);
});

test('an implausibly deep chain is incomplete', () => {
  // A resolver that always reports a fresh parent would loop forever without the
  // depth bound; MAX_LINEAGE_DEPTH turns that into a fail-closed Incomplete.
  let counter = 0;
  const endless: LineageResolver = { resolveParent: () => parentResolutionOf(`p${counter++}`) };
  assert.equal(assembleLineage(leaf('leaf', 'p-start'), endless), null);
  assert.ok(counter < MAX_LINEAGE_DEPTH + 2, 'the bound must stop the walk');
});

test('the check is handed a lineage and never a resolver', () => {
  // Structural, not behavioural: RevocationCheck's only method takes ids. A
  // check that could resolve would be the R.4.1 conflation the spec forbids.
  const store = InMemoryRevocationList.assumeNothingRevoked();
  assert.equal(store.checkLineage.length, 1, 'checkLineage takes exactly the lineage');
});

test('an injected durable-style backend is the one consulted at verification', () => {
  // Models the shape a self-hoster supplies: it returns Unavailable when its own
  // store cannot be reached, and verification fails closed on that.
  let reachable = true;
  const backend = {
    checkLineage: (): RevocationStatus =>
      reachable ? RevocationStatus.NotRevoked : RevocationStatus.Unavailable,
  };
  const issuer = ReferenceIssuer.ephemeral(1).withRevocationCheck(backend);
  const vaid = issueRoot(issuer, 'root');

  assert.equal(issuer.verifyVaid(vaid), true);
  reachable = false;
  assert.equal(issuer.revocationStatus(vaid), RevocationStatus.Unavailable);
  assert.equal(issuer.verifyVaid(vaid), false, 'fail closed — there is no fail-open option');

  // And the built-in store is no longer consulted once a backend is injected.
  reachable = true;
  issuer.revoke(vaid.vaid_id);
  assert.equal(
    issuer.verifyVaid(vaid),
    true,
    'revoking through the built-in store has no effect once a backend is injected',
  );
});

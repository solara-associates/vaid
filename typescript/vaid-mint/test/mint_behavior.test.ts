/**
 * Mint behaviour: root issuance, BYO-key proof-of-possession, and attenuated
 * delegation. Mirror of the Rust `vaid_mint::mint` unit tests and the Python
 * `test_mint_behavior.py`.
 *
 * The property under test throughout `mintChild` is containment: `child ⊆
 * parent`, checked fail-closed before any key work or nonce consumption.
 */

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  boundaryIsEvaluable,
  entryClaimedResource,
  isInScope,
  isWellFormedScopeBoundary,
  prefixEntry,
} from '../src/document.js';
import { test } from 'node:test';

import {
  ed25519PublicKey,
  ed25519Sign,
  randomEd25519Seed,
  signPayload,
  utcWholeSecondRfc3339,
} from 'vaid-pop';

import {
  buildMintPopPayload,
  buildUnsignedVaidDocument,
  canonicalVaidSigningBytes,
  computeLineageHash,
  ConfigError,
  DenyAll,
  IdentityError,
  InMemoryAudit,
  InMemoryRevocationList,
  MAX_LINEAGE_DEPTH,
  MINT_POP_FRESHNESS_SECS,
  MintError,
  MintService,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  parseVaidDocument,
  PermitAll,
  ReferenceIssuer,
  RevocationBackend,
  UnauthorizedError,
  validateMaxDelegationDepth,
  verifyVaidAuthenticity,
  type MintPop,
  type MintVaidRequest,
  type ParentResolution,
  type Vaid,
  type VaidSeed,
} from '../src/index.js';
import { kernelKeyThumbprint } from '../src/issuerIdentity.js';

function fixture(): { service: MintService; audit: InMemoryAudit; issuer: ReferenceIssuer } {
  const audit = new InMemoryAudit();
  // `assumingNothingRevoked()` because these tests are about minting, attenuation and
  // scope containment. Since 0.9.0 a bare issuer's revocation store is absent, so
  // `verifyVaid` would fail closed on Unavailable regardless of what the child's scope
  // says — a rejection for the wrong reason.
  const issuer = ReferenceIssuer.ephemeral(1).assumingNothingRevoked();
  return { service: new MintService(issuer, audit), audit, issuer };
}

/** A holder keypair: the seed stays with the holder, only the public half travels. */
function holderKeypair(): { seed: Uint8Array; publicKey: Uint8Array } {
  const seed = randomEd25519Seed();
  return { seed, publicKey: ed25519PublicKey(seed) };
}

function byoSeed(publicKey: Uint8Array): VaidSeed {
  return {
    agentClass: 'runner',
    version: '1.0.0',
    tenantId: 'acme',
    parentVaid: null,
    scopeBoundary: [prefixEntry('data.x')],
    capabilitySet: ['read'],
    publicKeyDer: publicKey,
  };
}

function makePop(
  seed: VaidSeed,
  registeredKey: Uint8Array,
  signingSeed: Uint8Array,
  nonce: string,
  issuedAt: string = utcWholeSecondRfc3339(),
): MintPop {
  const payload = buildMintPopPayload(seed, { publicKeyDer: registeredKey, nonce, issuedAt });
  return { nonce, issuedAt, signature: signPayload(payload, signingSeed) };
}

// ════════════════════════════════════════════════════════════════════════════
// mintRoot
// ════════════════════════════════════════════════════════════════════════════

test('root generate-and-discard mints and audits', async () => {
  const { service, audit } = fixture();
  const { vaid } = await service.mintRoot({
    seed: {
      agentClass: 'researcher',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: [prefixEntry('data.governance')],
      capabilitySet: ['read.documents'],
    },
  });
  assert.equal(vaid.agent_class, 'researcher');
  assert.deepEqual(vaid.scope_boundary, [prefixEntry('data.governance')]);
  assert.equal(vaid.parent_vaid, null);
  assert.equal(audit.length, 1);
  assert.equal(audit.entries()[0].eventType, 'vaid_minted');
  assert.equal(audit.entries()[0].details.delegated, false);
});

test('a root mint denied by the authorization gate has no side effects', async () => {
  const audit = new InMemoryAudit();
  const service = new MintService(ReferenceIssuer.ephemeral(1), audit, new DenyAll());
  await assert.rejects(
    service.mintRoot({ seed: { agentClass: 'researcher', version: '1.0.0', tenantId: 'acme' } }),
    (error: Error) => error instanceof UnauthorizedError && /denied by gate/.test(error.message),
  );
  assert.equal(audit.isEmpty(), true, 'a gate-denied root mint must not audit');
});

test('root BYO-key with a valid PoP binds the registered key', async () => {
  const { service, audit } = fixture();
  const holder = holderKeypair();
  const seed = byoSeed(holder.publicKey);
  const pop = makePop(seed, holder.publicKey, holder.seed, 'nonce-aaa');

  const { vaid } = await service.mintRoot({ seed, pop });
  assert.deepEqual(vaid.public_key_der, Array.from(holder.publicKey));
  assert.equal(audit.entries()[0].details.byo_key, true);
  assert.equal(audit.entries()[0].details.pop_verified, true);
});

test('THE CORE ATTACK: registering a key you do not control is rejected', async () => {
  const { service, audit } = fixture();
  const victim = holderKeypair();
  const attacker = holderKeypair();
  const seed = byoSeed(victim.publicKey);
  // Register the victim's public key, sign with the attacker's private key.
  const pop = makePop(seed, victim.publicKey, attacker.seed, 'nonce-bbb');

  await assert.rejects(
    service.mintRoot({ seed, pop }),
    (error: Error) => error instanceof IdentityError && /does not verify/.test(error.message),
  );
  assert.equal(audit.isEmpty(), true, 'no VAID minted → no audit');
});

test('root BYO-key without a PoP is rejected', async () => {
  const { service } = fixture();
  await assert.rejects(
    service.mintRoot({ seed: byoSeed(holderKeypair().publicKey) }),
    /proof-of-possession required/,
  );
});

test('a replayed PoP nonce is rejected', async () => {
  const { service } = fixture();
  const holder = holderKeypair();
  const seed = byoSeed(holder.publicKey);
  const pop = makePop(seed, holder.publicKey, holder.seed, 'nonce-replay');

  await service.mintRoot({ seed, pop });
  await assert.rejects(service.mintRoot({ seed, pop }), /replay/);
});

test('a stale PoP is rejected', async () => {
  const { service } = fixture();
  const holder = holderKeypair();
  const seed = byoSeed(holder.publicKey);
  const stale = utcWholeSecondRfc3339(
    new Date(Date.now() - (MINT_POP_FRESHNESS_SECS + 60) * 1000),
  );
  const pop = makePop(seed, holder.publicKey, holder.seed, 'nonce-stale', stale);
  await assert.rejects(service.mintRoot({ seed, pop }), /freshness window/);
});

// ════════════════════════════════════════════════════════════════════════════
// mintChild — attenuated delegation
// ════════════════════════════════════════════════════════════════════════════

function parentDoc(tenant: string, scope: string[], caps: string[]): Vaid {
  return ReferenceIssuer.ephemeral(1).issueVaidWithLineage({
    agentClass: 'parent',
    version: '1.0.0',
    tenantId: tenant,
    parentVaid: null,
    scopeBoundary: scope.map(prefixEntry),
    capabilitySet: caps,
  });
}

function childSeed(parent: Vaid, scope: string[], caps: string[], childPub: Uint8Array): VaidSeed {
  return {
    agentClass: 'child',
    version: '1.0.0',
    tenantId: parent.tenant_id,
    parentVaid: parent.vaid_id,
    scopeBoundary: scope.map(prefixEntry),
    capabilitySet: caps,
    publicKeyDer: childPub,
  };
}

function signedChild(parent: Vaid, scope: string[], caps: string[], nonce: string): MintVaidRequest {
  const holder = holderKeypair();
  const seed = childSeed(parent, scope, caps, holder.publicKey);
  return { seed, pop: makePop(seed, holder.publicKey, holder.seed, nonce) };
}

test('a child within bounds is minted with lineage and a delegated audit entry', async () => {
  const { service, audit } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read', 'write']);
  const request = signedChild(parent, ['data.aifactory.sub'], ['read'], 'ok-1');

  const { vaid } = await service.mintChild(request, parent);
  assert.equal(vaid.parent_vaid, parent.vaid_id, 'lineage bound');
  assert.equal(audit.entries()[0].details.delegated, true);
  assert.equal(audit.entries()[0].details.attenuation_verified, true);
});

test('a child scope exceeding the parent is denied', async () => {
  const { service, audit } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  await assert.rejects(
    service.mintChild(signedChild(parent, ['data.somewhere-else'], ['read'], 'deny-scope'), parent),
    /scope_boundary exceeds/,
  );
  assert.equal(audit.isEmpty(), true);
});

test('an EMPTY child scope under a restricted parent is denied — empty means ⊤', async () => {
  // The escalation the empty-child guard closes: a vacuous `every()` over zero
  // entries would mint an unrestricted child under a restricted parent.
  const { service } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  await assert.rejects(
    service.mintChild(signedChild(parent, [], ['read'], 'deny-empty-scope'), parent),
    /scope_boundary exceeds/,
  );
});

test('an unrestricted parent permits any child scope, including empty', async () => {
  const { service } = fixture();
  const parent = parentDoc('aifactory', [], ['read']);
  await service.mintChild(signedChild(parent, ['data.anything'], ['read'], 'u-1'), parent);
  await service.mintChild(signedChild(parent, [], ['read'], 'u-2'), parent);
});

test('child capabilities exceeding the parent are denied', async () => {
  const { service } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  await assert.rejects(
    service.mintChild(
      signedChild(parent, ['data.aifactory.sub'], ['read', 'write'], 'deny-caps'),
      parent,
    ),
    /capability_set exceeds/,
  );
});

test('an empty parent capability set may delegate nothing, but an empty child set is fine', async () => {
  // The deliberate scope/caps asymmetry: scope empty = ⊤ needs a guard, caps
  // empty = ∅ does not.
  const { service } = fixture();
  const parent = parentDoc('aifactory', [], []);
  await assert.rejects(
    service.mintChild(signedChild(parent, [], ['read'], 'caps-deny'), parent),
    /capability_set exceeds/,
  );
  await service.mintChild(signedChild(parent, [], [], 'caps-ok'), parent);
});

test('a cross-tenant child is denied', async () => {
  const { service, audit } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  const holder = holderKeypair();
  const seed = childSeed(parent, ['data.aifactory.sub'], ['read'], holder.publicKey);
  seed.tenantId = 'acme'; // forge a foreign tenant
  const pop = makePop(seed, holder.publicKey, holder.seed, 'forge-tenant');

  await assert.rejects(
    service.mintChild({ seed, pop }, parent),
    /cross-tenant delegation is denied/,
  );
  assert.equal(audit.isEmpty(), true);
});

test('a child claiming a different parent_vaid is denied', async () => {
  const { service, audit } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  const holder = holderKeypair();
  const seed = childSeed(parent, ['data.aifactory.sub'], ['read'], holder.publicKey);
  seed.parentVaid = crypto.randomUUID(); // forge a different parent
  const pop = makePop(seed, holder.publicKey, holder.seed, 'forge-parent');

  await assert.rejects(service.mintChild({ seed, pop }, parent), /parent_vaid/);
  assert.equal(audit.isEmpty(), true);
});

// ── DELEGATION-DEPTH ENFORCEMENT (0.11.0): default 1, configurable. ──

async function mintRealRoot(service: MintService, tenantId: string): Promise<Vaid> {
  const { vaid } = await service.mintRoot({
    seed: {
      agentClass: 'root',
      version: '1.0.0',
      tenantId,
      scopeBoundary: [prefixEntry('data.aifactory')],
      capabilitySet: ['read'],
    },
  });
  return vaid;
}

async function mintRealChild(service: MintService, parent: Vaid, nonce: string): Promise<Vaid> {
  const { vaid } = await service.mintChild(
    signedChild(parent, ['data.aifactory'], ['read'], nonce),
    parent,
  );
  return vaid;
}

test('default depth mints a root child but refuses a grandchild', async () => {
  const { service, audit } = fixture(); // default maxDelegationDepth === 1
  const root = await mintRealRoot(service, 'aifactory');
  const child = await mintRealChild(service, root, 'root-to-child');
  const eventsAfterChild = audit.length;
  assert.equal(eventsAfterChild, 2); // root mint + child mint

  const request = signedChild(child, ['data.aifactory'], ['read'], 'child-to-grandchild');
  await assert.rejects(service.mintChild(request, child), /delegation depth/);
  assert.equal(audit.length, eventsAfterChild, 'no grandchild minted');
});

test('a root child is always allowed regardless of configured depth', async () => {
  const issuer = ReferenceIssuer.ephemeral(1).assumingNothingRevoked();
  const service = new MintService(issuer, new InMemoryAudit(), new PermitAll(), 1);
  const root = await mintRealRoot(service, 'aifactory');
  const child = await mintRealChild(service, root, 'root-to-child-explicit-1');
  assert.equal(child.parent_vaid, root.vaid_id);
});

test('depth 2 mints a grandchild but refuses a great-grandchild', async () => {
  const issuer = ReferenceIssuer.ephemeral(1).assumingNothingRevoked();
  const service = new MintService(issuer, new InMemoryAudit(), new PermitAll(), 2);
  const root = await mintRealRoot(service, 'aifactory');
  const child = await mintRealChild(service, root, 'depth2-root-to-child');
  const grandchild = await mintRealChild(service, child, 'depth2-child-to-grandchild');
  assert.equal(grandchild.parent_vaid, child.vaid_id);

  const request = signedChild(
    grandchild,
    ['data.aifactory'],
    ['read'],
    'depth2-grandchild-to-greatgrandchild',
  );
  await assert.rejects(service.mintChild(request, grandchild), /delegation depth/);
});

test('depth refusal happens before any lineage write', async () => {
  const { service, audit } = fixture();
  const root = await mintRealRoot(service, 'aifactory');
  const child = await mintRealChild(service, root, 'before-write-root-to-child');
  const eventsBefore = audit.length;

  const request = signedChild(
    child,
    ['data.aifactory'],
    ['read'],
    'before-write-child-to-grandchild',
  );
  await assert.rejects(service.mintChild(request, child));
  assert.equal(audit.length, eventsBefore, 'a refused mint must not audit a mint');
});

// ── maxDelegationDepth VALIDATION: fails closed at construction, never
//    "unlimited". ──

test('maxDelegationDepth zero is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(0), ConfigError);
});

test('maxDelegationDepth negative is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(-1), ConfigError);
});

test('maxDelegationDepth non-integer is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(1.5), ConfigError);
});

test('maxDelegationDepth NaN is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(NaN), ConfigError);
});

test('maxDelegationDepth Infinity is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(Infinity), ConfigError);
});

test('maxDelegationDepth above the lineage bound is rejected', () => {
  assert.throws(() => validateMaxDelegationDepth(MAX_LINEAGE_DEPTH + 1), ConfigError);
});

test('maxDelegationDepth at the lineage bound is accepted', () => {
  assert.equal(validateMaxDelegationDepth(MAX_LINEAGE_DEPTH), MAX_LINEAGE_DEPTH);
});

test('maxDelegationDepth one is accepted', () => {
  assert.equal(validateMaxDelegationDepth(1), 1);
});

test('constructing a mint with an invalid depth fails closed', () => {
  const issuer = ReferenceIssuer.ephemeral(1);
  assert.throws(
    () => new MintService(issuer, new InMemoryAudit(), new PermitAll(), 0),
    ConfigError,
  );
});

// ── DELEGATION DEPTH FAILS CLOSED when ancestry cannot be fully resolved
//    (334 follow-up, 14 Oct 2026). Four properties: ──

/**
 * A hand-built doc with no real mint behind it, carrying `parent_vaid`.
 * Depth checking must never need the referenced parent to actually exist
 * anywhere; it only needs the LEAF's own signed field, which is why this is
 * enough for every test below. Signed by a throwaway issuer whose own
 * lineage store is irrelevant to the test — only the document's own fields
 * matter here.
 */
function docWithParent(tenant: string, parentVaid: string): Vaid {
  return ReferenceIssuer.ephemeral(1).issueVaidWithLineage({
    agentClass: 'child',
    version: '1.0.0',
    tenantId: tenant,
    parentVaid,
    scopeBoundary: [prefixEntry('data.aifactory')],
    capabilitySet: ['read'],
  });
}

/** A fresh, unique id to name as "the parent" below — nothing is minted for it. */
function freshVaidId(): string {
  return ReferenceIssuer.ephemeral(1).issueVaidWithLineage({
    agentClass: 'root',
    version: '1.0.0',
    tenantId: 'aifactory',
    parentVaid: null,
    scopeBoundary: [],
    capabilitySet: [],
  }).vaid_id;
}

test('depth 1 refuses when the grandparent cannot be resolved after a restart', async () => {
  // 1. RESTART TRUNCATION, default depth 1. A real root -> child chain is
  // minted, then the issuer's lineage map is cleared (the ops/test
  // primitive that models a process restart). `child`'s OWN document
  // still names its parent, but the map can no longer vouch that the
  // named parent is a genuine root. The naive bug this guards is treating
  // "can't resolve" as "assume it's a root", which would wrongly compute
  // parentDepth = 0 here and ALLOW the mint. The correct answer is
  // incomplete assembly, and refusal.
  const issuer = ReferenceIssuer.ephemeral(1);
  const audit = new InMemoryAudit();
  const service = new MintService(issuer, audit); // default depth 1
  const root = await mintRealRoot(service, 'aifactory');
  const child = await mintRealChild(service, root, 'restart-root-to-child');

  issuer.clearLineage(); // "process restart": the map forgets everything

  const request = signedChild(
    child,
    ['data.aifactory'],
    ['read'],
    'restart-child-to-grandchild',
  );
  await assert.rejects(service.mintChild(request, child), /could not be determined/);
});

test('depth 2 refuses when an ancestor beyond the first hop is unresolvable', async () => {
  // 2. An ancestor SEVERAL HOPS UP is unresolvable, after resolution has
  // already succeeded partway. A naive implementation might stop at the
  // first unresolved hop and accept the chain built so far as complete
  // (treating it as shorter than it really is). Here the resolver knows
  // `child`'s parent is `root` (one hop resolves cleanly) but has no
  // record of `root` itself, so the assembly must still fail as a whole,
  // never settle for "2 hops, that's enough".
  class PartialLineageStore {
    constructor(private readonly known: Map<string, ParentResolution>) {}
    record(_vaidId: string, _parent: string | null): void {}
    resolveParent(vaidId: string): ParentResolution {
      return this.known.get(vaidId) ?? parentResolutionUnknown();
    }
  }

  const rootId = freshVaidId();
  const child = docWithParent('aifactory', rootId);
  const grandchild = docWithParent('aifactory', child.vaid_id);

  // The resolver knows child -> root (one hop resolves), but has NO entry
  // for rootId at all: it cannot vouch root is a genuine root, nor
  // resolve any further. This must be incomplete, not "stop here".
  const store = new PartialLineageStore(
    new Map([[child.vaid_id, parentResolutionOf(rootId)]]),
  );

  const issuer = ReferenceIssuer.ephemeral(1).withRevocationBackend(
    new RevocationBackend(InMemoryRevocationList.assumeNothingRevoked(), store),
  );
  const service = new MintService(issuer, new InMemoryAudit(), new PermitAll(), 2);

  const request = signedChild(
    grandchild,
    ['data.aifactory'],
    ['read'],
    'partial-grandchild-to-greatgrandchild',
  );
  await assert.rejects(service.mintChild(request, grandchild), /could not be determined/);
});

test('depth 1 refuses regardless of what a lying resolver claims', async () => {
  // 3. The CHEAP, STATE-INDEPENDENT rule at depth 1: if the presented
  // parent's own document names a parentVaid at all, the mint must
  // refuse, regardless of what the lineage resolver answers about that
  // named id. Proven with a deliberately WRONG resolver that claims every
  // id is a genuine root: even then, the presented parent's OWN
  // parentVaid field contributes one guaranteed hop the resolver did not
  // invent, so the assembled chain is still length 2 and depth 1 is still
  // exceeded.
  class AlwaysRootLineageStore {
    record(_vaidId: string, _parent: string | null): void {}
    resolveParent(_vaidId: string): ParentResolution {
      return parentResolutionRoot(); // wrong for every id but a real root
    }
  }

  const rootId = freshVaidId();
  const childAsParent = docWithParent('aifactory', rootId);

  const issuer = ReferenceIssuer.ephemeral(1).withRevocationBackend(
    new RevocationBackend(
      InMemoryRevocationList.assumeNothingRevoked(),
      new AlwaysRootLineageStore(),
    ),
  );
  const service = new MintService(issuer, new InMemoryAudit()); // default depth 1

  const request = signedChild(
    childAsParent,
    ['data.aifactory'],
    ['read'],
    'lying-resolver-depth-2-attempt',
  );
  await assert.rejects(service.mintChild(request, childAsParent), /delegation depth/);
});

test('depth check refuses with the existing typed error on a lineage store failure', async () => {
  // 4. A lineage READ failure (the store cannot be consulted at all, not
  // merely "doesn't know this id yet") refuses with the SAME typed error
  // as every other denial in mintChild: UnauthorizedError, never a silent
  // allow and never an unhandled exception escaping. Modelled by a
  // resolver that always answers "unknown" — the only representable
  // "failure" a resolver can report, mirroring how revocation fails
  // closed: there is no distinct "errored" case to swallow, UNKNOWN is
  // the fail-closed signal.
  class FailingLineageStore {
    record(_vaidId: string, _parent: string | null): void {}
    resolveParent(_vaidId: string): ParentResolution {
      return parentResolutionUnknown();
    }
  }

  const issuer = ReferenceIssuer.ephemeral(1).withRevocationBackend(
    new RevocationBackend(
      InMemoryRevocationList.assumeNothingRevoked(),
      new FailingLineageStore(),
    ),
  );
  const audit = new InMemoryAudit();
  const service = new MintService(issuer, audit);

  const rootId = freshVaidId();
  const parent = docWithParent('aifactory', rootId);
  const request = signedChild(parent, ['data.aifactory'], ['read'], 'store-failure-attempt');

  await assert.rejects(
    service.mintChild(request, parent),
    (e: Error) => e instanceof UnauthorizedError,
  );
  assert.equal(audit.length, 0, 'a refused mint must not audit a mint');
});

test('mintChild without a verified parent in context is denied', async () => {
  const { service } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  const request = signedChild(parent, ['data.aifactory.sub'], ['read'], 'no-parent');
  await assert.rejects(service.mintChild(request, null), /no verified parent VAID/);
});

test('mintChild without a BYO key is denied', async () => {
  const { service } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);
  const seed = childSeed(parent, ['data.aifactory.sub'], ['read'], new Uint8Array());
  seed.publicKeyDer = null;
  await assert.rejects(service.mintChild({ seed }, parent), /BYO-key required/);
});

test('a rejected attenuation does not consume the PoP nonce', async () => {
  // Attenuation precedes the nonce insert, so an unauthorized delegation cannot
  // burn a nonce the holder would then be unable to reuse.
  const { service } = fixture();
  const parent = parentDoc('aifactory', ['data.aifactory'], ['read']);

  await assert.rejects(
    service.mintChild(signedChild(parent, ['data.elsewhere'], ['read'], 'N'), parent),
  );
  // A VALID request reusing the SAME nonce "N" now succeeds — proving "N" was
  // never consumed by the denied call.
  await service.mintChild(signedChild(parent, ['data.aifactory.sub'], ['read'], 'N'), parent);
});

test('end-to-end: a minted child verifies against its issuer and is contained by its parent', async () => {
  const audit = new InMemoryAudit();
  // Vouching: the subject is attenuation and scope containment, not the 0.9.0
  // fail-closed default (see revocation_seam.test.ts, cross-language scenarios).
  const issuer = ReferenceIssuer.ephemeral(1).assumingNothingRevoked();
  const service = new MintService(issuer, audit);

  // Mint a REAL parent root through the issuer, so its lineage is recorded and
  // the child's ancestry is resolvable at verification (R.4.2). A synthetic
  // parent never minted here would — correctly — leave the child's lineage
  // incomplete and fail closed.
  const { vaid: parent } = await service.mintRoot({
    seed: {
      agentClass: 'parent',
      version: '1.0.0',
      tenantId: 'aifactory',
      scopeBoundary: [prefixEntry('data.aifactory')],
      capabilitySet: ['read', 'write'],
    },
  });
  const { vaid: child } = await service.mintChild(
    signedChild(parent, ['data.aifactory.reports'], ['read'], 'e2e'),
    parent,
  );

  assert.equal(issuer.verifyVaid(child), true, 'a minted child must verify against the issuer');
  assert.ok(
    child.scope_boundary.every((e) => {
      const r = entryClaimedResource(e);
      return r !== null && isInScope(parent, r);
    }),
  );
  assert.ok(child.capability_set.every((c) => parent.capability_set.includes(c)));
});

// ════════════════════════════════════════════════════════════════════════════
// expiry containment at mint (vaid#79)
// ════════════════════════════════════════════════════════════════════════════

/**
 * A parent whose expiry sits `seconds` either side of now. Anchored to the clock
 * rather than to a hard-coded date, because a hard-coded date is how the Python
 * twin's parent fixture quietly became an expired parent.
 */
function parentExpiringIn(seconds: number): Vaid {
  const parent = parentDoc('acme', ['data.x'], ['read']);
  const expires = new Date(Date.now() + seconds * 1000);
  return {
    ...parent,
    expires_at: utcWholeSecondRfc3339(expires) as Vaid['expires_at'],
  };
}

test('a child is clamped to its parent expiry', async () => {
  // The mint half of vaid#79. The issuer's TTL is an hour; the parent has ten
  // minutes left; the child gets the parent's expiry, not the issuer's.
  const { service } = fixture(); // ReferenceIssuer.ephemeral(1) — a 1-hour TTL
  const parent = parentExpiringIn(600);

  const { vaid: child } = await service.mintChild(
    signedChild(parent, ['data.x'], ['read'], 'clamp-1'),
    parent,
  );

  assert.equal(
    child.expires_at,
    parent.expires_at,
    'the child must end exactly when its parent does, not an hour later',
  );
});

test('a child keeps the issuer TTL when it is the earlier bound', async () => {
  // THE CONTROL on the clamp. A clamp that always returned the parent's expiry
  // would pass the test above and would be wrong: the issuer's own TTL still binds
  // when it is the shorter of the two.
  const { service } = fixture();
  const parent = parentExpiringIn(86_400); // a day out; the issuer's TTL is an hour

  const { vaid: child } = await service.mintChild(
    signedChild(parent, ['data.x'], ['read'], 'clamp-2'),
    parent,
  );

  assert.ok(
    Date.parse(child.expires_at) < Date.parse(parent.expires_at),
    'the issuer TTL is the earlier bound here and must still apply',
  );
});

test('delegation works across a second boundary', async () => {
  // The regression this policy exists for. Under a refuse-instead-of-clamp rule,
  // ONE issuer with ONE TTL could only delegate inside the same whole second as the
  // parent's mint: `expires = now + ttl` is re-evaluated at every mint, so a child
  // minted a second later outlived its parent and was refused. Measured, not
  // assumed — this test waits past a second boundary.
  const { service } = fixture();
  const { vaid: parent } = await service.mintRoot({
    seed: {
      agentClass: 'parent',
      version: '1.0.0',
      tenantId: 'acme',
      parentVaid: null,
      scopeBoundary: [prefixEntry('data.x')],
      capabilitySet: ['read'],
    },
  });

  await new Promise((resolve) => setTimeout(resolve, 1100));

  const { vaid: child } = await service.mintChild(
    signedChild(parent, ['data.x'], ['read'], 'boundary'),
    parent,
  );

  assert.ok(Date.parse(child.expires_at) <= Date.parse(parent.expires_at));
});

test('delegating from an already expired parent is refused', async () => {
  // The one case a clamp cannot answer: the ceiling is in the past, so the child
  // would be issued dead. Refused before the PoP, with the expiry named.
  const { service } = fixture();
  const parent = parentExpiringIn(-60);

  await assert.rejects(
    service.mintChild(signedChild(parent, ['data.x'], ['read'], 'dead-parent'), parent),
    (e: Error) =>
      e instanceof UnauthorizedError &&
      e.message.includes(parent.expires_at) &&
      e.message.includes('expired'),
    'the refusal must name the parent expiry — a caller that cannot see which bound it hit has to guess',
  );
});

test('an unreadable parent expiry refuses the delegation', async () => {
  // Fail closed: an expiry that cannot be read is expired, so it is refused by the
  // same line rather than clamped to a ceiling nobody can evaluate.
  const { service } = fixture();
  const parent = {
    ...parentDoc('acme', ['data.x'], ['read']),
    expires_at: 'whenever' as Vaid['expires_at'],
  };

  await assert.rejects(
    service.mintChild(signedChild(parent, ['data.x'], ['read'], 'unreadable'), parent),
    UnauthorizedError,
  );
});

test('refusing a dead parent does not consume the PoP nonce', async () => {
  // The refusal sits with the other containment checks, BEFORE the PoP, so a caller
  // that renews the parent and retries is not denied for the wrong reason.
  const { service } = fixture();
  const dead = parentExpiringIn(-60);
  const live = parentExpiringIn(600);

  await assert.rejects(
    service.mintChild(signedChild(dead, ['data.x'], ['read'], 'shared-nonce'), dead),
    UnauthorizedError,
  );

  const { vaid } = await service.mintChild(
    signedChild(live, ['data.x'], ['read'], 'shared-nonce'),
    live,
  );
  assert.ok(vaid.vaid_id);
});

test('an issuer that ignores the ceiling is caught and the child withheld', async () => {
  // Step 7a. `notAfter` is an instruction to a seam a deployment supplies; the
  // invariant is a property of the document. An issuer written before this rule — or
  // one that simply gets it wrong — must not be able to put an over-long child into
  // circulation through this mint.
  const inner = ReferenceIssuer.ephemeral(1);
  const ignoresTheCeiling = {
    issueVaidWithKey: (attributes: Parameters<typeof inner.issueVaidWithKey>[0], key: Uint8Array) =>
      inner.issueVaidWithKey(attributes, key),
    issueVaidWithLineage: (attributes: Parameters<typeof inner.issueVaidWithLineage>[0]) =>
      inner.issueVaidWithLineage(attributes),
    verifyVaid: (v: Vaid) => inner.verifyVaid(v),
    resolveParent: (id: string) => inner.resolveParent(id),
    resolveDelegationAncestor: (id: string) => inner.resolveDelegationAncestor(id),
  };
  const service = new MintService(ignoresTheCeiling, new InMemoryAudit());
  const parent = parentExpiringIn(600);

  await assert.rejects(
    service.mintChild(signedChild(parent, ['data.x'], ['read'], 'bad-issuer'), parent),
    (e: Error) => e instanceof UnauthorizedError && e.message.includes('notAfter'),
  );
});

test('the root path is unclamped', async () => {
  // A root has no parent to be contained by, so nothing bounds its TTL. Stated as a
  // test because a clamp applied indiscriminately would silently shorten every root
  // mint in the estate.
  const { service } = fixture();
  const { vaid: root } = await service.mintRoot({
    seed: {
      agentClass: 'root',
      version: '1.0.0',
      tenantId: 'acme',
      parentVaid: null,
      scopeBoundary: [prefixEntry('data.x')],
      capabilitySet: ['read'],
    },
  });

  assert.equal(
    Date.parse(root.expires_at) - Date.parse(root.issued_at),
    3_600_000,
    'the issuer full TTL applies',
  );
});

// ════════════════════════════════════════════════════════════════════════════
// the clamp is visible to the caller, not only in a shorter expires_at
// ════════════════════════════════════════════════════════════════════════════

test('a clamped child says so on the response', async () => {
  // A silent shortening was the objection to clamping. `expires_at` alone looks
  // like an ordinary expiry: a caller would have to know the issuer's TTL and
  // subtract to notice its delegation had been cut short. The response says it.
  const { service } = fixture(); // ReferenceIssuer.ephemeral(1) — a 1-hour TTL
  const parent = parentExpiringIn(600); // ten minutes left

  const response = await service.mintChild(
    signedChild(parent, ['data.x'], ['read'], 'visible-1'),
    parent,
  );

  assert.equal(response.expiryBoundedByParent, true);
  assert.equal(response.parentExpiresAt, parent.expires_at);
  assert.equal(response.vaid.expires_at, parent.expires_at);
});

test('an unclamped child says that too', async () => {
  // THE CONTROL. A flag that is always true carries no information, and would pass
  // the test above while telling a caller nothing. Here the issuer's own TTL is the
  // earlier bound, nothing was taken away, and the flag must be false.
  const { service } = fixture();
  const parent = parentExpiringIn(86_400); // a day out; the issuer TTL is an hour

  const response = await service.mintChild(
    signedChild(parent, ['data.x'], ['read'], 'visible-2'),
    parent,
  );

  assert.equal(response.expiryBoundedByParent, false);
  assert.equal(response.parentExpiresAt, parent.expires_at);
  assert.ok(Date.parse(response.vaid.expires_at) < Date.parse(parent.expires_at));
});

test('a root mint is never bounded by a parent it does not have', async () => {
  const { service } = fixture();
  const response = await service.mintRoot({
    seed: {
      agentClass: 'root',
      version: '1.0.0',
      tenantId: 'acme',
      parentVaid: null,
      scopeBoundary: [prefixEntry('data.x')],
      capabilitySet: ['read'],
    },
  });

  assert.equal(response.expiryBoundedByParent, false);
  assert.equal(response.parentExpiresAt, null);
});

test('the clamp is recorded in the audit trail', async () => {
  // A caller that ignores the response still leaves a record. Without this, the
  // only evidence that a credential was deliberately shortened would be the
  // caller's own memory of a field it did not read.
  const { service, audit } = fixture();
  const parent = parentExpiringIn(600);

  await service.mintChild(signedChild(parent, ['data.x'], ['read'], 'visible-3'), parent);

  const recorded = audit.entries();
  const entry = recorded[recorded.length - 1]!;
  assert.equal(entry.details.expiry_bounded_by_parent, true);
  assert.equal(entry.details.expires_at, parent.expires_at);
  assert.equal(entry.details.parent_expires_at, parent.expires_at);
});

// ════════════════════════════════════════════════════════════════════════════
// S.8 well-formedness: the producer refuses what the wire parser would
// ════════════════════════════════════════════════════════════════════════════
//
// These exist because the two disagreed. A malformed boundary was carried
// through the mint, signed, and accepted by `verifyVaid`, and refused only by
// `parseVaidDocument` once the credential was read back off the wire, so a
// producer could mint an unparseable credential and be told it was fine.
//
// The checks are RUNTIME checks in a typed codebase on purpose. `VaidSeed`
// types `scopeBoundary` as `ScopeBoundaryEntry[]`, so `tsc` already rejects the
// pre-0.10.0 `['data.acme']` spelling. A plain JavaScript caller gets no such
// gate, and neither does typed code that parsed JSON and asserted a shape with
// `as`. That is what these casts simulate, and it is the only way a malformed
// boundary arrives. Every case uses the SAME predicate the wire parser uses
// (`isWellFormedScopeBoundary`), so there is one rule and not a mint-time copy.

/** The malformed shapes S.8 names, each a separate reason to refuse. */
const MALFORMED_BOUNDARIES: ReadonlyArray<readonly [string, unknown]> = [
  ['bare-v3-string', ['data.acme']],
  ['missing-value', [{ kind: 'prefix' }]],
  ['missing-kind', [{ value: 'data.acme' }]],
  ['extra-member', [{ kind: 'prefix', value: 'data.acme', max: 5 }]],
  ['empty-kind', [{ kind: '', value: 'data.acme' }]],
  ['prefix-value-not-a-string', [{ kind: 'prefix', value: 100 }]],
  ['one-good-one-bare', [prefixEntry('data.acme'), 'data.other']],
  ['boundary-not-a-list', 'data.acme'],
];

for (const [label, boundary] of MALFORMED_BOUNDARIES) {
  test(`mintRoot refuses a malformed scope_boundary (${label})`, async () => {
    const { service } = fixture();
    await assert.rejects(
      service.mintRoot({
        seed: {
          agentClass: 'orchestrator',
          version: '1.0.0',
          tenantId: 'acme',
          scopeBoundary: boundary as never,
          capabilitySet: ['read'],
        },
      }),
      (error: Error) => error instanceof MintError && /well-formed S\.8 boundary/.test(error.message),
    );
  });

  test(`mintChild refuses a malformed scope_boundary (${label})`, async () => {
    const { service } = fixture();
    const { vaid: parent } = await service.mintRoot({
      seed: {
        agentClass: 'orchestrator',
        version: '1.0.0',
        tenantId: 'acme',
        scopeBoundary: [prefixEntry('data.acme')],
        capabilitySet: ['read'],
      },
    });
    const holder = holderKeypair();
    await assert.rejects(
      service.mintChild(
        {
          seed: {
            agentClass: 'child',
            version: '1.0.0',
            tenantId: 'acme',
            parentVaid: parent.vaid_id,
            scopeBoundary: boundary as never,
            capabilitySet: ['read'],
            publicKeyDer: holder.publicKey,
          },
        },
        parent,
      ),
      (error: Error) => error instanceof MintError,
    );
  });
}

test('a mintRoot refused for shape signs nothing and records nothing', async () => {
  const { service, audit } = fixture();
  await assert.rejects(
    service.mintRoot({
      seed: {
        agentClass: 'orchestrator',
        version: '1.0.0',
        tenantId: 'acme',
        scopeBoundary: ['data.acme'] as never,
        capabilitySet: ['read'],
      },
    }),
    (error: Error) => error instanceof MintError,
  );
  assert.equal(audit.isEmpty(), true, 'a shape-refused mint must not audit');
});

/** A fixed kernel seed, so these tests hold the signing key. */
const SIGNING_SEED = new Uint8Array(32).fill(0x5a);

/**
 * An authentically signed document carrying `boundary` verbatim. Signed over its
 * own bytes, so a denial cannot be a signature failure in disguise.
 */
function handBuilt(issuer: ReferenceIssuer, boundary: unknown): Vaid {
  const id = randomUUID();
  const unsigned = buildUnsignedVaidDocument({
    vaidId: id,
    agentId: id,
    agentClass: 'hand-built',
    version: '1.0.0',
    tenantId: 'acme',
    issuedAt: '2026-06-04T12:00:00Z',
    expiresAt: '2999-01-01T00:00:00Z',
    publicKeyDer: [],
    parentVaid: null,
    scopeBoundary: boundary as never,
    lineageHash: computeLineageHash(null, id),
    capabilitySet: ['read'],
    trustDomain: 'vaid.example',
    kernelKeyThumbprint: kernelKeyThumbprint(issuer.kernelPublicKey()),
  });
  const signature = ed25519Sign(canonicalVaidSigningBytes(unsigned), SIGNING_SEED);
  return { ...unsigned, kernel_signature: Array.from(signature) } as Vaid;
}

for (const [label, boundary] of MALFORMED_BOUNDARIES) {
  test(`verifyVaid denies a malformed scope_boundary (${label})`, () => {
    const issuer = ReferenceIssuer.fromSeed(SIGNING_SEED, 1).assumingNothingRevoked();
    const signed = handBuilt(issuer, boundary);
    // The signature really is valid over these bytes. Without this the test
    // would pass for the wrong reason on any future change.
    assert.equal(verifyVaidAuthenticity(issuer.kernelPublicKey(), signed), true);
    // And the wire parser rejects it, which is the behaviour verifyVaid must now
    // agree with rather than contradict.
    assert.equal(parseVaidDocument(JSON.stringify(signed)), null);
    assert.equal(issuer.verifyVaid(signed), false);
  });
}

test('verifyVaid accepts the same hand-built document with typed entries', () => {
  const issuer = ReferenceIssuer.fromSeed(SIGNING_SEED, 1).assumingNothingRevoked();
  const signed = handBuilt(issuer, [prefixEntry('data.acme')]);
  assert.equal(issuer.verifyVaid(signed), true);
  assert.notEqual(parseVaidDocument(JSON.stringify(signed)), null);
});

test('well-formed entries mint, verify and parse', async () => {
  const { service, audit, issuer } = fixture();
  const { vaid } = await service.mintRoot({
    seed: {
      agentClass: 'orchestrator',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: [prefixEntry('data.acme')],
      capabilitySet: ['read'],
    },
  });
  assert.equal(isWellFormedScopeBoundary(vaid.scope_boundary), true);
  assert.equal(issuer.verifyVaid(vaid), true);
  // The property the split used to break: what verifies locally also parses off
  // the wire.
  assert.notEqual(parseVaidDocument(JSON.stringify(vaid)), null);
  assert.equal(audit.isEmpty(), false);
});

/**
 * S.8 (shape) is not S.10 (recognised kinds), and conflating them would break
 * extensibility. `{ kind: 'amount_limit', value: 100 }` is WELL FORMED and its
 * kind is simply unknown here, so it must mint and parse; it is refused at
 * VERIFY as `unknown_scope_kind`.
 *
 * This is the test that stops the new shape gate from being written as "only a
 * prefix entry is acceptable", which would pass every other test in this
 * section and silently close the extension point ADR-0009 exists to open.
 */
test('an unrecognised kind still mints and parses', async () => {
  const { service } = fixture();
  const { vaid } = await service.mintRoot({
    seed: {
      agentClass: 'orchestrator',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: [{ kind: 'amount_limit', value: 100 }] as never,
      capabilitySet: ['read'],
    },
  });
  assert.notEqual(parseVaidDocument(JSON.stringify(vaid)), null);
  assert.equal(boundaryIsEvaluable(vaid.scope_boundary), false);
});

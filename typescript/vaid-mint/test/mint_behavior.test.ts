/**
 * Mint behaviour: root issuance, BYO-key proof-of-possession, and attenuated
 * delegation. Mirror of the Rust `vaid_mint::mint` unit tests and the Python
 * `test_mint_behavior.py`.
 *
 * The property under test throughout `mintChild` is containment: `child ⊆
 * parent`, checked fail-closed before any key work or nonce consumption.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ed25519PublicKey,
  randomEd25519Seed,
  signPayload,
  utcWholeSecondRfc3339,
} from 'vaid-pop';

import {
  buildMintPopPayload,
  DenyAll,
  IdentityError,
  InMemoryAudit,
  MINT_POP_FRESHNESS_SECS,
  MintService,
  ReferenceIssuer,
  UnauthorizedError,
  type MintPop,
  type MintVaidRequest,
  type Vaid,
  type VaidSeed,
} from '../src/index.js';

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
    scopeBoundary: ['data.x'],
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
      scopeBoundary: ['data.governance'],
      capabilitySet: ['read.documents'],
    },
  });
  assert.equal(vaid.agent_class, 'researcher');
  assert.deepEqual(vaid.scope_boundary, ['data.governance']);
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
    scopeBoundary: scope,
    capabilitySet: caps,
  });
}

function childSeed(parent: Vaid, scope: string[], caps: string[], childPub: Uint8Array): VaidSeed {
  return {
    agentClass: 'child',
    version: '1.0.0',
    tenantId: parent.tenant_id,
    parentVaid: parent.vaid_id,
    scopeBoundary: scope,
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
      scopeBoundary: ['data.aifactory'],
      capabilitySet: ['read', 'write'],
    },
  });
  const { vaid: child } = await service.mintChild(
    signedChild(parent, ['data.aifactory.reports'], ['read'], 'e2e'),
    parent,
  );

  assert.equal(issuer.verifyVaid(child), true, 'a minted child must verify against the issuer');
  assert.ok(child.scope_boundary.every((s) => parent.scope_boundary.some((p) => s.startsWith(p))));
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
      scopeBoundary: ['data.x'],
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
      scopeBoundary: ['data.x'],
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
      scopeBoundary: ['data.x'],
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

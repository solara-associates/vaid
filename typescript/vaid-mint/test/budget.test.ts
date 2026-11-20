/**
 * Budget scope kinds (`docs/spec/budget.md`, ADR-0011) — mirror of the Rust
 * `budget` module's own test module, plus `mintChild` integration tests
 * mirroring the Rust `mint::tests` budget cases.
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
  BUDGET_KIND_CALLS,
  BUDGET_KIND_COST_USD_MICRO,
  BudgetAttenuationReason,
  budgetAttenuationReason,
  budgetEntry,
  inheritParentBudgets,
  isBudgetKind,
  validateBudgetBoundary,
} from '../src/budget.js';
import { isInScope, prefixEntry, type ScopeBoundaryEntry } from '../src/document.js';
import {
  buildMintPopPayload,
  InMemoryAudit,
  MintService,
  ReferenceIssuer,
  UnauthorizedError,
  type MintPop,
  type MintVaidRequest,
  type Vaid,
  type VaidSeed,
} from '../src/index.js';

function cost(limit: number): ScopeBoundaryEntry {
  return budgetEntry(BUDGET_KIND_COST_USD_MICRO, { limit });
}

function calls(scope: string, limit: number): ScopeBoundaryEntry {
  return budgetEntry(BUDGET_KIND_CALLS, { scope, limit });
}

// ── pure attenuation-rule tests (mirror of Rust budget::tests) ──

test('a narrower child cost ceiling attenuates', () => {
  assert.equal(
    budgetAttenuationReason([cost(500_000)], [cost(100_000)]),
    BudgetAttenuationReason.Attenuated,
  );
});

test('an equal child cost ceiling attenuates', () => {
  assert.equal(
    budgetAttenuationReason([cost(500_000)], [cost(500_000)]),
    BudgetAttenuationReason.Attenuated,
  );
});

test('a wider child cost ceiling is an escalation', () => {
  assert.equal(
    budgetAttenuationReason([cost(500_000)], [cost(500_001)]),
    BudgetAttenuationReason.BudgetEscalation,
  );
});

test('omitting a parent budget kind is an escalation', () => {
  assert.equal(
    budgetAttenuationReason([cost(500_000)], []),
    BudgetAttenuationReason.BudgetEscalation,
  );
});

test('a child adding a cap the parent never had is safe', () => {
  assert.equal(
    budgetAttenuationReason([], [cost(500_000)]),
    BudgetAttenuationReason.Attenuated,
  );
});

test('fan-out: two children each at the parents limit both attenuate', () => {
  const parent = [cost(500_000)];
  assert.equal(budgetAttenuationReason(parent, [cost(500_000)]), BudgetAttenuationReason.Attenuated);
  assert.equal(budgetAttenuationReason(parent, [cost(500_000)]), BudgetAttenuationReason.Attenuated);
});

test('per-tool calls entries are matched by kind and scope', () => {
  const parent = [calls('*', 500), calls('tool:browser.navigate', 50)];
  const childOk = [calls('*', 100), calls('tool:browser.navigate', 50)];
  assert.equal(budgetAttenuationReason(parent, childOk), BudgetAttenuationReason.Attenuated);
  const childWide = [calls('*', 100), calls('tool:browser.navigate', 51)];
  assert.equal(budgetAttenuationReason(parent, childWide), BudgetAttenuationReason.BudgetEscalation);
});

test('an unrecognised kind anywhere refuses rather than escalates', () => {
  const weird: ScopeBoundaryEntry = { kind: 'future_kind_v9', value: 'whatever' };
  assert.equal(
    budgetAttenuationReason([cost(500_000)], [weird]),
    BudgetAttenuationReason.UnknownBudgetKind,
  );
});

test('inheritParentBudgets copies budget entries only', () => {
  const parent = [prefixEntry('orders/'), cost(500_000), calls('*', 500)];
  const inherited = inheritParentBudgets(parent);
  assert.equal(inherited.length, 2);
  assert.ok(inherited.every((e) => isBudgetKind(e.kind)));
});

test('a malformed limit is refused at construction', () => {
  assert.throws(() => budgetEntry(BUDGET_KIND_COST_USD_MICRO, {}));
  assert.throws(() => budgetEntry(BUDGET_KIND_COST_USD_MICRO, { limit: -1 }));
  assert.throws(() => budgetEntry(BUDGET_KIND_CALLS, { limit: 5 }));
});

test('duplicate singleton entries are refused at boundary level', () => {
  assert.notEqual(validateBudgetBoundary([cost(500_000), cost(100_000)]), null);
});

test('duplicate calls scopes are refused at boundary level', () => {
  assert.notEqual(validateBudgetBoundary([calls('*', 500), calls('*', 100)]), null);
});

test('distinct calls scopes are fine', () => {
  assert.equal(validateBudgetBoundary([calls('*', 500), calls('tool:browser.navigate', 50)]), null);
});

// ── resource containment stays correct around budget entries ──

test('a budget-only boundary does not restrict resource access', () => {
  assert.ok(isInScope({ scope_boundary: [cost(500_000)] } as unknown as Vaid, 'anything/at/all'));
});

test('a budget entry cannot widen a prefix-restricted boundary', () => {
  const vaid = { scope_boundary: [prefixEntry('orders/'), cost(500_000)] } as unknown as Vaid;
  assert.ok(isInScope(vaid, 'orders/123'));
  assert.ok(!isInScope(vaid, 'something/else'));
});

// ── mintChild integration (mirror of Rust mint::tests budget cases) ──

function fixture(): { service: MintService; audit: InMemoryAudit } {
  const audit = new InMemoryAudit();
  const issuer = ReferenceIssuer.ephemeral(1).assumingNothingRevoked();
  return { service: new MintService(issuer, audit), audit };
}

function holderKeypair(): { seed: Uint8Array; publicKey: Uint8Array } {
  const seed = randomEd25519Seed();
  return { seed, publicKey: ed25519PublicKey(seed) };
}

function parentDocWithEntries(tenant: string, scope: ScopeBoundaryEntry[], caps: string[]): Vaid {
  return ReferenceIssuer.ephemeral(1).issueVaidWithLineage({
    agentClass: 'parent',
    version: '1.0.0',
    tenantId: tenant,
    parentVaid: null,
    scopeBoundary: scope,
    capabilitySet: caps,
  });
}

function makePop(
  seed: VaidSeed,
  registeredKey: Uint8Array,
  signingSeed: Uint8Array,
  nonce: string,
): MintPop {
  const issuedAt = utcWholeSecondRfc3339();
  const payload = buildMintPopPayload(seed, { publicKeyDer: registeredKey, nonce, issuedAt });
  return { nonce, issuedAt, signature: signPayload(payload, signingSeed) };
}

function signedChildWithEntries(
  parent: Vaid,
  scope: ScopeBoundaryEntry[],
  caps: string[],
  nonce: string,
): MintVaidRequest {
  const holder = holderKeypair();
  const seed: VaidSeed = {
    agentClass: 'child',
    version: '1.0.0',
    tenantId: parent.tenant_id,
    parentVaid: parent.vaid_id,
    scopeBoundary: scope,
    capabilitySet: caps,
    publicKeyDer: holder.publicKey,
  };
  return { seed, pop: makePop(seed, holder.publicKey, holder.seed, nonce) };
}

test('mintChild: a child narrower-budget than its parent mints', async () => {
  const { service } = fixture();
  const parent = parentDocWithEntries('aifactory', [prefixEntry('data.aifactory'), cost(500_000)], [
    'read',
  ]);
  const request = signedChildWithEntries(
    parent,
    [prefixEntry('data.aifactory.sub'), cost(100_000)],
    ['read'],
    'budget-ok',
  );
  const { vaid } = await service.mintChild(request, parent);
  assert.equal(vaid.parent_vaid, parent.vaid_id);
});

test('mintChild: a child wider-budget than its parent is denied', async () => {
  const { service, audit } = fixture();
  const parent = parentDocWithEntries('aifactory', [prefixEntry('data.aifactory'), cost(500_000)], [
    'read',
  ]);
  const request = signedChildWithEntries(
    parent,
    [prefixEntry('data.aifactory.sub'), cost(500_001)],
    ['read'],
    'budget-wide',
  );
  await assert.rejects(
    service.mintChild(request, parent),
    (error: Error) => error instanceof UnauthorizedError && /budget caveat/.test(error.message),
  );
  assert.equal(audit.isEmpty(), true);
});

test('mintChild: a child omitting a parent budget caveat is denied', async () => {
  const { service, audit } = fixture();
  const parent = parentDocWithEntries('aifactory', [prefixEntry('data.aifactory'), cost(500_000)], [
    'read',
  ]);
  const request = signedChildWithEntries(
    parent,
    [prefixEntry('data.aifactory.sub')],
    ['read'],
    'budget-omit',
  );
  await assert.rejects(
    service.mintChild(request, parent),
    (error: Error) => error instanceof UnauthorizedError && /budget caveat/.test(error.message),
  );
  assert.equal(audit.isEmpty(), true);
});

test('mintChild: fan-out — two children each at the parents exact budget both mint', async () => {
  const { service } = fixture();
  const parent = parentDocWithEntries('aifactory', [prefixEntry('data.aifactory'), cost(500_000)], [
    'read',
  ]);
  const reqA = signedChildWithEntries(
    parent,
    [prefixEntry('data.aifactory.sub'), cost(500_000)],
    ['read'],
    'fan-a',
  );
  const reqB = signedChildWithEntries(
    parent,
    [prefixEntry('data.aifactory.sub'), cost(500_000)],
    ['read'],
    'fan-b',
  );
  await service.mintChild(reqA, parent);
  await service.mintChild(reqB, parent);
});

test('mintChild: inheritParentBudgets helper produces a mintable child', async () => {
  const { service } = fixture();
  const parent = parentDocWithEntries('aifactory', [prefixEntry('data.aifactory'), cost(500_000)], [
    'read',
  ]);
  const childScope = [prefixEntry('data.aifactory.sub'), ...inheritParentBudgets(parent.scope_boundary)];
  const request = signedChildWithEntries(parent, childScope, ['read'], 'inherit-ok');
  const { vaid } = await service.mintChild(request, parent);
  assert.equal(vaid.parent_vaid, parent.vaid_id);
});

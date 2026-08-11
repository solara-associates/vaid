/**
 * The mint's own output must satisfy the spec the mint publishes (E.6).
 *
 * **The defect this exists to catch (BACKLOG B8).** The Rust issuer stored
 * `Utc::now()` unmodified and emitted `2026-08-11T08:04:18.165623Z` — RFC 3339,
 * and not the whole-second `Z` profile `docs/spec/encoding.md` E.6 requires of
 * every timestamp inside signed bytes.
 *
 * TypeScript was **not** affected: it routes through `utcWholeSecondRfc3339`, so
 * the profile is written out at the point the timestamp becomes a string. This
 * test exists anyway, for the reason the roundtrip gate gives for testing the
 * implementation that happened to be right: *that* is the one that silently
 * regresses, because nobody is watching it. It is also the implementation whose
 * platform default is wrong — `Date.prototype.toISOString()` emits `.000Z` — so
 * the conforming behaviour here rests entirely on one helper being called.
 *
 * **Why the existing suite could not see the Rust defect.** Every test that
 * touched a minted document minted it and then verified it, which is
 * self-consistent by construction. Conformance to a profile is not a property any
 * round-trip can reveal; it has to be asserted against the document directly.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { hasConformingTimestamps } from '../src/document.js';
import { InMemoryAudit } from '../src/audit.js';
import { MintService } from '../src/mint.js';
import { ReferenceIssuer } from '../src/issuer.js';

/**
 * The E.6 shape, spelled out rather than imported, so this test does not agree
 * with the implementation merely by sharing its definition of the answer.
 */
const E6 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

async function mintOne() {
  const issuer = await ReferenceIssuer.ephemeral(24, 'vaid.example');
  const mint = new MintService(issuer, new InMemoryAudit());
  const { vaid } = await mint.mintRoot({
    seed: {
      agentClass: 'conformance',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: ['data.acme'],
      capabilitySet: ['read'],
    },
  });
  return vaid;
}

test('a freshly minted document carries whole-second Z timestamps', async () => {
  const vaid = await mintOne();
  for (const field of ['issued_at', 'expires_at'] as const) {
    const value = vaid[field];
    assert.ok(
      E6.test(value),
      `the mint emitted ${field}=${JSON.stringify(value)}, which is not the whole-second ` +
        "`Z` profile E.6 requires of every timestamp inside signed bytes — the mint's " +
        "OWN output failing the mint's OWN spec (BACKLOG B8)",
    );
  }
});

test('the predicate agrees with the bytes', async () => {
  // Guards against the predicate and the serialization drifting apart: it would be
  // entirely possible to satisfy one and not the other.
  assert.ok(hasConformingTimestamps(await mintOne()));
});

test('the check rejects the form this defect shipped', () => {
  // THE CONTROL. The pattern must reject the form Rust actually shipped, otherwise
  // the test above passes for a check that accepts everything.
  assert.ok(E6.test('2026-08-11T08:04:18Z'));
  assert.ok(!E6.test('2026-08-11T08:04:18.165623Z'), 'the sub-second form B8 shipped');
  assert.ok(!E6.test('2026-08-11T08:04:18+00:00'), 'numeric offset is not E.6');
  assert.ok(
    !E6.test(new Date('2026-08-11T08:04:18Z').toISOString()),
    "toISOString() emits .000Z — the platform default is non-conforming, which is why " +
      'the helper exists',
  );
  assert.ok(!E6.test('not-a-timestamp'), 'garbage is not E.6');
});

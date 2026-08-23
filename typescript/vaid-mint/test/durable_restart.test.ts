/**
 * **The test is a restart, not a 200** — spec `docs/spec/revocation.md` R.4.6.
 *
 * Every other revocation test in this package writes and reads back inside one
 * process. `clearLineage()` *models* a restart; it does not perform one, and a
 * model of a restart cannot catch a store that silently fails to persist. This
 * file spawns real child processes (`durable_restart_phases.js`). Nothing crosses
 * between them except bytes on disk: the kernel seed, the lineage map, and the
 * revoked set.
 *
 * Mirror of `crates/vaid-mint/tests/durable_restart.rs` and
 * `python/vaid-mint/tests/test_durable_restart.py` — same phases, same
 * observations, same two mutations. There is deliberately no shared vector:
 * revocation is outside the conformance surface (R.1), and the languages agree by
 * construction rather than by a frozen artifact.
 *
 * What durability actually has to be, and why one store is not enough:
 *
 * | Persisted | Child credential (B) | Revoked root (C) |
 * |---|---|---|
 * | both (honest) | verifies | refused |
 * | lineage only | verifies | **verifies — the revocation is gone** |
 * | revoked set only | **Unavailable — outage** | refused |
 *
 * Half-done in one direction is a security hole and half-done in the other is an
 * outage that hits *every delegated credential and no root one*, at restart
 * rather than at deploy. Both are asserted positively against real processes —
 * not as "the test goes red", which proves only that an assertion exists.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { issuerFor, mint, type Observations } from './durable_restart_phases.js';

/** The compiled sibling module, run as its own process. */
const PHASES = fileURLToPath(new URL('./durable_restart_phases.js', import.meta.url));

function spawnPhase(phase: string, dir: string, breakMode = ''): string {
  return execFileSync(process.execPath, [PHASES, '--phase', phase, dir, breakMode], {
    encoding: 'utf8',
  });
}

function observationsFrom(stdout: string): Observations {
  const line = stdout.split('\n').find((l) => l.startsWith('OBSERVATIONS '));
  assert.ok(line, `no OBSERVATIONS line in child output:\n${stdout}`);
  return JSON.parse(line.slice('OBSERVATIONS '.length)) as Observations;
}

function stateDir(): string {
  return mkdtempSync(join(tmpdir(), 'vaid-restart-'));
}

function restartCycle(dir: string, mintBreak = '', verifyBreak = ''): Observations {
  spawnPhase('mint', dir, mintBreak);
  return observationsFrom(spawnPhase('verify', dir, verifyBreak));
}

const HONEST: Observations = {
  childAuthentic: true,
  childStatus: 'not_revoked',
  childVerifies: true,
  revokedRootStatus: 'revoked',
  revokedRootVerifies: false,
};

test('THE TEST: both stores durable survive a real process restart', () => {
  const dir = stateDir();
  try {
    assert.deepEqual(
      restartCycle(dir),
      HONEST,
      'with both halves durable, a restart must change nothing: the child’s ancestry ' +
        'still resolves through the persisted lineage store, and the revocation recorded ' +
        'before the restart is still in force',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('NON-VACUITY 1: lineage not persisted breaks every child and no root', () => {
  // The outage half. Every child credential goes Unavailable; every root keeps
  // working, because a root is trivially complete under R.4.2 and never touches
  // the resolver. Authenticity still passes, which is the assertion that retires
  // the "it must be a signing or clock problem" diagnosis.
  //
  // This is also the proof that the harness performs a REAL restart: it can only
  // pass if the in-memory lineage store phase 2 builds is empty, and it can only
  // be empty if phase 2 did not inherit phase 1's memory.
  const dir = stateDir();
  try {
    assert.deepEqual(
      restartCycle(dir, '', 'lineage'),
      {
        childAuthentic: true, // not a signature problem, not a clock problem
        childStatus: 'unavailable',
        childVerifies: false,
        revokedRootStatus: 'revoked', // a root needs no resolution
        revokedRootVerifies: false,
      },
      'a durable revoked set with an in-memory resolver must fail closed for every child ' +
        'and leave every root untouched — total for delegated credentials, invisible for ' +
        'root ones',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('NON-VACUITY 2: a revoked set that vouches when absent resurrects a revoked VAID', () => {
  // The security half, and the reason `assumeNothingRevoked` must never be the
  // shape a durable store copies: the revocation recorded before the restart is
  // gone, and the revoked credential verifies clean with no indication anything is
  // wrong.
  const dir = stateDir();
  try {
    spawnPhase('mint', dir);
    unlinkSync(join(dir, 'revoked.json'));
    assert.deepEqual(
      observationsFrom(spawnPhase('verify', dir, 'revocation-vouches-when-absent')),
      {
        childAuthentic: true,
        childStatus: 'not_revoked',
        childVerifies: true,
        // The revocation is simply gone, and nothing says so.
        revokedRootStatus: 'not_revoked',
        revokedRootVerifies: true,
      },
      'a store that vouches when its state is absent silently un-revokes everything ' +
        'revoked before the restart — R.4.6 exists to forbid exactly this, and an honest ' +
        'store answers Unavailable instead',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CONTROL: an honest store reports an absent revoked set as Unavailable', () => {
  // The control for the mutation above — the two runs differ in nothing but the
  // store's answer to a missing file.
  const dir = stateDir();
  try {
    spawnPhase('mint', dir);
    unlinkSync(join(dir, 'revoked.json'));
    const obs = observationsFrom(spawnPhase('verify', dir));
    assert.equal(obs.revokedRootStatus, 'unavailable');
    assert.equal(obs.revokedRootVerifies, false);
    assert.equal(obs.childStatus, 'unavailable');
    assert.ok(obs.childAuthentic, 'still authentic — only standing failed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the paired backend records mints into the INJECTED lineage store', () => {
  // Without a write half (`LineageStore.record`) a durable resolver would be
  // injectable and permanently empty, which is the failure above with extra steps.
  const dir = stateDir();
  try {
    const issuer = issuerFor(dir, '');
    const root = mint(issuer, 'root', null);
    const child = mint(issuer, 'child', root.vaid_id);

    const recorded = JSON.parse(readFileSync(join(dir, 'lineage.json'), 'utf8')) as Record<
      string,
      string | null
    >;
    assert.equal(recorded[root.vaid_id], null, 'a root must be recorded as a KNOWN root');
    assert.equal(recorded[child.vaid_id], root.vaid_id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

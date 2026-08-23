/**
 * The phases of the durable-restart proof, in a module of their own so the
 * restart test can `node` this file as a **separate process** (spec
 * `docs/spec/revocation.md` R.4.6).
 *
 * Not named `*.test.ts`: the package's test glob is `test-dist/test/*.test.js`,
 * and this file is a child entry point driven by `durable_restart.test.ts`, not a
 * suite of its own.
 *
 * `FileRevocationList` and `FileLineageStore` below are **test doubles**: JSON
 * files, no locking, no integrity, no concurrency story. Durable hash-chained
 * revocation is deliberately not in the open package. They exist to prove the
 * *seam* can carry a durable implementation across a restart, which is the only
 * property they demonstrate.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  InMemoryLineageStore,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  ReferenceIssuer,
  RevocationBackend,
  RevocationStatus,
  verifyVaidAuthenticity,
  type LineageStore,
  type ParentResolution,
  type RevocationCheck,
  type Vaid,
  type VaidId,
} from '../src/index.js';

/**
 * A fixed 32-byte kernel seed, persisted with the state so the restarted issuer
 * signs and verifies with the same key. Without it nothing would verify after the
 * restart for a reason that has nothing to do with revocation, and the mutation
 * runs would pass for the wrong reason.
 */
export const SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));

/**
 * File-backed revoked set. **A missing file is `Unavailable`, never an empty
 * vouching set** — that distinction is the whole of R.4.6, and getting it wrong is
 * what mutation two re-creates on purpose.
 */
export class FileRevocationList implements RevocationCheck {
  readonly #path: string;
  readonly #vouchWhenAbsent: boolean;

  constructor(dir: string, vouchWhenAbsent = false) {
    this.#path = join(dir, 'revoked.json');
    this.#vouchWhenAbsent = vouchWhenAbsent;
  }

  #load(): VaidId[] | null {
    try {
      return JSON.parse(readFileSync(this.#path, 'utf8')) as VaidId[];
    } catch {
      return null;
    }
  }

  revoke(vaidId: VaidId): void {
    const ids = this.#load() ?? [];
    ids.push(vaidId);
    writeFileSync(this.#path, JSON.stringify(ids));
  }

  checkLineage(lineage: readonly VaidId[]): RevocationStatus {
    const revoked = this.#load();
    if (revoked === null) {
      // No file: this store has never been populated in this deployment. It
      // cannot vouch for anything and says so (R.4.6).
      return this.#vouchWhenAbsent ? RevocationStatus.NotRevoked : RevocationStatus.Unavailable;
    }
    return lineage.some((id) => revoked.includes(id))
      ? RevocationStatus.Revoked
      : RevocationStatus.NotRevoked;
  }
}

/**
 * File-backed lineage store — the half that had no injection point before this
 * change, and therefore the half a self-hoster could not make durable at all.
 *
 * Records roots as `null`. A store that omitted roots would answer *unknown* for
 * every root and turn the entire deployment `Unavailable`; recording them is what
 * keeps *root* distinguishable from *unknown* (R.4.2).
 */
export class FileLineageStore implements LineageStore {
  readonly #path: string;

  constructor(dir: string) {
    this.#path = join(dir, 'lineage.json');
  }

  #load(): Record<string, VaidId | null> | null {
    try {
      return JSON.parse(readFileSync(this.#path, 'utf8')) as Record<string, VaidId | null>;
    } catch {
      return null;
    }
  }

  record(vaidId: VaidId, parent: VaidId | null): void {
    const entries = this.#load() ?? {};
    entries[vaidId] = parent;
    writeFileSync(this.#path, JSON.stringify(entries));
  }

  resolveParent(vaidId: VaidId): ParentResolution {
    const entries = this.#load();
    if (entries === null || !(vaidId in entries)) {
      // Nothing is known, so nothing is a root. *unknown* (→ `Unavailable`) is the
      // only honest answer; *root* here would be the exact masquerade R.4.2 exists
      // to forbid.
      return parentResolutionUnknown();
    }
    const parent = entries[vaidId] ?? null;
    return parent === null ? parentResolutionRoot() : parentResolutionOf(parent);
  }
}

export function issuerFor(dir: string, breakMode: string): ReferenceIssuer {
  const check = new FileRevocationList(dir, breakMode === 'revocation-vouches-when-absent');
  // BREAK "lineage": the deployment persisted the revoked set and left the
  // resolver in memory — the half-configuration this seam exists to make
  // unreachable by omission. Reached here only by naming it.
  const lineage: LineageStore =
    breakMode === 'lineage' ? new InMemoryLineageStore() : new FileLineageStore(dir);
  return ReferenceIssuer.fromSeed(SEED, 24, 'vaid.example').withRevocationBackend(
    new RevocationBackend(check, lineage),
  );
}

export function mint(issuer: ReferenceIssuer, agentClass: string, parent: VaidId | null): Vaid {
  return issuer.issueVaidWithLineage({
    agentClass,
    version: '1.0.0',
    tenantId: 'restart-tenant',
    parentVaid: parent,
    scopeBoundary: [],
    capabilitySet: [],
  });
}

/**
 * PHASE 1 — mint into the durable stores, revoke one, then exit. Everything this
 * process learned is now either on disk or gone.
 */
export function phaseMint(dir: string, breakMode: string): void {
  mkdirSync(dir, { recursive: true });
  const issuer = issuerFor(dir, breakMode);
  const rootA = mint(issuer, 'root-a', null);
  const childB = mint(issuer, 'child-b', rootA.vaid_id);
  const rootC = mint(issuer, 'root-c', null);

  // Revoke through the durable store, which is what a real deployment does —
  // `ReferenceIssuer.revoke` writes to the *built-in* store, which is not the one
  // consulted once a backend is injected.
  new FileRevocationList(dir).revoke(rootC.vaid_id);

  for (const [name, vaid] of [
    ['root_a', rootA],
    ['child_b', childB],
    ['root_c', rootC],
  ] as const) {
    writeFileSync(join(dir, `${name}.json`), JSON.stringify(vaid));
  }
}

export interface Observations {
  /**
   * Reported alongside the rest deliberately: the misdiagnosis this failure
   * invites is "a signing or clock problem", and the only way to retire that guess
   * is to show authenticity passing while standing fails.
   */
  childAuthentic: boolean;
  childStatus: string;
  childVerifies: boolean;
  revokedRootStatus: string;
  revokedRootVerifies: boolean;
}

/**
 * PHASE 2 — a genuinely new process. Rebuild the issuer from the seed and the
 * stores from the files, and report what the restarted deployment believes.
 */
export function phaseVerify(dir: string, breakMode: string): Observations {
  const issuer = issuerFor(dir, breakMode);
  const load = (name: string): Vaid =>
    JSON.parse(readFileSync(join(dir, `${name}.json`), 'utf8')) as Vaid;
  const childB = load('child_b');
  const rootC = load('root_c');
  return {
    childAuthentic: verifyVaidAuthenticity(issuer.kernelPublicKey(), childB),
    childStatus: issuer.revocationStatus(childB),
    childVerifies: issuer.verifyVaid(childB),
    revokedRootStatus: issuer.revocationStatus(rootC),
    revokedRootVerifies: issuer.verifyVaid(rootC),
  };
}

// Child entry point: `node durable_restart_phases.js --phase <phase> <dir> [break]`.
//
// The `--phase` sentinel is required, so importing this module from the test file
// (which it does, for the helpers) cannot be mistaken for an invocation. `node
// --test` passes file paths in argv, and a bare positional dispatch would read one
// of them as a phase name.
const argv = process.argv.slice(2);
if (argv[0] === '--phase') {
  const [, phase, dir, breakMode = ''] = argv;
  if (phase === 'mint') {
    phaseMint(dir!, breakMode);
  } else if (phase === 'verify') {
    console.log(`OBSERVATIONS ${JSON.stringify(phaseVerify(dir!, breakMode))}`);
  } else {
    throw new Error(`unknown phase ${phase}`);
  }
}

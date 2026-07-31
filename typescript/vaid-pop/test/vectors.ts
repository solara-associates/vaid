/**
 * Vector loading for the test suite.
 *
 * The tests read the vendored copies from `vectors/` — the same bytes shipped in
 * the published tarball and the same bytes CI `cmp`s against the Rust and Python
 * copies. Nothing in the suite may reconstruct a vector's contents in code: a
 * test that builds its own expectation proves only that the code agrees with
 * itself.
 */

import { readFileSync } from 'node:fs';

/** The frozen-vector fields the suites read. */
export interface FrozenVector {
  digest_sha256_hex: string;
  ed25519: {
    private_key_seed_hex?: string;
    kernel_private_key_seed_hex?: string;
    public_key_hex?: string;
    kernel_public_key_hex?: string;
    signature_hex: string;
  };
  input: Record<string, unknown>;
  assurance_tier_strings?: string[];
}

/** Load a vendored vector by file name, from the package's `vectors/` directory. */
export function loadFrozenVector(name: string): FrozenVector {
  return JSON.parse(
    readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'),
  ) as FrozenVector;
}

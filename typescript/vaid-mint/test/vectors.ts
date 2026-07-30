/**
 * Vector loading for the mint test suite.
 *
 * The tests read the vendored copy from `vectors/` — the same bytes shipped in
 * the published tarball and the same bytes CI `cmp`s against the Rust and Python
 * copies. Nothing in the suite may reconstruct the vector's contents in code: a
 * test that builds its own expectation proves only that the code agrees with
 * itself.
 */

import { readFileSync } from 'node:fs';

import type { MintVector } from '../src/conformance.js';

/** The frozen mint vector, read from the package's `vectors/` directory. */
export function loadMintVector(): MintVector {
  return JSON.parse(
    readFileSync(new URL('../../vectors/mint_v1.json', import.meta.url), 'utf8'),
  ) as MintVector;
}

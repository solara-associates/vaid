/**
 * The vendored trust anchor must be byte-identical to `docs/kernel-keys.json`,
 * and every key in it must hash to the thumbprint it is filed under.
 *
 * The package ships a copy of the anchor so that `vaid verify` works with the
 * network off — which is the whole proposition. The cost of that copy is that it
 * can go stale, and a stale trust anchor does not degrade verification: it makes
 * a verifier accept documents signed by whoever holds the key it still lists, and
 * reject the real issuer after a rotation. So the copy is checked in CI rather
 * than trusted.
 *
 * The second check is the same one the site's `check-kernel-keys-drift.mjs` runs,
 * deliberately duplicated rather than shared: this one must hold for the npm
 * tarball, which is built from this directory and never sees the site's scripts.
 *
 * Run: node scripts/check-anchor.mjs
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDORED = join(HERE, '..', 'trust-anchor.json');
const SOURCE = join(HERE, '..', '..', 'docs', 'kernel-keys.json');

const PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

function fail(msg) {
  console.error(`\n✗ VAID SKILL ANCHOR CHECK FAILED\n  ${msg}\n`);
  console.error('  A wrong anchor here makes `vaid verify` accept documents signed by');
  console.error('  somebody else, and reject the real issuer. Failing closed.\n');
  process.exit(1);
}

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const b64u = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

let vendored;
let source;
try {
  vendored = readFileSync(VENDORED);
} catch (e) {
  fail(`cannot read the vendored anchor: ${e.message}`);
}
try {
  source = readFileSync(SOURCE);
} catch (e) {
  fail(`cannot read the source of truth ${SOURCE}: ${e.message}`);
}

if (sha256(vendored) !== sha256(source)) {
  fail(
    `skill/trust-anchor.json has drifted from docs/kernel-keys.json.\n` +
      `    vendored: ${sha256(vendored)}\n` +
      `    source:   ${sha256(source)}\n` +
      `    Re-vendor with:  cp docs/kernel-keys.json skill/trust-anchor.json`,
  );
}

let doc;
try {
  doc = JSON.parse(vendored.toString('utf8'));
} catch (e) {
  fail(`the vendored anchor is not parseable JSON: ${e.message}`);
}

const keys = doc.keys;
if (!keys || typeof keys !== 'object' || Object.keys(keys).length === 0) {
  fail('no "keys" map, or it is empty — a trust anchor with no keys is not a trust anchor');
}

let n = 0;
for (const [claimed, jwk] of Object.entries(keys)) {
  if (!claimed.startsWith(PREFIX)) fail(`${claimed} is not an RFC 9278 sha-256 thumbprint URI`);
  if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519' || typeof jwk?.x !== 'string') {
    fail(`${claimed} is not an Ed25519 OKP JWK`);
  }
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  const actual = PREFIX + b64u(createHash('sha256').update(canonical).digest());
  if (actual !== claimed) {
    fail(`a key does NOT hash to the thumbprint it is filed under.\n    filed under: ${claimed}\n    recomputed:  ${actual}`);
  }
  n += 1;
}

console.log(`✓ skill/trust-anchor.json is byte-identical to docs/kernel-keys.json (sha256 ${sha256(vendored).slice(0, 16)}…)`);
console.log(`✓ ${n} published key(s) recomputed to the thumbprint they are filed under`);

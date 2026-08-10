/**
 * On-disk state for the CLI: the local issuer key, the keys this machine has
 * chosen to trust, and the local revocation list.
 *
 * Everything lives under `~/.vaid` (override with `VAID_HOME`) so that an agent
 * running in a repo never writes secrets into the repo. `issuer.json` holds an
 * Ed25519 **private** seed and is created `0600`.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function vaidHome() {
  return process.env.VAID_HOME || join(homedir(), '.vaid');
}

function pathFor(name) {
  return join(vaidHome(), name);
}

function ensureHome() {
  const dir = vaidHome();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function readJson(name, fallback) {
  const p = pathFor(name);
  if (!existsSync(p)) return fallback;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch (e) {
    throw new Error(`${p} is not readable JSON: ${e.message}`);
  }
}

function writeJson(name, value, mode = 0o600) {
  ensureHome();
  const p = pathFor(name);
  writeFileSync(p, `${JSON.stringify(value, null, 2)}\n`, { mode });
  chmodSync(p, mode);
  return p;
}

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

/**
 * Load the persistent local issuer seed, creating one on first use.
 *
 * Persistent rather than ephemeral because an ephemeral kernel key makes every
 * minted VAID unverifiable the moment the process exits — the recipient would
 * have to be handed a key that no longer exists anywhere. A stable local issuer
 * is what makes "send this to someone" mean anything for a self-hosted mint.
 */
export function loadIssuerSeed({ create = true } = {}) {
  const existing = readJson('issuer.json', null);
  if (existing) {
    return {
      seed: unb64u(existing.seed),
      trustDomain: existing.trust_domain,
      created: false,
      path: pathFor('issuer.json'),
    };
  }
  if (!create) return null;
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const trustDomain = 'vaid.example';
  const path = writeJson('issuer.json', {
    $comment:
      'PRIVATE KEY. This is the Ed25519 seed of a local VAID kernel signing key. Anyone holding it can mint VAIDs indistinguishable from yours. Do not commit it, do not paste it, do not put it in a container image.',
    seed: b64u(seed),
    trust_domain: trustDomain,
  });
  return { seed, trustDomain, created: true, path };
}

/**
 * Keep the holder seed a delegated child registered at mint time.
 *
 * A delegated VAID is BYO-key: the document commits to a `public_key_der` whose
 * private half is what lets the holder authenticate requests. Discarding that
 * half leaves a credential that verifies and cannot be used, which is a
 * confusing thing to hand somebody.
 */
export function saveHolderSeed(vaidId, seed) {
  ensureHome();
  const dir = join(vaidHome(), 'holders');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = join(dir, `${vaidId}.json`);
  writeFileSync(
    p,
    `${JSON.stringify(
      {
        $comment: 'PRIVATE KEY. The holder seed this VAID registered at mint time. Do not commit or paste it.',
        vaid_id: vaidId,
        seed: b64u(seed),
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  chmodSync(p, 0o600);
  return p;
}

/** Keys this machine accepts, beyond the vendored published anchor. */
export function loadTrustedKeys() {
  return readJson('trusted-keys.json', { keys: {} });
}

export function saveTrustedKeys(doc) {
  return writeJson('trusted-keys.json', doc, 0o644);
}

/**
 * The local revocation list.
 *
 * Read `docs/revocation.md` before giving this any weight: it is a file on one
 * machine that no third party can see, so it changes what *this* CLI reports and
 * nothing else in the world. It is not a published revocation list and does not
 * become one.
 */
export function loadRevoked() {
  return readJson('revoked.json', { $comment: 'LOCAL ONLY. No third party consults this file.', revoked: {} });
}

export function saveRevoked(doc) {
  return writeJson('revoked.json', doc, 0o644);
}

export { b64u, unb64u, pathFor };

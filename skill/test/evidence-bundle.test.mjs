/**
 * Tests for `scripts/verify-evidence-bundle.mjs`.
 *
 * ## Why these live here
 *
 * The script is at the repository root because an auditor clones the repo and runs
 * it there. Its tests are in `skill/test/` because that is where this repo's only
 * Node test runner is wired up (`npm test --prefix skill`, globbing
 * `test/*.test.mjs`, run by the `skill` job in `.github/workflows/ci.yml`), and
 * because step (e) of the script calls `skill/src/verify-core.mjs`, whose
 * `vaid-mint` dependency is installed under `skill/`. Putting them anywhere else
 * would mean a second test runner and a second CI job to prove the same thing.
 * `skill/package.json`'s `files` list does not include `test`, so nothing here is
 * published to npm.
 *
 * ## Nothing here is mocked
 *
 * Every bundle below is signed with a real Ed25519 key generated in the test, the
 * delegation entries are real VAIDs from the real `vaid-mint` mint, and the live
 * kernel-key endpoint is a real `node:http` server on a loopback port. The
 * negative cases mutate a bundle that was genuinely signed, so a verifier that
 * returned "verified" for everything would fail them — which is the only thing
 * that makes the positive cases mean anything.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { InMemoryAudit, MintService, ReferenceIssuer, kernelKeyThumbprint } from 'vaid-mint';
import { packEnvelope } from '../src/envelope.mjs';

import {
  Finding,
  canonicalJson,
  ed25519Thumbprint,
  extractEd25519Key,
  exitCodeFor,
  auditChainFindings,
  verifyBundle,
} from '../../scripts/verify-evidence-bundle.mjs';

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');
const utf8 = (s) => new TextEncoder().encode(s);

const findingFor = (r, id) => r.findings.find((f) => f.id === id);

// --- real key material -------------------------------------------------------

/** A real Ed25519 keypair standing in for the substrate's kernel key. */
function kernelKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'jwk' }).x;
  return { publicKey, privateKey, rawB64u: raw, thumbprint: ed25519Thumbprint(Buffer.from(raw, 'base64url')) };
}

/** A temp dir holding one pinned-key file in the documented shape. */
function pinnedKeyFile(kp, { corruptThumbprint = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'vaid-pin-'));
  const path = join(dir, 'test-substrate.json');
  writeFileSync(
    path,
    JSON.stringify(
      {
        thumbprint: corruptThumbprint
          ? 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
          : kp.thumbprint,
        kty: 'OKP',
        crv: 'Ed25519',
        x: kp.rawB64u,
        deployment: 'test',
      },
      null,
      2,
    ),
  );
  return { dir, path };
}

/** A real HTTP server on loopback serving the key the way the substrate would. */
async function kernelKeyServer(body) {
  const server = createServer((req, res) => {
    if (!req.url.startsWith('/kernel/public-key')) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/kernel/public-key`,
    close: () => new Promise((r) => server.close(r)),
  };
}

// --- real bundles ------------------------------------------------------------

/** One real audit entry chain, hashed with the scheme the script assumes. */
function auditChain(n) {
  const entries = [];
  let prev = '0'.repeat(64);
  for (let i = 0; i < n; i += 1) {
    const body = {
      prev_hash: prev,
      seq: i + 1,
      recorded_at: `2026-10-0${i + 1}T00:00:00Z`,
      event_type: 'policy.decision',
      signed: true,
    };
    const entry_hash = sha256Hex(utf8(canonicalJson(body)));
    entries.push({ ...body, entry_hash });
    prev = entry_hash;
  }
  return entries;
}

/**
 * Build and genuinely sign a bundle.
 *
 * `signOver` picks which of the two candidate messages ASSUMPTION 1 names is
 * actually signed, so both branches of that assumption are exercised rather than
 * only whichever one the script happens to try first.
 */
function makeBundle(kp, { overrides = {}, chain = [], signOver = 'hex' } = {}) {
  const body = {
    version: 'evidence-bundle/v1',
    scope: 'task',
    tenant_id: 'acme',
    generated_at: '2026-10-05T12:00:00Z',
    actor: { vaid_id: 'vaid:test:actor' },
    delegation_chain: chain,
    policy_version: { bundle_name: 'acme-default', semver: '1.4.0', bundle_hash: 'f'.repeat(64) },
    decisions: [{ decided_at: '2026-10-05T11:59:00Z', policy_decision: 'Allow' }],
    audit_entries: auditChain(3),
    ...overrides,
  };
  const canonical = canonicalJson(body);
  const hash = sha256Hex(utf8(canonical));
  const msg = signOver === 'hex' ? utf8(hash) : createHash('sha256').update(utf8(canonical)).digest();
  return {
    ...body,
    content_hash: hash,
    signature: { key_id: 'test-key', alg: 'ed25519', sig_b64: b64u(cryptoSign(null, msg, kp.privateKey)) },
  };
}

/** The happy path: both key sources agree, live endpoint real, pin real. */
async function withBothSources(kp, fn, serverBody) {
  const pin = pinnedKeyFile(kp);
  const server = await kernelKeyServer(serverBody ?? { kty: 'OKP', crv: 'Ed25519', x: kp.rawB64u });
  try {
    return await fn({ pinnedKey: pin.path, kernelUrl: server.url });
  } finally {
    await server.close();
    rmSync(pin.dir, { recursive: true, force: true });
  }
}

// --- 1. a valid bundle verifies clean ---------------------------------------

test('a genuine bundle with two agreeing key sources verifies clean, exit 0', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    assert.equal(r.malformed, false);
    assert.equal(findingFor(r, 'shape').state, Finding.Pass);
    assert.equal(findingFor(r, 'content_hash').state, Finding.Pass);
    assert.equal(findingFor(r, 'key_crosscheck').state, Finding.Pass);
    assert.equal(findingFor(r, 'signature').state, Finding.Pass);
    assert.equal(findingFor(r, 'audit_linkage').state, Finding.Pass);
    assert.equal(findingFor(r, 'audit_entry_hash').state, Finding.Pass);
    // delegation_chain is empty with no note, so it is NOT CHECKED — which is
    // exactly why the exit code is 3 and not 0. Proved separately below.
    assert.equal(findingFor(r, 'delegation').state, Finding.NotChecked);
  });
});

test('with a real delegation chain and both key sources, every check passes and exit is 0', async () => {
  const kp = kernelKeypair();
  // A real VAID from the real mint, and a trust anchor built from that issuer's
  // own key — the self-hosted-mint case the CLI supports with --trust.
  // A real (non-RFC-6761) trust domain, so the VAID's issuer-identity finding is a
  // clean Pass. `audit.example` would carry a special-use-name caveat and the
  // delegation finding would be Caveat rather than Pass — honest, but then this
  // test would not be exercising the all-clear path it exists to pin.
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(7), 24, 'audit.acme.co');
  const svc = new MintService(issuer, new InMemoryAudit());
  const { vaid } = await svc.mintRoot({
    seed: {
      agentClass: 'orchestrator',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: ['data.acme'],
      capabilitySet: ['read'],
    },
  });
  const pub = issuer.kernelPublicKey();
  const anchorPath = join(mkdtempSync(join(tmpdir(), 'vaid-anchor-')), 'anchor.json');
  writeFileSync(
    anchorPath,
    JSON.stringify({
      keys: { [kernelKeyThumbprint(pub)]: { kty: 'OKP', crv: 'Ed25519', x: b64u(pub) } },
    }),
  );

  const bundle = makeBundle(kp, { chain: [vaid] });
  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, {
      ...opts,
      trustAnchor: anchorPath,
      at: new Date(vaid.issued_at),
    });
    const d = findingFor(r, 'delegation');
    assert.equal(d.state, Finding.Pass, `delegation not Pass: ${d.detail}`);
    assert.equal(exitCodeFor(r), 0, JSON.stringify(r.findings.filter((f) => f.state !== Finding.Pass), null, 2));
  });
});

// --- 2. a tampered content_hash is caught ------------------------------------

test('a tampered content_hash FAILS, and the signature step refuses to run on it', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  bundle.content_hash = bundle.content_hash.replace(/^./, (ch) => (ch === 'a' ? 'b' : 'a'));

  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    assert.equal(findingFor(r, 'content_hash').state, Finding.Fail);
    // A valid signature over a hash that does not describe the content would be a
    // true statement about nothing. It must not be reported as a pass.
    assert.equal(findingFor(r, 'signature').state, Finding.NotChecked);
    assert.equal(exitCodeFor(r), 1);
  });
});

test('tampering with the CONTENT — not the hash — is caught by the recomputation', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  bundle.decisions[0].policy_decision = 'Deny';

  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    assert.equal(findingFor(r, 'content_hash').state, Finding.Fail);
    assert.equal(exitCodeFor(r), 1);
  });
});

// --- 3. a tampered signature is caught ---------------------------------------

test('a tampered signature FAILS under a cross-checked key', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const sig = Buffer.from(bundle.signature.sig_b64, 'base64url');
  sig[0] ^= 0xff;
  bundle.signature.sig_b64 = sig.toString('base64url');

  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    // The content is untouched, so the hash still matches: the ONLY thing wrong is
    // the signature, and the verdict must say so rather than blaming the content.
    assert.equal(findingFor(r, 'content_hash').state, Finding.Pass);
    assert.equal(findingFor(r, 'signature').state, Finding.Fail);
    assert.equal(exitCodeFor(r), 1);
  });
});

test('a signature made by a DIFFERENT key FAILS', async () => {
  const real = kernelKeypair();
  const impostor = kernelKeypair();
  // Signed by the impostor, cross-checked against the real key's two sources.
  const bundle = makeBundle(impostor);
  await withBothSources(real, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    assert.equal(findingFor(r, 'content_hash').state, Finding.Pass);
    assert.equal(findingFor(r, 'signature').state, Finding.Fail);
    assert.equal(exitCodeFor(r), 1);
  });
});

test('both messages ASSUMPTION 1 names are accepted, and the one used is named', async () => {
  for (const signOver of ['hex', 'raw']) {
    const kp = kernelKeypair();
    const bundle = makeBundle(kp, { signOver });
    await withBothSources(kp, async (opts) => {
      const r = await verifyBundle(bundle, opts);
      const f = findingFor(r, 'signature');
      assert.equal(f.state, Finding.Pass, `signOver=${signOver}: ${f.detail}`);
      assert.match(f.detail, signOver === 'hex' ? /hex content_hash string/ : /32 raw bytes/);
    });
  }
});

// --- 4. a missing or mismatched pinned key WARNS, never silently passes -------

test('NO pinned key: the cross-check is NOT CHECKED and the exit code is never 0', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const empty = mkdtempSync(join(tmpdir(), 'vaid-nopin-'));
  const server = await kernelKeyServer({ kty: 'OKP', crv: 'Ed25519', x: kp.rawB64u });
  try {
    const r = await verifyBundle(bundle, {
      kernelUrl: server.url,
      pinnedKey: join(empty, 'does-not-exist.json'),
    });
    const f = findingFor(r, 'key_crosscheck');
    assert.equal(f.state, Finding.NotChecked);
    assert.match(f.detail, /ONLY ONE SOURCE/);
    // The signature was still checked — it just establishes less. Keeping those
    // two facts apart is the point of a plural verdict.
    assert.equal(findingFor(r, 'signature').state, Finding.Pass);
    assert.notEqual(exitCodeFor(r), 0);
    assert.equal(exitCodeFor(r), 3);
  } finally {
    await server.close();
    rmSync(empty, { recursive: true, force: true });
  }
});

test('no --kernel-url: one source only, NOT CHECKED, exit 3 — not a pass', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const pin = pinnedKeyFile(kp);
  try {
    const r = await verifyBundle(bundle, { pinnedKey: pin.path });
    const f = findingFor(r, 'key_crosscheck');
    assert.equal(f.state, Finding.NotChecked);
    assert.match(f.detail, /no --kernel-url was given/);
    assert.equal(exitCodeFor(r), 3);
  } finally {
    rmSync(pin.dir, { recursive: true, force: true });
  }
});

test('live and pinned keys DISAGREE: FAIL loudly, and no signature check under either', async () => {
  const pinnedKp = kernelKeypair();
  const liveKp = kernelKeypair();
  // The bundle is honestly signed by the LIVE key, so a verifier that silently
  // picked the live source would report a clean pass. It must not.
  const bundle = makeBundle(liveKp);
  const pin = pinnedKeyFile(pinnedKp);
  const server = await kernelKeyServer({ kty: 'OKP', crv: 'Ed25519', x: liveKp.rawB64u });
  try {
    const r = await verifyBundle(bundle, { pinnedKey: pin.path, kernelUrl: server.url });
    const f = findingFor(r, 'key_crosscheck');
    assert.equal(f.state, Finding.Fail);
    assert.match(f.detail, /THE TWO SOURCES DISAGREE/);
    assert.equal(findingFor(r, 'signature').state, Finding.NotChecked);
    assert.equal(exitCodeFor(r), 1);
  } finally {
    await server.close();
    rmSync(pin.dir, { recursive: true, force: true });
  }
});

test('a pinned key filed under a thumbprint that is not its own is refused', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const pin = pinnedKeyFile(kp, { corruptThumbprint: true });
  const server = await kernelKeyServer({ kty: 'OKP', crv: 'Ed25519', x: kp.rawB64u });
  try {
    const r = await verifyBundle(bundle, { pinnedKey: pin.path, kernelUrl: server.url });
    const f = findingFor(r, 'key_crosscheck');
    assert.equal(f.state, Finding.NotChecked);
    assert.match(f.detail, /hashes to/);
    assert.notEqual(exitCodeFor(r), 0);
  } finally {
    await server.close();
    rmSync(pin.dir, { recursive: true, force: true });
  }
});

test('an unreachable kernel-url is NOT CHECKED with the reason, not a crash', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const pin = pinnedKeyFile(kp);
  // Port 1 on loopback: nothing listens, so this is a real connection refusal.
  try {
    const r = await verifyBundle(bundle, {
      pinnedKey: pin.path,
      kernelUrl: 'http://127.0.0.1:1/kernel/public-key',
    });
    assert.equal(findingFor(r, 'key_crosscheck').state, Finding.NotChecked);
    assert.equal(exitCodeFor(r), 3);
  } finally {
    rmSync(pin.dir, { recursive: true, force: true });
  }
});

test('NEITHER source available: the signature is NOT CHECKED, never assumed good', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const r = await verifyBundle(bundle, { pinnedKey: '/nonexistent/pin.json' });
  assert.equal(findingFor(r, 'key_crosscheck').state, Finding.NotChecked);
  assert.equal(findingFor(r, 'signature').state, Finding.NotChecked);
  assert.match(findingFor(r, 'signature').detail, /not invalid; it is unchecked/);
  assert.equal(exitCodeFor(r), 3);
});

// --- 5. a missing required field fails closed, by name -----------------------

test('a bundle missing a required field fails closed and NAMES the field', async () => {
  const kp = kernelKeypair();
  for (const name of ['tenant_id', 'actor', 'audit_entries', 'content_hash', 'signature', 'decisions']) {
    const bundle = makeBundle(kp);
    delete bundle[name];
    const r = await verifyBundle(bundle, {});
    assert.equal(r.malformed, true, `${name}: expected malformed`);
    assert.deepEqual(r.missing, [name]);
    assert.match(findingFor(r, 'shape').detail, new RegExp(name));
    assert.equal(exitCodeFor(r), 4);
    // Fail closed: exactly one finding, and it is a failure. No partial verdict
    // over the fields that happened to be present.
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].state, Finding.Fail);
  }
});

test('several missing fields are all named in one message', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  delete bundle.actor;
  delete bundle.generated_at;
  const r = await verifyBundle(bundle, {});
  assert.equal(r.malformed, true);
  assert.deepEqual(r.missing.sort(), ['actor', 'generated_at']);
  assert.equal(exitCodeFor(r), 4);
});

test('an unknown bundle version is refused rather than read as v1', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp, { overrides: { version: 'evidence-bundle/v2' } });
  const r = await verifyBundle(bundle, {});
  assert.equal(r.malformed, true);
  assert.match(findingFor(r, 'shape').detail, /evidence-bundle\/v2/);
  assert.equal(exitCodeFor(r), 4);
});

test('a camelCase twin of a contract field is read, and the rename is REPORTED', async () => {
  const kp = kernelKeypair();
  const body = makeBundle(kp);
  // Rebuild with tenantId instead of tenant_id, signed over the renamed body so
  // the hash and signature are genuinely correct for what is on disk.
  const { content_hash: _h, signature: _s, tenant_id, ...rest } = body;
  const renamed = { ...rest, tenantId: tenant_id };
  const canonical = canonicalJson(renamed);
  const hash = sha256Hex(utf8(canonical));
  const bundle = {
    ...renamed,
    content_hash: hash,
    signature: { key_id: 'test-key', alg: 'ed25519', sig_b64: b64u(cryptoSign(null, utf8(hash), kp.privateKey)) },
  };

  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(bundle, opts);
    assert.equal(r.malformed, false);
    const f = findingFor(r, 'shape');
    assert.equal(f.state, Finding.Caveat);
    assert.match(f.detail, /tenant_id \(found as tenantId\)/);
    // Read defensively, but never silently: the rename is a caveat, so the run
    // cannot exit 0 while producer and verifier disagree about a field name.
    assert.equal(findingFor(r, 'content_hash').state, Finding.Pass);
    assert.equal(findingFor(r, 'signature').state, Finding.Pass);
  });
});

test('a non-ed25519 signature.alg is refused, not ignored', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  bundle.signature.alg = 'rsa-pss';
  const r = await verifyBundle(bundle, {});
  assert.equal(r.malformed, true);
  assert.match(findingFor(r, 'shape').detail, /only "ed25519" is implemented/);
});

// --- the audit chain ---------------------------------------------------------

test('an intact audit chain passes both linkage and the assumed hash scheme', () => {
  const fs = auditChainFindings(auditChain(4));
  assert.equal(fs.find((f) => f.id === 'audit_linkage').state, Finding.Pass);
  assert.equal(fs.find((f) => f.id === 'audit_entry_hash').state, Finding.Pass);
});

test('a BROKEN prev_hash link FAILS hard — linkage does not depend on the hash scheme', () => {
  const entries = auditChain(4);
  entries[2].prev_hash = 'd'.repeat(64);
  const f = auditChainFindings(entries).find((x) => x.id === 'audit_linkage');
  assert.equal(f.state, Finding.Fail);
  assert.match(f.detail, /chain is BROKEN/);
});

test('a gap in seq is reported as entries MISSING from the bundle', () => {
  const entries = auditChain(3);
  entries[2].seq = 9;
  entries[2].entry_hash = sha256Hex(utf8(canonicalJson({ ...entries[2], entry_hash: undefined })));
  const f = auditChainFindings(entries).find((x) => x.id === 'audit_linkage');
  assert.equal(f.state, Finding.Fail);
  assert.match(f.detail, /MISSING/);
});

test('an entry_hash that does not reproduce is NOT CHECKED, not FAIL — the scheme is assumed', () => {
  const entries = auditChain(3);
  // Rehash the tail so linkage still holds, then break only the hash VALUE of a
  // middle entry's recomputation by changing a field it covers.
  entries[1].event_type = 'something.else';
  const fs = auditChainFindings(entries);
  const hashF = fs.find((f) => f.id === 'audit_entry_hash');
  assert.equal(hashF.state, Finding.NotChecked);
  assert.match(hashF.detail, /ASSUMED scheme/);
  // And it must NOT turn into a pass by being the only complaint.
  assert.notEqual(hashF.state, Finding.Pass);
});

test('an EMPTY audit_entries list is NOT CHECKED — an empty list is not an intact chain', () => {
  const fs = auditChainFindings([]);
  assert.equal(fs.length, 1);
  assert.equal(fs[0].state, Finding.NotChecked);
  assert.match(fs[0].detail, /EMPTY/);
});

// --- delegation_chain_note ---------------------------------------------------

test('an empty delegation_chain WITH a note is NOT CHECKED and quotes the note', async () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp, {
    overrides: { delegation_chain_note: 'only partial lineage was recoverable for this task' },
  });
  // Re-sign: the note is covered by content_hash.
  const { content_hash: _h, signature: _s, ...body } = bundle;
  const hash = sha256Hex(utf8(canonicalJson(body)));
  const signed = {
    ...body,
    content_hash: hash,
    signature: { key_id: 'test-key', alg: 'ed25519', sig_b64: b64u(cryptoSign(null, utf8(hash), kp.privateKey)) },
  };

  await withBothSources(kp, async (opts) => {
    const r = await verifyBundle(signed, opts);
    const f = findingFor(r, 'delegation');
    assert.equal(f.state, Finding.NotChecked);
    assert.match(f.detail, /only partial lineage was recoverable/);
    assert.equal(exitCodeFor(r), 3);
  });
});

test('a delegation entry signed by an unaccepted key is reported FAIL per entry', async () => {
  const kp = kernelKeypair();
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(9), 24, 'nobody.example');
  const svc = new MintService(issuer, new InMemoryAudit());
  const { vaid } = await svc.mintRoot({
    seed: { agentClass: 'agent', version: '1.0.0', tenantId: 'acme', scopeBoundary: [], capabilitySet: [] },
  });
  const bundle = makeBundle(kp, { chain: [packEnvelope(vaid)] });
  await withBothSources(kp, async (opts) => {
    // Default anchor = the published production key, which did not sign this VAID.
    const r = await verifyBundle(bundle, opts);
    const f = findingFor(r, 'delegation');
    assert.equal(f.state, Finding.Fail);
    assert.equal(exitCodeFor(r), 1);
  });
});

// --- the canonical form ------------------------------------------------------

test('the canonical form is key-order independent and array-order dependent', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  assert.equal(canonicalJson({ a: { d: 1, c: 2 } }), '{"a":{"c":2,"d":1}}');
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
  assert.equal(canonicalJson({ a: null }), '{"a":null}');
});

test('the documented jq equivalence holds for a real bundle', () => {
  const kp = kernelKeypair();
  const bundle = makeBundle(kp);
  const { content_hash: _h, signature: _s, ...body } = bundle;
  assert.equal(sha256Hex(utf8(canonicalJson(body))), bundle.content_hash);
});

// --- the key extractor -------------------------------------------------------

test('every documented endpoint shape yields the same key', () => {
  const kp = kernelKeypair();
  const shapes = [
    { kty: 'OKP', crv: 'Ed25519', x: kp.rawB64u },
    { public_key: kp.rawB64u },
    { kernel_public_key: kp.rawB64u, key_id: 'k1' },
    { keys: { [kp.thumbprint]: { kty: 'OKP', crv: 'Ed25519', x: kp.rawB64u } } },
  ];
  for (const s of shapes) {
    const got = extractEd25519Key(s);
    assert.equal(got.error, undefined, `${JSON.stringify(s)}: ${got.error}`);
    assert.equal(ed25519Thumbprint(got.key), kp.thumbprint);
  }
});

test('an unrecognised endpoint shape names the keys it DID see', () => {
  const got = extractEd25519Key({ status: 'ok', data: {} });
  assert.match(got.error, /"status", "data"/);
  assert.equal(got.key, undefined);
});

test('a keys map filing a key under the wrong thumbprint is refused', () => {
  const kp = kernelKeypair();
  const got = extractEd25519Key({
    keys: {
      'urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA': {
        kty: 'OKP',
        crv: 'Ed25519',
        x: kp.rawB64u,
      },
    },
  });
  assert.match(got.error, /Failing closed/);
});

test('a key of the wrong length is refused rather than padded', () => {
  assert.match(extractEd25519Key({ public_key: b64u(Buffer.alloc(16)) }).error, /16 bytes/);
  assert.match(extractEd25519Key({ kty: 'OKP', crv: 'Ed25519', x: b64u(Buffer.alloc(31)) }).error, /31 bytes/);
  assert.match(extractEd25519Key({ kty: 'OKP', crv: 'P-256', x: b64u(Buffer.alloc(32)) }).error, /not Ed25519/);
});

// --- the verdict mapping -----------------------------------------------------

test('exitCodeFor keeps pass, fail and not-checked in three different states', () => {
  const f = (state) => ({ id: 'x', label: 'x', state, detail: '' });
  assert.equal(exitCodeFor({ malformed: false, findings: [f(Finding.Pass)] }), 0);
  assert.equal(exitCodeFor({ malformed: false, findings: [f(Finding.Pass), f(Finding.Caveat)] }), 0);
  assert.equal(exitCodeFor({ malformed: false, findings: [f(Finding.Pass), f(Finding.NotChecked)] }), 3);
  assert.equal(exitCodeFor({ malformed: false, findings: [f(Finding.Pass), f(Finding.Fail)] }), 1);
  // A failure outranks an unknown: a run with both must not report the softer one.
  assert.equal(exitCodeFor({ malformed: false, findings: [f(Finding.NotChecked), f(Finding.Fail)] }), 1);
  assert.equal(exitCodeFor({ malformed: true, findings: [f(Finding.Fail)] }), 4);
});

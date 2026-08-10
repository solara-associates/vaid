/**
 * Tests for the verify core.
 *
 * The negative cases are not padding. A verifier that returns "valid" for
 * everything passes every happy-path test ever written against it, so each
 * positive assertion here is paired with the mutation that must break it. If a
 * change makes a `Pass` case pass and a `Fail` case also pass, the suite has
 * stopped testing anything.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { InMemoryAudit, MintService, ReferenceIssuer, kernelKeyThumbprint } from 'vaid-mint';
import { packEnvelope, parseEnvelope, EnvelopeError } from '../src/envelope.mjs';
import { mintAttenuatedChild } from '../src/delegate.mjs';
import { Finding, Headline, loadAnchor, verifyEnvelope } from '../src/verify-core.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

/** A trust anchor built from an issuer's own key — the local-mint case. */
function anchorFor(...issuers) {
  const keys = {};
  for (const i of issuers) {
    const k = i.kernelPublicKey();
    keys[kernelKeyThumbprint(k)] = { kty: 'OKP', crv: 'Ed25519', x: b64u(k) };
  }
  return loadAnchor({ keys });
}

function issuerFromSeed(byte) {
  return ReferenceIssuer.fromSeed(new Uint8Array(32).fill(byte), 24, 'test.example');
}

async function mintRoot(issuer, over = {}) {
  const svc = new MintService(issuer, new InMemoryAudit());
  const { vaid } = await svc.mintRoot({
    seed: {
      agentClass: 'orchestrator',
      version: '1.0.0',
      tenantId: 'acme',
      scopeBoundary: ['data.acme'],
      capabilitySet: ['read', 'write'],
      ...over,
    },
  });
  return vaid;
}

const findingFor = (r, id) => r.findings.find((f) => f.id === id);

// --- the shape of the verdict ------------------------------------------------

test('a genuine, in-date root verifies', async () => {
  const issuer = issuerFromSeed(1);
  const vaid = await mintRoot(issuer);
  const r = verifyEnvelope(packEnvelope(vaid), anchorFor(issuer), new Date(vaid.issued_at));

  assert.equal(findingFor(r, 'key').state, Finding.Pass);
  assert.equal(findingFor(r, 'authenticity').state, Finding.Pass);
  assert.equal(findingFor(r, 'expiry').state, Finding.Pass);
  // `test.example` is a special-use name, so the honest headline carries a caveat
  // rather than a clean VALID. That is the intended result, not a shortcoming.
  assert.equal(findingFor(r, 'issuer').state, Finding.Caveat);
  assert.equal(r.headline, Headline.ValidWithCaveats);
});

test('revocation is always reported, and always as NOT CHECKED', async () => {
  const issuer = issuerFromSeed(1);
  const vaid = await mintRoot(issuer);
  const anchor = anchorFor(issuer);

  for (const [label, input] of [
    ['accepted', packEnvelope(vaid)],
    ['rejected for an unknown key', packEnvelope({ ...vaid, kernel_key_thumbprint: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAA' })],
    ['tampered', packEnvelope({ ...vaid, capability_set: ['admin'] })],
  ]) {
    const r = verifyEnvelope(input, anchor, new Date(vaid.issued_at));
    const rev = findingFor(r, 'revocation');
    assert.ok(rev, `revocation finding missing on a ${label} verdict`);
    assert.equal(rev.state, Finding.NotChecked, `revocation was not NotChecked on a ${label} verdict`);
  }
});

test('a real issuer domain gets no caveat and a clean VALID', async () => {
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(9), 24, 'agents.acme.com');
  const vaid = await mintRoot(issuer);
  const r = verifyEnvelope(packEnvelope(vaid), anchorFor(issuer), new Date(vaid.issued_at));
  assert.equal(findingFor(r, 'issuer').state, Finding.Pass);
  assert.equal(r.headline, Headline.Valid);
});

// --- controls: the mutations that must break it ------------------------------

test('CONTROL — tampering with any signed field is rejected', async () => {
  const issuer = issuerFromSeed(2);
  const vaid = await mintRoot(issuer);
  const anchor = anchorFor(issuer);
  const at = new Date(vaid.issued_at);

  // One case per signed field a forger would actually want to change.
  const mutations = {
    'widened capabilities': { capability_set: ['read', 'write', 'admin'] },
    'widened scope': { scope_boundary: ['data.acme', 'data.everyone'] },
    'a different tenant': { tenant_id: 'victim' },
    'a longer life': { expires_at: '2099-01-01T00:00:00Z' },
    'a different agent class': { agent_class: 'root' },
    'a forged signature': { kernel_signature: new Array(64).fill(0) },
  };

  for (const [what, patch] of Object.entries(mutations)) {
    const r = verifyEnvelope(packEnvelope({ ...vaid, ...patch }), anchor, at);
    assert.equal(r.headline, Headline.Rejected, `${what} was NOT rejected`);
    assert.equal(findingFor(r, 'authenticity').state, Finding.Fail, `${what} did not fail the signature check`);
  }
});

test('CONTROL — a genuine VAID from an issuer not in the anchor is rejected', async () => {
  const mine = issuerFromSeed(3);
  const theirs = issuerFromSeed(4);
  const vaid = await mintRoot(theirs);

  const r = verifyEnvelope(packEnvelope(vaid), anchorFor(mine), new Date(vaid.issued_at));
  assert.equal(r.headline, Headline.Rejected);
  assert.equal(findingFor(r, 'key').state, Finding.Fail);
  // Rejected at the key, before any signature work — the document is perfectly
  // genuine, just not vouched for here.
  assert.equal(findingFor(r, 'authenticity'), undefined);
});

test('CONTROL — a corrupt trust anchor fails closed rather than dropping the bad key', () => {
  const good = { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(7)) };
  const tp = kernelKeyThumbprint(new Uint8Array(32).fill(7));
  assert.throws(
    () => loadAnchor({ keys: { [tp]: good, 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:WRONG': good } }),
    /trust anchor is corrupt/,
  );
});

test('CONTROL — malformed input never reaches a cryptographic verdict', () => {
  const anchor = loadAnchor({
    keys: { [kernelKeyThumbprint(new Uint8Array(32).fill(1))]: { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(1)) } },
  });
  for (const junk of ['', '   ', 'hello', 'vaid1:!!!!', 'vaid1:', '{"nope"', '[]']) {
    const r = verifyEnvelope(junk, anchor);
    assert.equal(r.headline, Headline.Malformed, `${JSON.stringify(junk)} did not come back malformed`);
    assert.equal(r.findings.length, 0);
  }
});

// --- expiry ------------------------------------------------------------------

test('an expired VAID is EXPIRED, not REJECTED', async () => {
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(5), 24, 'agents.acme.com');
  const vaid = await mintRoot(issuer);
  const after = new Date(Date.parse(vaid.expires_at) + 1000);

  const r = verifyEnvelope(packEnvelope(vaid), anchorFor(issuer), after);
  assert.equal(r.headline, Headline.Expired);
  assert.equal(findingFor(r, 'authenticity').state, Finding.Pass, 'an expired VAID is still authentic');
  assert.equal(findingFor(r, 'expiry').state, Finding.Fail);
});

// --- delegation --------------------------------------------------------------

test('a presented chain verifies, and the same leaf alone does not', async () => {
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(6), 24, 'agents.acme.com');
  const svc = new MintService(issuer, new InMemoryAudit());
  const root = await mintRoot(issuer);
  const { vaid: child } = await mintAttenuatedChild(svc, root, {
    agentClass: 'worker',
    version: '1.0.0',
    tenantId: 'acme',
    scopeBoundary: ['data.acme'],
    capabilitySet: ['read'],
  });
  const anchor = anchorFor(issuer);
  const at = new Date(child.issued_at);

  const withChain = verifyEnvelope(packEnvelope(child, [root]), anchor, at);
  assert.equal(findingFor(withChain, 'attenuation').state, Finding.Pass);
  assert.equal(withChain.headline, Headline.Valid);

  // Alone: authentic, but attenuation is unverifiable — which must NOT read as
  // satisfied. This is the distinction the whole findings list exists to keep.
  const alone = verifyEnvelope(packEnvelope(child), anchor, at);
  assert.equal(findingFor(alone, 'authenticity').state, Finding.Pass);
  assert.equal(findingFor(alone, 'attenuation').state, Finding.Caveat);
  assert.match(findingFor(alone, 'attenuation').detail, /UNVERIFIABLE/);
  assert.equal(alone.headline, Headline.ValidWithCaveats);
});

test('CONTROL — an incomplete chain is Fail, never quietly accepted', async () => {
  const issuer = ReferenceIssuer.fromSeed(new Uint8Array(32).fill(8), 24, 'agents.acme.com');
  const svc = new MintService(issuer, new InMemoryAudit());
  const root = await mintRoot(issuer);
  const { vaid: mid } = await mintAttenuatedChild(svc, root, {
    agentClass: 'mid', version: '1.0.0', tenantId: 'acme', scopeBoundary: ['data.acme'], capabilitySet: ['read'],
  });
  const { vaid: leaf } = await mintAttenuatedChild(svc, mid, {
    agentClass: 'leaf', version: '1.0.0', tenantId: 'acme', scopeBoundary: ['data.acme'], capabilitySet: ['read'],
  });

  // The middle document is presented; the root is not, so the chain cannot reach
  // a root and must be Unverifiable rather than "well, what we saw was fine".
  const r = verifyEnvelope(packEnvelope(leaf, [mid]), anchorFor(issuer), new Date(leaf.issued_at));
  assert.equal(findingFor(r, 'attenuation').state, Finding.Fail);
  assert.match(findingFor(r, 'attenuation').detail, /UNVERIFIABLE/);
  assert.equal(r.headline, Headline.Rejected);
});

// --- the real production document -------------------------------------------

test('a real substrate-minted VAID verifies against the published anchor', () => {
  // Not a fixture: a document minted by the deployed production substrate and
  // fetched from GET /operator/vaid, checked against the anchor this package
  // ships. If this breaks, third-party verification of production is broken.
  const vaid = JSON.parse(readFileSync(join(HERE, 'vectors', 'production-vaid.json'), 'utf8'));
  const anchor = loadAnchor(JSON.parse(readFileSync(join(HERE, '..', 'trust-anchor.json'), 'utf8')));

  const atIssue = verifyEnvelope(packEnvelope(vaid), anchor, new Date(vaid.issued_at));
  assert.equal(findingFor(atIssue, 'key').state, Finding.Pass);
  assert.equal(findingFor(atIssue, 'authenticity').state, Finding.Pass);
  assert.equal(findingFor(atIssue, 'expiry').state, Finding.Pass);
  // `substrate.internal` is special-use, so production is honestly reported as
  // signature-verified but issuer-unconfigured.
  assert.equal(findingFor(atIssue, 'issuer').state, Finding.Caveat);
  assert.match(findingFor(atIssue, 'issuer').detail, /special-use/);
  assert.equal(atIssue.headline, Headline.ValidWithCaveats);

  // And the same document today, long past its one-hour life.
  const now = verifyEnvelope(packEnvelope(vaid), anchor, new Date('2099-01-01T00:00:00Z'));
  assert.equal(now.headline, Headline.Expired);

  // CONTROL on the real document too: one flipped signature byte must break it.
  const sig = [...vaid.kernel_signature];
  sig[0] ^= 1;
  const tampered = verifyEnvelope(packEnvelope({ ...vaid, kernel_signature: sig }), anchor, new Date(vaid.issued_at));
  assert.equal(tampered.headline, Headline.Rejected);
});

// --- the envelope ------------------------------------------------------------

test('the envelope round-trips, including a chain', async () => {
  const issuer = issuerFromSeed(1);
  const a = await mintRoot(issuer);
  const b = await mintRoot(issuer);
  const parsed = parseEnvelope(packEnvelope(a, [b]));
  assert.deepEqual(parsed.vaid, a);
  assert.deepEqual(parsed.chain, [b]);
});

test('the envelope survives being reflowed by a mail client', async () => {
  const issuer = issuerFromSeed(1);
  const vaid = await mintRoot(issuer);
  const token = packEnvelope(vaid);
  // Hard-wrapped at 76 columns and re-indented, which is what happens to a long
  // token pasted into an email or a YAML block.
  const mangled = token.replace(/(.{76})/g, '$1\n   ');
  assert.deepEqual(parseEnvelope(mangled).vaid, vaid);
});

test('a bare document is accepted as a rootless presentation', async () => {
  const issuer = issuerFromSeed(1);
  const vaid = await mintRoot(issuer);
  const parsed = parseEnvelope(JSON.stringify(vaid));
  assert.deepEqual(parsed.vaid, vaid);
  assert.equal(parsed.bare, true);
});

test('CONTROL — a future envelope version is refused, not guessed at', () => {
  assert.throws(() => parseEnvelope(JSON.stringify({ v: 2, vaid: {} })), EnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ v: 1 })), EnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ v: 1, vaid: {}, chain: 'nope' })), EnvelopeError);
});

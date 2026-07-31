/**
 * `RequestSigner` behaviour beyond the frozen vectors: identity binding, header
 * shape, body/method/path coverage, and the failure modes.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  fromBase64,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_VAID,
  InvalidVaidError,
  popHeaderRecord,
  PopError,
  PortRequestSigner,
  randomEd25519Seed,
  RequestSigner,
  sha256Hex,
  SigningError,
  toHex,
  verifySignedPayload,
  type RequestAuthPayload,
} from '../src/index.js';
import { ed25519PublicKey, ed25519Sign } from 'vaid-pop';

const VAID_JSON = JSON.stringify({
  vaid_id: '11111111-1111-1111-1111-111111111111',
  tenant_id: 'acme',
});

function signerWithKey(): { signer: RequestSigner; publicKey: Uint8Array } {
  const seed = randomEd25519Seed();
  return { signer: new RequestSigner(VAID_JSON, seed), publicKey: ed25519PublicKey(seed) };
}

test('the four headers are emitted under their wire names', () => {
  const { signer } = signerWithKey();
  const record = popHeaderRecord(signer.signHeaders('POST', '/x'));
  assert.deepEqual(Object.keys(record).sort(), [
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    HEADER_VAID,
  ].sort());
});

test('the vaid header is base64 of the document JSON, verbatim', () => {
  const { signer } = signerWithKey();
  const headers = signer.signHeaders('GET', '/x');
  assert.equal(new TextDecoder().decode(fromBase64(headers.vaid)), VAID_JSON);
});

test('a signed request verifies against the reconstructed payload', () => {
  // What a verifier does: rebuild the payload from the headers plus the request
  // it received, and check the signature. Identity comes from the VAID, not the
  // request, which is why tenantId is not a caller argument.
  const { signer, publicKey } = signerWithKey();
  const body = new TextEncoder().encode('{"hello":"world"}');
  const headers = signer.signHeaders('post', '/vaid/mint?a=1', body);

  const rebuilt: RequestAuthPayload = {
    vaidId: '11111111-1111-1111-1111-111111111111',
    method: 'POST',
    path: '/vaid/mint?a=1',
    bodySha256: sha256Hex(body),
    tenantId: 'acme',
    timestamp: headers.timestamp,
    clientNonce: headers.nonce,
  };
  assert.equal(verifySignedPayload(rebuilt, publicKey, fromBase64(headers.signature)), true);
});

test('the method is upper-cased into the signed payload', () => {
  const { signer } = signerWithKey();
  const options = { now: new Date('2026-06-04T12:00:00Z'), nonce: 'n' };
  assert.equal(
    signer.signHeaders('post', '/x', new Uint8Array(), options).signature,
    signer.signHeaders('POST', '/x', new Uint8Array(), options).signature,
  );
});

test('a different body, method, or path yields a different signature', () => {
  const { signer } = signerWithKey();
  const options = { now: new Date('2026-06-04T12:00:00Z'), nonce: 'n' };
  const base = signer.signHeaders('POST', '/a', new TextEncoder().encode('x'), options).signature;
  assert.notEqual(base, signer.signHeaders('POST', '/b', new TextEncoder().encode('x'), options).signature);
  assert.notEqual(base, signer.signHeaders('PUT', '/a', new TextEncoder().encode('x'), options).signature);
  assert.notEqual(base, signer.signHeaders('POST', '/a', new TextEncoder().encode('y'), options).signature);
});

test('the timestamp is whole-second RFC 3339 Z — the chrono-serde fixed point', () => {
  const { signer } = signerWithKey();
  const headers = signer.signHeaders('GET', '/x', new Uint8Array(), {
    // Deliberately sub-second: it must be truncated, not rounded or carried.
    now: new Date('2026-06-04T12:00:00.987Z'),
    nonce: 'n',
  });
  assert.equal(headers.timestamp, '2026-06-04T12:00:00Z');
  assert.match(headers.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test('nonces are fresh per request by default', () => {
  const { signer } = signerWithKey();
  const a = signer.signHeaders('GET', '/x').nonce;
  const b = signer.signHeaders('GET', '/x').nonce;
  assert.notEqual(a, b);
  assert.match(a, /^[0-9a-f]{32}$/);
});

test('a VAID document missing the snake_case identity fields is rejected', () => {
  // camelCase is the RequestAuthPayload convention, NOT the document convention.
  // A camelCase document is the likeliest mistake, so it must fail loudly.
  assert.throws(
    () => new RequestSigner(JSON.stringify({ vaidId: 'x', tenantId: 'y' }), randomEd25519Seed()),
    InvalidVaidError,
  );
  assert.throws(() => new RequestSigner('not json', randomEd25519Seed()), InvalidVaidError);
});

test('a wrong-length private seed is rejected at construction', () => {
  assert.throws(() => new RequestSigner(VAID_JSON, new Uint8Array(16)), PopError);
});

test('a failing signing port surfaces as SigningError, not as the raw fault', () => {
  const port = {
    async sign(): Promise<Uint8Array> {
      throw new Error('keystore unreachable');
    },
    async publicKey(): Promise<Uint8Array> {
      return new Uint8Array(32);
    },
  };
  return assert.rejects(
    new PortRequestSigner(VAID_JSON, port).signHeaders('GET', '/x'),
    (error: Error) => error instanceof SigningError && /keystore unreachable/.test(error.message),
  );
});

test('a port returning a wrong-length signature is rejected, not emitted', () => {
  const port = {
    async sign(): Promise<Uint8Array> {
      return new Uint8Array(32);
    },
    async publicKey(): Promise<Uint8Array> {
      return new Uint8Array(32);
    },
  };
  return assert.rejects(
    new PortRequestSigner(VAID_JSON, port).signHeaders('GET', '/x'),
    /expected a raw 64-byte Ed25519 signature/,
  );
});

test('the port is handed the 32-byte digest — never the payload, never the key', () => {
  const seed = randomEd25519Seed();
  let seen: Uint8Array | null = null;
  const port = {
    async sign(canonicalBytes: Uint8Array): Promise<Uint8Array> {
      seen = canonicalBytes;
      return ed25519Sign(canonicalBytes, seed);
    },
    async publicKey(): Promise<Uint8Array> {
      return ed25519PublicKey(seed);
    },
  };
  return new PortRequestSigner(VAID_JSON, port).signHeaders('GET', '/x').then((headers) => {
    assert.equal((seen as Uint8Array | null)?.length, 32);
    assert.equal(toHex(fromBase64(headers.signature)).length, 128);
  });
});

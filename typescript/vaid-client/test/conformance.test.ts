/**
 * Canonical PoP + path-with-query conformance gates (TypeScript side of the
 * cross-language firewall).
 *
 * The vendored vectors ship inside the package so a consumer runs these gates
 * against the exact bytes the client was proven against. They assert the
 * `vaid-client` signer reproduces the frozen digest + Ed25519 signature
 * byte-for-byte, through the real `signHeaders` path rather than by calling the
 * primitive directly — a signer that assembled the payload wrongly would still
 * pass a primitive-level test.
 *
 * Mirror of the Rust `crates/vaid-client/tests/conformance.rs` and
 * `pathquery_conformance.rs`, and the Python `test_path_convention.py`.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  fromBase64,
  fromHex,
  PortRequestSigner,
  RequestSigner,
  toHex,
  verifySignedPayload,
  type OperatorSigningPort,
  type RequestAuthPayload,
} from '../src/index.js';
import type { ClientVector } from '../src/conformance.js';

function loadVector(name: string): ClientVector {
  return JSON.parse(
    readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'),
  ) as ClientVector;
}

function vaidJson(v: ClientVector): string {
  return JSON.stringify({ vaid_id: v.input.vaidId, tenant_id: v.input.tenantId });
}

const vectors: Array<[string, ClientVector]> = [
  ['operator_pop_v1', loadVector('operator_pop_v1.json')],
  ['pathquery_v1', loadVector('pathquery_v1.json')],
];

for (const [name, vector] of vectors) {
  const seed = fromHex(vector.ed25519.private_key_seed_hex);

  test(`${name}: reproduces the frozen digest byte-for-byte`, () => {
    const digest = canonicalRequestSigningBytes(vector.input as unknown as RequestAuthPayload);
    assert.equal(
      toHex(digest),
      vector.digest_sha256_hex,
      `TypeScript digest diverged from the frozen ${name} vector — BLOCKER`,
    );
  });

  test(`${name}: the real RequestSigner path reproduces the frozen signature`, () => {
    const signer = new RequestSigner(vaidJson(vector), seed);
    // The vector's bodySha256 is sha256("") — sign the empty body.
    const headers = signer.signHeaders(vector.input.method, vector.input.path, new Uint8Array(), {
      now: new Date(vector.input.timestamp),
      nonce: vector.input.clientNonce,
    });

    assert.equal(headers.timestamp, vector.input.timestamp);
    assert.equal(headers.nonce, vector.input.clientNonce);
    const signature = fromBase64(headers.signature);
    assert.equal(signature.length, 64);
    assert.equal(
      toHex(signature),
      vector.ed25519.signature_hex,
      `TypeScript client header signature diverged from the frozen ${name} vector — BLOCKER`,
    );
  });

  test(`${name}: the OperatorSigningPort path produces the identical signature`, async () => {
    // A port backed by the frozen seed — proves the external-keystore path and
    // the raw-key path canonicalize the same bytes.
    const port: OperatorSigningPort = {
      async sign(canonicalBytes) {
        const { ed25519Sign } = await import('vaid-pop');
        return ed25519Sign(canonicalBytes, seed);
      },
      async publicKey() {
        return ed25519PublicKey(seed);
      },
    };
    const signer = new PortRequestSigner(vaidJson(vector), port);
    const headers = await signer.signHeaders(
      vector.input.method,
      vector.input.path,
      new Uint8Array(),
      { now: new Date(vector.input.timestamp), nonce: vector.input.clientNonce },
    );
    assert.equal(
      toHex(fromBase64(headers.signature)),
      vector.ed25519.signature_hex,
      `OperatorSigningPort path diverged from the frozen ${name} vector — BLOCKER`,
    );
  });

  test(`${name}: the frozen signature verifies under the frozen public key`, () => {
    assert.equal(
      verifySignedPayload(
        vector.input,
        fromHex(vector.ed25519.public_key_hex),
        fromHex(vector.ed25519.signature_hex),
      ),
      true,
    );
  });
}

test('the pathquery vector really does pin a path WITH a query string', () => {
  // If this stops holding, the vector has stopped testing the convention it
  // exists for, and signing path-only would pass unnoticed.
  const [, pathquery] = vectors[1];
  assert.ok(pathquery.input.path.includes('?'));
});

test('signing path-only produces a DIFFERENT signature — the query is covered', () => {
  // The security decision behind the convention, asserted rather than asserted-in-prose.
  const [, pathquery] = vectors[1];
  const seed = fromHex(pathquery.ed25519.private_key_seed_hex);
  const signer = new RequestSigner(vaidJson(pathquery), seed);
  const pathOnly = pathquery.input.path.split('?')[0];
  const headers = signer.signHeaders(pathquery.input.method, pathOnly, new Uint8Array(), {
    now: new Date(pathquery.input.timestamp),
    nonce: pathquery.input.clientNonce,
  });
  assert.notEqual(
    toHex(fromBase64(headers.signature)),
    pathquery.ed25519.signature_hex,
    'a query string outside the signature would be tamperable',
  );
});

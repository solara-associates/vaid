/**
 * Packaged cross-language client conformance check — the firewall, shipped in the
 * tarball. TypeScript mirror of the Rust `crates/vaid-client/tests/conformance.rs`
 * and `pathquery_conformance.rs`.
 *
 * A consumer who has only `npm install vaid-client` can prove the signer they
 * installed reproduces the frozen cross-language vectors byte-for-byte:
 *
 * ```console
 * $ npx vaid-client-conformance      # exit 0 = PASS, 1 = BLOCKER
 * ```
 *
 * Two vectors, because the client pins two things: the base operator-signing
 * payload (`operator_pop_v1.json`) and the **path-with-query** signing convention
 * (`pathquery_v1.json`), where the signed `path` is the on-the-wire request target
 * including the query string. Signing path-only would leave the query outside the
 * signature and therefore tamperable, so that vector is a security decision, not
 * a formatting one.
 */

import { readFileSync } from 'node:fs';

import { fromBase64, fromHex, toHex } from 'vaid-pop';

import { RequestSigner } from './auth.js';

/** A cross-language byte-identity divergence — a hard BLOCKER. */
export class ConformanceError extends Error {
  override readonly name = 'ConformanceError';
}

/** The shape of a frozen vector file, as far as these checks read it. */
export interface ClientVector {
  digest_sha256_hex: string;
  ed25519: {
    private_key_seed_hex: string;
    public_key_hex: string;
    signature_hex: string;
  };
  input: {
    vaidId: string;
    method: string;
    path: string;
    bodySha256: string;
    tenantId: string;
    timestamp: string;
    clientNonce: string;
  };
}

function loadVectorFile(name: string): ClientVector {
  const url = new URL(`../vectors/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8')) as ClientVector;
}

/** The operator-signing vector bundled with the installed package. */
export function loadVector(): ClientVector {
  return loadVectorFile('operator_pop_v1.json');
}

/** The path-with-query vector bundled with the installed package. */
export function loadPathQueryVector(): ClientVector {
  return loadVectorFile('pathquery_v1.json');
}

/**
 * A minimal VAID document JSON carrying the snake_case identity the signer
 * parses. The signer binds identity from the document, never from a caller
 * argument, so the check has to go through a document.
 */
function vaidJson(v: ClientVector): string {
  return JSON.stringify({ vaid_id: v.input.vaidId, tenant_id: v.input.tenantId });
}

/**
 * The real signer path: {@link RequestSigner.signHeaders} builds the payload,
 * signs via the shared primitive, and its `x-synthera-signature` decodes to the
 * frozen signature byte-for-byte.
 *
 * The vector's `bodySha256` is `sha256("")`, so the empty body is signed.
 */
export function checkRequestSigner(v: ClientVector, label: string): void {
  const signer = new RequestSigner(vaidJson(v), fromHex(v.ed25519.private_key_seed_hex));
  const headers = signer.signHeaders(v.input.method, v.input.path, new Uint8Array(), {
    now: new Date(v.input.timestamp),
    nonce: v.input.clientNonce,
  });

  if (headers.timestamp !== v.input.timestamp) {
    throw new ConformanceError(
      `${label}: header timestamp diverged — BLOCKER\n  got    = ${headers.timestamp}\n  vector = ${v.input.timestamp}`,
    );
  }
  if (headers.nonce !== v.input.clientNonce) {
    throw new ConformanceError(`${label}: header nonce diverged — BLOCKER`);
  }

  const signature = fromBase64(headers.signature);
  if (signature.length !== 64) {
    throw new ConformanceError(
      `${label}: signature must be 64 bytes, got ${signature.length}`,
    );
  }
  if (toHex(signature) !== v.ed25519.signature_hex) {
    throw new ConformanceError(
      `${label}: TypeScript client header signature diverged from the frozen vector — BLOCKER\n` +
        `  got    = ${toHex(signature)}\n  vector = ${v.ed25519.signature_hex}`,
    );
  }
}

/** The pinned path-with-query convention: the signed path really carries a query. */
export function checkPathQuery(v: ClientVector): void {
  if (!v.input.path.includes('?')) {
    throw new ConformanceError("the pathquery vector's path must include a query string");
  }
  checkRequestSigner(v, 'pathquery');
}

/**
 * Run every firewall check against the bundled vectors. Throws
 * {@link ConformanceError} on any divergence; returns the vectors on PASS.
 */
export function run(): { pop: ClientVector; pathquery: ClientVector } {
  const pop = loadVector();
  checkRequestSigner(pop, 'operator_pop');
  const pathquery = loadPathQueryVector();
  checkPathQuery(pathquery);
  return { pop, pathquery };
}

/** CLI entry point: exit 0 on PASS, 1 on any divergence. */
export function main(): number {
  let result;
  try {
    result = run();
  } catch (error) {
    console.error(
      `CROSS-LANGUAGE CLIENT FIREWALL: MISMATCH — BLOCKER\n${(error as Error).message}`,
    );
    return 1;
  }
  console.log(
    'CROSS-LANGUAGE CLIENT FIREWALL: PASS — installed signer == frozen vectors, byte-for-byte\n' +
      `  operator_pop signature = ${result.pop.ed25519.signature_hex}\n` +
      `  pathquery signature    = ${result.pathquery.ed25519.signature_hex}`,
  );
  return 0;
}

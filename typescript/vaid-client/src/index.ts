/**
 * # vaid-client
 *
 * The VAID proof-of-possession request signer for TypeScript: assemble
 * `(method, path, body)` into the canonical `RequestAuthPayload`, sign it, and
 * emit the four `x-synthera-*` headers a conforming verifier checks.
 *
 * The canonicalization and the Ed25519 sign/verify live in `vaid-pop`; this
 * package never reimplements JCS, so the bytes stay identical to the Rust and
 * Python clients by construction. Byte-identity is locked by the vendored
 * cross-language vectors `operator_pop_v1.json` and `pathquery_v1.json`.
 *
 * ```ts
 * import { RequestSigner, popHeaderRecord } from 'vaid-client';
 *
 * const signer = new RequestSigner(vaidDocumentJson, agentPrivateSeed);
 * const headers = signer.signHeaders('POST', '/vaid/mint?tenant=acme', body);
 * await fetch(url, { method: 'POST', body, headers: popHeaderRecord(headers) });
 * ```
 *
 * Note the `path` convention: it is the on-the-wire request target **including
 * the query string**, not path-only. That is a security decision — signing
 * path-only would leave the query outside the signature — and it is pinned by a
 * frozen conformance vector.
 */

export {
  InvalidVaidError,
  PopError,
  PortRequestSigner,
  popHeaderPairs,
  popHeaderRecord,
  RequestSigner,
  SigningError,
  type OperatorSigningPort,
  type PopHeaders,
  type SignOptions,
} from './auth.js';

// Re-exported so a client-only consumer does not need a second install to build
// or verify a payload: one dependency, whole surface.
export {
  canonicalRequestSigningBytes,
  CONTROL_PLANE_CAPABILITY,
  ed25519PublicKey,
  fromBase64,
  fromHex,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_VAID,
  isOperator,
  OPERATOR_TENANT_ID,
  randomEd25519Seed,
  sha256Hex,
  signPayload,
  toBase64,
  toHex,
  utcWholeSecondRfc3339,
  verifySignedPayload,
  type Ed25519Seed,
  type Principal,
  type RequestAuthPayload,
  type Rfc3339Utc,
  type TenantId,
  type VaidId,
} from 'vaid-pop';

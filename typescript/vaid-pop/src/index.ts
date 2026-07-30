/**
 * # vaid-pop
 *
 * The proof-of-possession (PoP) signing primitive: the minimal, self-contained
 * surface an external client needs to authenticate a VAID-bound request. It
 * carries the canonicalization primitive, the per-request payload, the VAID
 * identity types, and the completion record, and nothing else.
 *
 * The Rust `vaid-pop` crate defines the CANONICAL contract; this is the
 * TypeScript **mirror**, not a second definition. Byte-identity is locked by the
 * shared cross-language vectors `operator_pop_v1.json` and `completion_v1.json`
 * (vendored into this package at `vectors/` and drift-checked against the Rust
 * copies in CI): if these bytes ever diverge from Rust or Python, the
 * conformance gate is a BLOCKER.
 *
 * Contract: RFC 8785 (JCS) over the camelCase payload → SHA-256 → 32-byte digest
 * → **pure Ed25519 over the digest as the raw message** → raw 64-byte signature.
 *
 * ```ts
 * import { canonicalRequestSigningBytes, signPayload, verifySignedPayload } from 'vaid-pop';
 * ```
 */

export {
  canonicalize,
  canonicalizeToString,
  JcsError,
  type JsonValue,
} from './jcs.js';

export {
  bytesToNumbers,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  fromBase64,
  fromHex,
  numbersToBytes,
  randomEd25519Seed,
  randomHex,
  sha256,
  sha256Hex,
  toBase64,
  toHex,
  type Ed25519PublicKey,
  type Ed25519Seed,
  type Ed25519Signature,
} from './crypto.js';

export {
  canonicalRequestSigningBytes,
  signPayload,
  verifySignedPayload,
} from './vaidPop.js';

export {
  buildRequestAuthPayload,
  CONTROL_PLANE_CAPABILITY,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_VAID,
  isOperator,
  OPERATOR_TENANT_ID,
  utcWholeSecondRfc3339,
  type Principal,
  type RequestAuthPayload,
  type Rfc3339Utc,
  type TenantId,
  type VaidId,
} from './requestAuth.js';

export {
  ASSURANCE_TIERS,
  AssuranceTier,
  buildCompletionRecord,
  type CompletionRecord,
} from './requestCompletion.js';

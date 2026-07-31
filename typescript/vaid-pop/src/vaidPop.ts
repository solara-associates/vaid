/**
 * Proof-of-possession request signing primitive — the TypeScript mirror of the
 * Rust `vaid_pop::vaid_pop` module.
 *
 * A holder proves it controls a private key by signing the RFC 8785 (JCS)
 * canonical SHA-256 digest of a request payload with that key; a verifier checks
 * the signature against the *public* half it was handed. The verifier never sees
 * the private key.
 *
 * The signed payload carries **no embedded signature field** — the signature
 * travels alongside the payload — so there is nothing to null before
 * canonicalizing. (The VAID *document* is the one place that is not true, and
 * `vaid-mint` handles it there.)
 *
 * This is the **single home** of the primitive in TypeScript: one
 * canonicalization implementation, so a signer and a conforming verifier agree
 * byte-for-byte.
 */

import { ed25519Sign, ed25519Verify, sha256, type Ed25519Seed } from './crypto.js';
import { canonicalize } from './jcs.js';

/**
 * The canonical 32-byte SHA-256 signing digest of any serializable request
 * payload, via RFC 8785. This is the exact byte string a holder signs and a
 * verifier checks — both sides MUST derive it the same way, which is why it
 * lives in one place.
 */
export function canonicalRequestSigningBytes(payload: unknown): Uint8Array {
  return sha256(canonicalize(payload));
}

/**
 * Sign a request payload with a raw 32-byte Ed25519 seed — the holder side of
 * proof-of-possession. Returns the detached raw 64-byte signature.
 */
export function signPayload(payload: unknown, seed: Ed25519Seed): Uint8Array {
  return ed25519Sign(canonicalRequestSigningBytes(payload), seed);
}

/**
 * Verify an Ed25519 proof-of-possession signature over a request payload against
 * the supplied raw 32-byte public key. `true` iff the signature is valid.
 *
 * No error surface: a bad or forged signature, a malformed key, and a
 * wrong-length signature are all simply a verification result (`false`), never a
 * fault.
 */
export function verifySignedPayload(
  payload: unknown,
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ed25519Verify(signature, canonicalRequestSigningBytes(payload), publicKey);
}

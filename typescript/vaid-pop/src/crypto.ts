/**
 * The crypto primitives, in one place.
 *
 * Ed25519 and SHA-256/SHA-512 come from `@noble/ed25519` and `@noble/hashes` —
 * audited, dependency-free, and available in every JavaScript runtime, which is
 * the reach this package exists for. `node:crypto` would tie the packages to
 * Node and buy nothing: the VAID contract is pure Ed25519 over a 32-byte digest
 * treated as a raw message, which every implementation of Ed25519 agrees on.
 *
 * `@noble/ed25519` ships without a bundled SHA-512 so it can stay
 * zero-dependency; wiring it once here is what makes the synchronous API usable,
 * and doing it in a single module is what stops two call sites from wiring it
 * differently.
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';

// Wire the hash @noble/ed25519 needs for its synchronous API. Idempotent, and
// done at module load so no caller can observe the unwired state.
ed25519.hashes.sha512 = nobleSha512;

/** Raw 32-byte Ed25519 private seed (RFC 8032 `k`). */
export type Ed25519Seed = Uint8Array;
/** Raw 32-byte Ed25519 public key. */
export type Ed25519PublicKey = Uint8Array;
/** Raw 64-byte Ed25519 signature. */
export type Ed25519Signature = Uint8Array;

/** SHA-256 of `bytes`, as 32 raw bytes. */
export function sha256(bytes: Uint8Array): Uint8Array {
  return nobleSha256(bytes);
}

/** Lowercase-hex SHA-256 of `bytes` — the encoding every VAID hash field uses. */
export function sha256Hex(bytes: Uint8Array): string {
  return toHex(sha256(bytes));
}

/** The raw 32-byte Ed25519 public key for a raw 32-byte private seed. */
export function ed25519PublicKey(seed: Ed25519Seed): Ed25519PublicKey {
  return ed25519.getPublicKey(seed);
}

/**
 * Pure Ed25519 signature over `message` — used throughout VAID with the 32-byte
 * canonical digest as the message, never with a pre-hash variant.
 */
export function ed25519Sign(message: Uint8Array, seed: Ed25519Seed): Ed25519Signature {
  return ed25519.sign(message, seed);
}

/**
 * Verify a pure Ed25519 signature. A forged signature, a malformed key, and a
 * wrong-length signature are all `false` — verification is a result, not a
 * fault, matching `vaid_pop::verify_signed_payload` in Rust and Python.
 */
export function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** Generate a fresh random 32-byte Ed25519 seed from the platform CSPRNG. */
export function randomEd25519Seed(): Ed25519Seed {
  return ed25519.utils.randomSecretKey();
}

/** Cryptographically random lowercase hex, `byteLength` bytes wide. */
export function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** Lowercase hex of `bytes`. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/** Bytes of a hex string. Throws on odd length or a non-hex digit. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex string has odd length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

/**
 * Standard base64 of `bytes` — the encoding the `x-synthera-*` headers use.
 * Written against `btoa` rather than `Buffer` so the packages stay runtime-neutral.
 */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Bytes of a standard-base64 string. */
export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Rust serializes `Vec<u8>` as a JSON array of numbers, so every byte-valued
 * field inside a signed VAID document (`public_key_der`, `kernel_signature`) is
 * a `number[]` on the wire. These two convert at the boundary; nothing in the
 * signing path may do it ad hoc.
 */
export function bytesToNumbers(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/** The inverse of {@link bytesToNumbers}. */
export function numbersToBytes(numbers: readonly number[]): Uint8Array {
  return Uint8Array.from(numbers);
}

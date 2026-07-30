/**
 * Packaged cross-language PoP conformance check — the firewall, shipped in the
 * tarball. TypeScript mirror of `vaid_pop.conformance` (Python) and the Rust
 * `tests/conformance.rs` / `tests/completion_conformance.rs` gates.
 *
 * A consumer who has only `npm install vaid-pop` can prove the primitive they
 * installed reproduces the frozen cross-language vectors byte-for-byte:
 *
 * ```console
 * $ npx vaid-pop-conformance      # exit 0 = PASS, 1 = BLOCKER
 * ```
 *
 * The vectors are the ones bundled with the package (`vectors/*.json`). The Rust
 * and Python gates assert the identical vectors; a repo-level drift check proves
 * every copy is byte-identical, so Rust output == Python output == TypeScript
 * output == vector.
 *
 * This module reads its vectors from disk and is therefore the one Node-only
 * entry point in the package; the library surface itself is runtime-neutral.
 */

import { readFileSync } from 'node:fs';

import {
  ed25519PublicKey,
  ed25519Sign,
  fromHex,
  toHex,
  type Ed25519Seed,
} from './crypto.js';
import { ASSURANCE_TIERS, type CompletionRecord } from './requestCompletion.js';
import type { RequestAuthPayload } from './requestAuth.js';
import { canonicalRequestSigningBytes, verifySignedPayload } from './vaidPop.js';

/** A cross-language byte-identity divergence — a hard BLOCKER. */
export class ConformanceError extends Error {
  override readonly name = 'ConformanceError';
}

/** The shape of a frozen vector file, as far as these checks read it. */
export interface Vector {
  digest_sha256_hex: string;
  ed25519: {
    private_key_seed_hex: string;
    public_key_hex: string;
    signature_hex: string;
  };
  input: Record<string, unknown>;
  assurance_tier_strings?: string[];
}

function loadVectorFile(name: string): Vector {
  // `../vectors` relative to this module resolves to the package's vectors/
  // directory from both `src/` (running from source) and `dist/` (installed).
  const url = new URL(`../vectors/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8')) as Vector;
}

/** The operator-signing PoP vector bundled with the installed package. */
export function loadVector(): Vector {
  return loadVectorFile('operator_pop_v1.json');
}

/** The completion-record vector bundled with the installed package. */
export function loadCompletionVector(): Vector {
  return loadVectorFile('completion_v1.json');
}

function seedOf(v: Vector): Ed25519Seed {
  return fromHex(v.ed25519.private_key_seed_hex);
}

function assertHex(label: string, got: string, want: string): void {
  if (got !== want) {
    throw new ConformanceError(
      `${label} diverged from the frozen vector — BLOCKER\n  got    = ${got}\n  vector = ${want}`,
    );
  }
}

/** JCS + SHA-256 over the camelCase `RequestAuthPayload` == the frozen digest. */
export function checkDigest(v: Vector): void {
  const digest = canonicalRequestSigningBytes(v.input as unknown as RequestAuthPayload);
  assertHex('TypeScript PoP digest', toHex(digest), v.digest_sha256_hex);
  if (digest.length !== 32) {
    throw new ConformanceError(`digest must be 32 bytes, got ${digest.length}`);
  }
}

/**
 * The frozen seed derives the frozen public key, signs the frozen digest to the
 * frozen signature, and that signature verifies through the public verifier
 * path.
 */
export function checkSignature(v: Vector): void {
  const seed = seedOf(v);
  const publicKey = ed25519PublicKey(seed);
  assertHex('Ed25519 public key', toHex(publicKey), v.ed25519.public_key_hex);

  const digest = canonicalRequestSigningBytes(v.input as unknown as RequestAuthPayload);
  const signature = ed25519Sign(digest, seed);
  assertHex('TypeScript PoP signature', toHex(signature), v.ed25519.signature_hex);
  if (signature.length !== 64) {
    throw new ConformanceError(`signature must be 64 bytes, got ${signature.length}`);
  }

  // Round-trip through the verifier a third party would actually call.
  if (!verifySignedPayload(v.input, publicKey, fromHex(v.ed25519.signature_hex))) {
    throw new ConformanceError(
      'the frozen signature does not verify under verifySignedPayload — BLOCKER',
    );
  }
}

/**
 * The completion record: digest, signature, and — because this is the FIRST
 * vector with an enum — every `AssuranceTier` string, in order. The enum is the
 * most likely place for silent cross-language drift, since the string lands
 * inside the signed bytes.
 */
export function checkCompletion(v: Vector): void {
  const digest = canonicalRequestSigningBytes(v.input as unknown as CompletionRecord);
  assertHex('TypeScript completion digest', toHex(digest), v.digest_sha256_hex);

  const seed = seedOf(v);
  assertHex('completion public key', toHex(ed25519PublicKey(seed)), v.ed25519.public_key_hex);
  assertHex('TypeScript completion signature', toHex(ed25519Sign(digest, seed)), v.ed25519.signature_hex);

  const frozen = v.assurance_tier_strings;
  if (!frozen) throw new ConformanceError('completion vector is missing assurance_tier_strings');
  const ours = [...ASSURANCE_TIERS];
  if (JSON.stringify(ours) !== JSON.stringify(frozen)) {
    throw new ConformanceError(
      `AssuranceTier strings diverged from the frozen vector — BLOCKER\n` +
        `  got    = ${JSON.stringify(ours)}\n  vector = ${JSON.stringify(frozen)}`,
    );
  }
  if ((v.input as unknown as CompletionRecord).assuranceTier !== 'selfReported') {
    throw new ConformanceError(
      "the completion vector's declared tier must be the substantiated 'selfReported'",
    );
  }
}

/**
 * Run every firewall check against the bundled vectors. Throws
 * {@link ConformanceError} on any divergence; returns the vectors on PASS.
 */
export function run(): { pop: Vector; completion: Vector } {
  const pop = loadVector();
  checkDigest(pop);
  checkSignature(pop);
  const completion = loadCompletionVector();
  checkCompletion(completion);
  return { pop, completion };
}

/** CLI entry point: exit 0 on PASS, 1 on any divergence. */
export function main(): number {
  let result;
  try {
    result = run();
  } catch (error) {
    console.error(
      `CROSS-LANGUAGE PoP FIREWALL: MISMATCH — BLOCKER\n${(error as Error).message}`,
    );
    return 1;
  }
  console.log(
    'CROSS-LANGUAGE PoP FIREWALL: PASS — installed vaid-pop == frozen vectors, byte-for-byte\n' +
      `  request digest    = ${result.pop.digest_sha256_hex}\n` +
      `  request signature = ${result.pop.ed25519.signature_hex}\n` +
      `  completion digest = ${result.completion.digest_sha256_hex}`,
  );
  return 0;
}

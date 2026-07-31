/**
 * Packaged cross-language mint conformance check — the firewall, shipped in the
 * tarball. TypeScript mirror of `vaid_mint.conformance` (Python) and the Rust
 * `tests/mint_conformance.rs` gate.
 *
 * A consumer who has only `npm install vaid-mint` can prove the mint they
 * installed reproduces the frozen cross-language VAID-document vector
 * byte-for-byte:
 *
 * ```console
 * $ npx vaid-mint-conformance      # exit 0 = PASS, 1 = BLOCKER
 * ```
 *
 * Two vectors are bundled with the package and both are checked:
 *
 * - `vectors/mint_v1.json` — the signed VAID document.
 * - `vectors/mint_pop_v1.json` — the `MintPopPayload` a holder signs to prove it
 *   controls the BYO key it registers at mint. Frozen later than the others: it
 *   was the one signed structure with no artifact holding the implementations to
 *   it (`docs/spec/encoding.md` E.11), and it is the only vector carrying a JSON
 *   `null` (E.7).
 *
 * The Rust and Python gates assert the identical vectors; a repo-level drift check
 * proves every copy is byte-identical, so Rust output == Python output ==
 * TypeScript output == vector.
 *
 * Per Decision B this proves self-consistency WITHIN this repo, NOT conformance
 * against the managed authority's VAID format.
 */

import { readFileSync } from 'node:fs';

import {
  canonicalizeToString,
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  ed25519Sign,
  fromHex,
  toHex,
  verifySignedPayload,
} from 'vaid-pop';

import {
  canonicalVaidSigningBytes,
  computeLineageHash,
  type Vaid,
} from './document.js';
import { buildMintPopPayload, type MintPopPayload } from './mintTypes.js';
import { verifyVaidAuthenticity } from './verify.js';

/** A cross-language byte-identity divergence — a hard BLOCKER. */
export class ConformanceError extends Error {
  override readonly name = 'ConformanceError';
}

/** The shape of the frozen mint vector, as far as these checks read it. */
export interface MintVector {
  digest_sha256_hex: string;
  ed25519: {
    kernel_private_key_seed_hex: string;
    kernel_public_key_hex: string;
    signature_hex: string;
  };
  /** A real UNSIGNED VAID document (snake_case), with `kernel_signature` empty. */
  input: Vaid;
}

/** The shape of the frozen mint-PoP vector, as far as these checks read it. */
export interface MintPopVector {
  digest_sha256_hex: string;
  ed25519: {
    private_key_seed_hex: string;
    public_key_hex: string;
    signature_hex: string;
  };
  /** A real camelCase `MintPopPayload`. */
  input: MintPopPayload;
}

// `../vectors` resolves to the package's vectors/ directory from both `src/`
// (running from source) and `dist/` (installed).
function loadVectorFile<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8')) as T;
}

/** The mint conformance vector bundled with the installed package. */
export function loadVector(): MintVector {
  return loadVectorFile<MintVector>('mint_v1.json');
}

/** The mint proof-of-possession vector bundled with the installed package. */
export function loadMintPopVector(): MintPopVector {
  return loadVectorFile<MintPopVector>('mint_pop_v1.json');
}

function assertHex(label: string, got: string, want: string): void {
  if (got !== want) {
    throw new ConformanceError(
      `${label} diverged from the frozen vector — BLOCKER\n  got    = ${got}\n  vector = ${want}`,
    );
  }
}

/**
 * JCS (with `kernel_signature` nulled) + SHA-256 over the VAID document == the
 * frozen digest.
 */
export function checkDocumentDigest(v: MintVector): void {
  const digest = canonicalVaidSigningBytes(v.input);
  assertHex('TypeScript VAID-document digest', toHex(digest), v.digest_sha256_hex);
  if (digest.length !== 32) {
    throw new ConformanceError(`digest must be 32 bytes, got ${digest.length}`);
  }
}

/**
 * From the frozen kernel seed, the kernel derives the frozen public key and signs
 * the digest to the frozen signature byte-for-byte.
 */
export function checkKernelSignature(v: MintVector): void {
  const seed = fromHex(v.ed25519.kernel_private_key_seed_hex);
  assertHex('kernel public key', toHex(ed25519PublicKey(seed)), v.ed25519.kernel_public_key_hex);

  const signature = ed25519Sign(canonicalVaidSigningBytes(v.input), seed);
  assertHex('TypeScript kernel signature', toHex(signature), v.ed25519.signature_hex);
  if (signature.length !== 64) {
    throw new ConformanceError(`signature must be 64 bytes, got ${signature.length}`);
  }
}

/**
 * The derived `lineage_hash` in the document equals
 * `computeLineageHash(parent_vaid, agent_id)` — proves the derivation, not just a
 * stored field.
 */
export function checkLineageHash(v: MintVector): void {
  const recomputed = computeLineageHash(v.input.parent_vaid, v.input.agent_id);
  assertHex('recomputed lineage_hash', recomputed, v.input.lineage_hash);
}

/** `vaid_id` is derived from `agent_id` — the same UUID. */
export function checkVaidIdEqualsAgentId(v: MintVector): void {
  if (v.input.vaid_id !== v.input.agent_id) {
    throw new ConformanceError(
      `vaid_id must equal agent_id — BLOCKER\n  vaid_id  = ${v.input.vaid_id}\n  agent_id = ${v.input.agent_id}`,
    );
  }
}

/**
 * The frozen signed document verifies against the frozen kernel PUBLIC key
 * alone — the surface a third party actually holds. The digest and signature
 * checks above prove the signer; this proves the verifier agrees with it.
 */
export function checkPublicKeyOnlyVerification(v: MintVector): void {
  const signed: Vaid = {
    ...v.input,
    kernel_signature: Array.from(fromHex(v.ed25519.signature_hex)),
  };
  if (!verifyVaidAuthenticity(fromHex(v.ed25519.kernel_public_key_hex), signed)) {
    throw new ConformanceError(
      'the frozen mint vector does not verify under its kernel public key alone — BLOCKER',
    );
  }
}

/**
 * The `MintPopPayload` gate (`docs/spec/encoding.md` E.11).
 *
 * Rebuilds the payload through {@link buildMintPopPayload} — the single
 * constructor both holder and mint use — rather than reading `input` back, so this
 * proves the code path that actually runs at mint emits these bytes, not merely
 * that an object round-trips.
 *
 * Also asserts the two properties this vector exists to pin: `parentVaid` is a
 * PRESENT JSON `null` (E.7 — an omitted key is a different key set and a different
 * digest), and the signature verifies against the key the payload REGISTERS, which
 * is the whole semantic content of proof-of-possession.
 */
export function checkMintPop(v: MintPopVector): void {
  const seed = fromHex(v.ed25519.private_key_seed_hex);
  const registered = ed25519PublicKey(seed);
  assertHex('holder public key', toHex(registered), v.ed25519.public_key_hex);

  const payload = buildMintPopPayload(
    {
      agentClass: 'runner',
      version: '1.0.0',
      tenantId: 'aifactory',
      parentVaid: null,
      scopeBoundary: ['data.aifactory'],
      capabilitySet: ['read'],
      publicKeyDer: registered,
    },
    {
      publicKeyDer: registered,
      nonce: '0123456789abcdef0123456789abcdef',
      issuedAt: '2026-06-04T12:00:00Z',
    },
  );
  // Compare CANONICALLY, not with JSON.stringify: key order is exactly what JCS
  // makes irrelevant, and the frozen vector's keys are sorted while a constructor
  // emits declaration order. An order-sensitive comparison here would report a
  // divergence that does not exist — and, worse, could be "fixed" by reordering
  // the struct, which changes nothing about the bytes.
  const canonicalPayload = canonicalizeToString(payload);
  if (canonicalPayload !== canonicalizeToString(v.input)) {
    throw new ConformanceError(
      "the mint's own PoP payload constructor diverged from the frozen vector — BLOCKER\n" +
        `  got    = ${canonicalPayload}\n  vector = ${canonicalizeToString(v.input)}`,
    );
  }

  // E.7: a present null, not an omitted key.
  if (!('parentVaid' in v.input) || v.input.parentVaid !== null) {
    throw new ConformanceError(
      'parentVaid must be a PRESENT JSON null in this vector — encoding.md E.7',
    );
  }
  const { parentVaid: _omitted, ...without } = v.input;
  if (toHex(canonicalRequestSigningBytes(without)) === v.digest_sha256_hex) {
    throw new ConformanceError(
      'omitting parentVaid MUST change the digest — otherwise E.7 is untested',
    );
  }

  const digest = canonicalRequestSigningBytes(payload);
  assertHex('TypeScript mint-PoP digest', toHex(digest), v.digest_sha256_hex);
  assertHex('TypeScript mint-PoP signature', toHex(ed25519Sign(digest, seed)), v.ed25519.signature_hex);

  // The PoP semantic: it must verify against the key it REGISTERS.
  const signature = fromHex(v.ed25519.signature_hex);
  if (!verifySignedPayload(payload, Uint8Array.from(payload.publicKeyDer), signature)) {
    throw new ConformanceError(
      'the frozen PoP must verify against the registered key — BLOCKER',
    );
  }
  if (verifySignedPayload({ ...payload, capabilitySet: ['read', 'write'] }, registered, signature)) {
    throw new ConformanceError(
      'a captured PoP must not be replayable to mint a higher-privilege VAID',
    );
  }
}

/**
 * Run every firewall check against the bundled vector. Throws
 * {@link ConformanceError} on any divergence; returns the vector on PASS.
 */
export function run(): { document: MintVector; mintPop: MintPopVector } {
  const document = loadVector();
  checkDocumentDigest(document);
  checkKernelSignature(document);
  checkLineageHash(document);
  checkVaidIdEqualsAgentId(document);
  checkPublicKeyOnlyVerification(document);
  const mintPop = loadMintPopVector();
  checkMintPop(mintPop);
  return { document, mintPop };
}

/** CLI entry point: exit 0 on PASS, 1 on any divergence. */
export function main(): number {
  let result: { document: MintVector; mintPop: MintPopVector };
  try {
    result = run();
  } catch (error) {
    console.error(
      `CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n${(error as Error).message}`,
    );
    return 1;
  }
  console.log(
    'CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == frozen vectors, byte-for-byte\n' +
      `  document digest    = ${result.document.digest_sha256_hex}\n` +
      `  document signature = ${result.document.ed25519.signature_hex}\n` +
      `  mint-PoP digest    = ${result.mintPop.digest_sha256_hex}`,
  );
  return 0;
}

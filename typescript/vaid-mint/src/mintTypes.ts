/**
 * Mint wire types — TypeScript mirror of the Rust `vaid_mint::mint_types`.
 *
 * {@link VaidSeed} is the requested attributes; {@link MintVaidRequest} pairs a
 * seed with an optional {@link MintPop}. {@link MintPop} /
 * {@link buildMintPopPayload} are the BYO-key proof-of-possession: the holder
 * signs the canonical mint-PoP payload with the private key matching the public
 * key it registers, and the mint verifies that self-signature before issuing. The
 * payload is signed via the SHARED `vaid-pop` primitive, so the bytes match a
 * conforming verifier by construction.
 *
 * The payload's field names and encodings mirror the Rust `MintPopPayload` serde
 * (`rename_all = "camelCase"`, `Vec<u8>` → array of numbers), so the signed bytes
 * agree cross-language by construction. Note the asymmetry with the VAID
 * *document*, which is snake_case: the PoP payload is camelCase like every other
 * signed payload in `vaid-pop`.
 */

import type { Rfc3339Utc, TenantId, VaidId } from 'vaid-pop';

import type { AgentClass, Vaid } from './document.js';

/** Requested attributes for a mint. */
export interface VaidSeed {
  agentClass: AgentClass;
  version: string;
  tenantId: TenantId;
  /** Optional parent VAID (delegation lineage). `null` for root agents. */
  parentVaid?: VaidId | null;
  /** Data domains / resource namespaces this agent may operate within. */
  scopeBoundary?: string[];
  /** Explicit capability grants at spawn — no ambient authority. */
  capabilitySet?: string[];
  /**
   * Holder-supplied Ed25519 public key (BYO-key), raw 32 bytes. When present, the
   * holder generated its own keypair and registers only the public half; the mint
   * binds it as the VAID's `public_key_der` and REQUIRES a {@link MintPop}
   * proving the holder controls the matching private key. When absent, the mint
   * generates a keypair and discards the private half (root/bootstrap path; no
   * PoP applies). `mintChild` is always BYO-key.
   */
  publicKeyDer?: Uint8Array | null;
}

/**
 * A holder's proof-of-possession for a mint. Carries the freshness material
 * (`nonce`, `issuedAt`) folded into the signed payload, plus the detached Ed25519
 * `signature` over that payload's canonical bytes. The mint reconstructs the
 * payload from `seed` + these fields and verifies.
 */
export interface MintPop {
  /** Per-request random nonce (hex of ≥128 random bits) — replay distinctness. */
  nonce: string;
  /** Client-asserted timestamp — freshness (rejected outside the window). */
  issuedAt: Rfc3339Utc;
  /** Ed25519 signature over the canonical mint-PoP payload bytes. */
  signature: Uint8Array;
}

/**
 * A mint request: a seed plus an optional proof-of-possession. The PoP is
 * REQUIRED when `seed.publicKeyDer` is present (BYO-key) and omitted for the
 * generate-and-discard path.
 */
export interface MintVaidRequest {
  seed: VaidSeed;
  pop?: MintPop | null;
}

/** A mint response: the newly-minted, signed VAID. */
export interface MintVaidResponse {
  vaid: Vaid;
}

/**
 * The exact canonical payload a holder signs to prove possession of the key it
 * registers at mint. Binds the public key being registered together with the full
 * set of requested attributes (so a captured request cannot be replayed to mint a
 * different-tenant or different-privilege VAID) and the freshness material.
 */
export interface MintPopPayload {
  /** THE key being registered — the subject of the possession proof. */
  publicKeyDer: number[];
  tenantId: TenantId;
  agentClass: AgentClass;
  version: string;
  parentVaid: VaidId | null;
  scopeBoundary: string[];
  capabilitySet: string[];
  nonce: string;
  issuedAt: Rfc3339Utc;
}

/**
 * Reconstruct the canonical {@link MintPopPayload} for `seed`.
 *
 * Both holder and mint build the payload through this one function so the signed
 * bytes match exactly. `publicKeyDer` (the registered key being proven) is
 * supplied explicitly because PoP only applies on the BYO-key path.
 */
export function buildMintPopPayload(
  seed: VaidSeed,
  options: { publicKeyDer: Uint8Array; nonce: string; issuedAt: Rfc3339Utc },
): MintPopPayload {
  return {
    publicKeyDer: Array.from(options.publicKeyDer),
    tenantId: seed.tenantId,
    agentClass: seed.agentClass,
    version: seed.version,
    parentVaid: seed.parentVaid ?? null,
    scopeBoundary: [...(seed.scopeBoundary ?? [])],
    capabilitySet: [...(seed.capabilitySet ?? [])],
    nonce: options.nonce,
    issuedAt: options.issuedAt,
  };
}

/**
 * Completion / provenance record — a signed statement that a VAID-authorized
 * action finished, with a status and a result hash. TypeScript mirror of the
 * Rust `vaid_pop::request_completion`.
 *
 * Reuses the request PoP pipeline verbatim: RFC 8785 (JCS) → SHA-256 → Ed25519
 * over the canonical {@link CompletionRecord} bytes (via {@link signPayload} /
 * {@link verifySignedPayload}). Like {@link RequestAuthPayload} it carries NO
 * embedded signature field — the signature travels detached.
 *
 * # Scope: self-signed, declared metadata only
 *
 * This primitive produces exactly **one** detached signature, by the holder of
 * {@link CompletionRecord.signerVaidId}'s key. That proves *only* "this signer
 * signed this record" — nothing about who else vouches for the outcome. The
 * {@link AssuranceTier} field is therefore **declared, not proven**. Provable
 * counter-signing and third-party attestation are deliberately OUT OF SCOPE
 * here — they require a multi-signature envelope and a key-trust model that this
 * repo does not contain, and are a separate, not-yet-built primitive.
 */

import type { Rfc3339Utc, TenantId, VaidId } from './requestAuth.js';

/**
 * Declared assurance level of a completion record. The SHAPE is borrowed from
 * AIP's three-tier attestation model; the names are our own.
 *
 * ## This tier is DECLARED, not PROVEN
 *
 * A {@link CompletionRecord} carries a single detached signature by
 * `signerVaidId`. That signature proves the signer signed the record — and
 * nothing more. In particular:
 *
 * - `selfReported` is the only tier this repo can *substantiate* on its own: the
 *   actor signs its own outcome, and the signature verifies against the actor's
 *   key.
 * - `counterSigned` and `thirdPartyAttested` are **NOT independently verifiable
 *   from this repo alone.** A self-reporting signer can set either value and the
 *   single signature still verifies — there is no second signature and no
 *   key-trust model here to check a counter-signer or attester against. Treat
 *   the top two tiers as an *unverified claim*.
 *
 * The string values are the wire values. They mirror the Rust enum's
 * `rename_all = "camelCase"` serialization EXACTLY, because they go inside the
 * signed bytes: a different casing is a different signature. `ASSURANCE_TIERS`
 * pins them in declaration order, and the conformance suite asserts that order
 * against the frozen vector's `assurance_tier_strings`.
 */
export const AssuranceTier = {
  /**
   * The actor asserts its own outcome. The single signature substantiates this
   * tier and only this tier.
   */
  SelfReported: 'selfReported',
  /** A second party co-signs. NOT verifiable from this repo alone. */
  CounterSigned: 'counterSigned',
  /** An independent attester vouches. NOT verifiable from this repo alone. */
  ThirdPartyAttested: 'thirdPartyAttested',
} as const;

export type AssuranceTier = (typeof AssuranceTier)[keyof typeof AssuranceTier];

/**
 * Every tier, in the frozen vector's order. The enum-string drift guard compares
 * against this — the first vector containing an enum is the most likely place
 * for silent cross-language divergence.
 */
export const ASSURANCE_TIERS: readonly AssuranceTier[] = [
  AssuranceTier.SelfReported,
  AssuranceTier.CounterSigned,
  AssuranceTier.ThirdPartyAttested,
];

/**
 * The exact payload a completer signs to record that a VAID-authorized action
 * finished. Reuses the request PoP pipeline verbatim; carries no embedded
 * signature. Serialized camelCase, matching {@link RequestAuthPayload}.
 *
 * See the module and {@link AssuranceTier} docs for the load-bearing caveat:
 * this is **self-signed declared metadata**; only `selfReported` is
 * substantiated by the signature.
 */
export interface CompletionRecord {
  /** The acting VAID whose authorized action this completes. */
  vaidId: VaidId;
  /**
   * Lowercase hex of the 32-byte canonical digest of the original signed
   * {@link RequestAuthPayload} — binds this record to the exact authorized
   * request, not merely to the actor.
   */
  requestDigestSha256: string;
  /** Tenant the action ran under (mirrors `RequestAuthPayload.tenantId`). */
  tenantId: TenantId;
  /**
   * Terminal status of the action, e.g. `"succeeded"` / `"failed"` /
   * `"cancelled"`. String-typed to stay transport-simple and JCS-stable; a
   * caller MAY constrain it to a fixed set.
   */
  status: string;
  /**
   * Lowercase hex of `SHA-256` over the caller-defined result bytes. The
   * primitive is blind to the result content — the caller hashes it, exactly as
   * the client hashes the request body into `RequestAuthPayload.bodySha256`.
   */
  resultSha256: string;
  /** Whole-second RFC 3339 `…Z` (the same fixed point as the request timestamp). */
  completedAt: Rfc3339Utc;
  /**
   * The VAID that produced THIS record (the completer). Equals `vaidId` for a
   * self-reported record; a different value is a *claim* that some other party
   * signed — unverified here (see {@link AssuranceTier}).
   */
  signerVaidId: VaidId;
  /** Declared assurance level (declared, not proven). */
  assuranceTier: AssuranceTier;
  /** Per-record nonce for distinctness (mirrors `RequestAuthPayload.clientNonce`). */
  recordNonce: string;
}

/** Build a {@link CompletionRecord} with the nine fields in one place. */
export function buildCompletionRecord(fields: CompletionRecord): CompletionRecord {
  return {
    vaidId: fields.vaidId,
    requestDigestSha256: fields.requestDigestSha256,
    tenantId: fields.tenantId,
    status: fields.status,
    resultSha256: fields.resultSha256,
    completedAt: fields.completedAt,
    signerVaidId: fields.signerVaidId,
    assuranceTier: fields.assuranceTier,
    recordNonce: fields.recordNonce,
  };
}

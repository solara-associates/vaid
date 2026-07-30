/**
 * The VAID document — the signed, immutable identity a mint produces. TypeScript
 * mirror of the Rust `vaid_mint::document`.
 *
 * The Rust `Vaid` struct defines the CANONICAL contract; this is the mirror, not
 * a second definition. Byte-identity of the signed document is locked by the
 * shared cross-language vector `mint_v1.json` (vendored at `vectors/` and
 * drift-checked against the Rust and Python copies in CI).
 *
 * Two encoding facts carry the whole contract, and both are load-bearing:
 *
 * - **The document is snake_case.** The Rust `Vaid` struct has no
 *   `serde(rename_all)`, unlike the camelCase `RequestAuthPayload`. A camelCase
 *   VAID document is a different document.
 * - **Byte fields are arrays of numbers.** Rust serializes `Vec<u8>` as a JSON
 *   array of integers, so `public_key_der` and `kernel_signature` are `number[]`
 *   here, not base64 and not hex.
 *
 * `canonicalVaidSigningBytes` nulls `kernel_signature` before canonicalizing — a
 * signature cannot cover its own value; it travels inside the document but
 * outside the signed bytes. Everything else is covered, including `sig_version`,
 * `public_key_der`, `expires_at`, `scope_boundary`, `capability_set`,
 * `parent_vaid`, and `lineage_hash`.
 *
 * Per Decision B this is self-consistent WITHIN this repo (Rust == Python ==
 * TypeScript); it is NOT byte-conformant against the managed authority's
 * (still-moving) VAID format.
 */

import {
  canonicalize,
  sha256,
  toHex,
  type Rfc3339Utc,
  type TenantId,
  type VaidId,
} from 'vaid-pop';

export type { Rfc3339Utc, TenantId, VaidId } from 'vaid-pop';

/**
 * Current VAID signature-scheme version. The whole canonical document is signed
 * (with `kernel_signature` nulled), and the version is itself a signed field, so
 * a downgrade to a weaker payload cannot be forged without breaking
 * verification. A document whose `sig_version` is not this value is rejected at
 * verify.
 */
export const VAID_SIG_VERSION_V2 = 2;

/** Unique identifier for an agent instance — a UUID string. */
export type AgentId = string;

/** Agent class identifier (e.g. `"researcher"`, `"code-reviewer"`). */
export type AgentClass = string;

/**
 * Verifiable Agent Identity Document (VAID) — immutable, signed at mint time.
 *
 * v2 fields: `parent_vaid` (delegation lineage), `scope_boundary` (data-domain
 * restrictions), `lineage_hash` (parent-chain hash), `capability_set` (explicit
 * grants). Every field except `kernel_signature` is covered by the signature.
 *
 * Field names are snake_case on purpose — see the module docs.
 */
export interface Vaid {
  /** Signature-scheme discriminant; `2` for every VAID minted here. */
  sig_version: number;
  vaid_id: VaidId;
  agent_id: AgentId;
  agent_class: AgentClass;
  version: string;
  tenant_id: TenantId;
  issued_at: Rfc3339Utc;
  expires_at: Rfc3339Utc;
  /** Raw Ed25519 public key bytes, as Rust serializes `Vec<u8>`. */
  public_key_der: number[];
  /** Raw 64-byte Ed25519 kernel signature, as Rust serializes `Vec<u8>`. */
  kernel_signature: number[];
  /** VAID of the spawning agent. Root agents have no parent (`null`). */
  parent_vaid: VaidId | null;
  /** Data domains / resource namespaces this agent may operate within. */
  scope_boundary: string[];
  /** Hash of the parent VAID chain — enables delegation-tree reconstruction. */
  lineage_hash: string;
  /** Explicit capability grants at spawn. No ambient authority. */
  capability_set: string[];
}

/**
 * The canonical 32-byte SHA-256 digest of a VAID document, for Ed25519
 * signing/verification.
 *
 * Reuses the exact RFC 8785 (JCS) discipline the PoP primitive uses:
 *
 * 1. copy the document, forcing `kernel_signature` to JSON `null` (a signature
 *    cannot cover its own value — it travels alongside the document);
 * 2. canonicalize per RFC 8785;
 * 3. SHA-256 the canonical bytes.
 *
 * Because the signature field is nulled rather than removed, attaching a
 * signature does not change what the signature covers: the digest of an unsigned
 * document and of the same document once signed are identical.
 */
export function canonicalVaidSigningBytes(vaid: Vaid): Uint8Array {
  const payload: Record<string, unknown> = { ...vaid, kernel_signature: null };
  return sha256(canonicalize(payload));
}

/**
 * Compute a lineage hash from the parent VAID chain. Root agents (no parent) get
 * a genesis hash. The hash is lowercase-hex SHA-256 of `"{parent}:{agent_id}"`,
 * or `"GENESIS:{agent_id}"` for a root. The Rust and Python mirrors compute the
 * identical string.
 */
export function computeLineageHash(parentVaid: VaidId | null, agentId: AgentId): string {
  const material = parentVaid === null ? `GENESIS:${agentId}` : `${parentVaid}:${agentId}`;
  return toHex(sha256(new TextEncoder().encode(material)));
}

/**
 * Assemble the snake_case VAID document with an empty `kernel_signature`. The
 * field set and names mirror the Rust `Vaid` struct exactly; the issuer signs the
 * canonical bytes of this and attaches the signature.
 */
export function buildUnsignedVaidDocument(fields: {
  vaidId: VaidId;
  agentId: AgentId;
  agentClass: AgentClass;
  version: string;
  tenantId: TenantId;
  issuedAt: Rfc3339Utc;
  expiresAt: Rfc3339Utc;
  publicKeyDer: readonly number[];
  parentVaid: VaidId | null;
  scopeBoundary: readonly string[];
  lineageHash: string;
  capabilitySet: readonly string[];
}): Vaid {
  return {
    sig_version: VAID_SIG_VERSION_V2,
    vaid_id: fields.vaidId,
    agent_id: fields.agentId,
    agent_class: fields.agentClass,
    version: fields.version,
    tenant_id: fields.tenantId,
    issued_at: fields.issuedAt,
    expires_at: fields.expiresAt,
    public_key_der: [...fields.publicKeyDer],
    kernel_signature: [],
    parent_vaid: fields.parentVaid,
    scope_boundary: [...fields.scopeBoundary],
    lineage_hash: fields.lineageHash,
    capability_set: [...fields.capabilitySet],
  };
}

/** True once past `expires_at`. Mirror of Rust `Vaid::is_expired`. */
export function isExpired(vaid: Vaid, now: Date = new Date()): boolean {
  return now.getTime() > Date.parse(vaid.expires_at);
}

/**
 * Is `resource` within this VAID's scope boundary? An empty boundary means
 * unrestricted (⊤).
 *
 * This is the SINGLE scope matcher — the mint-time attenuation check and any
 * runtime scope check both call it, so they cannot drift.
 */
export function isInScope(vaid: Vaid, resource: string): boolean {
  if (vaid.scope_boundary.length === 0) return true;
  return vaid.scope_boundary.some((scope) => resource.startsWith(scope));
}

/**
 * Does this VAID hold `capability` (exact membership)? The single
 * capability-membership predicate.
 */
export function hasCapability(vaid: Vaid, capability: string): boolean {
  return vaid.capability_set.includes(capability);
}

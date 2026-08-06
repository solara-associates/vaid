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
export const VAID_SIG_VERSION_V3 = 3;

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
  /** Signature-scheme discriminant; `3` for every VAID minted here. */
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
  /**
   * v3: the issuing deployment's trust domain — a constrained, DNS-shaped name
   * (ADR-0004). Gives a verifier something to look `kernel_key_thumbprint` up
   * **under**. Compared by byte equality, never normalized.
   */
  trust_domain: string;
  /**
   * v3: RFC 9278 thumbprint URI over the RFC 7638 JWK thumbprint of the kernel
   * public key that signed this document. A commitment, not a key — you cannot
   * verify a signature with a hash, so a verifier is structurally forced to
   * source the key from elsewhere and the trust decision stays visible.
   */
  kernel_key_thumbprint: string;
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
  trustDomain: string;
  kernelKeyThumbprint: string;
}): Vaid {
  return {
    sig_version: VAID_SIG_VERSION_V3,
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
    trust_domain: fields.trustDomain,
    kernel_key_thumbprint: fields.kernelKeyThumbprint,
  };
}

/**
 * The exact timestamp profile inside signed bytes (`docs/spec/encoding.md` E.6):
 * whole-second RFC 3339 in UTC with a literal `Z`.
 */
const E6_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * True once past `expires_at`. Mirror of Rust `Vaid::is_expired`.
 *
 * **Total: never throws** (issue #10). The three implementations disagreed here:
 * Python raised `ValueError` on any timestamp that was valid RFC 3339 but not
 * whole-second `Z`, while Rust and this returned a boolean. TypeScript inherited
 * Rust's permissiveness by default rather than by decision, and
 * majority-by-accident was becoming the de facto standard.
 *
 * Settled by splitting the surface rather than picking a winner: this stays total
 * and answers only "is it past expiry"; {@link hasConformingTimestamps} answers
 * the E.6 profile question explicitly.
 *
 * **An unparseable `expires_at` returns `true` — fail closed.** This is a
 * behaviour change, and it fixes a latent fail-open: `Date.parse` returns `NaN`
 * for garbage, and every comparison against `NaN` is `false`, so an unreadable
 * expiry previously reported "not expired". A document whose expiry cannot be
 * read is not a document that can be shown to be unexpired.
 */
export function isExpired(vaid: Vaid, now: Date = new Date()): boolean {
  const expires = Date.parse(vaid.expires_at);
  if (Number.isNaN(expires)) return true;
  return now.getTime() > expires;
}

/**
 * Do `issued_at` and `expires_at` match the E.6 profile exactly — whole-second
 * RFC 3339 in UTC with a literal `Z`?
 *
 * The explicit half of the issue #10 split. E.6 says implementations SHOULD
 * reject other forms rather than silently normalizing them; this is how a caller
 * asks. Sub-second precision (`...:00.000Z`, which `Date.prototype.toISOString`
 * emits by default, so this implementation gets it wrong unless it truncates) and
 * a numeric offset (`+00:00`) are both valid RFC 3339 and both non-conforming.
 *
 * Not consulted by authenticity verification: a document that reached a verifier
 * with a non-conforming timestamp will already fail the signature check, because
 * the verifier re-serializes into the profile and recomputes different bytes.
 * This exists so that failure can be *explained* rather than merely observed.
 */
export function hasConformingTimestamps(vaid: Vaid): boolean {
  for (const value of [vaid.issued_at, vaid.expires_at]) {
    if (typeof value !== "string" || !E6_TIMESTAMP.test(value)) return false;
    if (Number.isNaN(Date.parse(value))) return false;
  }
  return true;
}

/**
 * Is `resource` within this VAID's scope boundary? An empty boundary means
 * unrestricted (⊤).
 *
 * This is the SINGLE scope matcher — the mint-time attenuation check and any
 * runtime scope check both call it, so they cannot drift.
 */
/**
 * Is `resource` within `boundary`? An empty boundary means unrestricted (⊤).
 *
 * THE scope matcher. {@link isInScope} delegates here rather than implementing it,
 * so a caller holding a bare boundary — a consent attestation's `scope_boundary`,
 * which is attached to no document — is matched by exactly the same rule as a
 * document's own. Duplicating the rule for the detached case is how the two would
 * drift.
 *
 * ## Containment is segment-bounded (spec S.3)
 *
 * An entry `P` contains a resource `R` iff `R === P`, or `P` ends with a separator
 * and `R` starts with `P`, or `R` starts with `P` followed by a separator. Bare
 * prefix matching is not containment.
 *
 * Until 0.5.0 this was `resource.startsWith(scope)`, which made `data.governance`
 * contain `data.governance-secret` — a *sibling*, sharing a textual prefix and
 * nothing else. Because this same predicate decides mint-time attenuation and
 * third-party chain verification, that let a child be delegated authority its
 * parent never held, and let a verifier confirm the delegation. The rule below is
 * **strictly narrower**: it denies cases the old one allowed and permits nothing
 * new.
 *
 * ## Why both separators, always
 *
 * Honouring only one breaks real deployments in opposite directions, and making
 * the set a deployment setting is worse: under ADR-0003 a **third party**
 * recomputes containment from a presented chain, and a deployment-local rule
 * leaves it unable to reproduce the mint's verdict. So both are reserved by the
 * specification and a segment MUST NOT contain either (S.2) — that constraint is
 * doing the safety work. Without it, an implementer treating `/` as their
 * separator and `.` as an ordinary character would find `data/user` containing
 * `data/user.admin`: the same sibling-capture bug in the other separator. The
 * constraint is normative on producers but is **not enforced here** in 0.5.0 (S.6).
 *
 * Written with only `===`, `startsWith`, `endsWith` and concatenation — no
 * character indexing — so Rust (bytes), Python (code points) and TypeScript
 * (UTF-16) cannot diverge on a multi-byte boundary.
 */

/**
 * The reserved hierarchy separators (spec `docs/spec/scope.md` S.2). Both are
 * normative and both are always honoured; a scope segment MUST NOT contain either.
 */
export const SCOPE_SEPARATORS: readonly string[] = ['/', '.'];

/**
 * Does a single boundary entry contain `resource`? The one-entry core of
 * {@link scopeContains}, split out so the rule is stated exactly once.
 *
 * An empty entry matches everything, preserving the match-all an empty string had
 * under prefix matching. It is unreachable from a well-formed boundary (an empty
 * *array* is how ⊤ is expressed) and is kept only so the rule is total.
 */
function prefixContains(prefix: string, resource: string): boolean {
  if (prefix === '') return true;
  if (resource === prefix) return true;
  // A trailing separator already marks the boundary, so plain prefixing is
  // containment — `data.` contains `data.x` without needing a second dot.
  if (SCOPE_SEPARATORS.some((sep) => prefix.endsWith(sep))) {
    return resource.startsWith(prefix);
  }
  return SCOPE_SEPARATORS.some((sep) => resource.startsWith(prefix + sep));
}

export function scopeContains(
  boundary: readonly string[],
  resource: string,
): boolean {
  if (boundary.length === 0) return true;
  return boundary.some((scope) => prefixContains(scope, resource));
}

/**
 * Does `capabilities` hold `capability` (exact membership)? THE capability matcher;
 * {@link hasCapability} delegates here, for the same reason.
 */
export function capsContain(
  capabilities: readonly string[],
  capability: string,
): boolean {
  return capabilities.includes(capability);
}

export function isInScope(vaid: Vaid, resource: string): boolean {
  return scopeContains(vaid.scope_boundary, resource);
}

/**
 * Does this VAID hold `capability` (exact membership)? The single
 * capability-membership predicate.
 */
export function hasCapability(vaid: Vaid, capability: string): boolean {
  return capsContain(vaid.capability_set, capability);
}

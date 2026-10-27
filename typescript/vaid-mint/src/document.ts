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
/**
 * v4 (ADR-0009) types `scope_boundary`: its entries become
 * `{"kind": ..., "value": ...}` objects rather than bare strings. The v3 constant
 * is removed for exactly the reason the v2 one was, and keeping both would also be
 * forbidden: ADR-0010 states a verifier MAY accept two `sig_version` values only
 * where they require the SAME members. A v3 boundary's entries are strings; a v4
 * boundary's are objects, so `{3, 4}` is forbidden and there is no legacy
 * acceptance to write.
 */
export const VAID_SIG_VERSION_V4 = 4;

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
  scope_boundary: ScopeBoundaryEntry[];
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
  scopeBoundary: readonly ScopeBoundaryEntry[];
  lineageHash: string;
  capabilitySet: readonly string[];
  trustDomain: string;
  kernelKeyThumbprint: string;
}): Vaid {
  return {
    sig_version: VAID_SIG_VERSION_V4,
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
  const expires = parseRfc3339(vaid.expires_at);
  if (expires === null) return true;
  return now.getTime() > expires;
}

/**
 * RFC 3339 requires an offset. `Date.parse` does not.
 *
 * ECMAScript parses a date-time string with **no** offset as **local time**
 * (ECMA-262, Date Time String Format), so `Date.parse('2999-01-01T00:00:00')`
 * returns a different instant on every machine, and never the one the signer
 * wrote — they wrote no instant at all. Two consequences, both found by the
 * `chain_expiry_v1` vector rather than reasoned about:
 *
 * 1. **This implementation disagreed with the other two.** Python's
 *    `_parse_rfc3339` returns `None` for a naive timestamp and Rust's
 *    `DateTime::parse_from_rfc3339` refuses it, so both call such a document
 *    EXPIRED — fail closed. TypeScript called it live, for as long as the
 *    offsetless local time said so.
 * 2. **The verdict depended on the verifier's timezone.** The same document and
 *    the same comparison gave `refused` on a UTC+2 laptop and `permitted` on a
 *    UTC CI runner. A verifier whose answer moves with the machine is not a
 *    verifier.
 *
 * So the offset is required here, explicitly, rather than inherited from whatever
 * `Date.parse` is lenient about. Everything RFC 3339 does allow — `Z`, `+00:00`,
 * `-05:00`, fractional seconds, lower-case `t`/`z` — still parses, because the
 * profile question (E.6) is asked separately by {@link hasConformingTimestamps}
 * and a non-conforming timestamp must still verify if its signer signed it.
 *
 * Returns epoch milliseconds, or `null` if the value is not a readable RFC 3339
 * timestamp. Total: never throws.
 */
export function parseRfc3339(value: string | null | undefined): number | null {
  if (typeof value !== 'string') return null;
  // An offset is mandatory: `Z`/`z`, or ±HH:MM after the time.
  if (!/(?:[Zz]|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
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
 * The one scope-boundary kind v4 defines: today's resource-prefix semantics,
 * unchanged from the bare-string form it replaces (spec S.3).
 */
export const SCOPE_KIND_PREFIX = 'prefix';

/**
 * THE recognised-kind registry (spec S.7, S.10).
 *
 * Stated once, and consulted by both the matcher ({@link scopeContains}) and the
 * standing verdict ({@link verifyVaidStanding}). Two copies of this list is how a
 * kind gets recognised by one and not the other, which is the fail-closed rule of
 * S.10 failing open. `scope_kinds_v1.json` declares the same list and is checked
 * against this constant directly, so a kind added here without being added to the
 * specification fails conformance, and so does the reverse.
 */
export const RECOGNISED_SCOPE_KINDS: readonly string[] = [SCOPE_KIND_PREFIX];

/** The members a boundary entry carries, and no others (spec S.8). */
const ENTRY_MEMBERS: readonly string[] = ['kind', 'value'];

/**
 * One typed entry of a {@link Vaid}'s `scope_boundary` (spec S.8).
 *
 * ```json
 * { "kind": "prefix", "value": "orders/123/" }
 * ```
 *
 * `kind` names the sort of boundary; `value`'s JSON type is fixed by the kind. An
 * entry carries NO other member, and the shape gate below refuses one that does.
 */
export interface ScopeBoundaryEntry {
  kind: string;
  value: unknown;
}

/** A `prefix` entry over `value`. The only kind v4 defines. */
export function prefixEntry(value: string): ScopeBoundaryEntry {
  return { kind: SCOPE_KIND_PREFIX, value };
}

/**
 * Is `entry` a well-formed boundary entry (spec S.8)?
 *
 * An object with EXACTLY `kind` (a non-empty string) and `value`, whose type is
 * fixed by the kind. For a RECOGNISED kind the value type is checked here, so a
 * `prefix` entry carrying a number makes the document unparseable. For an
 * unrecognised kind the value is NOT inspected: this implementation does not know
 * what type a later kind's value takes, and guessing would mean refusing an
 * authentic future document for a reason it invented. That entry is well formed,
 * and S.10 refuses it at verify instead.
 *
 * This is the TypeScript half of the gate Rust gets from `serde`'s typed struct
 * plus `deny_unknown_fields`. Without it the three implementations would answer
 * different questions about a malformed boundary and a conformance vector
 * comparing them would be comparing nothing.
 *
 * The member set being EXACT is the S.11 asymmetry with ADR-0006. At DOCUMENT
 * level an unknown member is preserved, because it sits outside every predicate a
 * verifier computes. Inside an entry there is no outside: every member is part of
 * the authority the entry states, so a verifier that ignored
 * `{"kind": "prefix", "value": "a", "max": 5}` would compute a boundary strictly
 * wider than the one the signer committed to, and would do it silently.
 */
export function isWellFormedScopeEntry(entry: unknown): entry is ScopeBoundaryEntry {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return false;
  const keys = Object.keys(entry as Record<string, unknown>);
  if (keys.length !== ENTRY_MEMBERS.length) return false;
  if (!ENTRY_MEMBERS.every((m) => keys.includes(m))) return false;
  const { kind, value } = entry as { kind: unknown; value: unknown };
  if (typeof kind !== 'string' || kind === '') return false;
  if (kind === SCOPE_KIND_PREFIX && typeof value !== 'string') return false;
  return true;
}

/**
 * Is `boundary` a well-formed `scope_boundary` (spec S.8)?
 *
 * An array of well-formed entries. There is no per-entry fallback: one malformed
 * entry is a malformed boundary, which is what makes the bare-string form of v3
 * refused outright rather than reinterpreted.
 */
export function isWellFormedScopeBoundary(
  boundary: unknown,
): boundary is ScopeBoundaryEntry[] {
  return Array.isArray(boundary) && boundary.every(isWellFormedScopeEntry);
}

/**
 * The resource a child entry CLAIMS, for the attenuation predicate. `null` when
 * the entry is not one this implementation can evaluate.
 *
 * For the `prefix` kind a boundary and a resource are the same shape, which is why
 * attenuation has always been decidable with the containment predicate: a child
 * entry is fed to the matcher as if it were a resource, so mint-time and
 * verify-time cannot answer differently. A future kind whose boundary is not
 * resource-shaped will need its own containment rule rather than this projection;
 * `docs/spec/scope.md` S.13 records that as a constraint on the next revision.
 *
 * This is the module's SECOND and last branch on `kind`.
 * `every registered kind is evaluable` asserts that it and {@link entryContains}
 * both answer for every name in {@link RECOGNISED_SCOPE_KINDS}.
 */
export function entryClaimedResource(entry: ScopeBoundaryEntry): string | null {
  if (entry === null || typeof entry !== 'object') return null;
  if (entry.kind !== SCOPE_KIND_PREFIX) return null;
  return typeof entry.value === 'string' ? entry.value : null;
}

/**
 * Evaluate ONE entry against `resource`.
 *
 * `null` means this implementation cannot evaluate the entry at all: its kind is
 * not in {@link RECOGNISED_SCOPE_KINDS}, or it is of a recognised kind whose
 * `value` is not the type that kind fixes. This is the only place a kind's
 * containment rule is written; adding a kind means adding a branch here and a name
 * to the registry.
 */
function entryContains(entry: ScopeBoundaryEntry, resource: string): boolean | null {
  if (entry === null || typeof entry !== 'object') return null;
  if (entry.kind !== SCOPE_KIND_PREFIX) return null;
  if (typeof entry.value !== 'string') return null;
  return prefixContains(entry.value, resource);
}

/**
 * Can `entry` be evaluated here at all?
 *
 * DERIVED from {@link entryContains} rather than restated, so a kind cannot be
 * added to one and forgotten in the other. Whether `entryContains` returns a
 * verdict is a property of the entry alone and never of the resource, which is
 * what makes deriving it from a single arbitrary resource exact rather than
 * approximate; `evaluability does not depend on the resource` asserts that over
 * every boundary in the conformance vector.
 */
export function entryIsEvaluable(entry: ScopeBoundaryEntry): boolean {
  return entryContains(entry, '') !== null;
}

/**
 * Can every entry of `boundary` be evaluated here (spec S.10)?
 *
 * `false` is the S.10 refusal condition, and it is a property of the boundary
 * alone: a verifier reports it over a document rather than over a request, so the
 * standing verdict can reach it without having a resource in hand.
 */
export function boundaryIsEvaluable(boundary: readonly ScopeBoundaryEntry[]): boolean {
  return boundary.every(entryIsEvaluable);
}

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

/**
 * Is `resource` within `boundary`? An empty boundary means unrestricted (⊤).
 *
 * **An entry this implementation cannot read refuses the WHOLE boundary** (S.10),
 * not just itself. The natural implementation of a union is `some()`, and the
 * natural implementation returns `true` for a boundary of a satisfied `prefix`
 * entry plus one unrecognised entry: it finds the match and never reaches the
 * entry it cannot read. An unrecognised kind can only ever NARROW what the signer
 * meant, so skipping it grants authority the signer withheld. The loop below
 * therefore refuses on the first unevaluable entry even when a match is already in
 * hand. This is reachable from a bare boundary that never passed document verify,
 * so the refusal lives here and not only in the standing verdict.
 */
export function scopeContains(
  boundary: readonly ScopeBoundaryEntry[],
  resource: string,
): boolean {
  let contained = false;
  for (const entry of boundary) {
    const verdict = entryContains(entry, resource);
    // S.10: refuse the whole boundary, even with a match already found.
    if (verdict === null) return false;
    contained = contained || verdict;
  }
  return boundary.length === 0 || contained;
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

/**
 * The mint: issue a root VAID, and mint attenuated child VAIDs. TypeScript
 * mirror of the Rust `vaid_mint::mint`.
 *
 * {@link MintService} wraps a {@link VaidIssuer} and an {@link AuditSink}. Two
 * entry points:
 *
 * - {@link MintService.mintRoot} — mint a root (or operator) VAID. BYO-key with
 *   a verified proof-of-possession, or the generate-and-discard path.
 * - {@link MintService.mintChild} — **attenuated delegation**: an authenticated
 *   parent `P` mints a child `C` iff `C`'s tenant, lineage, scope, and
 *   capabilities are all within `P`'s, verified fail-closed BEFORE any key work
 *   or nonce consumption. `child ⊆ parent`, always.
 *
 * The attenuation predicates use the SINGLE scope/capability matchers on the
 * document ({@link isInScope} / {@link hasCapability}), so mint-time containment
 * and any runtime scope check cannot drift.
 */

import { utcWholeSecondRfc3339, verifySignedPayload, type Rfc3339Utc } from 'vaid-pop';

import type { AuditSink } from './audit.js';
import { PermitAll, type AuthorizationGate } from './authz.js';
import { hasCapability, isInScope, type Vaid } from './document.js';
import { IdentityError, UnauthorizedError } from './error.js';
import type { VaidIssuer } from './issuer.js';
import {
  buildMintPopPayload,
  type MintPop,
  type MintVaidRequest,
  type MintVaidResponse,
  type VaidSeed,
} from './mintTypes.js';

/**
 * Freshness window for a mint proof-of-possession, in seconds. A PoP whose
 * `issuedAt` is more than this from now (either direction) is rejected, so a
 * captured request is not mintable indefinitely.
 */
export const MINT_POP_FRESHNESS_SECS = 300;

/**
 * Scope attenuation: is every entry of `childScope` within `parent`'s scope? Uses
 * ONLY {@link isInScope} — the single scope matcher.
 *
 * The empty-child guard closes an escalation: an empty child scope means
 * *unrestricted* (⊤), so a naive `every()` over zero entries is vacuously true
 * and would mint an unrestricted child under a *restricted* parent — broader than
 * the parent. Fail closed: an empty child scope is permitted ONLY when the parent
 * is itself unrestricted (empty).
 */
export function scopeAttenuates(parent: Vaid, childScope: readonly string[]): boolean {
  if (childScope.length === 0) {
    // Child wants ⊤; allowed only if the parent is also ⊤.
    return parent.scope_boundary.length === 0;
  }
  return childScope.every((scope) => isInScope(parent, scope));
}

/**
 * Capability attenuation: is every entry of `childCaps` held by `parent`? Uses
 * ONLY {@link hasCapability} (exact membership).
 *
 * No empty-child guard is needed (and deliberately none is added): capabilities
 * are explicit grants where empty = ∅ (least privilege), so an empty child set is
 * safe by construction; and an empty *parent* set holds nothing, so every
 * requested child capability is rejected. This is the deliberate scope/caps
 * asymmetry — scope empty = ⊤ needs a guard, caps empty = ∅ does not.
 */
export function capsAttenuate(parent: Vaid, childCaps: readonly string[]): boolean {
  return childCaps.every((capability) => hasCapability(parent, capability));
}

/**
 * The mint service. Holds the issuer (kernel signer) and the audit sink, plus the
 * single-use PoP nonce set (at-mint replay defense).
 */
export class MintService {
  readonly #issuer: VaidIssuer;
  readonly #audit: AuditSink;
  /**
   * Root-mint authorization seam. Defaults to {@link PermitAll} — a
   * reference-implementation choice, NOT a security recommendation.
   */
  readonly #authz: AuthorizationGate;
  readonly #consumedPopNonces = new Set<string>();

  /**
   * Construct with an optional root-mint {@link AuthorizationGate}. Omitting it
   * selects {@link PermitAll} — convenient for tests and local self-hosting; a
   * production deployment should supply a real gate. This is the seam that closes
   * the "mintRoot has no authorization" gap visibly rather than silently.
   */
  constructor(issuer: VaidIssuer, audit: AuditSink, authz: AuthorizationGate = new PermitAll()) {
    this.#issuer = issuer;
    this.#audit = audit;
    this.#authz = authz;
  }

  /**
   * Proof-of-possession at mint. Verifies the caller controls the private key
   * matching `registeredKey` before the VAID is issued. Order:
   *
   * 1. **present** — a BYO-key mint without a `pop` is rejected;
   * 2. **fresh** — `issuedAt` within {@link MINT_POP_FRESHNESS_SECS} of now;
   * 3. **not replayed** — single-use nonce, recorded before the signature is
   *    accepted (record-before-process) so a concurrent replay cannot slip in;
   * 4. **signature** — the holder's signature over the canonical mint-PoP payload
   *    verifies against `registeredKey`.
   *
   * The holder's private key never enters mint state — only the public key and
   * the detached signature.
   */
  #verifyPopAtMint(seed: VaidSeed, registeredKey: Uint8Array, pop: MintPop | null | undefined): void {
    if (!pop) {
      throw new IdentityError(
        'proof-of-possession required — publicKeyDer was supplied (BYO-key) without a `pop` signature',
      );
    }

    // (2) Freshness.
    const issuedAtMs = Date.parse(pop.issuedAt);
    if (Number.isNaN(issuedAtMs)) {
      throw new IdentityError(`PoP issuedAt is not a parseable RFC 3339 timestamp: ${pop.issuedAt}`);
    }
    const skew = Math.abs(Math.trunc((Date.now() - issuedAtMs) / 1000));
    if (skew > MINT_POP_FRESHNESS_SECS) {
      throw new IdentityError(
        `PoP timestamp outside freshness window (${skew}s > ${MINT_POP_FRESHNESS_SECS}s)`,
      );
    }

    // (3) Replay — check-and-insert. Record before accepting the signature.
    if (this.#consumedPopNonces.has(pop.nonce)) {
      throw new IdentityError('PoP nonce already used — replay rejected');
    }
    this.#consumedPopNonces.add(pop.nonce);

    // (4) Signature over the canonical payload, against the REGISTERED key.
    const payload = buildMintPopPayload(seed, {
      publicKeyDer: registeredKey,
      nonce: pop.nonce,
      issuedAt: pop.issuedAt,
    });
    if (!verifySignedPayload(payload, registeredKey, pop.signature)) {
      throw new IdentityError(
        'PoP signature does not verify against the registered public key — ' +
          'cannot register a key you do not control',
      );
    }
  }

  /**
   * Mint a root (or operator) VAID. The root-mint {@link AuthorizationGate} is
   * consulted first (defaults to {@link PermitAll}); then, when
   * `seed.publicKeyDer` is present, this is a BYO-key mint and a valid
   * {@link MintPop} is required; otherwise the issuer generates a keypair and
   * discards the private half.
   */
  async mintRoot(request: MintVaidRequest): Promise<MintVaidResponse> {
    const seed = request.seed;

    // Root-mint authorization seam (defaults to PermitAll). Runs first, before
    // any key work or nonce consumption, so a denied mint has no side effects.
    await this.#authz.authorizeRootMint(seed);

    const attributes = seedAttributes(seed);
    const byoKey = seed.publicKeyDer != null;

    let vaid: Vaid;
    if (seed.publicKeyDer != null) {
      // BYO-key: prove possession of the matching private key before issue.
      this.#verifyPopAtMint(seed, seed.publicKeyDer, request.pop);
      vaid = this.#issuer.issueVaidWithKey(attributes, seed.publicKeyDer);
    } else {
      // Generate-and-discard: no holder key registered, so no PoP applies.
      vaid = this.#issuer.issueVaidWithLineage(attributes);
    }

    await this.#audit.record('vaid_minted', {
      agent_class: seed.agentClass,
      version: seed.version,
      tenant_id: seed.tenantId,
      parent_vaid: attributes.parentVaid,
      scope_boundary: attributes.scopeBoundary,
      capability_set_len: attributes.capabilitySet.length,
      byo_key: byoKey,
      pop_verified: byoKey,
      delegated: false,
    });

    return { vaid };
  }

  /**
   * Attenuated intra-tenant delegation. An authenticated parent VAID `P` mints a
   * child `C` iff — checked fail-closed BEFORE any key work or nonce
   * consumption — every condition holds:
   *
   * 1. **parent present** — a verified parent travelled in context; absent → deny;
   * 2. `C.tenant == P.tenant` — same tenant, from the VERIFIED parent, never the body;
   * 3. `C.parentVaid == P.vaid_id` — lineage bound to the authenticated parent;
   * 4. `C.scope ⊆ P.scope` — {@link scopeAttenuates};
   * 5. `C.caps ⊆ P.caps` — {@link capsAttenuate};
   * 6. child **BYO-key PoP** holds — `mintChild` is always BYO-key.
   *
   * Attenuation (2–5) runs BEFORE the PoP so a rejected delegation never consumes
   * a nonce. The child is issued with `parent_vaid` set (the issuer records
   * lineage), and a *delegated* audit entry is emitted.
   */
  async mintChild(
    request: MintVaidRequest,
    parent: Vaid | null | undefined,
  ): Promise<MintVaidResponse> {
    // (1) The parent's authority must have travelled — fail closed.
    if (!parent) {
      throw new UnauthorizedError(
        'no verified parent VAID in context — delegation requires an ' +
          'authenticated parent principal, fail-closed',
      );
    }
    const seed = request.seed;
    const attributes = seedAttributes(seed);

    // (2) Same tenant, grounded in the parent's VERIFIED VAID — never the body.
    if (seed.tenantId !== parent.tenant_id) {
      throw new UnauthorizedError(
        `child tenant '${seed.tenantId}' != authenticated parent tenant ` +
          `'${parent.tenant_id}' — cross-tenant delegation is denied`,
      );
    }

    // (3) Lineage bound to the AUTHENTICATED parent, not a claimed field.
    if (attributes.parentVaid !== parent.vaid_id) {
      throw new UnauthorizedError(
        `child parent_vaid ${JSON.stringify(attributes.parentVaid)} must equal the ` +
          `authenticated parent vaid_id ${parent.vaid_id} — the parent comes from ` +
          'the verified VAID, never the body',
      );
    }

    // (4) Scope attenuation — single `isInScope`, empty-child guard.
    if (!scopeAttenuates(parent, attributes.scopeBoundary)) {
      throw new UnauthorizedError(
        "child scope_boundary exceeds the parent's — least-privilege attenuation denied",
      );
    }

    // (5) Capability attenuation — single `hasCapability`.
    if (!capsAttenuate(parent, attributes.capabilitySet)) {
      throw new UnauthorizedError(
        "child capability_set exceeds the parent's — least-privilege attenuation denied",
      );
    }

    // (6) Child BYO-key PoP. Runs AFTER attenuation: an unauthorized delegation
    // must not burn a nonce. mintChild is always BYO-key.
    if (seed.publicKeyDer == null) {
      throw new IdentityError(
        'BYO-key required — a delegated child registers the parent-held child ' +
          'public key with a proof-of-possession',
      );
    }
    this.#verifyPopAtMint(seed, seed.publicKeyDer, request.pop);

    // (7) Issue the attenuated child. parentVaid is set → lineage recorded.
    const vaid = this.#issuer.issueVaidWithKey(attributes, seed.publicKeyDer);

    // (8) Delegated audit — distinguishes the delegation tree from root mints.
    await this.#audit.record('vaid_minted', {
      agent_class: seed.agentClass,
      version: seed.version,
      parent_vaid: attributes.parentVaid,
      scope_boundary: attributes.scopeBoundary,
      capability_set_len: attributes.capabilitySet.length,
      byo_key: true,
      pop_verified: true,
      delegated: true,
      attenuation_verified: true,
      parent_tenant: parent.tenant_id,
    });

    return { vaid };
  }
}

/**
 * Normalize a seed's optional fields into the total shape the issuer needs.
 * Doing it in one place is what keeps "absent" and "empty" from being read
 * differently by the attenuation checks and the issuer — an empty scope means ⊤,
 * so the two must never disagree about which one they were handed.
 */
function seedAttributes(seed: VaidSeed): {
  agentClass: string;
  version: string;
  tenantId: string;
  parentVaid: string | null;
  scopeBoundary: string[];
  capabilitySet: string[];
} {
  return {
    agentClass: seed.agentClass,
    version: seed.version,
    tenantId: seed.tenantId,
    parentVaid: seed.parentVaid ?? null,
    scopeBoundary: [...(seed.scopeBoundary ?? [])],
    capabilitySet: [...(seed.capabilitySet ?? [])],
  };
}

/**
 * The whole-second RFC 3339 timestamp a holder should stamp into a
 * {@link MintPop}. Re-exported from `vaid-pop` so a caller building a PoP does
 * not have to reach for the transport package to get the one timestamp format
 * the signed bytes accept.
 */
export function mintPopTimestamp(now: Date = new Date()): Rfc3339Utc {
  return utcWholeSecondRfc3339(now);
}

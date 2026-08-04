/**
 * Third-party end-to-end lineage verification, by **detached chain presentation**
 * (ADR-0003). Mirror of the Rust `vaid_mint::chain` and the Python
 * `vaid_mint.chain`.
 *
 * {@link verifyVaidAuthenticity} answers "is this document real". It cannot answer
 * "was the authority written into it legitimately derived from its parent's" — a
 * leaf carries its own `scope_boundary` and `capability_set`, not its ancestors'.
 * Under that alone, attenuation is a property of the mint's word.
 *
 * This module closes that without touching the document format. The **presenter**
 * supplies the ancestor documents alongside the leaf; the verifier walks them. No
 * new signed field, no `mint_v1` re-freeze, no `sig_version` bump.
 *
 * ## Why no document field is needed
 *
 * The leaf does not carry its ancestors' authority, but it carries their
 * **identity, signed**:
 *
 * - `parent_vaid` is inside the canonical signing bytes, so it cannot be altered
 *   without breaking the kernel signature;
 * - {@link verifyLineageHash} independently recomputes `lineage_hash` from
 *   `parent_vaid` and `agent_id`, so an inconsistent value is caught explicitly
 *   rather than incidentally.
 *
 * An ancestor VAID is itself a kernel-signed, self-authenticating statement of its
 * own authority. The verifier does not need the leaf to *describe* its ancestors;
 * it needs the ancestors, plus a pinned reference saying which ones are real. Both
 * already exist.
 *
 * ## Chain substitution is prevented by the existing signature
 *
 * To present a more privileged parent, an adversary needs a kernel-signed document
 * whose `vaid_id` equals the `parent_vaid` pinned inside the leaf's signed bytes.
 * Because `vaid_id` equals `agent_id` and is a fresh UUIDv4 per mint, that requires
 * a kernel-key compromise or a UUID collision. No new field contributes to this
 * property; the pin is already signed.
 *
 * ## Relationship to R.4.2
 *
 * `docs/spec/revocation.md` R.4.2 says the full lineage is not recoverable from the
 * VAID itself, and that assembly needs a resolver whose reference implementation is
 * the issuer's in-process lineage map — precisely what a third party lacks. That is
 * true **for revocation**, where assembly starts from a bare identifier and must
 * resolve upward.
 *
 * It is not a constraint here. The presenter supplies documents rather than
 * identifiers, and every document carries its own `parent_vaid`, so the resolver
 * becomes a lookup over the presented bundle. No issuer, no network, no new
 * protocol: {@link PresentedBundle} is a new implementation of the existing
 * {@link LineageResolver}, and the three-state shape is already correct.
 */

import { type Vaid } from './document.js';
import { capsAttenuate, scopeAttenuates, tenantAttenuates } from './mint.js';
import {
  assembleLineage,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  type LineageResolver,
  type ParentResolution,
} from './revocation.js';
import { verifyVaidAuthenticity } from './verify.js';

import { type VaidId } from 'vaid-pop';

/**
 * The outcome of an end-to-end chain verification.
 *
 * Only `Attenuated` is success. The three failure states are kept apart
 * deliberately, because collapsing them is how a verifier ends up reporting
 * *attenuation satisfied* when it means *attenuation unverifiable* — the same
 * conflation R.4.2 forbids for revocation.
 */
export const ChainVerification = {
  /**
   * Every presented document is authentic, the chain assembles completely from the
   * leaf to a root, and authority is contained at every hop.
   */
  Attenuated: 'attenuated',
  /**
   * A presented document — or the leaf — failed {@link verifyVaidAuthenticity}.
   * Nothing further was checked.
   */
  Inauthentic: 'inauthentic',
  /**
   * The chain could not be assembled: an ancestor named by a signed `parent_vaid`
   * was not presented, or assembly hit a cycle or `MAX_LINEAGE_DEPTH`. Means
   * **attenuation unverifiable** — never attenuation satisfied.
   */
  Unverifiable: 'unverifiable',
  /**
   * The chain is complete and authentic, but some child claims authority its parent
   * does not hold.
   */
  NotAttenuated: 'not_attenuated',
} as const;

export type ChainVerification =
  (typeof ChainVerification)[keyof typeof ChainVerification];

/**
 * Whether the chain verified. Provided so callers do not treat a non-success state
 * as acceptance by accident.
 */
export function isAttenuated(result: ChainVerification): boolean {
  return result === ChainVerification.Attenuated;
}

/**
 * The ancestor documents a presenter supplies alongside a leaf, indexed by
 * `vaid_id`. The third-party stand-in for the issuer's in-process lineage map: it
 * resolves ancestry from documents the presenter already holds, so no issuer and no
 * network are involved.
 *
 * Implements {@link LineageResolver}, so {@link assembleLineage} — including its
 * cycle detection and its `MAX_LINEAGE_DEPTH` bound — is reused unchanged.
 *
 * The bundle need not contain the leaf: {@link verifyChain} takes the leaf
 * separately, and `assembleLineage` reads the leaf's parent from the leaf's own
 * signed document, only resolving hops **above** it through this bundle.
 */
export class PresentedBundle implements LineageResolver {
  readonly #documents: Map<VaidId, Vaid>;

  /**
   * Build a bundle from the presented ancestor documents.
   *
   * Documents are keyed by their own `vaid_id`. A later document with a `vaid_id`
   * already present replaces the earlier one; this cannot be used to substitute a
   * more privileged ancestor, because every document on the assembled chain is
   * authenticated against the kernel key and pinned by a signed `parent_vaid` (see
   * the module docs).
   */
  constructor(documents: Iterable<Vaid> = []) {
    this.#documents = new Map();
    for (const doc of documents) {
      this.#documents.set(doc.vaid_id, doc);
    }
  }

  /** Look up a presented document by `vaid_id`. */
  get(vaidId: VaidId): Vaid | undefined {
    return this.#documents.get(vaidId);
  }

  /** Every presented document, in insertion order. */
  documents(): Vaid[] {
    return [...this.#documents.values()];
  }

  /** Number of presented documents. */
  get size(): number {
    return this.#documents.size;
  }

  /**
   * Resolve one hop from the presented documents. A presented document with no
   * `parent_vaid` is a **known root**; one with a `parent_vaid` is a **child**; an
   * id that was not presented is **unknown** — the R.4.2 distinction, which is what
   * makes an incomplete presentation fail closed instead of looking like a
   * legitimately rootless VAID.
   */
  resolveParent(vaidId: VaidId): ParentResolution {
    const doc = this.#documents.get(vaidId);
    if (doc === undefined) return parentResolutionUnknown();
    if (doc.parent_vaid === null) return parentResolutionRoot();
    return parentResolutionOf(doc.parent_vaid);
  }
}

/**
 * Verify a full delegation chain end to end, as a third party holding only the
 * issuer's kernel **public** key and the documents the presenter supplied.
 *
 * The procedure is ADR-0003's, in order:
 *
 * 1. **Authenticate every document** — the leaf and every presented ancestor, via
 *    {@link verifyVaidAuthenticity}. Any failure is `Inauthentic`.
 * 2. **Pin each hop** — {@link assembleLineage} requires a presented document whose
 *    `vaid_id` equals the `parent_vaid` pinned inside the child's signed bytes, and
 *    recurses until a document with no `parent_vaid` is reached.
 * 3. **Fail closed on an incomplete chain** — a `parent_vaid` that is present but
 *    not resolvable, a cycle, or an implausible depth all yield `Unverifiable`.
 * 4. **Check containment** — `scope_L ⊆ scope_P1 ⊆ … ⊆ scope_root`, and the same for
 *    capabilities, using the **mint-time** matchers ({@link scopeAttenuates} /
 *    {@link capsAttenuate}) so the verify-time check cannot drift from the one that
 *    gated issuance.
 *
 * ## What this does not check
 *
 * Consistent with {@link verifyVaidAuthenticity}, this answers *authenticity and
 * attenuation*, not *standing*. It does not consult **expiry** (call
 * `isExpired`) and does not consult **revocation** (evaluate a `RevocationCheck`
 * separately). A third party generally cannot assemble lineage for revocation from
 * identifiers alone — that is the R.4.2 constraint, and it is unchanged here.
 *
 * ## Single trust domain
 *
 * All documents on the chain must be signed by `kernelPublicKey`. Each document's
 * `kernel_key_thumbprint` is checked against that key inside
 * {@link verifyVaidAuthenticity}, so a chain crossing issuers returns `Inauthentic`
 * rather than being accepted under a key that did not sign it. Verifying a chain
 * whose hops were signed by *different* kernel keys would need a key-lookup seam
 * keyed on `kernel_key_thumbprint`; that is not built here, and until it is,
 * cross-issuer chains are out of scope rather than silently mis-verified.
 */
export function verifyChain(
  kernelPublicKey: Uint8Array,
  leaf: Vaid,
  bundle: PresentedBundle,
): ChainVerification {
  // Step 1 — authenticate the leaf and EVERY presented document, before any of them
  // is allowed to influence assembly. Authenticating the whole bundle rather than
  // only the documents that end up on the chain is the stricter reading of ADR-0003
  // step 1, and it means a presenter cannot mix an unauthenticated document into a
  // bundle and have it ignored.
  if (!verifyVaidAuthenticity(kernelPublicKey, leaf)) {
    return ChainVerification.Inauthentic;
  }
  for (const doc of bundle.documents()) {
    if (!verifyVaidAuthenticity(kernelPublicKey, doc)) {
      return ChainVerification.Inauthentic;
    }
  }

  // Steps 2 and 3 — pin each hop against the signed `parent_vaid`, failing closed on
  // any gap. Cycle detection and MAX_LINEAGE_DEPTH come from `assembleLineage`
  // unchanged.
  const chainIds = assembleLineage(leaf, bundle);
  if (chainIds === null) {
    return ChainVerification.Unverifiable;
  }

  // Resolve each id on the chain back to its document, root first. The leaf is
  // supplied separately and need not appear in the bundle, so it is matched first.
  // Any id that cannot be resolved to a document is a gap, and a gap is
  // `Unverifiable` — never a silently shortened chain.
  const chainDocs: Vaid[] = [];
  for (const id of chainIds) {
    if (id === leaf.vaid_id) {
      chainDocs.push(leaf);
      continue;
    }
    const doc = bundle.get(id);
    if (doc === undefined) {
      return ChainVerification.Unverifiable;
    }
    chainDocs.push(doc);
  }

  // Step 4 — containment at every hop, root first, using the mint-time matchers.
  //
  // Tenant is checked as the qualified `(trust_domain, tenant_id)` pair. The mint
  // refuses cross-tenant delegation, so a conforming chain cannot change tenant
  // mid-walk; checking it here means a verifier does not have to take the mint's
  // word for that — the same reasoning that puts scope and capabilities here. See
  // `tenantAttenuates` for what the guarantee is worth: defence against operator
  // error, not against a hostile issuer.
  for (let i = 0; i + 1 < chainDocs.length; i += 1) {
    const parent = chainDocs[i]!;
    const child = chainDocs[i + 1]!;
    if (!tenantAttenuates(parent, child.trust_domain, child.tenant_id)) {
      return ChainVerification.NotAttenuated;
    }
    if (!scopeAttenuates(parent, child.scope_boundary)) {
      return ChainVerification.NotAttenuated;
    }
    if (!capsAttenuate(parent, child.capability_set)) {
      return ChainVerification.NotAttenuated;
    }
  }

  return ChainVerification.Attenuated;
}

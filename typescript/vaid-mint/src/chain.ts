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

import {
  AttestationBundle,
  isCurrent,
  verifyAttestationAuthenticity,
} from './attestation.js';
import { type Vaid } from './document.js';
import { kernelKeyThumbprint } from './issuerIdentity.js';
import {
  capsAttenuate,
  capsAttenuateWithin,
  scopeAttenuates,
  scopeAttenuatesWithin,
  tenantAttenuates,
} from './mint.js';
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
  /**
   * A cross-key hop's consent attestation is **authentic but outside its validity
   * window** — lapsed, or not yet valid beyond the permitted clock skew.
   *
   * Kept distinct on purpose. An expired attestation is not forged: the parent
   * really did sign it, so `Inauthentic` would misdescribe it. Nor did the child
   * overreach, so `NotAttenuated` would be wrong too. The operational difference is
   * the point — this says *renew the attestation*, the other two say *you were never
   * authorized*. **Not withdrawal:** see the `attestation` module.
   */
  ConsentExpired: 'consent_expired',
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
/**
 * Resolves the kernel public key that signed a document, by its
 * `kernel_key_thumbprint`.
 *
 * **Why a seam and not a parameter.** A single-issuer chain needs one key and could
 * take it as an argument — which is what {@link verifyChain} does. A chain that
 * crosses organisations needs the key that signed *each* document, selected by the
 * thumbprint the document commits to (ADR-0004). That selection is the verifier's
 * trust decision and belongs to the caller.
 *
 * **Returning a key is an assertion of trust.** A resolver answering for a
 * thumbprint is saying "I accept documents signed by this key". Resolving it from
 * the document itself, or any source the presenter controls, verifies that a number
 * equals itself — see `docs/trust-anchor.md`.
 */
export interface KernelKeyResolver {
  /**
   * The raw 32-byte Ed25519 public key for `thumbprint`, or `undefined` if this
   * verifier does not accept that key. `undefined` fails closed.
   */
  resolveKey(thumbprint: string): Uint8Array | undefined;
}

/**
 * A resolver holding exactly one kernel key: the single-trust-domain case, and what
 * {@link verifyChain} wraps.
 */
export class SingleKernelKey implements KernelKeyResolver {
  readonly #thumbprint: string;
  readonly #publicKey: Uint8Array;

  /** The thumbprint is derived from the key, so the two cannot disagree. */
  constructor(publicKey: Uint8Array) {
    this.#thumbprint = kernelKeyThumbprint(publicKey);
    this.#publicKey = publicKey;
  }

  resolveKey(thumbprint: string): Uint8Array | undefined {
    return thumbprint === this.#thumbprint ? this.#publicKey : undefined;
  }
}

/**
 * A resolver over a map of accepted kernel keys, for chains that cross issuers.
 *
 * Every key placed here is one this verifier accepts. The map is the trust bundle;
 * populating it from a channel the presenter controls defeats the purpose.
 */
export class KernelKeyMap implements KernelKeyResolver {
  readonly #keys = new Map<string, Uint8Array>();

  /**
   * Each key is filed under its OWN derived thumbprint, so a key cannot be
   * registered under a thumbprint that is not its own.
   */
  constructor(publicKeys: Iterable<Uint8Array> = []) {
    for (const key of publicKeys) {
      this.#keys.set(kernelKeyThumbprint(key), key);
    }
  }

  resolveKey(thumbprint: string): Uint8Array | undefined {
    return this.#keys.get(thumbprint);
  }

  get size(): number {
    return this.#keys.size;
  }
}

/**
 * Verify a full delegation chain end to end against a **single** kernel key.
 *
 * Convenience over {@link verifyChainWith} for the single-trust-domain case: every
 * document must be signed by `kernelPublicKey`. Because no hop can cross a kernel
 * key, no consent attestation is required or consulted.
 */
export function verifyChain(
  kernelPublicKey: Uint8Array,
  leaf: Vaid,
  bundle: PresentedBundle,
): ChainVerification {
  return verifyChainWith(
    new SingleKernelKey(kernelPublicKey),
    leaf,
    bundle,
    new AttestationBundle(),
  );
}

/**
 * Verify a full delegation chain end to end, selecting a kernel key per document and
 * requiring parental consent for any hop that crosses one.
 *
 * ADR-0003's procedure, extended at the two points where crossing a kernel key
 * changes what can be concluded:
 *
 * 1. **Authenticate every document** — key selected from `keys` by the document's
 *    own `kernel_key_thumbprint`. An unaccepted thumbprint or a failed signature is
 *    `Inauthentic`.
 * 2. **Pin each hop** against the signed `parent_vaid`.
 * 3. **Fail closed on an incomplete chain** — `Unverifiable`.
 * 4. **Check containment** — tenant (same-key hops), scope, capabilities.
 * 5. **Require consent on a cross-key hop** — a valid {@link ConsentAttestation} for
 *    exactly that `(parent, child)` pair, signed by the issuer that minted the
 *    parent. Same-key hops need none: the single issuer enforced consent at mint.
 *
 * **Why step 5 exists.** Without it, an issuer B holding its own kernel key could
 * mint a document naming issuer A's root `vaid_id` as `parent_vaid`, with authority
 * inside A's, and have it verify as `Attenuated` — while A delegated nothing.
 *
 * **Verdict mapping.** Authenticity failures (missing consent, signed by a key that
 * did not issue the parent, naming another hop) are `Inauthentic`. Consent that is
 * authentic but outside its validity window is `ConsentExpired`. Authority failures
 * (consent narrower than the child claims, or broader than the parent holds) are
 * `NotAttenuated`. No cross-key hop reaches `Attenuated` without valid, current
 * consent.
 *
 * This overload uses the **system clock**; {@link verifyChainAt} takes an explicit
 * instant, and anything needing a reproducible verdict must use that.
 */
export function verifyChainWith(
  keys: KernelKeyResolver,
  leaf: Vaid,
  bundle: PresentedBundle,
  attestations: AttestationBundle,
): ChainVerification {
  return verifyChainAt(keys, leaf, bundle, attestations, new Date());
}

/**
 * Verify a full delegation chain end to end at an explicit instant, selecting a
 * kernel key per document and requiring parental consent for any hop that crosses
 * one. See {@link verifyChainWith} for the system-clock convenience wrapper and the
 * full procedure.
 *
 * `now` is explicit because expiry makes the verdict time-dependent. Anything that
 * needs a reproducible result — a conformance vector, a boundary test, replaying a
 * historical decision — must pass an instant rather than let the wall clock decide.
 */
export function verifyChainAt(
  keys: KernelKeyResolver,
  leaf: Vaid,
  bundle: PresentedBundle,
  attestations: AttestationBundle,
  now: Date,
): ChainVerification {
  // Step 1 — authenticate the leaf and EVERY presented document, before any of them
  // is allowed to influence assembly.
  const authenticate = (doc: Vaid): boolean => {
    const key = keys.resolveKey(doc.kernel_key_thumbprint);
    // An unaccepted issuer is not a degraded issuer, it is somebody else.
    return key === undefined ? false : verifyVaidAuthenticity(key, doc);
  };

  if (!authenticate(leaf)) return ChainVerification.Inauthentic;
  for (const doc of bundle.documents()) {
    if (!authenticate(doc)) return ChainVerification.Inauthentic;
  }

  // Steps 2 and 3 — pin each hop, failing closed on any gap. Cycle detection and
  // MAX_LINEAGE_DEPTH come from `assembleLineage` unchanged.
  const chainIds = assembleLineage(leaf, bundle);
  if (chainIds === null) return ChainVerification.Unverifiable;

  const chainDocs: Vaid[] = [];
  for (const id of chainIds) {
    if (id === leaf.vaid_id) {
      chainDocs.push(leaf);
      continue;
    }
    const doc = bundle.get(id);
    if (doc === undefined) return ChainVerification.Unverifiable;
    chainDocs.push(doc);
  }

  // Steps 4 and 5 — containment at every hop, root first, plus consent wherever a
  // hop crosses a kernel key.
  for (let i = 0; i + 1 < chainDocs.length; i += 1) {
    const parent = chainDocs[i]!;
    const child = chainDocs[i + 1]!;
    const sameKey = parent.kernel_key_thumbprint === child.kernel_key_thumbprint;

    // Tenant as the qualified pair — on SAME-KEY hops. A CROSS-KEY hop crosses trust
    // domains by definition, so requiring equality would forbid the very case
    // attestations exist to enable; the crossing is instead named and signed in the
    // attestation below. The pair is still checked on every hop — against a signed
    // statement rather than the parent's own values.
    if (sameKey && !tenantAttenuates(parent, child.trust_domain, child.tenant_id)) {
      return ChainVerification.NotAttenuated;
    }
    if (!scopeAttenuates(parent, child.scope_boundary)) {
      return ChainVerification.NotAttenuated;
    }
    if (!capsAttenuate(parent, child.capability_set)) {
      return ChainVerification.NotAttenuated;
    }

    // Same kernel key: one issuer signed both ends and enforced consent at mint
    // time. Behaviour unchanged from before cross-key support.
    if (sameKey) continue;

    // Cross-key hop. Consent must be presented, and must be the PARENT issuer's.
    const attestation = attestations.get(parent.vaid_id, child.vaid_id);
    if (attestation === undefined) {
      // Also the outcome for an attestation minted for a different hop: it is filed
      // under that hop's pair and is simply not found here. Replay is inert rather
      // than rejected.
      return ChainVerification.Inauthentic;
    }

    // The consenting party must be the party that issued the parent. Without this,
    // any accepted key could consent on any parent's behalf.
    if (
      attestation.kernel_key_thumbprint !== parent.kernel_key_thumbprint ||
      attestation.trust_domain !== parent.trust_domain
    ) {
      return ChainVerification.Inauthentic;
    }

    const attKey = keys.resolveKey(attestation.kernel_key_thumbprint);
    if (attKey === undefined || !verifyAttestationAuthenticity(attKey, attestation)) {
      return ChainVerification.Inauthentic;
    }

    // The consent must be current. Checked AFTER authenticity, so a forged
    // attestation is reported as forged rather than as merely stale — the stronger
    // statement is the more useful one.
    //
    // NOTE: this consults the ATTESTATION's window only. Document expiry is
    // deliberately not consulted here, exactly as elsewhere in this module; an
    // attestation may outlive the parent VAID it delegates from, and whether that
    // should change is a separate decision.
    if (!isCurrent(attestation, now)) {
      return ChainVerification.ConsentExpired;
    }

    // The consent must name the identity the child actually claims, or an
    // attestation for a child in one tenant would authorize the same vaid_id
    // claiming any other.
    if (
      attestation.child_trust_domain !== child.trust_domain ||
      attestation.child_tenant_id !== child.tenant_id
    ) {
      return ChainVerification.NotAttenuated;
    }

    // The child may hold no more than the parent consented to...
    if (
      !scopeAttenuatesWithin(attestation.scope_boundary, child.scope_boundary) ||
      !capsAttenuateWithin(attestation.capability_set, child.capability_set)
    ) {
      return ChainVerification.NotAttenuated;
    }

    // ...and the parent cannot consent to more than it holds. Checked separately
    // from the hop containment above: that compares child to parent, this compares
    // the ATTESTATION to parent — an over-broad attestation with a well-behaved
    // child would otherwise pass.
    if (
      !scopeAttenuates(parent, attestation.scope_boundary) ||
      !capsAttenuate(parent, attestation.capability_set)
    ) {
      return ChainVerification.NotAttenuated;
    }
  }

  return ChainVerification.Attenuated;
}

/**
 * **Detached consent attestation**: a parent issuer's signed statement that a
 * particular child may hold particular authority under a particular parent. Mirror
 * of the Rust `vaid_mint::attestation` and the Python `vaid_mint.attestation`.
 *
 * ## The gap this closes
 *
 * Nothing in a VAID document proves the parent *consented* to the delegation.
 * `mintChild` requires an authenticated parent principal and pins the child's
 * `parent_vaid` to that verified parent — but that enforcement is a property of the
 * mint's session, in-process, at mint time. None of it lands in the child document.
 * What the child carries is `parent_vaid` (a UUID its own issuer writes and signs
 * with its own kernel key) and `lineage_hash`, computed from that same issuer-chosen
 * value. The proof-of-possession proves the child controls its key, not that the
 * parent authorized anything.
 *
 * Under **one** kernel key this is invisible and the design is sound: the single
 * mint is the only thing that can sign, and it enforced consent before signing.
 * Widen the key set and it stops being sound. An issuer B, holding its own kernel
 * key, can mint a document naming issuer A's root `vaid_id` as `parent_vaid`, with
 * scope and capabilities inside A's, and sign it with B's key. Every document
 * authenticates under its own key, the chain assembles, containment holds — and A
 * never delegated anything to B. B needs only to *know* A's root `vaid_id`, which is
 * disclosed to every verifier in any chain presentation.
 *
 * This is why cross-key hops require an attestation and same-key hops do not.
 *
 * ## Additive, by construction
 *
 * No VAID document changes. No new field, no `sig_version` bump, no `mint_v1`
 * re-freeze. This is a **separate signed object** presented alongside the chain —
 * the same move ADR-0003 made for the ancestors themselves.
 *
 * ## What is deliberately absent
 *
 * **No timestamps.** An `expires_at` nobody consults is decoration, and chain
 * verification deliberately does not consult expiry for VAID documents either.
 * Replay is bound structurally instead: an attestation names both `parent_vaid` and
 * `child_vaid`, and both are fresh UUIDv4s, so it cannot be moved onto a different
 * pair.
 */

import { canonicalize, ed25519Verify, sha256, type VaidId } from 'vaid-pop';

import { isValidTrustDomain, kernelKeyThumbprint } from './issuerIdentity.js';

/**
 * Attestation format discriminant. Independent of `sig_version`: this is a separate
 * object with its own shape, and bumping one must not imply the other.
 */
export const ATTESTATION_VERSION = 1;

/**
 * A parent issuer's signed statement of consent to one delegation.
 *
 * Read it as: *the issuer holding the kernel key identified by
 * `kernel_key_thumbprint`, in trust domain `trust_domain`, consents to `child_vaid`
 * — claiming `child_trust_domain`/`child_tenant_id` — holding at most
 * `scope_boundary`/`capability_set` under `parent_vaid`.*
 */
export interface ConsentAttestation {
  /** Format discriminant ({@link ATTESTATION_VERSION}). */
  att_version: number;
  /** The parent whose authority is delegated. MUST equal the parent document's `vaid_id`. */
  parent_vaid: VaidId;
  /** The child receiving it. MUST equal the child document's `vaid_id`. */
  child_vaid: VaidId;
  /**
   * The trust domain the parent consents to the child claiming. MUST equal the
   * child document's `trust_domain`.
   *
   * This field is why a cross-key hop can legitimately change trust domain when a
   * same-key hop cannot. Same-key hops require the `(trust_domain, tenant_id)` pair
   * to be equal, because one issuer signed both ends and a conforming mint refuses
   * to cross that boundary. A cross-organisation delegation crosses it by
   * definition — so the crossing must be *named and signed* by the consenting
   * parent rather than merely permitted.
   */
  child_trust_domain: string;
  /** The tenant the parent consents to the child claiming. MUST equal the child's. */
  child_tenant_id: string;
  /** The maximum scope consented to; the child's own must be contained by it. */
  scope_boundary: string[];
  /** The maximum capabilities consented to. */
  capability_set: string[];
  /** The attesting issuer's trust domain. MUST equal the parent document's. */
  trust_domain: string;
  /**
   * RFC 9278 thumbprint URI of the kernel key that signed this. MUST equal the
   * parent document's: the party consenting must be the party that issued the parent.
   */
  kernel_key_thumbprint: string;
  /** Raw Ed25519 signature bytes, as Rust serializes `Vec<u8>`. Empty when unsigned. */
  signature: number[];
}

/**
 * Assemble the snake_case attestation with an empty `signature`. The field set and
 * names mirror the Rust `ConsentAttestation` exactly; the parent's issuer signs the
 * canonical bytes of this and attaches the signature.
 */
export function buildUnsignedAttestation(fields: {
  parentVaid: VaidId;
  childVaid: VaidId;
  childTrustDomain: string;
  childTenantId: string;
  scopeBoundary: readonly string[];
  capabilitySet: readonly string[];
  trustDomain: string;
  kernelKeyThumbprint: string;
}): ConsentAttestation {
  return {
    att_version: ATTESTATION_VERSION,
    parent_vaid: fields.parentVaid,
    child_vaid: fields.childVaid,
    child_trust_domain: fields.childTrustDomain,
    child_tenant_id: fields.childTenantId,
    scope_boundary: [...fields.scopeBoundary],
    capability_set: [...fields.capabilitySet],
    trust_domain: fields.trustDomain,
    kernel_key_thumbprint: fields.kernelKeyThumbprint,
    signature: [],
  };
}

/**
 * The 32-byte signing digest of an attestation.
 *
 * Same discipline as {@link canonicalVaidSigningBytes}: copy, force `signature` to
 * JSON `null` (a signature cannot cover its own value), canonicalize per RFC 8785,
 * SHA-256.
 */
export function canonicalAttestationSigningBytes(
  attestation: ConsentAttestation,
): Uint8Array {
  const payload: Record<string, unknown> = { ...attestation, signature: null };
  return sha256(canonicalize(payload));
}

/**
 * Verify an attestation's **authenticity** against a kernel public key: the format
 * discriminant, a well-formed `trust_domain`, that `kernel_key_thumbprint`
 * corresponds to `kernelPublicKey` (the same key-commitment check the document
 * verifier makes), and the Ed25519 signature.
 *
 * This answers only *is this attestation real*. Whether it applies to the hop in
 * front of you is checked by {@link verifyChainWith}, which has the documents.
 *
 * A malformed key, a bad signature, or any tampered field is `false`, never a throw.
 */
export function verifyAttestationAuthenticity(
  kernelPublicKey: Uint8Array,
  attestation: ConsentAttestation,
): boolean {
  if (attestation.att_version !== ATTESTATION_VERSION) return false;
  if (!isValidTrustDomain(attestation.trust_domain)) return false;
  let expected: string;
  try {
    expected = kernelKeyThumbprint(kernelPublicKey);
  } catch {
    return false;
  }
  if (attestation.kernel_key_thumbprint !== expected) return false;
  try {
    return ed25519Verify(
      Uint8Array.from(attestation.signature ?? []),
      canonicalAttestationSigningBytes(attestation),
      kernelPublicKey,
    );
  } catch {
    return false;
  }
}

/**
 * The attestations a presenter supplies alongside a chain, indexed by the
 * `(parent_vaid, child_vaid)` hop they cover.
 *
 * Lookup is by hop rather than by list scan, which is what makes a **replayed**
 * attestation structurally inert: one minted for a different delegation is filed
 * under that pair and is simply not found when a different pair is asked for. It
 * never has to be *rejected*, so there is no rejection path to get wrong.
 */
export class AttestationBundle {
  readonly #byHop: Map<string, ConsentAttestation>;

  constructor(attestations: Iterable<ConsentAttestation> = []) {
    this.#byHop = new Map();
    for (const a of attestations) {
      this.#byHop.set(AttestationBundle.#key(a.parent_vaid, a.child_vaid), a);
    }
  }

  static #key(parentVaid: VaidId, childVaid: VaidId): string {
    return `${parentVaid} ${childVaid}`;
  }

  /** The attestation covering this hop, if one was presented. */
  get(parentVaid: VaidId, childVaid: VaidId): ConsentAttestation | undefined {
    return this.#byHop.get(AttestationBundle.#key(parentVaid, childVaid));
  }

  get size(): number {
    return this.#byHop.size;
  }
}

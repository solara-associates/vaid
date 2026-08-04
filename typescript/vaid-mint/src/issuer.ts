/**
 * The issuer — the kernel signer that turns requested attributes into a signed
 * VAID document. TypeScript mirror of the Rust `vaid_mint::issuer`.
 *
 * {@link VaidIssuer} is the seam; {@link ReferenceIssuer} is the open,
 * self-hostable implementation. It holds an Ed25519 kernel key and signs the full
 * canonical VAID document. Three things a hosted authority adds that this
 * reference leaves to the self-hoster:
 *
 * - **No KMS / secret-store bootstrap.** The kernel key is either generated
 *   ephemerally ({@link ReferenceIssuer.ephemeral}) or supplied by the caller
 *   ({@link ReferenceIssuer.fromSeed}). A self-hoster persists and protects that
 *   key however they choose.
 * - **Non-durable revocation, but a pluggable seam.** The default in-memory
 *   revocation store does not survive restart. A self-hoster injects a durable
 *   backend via the three-state {@link RevocationCheck} seam
 *   ({@link ReferenceIssuer.withRevocationCheck}) without patching the package.
 *   See `docs/spec/revocation.md` R.4 and the README's "Trust model" section.
 * - **The issuer is the lineage resolver.** It records **every** mint in an
 *   in-memory map — roots with no parent, children with their parent — so it can
 *   tell a known root from an id it has never seen ({@link LineageResolver}, spec
 *   R.4.2). The map is not durable and is not a network service; after a restart
 *   it is empty, and a child presented against it resolves to `Unavailable`
 *   rather than being mistaken for a root.
 *
 * **Expiry (TTL) is a hard reject at verification.**
 * {@link ReferenceIssuer.verifyVaid} returns `false` for an expired VAID even
 * when its kernel signature is valid; {@link isExpired} remains available for a
 * caller that needs to distinguish "forged" from "expired" beforehand.
 */

import {
  buildUnsignedAttestation,
  canonicalAttestationSigningBytes,
  type ConsentAttestation,
} from './attestation.js';
import { MintError } from './error.js';
import { isValidTrustDomain, kernelKeyThumbprint } from './issuerIdentity.js';
import {
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  numbersToBytes,
  randomEd25519Seed,
  utcWholeSecondRfc3339,
  type Ed25519Seed,
  type Rfc3339Utc,
  type TenantId,
  type VaidId,
} from 'vaid-pop';

import {
  buildUnsignedVaidDocument,
  canonicalVaidSigningBytes,
  computeLineageHash,
  isExpired,
  VAID_SIG_VERSION_V3,
  type AgentClass,
  type Vaid,
} from './document.js';
import {
  assembleLineage,
  InMemoryRevocationList,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  RevocationStatus,
  type LineageResolver,
  type ParentResolution,
  type RevocationCheck,
} from './revocation.js';

/**
 * The default issuance TTL, in hours, when a caller does not supply one. Short by
 * design: with only non-durable revocation in this reference, a short TTL is the
 * primary control that bounds the exposure window of a leaked or compromised
 * VAID (see the README "Trust model"). The constructors still take an explicit
 * `vaidTtlHours`; this constant documents the recommended baseline.
 */
export const DEFAULT_VAID_TTL_HOURS = 1;

/** The attributes an issuer needs to build and sign a document. */
export interface IssueAttributes {
  agentClass: AgentClass;
  version: string;
  tenantId: TenantId;
  parentVaid: VaidId | null;
  scopeBoundary: readonly string[];
  capabilitySet: readonly string[];
}

/**
 * The issuer seam. The mint holds one of these and asks it to issue signed
 * documents. Synchronous: issuing is CPU-only (key handling + one Ed25519 sign);
 * no I/O is on this path in the reference.
 */
export interface VaidIssuer {
  /**
   * Issue a VAID under a caller-supplied public key (the BYO-key path — the mint
   * has already verified proof-of-possession of the matching private key). The
   * issuer signs the document with the kernel key.
   */
  issueVaidWithKey(attributes: IssueAttributes, publicKeyDer: Uint8Array): Vaid;

  /**
   * Issue a VAID under an issuer-generated keypair, discarding the private half
   * (no holder key is registered, so no PoP applies). The generate-and-discard
   * root/bootstrap path.
   */
  issueVaidWithLineage(attributes: IssueAttributes): Vaid;

  /**
   * Verify a VAID against this issuer: correct signature scheme, kernel signature
   * valid over the canonical document, **not expired**, and not revoked. A bad
   * signature is `false`, never a throw.
   */
  verifyVaid(vaid: Vaid): boolean;
}

/**
 * The open reference issuer. Holds an Ed25519 kernel key, an in-memory lineage
 * map recording every mint (so it can act as the verifier-side
 * {@link LineageResolver}), and the three-state {@link RevocationCheck} consulted
 * at verification.
 */
export class ReferenceIssuer implements VaidIssuer, LineageResolver {
  readonly #kernelSeed: Ed25519Seed;
  readonly #kernelPublicKey: Uint8Array;
  readonly #vaidTtlHours: number;

  /**
   * v3: the trust domain stamped into every VAID this issuer mints (ADR-0004).
   * Validated at construction. The companion thumbprint is NOT stored — it is
   * derived from the kernel key at mint time, so it cannot disagree with the key
   * that signs.
   */
  readonly #trustDomain: string;
  /**
   * Every minted VAID: the parent id for a child, `null` for a root. Recording
   * roots (not just children) is what lets {@link resolveParent} distinguish a
   * known root from an id it has never seen — the crux of spec R.4.2.
   */
  readonly #lineage = new Map<VaidId, VaidId | null>();
  /**
   * The built-in in-memory store {@link revoke} mutates. It is the default
   * `#revocation`; injecting a custom check leaves this in place but unconsulted
   * (revoke through the injected backend instead).
   */
  readonly #defaultStore: InMemoryRevocationList;
  /** The revocation store consulted in {@link verifyVaid}. */
  #revocation: RevocationCheck;

  private constructor(kernelSeed: Ed25519Seed, vaidTtlHours: number, trustDomain: string) {
    if (!isValidTrustDomain(trustDomain)) {
      // Reject at construction, not at mint: an issuer whose every output would
      // fail verification is not a useful object to hold.
      throw new MintError(
        `trust_domain ${JSON.stringify(trustDomain)} is not well-formed (ADR-0004): ` +
          "lowercase ASCII letters, digits, '-' and '.'; at least two labels; each 1-63 " +
          "bytes without a leading or trailing '-'; no trailing dot; 1-253 bytes total; " +
          'final label not all-numeric',
      );
    }
    this.#kernelSeed = kernelSeed;
    this.#kernelPublicKey = ed25519PublicKey(kernelSeed);
    this.#vaidTtlHours = vaidTtlHours;
    this.#trustDomain = trustDomain;
    // Default revocation posture: assume-nothing-revoked, so a live issuer
    // vouches "nothing revoked yet" and a fresh, un-revoked VAID verifies out of
    // the box rather than failing closed on Unavailable. RESTART BEHAVIOUR: this
    // store is non-durable and cannot detect its own restart — after a restart it
    // is reconstructed empty and again vouches NotRevoked, so a VAID revoked
    // before the restart verifies clean. For restart-safety, inject a durable
    // RevocationCheck, or hold the store absent until revocation state is
    // re-loaded. See `docs/spec/revocation.md` R.4.6.
    this.#defaultStore = InMemoryRevocationList.assumeNothingRevoked();
    this.#revocation = this.#defaultStore;
  }

  /**
   * Build with a freshly generated **ephemeral** kernel key. VAIDs signed by this
   * issuer verify only for this process's lifetime — the key is not persisted.
   * The zero-config default for local self-hosting and tests.
   */
  static ephemeral(
    vaidTtlHours: number = DEFAULT_VAID_TTL_HOURS,
    trustDomain = 'vaid.example',
  ): ReferenceIssuer {
    return new ReferenceIssuer(randomEd25519Seed(), vaidTtlHours, trustDomain);
  }

  /**
   * Build from a raw 32-byte Ed25519 seed — the self-hosting persistence path
   * (load the key from wherever you keep it and hand the bytes here), and the
   * path deterministic conformance vectors use, where every language must derive
   * the identical kernel key and produce identical signatures.
   */
  static fromSeed(
    seed: Uint8Array,
    vaidTtlHours: number = DEFAULT_VAID_TTL_HOURS,
    trustDomain = 'vaid.example',
  ): ReferenceIssuer {
    if (seed.length !== 32) {
      throw new RangeError(`kernel seed must be 32 bytes, got ${seed.length}`);
    }
    return new ReferenceIssuer(seed, vaidTtlHours, trustDomain);
  }

  /**
   * Replace the revocation store consulted at verification with an injected
   * {@link RevocationCheck} — e.g. a durable, restart-surviving backend that
   * returns `Unavailable` when its store is unreachable. The built-in
   * {@link revoke} store stays but is no longer consulted; revoke through the
   * injected backend instead. Returns `this` so it chains.
   */
  withRevocationCheck(revocationCheck: RevocationCheck): this {
    this.#revocation = revocationCheck;
    return this;
  }

  /** The kernel public key (raw 32 bytes) a verifier binds this issuer's VAIDs against. */
  kernelPublicKey(): Uint8Array {
    return this.#kernelPublicKey;
  }

  /**
   * Sign a **detached consent attestation**: this issuer, as the party that issued
   * `parentVaid`, consents to `childVaid` holding at most `scopeBoundary` and
   * `capabilitySet` under it. Mirror of the Rust `attest_delegation`.
   *
   * Consent is otherwise a property of the mint's *session* — `mintChild` enforces
   * it in-process and nothing about that enforcement lands in the child document,
   * so a cross-issuer verifier cannot see it. This makes it a signed object the
   * presenter can carry.
   *
   * The trust domain and thumbprint come from this issuer's own key and
   * configuration, never from a parameter, so an attestation cannot name a key or
   * domain other than the one about to sign it.
   *
   * **This does not check that `parentVaid` was actually minted here.** The
   * reference lineage map is in-memory and empty after restart (R.4.6), so such a
   * check would fail closed on legitimate attestations after any restart. A verifier
   * does not rely on it: it independently requires the attestation's thumbprint to
   * equal the parent document's.
   */
  attestDelegation(fields: {
    parentVaid: VaidId;
    childVaid: VaidId;
    childTrustDomain: string;
    childTenantId: string;
    /**
     * REQUIRED, with no default and no derived fallback: consent that outlives its
     * purpose must be somebody's stated intention, never a value that arrived by
     * omission. A time bound is a **mitigation, not withdrawal** — it limits how
     * long stale consent stays usable and does nothing about consent retracted
     * inside its window, which needs durable revocation, and durable revocation does
     * not exist here (R.4.6).
     */
    expiresAt: string;
    scopeBoundary: readonly string[];
    capabilitySet: readonly string[];
  }): ConsentAttestation {
    const unsigned = buildUnsignedAttestation({
      ...fields,
      // The issuing instant, as it is for a minted document.
      issuedAt: utcWholeSecondRfc3339(new Date()),
      expiresAt: fields.expiresAt,
      trustDomain: this.#trustDomain,
      kernelKeyThumbprint: kernelKeyThumbprint(this.kernelPublicKey()),
    });
    const signature = ed25519Sign(
      canonicalAttestationSigningBytes(unsigned),
      this.#kernelSeed,
    );
    return { ...unsigned, signature: Array.from(signature) };
  }

  /**
   * Revoke a VAID in the built-in in-memory store. A revoked VAID — and every
   * VAID attenuated from it (R.4.4) — fails {@link verifyVaid}. Does not survive
   * restart. Has no effect on verification if a custom {@link RevocationCheck}
   * was injected via {@link withRevocationCheck}; revoke through that backend
   * instead.
   */
  revoke(vaidId: VaidId): void {
    this.#defaultStore.revoke(vaidId);
  }

  /**
   * Clear the in-memory lineage map, modelling the loss of resolver state across
   * a process restart. Afterwards any VAID carrying a `parent_vaid` resolves to
   * `Unavailable` — its ancestry can no longer be completed (R.4.2) — while a
   * genuinely rootless VAID still verifies. An ops/test primitive.
   */
  clearLineage(): void {
    this.#lineage.clear();
  }

  /**
   * Resolve one hop from the in-memory lineage map. A recorded VAID with `null`
   * is a **known root**; a recorded VAID with a parent is a **child**; an
   * unrecorded id is **unknown** — the distinction spec R.4.2 turns on, and the
   * reason an empty (post-restart) map yields `Unavailable` for a child rather
   * than mistaking it for a root.
   */
  resolveParent(vaidId: VaidId): ParentResolution {
    if (!this.#lineage.has(vaidId)) return parentResolutionUnknown();
    const parent = this.#lineage.get(vaidId) ?? null;
    return parent === null ? parentResolutionRoot() : parentResolutionOf(parent);
  }

  /**
   * The revocation status of `vaid` under this issuer (spec R.4): assemble its
   * ordered lineage from this issuer's resolver, then consult the revocation
   * store with it. An incomplete lineage is `Unavailable` and the store is not
   * consulted (R.4.2). {@link verifyVaid} gates on this; it is exposed so a
   * caller can distinguish `Unavailable` from `NotRevoked` (R.4.3) rather than
   * seeing only a rejected/accepted boolean.
   */
  revocationStatus(vaid: Vaid): RevocationStatus {
    const lineage = assembleLineage(vaid, this);
    if (lineage === null) return RevocationStatus.Unavailable;
    return this.#revocation.checkLineage(lineage);
  }

  #buildAndSign(attributes: IssueAttributes, publicKeyDer: Uint8Array): Vaid {
    const agentId = crypto.randomUUID();
    const vaidId: VaidId = agentId; // VaidId::from_uuid(agent_id) — the same UUID.
    const now = new Date();
    const expires = new Date(now.getTime() + attributesTtlMillis(this.#vaidTtlHours));
    const lineageHash = computeLineageHash(attributes.parentVaid, agentId);

    // Build the full document with an empty signature, sign its canonical bytes
    // (which null `kernel_signature`), then attach the signature.
    const unsigned = buildUnsignedVaidDocument({
      vaidId,
      agentId,
      agentClass: attributes.agentClass,
      version: attributes.version,
      tenantId: attributes.tenantId,
      issuedAt: utcWholeSecondRfc3339(now) as Rfc3339Utc,
      expiresAt: utcWholeSecondRfc3339(expires) as Rfc3339Utc,
      publicKeyDer: Array.from(publicKeyDer),
      parentVaid: attributes.parentVaid,
      scopeBoundary: attributes.scopeBoundary,
      lineageHash,
      capabilitySet: attributes.capabilitySet,
      trustDomain: this.#trustDomain,
      // Derived from the signing key itself, never supplied: the thumbprint
      // cannot disagree with the key that is about to sign.
      kernelKeyThumbprint: kernelKeyThumbprint(this.kernelPublicKey()),
    });
    const signature = ed25519Sign(canonicalVaidSigningBytes(unsigned), this.#kernelSeed);
    const vaid: Vaid = { ...unsigned, kernel_signature: Array.from(signature) };

    // Record EVERY mint — roots as `null`, children as their parent — so the
    // resolver can distinguish a known root from an id it has never seen. This is
    // the bookkeeping spec R.4.2 depends on; it changes no document bytes.
    this.#lineage.set(vaidId, attributes.parentVaid);
    return vaid;
  }

  issueVaidWithKey(attributes: IssueAttributes, publicKeyDer: Uint8Array): Vaid {
    return this.#buildAndSign(attributes, publicKeyDer);
  }

  issueVaidWithLineage(attributes: IssueAttributes): Vaid {
    // Generate a keypair and discard the private half — no holder key is
    // registered, so no proof-of-possession applies.
    const agentSeed = randomEd25519Seed();
    return this.#buildAndSign(attributes, ed25519PublicKey(agentSeed));
  }

  verifyVaid(vaid: Vaid): boolean {
    if (vaid.sig_version !== VAID_SIG_VERSION_V3) return false;
    // TTL is enforced as a hard reject, not merely reported: an expired VAID
    // fails verification even with a valid kernel signature.
    if (isExpired(vaid)) return false;
    // Revocation over the FULL ordered lineage (R.4.4), failing closed on
    // Unavailable: an incomplete lineage or an unreachable store rejects the
    // VAID — it never silently passes (R.4.2, R.4.5).
    if (this.revocationStatus(vaid) !== RevocationStatus.NotRevoked) return false;
    return ed25519Verify(
      numbersToBytes(vaid.kernel_signature),
      canonicalVaidSigningBytes(vaid),
      this.#kernelPublicKey,
    );
  }
}

/**
 * TTL hours to milliseconds. Kept as a named function because a negative TTL is a
 * legitimate input — it is how the test suite constructs an already-expired VAID
 * whose kernel signature is nonetheless valid.
 */
function attributesTtlMillis(hours: number): number {
  return hours * 60 * 60 * 1000;
}

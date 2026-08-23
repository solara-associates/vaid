/**
 * The revocation seam — spec `docs/spec/revocation.md` R.4. TypeScript mirror of
 * the Rust `vaid_mint::revocation`.
 *
 * Revocation is **outside the VAID conformance surface** (spec R.1): no frozen
 * vector polices anything in this module, and nothing here is normative. It is
 * specified in prose, and pinned down here, precisely because no vector would
 * otherwise stop independent implementations from drifting into different
 * shapes — which is exactly the risk a third language introduces.
 *
 * ## Shape (0.2.0, replacing the 0.1.2 boolean seam)
 *
 * The 0.1.2 seam was a boolean, leaf-only check: `isRevoked(vaidId) => boolean`.
 * It could not express that a check was *unavailable*, and it consulted only the
 * presented leaf, so revoking a parent left an attenuated child verifiable. This
 * module implements the three-state, lineage-aware seam the spec defines. There
 * is deliberately no boolean shim: two interfaces named `RevocationCheck` with
 * different safety properties is the outcome being avoided.
 *
 * The design splits two jobs that must not be conflated (R.4.1):
 *
 * - **The verifier assembles the lineage.** {@link assembleLineage} resolves the
 *   ordered ancestry of the VAID under verification, root first, leaf last,
 *   using a {@link LineageResolver}. The check is never handed the resolver and
 *   performs no lookups.
 * - **The check answers about a lineage it is handed.** {@link RevocationCheck}
 *   receives an already-ordered `VaidId[]` and reports a
 *   {@link RevocationStatus} for it. A VAID is revoked if **any** VAID in its
 *   lineage is revoked (R.4.4).
 *
 * ## Three states, and failing closed (R.4.3, R.4.5)
 *
 * {@link RevocationStatus} is three-valued — never a boolean — and
 * `Unavailable` is a first-class return the caller can see, never an error to be
 * swallowed. Verification fails closed on `Unavailable`: a VAID whose revocation
 * status cannot be determined does not verify. There is no fail-open option in
 * this reference.
 *
 * ## Detectability of state loss (R.4.2, R.4.6)
 *
 * The full lineage is **not** recoverable from a VAID: it carries only its
 * immediate `parent_vaid` (one hop) and a one-way `lineage_hash`. Assembly
 * therefore needs a resolver, and the reference resolver is the issuer's
 * in-process lineage map. That map is empty after a restart. The danger the spec
 * names: a child verified against an empty map resolves nothing, a naive
 * implementation returns a single-element lineage of just the leaf, and that is
 * indistinguishable from a legitimately rootless VAID — the parent's revocation
 * is silently discarded.
 *
 * This module refuses that collapse in two places:
 *
 * - {@link LineageResolver.resolveParent} returns three-way
 *   ({@link ParentResolution}): a **known root** (recorded, no parent) is
 *   distinct from an **unknown** id (not recorded — unresolvable).
 *   {@link assembleLineage} turns *unknown* into `null`, which the verifier maps
 *   to `Unavailable`, never to a rootless lineage.
 * - {@link InMemoryRevocationList} represents **absent** state (`Unavailable`)
 *   distinctly from a **vouching** store (`NotRevoked`). A store that has not
 *   been populated cannot vouch for any VAID and says so.
 */

import type { VaidId } from 'vaid-pop';

import type { Vaid } from './document.js';

/**
 * Defensive bound on lineage depth. A resolver map corrupted into a cycle, or an
 * implausibly deep chain, yields an incomplete assembly rather than looping —
 * incomplete fails closed, so this never fails *open*.
 */
export const MAX_LINEAGE_DEPTH = 1024;

/**
 * The three-state result of a revocation check (spec R.4.3). Not a boolean.
 *
 * The caller MUST be able to tell `Unavailable` from `NotRevoked`: the first
 * means "status could not be determined" and fails closed, the second means
 * "checked, and clean".
 */
export const RevocationStatus = {
  /** The check completed against a complete lineage and nothing in it is revoked. */
  NotRevoked: 'not_revoked',
  /** At least one VAID in the lineage is revoked (R.4.4). */
  Revoked: 'revoked',
  /**
   * Status could not be determined — the store could not be consulted, or the
   * lineage could not be completely assembled. Verification fails closed here.
   */
  Unavailable: 'unavailable',
} as const;

export type RevocationStatus = (typeof RevocationStatus)[keyof typeof RevocationStatus];

/**
 * The revocation seam (R.4.1). Consulted at verification time with the full
 * ordered lineage (root first, leaf last) that the verifier has **already**
 * assembled. The check performs no lineage resolution and is not given the means
 * to: it answers only about the identifiers it is handed.
 */
export interface RevocationCheck {
  /**
   * Report revocation for an already-assembled, ordered lineage.
   *
   * Returns `Revoked` if **any** id in `lineage` is revoked (R.4.4),
   * `NotRevoked` if the store was consulted and none are, and `Unavailable` if
   * the backing store could not be consulted (R.4.3) — never collapse that last
   * case into `NotRevoked`.
   */
  checkLineage(lineage: readonly VaidId[]): RevocationStatus;
}

/**
 * The result of resolving one hop of ancestry (spec R.4.2). The three cases are
 * kept distinct on purpose: conflating **root** with **unknown** is the exact bug
 * that lets a post-restart child masquerade as rootless.
 */
export type ParentResolution =
  /** This VAID is known to the resolver and has no parent: a genuine root. */
  | { readonly kind: 'root' }
  /** This VAID is known to the resolver and its parent is this id. */
  | { readonly kind: 'parent'; readonly parent: VaidId }
  /** This VAID is not known to the resolver — its ancestry cannot be completed. */
  | { readonly kind: 'unknown' };

/** Known to the resolver, with no parent: a genuine root. */
export const parentResolutionRoot = (): ParentResolution => ({ kind: 'root' });
/** Known to the resolver, with this parent. */
export const parentResolutionOf = (parent: VaidId): ParentResolution => ({ kind: 'parent', parent });
/** Not known to the resolver — ancestry cannot be completed. */
export const parentResolutionUnknown = (): ParentResolution => ({ kind: 'unknown' });

/**
 * Resolves a VAID's immediate parent, one hop at a time (spec R.4.1/R.4.2). The
 * verifier owns this; the {@link RevocationCheck} never sees it.
 */
export interface LineageResolver {
  /**
   * Resolve the parent of `vaidId`. MUST distinguish a known root from an id it
   * cannot resolve.
   */
  resolveParent(vaidId: VaidId): ParentResolution;
}

/**
 * Assemble the ordered ancestor lineage of `leaf`, root first, leaf last (R.4.2).
 *
 * The leaf's immediate parent comes from its own signed document; every hop above
 * that is resolved through `resolver`. A leaf whose `parent_vaid` is absent is
 * trivially complete and returns a one-element lineage.
 *
 * Returns `null` for an **incomplete** assembly — a present `parent_vaid` that
 * resolves to unknown, a cycle, or an implausible depth. `null` MUST be treated
 * as {@link RevocationStatus.Unavailable} and MUST NOT be presented to the check
 * as though it were the whole lineage. It is never silently truncated to the leaf
 * alone; that truncation is the precise failure R.4.2 exists to forbid.
 */
export function assembleLineage(
  leaf: Vaid,
  resolver: LineageResolver,
): VaidId[] | null {
  const chain: VaidId[] = [leaf.vaid_id];
  let nextParent: VaidId | null = leaf.parent_vaid;

  while (nextParent !== null) {
    if (chain.includes(nextParent) || chain.length >= MAX_LINEAGE_DEPTH) {
      // A cycle, or an implausibly deep chain: cannot vouch for completeness.
      return null;
    }
    chain.push(nextParent);
    const resolved: ParentResolution = resolver.resolveParent(nextParent);
    if (resolved.kind === 'root') {
      nextParent = null;
    } else if (resolved.kind === 'parent') {
      nextParent = resolved.parent;
    } else {
      return null;
    }
  }

  chain.reverse(); // built leaf→root; the check wants root→leaf.
  return chain;
}

/**
 * A standalone, injectable in-memory revocation store implementing the
 * three-state seam. Non-durable: it does not survive a restart.
 *
 * It represents two conditions the spec (R.4.6) insists be kept apart:
 *
 * - **absent** (`new InMemoryRevocationList()` / {@link unavailable} /
 *   {@link markUnavailable}) — the store has not been populated and cannot vouch
 *   for anything, so {@link checkLineage} returns `Unavailable`. This is what a
 *   freshly reconstructed store looks like after a restart.
 * - **vouching** ({@link assumeNothingRevoked}, or after any {@link revoke}) —
 *   the store vouches for its contents, which may be empty, so an unrevoked
 *   lineage returns `NotRevoked`.
 *
 * A durable backend implements {@link RevocationCheck} itself and returns
 * `Unavailable` when *its* store is unreachable; this in-memory type is for tests
 * and for wiring the seam before such a backend exists.
 */
export class InMemoryRevocationList implements RevocationCheck {
  /** `null` = absent (cannot vouch → `Unavailable`); a set = vouching. */
  #revoked: Set<VaidId> | null = null;

  /**
   * A store that **vouches "nothing is revoked"** over an empty set.
   *
   * The name states the posture, not the state, because the state ("empty") is
   * the dangerous part read alone. This store answers `NotRevoked` for every VAID
   * it is not told about — and, being non-durable, it **cannot detect its own
   * restart**: after a process restart it is reconstructed empty and again
   * vouches `NotRevoked`, so a VAID revoked before the restart verifies clean.
   * That is a fail-*open* posture reached by assumption. It is fine for local
   * development and tests; for anything that must survive a restart, inject a
   * durable {@link RevocationCheck}, or hold the store in the default (absent)
   * state until you have re-loaded revocation state into it.
   */
  static assumeNothingRevoked(): InMemoryRevocationList {
    const list = new InMemoryRevocationList();
    list.#revoked = new Set();
    return list;
  }

  /**
   * Alias for the default constructor that reads as intent at a call site — e.g.
   * modelling a backing store that cannot be reached.
   */
  static unavailable(): InMemoryRevocationList {
    return new InMemoryRevocationList();
  }

  /**
   * Mark a VAID revoked. Populating the store also makes it **available**: a
   * store you have revoked into can vouch for what it holds.
   */
  revoke(vaidId: VaidId): void {
    (this.#revoked ??= new Set()).add(vaidId);
  }

  /**
   * Drop the store back to **absent** state (modelling state loss). Subsequent
   * checks report `Unavailable` rather than silently reporting `NotRevoked`.
   */
  markUnavailable(): void {
    this.#revoked = null;
  }

  /** True when the store is vouching for its contents, false when absent. */
  isAvailable(): boolean {
    return this.#revoked !== null;
  }

  checkLineage(lineage: readonly VaidId[]): RevocationStatus {
    const revoked = this.#revoked;
    if (revoked === null) return RevocationStatus.Unavailable;
    return lineage.some((id) => revoked.has(id))
      ? RevocationStatus.Revoked
      : RevocationStatus.NotRevoked;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The durable seam (spec R.4.6). Two stores, injected as one.
// ─────────────────────────────────────────────────────────────────────────────
//
// Durability under R.4.6 is TWO stores, not one — the revoked set and the lineage
// resolver — and getting exactly one of them durable is an outage, not a hole.
// Persist the revoked set, leave the resolver in memory, restart:
//
//   - every ROOT VAID keeps verifying (trivially complete under R.4.2, no
//     resolution needed, the durable set answers cleanly);
//   - every CHILD VAID stops verifying (its `parent_vaid` is now unresolvable, so
//     assembly is incomplete → Unavailable → fails closed under R.4.5).
//
// Total for delegated credentials, invisible for root ones, arriving at restart
// rather than at deploy, and first diagnosed as a signing or clock problem because
// revocation is the last subsystem anyone suspects when nothing was revoked. The
// system is choosing an outage over a security hole, correctly — but it is the
// wrong outage to have to diagnose from scratch.
//
// Until 0.7.0 that half-state was not merely *reachable*, it was the ONLY
// reachable state: the removed `withRevocationCheck` injected the revoked set, and no
// injection point for the resolver existed at all. A self-hoster following the
// documented path built exactly the half that produces the outage.
//
// `RevocationBackend` closes that by construction. It cannot be built without both
// halves, and it is the only way to replace either, so the half-state is no longer
// reachable **by omission** — only by explicitly naming `InMemoryLineageStore` as
// the durable resolver's replacement, which is a legitimate single-process choice
// and is visible at the call site.
//
// The two halves stay separate objects. A single interface carrying both methods
// would make the half-state unrepresentable too, and would violate R.4.1: "the
// check does not perform lookups and is not given the means to."

/**
 * The write half of the lineage resolver (spec R.4.2).
 *
 * {@link LineageResolver} is read-only, and a read-only durable resolver is inert:
 * nothing would ever populate it, because the issuer records every mint into its
 * own map. A durable resolver therefore needs {@link record} — the method whose
 * absence made durable lineage unimplementable from outside the package.
 *
 * Implementations MUST record roots as `null` rather than omitting them. An
 * unrecorded root is *unknown*, and a store that omits roots turns every root VAID
 * into `Unavailable` at verification.
 */
export interface LineageStore extends LineageResolver {
  /**
   * Record one mint: `parent` is the parent id for a child and `null` for a root.
   * Called on every successful mint, before the document is returned.
   */
  record(vaidId: VaidId, parent: VaidId | null): void;
}

/**
 * The reference lineage store: an in-process map, non-durable, empty after
 * restart. Extracted from `ReferenceIssuer` so that the thing a durable store
 * replaces is a named, injectable object rather than a private field.
 *
 * Records roots as `null` and children as their parent, which is what lets
 * {@link resolveParent} tell a **known root** from an **unknown** id — the
 * distinction spec R.4.2 turns on.
 */
export class InMemoryLineageStore implements LineageStore {
  readonly #entries = new Map<VaidId, VaidId | null>();

  record(vaidId: VaidId, parent: VaidId | null): void {
    this.#entries.set(vaidId, parent);
  }

  resolveParent(vaidId: VaidId): ParentResolution {
    if (!this.#entries.has(vaidId)) return parentResolutionUnknown();
    const parent = this.#entries.get(vaidId) ?? null;
    return parent === null ? parentResolutionRoot() : parentResolutionOf(parent);
  }

  /**
   * Drop every recorded mint, modelling the loss of resolver state across a
   * process restart. Afterwards any VAID carrying a `parent_vaid` resolves to
   * `Unavailable` while a genuinely rootless VAID still verifies. An ops/test
   * primitive.
   */
  clear(): void {
    this.#entries.clear();
  }

  /** Number of mints recorded. Diagnostic only. */
  get size(): number {
    return this.#entries.size;
  }
}

/**
 * Both halves of durable revocation, injected together (spec R.4.6).
 *
 * There is no constructor that takes one half. That is the point: the failure this
 * type exists to prevent is not a wrong value, it is a **missing second
 * argument**, and a missing argument is the one class of mistake a type can refuse
 * outright.
 *
 * ```ts
 * const issuer = ReferenceIssuer.ephemeral(1).withRevocationBackend(
 *   new RevocationBackend(durableRevoked, durableLineage),
 * );
 * ```
 *
 * Ordering note for anyone migrating a live deployment: make the **resolver**
 * durable first, or both in the same change. Doing the revoked set first is the
 * ordering that produces the delegated-credential outage described above.
 */
export class RevocationBackend {
  /**
   * Both halves. `check` answers about an assembled lineage; `lineage` records
   * mints and resolves ancestry. They are separate objects and neither is handed
   * the other (R.4.1).
   */
  constructor(
    readonly check: RevocationCheck,
    readonly lineage: LineageStore,
  ) {}
}

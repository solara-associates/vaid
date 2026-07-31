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

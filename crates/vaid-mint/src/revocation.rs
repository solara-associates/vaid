//! The revocation seam — spec `docs/spec/revocation.md` R.4.
//!
//! Revocation is **outside the VAID conformance surface** (spec R.1): no frozen
//! vector polices anything in this module, and nothing here is normative. It is
//! specified in prose, and pinned down here, precisely because no vector would
//! otherwise stop independent implementations from drifting into different shapes.
//!
//! ## Shape (0.2.0, replacing the 0.1.2 boolean seam)
//!
//! The 0.1.2 seam was a boolean, leaf-only check: `is_revoked(&VaidId) -> bool`.
//! It could not express that a check was *unavailable*, and it consulted only the
//! presented leaf, so revoking a parent left an attenuated child verifiable. This
//! module replaces it — a breaking change — with the three-state, lineage-aware
//! seam the spec defines. There is deliberately no shim keeping the old signature
//! alive: two traits named `RevocationCheck` with different safety properties is
//! the outcome being avoided.
//!
//! The design splits two jobs that must not be conflated (R.4.1):
//!
//! - **The verifier assembles the lineage.** [`assemble_lineage`] resolves the
//!   ordered ancestry of the VAID under verification, root first, leaf last, using
//!   a [`LineageResolver`]. The check is never handed the resolver and performs no
//!   lookups.
//! - **The check answers about a lineage it is handed.** [`RevocationCheck`]
//!   receives an already-ordered `&[VaidId]` and reports [`RevocationStatus`] for
//!   it. A VAID is revoked if **any** VAID in its lineage is revoked (R.4.4).
//!
//! ## Three states, and failing closed (R.4.3, R.4.5)
//!
//! [`RevocationStatus`] is three-valued — [`RevocationStatus::NotRevoked`],
//! [`RevocationStatus::Revoked`], [`RevocationStatus::Unavailable`] — never a
//! boolean, and `Unavailable` is a first-class return the caller can see, never an
//! error to be swallowed. Verification fails closed on `Unavailable`: a VAID whose
//! revocation status cannot be determined does not verify. There is no fail-open
//! option in this reference.
//!
//! ## Detectability of state loss (R.4.2, R.4.6)
//!
//! The full lineage is **not** recoverable from a VAID: it carries only its
//! immediate `parent_vaid` (one hop) and a one-way `lineage_hash`. Assembly
//! therefore needs a resolver, and the reference resolver is the issuer's
//! in-process lineage map. That map is empty after a restart. The danger the spec
//! names: a child verified against an empty map resolves nothing, a naive
//! implementation returns a single-element lineage of just the leaf, and that is
//! indistinguishable from a legitimately rootless VAID — the parent's revocation
//! is silently discarded.
//!
//! This module refuses that collapse in two places:
//!
//! - [`LineageResolver::resolve_parent`] returns three-way
//!   ([`ParentResolution`]): a **known root** (recorded, no parent) is distinct
//!   from an **unknown** id (not recorded — unresolvable). [`assemble_lineage`]
//!   turns *unknown* into [`LineageAssembly::Incomplete`], which the verifier maps
//!   to `Unavailable`, never to a rootless lineage.
//! - [`InMemoryRevocationList`] represents **absent** state (`Unavailable`)
//!   distinctly from **initialised-and-empty** (`NotRevoked`). A store that has
//!   not been populated cannot vouch for any VAID and says so.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::document::{Vaid, VaidId};

/// Defensive bound on lineage depth. A resolver map corrupted into a cycle, or an
/// implausibly deep chain, yields [`LineageAssembly::Incomplete`] rather than
/// looping — incomplete assembly fails closed, so this never fails *open*.
pub const MAX_LINEAGE_DEPTH: usize = 1024;

/// The three-state result of a revocation check (spec R.4.3). Not a boolean.
///
/// The caller MUST be able to tell [`Unavailable`](RevocationStatus::Unavailable)
/// from [`NotRevoked`](RevocationStatus::NotRevoked): the first means "status could
/// not be determined" and fails closed, the second means "checked, and clean".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The check completed against a complete lineage and nothing in it is revoked.
    NotRevoked,
    /// At least one VAID in the lineage is revoked (R.4.4).
    Revoked,
    /// Status could not be determined — the store could not be consulted, or the
    /// lineage could not be completely assembled. Verification fails closed here.
    Unavailable,
}

/// The revocation seam (R.4.1). Consulted at verification time with the full
/// ordered lineage (root first, leaf last) that the verifier has **already**
/// assembled. The check performs no lineage resolution and is not given the means
/// to: it answers only about the identifiers it is handed.
pub trait RevocationCheck: Send + Sync {
    /// Report revocation for an already-assembled, ordered lineage.
    ///
    /// Returns [`RevocationStatus::Revoked`] if **any** id in `lineage` is revoked
    /// (R.4.4), [`RevocationStatus::NotRevoked`] if the store was consulted and
    /// none are, and [`RevocationStatus::Unavailable`] if the backing store could
    /// not be consulted (R.4.3) — never collapse that last case into `NotRevoked`.
    fn check_lineage(&self, lineage: &[VaidId]) -> RevocationStatus;
}

/// The result of resolving one hop of ancestry (spec R.4.2). The three cases are
/// kept distinct on purpose: conflating **root** with **unknown** is the exact bug
/// that lets a post-restart child masquerade as rootless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentResolution {
    /// This VAID is known to the resolver and has no parent: a genuine root.
    Root,
    /// This VAID is known to the resolver and its parent is this id.
    Parent(VaidId),
    /// This VAID is not known to the resolver — its ancestry cannot be completed.
    Unknown,
}

/// Resolves a VAID's immediate parent, one hop at a time (spec R.4.1/R.4.2). The
/// verifier owns this; the [`RevocationCheck`] never sees it.
pub trait LineageResolver {
    /// Resolve the parent of `vaid_id`. MUST distinguish a known root
    /// ([`ParentResolution::Root`]) from an id it cannot resolve
    /// ([`ParentResolution::Unknown`]).
    fn resolve_parent(&self, vaid_id: &VaidId) -> ParentResolution;
}

/// The outcome of assembling a VAID's ordered lineage (spec R.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageAssembly {
    /// Every hop resolved, from a root (no parent) down to the leaf, ordered
    /// **root first, leaf last**. A leaf with no `parent_vaid` is its own root and
    /// assembles to a one-element complete lineage ("trivially complete").
    Complete(Vec<VaidId>),
    /// A `parent_vaid` was present but could not be resolved. MUST be treated as
    /// [`RevocationStatus::Unavailable`] and MUST NOT be presented to the check as
    /// though it were the whole lineage.
    Incomplete,
}

/// Assemble the ordered ancestor lineage of `leaf`, root first, leaf last (R.4.2).
///
/// The leaf's immediate parent comes from its own signed document; every hop above
/// that is resolved through `resolver`. A leaf whose `parent_vaid` is absent is
/// trivially complete. The moment any present parent resolves to
/// [`ParentResolution::Unknown`] — or a cycle or an implausible depth is hit — the
/// result is [`LineageAssembly::Incomplete`]; it is never silently truncated to the
/// leaf alone.
pub fn assemble_lineage(leaf: &Vaid, resolver: &dyn LineageResolver) -> LineageAssembly {
    let mut chain = vec![leaf.vaid_id()];
    let mut next_parent = leaf.parent_vaid();

    while let Some(pid) = next_parent {
        if chain.contains(&pid) || chain.len() >= MAX_LINEAGE_DEPTH {
            // A cycle, or an implausibly deep chain: cannot vouch for completeness.
            return LineageAssembly::Incomplete;
        }
        chain.push(pid);
        next_parent = match resolver.resolve_parent(&pid) {
            ParentResolution::Root => None,
            ParentResolution::Parent(grandparent) => Some(grandparent),
            ParentResolution::Unknown => return LineageAssembly::Incomplete,
        };
    }

    chain.reverse(); // built leaf→root; the check wants root→leaf.
    LineageAssembly::Complete(chain)
}

/// A standalone, injectable in-memory revocation store implementing the three-state
/// seam. Non-durable: it does not survive a restart.
///
/// It represents two conditions the spec (R.4.6) insists be kept apart:
///
/// - **absent** (`new` / [`unavailable`](Self::unavailable) /
///   [`mark_unavailable`](Self::mark_unavailable)) — the store has not been
///   populated and cannot vouch for anything, so [`check_lineage`] returns
///   [`RevocationStatus::Unavailable`]. This is what a freshly reconstructed store
///   looks like after a restart.
/// - **initialised-and-empty** ([`initialised_empty`](Self::initialised_empty), or
///   after any [`revoke`](Self::revoke)) — the store has authoritative contents,
///   which may be empty, so an unrevoked lineage returns
///   [`RevocationStatus::NotRevoked`].
///
/// A durable backend implements [`RevocationCheck`] itself and returns
/// `Unavailable` when *its* store is unreachable; this in-memory type is for tests
/// and for wiring the seam before such a backend exists.
pub struct InMemoryRevocationList {
    /// `None` = absent (cannot vouch → `Unavailable`); `Some(set)` = available.
    state: Mutex<Option<HashSet<VaidId>>>,
}

impl InMemoryRevocationList {
    /// A store with **absent** state: it reports `Unavailable` until populated.
    pub fn new() -> Self {
        Self { state: Mutex::new(None) }
    }

    /// A store explicitly initialised as **available and empty** — an authority
    /// asserting "I have loaded my revocation state; nothing is revoked yet."
    pub fn initialised_empty() -> Self {
        Self { state: Mutex::new(Some(HashSet::new())) }
    }

    /// Alias for [`new`](Self::new) that reads as intent at a call site — e.g.
    /// modelling a backing store that cannot be reached.
    pub fn unavailable() -> Self {
        Self::new()
    }

    /// Mark a VAID revoked. Populating the store also makes it **available**: a
    /// store you have revoked into can vouch for what it holds.
    pub fn revoke(&self, vaid_id: VaidId) {
        let mut guard = self.state.lock().expect("revocation lock not poisoned");
        guard.get_or_insert_with(HashSet::new).insert(vaid_id);
    }

    /// Drop the store back to **absent** state (modelling state loss). Subsequent
    /// checks report `Unavailable` rather than silently reporting `NotRevoked`.
    pub fn mark_unavailable(&self) {
        *self.state.lock().expect("revocation lock not poisoned") = None;
    }

    /// True when the store has authoritative contents (initialised), false when its
    /// state is absent.
    pub fn is_available(&self) -> bool {
        self.state.lock().expect("revocation lock not poisoned").is_some()
    }
}

impl Default for InMemoryRevocationList {
    /// Absent, matching [`new`](Self::new). A bare default cannot vouch.
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationCheck for InMemoryRevocationList {
    fn check_lineage(&self, lineage: &[VaidId]) -> RevocationStatus {
        let guard = self.state.lock().expect("revocation lock not poisoned");
        match &*guard {
            None => RevocationStatus::Unavailable,
            Some(revoked) => {
                if lineage.iter().any(|id| revoked.contains(id)) {
                    RevocationStatus::Revoked
                } else {
                    RevocationStatus::NotRevoked
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Assembly (`assemble_lineage`) is exercised end-to-end against the real issuer
    // resolver in `tests/revocation_seam.rs`; these unit tests cover the store's
    // three-state behaviour directly.

    #[test]
    fn absent_store_is_unavailable_initialised_empty_is_not_revoked() {
        let absent = InMemoryRevocationList::new();
        assert_eq!(absent.check_lineage(&[VaidId::new()]), RevocationStatus::Unavailable);
        let empty = InMemoryRevocationList::initialised_empty();
        assert_eq!(empty.check_lineage(&[VaidId::new()]), RevocationStatus::NotRevoked);
    }

    #[test]
    fn revoking_makes_a_store_available_and_reports_any_hop() {
        let list = InMemoryRevocationList::new();
        let root = VaidId::new();
        let leaf = VaidId::new();
        list.revoke(root);
        assert!(list.is_available());
        // Revoked if ANY id in the lineage is revoked, in any position.
        assert_eq!(list.check_lineage(&[root, leaf]), RevocationStatus::Revoked);
        assert_eq!(list.check_lineage(&[leaf]), RevocationStatus::NotRevoked);
    }

    #[test]
    fn mark_unavailable_flips_back_to_unavailable() {
        let list = InMemoryRevocationList::initialised_empty();
        assert_eq!(list.check_lineage(&[VaidId::new()]), RevocationStatus::NotRevoked);
        list.mark_unavailable();
        assert_eq!(list.check_lineage(&[VaidId::new()]), RevocationStatus::Unavailable);
    }
}

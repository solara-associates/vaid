//! The revocation seam — a pluggable check consulted at verification time.
//!
//! In the closed managed authority, revocation is a durable, hash-chained store
//! that survives restart and is broadcast across verifiers. This open reference
//! has only an in-memory set (see [`crate::issuer::ReferenceIssuer`]); this trait
//! makes the *seam* real so a self-hoster can inject a durable backend without
//! patching the crate — the missing piece is the backend, not the extension point.
//!
//! [`RevocationCheck`] is the seam; [`InMemoryRevocationList`] is a standalone
//! injectable in-memory implementation; [`NeverRevoked`] is an honest no-op a
//! caller may opt into. A production deployment implements [`RevocationCheck`]
//! over its own durable, restart-surviving store and injects it via
//! [`crate::issuer::ReferenceIssuer::with_revocation_check`].
//!
//! **The seam is additive-only.** An injected [`RevocationCheck`] is consulted
//! *in addition to* the reference issuer's built-in in-memory revoked set, never
//! instead of it — a VAID is rejected if *either* reports it revoked. The
//! built-in set cannot currently be disabled through this seam, only supplemented.
//!
//! ## Why this is SYNC (and why there is no honest-no-op *default*)
//!
//! This trait deliberately departs from the [`crate::authz::AuthorizationGate`] /
//! [`crate::audit::AuditSink`] convention in two ways, both on purpose:
//!
//! 1. **It is synchronous, not `async`.** It is consulted inside
//!    [`crate::issuer::VaidIssuer::verify_vaid`], which is documented as a
//!    sync, CPU-only, no-I/O path. A durable/pollable backend is normally
//!    consumed here as a periodically-refreshed in-memory snapshot the check
//!    reads without blocking, so a sync signature fits that model.
//! 2. **The crate default is NOT an honest no-op.** `AuthorizationGate` defaults
//!    to [`crate::authz::PermitAll`] and `AuditSink` offers
//!    [`crate::audit::NoopAudit`]; for *those* seams a no-op default is a neutral
//!    "not wired yet" state. For revocation it would be a functional
//!    **regression** — a no-op means nothing is ever checked, silently. So the
//!    reference issuer keeps its working in-memory revocation set as the default
//!    and layers any injected [`RevocationCheck`] on top. [`NeverRevoked`] exists
//!    for callers who explicitly want the no-op, but it is opt-in, never the
//!    default.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::document::VaidId;

/// The revocation seam. Consulted at verification time: return `true` to treat
/// `vaid_id` as revoked (which fails [`crate::issuer::VaidIssuer::verify_vaid`]),
/// `false` otherwise. Synchronous by design — see the module docs.
pub trait RevocationCheck: Send + Sync {
    /// Is this VAID revoked according to this backend? A production
    /// implementation reads its durable, restart-surviving store (or a locally
    /// cached snapshot of it) without blocking.
    fn is_revoked(&self, vaid_id: &VaidId) -> bool;
}

/// An honest no-op revocation check: nothing is ever reported revoked by *this*
/// backend.
///
/// This performs **no actual revocation checking whatsoever** — every VAID is
/// treated as un-revoked by this implementation.
///
/// **It does not, and cannot, disable the reference issuer's built-in in-memory
/// revoked set.** [`crate::issuer::VaidIssuer::verify_vaid`] consults the
/// built-in set *unconditionally* and treats any injected [`RevocationCheck`] as
/// an *additional* check layered on top — a VAID is rejected if *either* reports
/// it revoked (see [`crate::issuer::ReferenceIssuer::with_revocation_check`]).
/// Because this type never reports anything revoked, injecting it adds no
/// additional rejections and removes none: it is functionally identical to
/// injecting nothing at all. In particular, injecting it does **not** mean "this
/// crate performs no revocation checks" — the built-in set still runs.
///
/// There is currently **no way to bypass revocation checking entirely through
/// this seam**: the built-in set cannot be turned off from here. If you need the
/// mint's revocation check bypassed, front it with an external gateway that
/// answers before `verify_vaid` is ever called, rather than injecting this type.
///
/// It exists as an explicit, honest placeholder for a [`RevocationCheck`] slot
/// (in tests or wiring) where you deliberately want the injected backend to be a
/// no-op. It is **not** the default.
#[derive(Default)]
pub struct NeverRevoked;

impl RevocationCheck for NeverRevoked {
    fn is_revoked(&self, _vaid_id: &VaidId) -> bool {
        false
    }
}

/// A standalone, injectable in-memory revocation list — the same non-durable
/// behavior as the reference issuer's built-in set, exposed as a
/// [`RevocationCheck`] a caller can share across verifiers in one process.
///
/// Like the built-in set, this does **not** survive a restart. It is useful for
/// tests and for wiring the seam before a durable backend exists.
#[derive(Default)]
pub struct InMemoryRevocationList {
    revoked: Mutex<HashSet<VaidId>>,
}

impl InMemoryRevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a VAID revoked (in-memory, non-durable).
    pub fn revoke(&self, vaid_id: VaidId) {
        self.revoked.lock().expect("revocation lock not poisoned").insert(vaid_id);
    }

    /// Number of revoked entries.
    pub fn len(&self) -> usize {
        self.revoked.lock().expect("revocation lock not poisoned").len()
    }

    /// True if nothing has been revoked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RevocationCheck for InMemoryRevocationList {
    fn is_revoked(&self, vaid_id: &VaidId) -> bool {
        self.revoked.lock().expect("revocation lock not poisoned").contains(vaid_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_revoked_reports_nothing_revoked() {
        let check = NeverRevoked;
        assert!(!check.is_revoked(&VaidId::new()));
    }

    #[test]
    fn in_memory_list_reports_only_revoked_ids() {
        let list = InMemoryRevocationList::new();
        let a = VaidId::new();
        let b = VaidId::new();
        assert!(list.is_empty());
        list.revoke(a);
        assert!(list.is_revoked(&a));
        assert!(!list.is_revoked(&b), "an un-revoked id is not revoked");
        assert_eq!(list.len(), 1);
    }
}

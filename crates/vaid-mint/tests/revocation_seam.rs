//! Revocation seam gate (spec `docs/spec/revocation.md` R.4). Integration tests.
//!
//! Revocation is **outside the conformance surface** (R.1): nothing here is a
//! frozen vector, and this file must never become one. It exercises the three
//! states and the two failure modes a boolean, leaf-only check could not express.
//!
//! The scenario table in [`cross_language_scenarios`] is mirrored byte-for-intent
//! by the Python suite (`python/vaid-mint/tests/test_revocation.py`), which asserts
//! the identical (scenario → status) mapping. There is deliberately no shared
//! vector: the languages agree by construction, not by a frozen artifact.

use std::sync::Arc;

use vaid_mint::document::{AgentClass, TenantId};
use vaid_mint::issuer::{ReferenceIssuer, VaidIssuer};
use vaid_mint::revocation::{InMemoryRevocationList, RevocationStatus};

/// Issue a root (no parent) straight from the issuer. Enough to exercise the seam
/// without the full mint_child PoP dance, which is orthogonal to revocation.
fn issue_root(issuer: &ReferenceIssuer, class: &str) -> vaid_mint::document::Vaid {
    issuer
        .issue_vaid_with_lineage(
            AgentClass::new(class),
            "1.0.0".into(),
            TenantId::new("t"),
            None,
            vec![],
            vec![],
        )
        .unwrap()
}

/// Issue a child attenuated from `parent` (same lineage-recording path a real
/// mint_child uses).
fn issue_child(
    issuer: &ReferenceIssuer,
    parent: &vaid_mint::document::Vaid,
    class: &str,
) -> vaid_mint::document::Vaid {
    issuer
        .issue_vaid_with_lineage(
            AgentClass::new(class),
            "1.0.0".into(),
            TenantId::new("t"),
            Some(parent.vaid_id()),
            vec![],
            vec![],
        )
        .unwrap()
}

/// TEST 1 — BYPASS. Revoking a parent must revoke a child attenuated from it
/// (R.4.4). This is the case a leaf-only boolean check got wrong, and the reason
/// lineage checking exists.
#[test]
fn test1_bypass_revoking_parent_rejects_child() {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
    let root = issue_root(&issuer, "root");
    let child = issue_child(&issuer, &root, "child");

    assert!(
        issuer.verify_vaid(&child),
        "child verifies before revocation"
    );

    issuer.revoke(root.vaid_id());

    assert_eq!(
        issuer.revocation_status(&child),
        RevocationStatus::Revoked,
        "a child inherits its revoked parent's revocation"
    );
    assert!(
        !issuer.verify_vaid(&child),
        "BYPASS: a child of a revoked parent must not verify"
    );
}

/// TEST 2 — RESTART TRUNCATION. With the lineage map cleared (process restart), a
/// child whose parent can no longer be resolved is `Unavailable`, not `NotRevoked`.
/// Incomplete assembly must never be mistaken for a rootless VAID (R.4.2). This is
/// the case a boolean interface cannot represent.
#[test]
fn test2_restart_truncation_is_unavailable_not_notrevoked() {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
    let root = issue_root(&issuer, "root");
    let child = issue_child(&issuer, &root, "child");
    issuer.revoke(root.vaid_id());

    // Simulate a restart: the in-memory resolver state is gone.
    issuer.clear_lineage();

    let status = issuer.revocation_status(&child);
    assert_eq!(
        status,
        RevocationStatus::Unavailable,
        "a child whose parent is unresolvable is Unavailable"
    );
    assert_ne!(
        status,
        RevocationStatus::NotRevoked,
        "it must NOT silently pass as not-revoked — the whole point of R.4.2"
    );
    assert!(
        !issuer.verify_vaid(&child),
        "fails closed on Unavailable (R.4.5)"
    );
}

/// TEST 3 — STORE FAILURE. When the revocation store cannot be consulted, the
/// status is `Unavailable` and verification fails closed (R.4.3/R.4.5).
#[test]
fn test3_store_failure_is_unavailable_and_rejects() {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
        .unwrap()
        .with_revocation_check(Arc::new(InMemoryRevocationList::unavailable()));
    let vaid = issue_root(&issuer, "root");

    assert_eq!(
        issuer.revocation_status(&vaid),
        RevocationStatus::Unavailable,
        "an unreachable store yields Unavailable, not NotRevoked"
    );
    assert!(
        !issuer.verify_vaid(&vaid),
        "fails closed when the store is unavailable"
    );
}

/// TEST 4 — ROOTLESS. A rootless VAID with nothing revoked is `NotRevoked` and
/// verifies. This is the case tests 1 and 2 must not have broken: incomplete
/// assembly (test 2) and a genuine root (here) must land on different states.
#[test]
fn test4_rootless_clean_is_notrevoked_and_verifies() {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
    let vaid = issue_root(&issuer, "root");

    assert_eq!(
        issuer.revocation_status(&vaid),
        RevocationStatus::NotRevoked,
        "a rootless, unrevoked VAID is cleanly NotRevoked"
    );
    assert!(issuer.verify_vaid(&vaid), "and it verifies");
}

/// TEST 6 (cross-language) — the (scenario → status) table both languages agree on.
/// The Python suite asserts the identical mapping. All three states appear, and the
/// two indistinguishable-under-a-boolean cases (restart-truncation vs rootless) sit
/// on different rows.
#[test]
fn cross_language_scenarios() {
    // clean_root: rootless, nothing revoked        -> NotRevoked
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let root = issue_root(&issuer, "root");
        assert_eq!(
            issuer.revocation_status(&root),
            RevocationStatus::NotRevoked
        );
    }
    // revoked_root: rootless, itself revoked        -> Revoked
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let root = issue_root(&issuer, "root");
        issuer.revoke(root.vaid_id());
        assert_eq!(issuer.revocation_status(&root), RevocationStatus::Revoked);
    }
    // child_parent_revoked: child of a revoked root -> Revoked (R.4.4)
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let root = issue_root(&issuer, "root");
        let child = issue_child(&issuer, &root, "child");
        issuer.revoke(root.vaid_id());
        assert_eq!(issuer.revocation_status(&child), RevocationStatus::Revoked);
    }
    // child_clean: child of a clean root            -> NotRevoked
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let root = issue_root(&issuer, "root");
        let child = issue_child(&issuer, &root, "child");
        assert_eq!(
            issuer.revocation_status(&child),
            RevocationStatus::NotRevoked
        );
    }
    // child_parent_unresolvable: restart truncation -> Unavailable (R.4.2)
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let root = issue_root(&issuer, "root");
        let child = issue_child(&issuer, &root, "child");
        issuer.clear_lineage();
        assert_eq!(
            issuer.revocation_status(&child),
            RevocationStatus::Unavailable
        );
    }
    // store_unavailable: store unreachable          -> Unavailable (R.4.3)
    {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .with_revocation_check(Arc::new(InMemoryRevocationList::unavailable()));
        let root = issue_root(&issuer, "root");
        assert_eq!(
            issuer.revocation_status(&root),
            RevocationStatus::Unavailable
        );
    }
}

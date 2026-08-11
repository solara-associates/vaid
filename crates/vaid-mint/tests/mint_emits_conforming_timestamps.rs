//! The mint's own output must satisfy the spec the mint publishes (E.6).
//!
//! # The defect this exists to catch (BACKLOG B8)
//!
//! The Rust issuer stored `Utc::now()` unmodified. `chrono` serializes a
//! `DateTime<Utc>` with whatever precision it carries, so every document this
//! crate minted went out as `2026-08-11T08:04:18.165623Z` — RFC 3339, and not the
//! whole-second `Z` profile `docs/spec/encoding.md` E.6 requires of every
//! timestamp inside signed bytes.
//!
//! # Why the existing suite could not see it
//!
//! Every test that touched a minted document **minted it and then verified it**.
//! That is self-consistent by construction: the mint signs over the sub-second
//! form and the verifier recomputes over the same sub-second form, so the
//! signature matches and the document is, on its own terms, valid. Cross-language
//! checks did not see it either, because Python and TypeScript canonicalize the
//! presented string verbatim and therefore agree with whatever Rust emitted.
//!
//! Conformance to a *profile* is not a property any round-trip can reveal. It has
//! to be asserted against the document directly, which is what this file does and
//! what nothing did before.
//!
//! # Assert the string, not just the predicate
//!
//! `has_conforming_timestamps` is itself new (it was announced in this crate's
//! CHANGELOG and never implemented). A test that only called it would be checking
//! a new predicate with a new predicate. So the serialized form is asserted
//! directly as well — that is the thing a signer actually signs and another
//! implementation actually reads.

use std::sync::Arc;

use serde_json::Value;
use vaid_mint::audit::InMemoryAudit;
use vaid_mint::{MintService, MintVaidRequest, ReferenceIssuer, VaidSeed};

/// The E.6 shape, spelled out rather than imported, so this test does not agree
/// with the implementation merely by sharing its definition of the answer.
fn is_e6(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

async fn mint_one() -> Value {
    let issuer = Arc::new(ReferenceIssuer::ephemeral(24, "vaid.example").expect("issuer"));
    let mint = MintService::new(issuer, Arc::new(InMemoryAudit::default()));
    let response = mint
        .mint_root(MintVaidRequest {
            seed: VaidSeed {
                agent_class: "conformance".into(),
                version: "1.0.0".into(),
                tenant_id: "acme".into(),
                parent_vaid: None,
                scope_boundary: vec!["data.acme".into()],
                capability_set: vec!["read".into()],
                public_key_der: None,
            },
            pop: None,
        })
        .await
        .expect("mint_root");
    serde_json::to_value(&response.vaid).expect("serializes")
}

#[tokio::test]
async fn a_freshly_minted_document_carries_whole_second_z_timestamps() {
    let doc = mint_one().await;
    for field in ["issued_at", "expires_at"] {
        let value = doc[field].as_str().expect("timestamp is a string");
        assert!(
            is_e6(value),
            "the mint emitted {field} = {value:?}, which is not the whole-second `Z` \
             profile E.6 requires of every timestamp inside signed bytes. This is the \
             mint's OWN output failing the mint's OWN spec — see BACKLOG B8."
        );
    }
}

#[tokio::test]
async fn the_predicate_agrees_with_the_bytes() {
    // Guards against the predicate and the serialization drifting apart: it would
    // be entirely possible to satisfy one and not the other.
    let issuer = Arc::new(ReferenceIssuer::ephemeral(24, "vaid.example").expect("issuer"));
    let mint = MintService::new(issuer, Arc::new(InMemoryAudit::default()));
    let response = mint
        .mint_root(MintVaidRequest {
            seed: VaidSeed {
                agent_class: "conformance".into(),
                version: "1.0.0".into(),
                tenant_id: "acme".into(),
                parent_vaid: None,
                scope_boundary: vec!["data.acme".into()],
                capability_set: vec!["read".into()],
                public_key_der: None,
            },
            pop: None,
        })
        .await
        .expect("mint_root");
    assert!(
        response.vaid.has_conforming_timestamps(),
        "has_conforming_timestamps() is false for a freshly minted document"
    );
}

/// THE CONTROL. `is_e6` must reject the form the mint actually used to emit,
/// otherwise the test above passes for a predicate that accepts everything.
#[test]
fn the_check_rejects_the_form_this_defect_shipped() {
    assert!(is_e6("2026-08-11T08:04:18Z"));
    assert!(
        !is_e6("2026-08-11T08:04:18.165623Z"),
        "the sub-second form B8 shipped must NOT pass — a check that accepts it \
         asserts nothing"
    );
    assert!(
        !is_e6("2026-08-11T08:04:18+00:00"),
        "numeric offset is not E.6"
    );
    assert!(
        !is_e6("2026-08-11T08:04:18.000Z"),
        "millisecond form is not E.6"
    );
    assert!(
        !is_e6("2026-08-11t08:04:18z"),
        "lowercase designators are not E.6"
    );
    assert!(!is_e6("not-a-timestamp"), "garbage is not E.6");
}

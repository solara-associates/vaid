//! Public-key-only VAID document verification (Workstream 3). Integration tests —
//! the verifying party holds ONLY the kernel public key, never a `ReferenceIssuer`
//! and never a private key.
//!
//! Revocation is outside the conformance surface and is not consulted here; these
//! are authenticity tests. `verifies_the_frozen_mint_vector_...` is the shared,
//! byte-identical input the Python suite verifies too — the cross-language anchor.

use serde_json::json;

use vaid_mint::document::{AgentClass, TenantId, Vaid};
use vaid_mint::issuer::{ReferenceIssuer, VaidIssuer};
use vaid_mint::{verify_lineage_hash, verify_vaid_authenticity};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Mint a root, then return ONLY its issuer's kernel public key and the document —
/// the issuer itself is dropped, so verification has no access to it.
fn public_key_and_doc() -> (Vec<u8>, Vaid) {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
    let vaid = issuer
        .issue_vaid_with_lineage(
            AgentClass::new("root"),
            "1.0.0".into(),
            TenantId::new("t"),
            None,
            vec!["data.x".into()],
            vec!["read".into()],
            None,
        )
        .unwrap();
    (issuer.kernel_public_key().to_vec(), vaid)
}

#[test]
fn third_party_verifies_with_public_key_only() {
    let (public_key, vaid) = public_key_and_doc();
    // No issuer instance in scope — only the public key bytes and the document.
    assert!(
        verify_vaid_authenticity(&public_key, &vaid),
        "a genuine VAID must verify against the issuer's public key alone"
    );
}

#[test]
fn tampered_document_fails() {
    let (public_key, vaid) = public_key_and_doc();
    // Widen the scope after signing — a valid-looking document, broken signature.
    let mut val = serde_json::to_value(&vaid).unwrap();
    val["scope_boundary"] = json!(["data.x", "data.everything"]);
    let forged: Vaid = serde_json::from_value(val).unwrap();
    assert!(
        !verify_vaid_authenticity(&public_key, &forged),
        "a rewritten field must fail"
    );
}

#[test]
fn a_different_key_does_not_verify() {
    let (_public_key, vaid) = public_key_and_doc();
    let other = ReferenceIssuer::ephemeral(1, "vaid.example")
        .unwrap()
        .kernel_public_key()
        .to_vec();
    assert!(
        !verify_vaid_authenticity(&other, &vaid),
        "another issuer's key must not verify it"
    );
}

#[test]
fn lineage_hash_mismatch_detected_explicitly() {
    // A document whose lineage_hash is wrong. `verify_lineage_hash` must reject it
    // DIRECTLY — recomputing from parent_vaid + agent_id — not incidentally via the
    // kernel signature.
    let (_public_key, vaid) = public_key_and_doc();
    assert!(
        verify_lineage_hash(&vaid),
        "the genuine document's lineage_hash is consistent"
    );

    let mut val = serde_json::to_value(&vaid).unwrap();
    val["lineage_hash"] = json!("00000000000000000000000000000000000000000000000000000000deadbeef");
    let bad: Vaid = serde_json::from_value(val).unwrap();
    assert!(
        !verify_lineage_hash(&bad),
        "an inconsistent lineage_hash must be caught by the explicit check"
    );
}

#[test]
fn verifies_the_frozen_mint_vector_with_public_key_only() {
    // Reconstruct the signed document from the FROZEN mint_v1 vector and verify it
    // against the vector's kernel PUBLIC key alone. The Python suite verifies the
    // identical vector — this is the cross-language agreement anchor.
    let raw = include_str!("vectors/mint_v1.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();

    let mut doc = v["input"].clone();
    let sig = hex(v["ed25519"]["signature_hex"].as_str().unwrap());
    doc["kernel_signature"] = json!(sig);
    let vaid: Vaid = serde_json::from_value(doc).unwrap();

    let public_key = hex(v["ed25519"]["kernel_public_key_hex"].as_str().unwrap());
    assert!(
        verify_vaid_authenticity(&public_key, &vaid),
        "the frozen mint vector must verify under its kernel public key alone"
    );
    // And a one-byte flip of the signature must fail.
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0x01;
    let mut doc2 = v["input"].clone();
    doc2["kernel_signature"] = json!(bad_sig);
    let tampered: Vaid = serde_json::from_value(doc2).unwrap();
    assert!(!verify_vaid_authenticity(&public_key, &tampered));
}

// ── RFC 3339 requires an offset (vaid#79, Session 240) ──

/// The three implementations must agree, and for a while they did not.
///
/// JavaScript's `Date.parse` reads a date-time with no offset as LOCAL time, so the
/// TypeScript twin called such a document **live** — and gave a different answer on
/// a UTC+2 laptop than on a UTC runner. This implementation and the Python one both
/// refuse it and call it expired, fail-closed. Pinned in all three so the agreement
/// is a tested property rather than a coincidence of three parsers.
///
/// `verdict_v1.json` covers an unreadable expiry and a numeric-offset expiry. It has
/// no offsetless case, which is why nothing caught this.
#[test]
fn an_offsetless_expiry_is_expired_not_live() {
    let naive = vaid_with_expiry("2999-01-01T00:00:00");
    let zulu = vaid_with_expiry("2999-01-01T00:00:00Z");
    let offset = vaid_with_expiry("2999-01-01T00:00:00+00:00");

    assert!(
        naive.is_expired(),
        "an offsetless expiry is not readable — fail closed"
    );
    assert!(!zulu.is_expired());
    assert!(!offset.is_expired(), "RFC 3339 allows a numeric offset");
}

/// Build a document carrying exactly this `expires_at`, as presented.
///
/// Routed through JSON rather than the constructor because the constructor takes a
/// `DateTime<Utc>` and formats it — which would make an unrepresentable timestamp
/// unrepresentable in the test too, and this test is about presented bytes
/// (ADR-0006).
fn vaid_with_expiry(expires_at: &str) -> Vaid {
    let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
    let doc = issuer
        .issue_vaid_with_lineage(
            AgentClass::new("probe"),
            "1.0.0".into(),
            TenantId::new("t"),
            None,
            vec![],
            vec![],
            None,
        )
        .unwrap();
    let mut json = serde_json::to_value(&doc).unwrap();
    json["expires_at"] = serde_json::Value::String(expires_at.to_string());
    serde_json::from_value(json).unwrap()
}

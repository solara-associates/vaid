//! Generator for the frozen cross-language **consent attestation** vector
//! (`attestation_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_attestation_vector`.
//!
//! The attestation is a **separate signed object**, not a VAID document field, so
//! this vector is additive in the same sense `chain_v1.json` is: `mint_v1.json` and
//! `mint_pop_v1.json` are untouched, and `sig_version` is unchanged. What it freezes
//! is `att_version` 1 — the field set, the canonicalization, and the signature over
//! it.
//!
//! The two parties are deliberately distinct in the vector: the attesting issuer is
//! in `a.example` and the child it consents to is in `b.example`, so the vector
//! exercises the cross-trust-domain case the object exists for, and so a reader
//! cannot mistake the unprefixed `trust_domain` for the child's (spec C.2).
//!
//! Same RFC 8032 kernel seed as `mint_v1.json`, and reserved `.example` domains for
//! the same reason: this vector publishes its own private seed, so a real trust
//! domain here would be a published forgery generator for that deployment.

use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use vaid_mint::attestation::{canonical_attestation_signing_bytes, ConsentAttestation};
use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::VaidId;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    const KERNEL_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PARENT_UUID: &str = "d0000000-0000-0000-0000-000000000001";
    const CHILD_UUID: &str = "d0000000-0000-0000-0000-000000000002";

    let kernel_kp = Ed25519KeyPair::from_seed_unchecked(&unhex(KERNEL_SEED_HEX)).unwrap();
    let kernel_pub = kernel_kp.public_key().as_ref().to_vec();

    let unsigned = ConsentAttestation::new(
        VaidId::from_uuid(Uuid::parse_str(PARENT_UUID).unwrap()),
        VaidId::from_uuid(Uuid::parse_str(CHILD_UUID).unwrap()),
        "b.example".to_string(),
        "aifactory".to_string(),
        // Fixed instants, as elsewhere in the vectors: a probe that depends on the
        // wall clock cannot be diffed across three processes.
        chrono::DateTime::parse_from_rfc3339("2026-06-04T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        chrono::DateTime::parse_from_rfc3339("2026-06-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        vec!["data.aifactory.sub".to_string()],
        vec!["read".to_string()],
        "a.example".to_string(),
        kernel_key_thumbprint(&kernel_pub),
    );

    let digest = canonical_attestation_signing_bytes(&unsigned);
    let signature = kernel_kp.sign(&digest);

    let out = serde_json::json!({
        "_comment": "Consent attestation conformance vector (att_version 1). Load-bearing. \
                     `attestation` is a real UNSIGNED attestation (snake_case) with `signature` \
                     empty. A conforming implementation MUST produce `digest_sha256_hex` from it \
                     by nulling `signature`, canonicalizing per JCS (RFC 8785) and SHA-256; and \
                     (given the kernel seed) reproduce `signature_hex` byte-for-byte. ADDITIVE: \
                     the attestation is a SEPARATE SIGNED OBJECT, so mint_v1.json, \
                     mint_pop_v1.json and chain_v1.json are untouched and `sig_version` is \
                     unchanged — `att_version` is this object's own discriminant. WHOSE FIELDS \
                     ARE WHOSE (spec C.2): the top-level `trust_domain` and \
                     `kernel_key_thumbprint` are the ATTESTING PARENT ISSUER'S and MUST equal the \
                     parent document's; `child_trust_domain` and `child_tenant_id` are what is \
                     AUTHORIZED and MUST equal the child document's. The two differ here \
                     (`a.example` consenting to a child in `b.example`) precisely so that \
                     distinction is visible in the bytes. `issued_at`/`expires_at` bound the \
                     consent; per spec C.6 a time bound is a MITIGATION, NOT WITHDRAWAL — \
                     retraction inside the window needs durable revocation, which does not exist \
                     in this implementation. Both domains are RFC 2606 reserved BY DESIGN: this \
                     vector publishes its own kernel private seed, so anyone can sign under it. \
                     Any drift is a break. SELF-CONSISTENT within this repo only (Decision B) — \
                     NOT conformant against the closed VAID format.",
        "attestation": unsigned,
        "digest_sha256_hex": to_hex(&digest),
        "signature_hex": to_hex(signature.as_ref()),
        "ed25519": {
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
        },
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

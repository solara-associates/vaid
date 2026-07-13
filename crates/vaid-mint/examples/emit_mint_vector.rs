//! Generator for the frozen cross-language mint vector (`mint_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_mint_vector` to print the
//! vector JSON. It builds a fully-specified, deterministic **unsigned** VAID
//! document, computes its canonical signing digest, and signs that digest with a
//! deterministic kernel key. Both the Rust and Python conformance suites must
//! reproduce `digest_sha256_hex` and `ed25519.signature_hex` byte-for-byte from
//! the same `input`.
//!
//! This proves self-consistency WITHIN this repo (Decision B) — Rust and Python
//! minters agree — NOT byte-identity against the managed authority's VAID format.
//!
//! The kernel seed is the same RFC 8032 test seed used by `operator_pop_v1.json`,
//! so the kernel public key is already known; only the VAID digest and the
//! signature over it are new.

use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use vaid_mint::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid, VaidId,
    VAID_SIG_VERSION_V2,
};

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
    // ── Fixed inputs (deterministic) ──
    const KERNEL_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let agent_uuid = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
    let parent_uuid = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let agent_id = AgentId::from_uuid(agent_uuid);
    let parent_vaid = Some(VaidId::from_uuid(parent_uuid));
    let agent_class = "child";
    let version = "1.0.0";
    let tenant_id = "aifactory";
    let issued_at = "2026-06-04T12:00:00Z";
    let expires_at = "2026-06-05T12:00:00Z";
    // A fixed 32-byte "registered child key" — bytes 0x00..0x1f.
    let public_key_der: Vec<u8> = (0u8..32).collect();
    let scope_boundary = vec!["data.aifactory.sub".to_string()];
    let capability_set = vec!["read".to_string()];

    // Derived: lineage_hash (proves the derivation is cross-language identical).
    let lineage_hash = compute_lineage_hash(parent_vaid, &agent_id);

    // Build the unsigned document exactly as the issuer does (empty signature).
    let unsigned = Vaid::with_lineage(
        agent_id,
        AgentClass::new(agent_class),
        version.to_string(),
        TenantId::new(tenant_id),
        chrono::DateTime::parse_from_rfc3339(issued_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
        chrono::DateTime::parse_from_rfc3339(expires_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
        public_key_der.clone(),
        Vec::new(), // empty kernel_signature (unsigned)
        parent_vaid,
        scope_boundary.clone(),
        lineage_hash.clone(),
        capability_set.clone(),
    );

    // Canonical digest (nulls kernel_signature internally).
    let digest = canonical_vaid_signing_bytes(&unsigned);

    // Sign the digest with the deterministic kernel key.
    let kernel_kp = Ed25519KeyPair::from_seed_unchecked(&unhex(KERNEL_SEED_HEX)).unwrap();
    let kernel_pub = kernel_kp.public_key().as_ref().to_vec();
    let signature = kernel_kp.sign(&digest);

    // The `input` is the unsigned document, snake_case, kernel_signature = [].
    let input = serde_json::json!({
        "sig_version": VAID_SIG_VERSION_V2,
        "vaid_id": agent_uuid.to_string(),
        "agent_id": agent_uuid.to_string(),
        "agent_class": agent_class,
        "version": version,
        "tenant_id": tenant_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "public_key_der": public_key_der,
        "kernel_signature": [],
        "parent_vaid": parent_uuid.to_string(),
        "scope_boundary": scope_boundary,
        "lineage_hash": lineage_hash,
        "capability_set": capability_set,
    });

    let vector = serde_json::json!({
        "_comment": "Mint conformance vector (v1). Load-bearing. `input` is a real UNSIGNED \
                     VAID document (snake_case; the Rust `Vaid` has no serde rename), with \
                     `kernel_signature` empty. A conforming mint MUST produce `digest_sha256_hex` \
                     from `input` by nulling `kernel_signature`, canonicalizing per JCS (RFC 8785), \
                     and SHA-256; and (given the kernel seed) reproduce `ed25519.signature_hex` \
                     byte-for-byte. `input.lineage_hash` MUST equal \
                     sha256_hex(parent_vaid==null ? 'GENESIS:{agent_id}' : '{parent_vaid}:{agent_id}'), \
                     and `input.vaid_id` MUST equal `input.agent_id`. Any drift is a break. \
                     SELF-CONSISTENT within this repo only (Decision B) — NOT conformant against \
                     the closed VAID format.",
        "scheme": "JCS(RFC8785) over the full VAID document with kernel_signature nulled -> \
                   SHA-256 -> pure Ed25519 over the 32-byte digest as raw message; raw 64-byte \
                   signature; raw 32-byte kernel public key",
        "input": input,
        "digest_sha256_hex": to_hex(&digest),
        "ed25519": {
            "_comment": "Deterministic kernel key (same RFC 8032 seed as operator_pop_v1.json). \
                         Any conforming mint derives the same kernel public key and produces the \
                         same signature over digest_sha256_hex.",
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
            "signature_hex": to_hex(signature.as_ref()),
        }
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

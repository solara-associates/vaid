//! Byte-agreement probe for the **detached consent attestation** format.
//!
//! Run with `cargo run -p vaid-mint --example emit_attestation_digest`.
//!
//! This is deliberately NOT a frozen vector, and nothing vendors its output. The
//! attestation is a new signed object; freezing its canonicalization is the one
//! decision here that is expensive to unwind, so the format stays reviewable until
//! it has been reviewed. What this proves in the meantime is the property a vector
//! would prove — that all three implementations canonicalize and sign the same
//! bytes — without committing to the shape.
//!
//! The Python (`scripts/emit_attestation_digest.py`) and TypeScript
//! (`scripts/emit-attestation-digest.mjs`) probes emit byte-identical JSON;
//! `scripts/attestation_byte_agreement.sh` runs all three and diffs them.
//!
//! Same RFC 8032 kernel seed as `mint_v1.json`, and `vaid.example` for the same
//! reason: a probe that publishes its own private seed must not name a bindable
//! trust domain.

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
        vec!["data.aifactory.sub".to_string()],
        vec!["read".to_string()],
        "a.example".to_string(),
        kernel_key_thumbprint(&kernel_pub),
    );

    let digest = canonical_attestation_signing_bytes(&unsigned);
    let signature = kernel_kp.sign(&digest);

    let out = serde_json::json!({
        "_comment": "Byte-agreement probe for the consent attestation format. NOT A FROZEN \
                     VECTOR and not vendored anywhere. All three implementations must emit \
                     this file byte-identically; scripts/attestation_byte_agreement.sh checks it.",
        "attestation": unsigned,
        "digest_sha256_hex": to_hex(&digest),
        "signature_hex": to_hex(signature.as_ref()),
        "kernel_public_key_hex": to_hex(&kernel_pub),
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

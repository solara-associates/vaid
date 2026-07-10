//! Canonical mint conformance gate (Rust side of the cross-language firewall).
//!
//! The vendored vector `tests/vectors/mint_v1.json` is byte-identical to the copy
//! shipped in the Python `vaid-mint` package (a CI drift-check enforces that).
//! These tests assert the Rust mint reproduces the frozen VAID-document digest +
//! kernel signature byte-for-byte, and that the derived fields (`lineage_hash`,
//! `vaid_id == agent_id`) match. A mismatch is a BLOCKER.
//!
//! Per Decision B this proves self-consistency WITHIN this repo (Rust == Python),
//! NOT conformance against the closed substrate's VAID format.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_mint::{canonical_vaid_signing_bytes, compute_lineage_hash, Vaid, VaidId};

const VECTOR_JSON: &str = include_str!("vectors/mint_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("vector json parses")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn input_vaid(v: &Value) -> Vaid {
    serde_json::from_value(v["input"].clone())
        .expect("vector input must deserialize into a real (unsigned) Vaid document")
}

/// The canonical digest over the REAL `Vaid` document (kernel_signature nulled)
/// must equal the frozen vector.
#[test]
fn mint_reproduces_frozen_document_digest() {
    let v = vector();
    let vaid = input_vaid(&v);
    let digest = canonical_vaid_signing_bytes(&vaid);
    assert_eq!(
        to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap(),
        "Rust VAID-document digest diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(digest.len(), 32);
}

/// From the frozen kernel seed, the kernel signs the digest and reproduces the
/// frozen signature byte-for-byte, and it verifies under the kernel public key.
#[test]
fn mint_reproduces_frozen_kernel_signature() {
    let v = vector();
    let vaid = input_vaid(&v);
    let digest = canonical_vaid_signing_bytes(&vaid);

    let seed = unhex(v["ed25519"]["kernel_private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte kernel seed");

    // Kernel public key derives to the frozen value.
    assert_eq!(
        to_hex(kp.public_key().as_ref()),
        v["ed25519"]["kernel_public_key_hex"].as_str().unwrap(),
        "kernel public key diverged — BLOCKER"
    );

    let sig = kp.sign(&digest);
    assert_eq!(
        to_hex(sig.as_ref()),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "Rust kernel signature diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(sig.as_ref().len(), 64);
}

/// The derived `lineage_hash` in the document must equal
/// `compute_lineage_hash(parent_vaid, agent_id)` — proves the derivation, not
/// just a stored field.
#[test]
fn mint_reproduces_frozen_lineage_hash() {
    let v = vector();
    let vaid = input_vaid(&v);
    let recomputed = compute_lineage_hash(vaid.parent_vaid(), &vaid.agent_id());
    assert_eq!(
        recomputed,
        vaid.lineage_hash(),
        "recomputed lineage_hash diverged from the document — BLOCKER"
    );
}

/// `vaid_id` is derived from `agent_id` (same UUID) — assert the invariant holds
/// for the frozen document.
#[test]
fn vaid_id_equals_agent_id() {
    let v = vector();
    let vaid = input_vaid(&v);
    assert_eq!(
        vaid.vaid_id(),
        VaidId::from_uuid(*vaid.agent_id().as_uuid()),
        "vaid_id must equal VaidId::from_uuid(agent_id)"
    );
    // And the frozen strings agree.
    assert_eq!(
        v["input"]["vaid_id"], v["input"]["agent_id"],
        "vector vaid_id and agent_id strings must match"
    );
}

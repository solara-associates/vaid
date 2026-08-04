//! Consent attestation conformance gate (`att_version` 1). Rust side.
//!
//! The vendored vector `tests/vectors/attestation_v1.json` is byte-identical to the
//! Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies; CI `cmp`s all
//! three, so "Rust reproduces the vector" plus "the vectors are the same bytes"
//! gives Rust == Python == TypeScript without a fourth comparison.
//!
//! Nothing here reconstructs the vector's contents in code. A test that builds its
//! own expectation proves only that the code agrees with itself.
//!
//! ADDITIVE: the attestation is a separate signed object, so freezing it re-freezes
//! nothing. `mint_v1.json`, `mint_pop_v1.json` and `chain_v1.json` are untouched and
//! `sig_version` is unchanged.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_mint::attestation::{
    canonical_attestation_signing_bytes, verify_attestation_authenticity, ConsentAttestation,
    ATTESTATION_VERSION,
};

const VECTOR_JSON: &str = include_str!("vectors/attestation_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("attestation_v1.json parses")
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

fn unsigned(v: &Value) -> ConsentAttestation {
    serde_json::from_value(v["attestation"].clone()).expect("attestation deserializes")
}

/// The canonical digest, reproduced from the vector's own attestation.
#[test]
fn reproduces_the_frozen_digest() {
    let v = vector();
    assert_eq!(
        to_hex(&canonical_attestation_signing_bytes(&unsigned(&v))),
        v["digest_sha256_hex"].as_str().unwrap(),
        "attestation canonicalization drift"
    );
}

/// The kernel signature, reproduced from the vector's seed.
#[test]
fn reproduces_the_frozen_signature() {
    let v = vector();
    let seed = unhex(
        v["ed25519"]["kernel_private_key_seed_hex"]
            .as_str()
            .unwrap(),
    );
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();

    assert_eq!(
        to_hex(kp.public_key().as_ref()),
        v["ed25519"]["kernel_public_key_hex"].as_str().unwrap(),
        "the seed does not derive the vector's kernel public key"
    );

    let signature = kp.sign(&canonical_attestation_signing_bytes(&unsigned(&v)));
    assert_eq!(
        to_hex(signature.as_ref()),
        v["signature_hex"].as_str().unwrap(),
        "attestation signature drift"
    );
}

/// The frozen signature verifies as authentic under the frozen key — the property a
/// third party actually exercises.
#[test]
fn the_frozen_signature_verifies_as_authentic() {
    let v = vector();
    let signed = unsigned(&v).with_signature(unhex(v["signature_hex"].as_str().unwrap()));
    let key = unhex(v["ed25519"]["kernel_public_key_hex"].as_str().unwrap());

    assert!(
        verify_attestation_authenticity(&key, &signed),
        "the frozen attestation must verify under the frozen kernel key"
    );
}

/// The vector's own shape, so a regenerated vector that quietly changed the field
/// set or collapsed the two parties cannot still pass.
#[test]
fn the_frozen_attestation_has_the_expected_shape() {
    let v = vector();
    let a = &v["attestation"];

    assert_eq!(
        a["att_version"].as_u64().unwrap() as u8,
        ATTESTATION_VERSION,
        "att_version must be the current discriminant"
    );
    assert!(
        a["signature"].as_array().unwrap().is_empty(),
        "the vector's attestation is UNSIGNED; the signature travels separately"
    );

    // Spec C.2: the top-level pair is the ATTESTING PARENT ISSUER'S, the child_*
    // pair is what is AUTHORIZED. Frozen with the two DIFFERENT, so a future change
    // that conflated them would fail here rather than pass silently.
    assert_ne!(
        a["trust_domain"].as_str().unwrap(),
        a["child_trust_domain"].as_str().unwrap(),
        "the vector must exercise the cross-trust-domain case the object exists for"
    );

    // The window is bounded — an attestation with no expiry is not representable.
    assert!(a["issued_at"].is_string() && a["expires_at"].is_string());
    assert!(
        a["expires_at"].as_str().unwrap() > a["issued_at"].as_str().unwrap(),
        "the frozen window must be satisfiable"
    );
}

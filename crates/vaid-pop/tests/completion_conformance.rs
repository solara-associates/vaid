//! Completion-record conformance gate (Rust side of the cross-language firewall).
//!
//! The vendored vector `tests/vectors/completion_v1.json` is byte-identical to the
//! copy shipped in the Python `vaid-pop` package (a CI drift-check enforces that).
//! Asserts the Rust signer reproduces the frozen digest + signature for a real
//! [`CompletionRecord`], and — because this is the FIRST vector with an enum —
//! that every [`AssuranceTier`] serializes to exactly the frozen string (the most
//! likely place for silent Rust/Python drift). A mismatch is a BLOCKER.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_pop::request_completion::{AssuranceTier, CompletionRecord};
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

const VECTOR_JSON: &str = include_str!("vectors/completion_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("vector json parses")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn input_record(v: &Value) -> CompletionRecord {
    serde_json::from_value(v["input"].clone())
        .expect("vector input must deserialize into a real CompletionRecord (camelCase)")
}

#[test]
fn reproduces_frozen_completion_digest() {
    let v = vector();
    let rec = input_record(&v);
    let digest = canonical_request_signing_bytes(&rec);
    assert_eq!(
        to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap(),
        "Rust completion-record digest diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(digest.len(), 32);
}

#[test]
fn reproduces_frozen_completion_signature() {
    let v = vector();
    let rec = input_record(&v);
    let digest = canonical_request_signing_bytes(&rec);
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte seed");
    assert_eq!(
        to_hex(kp.public_key().as_ref()),
        v["ed25519"]["public_key_hex"].as_str().unwrap(),
        "public key diverged — BLOCKER"
    );
    let sig = kp.sign(&digest);
    assert_eq!(
        to_hex(sig.as_ref()),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "Rust completion signature diverged from the frozen vector — BLOCKER"
    );
}

/// THE ENUM DRIFT GUARD: every `AssuranceTier` variant must serialize to exactly
/// the frozen string in `assurance_tier_strings`, in order. This is the first
/// vector with an enum, and the field where Rust `rename_all=camelCase` and the
/// Python string values must agree byte-for-byte inside the signed document.
#[test]
fn assurance_tier_strings_match_frozen_vector() {
    let v = vector();
    let frozen: Vec<String> = v["assurance_tier_strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let tiers = [
        AssuranceTier::SelfReported,
        AssuranceTier::CounterSigned,
        AssuranceTier::ThirdPartyAttested,
    ];
    let serialized: Vec<String> = tiers
        .iter()
        .map(|t| serde_json::to_value(t).unwrap().as_str().unwrap().to_string())
        .collect();
    assert_eq!(serialized, frozen, "AssuranceTier strings diverged from the frozen vector — BLOCKER");

    // And the input's declared tier deserializes to the substantiated tier.
    let rec = input_record(&v);
    assert_eq!(rec.assurance_tier, AssuranceTier::SelfReported);
}

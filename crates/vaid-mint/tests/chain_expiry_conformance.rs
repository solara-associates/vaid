//! Expiry-containment conformance gate (vaid#79). Rust side.
//!
//! The vendored vector `tests/vectors/chain_expiry_v1.json` is byte-identical to the
//! Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies; CI `cmp`s all
//! three, so "Rust reproduces the vector" plus "the vectors are the same bytes"
//! gives Rust == Python == TypeScript without a fourth comparison.
//!
//! Nothing here reconstructs the vector's expectations in code. A test that builds
//! its own expectation proves only that the code agrees with itself — and that is
//! precisely how the defect this vector closes survived: `chain_v1` asserted
//! `attenuated` over a chain whose every document had expired, and three
//! implementations agreed with it.

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_mint::attestation::AttestationBundle;
use vaid_mint::chain::{verify_chain_at, ChainVerification, PresentedBundle, SingleKernelKey};
use vaid_mint::mint::expiry_attenuates_within;
use vaid_mint::{canonical_vaid_signing_bytes, Vaid};

const VECTOR_JSON: &str = include_str!("vectors/chain_expiry_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("chain_expiry_v1.json parses")
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

fn keypair(v: &Value) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&unhex(
        v["ed25519"]["kernel_private_key_seed_hex"]
            .as_str()
            .unwrap(),
    ))
    .expect("vector seed is a usable Ed25519 seed")
}

fn signed_document(entry: &Value) -> Vaid {
    let unsigned: Vaid =
        serde_json::from_value(entry["document"].clone()).expect("vector document deserializes");
    unsigned.with_kernel_signature(unhex(entry["signature_hex"].as_str().unwrap()))
}

fn instant(case: &Value) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(
        case["verification_instant"]
            .as_str()
            .expect("every case states the instant its verdict holds at"),
    )
    .expect("verification_instant is RFC 3339")
    .with_timezone(&Utc)
}

fn verdict_name(verdict: ChainVerification) -> &'static str {
    match verdict {
        ChainVerification::Attenuated => "attenuated",
        ChainVerification::Inauthentic => "inauthentic",
        ChainVerification::Unverifiable => "unverifiable",
        ChainVerification::NotAttenuated => "not_attenuated",
        ChainVerification::Expired => "expired",
        ChainVerification::ConsentExpired => "consent_expired",
    }
}

/// Every document in every case, from the vector's own kernel seed. Without this the
/// verdicts below could be verdicts over bytes nobody checked.
#[test]
fn reproduces_every_frozen_digest_and_signature() {
    let v = vector();
    let kp = keypair(&v);
    assert_eq!(
        to_hex(kp.public_key().as_ref()),
        v["ed25519"]["kernel_public_key_hex"].as_str().unwrap(),
        "the seed does not derive the vector's kernel public key"
    );

    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        for entry in case["chain"].as_array().unwrap() {
            let role = entry["_role"].as_str().unwrap();
            let unsigned: Vaid = serde_json::from_value(entry["document"].clone()).unwrap();
            let digest = canonical_vaid_signing_bytes(&unsigned);
            assert_eq!(
                to_hex(&digest),
                entry["digest_sha256_hex"].as_str().unwrap(),
                "digest drift at {name} / {role}"
            );
            assert_eq!(
                to_hex(kp.sign(&digest).as_ref()),
                entry["signature_hex"].as_str().unwrap(),
                "signature drift at {name} / {role}"
            );
        }
    }
}

/// THE MATCHER, as the mint applies it to a delegation not yet issued.
#[test]
fn every_expiry_containment_case() {
    let v = vector();
    for case in v["expiry_containment"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let permitted = expiry_attenuates_within(
            case["parent_expires_at"].as_str().unwrap_or(""),
            case["child_expires_at"].as_str(),
        );
        let want = case["expected"].as_str().unwrap() == "permitted";
        assert_eq!(
            permitted,
            want,
            "expiry containment drift: {name} — expected {}",
            case["expected"].as_str().unwrap()
        );
    }
}

/// THE WALK, at each case's own stated instant — never the suite's clock.
#[test]
fn every_chain_case_reaches_its_frozen_verdict() {
    let v = vector();
    let kp = keypair(&v);

    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let docs: Vec<Vaid> = case["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(signed_document)
            .collect();
        let leaf = docs.last().expect("chain is non-empty").clone();

        let actual = verdict_name(verify_chain_at(
            &SingleKernelKey::new(kp.public_key().as_ref()),
            &leaf,
            &PresentedBundle::new(docs),
            &AttestationBundle::default(),
            instant(case),
        ));
        assert_eq!(
            actual,
            case["expected_verification"].as_str().unwrap(),
            "chain verdict drift: {name}"
        );
    }
}

/// The controls are load-bearing, so their presence is asserted rather than assumed.
/// An implementation that refuses everything satisfies every negative case in this
/// file; only a case that MUST succeed catches it.
#[test]
fn the_vector_carries_positive_controls_on_both_surfaces() {
    let v = vector();
    let verdicts: Vec<&str> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["expected_verification"].as_str().unwrap())
        .collect();

    assert!(
        verdicts.contains(&"attenuated"),
        "no chain case must succeed — every negative below it is vacuous"
    );
    assert!(
        verdicts.contains(&"expired"),
        "the vector must carry the lapsed-ancestor case it exists for"
    );
    assert!(
        verdicts.contains(&"not_attenuated"),
        "the vector must carry the child-outliving-its-parent case"
    );
    assert!(
        v["expiry_containment"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["expected"].as_str() == Some("permitted")),
        "no containment case must succeed — the predicate could return false always"
    );
}

/// A case without a stated instant would be asserted against whatever the calendar
/// said on the day the suite ran — which is exactly how `chain_v1` came to pin
/// `attenuated` over three documents that had been dead since June.
#[test]
fn every_chain_case_states_its_own_verification_instant() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let stated = case["verification_instant"].as_str();
        assert!(
            stated.map(|s| s.ends_with('Z')).unwrap_or(false),
            "{} has no stated verification instant",
            case["name"].as_str().unwrap()
        );
    }
}

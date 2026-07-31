//! Mint proof-of-possession conformance gate (Rust side of the cross-language
//! firewall).
//!
//! The vendored vector `tests/vectors/mint_pop_v1.json` is byte-identical to the
//! copies shipped in the Python and TypeScript `vaid-mint` packages (a CI
//! drift-check enforces that). It pins [`MintPopPayload`] — the payload a holder
//! signs to prove it controls the BYO public key it registers at mint.
//!
//! ## Why this gate was added late
//!
//! `MintPopPayload` was, until this vector, the one **signed** structure in VAID
//! with no frozen artifact (`docs/spec/encoding.md` E.11). The three reference
//! implementations agreed on it *by construction* — they share the `vaid-pop`
//! primitive and were written against each other — not because anything held them
//! to it. A fourth implementation could have encoded it differently, passed every
//! conformance gate in the repo, and failed only later as an unexplained
//! proof-of-possession rejection at mint.
//!
//! ## What this vector pins that the other four do not
//!
//! - **A JSON `null` inside signed bytes.** This is the root case, so `parentVaid`
//!   is null. No other frozen vector contains a null, so nothing previously held
//!   an implementation to encoding.md E.7 — an absent value is `null` with its key
//!   retained, never an omitted key.
//! - **The registered key is the signing key.** `publicKeyDer` is the public half
//!   of the seed that produces `signature_hex`, so the vector is checkable
//!   end-to-end through `verify_signed_payload` — the same call
//!   `MintService::verify_pop_at_mint` makes before issuing.
//!
//! A mismatch is a BLOCKER.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_mint::mint_types::{MintPopPayload, VaidSeed};
use vaid_pop::vaid_pop::{canonical_request_signing_bytes, sign_payload, verify_signed_payload};

const VECTOR_JSON: &str = include_str!("vectors/mint_pop_v1.json");

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

fn input_payload(v: &Value) -> MintPopPayload {
    serde_json::from_value(v["input"].clone())
        .expect("vector input must deserialize into a real MintPopPayload (camelCase)")
}

fn holder_keypair(v: &Value) -> Ed25519KeyPair {
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte ed25519 seed")
}

/// The canonical digest over the REAL camelCase `MintPopPayload` must equal the
/// frozen vector.
#[test]
fn reproduces_frozen_mint_pop_digest() {
    let v = vector();
    let payload = input_payload(&v);
    let digest = canonical_request_signing_bytes(&payload);
    assert_eq!(
        to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap(),
        "Rust mint-PoP digest diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(digest.len(), 32);
}

/// From the frozen holder seed, signing the digest reproduces the frozen
/// signature byte-for-byte.
#[test]
fn reproduces_frozen_mint_pop_signature() {
    let v = vector();
    let payload = input_payload(&v);
    let kp = holder_keypair(&v);

    assert_eq!(
        to_hex(kp.public_key().as_ref()),
        v["ed25519"]["public_key_hex"].as_str().unwrap(),
        "holder public key diverged — BLOCKER"
    );

    let signature = sign_payload(&payload, &kp);
    assert_eq!(
        to_hex(&signature),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "Rust mint-PoP signature diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(signature.len(), 64);
}

/// `VaidSeed::pop_payload` — the SINGLE constructor both holder and mint build the
/// payload through — must produce exactly the frozen payload. Deserializing the
/// vector and re-serializing it would only prove serde round-trips; this proves
/// the code path that actually runs at mint emits these bytes.
#[test]
fn seed_pop_payload_constructor_reproduces_the_frozen_payload() {
    let v = vector();
    let kp = holder_keypair(&v);
    let registered_key = kp.public_key().as_ref().to_vec();

    let seed = VaidSeed {
        agent_class: "runner".into(),
        version: "1.0.0".into(),
        tenant_id: "aifactory".into(),
        parent_vaid: None,
        scope_boundary: vec!["data.aifactory".to_string()],
        capability_set: vec!["read".to_string()],
        public_key_der: Some(registered_key.clone()),
    };
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-06-04T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let built = seed.pop_payload(
        registered_key,
        "0123456789abcdef0123456789abcdef".to_string(),
        issued_at,
    );

    assert_eq!(
        serde_json::to_value(&built).unwrap(),
        v["input"],
        "the mint's own payload constructor diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(
        to_hex(&canonical_request_signing_bytes(&built)),
        v["digest_sha256_hex"].as_str().unwrap()
    );
}

/// THE E.7 GUARD: this is the only frozen vector carrying a JSON `null`, and the
/// null must be a PRESENT key. An implementation that omits `parentVaid` for a
/// root produces a different key set and a different digest.
#[test]
fn parent_vaid_is_a_present_null_not_an_omitted_key() {
    let v = vector();
    let input = v["input"].as_object().unwrap();
    assert!(
        input.contains_key("parentVaid"),
        "the key must be present — encoding.md E.7"
    );
    assert!(
        input["parentVaid"].is_null(),
        "this is the root case; parentVaid must be null"
    );

    // Omitting the key changes the canonical bytes. Proven, not asserted.
    let mut without = input.clone();
    without.remove("parentVaid");
    let digest_without = canonical_request_signing_bytes(&Value::Object(without));
    assert_ne!(
        to_hex(&digest_without),
        v["digest_sha256_hex"].as_str().unwrap(),
        "omitting parentVaid MUST change the digest — otherwise E.7 is untested"
    );
}

/// THE PoP SEMANTIC: the frozen signature verifies against the key the payload
/// REGISTERS — the same check `MintService::verify_pop_at_mint` performs. A
/// signature that verified against some other key would prove nothing about
/// possession of the registered key.
#[test]
fn frozen_signature_verifies_against_the_registered_key() {
    let v = vector();
    let payload = input_payload(&v);
    let registered_key = payload.public_key_der.clone();
    let signature = unhex(v["ed25519"]["signature_hex"].as_str().unwrap());

    assert_eq!(
        to_hex(&registered_key),
        v["ed25519"]["public_key_hex"].as_str().unwrap(),
        "publicKeyDer must BE the holder's public key — that is what PoP means"
    );
    assert!(
        verify_signed_payload(&payload, &registered_key, &signature),
        "the frozen PoP must verify against the registered key — BLOCKER"
    );

    // And a tampered payload must not verify: this is the replay/substitution
    // defence the payload's field set exists for.
    let mut escalated = payload.clone();
    escalated.capability_set = vec!["read".into(), "write".into()];
    assert!(
        !verify_signed_payload(&escalated, &registered_key, &signature),
        "a captured PoP must not be replayable to mint a higher-privilege VAID"
    );
}

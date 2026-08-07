//! Round-trip verification conformance (ADR-0006).
//!
//! Verify-only, and a shape the surface did not previously have: every other
//! vector pins one implementation's OUTPUT FOR A GIVEN INPUT; this one pins A
//! VERDICT OVER GIVEN BYTES. That is the only shape that can catch
//! cross-implementation disagreement, because the defect it exists for appears
//! only when one implementation mints and another verifies.
//!
//! Before ADR-0006 this crate FAILED case 2 and WRONGLY ACCEPTED case 4: its
//! typed `Vaid` discarded unrecognised members before canonicalizing, so it
//! hashed a document nobody sent. Python and TypeScript passed all four
//! throughout — the disagreement was invisible because nothing asked.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use vaid_mint::{canonical_vaid_signing_bytes, Vaid};

const VECTOR_JSON: &str = include_str!("vectors/roundtrip_v1.json");

#[derive(Deserialize)]
struct Vector {
    ed25519: Keys,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Keys {
    kernel_public_key_hex: String,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    why: String,
    document: serde_json::Value,
    expected_valid: bool,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vector() -> Vector {
    serde_json::from_str(VECTOR_JSON).expect("roundtrip_v1.json parses")
}

#[test]
fn every_case_returns_the_frozen_verdict() {
    let v = vector();
    let pk_bytes = unhex(&v.ed25519.kernel_public_key_hex);
    for case in &v.cases {
        let doc: Vaid =
            serde_json::from_value(case.document.clone()).expect("case document deserializes");
        let pk = UnparsedPublicKey::new(&ED25519, &pk_bytes);
        let got = pk
            .verify(&canonical_vaid_signing_bytes(&doc), doc.kernel_signature())
            .is_ok();
        assert_eq!(
            got, case.expected_valid,
            "roundtrip_v1 case '{}' returned {got}, expected {} — {}",
            case.name, case.expected_valid, case.why
        );
    }
}

/// The requirement behind the verdicts: parsing and re-serializing MUST
/// reproduce the presented object. If this fails, canonicalization has stopped
/// being a function of the input and the verdicts above are luck.
#[test]
fn every_case_round_trips_byte_exactly() {
    for case in &vector().cases {
        let doc: Vaid = serde_json::from_value(case.document.clone()).expect("deserializes");
        let back = serde_json::to_value(&doc).expect("serializes");
        assert_eq!(
            back, case.document,
            "roundtrip_v1 case '{}' did not round-trip: the implementation is \
             re-projecting the document rather than preserving it (ADR-0006)",
            case.name
        );
    }
}

/// The vector must DISCRIMINATE. A verify-only vector every implementation
/// passes regardless of behaviour asserts nothing, so this reconstructs the
/// pre-ADR-0006 dropping behaviour and requires it to fail — in BOTH
/// directions, since dropping produces a false negative on one case and a false
/// ACCEPT on another.
#[test]
fn the_vector_catches_an_implementation_that_drops_unknown_members() {
    let v = vector();
    let pk_bytes = unhex(&v.ed25519.kernel_public_key_hex);
    let mut caught_false_negative = false;
    let mut caught_false_accept = false;

    for case in &v.cases {
        let mut dropped = case.document.clone();
        let sig: Vec<u8> = dropped["kernel_signature"]
            .as_array()
            .expect("sig array")
            .iter()
            .map(|n| n.as_u64().expect("byte") as u8)
            .collect();
        // Simulate the defect: discard every member a typed struct would not name.
        if let serde_json::Value::Object(m) = &mut dropped {
            m.retain(|k, _| !k.starts_with("x_"));
            m.insert("kernel_signature".into(), serde_json::Value::Null);
        }
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(serde_jcs::to_vec(&dropped).expect("jcs")).to_vec()
        };
        let got = UnparsedPublicKey::new(&ED25519, &pk_bytes)
            .verify(&digest, &sig)
            .is_ok();
        if got != case.expected_valid {
            if case.expected_valid {
                caught_false_negative = true;
            } else {
                caught_false_accept = true;
            }
        }
    }

    assert!(
        caught_false_negative,
        "the vector no longer catches a dropping implementation rejecting a VALID \
         document — its core case has been weakened"
    );
    assert!(
        caught_false_accept,
        "the vector no longer catches a dropping implementation ACCEPTING an invalid \
         document — the sharper of the two directions has been lost"
    );
}

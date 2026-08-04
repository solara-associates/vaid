//! Chain-presentation conformance gate (ADR-0003 §3). Rust side.
//!
//! The vendored vector `tests/vectors/chain_v1.json` is byte-identical to the
//! Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies; CI `cmp`s all
//! three, so "Rust reproduces the vector" plus "the vectors are the same bytes"
//! gives Rust == Python == TypeScript without a fourth comparison.
//!
//! Nothing here reconstructs the vector's contents in code. A test that builds its
//! own expectation proves only that the code agrees with itself.
//!
//! This vector is **additive** (ADR-0003 §3): it does not re-freeze `mint_v1.json`
//! or `mint_pop_v1.json`, and it introduces no new signed field. What it pins that
//! `mint_v1` does not is the *walk* — the assembled lineage and the verdict.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_mint::chain::{verify_chain, ChainVerification, PresentedBundle};
use vaid_mint::revocation::{assemble_lineage, LineageAssembly};
use vaid_mint::{canonical_vaid_signing_bytes, Vaid};

const VECTOR_JSON: &str = include_str!("vectors/chain_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("chain_v1.json parses")
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

/// Deserialize one hop's `document` into a `Vaid` and attach its frozen signature.
/// The document in the vector is UNSIGNED, exactly as `mint_v1.json`'s `input` is.
fn signed_document(entry: &Value) -> Vaid {
    let unsigned: Vaid =
        serde_json::from_value(entry["document"].clone()).expect("document deserializes as a Vaid");
    unsigned.with_kernel_signature(unhex(entry["signature_hex"].as_str().unwrap()))
}

fn kernel_public_key(v: &Value) -> Vec<u8> {
    unhex(v["ed25519"]["kernel_public_key_hex"].as_str().unwrap())
}

/// Every hop's canonical digest is reproduced from the vector's own document.
#[test]
fn reproduces_every_frozen_hop_digest() {
    let v = vector();
    for entry in v["chain"].as_array().unwrap() {
        let unsigned: Vaid = serde_json::from_value(entry["document"].clone()).unwrap();
        assert_eq!(
            to_hex(&canonical_vaid_signing_bytes(&unsigned)),
            entry["digest_sha256_hex"].as_str().unwrap(),
            "digest drift at hop {}",
            entry["_role"]
        );
    }
}

/// Every hop's kernel signature is reproduced from the vector's kernel seed.
#[test]
fn reproduces_every_frozen_hop_signature() {
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

    for entry in v["chain"].as_array().unwrap() {
        let unsigned: Vaid = serde_json::from_value(entry["document"].clone()).unwrap();
        let signature = kp.sign(&canonical_vaid_signing_bytes(&unsigned));
        assert_eq!(
            to_hex(signature.as_ref()),
            entry["signature_hex"].as_str().unwrap(),
            "signature drift at hop {}",
            entry["_role"]
        );
    }
}

/// THE WALK, part 1: assembly order. Presented with the two ancestors as a
/// detached bundle, the leaf's lineage assembles to exactly the frozen order —
/// root first, leaf last.
#[test]
fn reproduces_the_frozen_assembled_lineage() {
    let v = vector();
    let docs: Vec<Vaid> = v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(signed_document)
        .collect();
    let leaf = docs.last().expect("chain is non-empty").clone();
    let bundle = PresentedBundle::new(docs);

    let expected: Vec<String> = v["expected"]["assembled_lineage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();

    match assemble_lineage(&leaf, &bundle) {
        LineageAssembly::Complete(ids) => assert_eq!(
            ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
            expected,
            "assembled lineage drift"
        ),
        LineageAssembly::Incomplete => panic!("the frozen chain must assemble completely"),
    }
}

/// THE WALK, part 2: the verdict. This is the assertion the vector exists for —
/// two implementations could agree on every digest and still disagree here.
#[test]
fn reproduces_the_frozen_verification_verdict() {
    let v = vector();
    let docs: Vec<Vaid> = v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(signed_document)
        .collect();
    let leaf = docs.last().expect("chain is non-empty").clone();
    let bundle = PresentedBundle::new(docs);

    let verdict = verify_chain(&kernel_public_key(&v), &leaf, &bundle);

    let expected = v["expected"]["verification"].as_str().unwrap();
    let actual = match verdict {
        ChainVerification::Attenuated => "attenuated",
        ChainVerification::Inauthentic => "inauthentic",
        ChainVerification::Unverifiable => "unverifiable",
        ChainVerification::NotAttenuated => "not_attenuated",
    };
    assert_eq!(actual, expected, "chain verification verdict drift");
}

/// The vector's own shape, asserted so a regenerated vector that quietly lost a
/// hop cannot still pass. Three hops is the smallest chain that exercises a
/// *transitive* subset relation.
#[test]
fn the_frozen_chain_is_three_hops_single_key_and_single_tenant() {
    let v = vector();
    let chain = v["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 3, "the frozen chain must have three hops");

    let thumbprint = v["ed25519"]["kernel_key_thumbprint"].as_str().unwrap();
    let tenant = chain[0]["document"]["tenant_id"].as_str().unwrap();
    let domain = chain[0]["document"]["trust_domain"].as_str().unwrap();

    for entry in chain {
        let doc = &entry["document"];
        assert_eq!(
            doc["kernel_key_thumbprint"].as_str().unwrap(),
            thumbprint,
            "every hop must be signed by the one kernel key"
        );
        assert_eq!(
            doc["tenant_id"].as_str().unwrap(),
            tenant,
            "tenant must be constant — cross-tenant delegation is denied at mint"
        );
        assert_eq!(
            doc["trust_domain"].as_str().unwrap(),
            domain,
            "trust_domain must be constant across a single-issuer chain"
        );
    }

    assert!(
        chain[0]["document"]["parent_vaid"].is_null(),
        "hop 0 must be the root"
    );
}

//! Generator for the frozen round-trip verification vector (`roundtrip_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_roundtrip_vector` to print the
//! vector JSON. It exists for the reason the other emitters exist: the vector
//! carries real signatures over real canonical bytes, so the only way to re-freeze
//! it after a wire change is to re-derive it, and the only way to keep it
//! reproducible is for the derivation to live in the tree.
//!
//! Written for the v4 re-freeze (ADR-0009). Until then this vector had no
//! generator and could only be re-frozen by hand, which is how a signature gets
//! edited into agreement with bytes nobody recomputed.
//!
//! # What each case does
//!
//! All four share one base document. The pairs are the point:
//!
//! 1. base, signed over base                            -> valid
//! 2. base + extension, signed over the EXTENDED bytes   -> valid
//! 3. case 2's document with the extension REMOVED       -> invalid
//! 4. case 1's document with the extension ADDED         -> invalid
//!
//! Cases 3 and 4 reuse the signatures of 2 and 1 unchanged. That is what makes
//! them negative: the bytes moved and the signature did not.
//!
//! The kernel seed is the same RFC 8032 test seed `mint_v1.json` uses.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Map, Value};

use vaid_mint::{canonical_vaid_signing_bytes, Vaid};

const KERNEL_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const EXTENSION_MEMBER: &str = "x_example_extension";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The base document, with `kernel_signature` empty. Written as JSON rather than
/// built through `Vaid::with_lineage` because three of the four cases are
/// documents a conforming mint would never produce, and the vector's whole point
/// is a verdict over PRESENTED bytes.
fn base_document() -> Map<String, Value> {
    let doc = json!({
        "sig_version": 4,
        "vaid_id": "b0000000-0000-4000-8000-000000000001",
        "agent_id": "b0000000-0000-4000-8000-000000000001",
        "agent_class": "roundtrip",
        "version": "1.0.0",
        "tenant_id": "acme",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "public_key_der": [3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184],
        "kernel_signature": [],
        "parent_vaid": null,
        "scope_boundary": [{ "kind": "prefix", "value": "data.acme" }],
        "lineage_hash": "81e986864029e5395751b617bfa699d97dc97dbfb659257da96b9c9b3f0d7e19",
        "capability_set": ["read"],
        "trust_domain": "vaid.example",
        "kernel_key_thumbprint": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y",
    });
    doc.as_object().unwrap().clone()
}

fn extension_value() -> Value {
    json!({"note": "an additive field a verifier does not know"})
}

/// Sign `doc`'s canonical bytes and return the document with the signature in
/// place. Goes through `Vaid` so the bytes signed are the ones the shipped
/// canonicalizer produces, unknown members included (ADR-0006).
fn signed(key: &Ed25519KeyPair, mut doc: Map<String, Value>) -> Map<String, Value> {
    let parsed: Vaid = serde_json::from_value(Value::Object(doc.clone()))
        .expect("the generator's own document must parse");
    let digest = canonical_vaid_signing_bytes(&parsed);
    let sig = key.sign(&digest);
    doc.insert("kernel_signature".to_string(), json!(sig.as_ref().to_vec()));
    doc
}

fn main() {
    let seed = unhex(KERNEL_SEED_HEX);
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("deterministic kernel key");
    let kernel_pub = key.public_key().as_ref().to_vec();

    // 1. base, signed over base.
    let case_known = signed(&key, base_document());

    // 2. base + extension, signed over the EXTENDED bytes.
    let mut extended = base_document();
    extended.insert(EXTENSION_MEMBER.to_string(), extension_value());
    let case_extended = signed(&key, extended);

    // 3. case 2 with the extension removed. The signature is case 2's, unchanged.
    let mut case_removed = case_extended.clone();
    case_removed.remove(EXTENSION_MEMBER);

    // 4. case 1 with the extension added. The signature is case 1's, unchanged.
    let mut case_added = case_known.clone();
    case_added.insert(EXTENSION_MEMBER.to_string(), extension_value());

    let vector = json!({
        "_comment": "Round-trip verification conformance vector (v1), per ADR-0006. VERIFY-ONLY, and a SHAPE THE SURFACE DID NOT PREVIOUSLY HAVE: every other vector pins one implementation's OUTPUT FOR A GIVEN INPUT; this one pins A VERDICT OVER GIVEN BYTES. That is the only shape that catches cross-implementation disagreement, because the defect it exists for appears only when one implementation MINTS and another VERIFIES. A conforming implementation MUST, for each case, load the document EXACTLY AS GIVEN, compute canonical_vaid_signing_bytes over it, and return `expected_valid` when checking `kernel_signature` against `ed25519.kernel_public_key_hex`. It MUST NOT drop members it does not recognise before canonicalizing -- that is precisely what this vector tests. It carries no digest of its own: the assertion is the verdict, not the bytes. mint_v1, mint_pop_v1, chain_v1, attestation_v1 and scope_v1 are untouched and NOT re-frozen.",
        "rule": {
            "statement": "A verifier canonicalizes the document it was PRESENTED. Unknown members are part of the signed bytes. An implementation MUST either verify over the presented bytes or reject the document explicitly; it MUST NOT re-project and return a verdict.",
            "rejecting_is_conforming": "An implementation MAY refuse a document carrying members it does not recognise (ADR-0006 Decision 2). Such an implementation reports the unknown-field cases as REJECTED rather than as the boolean below, and MUST say so explicitly. What it must never do is silently drop the member and report a verdict as though the document had not carried it.",
        },
        "ed25519": {
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
        },
        "cases": [
            {
                "name": "known fields only",
                "why": "control -- a conforming document with no extension must verify",
                "document": case_known,
                "expected_valid": true,
            },
            {
                "name": "additive extension, signed over the extended bytes",
                "why": "THE CORE CASE. An implementation that drops `x_example_extension` before canonicalizing computes a different digest and returns false for a genuinely valid document. Rust vaid-mint did exactly this before ADR-0006.",
                "document": case_extended,
                "expected_valid": true,
            },
            {
                "name": "extension removed after signing",
                "why": "proves the extension is INSIDE the digest rather than ignored: the same signature must not verify once the member is gone",
                "document": case_removed,
                "expected_valid": false,
            },
            {
                "name": "extra field not covered by the signature",
                "why": "the other direction -- an implementation that drops unknown members would wrongly ACCEPT this, because dropping it reproduces the signed bytes",
                "document": case_added,
                "expected_valid": false,
            },
        ],
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

//! Generator for the frozen completion-record vector (`completion_v1.json`).
//!
//! Run with `cargo run -p vaid-pop --example emit_completion_vector` to print the
//! vector JSON. It builds a deterministic [`CompletionRecord`] (a self-reported
//! completion of the operator vector's request), computes its canonical signing
//! digest, and signs it with the frozen operator-vector kernel seed. Both the
//! Rust and Python conformance suites must reproduce `digest_sha256_hex` and
//! `ed25519.signature_hex` byte-for-byte from `input`.
//!
//! `requestDigestSha256` is the operator vector's own digest — this record
//! attests completion of *that* request, a deliberate cross-reference.

use ring::signature::{Ed25519KeyPair, KeyPair};

use vaid_pop::request_completion::{AssuranceTier, CompletionRecord};
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    const KERNEL_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    // sha256("") — the empty result body.
    const EMPTY_SHA256: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // The operator vector's request digest — the request this completion attests.
    const OPERATOR_REQUEST_DIGEST: &str =
        "ee474ba87d703ebeacf663d7d6a2f15319bdef285c5b702e336d0f4af5b61327";

    let vaid_id = "11111111-1111-1111-1111-111111111111";
    let tenant_id = "synthera-control-plane";
    let completed_at = "2026-06-04T12:00:05Z";
    let record_nonce = "fedcba9876543210fedcba9876543210";

    let record = CompletionRecord {
        vaid_id: serde_json::from_value(serde_json::json!(vaid_id)).unwrap(),
        request_digest_sha256: OPERATOR_REQUEST_DIGEST.to_string(),
        tenant_id: tenant_id.to_string(),
        status: "succeeded".to_string(),
        result_sha256: EMPTY_SHA256.to_string(),
        completed_at: chrono::DateTime::parse_from_rfc3339(completed_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
        // Self-reported: the acting VAID signs its own completion.
        signer_vaid_id: serde_json::from_value(serde_json::json!(vaid_id)).unwrap(),
        assurance_tier: AssuranceTier::SelfReported,
        record_nonce: record_nonce.to_string(),
    };

    let digest = canonical_request_signing_bytes(&record);
    let kp = Ed25519KeyPair::from_seed_unchecked(&unhex(KERNEL_SEED_HEX)).unwrap();
    let signature = kp.sign(&digest);

    let vector = serde_json::json!({
        "_comment": "Completion-record conformance vector (v1). Load-bearing. `input` is a real \
                     CompletionRecord (camelCase). NOTE: this is the FIRST vector containing an \
                     ENUM (`assuranceTier`) — the most likely place for silent Rust/Python string \
                     divergence, so an explicit enum round-trip test accompanies it. A conforming \
                     implementation MUST produce `digest_sha256_hex` from `input` via JCS \
                     (RFC 8785) -> SHA-256 and reproduce `ed25519.signature_hex` byte-for-byte. \
                     SCOPE: self-signed DECLARED metadata only — the single signature substantiates \
                     `assuranceTier=selfReported` and nothing above it; counterSigned / \
                     thirdPartyAttested are unverified claims here (a separate, not-yet-built \
                     primitive would substantiate them). Same JCS→SHA-256→Ed25519 primitive as \
                     operator_pop_v1.json.",
        "scheme": "JCS(RFC8785) -> SHA-256 -> pure Ed25519 over the 32-byte digest as raw message; \
                   raw 64-byte signature; raw 32-byte Ed25519 public key",
        "input": {
            "vaidId": vaid_id,
            "requestDigestSha256": OPERATOR_REQUEST_DIGEST,
            "tenantId": tenant_id,
            "status": "succeeded",
            "resultSha256": EMPTY_SHA256,
            "completedAt": completed_at,
            "signerVaidId": vaid_id,
            "assuranceTier": "selfReported",
            "recordNonce": record_nonce,
        },
        "assurance_tier_strings": ["selfReported", "counterSigned", "thirdPartyAttested"],
        "digest_sha256_hex": to_hex(&digest),
        "ed25519": {
            "_comment": "Deterministic test key (same RFC 8032 seed as operator_pop_v1.json).",
            "private_key_seed_hex": KERNEL_SEED_HEX,
            "public_key_hex": to_hex(kp.public_key().as_ref()),
            "signature_hex": to_hex(signature.as_ref()),
        }
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

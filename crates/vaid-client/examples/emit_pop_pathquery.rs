//! Generator for the frozen path-with-query conformance vector (`pathquery_v1.json`).
//!
//! Run with `cargo run -p vaid-client --example emit_pop_pathquery` to print the
//! vector JSON. It signs a request whose target INCLUDES a query string, with the
//! frozen operator-vector seed/timestamp/nonce, pinning the adapter convention:
//! the signed `path` is the on-the-wire request target (percent-encoded path +
//! `?query`) — what an HTTP client's `raw_path` yields — NOT path-only. Signing
//! path-only would leave the query outside the signature (tamperable), so this is
//! a security decision, not a convenience.
//!
//! The `vaid-langchain` path-convention test asserts the Python signer reproduces
//! `digest_sha256_hex` + `ed25519.signature_hex` byte-for-byte from `input`, and a
//! CI drift-check enforces the two vendored copies are byte-identical.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_client::RequestSigner;
use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

const VECTOR_JSON: &str = include_str!("../tests/vectors/operator_pop_v1.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    // Reuse the operator vector's deterministic seed + identity + freshness so the
    // kernel public key is the already-known value; only the with-query path and
    // its signature are new.
    let v: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let seed_hex = v["ed25519"]["private_key_seed_hex"].as_str().unwrap();
    let kp = Ed25519KeyPair::from_seed_unchecked(&unhex(seed_hex)).unwrap();
    let public_key_hex = to_hex(kp.public_key().as_ref());

    let vaid_id = v["input"]["vaidId"].as_str().unwrap();
    let tenant_id = v["input"]["tenantId"].as_str().unwrap();
    let timestamp = v["input"]["timestamp"].as_str().unwrap();
    let nonce = v["input"]["clientNonce"].as_str().unwrap();

    // THE pinned convention: signed path = on-the-wire request target (path + query).
    let method = "POST";
    let path = "/vaid/mint?tenant=acme&limit=10";
    let body = b"";
    let body_sha256 = to_hex(ring::digest::digest(&ring::digest::SHA256, body).as_ref());

    let vaid_json = format!(r#"{{"vaid_id":"{vaid_id}","tenant_id":"{tenant_id}"}}"#);
    let signer = RequestSigner::from_vaid_json(vaid_json.as_bytes(), kp).unwrap();
    let now_dt = chrono::DateTime::parse_from_rfc3339(timestamp)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let headers = signer.sign_headers_at(method, path, body, now_dt, nonce).unwrap();

    // Canonical payload/digest for the vector `input`.
    let payload = RequestAuthPayload {
        vaid_id: serde_json::from_value(serde_json::json!(vaid_id)).unwrap(),
        method: method.to_string(),
        path: path.to_string(),
        body_sha256: body_sha256.clone(),
        tenant_id: tenant_id.to_string(),
        timestamp: now_dt,
        client_nonce: nonce.to_string(),
    };
    let digest = canonical_request_signing_bytes(&payload);
    let signature_hex = {
        use base64::Engine as _;
        to_hex(
            &base64::engine::general_purpose::STANDARD
                .decode(headers.signature.as_bytes())
                .unwrap(),
        )
    };

    let vector = serde_json::json!({
        "_comment": "Path-with-query conformance vector (v1). Load-bearing. `input` is a real \
                     RequestAuthPayload (camelCase) whose `path` is the on-the-wire request target \
                     INCLUDING the query string — the pinned signing convention for framework \
                     adapters (httpx `raw_path`), NOT path-only. Signing path-only would leave the \
                     query outside the signature (tamperable), so this is a security decision. A \
                     conforming signer MUST produce `digest_sha256_hex` from `input` via JCS \
                     (RFC 8785) -> SHA-256 and reproduce `ed25519.signature_hex` byte-for-byte from \
                     the seed. Same JCS→SHA-256→Ed25519 primitive as operator_pop_v1.json.",
        "scheme": "JCS(RFC8785) -> SHA-256 -> pure Ed25519 over the 32-byte digest as raw message; \
                   raw 64-byte signature; raw 32-byte Ed25519 public key",
        "input": {
            "vaidId": vaid_id,
            "method": method,
            "path": path,
            "bodySha256": body_sha256,
            "tenantId": tenant_id,
            "timestamp": timestamp,
            "clientNonce": nonce,
        },
        "digest_sha256_hex": to_hex(&digest),
        "ed25519": {
            "_comment": "Deterministic test key (same RFC 8032 seed as operator_pop_v1.json). Any \
                         conforming implementation derives the same public key and produces the same \
                         signature over digest_sha256_hex.",
            "private_key_seed_hex": seed_hex,
            "public_key_hex": public_key_hex,
            "signature_hex": signature_hex,
        }
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

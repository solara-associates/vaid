//! Emit the Rust client's PoP output for the frozen conformance vector.
//!
//! Runs the canonical `vaid-client` signer over the vendored vector's input
//! with the frozen seed/nonce/timestamp and prints a stable JSON blob:
//!
//! ```text
//! {"client_nonce":"…","digest_sha256_hex":"…","signature_hex":"…","timestamp":"…"}
//! ```
//!
//! The conformance test asserts this output is byte-identical to the frozen
//! vector, so an independent implementation can reproduce it and check interop.

use std::collections::BTreeMap;

use base64::Engine as _;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

use vaid_client::RequestSigner;
use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

const VECTOR_JSON: &str = include_str!("../tests/vectors/operator_pop_v1.json");

fn s(v: &Value, key: &str) -> String {
    v["input"][key].as_str().unwrap().to_string()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let v: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let kp = Ed25519KeyPair::from_seed_unchecked(&unhex(
        v["ed25519"]["private_key_seed_hex"].as_str().unwrap(),
    ))
    .unwrap();

    let vaid_json = format!(
        r#"{{"vaid_id":"{}","tenant_id":"{}"}}"#,
        s(&v, "vaidId"),
        s(&v, "tenantId")
    );
    let signer = RequestSigner::from_vaid_json(vaid_json.as_bytes(), kp).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339(&s(&v, "timestamp"))
        .unwrap()
        .with_timezone(&chrono::Utc);
    let nonce = s(&v, "clientNonce");
    let headers = signer
        .sign_headers_at(&s(&v, "method"), &s(&v, "path"), b"", now, &nonce)
        .unwrap();

    // Digest from the canonical payload (equals the vector's frozen digest).
    let payload: RequestAuthPayload = serde_json::from_value(v["input"].clone()).unwrap();
    let digest = canonical_request_signing_bytes(&payload);
    let sig = base64::engine::general_purpose::STANDARD
        .decode(headers.signature.as_bytes())
        .unwrap();

    let mut out: BTreeMap<&str, String> = BTreeMap::new();
    out.insert("digest_sha256_hex", to_hex(&digest));
    out.insert("signature_hex", to_hex(&sig));
    out.insert("timestamp", headers.timestamp);
    out.insert("client_nonce", headers.nonce);
    println!("{}", serde_json::to_string(&out).unwrap());
}

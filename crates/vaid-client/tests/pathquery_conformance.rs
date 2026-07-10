//! Path-with-query conformance gate (Rust side of the cross-language firewall).
//!
//! The vendored vector `tests/vectors/pathquery_v1.json` is byte-identical to the
//! copy shipped in the Python `vaid-langchain` package (a CI drift-check enforces
//! that). It pins the adapter signing convention: the signed `path` is the
//! on-the-wire request target (percent-encoded path + `?query`), NOT path-only.
//! This test asserts the Rust `vaid-client` signer reproduces the frozen digest +
//! signature byte-for-byte for that with-query target. A mismatch is a BLOCKER.

use base64::Engine as _;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

use vaid_client::RequestSigner;
use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

const VECTOR_JSON: &str = include_str!("vectors/pathquery_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR_JSON).expect("vector json parses")
}

fn vstr(v: &Value, key: &str) -> String {
    v["input"][key].as_str().expect("string field").to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The canonical digest over the REAL camelCase `RequestAuthPayload` (whose
/// `path` carries the query) equals the frozen vector.
#[test]
fn client_reproduces_frozen_pathquery_digest() {
    let v = vector();
    let payload: RequestAuthPayload = serde_json::from_value(v["input"].clone())
        .expect("vector input must deserialize into a real RequestAuthPayload (camelCase)");
    // Sanity: the pinned path really does include a query string.
    assert!(payload.path.contains('?'), "the pathquery vector's path must include a query");
    let digest = canonical_request_signing_bytes(&payload);
    assert_eq!(
        to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap(),
        "Rust digest diverged from the frozen path-with-query vector — BLOCKER"
    );
}

/// The real signer path over the with-query target reproduces the frozen
/// signature byte-for-byte.
#[test]
fn request_signer_reproduces_frozen_pathquery_signature() {
    let v = vector();
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte ed25519 seed");

    let vaid_json = format!(
        r#"{{"vaid_id":"{}","tenant_id":"{}"}}"#,
        vstr(&v, "vaidId"),
        vstr(&v, "tenantId")
    );
    let signer = RequestSigner::from_vaid_json(vaid_json.as_bytes(), kp).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339(&vstr(&v, "timestamp"))
        .unwrap()
        .with_timezone(&chrono::Utc);
    let nonce = vstr(&v, "clientNonce");
    // vector bodySha256 = sha256("") — sign the empty body.
    let headers = signer
        .sign_headers_at(&vstr(&v, "method"), &vstr(&v, "path"), b"", now, &nonce)
        .unwrap();

    let sig = base64::engine::general_purpose::STANDARD
        .decode(headers.signature.as_bytes())
        .unwrap();
    assert_eq!(
        to_hex(&sig),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "Rust signature diverged from the frozen path-with-query vector — BLOCKER"
    );
}

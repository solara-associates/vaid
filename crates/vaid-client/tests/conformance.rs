//! Canonical PoP conformance gate.
//!
//! The vendored vector `tests/vectors/operator_pop_v1.json` ships inside the crate
//! so a consumer runs this gate against the exact bytes the client was proven
//! against. These tests assert the `vaid-client` signer reproduces the frozen
//! digest + Ed25519 signature byte-for-byte. A mismatch is a BLOCKER: any
//! conforming implementation must reproduce the same vector.

use base64::Engine as _;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

use vaid_client::{PortRequestSigner, RequestSigner};
use vaid_pop::ports::{OperatorSigningPort, OperatorSigningResult};
use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

const VECTOR_JSON: &str = include_str!("vectors/operator_pop_v1.json");

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

/// A minimal VAID document JSON carrying the snake_case identity the signer parses.
fn vaid_json(v: &Value) -> String {
    format!(
        r#"{{"vaid_id":"{}","tenant_id":"{}"}}"#,
        vstr(v, "vaidId"),
        vstr(v, "tenantId")
    )
}

fn seed_keypair(v: &Value) -> Ed25519KeyPair {
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte ed25519 seed")
}

/// The canonical digest over the REAL camelCase `RequestAuthPayload` must equal
/// the frozen vector — proves this crate's reuse of the shared primitive didn't
/// drift the bytes.
#[test]
fn client_reproduces_frozen_digest() {
    let v = vector();
    let payload: RequestAuthPayload = serde_json::from_value(v["input"].clone())
        .expect("vector input must deserialize into a real RequestAuthPayload (camelCase)");
    let digest = canonical_request_signing_bytes(&payload);
    assert_eq!(
        to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap(),
        "Rust client digest diverged from the frozen vector — BLOCKER"
    );
    assert_eq!(digest.len(), 32);
}

/// The real signer path: `RequestSigner::sign_headers_at` builds the payload,
/// signs via the shared primitive, and its `x-synthera-signature` decodes to the
/// frozen signature byte-for-byte.
#[test]
fn request_signer_reproduces_frozen_signature() {
    let v = vector();
    let kp = seed_keypair(&v);
    let signer = RequestSigner::from_vaid_json(vaid_json(&v).as_bytes(), kp).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339(&vstr(&v, "timestamp"))
        .unwrap()
        .with_timezone(&chrono::Utc);
    let nonce = vstr(&v, "clientNonce");
    // vector bodySha256 = sha256("") — sign the empty body.
    let headers = signer
        .sign_headers_at(&vstr(&v, "method"), &vstr(&v, "path"), b"", now, &nonce)
        .unwrap();

    assert_eq!(headers.timestamp, vstr(&v, "timestamp"));
    assert_eq!(headers.nonce, nonce);

    let sig = base64::engine::general_purpose::STANDARD
        .decode(headers.signature.as_bytes())
        .unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(
        to_hex(&sig),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "Rust client header signature diverged from the frozen vector — BLOCKER"
    );
}

/// A fake `OperatorSigningPort` backed by the frozen seed key — proves the
/// port-signing path produces the identical signature as the raw-key path.
struct SeedPort {
    kp: Ed25519KeyPair,
}

#[async_trait::async_trait]
impl OperatorSigningPort for SeedPort {
    async fn sign(&self, canonical_bytes: &[u8]) -> OperatorSigningResult<[u8; 64]> {
        let sig = self.kp.sign(canonical_bytes);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        Ok(out)
    }
    async fn public_key(&self) -> OperatorSigningResult<[u8; 32]> {
        use ring::signature::KeyPair;
        let mut out = [0u8; 32];
        out.copy_from_slice(self.kp.public_key().as_ref());
        Ok(out)
    }
}

#[tokio::test]
async fn port_request_signer_matches_frozen_signature() {
    let v = vector();
    let port = SeedPort { kp: seed_keypair(&v) };
    let signer = PortRequestSigner::from_vaid_json(vaid_json(&v).as_bytes(), &port).unwrap();

    let now = chrono::DateTime::parse_from_rfc3339(&vstr(&v, "timestamp"))
        .unwrap()
        .with_timezone(&chrono::Utc);
    let nonce = vstr(&v, "clientNonce");
    let headers = signer
        .sign_headers_at(&vstr(&v, "method"), &vstr(&v, "path"), b"", now, &nonce)
        .await
        .unwrap();

    let sig = base64::engine::general_purpose::STANDARD
        .decode(headers.signature.as_bytes())
        .unwrap();
    assert_eq!(
        to_hex(&sig),
        v["ed25519"]["signature_hex"].as_str().unwrap(),
        "OperatorSigningPort path diverged from the frozen vector — BLOCKER"
    );
}

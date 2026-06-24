//! Proof-of-possession request signing — the Rust client-side transport.
//!
//! The glue that assembles `(method, path, body)` into the canonical
//! [`RequestAuthPayload`], signs it, and emits the four `x-synthera-*` headers.
//! The canonicalization and the Ed25519 sign/verify live in
//! [`vaid_pop::vaid_pop`]; this module never reimplements JCS, so the
//! bytes stay identical to a conforming verifier by construction.
//!
//! Two signing strategies, for two key custodies:
//! - [`RequestSigner`] — holds a raw [`ring`] `Ed25519KeyPair` (the agent-key
//!   case: a tenant that holds its own private key).
//! - [`PortRequestSigner`] — defers signing to an
//!   [`OperatorSigningPort`] (the external-key-store case: the key never leaves
//!   its keystore).

use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;

use vaid_pop::ports::OperatorSigningPort;
use vaid_pop::request_auth::{
    RequestAuthPayload, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, HEADER_VAID,
};
use vaid_pop::vaid_pop::{canonical_request_signing_bytes, sign_payload};
use vaid_pop::VaidId;

/// Errors constructing a signer or producing headers.
#[derive(Debug, thiserror::Error)]
pub enum PopError {
    /// The supplied VAID document JSON could not be parsed for the snake_case
    /// `vaid_id` / `tenant_id` identity fields the payload binds.
    #[error("invalid VAID document JSON: {0}")]
    InvalidVaid(#[from] serde_json::Error),
    /// The random source for nonce generation failed.
    #[error("nonce generation failed")]
    Nonce,
    /// The `OperatorSigningPort` failed to sign the digest.
    #[error("operator signing port failed: {0}")]
    Signing(String),
}

/// The four PoP headers for one signed request. Field order is irrelevant — a
/// verifier reads them by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopHeaders {
    /// `x-synthera-vaid` — base64(JSON of the VAID document).
    pub vaid: String,
    /// `x-synthera-timestamp` — whole-second RFC 3339 `…Z`.
    pub timestamp: String,
    /// `x-synthera-nonce` — fresh per-request 128-bit nonce, lowercase hex.
    pub nonce: String,
    /// `x-synthera-signature` — base64(raw 64-byte Ed25519 signature).
    pub signature: String,
}

impl PopHeaders {
    /// The four `(header-name, value)` pairs, ready to attach to a request.
    pub fn into_pairs(self) -> [(&'static str, String); 4] {
        [
            (HEADER_VAID, self.vaid),
            (HEADER_TIMESTAMP, self.timestamp),
            (HEADER_NONCE, self.nonce),
            (HEADER_SIGNATURE, self.signature),
        ]
    }
}

/// The request-binding identity shared by both signing strategies: the VAID
/// header (base64 of the document) plus the `vaid_id`/`tenant_id` the payload
/// binds. Parsed once from the minted VAID document JSON.
#[derive(Debug, Clone)]
struct PopIdentity {
    vaid_header: String,
    vaid_id: VaidId,
    tenant_id: String,
}

#[derive(Deserialize)]
struct VaidIdentity {
    // A VAID document is snake_case (`Vaid` has no serde rename), unlike the
    // camelCase `RequestAuthPayload`. Extract identity by snake_case keys.
    vaid_id: VaidId,
    tenant_id: String,
}

impl PopIdentity {
    fn from_vaid_json(vaid_json: &[u8]) -> Result<Self, PopError> {
        let id: VaidIdentity = serde_json::from_slice(vaid_json)?;
        // A verifier re-deserializes the VAID by field and recomputes its own
        // canonical bytes, so carrying the document bytes verbatim is correct.
        let vaid_header = base64::engine::general_purpose::STANDARD.encode(vaid_json);
        Ok(Self { vaid_header, vaid_id: id.vaid_id, tenant_id: id.tenant_id })
    }

    /// Build the canonical payload + the whole-second timestamp string for a
    /// request. The `now`/`nonce` are normalized so the header timestamp string
    /// and the `DateTime` the payload serializes from agree (a whole-second
    /// `…Z` round-trips through chrono-serde to itself — the fixed point a
    /// verifier relies on).
    fn payload(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        now: DateTime<Utc>,
        nonce: &str,
    ) -> (RequestAuthPayload, String) {
        let now = now.with_nanosecond(0).expect("zero nanoseconds is always valid");
        let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let payload = RequestAuthPayload {
            vaid_id: self.vaid_id,
            method: method.to_uppercase(),
            path: path.to_string(),
            body_sha256: hex_sha256(body),
            tenant_id: self.tenant_id.clone(),
            timestamp: now,
            client_nonce: nonce.to_string(),
        };
        (payload, timestamp)
    }

    fn headers(&self, timestamp: String, nonce: String, signature: &[u8]) -> PopHeaders {
        PopHeaders {
            vaid: self.vaid_header.clone(),
            timestamp,
            nonce,
            signature: base64::engine::general_purpose::STANDARD.encode(signature),
        }
    }
}

/// Signs requests with a raw agent key — the holder-custody case (a tenant that
/// holds its own Ed25519 private key).
pub struct RequestSigner {
    identity: PopIdentity,
    key: Ed25519KeyPair,
}

impl RequestSigner {
    /// Construct from the minted VAID document JSON and the agent's key pair.
    pub fn from_vaid_json(vaid_json: &[u8], key: Ed25519KeyPair) -> Result<Self, PopError> {
        Ok(Self { identity: PopIdentity::from_vaid_json(vaid_json)?, key })
    }

    /// Produce the four PoP headers for `(method, path, body)`, generating a
    /// fresh nonce and the current whole-second UTC timestamp.
    pub fn sign_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<PopHeaders, PopError> {
        self.sign_headers_at(method, path, body, Utc::now(), &fresh_nonce()?)
    }

    /// Deterministic variant: caller supplies `now` + `nonce` (for conformance
    /// vectors and replay-window tests).
    pub fn sign_headers_at(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        now: DateTime<Utc>,
        nonce: &str,
    ) -> Result<PopHeaders, PopError> {
        let (payload, timestamp) = self.identity.payload(method, path, body, now, nonce);
        // Reuse the shared primitive: canonicalize + sign in one call.
        let signature = sign_payload(&payload, &self.key);
        Ok(self.identity.headers(timestamp, nonce.to_string(), &signature))
    }
}

/// Signs requests by deferring the digest signature to an
/// [`OperatorSigningPort`] — the external-key-store case, where the private key
/// never leaves its keystore. The port receives the already-canonical 32-byte
/// digest.
pub struct PortRequestSigner<'a> {
    identity: PopIdentity,
    port: &'a dyn OperatorSigningPort,
}

impl<'a> PortRequestSigner<'a> {
    /// Construct from the minted VAID document JSON and an operator-signing port.
    pub fn from_vaid_json(
        vaid_json: &[u8],
        port: &'a dyn OperatorSigningPort,
    ) -> Result<Self, PopError> {
        Ok(Self { identity: PopIdentity::from_vaid_json(vaid_json)?, port })
    }

    /// Produce the four PoP headers, generating a fresh nonce + current timestamp.
    pub async fn sign_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<PopHeaders, PopError> {
        self.sign_headers_at(method, path, body, Utc::now(), &fresh_nonce()?).await
    }

    /// Deterministic variant: caller supplies `now` + `nonce`.
    pub async fn sign_headers_at(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        now: DateTime<Utc>,
        nonce: &str,
    ) -> Result<PopHeaders, PopError> {
        let (payload, timestamp) = self.identity.payload(method, path, body, now, nonce);
        // Canonicalize here (shared primitive), then hand the digest to the port.
        let digest = canonical_request_signing_bytes(&payload);
        let signature = self
            .port
            .sign(&digest)
            .await
            .map_err(|e| PopError::Signing(e.to_string()))?;
        Ok(self.identity.headers(timestamp, nonce.to_string(), &signature))
    }
}

/// Lowercase hex of `SHA-256(body)` — the `bodySha256` field. Uses ring's digest
/// (already a dependency) so no extra hashing crate is pulled in.
fn hex_sha256(body: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    to_hex(digest.as_ref())
}

/// A fresh 128-bit nonce as 32 lowercase hex chars.
fn fresh_nonce() -> Result<String, PopError> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).map_err(|_| PopError::Nonce)?;
    Ok(to_hex(&bytes))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

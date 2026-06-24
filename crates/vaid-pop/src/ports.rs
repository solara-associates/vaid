//! The operator-signing port: the signing seam for keys held in external custody.
//!
//! An adapter implements [`OperatorSigningPort`] to sign the canonical digest
//! with the operator key **without the private key leaving its keystore**. Any
//! external key store (hosted, hardware-backed, or local) can back it; the client
//! SDK's port-signing path consumes this trait.

use async_trait::async_trait;

/// An **infrastructure** failure from an operator-signing adapter — key store
/// unreachable, transport error, malformed backend response, or a view-only
/// adapter refusing to sign. A minimal, self-contained error so this crate has
/// no dependency beyond its own surface.
///
/// Distinct from a signature *verification* failure — that is a security event
/// surfaced as `vaid_pop::verify_signed_payload` → `false`, never an error. The
/// two warrant different fail-closed branches: an `OperatorSigningError` is a
/// retryable infrastructure fault; a verify-fail is a reject.
#[derive(Debug, Clone, thiserror::Error)]
#[error("operator signing error: {0}")]
pub struct OperatorSigningError(pub String);

impl OperatorSigningError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Convenience alias for results carrying an [`OperatorSigningError`].
pub type OperatorSigningResult<T> = Result<T, OperatorSigningError>;

/// Signs the operator key's canonical digest in external custody (the key never
/// leaves its keystore). A verifier consumes `public_key()` (read-only) to bind
/// the operator identity; the client SDK's `PortRequestSigner` consumes `sign()`.
#[async_trait]
pub trait OperatorSigningPort: Send + Sync {
    /// Sign the 32-byte canonical digest with the operator key, returning a
    /// **raw 64-byte** Ed25519 signature (not DER). The input is the digest
    /// [`crate::vaid_pop::canonical_request_signing_bytes`] returns; the adapter
    /// does not hash or canonicalize it again.
    async fn sign(&self, canonical_bytes: &[u8]) -> OperatorSigningResult<[u8; 64]>;

    /// Retrieve the operator public key as **raw 32 bytes** (the adapter
    /// performs any SPKI/DER → raw-32 unwrap on retrieval). This is what binds
    /// the operator VAID at bootstrap, and what `verify_signed_payload` expects.
    async fn public_key(&self) -> OperatorSigningResult<[u8; 32]>;
}

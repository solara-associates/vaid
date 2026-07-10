//! Minimal, self-contained error surface for the reference mint.
//!
//! This replaces the closed substrate's broad `SyntheraError` with exactly the
//! variants the mint path raises. Three kinds map cleanly:
//!
//! - [`MintError::Unauthorized`] — an authorization/attenuation denial (a child
//!   that exceeds its parent, a cross-tenant delegation, a forged lineage, a
//!   missing verified parent). Fail-closed policy decisions.
//! - [`MintError::Identity`] — a proof-of-possession / key failure (missing PoP,
//!   stale PoP, replayed nonce, a signature that does not verify, a missing
//!   BYO-key).
//! - [`MintError::Audit`] — the audit sink refused a write. A mint that cannot be
//!   recorded is a failed mint, so this is an error, not a warning.
//!
//! A signature *verification* result is NOT an error here — a bad signature is a
//! `false` from `vaid_pop::verify_signed_payload` that the mint turns into a
//! `MintError::Identity` reject, exactly as the closed path did.

/// An error from the reference mint.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MintError {
    /// An authorization or attenuation denial — the request was well-formed but
    /// not permitted (child exceeds parent, cross-tenant, forged lineage, no
    /// verified parent).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// A proof-of-possession / key failure — missing PoP, stale PoP, replayed
    /// nonce, a signature that does not verify, or a missing BYO-key.
    #[error("identity: {0}")]
    Identity(String),

    /// The audit sink refused the write — the mint is treated as failed.
    #[error("audit: {0}")]
    Audit(String),
}

/// Result alias carrying a [`MintError`].
pub type MintResult<T> = Result<T, MintError>;

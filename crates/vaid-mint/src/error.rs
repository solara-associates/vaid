//! Minimal, self-contained error surface for the reference mint.
//!
//! This replaces a broad, catch-all error type with exactly the
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
//! - [`MintError::Lineage`] — the durable lineage write failed (0.11.0). A VAID
//!   whose lineage was not recorded must never be returned, so this is an error,
//!   not a warning — see [`crate::revocation::LineageStore::try_record`].
//! - [`MintError::Config`] — a mint was constructed with an invalid configuration
//!   value (e.g. `max_delegation_depth`). Raised at construction, before any
//!   request is served, so a misconfigured mint never starts minting.
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

    /// The durable lineage write failed (0.11.0) — the mint fails closed and
    /// withholds the VAID it was about to return; its lineage was never
    /// recorded. See [`crate::revocation::LineageStore::try_record`].
    #[error("lineage: {0}")]
    Lineage(String),

    /// A mint was constructed with an invalid configuration value. Raised at
    /// construction, before any request is served.
    #[error("config: {0}")]
    Config(String),
}

/// Result alias carrying a [`MintError`].
pub type MintResult<T> = Result<T, MintError>;

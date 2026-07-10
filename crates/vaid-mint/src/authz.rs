//! The authorization seam for root mints.
//!
//! `mint_root` issues a root (or operator) VAID. In the closed managed authority
//! that path is operator-gated (a control-plane concern). This open reference
//! does NOT carry that gate — but that absence is made **visible as a seam**,
//! exactly like [`crate::audit::AuditSink`], rather than being silently missing.
//!
//! [`AuthorizationGate`] is the seam; [`PermitAll`] is the default. A production
//! deployment supplies a real gate (checking whatever caller/operator context it
//! authenticates) by constructing [`crate::mint::MintService`] via
//! [`crate::mint::MintService::with_authorization`].
//!
//! `mint_child` is deliberately NOT routed through this gate: its authorization
//! IS the attenuation check (`child ⊆ parent`, bound to a verified parent), which
//! is intrinsic and cannot be turned off. The gate governs only the *root* mint,
//! where there is otherwise no authority to check against.

use async_trait::async_trait;

use crate::error::MintResult;
use crate::mint_types::VaidSeed;

/// The root-mint authorization seam. Return `Ok(())` to permit the mint, or
/// `Err(MintError::Unauthorized(..))` to deny it. Async so a real gate may
/// consult an external authenticator/policy; the [`PermitAll`] default does not.
#[async_trait]
pub trait AuthorizationGate: Send + Sync {
    /// Decide whether a root mint of `seed` is permitted. A gate that needs
    /// caller identity carries it via its own construction (e.g. a gate built for
    /// one authenticated session), since the open `mint_root` request itself
    /// carries no principal.
    async fn authorize_root_mint(&self, seed: &VaidSeed) -> MintResult<()>;
}

/// The default gate: permits every root mint.
///
/// This is a REFERENCE-IMPLEMENTATION CHOICE, not a security recommendation. A
/// production deployment should supply a real [`AuthorizationGate`]; leaving
/// `PermitAll` in place means anyone who can reach the mint can issue a root
/// VAID.
#[derive(Default)]
pub struct PermitAll;

#[async_trait]
impl AuthorizationGate for PermitAll {
    async fn authorize_root_mint(&self, _seed: &VaidSeed) -> MintResult<()> {
        Ok(())
    }
}

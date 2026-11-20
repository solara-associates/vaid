//! The authorization seam for root mints.
//!
//! `mint_root` issues a root (or operator) VAID. In the closed managed authority
//! that path is operator-gated (a control-plane concern). This open reference
//! does NOT carry that gate — but that absence is made **visible as a seam**,
//! exactly like [`crate::audit::AuditSink`], rather than being silently missing.
//!
//! [`AuthorizationGate`] is the seam; [`DenyAll`] is the default — **deny by
//! default**. A production deployment supplies a real gate (checking whatever
//! caller/operator context it authenticates) by constructing
//! [`crate::mint::MintService`] via [`crate::mint::MintService::with_authorization`].
//! [`InsecurePermitAll`] is the explicit, clearly-named opt-in for local
//! self-hosting, tests and demos — never for production.
//!
//! `mint_child` is deliberately NOT routed through this gate: its authorization
//! IS the attenuation check (`child ⊆ parent`, bound to a verified parent), which
//! is intrinsic and cannot be turned off. The gate governs only the *root* mint,
//! where there is otherwise no authority to check against.

use async_trait::async_trait;

use crate::error::{MintError, MintResult};
use crate::mint_types::VaidSeed;

/// The root-mint authorization seam. Return `Ok(())` to permit the mint, or
/// `Err(MintError::Unauthorized(..))` to deny it. Async so a real gate may
/// consult an external authenticator/policy; the [`DenyAll`] default does not.
#[async_trait]
pub trait AuthorizationGate: Send + Sync {
    /// Decide whether a root mint of `seed` is permitted. A gate that needs
    /// caller identity carries it via its own construction (e.g. a gate built for
    /// one authenticated session), since the open `mint_root` request itself
    /// carries no principal.
    async fn authorize_root_mint(&self, seed: &VaidSeed) -> MintResult<()>;
}

/// The default gate: denies every root mint.
///
/// `mint_root` has no authority to check against out of the box, so the safe
/// default is to issue nothing until a real [`AuthorizationGate`] is supplied via
/// [`crate::mint::MintService::with_authorization`]. For local self-hosting,
/// tests, or demos that intentionally want every root mint to succeed, opt in
/// explicitly with [`InsecurePermitAll`].
#[derive(Default)]
pub struct DenyAll;

#[async_trait]
impl AuthorizationGate for DenyAll {
    async fn authorize_root_mint(&self, _seed: &VaidSeed) -> MintResult<()> {
        Err(MintError::Unauthorized(
            "root mint denied: no AuthorizationGate configured (deny-by-default). \
             Construct MintService::with_authorization with a real gate, or opt \
             into InsecurePermitAll for tests/demos only"
                .into(),
        ))
    }
}

/// An explicit, clearly-named opt-in that permits every root mint.
///
/// **INSECURE. For tests and local demos only — never use in production.**
/// Anyone who can reach a mint constructed with this gate can issue a root VAID.
/// A production deployment must supply a real [`AuthorizationGate`] to
/// [`crate::mint::MintService::with_authorization`] instead.
#[derive(Default)]
pub struct InsecurePermitAll;

#[async_trait]
impl AuthorizationGate for InsecurePermitAll {
    async fn authorize_root_mint(&self, _seed: &VaidSeed) -> MintResult<()> {
        Ok(())
    }
}

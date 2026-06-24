//! # vaid-pop
//!
//! The proof-of-possession (PoP) signing primitive: the minimal, self-contained
//! surface an external client needs to authenticate a VAID-bound request. It
//! carries the canonicalization primitive, the per-request payload, the VAID
//! identity newtypes, and the operator-signing port, and nothing else.
//!
//! ## Contents
//!
//! - [`vaid_pop`] — the canonical signing primitive: RFC 8785 (JCS) → SHA-256 →
//!   pure Ed25519 over the 32-byte digest. One implementation, so a signer and a
//!   conforming verifier derive identical bytes by construction.
//! - [`request_auth`] — [`request_auth::RequestAuthPayload`]: the exact camelCase
//!   payload a holder signs per request, plus the `x-synthera-*` header names.
//! - [`VaidId`] / [`TenantId`] — the VAID identity newtypes the payload binds.
//! - [`ports::OperatorSigningPort`] — the signing port for keys held in external
//!   custody (sign the digest without the private key leaving its keystore), with
//!   its own minimal [`OperatorSigningError`].

pub mod identity;
pub mod ports;
pub mod request_auth;
pub mod vaid_pop;

pub use identity::{TenantId, VaidId};
pub use ports::{OperatorSigningError, OperatorSigningPort};

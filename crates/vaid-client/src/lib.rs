//! # vaid-client
//!
//! The Synthera VAID client SDK for Rust. This crate is the **seed of a general
//! client SDK**, not a single-purpose signer: its first capability is
//! proof-of-possession (PoP) request signing ([`auth`]); the HTTP-calling surface
//! against a deployment is the intended next inhabitant. The module boundary is
//! drawn so later capabilities slot in without reshaping the public API.
//!
//! ## What ships today: [`auth`]
//!
//! Authenticating a request requires a fresh, replay-protected Ed25519 signature
//! over it. [`auth::RequestSigner`] (raw key) and [`auth::PortRequestSigner`]
//! (an [`vaid_pop::ports::OperatorSigningPort`], e.g. an external key
//! store) build the four `x-synthera-*` headers that carry it.
//!
//! Canonicalization is **not** reimplemented here — it reuses
//! [`vaid_pop::vaid_pop::canonical_request_signing_bytes`] /
//! [`vaid_pop::vaid_pop::sign_payload`], so this client and a conforming
//! verifier derive identical bytes by construction. Byte-identity is locked by
//! the vendored vector `tests/vectors/operator_pop_v1.json`, which the conformance
//! test reproduces exactly.

pub mod auth;

pub use auth::{PopError, PopHeaders, PortRequestSigner, RequestSigner};

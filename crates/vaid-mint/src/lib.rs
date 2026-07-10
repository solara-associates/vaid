//! # vaid-mint
//!
//! The open, self-hostable **reference mint** for the VAID standard: mint a root
//! VAID, and mint **attenuated child VAIDs** — delegation where a child's
//! authority is always a subset of its parent's (`child ⊆ parent`), verified
//! fail-closed at mint time.
//!
//! ## The split
//!
//! This is the open engine of a HashiCorp-Vault-style split. What is here:
//!
//! - [`document`] — the signed VAID document ([`document::Vaid`]), its single
//!   scope/capability matchers, and the canonical signing bytes.
//! - [`issuer`] — the kernel signer ([`issuer::ReferenceIssuer`]), with an
//!   ephemeral or caller-supplied Ed25519 key. No KMS, no secret-store bootstrap.
//! - [`mint`] — [`mint::MintService`] with [`mint::MintService::mint_root`] and
//!   [`mint::MintService::mint_child`] (attenuated delegation).
//! - [`audit`] — a stubbed [`audit::AuditSink`] seam (in-memory / no-op).
//! - [`authz`] — the [`authz::AuthorizationGate`] seam for root mints, defaulting
//!   to [`authz::PermitAll`] (a reference choice, not a security recommendation).
//!
//! What is deliberately NOT here (it is the closed managed authority — the
//! commercial product): durable hash-chained revocation, KMS-backed kernel keys,
//! the audit-of-record, and any policy/mesh/federation control plane.
//!
//! ## Reuse, not reimplementation
//!
//! Proof-of-possession at mint reuses the `vaid-pop` primitive verbatim
//! (RFC 8785 JCS → SHA-256 → Ed25519), and the VAID identity newtypes
//! ([`document::VaidId`] / [`document::TenantId`]) are the same types the
//! per-request PoP payload binds. The VAID-*document* canonicalizer
//! ([`document::canonical_vaid_signing_bytes`]) applies the identical JCS
//! discipline to the whole document.
//!
//! ## Self-consistent, not cross-repo-conformant (Decision B)
//!
//! This is an **independent reference implementation**. Its VAID document shape
//! is self-consistent within this repo and is **not** pinned to be byte-identical
//! against the closed substrate's (still-moving) VAID format. The frozen mint
//! conformance vector proves only that this repo's Rust and Python minters agree
//! with each other.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//! use vaid_mint::audit::InMemoryAudit;
//! use vaid_mint::issuer::{ReferenceIssuer, VaidIssuer};
//! use vaid_mint::mint::MintService;
//! use vaid_mint::mint_types::{MintVaidRequest, VaidSeed};
//!
//! # tokio_test_block(async {
//! let issuer = Arc::new(ReferenceIssuer::ephemeral(24).unwrap());
//! let audit = Arc::new(InMemoryAudit::new());
//! let mint = MintService::new(issuer.clone(), audit);
//!
//! // Mint a root VAID (generate-and-discard key path).
//! let root = mint
//!     .mint_root(MintVaidRequest {
//!         seed: VaidSeed {
//!             agent_class: "orchestrator".into(),
//!             version: "1.0.0".into(),
//!             tenant_id: "acme".into(),
//!             parent_vaid: None,
//!             scope_boundary: vec!["data.acme".into()],
//!             capability_set: vec!["read".into(), "write".into()],
//!             public_key_der: None,
//!         },
//!         pop: None,
//!     })
//!     .await
//!     .unwrap()
//!     .vaid;
//!
//! assert!(issuer.verify_vaid(&root));
//! # });
//! # fn tokio_test_block<F: std::future::Future>(f: F) { let rt = tokio::runtime::Builder::new_current_thread().build().unwrap(); rt.block_on(f); }
//! ```

pub mod audit;
pub mod authz;
pub mod document;
pub mod error;
pub mod issuer;
pub mod mint;
pub mod mint_types;

pub use document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid, VaidId,
    VAID_SIG_VERSION_V2,
};
pub use authz::{AuthorizationGate, PermitAll};
pub use error::{MintError, MintResult};
pub use issuer::{ReferenceIssuer, VaidIssuer};
pub use mint::{MintService, MINT_POP_FRESHNESS_SECS};
pub use mint_types::{MintPop, MintPopPayload, MintVaidRequest, MintVaidResponse, VaidSeed};

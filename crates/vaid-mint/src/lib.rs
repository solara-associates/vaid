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
//! - [`revocation`] — the three-state, lineage-aware [`revocation::RevocationCheck`]
//!   seam (spec `docs/spec/revocation.md` R.4). The verifier assembles the ordered
//!   ancestry ([`revocation::assemble_lineage`]) and hands it to the check, which
//!   returns [`revocation::RevocationStatus`] (`NotRevoked`/`Revoked`/`Unavailable`)
//!   — a VAID is revoked if **any** ancestor is (R.4.4), and verification fails
//!   closed on `Unavailable`. The reference default store is non-durable, in-memory
//!   and **absent** — so verification fails closed out of the box — and both it and
//!   the lineage store are injectable together
//!   ([`issuer::ReferenceIssuer::with_revocation_backend`]; durability under R.4.6
//!   is two stores, and a single-half constructor does not exist). Revocation is
//!   **outside the conformance surface**: no vector polices it.
//!
//! Not included here — a hosted authority layers these on top: a *durable*,
//! hash-chained revocation store, KMS-backed kernel keys, a *durable,
//! hash-chained* audit-of-record (the [`audit::AuditSink`] seam and its
//! in-memory/no-op sinks *are* here — the durable ledger is not), and a
//! policy/mesh/federation control plane. Revocation *durability* remains
//! the one gap with production impact today: the seam exists but the shipped
//! default is in-memory and non-durable. See the README's "Trust model" section.
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
//! against the managed authority's (still-moving) VAID format. The frozen mint
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
//! // `assuming_nothing_revoked()` is the pre-0.8.0 default, asked for BY NAME.
//! // Since 0.8.0 a bare issuer's revocation store is ABSENT: it reports
//! // `Unavailable` and `verify_vaid` fails closed until revocation state is loaded
//! // (R.4.5). This is a fail-OPEN posture and it is fine here — a quickstart with
//! // no revocation store — but it does not survive a restart. For anything that
//! // must, inject a durable backend with `with_revocation_backend`; durability is
//! // two stores, and `RevocationBackend` requires both.
//! let issuer = Arc::new(
//!     ReferenceIssuer::ephemeral(24, "vaid.example")
//!         .unwrap()
//!         .assuming_nothing_revoked(),
//! );
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

pub mod attestation;
pub mod audit;
pub mod authz;
pub mod chain;
pub mod document;
pub mod error;
pub mod issuer;
pub mod issuer_identity;
pub mod mint;
pub mod mint_types;
pub mod revocation;
pub mod verify;

pub use attestation::{
    canonical_attestation_signing_bytes, verify_attestation_authenticity, AttestationBundle,
    ConsentAttestation, ATTESTATION_VERSION,
};
pub use authz::{AuthorizationGate, PermitAll};
pub use chain::{
    verify_chain, verify_chain_at, verify_chain_with, ChainVerification, KernelKeyMap,
    KernelKeyResolver, PresentedBundle, SingleKernelKey,
};
pub use document::{
    canonical_vaid_signing_bytes, caps_contain, compute_lineage_hash, has_duplicate_member_names,
    scope_contains, AgentClass, AgentId, PresentedUuid, TenantId, Vaid, VaidId, SCOPE_SEPARATORS,
    VAID_SIG_VERSION_V3,
};
pub use error::{MintError, MintResult};
pub use issuer::{ReferenceIssuer, VaidIssuer, DEFAULT_VAID_TTL_HOURS};
pub use mint::{scope_attenuates_within, MintService, MINT_POP_FRESHNESS_SECS};
pub use mint_types::{MintPop, MintPopPayload, MintVaidRequest, MintVaidResponse, VaidSeed};
pub use revocation::{
    assemble_lineage, InMemoryLineageStore, InMemoryRevocationList, LineageAssembly,
    LineageResolver, LineageStore, ParentResolution, RevocationBackend, RevocationCheck,
    RevocationStatus,
};
pub use verify::{
    verify_lineage_hash, verify_vaid_authenticity, verify_vaid_authenticity_graded,
    verify_vaid_standing, verify_vaid_standing_from_json, VaidVerdict,
};

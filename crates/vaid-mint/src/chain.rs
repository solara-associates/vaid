//! Third-party end-to-end lineage verification, by **detached chain
//! presentation** (ADR-0003).
//!
//! [`crate::verify::verify_vaid_authenticity`] answers "is this document real".
//! It cannot answer "was the authority written into it legitimately derived from
//! its parent's" — a leaf carries its own `scope_boundary` and `capability_set`,
//! not its ancestors'. Under that alone, attenuation is a property of the mint's
//! word.
//!
//! This module closes that without touching the document format. The **presenter**
//! supplies the ancestor documents alongside the leaf; the verifier walks them.
//! No new signed field, no `mint_v1` re-freeze, no `sig_version` bump.
//!
//! ## Why no document field is needed
//!
//! The leaf does not carry its ancestors' authority, but it carries their
//! **identity, signed**:
//!
//! - `parent_vaid` is inside the canonical signing bytes, so it cannot be altered
//!   without breaking the kernel signature;
//! - [`crate::verify::verify_lineage_hash`] independently recomputes
//!   `lineage_hash` from `parent_vaid` and `agent_id`, so an inconsistent value is
//!   caught explicitly rather than incidentally.
//!
//! An ancestor VAID is itself a kernel-signed, self-authenticating statement of
//! its own authority. The verifier does not need the leaf to *describe* its
//! ancestors; it needs the ancestors, plus a pinned reference saying which ones
//! are real. Both already exist.
//!
//! ## Chain substitution is prevented by the existing signature
//!
//! To present a more privileged parent, an adversary needs a kernel-signed
//! document whose `vaid_id` equals the `L.parent_vaid` pinned inside the leaf's
//! signed bytes. Because `vaid_id` equals `agent_id` and is a fresh UUIDv4 per
//! mint, that requires a kernel-key compromise or a UUID collision. No new field
//! contributes to this property; the pin is already signed.
//!
//! ## Relationship to R.4.2
//!
//! `docs/spec/revocation.md` R.4.2 says the full lineage is not recoverable from
//! the VAID itself, and that assembly needs a resolver whose reference
//! implementation is the issuer's in-process lineage map — precisely what a third
//! party lacks. That is true **for revocation**, where assembly starts from a bare
//! identifier and must resolve upward.
//!
//! It is not a constraint here. The presenter supplies documents rather than
//! identifiers, and every document carries its own `parent_vaid`, so the resolver
//! becomes a lookup over the presented bundle: `Root` when `parent_vaid` is
//! absent, `Parent(p)` when present, `Unknown` when the document was not
//! presented. No issuer, no network, no new trait — [`PresentedBundle`] is a new
//! implementation of the existing [`LineageResolver`], and the three-state shape
//! is already correct.

use std::collections::HashMap;

use crate::document::{Vaid, VaidId};
use crate::mint::{caps_attenuate, scope_attenuates};
use crate::revocation::{assemble_lineage, LineageAssembly, LineageResolver, ParentResolution};
use crate::verify::verify_vaid_authenticity;

/// The ancestor documents a presenter supplies alongside a leaf, indexed by
/// `vaid_id`. This is the third-party stand-in for the issuer's in-process lineage
/// map: it resolves ancestry from documents the presenter already holds, so no
/// issuer and no network are involved.
///
/// It implements [`LineageResolver`], so [`assemble_lineage`] — including its
/// cycle detection and its [`MAX_LINEAGE_DEPTH`](crate::revocation::MAX_LINEAGE_DEPTH) bound — is reused unchanged.
///
/// The bundle need not contain the leaf: [`verify_chain`] takes the leaf
/// separately, and [`assemble_lineage`] reads the leaf's parent from the leaf's
/// own signed document, only resolving hops **above** it through this bundle.
#[derive(Debug, Clone, Default)]
pub struct PresentedBundle {
    documents: HashMap<VaidId, Vaid>,
}

impl PresentedBundle {
    /// Build a bundle from the presented ancestor documents.
    ///
    /// Documents are keyed by their own `vaid_id`. A later document with a
    /// `vaid_id` already present replaces the earlier one; this cannot be used to
    /// substitute a more privileged ancestor, because every document on the
    /// assembled chain is authenticated against the kernel key and pinned by a
    /// signed `parent_vaid` (see the module docs).
    pub fn new(documents: impl IntoIterator<Item = Vaid>) -> Self {
        Self {
            documents: documents.into_iter().map(|d| (d.vaid_id(), d)).collect(),
        }
    }

    /// An empty bundle. Any leaf with a `parent_vaid` resolves to
    /// [`ChainVerification::Unverifiable`] against it — the fail-closed default.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Look up a presented document by `vaid_id`.
    pub fn get(&self, vaid_id: &VaidId) -> Option<&Vaid> {
        self.documents.get(vaid_id)
    }

    /// Number of presented documents.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether nothing was presented.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

impl LineageResolver for PresentedBundle {
    /// Resolve one hop from the presented documents. A presented document with no
    /// `parent_vaid` is a **known root**; one with a `parent_vaid` is a **child**;
    /// an id that was not presented is **unknown** — the R.4.2 distinction, which
    /// is what makes an incomplete presentation fail closed instead of looking
    /// like a legitimately rootless VAID.
    fn resolve_parent(&self, vaid_id: &VaidId) -> ParentResolution {
        match self.documents.get(vaid_id) {
            None => ParentResolution::Unknown,
            Some(doc) => match doc.parent_vaid() {
                None => ParentResolution::Root,
                Some(parent) => ParentResolution::Parent(parent),
            },
        }
    }
}

/// The outcome of an end-to-end chain verification.
///
/// Only [`Attenuated`](ChainVerification::Attenuated) is success. The three
/// failure states are kept apart deliberately, because collapsing them is how a
/// verifier ends up reporting *attenuation satisfied* when it means *attenuation
/// unverifiable* — the same conflation R.4.2 forbids for revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainVerification {
    /// Every presented document is authentic, the chain assembles completely from
    /// the leaf to a root, and authority is contained at every hop.
    Attenuated,
    /// A presented document — or the leaf — failed
    /// [`verify_vaid_authenticity`]. Nothing further was checked.
    Inauthentic,
    /// The chain could not be assembled: an ancestor named by a signed
    /// `parent_vaid` was not presented, or assembly hit a cycle or
    /// [`MAX_LINEAGE_DEPTH`](crate::revocation::MAX_LINEAGE_DEPTH). This means **attenuation unverifiable** — never
    /// attenuation satisfied.
    Unverifiable,
    /// The chain is complete and authentic, but some child claims authority its
    /// parent does not hold.
    NotAttenuated,
}

impl ChainVerification {
    /// Whether the chain verified. Provided so callers do not pattern-match a
    /// non-success state into acceptance by accident.
    pub fn is_attenuated(&self) -> bool {
        matches!(self, ChainVerification::Attenuated)
    }
}

/// Verify a full delegation chain end to end, as a third party holding only the
/// issuer's kernel **public** key and the documents the presenter supplied.
///
/// The procedure is ADR-0003's, in order:
///
/// 1. **Authenticate every document** — the leaf and every presented ancestor, via
///    [`verify_vaid_authenticity`]. Any failure is
///    [`ChainVerification::Inauthentic`].
/// 2. **Pin each hop** — [`assemble_lineage`] requires a presented document whose
///    `vaid_id` equals the `parent_vaid` pinned inside the child's signed bytes,
///    and recurses until a document with no `parent_vaid` is reached.
/// 3. **Fail closed on an incomplete chain** — a `parent_vaid` that is present but
///    not resolvable, a cycle, or an implausible depth all yield
///    [`ChainVerification::Unverifiable`].
/// 4. **Check containment** — `scope_L ⊆ scope_P1 ⊆ … ⊆ scope_root`, and the same
///    for capabilities, using the **mint-time** matchers so the verify-time check
///    cannot drift from the one that gated issuance.
///
/// ## What this does not check
///
/// Consistent with [`verify_vaid_authenticity`], this answers *authenticity and
/// attenuation*, not *standing*. It does not consult **expiry** (call
/// [`Vaid::is_expired`]) and does not consult **revocation** (evaluate a
/// [`crate::revocation::RevocationCheck`] separately). A third party generally
/// cannot assemble lineage for revocation from identifiers alone — that is the
/// R.4.2 constraint, and it is unchanged by this module.
///
/// ## Single trust domain
///
/// All documents on the chain must be signed by `kernel_public_key`. Each
/// document's `kernel_key_thumbprint` is checked against that key inside
/// [`verify_vaid_authenticity`], so a chain crossing issuers returns
/// [`ChainVerification::Inauthentic`] rather than being accepted under a key that
/// did not sign it. Verifying a chain whose hops were signed by *different* kernel
/// keys would need a key-lookup seam keyed on `kernel_key_thumbprint`; that is not
/// built here, and until it is, cross-issuer chains are out of scope rather than
/// silently mis-verified.
pub fn verify_chain(
    kernel_public_key: &[u8],
    leaf: &Vaid,
    bundle: &PresentedBundle,
) -> ChainVerification {
    // Step 1 — authenticate the leaf and EVERY presented document, before any of
    // them is allowed to influence assembly. Authenticating the whole bundle
    // rather than only the documents that end up on the chain is the stricter
    // reading of ADR-0003 step 1, and it means a presenter cannot mix an
    // unauthenticated document into a bundle and have it ignored.
    if !verify_vaid_authenticity(kernel_public_key, leaf) {
        return ChainVerification::Inauthentic;
    }
    for doc in bundle.documents.values() {
        if !verify_vaid_authenticity(kernel_public_key, doc) {
            return ChainVerification::Inauthentic;
        }
    }

    // Steps 2 and 3 — pin each hop against the signed `parent_vaid`, failing
    // closed on any gap. Cycle detection and MAX_LINEAGE_DEPTH come from
    // `assemble_lineage` unchanged.
    let chain_ids = match assemble_lineage(leaf, bundle) {
        LineageAssembly::Incomplete => return ChainVerification::Unverifiable,
        LineageAssembly::Complete(ids) => ids,
    };

    // Resolve each id on the chain back to its document, root first. The leaf is
    // supplied separately and need not appear in the bundle, so it is matched
    // first. Any id that cannot be resolved to a document is a gap, and a gap is
    // `Unverifiable` — never a silently shortened chain.
    let mut chain_docs: Vec<&Vaid> = Vec::with_capacity(chain_ids.len());
    for id in &chain_ids {
        let doc = if *id == leaf.vaid_id() {
            leaf
        } else {
            match bundle.get(id) {
                Some(doc) => doc,
                None => return ChainVerification::Unverifiable,
            }
        };
        chain_docs.push(doc);
    }

    // Step 4 — containment at every hop, root first, using the mint-time matchers.
    for pair in chain_docs.windows(2) {
        let (parent, child) = (pair[0], pair[1]);
        if !scope_attenuates(parent, child.scope_boundary()) {
            return ChainVerification::NotAttenuated;
        }
        if !caps_attenuate(parent, child.capability_set()) {
            return ChainVerification::NotAttenuated;
        }
    }

    ChainVerification::Attenuated
}

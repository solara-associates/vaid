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

use chrono::{DateTime, Utc};

use crate::attestation::{verify_attestation_authenticity, AttestationBundle};
use crate::document::{Vaid, VaidId};
use crate::mint::{
    caps_attenuate, caps_attenuate_within, scope_attenuates, scope_attenuates_within,
    tenant_attenuates,
};
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
    /// A cross-key hop's consent attestation is **authentic but outside its
    /// validity window** — lapsed, or not yet valid beyond the permitted clock
    /// skew.
    ///
    /// Kept distinct from the other three on purpose. An expired attestation is
    /// not forged: the parent really did sign it, so reporting
    /// [`Inauthentic`](ChainVerification::Inauthentic) would misdescribe what
    /// happened. Nor did the child overreach, so
    /// [`NotAttenuated`](ChainVerification::NotAttenuated) would be wrong too. The
    /// operational difference is the point: this one says *renew the attestation*,
    /// the other two say *you were never authorized*, and an operator sent down the
    /// wrong path by a collapsed verdict wastes the incident.
    ///
    /// **This is not withdrawal.** See [`crate::attestation`]: a validity window
    /// bounds stale consent and does nothing about consent retracted inside it.
    ConsentExpired,
}

impl ChainVerification {
    /// Whether the chain verified. Provided so callers do not pattern-match a
    /// non-success state into acceptance by accident.
    pub fn is_attenuated(&self) -> bool {
        matches!(self, ChainVerification::Attenuated)
    }
}

/// Resolves the kernel public key that signed a document, by its
/// `kernel_key_thumbprint`.
///
/// # Why this is a seam and not a parameter
///
/// A single-issuer chain needs one key and could take it as an argument — which is
/// what [`verify_chain`] does. A chain that crosses organisations needs the key
/// that signed *each* document, selected by the thumbprint the document commits to
/// (ADR-0004). That selection is the verifier's trust decision and belongs to the
/// caller: the resolver is where a deployment plugs in its trust bundle.
///
/// **Returning a key is an assertion of trust.** A resolver that answers for a
/// thumbprint is saying "I accept documents signed by this key". Resolving a
/// thumbprint from the document itself, or from any source the presenter controls,
/// verifies that a number equals itself — see `docs/trust-anchor.md`.
pub trait KernelKeyResolver {
    /// The raw 32-byte Ed25519 public key for `thumbprint`, or `None` if this
    /// verifier does not accept that key. `None` fails closed.
    fn resolve_key(&self, thumbprint: &str) -> Option<Vec<u8>>;
}

/// A resolver holding exactly one kernel key: the single-trust-domain case, and
/// what [`verify_chain`] wraps.
pub struct SingleKernelKey {
    thumbprint: String,
    public_key: Vec<u8>,
}

impl SingleKernelKey {
    /// Build from a raw 32-byte Ed25519 kernel public key. The thumbprint is
    /// derived from the key rather than supplied, so the two cannot disagree.
    pub fn new(public_key: &[u8]) -> Self {
        Self {
            thumbprint: crate::issuer_identity::kernel_key_thumbprint(public_key),
            public_key: public_key.to_vec(),
        }
    }
}

impl KernelKeyResolver for SingleKernelKey {
    fn resolve_key(&self, thumbprint: &str) -> Option<Vec<u8>> {
        (thumbprint == self.thumbprint).then(|| self.public_key.clone())
    }
}

/// A resolver over a map of accepted kernel keys, for chains that cross issuers.
///
/// Every key placed in here is one this verifier accepts. The map is the trust
/// bundle; populating it from a channel the presenter controls defeats the purpose.
#[derive(Debug, Clone, Default)]
pub struct KernelKeyMap {
    keys: HashMap<String, Vec<u8>>,
}

impl KernelKeyMap {
    /// Build from raw 32-byte Ed25519 kernel public keys. Each is filed under its
    /// own derived thumbprint, so a key cannot be registered under a thumbprint
    /// that is not its own.
    pub fn new(public_keys: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            keys: public_keys
                .into_iter()
                .map(|k| (crate::issuer_identity::kernel_key_thumbprint(&k), k))
                .collect(),
        }
    }

    /// Number of accepted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is accepted — every document fails closed.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KernelKeyResolver for KernelKeyMap {
    fn resolve_key(&self, thumbprint: &str) -> Option<Vec<u8>> {
        self.keys.get(thumbprint).cloned()
    }
}

/// Verify a full delegation chain end to end against a **single** kernel key.
///
/// Convenience over [`verify_chain_with`] for the single-trust-domain case: every
/// document on the chain must be signed by `kernel_public_key`. Because no hop can
/// cross a kernel key, no consent attestation is required or consulted, and
/// behaviour is exactly what it was before cross-key support existed.
///
/// For a chain that crosses issuers, use [`verify_chain_with`] — a cross-key hop
/// here simply fails to resolve a key and returns
/// [`ChainVerification::Inauthentic`].
pub fn verify_chain(
    kernel_public_key: &[u8],
    leaf: &Vaid,
    bundle: &PresentedBundle,
) -> ChainVerification {
    verify_chain_with(
        &SingleKernelKey::new(kernel_public_key),
        leaf,
        bundle,
        &AttestationBundle::empty(),
    )
}

/// [`verify_chain_at`] against the system clock.
///
/// Convenience for callers with no reason to control time. Anything that needs a
/// reproducible verdict — a conformance vector, a boundary test, replaying a
/// historical decision — must call [`verify_chain_at`] with an explicit instant
/// instead, or it is asserting against whenever it happened to run.
pub fn verify_chain_with(
    keys: &dyn KernelKeyResolver,
    leaf: &Vaid,
    bundle: &PresentedBundle,
    attestations: &AttestationBundle,
) -> ChainVerification {
    verify_chain_at(keys, leaf, bundle, attestations, Utc::now())
}

/// Verify a full delegation chain end to end, selecting a kernel key per document
/// and requiring parental consent for any hop that crosses one.
///
/// The procedure is ADR-0003's, extended at the two points where crossing a kernel
/// key changes what can be concluded:
///
/// 1. **Authenticate every document** — the leaf and every presented ancestor. The
///    key is selected from `keys` by the document's own `kernel_key_thumbprint`
///    (ADR-0004). A thumbprint the resolver does not accept is
///    [`ChainVerification::Inauthentic`]; so is a failed signature.
/// 2. **Pin each hop** — [`assemble_lineage`] requires a presented document whose
///    `vaid_id` equals the `parent_vaid` pinned inside the child's signed bytes.
/// 3. **Fail closed on an incomplete chain** — an unresolvable parent, a cycle, or
///    an implausible depth all yield [`ChainVerification::Unverifiable`].
/// 4. **Check containment** — tenant as the qualified `(trust_domain, tenant_id)`
///    pair, then scope and capabilities, using the mint-time matchers.
/// 5. **Require consent on a cross-key hop** — if a hop's parent and child were
///    signed by *different* kernel keys, the mint that enforced attenuation for one
///    is not the mint that issued the other, so a valid
///    [`ConsentAttestation`](crate::attestation::ConsentAttestation) for exactly
///    that `(parent, child)` pair is required. Same-key hops need none: the single
///    issuer enforced consent at mint time.
///
/// # Why step 5 exists
///
/// Without it, an issuer B holding its own kernel key could mint a document naming
/// issuer A's root `vaid_id` as `parent_vaid`, with authority inside A's, and have
/// it verify as `Attenuated` — while A delegated nothing. B needs only to know A's
/// root `vaid_id`, which every chain presentation discloses. See
/// [`crate::attestation`] for the full analysis.
///
/// # Verdict mapping
///
/// Authenticity failures — a missing attestation, one signed by a key that did not
/// issue the parent, one naming a different hop — are
/// [`ChainVerification::Inauthentic`]. Authority failures — an attestation that
/// does not cover what the child claims, or that exceeds what the parent holds —
/// are [`ChainVerification::NotAttenuated`]. No cross-key hop can reach
/// [`ChainVerification::Attenuated`] without a valid attestation.
///
/// # What this does not check
///
/// Expiry and revocation, as before. See [`verify_chain`].
pub fn verify_chain_at(
    keys: &dyn KernelKeyResolver,
    leaf: &Vaid,
    bundle: &PresentedBundle,
    attestations: &AttestationBundle,
    now: DateTime<Utc>,
) -> ChainVerification {
    // Step 1 — authenticate the leaf and EVERY presented document, before any of
    // them is allowed to influence assembly. Authenticating the whole bundle rather
    // than only the documents that end up on the chain is the stricter reading of
    // ADR-0003 step 1, and it means a presenter cannot mix an unauthenticated
    // document into a bundle and have it ignored.
    let authenticate = |doc: &Vaid| match keys.resolve_key(doc.kernel_key_thumbprint()) {
        // The resolver does not accept the key this document names. Fail closed:
        // an unaccepted issuer is not a degraded issuer, it is somebody else.
        None => false,
        Some(key) => verify_vaid_authenticity(&key, doc),
    };

    if !authenticate(leaf) {
        return ChainVerification::Inauthentic;
    }
    for doc in bundle.documents.values() {
        if !authenticate(doc) {
            return ChainVerification::Inauthentic;
        }
    }

    // Steps 2 and 3 — pin each hop against the signed `parent_vaid`, failing closed
    // on any gap. Cycle detection and MAX_LINEAGE_DEPTH come from
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

    // Steps 4 and 5 — containment at every hop, root first, plus consent wherever a
    // hop crosses a kernel key.
    for pair in chain_docs.windows(2) {
        let (parent, child) = (pair[0], pair[1]);

        let same_key = parent.kernel_key_thumbprint() == child.kernel_key_thumbprint();

        // Tenant as the qualified pair — on SAME-KEY hops. One issuer signed both
        // ends and a conforming mint refuses to cross a tenant boundary, so a
        // verifier can require the pair to be equal without taking the mint's word
        // for it. See `tenant_attenuates` for what that guarantee is worth.
        //
        // A CROSS-KEY hop crosses trust domains by definition — that is what
        // cross-organisation delegation is — so requiring equality here would
        // forbid the very case attestations exist to enable. The crossing is
        // instead authorized explicitly: the attestation below names the child's
        // `(trust_domain, tenant_id)` and is signed by the consenting parent, so
        // the pair is still checked, against a signed statement rather than against
        // the parent's own values. Consent to cross is narrower than permission to
        // cross unchecked.
        if same_key && !tenant_attenuates(parent, child.trust_domain(), child.tenant_id().as_str())
        {
            return ChainVerification::NotAttenuated;
        }
        if !scope_attenuates(parent, child.scope_boundary()) {
            return ChainVerification::NotAttenuated;
        }
        if !caps_attenuate(parent, child.capability_set()) {
            return ChainVerification::NotAttenuated;
        }

        // Same kernel key: one issuer signed both ends, and that issuer enforced
        // consent at mint time. Nothing further is required, and behaviour is
        // unchanged from before cross-key support.
        if same_key {
            continue;
        }

        // Cross-key hop. Consent must be presented, and must be the PARENT
        // issuer's.
        let attestation = match attestations.get(&parent.vaid_id(), &child.vaid_id()) {
            // Also the outcome for an attestation minted for a different hop: it is
            // filed under that hop's pair and is simply not found here. A replayed
            // attestation is inert rather than rejected.
            None => return ChainVerification::Inauthentic,
            Some(a) => a,
        };

        // The consenting party must be the party that issued the parent. Without
        // this, any accepted key could consent on any parent's behalf — which is
        // the forgery this whole step exists to stop, moved one level up.
        if attestation.kernel_key_thumbprint != parent.kernel_key_thumbprint()
            || attestation.trust_domain != parent.trust_domain()
        {
            return ChainVerification::Inauthentic;
        }

        // The consent must name the identity the child actually claims. Without
        // this, an attestation for a child in one tenant would authorize the same
        // `vaid_id` claiming any other — reintroducing, across the key boundary,
        // exactly the cross-tenant hole the same-key branch closes.
        if attestation.child_trust_domain != child.trust_domain()
            || attestation.child_tenant_id != child.tenant_id().as_str()
        {
            return ChainVerification::NotAttenuated;
        }

        match keys.resolve_key(&attestation.kernel_key_thumbprint) {
            None => return ChainVerification::Inauthentic,
            Some(key) => {
                if !verify_attestation_authenticity(&key, attestation) {
                    return ChainVerification::Inauthentic;
                }
            }
        }

        // The consent must be current. Checked AFTER authenticity, so a forged
        // attestation is reported as forged rather than as merely stale — the
        // stronger statement is the more useful one.
        //
        // NOTE: this consults the ATTESTATION's window only. Document expiry is
        // deliberately not consulted here, exactly as elsewhere in this module; an
        // attestation may outlive the parent VAID it delegates from, and whether
        // that should change is a separate decision.
        if !attestation.is_current(now) {
            return ChainVerification::ConsentExpired;
        }

        // The child may hold no more than the parent consented to...
        if !scope_attenuates_within(&attestation.scope_boundary, child.scope_boundary())
            || !caps_attenuate_within(&attestation.capability_set, child.capability_set())
        {
            return ChainVerification::NotAttenuated;
        }

        // ...and the parent cannot consent to more than it holds itself. Checked
        // separately from the hop containment above, because that compares the
        // child to the parent and this compares the ATTESTATION to the parent — an
        // over-broad attestation with a well-behaved child would otherwise pass.
        if !scope_attenuates(parent, &attestation.scope_boundary)
            || !caps_attenuate(parent, &attestation.capability_set)
        {
            return ChainVerification::NotAttenuated;
        }
    }

    ChainVerification::Attenuated
}

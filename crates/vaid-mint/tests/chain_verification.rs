//! Third-party end-to-end lineage verification (ADR-0003). Integration tests.
//!
//! Every test here asserts a **fail-closed** outcome for a chain a third party
//! cannot fully establish, plus one positive control so the suite cannot pass
//! vacuously.
//!
//! Nothing in this file is a frozen vector and this file must never become one.
//! ADR-0003 §3 calls for a chain-presentation vector as *additive* conformance
//! work; it is deliberately not generated or frozen here, so the verifier
//! semantics can be reviewed before anything is frozen against them.
//!
//! ## Why these documents are signed locally rather than minted
//!
//! Most cases below are constructible through [`ReferenceIssuer`], but two are
//! not: a **cycle** and a **depth overflow** both require choosing a document's
//! `vaid_id`, and the issuer generates a fresh UUIDv4 per mint and never accepts
//! one. That is a security property, not an obstacle to route around — it is
//! exactly what makes chain substitution infeasible.
//!
//! So the suite drives a local `TestMint`: a kernel keypair plus the same public
//! document-building and canonical-signing calls the issuer itself makes
//! (`Vaid::with_lineage` → `canonical_vaid_signing_bytes` → `with_kernel_signature`).
//! Documents it produces are genuinely authentic under its own kernel key, which
//! is the point: it lets a test present an *authentic but adversarially shaped*
//! chain, which is the threat model the verifier exists for. It also deliberately
//! does not enforce attenuation, so a child claiming authority its parent never
//! held can be signed and presented.

use chrono::{Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use vaid_mint::chain::{verify_chain, ChainVerification, PresentedBundle};
use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::revocation::{
    assemble_lineage, LineageAssembly, LineageResolver, ParentResolution, MAX_LINEAGE_DEPTH,
};
use vaid_mint::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid, VaidId,
};

/// A kernel key plus the issuer's own document-building and signing calls.
/// Produces authentic documents while leaving `agent_id`, lineage and authority
/// under the test's control. Attenuation is NOT enforced here — see module docs.
struct TestMint {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>,
}

impl TestMint {
    /// A deterministic kernel key. `from_seed_unchecked` keeps the suite
    /// reproducible; nothing here depends on the seed's value.
    fn new(seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid ed25519 seed");
        let public_key = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            public_key,
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Build and kernel-sign a VAID with a caller-chosen id, parent and authority.
    fn sign(
        &self,
        agent_id: AgentId,
        parent_vaid: Option<VaidId>,
        scope: &[&str],
        caps: &[&str],
    ) -> Vaid {
        let now = Utc::now();
        let unsigned = Vaid::with_lineage(
            agent_id,
            AgentClass::new("test"),
            "1.0.0".to_string(),
            TenantId::new("t"),
            now,
            now + Duration::hours(1),
            (0u8..32).collect(),
            Vec::new(),
            parent_vaid,
            scope.iter().map(|s| s.to_string()).collect(),
            compute_lineage_hash(parent_vaid, &agent_id),
            caps.iter().map(|c| c.to_string()).collect(),
            // RFC 2606 reserved, matching the frozen vector's reasoning: a suite
            // that publishes signable keys must not name a bindable domain.
            "vaid.example".to_string(),
            kernel_key_thumbprint(&self.public_key),
        );
        let signature = self.key_pair.sign(&canonical_vaid_signing_bytes(&unsigned));
        unsigned.with_kernel_signature(signature.as_ref().to_vec())
    }
}

/// A stable `AgentId` from a small integer, so a test can name the ids it wants
/// to arrange into a cycle or a long chain.
fn id(n: u128) -> AgentId {
    AgentId::from_uuid(Uuid::from_u128(n))
}

fn vid(agent_id: &AgentId) -> VaidId {
    VaidId::from_uuid(*agent_id.as_uuid())
}

// ─────────────────────────────────────────────────────────────────────────────
// POSITIVE CONTROL
// ─────────────────────────────────────────────────────────────────────────────

/// A complete, authentic, properly attenuated three-hop chain verifies.
///
/// Without this the whole suite could pass by rejecting everything.
#[test]
fn positive_control_complete_attenuated_chain_verifies() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let mid_id = id(2);
    let leaf_id = id(3);

    let root = mint.sign(root_id, None, &["data.tenant"], &["read", "write"]);
    let mid = mint.sign(
        mid_id,
        Some(vid(&root_id)),
        &["data.tenant.sub"],
        &["read", "write"],
    );
    let leaf = mint.sign(
        leaf_id,
        Some(vid(&mid_id)),
        &["data.tenant.sub.leaf"],
        &["read"],
    );

    let bundle = PresentedBundle::new(vec![root, mid]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::Attenuated,
        "a complete, authentic, contained chain must verify"
    );
}

/// A rootless leaf is trivially complete: one hop, nothing to contain.
#[test]
fn positive_control_rootless_leaf_verifies_against_empty_bundle() {
    let mint = TestMint::new(1);
    let root = mint.sign(id(1), None, &["data.tenant"], &["read"]);

    assert_eq!(
        verify_chain(mint.public_key(), &root, &PresentedBundle::empty()),
        ChainVerification::Attenuated,
        "a VAID with no parent_vaid is its own root and needs no ancestors"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// FAIL-CLOSED CASES
// ─────────────────────────────────────────────────────────────────────────────

/// MISSING ANCESTOR. The middle document is withheld, so the hop above the leaf
/// resolves to `Unknown`. Must be `Unverifiable` — never a chain silently
/// shortened to the documents that happen to be present.
#[test]
fn missing_ancestor_is_unverifiable() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let mid_id = id(2);
    let leaf_id = id(3);

    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    let _mid = mint.sign(mid_id, Some(vid(&root_id)), &["data.tenant.sub"], &["read"]);
    let leaf = mint.sign(
        leaf_id,
        Some(vid(&mid_id)),
        &["data.tenant.sub.leaf"],
        &["read"],
    );

    // The root is presented but the middle hop is not.
    let bundle = PresentedBundle::new(vec![root]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::Unverifiable,
        "an unpresented ancestor must be attenuation-unverifiable, not satisfied"
    );
}

/// UNREACHABLE RESOLVER. Nothing at all is presented for a leaf that names a
/// parent — the third-party analogue of a resolver that cannot be consulted.
#[test]
fn unreachable_resolver_empty_bundle_is_unverifiable() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let leaf = mint.sign(id(2), Some(vid(&root_id)), &["data.tenant"], &["read"]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &PresentedBundle::empty()),
        ChainVerification::Unverifiable,
        "no presented ancestors must fail closed, not resolve the leaf as a root"
    );
}

/// TAMPERED `parent_vaid`. The leaf's parent pointer is swapped to a
/// more-privileged ancestor while its original kernel signature is kept.
/// `parent_vaid` is inside the canonical signing bytes, so this breaks the
/// signature; `lineage_hash` no longer matches either. Must be `Inauthentic`.
#[test]
fn tampered_parent_vaid_is_inauthentic() {
    let mint = TestMint::new(1);

    let privileged_id = id(1);
    let restricted_id = id(2);
    let leaf_id = id(3);

    let privileged = mint.sign(privileged_id, None, &["data"], &["read", "write"]);
    let restricted = mint.sign(
        restricted_id,
        Some(vid(&privileged_id)),
        &["data.tenant"],
        &["read"],
    );
    let leaf = mint.sign(
        leaf_id,
        Some(vid(&restricted_id)),
        &["data.tenant.sub"],
        &["read"],
    );

    // Re-point the leaf at the privileged ancestor, keeping every other field
    // and the ORIGINAL signature.
    let forged = Vaid::with_lineage(
        leaf.agent_id(),
        leaf.agent_class().clone(),
        leaf.version().to_string(),
        leaf.tenant_id().clone(),
        leaf.issued_at(),
        leaf.expires_at(),
        leaf.public_key_der().to_vec(),
        Vec::new(),
        Some(vid(&privileged_id)),
        leaf.scope_boundary().to_vec(),
        leaf.lineage_hash().to_string(),
        leaf.capability_set().to_vec(),
        leaf.trust_domain().to_string(),
        leaf.kernel_key_thumbprint().to_string(),
    )
    .with_kernel_signature(leaf.kernel_signature().to_vec());

    let bundle = PresentedBundle::new(vec![privileged, restricted]);

    assert_eq!(
        verify_chain(mint.public_key(), &forged, &bundle),
        ChainVerification::Inauthentic,
        "a re-pointed parent_vaid must break the kernel signature"
    );
}

/// A presented ancestor signed by a DIFFERENT kernel key. The v3 thumbprint
/// check rejects it before its signature is even considered.
#[test]
fn ancestor_signed_by_another_kernel_key_is_inauthentic() {
    let mint = TestMint::new(1);
    let other = TestMint::new(2);

    let root_id = id(1);
    let root = other.sign(root_id, None, &["data"], &["read"]);
    let leaf = mint.sign(id(2), Some(vid(&root_id)), &["data.tenant"], &["read"]);

    let bundle = PresentedBundle::new(vec![root]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::Inauthentic,
        "a chain crossing kernel keys must be rejected, not verified under a key that did not sign it"
    );
}

/// A CHILD CLAIMING SCOPE ITS PARENT NEVER HELD. Every document is authentic and
/// the chain is complete — the only defect is containment, which is precisely
/// what a third party could not previously check.
#[test]
fn child_exceeding_parent_scope_is_not_attenuated() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    // `data.other` is not within `data.tenant`.
    let leaf = mint.sign(id(2), Some(vid(&root_id)), &["data.other"], &["read"]);

    let bundle = PresentedBundle::new(vec![root]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::NotAttenuated,
        "a child must not hold scope outside its parent's, however well signed"
    );
}

/// The same, one hop further up: containment is checked at EVERY hop, not just
/// the leaf's. The leaf is contained by its parent but the parent escaped the
/// root, so the transitive subset relation is broken above the leaf.
#[test]
fn mid_chain_scope_escalation_is_not_attenuated() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let mid_id = id(2);

    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    // `data.other` escapes the root.
    let mid = mint.sign(mid_id, Some(vid(&root_id)), &["data.other"], &["read"]);
    // The leaf is properly contained by `mid`, so a leaf-only check would pass.
    let leaf = mint.sign(id(3), Some(vid(&mid_id)), &["data.other.sub"], &["read"]);

    let bundle = PresentedBundle::new(vec![root, mid]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::NotAttenuated,
        "containment must hold at every hop, not only the one nearest the leaf"
    );
}

/// A child claiming a CAPABILITY its parent never held.
#[test]
fn child_exceeding_parent_capabilities_is_not_attenuated() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    let leaf = mint.sign(
        id(2),
        Some(vid(&root_id)),
        &["data.tenant.sub"],
        &["read", "write"],
    );

    let bundle = PresentedBundle::new(vec![root]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::NotAttenuated,
        "a child must not hold a capability its parent lacks"
    );
}

/// THE ⊤ ESCALATION. An empty child scope means *unrestricted*, so a naive
/// `all()` over zero entries is vacuously true and would admit an unrestricted
/// child under a restricted parent. Reusing the mint-time matcher is what carries
/// this guard to verify time; reimplementing containment is how it would be lost.
#[test]
fn empty_child_scope_under_restricted_parent_is_not_attenuated() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    // Empty scope = ⊤, strictly broader than the restricted parent.
    let leaf = mint.sign(id(2), Some(vid(&root_id)), &[], &["read"]);

    let bundle = PresentedBundle::new(vec![root]);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::NotAttenuated,
        "an empty (unrestricted) child scope under a restricted parent is an escalation"
    );
}

/// A CYCLE. Two authentic documents each naming the other as parent. Assembly
/// must terminate and fail closed rather than loop.
///
/// This shape cannot arise from `ReferenceIssuer` — a cycle needs a document to
/// name a `vaid_id` that does not exist yet, and the issuer mints a fresh UUIDv4
/// every time. The test builds it directly to prove the verifier survives it.
#[test]
fn cycle_is_unverifiable() {
    let mint = TestMint::new(1);

    let a_id = id(1);
    let b_id = id(2);

    let a = mint.sign(a_id, Some(vid(&b_id)), &["data.tenant"], &["read"]);
    let b = mint.sign(b_id, Some(vid(&a_id)), &["data.tenant"], &["read"]);

    let bundle = PresentedBundle::new(vec![a.clone(), b]);

    assert_eq!(
        verify_chain(mint.public_key(), &a, &bundle),
        ChainVerification::Unverifiable,
        "a cyclic presentation must fail closed, not loop or resolve"
    );
}

/// DEPTH OVERFLOW. A chain longer than `MAX_LINEAGE_DEPTH` must fail closed on
/// the bound rather than being walked.
#[test]
fn depth_overflow_is_unverifiable() {
    let mint = TestMint::new(1);

    // Root at index 0, then MAX_LINEAGE_DEPTH more hops, so the leaf sits beyond
    // the bound. Authority is identical at every hop, so the ONLY reason this can
    // fail is the depth bound.
    let depth = MAX_LINEAGE_DEPTH + 1;
    let mut docs: Vec<Vaid> = Vec::with_capacity(depth + 1);

    let root_id = id(0);
    docs.push(mint.sign(root_id, None, &["data.tenant"], &["read"]));

    for n in 1..=depth {
        let this_id = id(n as u128);
        let parent = vid(&id((n - 1) as u128));
        docs.push(mint.sign(this_id, Some(parent), &["data.tenant"], &["read"]));
    }

    let leaf = docs.pop().expect("chain is non-empty");
    let bundle = PresentedBundle::new(docs);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::Unverifiable,
        "a chain deeper than MAX_LINEAGE_DEPTH must fail closed"
    );
}

/// Boundary control for the test above. A chain of exactly `MAX_LINEAGE_DEPTH`
/// documents still verifies, so `depth_overflow_is_unverifiable` is failing on
/// the bound rather than on some incidental property of a long chain.
#[test]
fn chain_at_the_depth_bound_still_verifies() {
    let mint = TestMint::new(1);

    // `assemble_lineage` admits a chain of up to MAX_LINEAGE_DEPTH entries: a
    // root plus MAX_LINEAGE_DEPTH - 1 hops.
    let hops = MAX_LINEAGE_DEPTH - 1;
    let mut docs: Vec<Vaid> = Vec::with_capacity(hops + 1);

    docs.push(mint.sign(id(0), None, &["data.tenant"], &["read"]));
    for n in 1..=hops {
        let parent = vid(&id((n - 1) as u128));
        docs.push(mint.sign(id(n as u128), Some(parent), &["data.tenant"], &["read"]));
    }

    let leaf = docs.pop().expect("chain is non-empty");
    let bundle = PresentedBundle::new(docs);

    assert_eq!(
        verify_chain(mint.public_key(), &leaf, &bundle),
        ChainVerification::Attenuated,
        "a chain exactly at the depth bound must still verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESOLVER CONTRACT
// ─────────────────────────────────────────────────────────────────────────────

/// The bundle's three-state resolution, asserted directly. Conflating a genuine
/// root with an unpresented document is the R.4.2 bug that lets a leaf whose
/// ancestors were withheld pass as rootless.
#[test]
fn bundle_resolver_distinguishes_root_from_unknown() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let child_id = id(2);
    let absent_id = id(99);

    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    let child = mint.sign(child_id, Some(vid(&root_id)), &["data.tenant"], &["read"]);

    let bundle = PresentedBundle::new(vec![root, child]);

    assert_eq!(
        bundle.resolve_parent(&vid(&root_id)),
        ParentResolution::Root,
        "a presented document with no parent_vaid is a KNOWN root"
    );
    assert_eq!(
        bundle.resolve_parent(&vid(&child_id)),
        ParentResolution::Parent(vid(&root_id)),
        "a presented document with a parent_vaid resolves that hop"
    );
    assert_eq!(
        bundle.resolve_parent(&vid(&absent_id)),
        ParentResolution::Unknown,
        "an unpresented id is UNKNOWN — never mistaken for a root"
    );
}

/// The bundle drives the existing `assemble_lineage` unchanged, root first.
#[test]
fn bundle_assembles_ordered_lineage_root_first() {
    let mint = TestMint::new(1);

    let root_id = id(1);
    let mid_id = id(2);
    let leaf_id = id(3);

    let root = mint.sign(root_id, None, &["data.tenant"], &["read"]);
    let mid = mint.sign(mid_id, Some(vid(&root_id)), &["data.tenant"], &["read"]);
    let leaf = mint.sign(leaf_id, Some(vid(&mid_id)), &["data.tenant"], &["read"]);

    let bundle = PresentedBundle::new(vec![root, mid]);

    assert_eq!(
        assemble_lineage(&leaf, &bundle),
        LineageAssembly::Complete(vec![vid(&root_id), vid(&mid_id), vid(&leaf_id)]),
        "ordered root first, leaf last"
    );
}

//! Cross-key chain verification and detached consent attestations. Adversarial
//! tests, Rust side.
//!
//! The first test in this file is the one the whole feature turns on: a hop that
//! crosses a kernel key, with no attestation, must NOT verify. Everything else here
//! is a way of getting that wrong more subtly.
//!
//! Nothing here is a frozen vector and this file must never become one. The
//! attestation format is deliberately UNFROZEN — see `emit_attestation_digest` for
//! the byte-agreement evidence that stands in for a vector until it is.
//!
//! Two organisations throughout: `A` (`a.example`) and `B` (`b.example`), each with
//! its own kernel key. `A` is the delegating parent; `B` mints the child.

use chrono::{Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use vaid_mint::attestation::{
    canonical_attestation_signing_bytes, AttestationBundle, ConsentAttestation,
};
use vaid_mint::chain::{
    verify_chain_with, ChainVerification, KernelKeyMap, PresentedBundle, SingleKernelKey,
};
use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid, VaidId,
};

/// One organisation: a kernel key plus a trust domain. Signs both VAID documents
/// and consent attestations, using the same public calls the reference issuer uses.
/// Enforces nothing — that is the point, since these tests present authentic but
/// adversarially shaped material.
struct Org {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>,
    trust_domain: &'static str,
}

impl Org {
    fn new(seed_byte: u8, trust_domain: &'static str) -> Self {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).expect("valid seed");
        let public_key = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            public_key,
            trust_domain,
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn thumbprint(&self) -> String {
        kernel_key_thumbprint(&self.public_key)
    }

    fn sign(
        &self,
        agent_id: AgentId,
        parent_vaid: Option<VaidId>,
        tenant: &str,
        scope: &[&str],
        caps: &[&str],
    ) -> Vaid {
        let now = Utc::now();
        let unsigned = Vaid::with_lineage(
            agent_id,
            AgentClass::new("test"),
            "1.0.0".to_string(),
            TenantId::new(tenant),
            now,
            now + Duration::hours(1),
            (0u8..32).collect(),
            Vec::new(),
            parent_vaid,
            scope.iter().map(|s| s.to_string()).collect(),
            compute_lineage_hash(parent_vaid, &agent_id),
            caps.iter().map(|c| c.to_string()).collect(),
            self.trust_domain.to_string(),
            self.thumbprint(),
        );
        let signature = self.key_pair.sign(&canonical_vaid_signing_bytes(&unsigned));
        unsigned.with_kernel_signature(signature.as_ref().to_vec())
    }

    /// Sign a consent attestation as the parent's issuer.
    #[allow(clippy::too_many_arguments)]
    fn attest(
        &self,
        parent_vaid: VaidId,
        child_vaid: VaidId,
        child_trust_domain: &str,
        child_tenant: &str,
        scope: &[&str],
        caps: &[&str],
    ) -> ConsentAttestation {
        let unsigned = ConsentAttestation::new(
            parent_vaid,
            child_vaid,
            child_trust_domain.to_string(),
            child_tenant.to_string(),
            scope.iter().map(|s| s.to_string()).collect(),
            caps.iter().map(|c| c.to_string()).collect(),
            self.trust_domain.to_string(),
            self.thumbprint(),
        );
        let signature = self
            .key_pair
            .sign(&canonical_attestation_signing_bytes(&unsigned));
        unsigned.with_signature(signature.as_ref().to_vec())
    }
}

fn id(n: u128) -> AgentId {
    AgentId::from_uuid(Uuid::from_u128(n))
}

fn vid(agent_id: &AgentId) -> VaidId {
    VaidId::from_uuid(*agent_id.as_uuid())
}

/// A verifier that accepts BOTH organisations' kernel keys — the multi-key case.
/// Accepting a key is an assertion of trust, so this is the strongest position an
/// adversary could hope for: both issuers are trusted, and the chain must still
/// fail without consent.
fn both_keys(a: &Org, b: &Org) -> KernelKeyMap {
    KernelKeyMap::new(vec![a.public_key().to_vec(), b.public_key().to_vec()])
}

// ─────────────────────────────────────────────────────────────────────────────
// THE LOAD-BEARING TEST
// ─────────────────────────────────────────────────────────────────────────────

/// A cross-key hop with NO attestation must never be `Attenuated`.
///
/// Written first, deliberately. Everything else in the cross-key feature is only
/// worth having if this holds: both kernel keys are trusted, every document is
/// authentic, the chain assembles, and authority is properly contained — the ONLY
/// thing missing is the parent's consent.
#[test]
fn cross_key_hop_without_an_attestation_is_never_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read", "write"]);
    let child = b.sign(
        id(2),
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    let verdict = verify_chain_with(
        &both_keys(&a, &b),
        &child,
        &PresentedBundle::new(vec![root]),
        &AttestationBundle::empty(),
    );

    assert_ne!(
        verdict,
        ChainVerification::Attenuated,
        "a cross-key hop without consent must NEVER verify"
    );
    assert_eq!(
        verdict,
        ChainVerification::Inauthentic,
        "missing consent on a cross-key hop is an authenticity failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// POSITIVE CONTROLS
// ─────────────────────────────────────────────────────────────────────────────

/// The same chain, WITH the parent issuer's consent, verifies. Without this the
/// suite could pass by rejecting every cross-key chain unconditionally.
#[test]
fn cross_key_hop_with_valid_consent_verifies() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read", "write"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    let attestation = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::Attenuated,
        "a cross-key hop with the parent issuer's signed consent must verify"
    );
}

/// A single-key chain is unchanged by any of this: no attestation is required or
/// consulted, and the single-key resolver reaches the same verdict.
#[test]
fn same_key_chain_needs_no_attestation() {
    let a = Org::new(1, "a.example");

    let root_id = id(1);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    let child = a.sign(
        id(2),
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &SingleKernelKey::new(a.public_key()),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::empty(),
        ),
        ChainVerification::Attenuated,
        "same-key hops keep their existing behaviour"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ADVERSARIAL
// ─────────────────────────────────────────────────────────────────────────────

/// THE FORGED SIBLING. Org B mints a document naming A's root as its parent, with
/// a strict subset of A's authority, signed with B's own key, and presents it with
/// no attestation.
///
/// This is the attack the whole cross-key design exists to stop. B needs only to
/// KNOW A's root `vaid_id` — which every chain presentation discloses to its
/// verifier — and A never delegated anything.
#[test]
fn forged_sibling_without_consent_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let a_root_id = id(1);
    let a_root = a.sign(
        a_root_id,
        None,
        "acme",
        &["data.acme"],
        &["read", "write", "admin"],
    );

    // B forges a child of A's root. Strict subset: containment cannot catch it.
    let forged = b.sign(
        id(99),
        Some(vid(&a_root_id)),
        "acme",
        &["data.acme.stolen"],
        &["read"],
    );

    let verdict = verify_chain_with(
        &both_keys(&a, &b),
        &forged,
        &PresentedBundle::new(vec![a_root]),
        &AttestationBundle::empty(),
    );

    assert_ne!(
        verdict,
        ChainVerification::Attenuated,
        "FORGED SIBLING: an unconsented cross-issuer child must not verify"
    );
}

/// An attestation signed by the WRONG KEY. B signs its own permission slip. The
/// consenting party must be the party that issued the parent.
#[test]
fn attestation_signed_by_the_wrong_key_is_inauthentic() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    // B attests to its own delegation. Authentic under B's key, and irrelevant.
    let self_signed = b.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![self_signed]),
        ),
        ChainVerification::Inauthentic,
        "only the issuer that minted the parent may consent on its behalf"
    );
}

/// An attestation for a DIFFERENT CHILD. A consented to one delegation; a second,
/// unconsented child tries to ride it.
#[test]
fn attestation_for_a_different_child_does_not_apply() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let blessed_id = id(2);
    let other_id = id(3);

    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    // A consented to `blessed`, and only to `blessed`.
    let attestation = a.attest(
        vid(&root_id),
        vid(&blessed_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    let other = b.sign(
        other_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &other,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::Inauthentic,
        "consent names one child; another cannot borrow it"
    );
}

/// An attestation NARROWER than what the child claims. A consented to `read`; the
/// child's document claims `read` and `write`, both within the root's authority so
/// hop containment alone passes.
#[test]
fn attestation_narrower_than_the_child_claims_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);

    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read", "write"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read", "write"],
    );

    // Consent to `read` only.
    let attestation = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::NotAttenuated,
        "a child may hold no more than the parent consented to"
    );
}

/// The scope counterpart of the test above: consent to one subtree, child claims
/// a sibling subtree that is still inside the root's.
#[test]
fn attestation_for_a_different_subtree_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);

    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.other"],
        &["read"],
    );

    let attestation = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.blessed"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::NotAttenuated,
        "consent to one subtree does not authorize a sibling"
    );
}

/// An attestation REPLAYED onto a different chain. The attestation is genuine, is
/// signed by A, and is presented against a chain whose parent is a different root.
///
/// It is filed under the `(parent, child)` pair it names, so the lookup for this
/// hop simply does not find it. Replay is structurally inert rather than rejected
/// by a check that could be got wrong.
#[test]
fn attestation_replayed_onto_a_different_chain_does_not_apply() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_one = id(1);
    let root_two = id(2);
    let child_id = id(3);

    // A genuine consent, issued against root_one.
    let genuine = a.attest(
        vid(&root_one),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    // A different chain: the same child id presented under a DIFFERENT root.
    let other_root = a.sign(root_two, None, "acme", &["data.acme"], &["read"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_two)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![other_root]),
            &AttestationBundle::new(vec![genuine]),
        ),
        ChainVerification::Inauthentic,
        "consent is bound to one (parent, child) pair and cannot be replayed"
    );
}

/// A MID-CHAIN cross-key hop where only the LEAF hop is attested. The chain is
/// A(root) -> B(mid) -> B(leaf): the leaf hop is same-key and needs nothing, while
/// the mid hop crosses and is unattested. A verifier that stopped at the hop
/// nearest the leaf, or that accepted "some attestation was presented", would pass
/// this.
#[test]
fn mid_chain_cross_key_hop_unattested_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let mid_id = id(2);
    let leaf_id = id(3);

    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    // Cross-key hop, deliberately unattested.
    let mid = b.sign(
        mid_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );
    // Same-key hop below it.
    let leaf = b.sign(
        leaf_id,
        Some(vid(&mid_id)),
        "acme",
        &["data.acme.sub.task"],
        &["read"],
    );

    // An attestation IS presented — for the wrong hop (the same-key one, which
    // needs none). Presence of consent somewhere must not satisfy the hop lacking it.
    let irrelevant = b.attest(
        vid(&mid_id),
        vid(&leaf_id),
        "b.example",
        "acme",
        &["data.acme.sub.task"],
        &["read"],
    );

    let verdict = verify_chain_with(
        &both_keys(&a, &b),
        &leaf,
        &PresentedBundle::new(vec![root, mid]),
        &AttestationBundle::new(vec![irrelevant]),
    );

    assert_ne!(
        verdict,
        ChainVerification::Attenuated,
        "an unattested cross-key hop anywhere on the chain must fail the whole chain"
    );
    assert_eq!(verdict, ChainVerification::Inauthentic);
}

/// An attestation consenting to MORE than the parent itself holds. The child stays
/// within the attestation, so the child-vs-attestation check passes; only the
/// attestation-vs-parent check catches it.
#[test]
fn attestation_exceeding_the_parent_authority_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);

    // The root holds `read` only.
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    // ...but consents to `read` AND `write`.
    let over_broad = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read", "write"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![over_broad]),
        ),
        ChainVerification::NotAttenuated,
        "a parent cannot consent to more than it holds"
    );
}

/// Consent that names a DIFFERENT tenant than the child claims. Cross-key hops
/// skip the pair-equality check (they cross domains by definition), so the
/// attestation is the only thing binding the child's claimed identity.
#[test]
fn attestation_naming_a_different_tenant_is_not_attenuated() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);

    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    // The child claims tenant `other`.
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "other",
        &["data.acme.sub"],
        &["read"],
    );
    // A consented to a child in tenant `acme`.
    let attestation = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::NotAttenuated,
        "consent must name the identity the child actually claims"
    );
}

/// A key the resolver does not accept fails closed, even with valid consent.
/// Accepting a key is the verifier's trust decision; an unaccepted issuer is not a
/// degraded issuer, it is somebody else.
#[test]
fn an_unaccepted_kernel_key_is_inauthentic() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read"],
    );
    let attestation = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );

    // Only A is accepted; B's child cannot be authenticated at all.
    assert_eq!(
        verify_chain_with(
            &KernelKeyMap::new(vec![a.public_key().to_vec()]),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![attestation]),
        ),
        ChainVerification::Inauthentic,
        "a document signed by an unaccepted key must fail closed"
    );
}

/// A tampered attestation — any field altered after signing — fails authenticity.
#[test]
fn tampered_attestation_is_inauthentic() {
    let a = Org::new(1, "a.example");
    let b = Org::new(2, "b.example");

    let root_id = id(1);
    let child_id = id(2);
    let root = a.sign(root_id, None, "acme", &["data.acme"], &["read", "write"]);
    let child = b.sign(
        child_id,
        Some(vid(&root_id)),
        "acme",
        &["data.acme.sub"],
        &["read", "write"],
    );

    // Genuine consent to `read`, then widened to `write` while keeping A's
    // signature.
    let mut tampered = a.attest(
        vid(&root_id),
        vid(&child_id),
        "b.example",
        "acme",
        &["data.acme.sub"],
        &["read"],
    );
    tampered.capability_set = vec!["read".to_string(), "write".to_string()];

    assert_eq!(
        verify_chain_with(
            &both_keys(&a, &b),
            &child,
            &PresentedBundle::new(vec![root]),
            &AttestationBundle::new(vec![tampered]),
        ),
        ChainVerification::Inauthentic,
        "widening consent after signing must break its signature"
    );
}

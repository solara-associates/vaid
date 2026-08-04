//! **Detached consent attestation**: a parent issuer's signed statement that a
//! particular child may hold particular authority under a particular parent.
//!
//! # The gap this closes
//!
//! Nothing in a VAID document proves the parent *consented* to the delegation.
//! `mint_child` requires an authenticated parent principal and pins the child's
//! `parent_vaid` to that verified parent — but that enforcement is a property of
//! the mint's session, in-process, at mint time. None of it lands in the child
//! document. What the child carries is `parent_vaid` (a UUID its own issuer writes
//! and signs with its own kernel key) and `lineage_hash`, computed from that same
//! issuer-chosen value. The proof-of-possession proves the child controls its key,
//! not that the parent authorized anything.
//!
//! Under **one** kernel key this is invisible and the design is sound: the single
//! mint is the only thing that can sign, and it enforced consent before signing.
//! Widen the key set and it stops being sound. An issuer B, holding its own kernel
//! key, can mint a document naming issuer A's root `vaid_id` as `parent_vaid`, with
//! scope and capabilities inside A's, and sign it with B's key. Every document
//! authenticates under its own key, the chain assembles, containment holds — and A
//! never delegated anything to B. B needs only to *know* A's root `vaid_id`, which
//! is disclosed to every verifier in any chain presentation.
//!
//! This is why cross-key hops require an attestation and same-key hops do not.
//!
//! # Additive, by construction
//!
//! No VAID document changes. No new field, no `sig_version` bump, no `mint_v1`
//! re-freeze. This is a **separate signed object** presented alongside the chain —
//! the same move ADR-0003 made for the ancestors themselves.
//!
//! # Canonicalization
//!
//! Identical discipline to the VAID document ([`crate::document::canonical_vaid_signing_bytes`]):
//! serialize, force the signature field to JSON `null` (a signature cannot cover its
//! own value), canonicalize per RFC 8785 (JCS), SHA-256. The kernel key then signs
//! that digest. Nulling rather than removing means the digest of an unsigned
//! attestation and of the same attestation once signed are identical.
//!
//! # Replayed and absent consent are indistinguishable in the verdict
//!
//! [`AttestationBundle`] indexes attestations by the `(parent_vaid, child_vaid)`
//! hop they name. The verifier asks for the hop in front of it, so an attestation
//! minted for a *different* delegation is filed under a different key and is simply
//! not found. It is never **rejected** — there is no rejection path, and therefore
//! no rejection path to get wrong.
//!
//! **The cost, stated because it is real:** a presenter who replays a genuine
//! attestation onto the wrong chain and a presenter who supplies nothing at all
//! receive the *same* verdict, [`ChainVerification::Inauthentic`](crate::chain::ChainVerification::Inauthentic).
//! Both are safe — neither can reach `Attenuated` — but the verdict alone cannot
//! tell an operator which happened. Diagnosing "I presented consent and it was
//! ignored" means comparing the attestation's own `parent_vaid`/`child_vaid`
//! against the hop by hand, outside the verifier.
//!
//! This was chosen deliberately over an explicit "this attestation names a
//! different hop" check. Such a check is a second code path that must agree with
//! the lookup, and a disagreement between the two is precisely the shape of bug
//! that lets a mismatched attestation through. Structural inertness has no such
//! failure mode. If a deployment needs to tell the two apart, the right fix is a
//! *diagnostic* that reports which hops lacked consent — not a rejection branch in
//! the verifier.
//!
//! # What is deliberately absent
//!
//! **No timestamps.** An `expires_at` nobody consults is decoration, and chain
//! verification deliberately does not consult expiry for VAID documents either
//! ([`crate::chain::verify_chain`]). Replay is bound structurally instead: an
//! attestation names both `parent_vaid` and `child_vaid`, and both are fresh
//! UUIDv4s, so it cannot be moved onto a different pair. If a deployment needs
//! time-bounded consent, that is a real requirement and it needs a field plus a
//! verifier that checks it — not a field that only looks like one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ring::signature::{UnparsedPublicKey, ED25519};

use crate::document::VaidId;

/// Attestation format discriminant. Independent of `sig_version`: this is a
/// separate object with its own shape, and bumping one must not imply the other.
pub const ATTESTATION_VERSION: u8 = 1;

/// A parent issuer's signed statement of consent to one delegation.
///
/// Read it as: *the issuer holding the kernel key identified by
/// `kernel_key_thumbprint`, in trust domain `trust_domain`, consents to
/// `child_vaid` holding at most `scope_boundary`/`capability_set` under
/// `parent_vaid`.*
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentAttestation {
    /// Format discriminant ([`ATTESTATION_VERSION`]).
    pub att_version: u8,
    /// The parent whose authority is being delegated. MUST equal the `vaid_id` of
    /// the parent document on the hop this attestation covers.
    pub parent_vaid: VaidId,
    /// The child receiving the delegation. MUST equal the `vaid_id` of the child
    /// document on that hop.
    pub child_vaid: VaidId,
    /// The trust domain the parent consents to the child claiming. MUST equal the
    /// child document's `trust_domain`.
    ///
    /// This field is why a cross-key hop can legitimately change trust domain when
    /// a same-key hop cannot. Same-key hops require the `(trust_domain, tenant_id)`
    /// pair to be equal across the hop, because one issuer signed both ends and a
    /// conforming mint refuses to cross that boundary. A cross-organisation
    /// delegation crosses it by definition — so the crossing must be *named and
    /// signed* by the consenting parent rather than merely permitted.
    pub child_trust_domain: String,
    /// The tenant the parent consents to the child claiming. MUST equal the child
    /// document's `tenant_id`. See [`ConsentAttestation::child_trust_domain`].
    pub child_tenant_id: String,
    /// The maximum scope the parent consents to. The child's own
    /// `scope_boundary` must be contained by this.
    pub scope_boundary: Vec<String>,
    /// The maximum capabilities the parent consents to.
    pub capability_set: Vec<String>,
    /// The attesting issuer's trust domain. MUST equal the parent document's, so
    /// an attestation cannot be issued for a parent in a domain it does not claim.
    pub trust_domain: String,
    /// RFC 9278 thumbprint URI of the kernel key that signed this attestation.
    /// MUST equal the parent document's `kernel_key_thumbprint`: the party
    /// consenting must be the party that issued the parent.
    pub kernel_key_thumbprint: String,
    /// Raw Ed25519 signature over [`canonical_attestation_signing_bytes`]. Empty
    /// on an unsigned attestation.
    pub signature: Vec<u8>,
}

impl ConsentAttestation {
    /// Build an **unsigned** attestation. The parent's issuer signs its canonical
    /// bytes and attaches the result — see
    /// [`ReferenceIssuer::attest_delegation`](crate::issuer::ReferenceIssuer::attest_delegation),
    /// or [`ConsentAttestation::with_signature`] to attach one directly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_vaid: VaidId,
        child_vaid: VaidId,
        child_trust_domain: String,
        child_tenant_id: String,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
        trust_domain: String,
        kernel_key_thumbprint: String,
    ) -> Self {
        Self {
            att_version: ATTESTATION_VERSION,
            parent_vaid,
            child_vaid,
            child_trust_domain,
            child_tenant_id,
            scope_boundary,
            capability_set,
            trust_domain,
            kernel_key_thumbprint,
            signature: Vec::new(),
        }
    }

    /// Attach a signature. Consuming, to keep the object otherwise immutable.
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// The `(parent_vaid, child_vaid)` hop this attestation covers.
    pub fn hop(&self) -> (VaidId, VaidId) {
        (self.parent_vaid, self.child_vaid)
    }
}

/// The 32-byte signing digest of an attestation.
///
/// Same discipline as the VAID document: force `signature` to JSON `null`,
/// canonicalize per RFC 8785 (JCS), SHA-256.
pub fn canonical_attestation_signing_bytes(attestation: &ConsentAttestation) -> Vec<u8> {
    let mut value =
        serde_json::to_value(attestation).expect("ConsentAttestation must be serde-serializable");
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert("signature".to_string(), serde_json::Value::Null);
    }
    let canonical =
        serde_jcs::to_vec(&value).expect("RFC 8785 canonicalization of a valid Value cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher.finalize().to_vec()
}

/// Verify an attestation's **authenticity** against a kernel public key.
///
/// Checks, all of which must hold:
///
/// - the format discriminant is current ([`ATTESTATION_VERSION`]);
/// - `trust_domain` is well-formed;
/// - `kernel_key_thumbprint` **corresponds to** `kernel_public_key` — the same
///   key-commitment check the VAID document verifier makes, and for the same
///   reason: "verified under some key we hold" is a verdict nobody can audit;
/// - the Ed25519 signature is valid over the canonical bytes.
///
/// This answers only *is this attestation real*. Whether it applies to the hop in
/// front of you — whether it names the right parent and child, was signed by the
/// key that issued the parent, and covers the authority the child claims — is
/// checked by [`crate::chain::verify_chain_with`], because those questions need the
/// documents and this function does not have them.
///
/// A malformed key, a bad signature, or any tampered field is `false`, never an
/// error.
pub fn verify_attestation_authenticity(
    kernel_public_key: &[u8],
    attestation: &ConsentAttestation,
) -> bool {
    if attestation.att_version != ATTESTATION_VERSION {
        return false;
    }
    if !crate::issuer_identity::is_valid_trust_domain(&attestation.trust_domain) {
        return false;
    }
    if attestation.kernel_key_thumbprint
        != crate::issuer_identity::kernel_key_thumbprint(kernel_public_key)
    {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, kernel_public_key)
        .verify(
            &canonical_attestation_signing_bytes(attestation),
            &attestation.signature,
        )
        .is_ok()
}

/// The attestations a presenter supplies alongside a chain, indexed by the
/// `(parent_vaid, child_vaid)` hop they cover.
///
/// Lookup is by hop rather than by list scan, which is what makes a **replayed**
/// attestation structurally inert: an attestation minted for one delegation is
/// filed under that pair and is simply not found when a different pair is asked
/// for. It never has to be *rejected*, so there is no rejection path to get wrong.
#[derive(Debug, Clone, Default)]
pub struct AttestationBundle {
    attestations: std::collections::HashMap<(VaidId, VaidId), ConsentAttestation>,
}

impl AttestationBundle {
    /// Build from the presented attestations. A later attestation covering a hop
    /// already present replaces the earlier one; this grants nothing, because every
    /// attestation used is still authenticated against the key that issued the
    /// parent and still has to cover the authority the child claims.
    pub fn new(attestations: impl IntoIterator<Item = ConsentAttestation>) -> Self {
        Self {
            attestations: attestations.into_iter().map(|a| (a.hop(), a)).collect(),
        }
    }

    /// An empty bundle. Any cross-key hop fails closed against it.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The attestation covering this hop, if one was presented.
    pub fn get(&self, parent_vaid: &VaidId, child_vaid: &VaidId) -> Option<&ConsentAttestation> {
        self.attestations.get(&(*parent_vaid, *child_vaid))
    }

    /// Number of presented attestations.
    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    /// Whether nothing was presented.
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

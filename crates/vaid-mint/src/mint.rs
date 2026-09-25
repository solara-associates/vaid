//! The mint: issue a root VAID, and mint attenuated child VAIDs.
//!
//! [`MintService`] wraps an [`crate::issuer::VaidIssuer`] and an
//! [`crate::audit::AuditSink`]. Two entry points:
//!
//! - [`MintService::mint_root`] — mint a root (or operator) VAID. BYO-key with a
//!   verified proof-of-possession, or the generate-and-discard path.
//! - [`MintService::mint_child`] — **attenuated delegation**: an authenticated
//!   parent `P` mints a child `C` iff `C`'s tenant, lineage, scope, and
//!   capabilities are all within `P`'s, verified fail-closed BEFORE any key work
//!   or nonce consumption. `child ⊆ parent`, always.
//!
//! The attenuation predicates use the SINGLE scope/capability matchers on
//! [`crate::document::Vaid`] ([`Vaid::is_in_scope`] / [`Vaid::has_capability`]),
//! so mint-time containment and any runtime scope check cannot drift.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::json;

use vaid_pop::vaid_pop::verify_signed_payload;

use crate::audit::AuditSink;
use crate::authz::{AuthorizationGate, PermitAll};
use crate::document::{AgentClass, TenantId, Vaid};
use crate::error::{MintError, MintResult};
use crate::issuer::VaidIssuer;
use crate::mint_types::{MintPop, MintVaidRequest, MintVaidResponse, VaidSeed};

/// Freshness window for a mint proof-of-possession, in seconds. A PoP whose
/// `issued_at` is more than this from now (either direction) is rejected, so a
/// captured request is not mintable indefinitely.
pub const MINT_POP_FRESHNESS_SECS: i64 = 300;

/// Scope attenuation: is every entry of `child_scope` within `parent`'s scope?
/// Uses ONLY [`Vaid::is_in_scope`] — the single scope matcher.
///
/// The empty-child guard closes an escalation: an empty child scope means
/// *unrestricted* (⊤), so a naive `all()` over zero entries is vacuously true and
/// would mint an unrestricted child under a *restricted* parent — broader than
/// the parent. Fail closed: an empty child scope is permitted ONLY when the
/// parent is itself unrestricted (empty).
pub(crate) fn scope_attenuates(parent: &Vaid, child_scope: &[String]) -> bool {
    scope_attenuates_within(parent.scope_boundary(), child_scope)
}

/// The same predicate over a bare boundary rather than a document.
///
/// A consent attestation carries a `scope_boundary` that belongs to no document,
/// and the child's authority must be contained by it under EXACTLY this rule —
/// including the empty-child guard, which is the subtle half. Reimplementing the
/// rule for the detached case is how the guard would be lost in one of them.
///
/// Public because the attenuation half of `verdict_v1.json` is a predicate over
/// two bare boundaries and nothing else. The packaged firewall is a separate crate
/// from the library, so a `pub(crate)` predicate is one a `cargo install` consumer
/// cannot have checked — and the Python and TypeScript twins have both exported
/// their equivalent all along, so this also removes an asymmetry rather than
/// creating one.
pub fn scope_attenuates_within(parent_scope: &[String], child_scope: &[String]) -> bool {
    if child_scope.is_empty() {
        // Child wants ⊤; allowed only if the parent is also ⊤.
        parent_scope.is_empty()
    } else {
        child_scope
            .iter()
            .all(|s| crate::document::scope_contains(parent_scope, s))
    }
}

/// Tenant containment, as the **qualified pair** `(trust_domain, tenant_id)`.
/// Both components must match the parent's.
///
/// # Why the pair, and not `tenant_id` alone
///
/// `tenant_id` is not globally meaningful. It names a tenant *within an unnamed
/// deployment* and is namespaced by nothing: two self-hosters both minting
/// `tenant_id: "acme"` produce documents that are indistinguishable on that field
/// (ADR-0004). Comparing it alone is safe only while every document on a chain
/// came from one issuer — which is exactly the assumption that stops holding the
/// moment chains cross kernel keys. Qualifying it by `trust_domain` makes the
/// check mean the same thing in both worlds, so this does not need redoing later.
///
/// # What `trust_domain` is, and what it is therefore worth
///
/// **It is issuer-stamped, not holder-supplied.** It is not a field of
/// [`crate::mint_types::VaidSeed`]; the issuer holds it, validates it at
/// construction, and stamps it into every document it mints. It is inside the
/// canonical signing bytes, so it cannot be altered without breaking the kernel
/// signature.
///
/// **But it is self-asserted.** Nothing forces an issuer to stamp a domain it
/// actually controls, and neither `trust_domain` nor `kernel_key_thumbprint`
/// establishes attribution on its own — a self-signed document whose thumbprint
/// matches its own key is internally consistent and entirely unauthorized. The
/// binding from a trust domain to an authorized key set is out-of-band, static
/// and cached (ADR-0004, `docs/trust-anchor.md`).
///
/// **So state the guarantee honestly: this is defence against operator error, not
/// against a hostile issuer.** It catches a misconfigured or buggy mint that
/// delegates across a tenant boundary, and a chain assembled from documents that
/// were never meant to be in one chain. It does not constrain an issuer whose key
/// the verifier already trusts: such an issuer can stamp whatever pair it likes
/// and this check will pass. Only the out-of-band trust-domain-to-key binding
/// constrains that, and it lives outside this crate.
pub(crate) fn tenant_attenuates(
    parent: &Vaid,
    child_trust_domain: &str,
    child_tenant: &str,
) -> bool {
    parent.trust_domain() == child_trust_domain && parent.tenant_id().as_str() == child_tenant
}

/// Capability attenuation: is every entry of `child_caps` held by `parent`? Uses
/// ONLY [`Vaid::has_capability`] (exact membership).
///
/// No empty-child guard is needed (and deliberately none is added): capabilities
/// are explicit grants where empty = ∅ (least privilege), so an empty child set
/// is safe by construction; and an empty *parent* set holds nothing, so every
/// requested child capability is rejected. This is the deliberate scope/caps
/// asymmetry — scope empty = ⊤ needs a guard, caps empty = ∅ does not.
pub(crate) fn caps_attenuate(parent: &Vaid, child_caps: &[String]) -> bool {
    caps_attenuate_within(parent.capability_set(), child_caps)
}

/// The same predicate over a bare capability set rather than a document — the
/// attestation counterpart of [`scope_attenuates_within`].
pub(crate) fn caps_attenuate_within(parent_caps: &[String], child_caps: &[String]) -> bool {
    child_caps
        .iter()
        .all(|c| crate::document::caps_contain(parent_caps, c))
}

/// Does `child_expires_at` fall at or before `parent`'s `expires_at`?
///
/// The fifth containment property, and the one vaid#79 found missing: a child's
/// authority is derived from its parent's, and authority that outlives the
/// authority it came from was never contained by it. AAT I3 (TTL monotonicity),
/// `draft-niyikiza-oauth-attenuating-agent-tokens-01` §4.4.
///
/// **One matcher, two call sites**, exactly as [`scope_attenuates`] and
/// [`caps_attenuate`] are: [`MintService::mint_child`] refuses a delegation this
/// rejects, and [`verify_chain_at`](crate::chain::verify_chain_at) refuses a
/// presented hop it rejects. A second implementation of the rule is how the two
/// would drift apart.
///
/// **Equality is allowed.** A child expiring at exactly its parent's `expires_at`
/// holds authority for no instant in which the parent holds none.
///
/// **Fails closed.** An unreadable or absent expiry on either side is not
/// containment — the same rule [`Vaid::is_expired`] states for standing.
///
/// The comparison is over PARSED instants, never over the strings: a presented
/// timestamp may be in any valid RFC 3339 form (ADR-0006), and two spellings of
/// the same instant do not compare as text.
pub(crate) fn expiry_attenuates(parent: &Vaid, child_expires_at: Option<&str>) -> bool {
    expiry_attenuates_within(parent.expires_at_as_presented(), child_expires_at)
}

/// The same predicate over bare timestamps rather than documents — the form the
/// mint needs, where the child's document does not exist yet and its expiry is
/// only the instant the issuer says it would stamp.
pub fn expiry_attenuates_within(parent_expires_at: &str, child_expires_at: Option<&str>) -> bool {
    match (
        crate::document::parse_rfc3339(parent_expires_at),
        child_expires_at.and_then(crate::document::parse_rfc3339),
    ) {
        (Some(parent), Some(child)) => child <= parent,
        _ => false,
    }
}

/// The mint service. Holds the issuer (kernel signer) and the audit sink, plus
/// the single-use PoP nonce set (at-mint replay defense).
pub struct MintService {
    issuer: Arc<dyn VaidIssuer>,
    audit: Arc<dyn AuditSink>,
    /// Root-mint authorization seam. Defaults to [`PermitAll`] — a
    /// reference-implementation choice, NOT a security recommendation. See
    /// [`crate::authz`].
    authz: Arc<dyn AuthorizationGate>,
    consumed_pop_nonces: Mutex<HashSet<String>>,
}

impl MintService {
    /// Construct with the default root-mint authorization gate ([`PermitAll`]).
    /// Convenience for tests and local self-hosting; a production deployment
    /// should use [`MintService::with_authorization`] to supply a real gate.
    pub fn new(issuer: Arc<dyn VaidIssuer>, audit: Arc<dyn AuditSink>) -> Self {
        Self::with_authorization(issuer, audit, Arc::new(PermitAll))
    }

    /// Construct with an explicit root-mint [`AuthorizationGate`]. This is the
    /// seam that closes the "mint_root has no authorization" gap visibly rather
    /// than silently.
    pub fn with_authorization(
        issuer: Arc<dyn VaidIssuer>,
        audit: Arc<dyn AuditSink>,
        authz: Arc<dyn AuthorizationGate>,
    ) -> Self {
        Self {
            issuer,
            audit,
            authz,
            consumed_pop_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Proof-of-possession at mint. Verifies the caller controls the private key
    /// matching `registered_key` before the VAID is issued. Order:
    ///
    /// 1. **present** — a BYO-key mint without a `pop` is rejected;
    /// 2. **fresh** — `issued_at` within [`MINT_POP_FRESHNESS_SECS`] of now;
    /// 3. **not replayed** — single-use nonce, recorded before the signature is
    ///    accepted (record-before-process) so a concurrent replay cannot slip in;
    /// 4. **signature** — the holder's signature over the canonical
    ///    [`crate::mint_types::MintPopPayload`] verifies against `registered_key`.
    ///
    /// The holder's private key never enters mint state — only the public key and
    /// the detached signature.
    fn verify_pop_at_mint(
        &self,
        seed: &VaidSeed,
        registered_key: &[u8],
        pop: Option<&MintPop>,
    ) -> MintResult<()> {
        let pop = pop.ok_or_else(|| {
            MintError::Identity(
                "proof-of-possession required — public_key_der was supplied \
                 (BYO-key) without a `pop` signature"
                    .into(),
            )
        })?;

        // (2) Freshness.
        let skew = (Utc::now() - pop.issued_at).num_seconds().abs();
        if skew > MINT_POP_FRESHNESS_SECS {
            return Err(MintError::Identity(format!(
                "PoP timestamp outside freshness window ({skew}s > {MINT_POP_FRESHNESS_SECS}s)"
            )));
        }

        // (3) Replay — atomic check-and-insert. `insert` returns false if the
        // nonce was already present. Record before accepting the signature.
        {
            let mut nonces = self
                .consumed_pop_nonces
                .lock()
                .expect("nonce lock not poisoned");
            if !nonces.insert(pop.nonce.clone()) {
                return Err(MintError::Identity(
                    "PoP nonce already used — replay rejected".into(),
                ));
            }
        }

        // (4) Signature over the canonical payload, against the REGISTERED key.
        let payload = seed.pop_payload(registered_key.to_vec(), pop.nonce.clone(), pop.issued_at);
        if !verify_signed_payload(&payload, registered_key, &pop.signature) {
            return Err(MintError::Identity(
                "PoP signature does not verify against the registered public key — \
                 cannot register a key you do not control"
                    .into(),
            ));
        }

        Ok(())
    }

    /// Mint a root (or operator) VAID. The root-mint [`AuthorizationGate`] is
    /// consulted first (defaults to [`PermitAll`]); then, when
    /// `seed.public_key_der` is `Some`, this is a BYO-key mint and a valid
    /// [`MintPop`] is required; otherwise the issuer generates a keypair and
    /// discards the private half.
    pub async fn mint_root(&self, request: MintVaidRequest) -> MintResult<MintVaidResponse> {
        let seed = request.seed;

        // Root-mint authorization seam (defaults to PermitAll). Runs first, before
        // any key work or nonce consumption, so a denied mint has no side effects.
        self.authz.authorize_root_mint(&seed).await?;

        let byo_key = seed.public_key_der.is_some();

        let vaid = if let Some(ref key) = seed.public_key_der {
            // BYO-key: prove possession of the matching private key before issue.
            self.verify_pop_at_mint(&seed, key, request.pop.as_ref())?;
            self.issuer.issue_vaid_with_key(
                AgentClass::new(&seed.agent_class),
                seed.version.clone(),
                TenantId::new(&seed.tenant_id),
                seed.parent_vaid,
                seed.scope_boundary.clone(),
                seed.capability_set.clone(),
                key.clone(),
                None, // a root has no parent to be contained by
            )?
        } else {
            // Generate-and-discard: no holder key registered, so no PoP applies.
            self.issuer.issue_vaid_with_lineage(
                AgentClass::new(&seed.agent_class),
                seed.version.clone(),
                TenantId::new(&seed.tenant_id),
                seed.parent_vaid,
                seed.scope_boundary.clone(),
                seed.capability_set.clone(),
                None, // a root has no parent to be contained by
            )?
        };

        self.audit
            .record(
                "vaid_minted",
                json!({
                    "agent_class": seed.agent_class,
                    "version": seed.version,
                    "tenant_id": seed.tenant_id,
                    "parent_vaid": seed.parent_vaid,
                    "scope_boundary": seed.scope_boundary,
                    "capability_set_len": seed.capability_set.len(),
                    "byo_key": byo_key,
                    "pop_verified": byo_key,
                    "delegated": false,
                }),
            )
            .await?;

        Ok(MintVaidResponse {
            vaid,
            // A root has no parent to be bounded by, so its TTL is the issuer's alone.
            expiry_bounded_by_parent: false,
            parent_expires_at: None,
        })
    }

    /// Attenuated intra-tenant delegation. An authenticated parent VAID `P` mints
    /// a child `C` iff — checked fail-closed BEFORE any key work or nonce
    /// consumption — every condition holds:
    ///
    /// 1. **parent present** — a verified parent travelled in context; absent → deny;
    /// 2. `C.tenant == P.tenant` — same tenant, from the VERIFIED parent, never the body;
    /// 3. `C.parent_vaid == Some(P.vaid_id)` — lineage bound to the authenticated parent;
    /// 4. `C.scope ⊆ P.scope` — `scope_attenuates`;
    /// 5. `C.caps ⊆ P.caps` — `caps_attenuate`; and (check 5a) the parent is
    ///    **not already expired** — its expiry is the ceiling the child is clamped
    ///    to at step 7, and a ceiling in the past bounds nothing;
    /// 6. child **BYO-key PoP** holds — `mint_child` is always BYO-key.
    ///
    /// Attenuation (2–5) runs BEFORE the PoP so a rejected delegation never
    /// consumes a nonce. The child is issued with `parent_vaid` set (the issuer
    /// records lineage), and a *delegated* audit entry is emitted.
    pub async fn mint_child(
        &self,
        request: MintVaidRequest,
        parent: Option<&Vaid>,
    ) -> MintResult<MintVaidResponse> {
        // (1) The parent's authority must have travelled — fail closed.
        let parent = parent.ok_or_else(|| {
            MintError::Unauthorized(
                "no verified parent VAID in context — delegation requires an \
                 authenticated parent principal, fail-closed"
                    .into(),
            )
        })?;
        let seed = &request.seed;

        // (2) Same tenant, grounded in the parent's VERIFIED VAID — never the body.
        //
        // Shares `tenant_attenuates` with verify-time chain walking, so the two
        // cannot drift. The `trust_domain` component is passed as the parent's
        // own: at mint time the child's document does not exist yet, and the
        // domain it will carry is this issuer's, so that component is trivially
        // satisfied here and the only free variable is the tenant. Behaviour is
        // unchanged from the inline comparison this replaces — the pair does real
        // work at verify time, where both documents are already built and may not
        // share an issuer.
        if !tenant_attenuates(parent, parent.trust_domain(), &seed.tenant_id) {
            return Err(MintError::Unauthorized(format!(
                "child tenant '{}' != authenticated parent tenant '{}' — \
                 cross-tenant delegation is denied",
                seed.tenant_id,
                parent.tenant_id().as_str()
            )));
        }

        // (3) Lineage bound to the AUTHENTICATED parent, not a claimed field.
        if seed.parent_vaid != Some(parent.vaid_id()) {
            return Err(MintError::Unauthorized(format!(
                "child parent_vaid {:?} must equal the authenticated parent vaid_id {} — \
                 the parent comes from the verified VAID, never the body",
                seed.parent_vaid,
                parent.vaid_id()
            )));
        }

        // (4) Scope attenuation — single `is_in_scope`, empty-child guard.
        if !scope_attenuates(parent, &seed.scope_boundary) {
            return Err(MintError::Unauthorized(
                "child scope_boundary exceeds the parent's — least-privilege \
                 attenuation denied"
                    .into(),
            ));
        }

        // (5) Capability attenuation — single `has_capability`.
        if !caps_attenuate(parent, &seed.capability_set) {
            return Err(MintError::Unauthorized(
                "child capability_set exceeds the parent's — least-privilege \
                 attenuation denied"
                    .into(),
            ));
        }

        // (5a) The parent must still be alive (vaid#79).
        //
        // The child's expiry is CLAMPED to the parent's at issuance (step 7), so a
        // delegation can never produce a child that outlives its parent and no
        // working delegation is refused for a TTL the caller did not choose. The one
        // case a clamp cannot answer is a parent that has already expired: the
        // clamp's own ceiling is in the past, so the child would be issued
        // dead-on-arrival. That is refused instead, HERE — with (4) and (5) and
        // before the PoP, so the refusal burns no nonce.
        //
        // An unreadable expiry is expired (`is_expired` is total and fails closed),
        // so a parent whose expiry cannot be read is refused by the same line.
        if parent.is_expired() {
            return Err(MintError::Unauthorized(format!(
                "authenticated parent {} expired at '{}' — a child may not outlive \
                 the authority it derives from, and a child of a dead parent would \
                 be issued already expired. Renew the parent, then delegate",
                parent.vaid_id(),
                parent.expires_at_as_presented()
            )));
        }

        // (6) Child BYO-key PoP. Runs AFTER attenuation: an unauthorized
        // delegation must not burn a nonce. mint_child is always BYO-key.
        let key = seed.public_key_der.as_ref().ok_or_else(|| {
            MintError::Identity(
                "BYO-key required — a delegated child registers the parent-held \
                 child public key with a proof-of-possession"
                    .into(),
            )
        })?;
        self.verify_pop_at_mint(seed, key, request.pop.as_ref())?;

        // (7) Issue the attenuated child. parent_vaid is Some → lineage recorded.
        // The parent's expiry is passed as a ceiling: the child ends at the earlier
        // of that and the issuer's own TTL.
        let vaid = self.issuer.issue_vaid_with_key(
            AgentClass::new(&seed.agent_class),
            seed.version.clone(),
            TenantId::new(&seed.tenant_id),
            seed.parent_vaid,
            seed.scope_boundary.clone(),
            seed.capability_set.clone(),
            key.clone(),
            Some(parent.expires_at_as_presented()),
        )?;

        // (7a) ...and CHECK what came back. The ceiling above is an instruction to
        // the issuer; this is the property. An issuer is a seam a deployment
        // supplies, and one that ignores `not_after` — a third-party implementation
        // written before this rule existed, or one that simply gets it wrong — would
        // emit a child outliving its parent that nothing downstream could
        // distinguish from a legitimate one. The same matcher the chain verifier
        // refuses on is applied to the document actually issued, so the mint never
        // hands out a document its own verifier would reject.
        //
        // This one refusal DOES consume the nonce, unavoidably: the PoP has already
        // been spent by the time a document exists to check. That is the right trade
        // — it fires only for a broken issuer, never for a caller's mistake.
        if !expiry_attenuates(parent, Some(vaid.expires_at_as_presented())) {
            return Err(MintError::Unauthorized(format!(
                "issuer returned a child expiring '{}', after the parent's '{}', \
                 despite a not_after ceiling — the issuer does not honour expiry \
                 containment and the child has not been returned",
                vaid.expires_at_as_presented(),
                parent.expires_at_as_presented()
            )));
        }

        // (8) Was the child's life cut short by its parent's, rather than by this
        // issuer's TTL? Computed from the two documents rather than reported by the
        // issuer: the issuer returns a `Vaid` and nothing else, and reading the
        // SIGNED bytes is the stronger statement anyway — it describes the document
        // the caller is actually holding, not the issuer's intent.
        //
        // The one inexact case is a tie: an issuer whose TTL lands exactly on the
        // parent's expiry sets this true although nothing was taken away. The field
        // is named for what is literally true of the document — the child's expiry
        // IS the parent's bound — rather than for the issuer's arithmetic, so the
        // tie is still an accurate statement.
        let expiry_bounded_by_parent =
            vaid.expires_at_as_presented() == parent.expires_at_as_presented();

        // (9) Delegated audit — distinguishes the delegation tree from root mints,
        // and records the shortening, so a caller that ignored the response can
        // still find out from the audit trail why a credential was short-lived.
        self.audit
            .record(
                "vaid_minted",
                json!({
                    "agent_class": seed.agent_class,
                    "version": seed.version,
                    "parent_vaid": seed.parent_vaid,
                    "scope_boundary": seed.scope_boundary,
                    "capability_set_len": seed.capability_set.len(),
                    "byo_key": true,
                    "pop_verified": true,
                    "delegated": true,
                    "attenuation_verified": true,
                    "parent_tenant": parent.tenant_id().as_str(),
                    "expiry_bounded_by_parent": expiry_bounded_by_parent,
                    "expires_at": vaid.expires_at_as_presented(),
                    "parent_expires_at": parent.expires_at_as_presented(),
                }),
            )
            .await?;

        Ok(MintVaidResponse {
            vaid,
            expiry_bounded_by_parent,
            parent_expires_at: Some(parent.expires_at_as_presented().to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use vaid_pop::vaid_pop::sign_payload;

    use crate::audit::InMemoryAudit;
    use crate::document::{AgentId, VaidId};
    use crate::issuer::ReferenceIssuer;

    fn fixture() -> (MintService, Arc<InMemoryAudit>) {
        let audit = Arc::new(InMemoryAudit::new());
        let issuer = Arc::new(ReferenceIssuer::ephemeral(1, "vaid.example").unwrap());
        let svc = MintService::new(issuer, audit.clone());
        (svc, audit)
    }

    // ── PoP helpers: stand up a real holder keypair and produce a valid PoP. ──

    fn holder_keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn pubkey(kp: &Ed25519KeyPair) -> Vec<u8> {
        kp.public_key().as_ref().to_vec()
    }

    fn byo_seed(public_key_der: Vec<u8>) -> VaidSeed {
        VaidSeed {
            agent_class: "runner".into(),
            version: "1.0.0".into(),
            tenant_id: "acme".into(),
            parent_vaid: None,
            scope_boundary: vec!["data.x".into()],
            capability_set: vec!["read".into()],
            public_key_der: Some(public_key_der),
        }
    }

    fn make_pop(
        seed: &VaidSeed,
        registered_key: &[u8],
        signing_key: &Ed25519KeyPair,
        nonce: &str,
        issued_at: chrono::DateTime<Utc>,
    ) -> MintPop {
        let payload = seed.pop_payload(registered_key.to_vec(), nonce.into(), issued_at);
        MintPop {
            nonce: nonce.into(),
            issued_at,
            signature: sign_payload(&payload, signing_key),
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // mint_root
    // ════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn root_generate_and_discard_mints_and_audits() {
        let (svc, audit) = fixture();
        let req = MintVaidRequest {
            seed: VaidSeed {
                agent_class: "researcher".into(),
                version: "1.0.0".into(),
                tenant_id: "acme".into(),
                parent_vaid: None,
                scope_boundary: vec!["data.governance".into()],
                capability_set: vec!["read.documents".into()],
                public_key_der: None,
            },
            pop: None,
        };
        let resp = svc.mint_root(req).await.unwrap();
        assert_eq!(resp.vaid.agent_class().as_str(), "researcher");
        assert_eq!(resp.vaid.scope_boundary(), &["data.governance"]);
        assert_eq!(resp.vaid.parent_vaid(), None);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit.entries()[0].event_type, "vaid_minted");
        assert_eq!(audit.entries()[0].details["delegated"], json!(false));
    }

    #[tokio::test]
    async fn root_mint_denied_by_authorization_gate_has_no_side_effects() {
        use crate::authz::AuthorizationGate;

        // A gate that denies every root mint. Proves the seam is real: the mint
        // is rejected before any issuance or audit.
        struct DenyAll;
        #[async_trait::async_trait]
        impl AuthorizationGate for DenyAll {
            async fn authorize_root_mint(&self, _seed: &VaidSeed) -> MintResult<()> {
                Err(MintError::Unauthorized("root mint denied by gate".into()))
            }
        }

        let audit = Arc::new(InMemoryAudit::new());
        let issuer = Arc::new(ReferenceIssuer::ephemeral(1, "vaid.example").unwrap());
        let svc = MintService::with_authorization(issuer, audit.clone(), Arc::new(DenyAll));

        let req = MintVaidRequest {
            seed: VaidSeed {
                agent_class: "researcher".into(),
                version: "1.0.0".into(),
                tenant_id: "acme".into(),
                parent_vaid: None,
                scope_boundary: vec![],
                capability_set: vec![],
                public_key_der: None,
            },
            pop: None,
        };
        let err = svc.mint_root(req).await.unwrap_err();
        assert!(err.to_string().contains("denied by gate"), "got: {err}");
        assert!(audit.is_empty(), "a gate-denied root mint must not audit");
    }

    #[tokio::test]
    async fn root_byo_key_with_valid_pop_binds_key() {
        let (svc, audit) = fixture();
        let kp = holder_keypair();
        let registered = pubkey(&kp);
        let seed = byo_seed(registered.clone());
        let pop = make_pop(&seed, &registered, &kp, "nonce-aaa", Utc::now());

        let resp = svc
            .mint_root(MintVaidRequest {
                seed,
                pop: Some(pop),
            })
            .await
            .unwrap();
        assert_eq!(resp.vaid.public_key_der(), registered.as_slice());
        assert_eq!(audit.entries()[0].details["byo_key"], json!(true));
        assert_eq!(audit.entries()[0].details["pop_verified"], json!(true));
    }

    #[tokio::test]
    async fn root_byo_key_with_pop_for_different_key_is_rejected() {
        // THE CORE ATTACK: register a key you do not control, sign with your own.
        let (svc, audit) = fixture();
        let victim = holder_keypair();
        let attacker = holder_keypair();
        let victim_pub = pubkey(&victim);
        let seed = byo_seed(victim_pub.clone());
        let pop = make_pop(&seed, &victim_pub, &attacker, "nonce-bbb", Utc::now());

        let err = svc
            .mint_root(MintVaidRequest {
                seed,
                pop: Some(pop),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not verify"), "got: {err}");
        assert!(audit.is_empty(), "no VAID minted → no audit");
    }

    #[tokio::test]
    async fn root_byo_key_without_pop_is_rejected() {
        let (svc, _) = fixture();
        let seed = byo_seed(pubkey(&holder_keypair()));
        let err = svc
            .mint_root(MintVaidRequest { seed, pop: None })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("proof-of-possession required"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn root_byo_key_replay_is_rejected() {
        let (svc, _) = fixture();
        let kp = holder_keypair();
        let registered = pubkey(&kp);
        let seed = byo_seed(registered.clone());
        let pop = make_pop(&seed, &registered, &kp, "nonce-replay", Utc::now());

        let first = svc
            .mint_root(MintVaidRequest {
                seed: seed.clone(),
                pop: Some(pop.clone()),
            })
            .await;
        assert!(first.is_ok());
        let replay = svc
            .mint_root(MintVaidRequest {
                seed,
                pop: Some(pop),
            })
            .await;
        assert!(replay.unwrap_err().to_string().contains("replay"));
    }

    #[tokio::test]
    async fn root_byo_key_stale_pop_is_rejected() {
        let (svc, _) = fixture();
        let kp = holder_keypair();
        let registered = pubkey(&kp);
        let seed = byo_seed(registered.clone());
        let stale = Utc::now() - chrono::Duration::seconds(MINT_POP_FRESHNESS_SECS + 60);
        let pop = make_pop(&seed, &registered, &kp, "nonce-stale", stale);
        let err = svc
            .mint_root(MintVaidRequest {
                seed,
                pop: Some(pop),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("freshness window"), "got: {err}");
    }

    // ════════════════════════════════════════════════════════════════════
    // mint_child — attenuated delegation
    // ════════════════════════════════════════════════════════════════════

    fn parent_doc(tenant: &str, scope: Vec<&str>, caps: Vec<&str>) -> Vaid {
        Vaid::with_lineage(
            AgentId::new(),
            AgentClass::new("parent"),
            "1.0.0".into(),
            TenantId::new(tenant),
            Utc::now(),
            Utc::now() + chrono::Duration::hours(1),
            vec![],
            vec![],
            None,
            scope.into_iter().map(String::from).collect(),
            "lineage".into(),
            caps.into_iter().map(String::from).collect(),
            "vaid.example".into(),
            crate::issuer_identity::kernel_key_thumbprint(&[0u8; 32]),
        )
    }

    fn child_seed(
        parent: &Vaid,
        scope: Vec<&str>,
        caps: Vec<&str>,
        child_pub: Vec<u8>,
    ) -> VaidSeed {
        VaidSeed {
            agent_class: "child".into(),
            version: "1.0.0".into(),
            tenant_id: parent.tenant_id().as_str().to_string(),
            parent_vaid: Some(parent.vaid_id()),
            scope_boundary: scope.into_iter().map(String::from).collect(),
            capability_set: caps.into_iter().map(String::from).collect(),
            public_key_der: Some(child_pub),
        }
    }

    fn signed_child(
        parent: &Vaid,
        scope: Vec<&str>,
        caps: Vec<&str>,
        nonce: &str,
    ) -> MintVaidRequest {
        let kp = holder_keypair();
        let pubk = pubkey(&kp);
        let seed = child_seed(parent, scope, caps, pubk.clone());
        let pop = make_pop(&seed, &pubk, &kp, nonce, Utc::now());
        MintVaidRequest {
            seed,
            pop: Some(pop),
        }
    }

    #[tokio::test]
    async fn child_within_bounds_is_minted_with_lineage_and_delegated_audit() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read", "write"]);
        let req = signed_child(&parent, vec!["data.aifactory.sub"], vec!["read"], "ok-1");

        let resp = svc.mint_child(req, Some(&parent)).await.unwrap();
        assert_eq!(
            resp.vaid.parent_vaid(),
            Some(parent.vaid_id()),
            "lineage bound"
        );
        assert_eq!(audit.entries()[0].details["delegated"], json!(true));
        assert_eq!(
            audit.entries()[0].details["attenuation_verified"],
            json!(true)
        );
    }

    #[tokio::test]
    async fn child_scope_exceeding_parent_is_denied() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(
            &parent,
            vec!["data.somewhere-else"],
            vec!["read"],
            "deny-scope",
        );
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(
            err.to_string().contains("scope_boundary exceeds"),
            "got: {err}"
        );
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn empty_child_scope_under_restricted_parent_is_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(&parent, vec![], vec!["read"], "deny-empty-scope");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(
            err.to_string().contains("scope_boundary exceeds"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn empty_parent_scope_permits_any_child_scope() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec![], vec!["read"]);
        let req1 = signed_child(&parent, vec!["data.anything"], vec!["read"], "u-1");
        assert!(svc.mint_child(req1, Some(&parent)).await.is_ok());
        let req2 = signed_child(&parent, vec![], vec!["read"], "u-2");
        assert!(svc.mint_child(req2, Some(&parent)).await.is_ok());
    }

    #[tokio::test]
    async fn child_caps_exceeding_parent_are_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(
            &parent,
            vec!["data.aifactory.sub"],
            vec!["read", "write"],
            "deny-caps",
        );
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(
            err.to_string().contains("capability_set exceeds"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn empty_parent_caps_may_delegate_nothing_but_empty_child_caps_ok() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec![], vec![]);
        let deny = signed_child(&parent, vec![], vec!["read"], "caps-deny");
        assert!(svc
            .mint_child(deny, Some(&parent))
            .await
            .unwrap_err()
            .to_string()
            .contains("capability_set exceeds"));
        let ok = signed_child(&parent, vec![], vec![], "caps-ok");
        assert!(svc.mint_child(ok, Some(&parent)).await.is_ok());
    }

    #[tokio::test]
    async fn cross_tenant_child_is_denied() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let kp = holder_keypair();
        let pubk = pubkey(&kp);
        let mut seed = child_seed(
            &parent,
            vec!["data.aifactory.sub"],
            vec!["read"],
            pubk.clone(),
        );
        seed.tenant_id = "acme".into(); // forge a foreign tenant
        let pop = make_pop(&seed, &pubk, &kp, "forge-tenant", Utc::now());
        let err = svc
            .mint_child(
                MintVaidRequest {
                    seed,
                    pop: Some(pop),
                },
                Some(&parent),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cross-tenant delegation is denied"),
            "got: {err}"
        );
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn child_claiming_a_different_parent_vaid_is_denied() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let kp = holder_keypair();
        let pubk = pubkey(&kp);
        let mut seed = child_seed(
            &parent,
            vec!["data.aifactory.sub"],
            vec!["read"],
            pubk.clone(),
        );
        seed.parent_vaid = Some(VaidId::new()); // forge a different parent
        let pop = make_pop(&seed, &pubk, &kp, "forge-parent", Utc::now());
        let err = svc
            .mint_child(
                MintVaidRequest {
                    seed,
                    pop: Some(pop),
                },
                Some(&parent),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("parent_vaid"), "got: {err}");
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn mint_child_without_parent_context_is_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(
            &parent,
            vec!["data.aifactory.sub"],
            vec!["read"],
            "no-parent",
        );
        let err = svc.mint_child(req, None).await.unwrap_err();
        assert!(
            err.to_string().contains("no verified parent VAID"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn mint_child_without_byo_key_is_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let mut seed = child_seed(&parent, vec!["data.aifactory.sub"], vec!["read"], vec![]);
        seed.public_key_der = None;
        let err = svc
            .mint_child(MintVaidRequest { seed, pop: None }, Some(&parent))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BYO-key required"), "got: {err}");
    }

    #[tokio::test]
    async fn rejected_attenuation_does_not_consume_the_pop_nonce() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        // Scope-exceeding request using nonce "N" → denied at attenuation, BEFORE
        // the nonce insert.
        let denied = signed_child(&parent, vec!["data.elsewhere"], vec!["read"], "N");
        assert!(svc.mint_child(denied, Some(&parent)).await.is_err());
        // A VALID request reusing the SAME nonce "N" now succeeds — proving "N"
        // was never consumed by the denied call.
        let ok = signed_child(&parent, vec!["data.aifactory.sub"], vec!["read"], "N");
        assert!(
            svc.mint_child(ok, Some(&parent)).await.is_ok(),
            "nonce must survive an attenuation rejection (attenuation precedes nonce insert)"
        );
    }

    // ── end-to-end: a child minted through the real issuer verifies against it,
    //    and its scope/caps are within the parent's (the containment property). ──
    #[tokio::test]
    async fn minted_child_verifies_and_is_contained_by_parent() {
        let audit = Arc::new(InMemoryAudit::new());
        // `assuming_nothing_revoked()` because this test is about attenuation and
        // scope containment. Since 0.9.0 a bare issuer's revocation store is absent,
        // so `verify_vaid` would fail closed on `Unavailable` regardless of what the
        // child's scope says — a rejection for the wrong reason.
        let issuer = Arc::new(
            ReferenceIssuer::ephemeral(1, "vaid.example")
                .unwrap()
                .assuming_nothing_revoked(),
        );
        let svc = MintService::new(issuer.clone(), audit);
        // Mint a REAL parent root through the issuer, so its lineage is recorded and
        // the child's ancestry is resolvable at verification (R.4.2). A synthetic
        // parent never minted here would — correctly — leave the child's lineage
        // incomplete and fail closed.
        let parent = svc
            .mint_root(MintVaidRequest {
                seed: VaidSeed {
                    agent_class: "parent".into(),
                    version: "1.0.0".into(),
                    tenant_id: "aifactory".into(),
                    parent_vaid: None,
                    scope_boundary: vec!["data.aifactory".into()],
                    capability_set: vec!["read".into(), "write".into()],
                    public_key_der: None,
                },
                pop: None,
            })
            .await
            .unwrap()
            .vaid;
        let req = signed_child(&parent, vec!["data.aifactory.reports"], vec!["read"], "e2e");
        let child = svc.mint_child(req, Some(&parent)).await.unwrap().vaid;

        assert!(
            issuer.verify_vaid(&child),
            "minted child must verify against the issuer"
        );
        // Containment: every child scope entry is within the parent, every child
        // cap is held by the parent.
        assert!(child.scope_boundary().iter().all(|s| parent.is_in_scope(s)));
        assert!(child
            .capability_set()
            .iter()
            .all(|c| parent.has_capability(c)));
    }

    // ── expiry containment at mint (vaid#79) ──

    /// A parent whose expiry sits `seconds` either side of now. Anchored to the
    /// clock rather than to a hard-coded date, because a hard-coded date is how the
    /// Python twin's parent fixture quietly became an expired parent.
    fn parent_expiring_in(seconds: i64) -> Vaid {
        use chrono::SubsecRound;
        let expires = (Utc::now() + chrono::Duration::seconds(seconds)).trunc_subsecs(0);
        Vaid::with_lineage(
            AgentId::new(),
            AgentClass::new("parent"),
            "1.0.0".into(),
            TenantId::new("acme"),
            Utc::now() - chrono::Duration::hours(1),
            expires,
            vec![],
            vec![],
            None,
            vec!["data.x".into()],
            "lineage".into(),
            vec!["read".into()],
            "vaid.example".into(),
            crate::issuer_identity::kernel_key_thumbprint(&[0u8; 32]),
        )
    }

    /// The mint half of vaid#79. The issuer's TTL is an hour; the parent has ten
    /// minutes left; the child gets the parent's expiry, not the issuer's.
    #[tokio::test]
    async fn child_is_clamped_to_its_parents_expiry() {
        let (svc, _) = fixture(); // ReferenceIssuer::ephemeral(1, ..) — a 1-hour TTL
        let parent = parent_expiring_in(600);

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "clamp-1");
        let child = svc.mint_child(req, Some(&parent)).await.unwrap().vaid;

        assert_eq!(
            child.expires_at_as_presented(),
            parent.expires_at_as_presented(),
            "the child must end exactly when its parent does, not an hour later"
        );
    }

    /// THE CONTROL on the clamp. A clamp that always returned the parent's expiry
    /// would pass the test above and would be wrong: the issuer's own TTL still
    /// binds when it is the shorter of the two.
    #[tokio::test]
    async fn child_keeps_the_issuer_ttl_when_it_is_the_earlier_bound() {
        let (svc, _) = fixture();
        let parent = parent_expiring_in(86_400); // a day out; the issuer's TTL is an hour

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "clamp-2");
        let child = svc.mint_child(req, Some(&parent)).await.unwrap().vaid;

        assert!(
            child.expires_at().unwrap() < parent.expires_at().unwrap(),
            "the issuer's TTL is the earlier bound here and must still apply"
        );
    }

    /// The regression this policy exists for. Under a refuse-instead-of-clamp rule,
    /// ONE issuer with ONE TTL could only delegate inside the same whole second as
    /// the parent's mint: `expires = now + ttl` is re-evaluated at every mint, so a
    /// child minted a second later outlived its parent and was refused. Measured,
    /// not assumed — this test sleeps past a second boundary.
    #[tokio::test]
    async fn delegation_works_across_a_second_boundary() {
        let (svc, _) = fixture();
        let parent = svc
            .mint_root(MintVaidRequest {
                seed: VaidSeed {
                    agent_class: "parent".into(),
                    version: "1.0.0".into(),
                    tenant_id: "acme".into(),
                    parent_vaid: None,
                    scope_boundary: vec!["data.x".into()],
                    capability_set: vec!["read".into()],
                    public_key_der: None,
                },
                pop: None,
            })
            .await
            .unwrap()
            .vaid;

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "boundary");
        let child = svc.mint_child(req, Some(&parent)).await.unwrap().vaid;

        assert!(child.expires_at().unwrap() <= parent.expires_at().unwrap());
    }

    /// The one case a clamp cannot answer: the ceiling is in the past, so the child
    /// would be issued dead. Refused before the PoP, with the expiry named.
    #[tokio::test]
    async fn delegating_from_an_already_expired_parent_is_refused() {
        let (svc, _) = fixture();
        let parent = parent_expiring_in(-60);

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "dead-parent");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();

        let message = format!("{err}");
        assert!(
            message.contains(parent.expires_at_as_presented()),
            "the refusal must name the parent's expiry: {message}"
        );
        assert!(message.contains("expired"), "{message}");
    }

    /// Fail closed: an expiry that cannot be read is expired, so it is refused by
    /// the same line rather than clamped to a ceiling nobody can evaluate.
    #[tokio::test]
    async fn an_unreadable_parent_expiry_refuses_the_delegation() {
        let (svc, _) = fixture();
        let parent = Vaid::with_lineage(
            AgentId::new(),
            AgentClass::new("parent"),
            "1.0.0".into(),
            TenantId::new("acme"),
            Utc::now(),
            Utc::now() + chrono::Duration::hours(1),
            vec![],
            vec![],
            None,
            vec!["data.x".into()],
            "lineage".into(),
            vec!["read".into()],
            "vaid.example".into(),
            crate::issuer_identity::kernel_key_thumbprint(&[0u8; 32]),
        );
        // Rewrite the presented expiry to something unreadable, exactly as a
        // presenter could (ADR-0006: the verifier canonicalizes what it is given).
        let mut json = serde_json::to_value(&parent).unwrap();
        json["expires_at"] = serde_json::Value::String("whenever".into());
        let parent: Vaid = serde_json::from_value(json).unwrap();

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "unreadable");
        assert!(svc.mint_child(req, Some(&parent)).await.is_err());
    }

    /// The refusal sits with the other containment checks, BEFORE the PoP, so a
    /// caller that renews the parent and retries is not denied for the wrong reason.
    #[tokio::test]
    async fn refusing_a_dead_parent_does_not_consume_the_pop_nonce() {
        let (svc, _) = fixture();
        let dead = parent_expiring_in(-60);
        let live = parent_expiring_in(600);

        let req = signed_child(&dead, vec!["data.x"], vec!["read"], "shared-nonce");
        assert!(svc.mint_child(req, Some(&dead)).await.is_err());

        let req_ok = signed_child(&live, vec!["data.x"], vec!["read"], "shared-nonce");
        assert!(svc.mint_child(req_ok, Some(&live)).await.is_ok());
    }

    /// Step 7a. `not_after` is an instruction to a seam a deployment supplies; the
    /// invariant is a property of the document. An issuer written before this rule —
    /// or one that simply gets it wrong — must not be able to put an over-long child
    /// into circulation through this mint.
    #[tokio::test]
    async fn an_issuer_that_ignores_the_ceiling_is_caught_and_the_child_withheld() {
        /// Delegates everything to the real issuer but drops the ceiling.
        struct IgnoresTheCeiling(ReferenceIssuer);

        impl VaidIssuer for IgnoresTheCeiling {
            #[allow(clippy::too_many_arguments)]
            fn issue_vaid_with_key(
                &self,
                agent_class: AgentClass,
                version: String,
                tenant_id: TenantId,
                parent_vaid: Option<VaidId>,
                scope_boundary: Vec<String>,
                capability_set: Vec<String>,
                public_key_der: Vec<u8>,
                _not_after: Option<&str>,
            ) -> MintResult<Vaid> {
                self.0.issue_vaid_with_key(
                    agent_class,
                    version,
                    tenant_id,
                    parent_vaid,
                    scope_boundary,
                    capability_set,
                    public_key_der,
                    None,
                )
            }

            fn issue_vaid_with_lineage(
                &self,
                agent_class: AgentClass,
                version: String,
                tenant_id: TenantId,
                parent_vaid: Option<VaidId>,
                scope_boundary: Vec<String>,
                capability_set: Vec<String>,
                _not_after: Option<&str>,
            ) -> MintResult<Vaid> {
                self.0.issue_vaid_with_lineage(
                    agent_class,
                    version,
                    tenant_id,
                    parent_vaid,
                    scope_boundary,
                    capability_set,
                    None,
                )
            }

            fn verify_vaid(&self, vaid: &Vaid) -> bool {
                self.0.verify_vaid(vaid)
            }
        }

        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let svc = MintService::new(
            Arc::new(IgnoresTheCeiling(issuer)),
            Arc::new(InMemoryAudit::default()),
        );
        let parent = parent_expiring_in(600);

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "bad-issuer");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(format!("{err}").contains("not_after"), "{err}");
    }

    /// A root has no parent to be contained by, so nothing bounds its TTL. Stated as
    /// a test because a clamp applied indiscriminately would silently shorten every
    /// root mint in the estate.
    #[tokio::test]
    async fn the_root_path_is_unclamped() {
        let (svc, _) = fixture();
        let root = svc
            .mint_root(MintVaidRequest {
                seed: VaidSeed {
                    agent_class: "root".into(),
                    version: "1.0.0".into(),
                    tenant_id: "acme".into(),
                    parent_vaid: None,
                    scope_boundary: vec!["data.x".into()],
                    capability_set: vec!["read".into()],
                    public_key_der: None,
                },
                pop: None,
            })
            .await
            .unwrap()
            .vaid;

        assert_eq!(
            root.expires_at().unwrap() - root.issued_at().unwrap(),
            chrono::Duration::hours(1),
            "the issuer's full TTL applies"
        );
    }

    // ── the clamp is visible to the caller, not only in a shorter expires_at ──

    /// A silent shortening was the objection to clamping. `expires_at` alone looks
    /// like an ordinary expiry: a caller would have to know the issuer's TTL and
    /// subtract to notice its delegation had been cut short. The response says it.
    #[tokio::test]
    async fn a_clamped_child_says_so_on_the_response() {
        let (svc, _) = fixture(); // ReferenceIssuer::ephemeral(1, ..) — a 1-hour TTL
        let parent = parent_expiring_in(600); // ten minutes left

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "visible-1");
        let response = svc.mint_child(req, Some(&parent)).await.unwrap();

        assert!(response.expiry_bounded_by_parent);
        assert_eq!(
            response.parent_expires_at.as_deref(),
            Some(parent.expires_at_as_presented())
        );
        assert_eq!(
            response.vaid.expires_at_as_presented(),
            parent.expires_at_as_presented()
        );
    }

    /// THE CONTROL. A flag that is always true carries no information, and would
    /// pass the test above while telling a caller nothing. Here the issuer's own
    /// TTL is the earlier bound, nothing was taken away, and the flag must be false.
    #[tokio::test]
    async fn an_unclamped_child_says_that_too() {
        let (svc, _) = fixture();
        let parent = parent_expiring_in(86_400); // a day out; the issuer TTL is an hour

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "visible-2");
        let response = svc.mint_child(req, Some(&parent)).await.unwrap();

        assert!(!response.expiry_bounded_by_parent);
        assert_eq!(
            response.parent_expires_at.as_deref(),
            Some(parent.expires_at_as_presented())
        );
        assert!(response.vaid.expires_at().unwrap() < parent.expires_at().unwrap());
    }

    /// A root has no parent to be bounded by, and must not claim one.
    #[tokio::test]
    async fn a_root_mint_is_never_bounded_by_a_parent_it_does_not_have() {
        let (svc, _) = fixture();
        let response = svc
            .mint_root(MintVaidRequest {
                seed: VaidSeed {
                    agent_class: "root".into(),
                    version: "1.0.0".into(),
                    tenant_id: "acme".into(),
                    parent_vaid: None,
                    scope_boundary: vec!["data.x".into()],
                    capability_set: vec!["read".into()],
                    public_key_der: None,
                },
                pop: None,
            })
            .await
            .unwrap();

        assert!(!response.expiry_bounded_by_parent);
        assert_eq!(response.parent_expires_at, None);
    }

    /// A caller that ignores the response still leaves a record. Without this, the
    /// only evidence that a credential was deliberately shortened would be the
    /// caller's own memory of a field it did not read.
    #[tokio::test]
    async fn the_clamp_is_recorded_in_the_audit_trail() {
        let (svc, audit) = fixture();
        let parent = parent_expiring_in(600);

        let req = signed_child(&parent, vec!["data.x"], vec!["read"], "visible-3");
        svc.mint_child(req, Some(&parent)).await.unwrap();

        let entries = audit.entries();
        let details = &entries.last().expect("one entry").details;
        assert_eq!(details["expiry_bounded_by_parent"], json!(true));
        assert_eq!(
            details["expires_at"],
            json!(parent.expires_at_as_presented())
        );
        assert_eq!(
            details["parent_expires_at"],
            json!(parent.expires_at_as_presented())
        );
    }
}

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
fn scope_attenuates(parent: &Vaid, child_scope: &[String]) -> bool {
    if child_scope.is_empty() {
        // Child wants ⊤; allowed only if the parent is also ⊤.
        parent.scope_boundary().is_empty()
    } else {
        child_scope.iter().all(|s| parent.is_in_scope(s))
    }
}

/// Capability attenuation: is every entry of `child_caps` held by `parent`? Uses
/// ONLY [`Vaid::has_capability`] (exact membership).
///
/// No empty-child guard is needed (and deliberately none is added): capabilities
/// are explicit grants where empty = ∅ (least privilege), so an empty child set
/// is safe by construction; and an empty *parent* set holds nothing, so every
/// requested child capability is rejected. This is the deliberate scope/caps
/// asymmetry — scope empty = ⊤ needs a guard, caps empty = ∅ does not.
fn caps_attenuate(parent: &Vaid, child_caps: &[String]) -> bool {
    child_caps.iter().all(|c| parent.has_capability(c))
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
            let mut nonces = self.consumed_pop_nonces.lock().expect("nonce lock not poisoned");
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

        Ok(MintVaidResponse { vaid })
    }

    /// Attenuated intra-tenant delegation. An authenticated parent VAID `P` mints
    /// a child `C` iff — checked fail-closed BEFORE any key work or nonce
    /// consumption — every condition holds:
    ///
    /// 1. **parent present** — a verified parent travelled in context; absent → deny;
    /// 2. `C.tenant == P.tenant` — same tenant, from the VERIFIED parent, never the body;
    /// 3. `C.parent_vaid == Some(P.vaid_id)` — lineage bound to the authenticated parent;
    /// 4. `C.scope ⊆ P.scope` — [`scope_attenuates`];
    /// 5. `C.caps ⊆ P.caps` — [`caps_attenuate`];
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
        if seed.tenant_id != parent.tenant_id().as_str() {
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
        let vaid = self.issuer.issue_vaid_with_key(
            AgentClass::new(&seed.agent_class),
            seed.version.clone(),
            TenantId::new(&seed.tenant_id),
            seed.parent_vaid,
            seed.scope_boundary.clone(),
            seed.capability_set.clone(),
            key.clone(),
        )?;

        // (8) Delegated audit — distinguishes the delegation tree from root mints.
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
                }),
            )
            .await?;

        Ok(MintVaidResponse { vaid })
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
        let issuer = Arc::new(ReferenceIssuer::ephemeral(1).unwrap());
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
            tenant_id: "codex".into(),
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
                tenant_id: "codex".into(),
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
        let issuer = Arc::new(ReferenceIssuer::ephemeral(1).unwrap());
        let svc = MintService::with_authorization(issuer, audit.clone(), Arc::new(DenyAll));

        let req = MintVaidRequest {
            seed: VaidSeed {
                agent_class: "researcher".into(),
                version: "1.0.0".into(),
                tenant_id: "codex".into(),
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

        let resp = svc.mint_root(MintVaidRequest { seed, pop: Some(pop) }).await.unwrap();
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

        let err = svc.mint_root(MintVaidRequest { seed, pop: Some(pop) }).await.unwrap_err();
        assert!(err.to_string().contains("does not verify"), "got: {err}");
        assert!(audit.is_empty(), "no VAID minted → no audit");
    }

    #[tokio::test]
    async fn root_byo_key_without_pop_is_rejected() {
        let (svc, _) = fixture();
        let seed = byo_seed(pubkey(&holder_keypair()));
        let err = svc.mint_root(MintVaidRequest { seed, pop: None }).await.unwrap_err();
        assert!(err.to_string().contains("proof-of-possession required"), "got: {err}");
    }

    #[tokio::test]
    async fn root_byo_key_replay_is_rejected() {
        let (svc, _) = fixture();
        let kp = holder_keypair();
        let registered = pubkey(&kp);
        let seed = byo_seed(registered.clone());
        let pop = make_pop(&seed, &registered, &kp, "nonce-replay", Utc::now());

        let first = svc
            .mint_root(MintVaidRequest { seed: seed.clone(), pop: Some(pop.clone()) })
            .await;
        assert!(first.is_ok());
        let replay = svc.mint_root(MintVaidRequest { seed, pop: Some(pop) }).await;
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
        let err = svc.mint_root(MintVaidRequest { seed, pop: Some(pop) }).await.unwrap_err();
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
        )
    }

    fn child_seed(parent: &Vaid, scope: Vec<&str>, caps: Vec<&str>, child_pub: Vec<u8>) -> VaidSeed {
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
        MintVaidRequest { seed, pop: Some(pop) }
    }

    #[tokio::test]
    async fn child_within_bounds_is_minted_with_lineage_and_delegated_audit() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read", "write"]);
        let req = signed_child(&parent, vec!["data.aifactory.sub"], vec!["read"], "ok-1");

        let resp = svc.mint_child(req, Some(&parent)).await.unwrap();
        assert_eq!(resp.vaid.parent_vaid(), Some(parent.vaid_id()), "lineage bound");
        assert_eq!(audit.entries()[0].details["delegated"], json!(true));
        assert_eq!(audit.entries()[0].details["attenuation_verified"], json!(true));
    }

    #[tokio::test]
    async fn child_scope_exceeding_parent_is_denied() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(&parent, vec!["data.somewhere-else"], vec!["read"], "deny-scope");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(err.to_string().contains("scope_boundary exceeds"), "got: {err}");
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn empty_child_scope_under_restricted_parent_is_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(&parent, vec![], vec!["read"], "deny-empty-scope");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(err.to_string().contains("scope_boundary exceeds"), "got: {err}");
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
        let req = signed_child(&parent, vec!["data.aifactory.sub"], vec!["read", "write"], "deny-caps");
        let err = svc.mint_child(req, Some(&parent)).await.unwrap_err();
        assert!(err.to_string().contains("capability_set exceeds"), "got: {err}");
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
        let mut seed = child_seed(&parent, vec!["data.aifactory.sub"], vec!["read"], pubk.clone());
        seed.tenant_id = "codex".into(); // forge a foreign tenant
        let pop = make_pop(&seed, &pubk, &kp, "forge-tenant", Utc::now());
        let err = svc
            .mint_child(MintVaidRequest { seed, pop: Some(pop) }, Some(&parent))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cross-tenant delegation is denied"), "got: {err}");
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn child_claiming_a_different_parent_vaid_is_denied() {
        let (svc, audit) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let kp = holder_keypair();
        let pubk = pubkey(&kp);
        let mut seed = child_seed(&parent, vec!["data.aifactory.sub"], vec!["read"], pubk.clone());
        seed.parent_vaid = Some(VaidId::new()); // forge a different parent
        let pop = make_pop(&seed, &pubk, &kp, "forge-parent", Utc::now());
        let err = svc
            .mint_child(MintVaidRequest { seed, pop: Some(pop) }, Some(&parent))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("parent_vaid"), "got: {err}");
        assert!(audit.is_empty());
    }

    #[tokio::test]
    async fn mint_child_without_parent_context_is_denied() {
        let (svc, _) = fixture();
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read"]);
        let req = signed_child(&parent, vec!["data.aifactory.sub"], vec!["read"], "no-parent");
        let err = svc.mint_child(req, None).await.unwrap_err();
        assert!(err.to_string().contains("no verified parent VAID"), "got: {err}");
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
        let issuer = Arc::new(ReferenceIssuer::ephemeral(1).unwrap());
        let svc = MintService::new(issuer.clone(), audit);
        let parent = parent_doc("aifactory", vec!["data.aifactory"], vec!["read", "write"]);
        let req = signed_child(&parent, vec!["data.aifactory.reports"], vec!["read"], "e2e");
        let child = svc.mint_child(req, Some(&parent)).await.unwrap().vaid;

        assert!(issuer.verify_vaid(&child), "minted child must verify against the issuer");
        // Containment: every child scope entry is within the parent, every child
        // cap is held by the parent.
        assert!(child.scope_boundary().iter().all(|s| parent.is_in_scope(s)));
        assert!(child.capability_set().iter().all(|c| parent.has_capability(c)));
    }
}

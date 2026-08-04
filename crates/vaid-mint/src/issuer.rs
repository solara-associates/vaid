//! The issuer — the kernel signer that turns requested attributes into a signed
//! VAID document.
//!
//! [`VaidIssuer`] is the seam; [`ReferenceIssuer`] is the open, self-hostable
//! implementation. It holds an Ed25519 kernel key and signs the full canonical
//! VAID document. Three things a hosted authority adds that this reference
//! leaves to the self-hoster:
//!
//! - **No KMS / secret-store bootstrap.** The kernel key is either generated
//!   ephemerally ([`ReferenceIssuer::ephemeral`]) or supplied by the caller
//!   ([`ReferenceIssuer::from_pkcs8`] / [`ReferenceIssuer::from_seed`]). A
//!   self-hoster persists and protects that key however they choose.
//! - **Non-durable revocation, but a pluggable seam.** The default in-memory
//!   revocation store does not survive restart. A self-hoster injects a durable
//!   backend via the three-state [`crate::revocation::RevocationCheck`] seam
//!   ([`ReferenceIssuer::with_revocation_check`]) without patching the crate. See
//!   `docs/spec/revocation.md` R.4 and the crate README's "Trust model" section.
//! - **The issuer is the lineage resolver.** It records **every** mint in an
//!   in-memory map — roots with no parent, children with their parent — so it can
//!   tell a known root from an id it has never seen ([`LineageResolver`], spec
//!   R.4.2). The map is not durable and is not a network service; after a restart
//!   it is empty, and a child presented against it resolves to
//!   [`RevocationStatus::Unavailable`] rather than being mistaken for a root.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid,
    VaidId, VAID_SIG_VERSION_V3,
};
use crate::error::{MintError, MintResult};
use crate::revocation::{
    assemble_lineage, InMemoryRevocationList, LineageAssembly, LineageResolver, ParentResolution,
    RevocationCheck, RevocationStatus,
};

/// The default issuance TTL, in hours, when a caller does not supply one. Short
/// by design: with only non-durable revocation in this reference, a short TTL is
/// the primary control that bounds the exposure window of a leaked or compromised
/// VAID (see the README "Trust model"). The constructors still take an explicit
/// `vaid_ttl_hours`; this constant documents the recommended baseline.
pub const DEFAULT_VAID_TTL_HOURS: i64 = 1;

/// The issuer seam. The mint holds one of these and asks it to issue signed
/// documents. Sync (not async): issuing is CPU-only (key handling + one Ed25519
/// sign); no I/O is on this path in the reference.
pub trait VaidIssuer: Send + Sync {
    /// Issue a VAID under a caller-supplied public key (the BYO-key path — the
    /// mint has already verified proof-of-possession of the matching private
    /// key). The issuer signs the document with the kernel key.
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
    ) -> MintResult<Vaid>;

    /// Issue a VAID under an issuer-generated keypair, discarding the private
    /// half (no holder key is registered, so no PoP applies). The
    /// generate-and-discard root/bootstrap path.
    fn issue_vaid_with_lineage(
        &self,
        agent_class: AgentClass,
        version: String,
        tenant_id: TenantId,
        parent_vaid: Option<VaidId>,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
    ) -> MintResult<Vaid>;

    /// Verify a VAID against this issuer: correct signature scheme, kernel
    /// signature valid over the canonical document, **not expired**, and not
    /// revoked. Expiry is now a hard reject — an expired VAID returns `false`
    /// even with a valid kernel signature. [`Vaid::is_expired`] remains available
    /// for a caller that needs to distinguish "forged" from "expired" before
    /// calling this. A bad signature is `false`, never an error.
    fn verify_vaid(&self, vaid: &Vaid) -> bool;
}

/// The open reference issuer. Holds an Ed25519 kernel key, an in-memory lineage
/// map recording every mint (so it can act as the verifier-side
/// [`LineageResolver`]), and the three-state [`RevocationCheck`] consulted at
/// verification.
pub struct ReferenceIssuer {
    kernel_key_pair: Ed25519KeyPair,
    vaid_ttl_hours: i64,
    /// v3: the trust domain stamped into every VAID this issuer mints
    /// (ADR-0004). Validated at construction, so an issuer that could only emit
    /// non-conforming documents cannot be built. The companion
    /// `kernel_key_thumbprint` is NOT stored here — it is derived from the kernel
    /// key at mint time, so it cannot disagree with the key that signs.
    trust_domain: String,
    /// Every minted VAID: `Some(parent)` for a child, `None` for a root. Recording
    /// roots (not just children) is what lets [`resolve_parent`] distinguish a
    /// known root from an unknown id — the crux of spec R.4.2.
    ///
    /// [`resolve_parent`]: ReferenceIssuer::resolve_parent
    lineage: Mutex<HashMap<VaidId, Option<VaidId>>>,
    /// The revocation store consulted in `verify_vaid`. Defaults to `default_store`
    /// (in-memory, [`InMemoryRevocationList::assume_nothing_revoked`]); replaced by
    /// [`ReferenceIssuer::with_revocation_check`].
    revocation: Arc<dyn RevocationCheck>,
    /// The built-in in-memory store that [`ReferenceIssuer::revoke`] mutates. It is
    /// the default `revocation`; injecting a custom check leaves this in place but
    /// unconsulted (revoke through the injected backend instead).
    default_store: Arc<InMemoryRevocationList>,
}

impl ReferenceIssuer {
    /// Build with a freshly generated **ephemeral** kernel key. VAIDs signed by
    /// this issuer verify only for this process's lifetime — the key is not
    /// persisted. The zero-config default for local self-hosting and tests.
    pub fn ephemeral(vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| MintError::Identity(format!("kernel key generation failed: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), vaid_ttl_hours, trust_domain)
    }

    /// Build from a caller-supplied PKCS#8 kernel key — the self-hosting
    /// persistence path (load the key from wherever you keep it and hand the
    /// bytes here). VAIDs signed by this issuer verify across restarts as long as
    /// the same key is supplied.
    pub fn from_pkcs8(pkcs8: &[u8], vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let trust_domain = Self::checked_trust_domain(trust_domain)?;
        let kernel_key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| MintError::Identity(format!("kernel key parse failed: {e}")))?;
        Ok(Self::with_key(
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
        ))
    }

    /// Reject a malformed trust domain at construction rather than at mint.
    /// An issuer whose every output would fail verification is not a useful
    /// object to hold.
    fn checked_trust_domain(trust_domain: &str) -> MintResult<String> {
        if !crate::issuer_identity::is_valid_trust_domain(trust_domain) {
            return Err(MintError::Identity(format!(
                "trust_domain {trust_domain:?} is not well-formed (ADR-0004): lowercase ASCII \
                 letters, digits, '-' and '.'; at least two labels; each 1-63 bytes without a \
                 leading or trailing '-'; no trailing dot; 1-253 bytes total; final label not \
                 all-numeric"
            )));
        }
        Ok(trust_domain.to_string())
    }

    /// Build from a raw 32-byte Ed25519 seed. Primarily for deterministic
    /// conformance vectors (RFC 8032 test seeds), where both languages must
    /// derive the identical kernel key and produce identical signatures.
    pub fn from_seed(seed: &[u8], vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let trust_domain = Self::checked_trust_domain(trust_domain)?;
        let kernel_key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| MintError::Identity(format!("kernel seed parse failed: {e}")))?;
        Ok(Self::with_key(
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
        ))
    }

    /// The trust domain this issuer stamps into every VAID it mints.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The RFC 9278 thumbprint URI of this issuer's kernel public key — the value
    /// stamped into every VAID it mints, and the value a verifier uses to select
    /// this issuer's key from a trust bundle.
    pub fn kernel_key_thumbprint(&self) -> String {
        crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key())
    }

    fn with_key(
        kernel_key_pair: Ed25519KeyPair,
        vaid_ttl_hours: i64,
        trust_domain: String,
    ) -> Self {
        // Default revocation posture: assume-nothing-revoked, so a live issuer
        // vouches "nothing revoked yet" and a fresh, un-revoked VAID verifies out of
        // the box rather than failing closed on Unavailable. RESTART BEHAVIOUR: this
        // store is non-durable and cannot detect its own restart — after a restart it
        // is reconstructed empty and again vouches NotRevoked, so a VAID revoked
        // before the restart verifies clean. For restart-safety, inject a durable
        // `RevocationCheck`, or hold the store absent until revocation state is
        // re-loaded. See `docs/spec/revocation.md` R.4.6.
        let default_store = Arc::new(InMemoryRevocationList::assume_nothing_revoked());
        Self {
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
            lineage: Mutex::new(HashMap::new()),
            revocation: default_store.clone(),
            default_store,
        }
    }

    /// Replace the revocation store consulted at verification with an injected
    /// [`RevocationCheck`] — e.g. a durable, restart-surviving backend that returns
    /// [`RevocationStatus::Unavailable`] when its store is unreachable. The built-in
    /// [`ReferenceIssuer::revoke`] store stays but is no longer consulted; revoke
    /// through the injected backend instead. Consumes and re-wraps `self`,
    /// preserving the kernel key, TTL, and any lineage already recorded.
    pub fn with_revocation_check(mut self, revocation_check: Arc<dyn RevocationCheck>) -> Self {
        self.revocation = revocation_check;
        self
    }

    /// The kernel public key (raw 32 bytes) a verifier binds this issuer's VAIDs
    /// against.
    pub fn kernel_public_key(&self) -> &[u8] {
        self.kernel_key_pair.public_key().as_ref()
    }

    /// Sign a **detached consent attestation**: this issuer, as the party that
    /// issued `parent_vaid`, consents to `child_vaid` holding at most `scope` and
    /// `capability_set` under it.
    ///
    /// This is the signer half of
    /// [`crate::attestation::ConsentAttestation`]. It exists because consent is
    /// otherwise a property of the mint's *session* — `mint_child` enforces it
    /// in-process and nothing about that enforcement lands in the child document.
    /// A cross-issuer verifier has no way to see it. This makes it a signed object
    /// the presenter can carry.
    ///
    /// The trust domain and thumbprint come from this issuer's own key and
    /// configuration, never from a parameter, so an attestation cannot name a key
    /// or a domain other than the one about to sign it.
    ///
    /// **This does not check that `parent_vaid` was actually minted here.** The
    /// reference issuer's lineage map is in-memory and empty after restart
    /// (R.4.6), so a check against it would fail closed on legitimate attestations
    /// after any restart, which is worse than not checking. A verifier does not
    /// rely on this: it independently requires the attestation's thumbprint to
    /// equal the parent document's, so an attestation signed by the wrong issuer is
    /// rejected at verification regardless of what was checked here.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_delegation(
        &self,
        parent_vaid: VaidId,
        child_vaid: VaidId,
        child_trust_domain: String,
        child_tenant_id: String,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
    ) -> crate::attestation::ConsentAttestation {
        let unsigned = crate::attestation::ConsentAttestation::new(
            parent_vaid,
            child_vaid,
            child_trust_domain,
            child_tenant_id,
            scope_boundary,
            capability_set,
            self.trust_domain.clone(),
            crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key()),
        );
        let signature =
            self.kernel_key_pair
                .sign(&crate::attestation::canonical_attestation_signing_bytes(
                    &unsigned,
                ));
        unsigned.with_signature(signature.as_ref().to_vec())
    }

    /// Revoke a VAID in the built-in in-memory store. A revoked VAID — and every
    /// VAID attenuated from it (R.4.4) — fails [`VaidIssuer::verify_vaid`]. Does not
    /// survive restart. Has no effect on verification if a custom [`RevocationCheck`]
    /// was injected via [`ReferenceIssuer::with_revocation_check`]; revoke through
    /// that backend instead.
    pub fn revoke(&self, vaid_id: VaidId) {
        self.default_store.revoke(vaid_id);
    }

    /// Clear the in-memory lineage map, modelling the loss of resolver state across
    /// a process restart. Afterwards any VAID carrying a `parent_vaid` resolves to
    /// [`RevocationStatus::Unavailable`] — its ancestry can no longer be completed
    /// (R.4.2) — while a genuinely rootless VAID still verifies. An ops/test
    /// primitive.
    pub fn clear_lineage(&self) {
        self.lineage
            .lock()
            .expect("lineage lock not poisoned")
            .clear();
    }

    /// The revocation status of `vaid` under this issuer (spec R.4): assemble its
    /// ordered lineage from this issuer's resolver, then consult the revocation
    /// store with it. An incomplete lineage is [`RevocationStatus::Unavailable`] and
    /// the store is not consulted (R.4.2). [`VaidIssuer::verify_vaid`] gates on this;
    /// it is exposed so a caller can distinguish `Unavailable` from `NotRevoked`
    /// (R.4.3) rather than seeing only a rejected/accepted boolean.
    pub fn revocation_status(&self, vaid: &Vaid) -> RevocationStatus {
        match assemble_lineage(vaid, self) {
            LineageAssembly::Incomplete => RevocationStatus::Unavailable,
            LineageAssembly::Complete(lineage) => self.revocation.check_lineage(&lineage),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_and_sign_vaid(
        &self,
        agent_class: AgentClass,
        version: String,
        tenant_id: TenantId,
        parent_vaid: Option<VaidId>,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
        public_key_der: Vec<u8>,
    ) -> MintResult<Vaid> {
        let agent_id = AgentId::new();
        let now = Utc::now();
        let expires = now + Duration::hours(self.vaid_ttl_hours);
        let lineage_hash = compute_lineage_hash(parent_vaid, &agent_id);

        // Build the full document with an empty signature, sign its canonical
        // bytes (which null `kernel_signature`), then attach the signature.
        let unsigned = Vaid::with_lineage(
            agent_id,
            agent_class,
            version,
            tenant_id,
            now,
            expires,
            public_key_der,
            Vec::new(),
            parent_vaid,
            scope_boundary,
            lineage_hash,
            capability_set,
            self.trust_domain.clone(),
            // Derived from the signing key itself, never supplied: the thumbprint
            // cannot disagree with the key that is about to sign.
            crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key()),
        );
        let signature = self
            .kernel_key_pair
            .sign(&canonical_vaid_signing_bytes(&unsigned));
        let vaid = unsigned.with_kernel_signature(signature.as_ref().to_vec());

        // Record EVERY mint — roots as `None`, children as `Some(parent)` — so the
        // resolver can distinguish a known root from an id it has never seen. This
        // is the bookkeeping spec R.4.2 depends on; it changes no document bytes.
        self.lineage
            .lock()
            .expect("lineage lock not poisoned")
            .insert(vaid.vaid_id(), parent_vaid);

        Ok(vaid)
    }
}

// `compute_lineage_hash` lives in `document` (a document concern, and the
// conformance vector references it); re-exported implicitly via crate root.

impl LineageResolver for ReferenceIssuer {
    /// Resolve one hop from the in-memory lineage map. A recorded VAID with `None`
    /// is a **known root**; a recorded VAID with `Some(parent)` is a **child**; an
    /// unrecorded id is **unknown** — the distinction spec R.4.2 turns on, and the
    /// reason an empty (post-restart) map yields `Unavailable` for a child rather
    /// than mistaking it for a root.
    fn resolve_parent(&self, vaid_id: &VaidId) -> ParentResolution {
        match self
            .lineage
            .lock()
            .expect("lineage lock not poisoned")
            .get(vaid_id)
        {
            Some(Some(parent)) => ParentResolution::Parent(*parent),
            Some(None) => ParentResolution::Root,
            None => ParentResolution::Unknown,
        }
    }
}

impl VaidIssuer for ReferenceIssuer {
    fn issue_vaid_with_key(
        &self,
        agent_class: AgentClass,
        version: String,
        tenant_id: TenantId,
        parent_vaid: Option<VaidId>,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
        public_key_der: Vec<u8>,
    ) -> MintResult<Vaid> {
        self.build_and_sign_vaid(
            agent_class,
            version,
            tenant_id,
            parent_vaid,
            scope_boundary,
            capability_set,
            public_key_der,
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
    ) -> MintResult<Vaid> {
        let rng = SystemRandom::new();
        let agent_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| MintError::Identity(format!("agent key generation failed: {e}")))?;
        let agent_key = Ed25519KeyPair::from_pkcs8(agent_pkcs8.as_ref())
            .map_err(|e| MintError::Identity(format!("agent key parse failed: {e}")))?;
        let public_key_der = agent_key.public_key().as_ref().to_vec();

        self.build_and_sign_vaid(
            agent_class,
            version,
            tenant_id,
            parent_vaid,
            scope_boundary,
            capability_set,
            public_key_der,
        )
    }

    fn verify_vaid(&self, vaid: &Vaid) -> bool {
        if vaid.sig_version() != VAID_SIG_VERSION_V3 {
            return false;
        }
        // TTL is now enforced as a hard reject, not merely reported: an expired
        // VAID fails verification even with a valid kernel signature.
        if vaid.is_expired() {
            return false;
        }
        // Revocation over the FULL ordered lineage (R.4.4), failing closed on
        // Unavailable: an incomplete lineage or an unreachable store rejects the
        // VAID — it never silently passes (R.4.2, R.4.5).
        match self.revocation_status(vaid) {
            RevocationStatus::NotRevoked => {}
            RevocationStatus::Revoked | RevocationStatus::Unavailable => return false,
        }
        let public_key = UnparsedPublicKey::new(&ED25519, self.kernel_public_key());
        public_key
            .verify(&canonical_vaid_signing_bytes(vaid), vaid.kernel_signature())
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_root_vaid_verifies_against_its_issuer() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert!(
            issuer.verify_vaid(&vaid),
            "a freshly issued VAID must verify"
        );
        assert_eq!(vaid.parent_vaid(), None);
        assert_eq!(vaid.sig_version(), VAID_SIG_VERSION_V3);
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec!["data.x".into()],
                vec!["read".into()],
            )
            .unwrap();
        // Re-serialize, widen the scope, deserialize — the signature no longer
        // covers the document.
        let mut val = serde_json::to_value(&vaid).unwrap();
        val["scope_boundary"] = serde_json::json!(["data.x", "data.everything"]);
        let forged: Vaid = serde_json::from_value(val).unwrap();
        assert!(
            !issuer.verify_vaid(&forged),
            "a rewritten scope must break the signature"
        );
    }

    #[test]
    fn a_different_issuer_does_not_verify() {
        let a = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let b = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let vaid = a
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert!(a.verify_vaid(&vaid));
        assert!(
            !b.verify_vaid(&vaid),
            "another issuer's key must not verify this VAID"
        );
    }

    #[test]
    fn revocation_fails_verification() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert!(issuer.verify_vaid(&vaid));
        issuer.revoke(vaid.vaid_id());
        assert!(!issuer.verify_vaid(&vaid), "a revoked VAID must not verify");
    }

    #[test]
    fn expired_vaid_fails_verification() {
        // A negative TTL issues a VAID whose `expires_at` is already in the past;
        // its kernel signature is valid but verification must now hard-reject it.
        let issuer = ReferenceIssuer::ephemeral(-1, "vaid.example").unwrap();
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert!(vaid.is_expired(), "fixture must be expired");
        assert!(
            !issuer.verify_vaid(&vaid),
            "an expired VAID must fail verification even with a valid kernel signature"
        );
    }

    #[test]
    fn injected_revocation_check_is_consulted() {
        // An assume-nothing-revoked injected store: verifies until something is
        // revoked through it.
        let store = Arc::new(InMemoryRevocationList::assume_nothing_revoked());
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .with_revocation_check(store.clone());
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert!(issuer.verify_vaid(&vaid), "not yet revoked → verifies");
        store.revoke(vaid.vaid_id());
        assert!(
            !issuer.verify_vaid(&vaid),
            "an injected revocation backend must be consulted at verification"
        );
    }

    #[test]
    fn injected_unavailable_store_fails_closed() {
        // A store whose state is absent (e.g. a durable backend that is
        // unreachable) reports Unavailable, and verification fails closed (R.4.5).
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .with_revocation_check(Arc::new(InMemoryRevocationList::unavailable()));
        let vaid = issuer
            .issue_vaid_with_lineage(
                AgentClass::new("root"),
                "1.0.0".into(),
                TenantId::new("t"),
                None,
                vec![],
                vec![],
            )
            .unwrap();
        assert_eq!(
            issuer.revocation_status(&vaid),
            RevocationStatus::Unavailable
        );
        assert!(
            !issuer.verify_vaid(&vaid),
            "a VAID whose revocation store is unavailable must fail closed"
        );
    }

    #[test]
    fn same_seed_issuer_produces_the_same_kernel_public_key() {
        // Determinism the frozen conformance vector will depend on.
        let seed = [7u8; 32];
        let a = ReferenceIssuer::from_seed(&seed, 1, "vaid.example").unwrap();
        let b = ReferenceIssuer::from_seed(&seed, 1, "vaid.example").unwrap();
        assert_eq!(a.kernel_public_key(), b.kernel_public_key());
    }
}

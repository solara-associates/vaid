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
//! - **Non-durable revocation, but a pluggable seam.** The built-in revoked set
//!   is in-memory and does not survive restart. A self-hoster can now inject a
//!   durable backend via the [`crate::revocation::RevocationCheck`] seam
//!   ([`ReferenceIssuer::with_revocation_check`]) without patching the crate; the
//!   built-in in-memory set remains the default and any injected check is layered
//!   on top of it. See the crate README's "Trust model" section.
//! - **No lineage lookup service.** The child→parent map is kept in memory for
//!   local inspection only.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid, VaidId,
    VAID_SIG_VERSION_V2,
};
use crate::error::{MintError, MintResult};
use crate::revocation::RevocationCheck;

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

/// The open reference issuer. Holds an Ed25519 kernel key, an in-memory
/// child→parent lineage map, an in-memory revoked set (the default revocation
/// backend), and an optional injected [`RevocationCheck`] layered on top of it.
pub struct ReferenceIssuer {
    kernel_key_pair: Ed25519KeyPair,
    vaid_ttl_hours: i64,
    lineage: Mutex<HashMap<VaidId, VaidId>>,
    revoked: Mutex<HashSet<VaidId>>,
    /// An optional additional revocation backend, consulted in `verify_vaid`
    /// alongside (not instead of) the built-in `revoked` set. `None` by default;
    /// injected via [`ReferenceIssuer::with_revocation_check`].
    revocation_check: Option<Arc<dyn RevocationCheck>>,
}

impl ReferenceIssuer {
    /// Build with a freshly generated **ephemeral** kernel key. VAIDs signed by
    /// this issuer verify only for this process's lifetime — the key is not
    /// persisted. The zero-config default for local self-hosting and tests.
    pub fn ephemeral(vaid_ttl_hours: i64) -> MintResult<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| MintError::Identity(format!("kernel key generation failed: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), vaid_ttl_hours)
    }

    /// Build from a caller-supplied PKCS#8 kernel key — the self-hosting
    /// persistence path (load the key from wherever you keep it and hand the
    /// bytes here). VAIDs signed by this issuer verify across restarts as long as
    /// the same key is supplied.
    pub fn from_pkcs8(pkcs8: &[u8], vaid_ttl_hours: i64) -> MintResult<Self> {
        let kernel_key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| MintError::Identity(format!("kernel key parse failed: {e}")))?;
        Ok(Self::with_key(kernel_key_pair, vaid_ttl_hours))
    }

    /// Build from a raw 32-byte Ed25519 seed. Primarily for deterministic
    /// conformance vectors (RFC 8032 test seeds), where both languages must
    /// derive the identical kernel key and produce identical signatures.
    pub fn from_seed(seed: &[u8], vaid_ttl_hours: i64) -> MintResult<Self> {
        let kernel_key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| MintError::Identity(format!("kernel seed parse failed: {e}")))?;
        Ok(Self::with_key(kernel_key_pair, vaid_ttl_hours))
    }

    fn with_key(kernel_key_pair: Ed25519KeyPair, vaid_ttl_hours: i64) -> Self {
        Self {
            kernel_key_pair,
            vaid_ttl_hours,
            lineage: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            revocation_check: None,
        }
    }

    /// Inject an additional [`RevocationCheck`] backend (e.g. a durable,
    /// restart-surviving store). It is consulted in [`VaidIssuer::verify_vaid`]
    /// **in addition to** the built-in in-memory revoked set — a VAID is rejected
    /// if either reports it revoked — so enabling the seam never silently disables
    /// the built-in behavior. Consumes and re-wraps `self`, preserving the kernel
    /// key, TTL, and any lineage/revocations already recorded.
    pub fn with_revocation_check(mut self, revocation_check: Arc<dyn RevocationCheck>) -> Self {
        self.revocation_check = Some(revocation_check);
        self
    }

    /// The kernel public key (raw 32 bytes) a verifier binds this issuer's VAIDs
    /// against.
    pub fn kernel_public_key(&self) -> &[u8] {
        self.kernel_key_pair.public_key().as_ref()
    }

    /// Revoke a VAID (in-memory). A revoked VAID fails [`VaidIssuer::verify_vaid`]
    /// regardless of signature validity. Does not survive restart.
    pub fn revoke(&self, vaid_id: VaidId) {
        self.revoked.lock().expect("revoked lock not poisoned").insert(vaid_id);
    }

    /// Is this VAID revoked in this issuer's in-memory set?
    pub fn is_revoked(&self, vaid_id: &VaidId) -> bool {
        self.revoked.lock().expect("revoked lock not poisoned").contains(vaid_id)
    }

    /// The recorded parent of a VAID, if this issuer minted it with lineage.
    pub fn parent_of(&self, vaid_id: &VaidId) -> Option<VaidId> {
        self.lineage.lock().expect("lineage lock not poisoned").get(vaid_id).copied()
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
        );
        let signature = self.kernel_key_pair.sign(&canonical_vaid_signing_bytes(&unsigned));
        let vaid = unsigned.with_kernel_signature(signature.as_ref().to_vec());

        if let Some(parent) = parent_vaid {
            self.lineage
                .lock()
                .expect("lineage lock not poisoned")
                .insert(vaid.vaid_id(), parent);
        }

        Ok(vaid)
    }
}

// `compute_lineage_hash` lives in `document` (a document concern, and the
// conformance vector references it); re-exported implicitly via crate root.

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
        if vaid.sig_version() != VAID_SIG_VERSION_V2 {
            return false;
        }
        // TTL is now enforced as a hard reject, not merely reported: an expired
        // VAID fails verification even with a valid kernel signature.
        if vaid.is_expired() {
            return false;
        }
        // Built-in in-memory revoked set, plus any injected revocation backend.
        if self.is_revoked(&vaid.vaid_id()) {
            return false;
        }
        if let Some(check) = &self.revocation_check {
            if check.is_revoked(&vaid.vaid_id()) {
                return false;
            }
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
        let issuer = ReferenceIssuer::ephemeral(1).unwrap();
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
        assert!(issuer.verify_vaid(&vaid), "a freshly issued VAID must verify");
        assert_eq!(vaid.parent_vaid(), None);
        assert_eq!(vaid.sig_version(), VAID_SIG_VERSION_V2);
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let issuer = ReferenceIssuer::ephemeral(1).unwrap();
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
        assert!(!issuer.verify_vaid(&forged), "a rewritten scope must break the signature");
    }

    #[test]
    fn a_different_issuer_does_not_verify() {
        let a = ReferenceIssuer::ephemeral(1).unwrap();
        let b = ReferenceIssuer::ephemeral(1).unwrap();
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
        assert!(!b.verify_vaid(&vaid), "another issuer's key must not verify this VAID");
    }

    #[test]
    fn revocation_fails_verification() {
        let issuer = ReferenceIssuer::ephemeral(1).unwrap();
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
        let issuer = ReferenceIssuer::ephemeral(-1).unwrap();
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
        use crate::revocation::InMemoryRevocationList;

        let list = Arc::new(InMemoryRevocationList::new());
        let issuer = ReferenceIssuer::ephemeral(1)
            .unwrap()
            .with_revocation_check(list.clone());
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
        // Revoke via the injected backend only (not the issuer's built-in set).
        list.revoke(vaid.vaid_id());
        assert!(
            !issuer.verify_vaid(&vaid),
            "an injected revocation backend must be consulted at verification"
        );
    }

    #[test]
    fn injected_never_revoked_does_not_break_normal_verification() {
        use crate::revocation::NeverRevoked;

        let issuer = ReferenceIssuer::ephemeral(1)
            .unwrap()
            .with_revocation_check(Arc::new(NeverRevoked));
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
        // The built-in set still works even with a no-op backend injected.
        issuer.revoke(vaid.vaid_id());
        assert!(!issuer.verify_vaid(&vaid), "built-in revoked set still enforced");
    }

    #[test]
    fn same_seed_issuer_produces_the_same_kernel_public_key() {
        // Determinism the frozen conformance vector will depend on.
        let seed = [7u8; 32];
        let a = ReferenceIssuer::from_seed(&seed, 1).unwrap();
        let b = ReferenceIssuer::from_seed(&seed, 1).unwrap();
        assert_eq!(a.kernel_public_key(), b.kernel_public_key());
    }
}

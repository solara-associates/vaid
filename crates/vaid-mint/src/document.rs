//! The VAID document — the signed, immutable identity a mint produces.
//!
//! This is the reference-repo copy of the v2 VAID document: every
//! identity-bearing field is covered by the kernel signature (with
//! `kernel_signature` itself nulled before signing). `VaidId`/`TenantId` are the
//! shared identity newtypes reused from `vaid-pop` — the same types the
//! per-request PoP payload binds — so a document minted here and a request signed
//! by its holder speak of the same identity. `AgentId`/`AgentClass` are NOT part
//! of the PoP signing contract and are defined here.
//!
//! NOTE (Decision B): this document is self-consistent within this repo. Its
//! canonical bytes are NOT pinned to the closed substrate's VAID format — that
//! format is still moving, and a cross-repo byte-identity commitment would be a
//! maintenance trap until it settles.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// The identity newtypes the PoP payload binds are shared, one definition, from
// the signing-primitive leaf.
pub use vaid_pop::{TenantId, VaidId};

/// Current VAID signature-scheme version. The whole canonical document is signed
/// (with `kernel_signature` nulled), and the version is itself a signed field, so
/// a downgrade to a weaker payload cannot be forged without breaking
/// verification. A document whose `sig_version` is not this value is rejected at
/// verify.
pub const VAID_SIG_VERSION_V2: u8 = 2;

/// Unique identifier for an agent instance. Not part of the PoP signing contract,
/// so it is defined here rather than in `vaid-pop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    /// Construct from a specific UUID — used to build deterministic documents
    /// (e.g. the frozen conformance vector), where the id must be fixed.
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Agent class identifier (e.g. "researcher", "code-reviewer").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentClass(String);

impl AgentClass {
    pub fn new(class: impl Into<String>) -> Self {
        Self(class.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Verifiable Agent Identity Document (VAID) — immutable, signed at mint time.
///
/// v2 fields: `parent_vaid` (delegation lineage), `scope_boundary` (data-domain
/// restrictions), `lineage_hash` (parent-chain hash), `capability_set` (explicit
/// grants). Every field except `kernel_signature` is covered by the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vaid {
    /// Signature-scheme discriminant; `2` for every VAID minted here. Covered by
    /// the signature and gated at verify. `#[serde(default)]` so a pre-v2 / forged
    /// document deserializes to `0` and is cleanly rejected rather than failing to
    /// parse.
    #[serde(default)]
    sig_version: u8,
    vaid_id: VaidId,
    agent_id: AgentId,
    agent_class: AgentClass,
    version: String,
    tenant_id: TenantId,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    public_key_der: Vec<u8>,
    kernel_signature: Vec<u8>,
    /// VAID of the spawning agent. Root agents have no parent (`None`).
    parent_vaid: Option<VaidId>,
    /// Data domains / resource namespaces this agent may operate within.
    scope_boundary: Vec<String>,
    /// Hash of the parent VAID chain — enables delegation-tree reconstruction.
    lineage_hash: String,
    /// Explicit capability grants at spawn. No ambient authority.
    capability_set: Vec<String>,
}

impl Vaid {
    /// Build a VAID with v2 lineage and scope fields. The issuer calls this to
    /// assemble the unsigned document; `kernel_signature` is attached afterwards
    /// via [`Vaid::with_kernel_signature`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_lineage(
        agent_id: AgentId,
        agent_class: AgentClass,
        version: String,
        tenant_id: TenantId,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        public_key_der: Vec<u8>,
        kernel_signature: Vec<u8>,
        parent_vaid: Option<VaidId>,
        scope_boundary: Vec<String>,
        lineage_hash: String,
        capability_set: Vec<String>,
    ) -> Self {
        let vaid_id = VaidId::from_uuid(*agent_id.as_uuid());
        Self {
            sig_version: VAID_SIG_VERSION_V2,
            vaid_id,
            agent_id,
            agent_class,
            version,
            tenant_id,
            issued_at,
            expires_at,
            public_key_der,
            kernel_signature,
            parent_vaid,
            scope_boundary,
            lineage_hash,
            capability_set,
        }
    }

    /// Attach the kernel signature to a freshly-built (unsigned) VAID. Consuming,
    /// to keep the document otherwise immutable.
    pub fn with_kernel_signature(mut self, signature: Vec<u8>) -> Self {
        self.kernel_signature = signature;
        self
    }

    pub fn sig_version(&self) -> u8 {
        self.sig_version
    }
    pub fn vaid_id(&self) -> VaidId {
        self.vaid_id
    }
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }
    pub fn agent_class(&self) -> &AgentClass {
        &self.agent_class
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }
    pub fn kernel_signature(&self) -> &[u8] {
        &self.kernel_signature
    }
    pub fn parent_vaid(&self) -> Option<VaidId> {
        self.parent_vaid
    }
    pub fn scope_boundary(&self) -> &[String] {
        &self.scope_boundary
    }
    pub fn lineage_hash(&self) -> &str {
        &self.lineage_hash
    }
    pub fn capability_set(&self) -> &[String] {
        &self.capability_set
    }

    /// True once past `expires_at`.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Is `resource` within this VAID's scope boundary? An empty boundary means
    /// unrestricted (⊤). This is the SINGLE scope matcher — the mint-time
    /// attenuation check and any runtime scope check both call it, so they cannot
    /// drift.
    pub fn is_in_scope(&self, resource: &str) -> bool {
        if self.scope_boundary.is_empty() {
            return true;
        }
        self.scope_boundary
            .iter()
            .any(|scope| resource.starts_with(scope))
    }

    /// Does this VAID hold `capability` (exact membership)? The single
    /// capability-membership predicate.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capability_set.iter().any(|c| c == capability)
    }
}

/// Compute the canonical 32-byte SHA-256 digest of a [`Vaid`] for Ed25519
/// signing/verification.
///
/// Reuses the exact RFC 8785 (JCS) discipline the PoP primitive uses:
/// 1. serialize the whole VAID to a `serde_json::Value`, forcing
///    `kernel_signature` to JSON `null` (a signature cannot cover its own value —
///    it travels alongside the document);
/// 2. canonicalize per RFC 8785 via `serde_jcs`;
/// 3. SHA-256 the canonical bytes.
///
/// Every other field is covered, including `sig_version`, `public_key_der`,
/// `expires_at`, `scope_boundary`, `capability_set`, `parent_vaid`, and
/// `lineage_hash`.
/// Compute a lineage hash from the parent VAID chain. Root agents (no parent)
/// get a genesis hash. The hash is `SHA-256` (lowercase hex) of
/// `"{parent}:{agent_id}"`, or `"GENESIS:{agent_id}"` for a root. The Python
/// mirror computes the identical string.
pub fn compute_lineage_hash(parent_vaid: Option<VaidId>, agent_id: &AgentId) -> String {
    let mut hasher = Sha256::new();
    match parent_vaid {
        Some(parent) => hasher.update(format!("{parent}:{agent_id}").as_bytes()),
        None => hasher.update(format!("GENESIS:{agent_id}").as_bytes()),
    }
    format!("{:x}", hasher.finalize())
}

pub fn canonical_vaid_signing_bytes(vaid: &Vaid) -> Vec<u8> {
    let mut value = serde_json::to_value(vaid).expect("Vaid must be serde-serializable");
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert("kernel_signature".to_string(), serde_json::Value::Null);
    }
    let canonical =
        serde_jcs::to_vec(&value).expect("RFC 8785 canonicalization of a valid Value cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(scope: Vec<&str>, caps: Vec<&str>) -> Vaid {
        Vaid::with_lineage(
            AgentId::new(),
            AgentClass::new("x"),
            "1.0.0".into(),
            TenantId::new("t"),
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

    #[test]
    fn empty_scope_is_unrestricted() {
        assert!(doc(vec![], vec![]).is_in_scope("anything.at.all"));
    }

    #[test]
    fn scope_is_prefix_matched() {
        let v = doc(vec!["data.x"], vec![]);
        assert!(v.is_in_scope("data.x.sub"));
        assert!(!v.is_in_scope("data.y"));
    }

    #[test]
    fn capability_is_exact_membership() {
        let v = doc(vec![], vec!["read"]);
        assert!(v.has_capability("read"));
        assert!(!v.has_capability("write"));
        assert!(!v.has_capability("rea"));
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_32_bytes() {
        let v = doc(vec!["data.x"], vec!["read"]);
        let a = canonical_vaid_signing_bytes(&v);
        let b = canonical_vaid_signing_bytes(&v);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn nulling_signature_makes_bytes_independent_of_signature_value() {
        // The signing bytes must not depend on kernel_signature (it is nulled),
        // so attaching a signature does not change what the signature covers.
        let unsigned = doc(vec!["data.x"], vec!["read"]);
        let before = canonical_vaid_signing_bytes(&unsigned);
        let signed = unsigned.clone().with_kernel_signature(vec![9u8; 64]);
        let after = canonical_vaid_signing_bytes(&signed);
        assert_eq!(before, after);
    }
}

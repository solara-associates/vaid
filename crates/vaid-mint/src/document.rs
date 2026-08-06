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
//! canonical bytes are NOT pinned to the managed authority's VAID format — that
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
///
/// **v3 (ADR-0004).** v3 adds `trust_domain` and `kernel_key_thumbprint`. The
/// v2 constant is deliberately **removed** rather than retained: every use site
/// becomes a compile error, so none is missed, and no code can accidentally
/// accept a v2 document. There is no dual-version acceptance — a v2 document must
/// not verify under a v3 verifier, because accepting both would recreate the very
/// downgrade surface that signing `sig_version` exists to close.
pub const VAID_SIG_VERSION_V3: u8 = 3;

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
/// grants). v3 adds `trust_domain` and `kernel_key_thumbprint` (ADR-0004). Every
/// field except `kernel_signature` is covered by the signature.
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
    /// v3: the issuing deployment's trust domain — a constrained, DNS-shaped
    /// name (ADR-0004). Gives a verifier something to look `kernel_key_thumbprint`
    /// up **under**; a thumbprint alone is selection with nothing to select
    /// within. Compared by byte equality, never normalized.
    trust_domain: String,
    /// v3: RFC 9278 thumbprint URI over the RFC 7638 JWK thumbprint of the
    /// kernel public key that signed this document. A commitment, not a key —
    /// you cannot verify a signature with a hash, so a verifier is structurally
    /// forced to source the key from elsewhere and the trust decision stays
    /// visible. See ADR-0004 for why that failure mode, not circularity, is the
    /// reason the key itself is not embedded.
    kernel_key_thumbprint: String,
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
        trust_domain: String,
        kernel_key_thumbprint: String,
    ) -> Self {
        let vaid_id = VaidId::from_uuid(*agent_id.as_uuid());
        Self {
            sig_version: VAID_SIG_VERSION_V3,
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
            trust_domain,
            kernel_key_thumbprint,
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
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
    pub fn kernel_key_thumbprint(&self) -> &str {
        &self.kernel_key_thumbprint
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
        scope_contains(&self.scope_boundary, resource)
    }

    /// Does this VAID hold `capability` (exact membership)? The single
    /// capability-membership predicate.
    pub fn has_capability(&self, capability: &str) -> bool {
        caps_contain(&self.capability_set, capability)
    }
}

/// The reserved hierarchy separators (spec `docs/spec/scope.md` S.2).
///
/// Both are normative and both are always honoured. A scope segment MUST NOT
/// contain either — that constraint is what makes honouring both safe rather
/// than widening, and it is the reason this set is fixed by the specification
/// instead of being a property of a deployment. See [`scope_contains`].
pub const SCOPE_SEPARATORS: [char; 2] = ['/', '.'];

/// Is `resource` within `boundary`? An empty boundary means unrestricted (⊤).
///
/// This is THE scope matcher. [`Vaid::is_in_scope`] delegates here rather than
/// implementing it, so a caller holding a bare boundary — a consent attestation's
/// `scope_boundary`, which is not attached to any document — is matched by exactly
/// the same rule as a document's own. Duplicating the rule for the detached case is
/// how the two would drift.
///
/// # Containment is segment-bounded (spec S.3)
///
/// A boundary entry `P` contains a resource `R` iff `R == P`, or `P` ends with a
/// separator and `R` starts with `P`, or `R` starts with `P` followed by a
/// separator. **Bare prefix matching is not containment.**
///
/// Until 0.5.0 this was `R.starts_with(P)`, which made `data.governance` contain
/// `data.governance-secret` — a *sibling*, sharing a textual prefix and nothing
/// else. Because this same predicate decides mint-time attenuation
/// (`scope_attenuates`) and third-party chain verification
/// ([`crate::chain::verify_chain`]), that let a child be delegated authority its
/// parent never held, and let a verifier confirm the delegation as legitimate.
/// The rule below is **strictly narrower**: it denies cases the old one allowed
/// and permits nothing new, so no previously-rejected delegation becomes
/// possible.
///
/// # Why both separators, always
///
/// Honouring only one would break real deployments in opposite directions — a
/// `.`-only rule stops `t/research` containing `t/research/sub`, a `/`-only rule
/// stops `data.governance` containing `data.governance.reports`. Making the set
/// a deployment setting is worse still: under ADR-0003 a **third party**
/// recomputes containment from a presented chain, and a deployment-local rule
/// leaves it unable to reproduce the mint's verdict.
///
/// So both are reserved by the specification, and a segment MUST NOT contain
/// either (S.2). That constraint is doing the safety work. Without it, an
/// implementer treating `/` as their separator and `.` as an ordinary character
/// would find `data/user` containing `data/user.admin` — the same
/// sibling-capture bug in the other separator. With it, `data/user.admin` is
/// unambiguously the path `data`, `user`, `admin`, and containment is correct.
///
/// The segment constraint is normative on producers but is **not enforced here**
/// in 0.5.0; enforcement would reject documents this version accepts, which is a
/// second breaking change. See `docs/spec/scope.md` S.6.
///
/// Formulated with only `==`, `starts_with`, `ends_with` and concatenation — no
/// character indexing — so Rust (bytes), Python (code points) and TypeScript
/// (UTF-16) cannot diverge on a multi-byte boundary.
pub fn scope_contains(boundary: &[String], resource: &str) -> bool {
    if boundary.is_empty() {
        return true;
    }
    boundary.iter().any(|scope| prefix_contains(scope, resource))
}

/// Does a single boundary entry `prefix` contain `resource`? The one-entry core
/// of [`scope_contains`], split out so the rule is stated exactly once.
///
/// An empty entry matches everything, preserving the match-all that an empty
/// string had under prefix matching. It is unreachable from a well-formed
/// boundary (an empty *list* is the way to say ⊤) and is kept only so the rule
/// is total.
fn prefix_contains(prefix: &str, resource: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if resource == prefix {
        return true;
    }
    // A trailing separator already marks the boundary, so plain prefixing is
    // containment — `data.` contains `data.x` without needing a second dot.
    if SCOPE_SEPARATORS.iter().any(|sep| prefix.ends_with(*sep)) {
        return resource.starts_with(prefix);
    }
    SCOPE_SEPARATORS
        .iter()
        .any(|sep| resource.starts_with(&format!("{prefix}{sep}")))
}

/// Does `capabilities` hold `capability` (exact membership)? THE capability
/// matcher; [`Vaid::has_capability`] delegates here, for the same reason.
pub fn caps_contain(capabilities: &[String], capability: &str) -> bool {
    capabilities.iter().any(|c| c == capability)
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
            "vaid.example".into(),
            crate::issuer_identity::kernel_key_thumbprint(&[0u8; 32]),
        )
    }

    #[test]
    fn empty_scope_is_unrestricted() {
        assert!(doc(vec![], vec![]).is_in_scope("anything.at.all"));
    }

    #[test]
    fn scope_is_segment_matched() {
        let v = doc(vec!["data.x"], vec![]);
        assert!(v.is_in_scope("data.x.sub"));
        assert!(!v.is_in_scope("data.y"));
    }

    /// THE regression this rule exists for. `data.governance-secret` is a
    /// SIBLING of `data.governance`: it shares a textual prefix and nothing else.
    /// Prefix matching called it contained, so it could be delegated to a child
    /// of a `data.governance` parent and a third-party verifier would confirm the
    /// delegation.
    #[test]
    fn a_sibling_sharing_a_textual_prefix_is_not_contained() {
        let v = doc(vec!["data.governance"], vec![]);
        assert!(v.is_in_scope("data.governance"), "the entry contains itself");
        assert!(v.is_in_scope("data.governance.reports"), "a real child");
        assert!(
            !v.is_in_scope("data.governance-secret"),
            "a hyphenated sibling must NOT be contained — this is the bug"
        );
        assert!(!v.is_in_scope("data.governanceX"));
        assert!(!v.is_in_scope("data.governance2"));
    }

    /// Both separators, always — the union rule (spec S.3). Neither convention
    /// may be privileged, because a verifier recomputing containment under
    /// ADR-0003 has no way to learn which one a deployment meant.
    #[test]
    fn both_reserved_separators_are_honoured() {
        let slash = doc(vec!["t/research"], vec![]);
        assert!(slash.is_in_scope("t/research/sub"));
        assert!(!slash.is_in_scope("t/research-secret"));

        let dot = doc(vec!["data.governance"], vec![]);
        assert!(dot.is_in_scope("data.governance.reports"));

        // Mixed: `.` is a separator by fiat, so this is the path a,b,c — NOT a
        // segment literally named `b.c`. That is exactly what S.2 reserves.
        let mixed = doc(vec!["a/b"], vec![]);
        assert!(mixed.is_in_scope("a/b.c"));
        assert!(mixed.is_in_scope("a/b/c"));
        assert!(!mixed.is_in_scope("a/bc"));
    }

    /// An entry already ending in a separator needs no second one.
    #[test]
    fn a_trailing_separator_entry_matches_by_plain_prefix() {
        let v = doc(vec!["data."], vec![]);
        assert!(v.is_in_scope("data.x"));
        assert!(v.is_in_scope("data.."));
        assert!(!v.is_in_scope("datax"));

        let s = doc(vec!["t/"], vec![]);
        assert!(s.is_in_scope("t/x"));
        assert!(!s.is_in_scope("tx"));
    }

    /// The new rule permits NOTHING the old one denied. Stated as a property
    /// rather than as examples, because "strictly narrower" is the whole safety
    /// argument for shipping this as a minor bump: no previously-rejected
    /// delegation can become possible.
    #[test]
    fn the_rule_is_strictly_narrower_than_bare_prefix_matching() {
        let alphabet = ["a", "b", ".", "/", "-", ""];
        let mut corpus: Vec<String> = Vec::new();
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    corpus.push(format!("{a}{b}{c}"));
                }
            }
        }
        corpus.sort();
        corpus.dedup();

        let mut narrowed = 0usize;
        for p in &corpus {
            for r in &corpus {
                let old = r.starts_with(p.as_str());
                let new = prefix_contains(p, r);
                if new && !old {
                    panic!(
                        "WIDENING: {p:?} now contains {r:?} but did not before — the \
                         new rule must never permit what bare prefixing denied"
                    );
                }
                if old && !new {
                    narrowed += 1;
                }
            }
        }
        assert!(
            narrowed > 0,
            "the rule must actually deny something, or it changed nothing"
        );
    }

    /// Multi-byte input must not be split differently by byte/code-point/UTF-16
    /// length. The rule uses no character indexing; this pins that.
    #[test]
    fn multibyte_segments_are_handled_consistently() {
        let v = doc(vec!["data.données"], vec![]);
        assert!(v.is_in_scope("data.données"));
        assert!(v.is_in_scope("data.données.sub"));
        assert!(!v.is_in_scope("data.donnéesX"));
        assert!(!v.is_in_scope("data.donné"));
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

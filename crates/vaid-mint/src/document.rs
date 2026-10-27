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
///
/// **v4 (ADR-0009).** v4 types `scope_boundary`: its entries become
/// `{"kind": ..., "value": ...}` objects rather than bare strings. No member is
/// added or removed, but the type of an existing member's elements changes, so
/// the canonical bytes of every document with a non-empty boundary move.
///
/// The v3 constant is removed for exactly the reason the v2 one was. It is also
/// the case that keeping both would be forbidden rather than merely unwise:
/// ADR-0010 states that a verifier MAY accept two `sig_version` values only
/// where they require the SAME members, and that if two accepted values do not,
/// one is a downgrade of the other. A v3 document's boundary entries are
/// strings; a v4 document's are objects. They do not require the same shape, so
/// `{3, 4}` is forbidden and there is no legacy acceptance to write.
pub const VAID_SIG_VERSION_V4: u8 = 4;

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

/// Render an instant into the E.6 profile: whole-second RFC 3339, UTC, literal
/// `Z`. The one place a `DateTime` becomes a document timestamp.
///
/// Truncating rather than rejecting is safe in the only direction it moves: it
/// can shorten a validity window by under a second, never extend one.
pub(crate) fn format_e6(instant: DateTime<Utc>) -> String {
    instant.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse an RFC 3339 timestamp **permissively**, or `None`.
///
/// Permissive on purpose, and it must stay total: this is what [`Vaid::is_expired`]
/// uses, and conformance to the narrower E.6 profile is a separate question asked
/// separately by [`Vaid::has_conforming_timestamps`]. That split is issue #10,
/// already settled the same way in Python and TypeScript; this is Rust adopting
/// it now that the field is a string rather than a pre-parsed instant.
pub(crate) fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Does `value` match the E.6 profile exactly — whole-second RFC 3339 in UTC with
/// a literal `Z`?
///
/// Checked with explicit character tests rather than a regular expression, per
/// E.6's own guidance: the three languages' regex dialects disagree, and this
/// predicate must give the same answer in all of them.
pub(crate) fn is_e6_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
        && parse_rfc3339(value).is_some()
}

/// Deserialize a member as PRESENT, distinguishing it from an absent one.
///
/// `Option<Option<T>>` does not do this on its own: serde's `Option` deserializer
/// answers `None` for a JSON `null`, so a present null and a missing member both
/// arrive as the outer `None` and the distinction is gone before anything can use
/// it. This is only called when the key is present — `#[serde(default)]` covers
/// the absent case — so wrapping unconditionally in `Some` is exactly the
/// presence bit that was being lost.
///
/// Found by the chain vector: without this, a root document's present
/// `"parent_vaid": null` collapsed to absent, `skip_serializing_if` then dropped
/// the member, and the frozen hop digest moved. The vector caught a bug in the
/// fix for a bug the vectors could not previously see.
fn deserialize_present<'de, D>(deserializer: D) -> Result<Option<Option<PresentedUuid>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<PresentedUuid>::deserialize(deserializer).map(Some)
}

/// A UUID-valued member, kept **exactly as it was presented** alongside its
/// parsed value.
///
/// # Why this type exists (ADR-0006 Requirement 3, BACKLOG B7)
///
/// ADR-0006 requires that parsing a document and re-serializing it reproduce the
/// presented object, "so that canonicalization is a function of the input alone".
/// A bare `Uuid` field does not satisfy that. `uuid` accepts several spellings of
/// the same value — uppercase, braced, `urn:uuid:`-prefixed, hyphenless — and
/// **normalizes every one of them to lowercase-hyphenated on the way out**. A
/// document presented in any of those forms was therefore canonicalized as a
/// *different byte string* than the one the caller supplied, and the verifier
/// returned a verdict about bytes nobody sent.
///
/// That is the same defect ADR-0006 was written for, one layer down: ADR-0006
/// closed it for unrecognised *members* (the `unknown_fields` capture map) and
/// left it open for recognised members whose *values* have more than one
/// spelling. It was not theoretical — Rust reported `authentic = true` for
/// documents whose `vaid_id` had been rewritten into an equivalent spelling
/// **after signing**, while Python and TypeScript correctly refused them.
///
/// # Why parse eagerly here, but not for timestamps
///
/// A document whose `vaid_id` is not a UUID has no identity: it cannot be placed
/// in a lineage, so there is nothing to have an opinion about, and refusing to
/// parse it is the honest answer. A document whose `expires_at` is unreadable
/// still has an identity — it is simply not one that can be shown to be
/// unexpired, which is a *verdict* ([`Vaid::is_expired`] fails closed) rather
/// than a parse failure. So UUIDs are validated at deserialization and timestamps
/// are not, and that asymmetry is a decision rather than an accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedUuid {
    /// The member exactly as presented. This is what is serialized, and therefore
    /// what is canonicalized and signed over.
    raw: String,
    /// The parsed value. Validated at deserialization, so this cannot be absent.
    uuid: Uuid,
}

impl PresentedUuid {
    /// The UUID this member denotes.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
    /// The member exactly as presented — the bytes a signature covers.
    pub fn as_presented(&self) -> &str {
        &self.raw
    }
    /// Is this member written in the canonical lowercase-hyphenated form?
    ///
    /// Presenting a non-canonical spelling is legal and verifies; a *producer*
    /// should still emit the canonical one, and this is how that is asked.
    pub fn is_canonical(&self) -> bool {
        self.raw == self.uuid.to_string()
    }
}

impl From<Uuid> for PresentedUuid {
    /// Build from a value rather than from presented bytes — the mint's path.
    /// Produces the canonical spelling by construction.
    fn from(uuid: Uuid) -> Self {
        Self {
            raw: uuid.to_string(),
            uuid,
        }
    }
}

impl Serialize for PresentedUuid {
    /// Emits the presented form, never a re-rendering of the parsed value. This
    /// one line is the whole of ADR-0006 Requirement 3 for this member.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for PresentedUuid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&raw).map_err(serde::de::Error::custom)?;
        Ok(Self { raw, uuid })
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
    vaid_id: PresentedUuid,
    agent_id: PresentedUuid,
    agent_class: AgentClass,
    version: String,
    tenant_id: TenantId,
    /// Kept as the presented string, not a parsed instant (ADR-0006 Req. 3).
    /// `chrono` normalizes `+00:00` to `Z` and drops or adds sub-second digits on
    /// re-serialization, so a parsed field canonicalized a different byte string
    /// than the one presented — see [`PresentedUuid`] for the same defect on the
    /// identity members. Unlike those, this is NOT validated at deserialization:
    /// a document with an unreadable expiry still has an identity, and "cannot be
    /// shown to be unexpired" is a verdict ([`Vaid::is_expired`], which fails
    /// closed) rather than a parse failure.
    issued_at: String,
    expires_at: String,
    public_key_der: Vec<u8>,
    kernel_signature: Vec<u8>,
    /// VAID of the spawning agent. Root agents have no parent (`None`).
    ///
    /// **Three states, not two** (ADR-0006 Req. 3). `Option<PresentedUuid>` cannot
    /// tell an ABSENT member from a member present as JSON `null`, and serde
    /// renders `None` as `null` on the way out — so a document with `parent_vaid`
    /// *deleted* re-serialized with it restored, reproducing bytes the presenter
    /// never sent and verifying against a signature that covered them. The outer
    /// `Option` is presence; the inner is the value. E.7 requires a root document
    /// to carry a PRESENT null, and `skip_serializing_if` keeps an absent member
    /// absent rather than inventing one.
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    parent_vaid: Option<Option<PresentedUuid>>,
    /// Data domains / resource namespaces this agent may operate within. v4
    /// types the entries: see [`ScopeBoundaryEntry`] and `docs/spec/scope.md`
    /// S.8.
    scope_boundary: Vec<ScopeBoundaryEntry>,
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
    /// Every field of the presented document this struct does not name.
    ///
    /// A verifier MUST canonicalize the bytes it was PRESENTED, not its own
    /// projection of them. Without this map, serde's default
    /// ignore-unknown-fields silently discarded any additive extension before
    /// [`canonical_vaid_signing_bytes`] ran, so this implementation hashed a
    /// document nobody sent and returned a verdict about it. See ADR-0006.
    ///
    /// `flatten` puts these back at the top level on serialize, so the canonical
    /// bytes reproduce the presented key set exactly. A document minted here has
    /// an empty map and is byte-identical to one minted before this existed —
    /// `mint_v1.json` is unaffected.
    #[serde(flatten)]
    unknown_fields: std::collections::BTreeMap<String, serde_json::Value>,
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
        scope_boundary: Vec<ScopeBoundaryEntry>,
        lineage_hash: String,
        capability_set: Vec<String>,
        trust_domain: String,
        kernel_key_thumbprint: String,
    ) -> Self {
        let vaid_id = PresentedUuid::from(*agent_id.as_uuid());
        Self {
            sig_version: VAID_SIG_VERSION_V4,
            vaid_id,
            agent_id: PresentedUuid::from(*agent_id.as_uuid()),
            agent_class,
            version,
            tenant_id,
            // Rendered into the E.6 profile HERE, so a document built through this
            // constructor cannot carry a non-conforming timestamp regardless of the
            // precision the caller's clock happened to have (BACKLOG B8).
            issued_at: format_e6(issued_at),
            expires_at: format_e6(expires_at),
            public_key_der,
            kernel_signature,
            // A minted document always carries the member — present-null for a root
            // (E.7) — so `mint_v1.json` is byte-identical to before this change.
            parent_vaid: Some(parent_vaid.map(|p| PresentedUuid::from(*p.as_uuid()))),
            scope_boundary,
            lineage_hash,
            capability_set,
            trust_domain,
            kernel_key_thumbprint,
            unknown_fields: std::collections::BTreeMap::new(),
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
        VaidId::from_uuid(self.vaid_id.uuid())
    }
    /// `vaid_id` exactly as presented, including a non-canonical spelling.
    pub fn vaid_id_as_presented(&self) -> &str {
        self.vaid_id.as_presented()
    }
    pub fn agent_id(&self) -> AgentId {
        AgentId::from_uuid(self.agent_id.uuid())
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
    /// `issued_at`, parsed — `None` when the presented value is not a readable
    /// RFC 3339 timestamp. **This return type changed**: it was
    /// `DateTime<Utc>`, which was only total because the field used to be parsed
    /// at deserialization, which is the behaviour ADR-0006 Req. 3 forbids.
    pub fn issued_at(&self) -> Option<DateTime<Utc>> {
        parse_rfc3339(&self.issued_at)
    }
    /// `issued_at` exactly as presented — the bytes the signature covers.
    pub fn issued_at_as_presented(&self) -> &str {
        &self.issued_at
    }
    /// `expires_at`, parsed — `None` when the presented value is not a readable
    /// RFC 3339 timestamp. See [`Vaid::is_expired`] for what `None` means.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        parse_rfc3339(&self.expires_at)
    }
    /// `expires_at` exactly as presented — the bytes the signature covers.
    pub fn expires_at_as_presented(&self) -> &str {
        &self.expires_at
    }
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }
    pub fn kernel_signature(&self) -> &[u8] {
        &self.kernel_signature
    }
    pub fn parent_vaid(&self) -> Option<VaidId> {
        self.parent_vaid
            .as_ref()
            .and_then(|p| p.as_ref())
            .map(|p| VaidId::from_uuid(p.uuid()))
    }
    pub fn scope_boundary(&self) -> &[ScopeBoundaryEntry] {
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
    /// Members of the presented document this type does not name, preserved so
    /// canonicalization covers the bytes as presented (ADR-0006). Empty for any
    /// document this crate minted. Exposed read-only so a caller can SEE an
    /// extension it does not understand and decide what to do about it, rather
    /// than being unable to tell one was there.
    pub fn unknown_fields(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        &self.unknown_fields
    }

    /// True once past `expires_at`.
    ///
    /// **Total, and fails closed.** An `expires_at` that cannot be parsed returns
    /// `true` — a document whose expiry cannot be read is not a document that can
    /// be shown to be unexpired. That path became reachable in Rust when this
    /// field stopped being parsed at deserialization (ADR-0006 Req. 3), and it is
    /// stated here rather than left to be discovered. Python and TypeScript have
    /// always behaved this way; this is the third implementation arriving at the
    /// rule the other two already had, not a new rule.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// [`is_expired`](Vaid::is_expired) against a **given** instant rather than
    /// the wall clock.
    ///
    /// The same predicate with the clock read lifted out. `is_expired` is the
    /// convenience for a caller with no reason to control time; anything that must
    /// be reproducible — a conformance vector, a boundary case, replaying a
    /// historical decision — asks at a stated instant instead, and
    /// [`verify_chain_at`](crate::chain::verify_chain_at) passes its own `now`
    /// down here so a chain's verdict does not depend on when the suite happened
    /// to run (BACKLOG B9, on the verify side).
    ///
    /// Fails closed identically. The boundary is `now > expires_at`, so a document
    /// is live **at** its own `expires_at` and expired the first instant after it —
    /// stated because the three implementations must agree on the boundary and not
    /// merely on the interior.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at() {
            Some(expires_at) => now > expires_at,
            None => true,
        }
    }

    /// Do `issued_at` and `expires_at` match the E.6 profile exactly — whole-second
    /// RFC 3339 in UTC with a literal `Z`?
    ///
    /// The Rust half of the issue-#10 split, and **it was missing**. The Python and
    /// TypeScript twins have carried `has_conforming_timestamps` since that issue
    /// was settled, and this crate's own CHANGELOG announces it under a released
    /// version — but the function was never written here. Nothing in Rust could ask
    /// whether a document met the profile, which is the direct reason the mint was
    /// able to emit non-conforming timestamps for as long as it did (BACKLOG B8):
    /// the check that would have caught it had been promised and not built.
    ///
    /// Because this type holds `DateTime<Utc>` rather than the presented string,
    /// the question reduces exactly to whether the instants carry sub-second
    /// precision — a `DateTime<Utc>` with zero nanoseconds re-serializes to
    /// `…:SSZ` and one with any does not. Offset and case cannot vary here; they
    /// are properties of a *string*, and this type has already parsed one. The
    /// Python and TypeScript versions test the string because that is what they
    /// hold, and all three therefore answer the same question about the same
    /// document by whatever route their representation allows.
    ///
    /// Not consulted by authenticity verification: E.6 exists so that a signer's
    /// bytes and a verifier's recomputation agree, so a non-conforming timestamp
    /// shows up there as a signature failure. This is how that failure is
    /// *explained* rather than merely observed.
    pub fn has_conforming_timestamps(&self) -> bool {
        is_e6_timestamp(&self.issued_at) && is_e6_timestamp(&self.expires_at)
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

/// The one scope-boundary kind v4 defines: today's resource-prefix semantics,
/// unchanged from the bare-string form it replaces (spec S.3).
pub const SCOPE_KIND_PREFIX: &str = "prefix";

/// THE recognised-kind registry (spec S.7, S.10).
///
/// Stated once, and consulted by both the matcher ([`scope_contains`]) and the
/// standing verdict ([`crate::verify::verify_vaid`]). Two copies of this list is
/// how a kind gets recognised by one and not the other, which is the fail-closed
/// rule of S.10 failing open. `scope_kinds_v1.json` declares the same list and
/// is checked against this constant directly, so a kind added here without being
/// added to the specification fails conformance, and so does the reverse.
pub const RECOGNISED_SCOPE_KINDS: [&str; 1] = [SCOPE_KIND_PREFIX];

/// A build that recognises no kind contains every boundary in nothing, so the
/// registry must never be empty. Asserted at COMPILE time rather than in a test,
/// because the registry is a constant and a runtime assertion over it is vacuous
/// (clippy's `const_is_empty`). The Python and TypeScript twins assert the same
/// thing in their conformance gates, which is the earliest point either of them
/// can.
const _: () = assert!(!RECOGNISED_SCOPE_KINDS.is_empty());

/// One typed entry of a [`Vaid`]'s `scope_boundary` (spec S.8).
///
/// ```json
/// { "kind": "prefix", "value": "orders/123/" }
/// ```
///
/// `kind` names the sort of boundary; `value`'s JSON type is fixed by the kind.
/// An entry carries NO other member, and `Deserialize` refuses one that does.
///
/// # Why `value` is a `serde_json::Value` and `kind` is a `String`
///
/// The obvious Rust shape is an adjacently-tagged enum
/// (`#[serde(tag = "kind", content = "value")]`), and it is wrong here. Serde
/// refuses an unknown variant at DESERIALIZATION, so an unrecognised kind would
/// be a parse failure in Rust and a verdict over an authentic document in Python
/// and TypeScript, which have no such gate. The booleans would agree and the
/// REASONS would not, for an authentic future-version credential: precisely the
/// cross-implementation divergence `verdict_v1.json` exists to police, and
/// precisely the distinction S.10 draws. So the entry is parsed structurally and
/// classified afterwards, by the same two steps in all three implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeBoundaryEntry {
    kind: String,
    value: serde_json::Value,
}

impl ScopeBoundaryEntry {
    /// A `prefix` entry over `value`. The only kind v4 defines, so this is the
    /// constructor a producer wants.
    pub fn prefix(value: impl Into<String>) -> Self {
        Self {
            kind: SCOPE_KIND_PREFIX.to_string(),
            value: serde_json::Value::String(value.into()),
        }
    }

    /// An entry of an arbitrary kind, subject to the same validation
    /// `Deserialize` applies, so an entry that could not have been parsed cannot
    /// be constructed either. Public because the conformance vector's
    /// unrecognised-kind cases are built in-process rather than parsed, and
    /// because the matcher's refusal path must be reachable from a bare boundary
    /// that never passed document verify.
    pub fn new(kind: impl Into<String>, value: serde_json::Value) -> Result<Self, String> {
        let kind = kind.into();
        validate_scope_entry(&kind, &value)?;
        Ok(Self { kind, value })
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// The in-process convenience for the only kind v4 defines: a bare string is a
/// `prefix` entry.
///
/// This is NOT a wire-level fallback, and the distinction matters. `Deserialize`
/// refuses a bare string outright (S.8), so no document can reach a verifier in
/// the old form and be quietly reinterpreted. This conversion exists only for
/// callers constructing a boundary in process, where `prefix` is the only kind
/// there is to mean.
impl From<&str> for ScopeBoundaryEntry {
    fn from(value: &str) -> Self {
        Self::prefix(value)
    }
}

impl From<String> for ScopeBoundaryEntry {
    fn from(value: String) -> Self {
        Self::prefix(value)
    }
}

/// Compare an entry to a bare string, meaning its `prefix` value. Lets an
/// assertion over a boundary stay readable without spelling out an entry
/// literal; an entry of any other kind equals no string.
impl PartialEq<&str> for ScopeBoundaryEntry {
    fn eq(&self, other: &&str) -> bool {
        self.kind == SCOPE_KIND_PREFIX && self.value.as_str() == Some(*other)
    }
}

/// The entry-shape rule of S.8, stated once and applied by both
/// [`ScopeBoundaryEntry::new`] and `Deserialize`.
///
/// For a RECOGNISED kind the `value` type is fixed and checked here, so a
/// `prefix` entry carrying a number makes the document unparseable. For an
/// unrecognised kind the `value` is NOT inspected: this implementation does not
/// know what type a later kind's value takes, and guessing would mean refusing
/// an authentic future document for a reason it invented. That entry parses, and
/// S.10 refuses it at verify instead.
fn validate_scope_entry(kind: &str, value: &serde_json::Value) -> Result<(), String> {
    if kind.is_empty() {
        return Err("scope_boundary entry `kind` must be a non-empty string".to_string());
    }
    if kind == SCOPE_KIND_PREFIX && !value.is_string() {
        return Err(format!(
            "scope_boundary entry of kind `{SCOPE_KIND_PREFIX}` must carry a string `value`"
        ));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ScopeBoundaryEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// `deny_unknown_fields` is the S.11 asymmetry with ADR-0006, in one
        /// attribute. At DOCUMENT level an unknown member is preserved, because
        /// it sits outside every predicate a verifier computes. Inside an entry
        /// there is no outside: every member is part of the authority the entry
        /// states, so a verifier that ignored `{"kind": "prefix", "value": "a",
        /// "max": 5}` would compute a boundary strictly wider than the one the
        /// signer committed to, and would do it silently.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            kind: String,
            value: serde_json::Value,
        }
        let raw = Raw::deserialize(deserializer)?;
        validate_scope_entry(&raw.kind, &raw.value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            kind: raw.kind,
            value: raw.value,
        })
    }
}

/// Evaluate ONE entry against `resource`.
///
/// `None` means this implementation cannot evaluate the entry at all: its kind
/// is not in [`RECOGNISED_SCOPE_KINDS`], or it is of a recognised kind whose
/// `value` is not the type that kind fixes. This is the ONLY `match` on `kind`
/// in the crate; adding a kind means adding an arm here and a name to the
/// registry, and nothing else reads a kind.
fn entry_contains(entry: &ScopeBoundaryEntry, resource: &str) -> Option<bool> {
    match entry.kind.as_str() {
        SCOPE_KIND_PREFIX => entry.value.as_str().map(|p| prefix_contains(p, resource)),
        _ => None,
    }
}

/// The resource a child entry CLAIMS, for the attenuation predicate. `None`
/// when the entry is not one this implementation can evaluate.
///
/// For the `prefix` kind a boundary and a resource are the same shape, which is
/// why attenuation has always been decidable with the containment predicate: a
/// child entry is fed to the matcher as if it were a resource, so mint-time and
/// verify-time cannot answer differently. A future kind whose boundary is not
/// resource-shaped will need its own containment rule rather than this
/// projection; `docs/spec/scope.md` S.13 records that as a constraint on the
/// next revision.
///
/// This is the crate's SECOND and last `match` on `kind`.
/// `every_registered_kind_is_one_the_matcher_can_evaluate` asserts that both it
/// and [`entry_contains`] answer for every name in
/// [`RECOGNISED_SCOPE_KINDS`], so a kind cannot be added to the registry and
/// one of the two matches and not the other.
pub fn entry_claimed_resource(entry: &ScopeBoundaryEntry) -> Option<&str> {
    match entry.kind.as_str() {
        SCOPE_KIND_PREFIX => entry.value.as_str(),
        _ => None,
    }
}

/// Can `entry` be evaluated here at all?
///
/// DERIVED from [`entry_contains`] rather than restated, so a kind cannot be
/// added to one and forgotten in the other. Whether `entry_contains` returns
/// `Some` is a property of the entry alone and never of the resource, which is
/// what makes deriving it from a single arbitrary resource exact rather than
/// approximate. `evaluability_does_not_depend_on_the_resource` asserts that
/// over every boundary in the conformance vector.
fn entry_is_evaluable(entry: &ScopeBoundaryEntry) -> bool {
    entry_contains(entry, "").is_some()
}

/// Can every entry of `boundary` be evaluated here (spec S.10)?
///
/// `false` is the S.10 refusal condition, and it is a property of the boundary
/// alone: a verifier reports it over a document rather than over a request, so
/// the standing verdict can reach it without having a resource in hand.
pub fn boundary_is_evaluable(boundary: &[ScopeBoundaryEntry]) -> bool {
    boundary.iter().all(entry_is_evaluable)
}

/// Is `resource` within `boundary`? An empty boundary means unrestricted (⊤).
///
/// This is THE scope matcher. [`Vaid::is_in_scope`] delegates here rather than
/// implementing it, so a caller holding a bare boundary — a consent attestation's
/// `scope_boundary`, which is not attached to any document — is matched by exactly
/// the same rule as a document's own. Duplicating the rule for the detached case is
/// how the two would drift.
///
/// # An entry this implementation cannot read refuses the WHOLE boundary (S.10)
///
/// Not just itself. The natural implementation of a union is
/// `boundary.iter().any(..)`, and the natural implementation returns `true` for
/// a boundary of a satisfied `prefix` entry plus one unrecognised entry: it
/// finds the match and never reaches the entry it cannot read. An unrecognised
/// kind can only ever NARROW what the signer meant, so skipping it grants
/// authority the signer withheld. The loop below therefore refuses on the first
/// unevaluable entry even when a match is already in hand.
///
/// This is reachable from a bare boundary that never passed document verify, so
/// the refusal lives here and not only in [`crate::verify::verify_vaid`].
///
/// # Containment is segment-bounded for the `prefix` kind (spec S.3)
///
/// A `prefix` entry whose `value` is `P` contains a resource `R` iff `R == P`,
/// or `P` ends with a separator and `R` starts with `P`, or `R` starts with `P`
/// followed by a separator. **Bare prefix matching is not containment.**
///
/// Until 0.5.0 this was `R.starts_with(P)`, which made `data.governance` contain
/// `data.governance-secret` — a *sibling*, sharing a textual prefix and nothing
/// else. Because this same predicate decides mint-time attenuation
/// (`scope_attenuates`) and third-party chain verification
/// ([`crate::chain::verify_chain`]), that let a child be delegated authority its
/// parent never held, and let a verifier confirm the delegation as legitimate.
/// The rule below is **strictly narrower**: it denies cases the old one allowed
/// and permits nothing new, so no previously-rejected delegation becomes
/// possible. v4 typed the entries and did not touch the rule.
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
/// The segment constraint is normative on producers but is **not enforced here**;
/// enforcement would reject documents this version accepts, which is a further
/// breaking change. See `docs/spec/scope.md` S.6.
///
/// Formulated with only `==`, `starts_with`, `ends_with` and concatenation — no
/// character indexing — so Rust (bytes), Python (code points) and TypeScript
/// (UTF-16) cannot diverge on a multi-byte boundary.
pub fn scope_contains(boundary: &[ScopeBoundaryEntry], resource: &str) -> bool {
    let mut contained = false;
    for entry in boundary {
        match entry_contains(entry, resource) {
            // S.10: refuse the whole boundary, even with a match already found.
            None => return false,
            Some(true) => contained = true,
            Some(false) => {}
        }
    }
    boundary.is_empty() || contained
}

/// Does a single `prefix` value contain `resource`? The one-entry core of
/// [`scope_contains`], split out so the rule is stated exactly once.
///
/// An empty value matches everything, preserving the match-all that an empty
/// string had under the bare-string form. It is unreachable from a well-formed
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

/// Does `json` contain a repeated member name inside any single object, at any
/// depth?
///
/// # Why this is checked explicitly rather than left to the parser (BACKLOG B7)
///
/// The three languages' JSON parsers disagree, and the disagreement is silent.
/// `serde` rejects a repeated field on a typed struct; `json.loads` and
/// `JSON.parse` both keep the **last** occurrence and discard the earlier ones
/// without a word. So `{"sig_version": 3, "sig_version": 2}` was refused outright
/// by Rust and read as `2` by the other two — one implementation declining to
/// parse a document the others declared authentic.
///
/// Last-wins is the dangerous half. A signed document is a statement about a
/// specific byte string; silently choosing one of two competing values for a
/// member and verifying the result means the reader and the signer may disagree
/// about what was signed, with nothing in the verdict to indicate it. That is a
/// classic parser-differential, and the safe direction is the one that refuses.
///
/// So the rule is normative (`docs/spec/encoding.md` E.7a) and implemented the
/// same way in all three: **a document containing a duplicate member name is not
/// a document.** Rust's parser already refused the struct-field case; this
/// extends the same answer to nested and unrecognised members, which `serde`
/// would otherwise resolve by last-wins inside a `Value`.
///
/// Scans the raw text because that is the only place the evidence survives — by
/// the time any of the three has a parsed object, the duplicate is gone.
pub fn has_duplicate_member_names(json: &str) -> bool {
    let b = json.as_bytes();
    let mut i = 0usize;
    // One set of seen names per open object; `None` marks an open array, which
    // has no member names of its own but must still be tracked so that a string
    // inside it is never mistaken for a key.
    let mut stack: Vec<Option<std::collections::HashSet<String>>> = Vec::new();

    while i < b.len() {
        match b[i] {
            b'{' => {
                stack.push(Some(std::collections::HashSet::new()));
                i += 1;
            }
            b'[' => {
                stack.push(None);
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b'"' => {
                let (text, next) = match scan_json_string(b, i) {
                    Some(pair) => pair,
                    // Unterminated string: not our error to report. Whatever parses
                    // this next will refuse it, and claiming "duplicate" here would
                    // be the wrong reason.
                    None => return false,
                };
                // A string is a KEY only if the next non-whitespace byte is ':'.
                let mut j = next;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() && b[j] == b':' {
                    if let Some(Some(seen)) = stack.last_mut() {
                        if !seen.insert(text) {
                            return true;
                        }
                    }
                }
                i = next;
            }
            _ => i += 1,
        }
    }
    false
}

/// Read a JSON string starting at `start` (which must be the opening quote),
/// returning its decoded-enough text and the index just past the closing quote.
///
/// "Decoded enough" means escapes are consumed so they cannot hide a quote, and
/// `\\uXXXX` is left as written: two member names that differ only by escaping are
/// the same name to a conforming parser, but treating them as different here can
/// only ever MISS a duplicate, never invent one — and missing is the direction
/// that leaves the existing parsers in charge rather than overruling them.
fn scan_json_string(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                if i + 1 >= b.len() {
                    return None;
                }
                out.push('\\');
                out.push(b[i + 1] as char);
                i += 2;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    None
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::has_duplicate_member_names;

    #[test]
    fn finds_a_duplicate_at_the_top_level() {
        assert!(has_duplicate_member_names(r#"{"a":1,"a":2}"#));
    }

    #[test]
    fn finds_a_duplicate_nested_inside_an_extension() {
        assert!(has_duplicate_member_names(r#"{"x":{"a":1,"a":2}}"#));
    }

    #[test]
    fn the_same_name_at_different_depths_is_not_a_duplicate() {
        // THE CONTROL for over-firing: a checker that flagged this would reject
        // every real document, and would pass a naive positive test while doing so.
        assert!(!has_duplicate_member_names(r#"{"a":1,"b":{"a":2}}"#));
    }

    #[test]
    fn repeated_strings_in_an_array_are_values_not_keys() {
        assert!(!has_duplicate_member_names(r#"{"s":["a","a"]}"#));
        assert!(!has_duplicate_member_names(r#"{"s":[{"a":1},{"a":1}]}"#));
    }

    #[test]
    fn a_value_that_looks_like_a_key_is_not_one() {
        // The string `"a":1` appears twice as a VALUE. Only a scanner that checks
        // for a following colon at the right nesting level gets this right.
        assert!(!has_duplicate_member_names(
            r#"{"p":"\"a\":1","q":"\"a\":1"}"#
        ));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        assert!(!has_duplicate_member_names(r#"{"a\"b":1,"c":2}"#));
    }

    #[test]
    fn an_unterminated_string_is_not_reported_as_a_duplicate() {
        // Malformed, but not OUR error to name — whatever parses it next refuses
        // it, and "duplicate" would be the wrong reason.
        assert!(!has_duplicate_member_names(r#"{"a":"unterminated"#));
    }
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
            scope.into_iter().map(ScopeBoundaryEntry::prefix).collect(),
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
        assert!(
            v.is_in_scope("data.governance"),
            "the entry contains itself"
        );
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

    // ---- v4 typed boundary entries (spec S.8, S.10, ADR-0009) ----

    fn entry(json: &str) -> Result<ScopeBoundaryEntry, serde_json::Error> {
        serde_json::from_str::<ScopeBoundaryEntry>(json)
    }

    #[test]
    fn a_well_formed_prefix_entry_parses() {
        let e = entry(r#"{"kind":"prefix","value":"orders/123/"}"#).expect("parses");
        assert_eq!(e.kind(), "prefix");
        assert_eq!(e.value().as_str(), Some("orders/123/"));
    }

    /// An unrecognised kind PARSES. It is refused at verify (S.10), not here:
    /// collapsing the two would report an authentic, correctly signed,
    /// future-version credential as malformed bytes.
    #[test]
    fn an_unrecognised_kind_parses_and_is_not_evaluable() {
        let e = entry(r#"{"kind":"amount","value":100}"#).expect("parses");
        assert!(!entry_is_evaluable(&e));
        assert!(!boundary_is_evaluable(std::slice::from_ref(&e)));
    }

    #[test]
    fn a_bare_string_entry_is_not_an_entry() {
        assert!(entry(r#""data.governance""#).is_err());
    }

    #[test]
    fn an_entry_missing_a_required_member_is_not_an_entry() {
        assert!(entry(r#"{"kind":"prefix"}"#).is_err());
        assert!(entry(r#"{"value":"a"}"#).is_err());
    }

    /// S.11: the deliberate asymmetry with ADR-0006. At document level an
    /// unknown member is preserved; inside an entry it is refused, because a
    /// verifier ignoring it would compute a wider boundary than was signed.
    #[test]
    fn an_entry_with_an_extra_member_is_not_an_entry() {
        assert!(entry(r#"{"kind":"prefix","value":"a","max":5}"#).is_err());
    }

    #[test]
    fn a_prefix_entry_with_a_non_string_value_is_not_an_entry() {
        assert!(entry(r#"{"kind":"prefix","value":5}"#).is_err());
        assert!(entry(r#"{"kind":"prefix","value":null}"#).is_err());
    }

    #[test]
    fn an_empty_kind_is_not_an_entry() {
        assert!(entry(r#"{"kind":"","value":"a"}"#).is_err());
    }

    /// The in-process constructor applies the same rule as `Deserialize`, so an
    /// entry that could not have been parsed cannot be built either.
    #[test]
    fn the_constructor_applies_the_same_shape_rule_as_deserialize() {
        assert!(ScopeBoundaryEntry::new("prefix", serde_json::json!(5)).is_err());
        assert!(ScopeBoundaryEntry::new("", serde_json::json!("a")).is_err());
        // An unrecognised kind's value is never inspected, so this is accepted
        // here and refused at verify.
        assert!(ScopeBoundaryEntry::new("amount", serde_json::json!(100)).is_ok());
    }

    // ---- S.8 at DOCUMENT level: `verify_vaid` cannot be reached with a
    // malformed boundary, because the document does not deserialize ----
    //
    // Python and TypeScript needed an explicit well-formedness gate added to
    // `mint_root`/`mint_child` and `verify_vaid`, because in both a malformed
    // boundary could be carried through the mint, signed, and accepted by the
    // local verifier while `parse_vaid_document` refused it off the wire.
    //
    // Rust cannot reach that state, and these tests pin WHY rather than leaving
    // it as a claim about the type system. `Vaid::scope_boundary` is
    // `Vec<ScopeBoundaryEntry>`; the entry's fields are private; and its only
    // construction paths are `prefix` (valid by construction), `new` and
    // `From<&str>`/`From<String>` (which apply `validate_scope_entry`), and
    // `Deserialize` (same predicate, see the per-entry tests above). So no
    // runtime check was added to `mint_root`, `mint_child` or `verify_vaid`
    // here: it would be unreachable code and a second copy of a rule that is
    // already stated exactly once.
    //
    // The risk that remains is a future refactor that loosens the field type or
    // adds a constructor that skips validation. These tests fail if that
    // happens.

    fn vaid_json_with_boundary(boundary: serde_json::Value) -> String {
        let mut v = serde_json::to_value(doc(vec!["data.x"], vec!["read"])).unwrap();
        v["scope_boundary"] = boundary;
        serde_json::to_string(&v).unwrap()
    }

    // The enumeration of malformed shapes lives in `scope_kinds_v1.json` and is
    // driven over the document surface by
    // `tests/scope_kinds_conformance.rs::a_document_carrying_an_unparseable_shape_case_does_not_deserialize`,
    // so the case table is stated once and all three languages read the same one.
    // What remains here are the controls that table cannot express: that the
    // typed form round-trips, and that an unrecognised KIND is well formed.

    /// Positive control for the conformance loop: the identical construction
    /// with typed entries round-trips. Without it, a `Vaid` that failed to
    /// deserialize for an unrelated reason would pass that test.
    #[test]
    fn a_document_with_typed_entries_round_trips() {
        let text =
            vaid_json_with_boundary(serde_json::json!([{"kind": "prefix", "value": "data.x"}]));
        let parsed = serde_json::from_str::<Vaid>(&text).expect("round-trips");
        assert_eq!(parsed.scope_boundary().len(), 1);
        assert_eq!(parsed.scope_boundary()[0].kind(), "prefix");
    }

    /// An unrecognised KIND is well formed, so the document must deserialize.
    /// This is what stops the document-level gate from being written as "only a
    /// prefix entry is acceptable", which would pass every test above and
    /// silently close the extension point ADR-0009 exists to open. It is
    /// refused at verify (S.10), which `verdict_v1` and the agreement job pin.
    #[test]
    fn a_document_with_an_unrecognised_kind_deserializes() {
        let text =
            vaid_json_with_boundary(serde_json::json!([{"kind": "amount_limit", "value": 100}]));
        let parsed = serde_json::from_str::<Vaid>(&text).expect("deserializes");
        assert!(!boundary_is_evaluable(parsed.scope_boundary()));
    }

    /// THE SUBTLE ONE (S.10). `any()` over the entries finds the satisfied
    /// prefix and never reaches the entry it cannot read, so it returns true.
    /// An unrecognised kind can only ever NARROW what the signer meant, so an
    /// unreadable entry must refuse the whole boundary.
    #[test]
    fn an_unreadable_entry_refuses_the_whole_boundary_even_when_another_matches() {
        let boundary = vec![
            ScopeBoundaryEntry::prefix("data.governance"),
            ScopeBoundaryEntry::new("amount", serde_json::json!(100)).unwrap(),
        ];
        assert!(
            scope_contains(
                std::slice::from_ref(&boundary[0]),
                "data.governance.reports"
            ),
            "control: the prefix entry alone does contain the resource"
        );
        assert!(
            !scope_contains(&boundary, "data.governance.reports"),
            "an entry this implementation cannot read must refuse the boundary"
        );
    }

    #[test]
    fn an_unreadable_entry_alone_contains_nothing() {
        let boundary = vec![ScopeBoundaryEntry::new("amount", serde_json::json!(100)).unwrap()];
        assert!(!scope_contains(&boundary, "anything.at.all"));
        assert!(!scope_contains(&boundary, ""));
    }

    /// `entry_is_evaluable` derives evaluability from `entry_contains` over one
    /// arbitrary resource. That is exact only if Some-ness is a property of the
    /// entry alone. Asserted rather than assumed.
    #[test]
    fn evaluability_does_not_depend_on_the_resource() {
        let entries = vec![
            ScopeBoundaryEntry::prefix(""),
            ScopeBoundaryEntry::prefix("data.governance"),
            ScopeBoundaryEntry::prefix("t/"),
            ScopeBoundaryEntry::new("amount", serde_json::json!(100)).unwrap(),
            ScopeBoundaryEntry::new("future", serde_json::json!({"a": 1})).unwrap(),
        ];
        let resources = ["", "data.governance", "data.governance.reports", "t/x", "z"];
        for e in &entries {
            let derived = entry_is_evaluable(e);
            for r in resources {
                assert_eq!(
                    entry_contains(e, r).is_some(),
                    derived,
                    "evaluability of {:?} changed with the resource {r:?}",
                    e.kind()
                );
            }
        }
    }

    /// A kind named in the registry must be one `entry_contains` can actually
    /// evaluate. Without this, a name could be added to the registry alone and
    /// the matcher would refuse a kind the specification says is recognised.
    #[test]
    fn every_registered_kind_is_one_the_matcher_can_evaluate() {
        for kind in RECOGNISED_SCOPE_KINDS {
            let e = match kind {
                SCOPE_KIND_PREFIX => ScopeBoundaryEntry::prefix("data.x"),
                other => {
                    panic!("registered kind {other:?} has no witness here — add one with the kind")
                }
            };
            assert!(
                entry_is_evaluable(&e),
                "registered kind {kind:?} is not evaluable by the matcher"
            );
            assert!(
                entry_claimed_resource(&e).is_some(),
                "registered kind {kind:?} has no attenuation projection"
            );
        }
    }
}

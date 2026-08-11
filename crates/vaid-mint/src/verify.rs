//! Standalone, public-key-only verification of a VAID document.
//!
//! [`crate::issuer::VaidIssuer::verify_vaid`] can only be called by a party
//! holding a [`crate::issuer::ReferenceIssuer`], and every issuer constructor needs
//! the kernel **private** key. An Ed25519 signature needs only the **public** key to
//! verify, so this module exposes what the issuer method trapped inside itself: a
//! third party holding just the issuer's kernel public key can confirm a VAID
//! document is authentic — no issuer instance, no private key.
//!
//! ## Scope: authenticity, not standing
//!
//! [`verify_vaid_authenticity`] answers "was this document genuinely issued under this
//! key, and is it internally consistent" — the signature-scheme version, the kernel
//! Ed25519 signature over the canonical document, and the consistency of
//! `lineage_hash`. It deliberately does **not**:
//!
//! - check **expiry** — a temporal concern; call [`crate::document::Vaid::is_expired`]
//!   separately if the caller cares about validity now;
//! - consult **revocation** — this is the load-bearing decision. A resolver-less
//!   verifier answers authenticity; gating that on a lineage/revocation lookup the
//!   verifier cannot perform would make every third-party verification fail closed,
//!   rebuilding the R.4.2 problem in a new place. Revocation status is reported on a
//!   separate path ([`crate::issuer::ReferenceIssuer::revocation_status`]) or not at
//!   all here.
//!
//! ## The graded verdict
//!
//! [`VaidVerdict`] reports *why*, not merely *whether*. [`verify_vaid_standing`]
//! composes authenticity with expiry and a revocation status the caller supplies,
//! and [`verify_vaid_standing_from_json`] starts from bytes so that "this is not a
//! VAID" is a verdict rather than a parse error.
//!
//! This is **additive**. [`verify_vaid_authenticity`] keeps its signature and its
//! behaviour exactly; it is now expressed as `verify_vaid_authenticity_graded(..).is_valid()`
//! so the boolean and the reason are the same computation rather than two copies
//! of it. The revocation posture above is unchanged: the graded path still performs
//! no lookup, it only says what the caller's answer means.

use ring::signature::{UnparsedPublicKey, ED25519};

use crate::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, Vaid, VAID_SIG_VERSION_V3,
};

/// Verify a VAID document's **authenticity** against an issuer's kernel **public**
/// key (raw 32-byte Ed25519). No issuer instance, no private key.
///
/// This answers *authenticity* — "genuinely issued under this key, and internally
/// consistent" — **not** *standing* ("valid and unrevoked right now"). A `true`
/// result does not mean the VAID is currently usable; it means it is real.
///
/// **Checks (all must hold for `true`):**
/// - the signature-scheme version is current (v3 only — a v2 document is
///   rejected, and there is no dual-version path);
/// - `trust_domain` is well-formed ([`crate::issuer_identity::is_valid_trust_domain`]);
/// - `kernel_key_thumbprint` **corresponds to `kernel_public_key`** — the v3
///   key-commitment check. Without it a caller could verify a document against a
///   key the document never named, and "verified under some key we hold" is a
///   verdict nobody can audit;
/// - `lineage_hash` is internally consistent ([`verify_lineage_hash`]);
/// - the kernel Ed25519 signature is valid over the canonical document under
///   `kernel_public_key`.
///
/// The thumbprint check is ordered **before** the signature check deliberately:
/// it is one hash against 64 bytes of Ed25519 verification, so a caller holding a
/// bundle can reject a non-corresponding key without paying for a signature
/// verification it already knows will fail.
///
/// **Does NOT check — the caller must handle these separately:**
/// - **expiry** — call [`crate::document::Vaid::is_expired`]; an expired-but-signed
///   VAID returns `true` here;
/// - **revocation** — evaluate a [`crate::revocation::RevocationCheck`] (or, in the
///   reference, [`crate::issuer::ReferenceIssuer::revocation_status`]) on a separate
///   path. Revocation is deliberately *not* consulted here — see the module docs.
///
/// A malformed key, a bad signature, or any tampered signed field is `false`, never
/// an error.
pub fn verify_vaid_authenticity(kernel_public_key: &[u8], vaid: &Vaid) -> bool {
    // Expressed in terms of the graded verdict rather than duplicating its
    // branches. Two parallel implementations of the same check are two things that
    // can drift; this way the boolean IS the graded verdict, read narrowly, and a
    // future edit cannot change one without changing the other.
    verify_vaid_authenticity_graded(kernel_public_key, vaid).is_valid()
}

/// Recompute `lineage_hash` from the document's own `parent_vaid` and `agent_id`
/// (via [`compute_lineage_hash`]) and compare. Catches an inconsistent
/// `lineage_hash` **explicitly**, rather than relying on it being incidentally
/// covered by the kernel signature — so a caller can check lineage integrity on its
/// own, and so a mint that signs a malformed `lineage_hash` is caught here.
pub fn verify_lineage_hash(vaid: &Vaid) -> bool {
    compute_lineage_hash(vaid.parent_vaid(), &vaid.agent_id()) == vaid.lineage_hash()
}

/* ────────────────────────── the graded verdict ─────────────────────────── */

/// Why a VAID was or was not honoured — the reason alongside the boolean.
///
/// # Why a boolean was not enough
///
/// `false` collapses "this document is forged" into "I could not reach a
/// revocation list". Both are refusals; only one is an accusation. A caller that
/// cannot tell them apart cannot log the difference, cannot alert on the
/// difference, and cannot retry the one that is worth retrying.
///
/// # Two rules inherited from decisions this repo has already made
///
/// 1. **"I could not determine this" is its own state.** It is
///    [`Indeterminate`](VaidVerdict::Indeterminate), and it is never folded into a
///    negative. The same rule already governs
///    [`RevocationStatus::Unavailable`](crate::revocation::RevocationStatus::Unavailable),
///    the four-valued [`ChainVerification`](crate::chain::ChainVerification), and
///    the packaged firewall's refusal to report PASS over zero vectors.
/// 2. **Fail closed on ambiguity.** [`Indeterminate`](VaidVerdict::Indeterminate)
///    is not valid: [`is_valid`](VaidVerdict::is_valid) is true for
///    [`Valid`](VaidVerdict::Valid) and nothing else. Unavailable never reads as
///    usable.
///
/// # Additive
///
/// Nothing here changes an existing verdict or an existing signature.
/// [`verify_vaid_authenticity`] keeps its exact signature and its exact
/// behaviour — it is now *defined as* `verify_vaid_authenticity_graded(..).is_valid()`,
/// which is the same function read narrowly rather than a second copy of it.
///
/// # The states are the ones the vectors distinguish
///
/// Each variant below is reachable by at least one case in `verdict_v1.json`. A
/// state no vector can produce would be a claim with no evidence behind it, so
/// there are no such states here: candidates that no case could separate were
/// merged rather than kept for symmetry with anyone else's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaidVerdict {
    /// Authentic, unexpired, and revocation was consulted and reported clean.
    /// The only variant for which [`is_valid`](VaidVerdict::is_valid) is true.
    Valid,
    /// The bytes are not a VAID document: truncated, not JSON, a required member
    /// absent, or a member of the wrong type. Nothing downstream was evaluated
    /// because there was nothing to evaluate.
    Unparseable,
    /// Parsed, but the signature-scheme discriminant is not the current one. A v2
    /// document reaches this; so does a forged document with no `sig_version` at
    /// all, which deserializes to `0`.
    UnsupportedSigVersion,
    /// Parsed, but `trust_domain` is not a well-formed DNS-shaped name (ADR-0004).
    /// The document names an issuer nobody can look up.
    MalformedTrustDomain,
    /// The document's `kernel_key_thumbprint` does not correspond to the key it is
    /// being verified against — the v3 key-commitment check. This is the verdict
    /// for a document signed by a non-kernel key that also rewrote the thumbprint
    /// to match its own: the signature is internally consistent, and it is the
    /// *wrong issuer*. Distinct from [`Inauthentic`](VaidVerdict::Inauthentic),
    /// which is the same forgery that left the thumbprint alone.
    IssuerMismatch,
    /// `lineage_hash` does not recompute from the document's own `parent_vaid` and
    /// `agent_id`. Caught explicitly rather than incidentally via the signature, so
    /// a document whose mint signed a malformed lineage is named as such.
    LineageInconsistent,
    /// The kernel signature does not verify over the presented bytes. Payload
    /// tampered, signature tampered, or signed by a key that is not the one the
    /// document commits to. This is the accusation; everything above it is a
    /// structural complaint.
    Inauthentic,
    /// Authentic, and past `expires_at`. Checked *after* authenticity on purpose:
    /// a forged expired document is [`Inauthentic`](VaidVerdict::Inauthentic), not
    /// [`Expired`](VaidVerdict::Expired) — the more serious reason wins, because
    /// "expired" invites a renewal that would hand a forger a fresh document.
    Expired,
    /// Authentic and unexpired, but some VAID in its lineage is revoked (R.4.4).
    Revoked,
    /// Standing could not be determined: the revocation store could not be
    /// consulted, or the lineage could not be completely assembled. **Not** a
    /// negative and **not** a positive — the third state, reported as itself.
    /// Fails closed: [`is_valid`](VaidVerdict::is_valid) is false.
    Indeterminate,
}

impl VaidVerdict {
    /// Every verdict this implementation can return.
    ///
    /// Exists so the vector and the enum can police each other in **both**
    /// directions: a reason the vector declares that this build does not have is a
    /// vector written against a different implementation, and a verdict this build
    /// can return that no vector declares is a state that ships unchecked. Rust
    /// has no reflection over enum variants, so the list is written out; the gate
    /// in `tests/verdict_conformance.rs` is what stops it going stale, because a
    /// variant missing from here is a variant the vector will report as
    /// undeclared.
    pub const ALL: &'static [VaidVerdict] = &[
        VaidVerdict::Valid,
        VaidVerdict::Unparseable,
        VaidVerdict::UnsupportedSigVersion,
        VaidVerdict::MalformedTrustDomain,
        VaidVerdict::IssuerMismatch,
        VaidVerdict::LineageInconsistent,
        VaidVerdict::Inauthentic,
        VaidVerdict::Expired,
        VaidVerdict::Revoked,
        VaidVerdict::Indeterminate,
    ];

    /// True for [`Valid`](VaidVerdict::Valid) alone.
    ///
    /// This is the fail-closed rule in one line: every other variant, including
    /// [`Indeterminate`](VaidVerdict::Indeterminate), is not usable. A caller that
    /// only wants the boolean gets exactly the pre-existing behaviour.
    pub fn is_valid(self) -> bool {
        matches!(self, VaidVerdict::Valid)
    }

    /// The stable wire string for this verdict — the vocabulary `verdict_v1.json`
    /// is written in, and the thing three implementations must agree on.
    ///
    /// These strings are part of the conformance surface: two implementations that
    /// reject the same document for different reasons disagree even though their
    /// booleans match, and that disagreement is only visible if the reason has a
    /// name both of them spell the same way.
    pub fn code(self) -> &'static str {
        match self {
            VaidVerdict::Valid => "valid",
            VaidVerdict::Unparseable => "unparseable",
            VaidVerdict::UnsupportedSigVersion => "unsupported_sig_version",
            VaidVerdict::MalformedTrustDomain => "malformed_trust_domain",
            VaidVerdict::IssuerMismatch => "issuer_mismatch",
            VaidVerdict::LineageInconsistent => "lineage_inconsistent",
            VaidVerdict::Inauthentic => "inauthentic",
            VaidVerdict::Expired => "expired",
            VaidVerdict::Revoked => "revoked",
            VaidVerdict::Indeterminate => "indeterminate",
        }
    }

    /// Parse a wire string back to a verdict, or `None` if it names no known state.
    ///
    /// `None` rather than a fallback variant: an unrecognised reason code is not a
    /// verdict, and silently mapping it to one would let a vector naming a state
    /// this build does not have report agreement it never established.
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "valid" => VaidVerdict::Valid,
            "unparseable" => VaidVerdict::Unparseable,
            "unsupported_sig_version" => VaidVerdict::UnsupportedSigVersion,
            "malformed_trust_domain" => VaidVerdict::MalformedTrustDomain,
            "issuer_mismatch" => VaidVerdict::IssuerMismatch,
            "lineage_inconsistent" => VaidVerdict::LineageInconsistent,
            "inauthentic" => VaidVerdict::Inauthentic,
            "expired" => VaidVerdict::Expired,
            "revoked" => VaidVerdict::Revoked,
            "indeterminate" => VaidVerdict::Indeterminate,
            _ => return None,
        })
    }
}

impl std::fmt::Display for VaidVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Graded [`verify_vaid_authenticity`]: the same checks, in the same order, saying
/// which one refused.
///
/// The branch order is **load-bearing and unchanged** — `sig_version`,
/// `trust_domain`, thumbprint, `lineage_hash`, signature. It is not the only
/// defensible order, but it is the order all three implementations already had,
/// and reordering it here would silently change which reason a document gets while
/// leaving every boolean identical. That is precisely the class of divergence
/// `verdict_v1.json` exists to catch, so this function must not introduce one.
///
/// Never returns [`Expired`](VaidVerdict::Expired),
/// [`Revoked`](VaidVerdict::Revoked) or [`Indeterminate`](VaidVerdict::Indeterminate):
/// authenticity is not standing. Use [`verify_vaid_standing`] for that.
pub fn verify_vaid_authenticity_graded(kernel_public_key: &[u8], vaid: &Vaid) -> VaidVerdict {
    if vaid.sig_version() != VAID_SIG_VERSION_V3 {
        return VaidVerdict::UnsupportedSigVersion;
    }
    if !crate::issuer_identity::is_valid_trust_domain(vaid.trust_domain()) {
        return VaidVerdict::MalformedTrustDomain;
    }
    if vaid.kernel_key_thumbprint()
        != crate::issuer_identity::kernel_key_thumbprint(kernel_public_key)
    {
        return VaidVerdict::IssuerMismatch;
    }
    if !verify_lineage_hash(vaid) {
        return VaidVerdict::LineageInconsistent;
    }
    if UnparsedPublicKey::new(&ED25519, kernel_public_key)
        .verify(&canonical_vaid_signing_bytes(vaid), vaid.kernel_signature())
        .is_err()
    {
        return VaidVerdict::Inauthentic;
    }
    VaidVerdict::Valid
}

/// The full standing verdict: authenticity, then expiry, then revocation.
///
/// Revocation is **passed in**, not looked up. This module still performs no
/// resolution — gating third-party verification on a lookup the verifier cannot do
/// is the R.4.2 problem, and adding a graded return is not a licence to rebuild it.
/// The caller assembles the lineage ([`crate::revocation::assemble_lineage`]) and
/// consults its [`RevocationCheck`](crate::revocation::RevocationCheck); this
/// function says what the answer means. An incomplete assembly is
/// [`RevocationStatus::Unavailable`], which arrives here as
/// [`Indeterminate`](VaidVerdict::Indeterminate).
///
/// # Order, and why it is this one
///
/// 1. **Authenticity.** A document that is not real has no standing to discuss. A
///    forgery that happens to be expired is reported as a forgery.
/// 2. **Expiry.** Determinable from the document alone. It is checked before
///    revocation so that a definite answer is never displaced by
///    [`Indeterminate`](VaidVerdict::Indeterminate) — reporting "I could not tell"
///    about a document we can positively see has expired discards information we
///    already hold.
/// 3. **Revocation.** The only input that can be unavailable, so it is last.
///
/// Expiry uses [`Vaid::is_expired`](crate::document::Vaid::is_expired), which reads
/// the wall clock.
pub fn verify_vaid_standing(
    kernel_public_key: &[u8],
    vaid: &Vaid,
    revocation: crate::revocation::RevocationStatus,
) -> VaidVerdict {
    use crate::revocation::RevocationStatus;

    let authenticity = verify_vaid_authenticity_graded(kernel_public_key, vaid);
    if !authenticity.is_valid() {
        return authenticity;
    }
    if vaid.is_expired() {
        return VaidVerdict::Expired;
    }
    match revocation {
        RevocationStatus::NotRevoked => VaidVerdict::Valid,
        RevocationStatus::Revoked => VaidVerdict::Revoked,
        RevocationStatus::Unavailable => VaidVerdict::Indeterminate,
    }
}

/// [`verify_vaid_standing`] over JSON text, so that "these bytes are not a VAID"
/// is a *verdict* rather than a deserialization error the caller has to catch.
///
/// This exists for a cross-language reason as much as an ergonomic one. Rust's
/// [`Vaid`] is a typed struct, so a truncated or structurally invalid document
/// cannot even be constructed — the failure happens at `serde_json::from_str`,
/// before any verifier sees it. Python and TypeScript hand their verifiers a plain
/// map, which has no such gate. Without a shared entry point that starts from
/// *text*, the three implementations would be answering different questions about
/// malformed input, and a conformance vector comparing them would be comparing
/// nothing.
///
/// Parse failure is [`Unparseable`](VaidVerdict::Unparseable) — a refusal, never a
/// panic and never an error type.
pub fn verify_vaid_standing_from_json(
    kernel_public_key: &[u8],
    document_json: &str,
    revocation: crate::revocation::RevocationStatus,
) -> VaidVerdict {
    // A duplicate member name is checked FIRST, and on the raw text, because that
    // is the only place the evidence survives: every parser here resolves the
    // collision before returning, so by the time there is a document to inspect
    // the duplicate is gone. `serde` refuses a repeated struct field but resolves
    // a repeated nested or unrecognised one by last-wins, exactly as `json.loads`
    // and `JSON.parse` do — so without this the three agree on some duplicates and
    // not others. See `docs/spec/encoding.md` E.7a.
    if crate::document::has_duplicate_member_names(document_json) {
        return VaidVerdict::Unparseable;
    }
    match serde_json::from_str::<Vaid>(document_json) {
        Ok(vaid) => verify_vaid_standing(kernel_public_key, &vaid, revocation),
        Err(_) => VaidVerdict::Unparseable,
    }
}

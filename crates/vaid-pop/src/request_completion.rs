//! Completion / provenance record — a signed statement that a VAID-authorized
//! action finished, with a status and a result hash.
//!
//! Reuses the request PoP pipeline verbatim: RFC 8785 (JCS) →  SHA-256 → Ed25519
//! over the canonical [`CompletionRecord`] bytes (via
//! [`crate::vaid_pop::sign_payload`] / [`crate::vaid_pop::verify_signed_payload`]).
//! Like [`crate::request_auth::RequestAuthPayload`] it carries NO embedded
//! signature field — the signature travels detached.
//!
//! # Scope: self-signed, declared metadata only
//!
//! This primitive produces exactly **one** detached signature, by the holder of
//! [`CompletionRecord::signer_vaid_id`]'s key. That proves *only* "this signer
//! signed this record" — nothing about who else vouches for the outcome. The
//! [`AssuranceTier`] field is therefore **declared, not proven** (see its docs).
//! Provable counter-signing and third-party attestation are deliberately OUT OF
//! SCOPE here — they require a multi-signature envelope and a key-trust model that
//! this repo does not contain, and are a separate, not-yet-built primitive.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::VaidId;

/// Declared assurance level of a completion record. The SHAPE is borrowed from
/// AIP's three-tier attestation model; the names are our own.
///
/// # This tier is DECLARED, not PROVEN
///
/// A [`CompletionRecord`] carries a single detached signature by
/// `signer_vaid_id`. That signature proves the signer signed the record — and
/// nothing more. In particular:
///
/// - [`AssuranceTier::SelfReported`] is the only tier this repo can *substantiate*
///   on its own: the actor signs its own outcome, and the signature verifies
///   against the actor's key.
/// - [`AssuranceTier::CounterSigned`] and [`AssuranceTier::ThirdPartyAttested`]
///   are **NOT independently verifiable from this repo alone.** A self-reporting
///   signer can set either value and the single signature still verifies —
///   there is no second signature and no key-trust model here to check a
///   counter-signer or attester against. Treat the top two tiers as an
///   *unverified claim* until a separate counter-signature/attestation envelope
///   primitive (not yet built) substantiates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssuranceTier {
    /// The actor asserts its own outcome. The single signature substantiates this
    /// tier and only this tier.
    SelfReported,
    /// A second party co-signs. NOT verifiable from this repo alone (see type docs).
    CounterSigned,
    /// An independent attester vouches. NOT verifiable from this repo alone.
    ThirdPartyAttested,
}

/// The exact payload a completer signs to record that a VAID-authorized action
/// finished. Reuses the request PoP pipeline verbatim; carries no embedded
/// signature. Serialized camelCase (matching [`crate::request_auth`]).
///
/// See the module and [`AssuranceTier`] docs for the load-bearing caveat: this is
/// **self-signed declared metadata**; only [`AssuranceTier::SelfReported`] is
/// substantiated by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionRecord {
    /// The acting VAID whose authorized action this completes.
    pub vaid_id: VaidId,
    /// Lowercase hex of the 32-byte canonical digest of the original signed
    /// [`crate::request_auth::RequestAuthPayload`] — binds this record to the
    /// exact authorized request, not merely to the actor.
    pub request_digest_sha256: String,
    /// Tenant the action ran under (mirrors `RequestAuthPayload.tenant_id`).
    pub tenant_id: String,
    /// Terminal status of the action, e.g. `"succeeded"` / `"failed"` /
    /// `"cancelled"`. String-typed to stay transport-simple and JCS-stable; a
    /// caller MAY constrain it to a fixed set.
    pub status: String,
    /// Lowercase hex of `SHA-256` over the caller-defined result bytes. The
    /// primitive is blind to the result content — the caller hashes it, exactly
    /// as the client hashes the request body into `RequestAuthPayload.body_sha256`.
    pub result_sha256: String,
    /// Whole-second RFC 3339 `…Z` (the same chrono-serde fixed point as
    /// `RequestAuthPayload.timestamp`).
    pub completed_at: DateTime<Utc>,
    /// The VAID that produced THIS record (the completer). Equals `vaid_id` for a
    /// self-reported record; a different value is a *claim* that some other party
    /// signed — unverified here (see [`AssuranceTier`]).
    pub signer_vaid_id: VaidId,
    /// Declared assurance level (see [`AssuranceTier`] — declared, not proven).
    pub assurance_tier: AssuranceTier,
    /// Per-record nonce for distinctness (mirrors `RequestAuthPayload.client_nonce`).
    pub record_nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike as _;

    #[test]
    fn assurance_tier_serializes_camelcase() {
        // The enum string values — the first enum in a conformance vector, and the
        // most likely place for silent Rust/Python drift. Pin them here too.
        assert_eq!(
            serde_json::to_string(&AssuranceTier::SelfReported).unwrap(),
            "\"selfReported\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceTier::CounterSigned).unwrap(),
            "\"counterSigned\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceTier::ThirdPartyAttested).unwrap(),
            "\"thirdPartyAttested\""
        );
    }

    #[test]
    fn assurance_tier_round_trips() {
        for tier in [
            AssuranceTier::SelfReported,
            AssuranceTier::CounterSigned,
            AssuranceTier::ThirdPartyAttested,
        ] {
            let s = serde_json::to_string(&tier).unwrap();
            let back: AssuranceTier = serde_json::from_str(&s).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn completion_record_round_trips_through_json() {
        let rec = CompletionRecord {
            vaid_id: VaidId::new(),
            request_digest_sha256: "ee474ba8".into(),
            tenant_id: "acme".into(),
            status: "succeeded".into(),
            result_sha256: "e3b0c442".into(),
            completed_at: Utc::now().with_nanosecond(0).unwrap(),
            signer_vaid_id: VaidId::new(),
            assurance_tier: AssuranceTier::SelfReported,
            record_nonce: "abc".into(),
        };
        let s = serde_json::to_string(&rec).unwrap();
        let back: CompletionRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(rec, back);
    }
}

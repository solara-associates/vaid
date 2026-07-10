//! Mint wire types: the request/response shapes and the proof-of-possession
//! payload a holder signs at mint.
//!
//! `VaidSeed` is the requested attributes; `MintVaidRequest` pairs a seed with an
//! optional [`MintPop`]; `MintVaidResponse` returns the signed VAID. `MintPop` /
//! [`MintPopPayload`] are the BYO-key proof-of-possession: the holder signs the
//! canonical [`MintPopPayload`] with the private key matching the public key it
//! registers, and the mint verifies that self-signature before issuing. The
//! payload is signed via the SHARED `vaid-pop` primitive, so the bytes match a
//! conforming verifier by construction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::document::{Vaid, VaidId};

/// Requested attributes for a mint. Serialized camelCase, matching the repo's
/// wire convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaidSeed {
    pub agent_class: String,
    pub version: String,
    pub tenant_id: String,
    /// Optional parent VAID (delegation lineage). `None` for root agents.
    #[serde(default)]
    pub parent_vaid: Option<VaidId>,
    /// Data domains / resource namespaces this agent may operate within.
    #[serde(default)]
    pub scope_boundary: Vec<String>,
    /// Explicit capability grants at spawn — no ambient authority.
    #[serde(default)]
    pub capability_set: Vec<String>,
    /// Holder-supplied Ed25519 public key (BYO-key). When `Some`, the holder
    /// generated its own keypair and registers only the public half; the mint
    /// binds it as the VAID's `public_key_der` and REQUIRES a [`MintPop`] proving
    /// the holder controls the matching private key. When `None`, the mint
    /// generates a keypair and discards the private half (root/bootstrap path; no
    /// PoP applies). `mint_child` is always BYO-key.
    #[serde(default)]
    pub public_key_der: Option<Vec<u8>>,
}

/// A mint request: a seed plus an optional proof-of-possession. The PoP is
/// REQUIRED when `seed.public_key_der` is `Some` (BYO-key) and omitted for the
/// generate-and-discard path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintVaidRequest {
    pub seed: VaidSeed,
    #[serde(default)]
    pub pop: Option<MintPop>,
}

/// A holder's proof-of-possession for a mint. Carries the freshness material
/// (`nonce`, `issued_at`) folded into the signed [`MintPopPayload`], plus the
/// detached Ed25519 `signature` over that payload's canonical bytes. The mint
/// reconstructs the payload from `seed` + these fields and verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintPop {
    /// Per-request random nonce (hex of ≥128 random bits) — replay distinctness.
    pub nonce: String,
    /// Client-asserted timestamp — freshness (rejected outside the window).
    pub issued_at: DateTime<Utc>,
    /// Ed25519 signature over `canonical_request_signing_bytes(MintPopPayload)`,
    /// produced with the private key matching `seed.public_key_der`.
    pub signature: Vec<u8>,
}

/// The exact canonical payload a holder signs to prove possession of the key it
/// registers at mint. Binds the public key being registered together with the
/// full set of requested attributes (so a captured request cannot be replayed to
/// mint a different-tenant or different-privilege VAID) and the freshness
/// material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintPopPayload {
    /// THE key being registered — the subject of the possession proof.
    pub public_key_der: Vec<u8>,
    pub tenant_id: String,
    pub agent_class: String,
    pub version: String,
    pub parent_vaid: Option<VaidId>,
    pub scope_boundary: Vec<String>,
    pub capability_set: Vec<String>,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
}

/// A mint response: the newly-minted, signed VAID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintVaidResponse {
    pub vaid: Vaid,
}

impl VaidSeed {
    /// Reconstruct the canonical [`MintPopPayload`] for this seed at the given
    /// freshness. Both holder and mint build the payload through this single
    /// function so the signed bytes match exactly. `public_key_der` is the
    /// holder-registered key being proven; callers supply it explicitly because
    /// PoP only applies on the BYO-key path.
    pub fn pop_payload(
        &self,
        public_key_der: Vec<u8>,
        nonce: String,
        issued_at: DateTime<Utc>,
    ) -> MintPopPayload {
        MintPopPayload {
            public_key_der,
            tenant_id: self.tenant_id.clone(),
            agent_class: self.agent_class.clone(),
            version: self.version.clone(),
            parent_vaid: self.parent_vaid,
            scope_boundary: self.scope_boundary.clone(),
            capability_set: self.capability_set.clone(),
            nonce,
            issued_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let req = MintVaidRequest {
            seed: VaidSeed {
                agent_class: "researcher".into(),
                version: "1.0.0".into(),
                tenant_id: "codex".into(),
                parent_vaid: None,
                scope_boundary: vec!["data.governance.*".into()],
                capability_set: vec!["read.documents".into()],
                public_key_der: None,
            },
            pop: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: MintVaidRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.seed.agent_class, "researcher");
    }

    #[test]
    fn seed_without_public_key_der_deserializes() {
        let json = r#"{"agentClass":"a","version":"1.0","tenantId":"t"}"#;
        let seed: VaidSeed = serde_json::from_str(json).unwrap();
        assert!(seed.public_key_der.is_none());
    }
}

//! Per-request authentication payload + authenticated principal
//! (stateless signed-request proof-of-possession).
//!
//! A caller signs each request with its VAID private key over the canonical
//! bytes of a [`RequestAuthPayload`]; a verifier recomputes the same payload and
//! verifies the signature against the caller's VAID public key, using the shared
//! [`crate::vaid_pop::verify_signed_payload`] primitive. On success it derives a
//! [`Principal`] **from the cryptographically verified VAID**, never from a
//! body-asserted identity.
//!
//! These types are pure and transport-agnostic: the HTTP carrier (headers), body
//! buffering, and replay cache live in the calling service. They live here so a
//! holder and a conforming verifier derive the *exact same* signed bytes from one
//! definition.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{TenantId, VaidId};

/// Reserved tenant id for the bootstrapped control-plane operator. The operator
/// is authenticated by exactly the same per-request PoP as any tenant; it is
/// *distinguished* by carrying this reserved tenant. A principal whose
/// `tenant_id` equals this resolves to the highest-privilege role, off this
/// constant (`Principal::is_operator`) rather than any body field.
pub const OPERATOR_TENANT_ID: &str = "synthera-control-plane";

/// Capability marker placed in the operator VAID's `capability_set` at
/// bootstrap. Belt-and-suspenders alongside the reserved tenant: it makes the
/// control-plane grant visible in the VAID itself.
pub const CONTROL_PLANE_CAPABILITY: &str = "synthera:control-plane";

/// HTTP header carrying the full presented VAID, base64(JSON). The VAID is
/// self-verifying via its signature, so no server-side VAID store is needed to
/// authenticate a request.
pub const HEADER_VAID: &str = "x-synthera-vaid";
/// HTTP header carrying the client-asserted RFC 3339 timestamp (freshness).
pub const HEADER_TIMESTAMP: &str = "x-synthera-timestamp";
/// HTTP header carrying the per-request client nonce (replay distinctness).
pub const HEADER_NONCE: &str = "x-synthera-nonce";
/// HTTP header carrying the base64 Ed25519 signature over the canonical
/// [`RequestAuthPayload`] bytes.
pub const HEADER_SIGNATURE: &str = "x-synthera-signature";

/// The exact payload a holder signs per request. Binds the request material so a
/// captured signature cannot be lifted onto a different request or replayed:
///
/// - `method` + `path` + `body_sha256` bind the verb, route, and exact body —
///   a signature for `POST /a {body X}` is useless for `POST /b` or `{body Y}`;
/// - `tenant_id` binds cross-tenant intent — and a verifier reconstructs it from
///   the **verified VAID's** tenant, so a caller can only ever produce a valid
///   signature for its own tenant;
/// - `timestamp` + `client_nonce` give freshness and replay distinctness.
///
/// The field set is exactly these seven — no more, no less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuthPayload {
    pub vaid_id: VaidId,
    pub method: String,
    pub path: String,
    /// Lowercase hex of `SHA-256(request_body)`.
    pub body_sha256: String,
    pub tenant_id: String,
    pub timestamp: DateTime<Utc>,
    pub client_nonce: String,
}

/// An authenticated principal. Produced ONLY after a VAID verifies (signature +
/// unexpired + unrevoked) and its key signs the request. Both fields are derived
/// from the **verified VAID**, never from a body-asserted `tenant_id`, so a
/// handler never trusts a body-asserted identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub vaid_id: VaidId,
    pub tenant_id: TenantId,
}

impl Principal {
    /// True iff this principal is the bootstrapped control-plane operator —
    /// i.e. its (cryptographically verified) VAID carries the reserved
    /// [`OPERATOR_TENANT_ID`]. A caller uses this to grant the highest-privilege
    /// role without consulting any body-asserted field.
    pub fn is_operator(&self) -> bool {
        self.tenant_id.as_str() == OPERATOR_TENANT_ID
    }
}

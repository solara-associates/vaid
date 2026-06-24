//! VAID identity newtypes the PoP payload binds.
//!
//! `VaidId` and `TenantId` are the two identity fields a signed
//! [`crate::request_auth::RequestAuthPayload`] carries. They are defined here, in
//! one place, so a signer and a conforming verifier bind the same identity types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tenant identifier for multi-tenancy isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unique VAID identifier for referencing parent/child relationships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaidId(Uuid);

impl VaidId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Construct a VAID id from a raw UUID, for callers that derive the id from
    /// an existing UUID rather than generating a fresh one.
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// The underlying UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for VaidId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VaidId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

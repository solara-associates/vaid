//! Standalone, public-key-only verification of a VAID document.
//!
//! [`crate::issuer::ReferenceIssuer::verify_vaid`] can only be called by a party
//! holding a [`crate::issuer::ReferenceIssuer`], and every issuer constructor needs
//! the kernel **private** key. An Ed25519 signature needs only the **public** key to
//! verify, so this module exposes what the issuer method trapped inside itself: a
//! third party holding just the issuer's kernel public key can confirm a VAID
//! document is authentic — no issuer instance, no private key.
//!
//! ## Scope: authenticity, not standing
//!
//! [`verify_vaid_document`] answers "was this document genuinely issued under this
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

use ring::signature::{UnparsedPublicKey, ED25519};

use crate::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, Vaid, VAID_SIG_VERSION_V2,
};

/// Verify a VAID document's **authenticity** against an issuer's kernel **public**
/// key (raw 32-byte Ed25519). No issuer instance, no private key.
///
/// This answers *authenticity* — "genuinely issued under this key, and internally
/// consistent" — **not** *standing* ("valid and unrevoked right now"). A `true`
/// result does not mean the VAID is currently usable; it means it is real.
///
/// **Checks (all must hold for `true`):**
/// - the signature-scheme version is current;
/// - `lineage_hash` is internally consistent ([`verify_lineage_hash`]);
/// - the kernel Ed25519 signature is valid over the canonical document under
///   `kernel_public_key`.
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
pub fn verify_vaid_document(kernel_public_key: &[u8], vaid: &Vaid) -> bool {
    if vaid.sig_version() != VAID_SIG_VERSION_V2 {
        return false;
    }
    if !verify_lineage_hash(vaid) {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, kernel_public_key)
        .verify(&canonical_vaid_signing_bytes(vaid), vaid.kernel_signature())
        .is_ok()
}

/// Recompute `lineage_hash` from the document's own `parent_vaid` and `agent_id`
/// (via [`compute_lineage_hash`]) and compare. Catches an inconsistent
/// `lineage_hash` **explicitly**, rather than relying on it being incidentally
/// covered by the kernel signature — so a caller can check lineage integrity on its
/// own, and so a mint that signs a malformed `lineage_hash` is caught here.
pub fn verify_lineage_hash(vaid: &Vaid) -> bool {
    compute_lineage_hash(vaid.parent_vaid(), &vaid.agent_id()) == vaid.lineage_hash()
}

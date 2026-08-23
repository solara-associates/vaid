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
//! - **Non-durable revocation, a pluggable seam, and a fail-CLOSED default.** The
//!   built-in revocation and lineage stores are in-memory and do not survive a
//!   restart, so the revocation store starts **absent**: it reports `Unavailable`
//!   and verification fails closed until state is loaded (R.4.5). A self-hoster
//!   injects a durable backend — **both halves together**, via
//!   [`ReferenceIssuer::with_revocation_backend`] and
//!   [`crate::revocation::RevocationBackend`] — without patching the crate. A
//!   caller who wants the pre-0.8.0 vouching posture asks for it by name with
//!   [`ReferenceIssuer::assuming_nothing_revoked`]. See `docs/spec/revocation.md`
//!   R.4 and the crate README's "Trust model" section.
//! - **The issuer is the lineage resolver.** It records **every** mint in an
//!   in-memory map — roots with no parent, children with their parent — so it can
//!   tell a known root from an id it has never seen ([`LineageResolver`], spec
//!   R.4.2). The map is not durable and is not a network service; after a restart
//!   it is empty, and a child presented against it resolves to
//!   [`RevocationStatus::Unavailable`] rather than being mistaken for a root.


use std::sync::Arc;

use chrono::{DateTime, Duration, SubsecRound, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid,
    VaidId, VAID_SIG_VERSION_V3,
};
use crate::error::{MintError, MintResult};
use crate::revocation::{
    assemble_lineage, InMemoryLineageStore, InMemoryRevocationList, LineageAssembly, LineageResolver,
    LineageStore, ParentResolution, RevocationBackend, RevocationCheck, RevocationStatus,
};

/// The default issuance TTL, in hours, when a caller does not supply one. Short
/// by design: with only non-durable revocation in this reference, a short TTL is
/// the primary control that bounds the exposure window of a leaked or compromised
/// VAID (see the README "Trust model"). The constructors still take an explicit
/// `vaid_ttl_hours`; this constant documents the recommended baseline.
pub const DEFAULT_VAID_TTL_HOURS: i64 = 1;

/// The issuer seam. The mint holds one of these and asks it to issue signed
/// documents. Sync (not async): issuing is CPU-only (key handling + one Ed25519
/// sign); no I/O is on this path in the reference.
/// The current instant, truncated to a whole second — the only clock read that
/// may reach a signed document (spec `docs/spec/encoding.md` E.6).
///
/// # Why this exists as a named function rather than as a `.trunc_subsecs(0)` at
/// each call site
///
/// Because the omission it prevents is invisible. `chrono` serializes a
/// `DateTime<Utc>` with whatever precision it carries, and `Utc::now()` carries
/// microseconds, so a mint that simply stores the clock emits
/// `2026-08-11T08:04:18.165623Z` — RFC 3339, and **not** the whole-second `Z`
/// profile E.6 requires. Nothing in the type system distinguishes a conforming
/// instant from a non-conforming one: both are `DateTime<Utc>`, the field is
/// serialized by a derived `Serialize` nobody reads, and the document verifies
/// against itself, so no test that mints and then verifies can see it.
///
/// That is exactly how it shipped (BACKLOG B8). **Rust was the only implementation
/// where the omission could hide.** Python formats with
/// `strftime("%Y-%m-%dT%H:%M:%SZ")` and TypeScript routes through
/// `utcWholeSecondRfc3339` — in both, the profile is written out at the point the
/// timestamp becomes a string, so a reader sees it and an author choosing
/// otherwise has to do so deliberately. `vaid-client` shows the same thing inside
/// Rust: its request timestamp goes through
/// `to_rfc3339_opts(SecondsFormat::Secs, true)` and has always been conforming,
/// because there the rendering is explicit code. The mint's was a derive.
///
/// Naming the function is the fix for that: a clock read that is *not* this one is
/// now visibly a clock read that is not this one.
pub fn whole_second_now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(0)
}

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

/// The open reference issuer. Holds an Ed25519 kernel key, an in-memory lineage
/// map recording every mint (so it can act as the verifier-side
/// [`LineageResolver`]), and the three-state [`RevocationCheck`] consulted at
/// verification.
pub struct ReferenceIssuer {
    kernel_key_pair: Ed25519KeyPair,
    vaid_ttl_hours: i64,
    /// v3: the trust domain stamped into every VAID this issuer mints
    /// (ADR-0004). Validated at construction, so an issuer that could only emit
    /// non-conforming documents cannot be built. The companion
    /// `kernel_key_thumbprint` is NOT stored here — it is derived from the kernel
    /// key at mint time, so it cannot disagree with the key that signs.
    trust_domain: String,
    /// The lineage store: written on every mint, read by [`resolve_parent`] to
    /// assemble ancestry at verification. Defaults to `default_lineage`
    /// (in-memory, empty after restart); replaced — **only together with the
    /// revocation check** — by [`ReferenceIssuer::with_revocation_backend`].
    ///
    /// [`resolve_parent`]: ReferenceIssuer::resolve_parent
    lineage: Arc<dyn LineageStore>,
    /// The built-in in-memory lineage store that [`ReferenceIssuer::clear_lineage`]
    /// mutates. It is the default `lineage`; injecting a backend leaves this in
    /// place but unconsulted.
    default_lineage: Arc<InMemoryLineageStore>,
    /// The revocation store consulted in `verify_vaid`. Defaults to `default_store`
    /// (in-memory, **absent** — [`InMemoryRevocationList::new`] — so verification
    /// fails closed out of the box); replaced by
    /// [`ReferenceIssuer::with_revocation_backend`], or flipped to the pre-0.8.0
    /// vouching posture by [`ReferenceIssuer::assuming_nothing_revoked`].
    revocation: Arc<dyn RevocationCheck>,
    /// The built-in in-memory store that [`ReferenceIssuer::revoke`] mutates. It is
    /// the default `revocation`; injecting a custom check leaves this in place but
    /// unconsulted (revoke through the injected backend instead).
    default_store: Arc<InMemoryRevocationList>,
}

impl ReferenceIssuer {
    /// Build with a freshly generated **ephemeral** kernel key. VAIDs signed by
    /// this issuer verify only for this process's lifetime — the key is not
    /// persisted. The zero-config default for local self-hosting and tests.
    pub fn ephemeral(vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| MintError::Identity(format!("kernel key generation failed: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), vaid_ttl_hours, trust_domain)
    }

    /// Build from a caller-supplied PKCS#8 kernel key — the self-hosting
    /// persistence path (load the key from wherever you keep it and hand the
    /// bytes here). VAIDs signed by this issuer verify across restarts as long as
    /// the same key is supplied.
    pub fn from_pkcs8(pkcs8: &[u8], vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let trust_domain = Self::checked_trust_domain(trust_domain)?;
        let kernel_key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| MintError::Identity(format!("kernel key parse failed: {e}")))?;
        Ok(Self::with_key(
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
        ))
    }

    /// Reject a malformed trust domain at construction rather than at mint.
    /// An issuer whose every output would fail verification is not a useful
    /// object to hold.
    fn checked_trust_domain(trust_domain: &str) -> MintResult<String> {
        if !crate::issuer_identity::is_valid_trust_domain(trust_domain) {
            return Err(MintError::Identity(format!(
                "trust_domain {trust_domain:?} is not well-formed (ADR-0004): lowercase ASCII \
                 letters, digits, '-' and '.'; at least two labels; each 1-63 bytes without a \
                 leading or trailing '-'; no trailing dot; 1-253 bytes total; final label not \
                 all-numeric"
            )));
        }
        Ok(trust_domain.to_string())
    }

    /// Build from a raw 32-byte Ed25519 seed. Primarily for deterministic
    /// conformance vectors (RFC 8032 test seeds), where both languages must
    /// derive the identical kernel key and produce identical signatures.
    pub fn from_seed(seed: &[u8], vaid_ttl_hours: i64, trust_domain: &str) -> MintResult<Self> {
        let trust_domain = Self::checked_trust_domain(trust_domain)?;
        let kernel_key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| MintError::Identity(format!("kernel seed parse failed: {e}")))?;
        Ok(Self::with_key(
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
        ))
    }

    /// The trust domain this issuer stamps into every VAID it mints.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The RFC 9278 thumbprint URI of this issuer's kernel public key — the value
    /// stamped into every VAID it mints, and the value a verifier uses to select
    /// this issuer's key from a trust bundle.
    pub fn kernel_key_thumbprint(&self) -> String {
        crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key())
    }

    fn with_key(
        kernel_key_pair: Ed25519KeyPair,
        vaid_ttl_hours: i64,
        trust_domain: String,
    ) -> Self {
        // Default revocation posture (0.8.0 onward): ABSENT. The store has not been
        // populated, cannot vouch for anything, and reports `Unavailable`, so
        // verification FAILS CLOSED out of the box (R.4.5).
        //
        // Until 0.8.0 this was `assume_nothing_revoked()` — a store that vouched
        // `NotRevoked` over an empty set so a fresh issuer verified immediately.
        // Being non-durable it could not detect its own restart, so a VAID revoked
        // before a restart verified clean afterwards: a fail-open posture, reached by
        // assumption, arrived at by default. R.4.5 requires that fail-open never BE
        // the default and always be named; the reference now obeys that rather than
        // relying on R.4.6's narrower carve-out for it.
        //
        // Three ways forward for a caller: inject a durable backend
        // (`with_revocation_backend`); load revocation state before verifying, so the
        // absent store fails closed only while it warms; or ask for the old posture
        // BY NAME with `assuming_nothing_revoked()`. See `docs/spec/revocation.md`
        // R.4.5 and R.4.6.
        let default_store = Arc::new(InMemoryRevocationList::new());
        // The lineage half of the same default: in-process, empty after restart.
        // R.4.6 durability is TWO stores, and this is the one that had no
        // injection point at all before 0.7.0 — see `RevocationBackend`.
        let default_lineage = Arc::new(InMemoryLineageStore::new());
        Self {
            kernel_key_pair,
            vaid_ttl_hours,
            trust_domain,
            lineage: default_lineage.clone(),
            default_lineage,
            revocation: default_store.clone(),
            default_store,
        }
    }

    /// Replace **both** durable halves at once (spec R.4.6): the revocation check
    /// consulted at verification, and the lineage store written on every mint and
    /// read to assemble ancestry. The built-in [`ReferenceIssuer::revoke`] and
    /// [`ReferenceIssuer::clear_lineage`] stores stay but are no longer consulted;
    /// revoke through the injected backend instead. Consumes and re-wraps `self`,
    /// preserving the kernel key and TTL.
    ///
    /// **Lineage already recorded is NOT copied into the injected store.** Install
    /// the backend at construction, before the first mint — an issuer that has
    /// minted into one store and then swaps in another has ancestry split across
    /// two places, and the half in the abandoned store resolves to
    /// [`ParentResolution::Unknown`], i.e. `Unavailable`, for the rest of the
    /// process's life.
    ///
    /// This is the only way to replace either half, and [`RevocationBackend`] has
    /// no single-half constructor, so "revoked set durable, lineage not" — the
    /// configuration whose symptom is that every child credential fails and every
    /// root keeps working — cannot be reached by omitting an argument.
    pub fn with_revocation_backend(mut self, backend: RevocationBackend) -> Self {
        self.revocation = backend.check();
        self.lineage = backend.lineage();
        self
    }

    /// Ask for the pre-0.8.0 default **by name**: an in-memory revocation store that
    /// vouches "nothing is revoked" over an empty set, so a fresh issuer verifies
    /// immediately.
    ///
    /// This is a **fail-open posture**. The store is non-durable and cannot detect
    /// its own restart: after a restart it is reconstructed empty and again vouches
    /// `NotRevoked`, so a VAID revoked before the restart verifies clean. Fine for
    /// local development, quickstarts and tests; not for anything that must survive
    /// a restart.
    ///
    /// It exists because R.4.5 permits fail-open as an explicit configuration and
    /// forbids it as a default — *"it MUST NOT be the default; it MUST be named to
    /// state what it does rather than obscure it."* Until 0.8.0 this posture was the
    /// default and the name appeared nowhere at a call site. It is the same
    /// behaviour; the difference is that asking for it is now visible in the code
    /// that asks.
    ///
    /// The lineage store is untouched and stays in-memory. It has no fail-open
    /// posture to opt into: an unrecorded id is `Unknown`, which is `Unavailable`,
    /// which fails closed.
    ///
    /// ```
    /// # use vaid_mint::{ReferenceIssuer, VaidIssuer};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")?.assuming_nothing_revoked();
    /// # Ok(()) }
    /// ```
    pub fn assuming_nothing_revoked(mut self) -> Self {
        let vouching = Arc::new(InMemoryRevocationList::assume_nothing_revoked());
        self.revocation = vouching.clone();
        self.default_store = vouching;
        self
    }


    /// The kernel public key (raw 32 bytes) a verifier binds this issuer's VAIDs
    /// against.
    pub fn kernel_public_key(&self) -> &[u8] {
        self.kernel_key_pair.public_key().as_ref()
    }

    /// Sign a **detached consent attestation**: this issuer, as the party that
    /// issued `parent_vaid`, consents to `child_vaid` holding at most `scope` and
    /// `capability_set` under it.
    ///
    /// This is the signer half of
    /// [`crate::attestation::ConsentAttestation`]. It exists because consent is
    /// otherwise a property of the mint's *session* — `mint_child` enforces it
    /// in-process and nothing about that enforcement lands in the child document.
    /// A cross-issuer verifier has no way to see it. This makes it a signed object
    /// the presenter can carry.
    ///
    /// The trust domain and thumbprint come from this issuer's own key and
    /// configuration, never from a parameter, so an attestation cannot name a key
    /// or a domain other than the one about to sign it.
    ///
    /// `expires_at` is required. A time bound is a **mitigation, not withdrawal**:
    /// it limits how long stale consent stays usable and does nothing about consent
    /// retracted inside its window, which needs durable revocation — and durable
    /// revocation does not exist here (R.4.6). Choose a short window; that is the
    /// whole of the control.
    ///
    /// **This does not check that `parent_vaid` was actually minted here.** The
    /// reference issuer's lineage map is in-memory and empty after restart
    /// (R.4.6), so a check against it would fail closed on legitimate attestations
    /// after any restart, which is worse than not checking. A verifier does not
    /// rely on this: it independently requires the attestation's thumbprint to
    /// equal the parent document's, so an attestation signed by the wrong issuer is
    /// rejected at verification regardless of what was checked here.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_delegation(
        &self,
        parent_vaid: VaidId,
        child_vaid: VaidId,
        child_trust_domain: String,
        child_tenant_id: String,
        expires_at: DateTime<Utc>,
        scope_boundary: Vec<String>,
        capability_set: Vec<String>,
    ) -> crate::attestation::ConsentAttestation {
        // `issued_at` is the issuing instant, as it is for a minted document.
        // `expires_at` is a REQUIRED parameter with no default and no derived
        // fallback: consent that outlives its purpose must be somebody's stated
        // intention, never a value that arrived by omission.
        //
        // Both are truncated to a whole second (E.6). The caller's `expires_at` is
        // truncated too, because a caller-supplied instant is just as capable of
        // carrying sub-second precision as a clock read and the profile is a
        // property of the SIGNED BYTES, not of who chose the value. Truncation
        // moves an expiry EARLIER by under a second, so it can only ever shorten
        // consent — the safe direction, and the reason this is a truncation rather
        // than a rejection of the caller's argument.
        let unsigned = crate::attestation::ConsentAttestation::new(
            parent_vaid,
            child_vaid,
            child_trust_domain,
            child_tenant_id,
            whole_second_now(),
            expires_at.trunc_subsecs(0),
            scope_boundary,
            capability_set,
            self.trust_domain.clone(),
            crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key()),
        );
        let signature =
            self.kernel_key_pair
                .sign(&crate::attestation::canonical_attestation_signing_bytes(
                    &unsigned,
                ));
        unsigned.with_signature(signature.as_ref().to_vec())
    }

    /// Revoke a VAID in the built-in in-memory store. A revoked VAID — and every
    /// VAID attenuated from it (R.4.4) — fails [`VaidIssuer::verify_vaid`]. Does not
    /// survive restart. Revoking into an absent store also makes it **available**:
    /// a store you have revoked into can vouch for what it holds. Has no effect on
    /// verification if a backend was injected via
    /// [`ReferenceIssuer::with_revocation_backend`]; revoke through that backend
    /// instead.
    pub fn revoke(&self, vaid_id: VaidId) {
        self.default_store.revoke(vaid_id);
    }

    /// Clear the in-memory lineage map, modelling the loss of resolver state across
    /// a process restart. Afterwards any VAID carrying a `parent_vaid` resolves to
    /// [`RevocationStatus::Unavailable`] — its ancestry can no longer be completed
    /// (R.4.2) — while a genuinely rootless VAID still verifies. An ops/test
    /// primitive.
    pub fn clear_lineage(&self) {
        self.default_lineage.clear();
    }

    /// The revocation status of `vaid` under this issuer (spec R.4): assemble its
    /// ordered lineage from this issuer's resolver, then consult the revocation
    /// store with it. An incomplete lineage is [`RevocationStatus::Unavailable`] and
    /// the store is not consulted (R.4.2). [`VaidIssuer::verify_vaid`] gates on this;
    /// it is exposed so a caller can distinguish `Unavailable` from `NotRevoked`
    /// (R.4.3) rather than seeing only a rejected/accepted boolean.
    pub fn revocation_status(&self, vaid: &Vaid) -> RevocationStatus {
        match assemble_lineage(vaid, self) {
            LineageAssembly::Incomplete => RevocationStatus::Unavailable,
            LineageAssembly::Complete(lineage) => self.revocation.check_lineage(&lineage),
        }
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
        // Whole-second, per E.6 — see `whole_second_now`. `expires` stays whole
        // because a whole number of hours added to a whole second is one.
        let now = whole_second_now();
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
            self.trust_domain.clone(),
            // Derived from the signing key itself, never supplied: the thumbprint
            // cannot disagree with the key that is about to sign.
            crate::issuer_identity::kernel_key_thumbprint(self.kernel_public_key()),
        );
        let signature = self
            .kernel_key_pair
            .sign(&canonical_vaid_signing_bytes(&unsigned));
        let vaid = unsigned.with_kernel_signature(signature.as_ref().to_vec());

        // Record EVERY mint — roots as `None`, children as `Some(parent)` — so the
        // resolver can distinguish a known root from an id it has never seen. This
        // is the bookkeeping spec R.4.2 depends on; it changes no document bytes.
        self.lineage.record(vaid.vaid_id(), parent_vaid);

        Ok(vaid)
    }
}

// `compute_lineage_hash` lives in `document` (a document concern, and the
// conformance vector references it); re-exported implicitly via crate root.

impl LineageResolver for ReferenceIssuer {
    /// Resolve one hop from the in-memory lineage map. A recorded VAID with `None`
    /// is a **known root**; a recorded VAID with `Some(parent)` is a **child**; an
    /// unrecorded id is **unknown** — the distinction spec R.4.2 turns on, and the
    /// reason an empty (post-restart) map yields `Unavailable` for a child rather
    /// than mistaking it for a root.
    fn resolve_parent(&self, vaid_id: &VaidId) -> ParentResolution {
        self.lineage.resolve_parent(vaid_id)
    }
}

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
        if vaid.sig_version() != VAID_SIG_VERSION_V3 {
            return false;
        }
        // TTL is now enforced as a hard reject, not merely reported: an expired
        // VAID fails verification even with a valid kernel signature.
        if vaid.is_expired() {
            return false;
        }
        // Revocation over the FULL ordered lineage (R.4.4), failing closed on
        // Unavailable: an incomplete lineage or an unreachable store rejects the
        // VAID — it never silently passes (R.4.2, R.4.5).
        match self.revocation_status(vaid) {
            RevocationStatus::NotRevoked => {}
            RevocationStatus::Revoked | RevocationStatus::Unavailable => return false,
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
        // `assuming_nothing_revoked()` because this test is about the SIGNATURE, not
        // the revocation posture. Since 0.8.0 a bare issuer's revocation store is
        // absent, so `verify_vaid` fails closed on `Unavailable` before the signature
        // is ever in question — see `default_revocation_store_is_absent_and_fails_closed`.
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .assuming_nothing_revoked();
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
        assert!(
            issuer.verify_vaid(&vaid),
            "a freshly issued VAID must verify"
        );
        assert_eq!(vaid.parent_vaid(), None);
        assert_eq!(vaid.sig_version(), VAID_SIG_VERSION_V3);
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
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
        assert!(
            !issuer.verify_vaid(&forged),
            "a rewritten scope must break the signature"
        );
    }

    #[test]
    fn a_different_issuer_does_not_verify() {
        // Both vouching: the assertion under test is that B's KEY does not verify
        // A's VAID, which is only meaningful if revocation is not what rejects it.
        let a = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .assuming_nothing_revoked();
        let b = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .assuming_nothing_revoked();
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
        assert!(
            !b.verify_vaid(&vaid),
            "another issuer's key must not verify this VAID"
        );
    }

    #[test]
    fn revocation_fails_verification() {
        // Vouching, so the FIRST assertion (verifies before revocation) is about
        // revocation rather than about an absent store.
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .assuming_nothing_revoked();
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
        let issuer = ReferenceIssuer::ephemeral(-1, "vaid.example").unwrap();
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

    /// THE 0.8.0 DEFAULT. A bare issuer's revocation store is **absent**, not
    /// vouching: it reports `Unavailable` and verification fails closed (R.4.5).
    /// Until 0.8.0 this returned `NotRevoked` and `true`.
    ///
    /// The paired assertion matters as much as the first: the VAID is still
    /// **authentic**. What changed is standing, not the document — an evaluator who
    /// sees `verify_vaid` return false must be able to tell that apart from a
    /// signing failure.
    #[test]
    fn default_revocation_store_is_absent_and_fails_closed() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example").unwrap();
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
        assert_eq!(
            issuer.revocation_status(&vaid),
            RevocationStatus::Unavailable,
            "a bare issuer has not been told anything about revocation and must not \
             pretend otherwise"
        );
        assert!(!issuer.verify_vaid(&vaid), "fails closed (R.4.5)");
        assert!(
            crate::verify::verify_vaid_authenticity(issuer.kernel_public_key(), &vaid),
            "still authentic — only STANDING failed"
        );
    }

    /// The named opt-in restores the pre-0.8.0 posture exactly, and says so at the
    /// call site. R.4.5 permits fail-open as a configuration and forbids it as a
    /// default; this is the configuration.
    #[test]
    fn assuming_nothing_revoked_restores_the_pre_0_8_posture() {
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .assuming_nothing_revoked();
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
        assert_eq!(issuer.revocation_status(&vaid), RevocationStatus::NotRevoked);
        assert!(issuer.verify_vaid(&vaid));
        // And `revoke` still reaches the store the opt-in installed.
        issuer.revoke(vaid.vaid_id());
        assert_eq!(issuer.revocation_status(&vaid), RevocationStatus::Revoked);
    }

    #[test]
    fn injected_revocation_check_is_consulted() {
        // An assume-nothing-revoked injected store: verifies until something is
        // revoked through it.
        let store = Arc::new(InMemoryRevocationList::assume_nothing_revoked());
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .with_revocation_backend(RevocationBackend::new(
                store.clone(),
                Arc::new(InMemoryLineageStore::new()),
            ));
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
        store.revoke(vaid.vaid_id());
        assert!(
            !issuer.verify_vaid(&vaid),
            "an injected revocation backend must be consulted at verification"
        );
    }

    #[test]
    fn injected_unavailable_store_fails_closed() {
        // A store whose state is absent (e.g. a durable backend that is
        // unreachable) reports Unavailable, and verification fails closed (R.4.5).
        let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")
            .unwrap()
            .with_revocation_backend(RevocationBackend::new(
                Arc::new(InMemoryRevocationList::unavailable()),
                Arc::new(InMemoryLineageStore::new()),
            ));
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
        assert_eq!(
            issuer.revocation_status(&vaid),
            RevocationStatus::Unavailable
        );
        assert!(
            !issuer.verify_vaid(&vaid),
            "a VAID whose revocation store is unavailable must fail closed"
        );
    }

    #[test]
    fn same_seed_issuer_produces_the_same_kernel_public_key() {
        // Determinism the frozen conformance vector will depend on.
        let seed = [7u8; 32];
        let a = ReferenceIssuer::from_seed(&seed, 1, "vaid.example").unwrap();
        let b = ReferenceIssuer::from_seed(&seed, 1, "vaid.example").unwrap();
        assert_eq!(a.kernel_public_key(), b.kernel_public_key());
    }
}

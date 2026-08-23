"""The issuer — Python mirror of the Rust ``vaid_mint::issuer``.

:class:`ReferenceIssuer` holds an Ed25519 kernel key and signs the full canonical
VAID document. Like the Rust reference it deliberately omits the closed managed
authority's machinery. Three things a hosted authority adds that this reference
leaves to the self-hoster:

- **No KMS / secret-store bootstrap.** The kernel key is either generated
  ephemerally (:meth:`ReferenceIssuer.ephemeral`) or supplied by the caller
  (:meth:`ReferenceIssuer.from_seed`). A self-hoster persists and protects that
  key however they choose.
- **Non-durable revocation, a pluggable seam, and a fail-CLOSED default.** The in-memory
  revocation and lineage stores do not survive restart. A self-hoster injects a durable
  backend via the three-state :class:`~vaid_mint.revocation.RevocationCheck` seam
  (:meth:`ReferenceIssuer.with_revocation_backend`, which requires BOTH durable
  halves) without patching the package. The default store is **absent**, so
  verification fails closed out of the box; :meth:`ReferenceIssuer.assuming_nothing_revoked`
  asks for the pre-0.8.0 vouching posture by name. See
  ``docs/spec/revocation.md`` R.4 and the package README's "Trust model" section.
- **The issuer is the lineage resolver.** It records **every** mint in an in-memory
  map — roots with no parent, children with their parent — so it can tell a known
  root from an id it has never seen (:class:`~vaid_mint.revocation.LineageResolver`,
  spec R.4.2). The map is not durable and is not a network service; after a restart
  it is empty, and a child presented against it resolves to ``UNAVAILABLE`` rather
  than being mistaken for a root.

**Expiry (TTL) is a hard reject at verification.** :meth:`ReferenceIssuer.verify_vaid`
returns ``False`` for an expired VAID even when its kernel signature is valid;
:func:`~vaid_mint.document.is_expired` remains available for a caller that needs to
distinguish "forged" from "expired" beforehand.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_mint.error import IdentityError
from vaid_mint.issuer_identity import (
    is_valid_trust_domain,
    kernel_key_thumbprint,
)
from vaid_mint.document import (
    VAID_SIG_VERSION_V3,
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    is_expired,
)
from vaid_mint.revocation import (
    InMemoryLineageStore,
    InMemoryRevocationList,
    LineageStore,
    ParentResolution,
    RevocationBackend,
    RevocationCheck,
    RevocationStatus,
    assemble_lineage,
)

# The default issuance TTL, in hours, when a caller does not supply one. Short by
# design: with only non-durable revocation in this reference, a short TTL is the
# primary control that bounds the exposure window of a leaked or compromised VAID
# (see the README "Trust model"). The constructors still take an explicit
# ``vaid_ttl_hours``; this constant documents the recommended baseline.
DEFAULT_VAID_TTL_HOURS = 1


def _whole_second_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReferenceIssuer:
    """The open reference issuer. Holds an Ed25519 kernel key, an in-memory lineage
    map recording every mint (so it can act as the verifier-side
    :class:`~vaid_mint.revocation.LineageResolver`), and the three-state
    :class:`~vaid_mint.revocation.RevocationCheck` consulted at verification."""

    def __init__(
        self,
        kernel_key: Ed25519PrivateKey,
        vaid_ttl_hours: int,
        trust_domain: str,
    ) -> None:
        if not is_valid_trust_domain(trust_domain):
            # Reject at construction, not at mint: an issuer whose every output
            # would fail verification is not a useful object to hold.
            raise IdentityError(
                f"trust_domain {trust_domain!r} is not well-formed (ADR-0004): "
                "lowercase ASCII letters, digits, '-' and '.'; at least two labels; "
                "each 1-63 bytes without a leading or trailing '-'; no trailing dot; "
                "1-253 bytes total; final label not all-numeric"
            )
        self._trust_domain = trust_domain
        self._kernel_key = kernel_key
        self._vaid_ttl_hours = vaid_ttl_hours
        # The lineage half of the R.4.6 default: in-process, empty after restart.
        # This is the store that had no injection point at all before 0.7.0 — see
        # :class:`~vaid_mint.revocation.RevocationBackend`. Recording roots (not
        # just children) is what lets :meth:`resolve_parent` distinguish a known
        # root from an unknown id — the crux of spec R.4.2.
        self._default_lineage = InMemoryLineageStore()
        # The lineage store written on every mint and read to assemble ancestry;
        # replaced — only together with the revocation check — by
        # :meth:`with_revocation_backend`.
        self._lineage: LineageStore = self._default_lineage
        # The built-in store :meth:`revoke` mutates; the default ``_revocation``.
        #
        # Default revocation posture (0.8.0 onward): ABSENT. The store has not been
        # populated, cannot vouch for anything, and reports UNAVAILABLE, so
        # verification FAILS CLOSED out of the box (R.4.5).
        #
        # Until 0.8.0 this was ``assume_nothing_revoked()`` — a store that vouched
        # NOT_REVOKED over an empty set so a fresh issuer verified immediately. Being
        # non-durable it could not detect its own restart, so a VAID revoked before a
        # restart verified clean afterwards: a fail-open posture, reached by
        # assumption, arrived at by default. R.4.5 requires that fail-open never BE
        # the default and always be named; the reference now obeys that rather than
        # relying on R.4.6's narrower carve-out for it.
        #
        # Three ways forward for a caller: inject a durable backend
        # (:meth:`with_revocation_backend`); load revocation state before verifying,
        # so the absent store fails closed only while it warms; or ask for the old
        # posture BY NAME with :meth:`assuming_nothing_revoked`. See
        # ``docs/spec/revocation.md`` R.4.5 and R.4.6.
        self._store = InMemoryRevocationList()
        # The revocation store consulted in ``verify_vaid``; replaced by
        # :meth:`with_revocation_backend`.
        self._revocation: RevocationCheck = self._store

    # ── constructors mirroring the Rust ones ──

    @classmethod
    def ephemeral(cls, vaid_ttl_hours: int, trust_domain: str) -> "ReferenceIssuer":
        """Freshly generated ephemeral kernel key (not persisted)."""
        return cls(Ed25519PrivateKey.generate(), vaid_ttl_hours, trust_domain)

    @classmethod
    def from_seed(cls, seed: bytes, vaid_ttl_hours: int, trust_domain: str) -> "ReferenceIssuer":
        """Build from a raw 32-byte Ed25519 seed — for deterministic vectors."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed), vaid_ttl_hours, trust_domain)

    def with_revocation_backend(self, backend: RevocationBackend) -> "ReferenceIssuer":
        """Replace **both** durable halves at once (spec R.4.6): the revocation
        check consulted at verification, and the lineage store written on every
        mint and read to assemble ancestry. The built-in :meth:`revoke` and
        :meth:`clear_lineage` stores stay but are no longer consulted; revoke
        through the injected backend instead.

        **Lineage already recorded is NOT copied into the injected store.** Install
        the backend before the first mint — an issuer that has minted into one
        store and then swaps in another has ancestry split across two places, and
        the half in the abandoned store resolves to *unknown*, i.e. ``UNAVAILABLE``,
        for the rest of the process's life.

        This is the only way to replace either half, and
        :class:`~vaid_mint.revocation.RevocationBackend` has no single-half
        constructor, so "revoked set durable, lineage not" — the configuration
        whose symptom is that every child credential fails and every root keeps
        working — cannot be reached by omitting an argument.

        Returns ``self`` so it chains::

            issuer = ReferenceIssuer.ephemeral(1, "vaid.example").with_revocation_backend(
                RevocationBackend(check=durable_revoked, lineage=durable_lineage)
            )
        """
        self._revocation = backend.check
        self._lineage = backend.lineage
        return self

    def assuming_nothing_revoked(self) -> "ReferenceIssuer":
        """Ask for the pre-0.8.0 default **by name**: an in-memory revocation store
        that vouches "nothing is revoked" over an empty set, so a fresh issuer
        verifies immediately.

        This is a **fail-open posture**. The store is non-durable and cannot detect
        its own restart: after a restart it is reconstructed empty and again vouches
        ``NOT_REVOKED``, so a VAID revoked before the restart verifies clean. Fine
        for local development, quickstarts and tests; not for anything that must
        survive a restart.

        It exists because R.4.5 permits fail-open as an explicit configuration and
        forbids it as a default — *"it MUST NOT be the default; it MUST be named to
        state what it does rather than obscure it."* Until 0.8.0 this posture was the
        default and the name appeared nowhere at a call site. It is the same
        behaviour; the difference is that asking for it is now visible in the code
        that asks.

        The lineage store is untouched and stays in-memory. It has no fail-open
        posture to opt into: an unrecorded id is *unknown*, which is ``UNAVAILABLE``,
        which fails closed.

        Returns ``self`` so it chains::

            issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
        """
        self._store = InMemoryRevocationList.assume_nothing_revoked()
        self._revocation = self._store
        return self

    def kernel_public_key(self) -> bytes:
        """The kernel public key (raw 32 bytes) a verifier binds VAIDs against."""
        return self._kernel_key.public_key().public_bytes_raw()

    def attest_delegation(
        self,
        parent_vaid: str,
        child_vaid: str,
        child_trust_domain: str,
        child_tenant_id: str,
        expires_at: str,
        scope_boundary: list[str],
        capability_set: list[str],
    ) -> dict:
        """Sign a **detached consent attestation**: this issuer, as the party that
        issued ``parent_vaid``, consents to ``child_vaid`` holding at most ``scope``
        and ``capability_set`` under it. Mirror of the Rust ``attest_delegation``.

        Consent is otherwise a property of the mint's *session* — ``mint_child``
        enforces it in-process and nothing about that enforcement lands in the child
        document, so a cross-issuer verifier cannot see it. This makes it a signed
        object the presenter can carry.

        The trust domain and thumbprint come from this issuer's own key and
        configuration, never from a parameter, so an attestation cannot name a key
        or domain other than the one about to sign it.

        ``expires_at`` is required. A time bound is a **mitigation, not
        withdrawal**: it limits how long stale consent stays usable and does nothing
        about consent retracted inside its window, which needs durable revocation —
        and durable revocation does not exist here (R.4.6).

        **This does not check that ``parent_vaid`` was actually minted here.** The
        reference lineage map is in-memory and empty after restart (R.4.6), so such
        a check would fail closed on legitimate attestations after any restart. A
        verifier does not rely on it: it independently requires the attestation's
        thumbprint to equal the parent document's.
        """
        from vaid_mint.attestation import (
            build_unsigned_attestation,
            canonical_attestation_signing_bytes,
        )

        # ``issued_at`` is the issuing instant, as it is for a minted document.
        # ``expires_at`` is a REQUIRED parameter with no default and no derived
        # fallback: consent that outlives its purpose must be somebody's stated
        # intention, never a value that arrived by omission.
        unsigned = build_unsigned_attestation(
            parent_vaid=parent_vaid,
            child_vaid=child_vaid,
            child_trust_domain=child_trust_domain,
            child_tenant_id=child_tenant_id,
            issued_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=expires_at,
            scope_boundary=scope_boundary,
            capability_set=capability_set,
            trust_domain=self._trust_domain,
            kernel_key_thumbprint=kernel_key_thumbprint(self.kernel_public_key()),
        )
        signature = self._kernel_key.sign(canonical_attestation_signing_bytes(unsigned))
        return {**unsigned, "signature": list(signature)}

    def revoke(self, vaid_id: str) -> None:
        """Revoke a VAID in the built-in in-memory store. A revoked VAID — and every
        VAID attenuated from it (R.4.4) — fails :meth:`verify_vaid`. Does not survive
        restart. No effect on verification if a custom
        :class:`~vaid_mint.revocation.RevocationCheck` was injected via
        :meth:`with_revocation_backend`; revoke through that backend instead.

        Revoking into an absent store also makes it **available**: a store you have
        revoked into can vouch for what it holds."""
        self._store.revoke(vaid_id)

    def clear_lineage(self) -> None:
        """Clear the in-memory lineage map, modelling the loss of resolver state
        across a process restart. Afterwards any VAID carrying a ``parent_vaid``
        resolves to ``UNAVAILABLE`` — its ancestry can no longer be completed
        (R.4.2) — while a genuinely rootless VAID still verifies. An ops/test
        primitive."""
        self._default_lineage.clear()

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        """Resolve one hop from the in-memory lineage map (spec R.4.2). A recorded
        VAID mapped to ``None`` is a **known root**; mapped to a parent id it is a
        **child**; an unrecorded id is **unknown** — the distinction that makes an
        empty (post-restart) map yield ``UNAVAILABLE`` for a child rather than
        mistaking it for a root."""
        return self._lineage.resolve_parent(vaid_id)

    def revocation_status(self, vaid: dict) -> RevocationStatus:
        """The revocation status of ``vaid`` under this issuer (spec R.4): assemble
        its ordered lineage from this issuer's resolver, then consult the revocation
        store with it. An incomplete lineage is ``UNAVAILABLE`` and the store is not
        consulted (R.4.2). :meth:`verify_vaid` gates on this; it is exposed so a
        caller can distinguish ``UNAVAILABLE`` from ``NOT_REVOKED`` (R.4.3) rather
        than seeing only a rejected/accepted boolean."""
        lineage = assemble_lineage(vaid, self)
        if lineage is None:
            return RevocationStatus.UNAVAILABLE
        return self._revocation.check_lineage(lineage)

    # ── issuance ──

    def _build_and_sign(
        self,
        *,
        agent_class: str,
        version: str,
        tenant_id: str,
        parent_vaid: str | None,
        scope_boundary: list[str],
        capability_set: list[str],
        public_key_der: bytes,
    ) -> dict:
        agent_id = str(uuid.uuid4())
        vaid_id = agent_id  # VaidId::from_uuid(agent_id) — same UUID
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=self._vaid_ttl_hours)
        lineage_hash = compute_lineage_hash(parent_vaid, agent_id)

        unsigned = build_unsigned_vaid_document(
            vaid_id=vaid_id,
            agent_id=agent_id,
            agent_class=agent_class,
            version=version,
            tenant_id=tenant_id,
            issued_at=_whole_second_rfc3339(now),
            expires_at=_whole_second_rfc3339(expires),
            public_key_der=list(public_key_der),
            parent_vaid=parent_vaid,
            scope_boundary=scope_boundary,
            lineage_hash=lineage_hash,
            capability_set=capability_set,
            trust_domain=self._trust_domain,
            # Derived from the signing key itself, never supplied: the thumbprint
            # cannot disagree with the key that is about to sign.
            kernel_key_thumbprint=kernel_key_thumbprint(
                self._kernel_key.public_key().public_bytes_raw()
            ),
        )
        digest = canonical_vaid_signing_bytes(unsigned)
        signature = self._kernel_key.sign(digest)  # raw 64-byte Ed25519
        signed = dict(unsigned)
        signed["kernel_signature"] = list(signature)

        # Record EVERY mint — roots as ``None``, children as their parent — so the
        # resolver can distinguish a known root from an id it has never seen. This
        # is the bookkeeping spec R.4.2 depends on; it changes no document bytes.
        self._lineage.record(vaid_id, parent_vaid)
        return signed

    def issue_vaid_with_key(
        self,
        *,
        agent_class: str,
        version: str,
        tenant_id: str,
        parent_vaid: str | None,
        scope_boundary: list[str],
        capability_set: list[str],
        public_key_der: bytes,
    ) -> dict:
        """Issue under a caller-supplied public key (BYO-key path; PoP already
        verified by the mint)."""
        return self._build_and_sign(
            agent_class=agent_class,
            version=version,
            tenant_id=tenant_id,
            parent_vaid=parent_vaid,
            scope_boundary=scope_boundary,
            capability_set=capability_set,
            public_key_der=public_key_der,
        )

    def issue_vaid_with_lineage(
        self,
        *,
        agent_class: str,
        version: str,
        tenant_id: str,
        parent_vaid: str | None,
        scope_boundary: list[str],
        capability_set: list[str],
    ) -> dict:
        """Issue under an issuer-generated keypair, discarding the private half."""
        ephemeral = Ed25519PrivateKey.generate()
        public_key_der = ephemeral.public_key().public_bytes_raw()
        return self._build_and_sign(
            agent_class=agent_class,
            version=version,
            tenant_id=tenant_id,
            parent_vaid=parent_vaid,
            scope_boundary=scope_boundary,
            capability_set=capability_set,
            public_key_der=public_key_der,
        )

    def verify_vaid(self, vaid: dict) -> bool:
        """Verify a VAID against this issuer: correct signature scheme, kernel
        signature valid over the canonical document, **not expired**, and not
        revoked.

        Expiry is a hard reject — an expired VAID returns ``False`` even with a
        valid kernel signature. :func:`~vaid_mint.document.is_expired` remains
        available for a caller that needs to distinguish "forged" from "expired"
        before calling this.

        Revocation is checked over the VAID's full ordered lineage via
        :meth:`revocation_status` (spec R.4): a VAID is rejected if any ancestor is
        revoked (R.4.4), and verification **fails closed** when the status is
        ``UNAVAILABLE`` — an incomplete lineage or an unreachable store
        (R.4.2/R.4.5).

        A bad signature is ``False``, never an exception.
        """
        if vaid.get("sig_version") != VAID_SIG_VERSION_V3:
            return False
        # TTL is enforced as a hard reject, not merely reported: an expired VAID
        # fails verification even with a valid kernel signature.
        if is_expired(vaid):
            return False
        # Revocation over the FULL ordered lineage (R.4.4), failing closed on
        # UNAVAILABLE: an incomplete lineage or an unreachable store rejects the
        # VAID — it never silently passes (R.4.2, R.4.5).
        if self.revocation_status(vaid) is not RevocationStatus.NOT_REVOKED:
            return False
        digest = canonical_vaid_signing_bytes(vaid)
        sig = bytes(vaid["kernel_signature"])
        public_key = Ed25519PublicKey.from_public_bytes(self.kernel_public_key())
        try:
            public_key.verify(sig, digest)
            return True
        except InvalidSignature:
            return False

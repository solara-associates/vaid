"""The issuer — Python mirror of the Rust ``vaid_mint::issuer``.

:class:`ReferenceIssuer` holds an Ed25519 kernel key and signs the full canonical
VAID document. Like the Rust reference it deliberately omits the closed managed
authority's machinery. Three things a hosted authority adds that this reference
leaves to the self-hoster:

- **No KMS / secret-store bootstrap.** The kernel key is either generated
  ephemerally (:meth:`ReferenceIssuer.ephemeral`) or supplied by the caller
  (:meth:`ReferenceIssuer.from_seed`). A self-hoster persists and protects that
  key however they choose.
- **Non-durable revocation, but a pluggable seam.** The default in-memory
  revocation store does not survive restart. A self-hoster injects a durable
  backend via the three-state :class:`~vaid_mint.revocation.RevocationCheck` seam
  (:meth:`ReferenceIssuer.with_revocation_check`) without patching the package. See
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

from vaid_mint.document import (
    VAID_SIG_VERSION_V2,
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    is_expired,
)
from vaid_mint.revocation import (
    InMemoryRevocationList,
    ParentResolution,
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

    def __init__(self, kernel_key: Ed25519PrivateKey, vaid_ttl_hours: int) -> None:
        self._kernel_key = kernel_key
        self._vaid_ttl_hours = vaid_ttl_hours
        # Every minted VAID: parent id for a child, ``None`` for a root. Recording
        # roots (not just children) is what lets :meth:`resolve_parent` distinguish
        # a known root from an unknown id — the crux of spec R.4.2.
        self._lineage: dict[str, str | None] = {}
        # The built-in store :meth:`revoke` mutates; the default ``_revocation``.
        # Initialised-and-empty so a live issuer can vouch "nothing revoked yet".
        self._store = InMemoryRevocationList.initialised_empty()
        # The revocation store consulted in ``verify_vaid``; replaced by
        # :meth:`with_revocation_check`.
        self._revocation: RevocationCheck = self._store

    # ── constructors mirroring the Rust ones ──

    @classmethod
    def ephemeral(cls, vaid_ttl_hours: int) -> "ReferenceIssuer":
        """Freshly generated ephemeral kernel key (not persisted)."""
        return cls(Ed25519PrivateKey.generate(), vaid_ttl_hours)

    @classmethod
    def from_seed(cls, seed: bytes, vaid_ttl_hours: int) -> "ReferenceIssuer":
        """Build from a raw 32-byte Ed25519 seed — for deterministic vectors."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed), vaid_ttl_hours)

    def with_revocation_check(self, revocation_check: RevocationCheck) -> "ReferenceIssuer":
        """Replace the revocation store consulted at verification with an injected
        :class:`~vaid_mint.revocation.RevocationCheck` — e.g. a durable,
        restart-surviving backend that returns ``UNAVAILABLE`` when its store is
        unreachable. The built-in :meth:`revoke` store stays but is no longer
        consulted; revoke through the injected backend instead.

        Returns ``self`` so it chains::

            issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(check)
        """
        self._revocation = revocation_check
        return self

    def kernel_public_key(self) -> bytes:
        """The kernel public key (raw 32 bytes) a verifier binds VAIDs against."""
        return self._kernel_key.public_key().public_bytes_raw()

    def revoke(self, vaid_id: str) -> None:
        """Revoke a VAID in the built-in in-memory store. A revoked VAID — and every
        VAID attenuated from it (R.4.4) — fails :meth:`verify_vaid`. Does not survive
        restart. No effect on verification if a custom
        :class:`~vaid_mint.revocation.RevocationCheck` was injected via
        :meth:`with_revocation_check`; revoke through that backend instead."""
        self._store.revoke(vaid_id)

    def clear_lineage(self) -> None:
        """Clear the in-memory lineage map, modelling the loss of resolver state
        across a process restart. Afterwards any VAID carrying a ``parent_vaid``
        resolves to ``UNAVAILABLE`` — its ancestry can no longer be completed
        (R.4.2) — while a genuinely rootless VAID still verifies. An ops/test
        primitive."""
        self._lineage.clear()

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        """Resolve one hop from the in-memory lineage map (spec R.4.2). A recorded
        VAID mapped to ``None`` is a **known root**; mapped to a parent id it is a
        **child**; an unrecorded id is **unknown** — the distinction that makes an
        empty (post-restart) map yield ``UNAVAILABLE`` for a child rather than
        mistaking it for a root."""
        if vaid_id not in self._lineage:
            return ParentResolution.unknown()
        parent = self._lineage[vaid_id]
        return ParentResolution.root() if parent is None else ParentResolution.of_parent(parent)

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
        )
        digest = canonical_vaid_signing_bytes(unsigned)
        signature = self._kernel_key.sign(digest)  # raw 64-byte Ed25519
        signed = dict(unsigned)
        signed["kernel_signature"] = list(signature)

        # Record EVERY mint — roots as ``None``, children as their parent — so the
        # resolver can distinguish a known root from an id it has never seen. This
        # is the bookkeeping spec R.4.2 depends on; it changes no document bytes.
        self._lineage[vaid_id] = parent_vaid
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
        if vaid.get("sig_version") != VAID_SIG_VERSION_V2:
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

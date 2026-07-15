"""The issuer — Python mirror of the Rust ``vaid_mint::issuer``.

:class:`ReferenceIssuer` holds an Ed25519 kernel key and signs the full canonical
VAID document. Like the Rust reference it deliberately omits the closed managed
authority's machinery. Three things a hosted authority adds that this reference
leaves to the self-hoster:

- **No KMS / secret-store bootstrap.** The kernel key is either generated
  ephemerally (:meth:`ReferenceIssuer.ephemeral`) or supplied by the caller
  (:meth:`ReferenceIssuer.from_seed`). A self-hoster persists and protects that
  key however they choose.
- **Non-durable revocation, but a pluggable seam.** The built-in revoked set is
  in-memory and does not survive restart. A self-hoster can now inject a durable
  backend via the :class:`~vaid_mint.revocation.RevocationCheck` seam
  (:meth:`ReferenceIssuer.with_revocation_check`) without patching the package;
  the built-in in-memory set remains the default and any injected check is layered
  on top of it. See the package README's "Trust model" section.
- **No lineage lookup service.** The child→parent map is kept in memory for local
  inspection only.

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
from vaid_mint.revocation import RevocationCheck

# The default issuance TTL, in hours, when a caller does not supply one. Short by
# design: with only non-durable revocation in this reference, a short TTL is the
# primary control that bounds the exposure window of a leaked or compromised VAID
# (see the README "Trust model"). The constructors still take an explicit
# ``vaid_ttl_hours``; this constant documents the recommended baseline.
DEFAULT_VAID_TTL_HOURS = 1


def _whole_second_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReferenceIssuer:
    """The open reference issuer. Holds an Ed25519 kernel key, an in-memory
    child→parent lineage map, an in-memory revoked set (the default revocation
    backend), and an optional injected
    :class:`~vaid_mint.revocation.RevocationCheck` layered on top of it."""

    def __init__(self, kernel_key: Ed25519PrivateKey, vaid_ttl_hours: int) -> None:
        self._kernel_key = kernel_key
        self._vaid_ttl_hours = vaid_ttl_hours
        self._lineage: dict[str, str] = {}
        self._revoked: set[str] = set()
        # An optional additional revocation backend, consulted in ``verify_vaid``
        # alongside (not instead of) the built-in ``_revoked`` set. ``None`` by
        # default; injected via :meth:`with_revocation_check`.
        self._revocation_check: RevocationCheck | None = None

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
        """Inject an additional :class:`~vaid_mint.revocation.RevocationCheck`
        backend (e.g. a durable, restart-surviving store). It is consulted in
        :meth:`verify_vaid` **in addition to** the built-in in-memory revoked set
        — a VAID is rejected if either reports it revoked — so enabling the seam
        never silently disables the built-in behavior.

        Returns ``self`` so it chains::

            issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(check)
        """
        self._revocation_check = revocation_check
        return self

    def kernel_public_key(self) -> bytes:
        """The kernel public key (raw 32 bytes) a verifier binds VAIDs against."""
        return self._kernel_key.public_key().public_bytes_raw()

    def revoke(self, vaid_id: str) -> None:
        """Revoke a VAID (in-memory). A revoked VAID fails :meth:`verify_vaid`
        regardless of signature validity. Does not survive restart."""
        self._revoked.add(vaid_id)

    def is_revoked(self, vaid_id: str) -> bool:
        """Is this VAID revoked in this issuer's built-in in-memory set?"""
        return vaid_id in self._revoked

    def parent_of(self, vaid_id: str) -> str | None:
        return self._lineage.get(vaid_id)

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

        if parent_vaid is not None:
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

        Revocation is checked against the built-in in-memory revoked set *and*
        any :class:`~vaid_mint.revocation.RevocationCheck` injected via
        :meth:`with_revocation_check` — the seam is additive, so a VAID is
        rejected if *either* reports it revoked.

        A bad signature is ``False``, never an exception.
        """
        if vaid.get("sig_version") != VAID_SIG_VERSION_V2:
            return False
        # TTL is enforced as a hard reject, not merely reported: an expired VAID
        # fails verification even with a valid kernel signature.
        if is_expired(vaid):
            return False
        # Built-in in-memory revoked set, plus any injected revocation backend.
        if self.is_revoked(vaid["vaid_id"]):
            return False
        if self._revocation_check is not None and self._revocation_check.is_revoked(
            vaid["vaid_id"]
        ):
            return False
        digest = canonical_vaid_signing_bytes(vaid)
        sig = bytes(vaid["kernel_signature"])
        public_key = Ed25519PublicKey.from_public_bytes(self.kernel_public_key())
        try:
            public_key.verify(sig, digest)
            return True
        except InvalidSignature:
            return False

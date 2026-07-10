"""The issuer — Python mirror of the Rust ``vaid_mint::issuer``.

:class:`ReferenceIssuer` holds an Ed25519 kernel key and signs the full canonical
VAID document. Like the Rust reference it deliberately omits the closed managed
authority's machinery: no KMS/secret-store bootstrap (the key is ephemeral or
caller/seed-supplied), no durable revocation (in-memory only), no lineage service
(in-memory map for local inspection).
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
)


def _whole_second_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReferenceIssuer:
    """The open reference issuer. Holds an Ed25519 kernel key, an in-memory
    child→parent lineage map, and an in-memory revoked set."""

    def __init__(self, kernel_key: Ed25519PrivateKey, vaid_ttl_hours: int) -> None:
        self._kernel_key = kernel_key
        self._vaid_ttl_hours = vaid_ttl_hours
        self._lineage: dict[str, str] = {}
        self._revoked: set[str] = set()

    # ── constructors mirroring the Rust ones ──

    @classmethod
    def ephemeral(cls, vaid_ttl_hours: int) -> "ReferenceIssuer":
        """Freshly generated ephemeral kernel key (not persisted)."""
        return cls(Ed25519PrivateKey.generate(), vaid_ttl_hours)

    @classmethod
    def from_seed(cls, seed: bytes, vaid_ttl_hours: int) -> "ReferenceIssuer":
        """Build from a raw 32-byte Ed25519 seed — for deterministic vectors."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed), vaid_ttl_hours)

    def kernel_public_key(self) -> bytes:
        """The kernel public key (raw 32 bytes) a verifier binds VAIDs against."""
        return self._kernel_key.public_key().public_bytes_raw()

    def revoke(self, vaid_id: str) -> None:
        self._revoked.add(vaid_id)

    def is_revoked(self, vaid_id: str) -> bool:
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
        """Verify a VAID against this issuer: correct scheme, kernel signature
        valid over the canonical document, and not revoked. A bad signature is
        ``False``, never an exception."""
        if vaid.get("sig_version") != VAID_SIG_VERSION_V2:
            return False
        if self.is_revoked(vaid["vaid_id"]):
            return False
        digest = canonical_vaid_signing_bytes(vaid)
        sig = bytes(vaid["kernel_signature"])
        public_key = Ed25519PublicKey.from_public_bytes(self.kernel_public_key())
        try:
            public_key.verify(sig, digest)
            return True
        except InvalidSignature:
            return False

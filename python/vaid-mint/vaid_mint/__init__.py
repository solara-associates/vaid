"""vaid-mint — the open, self-hostable reference mint for the VAID standard (Python).

The Python mirror of the Rust ``vaid-mint`` crate: mint a root VAID
(:meth:`~vaid_mint.mint.MintService.mint_root`) and mint attenuated child VAIDs
(:meth:`~vaid_mint.mint.MintService.mint_child`), where a child's authority is
always a subset of its parent's (``child ⊆ parent``).

This is the open engine of a HashiCorp-Vault-style split; the managed authority
(KMS-backed keys, the audit-of-record, and *durable* revocation) is the closed
product and is deliberately NOT here. Revocation has a pluggable seam here as of
0.1.2 (:class:`~vaid_mint.revocation.RevocationCheck`, injected via
:meth:`~vaid_mint.issuer.ReferenceIssuer.with_revocation_check`) — additive, with a
non-durable in-memory default — and VAID expiry (TTL) is hard-enforced at
verification. What stays commercial is durable, restart-surviving revocation
itself. Proof-of-possession reuses the ``vaid-pop`` primitive verbatim. Byte-identity of the signed VAID document with the Rust mint is locked
by the vendored cross-language vector ``vaid_mint/vectors/mint_v1.json``.

Per Decision B this is self-consistent WITHIN this repo (Rust == Python), NOT
byte-conformant against the managed authority's VAID format.

Usage::

    from vaid_mint import ReferenceIssuer, InMemoryAudit, MintService, VaidSeed

    issuer = ReferenceIssuer.ephemeral(24)
    mint = MintService(issuer, InMemoryAudit())
    vaid = mint.mint_root(VaidSeed(agent_class="orchestrator", version="1.0.0",
                                   tenant_id="acme", scope_boundary=["data.acme"],
                                   capability_set=["read"]))
    assert issuer.verify_vaid(vaid)
"""

from vaid_mint.audit import AuditEntry, AuditSink, InMemoryAudit, NoopAudit
from vaid_mint.authz import AuthorizationGate, DenyAll, PermitAll
from vaid_mint.document import (
    VAID_SIG_VERSION_V2,
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    has_capability,
    is_expired,
    is_in_scope,
)
from vaid_mint.error import AuditError, IdentityError, MintError, UnauthorizedError
from vaid_mint.issuer import DEFAULT_VAID_TTL_HOURS, ReferenceIssuer
from vaid_mint.mint import (
    MINT_POP_FRESHNESS_SECS,
    MintService,
    caps_attenuate,
    scope_attenuates,
)
from vaid_mint.mint_types import MintPop, VaidSeed, build_mint_pop_payload
from vaid_mint.revocation import InMemoryRevocationList, NeverRevoked, RevocationCheck

__all__ = [
    "ReferenceIssuer",
    "MintService",
    "VaidSeed",
    "MintPop",
    "build_mint_pop_payload",
    "canonical_vaid_signing_bytes",
    "compute_lineage_hash",
    "build_unsigned_vaid_document",
    "is_in_scope",
    "is_expired",
    "has_capability",
    "scope_attenuates",
    "caps_attenuate",
    "VAID_SIG_VERSION_V2",
    "MINT_POP_FRESHNESS_SECS",
    "DEFAULT_VAID_TTL_HOURS",
    "RevocationCheck",
    "NeverRevoked",
    "InMemoryRevocationList",
    "AuditSink",
    "AuditEntry",
    "InMemoryAudit",
    "NoopAudit",
    "AuthorizationGate",
    "PermitAll",
    "DenyAll",
    "MintError",
    "UnauthorizedError",
    "IdentityError",
    "AuditError",
]

__version__ = "0.1.2"

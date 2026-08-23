"""vaid-mint — the open, self-hostable reference mint for the VAID standard (Python).

The Python mirror of the Rust ``vaid-mint`` crate: mint a root VAID
(:meth:`~vaid_mint.mint.MintService.mint_root`) and mint attenuated child VAIDs
(:meth:`~vaid_mint.mint.MintService.mint_child`), where a child's authority is
always a subset of its parent's (``child ⊆ parent``).

This is the open engine of a HashiCorp-Vault-style split; the managed authority
(KMS-backed keys, the *durable, hash-chained* audit-of-record, and *durable*
revocation) is the closed
product and is deliberately NOT here. Revocation has a pluggable seam here — three-state
and lineage-aware as of 0.2.0 (:class:`~vaid_mint.revocation.RevocationCheck`,
injected via :meth:`~vaid_mint.issuer.ReferenceIssuer.with_revocation_check`),
specified in ``docs/spec/revocation.md`` R.4 and failing closed when status is
unavailable — with a non-durable in-memory default, and VAID expiry (TTL) is
hard-enforced at verification. What stays commercial is durable, restart-surviving
revocation itself. Proof-of-possession reuses the ``vaid-pop`` primitive verbatim. Byte-identity of the signed VAID document with the Rust mint is locked
by the vendored cross-language vector ``vaid_mint/vectors/mint_v1.json``.

Per Decision B this is self-consistent WITHIN this repo (Rust == Python), NOT
byte-conformant against the managed authority's VAID format.

Usage::

    from vaid_mint import ReferenceIssuer, InMemoryAudit, MintService, VaidSeed

    issuer = ReferenceIssuer.ephemeral(24, "vaid.example")
    mint = MintService(issuer, InMemoryAudit())
    vaid = mint.mint_root(VaidSeed(agent_class="orchestrator", version="1.0.0",
                                   tenant_id="acme", scope_boundary=["data.acme"],
                                   capability_set=["read"]))
    assert issuer.verify_vaid(vaid)
"""

from vaid_mint.audit import AuditEntry, AuditSink, InMemoryAudit, NoopAudit
from vaid_mint.attestation import (
    ATTESTATION_VERSION,
    AttestationBundle,
    build_unsigned_attestation,
    canonical_attestation_signing_bytes,
    verify_attestation_authenticity,
)
from vaid_mint.chain import (
    ChainVerification,
    KernelKeyMap,
    KernelKeyResolver,
    PresentedBundle,
    SingleKernelKey,
    verify_chain,
    verify_chain_at,
    verify_chain_with,
)
from vaid_mint.authz import AuthorizationGate, DenyAll, PermitAll
from vaid_mint.document import (
    VAID_SIG_VERSION_V3,
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    has_capability,
    is_expired,
    has_conforming_timestamps,
    is_in_scope,
)
from vaid_mint.error import AuditError, IdentityError, MintError, UnauthorizedError
from vaid_mint.issuer import DEFAULT_VAID_TTL_HOURS, ReferenceIssuer
from vaid_mint.mint import (
    MINT_POP_FRESHNESS_SECS,
    MintService,
    caps_attenuate,
    scope_attenuates,
    scope_attenuates_within,
    tenant_attenuates,
)
from vaid_mint.mint_types import MintPop, VaidSeed, build_mint_pop_payload
from vaid_mint.verify import (
    parse_vaid_document,
    verify_lineage_hash,
    verify_vaid_authenticity,
    verify_vaid_authenticity_graded,
    verify_vaid_standing,
    verify_vaid_standing_from_json,
    VaidVerdict,
)
from vaid_mint.revocation import (
    InMemoryLineageStore,
    InMemoryRevocationList,
    LineageResolver,
    LineageStore,
    ParentResolution,
    RevocationBackend,
    RevocationCheck,
    RevocationStatus,
    assemble_lineage,
)

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
    "has_conforming_timestamps",
    "has_capability",
    "scope_attenuates",
    "scope_attenuates_within",
    "caps_attenuate",
    "tenant_attenuates",
    "VAID_SIG_VERSION_V3",
    "MINT_POP_FRESHNESS_SECS",
    "DEFAULT_VAID_TTL_HOURS",
    "RevocationCheck",
    "RevocationStatus",
    "InMemoryLineageStore",
    "InMemoryRevocationList",
    "LineageResolver",
    "LineageStore",
    "RevocationBackend",
    "ParentResolution",
    "assemble_lineage",
    "verify_vaid_authenticity",
    "verify_lineage_hash",
    "VaidVerdict",
    "verify_vaid_authenticity_graded",
    "verify_vaid_standing",
    "verify_vaid_standing_from_json",
    "parse_vaid_document",
    "verify_chain",
    "ChainVerification",
    "PresentedBundle",
    "verify_chain_with",
    "verify_chain_at",
    "KernelKeyResolver",
    "SingleKernelKey",
    "KernelKeyMap",
    "AttestationBundle",
    "ATTESTATION_VERSION",
    "build_unsigned_attestation",
    "canonical_attestation_signing_bytes",
    "verify_attestation_authenticity",
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

__version__ = "0.8.0"

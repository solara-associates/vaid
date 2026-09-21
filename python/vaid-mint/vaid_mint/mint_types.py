"""Mint wire types — Python mirror of the Rust ``vaid_mint::mint_types``.

``VaidSeed`` / ``MintPop`` are the request shapes; ``build_mint_pop_payload``
reconstructs the exact camelCase ``MintPopPayload`` a holder signs (via the shared
``vaid-pop`` primitive) to prove possession of the BYO key it registers. The
payload field names/encodings mirror the Rust ``MintPopPayload`` serde
(``rename_all = "camelCase"``, ``Vec<u8>`` → list of ints) so the signed bytes
agree cross-language by construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VaidSeed:
    """Requested attributes for a mint (mirror of the Rust ``VaidSeed``)."""

    agent_class: str
    version: str
    tenant_id: str
    parent_vaid: str | None = None
    scope_boundary: list[str] = field(default_factory=list)
    capability_set: list[str] = field(default_factory=list)
    # Holder-supplied Ed25519 public key (BYO-key), as raw bytes. ``None`` = the
    # generate-and-discard path (root only; no PoP applies).
    public_key_der: bytes | None = None


@dataclass(frozen=True)
class MintChildResponse:
    """What :meth:`~vaid_mint.mint.MintService.mint_child` returns: the signed
    child document, and what the mint did to its lifetime.

    **This replaces the bare document the method used to return** (0.8.0,
    breaking). The reason is ADR-0007: a delegated child is **clamped** to its
    parent's expiry rather than refused for exceeding it, and the objection to
    clamping is that an issuer handing back a credential shorter than its stated
    policy is a surprise the caller cannot see. ``expires_at`` alone looks like an
    ordinary expiry; a caller would have to know the issuer's TTL and subtract to
    notice anything had happened. So the mint says it outright.

    Migrating: ``vaid = svc.mint_child(...)`` becomes
    ``vaid = svc.mint_child(...).vaid``. The Rust and TypeScript twins already
    returned a response object (``MintVaidResponse``) and gained the same two
    fields, so this brings Python into line rather than inventing a shape.
    """

    #: The newly-minted, signed child VAID document.
    vaid: dict
    #: **The child's lifetime was bounded by its parent's, not by the issuer's
    #: TTL.** True exactly when the issued ``expires_at`` equals
    #: :attr:`parent_expires_at`. A caller that cares about the child's remaining
    #: life should read this: the usual reaction is to renew the parent before
    #: delegating, not to retry.
    expiry_bounded_by_parent: bool
    #: The authenticated parent's ``expires_at``, exactly as presented, so the
    #: caller can see the bound itself and not only that one applied.
    parent_expires_at: str


@dataclass
class MintPop:
    """A holder's proof-of-possession for a mint (mirror of the Rust ``MintPop``)."""

    nonce: str
    issued_at: str  # whole-second RFC 3339 "…Z"
    signature: bytes


def build_mint_pop_payload(
    seed: VaidSeed,
    *,
    public_key_der: bytes,
    nonce: str,
    issued_at: str,
) -> dict:
    """Reconstruct the canonical ``MintPopPayload`` (camelCase) for ``seed``.

    Both holder and mint build the payload through this one function so the signed
    bytes match exactly. ``public_key_der`` (the registered key being proven) is
    supplied explicitly because PoP only applies on the BYO-key path. Byte fields
    are lists of ints, mirroring Rust ``Vec<u8>`` serialization.
    """
    return {
        "publicKeyDer": list(public_key_der),
        "tenantId": seed.tenant_id,
        "agentClass": seed.agent_class,
        "version": seed.version,
        "parentVaid": seed.parent_vaid,
        "scopeBoundary": list(seed.scope_boundary),
        "capabilitySet": list(seed.capability_set),
        "nonce": nonce,
        "issuedAt": issued_at,
    }

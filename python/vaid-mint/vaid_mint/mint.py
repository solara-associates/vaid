"""The mint — Python mirror of the Rust ``vaid_mint::mint``.

:class:`MintService` wraps a :class:`~vaid_mint.issuer.ReferenceIssuer`, an
:class:`~vaid_mint.audit.AuditSink`, and a root-mint
:class:`~vaid_mint.authz.AuthorizationGate` (default :class:`PermitAll`). Two
entry points:

- :meth:`MintService.mint_root` — mint a root/operator VAID (gated), BYO-key with
  a verified proof-of-possession or generate-and-discard.
- :meth:`MintService.mint_child` — attenuated delegation: an authenticated parent
  ``P`` mints child ``C`` iff ``C``'s tenant, lineage, scope, and capabilities are
  all within ``P``'s, verified fail-closed BEFORE any key work or nonce
  consumption. ``child ⊆ parent``, always.

Proof-of-possession reuses the ``vaid-pop`` primitive verbatim, so the mint's PoP
bytes match a conforming verifier by construction.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_pop import canonical_request_signing_bytes

from vaid_mint.audit import AuditSink
from vaid_mint.authz import AuthorizationGate, PermitAll
from vaid_mint.document import has_capability, is_in_scope
from vaid_mint.error import IdentityError, UnauthorizedError
from vaid_mint.issuer import ReferenceIssuer
from vaid_mint.mint_types import MintPop, VaidSeed, build_mint_pop_payload

# Freshness window for a mint proof-of-possession, in seconds.
MINT_POP_FRESHNESS_SECS = 300


def scope_attenuates(parent: dict, child_scope: list[str]) -> bool:
    """Is every entry of ``child_scope`` within ``parent``'s scope? Uses only
    ``is_in_scope`` (the single matcher). Empty child scope = ⊤ is permitted only
    under an empty/⊤ parent (the escalation guard)."""
    if not child_scope:
        return not parent["scope_boundary"]
    return all(is_in_scope(parent, s) for s in child_scope)


def caps_attenuate(parent: dict, child_caps: list[str]) -> bool:
    """Is every entry of ``child_caps`` held by ``parent``? Uses only
    ``has_capability``. Empty child caps = ∅ is safe; empty parent caps holds
    nothing (the deliberate scope/caps asymmetry)."""
    return all(has_capability(parent, c) for c in child_caps)


class MintService:
    def __init__(
        self,
        issuer: ReferenceIssuer,
        audit: AuditSink,
        authz: AuthorizationGate | None = None,
    ) -> None:
        """Construct the mint. ``authz`` defaults to :class:`PermitAll` — a
        reference choice, NOT a security recommendation; a production deployment
        supplies a real gate here."""
        self._issuer = issuer
        self._audit = audit
        self._authz: AuthorizationGate = authz if authz is not None else PermitAll()
        self._consumed_pop_nonces: set[str] = set()

    def _verify_pop_at_mint(
        self, seed: VaidSeed, registered_key: bytes, pop: MintPop | None
    ) -> None:
        """Proof-of-possession at mint — mirror of the Rust ``verify_pop_at_mint``.
        Order: present → fresh → not replayed (record-before-process) → signature
        verifies against the registered key."""
        if pop is None:
            raise IdentityError(
                "proof-of-possession required — public_key_der was supplied "
                "(BYO-key) without a `pop` signature"
            )

        # (2) Freshness.
        issued = datetime.strptime(pop.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        skew = abs((datetime.now(timezone.utc) - issued).total_seconds())
        if skew > MINT_POP_FRESHNESS_SECS:
            raise IdentityError(
                f"PoP timestamp outside freshness window "
                f"({int(skew)}s > {MINT_POP_FRESHNESS_SECS}s)"
            )

        # (3) Replay — record before accepting the signature.
        if pop.nonce in self._consumed_pop_nonces:
            raise IdentityError("PoP nonce already used — replay rejected")
        self._consumed_pop_nonces.add(pop.nonce)

        # (4) Signature over the canonical payload, against the REGISTERED key.
        payload = build_mint_pop_payload(
            seed, public_key_der=registered_key, nonce=pop.nonce, issued_at=pop.issued_at
        )
        digest = canonical_request_signing_bytes(payload)
        try:
            Ed25519PublicKey.from_public_bytes(registered_key).verify(pop.signature, digest)
        except InvalidSignature as exc:
            raise IdentityError(
                "PoP signature does not verify against the registered public key — "
                "cannot register a key you do not control"
            ) from exc

    def mint_root(self, seed: VaidSeed, pop: MintPop | None = None) -> dict:
        """Mint a root/operator VAID. The authorization gate runs first; then, for
        a BYO-key seed, a valid PoP is required; otherwise generate-and-discard."""
        # Root-mint authorization seam (defaults to PermitAll). First, before any
        # key work — a denied mint has no side effects.
        self._authz.authorize_root_mint(seed)

        byo_key = seed.public_key_der is not None
        if byo_key:
            self._verify_pop_at_mint(seed, seed.public_key_der, pop)
            vaid = self._issuer.issue_vaid_with_key(
                agent_class=seed.agent_class,
                version=seed.version,
                tenant_id=seed.tenant_id,
                parent_vaid=seed.parent_vaid,
                scope_boundary=seed.scope_boundary,
                capability_set=seed.capability_set,
                public_key_der=seed.public_key_der,
            )
        else:
            vaid = self._issuer.issue_vaid_with_lineage(
                agent_class=seed.agent_class,
                version=seed.version,
                tenant_id=seed.tenant_id,
                parent_vaid=seed.parent_vaid,
                scope_boundary=seed.scope_boundary,
                capability_set=seed.capability_set,
            )

        self._audit.record(
            "vaid_minted",
            {
                "agent_class": seed.agent_class,
                "version": seed.version,
                "tenant_id": seed.tenant_id,
                "parent_vaid": seed.parent_vaid,
                "scope_boundary": seed.scope_boundary,
                "capability_set_len": len(seed.capability_set),
                "byo_key": byo_key,
                "pop_verified": byo_key,
                "delegated": False,
            },
        )
        return vaid

    def mint_child(self, seed: VaidSeed, parent: dict | None, pop: MintPop | None = None) -> dict:
        """Attenuated delegation — mirror of the Rust ``mint_child``. All of
        (parent present, same tenant, bound lineage, scope ⊆, caps ⊆) are checked
        fail-closed BEFORE the PoP so a rejected delegation never burns a nonce."""
        # (1) The parent's authority must have travelled — fail closed.
        if parent is None:
            raise UnauthorizedError(
                "no verified parent VAID in context — delegation requires an "
                "authenticated parent principal, fail-closed"
            )

        # (2) Same tenant, grounded in the parent's VERIFIED VAID — never the body.
        if seed.tenant_id != parent["tenant_id"]:
            raise UnauthorizedError(
                f"child tenant '{seed.tenant_id}' != authenticated parent tenant "
                f"'{parent['tenant_id']}' — cross-tenant delegation is denied"
            )

        # (3) Lineage bound to the AUTHENTICATED parent, not a claimed field.
        if seed.parent_vaid != parent["vaid_id"]:
            raise UnauthorizedError(
                f"child parent_vaid {seed.parent_vaid!r} must equal the authenticated "
                f"parent vaid_id {parent['vaid_id']} — the parent comes from the "
                "verified VAID, never the body"
            )

        # (4) Scope attenuation — single matcher, empty-child guard.
        if not scope_attenuates(parent, seed.scope_boundary):
            raise UnauthorizedError(
                "child scope_boundary exceeds the parent's — least-privilege "
                "attenuation denied"
            )

        # (5) Capability attenuation — single matcher.
        if not caps_attenuate(parent, seed.capability_set):
            raise UnauthorizedError(
                "child capability_set exceeds the parent's — least-privilege "
                "attenuation denied"
            )

        # (6) Child BYO-key PoP. AFTER attenuation: an unauthorized delegation must
        # not burn a nonce. mint_child is always BYO-key.
        if seed.public_key_der is None:
            raise IdentityError(
                "BYO-key required — a delegated child registers the parent-held "
                "child public key with a proof-of-possession"
            )
        self._verify_pop_at_mint(seed, seed.public_key_der, pop)

        # (7) Issue the attenuated child (issuer records lineage).
        vaid = self._issuer.issue_vaid_with_key(
            agent_class=seed.agent_class,
            version=seed.version,
            tenant_id=seed.tenant_id,
            parent_vaid=seed.parent_vaid,
            scope_boundary=seed.scope_boundary,
            capability_set=seed.capability_set,
            public_key_der=seed.public_key_der,
        )

        # (8) Delegated audit.
        self._audit.record(
            "vaid_minted",
            {
                "agent_class": seed.agent_class,
                "version": seed.version,
                "parent_vaid": seed.parent_vaid,
                "scope_boundary": seed.scope_boundary,
                "capability_set_len": len(seed.capability_set),
                "byo_key": True,
                "pop_verified": True,
                "delegated": True,
                "attenuation_verified": True,
                "parent_tenant": parent["tenant_id"],
            },
        )
        return vaid

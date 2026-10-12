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
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_pop import canonical_request_signing_bytes

from vaid_mint.audit import AuditSink
from vaid_mint.authz import AuthorizationGate, PermitAll
from vaid_mint.document import (
    boundary_is_evaluable,
    entry_claimed_resource,
    _parse_rfc3339,
    is_expired,
    caps_contain,
    has_capability,
    is_in_scope,
    is_well_formed_scope_boundary,
    scope_contains,
)
from vaid_mint.error import IdentityError, MintError, UnauthorizedError
from vaid_mint.issuer import ReferenceIssuer
from vaid_mint.mint_types import (
    MintChildResponse,
    MintPop,
    VaidSeed,
    build_mint_pop_payload,
)

# Freshness window for a mint proof-of-possession, in seconds.
MINT_POP_FRESHNESS_SECS = 300


def scope_attenuates(parent: dict, child_scope: list[dict]) -> bool:
    """Is every entry of ``child_scope`` within ``parent``'s scope? Uses only
    ``is_in_scope`` (the single matcher). Empty child scope = ⊤ is permitted only
    under an empty/⊤ parent (the escalation guard)."""
    return scope_attenuates_within(parent["scope_boundary"], child_scope)


class AttenuationReason(str, Enum):
    """Why a child boundary does or does not attenuate its parent's.

    Three outcomes and not two, for the reason ``verdict_v1.json`` states for the
    standing surface: three implementations that refuse the same delegation for
    three different reasons agree on every boolean and disagree about what
    happened. A refusal is also a different accusation in each case, and a caller
    is entitled to tell them apart.
    """

    #: Every entry of the child's boundary is within the parent's.
    ATTENUATED = "attenuated"
    #: The child names authority the parent does not hold.
    SCOPE_ESCALATION = "scope_escalation"
    #: One side carries a boundary kind this implementation cannot evaluate
    #: (spec S.10), so containment cannot be computed at all. NOT an escalation:
    #: the verifier is not saying the delegation is wider, it is saying it cannot
    #: tell.
    UNKNOWN_SCOPE_KIND = "unknown_scope_kind"


def scope_attenuates_within(parent_scope: list[dict], child_scope: list[dict]) -> bool:
    """The same predicate over a bare boundary rather than a document.

    A consent attestation carries a ``scope_boundary`` belonging to no document, and
    the child's authority must be contained by it under EXACTLY this rule —
    including the empty-child ⊤ guard, which is the subtle half. Reimplementing the
    rule for the detached case is how the guard would be lost in one of them.

    ``== ATTENUATED`` over :func:`scope_attenuation_reason`, so the bool and the
    reason cannot drift.
    """
    return scope_attenuation_reason(parent_scope, child_scope) is AttenuationReason.ATTENUATED


def scope_attenuation_reason(
    parent_scope: list[dict], child_scope: list[dict]
) -> AttenuationReason:
    """THE attenuation rule. Mirror of Rust ``scope_attenuation_reason``.

    **Both sides are checked for evaluability, not just the child.** An unreadable
    CHILD boundary cannot be shown to be within anything. An unreadable PARENT
    boundary bounds nothing this implementation can compute, so no child is
    provably within it. An implementation guarding only its input loses the second
    direction, and a boundary that is unreadable on BOTH sides is the case an
    equality short-circuit reports as attenuated while reading neither side.
    """
    if not boundary_is_evaluable(parent_scope) or not boundary_is_evaluable(child_scope):
        return AttenuationReason.UNKNOWN_SCOPE_KIND
    if not child_scope:
        # Child wants ⊤; allowed only if the parent is also ⊤.
        attenuates = not parent_scope
    else:
        attenuates = all(
            (resource := entry_claimed_resource(e)) is not None
            and scope_contains(parent_scope, resource)
            for e in child_scope
        )
    return (
        AttenuationReason.ATTENUATED if attenuates else AttenuationReason.SCOPE_ESCALATION
    )


def tenant_attenuates(parent: dict, child_trust_domain: str, child_tenant: str) -> bool:
    """Tenant containment, as the **qualified pair** ``(trust_domain, tenant_id)``.
    Both components must match the parent's. Mirror of the Rust
    ``tenant_attenuates``.

    **Why the pair, and not ``tenant_id`` alone.** ``tenant_id`` is not globally
    meaningful: it names a tenant *within an unnamed deployment* and is namespaced
    by nothing, so two self-hosters both minting ``tenant_id: "acme"`` produce
    documents indistinguishable on that field (ADR-0004). Comparing it alone is
    safe only while every document on a chain came from one issuer — the assumption
    that stops holding the moment chains cross kernel keys.

    **What ``trust_domain`` is worth.** It is *issuer-stamped, not holder-supplied*
    — it is not a field of :class:`~vaid_mint.mint_types.VaidSeed`; the issuer holds
    it, validates it at construction, and stamps it into every document it mints. It
    is inside the canonical signing bytes, so it cannot be altered without breaking
    the kernel signature. **But it is self-asserted:** nothing forces an issuer to
    stamp a domain it controls, and neither ``trust_domain`` nor
    ``kernel_key_thumbprint`` establishes attribution on its own. The binding from a
    trust domain to an authorized key set is out-of-band (ADR-0004,
    ``docs/trust-anchor.md``).

    **So, plainly: this is defence against operator error, not against a hostile
    issuer.** It catches a misconfigured mint that delegates across a tenant
    boundary, and documents assembled into a chain they were never meant to be in.
    It does not constrain an issuer whose key the verifier already trusts.
    """
    return (
        parent["trust_domain"] == child_trust_domain
        and parent["tenant_id"] == child_tenant
    )


def caps_attenuate(parent: dict, child_caps: list[str]) -> bool:
    """Is every entry of ``child_caps`` held by ``parent``? Uses only
    ``has_capability``. Empty child caps = ∅ is safe; empty parent caps holds
    nothing (the deliberate scope/caps asymmetry)."""
    return caps_attenuate_within(parent["capability_set"], child_caps)


def caps_attenuate_within(parent_caps: list[str], child_caps: list[str]) -> bool:
    """The same predicate over a bare capability set — the attestation counterpart
    of :func:`scope_attenuates_within`."""
    return all(caps_contain(parent_caps, c) for c in child_caps)


def expiry_attenuates(parent: dict, child_expires_at: object) -> bool:
    """Does ``child_expires_at`` fall at or before ``parent``'s ``expires_at``?

    The fifth containment property, and the one vaid#79 found missing: a child's
    authority is derived from its parent's, and authority that outlives the
    authority it came from was never contained by it. AAT I3 (TTL monotonicity),
    ``draft-niyikiza-oauth-attenuating-agent-tokens-01`` §4.4.

    **One matcher, two call sites**, exactly as ``scope_attenuates`` and
    ``caps_attenuate`` are: :meth:`MintService.mint_child` refuses a delegation this
    rejects, and :func:`~vaid_mint.chain.verify_chain_at` refuses a presented hop it
    rejects. A second implementation of the rule is how the two would drift apart,
    which is the defect pattern this repo keeps finding.

    **Equality is allowed.** A child expiring at exactly its parent's
    ``expires_at`` is contained — it holds authority for no instant in which the
    parent holds none. Only strictly later is refused.

    **Fails closed.** An unparseable or absent expiry on either side is not
    containment: it is an expiry that cannot be read, and a rule that cannot be
    evaluated must not report that it passed. This mirrors
    :func:`~vaid_mint.document.is_expired`, where an unreadable expiry is expired.
    """
    parent_expires = _parse_rfc3339(parent.get("expires_at"))
    child_expires = _parse_rfc3339(child_expires_at)
    if parent_expires is None or child_expires is None:
        return False
    return child_expires <= parent_expires


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

    @staticmethod
    def _require_well_formed_boundary(seed: VaidSeed) -> None:
        """Refuse a seed whose ``scope_boundary`` is not a well-formed S.8
        boundary, before anything is signed.

        The SAME predicate the wire parser applies, so there is one rule and not
        a mint-time copy of it. It is needed because Python has no
        string-to-entry coercion: Rust's ``From<&str> for ScopeBoundaryEntry``
        makes the v3 spelling a typed entry and TypeScript's types reject it at
        compile time, while here ``scope_boundary=["data.acme"]`` was simply
        carried through, signed, and accepted by ``verify_vaid``. Only
        ``parse_vaid_document`` refused it, by which point the credential was
        issued and the producer had been told it was fine.

        A ``MintError`` and not an ``UnauthorizedError``: the seed is
        malformed, which is a bad request, not an authority the caller was
        denied.
        """
        if not is_well_formed_scope_boundary(seed.scope_boundary):
            raise MintError(
                "seed scope_boundary is not a well-formed S.8 boundary: each "
                "entry must be an object carrying exactly `kind` and `value` "
                "(ADR-0009). Since 0.10.0 a bare string is not a boundary "
                "entry; build entries with "
                "`vaid_mint.document.prefix_entry(\"...\")`. Refused here "
                "rather than signed, because a document carrying this would be "
                "rejected by every verifier that parses it off the wire."
            )

    def mint_root(self, seed: VaidSeed, pop: MintPop | None = None) -> dict:
        """Mint a root/operator VAID. The authorization gate runs first; then, for
        a BYO-key seed, a valid PoP is required; otherwise generate-and-discard."""
        # Shape before anything else: a seed that cannot produce a parseable
        # document is refused before the authorization seam is consulted, so a
        # malformed request is never recorded as an authorization decision.
        self._require_well_formed_boundary(seed)
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

    def mint_child(
        self, seed: VaidSeed, parent: dict | None, pop: MintPop | None = None
    ) -> MintChildResponse:
        """Attenuated delegation — mirror of the Rust ``mint_child``. All of
        (parent present, same tenant, bound lineage, scope ⊆, caps ⊆, parent still
        live) are checked fail-closed BEFORE the PoP so a rejected delegation never
        burns a nonce. The child's expiry is clamped to the parent's at issuance and
        the issued document is checked against it (vaid#79)."""
        # (0) Shape first, by the same predicate as mint_root: an unparseable
        # boundary is refused before the attenuation ladder, so a malformed
        # child is never reported as a scope escalation it was never coherent
        # enough to attempt.
        self._require_well_formed_boundary(seed)

        # (1) The parent's authority must have travelled — fail closed.
        if parent is None:
            raise UnauthorizedError(
                "no verified parent VAID in context — delegation requires an "
                "authenticated parent principal, fail-closed"
            )

        # (2) Same tenant, grounded in the parent's VERIFIED VAID — never the body.
        #
        # Shares ``tenant_attenuates`` with verify-time chain walking, so the two
        # cannot drift. The ``trust_domain`` component is passed as the parent's
        # own: at mint time the child's document does not exist yet and the domain
        # it will carry is this issuer's, so that component is trivially satisfied
        # here and the only free variable is the tenant. Behaviour is unchanged
        # from the inline comparison this replaces — the pair does real work at
        # verify time, where both documents exist and may not share an issuer.
        if not tenant_attenuates(parent, parent["trust_domain"], seed.tenant_id):
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

        # (5a) The parent must still be alive (vaid#79).
        #
        # The child's expiry is CLAMPED to the parent's at issuance (step 7), so a
        # delegation can never produce a child that outlives its parent and no
        # working delegation is refused for a TTL the caller did not choose. The one
        # case a clamp cannot answer is a parent that has already expired: the
        # clamp's own ceiling is in the past, so the child would be issued
        # dead-on-arrival. That is refused instead, HERE — with (4) and (5) and
        # before the PoP, so the refusal burns no nonce.
        #
        # An unreadable expiry is expired (``is_expired`` is total and fails closed),
        # so a parent whose expiry cannot be read is refused by the same line.
        if is_expired(parent):
            raise UnauthorizedError(
                f"authenticated parent {parent['vaid_id']} expired at "
                f"{parent.get('expires_at')!r} — a child may not outlive the "
                "authority it derives from, and a child of a dead parent would be "
                "issued already expired. Renew the parent, then delegate"
            )

        # (6) Child BYO-key PoP. AFTER attenuation: an unauthorized delegation must
        # not burn a nonce. mint_child is always BYO-key.
        if seed.public_key_der is None:
            raise IdentityError(
                "BYO-key required — a delegated child registers the parent-held "
                "child public key with a proof-of-possession"
            )
        self._verify_pop_at_mint(seed, seed.public_key_der, pop)

        # (7) Issue the attenuated child (issuer records lineage), with the
        # parent's expiry as a ceiling: the child ends at the earlier of that and
        # the issuer's own TTL.
        vaid = self._issuer.issue_vaid_with_key(
            agent_class=seed.agent_class,
            version=seed.version,
            tenant_id=seed.tenant_id,
            parent_vaid=seed.parent_vaid,
            scope_boundary=seed.scope_boundary,
            capability_set=seed.capability_set,
            public_key_der=seed.public_key_der,
            not_after=parent["expires_at"],
        )

        # (7a) ...and CHECK what came back. The ceiling above is an instruction to
        # the issuer; this is the property. An issuer is a seam a deployment
        # supplies, and one that ignores ``not_after`` — a third-party
        # implementation written before this rule existed, or one that simply gets
        # it wrong — would emit a child outliving its parent that nothing
        # downstream could distinguish from a legitimate one. The same matcher the
        # chain verifier refuses on is applied to the document actually issued, so
        # the mint never hands out a document its own verifier would reject.
        #
        # This one refusal DOES consume the nonce, unavoidably: the PoP has already
        # been spent by the time a document exists to check. That is the right
        # trade — it fires only for a broken issuer, never for a caller's mistake.
        if not expiry_attenuates(parent, vaid.get("expires_at")):
            raise UnauthorizedError(
                f"issuer returned a child expiring {vaid.get('expires_at')!r}, "
                f"after the parent's {parent.get('expires_at')!r}, despite a "
                "not_after ceiling — the issuer does not honour expiry containment "
                "and the child has not been returned"
            )

        # (8) Was the child's life cut short by its parent's, rather than by this
        # issuer's TTL? Computed from the two documents rather than reported by the
        # issuer: the issuer returns a document and nothing else, and reading the
        # SIGNED bytes is the stronger statement anyway — it describes the document
        # the caller is actually holding, not the issuer's intent.
        #
        # The one inexact case is a tie: an issuer whose TTL lands exactly on the
        # parent's expiry sets this true although nothing was taken away. The field
        # is named for what is literally true of the document — the child's expiry
        # IS the parent's bound — rather than for the issuer's arithmetic, so the
        # tie is still an accurate statement.
        expiry_bounded_by_parent = vaid["expires_at"] == parent["expires_at"]

        # (9) Delegated audit — distinguishes the delegation tree from root mints,
        # and records the shortening, so a caller that ignored the response can
        # still find out from the audit trail why a credential was short-lived.
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
                "expiry_bounded_by_parent": expiry_bounded_by_parent,
                "expires_at": vaid["expires_at"],
                "parent_expires_at": parent["expires_at"],
            },
        )
        return MintChildResponse(
            vaid=vaid,
            expiry_bounded_by_parent=expiry_bounded_by_parent,
            parent_expires_at=parent["expires_at"],
        )

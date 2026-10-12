"""The token bridge itself: verify a VAID chain end to end and, only on a full
pass, issue a short-lived JWT. See docs/jwt/v1/profile.md SS1-3.

Built only on ``vaid_mint`` primitives (same verification order as
``vaid_adk._verify.verify_presentation`` / ``vaid_a2a.verifier`` — this is the
estate's existing answer to "how do you check a presented VAID end to end",
re-derived against the same ``vaid_mint`` functions rather than importing
either package, exactly as ``vaid_adk`` does for the same reason: neither has
a release cadence this package should couple to) plus this profile's own
claim-shape and token-exchange-protocol additions.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from vaid_mint.attestation import AttestationBundle
from vaid_mint.chain import ChainVerification, PresentedBundle, verify_chain_at
from vaid_mint.document import boundary_is_evaluable, is_expired_at
from vaid_mint.revocation import RevocationCheck, RevocationStatus, assemble_lineage
from vaid_mint.verify import VaidVerdict, verify_vaid_authenticity_graded

from vaid_jwt_bridge.claims import build_sub_and_act, build_vaid_claim
from vaid_jwt_bridge.keys import Signer
from vaid_jwt_bridge.trust import TrustedIssuers, require_domain_binding

#: The only ``requested_token_type`` this bridge issues (RFC 8693 SS3).
ISSUED_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

#: This profile's ``subject_token_type`` (docs/jwt/v1/profile.md SS6) — a
#: profile-defined URI under a VAID-specific namespace, not an
#: IETF-registered one; RFC 8693 SS3 explicitly permits this.
SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1 = "urn:vaid:params:oauth:token-exchange:token-type:vaid-chain-v1"

#: Default JWT lifetime (profile SS3.1) — never exceeded, and clamped
#: further down to the leaf's own ``expires_at`` when that is sooner.
DEFAULT_TTL_SECONDS = 300


class DenialReason(enum.Enum):
    """Why :func:`exchange` refused — mirrors, one-to-one, the step that
    failed in docs/jwt/v1/profile.md SS2, so a caller logging or auditing a
    denial can say exactly which check was not met."""

    NO_LEAF = "no_leaf"
    UNSUPPORTED_SIG_VERSION = "unsupported_sig_version"
    MALFORMED_TRUST_DOMAIN = "malformed_trust_domain"
    ISSUER_MISMATCH = "issuer_mismatch"
    LINEAGE_INCONSISTENT = "lineage_inconsistent"
    INAUTHENTIC = "inauthentic"
    LEAF_EXPIRED = "leaf_expired"
    UNKNOWN_SCOPE_KIND = "unknown_scope_kind"
    CHAIN_UNVERIFIABLE = "chain_unverifiable"
    CHAIN_NOT_ATTENUATED = "chain_not_attenuated"
    CHAIN_EXPIRED = "chain_expired"
    CHAIN_CONSENT_EXPIRED = "chain_consent_expired"
    REVOKED = "revoked"
    REVOCATION_UNAVAILABLE = "revocation_unavailable"
    MISSING_AUDIENCE = "missing_audience"
    UNSUPPORTED_REQUESTED_TOKEN_TYPE = "unsupported_requested_token_type"


_AUTHENTICITY_TO_REASON: dict[VaidVerdict, DenialReason] = {
    VaidVerdict.UNSUPPORTED_SIG_VERSION: DenialReason.UNSUPPORTED_SIG_VERSION,
    VaidVerdict.MALFORMED_TRUST_DOMAIN: DenialReason.MALFORMED_TRUST_DOMAIN,
    VaidVerdict.ISSUER_MISMATCH: DenialReason.ISSUER_MISMATCH,
    VaidVerdict.LINEAGE_INCONSISTENT: DenialReason.LINEAGE_INCONSISTENT,
    VaidVerdict.INAUTHENTIC: DenialReason.INAUTHENTIC,
}

_CHAIN_TO_REASON: dict[ChainVerification, DenialReason] = {
    ChainVerification.INAUTHENTIC: DenialReason.INAUTHENTIC,
    ChainVerification.UNVERIFIABLE: DenialReason.CHAIN_UNVERIFIABLE,
    ChainVerification.NOT_ATTENUATED: DenialReason.CHAIN_NOT_ATTENUATED,
    ChainVerification.EXPIRED: DenialReason.CHAIN_EXPIRED,
    ChainVerification.CONSENT_EXPIRED: DenialReason.CHAIN_CONSENT_EXPIRED,
}


@dataclass(frozen=True)
class ExchangeRequest:
    """What a caller presents for exchange (profile SS1/SS6): the leaf VAID,
    its detached ancestor chain, the requested audience, and — if the caller
    supplied one — the RFC 8693 ``requested_token_type`` (must be the JWT
    URI or absent; anything else is a denial, never silently ignored)."""

    leaf: dict | None
    chain: tuple[dict, ...] = field(default_factory=tuple)
    audience: str | None = None
    requested_token_type: str | None = None


@dataclass(frozen=True)
class Issued:
    """A successful exchange: the RFC 8693 SS2.2 response fields."""

    access_token: str
    issued_token_type: str
    token_type: str
    expires_in: int


@dataclass(frozen=True)
class Denied:
    """A refused exchange. Nothing is signed; ``access_token`` does not exist
    on this type by construction, so a caller cannot reach for it on a
    denial by accident."""

    reason: DenialReason
    detail: str


ExchangeResult = Issued | Denied


def _deny(reason: DenialReason, detail: str) -> Denied:
    return Denied(reason=reason, detail=detail)


def _parse_rfc3339_z(value: str) -> datetime:
    """Parse an aware RFC 3339 timestamp. Only called after
    ``is_expired_at`` has already returned ``False`` for the same value,
    which is only possible if that same permissive parser
    (``vaid_mint.document``) already parsed it successfully — so this
    cannot raise in practice, but it still asks for an aware result rather
    than assuming one, consistent with the fail-closed posture elsewhere in
    this package."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError(f"expires_at {value!r} has no timezone offset")
    return dt.astimezone(timezone.utc)


def exchange(
    request: ExchangeRequest,
    *,
    keys: TrustedIssuers,
    revocation: RevocationCheck,
    issuer: str,
    signer: Signer,
    default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: datetime | None = None,
) -> ExchangeResult:
    """Verify ``request``'s VAID chain end to end and, only on a full pass,
    issue a JWT. Fails closed: any denial returns :class:`Denied` and signs
    nothing. See docs/jwt/v1/profile.md SS2-3 for the normative procedure this
    implements step for step.

    ``keys`` is the bridge's trusted issuer config (profile SS1): kernel keys
    each bound to the one trust domain it is trusted for
    (:class:`~vaid_jwt_bridge.trust.TrustedIssuers`). A resolver that cannot
    answer that second question raises
    :class:`~vaid_jwt_bridge.trust.TrustedIssuersConfigError` — a defect in the
    deployment's configuration, not a verdict about any one exchange, so it is
    raised rather than returned as a :class:`Denied`.
    """
    now = now or datetime.now(timezone.utc)

    # Checked before anything about `request`, so a resolver that cannot bind a
    # domain to a key always raises, independent of what this particular
    # exchange happens to carry. A configuration mistake is a property of the
    # deployment, not of a request.
    require_domain_binding(keys)

    if request.leaf is None:
        return _deny(DenialReason.NO_LEAF, "no VAID presented")
    if not request.audience:
        return _deny(DenialReason.MISSING_AUDIENCE, "an audience is required to issue a JWT")
    if (
        request.requested_token_type is not None
        and request.requested_token_type != ISSUED_TOKEN_TYPE_JWT
    ):
        return _deny(
            DenialReason.UNSUPPORTED_REQUESTED_TOKEN_TYPE,
            f"this bridge issues only {ISSUED_TOKEN_TYPE_JWT!r}, "
            f"got {request.requested_token_type!r}",
        )

    leaf = request.leaf

    # Step 1 (profile SS2.1): the LEAF's own trust-domain binding, then its
    # authenticity.
    #
    # Resolved ahead of verify_chain_at so an unrecognised or misbound issuer
    # (ISSUER_MISMATCH) is distinguishable from a recognised, correctly-bound
    # issuer whose signature does not verify (INAUTHENTIC) — chain.py's own
    # key-resolution closure collapses both into INAUTHENTIC, which is right
    # for a chain hop but loses a distinction a denial record needs.
    #
    # The binding check runs BEFORE the signature check, and is scoped to the
    # LEAF alone: it must reach its verdict on the leaf's own defects before
    # anything about the presented chain is examined. A misbound ancestor is a
    # step 3 concern below; folding it in here would make the leaf's own
    # INAUTHENTIC/ISSUER_MISMATCH outcome depend on what else happens to be
    # presented alongside it, which is the exact nondeterminism this ordering
    # exists to remove (profile SS2, extension.md SS5).
    thumbprint = leaf.get("kernel_key_thumbprint")
    key = keys.resolve_key(thumbprint) if isinstance(thumbprint, str) else None
    if key is None:
        return _deny(
            DenialReason.ISSUER_MISMATCH,
            f"no trusted kernel key for thumbprint {thumbprint!r}",
        )
    bound_domain = keys.trust_domain_for(thumbprint)
    if bound_domain != leaf.get("trust_domain"):
        return _deny(
            DenialReason.ISSUER_MISMATCH,
            f"leaf claims trust_domain {leaf.get('trust_domain')!r}, but kernel "
            f"key thumbprint {thumbprint!r} is trusted only for "
            f"{bound_domain!r}: a key is trusted for the domain it is paired "
            "with, not for any domain a document claims",
        )
    authenticity = verify_vaid_authenticity_graded(key, leaf)
    if authenticity is not VaidVerdict.VALID:
        reason = _AUTHENTICITY_TO_REASON.get(authenticity, DenialReason.INAUTHENTIC)
        return _deny(reason, f"leaf authenticity check failed: {authenticity.code}")

    # Step 2 (profile SS2.2): leaf's own expiry. verify_chain_at does not
    # check it (only ancestors), so it is checked here.
    if is_expired_at(leaf, now):
        return _deny(DenialReason.LEAF_EXPIRED, "leaf VAID has passed its own expires_at")

    # Step 2a (ADR-0009 S.10): every presented boundary is one this bridge can
    # read.
    #
    # A `scope_boundary` entry carries a `kind`, and an entry whose kind this
    # bridge does not recognise refuses the WHOLE boundary and so the whole
    # exchange, because an unrecognised kind can only ever NARROW what the
    # signer granted.
    #
    # The stake is higher here than in a verifier that answers one request.
    # `build_vaid_claim` copies `scope_boundary` verbatim into the issued JWT's
    # `vaid` claim, and the bridge authorises no specific resource, so there is
    # no later containment check to fail closed. Without this step the bridge
    # would mint a signed, audience-scoped token asserting a boundary it could
    # not evaluate, and hand it to a relying party even less likely to
    # recognise the kind. The narrowing constraint would then have been
    # laundered through a token that looks fully verified.
    #
    # Ordered as vaid_mint.verify.verify_vaid_standing orders it: after
    # authenticity, after expiry, before revocation. Over the ancestors as well
    # as the leaf, because attenuation only runs where there is a parent, so a
    # ROOT leaf would otherwise pass unchecked.
    for doc in (leaf, *request.chain):
        boundary = doc.get("scope_boundary")
        if not isinstance(boundary, list) or not boundary_is_evaluable(boundary):
            return _deny(
                DenialReason.UNKNOWN_SCOPE_KIND,
                f"document {doc.get('vaid_id')!r} carries a scope_boundary entry "
                "of a kind this bridge does not recognise: no token is issued, "
                "because an unrecognised kind can only narrow the authority "
                "granted and the issued claim would assert a boundary that was "
                "never evaluated",
            )

    # Steps 3/4 (profile SS2.3/SS2.4): chain integrity and attenuation back to
    # a trusted root.
    #
    # Each presented ancestor's own trust-domain binding is checked first, by
    # the same rule as step 1 and reporting the same reason, over the presented
    # chain only (the leaf was already settled in step 1) and only once the
    # leaf itself has cleared steps 1-2 — so a bad leaf signature is always
    # INAUTHENTIC on its own, never pre-empted by an unrelated wrong-domain
    # ancestor elsewhere in the chain.
    #
    # This is NOT what verify_chain_at enforces. That function requires a
    # current, authentic consent attestation for a hop that crosses a kernel
    # key, and binds tenant and trust domain from the PARENT DOCUMENT for a
    # same-key hop — both checks between documents. Neither compares a
    # document's claimed trust_domain against the domain this bridge's own
    # trusted issuer config binds to the key that signed it, which is the
    # check here (GHSA-hfjh-v2x2-r58v).
    #
    # A document whose thumbprint resolves to NO trusted key is deliberately
    # left to verify_chain_at below, which refuses it on its own terms — there
    # is no bound domain to compare against, so there is nothing for this
    # check to say about it.
    for doc in request.chain:
        doc_thumbprint = doc.get("kernel_key_thumbprint")
        if not isinstance(doc_thumbprint, str):
            continue
        doc_bound_domain = keys.trust_domain_for(doc_thumbprint)
        if doc_bound_domain is not None and doc_bound_domain != doc.get("trust_domain"):
            return _deny(
                DenialReason.ISSUER_MISMATCH,
                f"document {doc.get('vaid_id')!r} claims trust_domain "
                f"{doc.get('trust_domain')!r}, but kernel key thumbprint "
                f"{doc_thumbprint!r} is trusted only for {doc_bound_domain!r}: "
                "a key is trusted for the domain it is paired with, not for "
                "any domain a document claims",
            )

    bundle = PresentedBundle(request.chain)
    chain_verdict = verify_chain_at(keys, leaf, bundle, AttestationBundle(), now)
    if chain_verdict is not ChainVerification.ATTENUATED:
        reason = _CHAIN_TO_REASON.get(chain_verdict, DenialReason.CHAIN_UNVERIFIABLE)
        return _deny(reason, f"chain verification did not attenuate: {chain_verdict.value}")

    # Step 5 (profile SS2.5): revocation of every link. assemble_lineage is
    # pure and deterministic, so recomputing it here reproduces exactly the
    # chain verify_chain_at just confirmed ATTENUATED over (it does not
    # return its internal ordered chain, so this is the one place that
    # re-derives it — from the same presented leaf/bundle, nothing new).
    chain_ids = assemble_lineage(leaf, bundle)
    if chain_ids is None:
        # Unreachable given ATTENUATED above (that already requires a
        # complete assembly). Kept as an explicit fail-closed branch rather
        # than an assertion, so a future change to either function cannot
        # turn this into a silent issuance.
        return _deny(
            DenialReason.CHAIN_UNVERIFIABLE,
            "lineage could not be reassembled after attenuation passed",
        )

    status = revocation.check_lineage(chain_ids)
    if status is RevocationStatus.REVOKED:
        return _deny(DenialReason.REVOKED, "a VAID in the lineage is revoked")
    if status is RevocationStatus.UNAVAILABLE:
        return _deny(
            DenialReason.REVOCATION_UNAVAILABLE,
            "revocation check unavailable - fails closed, never read as not-revoked",
        )

    chain_docs = [
        leaf if vaid_id == leaf["vaid_id"] else bundle.get(vaid_id) for vaid_id in chain_ids
    ]

    sub, act = build_sub_and_act(chain_docs)
    vaid_claim = build_vaid_claim(leaf, chain_docs)

    # exp: never later than the leaf's own expires_at (profile SS3.1). Safe to
    # parse unconditionally: is_expired_at(leaf, now) already returned False
    # above, which that function can only do for a value it parsed.
    leaf_expires_at = _parse_rfc3339_z(leaf["expires_at"])
    iat = int(now.timestamp())
    exp = min(iat + default_ttl_seconds, int(leaf_expires_at.timestamp()))
    if exp <= iat:
        return _deny(
            DenialReason.LEAF_EXPIRED,
            "leaf has no remaining life to bound a non-empty-lived JWT to",
        )

    claims: dict = {
        "iss": issuer,
        "aud": request.audience,
        "iat": iat,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "sub": sub,
        "vaid": vaid_claim,
    }
    if act is not None:
        claims["act"] = act

    access_token = signer.sign(claims)
    return Issued(
        access_token=access_token,
        issued_token_type=ISSUED_TOKEN_TYPE_JWT,
        token_type="N_A",
        expires_in=exp - iat,
    )

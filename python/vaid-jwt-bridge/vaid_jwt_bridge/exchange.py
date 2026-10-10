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
from vaid_mint.chain import ChainVerification, KernelKeyResolver, PresentedBundle, verify_chain_at
from vaid_mint.document import is_expired_at
from vaid_mint.revocation import RevocationCheck, RevocationStatus, assemble_lineage
from vaid_mint.verify import VaidVerdict, verify_vaid_authenticity_graded

from vaid_jwt_bridge.claims import build_sub_and_act, build_vaid_claim
from vaid_jwt_bridge.keys import Signer

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
    keys: KernelKeyResolver,
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
    """
    now = now or datetime.now(timezone.utc)

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

    # Step 1 (profile SS2.1): leaf authenticity, resolved ahead of
    # verify_chain_at so an unrecognised issuer is distinguishable from a
    # recognised issuer whose signature does not verify.
    thumbprint = leaf.get("kernel_key_thumbprint")
    key = keys.resolve_key(thumbprint) if isinstance(thumbprint, str) else None
    if key is None:
        return _deny(
            DenialReason.ISSUER_MISMATCH,
            f"no trusted kernel key for thumbprint {thumbprint!r}",
        )
    authenticity = verify_vaid_authenticity_graded(key, leaf)
    if authenticity is not VaidVerdict.VALID:
        reason = _AUTHENTICITY_TO_REASON.get(authenticity, DenialReason.INAUTHENTIC)
        return _deny(reason, f"leaf authenticity check failed: {authenticity.code}")

    # Step 2 (profile SS2.2): leaf's own expiry. verify_chain_at does not
    # check it (only ancestors), so it is checked here.
    if is_expired_at(leaf, now):
        return _deny(DenialReason.LEAF_EXPIRED, "leaf VAID has passed its own expires_at")

    # Steps 3/4 (profile SS2.3/SS2.4): chain integrity and attenuation back to
    # a trusted root, with trust-domain binding and consent enforced per hop
    # inside verify_chain_at itself.
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

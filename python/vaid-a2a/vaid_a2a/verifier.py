"""The VAID A2A extension's reference verifier.

Implements the verification order from ``docs/a2a/v1/extension.md`` §5:
signature, expiry, chain integrity, per-hop attenuation, requested-action
scope, revocation — fail closed at the first failing step, and "could not
determine" is never folded into either a pass or a specific denial.

Takes an A2A ``Message`` as a plain ``dict`` (no dependency on ``a2a-python``
or any A2A SDK, per the brief: this works against any A2A server or client
that produces message-shaped dicts) plus the trust configuration an
``AgentCard``'s extension entry would declare (§2) and a
:class:`~vaid_mint.revocation.RevocationCheck` the caller already has wired to
its own revocation store.

Every check here is delegated to the existing ``vaid_mint`` primitives — this
module extracts the VAID(s) from A2A metadata, builds the key resolver from
the trust config, and calls them in the specified order. It is not a second
implementation of signature, attenuation or revocation checking.
"""

from __future__ import annotations

import base64
import binascii
import enum
from dataclasses import dataclass
from datetime import datetime, timezone

from vaid_mint.attestation import AttestationBundle
from vaid_mint.chain import (
    ChainVerification,
    PresentedBundle,
    verify_chain_at,
)
from vaid_mint.document import is_expired_at, is_in_scope
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import RevocationCheck, RevocationStatus, assemble_lineage
from vaid_mint.verify import VaidVerdict, verify_vaid_authenticity_graded

#: This extension's permanent URI (see docs/a2a/v1/extension.md §0), decided
#: by Allan in the session 306 follow-up. Importing this constant, rather
#: than a caller hardcoding the string, is what makes a future version's URI
#: a one-file change instead of a grep-and-replace across every consumer.
EXTENSION_URI = "https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md"

#: Where the leaf VAID document lives in ``Message.metadata`` (spec §4).
METADATA_VAID_KEY = f"{EXTENSION_URI}/vaid"

#: Where the presented ancestor documents live in ``Message.metadata`` (spec §4).
METADATA_CHAIN_KEY = f"{EXTENSION_URI}/vaidChain"


class VerifyCode(enum.Enum):
    """Why :func:`verify_a2a_message` allowed or denied a request — the reason
    alongside the boolean, for the same reason
    :class:`~vaid_mint.verify.VaidVerdict` is graded rather than a bare bool:
    a caller that cannot tell "forged" from "I could not check revocation"
    cannot log, alert, or retry the two differently.

    Values are the wire strings used in ``docs/a2a/v1/vectors/*.json``'s
    ``expected_error_code`` and in this module's docstrings — not a new
    vocabulary; each name maps onto an existing ``VaidVerdict`` or
    ``ChainVerification`` member except :attr:`ALLOWED`, :attr:`NO_VAID` and
    :attr:`OUT_OF_SCOPE`, which this extension adds because they are extension
    -level concerns (metadata presence; the specific requested action) that
    ``vaid_mint`` itself has no occasion to name.
    """

    ALLOWED = "allowed"
    NO_VAID = "no_vaid"
    UNPARSEABLE = "unparseable"
    UNSUPPORTED_SIG_VERSION = "unsupported_sig_version"
    MALFORMED_TRUST_DOMAIN = "malformed_trust_domain"
    ISSUER_MISMATCH = "issuer_mismatch"
    LINEAGE_INCONSISTENT = "lineage_inconsistent"
    INAUTHENTIC = "inauthentic"
    EXPIRED = "expired"
    UNVERIFIABLE = "unverifiable"
    NOT_ATTENUATED = "not_attenuated"
    CONSENT_EXPIRED = "consent_expired"
    OUT_OF_SCOPE = "out_of_scope"
    REVOKED = "revoked"
    INDETERMINATE = "indeterminate"

    @property
    def is_determined_denial(self) -> bool:
        """True for a positive refusal (forged, attenuation violated,
        revoked, ...); false for :attr:`ALLOWED`, :attr:`NO_VAID` (when
        permitted to pass through) and :attr:`INDETERMINATE` — the "could not
        tell" state is deliberately not a determined denial, mirroring
        ``VaidVerdict.INDETERMINATE``'s own docstring: both are refusals, only
        one is an accusation."""
        return self not in (VerifyCode.ALLOWED, VerifyCode.NO_VAID, VerifyCode.INDETERMINATE)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :func:`verify_a2a_message`. ``allowed`` is the one field
    a caller in a hurry needs; ``code`` and ``reason`` are there for the
    caller that logs, alerts, or has to explain a denial to an operator."""

    allowed: bool
    code: VerifyCode
    reason: str


def _allow(code: VerifyCode, reason: str) -> VerifyResult:
    return VerifyResult(allowed=True, code=code, reason=reason)


def _deny(code: VerifyCode, reason: str) -> VerifyResult:
    return VerifyResult(allowed=False, code=code, reason=reason)


_AUTHENTICITY_VERDICT_TO_CODE: dict[VaidVerdict, VerifyCode] = {
    VaidVerdict.UNSUPPORTED_SIG_VERSION: VerifyCode.UNSUPPORTED_SIG_VERSION,
    VaidVerdict.MALFORMED_TRUST_DOMAIN: VerifyCode.MALFORMED_TRUST_DOMAIN,
    VaidVerdict.ISSUER_MISMATCH: VerifyCode.ISSUER_MISMATCH,
    VaidVerdict.LINEAGE_INCONSISTENT: VerifyCode.LINEAGE_INCONSISTENT,
    VaidVerdict.INAUTHENTIC: VerifyCode.INAUTHENTIC,
}

_CHAIN_VERDICT_TO_CODE: dict[ChainVerification, VerifyCode] = {
    ChainVerification.INAUTHENTIC: VerifyCode.INAUTHENTIC,
    ChainVerification.UNVERIFIABLE: VerifyCode.UNVERIFIABLE,
    ChainVerification.NOT_ATTENUATED: VerifyCode.NOT_ATTENUATED,
    ChainVerification.EXPIRED: VerifyCode.EXPIRED,
    ChainVerification.CONSENT_EXPIRED: VerifyCode.CONSENT_EXPIRED,
}


def _b64url_decode(value: str) -> bytes:
    """Decode base64url with or without the trailing ``=`` padding that
    :func:`base64.urlsafe_b64encode` emits and that a hand-written
    ``trustedIssuers`` entry may omit."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


@dataclass(frozen=True)
class _TrustedIssuer:
    """One resolved ``trustedIssuers`` entry: a kernel key, filed under its
    own derived thumbprint, paired with the trust domain spec §2 declares
    that key for. ``vaid_mint.chain.KernelKeyMap`` keeps only the key bytes
    — correct for its own job, selecting a key to check a signature against
    — so this extension keeps the pairing itself, the half spec §2's
    ``trustedIssuers`` row and §5 step 1 both require ("a kernel public key
    this agent trusts for the claimed ``trust_domain``") and that
    ``vaid_mint.mint.tenant_attenuates`` documents as deliberately out of
    band for ``vaid_mint`` to enforce on its own."""

    public_key: bytes
    trust_domain: str


class _TrustedIssuerMap:
    """Resolves a kernel key by thumbprint like
    :class:`~vaid_mint.chain.KernelKeyMap` (and satisfies the same
    ``KernelKeyResolver`` protocol, so it can be passed straight to
    :func:`~vaid_mint.chain.verify_chain_at`), while also answering which
    trust domain each resolved key is bound to."""

    def __init__(self, entries: dict[str, _TrustedIssuer]) -> None:
        self._entries = entries

    def resolve_key(self, thumbprint: str) -> bytes | None:
        entry = self._entries.get(thumbprint)
        return entry.public_key if entry else None

    def trust_domain_for(self, thumbprint: str) -> str | None:
        """The trust domain this map's ``trustedIssuers`` configuration
        binds to ``thumbprint``, or ``None`` if ``thumbprint`` resolves to no
        trusted key."""
        entry = self._entries.get(thumbprint)
        return entry.trust_domain if entry else None


def _build_key_resolver(trust_config: dict) -> _TrustedIssuerMap:
    """Build a :class:`_TrustedIssuerMap` from an ``AgentCard`` extension
    entry's ``params`` shape — ``{"trustedIssuers": [{"trustDomain": ...,
    "kernelPublicKey": "<base64url>"}]}`` (spec §2).

    Every key is filed under the thumbprint it itself derives to, never from
    a caller-supplied thumbprint — a ``trustedIssuers`` entry with no
    parseable ``kernelPublicKey`` or ``trustDomain`` is skipped rather than
    trusted on the strength of its other fields, since a thumbprint or trust
    domain alone is not key material (spec §2's ``trustedIssuers`` row).
    """
    issuers = trust_config.get("trustedIssuers") or []
    entries: dict[str, _TrustedIssuer] = {}
    for entry in issuers:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("kernelPublicKey")
        domain = entry.get("trustDomain")
        if not isinstance(raw, str) or not isinstance(domain, str):
            continue
        try:
            key_bytes = _b64url_decode(raw)
        except (binascii.Error, ValueError):
            continue
        entries[kernel_key_thumbprint(key_bytes)] = _TrustedIssuer(
            public_key=key_bytes, trust_domain=domain
        )
    return _TrustedIssuerMap(entries)


def verify_a2a_message(
    message: dict,
    *,
    trust_config: dict,
    revocation: RevocationCheck,
    requested_action: str | None,
    now: datetime | None = None,
    require_vaid: bool = False,
) -> VerifyResult:
    """Verify the VAID(s) carried on an A2A ``Message`` under this extension.

    :param message: the A2A ``Message`` as a plain dict. Only ``message["metadata"]``
        is read.
    :param trust_config: this extension's ``AgentCard`` ``params`` — at minimum
        ``{"trustedIssuers": [...]}`` as built by :func:`_build_key_resolver`.
    :param revocation: the caller's revocation seam, consulted over the full
        assembled lineage (spec §5 step 6). Never resolved or looked up by this
        function — the caller owns that, exactly as ``vaid_mint`` requires.
    :param requested_action: the resource/action the message is asking this
        agent to perform, checked against the leaf's own ``scope_boundary``
        (spec §5 step 5, ``vaid_mint.document.is_in_scope``). Required, with
        no default, so that skipping this check is always a decision a
        caller makes by name — passing ``None`` explicitly — never something
        that happens because a caller forgot the argument. Pass ``None``
        only when the caller enforces this check elsewhere, or when this
        call is checking standing rather than a specific action.
    :param now: the verification instant. Defaults to the system clock;
        pass an explicit value for a reproducible verdict (replaying a vector,
        a historical decision) rather than asserting against whenever this
        happened to run — the same rule :func:`~vaid_mint.chain.verify_chain_at`
        states for itself.
    :param require_vaid: mirrors the extension's own ``params.requireVaid``
        (spec §2). If ``True``, a message with no VAID under
        :data:`METADATA_VAID_KEY` is denied (:attr:`VerifyCode.NO_VAID`) rather
        than passed through.

    Returns a :class:`VerifyResult`. Never raises for a malformed or absent
    VAID — that is :attr:`VerifyCode.NO_VAID` or :attr:`VerifyCode.UNPARSEABLE`,
    a result, not an exception, mirroring
    :func:`~vaid_mint.verify.verify_vaid_standing_from_json`'s own refusal-not-
    raise convention.
    """
    now = now or datetime.now(timezone.utc)
    metadata = message.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    leaf = metadata.get(METADATA_VAID_KEY)
    if leaf is None:
        if require_vaid:
            return _deny(
                VerifyCode.NO_VAID,
                f"no VAID present under metadata key {METADATA_VAID_KEY!r}, and "
                "requireVaid is set",
            )
        # The extension degrades to absent, never to a weaker check (spec §2,
        # requireVaid row): a hop carrying no VAID is simply outside this
        # extension's concern when requireVaid is false.
        return _allow(
            VerifyCode.NO_VAID,
            "no VAID present under the extension's metadata key; requireVaid "
            "is not set, so this extension makes no claim about this message",
        )
    if not isinstance(leaf, dict):
        return _deny(
            VerifyCode.UNPARSEABLE,
            f"metadata[{METADATA_VAID_KEY!r}] is present but is not a VAID "
            "document object",
        )

    chain_raw = metadata.get(METADATA_CHAIN_KEY)
    if chain_raw is None:
        chain_raw = []
    if not isinstance(chain_raw, list) or not all(isinstance(d, dict) for d in chain_raw):
        return _deny(
            VerifyCode.UNPARSEABLE,
            f"metadata[{METADATA_CHAIN_KEY!r}] is present but is not a list of "
            "VAID document objects",
        )

    keys = _build_key_resolver(trust_config)

    # ── Trust-domain binding, over the LEAF and every presented chain
    # document (spec §2's trustedIssuers row pairs a trust domain with a
    # key; §5 step 1 requires "a kernel public key this agent trusts for the
    # claimed trust_domain") ──
    #
    # A key accepted under trust_config.trustedIssuers is accepted FOR THE
    # DOMAIN trustedIssuers pairs it with, not for any domain a document
    # cares to claim. Checked before any document is allowed to influence
    # authenticity or chain assembly, and over every hop — not only the
    # leaf — because the same misbinding is exploitable anywhere a document
    # names a trusted key's thumbprint while claiming a trust_domain that
    # key is not configured for.
    for doc in (leaf, *chain_raw):
        doc_thumbprint = doc.get("kernel_key_thumbprint")
        if not isinstance(doc_thumbprint, str):
            continue
        bound_domain = keys.trust_domain_for(doc_thumbprint)
        if bound_domain is not None and bound_domain != doc.get("trust_domain"):
            return _deny(
                VerifyCode.ISSUER_MISMATCH,
                f"document {doc.get('vaid_id')!r} claims trust_domain "
                f"{doc.get('trust_domain')!r}, but kernel key thumbprint "
                f"{doc_thumbprint!r} is trusted under trust_config.trustedIssuers "
                f"only for {bound_domain!r} — a key is trusted for the domain "
                "it is paired with, not for any domain a document claims",
            )

    # ── Step 1: signature / authenticity of the LEAF ──
    #
    # Resolved and checked ahead of verify_chain_at so an unrecognised issuer
    # (ISSUER_MISMATCH) is distinguishable from a recognised issuer whose
    # signature does not verify (INAUTHENTIC) — chain.py's own key-resolution
    # closure collapses both into INAUTHENTIC, which is correct for a chain
    # hop but loses a distinction §5's audit-trail note asks the extension to
    # keep for the leaf.
    thumbprint = leaf.get("kernel_key_thumbprint")
    key = keys.resolve_key(thumbprint) if isinstance(thumbprint, str) else None
    if key is None:
        return _deny(
            VerifyCode.ISSUER_MISMATCH,
            f"no trusted kernel key for thumbprint {thumbprint!r} — this issuer "
            "is not in trust_config.trustedIssuers",
        )
    authenticity = verify_vaid_authenticity_graded(key, leaf)
    if authenticity is not VaidVerdict.VALID:
        code = _AUTHENTICITY_VERDICT_TO_CODE.get(authenticity, VerifyCode.INAUTHENTIC)
        return _deny(code, f"leaf authenticity check failed: {authenticity.code}")

    # ── Step 2: leaf expiry / TTL ──
    #
    # verify_chain_at deliberately does NOT check the leaf's own expiry (only
    # ancestors — see chain.py's "THE LEAF IS DELIBERATELY NOT CHECKED HERE"),
    # so this extension checks it here, between authenticity and chain
    # integrity, per spec §5.
    if is_expired_at(leaf, now):
        return _deny(VerifyCode.EXPIRED, "leaf VAID has passed its own expires_at")

    # ── Steps 3 and 4: chain integrity back to a trusted root, and per-hop
    # attenuation (scope, capabilities, tenant, expiry) ──
    bundle = PresentedBundle(chain_raw)
    chain_verdict = verify_chain_at(keys, leaf, bundle, AttestationBundle(), now)
    if chain_verdict is not ChainVerification.ATTENUATED:
        code = _CHAIN_VERDICT_TO_CODE.get(chain_verdict, VerifyCode.UNVERIFIABLE)
        return _deny(code, f"chain verification did not attenuate: {chain_verdict.value}")

    # ── Step 5: the requested action is within the LEAF's own scope ──
    #
    # Deliberately not subsumed by step 4: a well-attenuated chain says
    # nothing about whether the leaf's own scope_boundary covers the specific
    # action this message is asking to perform.
    if requested_action is not None and not is_in_scope(leaf, requested_action):
        return _deny(
            VerifyCode.OUT_OF_SCOPE,
            f"requested action {requested_action!r} is outside the leaf's "
            "scope_boundary",
        )

    # ── Step 6: revocation of every link, via the caller's RevocationCheck ──
    #
    # The verifier assembles the lineage (this module's job); the check only
    # answers about a lineage it is handed (vaid_mint.revocation's division of
    # labour) — never resolved or looked up by verify_a2a_message itself.
    lineage = assemble_lineage(leaf, bundle)
    if lineage is None:
        return _deny(
            VerifyCode.INDETERMINATE,
            "lineage could not be completely assembled from the presented "
            "chain — standing cannot be determined, fails closed",
        )
    status = revocation.check_lineage(lineage)
    if status is RevocationStatus.REVOKED:
        return _deny(VerifyCode.REVOKED, "a VAID in the lineage is revoked")
    if status is RevocationStatus.UNAVAILABLE:
        return _deny(
            VerifyCode.INDETERMINATE,
            "revocation check unavailable — fails closed, never read as "
            "not-revoked",
        )

    return _allow(
        VerifyCode.ALLOWED,
        "signature, expiry, chain integrity, attenuation, requested-action "
        "scope and revocation all checked clean",
    )

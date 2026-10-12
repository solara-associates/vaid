"""VAID standing verification for a presented identity: leaf + ancestor chain.

Self-contained, built only on ``vaid_mint`` primitives (no dependency on
``vaid_a2a`` — that package has its own release cadence and is not something
this package should couple to). The verification order mirrors
``vaid_a2a.verifier.verify_a2a_message`` because that order is already the
estate's answer to "how do you check a presented VAID end to end": authenticity
of the leaf, leaf expiry, chain integrity and attenuation back to a trusted
root, revocation over the full assembled lineage. This module re-derives that
order against the same ``vaid_mint`` functions rather than importing the other
package's implementation.
"""

from __future__ import annotations

import base64
import binascii
import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from vaid_mint.attestation import AttestationBundle
from vaid_mint.chain import (
    ChainVerification,
    PresentedBundle,
    verify_chain_at,
)
from vaid_mint.document import has_capability, is_expired_at, is_in_scope
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import RevocationCheck, RevocationStatus, assemble_lineage
from vaid_mint.verify import VaidVerdict, verify_vaid_authenticity_graded


class VerifyCode(enum.Enum):
    """Why :func:`verify_presentation` allowed or denied — the reason
    alongside the boolean. A caller that can only see a boolean cannot log,
    alert, or retry "forged" differently from "could not reach the revocation
    store"."""

    ALLOWED = "allowed"
    NO_VAID = "no_vaid"
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
    MISSING_CAPABILITY = "missing_capability"
    REVOKED = "revoked"
    INDETERMINATE = "indeterminate"

    @property
    def is_determined_denial(self) -> bool:
        """True for a positive refusal; false for :attr:`ALLOWED` and
        :attr:`INDETERMINATE` — "could not tell" is a refusal but not an
        accusation, mirroring :attr:`~vaid_mint.verify.VaidVerdict.INDETERMINATE`."""
        return self not in (VerifyCode.ALLOWED, VerifyCode.INDETERMINATE)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :func:`verify_presentation`. ``allowed`` is the field a
    gate checks first; ``code`` and ``reason`` are for the caller that logs or
    audits a denial."""

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


#: Length of a raw Ed25519 public key. A trust configuration carries raw keys,
#: never DER or PEM, so this is the only accepted length (the same rule the
#: VAID A2A extension states for its own ``trustedIssuers``, spec §2.1).
_ED25519_PUBLIC_KEY_BYTES = 32

#: Unpadded base64url alphabet, anchored and non-empty. ``=`` is deliberately
#: absent: the configured form is unpadded, so a padded string is a padding
#: error rather than an alternative spelling.
_B64URL_UNPADDED = re.compile(r"[A-Za-z0-9_-]+")


def _strict_b64url_decode(value: str) -> bytes:
    """Decode ``value`` as **strict unpadded base64url**, raising
    :class:`ValueError` on anything that is not exactly that.

    Strict means all three of the following are errors, not inputs to be
    repaired, because each of them makes the decoded bytes something other
    than what the configuration literally says:

    - a character outside the unpadded base64url alphabet, ``=`` included,
      which :func:`base64.urlsafe_b64decode` would otherwise DISCARD, so
      ``"!!!!"`` decodes to ``b""`` and would be accepted as a key;
    - a length no base64 string can have (``len % 4 == 1``), and the empty
      string, which decodes to zero bytes;
    - a non-canonical encoding: a final character whose unused low bits are
      not zero, so two distinct strings decode to the same bytes and the
      thumbprint a reader derives by hand from the configured text need not
      be the one this loader files the key under.

    Canonicality is checked by re-encoding rather than by masking bits, so
    the assertion is the one that matters directly: this string is the one
    and only base64url spelling of these bytes.

    This mirrors ``vaid_a2a.verifier._strict_b64url_decode`` deliberately —
    same rule, same spec paragraph (A2A extension §2.1) — rather than being a
    second, subtly different notion of strictness in the estate.
    """
    if not _B64URL_UNPADDED.fullmatch(value):
        raise ValueError(
            "not strict unpadded base64url (allowed characters are A-Z, a-z, "
            "0-9, '-' and '_', with no '=' padding, and the value must not "
            "be empty)"
        )
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError(
            "non-canonical base64url: the trailing bits of the final "
            "character are not zero, so this is not the unique encoding of "
            "the bytes it decodes to"
        )
    return decoded


class TrustedIssuersConfigError(ValueError):
    """The trust configuration itself is malformed, rather than merely
    resolving to no trusted key. Raised by :class:`TrustedIssuers` and by
    :func:`verify_presentation`/:class:`~vaid_adk.plugin.VaidAuthPlugin` when
    handed a resolver that cannot name the domain a key is trusted for, and
    never swallowed: an operator who misconfigures trust needs to find out
    when the process starts, not have it silently narrowed to "the entries we
    could make sense of"."""


@dataclass(frozen=True)
class _TrustedIssuer:
    """One resolved trust-configuration entry: a kernel key, filed under its
    own derived thumbprint, paired with the one trust domain that key is
    trusted for."""

    public_key: bytes
    trust_domain: str


class TrustedIssuers:
    """The trust configuration this package verifies against: a set of kernel
    public keys, each **bound to the one trust domain it is trusted for**.

    **Why this type exists rather than ``vaid_mint.chain.KernelKeyMap``.**
    ``KernelKeyMap`` resolves a key by thumbprint and keeps only the key
    bytes, which is correct for its own job — selecting a key to check a
    signature against. It cannot answer "which trust domain is this key
    trusted for", so a verifier built on it alone accepts a document signed
    by *any* trusted key while claiming *any* trust domain: a key trusted for
    one issuer's domain vouching for another issuer's identity, with no
    forged signature and no stolen key anywhere in the attack
    (GHSA-hfjh-v2x2-r58v). Holding the pairing is the half ``vaid_mint`` keeps
    deliberately out of band (see ``vaid_mint.mint.tenant_attenuates``), and
    this is where this package holds it.

    Entries use the VAID A2A extension's ``trustedIssuers`` shape (§2.1) —
    ``{"trustDomain": ..., "kernelPublicKey": "<unpadded base64url>"}`` — so
    one agent's trust configuration can be read from the same source whether
    it is serving A2A or running under ADK. Use :meth:`from_raw_keys` when the
    keys are already raw bytes in the process rather than text in a config
    file.

    Every shape below is a configuration error, raised rather than skipped or
    narrowed to a best-guess reading (A2A extension §2.1):

    - An entry that is not an object. It names neither a key nor a domain.
    - An entry with no parseable ``kernelPublicKey``: absent, not a string,
      or not **strict unpadded base64url decoding to exactly 32 bytes**.
      There is no reading of such an entry that resolves to key material a
      loader could actually trust.
    - An entry with no ``trustDomain``. A key with no domain attached binds
      to nothing, so accepting it would leave every document's claimed
      ``trust_domain`` effectively unchecked for that key — the very gap
      this type exists to close.
    - The same kernel public key listed more than once. Whichever domain a
      lookup happened to land on last would otherwise decide, silently,
      which domain that key is actually trusted for.
    """

    def __init__(self, trusted_issuers: Iterable[dict]) -> None:
        entries: dict[str, _TrustedIssuer] = {}
        domains_by_thumbprint: dict[str, list[str]] = {}
        for entry in trusted_issuers:
            if not isinstance(entry, dict):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry {entry!r} is not an object, every "
                    "entry must be {'trustDomain': ..., 'kernelPublicKey': ...}"
                )
            raw = entry.get("kernelPublicKey")
            if not isinstance(raw, str):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry {entry!r} has no parseable "
                    "kernelPublicKey, every entry must name the raw kernel "
                    "public key it trusts"
                )
            try:
                key_bytes = _strict_b64url_decode(raw)
            except (binascii.Error, ValueError) as exc:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernelPublicKey {raw!r} could "
                    f"not be decoded as strict unpadded base64url: {exc}"
                ) from exc
            if len(key_bytes) != _ED25519_PUBLIC_KEY_BYTES:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernelPublicKey {raw!r} decodes "
                    f"to {len(key_bytes)} bytes, a raw Ed25519 public key is "
                    f"exactly {_ED25519_PUBLIC_KEY_BYTES} bytes"
                )
            domain = entry.get("trustDomain")
            if not isinstance(domain, str):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernel public key {raw!r} has "
                    "no trustDomain, every entry must name the domain its key "
                    "is trusted for"
                )
            # Filed under the thumbprint the key itself derives to, never a
            # caller-supplied one: a thumbprint alone is not key material.
            thumbprint = kernel_key_thumbprint(key_bytes)
            domains_by_thumbprint.setdefault(thumbprint, []).append(domain)
            entries[thumbprint] = _TrustedIssuer(public_key=key_bytes, trust_domain=domain)

        for thumbprint, domains in domains_by_thumbprint.items():
            if len(domains) > 1:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers lists kernel key thumbprint {thumbprint!r} "
                    f"more than once, for domains {domains!r}, a key must be "
                    "trusted for exactly one trust_domain, never whichever "
                    "domain the last entry happened to list"
                )
        self._entries = entries

    @classmethod
    def from_raw_keys(cls, pairs: Iterable[tuple[str, bytes]]) -> "TrustedIssuers":
        """Build the same configuration from ``(trust_domain, raw_public_key)``
        pairs, for a caller that already holds key bytes in the process (a
        local issuer, a test, a key just fetched from a KMS) rather than
        base64url text in a config file.

        One trust domain may legitimately appear in several pairs — an issuer
        rotating or running more than one kernel key — but one key may not
        appear under two domains, the same rule :class:`TrustedIssuers`
        enforces over config entries, and for the same reason.
        """
        return cls(
            [
                {
                    "trustDomain": domain,
                    "kernelPublicKey": base64.urlsafe_b64encode(bytes(key))
                    .rstrip(b"=")
                    .decode("ascii"),
                }
                for domain, key in pairs
            ]
        )

    def resolve_key(self, thumbprint: str) -> bytes | None:
        """The raw Ed25519 public key for ``thumbprint``, or ``None`` if this
        configuration does not trust that key. Satisfies
        :class:`~vaid_mint.chain.KernelKeyResolver`, so an instance can be
        passed straight to :func:`~vaid_mint.chain.verify_chain_at`."""
        entry = self._entries.get(thumbprint)
        return entry.public_key if entry else None

    def trust_domain_for(self, thumbprint: str) -> str | None:
        """The one trust domain this configuration binds to ``thumbprint``, or
        ``None`` if ``thumbprint`` resolves to no trusted key."""
        entry = self._entries.get(thumbprint)
        return entry.trust_domain if entry else None

    def __len__(self) -> int:
        return len(self._entries)


def require_domain_binding(keys: object) -> None:
    """Raise :class:`TrustedIssuersConfigError` unless ``keys`` can say which
    trust domain each key it resolves is trusted for.

    A resolver that only answers :meth:`resolve_key` — ``KernelKeyMap`` and
    ``SingleKernelKey`` are both such resolvers — cannot have its documents'
    claimed ``trust_domain`` checked against anything, which is exactly the
    posture GHSA-hfjh-v2x2-r58v describes. Accepting one and skipping the
    binding check would leave that gap open by omission, so it is refused
    outright, and refused as early as the configuration is handed over
    (:class:`~vaid_adk.plugin.VaidAuthPlugin`'s constructor) rather than at
    the first request: a missing control must fail at startup, where an
    operator sees it, not quietly per-request.

    Duck-typed rather than an ``isinstance`` check against
    :class:`TrustedIssuers`, so a caller whose keys live in a KMS or a
    directory can supply its own resolver — provided it answers both
    questions.
    """
    binding = getattr(keys, "trust_domain_for", None)
    if not callable(binding):
        raise TrustedIssuersConfigError(
            f"keys={keys!r} resolves kernel keys but cannot name the trust "
            "domain each key is trusted for (no callable trust_domain_for), so "
            "a document's claimed trust_domain could not be checked against "
            "the key that signed it. Pass a vaid_adk.TrustedIssuers (or any "
            "resolver answering both resolve_key and trust_domain_for); a bare "
            "vaid_mint KernelKeyMap/SingleKernelKey is not sufficient "
            "(GHSA-hfjh-v2x2-r58v)."
        )


@dataclass(frozen=True)
class VaidPresentation:
    """What one ADK agent presents as its identity: its own signed VAID
    document (``leaf``) plus the ancestor documents it is holding so a
    verifier can walk the chain back to a trusted root (``chain``, not
    including ``leaf`` itself — the detached-chain-presentation convention of
    ``vaid_mint.chain`` / the VAID A2A extension)."""

    leaf: dict
    chain: tuple[dict, ...] = ()


def verify_presentation(
    presentation: VaidPresentation | None,
    *,
    keys: TrustedIssuers,
    revocation: RevocationCheck,
    requested_resource: str | None = None,
    requested_capability: str | None = None,
    now: datetime | None = None,
) -> VerifyResult:
    """Verify a presented VAID end to end: authenticity, leaf expiry, chain
    integrity and attenuation back to a trusted root, the specific
    resource/capability this call requires (if given), and revocation over
    the full assembled lineage.

    ``keys`` is the trust configuration: kernel keys each bound to the one
    trust domain it is trusted for (:class:`TrustedIssuers`). A resolver that
    cannot answer that second question raises
    :class:`TrustedIssuersConfigError` — see :func:`require_domain_binding`;
    it is a defect in the caller's configuration, not a verdict about any one
    presentation, so it is raised rather than returned as a denial, and it is
    raised before anything about ``presentation`` is looked at.

    Returns a refusal — never raises — for a missing or malformed
    presentation. ``presentation is None`` is :attr:`VerifyCode.NO_VAID`, and
    this module has no "pass through" posture for it: unlike the A2A
    extension's ``requireVaid`` switch, a caller invoking this function has
    already decided a VAID is required, so a missing one is always denied.
    """
    now = now or datetime.now(timezone.utc)

    # Checked first, before any presentation-shaped early return below, so a
    # resolver that cannot bind a domain to a key always raises, independent
    # of whether this particular call happens to carry a presentation at all.
    # A configuration mistake is a property of the caller, not of a request.
    require_domain_binding(keys)

    if presentation is None:
        return _deny(VerifyCode.NO_VAID, "no VAID presented")

    leaf = presentation.leaf

    # Step 1: the LEAF's own trust-domain binding, then its authenticity.
    #
    # Resolved ahead of verify_chain_at so an unrecognised or misbound issuer
    # (ISSUER_MISMATCH) is distinguishable from a recognised, correctly-bound
    # issuer whose signature does not verify (INAUTHENTIC) — chain.py's own
    # key-resolution closure collapses both into INAUTHENTIC, which is right
    # for a chain hop but loses a distinction an audit trail needs for the
    # leaf. Mirrors vaid_a2a.verifier step 1.
    #
    # The binding check runs BEFORE the signature check, and is scoped to the
    # LEAF alone: it must reach its verdict on the leaf's own defects before
    # anything about the presented chain is examined. A misbound ancestor is a
    # step 3 concern below; folding it in here would make the leaf's own
    # INAUTHENTIC/ISSUER_MISMATCH outcome depend on what else happens to be
    # presented alongside it, which is the exact nondeterminism this ordering
    # exists to remove.
    thumbprint = leaf.get("kernel_key_thumbprint")
    key = keys.resolve_key(thumbprint) if isinstance(thumbprint, str) else None
    if key is None:
        return _deny(
            VerifyCode.ISSUER_MISMATCH,
            f"no trusted kernel key for thumbprint {thumbprint!r}",
        )
    bound_domain = keys.trust_domain_for(thumbprint)
    if bound_domain != leaf.get("trust_domain"):
        return _deny(
            VerifyCode.ISSUER_MISMATCH,
            f"leaf claims trust_domain {leaf.get('trust_domain')!r}, but kernel "
            f"key thumbprint {thumbprint!r} is trusted only for "
            f"{bound_domain!r}: a key is trusted for the domain it is paired "
            "with, not for any domain a document claims",
        )
    authenticity = verify_vaid_authenticity_graded(key, leaf)
    if authenticity is not VaidVerdict.VALID:
        code = _AUTHENTICITY_VERDICT_TO_CODE.get(authenticity, VerifyCode.INAUTHENTIC)
        return _deny(code, f"leaf authenticity check failed: {authenticity.code}")

    # Step 2: leaf expiry. verify_chain_at deliberately does not check the
    # leaf's own expiry (only ancestors), so it is checked here.
    if is_expired_at(leaf, now):
        return _deny(VerifyCode.EXPIRED, "leaf VAID has passed its own expires_at")

    # Steps 3/4: chain integrity back to a trusted root, and per-hop
    # attenuation (scope, capabilities, tenant, expiry).
    #
    # Each presented ancestor's own trust-domain binding is checked first, by
    # the same rule as step 1 and reporting the same code, over the presented
    # chain only (the leaf was already settled in step 1) and only once the
    # leaf itself has cleared steps 1-2 — so a bad leaf signature is always
    # INAUTHENTIC on its own, never pre-empted by an unrelated wrong-domain
    # ancestor elsewhere in the chain.
    #
    # A document whose thumbprint resolves to NO trusted key is deliberately
    # left to verify_chain_at below, which refuses it on its own terms
    # (INAUTHENTIC/UNVERIFIABLE) — there is no domain to compare against, so
    # there is nothing for this check to say about it.
    for doc in presentation.chain:
        doc_thumbprint = doc.get("kernel_key_thumbprint")
        if not isinstance(doc_thumbprint, str):
            continue
        doc_bound_domain = keys.trust_domain_for(doc_thumbprint)
        if doc_bound_domain is not None and doc_bound_domain != doc.get("trust_domain"):
            return _deny(
                VerifyCode.ISSUER_MISMATCH,
                f"document {doc.get('vaid_id')!r} claims trust_domain "
                f"{doc.get('trust_domain')!r}, but kernel key thumbprint "
                f"{doc_thumbprint!r} is trusted only for {doc_bound_domain!r}: "
                "a key is trusted for the domain it is paired with, not for "
                "any domain a document claims",
            )

    bundle = PresentedBundle(presentation.chain)
    chain_verdict = verify_chain_at(keys, leaf, bundle, AttestationBundle(), now)
    if chain_verdict is not ChainVerification.ATTENUATED:
        code = _CHAIN_VERDICT_TO_CODE.get(chain_verdict, VerifyCode.UNVERIFIABLE)
        return _deny(code, f"chain verification did not attenuate: {chain_verdict.value}")

    # Step 5: the specific action this call requires is within the LEAF's own
    # scope_boundary / capability_set. Deliberately not subsumed by step 4: a
    # well-attenuated chain says nothing about whether this leaf's own bounds
    # cover the thing being asked of it right now.
    if requested_resource is not None and not is_in_scope(leaf, requested_resource):
        return _deny(
            VerifyCode.OUT_OF_SCOPE,
            f"requested resource {requested_resource!r} is outside the leaf's "
            "scope_boundary",
        )
    if requested_capability is not None and not has_capability(leaf, requested_capability):
        return _deny(
            VerifyCode.MISSING_CAPABILITY,
            f"requested capability {requested_capability!r} is not in the "
            "leaf's capability_set",
        )

    # Step 6: revocation of every link, via the caller's RevocationCheck. The
    # verifier assembles the lineage; the check only answers about a lineage
    # it is handed (vaid_mint.revocation's division of labour).
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
        "signature, expiry, chain integrity, attenuation, requested action "
        "and revocation all checked clean",
    )

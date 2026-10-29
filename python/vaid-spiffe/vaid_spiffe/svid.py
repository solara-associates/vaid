"""The SPIFFE "door": verify a presented X.509-SVID chain and extract its
SPIFFE ID.

This module answers exactly one question - is the presented certificate chain
a currently-valid SVID, chaining to a trusted root, that carries exactly one
``spiffe://`` identity in the expected trust domain - and nothing else. It does
not touch keys, PoP, or the VAID mint; :mod:`vaid_spiffe.mint` composes this
with those.

Every check fails closed: any defect (expired cert, untrusted chain, zero or
more than one URI SAN, wrong trust domain) raises
:class:`vaid_mint.error.IdentityError` and no SPIFFE ID is returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from spiffe.spiffe_id.spiffe_id import SpiffeId, SpiffeIdError, TrustDomain

from vaid_mint.error import IdentityError

__all__ = ["VerifiedSvid", "verify_svid_chain"]


@dataclass(frozen=True)
class VerifiedSvid:
    """The result of a successful :func:`verify_svid_chain`: an established
    identity reference, plus the leaf certificate (needed by
    :mod:`vaid_spiffe.possession` to check the presenter actually holds the
    SVID's private key)."""

    #: The full ``spiffe://trust-domain/path`` URI from the leaf's SAN.
    spiffe_id: str
    #: The SPIFFE trust domain (the authority component of ``spiffe_id``).
    trust_domain: str
    #: The leaf certificate, already verified to chain to a trusted root.
    leaf: x509.Certificate


def _leaf_spiffe_id(leaf: x509.Certificate) -> SpiffeId:
    """Extract and parse the leaf's SPIFFE ID. Fails closed on anything but
    exactly one well-formed ``spiffe://`` URI SAN (SPIFFE X.509-SVID spec
    section 2: "the SVID MUST have exactly one URI SAN, and it MUST be the
    SPIFFE ID")."""
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        uris = []
    if len(uris) != 1:
        raise IdentityError(
            f"SVID leaf must carry exactly one URI SAN (the SPIFFE ID), found {len(uris)}"
        )

    try:
        return SpiffeId(uris[0])
    except SpiffeIdError as exc:
        raise IdentityError(f"SVID leaf URI SAN is not a well-formed SPIFFE ID: {exc}") from exc


def verify_svid_chain(
    *,
    leaf: bytes,
    intermediates: list[bytes] = (),
    trust_bundle: list[bytes],
    expected_trust_domain: str,
    time: datetime | None = None,
) -> VerifiedSvid:
    """Verify a presented X.509-SVID chain against a supplied trust bundle.

    Args:
        leaf: The SVID leaf certificate, DER-encoded.
        intermediates: Any intermediate CA certificates, DER-encoded, in
            order (the leaf's issuer first). Empty for a chain that anchors
            directly at a root in ``trust_bundle``.
        trust_bundle: The trusted CA certificate(s) for the expected trust
            domain, DER-encoded. There is no SPIRE Workload API client here -
            the bundle is supplied by the caller (fetched out of band, exactly
            as a trust anchor is for any other verifier).
        expected_trust_domain: The SPIFFE trust domain the caller requires -
            e.g. a trust-domain-to-tenant mapping decided the VAID's
            ``tenant_id`` before this call, and the leaf's SPIFFE ID must
            belong to that domain or the binding is refused.
        time: The instant to validate expiry against. Defaults to now (UTC).
            A test fixes this for deterministic vectors.

    Returns:
        The verified identity reference.

    Raises:
        vaid_mint.error.IdentityError: on any failure - expired or
            not-yet-valid certificate anywhere in the chain, a chain that does
            not anchor to ``trust_bundle``, zero or more than one URI SAN on
            the leaf, a URI SAN that is not a well-formed SPIFFE ID, or a
            SPIFFE ID outside ``expected_trust_domain``. Fails closed: a
            defect anywhere means no :class:`VerifiedSvid`.
    """
    try:
        leaf_cert = x509.load_der_x509_certificate(leaf)
    except ValueError as exc:
        raise IdentityError(f"SVID leaf is not a valid DER certificate: {exc}") from exc

    try:
        intermediate_certs = [x509.load_der_x509_certificate(c) for c in intermediates]
    except ValueError as exc:
        raise IdentityError(f"SVID intermediate is not a valid DER certificate: {exc}") from exc

    try:
        root_certs = [x509.load_der_x509_certificate(c) for c in trust_bundle]
    except ValueError as exc:
        raise IdentityError(
            f"trust bundle entry is not a valid DER certificate: {exc}"
        ) from exc
    if not root_certs:
        raise IdentityError("trust bundle is empty - nothing to anchor the SVID chain to")

    # (1) SPIFFE ID + trust domain, from the leaf SAN, before any path
    # validation: a leaf that is not a well-formed SVID is refused for what it
    # is, rather than for whether its chain happens to validate.
    spiffe_id = _leaf_spiffe_id(leaf_cert)
    if spiffe_id.trust_domain != TrustDomain(expected_trust_domain):
        raise IdentityError(
            f"SVID trust domain '{spiffe_id.trust_domain}' does not match the "
            f"expected trust domain '{expected_trust_domain}'"
        )

    # (2) RFC 5280 path validation: chain to a trusted root in the bundle,
    # every certificate within its validity window. ClientVerifier (not
    # ServerVerifier) is used deliberately - a SPIFFE ID is a URI SAN, not a
    # DNS name, so there is no server hostname to match against.
    store = Store(root_certs)
    verify_time = time or datetime.now(timezone.utc)
    verifier = PolicyBuilder().store(store).time(verify_time).build_client_verifier()
    try:
        verifier.verify(leaf_cert, intermediate_certs)
    except VerificationError as exc:
        raise IdentityError(f"SVID certificate chain did not verify: {exc}") from exc

    return VerifiedSvid(
        spiffe_id=str(spiffe_id),
        trust_domain=str(spiffe_id.trust_domain),
        leaf=leaf_cert,
    )

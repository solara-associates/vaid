"""Proof that the presenter of a verified SVID controls its private key.

A verified certificate chain (:mod:`vaid_spiffe.svid`) proves the SVID was
issued by a trusted authority; it does not by itself prove the party
presenting it holds the matching private key, and a certificate chain is not
secret (the same bytes that cross a TLS handshake could be replayed by an
observer who never held the key). This module closes that gap with a
one-time challenge: the holder signs a payload binding the VAID operating key
it is registering, in the SVID's OWN algorithm (ECDSA, Ed25519 or RSA -
whatever the leaf certificate carries), and this module verifies that
signature against the leaf's public key.

This is a separate operation from the VAID mint's own Ed25519
proof-of-possession (``vaid_mint.mint._verify_pop_at_mint``): that one proves
the holder controls the VAID's Ed25519 operating key; this one proves the
holder controls the SVID's key, which may be any algorithm the certificate
carries. The two are not interchangeable and this module does not call into
vaid_mint's PoP verifier.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import Certificate

from vaid_mint.error import IdentityError

__all__ = [
    "SvidPossession",
    "build_svid_possession_payload",
    "canonical_svid_possession_bytes",
    "verify_svid_possession",
]

# Freshness window for an SVID possession proof, in seconds. Mirrors
# vaid_mint.mint.MINT_POP_FRESHNESS_SECS so the two proofs a bind-by-reference
# mint collects carry the same freshness contract.
POSSESSION_FRESHNESS_SECS = 300


@dataclass(frozen=True)
class SvidPossession:
    """A holder's proof-of-possession for the SVID's private key."""

    nonce: str
    issued_at: str  # whole-second RFC 3339 "...Z", matching vaid_mint.MintPop
    signature: bytes


def build_svid_possession_payload(
    *, operating_public_key_der: bytes, nonce: str, issued_at: str
) -> dict:
    """The canonical payload the SVID key signs. Binds the VAID operating key
    being registered together with the freshness material, so a captured
    possession proof cannot be replayed to bind a different operating key.

    Both holder and verifier build the payload through this one function so
    the signed bytes match exactly.
    """
    return {
        "operatingPublicKeyDer": list(operating_public_key_der),
        "nonce": nonce,
        "issuedAt": issued_at,
    }


def canonical_svid_possession_bytes(payload: dict) -> bytes:
    """Deterministic JSON bytes for a possession ``payload``: sorted keys, no
    insignificant whitespace. A real holder signs exactly these bytes with
    the SVID's private key, so this is public API, not a verifier-internal
    helper - both sides must build the same bytes from the same function.

    This payload type is internal to this package - nothing outside it needs
    to reproduce these bytes - so a minimal canonicalization is sufficient;
    it does not need to match vaid-pop's RFC 8785 JCS encoding."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_with_leaf_key(leaf: Certificate, message: bytes, signature: bytes) -> None:
    """Verify ``signature`` over ``message`` using the leaf's own public key,
    dispatching on whatever algorithm the certificate carries. Raises
    ``InvalidSignature`` (from ``cryptography``) on a bad signature, or
    :class:`IdentityError` for a key type this package does not support."""
    key = leaf.public_key()
    if isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(signature, message)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise IdentityError(
            f"SVID leaf key type {type(key).__name__} is not supported for a "
            "possession proof - supported: Ed25519, EC (ECDSA/SHA-256), RSA "
            "(PKCS#1 v1.5/SHA-256)"
        )


def verify_svid_possession(
    *,
    leaf: Certificate,
    operating_public_key_der: bytes,
    possession: SvidPossession,
    consumed_nonces: set[str],
    freshness_secs: int = POSSESSION_FRESHNESS_SECS,
) -> None:
    """Verify a holder's possession proof for the SVID's private key.

    Order mirrors ``vaid_mint.mint._verify_pop_at_mint``: fresh, then not
    replayed (recorded before the signature is checked), then the signature
    itself. Every failure raises :class:`IdentityError`; nothing here returns
    a bare ``False``.

    Args:
        leaf: The verified SVID leaf certificate (from
            :func:`vaid_spiffe.svid.verify_svid_chain`).
        operating_public_key_der: The VAID operating key being registered -
            the same bytes passed as ``public_key_der`` on the mint's
            ``VaidSeed``.
        possession: The holder's proof.
        consumed_nonces: Mutated in place to record ``possession.nonce`` -
            kept separate from the mint's own PoP nonce set so the two proofs
            cannot interfere with each other's replay defense.
        freshness_secs: Maximum allowed clock skew between now and
            ``possession.issued_at``.
    """
    issued = datetime.strptime(possession.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    skew = abs((datetime.now(timezone.utc) - issued).total_seconds())
    if skew > freshness_secs:
        raise IdentityError(
            f"SVID possession timestamp outside freshness window "
            f"({int(skew)}s > {freshness_secs}s)"
        )

    if possession.nonce in consumed_nonces:
        raise IdentityError("SVID possession nonce already used - replay rejected")
    consumed_nonces.add(possession.nonce)

    payload = build_svid_possession_payload(
        operating_public_key_der=operating_public_key_der,
        nonce=possession.nonce,
        issued_at=possession.issued_at,
    )
    message = canonical_svid_possession_bytes(payload)
    try:
        _verify_with_leaf_key(leaf, message, possession.signature)
    except InvalidSignature as exc:
        raise IdentityError(
            "SVID possession proof does not verify against the SVID leaf's "
            "public key - cannot bind an SVID you do not hold the key for"
        ) from exc

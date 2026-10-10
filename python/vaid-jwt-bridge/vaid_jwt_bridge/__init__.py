"""vaid-jwt-bridge — a token bridge for the VAID standard.

Verifies a full VAID delegation chain (signature, expiry, chain integrity and
attenuation to a trusted root, trust-domain binding, revocation of every
link) and, only on a full pass, issues a short-lived standard JWT a gateway
can verify against this bridge's published JWKS using any standard JWT
library. This is a token bridge, not "VAID as a JWT end to end": a gateway
holding an issued JWT is trusting the bridge's verification, not any
individual hop of the original chain.

Normative profile: ``docs/jwt/v1/profile.md``.

Usage::

    from vaid_jwt_bridge import exchange, ExchangeRequest, KeyRing, load_signer_from_file
    from vaid_mint.chain import SingleKernelKey
    from vaid_mint.revocation import InMemoryRevocationList

    signer = load_signer_from_file("signing-key.pem")
    result = exchange(
        ExchangeRequest(leaf=leaf_vaid, chain=(), audience="https://api.example.com"),
        keys=SingleKernelKey(kernel_public_key),
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        issuer="https://bridge.example.com",
        signer=signer,
    )
"""

from vaid_jwt_bridge.claims import build_sub_and_act, build_vaid_claim, chain_sha256
from vaid_jwt_bridge.exchange import (
    DEFAULT_TTL_SECONDS,
    ISSUED_TOKEN_TYPE_JWT,
    SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
    DenialReason,
    Denied,
    ExchangeRequest,
    ExchangeResult,
    Issued,
    exchange,
)
from vaid_jwt_bridge.keys import (
    JwcryptoSigner,
    KeyRing,
    Signer,
    load_signer_from_env,
    load_signer_from_file,
    load_signer_from_pem,
)

__all__ = [
    "exchange",
    "ExchangeRequest",
    "ExchangeResult",
    "Issued",
    "Denied",
    "DenialReason",
    "ISSUED_TOKEN_TYPE_JWT",
    "SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1",
    "DEFAULT_TTL_SECONDS",
    "build_sub_and_act",
    "build_vaid_claim",
    "chain_sha256",
    "Signer",
    "JwcryptoSigner",
    "KeyRing",
    "load_signer_from_pem",
    "load_signer_from_env",
    "load_signer_from_file",
]

__version__ = "0.1.0"

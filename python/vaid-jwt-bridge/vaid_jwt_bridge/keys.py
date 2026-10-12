"""Signing keys and the JWKS the bridge publishes.

``Signer`` is a small seam (one method that signs, one that exports a public
JWK) specifically so a future cloud-KMS-backed implementation can hold no
private key material in this process at all: it would call out to KMS for the
signature and otherwise implement the same two methods. The two shipped here
(:class:`JwcryptoSigner`, produced by :func:`load_signer_from_pem` /
:func:`load_signer_from_env` / :func:`load_signer_from_file`) hold the key
in-process via ``jwcrypto``, which is the right tradeoff for "load from a file
or environment variable for now" (docs/jwt/v1/profile.md SS8) but is not the
only thing that can satisfy ``Signer``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT


@runtime_checkable
class Signer(Protocol):
    """What :func:`vaid_jwt_bridge.exchange.exchange` needs to issue a JWT.

    Deliberately minimal: a signer identifies its own ``alg``/``kid`` and can
    (a) sign a claim set into a compact JWT and (b) export its own public key
    as a JWK — nothing here requires the private key to live in this process.
    """

    @property
    def alg(self) -> str:
        """``"EdDSA"`` or ``"ES256"``."""
        ...

    @property
    def kid(self) -> str:
        """RFC 7638 JWK thumbprint of the public key — see
        docs/jwt/v1/profile.md SS8 for why this, and not
        ``vaid_mint``'s ``kernel_key_thumbprint``, is used here."""
        ...

    def sign(self, claims: dict) -> str:
        """Return a compact-serialized JWS over ``claims``, header
        ``{"alg": self.alg, "kid": self.kid}``. Must never log or otherwise
        expose private key material."""
        ...

    def public_jwk(self) -> dict:
        """This signer's public key as a JSON-serializable JWK (RFC 7517),
        with ``kid``, ``alg`` and ``use: "sig"`` set."""
        ...


_SUPPORTED_ALGS = ("EdDSA", "ES256")


class JwcryptoSigner:
    """A :class:`Signer` holding its private key in-process via ``jwcrypto``.

    ``alg`` is derived from the loaded key's own type, never taken as a
    separate parameter — a caller cannot construct one with an ``alg`` that
    disagrees with the key it actually holds.
    """

    def __init__(self, private_jwk: JWK, *, alg: str) -> None:
        if alg not in _SUPPORTED_ALGS:
            raise ValueError(f"unsupported alg {alg!r}; must be one of {_SUPPORTED_ALGS}")
        self._jwk = private_jwk
        self._alg = alg
        self._kid = private_jwk.thumbprint()

    @property
    def alg(self) -> str:
        return self._alg

    @property
    def kid(self) -> str:
        return self._kid

    def sign(self, claims: dict) -> str:
        token = JWT(header={"alg": self._alg, "kid": self._kid}, claims=claims)
        token.make_signed_token(self._jwk)
        return token.serialize()

    def public_jwk(self) -> dict:
        exported = json.loads(self._jwk.export_public())
        exported["kid"] = self._kid
        exported["alg"] = self._alg
        exported["use"] = "sig"
        return exported


def _signer_from_private_key(private_key) -> JwcryptoSigner:
    """Build a :class:`JwcryptoSigner` from a loaded ``cryptography`` private
    key object, inferring ``alg`` from the key's own type/curve — never
    guessed from caller input."""
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        alg = "EdDSA"
    elif isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(
        private_key.curve, ec.SECP256R1
    ):
        alg = "ES256"
    else:
        raise ValueError(
            "unsupported key type for the VAID JWT bridge: only Ed25519 (EdDSA) "
            "and NIST P-256 (ES256) private keys are accepted"
        )
    return JwcryptoSigner(JWK.from_pyca(private_key), alg=alg)


def load_signer_from_pem(pem_bytes: bytes) -> JwcryptoSigner:
    """Load a PEM-encoded, unencrypted Ed25519 or P-256 private key.

    Never logs ``pem_bytes`` or any derived private material.
    """
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    return _signer_from_private_key(private_key)


def load_signer_from_env(var_name: str) -> JwcryptoSigner:
    """Load a signer from a PEM-encoded private key held in the environment
    variable ``var_name``. Raises :class:`KeyError` if it is unset."""
    pem = os.environ[var_name]
    return load_signer_from_pem(pem.encode("utf-8"))


def load_signer_from_file(path: str | Path) -> JwcryptoSigner:
    """Load a signer from a PEM-encoded private key file at ``path``."""
    return load_signer_from_pem(Path(path).read_bytes())


class KeyRing:
    """The bridge's full set of configured signing keys: one or more
    :class:`Signer` instances, with one designated active for new issuance.

    Every configured key's public half is published in :meth:`jwks`
    regardless of whether it is active — this is what makes a key rotation
    (publish the new key, flip ``active_kid`` later, retire the old key
    after its last issued token expires) possible without a verifying
    gateway ever seeing an unresolvable ``kid``.
    """

    def __init__(self, signers: list[Signer], *, active_kid: str | None = None) -> None:
        if not signers:
            raise ValueError("a KeyRing needs at least one signer")
        self._signers: dict[str, Signer] = {}
        for s in signers:
            if s.kid in self._signers:
                raise ValueError(f"duplicate kid {s.kid!r} in KeyRing")
            self._signers[s.kid] = s
        self._active_kid = active_kid or signers[0].kid
        if self._active_kid not in self._signers:
            raise ValueError(f"active_kid {self._active_kid!r} is not among the configured signers")

    @property
    def active(self) -> Signer:
        """The signer used to issue new tokens."""
        return self._signers[self._active_kid]

    def jwks(self) -> dict:
        """The RFC 7517 JWK Set this bridge publishes at
        ``/.well-known/jwks.json`` — every configured key's public half."""
        return {"keys": [s.public_jwk() for s in self._signers.values()]}

"""Holder-side helpers shared by the test suite: build the VAID operating
keypair, its proof-of-possession, and the SVID possession proof."""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_mint import VaidSeed, build_mint_pop_payload, prefix_entry
from vaid_mint.mint_types import MintPop

from vaid_spiffe.possession import (
    SvidPossession,
    build_svid_possession_payload,
    canonical_svid_possession_bytes,
)


def operating_keypair():
    key = ed25519.Ed25519PrivateKey.generate()
    return key, key.public_key().public_bytes_raw()


def seed_with_operating_key(
    operating_public_key_der: bytes, *, tenant_id: str = "acme"
) -> VaidSeed:
    return VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id=tenant_id,
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=operating_public_key_der,
    )


def make_mint_pop(seed: VaidSeed, operating_public_key_der: bytes, operating_key) -> MintPop:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(
        seed, public_key_der=operating_public_key_der, nonce=nonce, issued_at=issued_at
    )
    digest = canonical_request_signing_bytes(payload)
    return MintPop(nonce=nonce, issued_at=issued_at, signature=operating_key.sign(digest))


def _sign_with_leaf_key(leaf_key, message: bytes) -> bytes:
    if isinstance(leaf_key, ed25519.Ed25519PrivateKey):
        return leaf_key.sign(message)
    if isinstance(leaf_key, ec.EllipticCurvePrivateKey):
        return leaf_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if isinstance(leaf_key, rsa.RSAPrivateKey):
        return leaf_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise TypeError(f"unsupported leaf key type for test fixture: {type(leaf_key)}")


def make_svid_possession(leaf_key, operating_public_key_der: bytes) -> SvidPossession:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_svid_possession_payload(
        operating_public_key_der=operating_public_key_der, nonce=nonce, issued_at=issued_at
    )
    signature = _sign_with_leaf_key(leaf_key, canonical_svid_possession_bytes(payload))
    return SvidPossession(nonce=nonce, issued_at=issued_at, signature=signature)

"""Tests for the SVID possession proof (:mod:`vaid_spiffe.possession`):
freshness, replay, signature, and multi-algorithm dispatch."""

from __future__ import annotations

import datetime

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from vaid_mint.error import IdentityError
from vaid_spiffe.possession import (
    SvidPossession,
    build_svid_possession_payload,
    canonical_svid_possession_bytes,
    verify_svid_possession,
)

from conftest import make_root_ca, make_svid_leaf
from helpers import make_svid_possession, operating_keypair


def test_valid_possession_verifies(valid_svid):
    _, operating_pub = operating_keypair()
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    verify_svid_possession(
        leaf=valid_svid["leaf_cert"],
        operating_public_key_der=operating_pub,
        possession=possession,
        consumed_nonces=set(),
    )


def test_stale_possession_is_refused(valid_svid):
    _, operating_pub = operating_keypair()
    stale = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    payload = build_svid_possession_payload(
        operating_public_key_der=operating_pub, nonce="n1", issued_at=stale
    )
    signature = valid_svid["leaf_key"].sign(
        canonical_svid_possession_bytes(payload), ec.ECDSA(hashes.SHA256())
    )
    possession = SvidPossession(nonce="n1", issued_at=stale, signature=signature)
    with pytest.raises(IdentityError, match="freshness window"):
        verify_svid_possession(
            leaf=valid_svid["leaf_cert"],
            operating_public_key_der=operating_pub,
            possession=possession,
            consumed_nonces=set(),
        )


def test_replayed_nonce_is_refused(valid_svid):
    _, operating_pub = operating_keypair()
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    consumed: set[str] = set()
    verify_svid_possession(
        leaf=valid_svid["leaf_cert"],
        operating_public_key_der=operating_pub,
        possession=possession,
        consumed_nonces=consumed,
    )
    with pytest.raises(IdentityError, match="replay"):
        verify_svid_possession(
            leaf=valid_svid["leaf_cert"],
            operating_public_key_der=operating_pub,
            possession=possession,
            consumed_nonces=consumed,
        )


def test_possession_signed_with_wrong_key_is_refused(valid_svid):
    """Signed with a key other than the SVID leaf's - proves nothing about
    that SVID, and must be rejected."""
    _, operating_pub = operating_keypair()
    impostor_key = ed25519.Ed25519PrivateKey.generate()
    possession = make_svid_possession(impostor_key, operating_pub)
    with pytest.raises(IdentityError, match="does not verify"):
        verify_svid_possession(
            leaf=valid_svid["leaf_cert"],
            operating_public_key_der=operating_pub,
            possession=possession,
            consumed_nonces=set(),
        )


def test_possession_bound_to_a_different_operating_key_is_refused(valid_svid):
    """The possession proof binds a specific operating key; presenting it
    alongside a DIFFERENT operating key must fail, or a captured proof could
    be replayed to bind someone else's key."""
    _, operating_pub = operating_keypair()
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    _, other_operating_pub = operating_keypair()
    with pytest.raises(IdentityError, match="does not verify"):
        verify_svid_possession(
            leaf=valid_svid["leaf_cert"],
            operating_public_key_der=other_operating_pub,
            possession=possession,
            consumed_nonces=set(),
        )


def test_ed25519_svid_key_possession_verifies(trust_domain):
    ca_key, ca_cert = make_root_ca()
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=f"spiffe://{trust_domain}/agent/ed25519",
        leaf_key=leaf_key,
    )
    _, operating_pub = operating_keypair()
    possession = make_svid_possession(leaf_key, operating_pub)
    verify_svid_possession(
        leaf=leaf_cert,
        operating_public_key_der=operating_pub,
        possession=possession,
        consumed_nonces=set(),
    )


def test_rsa_svid_key_possession_verifies(trust_domain):
    ca_key, ca_cert = make_root_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=f"spiffe://{trust_domain}/agent/rsa",
        leaf_key=leaf_key,
    )
    _, operating_pub = operating_keypair()
    possession = make_svid_possession(leaf_key, operating_pub)
    verify_svid_possession(
        leaf=leaf_cert,
        operating_public_key_der=operating_pub,
        possession=possession,
        consumed_nonces=set(),
    )

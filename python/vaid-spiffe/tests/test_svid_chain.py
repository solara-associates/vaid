"""Tests for the SVID door (:mod:`vaid_spiffe.svid`): chain, expiry, SAN
count, and trust domain, each checked in isolation."""

from __future__ import annotations

import datetime

import pytest
from cryptography.hazmat.primitives import serialization

from vaid_mint.error import IdentityError
from vaid_spiffe.svid import verify_svid_chain

from conftest import make_root_ca, make_svid_leaf


def test_valid_svid_verifies(valid_svid, trust_domain):
    verified = verify_svid_chain(
        leaf=valid_svid["leaf_der"],
        intermediates=[],
        trust_bundle=valid_svid["trust_bundle_der"],
        expected_trust_domain=trust_domain,
    )
    assert verified.spiffe_id == valid_svid["spiffe_id"]
    assert verified.trust_domain == trust_domain


def test_expired_svid_is_refused(ca, trust_domain):
    ca_key, ca_cert = ca
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=f"spiffe://{trust_domain}/agent/researcher",
        not_before_delta=datetime.timedelta(hours=-3),
        not_after_delta=datetime.timedelta(hours=-1),
    )
    with pytest.raises(IdentityError):
        verify_svid_chain(
            leaf=leaf_cert.public_bytes(serialization.Encoding.DER),
            intermediates=[],
            trust_bundle=[ca_cert.public_bytes(serialization.Encoding.DER)],
            expected_trust_domain=trust_domain,
        )


def test_not_yet_valid_svid_is_refused(ca, trust_domain):
    ca_key, ca_cert = ca
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=f"spiffe://{trust_domain}/agent/researcher",
        not_before_delta=datetime.timedelta(hours=1),
        not_after_delta=datetime.timedelta(hours=3),
    )
    with pytest.raises(IdentityError):
        verify_svid_chain(
            leaf=leaf_cert.public_bytes(serialization.Encoding.DER),
            intermediates=[],
            trust_bundle=[ca_cert.public_bytes(serialization.Encoding.DER)],
            expected_trust_domain=trust_domain,
        )


def test_wrong_trust_domain_is_refused(valid_svid):
    with pytest.raises(IdentityError):
        verify_svid_chain(
            leaf=valid_svid["leaf_der"],
            intermediates=[],
            trust_bundle=valid_svid["trust_bundle_der"],
            expected_trust_domain="some-other-domain.test",
        )


def test_missing_uri_san_is_refused(ca, trust_domain):
    ca_key, ca_cert = ca
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=f"spiffe://{trust_domain}/agent/researcher",
        omit_san=True,
    )
    with pytest.raises(IdentityError, match="exactly one URI SAN"):
        verify_svid_chain(
            leaf=leaf_cert.public_bytes(serialization.Encoding.DER),
            intermediates=[],
            trust_bundle=[ca_cert.public_bytes(serialization.Encoding.DER)],
            expected_trust_domain=trust_domain,
        )


def test_multiple_uri_sans_is_refused(ca, trust_domain):
    ca_key, ca_cert = ca
    primary = f"spiffe://{trust_domain}/agent/researcher"
    _, leaf_cert = make_svid_leaf(
        ca_key,
        ca_cert,
        spiffe_id=primary,
        extra_uri_sans=[f"spiffe://{trust_domain}/agent/other"],
    )
    with pytest.raises(IdentityError, match="exactly one URI SAN"):
        verify_svid_chain(
            leaf=leaf_cert.public_bytes(serialization.Encoding.DER),
            intermediates=[],
            trust_bundle=[ca_cert.public_bytes(serialization.Encoding.DER)],
            expected_trust_domain=trust_domain,
        )


def test_untrusted_chain_is_refused(valid_svid, trust_domain):
    # A different, unrelated root - the leaf was never signed by it.
    _, unrelated_root = make_root_ca("unrelated root")
    with pytest.raises(IdentityError):
        verify_svid_chain(
            leaf=valid_svid["leaf_der"],
            intermediates=[],
            trust_bundle=[unrelated_root.public_bytes(serialization.Encoding.DER)],
            expected_trust_domain=trust_domain,
        )


def test_empty_trust_bundle_is_refused(valid_svid, trust_domain):
    with pytest.raises(IdentityError, match="trust bundle is empty"):
        verify_svid_chain(
            leaf=valid_svid["leaf_der"],
            intermediates=[],
            trust_bundle=[],
            expected_trust_domain=trust_domain,
        )

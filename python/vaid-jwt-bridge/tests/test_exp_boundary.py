"""`exp` never exceeds the leaf's own `expires_at` (docs/jwt/v1/profile.md
SS3.1) — tested both where the default TTL is the binding constraint and
where the leaf's remaining life is."""

from __future__ import annotations

from datetime import timedelta

import jwt as pyjwt

from vaid_jwt_bridge import ExchangeRequest, Issued, KeyRing, exchange


def test_exp_bounded_by_default_ttl_when_leaf_outlives_it(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    """The ordinary case: the leaf has far longer to live than the
    bridge's own default TTL, so `exp` is `iat + ttl`, not the leaf's."""
    root, child, leaf = three_hop_chain

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        default_ttl_seconds=300,
        now=verification_now,
    )
    assert isinstance(result, Issued)
    header_claims = pyjwt.decode(result.access_token, options={"verify_signature": False})
    assert header_claims["exp"] - header_claims["iat"] == 300
    assert result.expires_in == 300


def test_exp_clamped_to_leaf_expiry_when_shorter_than_ttl(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer
):
    """The leaf has LESS remaining life than the configured default TTL:
    `exp` must equal the leaf's own `expires_at`, never later."""
    from datetime import datetime, timezone

    root, child, leaf = three_hop_chain
    leaf_expires_at = datetime.fromisoformat(leaf["expires_at"].replace("Z", "+00:00"))
    almost_expired = leaf_expires_at - timedelta(seconds=10)  # 10s of life left

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        default_ttl_seconds=3600,  # far longer than the leaf's remaining life
        now=almost_expired,
    )

    assert isinstance(result, Issued)
    claims = pyjwt.decode(result.access_token, options={"verify_signature": False})
    assert claims["exp"] == int(leaf_expires_at.timestamp())
    assert result.expires_in == 10

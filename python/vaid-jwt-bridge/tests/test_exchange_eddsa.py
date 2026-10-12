"""A valid 3-hop chain, exchanged and issued under EdDSA, verified by an
INDEPENDENT standard library (PyJWT) using ONLY the bridge's served JWKS —
proving the token is genuinely standard-compliant, not merely self-consistent
with the library that produced it (docs/jwt/v1/profile.md SS8)."""

from __future__ import annotations

import json

import jwt as pyjwt

from vaid_jwt_bridge import ExchangeRequest, Issued, KeyRing, exchange


def test_eddsa_round_trip_via_jwks(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    keyring = KeyRing([eddsa_signer])

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="https://api.example.com"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Issued)
    assert result.issued_token_type == "urn:ietf:params:oauth:token-type:jwt"
    assert result.token_type == "N_A"

    jwks = keyring.jwks()
    assert jwks["keys"][0]["alg"] == "EdDSA"
    assert jwks["keys"][0]["kty"] == "OKP"
    signing_key = pyjwt.PyJWK.from_json(json.dumps(jwks["keys"][0]))

    decoded = pyjwt.decode(
        result.access_token,
        key=signing_key,
        algorithms=["EdDSA"],
        audience="https://api.example.com",
        issuer="https://bridge.example.com",
    )

    assert decoded["iss"] == "https://bridge.example.com"
    assert decoded["aud"] == "https://api.example.com"
    assert decoded["sub"] == root["vaid_id"]
    assert decoded["vaid"]["vaid_id"] == leaf["vaid_id"]
    assert decoded["vaid"]["trust_domain"] == leaf["trust_domain"]
    assert decoded["vaid"]["scope_boundary"] == leaf["scope_boundary"]
    assert decoded["vaid"]["capability_set"] == leaf["capability_set"]
    assert "jti" in decoded


def test_header_kid_matches_jwks(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    keyring = KeyRing([eddsa_signer])
    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Issued)
    header = pyjwt.get_unverified_header(result.access_token)
    published_kids = {k["kid"] for k in keyring.jwks()["keys"]}
    assert header["kid"] in published_kids
    assert header["alg"] == "EdDSA"

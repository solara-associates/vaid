"""The ES256 path — same proof as test_exchange_eddsa.py, the other
supported algorithm, confirming both are genuinely wired rather than one
being untested scaffolding."""

from __future__ import annotations

import json

import jwt as pyjwt

from vaid_jwt_bridge import ExchangeRequest, Issued, KeyRing, exchange


def test_es256_round_trip_via_jwks(
    three_hop_chain, trusted_keys, vouching_revocation, es256_signer, verification_now
):
    root, child, leaf = three_hop_chain
    keyring = KeyRing([es256_signer])

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="https://api.example.com"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=es256_signer,
        now=verification_now,
    )

    assert isinstance(result, Issued)

    jwks = keyring.jwks()
    assert jwks["keys"][0]["alg"] == "ES256"
    assert jwks["keys"][0]["kty"] == "EC"
    assert jwks["keys"][0]["crv"] == "P-256"
    signing_key = pyjwt.PyJWK.from_json(json.dumps(jwks["keys"][0]))

    decoded = pyjwt.decode(
        result.access_token,
        key=signing_key,
        algorithms=["ES256"],
        audience="https://api.example.com",
        issuer="https://bridge.example.com",
    )
    assert decoded["sub"] == root["vaid_id"]
    assert decoded["vaid"]["vaid_id"] == leaf["vaid_id"]


def test_jwks_can_publish_both_algorithms_simultaneously(eddsa_signer, es256_signer):
    keyring = KeyRing([eddsa_signer, es256_signer], active_kid=eddsa_signer.kid)
    algs = {k["alg"] for k in keyring.jwks()["keys"]}
    assert algs == {"EdDSA", "ES256"}
    assert keyring.active.alg == "EdDSA"

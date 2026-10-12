"""Client-shaped test of the HTTP service (A8.client-test): drives
`POST /token-exchange` and `GET /.well-known/jwks.json` exactly as an
external caller would, over the real ASGI app, not by calling internal
functions directly."""

from __future__ import annotations

import json
from urllib.parse import urlencode

import jwt as pyjwt
from starlette.testclient import TestClient

from vaid_jwt_bridge.exchange import SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1
from vaid_jwt_bridge.keys import KeyRing
from vaid_jwt_bridge.service import GRANT_TYPE_TOKEN_EXCHANGE, BridgeConfig, build_app


def _client(trusted_keys, vouching_revocation, eddsa_signer) -> TestClient:
    config = BridgeConfig(
        issuer="https://bridge.example.com",
        keys=trusted_keys,
        revocation=vouching_revocation,
        keyring=KeyRing([eddsa_signer]),
    )
    return TestClient(build_app(config))


def test_token_exchange_and_jwks_over_http(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer
):
    root, child, leaf = three_hop_chain
    client = _client(trusted_keys, vouching_revocation, eddsa_signer)

    jwks_response = client.get("/.well-known/jwks.json")
    assert jwks_response.status_code == 200
    jwks = jwks_response.json()
    assert len(jwks["keys"]) == 1

    body = urlencode(
        {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token_type": SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
            "subject_token": json.dumps({"leaf": leaf, "chain": [root, child]}),
            "audience": "https://api.example.com",
        }
    )
    response = client.post(
        "/token-exchange",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
    assert payload["token_type"] == "N_A"

    signing_key = pyjwt.PyJWK.from_json(json.dumps(jwks["keys"][0]))
    decoded = pyjwt.decode(
        payload["access_token"],
        key=signing_key,
        algorithms=["EdDSA"],
        audience="https://api.example.com",
        issuer="https://bridge.example.com",
    )
    assert decoded["sub"] == root["vaid_id"]


def test_denied_exchange_over_http_returns_invalid_grant_and_no_token(
    three_hop_chain, trusted_keys, eddsa_signer
):
    from vaid_mint.revocation import InMemoryRevocationList

    root, child, leaf = three_hop_chain
    revocation = InMemoryRevocationList.assume_nothing_revoked()
    revocation.revoke(leaf["vaid_id"])
    client = _client(trusted_keys, revocation, eddsa_signer)

    body = urlencode(
        {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token_type": SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
            "subject_token": json.dumps({"leaf": leaf, "chain": [root, child]}),
            "audience": "https://api.example.com",
        }
    )
    response = client.post(
        "/token-exchange",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    payload = response.json()
    assert payload["error"] == "invalid_grant"
    assert "access_token" not in payload
    assert "revoked" in payload["error_description"]


def test_wrong_grant_type_is_rejected(three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer):
    root, child, leaf = three_hop_chain
    client = _client(trusted_keys, vouching_revocation, eddsa_signer)

    body = urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:client-credentials",
            "subject_token_type": SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
            "subject_token": json.dumps({"leaf": leaf, "chain": [root, child]}),
            "audience": "aud",
        }
    )
    response = client.post(
        "/token-exchange",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_malformed_subject_token_is_rejected(trusted_keys, vouching_revocation, eddsa_signer):
    client = _client(trusted_keys, vouching_revocation, eddsa_signer)

    body = urlencode(
        {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token_type": SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
            "subject_token": "not json",
            "audience": "aud",
        }
    )
    response = client.post(
        "/token-exchange",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"

"""VaidAuth attaches valid PoP headers to every outbound request.

Uses httpx's MockTransport so no network/server is needed: the handler receives
the request AFTER auth_flow has run, so we can assert the four x-synthera-* headers
are present and that the signature verifies over the reconstructed payload — with
the raw_path (path+query) convention, and with a body-less (GET) request.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    HEADER_VAID,
    RequestSigner,
    build_request_auth_payload,
    canonical_request_signing_bytes,
)

from vaid_langchain import VaidAuth
from vaid_langchain._target import request_target

SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
VAID_ID = "11111111-1111-1111-1111-111111111111"
TENANT_ID = "synthera-control-plane"


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))


def _signer() -> RequestSigner:
    return RequestSigner(vaid={"vaid_id": VAID_ID, "tenant_id": TENANT_ID}, private_key=_key())


def _verify_headers(request: httpx.Request) -> bool:
    """Reconstruct the payload from the request using the SAME convention the auth
    used (raw_path) and verify the PoP signature against the agent public key."""
    target = request_target(request)
    body = request.content or b""
    payload = build_request_auth_payload(
        vaid_id=VAID_ID,
        method=request.method.upper(),
        path=target,
        body_sha256=hashlib.sha256(body).hexdigest(),
        tenant_id=TENANT_ID,
        timestamp=request.headers[HEADER_TIMESTAMP],
        client_nonce=request.headers[HEADER_NONCE],
    )
    digest = canonical_request_signing_bytes(payload)
    sig = base64.b64decode(request.headers[HEADER_SIGNATURE])
    pub = _key().public_key().public_bytes_raw()
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)
        return True
    except Exception:
        return False


def _client(handler) -> httpx.Client:
    return httpx.Client(
        base_url="https://api.example.com",
        auth=VaidAuth(_signer()),
        transport=httpx.MockTransport(handler),
    )


def test_all_four_headers_attached_and_signature_valid_post_with_body():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text="ok")

    with _client(handler) as c:
        c.post("/vaid/mint", json={"seed": {"agentClass": "x"}})

    req = captured["req"]
    for h in (HEADER_VAID, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE):
        assert h in req.headers, f"missing {h}"
    assert _verify_headers(req), "PoP signature must verify over the signed request"


def test_signature_covers_query_string():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text="ok")

    with _client(handler) as c:
        c.post("/vaid/mint?tenant=acme&limit=10", json={})

    req = captured["req"]
    # The signed target includes the query, and it verifies.
    assert request_target(req) == "/vaid/mint?tenant=acme&limit=10"
    assert _verify_headers(req)


def test_tampering_with_query_after_signing_breaks_verification():
    """A verifier that sees a DIFFERENT query than what was signed must reject —
    this is the property path-only signing would forfeit."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text="ok")

    with _client(handler) as c:
        c.post("/vaid/mint?tenant=acme", json={})

    req = captured["req"]
    # Simulate a verifier reconstructing with a tampered query.
    payload = build_request_auth_payload(
        vaid_id=VAID_ID,
        method="POST",
        path="/vaid/mint?tenant=attacker",  # tampered
        body_sha256=hashlib.sha256(req.content or b"").hexdigest(),
        tenant_id=TENANT_ID,
        timestamp=req.headers[HEADER_TIMESTAMP],
        client_nonce=req.headers[HEADER_NONCE],
    )
    digest = canonical_request_signing_bytes(payload)
    sig = base64.b64decode(req.headers[HEADER_SIGNATURE])
    pub = _key().public_key().public_bytes_raw()
    with pytest.raises(Exception):
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)


def test_body_less_get_signs_empty_body():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text="ok")

    with _client(handler) as c:
        c.get("/status")

    req = captured["req"]
    assert (req.content or b"") == b""
    assert _verify_headers(req), "a GET with no body must sign b'' and verify"


def test_each_request_gets_a_fresh_nonce():
    nonces = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonces.append(request.headers[HEADER_NONCE])
        return httpx.Response(200, text="ok")

    with _client(handler) as c:
        c.post("/a", json={})
        c.post("/a", json={})

    assert len(nonces) == 2 and nonces[0] != nonces[1], "nonce must be per-request fresh"

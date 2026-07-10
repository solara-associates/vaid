"""The LangChain tool wrapper produces VAID-signed requests when invoked.

Proves the end-to-end path an agent takes: invoke the StructuredTool → it calls
the protected backend through the VaidAuth-bearing client → the request arriving
at the backend carries valid PoP headers. A MockTransport stands in for the
backend so no server/LLM is needed.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
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

from vaid_langchain import VaidAuth, make_vaid_tool
from vaid_langchain._target import request_target

SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
VAID_ID = "11111111-1111-1111-1111-111111111111"
TENANT_ID = "synthera-control-plane"


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))


def _signer() -> RequestSigner:
    return RequestSigner(vaid={"vaid_id": VAID_ID, "tenant_id": TENANT_ID}, private_key=_key())


def _verify(request: httpx.Request) -> bool:
    payload = build_request_auth_payload(
        vaid_id=VAID_ID,
        method=request.method.upper(),
        path=request_target(request),
        body_sha256=hashlib.sha256(request.content or b"").hexdigest(),
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


def _tool_with_mock_backend(handler):
    client = httpx.Client(
        base_url="https://api.example.com",
        auth=VaidAuth(_signer()),
        transport=httpx.MockTransport(handler),
    )
    return make_vaid_tool(_signer(), "https://api.example.com", client=client)


def test_tool_invocation_sends_a_signed_request():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text='{"ok": true}')

    tool = _tool_with_mock_backend(handler)
    out = tool.invoke({"path": "/vaid/mint", "payload": {"seed": {"agentClass": "x"}}})

    assert out == '{"ok": true}'
    req = captured["req"]
    for h in (HEADER_VAID, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE):
        assert h in req.headers
    assert _verify(req), "the tool's outbound request must carry a valid PoP signature"


def test_tool_has_expected_name_and_is_a_langchain_tool():
    tool = make_vaid_tool(_signer(), "https://api.example.com", name="mint_via_synthera")
    from langchain_core.tools import BaseTool

    assert isinstance(tool, BaseTool)
    assert tool.name == "mint_via_synthera"


def test_tool_signs_query_string_in_path():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, text="ok")

    tool = _tool_with_mock_backend(handler)
    tool.invoke({"path": "/things?owner=acme&limit=5", "payload": {}})

    req = captured["req"]
    assert request_target(req) == "/things?owner=acme&limit=5"
    assert _verify(req)

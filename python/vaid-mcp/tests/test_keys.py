from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mcp.keys import KeySourceError, resolve_keys


def _pub() -> bytes:
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw()


def test_resolve_from_hex_public_key():
    raw = _pub()
    resolved = resolve_keys(public_key=raw.hex(), key_url=None)
    assert resolved.source == "public_key"
    assert resolved.resolver.resolve_key(kernel_key_thumbprint(raw)) == raw


def test_resolve_from_base64url_public_key():
    raw = _pub()
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    resolved = resolve_keys(public_key=b64, key_url=None)
    assert resolved.resolver.resolve_key(kernel_key_thumbprint(raw)) == raw


def test_rejects_both_public_key_and_key_url():
    raw = _pub()
    with pytest.raises(KeySourceError, match="exactly one"):
        resolve_keys(public_key=raw.hex(), key_url="https://example.com/keys.json")


def test_rejects_neither_public_key_nor_key_url():
    with pytest.raises(KeySourceError, match="exactly one"):
        resolve_keys(public_key=None, key_url=None)


def test_rejects_malformed_public_key():
    with pytest.raises(KeySourceError):
        resolve_keys(public_key="not-a-key", key_url=None)


def test_rejects_wrong_length_public_key():
    short_key_b64 = base64.urlsafe_b64encode(b"\x00" * 16).rstrip(b"=").decode("ascii")
    with pytest.raises(KeySourceError, match="32"):
        resolve_keys(public_key=short_key_b64, key_url=None)


class _Handler(BaseHTTPRequestHandler):
    body: bytes = b"{}"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args, **kwargs):
        pass


@pytest.fixture
def key_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join()


def _jwk_doc(raw: bytes) -> bytes:
    thumbprint = kernel_key_thumbprint(raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return json.dumps(
        {"keys": {thumbprint: {"kty": "OKP", "crv": "Ed25519", "x": x}}}
    ).encode("utf-8")


def test_resolve_from_key_url(key_server):
    raw = _pub()
    _Handler.body = _jwk_doc(raw)
    url = f"http://127.0.0.1:{key_server.server_port}/vaid-keys.json"
    resolved = resolve_keys(public_key=None, key_url=url)
    assert resolved.source == url
    assert resolved.resolver.resolve_key(kernel_key_thumbprint(raw)) == raw


def test_rejects_key_url_with_mismatched_thumbprint(key_server):
    raw = _pub()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    _Handler.body = json.dumps(
        {"keys": {"urn:ietf:params:oauth:jwk-thumbprint:sha-256:wrong": {"kty": "OKP", "crv": "Ed25519", "x": x}}}
    ).encode("utf-8")
    url = f"http://127.0.0.1:{key_server.server_port}/vaid-keys.json"
    with pytest.raises(KeySourceError, match="does not match"):
        resolve_keys(public_key=None, key_url=url)


def test_rejects_key_url_with_no_keys_map(key_server):
    _Handler.body = b"{}"
    url = f"http://127.0.0.1:{key_server.server_port}/vaid-keys.json"
    with pytest.raises(KeySourceError, match="no usable"):
        resolve_keys(public_key=None, key_url=url)


def test_rejects_non_http_key_url():
    with pytest.raises(KeySourceError, match="http"):
        resolve_keys(public_key=None, key_url="ftp://example.com/keys.json")


def test_rejects_unreachable_key_url():
    with pytest.raises(KeySourceError, match="could not fetch"):
        resolve_keys(public_key=None, key_url="http://127.0.0.1:1/keys.json")

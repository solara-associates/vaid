from __future__ import annotations

import base64
import json
import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mcp import keys as keys_module
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


# ── key_url hardening ──────────────────────────────────────────────────────
#
# Every refusal below is decided by `_validate_fetch_target` BEFORE any
# request is made, so none of these need a real server or network access —
# that is the property under test as much as the refusal itself: an SSRF
# guard that only fires after the request already went out has already lost.


def _mock_public_dns(monkeypatch, host: str = "keys.example") -> None:
    """`_open_url`-mocking tests use a hostname that is never real (RFC 2606
    `.example`), so DNS resolution — which `_validate_fetch_target` always
    runs first, before `_open_url` is ever reached — needs a stand-in too.
    Resolves to a fixed public-looking address so these tests exercise the
    redirect/size/status logic without touching the network at any point."""

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(requested_host, port, *args, **kwargs):
        if requested_host == host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        # An IP-literal redirect target (e.g. 169.254.169.254) needs no DNS at
        # all; let the real resolver handle it rather than special-casing it.
        return real_getaddrinfo(requested_host, port, *args, **kwargs)

    monkeypatch.setattr(keys_module.socket, "getaddrinfo", fake_getaddrinfo)


def _jwk_doc(raw: bytes) -> dict:
    thumbprint = kernel_key_thumbprint(raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"keys": {thumbprint: {"kty": "OKP", "crv": "Ed25519", "x": x}}}


class _FakeResponse:
    """Stands in for `http.client.HTTPResponse` — a context manager with
    `.status`, `.headers` (dict-like, `.get`) and `.read(n)`."""

    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_rejects_http_key_url_scheme():
    with pytest.raises(KeySourceError, match="https"):
        resolve_keys(public_key=None, key_url="http://example.com/keys.json")


def test_rejects_non_http_scheme():
    with pytest.raises(KeySourceError, match="https"):
        resolve_keys(public_key=None, key_url="ftp://example.com/keys.json")


def test_rejects_loopback_address():
    with pytest.raises(KeySourceError, match="loopback|private"):
        resolve_keys(public_key=None, key_url="https://127.0.0.1/keys.json")


def test_rejects_ipv6_loopback_address():
    with pytest.raises(KeySourceError, match="loopback|private"):
        resolve_keys(public_key=None, key_url="https://[::1]/keys.json")


def test_rejects_private_rfc1918_address():
    with pytest.raises(KeySourceError, match="loopback|private"):
        resolve_keys(public_key=None, key_url="https://10.1.2.3/keys.json")


def test_rejects_link_local_metadata_address():
    """169.254.169.254 is the cloud-provider instance-metadata address — the
    classic SSRF target for exfiltrating credentials. It falls under
    link-local (169.254.0.0/16), so no special case is needed to catch it,
    but it is named explicitly here so the coverage is not an accident."""
    with pytest.raises(KeySourceError, match="link-local"):
        resolve_keys(public_key=None, key_url="https://169.254.169.254/keys.json")


def test_rejects_multicast_address():
    with pytest.raises(KeySourceError, match="multicast"):
        resolve_keys(public_key=None, key_url="https://224.0.0.1/keys.json")


def test_rejects_unresolvable_host():
    with pytest.raises(KeySourceError, match="could not resolve"):
        resolve_keys(public_key=None, key_url="https://this-host-does-not-resolve.invalid/keys.json")


def test_rejects_hostname_resolving_to_a_private_address(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "internal.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

    monkeypatch.setattr(keys_module.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(KeySourceError, match="private"):
        resolve_keys(public_key=None, key_url="https://internal.example/keys.json")


def test_rejects_no_host_in_url():
    with pytest.raises(KeySourceError, match="no host"):
        resolve_keys(public_key=None, key_url="https:///keys.json")


def test_resolve_from_key_url_over_https(monkeypatch):
    _mock_public_dns(monkeypatch)
    raw = _pub()
    body = json.dumps(_jwk_doc(raw)).encode("utf-8")

    def fake_open(url):
        assert url == "https://keys.example/vaid-keys.json"
        return _FakeResponse(200, body)

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    resolved = resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")
    assert resolved.source == "https://keys.example/vaid-keys.json"
    assert resolved.resolver.resolve_key(kernel_key_thumbprint(raw)) == raw


def test_rejects_key_url_with_mismatched_thumbprint(monkeypatch):
    _mock_public_dns(monkeypatch)
    raw = _pub()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    body = json.dumps(
        {"keys": {"urn:ietf:params:oauth:jwk-thumbprint:sha-256:wrong": {"kty": "OKP", "crv": "Ed25519", "x": x}}}
    ).encode("utf-8")
    monkeypatch.setattr(keys_module, "_open_url", lambda url: _FakeResponse(200, body))
    with pytest.raises(KeySourceError, match="does not match"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_rejects_key_url_with_no_keys_map(monkeypatch):
    _mock_public_dns(monkeypatch)
    monkeypatch.setattr(keys_module, "_open_url", lambda url: _FakeResponse(200, b"{}"))
    with pytest.raises(KeySourceError, match="no usable"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_rejects_non_json_body(monkeypatch):
    _mock_public_dns(monkeypatch)
    monkeypatch.setattr(keys_module, "_open_url", lambda url: _FakeResponse(200, b"not json"))
    with pytest.raises(KeySourceError, match="valid JSON"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_rejects_non_200_status(monkeypatch):
    _mock_public_dns(monkeypatch)
    monkeypatch.setattr(keys_module, "_open_url", lambda url: _FakeResponse(404, b""))
    with pytest.raises(KeySourceError, match="404"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_rejects_response_over_size_cap(monkeypatch):
    _mock_public_dns(monkeypatch)
    oversized = b"x" * (keys_module.MAX_KEY_RESPONSE_BYTES + 1)
    monkeypatch.setattr(keys_module, "_open_url", lambda url: _FakeResponse(200, oversized))
    with pytest.raises(KeySourceError, match="byte cap"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_rejects_unreachable_connection(monkeypatch):
    _mock_public_dns(monkeypatch)
    import urllib.error

    def fail(url):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(keys_module, "_open_url", fail)
    with pytest.raises(KeySourceError, match="could not fetch"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")


def test_follows_a_same_scheme_redirect_and_revalidates_each_hop(monkeypatch):
    _mock_public_dns(monkeypatch)
    raw = _pub()
    body = json.dumps(_jwk_doc(raw)).encode("utf-8")
    calls = []

    def fake_open(url):
        calls.append(url)
        if url == "https://keys.example/old-location.json":
            return _FakeResponse(302, b"", headers={"Location": "https://keys.example/new-location.json"})
        assert url == "https://keys.example/new-location.json"
        return _FakeResponse(200, body)

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    resolved = resolve_keys(public_key=None, key_url="https://keys.example/old-location.json")
    assert calls == [
        "https://keys.example/old-location.json",
        "https://keys.example/new-location.json",
    ]
    assert resolved.resolver.resolve_key(kernel_key_thumbprint(raw)) == raw


def test_refuses_a_redirect_into_a_private_address(monkeypatch):
    _mock_public_dns(monkeypatch)
    def fake_open(url):
        assert url == "https://keys.example/redirect.json"
        return _FakeResponse(302, b"", headers={"Location": "https://169.254.169.254/steal"})

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    with pytest.raises(KeySourceError, match="link-local"):
        resolve_keys(public_key=None, key_url="https://keys.example/redirect.json")


def test_refuses_a_redirect_to_a_non_https_scheme(monkeypatch):
    _mock_public_dns(monkeypatch)
    def fake_open(url):
        return _FakeResponse(302, b"", headers={"Location": "http://keys.example/downgrade.json"})

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    with pytest.raises(KeySourceError, match="https"):
        resolve_keys(public_key=None, key_url="https://keys.example/redirect.json")


def test_refuses_too_many_redirects(monkeypatch):
    _mock_public_dns(monkeypatch)
    def fake_open(url):
        return _FakeResponse(302, b"", headers={"Location": "https://keys.example/next.json"})

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    with pytest.raises(KeySourceError, match="redirect"):
        resolve_keys(public_key=None, key_url="https://keys.example/first.json")


def test_refuses_a_redirect_with_no_location_header(monkeypatch):
    _mock_public_dns(monkeypatch)
    def fake_open(url):
        return _FakeResponse(302, b"", headers={})

    monkeypatch.setattr(keys_module, "_open_url", fake_open)
    with pytest.raises(KeySourceError, match="Location"):
        resolve_keys(public_key=None, key_url="https://keys.example/redirect.json")


def test_fetch_uses_the_configured_timeout(monkeypatch):
    _mock_public_dns(monkeypatch)
    captured = {}

    class _CapturingOpener:
        def open(self, request, timeout):
            captured["timeout"] = timeout
            return _FakeResponse(200, b"{}")

    monkeypatch.setattr(keys_module, "_opener", _CapturingOpener())
    with pytest.raises(KeySourceError, match="no usable"):
        resolve_keys(public_key=None, key_url="https://keys.example/vaid-keys.json")
    assert captured["timeout"] == keys_module.KEY_FETCH_TIMEOUT_SECS

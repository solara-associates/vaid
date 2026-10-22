"""Resolving the trust key(s) a tool call verifies against.

A VAID's own `kernel_key_thumbprint` field anchors nothing by itself — see
`docs/trust-anchor.md` in this repo. A caller must supply the key through a
channel it trusts: either the raw public key bytes directly, or a URL it
points at (its own copy of a `.well-known/vaid-keys.json`-shaped document,
the same keyed-by-RFC-9278-thumbprint format `docs/kernel-keys.json` in this
repo uses). This module never chooses a key on its own and never calls
anywhere the caller did not name.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from vaid_mint.chain import KernelKeyMap, KernelKeyResolver, SingleKernelKey
from vaid_mint.issuer_identity import kernel_key_thumbprint

#: Fetching a caller-supplied URL is the one network call this package makes.
#: Bounded so a slow or hanging key host cannot stall a tool call indefinitely.
KEY_FETCH_TIMEOUT_SECS = 10

#: A key file is small by nature (a handful of JWKs); capped well above any
#: legitimate size so a hostile or misconfigured host cannot make this tool
#: buffer an unbounded response into memory.
MAX_KEY_RESPONSE_BYTES = 1 * 1024 * 1024

#: Hops followed before giving up — bounded so a redirect loop, or a chain of
#: redirects each individually revalidated, cannot be used to stall a call.
MAX_REDIRECTS = 5

#: Only https:// is accepted. An http:// key file is interceptable and
#: modifiable in transit by anyone on the path — see docs/trust-anchor.md's
#: point that the hash, not the transport, is what makes a fetch safe; https
#: is still required here because this tool has no hash to compare against
#: in advance, unlike that document's vendor-and-pin flow.
ALLOWED_SCHEME = "https"


def _is_blocked_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Refuses loopback, private, link-local (which covers the
    169.254.169.254 cloud metadata address), multicast, reserved and
    unspecified addresses. A caller-supplied key_url has no business
    resolving anywhere but a public host."""
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_fetch_target(url: str) -> None:
    """Scheme and DNS-resolved-address checks, run before every request this
    module makes — including on each redirect hop, so a same-scheme redirect
    to a blocked address is caught rather than followed."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != ALLOWED_SCHEME:
        raise KeySourceError(
            f"key_url must be {ALLOWED_SCHEME}:// (got scheme {parsed.scheme!r} for {url!r})"
        )
    host = parsed.hostname
    if not host:
        raise KeySourceError(f"key_url {url!r} has no host")
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise KeySourceError(f"could not resolve key_url host {host!r}: {exc}") from exc
    for addr in resolved:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
        if _is_blocked_address(ip):
            raise KeySourceError(
                f"key_url host {host!r} resolves to {ip}, a loopback, private, "
                "link-local, multicast or reserved address — refusing to fetch a "
                "key from a non-public target"
            )


class KeySourceError(ValueError):
    """The supplied public key or key URL could not be turned into a trust set."""


@dataclass(frozen=True)
class ResolvedKeys:
    """The trust set a chain or VAID was checked against, for display back to
    the caller — never for a second, implicit trust decision downstream."""

    resolver: KernelKeyResolver
    thumbprints: tuple[str, ...]
    source: str


def _decode_public_key(value: str) -> bytes:
    """A raw 32-byte Ed25519 public key, as base64url (unpadded) or hex."""
    text = value.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    padded = text + "=" * (-len(text) % 4)
    try:
        key = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise KeySourceError(
            f"public_key is neither 64 hex characters nor base64url: {exc}"
        ) from exc
    if len(key) != 32:
        raise KeySourceError(
            f"decoded public_key is {len(key)} bytes, expected 32 (raw Ed25519)"
        )
    return key


def _jwk_to_raw(jwk: dict) -> bytes:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise KeySourceError(f"unsupported JWK kty/crv: {jwk.get('kty')}/{jwk.get('crv')}")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise KeySourceError("JWK entry has no 'x' coordinate")
    padded = x + "=" * (-len(x) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise KeySourceError(f"JWK 'x' decodes to {len(raw)} bytes, expected 32")
    return raw


class _NoRedirectErrorProcessor(urllib.request.HTTPErrorProcessor):
    """Hands a 3xx response back to the caller instead of urllib following it
    automatically. Redirects are followed by `_fetch_key_url` itself, one hop
    at a time, so every hop's target is validated before it is requested —
    `urllib`'s own redirect handling validates nothing and follows before the
    caller ever sees the new URL."""

    def http_response(self, request, response):
        return response

    https_response = http_response


_opener = urllib.request.build_opener(_NoRedirectErrorProcessor())


def _open_url(url: str):
    """The one point this module calls out to the network. Isolated to a
    single function so tests can replace it with a fake response instead of
    needing a real server — every refusal this module makes is decided
    before this is ever called, so none of those tests need network access
    either."""
    request = urllib.request.Request(url, headers={"User-Agent": "vaid-mcp key fetch"})
    return _opener.open(request, timeout=KEY_FETCH_TIMEOUT_SECS)


def _fetch_key_url(url: str) -> dict:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_fetch_target(current)
        try:
            response = _open_url(current)
        except urllib.error.URLError as exc:
            raise KeySourceError(f"could not fetch key_url {current!r}: {exc}") from exc
        with response:
            status = getattr(response, "status", None) or response.getcode()
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise KeySourceError(
                        f"key_url {current!r} redirected ({status}) with no Location header"
                    )
                current = urllib.parse.urljoin(current, location)
                continue
            if status != 200:
                raise KeySourceError(f"key_url {current!r} returned HTTP {status}")
            body = response.read(MAX_KEY_RESPONSE_BYTES + 1)
        if len(body) > MAX_KEY_RESPONSE_BYTES:
            raise KeySourceError(
                f"key_url {current!r} response exceeds the {MAX_KEY_RESPONSE_BYTES}-byte cap"
            )
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise KeySourceError(f"key_url {current!r} did not return valid JSON: {exc}") from exc
    raise KeySourceError(f"key_url {url!r} did not resolve within {MAX_REDIRECTS} redirects")


def resolve_keys(*, public_key: str | None, key_url: str | None) -> ResolvedKeys:
    """Build a `KernelKeyResolver` from exactly one of a raw public key or a
    key URL. Fails closed — an ambiguous or empty request is a `KeySourceError`,
    never a resolver that happens to accept nothing."""
    if bool(public_key) == bool(key_url):
        raise KeySourceError(
            "supply exactly one of public_key or key_url, not both and not neither"
        )
    if public_key:
        raw = _decode_public_key(public_key)
        return ResolvedKeys(
            resolver=SingleKernelKey(raw),
            thumbprints=(kernel_key_thumbprint(raw),),
            source="public_key",
        )

    doc = _fetch_key_url(key_url)
    keys = doc.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise KeySourceError(
            f"key_url {key_url!r} returned no usable 'keys' map "
            "(expected the vaid-keys.json shape: {\"keys\": {\"<thumbprint>\": {JWK...}}})"
        )
    raw_keys: list[bytes] = []
    for claimed_thumbprint, jwk in keys.items():
        raw = _jwk_to_raw(jwk)
        actual = kernel_key_thumbprint(raw)
        if actual != claimed_thumbprint:
            raise KeySourceError(
                f"key_url {key_url!r} entry {claimed_thumbprint!r} does not match its "
                f"own key material (recomputed thumbprint is {actual!r}) — refusing a "
                "key file that cannot authenticate its own table"
            )
        raw_keys.append(raw)
    key_map = KernelKeyMap(raw_keys)
    return ResolvedKeys(resolver=key_map, thumbprints=tuple(keys.keys()), source=key_url)

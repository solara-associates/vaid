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
import json
import urllib.request
from dataclasses import dataclass

from vaid_mint.chain import KernelKeyMap, KernelKeyResolver, SingleKernelKey
from vaid_mint.issuer_identity import kernel_key_thumbprint

#: Fetching a caller-supplied URL is the one network call this package makes.
#: Bounded so a slow or hanging key host cannot stall a tool call indefinitely.
KEY_FETCH_TIMEOUT_SECS = 10


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


def _fetch_key_url(url: str) -> dict:
    if not (url.startswith("https://") or url.startswith("http://")):
        raise KeySourceError("key_url must be an http(s) URL")
    try:
        with urllib.request.urlopen(url, timeout=KEY_FETCH_TIMEOUT_SECS) as resp:
            body = resp.read()
    except Exception as exc:
        raise KeySourceError(f"could not fetch key_url {url!r}: {exc}") from exc
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise KeySourceError(f"key_url {url!r} did not return valid JSON: {exc}") from exc


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

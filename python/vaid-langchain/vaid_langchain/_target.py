"""The pinned request-target convention for VAID request signing.

Investigation 3 flagged the one silent-failure landmine: the ``path`` a client
signs must be the exact string a verifier reconstructs, and whether the query
string is included is a convention that MUST be pinned — a mismatch rejects every
signature (or, worse, leaves query params unsigned and tamperable).

PINNED CONVENTION (permanent, a SECURITY decision — not a demo convenience): the
signed ``path`` is the **on-the-wire request target** — the percent-encoded path
plus ``?query`` when present — i.e. exactly what appears after the method on the
HTTP request line. For an ``httpx`` request this is ``request.url.raw_path``
(ASCII bytes), NOT ``request.url.path``.

Signing path-only would leave the query string **outside** the signature, so an
attacker could alter query parameters (``?tenant=…``, ``?limit=…``, ids, filters)
under a still-valid signature. Because the query frequently carries
authorization-relevant material, it MUST be part of the signed target. This is
why ``raw_path`` (path + query) is the permanent convention.

Why ``raw_path`` and not ``path``:
  * ``.path`` DROPS the query string, leaving query params outside the signature
    (an attacker can alter ``?tenant=…`` under a valid signature) — unacceptable.
  * ``.path`` is percent-DECODED ("/a b/x"), so two distinct wire targets can map
    to the same string — ambiguous.
  * ``.raw_path`` is the percent-encoded path + query, deterministic and equal to
    what a server reads from the request line — so a verifier reconstructs the
    identical string.

The Rust canonical signer binds ``path`` verbatim (no normalization), so this
string is signed exactly as produced; the frozen operator vector's "/vaid/mint"
(no query) is the query-absent case of this same rule.
"""

from __future__ import annotations

from typing import Any


def request_target(request: Any) -> str:
    """The pinned signed-path string for an ``httpx.Request``: percent-encoded
    path + query (the on-the-wire request target). ``raw_path`` is ASCII bytes;
    decode to the ``str`` the signer/verifier bind."""
    return request.url.raw_path.decode("ascii")

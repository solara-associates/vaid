"""The minimal HTTP service: an RFC 8693 token-exchange endpoint and the JWKS
endpoint the issued tokens verify against (docs/jwt/v1/profile.md SS6, SS8).

Built on Starlette: a bare ASGI toolkit with no templating, ORM, or
form-validation layer bundled in, which matches this package's own
dependency posture (``vaid_jwt_bridge.exchange`` itself has no web-framework
dependency at all) better than a batteries-included framework would — there
is exactly one request body to parse and two responses to shape, so the
"batteries" buy nothing here. It is optional (the ``service`` extra): a
caller embedding :func:`vaid_jwt_bridge.exchange.exchange` in their own
service pulls in none of this.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from vaid_mint.chain import KernelKeyResolver
from vaid_mint.revocation import RevocationCheck

from vaid_jwt_bridge.exchange import (
    ISSUED_TOKEN_TYPE_JWT,
    SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1,
    DEFAULT_TTL_SECONDS,
    Denied,
    ExchangeRequest,
    Issued,
    exchange,
)
from vaid_jwt_bridge.keys import KeyRing

#: RFC 8693 SS2.1.
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


@dataclass(frozen=True)
class BridgeConfig:
    """Everything one running bridge deployment needs: its own issuer
    identifier, the trust anchor for VAID chains it will verify, the
    (required — profile SS1) revocation backend, and the keys it signs
    issued JWTs with."""

    issuer: str
    keys: KernelKeyResolver
    revocation: RevocationCheck
    keyring: KeyRing
    default_ttl_seconds: int = DEFAULT_TTL_SECONDS


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """RFC 6749 SS5.2-shaped error body. Used for both a malformed request and
    a denied exchange — a denial is `invalid_grant` either way (RFC 8693
    defines no richer error vocabulary for a failed exchange), with the
    specific :class:`~vaid_jwt_bridge.exchange.DenialReason` in
    ``error_description`` for whoever is logging or auditing it."""
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
    )


def _parse_subject_token(raw: str) -> tuple[dict | None, tuple[dict, ...]]:
    """Profile SS6 wire encoding: ``subject_token`` is a JSON object
    ``{"leaf": <VAID>, "chain": [<VAID>, ...]}``. Returns ``(None, ())`` for
    anything that does not parse as that shape — the caller turns that into
    a denial, never an exception."""
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ()
    if not isinstance(parsed, dict):
        return None, ()
    leaf = parsed.get("leaf")
    if not isinstance(leaf, dict):
        return None, ()
    chain = parsed.get("chain", [])
    if not isinstance(chain, list) or not all(isinstance(d, dict) for d in chain):
        return None, ()
    return leaf, tuple(chain)


def build_app(config: BridgeConfig) -> Starlette:
    """Build the ASGI app: ``POST /token-exchange`` and
    ``GET /.well-known/jwks.json``."""

    async def token_exchange(request: Request) -> JSONResponse:
        body = (await request.body()).decode("utf-8")
        form = dict(parse_qsl(body, keep_blank_values=True))

        if form.get("grant_type") != GRANT_TYPE_TOKEN_EXCHANGE:
            return _oauth_error(
                "unsupported_grant_type",
                f"grant_type must be {GRANT_TYPE_TOKEN_EXCHANGE!r}",
            )
        if form.get("subject_token_type") != SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1:
            return _oauth_error(
                "invalid_request",
                f"subject_token_type must be {SUBJECT_TOKEN_TYPE_VAID_CHAIN_V1!r}",
            )
        subject_token = form.get("subject_token")
        if subject_token is None:
            return _oauth_error("invalid_request", "subject_token is required")

        leaf, chain = _parse_subject_token(subject_token)
        if leaf is None:
            return _oauth_error(
                "invalid_request",
                'subject_token must be {"leaf": <VAID>, "chain": [<VAID>, ...]}',
            )

        exchange_request = ExchangeRequest(
            leaf=leaf,
            chain=chain,
            audience=form.get("audience"),
            requested_token_type=form.get("requested_token_type"),
        )
        result = exchange(
            exchange_request,
            keys=config.keys,
            revocation=config.revocation,
            issuer=config.issuer,
            signer=config.keyring.active,
            default_ttl_seconds=config.default_ttl_seconds,
        )

        if isinstance(result, Denied):
            return _oauth_error("invalid_grant", f"{result.reason.value}: {result.detail}")
        assert isinstance(result, Issued)
        return JSONResponse(
            {
                "access_token": result.access_token,
                "issued_token_type": result.issued_token_type,
                "token_type": result.token_type,
                "expires_in": result.expires_in,
            }
        )

    async def jwks(request: Request) -> JSONResponse:
        return JSONResponse(config.keyring.jwks())

    return Starlette(
        routes=[
            Route("/token-exchange", token_exchange, methods=["POST"]),
            Route("/.well-known/jwks.json", jwks, methods=["GET"]),
        ]
    )

"""``VaidAuth`` — the shared httpx auth that signs any outbound request with a VAID.

Agent frameworks (LangChain, CrewAI, ADK) hook at the *tool-call* layer, which is
function-call-shaped (a name + kwargs). VAID proof-of-possession signs an *HTTP
request* — it binds ``(method, request-target, body_sha256)``. So the clean,
non-forking seam is NOT the framework's tool layer but the **HTTP client** the
tool uses: an ``httpx.Auth`` subclass runs on every outbound request and attaches
the four ``x-synthera-*`` PoP headers. This one class is the whole reusable
adapter; a framework "adapter" is then just that framework's idiomatic way of
registering a tool whose client carries this auth.

Canonicalization/signing is NOT reimplemented here — it defers to
``vaid_pop.RequestSigner``, so a conforming verifier derives identical bytes.
"""

from __future__ import annotations

from typing import Any, Generator

import httpx
from vaid_pop import RequestSigner

from vaid_langchain._target import request_target


class VaidAuth(httpx.Auth):
    """Signs every outbound ``httpx`` request with a VAID proof-of-possession.

    Attach to any client: ``httpx.Client(auth=VaidAuth(signer))``. On each request
    it signs ``(method, raw_path, body)`` via ``vaid_pop.RequestSigner`` and
    attaches the four ``x-synthera-*`` headers.

    ``requires_request_body = True`` is MANDATORY: without it, ``request.content``
    is not populated inside ``auth_flow`` and the ``bodySha256`` would be computed
    over an empty body while a non-empty body is sent — every signature would then
    fail verification. Do not remove it.
    """

    # Tell httpx to read/buffer the request body before invoking auth_flow, so
    # `request.content` is available here.
    requires_request_body = True

    def __init__(self, signer: RequestSigner) -> None:
        self._signer = signer

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, Any, None]:
        # The signed target is the on-the-wire path + query (raw_path), the pinned
        # security convention — see `_target.request_target`.
        target = request_target(request)
        # Body must be bytes; a body-less request (e.g. GET) signs b"" — never
        # None (hashlib.sha256(None) raises) and never a str.
        body = request.content or b""
        headers = self._signer.sign_headers(request.method, target, body)
        request.headers.update(headers)
        yield request

"""LangChain tool wrapper — a thin registration layer over :class:`VaidAuth`.

All the signing lives in :class:`~vaid_langchain.auth.VaidAuth`; this module is
just LangChain's idiomatic way of exposing a tool whose HTTP client carries that
auth. :func:`make_vaid_tool` returns a LangChain ``StructuredTool`` an agent can
call; every request the tool makes to the protected backend is VAID-signed.

``langchain_core`` is imported lazily so this package (and :class:`VaidAuth`)
imports without LangChain installed — you only need it for this wrapper.
"""

from __future__ import annotations

from typing import Any

import httpx
from vaid_pop import RequestSigner

from vaid_langchain.auth import VaidAuth

_DEFAULT_DESCRIPTION = (
    "Call a VAID-protected HTTP API. Pass the request `path` (e.g. '/vaid/mint', "
    "including any ?query) and an optional JSON `payload`. The request is signed "
    "with the agent's VAID proof-of-possession before it is sent."
)


def make_vaid_tool(
    signer: RequestSigner,
    base_url: str,
    *,
    name: str = "call_protected_api",
    description: str = _DEFAULT_DESCRIPTION,
    method: str = "POST",
    client: httpx.Client | None = None,
) -> Any:
    """Build a LangChain ``StructuredTool`` that calls a VAID-protected API.

    Parameters
    ----------
    signer:
        A ``vaid_pop.RequestSigner`` built from the agent's minted VAID document
        and its Ed25519 private key. Provisioning that key/VAID is the caller's
        job — see the README; it is NOT managed by this SDK.
    base_url:
        Base URL of the protected backend (e.g. ``https://api.example.com``).
    name / description:
        Surface the tool presents to the agent/LLM.
    method:
        HTTP method the tool issues (default ``POST``).
    client:
        Optional pre-built ``httpx.Client`` (used in tests to inject a mock
        transport). When omitted, a client bound to ``base_url`` with
        ``VaidAuth(signer)`` is created.

    Returns
    -------
    A ``langchain_core.tools.StructuredTool``.
    """
    from langchain_core.tools import StructuredTool  # lazy: LangChain optional

    http = client or httpx.Client(base_url=base_url, auth=VaidAuth(signer))

    def call_protected_api(path: str, payload: dict | None = None) -> str:
        """Send a signed request to the protected API and return the response body."""
        resp = http.request(method, path, json=payload if payload is not None else {})
        resp.raise_for_status()
        return resp.text

    return StructuredTool.from_function(
        call_protected_api, name=name, description=description
    )

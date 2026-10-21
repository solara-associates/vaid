"""The vaid-mcp stdio server: four tools over vaid-mint, nothing else.

No tool here persists a key, calls any Solara-internal service, or sends
data anywhere except a `key_url` a caller explicitly supplies to
`verify_chain` or `check_scope`. Transport is stdio only, per the brief —
no streamable-HTTP app is started.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from vaid_mcp._entrypoint import public
from vaid_mcp.chains import ChainFormatError, verify_chain_result
from vaid_mcp.demo import mint_demo_chain
from vaid_mcp.explain import explain_vaid
from vaid_mcp.keys import KeySourceError, resolve_keys
from vaid_mcp.scope import check_scope

mcp = FastMCP(
    name="vaid-mcp",
    instructions=(
        "Tools for the open VAID agent-identity standard: verify a pasted "
        "delegation chain, decode a VAID into plain language, check whether a "
        "chain permits a specific action on a specific resource, and mint a "
        "throwaway demo chain to try the others with no setup. Every check runs "
        "against the published open-source vaid-mint library only; nothing is "
        "verified against or sent to any Solara-internal service."
    ),
)


def _keys_from_args(public_key: str | None, key_url: str | None):
    try:
        return resolve_keys(public_key=public_key, key_url=key_url)
    except KeySourceError as exc:
        raise ValueError(str(exc)) from exc


@mcp.tool()
@public
def verify_chain(chain: dict, public_key: str | None = None, key_url: str | None = None) -> dict:
    """Verify a pasted VAID delegation chain.

    `chain` is `{"leaf": {...signed VAID document...}, "ancestors": [{...}, ...]}`
    — `ancestors` may be omitted for a standalone root VAID.

    Supply exactly one trust source: `public_key` (a raw 32-byte Ed25519 key, as
    64 hex characters or unpadded base64url) or `key_url` (an https:// URL to a
    document shaped like this repo's `docs/kernel-keys.json`, i.e.
    `{"keys": {"<thumbprint>": {<JWK>}}}`). `key_url` is the only network call
    this tool makes, and only to the URL the caller gave it.

    Returns the overall verdict, a plain-English reason, and a per-hop
    authenticity breakdown.
    """
    keys = _keys_from_args(public_key, key_url)
    try:
        result = verify_chain_result(chain, keys)
    except ChainFormatError as exc:
        raise ValueError(str(exc)) from exc
    return {
        "verdict": result.verdict.value,
        "is_valid": result.verdict.is_attenuated(),
        "reason": result.plain_reason,
        "hops": [asdict(h) for h in result.hops],
        "trust_source": result.trust_source,
        "trust_thumbprints": list(result.trust_thumbprints),
    }


@mcp.tool()
@public
def explain_vaid_tool(vaid: dict) -> dict:
    """Decode a single VAID document into plain language: who it identifies,
    who delegated it (if anyone), what it claims it may do and where, and
    until when. Performs NO verification — it describes what the document
    claims, which could be entirely fabricated. Use `verify_chain` to find
    out whether a chain is genuine."""
    explanation = explain_vaid(vaid)
    return asdict(explanation)


@mcp.tool()
@public
def check_scope_tool(
    chain: dict,
    requested_action: str,
    resource: str,
    public_key: str | None = None,
    key_url: str | None = None,
) -> dict:
    """Does this chain's leaf credential permit `requested_action` on
    `resource`? First verifies the whole chain (same trust-source rules as
    `verify_chain`); if the chain itself does not verify, this refuses to say
    permitted or denied and explains why instead — an unverifiable chain is
    never treated as permissive."""
    keys = _keys_from_args(public_key, key_url)
    try:
        result = check_scope(chain, keys, requested_action, resource)
    except ChainFormatError as exc:
        raise ValueError(str(exc)) from exc
    return {
        "answerable": result.answerable,
        "permitted": result.permitted,
        "reason": result.reason,
        "chain_verdict": result.chain_result.verdict.value,
    }


@mcp.tool()
@public
def mint_demo_chain_tool(resource: str = "demo.sandbox", capability: str = "read") -> dict:
    """Mint a throwaway two-hop demo VAID chain (a root plus one attenuated
    child) with a fresh, in-memory, never-persisted key, so you can try
    verify_chain, explain_vaid and check_scope immediately with no setup.
    Clearly labelled demo-only; discard it after this call."""
    demo = mint_demo_chain(resource=resource, capability=capability)
    return {
        "label": demo.label,
        "chain": {"leaf": demo.child, "ancestors": [demo.root]},
        "public_key_hex": demo.kernel_public_key_hex,
        "public_key_base64url": demo.kernel_public_key_b64url,
        "kernel_key_thumbprint": demo.kernel_key_thumbprint,
        "try_next": (
            "Pass this chain and public_key_hex straight into verify_chain or "
            "check_scope_tool to see them work."
        ),
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

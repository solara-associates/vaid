"""vaid-adk — VAID verification for Google ADK agent delegation and tool calls.

Google's Agent Development Kit (ADK) has no built-in mechanism to verify an
agent's identity before it runs, before it is delegated to as a sub-agent, or
before it calls a tool (google/adk-python#4992, #6551). This package closes
that gap for an agent already carrying a VAID (https://github.com/solara-
associates/vaid): a ``BasePlugin`` that verifies the presented VAID's
signature, expiry, delegation-chain attenuation and revocation status, and
maps its ``scope_boundary``/``capability_set`` onto the specific tool being
called, denying fail-closed whenever any of that cannot be positively
checked.

It mints nothing — minting an attenuated child VAID for a sub-agent is the
caller's job via ``vaid_mint.mint.MintService.mint_child``, exactly as the
existing forge-agents/synthera ADK adapters already do. This package only
verifies and authorizes what has already been minted, using the same
``vaid_mint`` primitives ``vaid-langchain`` and the VAID A2A extension build
on.

Usage::

    from vaid_adk import (
        ToolAuthorization,
        TrustedIssuers,
        VaidAuthPlugin,
        VaidPresentation,
    )
    from vaid_mint.revocation import InMemoryRevocationList

    plugin = VaidAuthPlugin(
        # Each kernel key is bound to the ONE trust domain it is trusted for;
        # a document claiming any other domain is refused even though its
        # signature verifies (GHSA-hfjh-v2x2-r58v).
        keys=TrustedIssuers.from_raw_keys([("vaid.example", issuer_kernel_public_key)]),
        revocation=my_revocation_check,  # see the README's production note
        tool_authorizations={"lookup_order": ToolAuthorization(capability="read")},
    )
    plugin.register("sub_agent", VaidPresentation(leaf=child_vaid, chain=(parent_vaid,)))
    # runner = Runner(..., plugins=[plugin])
"""

from vaid_mint.revocation import InMemoryRevocationList, RevocationCheck, RevocationStatus

from ._verify import (
    TrustedIssuers,
    TrustedIssuersConfigError,
    VaidPresentation,
    VerifyCode,
    VerifyResult,
    require_domain_binding,
    verify_presentation,
)
from .plugin import ToolAuthorization, VaidAuthPlugin

__all__ = [
    "InMemoryRevocationList",
    "RevocationCheck",
    "RevocationStatus",
    "ToolAuthorization",
    "TrustedIssuers",
    "TrustedIssuersConfigError",
    "VaidAuthPlugin",
    "VaidPresentation",
    "VerifyCode",
    "VerifyResult",
    "require_domain_binding",
    "verify_presentation",
]

__version__ = "0.1.0"

"""Mint a throwaway demo chain so a developer can try the other three tools
with zero setup.

Everything here is ephemeral and marked as such. The kernel key is generated
fresh in memory for this one call and never written anywhere; the mint uses
`NoopAudit` (no durable record); nothing is persisted, cached, or reused
between calls. This is a toy to explore the shape of a VAID chain, never a
credential meant to outlive the response it is returned in.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_mint.audit import NoopAudit
from vaid_mint.document import prefix_entry
from vaid_mint.issuer import ReferenceIssuer
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.mint import MintService
from vaid_mint.mint_types import MintPop, VaidSeed, build_mint_pop_payload

#: Short-lived on purpose — long enough to experiment with in one sitting,
#: short enough that nobody mistakes the output for a real credential.
DEMO_TTL_HOURS = 1
DEMO_TRUST_DOMAIN = "vaid-mcp-demo.example"


@dataclass(frozen=True)
class DemoChain:
    root: dict
    child: dict
    kernel_public_key_b64url: str
    kernel_public_key_hex: str
    kernel_key_thumbprint: str
    label: str


def mint_demo_chain(resource: str = "demo.sandbox", capability: str = "read") -> DemoChain:
    """Mint a two-hop demo chain: an ephemeral root, and a child attenuated to
    exactly `(resource, capability)`. Both documents are genuinely signed —
    they will pass `verify_chain` against the returned public key — but the
    key behind them exists only for the duration of this call."""
    issuer = ReferenceIssuer.ephemeral(DEMO_TTL_HOURS, DEMO_TRUST_DOMAIN).assuming_nothing_revoked()
    mint = MintService(issuer, NoopAudit())

    root = mint.mint_root(
        VaidSeed(
            agent_class="demo-orchestrator",
            version="0.0.0-demo",
            tenant_id="demo-tenant",
            scope_boundary=[prefix_entry(resource)],
            capability_set=[capability, "delegate"],
        )
    )
    holder_key = Ed25519PrivateKey.generate()
    holder_public = holder_key.public_key().public_bytes_raw()
    child_seed = VaidSeed(
        agent_class="demo-worker",
        version="0.0.0-demo",
        tenant_id="demo-tenant",
        parent_vaid=root["vaid_id"],
        scope_boundary=[prefix_entry(resource)],
        capability_set=[capability],
        public_key_der=holder_public,
    )
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    issued_at = utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(
        child_seed, public_key_der=holder_public, nonce=nonce, issued_at=issued_at
    )
    digest = canonical_request_signing_bytes(payload)
    pop = MintPop(nonce=nonce, issued_at=issued_at, signature=holder_key.sign(digest))
    child_response = mint.mint_child(child_seed, parent=root, pop=pop)

    public_key = issuer.kernel_public_key()
    return DemoChain(
        root=root,
        child=child_response.vaid,
        kernel_public_key_b64url=base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii"),
        kernel_public_key_hex=public_key.hex(),
        kernel_key_thumbprint=kernel_key_thumbprint(public_key),
        label=(
            "DEMO ONLY — minted fresh for this call with a throwaway key that "
            "exists nowhere else and is discarded the moment this response is "
            "sent. Do not treat this chain or key as a real credential."
        ),
    )

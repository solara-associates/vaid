from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_mint.audit import NoopAudit
from vaid_mint.document import prefix_entry
from vaid_mint.issuer import ReferenceIssuer
from vaid_mint.mint import MintService
from vaid_mint.mint_types import MintPop, VaidSeed, build_mint_pop_payload

from vaid_mcp.keys import resolve_keys


def _pop_for(seed: VaidSeed, holder_key: Ed25519PrivateKey) -> MintPop:
    holder_public = holder_key.public_key().public_bytes_raw()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    issued_at = utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(seed, public_key_der=holder_public, nonce=nonce, issued_at=issued_at)
    digest = canonical_request_signing_bytes(payload)
    return MintPop(nonce=nonce, issued_at=issued_at, signature=holder_key.sign(digest))


class ChainFixture:
    """A minted root+child chain this test file can mutate before verifying,
    plus the matching trust key, for exercising vaid-mcp's tools against a
    chain this package did NOT mint through `mint_demo_chain`."""

    def __init__(self, ttl_hours: int = 1) -> None:
        self.issuer = ReferenceIssuer.ephemeral(ttl_hours, "vaid-mcp-test.example").assuming_nothing_revoked()
        self.mint = MintService(self.issuer, NoopAudit())
        self.public_key = self.issuer.kernel_public_key()

        self.root = self.mint.mint_root(
            VaidSeed(
                agent_class="orchestrator",
                version="1.0.0",
                tenant_id="acme",
                scope_boundary=[prefix_entry("data.acme")],
                capability_set=["read", "write", "delegate"],
            )
        )

        holder_key = Ed25519PrivateKey.generate()
        holder_public = holder_key.public_key().public_bytes_raw()
        child_seed = VaidSeed(
            agent_class="worker",
            version="1.0.0",
            tenant_id="acme",
            parent_vaid=self.root["vaid_id"],
            scope_boundary=[prefix_entry("data.acme.sub")],
            capability_set=["read"],
            public_key_der=holder_public,
        )
        pop = _pop_for(child_seed, holder_key)
        self.child = self.mint.mint_child(child_seed, parent=self.root, pop=pop).vaid

    def chain(self) -> dict:
        return {"leaf": self.child, "ancestors": [self.root]}

    def keys(self):
        return resolve_keys(public_key=self.public_key.hex(), key_url=None)


@pytest.fixture
def chain_fixture():
    return ChainFixture()

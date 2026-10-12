"""Mint a 3-hop VAID delegation chain, exchange the leaf for a JWT, and
verify that JWT independently with PyJWT against the bridge's own served
JWKS — the whole round trip this package exists for.

Run: python examples/quickstart.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint import (
    InMemoryAudit,
    MintService,
    ReferenceIssuer,
    VaidSeed,
    prefix_entry,
)
from vaid_mint.mint_types import MintPop, build_mint_pop_payload
from vaid_mint.revocation import InMemoryRevocationList
from vaid_pop import canonical_request_signing_bytes

from vaid_jwt_bridge import (
    ExchangeRequest,
    Issued,
    KeyRing,
    TrustedIssuers,
    exchange,
)

# RFC 2606 reserved domain. Named once because the issuer stamps it into every
# document it mints and the trust anchor binds the kernel key to it; if those
# two disagree, every exchange is refused ISSUER_MISMATCH.
TRUST_DOMAIN = "vaid.example"
from vaid_jwt_bridge.keys import JwcryptoSigner
from jwcrypto.jwk import JWK


def mint_child_byo(mint: MintService, parent: dict, *, agent_class: str, scope, caps) -> dict:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    seed = VaidSeed(
        public_key_der=public,
        parent_vaid=parent["vaid_id"],
        agent_class=agent_class,
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry(v) for v in scope],
        capability_set=caps,
    )
    nonce = f"nonce-{agent_class}"
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = build_mint_pop_payload(seed, public_key_der=public, nonce=nonce, issued_at=issued_at)
    pop = MintPop(nonce=nonce, issued_at=issued_at, signature=key.sign(canonical_request_signing_bytes(payload)))
    return mint.mint_child(seed, parent, pop).vaid


def main() -> None:
    # 1. Mint a 3-hop chain: orchestrator -> report-worker -> report-reader.
    kernel_key = Ed25519PrivateKey.generate()
    issuer = ReferenceIssuer.from_seed(
        kernel_key.private_bytes_raw(), vaid_ttl_hours=1, trust_domain=TRUST_DOMAIN
    )
    mint = MintService(issuer, InMemoryAudit())

    root = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=[prefix_entry("data.acme")],
            capability_set=["read", "write"],
        )
    )
    child = mint_child_byo(
        mint, root, agent_class="report-worker", scope=["data.acme.reports"], caps=["read"]
    )
    leaf = mint_child_byo(
        mint, child, agent_class="report-reader", scope=["data.acme.reports"], caps=["read"]
    )

    # 2. Stand up the bridge's signer and trust configuration.
    bridge_key = Ed25519PrivateKey.generate()
    signer = JwcryptoSigner(JWK.from_pyca(bridge_key), alg="EdDSA")
    keyring = KeyRing([signer])
    # The bridge's trust anchor: each kernel key bound to the one trust domain
    # it is trusted for (GHSA-hfjh-v2x2-r58v).
    trusted_keys = TrustedIssuers.from_raw_keys(
        [(TRUST_DOMAIN, issuer.kernel_public_key())]
    )
    revocation = InMemoryRevocationList.assume_nothing_revoked()

    # 3. Exchange: verify the full chain, issue a JWT only on a full pass.
    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="https://reports.acme.example"),
        keys=trusted_keys,
        revocation=revocation,
        issuer="https://bridge.acme.example",
        signer=signer,
    )
    assert isinstance(result, Issued)
    print("Issued JWT:", result.access_token)
    print("expires_in:", result.expires_in)

    # 4. A gateway's-eye view: verify with PyJWT, using ONLY the served JWKS.
    jwks = keyring.jwks()
    signing_key = pyjwt.PyJWK.from_json(json.dumps(jwks["keys"][0]))
    decoded = pyjwt.decode(
        result.access_token,
        key=signing_key,
        algorithms=["EdDSA"],
        audience="https://reports.acme.example",
        issuer="https://bridge.acme.example",
    )
    print("\nVerified claims (via PyJWT against the served JWKS):")
    print(json.dumps(decoded, indent=2))


if __name__ == "__main__":
    main()

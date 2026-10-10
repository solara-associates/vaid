"""Fixed seeds, shared by the whole suite, plus a verification clock each
test controls explicitly rather than leaving to the wall clock.

"Fixed seeds": the kernel key and every per-hop BYO key are derived from
fixed 32-byte seeds, never from randomness, so key material (and therefore
`kid`/thumbprints) is identical across runs.

"Fixed clock": `vaid_mint`'s mint functions have no `now` override (they
always stamp `issued_at`/`expires_at` from the real wall clock — a
`vaid_mint` property this package does not change), so full determinism of
a minted document's timestamps is not available to a caller of this
package. What IS controllable, and what every test below controls
explicitly, is the verification instant: `exchange(..., now=...)` is always
passed an explicit `datetime`, never left to default to
`datetime.now(timezone.utc)` — so a boundary test (leaf expiry, `exp`
capping) asserts against a `now` the test chose, not whenever the suite
happened to run.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed
from vaid_mint.chain import SingleKernelKey
from vaid_mint.mint_types import MintPop, build_mint_pop_payload
from vaid_mint.revocation import InMemoryRevocationList
from vaid_pop import canonical_request_signing_bytes

#: Fixed 32-byte seeds — never derived from randomness — for the kernel key
#: and every per-hop BYO key the suite mints with.
KERNEL_SEED = b"\x01" * 32
CHILD_SEED = b"\x03" * 32
LEAF_SEED = b"\x04" * 32
OTHER_ISSUER_SEED = b"\x05" * 32  # an untrusted issuer's kernel key, for denial tests


def mint_child_byo(mint: MintService, parent: dict, *, key_seed: bytes, **seed_kwargs) -> dict:
    """Mint a BYO-key attenuated child with a fixed key seed. The PoP
    nonce/timestamp is real wall-clock: `MintService._verify_pop_at_mint`
    enforces a 300s freshness window against the actual clock
    (`vaid_mint.mint.MINT_POP_FRESHNESS_SECS`), a `vaid_mint` property this
    package does not override, so the PoP step of minting cannot be driven
    by a fixed historical timestamp without failing that window."""
    key = Ed25519PrivateKey.from_private_bytes(key_seed)
    public = key.public_key().public_bytes_raw()
    seed = VaidSeed(public_key_der=public, parent_vaid=parent["vaid_id"], **seed_kwargs)
    nonce = f"fixed-nonce-{seed_kwargs['agent_class']}"
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = build_mint_pop_payload(seed, public_key_der=public, nonce=nonce, issued_at=issued_at)
    pop = MintPop(
        nonce=nonce,
        issued_at=issued_at,
        signature=key.sign(canonical_request_signing_bytes(payload)),
    )
    return mint.mint_child(seed, parent, pop).vaid


@pytest.fixture
def kernel_key():
    return Ed25519PrivateKey.from_private_bytes(KERNEL_SEED)


@pytest.fixture
def issuer(kernel_key):
    return ReferenceIssuer.from_seed(KERNEL_SEED, vaid_ttl_hours=24, trust_domain="vaid.example")


@pytest.fixture
def mint(issuer):
    return MintService(issuer, InMemoryAudit())


@pytest.fixture
def trusted_keys(issuer):
    """The bridge's trust anchor: the one kernel key it accepts."""
    return SingleKernelKey(issuer.kernel_public_key())


@pytest.fixture
def vouching_revocation():
    return InMemoryRevocationList.assume_nothing_revoked()


@pytest.fixture
def three_hop_chain(mint):
    """root -> child -> leaf, all same tenant/trust-domain, scope/caps
    narrowing at each hop, all minted under the fixed kernel key and fixed
    per-hop key seeds. Returns (root, child, leaf)."""
    root = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=["data.acme"],
            capability_set=["read", "write"],
        )
    )
    child = mint_child_byo(
        mint,
        root,
        key_seed=CHILD_SEED,
        agent_class="worker",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=["data.acme.reports"],
        capability_set=["read"],
    )
    leaf = mint_child_byo(
        mint,
        child,
        key_seed=LEAF_SEED,
        agent_class="leafagent",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=["data.acme.reports"],
        capability_set=["read"],
    )
    return root, child, leaf


#: Fixed signing-key seeds for the BRIDGE's own JWT-signing keys — distinct
#: from the VAID kernel/holder seeds above, since they sign a different
#: artifact for a different audience (the issued JWT, not a VAID document).
BRIDGE_EDDSA_SEED = b"\x10" * 32
BRIDGE_ES256_SEED = 0x11 * (2**248)  # a fixed, in-range P-256 private scalar


@pytest.fixture
def eddsa_signer():
    from vaid_jwt_bridge.keys import JwcryptoSigner
    from jwcrypto.jwk import JWK

    key = Ed25519PrivateKey.from_private_bytes(BRIDGE_EDDSA_SEED)
    return JwcryptoSigner(JWK.from_pyca(key), alg="EdDSA")


@pytest.fixture
def es256_signer():
    from vaid_jwt_bridge.keys import JwcryptoSigner
    from jwcrypto.jwk import JWK
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(BRIDGE_ES256_SEED, ec.SECP256R1())
    return JwcryptoSigner(JWK.from_pyca(key), alg="ES256")


@pytest.fixture
def verification_now():
    """A single verification instant, captured once per test rather than
    read fresh inside `exchange()` — every call in a test passes this
    explicitly so the test's own assertions about `exp`/expiry agree with
    what was actually checked."""
    return datetime.now(timezone.utc)

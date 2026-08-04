"""Chain-presentation conformance gate (ADR-0003 §3). Python side.

The vendored vector ``vaid_mint/vectors/chain_v1.json`` is byte-identical to the
Rust (``crates/vaid-mint/tests/vectors/``) and TypeScript
(``typescript/vaid-mint/vectors/``) copies; CI ``cmp``s all three, so "Python
reproduces the vector" plus "the vectors are the same bytes" gives Rust == Python
== TypeScript without a fourth comparison.

Nothing here reconstructs the vector's contents in code. A test that builds its own
expectation proves only that the code agrees with itself.

This vector is **additive** (ADR-0003 §3): it does not re-freeze ``mint_v1.json``
or ``mint_pop_v1.json``, and it introduces no new signed field. What it pins that
``mint_v1`` does not is the *walk* — the assembled lineage and the verdict.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.chain import ChainVerification, PresentedBundle, verify_chain
from vaid_mint.document import canonical_vaid_signing_bytes
from vaid_mint.revocation import assemble_lineage

VECTOR = json.loads(
    files("vaid_mint").joinpath("vectors/chain_v1.json").read_text(encoding="utf-8")
)


def _signed_document(entry: dict) -> dict:
    """The vector's document is UNSIGNED, exactly as mint_v1.json's ``input`` is;
    attach its frozen signature."""
    return {
        **entry["document"],
        "kernel_signature": list(bytes.fromhex(entry["signature_hex"])),
    }


def _chain() -> list[dict]:
    return [_signed_document(e) for e in VECTOR["chain"]]


def _kernel_public_key() -> bytes:
    return bytes.fromhex(VECTOR["ed25519"]["kernel_public_key_hex"])


def test_reproduces_every_frozen_hop_digest() -> None:
    """Every hop's canonical digest, from the vector's own document."""
    for entry in VECTOR["chain"]:
        digest = canonical_vaid_signing_bytes(entry["document"])
        assert digest.hex() == entry["digest_sha256_hex"], (
            f"digest drift at hop {entry['_role']}"
        )


def test_reproduces_every_frozen_hop_signature() -> None:
    """Every hop's kernel signature, from the vector's kernel seed."""
    seed = bytes.fromhex(VECTOR["ed25519"]["kernel_private_key_seed_hex"])
    key = Ed25519PrivateKey.from_private_bytes(seed)

    assert (
        key.public_key().public_bytes_raw().hex()
        == VECTOR["ed25519"]["kernel_public_key_hex"]
    ), "the seed does not derive the vector's kernel public key"

    for entry in VECTOR["chain"]:
        signature = key.sign(canonical_vaid_signing_bytes(entry["document"]))
        assert signature.hex() == entry["signature_hex"], (
            f"signature drift at hop {entry['_role']}"
        )


def test_reproduces_the_frozen_assembled_lineage() -> None:
    """THE WALK, part 1: assembly order. Presented with the two ancestors as a
    detached bundle, the leaf's lineage assembles to exactly the frozen order —
    root first, leaf last."""
    docs = _chain()
    leaf = docs[-1]

    assert (
        assemble_lineage(leaf, PresentedBundle(docs))
        == VECTOR["expected"]["assembled_lineage"]
    ), "assembled lineage drift"


def test_reproduces_the_frozen_verification_verdict() -> None:
    """THE WALK, part 2: the verdict. This is the assertion the vector exists for —
    two implementations could agree on every digest and still disagree here."""
    docs = _chain()
    leaf = docs[-1]

    verdict = verify_chain(_kernel_public_key(), leaf, PresentedBundle(docs))

    assert verdict.value == VECTOR["expected"]["verification"], (
        "chain verification verdict drift"
    )
    assert verdict is ChainVerification.ATTENUATED


def test_reproduces_the_frozen_contract_digest() -> None:
    """The top-level contract digest is reproducible from the vector's own contents.

    Without this the field would be decoration: present so
    ``scripts/verify-vector-freeze.mjs`` can pin the vector, but never checked
    against what it claims to summarise. The per-hop digests pin each document; this
    pins the SET of documents and the verdict.
    """
    import hashlib

    import rfc8785

    expected = {k: v for k, v in VECTOR["expected"].items() if k != "_comment"}
    contract = {"chain": VECTOR["chain"], "expected": expected}
    digest = hashlib.sha256(rfc8785.dumps(contract)).hexdigest()

    assert digest == VECTOR["digest_sha256_hex"], (
        "contract digest drift — the chain or the expected outcome moved"
    )


def test_the_frozen_chain_is_three_hops_single_key_and_single_tenant() -> None:
    """The vector's own shape, so a regenerated vector that quietly lost a hop
    cannot still pass. Three hops is the smallest chain that exercises a
    *transitive* subset relation."""
    chain = VECTOR["chain"]
    assert len(chain) == 3, "the frozen chain must have three hops"

    thumbprint = VECTOR["ed25519"]["kernel_key_thumbprint"]
    tenant = chain[0]["document"]["tenant_id"]
    domain = chain[0]["document"]["trust_domain"]

    for entry in chain:
        doc = entry["document"]
        assert doc["kernel_key_thumbprint"] == thumbprint, (
            "every hop must be signed by the one kernel key"
        )
        assert doc["tenant_id"] == tenant, (
            "tenant must be constant — cross-tenant delegation is denied at mint"
        )
        assert doc["trust_domain"] == domain, (
            "trust_domain must be constant across a single-issuer chain"
        )

    assert chain[0]["document"]["parent_vaid"] is None, "hop 0 must be the root"

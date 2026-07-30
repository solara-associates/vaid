"""Packaged cross-language mint conformance check — the firewall, shipped in the wheel.

Mirror of the Rust ``tests/mint_conformance.rs``. A consumer who has only
``pip install vaid-mint`` can prove the mint they installed reproduces the frozen
cross-language VAID-document vector byte-for-byte::

    python -m vaid_mint.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-mint-conformance                # same, via the console entry point

Two vectors are bundled with the package and both are checked:

- ``vaid_mint/vectors/mint_v1.json`` — the signed VAID document.
- ``vaid_mint/vectors/mint_pop_v1.json`` — the ``MintPopPayload`` a holder signs
  to prove it controls the BYO key it registers at mint. Frozen later than the
  others: it was the one signed structure with no artifact holding the
  implementations to it (``docs/spec/encoding.md`` E.11), and it is the only
  vector carrying a JSON ``null`` (E.7).

The Rust ``mint_conformance`` / ``mint_pop_conformance`` tests assert the
identical vectors; a repo-level drift-check proves every copy is byte-identical,
so Rust output == Python output == TypeScript output == vector.

Per Decision B this proves self-consistency WITHIN this repo, NOT conformance
against the managed authority's VAID format.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import canonical_request_signing_bytes, verify_signed_payload

from vaid_mint.document import canonical_vaid_signing_bytes, compute_lineage_hash
from vaid_mint.mint_types import VaidSeed, build_mint_pop_payload


class ConformanceError(AssertionError):
    """A cross-language byte-identity divergence — a hard BLOCKER."""


def load_vector() -> dict:
    """The mint conformance vector bundled with the installed package."""
    data = files("vaid_mint").joinpath("vectors/mint_v1.json").read_text()
    return json.loads(data)


def check_document_digest(v: dict) -> None:
    """Python JCS (kernel_signature nulled) + SHA-256 over the VAID document ==
    frozen digest."""
    digest = canonical_vaid_signing_bytes(v["input"])
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError(
            f"VAID-document digest diverged from the frozen vector — BLOCKER\n"
            f"  got    = {digest.hex()}\n  vector = {v['digest_sha256_hex']}"
        )
    if len(digest) != 32:
        raise ConformanceError(f"digest is {len(digest)} bytes, expected 32")


def check_kernel_signature(v: dict) -> None:
    """From the frozen kernel seed, derive the same public key + deterministic
    signature over the document digest."""
    seed = bytes.fromhex(v["ed25519"]["kernel_private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    if pub.hex() != v["ed25519"]["kernel_public_key_hex"]:
        raise ConformanceError(
            f"kernel public key diverged — BLOCKER\n"
            f"  got    = {pub.hex()}\n  vector = {v['ed25519']['kernel_public_key_hex']}"
        )

    digest = canonical_vaid_signing_bytes(v["input"])
    sig = sk.sign(digest)
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError(
            f"kernel signature diverged — BLOCKER\n"
            f"  got    = {sig.hex()}\n  vector = {v['ed25519']['signature_hex']}"
        )
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def check_lineage_hash(v: dict) -> None:
    """The document's ``lineage_hash`` == recompute from ``parent_vaid`` +
    ``agent_id`` — proves the derivation is cross-language identical."""
    inp = v["input"]
    recomputed = compute_lineage_hash(inp["parent_vaid"], inp["agent_id"])
    if recomputed != inp["lineage_hash"]:
        raise ConformanceError(
            f"recomputed lineage_hash diverged from the document — BLOCKER\n"
            f"  got    = {recomputed}\n  vector = {inp['lineage_hash']}"
        )


def check_vaid_id_equals_agent_id(v: dict) -> None:
    """``vaid_id`` is derived from ``agent_id`` (same UUID)."""
    inp = v["input"]
    if inp["vaid_id"] != inp["agent_id"]:
        raise ConformanceError("vaid_id must equal agent_id — BLOCKER")


def load_mint_pop_vector() -> dict:
    """The mint proof-of-possession vector bundled with the installed package."""
    data = files("vaid_mint").joinpath("vectors/mint_pop_v1.json").read_text()
    return json.loads(data)


def check_mint_pop(v: dict) -> None:
    """The ``MintPopPayload`` gate (``docs/spec/encoding.md`` E.11).

    Rebuilds the payload through :func:`~vaid_mint.mint_types.build_mint_pop_payload`
    — the single constructor both holder and mint use — rather than reading
    ``input`` back, so this proves the code path that actually runs at mint emits
    these bytes, not merely that a dict round-trips.

    Also asserts the two properties this vector exists to pin: ``parentVaid`` is a
    PRESENT JSON ``null`` (E.7 — an omitted key is a different key set and a
    different digest), and the signature verifies against the key the payload
    REGISTERS, which is the whole semantic content of proof-of-possession.
    """
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    registered = sk.public_key().public_bytes_raw()

    if registered.hex() != v["ed25519"]["public_key_hex"]:
        raise ConformanceError(
            f"holder public key diverged — BLOCKER\n"
            f"  got    = {registered.hex()}\n  vector = {v['ed25519']['public_key_hex']}"
        )

    payload = build_mint_pop_payload(
        VaidSeed(
            agent_class="runner",
            version="1.0.0",
            tenant_id="aifactory",
            parent_vaid=None,
            scope_boundary=["data.aifactory"],
            capability_set=["read"],
            public_key_der=registered,
        ),
        public_key_der=registered,
        nonce="0123456789abcdef0123456789abcdef",
        issued_at="2026-06-04T12:00:00Z",
    )
    if payload != v["input"]:
        raise ConformanceError(
            f"the mint's own PoP payload constructor diverged from the frozen "
            f"vector — BLOCKER\n  got    = {payload}\n  vector = {v['input']}"
        )

    # E.7: a present null, not an omitted key.
    if "parentVaid" not in v["input"] or v["input"]["parentVaid"] is not None:
        raise ConformanceError(
            "parentVaid must be a PRESENT JSON null in this vector — encoding.md E.7"
        )
    without = {k: x for k, x in v["input"].items() if k != "parentVaid"}
    if canonical_request_signing_bytes(without).hex() == v["digest_sha256_hex"]:
        raise ConformanceError(
            "omitting parentVaid MUST change the digest — otherwise E.7 is untested"
        )

    digest = canonical_request_signing_bytes(payload)
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError(
            f"mint-PoP digest diverged from the frozen vector — BLOCKER\n"
            f"  got    = {digest.hex()}\n  vector = {v['digest_sha256_hex']}"
        )
    sig = sk.sign(digest)
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError(
            f"mint-PoP signature diverged — BLOCKER\n"
            f"  got    = {sig.hex()}\n  vector = {v['ed25519']['signature_hex']}"
        )

    # The PoP semantic: it must verify against the key it REGISTERS.
    if not verify_signed_payload(payload, bytes(payload["publicKeyDer"]),
                                 bytes.fromhex(v["ed25519"]["signature_hex"])):
        raise ConformanceError(
            "the frozen PoP must verify against the registered key — BLOCKER"
        )
    escalated = dict(payload, capabilitySet=["read", "write"])
    if verify_signed_payload(escalated, registered,
                             bytes.fromhex(v["ed25519"]["signature_hex"])):
        raise ConformanceError(
            "a captured PoP must not be replayable to mint a higher-privilege VAID"
        )


def run() -> dict:
    """Run all firewall checks against the bundled vector. Raises
    ConformanceError on any divergence; returns the vector on PASS."""
    v = load_vector()
    check_document_digest(v)
    check_kernel_signature(v)
    check_lineage_hash(v)
    check_vaid_id_equals_agent_id(v)
    pop = load_mint_pop_vector()
    check_mint_pop(pop)
    return {"document": v, "mint_pop": pop}


# --- pytest discovery ---


def test_packaged_document_digest_matches_frozen_vector() -> None:
    check_document_digest(load_vector())


def test_packaged_kernel_signature_matches_frozen_vector() -> None:
    check_kernel_signature(load_vector())


def test_packaged_lineage_hash_matches_frozen_vector() -> None:
    check_lineage_hash(load_vector())


def test_packaged_vaid_id_equals_agent_id() -> None:
    check_vaid_id_equals_agent_id(load_vector())


def test_packaged_mint_pop_matches_frozen_vector() -> None:
    check_mint_pop(load_mint_pop_vector())


def main() -> int:
    try:
        result = run()
    except ConformanceError as exc:
        print(f"CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    doc, pop = result["document"], result["mint_pop"]
    print(
        "CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == frozen vectors, "
        "byte-for-byte\n"
        f"  document digest    = {doc['digest_sha256_hex']}\n"
        f"  document signature = {doc['ed25519']['signature_hex']}\n"
        f"  mint-PoP digest    = {pop['digest_sha256_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

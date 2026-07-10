"""Packaged cross-language mint conformance check — the firewall, shipped in the wheel.

Mirror of the Rust ``tests/mint_conformance.rs``. A consumer who has only
``pip install vaid-mint`` can prove the mint they installed reproduces the frozen
cross-language VAID-document vector byte-for-byte::

    python -m vaid_mint.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-mint-conformance                # same, via the console entry point

The vector is the one bundled with the package
(``vaid_mint/vectors/mint_v1.json``). The Rust ``mint_conformance`` test asserts
the identical vector; a repo-level drift-check proves the two copies are
byte-identical, so Rust output == Python output == vector.

Per Decision B this proves self-consistency WITHIN this repo, NOT conformance
against the closed substrate's VAID format.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_mint.document import canonical_vaid_signing_bytes, compute_lineage_hash


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


def run() -> dict:
    """Run all firewall checks against the bundled vector. Raises
    ConformanceError on any divergence; returns the vector on PASS."""
    v = load_vector()
    check_document_digest(v)
    check_kernel_signature(v)
    check_lineage_hash(v)
    check_vaid_id_equals_agent_id(v)
    return v


# --- pytest discovery ---


def test_packaged_document_digest_matches_frozen_vector() -> None:
    check_document_digest(load_vector())


def test_packaged_kernel_signature_matches_frozen_vector() -> None:
    check_kernel_signature(load_vector())


def test_packaged_lineage_hash_matches_frozen_vector() -> None:
    check_lineage_hash(load_vector())


def test_packaged_vaid_id_equals_agent_id() -> None:
    check_vaid_id_equals_agent_id(load_vector())


def main() -> int:
    try:
        v = run()
    except ConformanceError as exc:
        print(f"CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    print(
        "CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == frozen vector, "
        "byte-for-byte\n"
        f"  digest    = {v['digest_sha256_hex']}\n"
        f"  signature = {v['ed25519']['signature_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

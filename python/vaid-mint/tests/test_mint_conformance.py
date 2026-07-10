"""Canonical mint conformance gate (Python side of the cross-language firewall).

The vendored vector ``vaid_mint/vectors/mint_v1.json`` is byte-identical to the
Rust copy (a CI drift-check enforces that). These tests assert the Python mint
reproduces the frozen VAID-document digest + kernel signature byte-for-byte, and
that the derived fields (``lineage_hash``, ``vaid_id == agent_id``) match. A
mismatch is a BLOCKER. The Rust ``mint_conformance`` test asserts the same vector.

Per Decision B this proves self-consistency WITHIN this repo (Rust == Python),
NOT conformance against the closed substrate's VAID format.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_mint.document import canonical_vaid_signing_bytes, compute_lineage_hash


def _vector() -> dict:
    data = files("vaid_mint").joinpath("vectors/mint_v1.json").read_text()
    return json.loads(data)


def test_document_digest_matches_frozen_vector():
    v = _vector()
    digest = canonical_vaid_signing_bytes(v["input"])
    assert digest.hex() == v["digest_sha256_hex"], (
        "Python VAID-document digest diverged from the frozen vector — BLOCKER"
    )
    assert len(digest) == 32


def test_kernel_signature_matches_frozen_vector():
    v = _vector()
    seed = bytes.fromhex(v["ed25519"]["kernel_private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    assert pub.hex() == v["ed25519"]["kernel_public_key_hex"], "kernel pubkey diverged — BLOCKER"

    digest = canonical_vaid_signing_bytes(v["input"])
    sig = sk.sign(digest)
    assert sig.hex() == v["ed25519"]["signature_hex"], "kernel signature diverged — BLOCKER"
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def test_lineage_hash_derivation_matches_frozen_vector():
    v = _vector()
    inp = v["input"]
    assert compute_lineage_hash(inp["parent_vaid"], inp["agent_id"]) == inp["lineage_hash"], (
        "recomputed lineage_hash diverged — BLOCKER"
    )


def test_vaid_id_equals_agent_id():
    v = _vector()
    assert v["input"]["vaid_id"] == v["input"]["agent_id"]

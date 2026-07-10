"""Completion-record conformance gate (Python side of the cross-language firewall).

The vendored vector ``vaid_pop/vectors/completion_v1.json`` is byte-identical to
the Rust copy (a CI drift-check enforces that). Asserts the Python signer
reproduces the frozen digest + signature for a real CompletionRecord, and — since
this is the FIRST vector with an ENUM — that every AssuranceTier serializes to
exactly the frozen string (the most likely place for silent Rust/Python drift).
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import (
    AssuranceTier,
    build_completion_record,
    canonical_request_signing_bytes,
)


def _vector() -> dict:
    data = files("vaid_pop").joinpath("vectors/completion_v1.json").read_text()
    return json.loads(data)


def _record_from_input(inp: dict) -> dict:
    # Rebuild through the package builder (not the raw vector dict) so the test
    # exercises the real construction path, then assert it equals the frozen input.
    return build_completion_record(
        vaid_id=inp["vaidId"],
        request_digest_sha256=inp["requestDigestSha256"],
        tenant_id=inp["tenantId"],
        status=inp["status"],
        result_sha256=inp["resultSha256"],
        completed_at=inp["completedAt"],
        signer_vaid_id=inp["signerVaidId"],
        assurance_tier=inp["assuranceTier"],
        record_nonce=inp["recordNonce"],
    )


def test_completion_digest_matches_frozen_vector():
    v = _vector()
    record = _record_from_input(v["input"])
    assert record == v["input"], "builder output must equal the frozen input dict"
    digest = canonical_request_signing_bytes(record)
    assert digest.hex() == v["digest_sha256_hex"], (
        "Python completion-record digest diverged from the frozen vector — BLOCKER"
    )
    assert len(digest) == 32


def test_completion_signature_matches_frozen_vector():
    v = _vector()
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    assert pub.hex() == v["ed25519"]["public_key_hex"], "public key diverged — BLOCKER"

    digest = canonical_request_signing_bytes(_record_from_input(v["input"]))
    sig = sk.sign(digest)
    assert sig.hex() == v["ed25519"]["signature_hex"], "signature diverged — BLOCKER"
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def test_assurance_tier_strings_match_frozen_vector():
    """THE ENUM DRIFT GUARD: the Python AssuranceTier values must equal the frozen
    strings, in order — the field where Rust camelCase serde and Python enum values
    must agree byte-for-byte inside the signed document."""
    v = _vector()
    frozen = v["assurance_tier_strings"]
    py_values = [
        AssuranceTier.SELF_REPORTED.value,
        AssuranceTier.COUNTER_SIGNED.value,
        AssuranceTier.THIRD_PARTY_ATTESTED.value,
    ]
    assert py_values == frozen, "AssuranceTier strings diverged from the frozen vector — BLOCKER"
    # The declared tier in `input` is the only substantiated tier.
    assert v["input"]["assuranceTier"] == AssuranceTier.SELF_REPORTED.value

"""Consent attestation conformance gate (``att_version`` 1). Python side.

The vendored vector ``vaid_mint/vectors/attestation_v1.json`` is byte-identical to
the Rust and TypeScript copies; CI ``cmp``s all three, so "Python reproduces the
vector" plus "the vectors are the same bytes" gives Rust == Python == TypeScript.

Nothing here reconstructs the vector's contents in code.

ADDITIVE: the attestation is a separate signed object, so freezing it re-freezes
nothing. ``mint_v1.json``, ``mint_pop_v1.json`` and ``chain_v1.json`` are untouched
and ``sig_version`` is unchanged.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.attestation import (
    ATTESTATION_VERSION,
    canonical_attestation_signing_bytes,
    verify_attestation_authenticity,
)

VECTOR = json.loads(
    files("vaid_mint").joinpath("vectors/attestation_v1.json").read_text(encoding="utf-8")
)


def test_reproduces_the_frozen_digest() -> None:
    """The canonical digest, from the vector's own attestation."""
    digest = canonical_attestation_signing_bytes(VECTOR["attestation"])
    assert digest.hex() == VECTOR["digest_sha256_hex"], "canonicalization drift"


def test_reproduces_the_frozen_signature() -> None:
    """The kernel signature, from the vector's seed."""
    seed = bytes.fromhex(VECTOR["ed25519"]["kernel_private_key_seed_hex"])
    key = Ed25519PrivateKey.from_private_bytes(seed)

    assert (
        key.public_key().public_bytes_raw().hex()
        == VECTOR["ed25519"]["kernel_public_key_hex"]
    ), "the seed does not derive the vector's kernel public key"

    signature = key.sign(canonical_attestation_signing_bytes(VECTOR["attestation"]))
    assert signature.hex() == VECTOR["signature_hex"], "signature drift"


def test_the_frozen_signature_verifies_as_authentic() -> None:
    """The property a third party actually exercises."""
    signed = {
        **VECTOR["attestation"],
        "signature": list(bytes.fromhex(VECTOR["signature_hex"])),
    }
    key = bytes.fromhex(VECTOR["ed25519"]["kernel_public_key_hex"])

    assert verify_attestation_authenticity(key, signed), (
        "the frozen attestation must verify under the frozen kernel key"
    )


def test_the_frozen_attestation_has_the_expected_shape() -> None:
    """So a regenerated vector that quietly changed the field set or collapsed the
    two parties cannot still pass."""
    a = VECTOR["attestation"]

    assert a["att_version"] == ATTESTATION_VERSION
    assert a["signature"] == [], "the vector's attestation is UNSIGNED"

    # Spec C.2: the top-level pair is the ATTESTING PARENT ISSUER'S, the child_*
    # pair is what is AUTHORIZED. Frozen with the two DIFFERENT, so a future change
    # that conflated them would fail here rather than pass silently.
    assert a["trust_domain"] != a["child_trust_domain"], (
        "the vector must exercise the cross-trust-domain case the object exists for"
    )

    assert isinstance(a["issued_at"], str) and isinstance(a["expires_at"], str)
    assert a["expires_at"] > a["issued_at"], "the frozen window must be satisfiable"

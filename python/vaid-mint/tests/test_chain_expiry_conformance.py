"""Expiry-containment conformance gate (vaid#79). Python side.

The vendored vector ``vaid_mint/vectors/chain_expiry_v1.json`` is byte-identical to
the Rust (``crates/vaid-mint/tests/vectors/``) and TypeScript
(``typescript/vaid-mint/vectors/``) copies; CI ``cmp``s all three, so "Python
reproduces the vector" plus "the vectors are the same bytes" gives Rust == Python
== TypeScript without a fourth comparison.

Nothing here reconstructs the vector's expectations in code. A test that builds its
own expectation proves only that the code agrees with itself — and that is precisely
how the defect this vector closes survived: ``chain_v1`` asserted ``attenuated`` over
a chain whose every document had expired, and three implementations agreed with it.
"""

from __future__ import annotations

import json
from datetime import datetime
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.attestation import AttestationBundle
from vaid_mint.chain import (
    ChainVerification,
    PresentedBundle,
    SingleKernelKey,
    verify_chain_at,
)
from vaid_mint.document import canonical_vaid_signing_bytes
from vaid_mint.mint import expiry_attenuates

VECTOR = json.loads(
    files("vaid_mint")
    .joinpath("vectors/chain_expiry_v1.json")
    .read_text(encoding="utf-8")
)


def _signed(entry: dict) -> dict:
    return {
        **entry["document"],
        "kernel_signature": list(bytes.fromhex(entry["signature_hex"])),
    }


def _kernel_public_key() -> bytes:
    return bytes.fromhex(VECTOR["ed25519"]["kernel_public_key_hex"])


def test_reproduces_every_frozen_digest_and_signature() -> None:
    """Every document in every case, from the vector's own kernel seed. Without
    this the verdicts below could be verdicts over bytes nobody checked."""
    seed = bytes.fromhex(VECTOR["ed25519"]["kernel_private_key_seed_hex"])
    key = Ed25519PrivateKey.from_private_bytes(seed)
    assert (
        key.public_key().public_bytes_raw().hex()
        == VECTOR["ed25519"]["kernel_public_key_hex"]
    ), "the seed does not derive the vector's kernel public key"

    for case in VECTOR["cases"]:
        for entry in case["chain"]:
            digest = canonical_vaid_signing_bytes(entry["document"])
            assert digest.hex() == entry["digest_sha256_hex"], (
                f"digest drift at {case['name']} / {entry['_role']}"
            )
            assert key.sign(digest).hex() == entry["signature_hex"], (
                f"signature drift at {case['name']} / {entry['_role']}"
            )


def test_every_expiry_containment_case() -> None:
    """THE MATCHER, as the mint applies it to a delegation not yet issued."""
    for case in VECTOR["expiry_containment"]:
        parent = {"expires_at": case["parent_expires_at"]}
        permitted = expiry_attenuates(parent, case["child_expires_at"])
        assert permitted == (case["expected"] == "permitted"), (
            f"expiry containment drift: {case['name']} — expected "
            f"{case['expected']}, got {'permitted' if permitted else 'refused'}"
        )


def test_every_chain_case_reaches_its_frozen_verdict() -> None:
    """THE WALK, at each case's own stated instant — never the suite's clock."""
    for case in VECTOR["cases"]:
        docs = [_signed(e) for e in case["chain"]]
        leaf = docs[-1]
        now = datetime.fromisoformat(case["verification_instant"])

        verdict = verify_chain_at(
            SingleKernelKey(_kernel_public_key()),
            leaf,
            PresentedBundle(docs),
            AttestationBundle(),
            now,
        )
        assert verdict.value == case["expected_verification"], (
            f"chain verdict drift: {case['name']} — expected "
            f"{case['expected_verification']}, got {verdict.value}"
        )


def test_the_vector_carries_positive_controls_on_both_surfaces() -> None:
    """The controls are load-bearing, so their presence is asserted rather than
    assumed. An implementation that refuses everything satisfies every negative
    case in this file; only a case that MUST succeed catches it. A later edit that
    drops the controls would disarm the vector without changing a negative."""
    assert any(
        c["expected_verification"] == "attenuated" for c in VECTOR["cases"]
    ), "no chain case must succeed — every negative below it is vacuous"
    assert any(
        c["expected"] == "permitted" for c in VECTOR["expiry_containment"]
    ), "no containment case must succeed — the predicate could return false always"
    assert any(
        c["expected_verification"] == "expired" for c in VECTOR["cases"]
    ), "the vector must carry the lapsed-ancestor case it exists for"
    assert any(
        c["expected_verification"] == "not_attenuated" for c in VECTOR["cases"]
    ), "the vector must carry the child-outliving-its-parent case"


def test_every_chain_case_states_its_own_verification_instant() -> None:
    """A case without a stated instant would be asserted against whatever the
    calendar said on the day the suite ran — which is exactly how chain_v1 came to
    pin ``attenuated`` over three documents that had been dead since June."""
    for case in VECTOR["cases"]:
        instant = case.get("verification_instant")
        assert isinstance(instant, str) and instant.endswith("Z"), (
            f"{case['name']} has no stated verification instant"
        )
        assert ChainVerification(case["expected_verification"]) is not None

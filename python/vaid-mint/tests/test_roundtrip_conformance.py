"""Round-trip verification conformance (ADR-0006).

Verify-only, and a shape the surface did not previously have: every other vector
pins one implementation's OUTPUT FOR A GIVEN INPUT; this one pins A VERDICT OVER
GIVEN BYTES — the only shape that catches cross-implementation disagreement.

Python passed all four cases throughout; Rust failed case 2 and wrongly accepted
case 4 before ADR-0006. Python is gated here anyway, because "the implementation
that happened to be right" is exactly the one that silently regresses.
"""

from __future__ import annotations

import json
from importlib.resources import files

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_mint.document import canonical_vaid_signing_bytes

VECTOR = json.loads(files("vaid_mint").joinpath("vectors/roundtrip_v1.json").read_text())
PUB = Ed25519PublicKey.from_public_bytes(
    bytes.fromhex(VECTOR["ed25519"]["kernel_public_key_hex"])
)


def _verify(doc: dict) -> bool:
    try:
        PUB.verify(bytes(doc["kernel_signature"]), canonical_vaid_signing_bytes(doc))
        return True
    except InvalidSignature:
        return False


def test_every_case_returns_the_frozen_verdict() -> None:
    assert VECTOR["cases"], "vector must carry cases"
    for case in VECTOR["cases"]:
        got = _verify(case["document"])
        assert got == case["expected_valid"], (
            f"roundtrip_v1 case {case['name']!r} returned {got}, expected "
            f"{case['expected_valid']} — {case['why']}"
        )


def test_the_vector_catches_an_implementation_that_drops_unknown_members() -> None:
    """The vector must DISCRIMINATE, in both directions: dropping unknown members
    produces a false NEGATIVE on one case and a false ACCEPT on another."""
    false_negative = false_accept = False
    for case in VECTOR["cases"]:
        doc = case["document"]
        dropped = {k: v for k, v in doc.items() if not k.startswith("x_")}
        try:
            PUB.verify(bytes(doc["kernel_signature"]), canonical_vaid_signing_bytes(dropped))
            got = True
        except InvalidSignature:
            got = False
        if got != case["expected_valid"]:
            if case["expected_valid"]:
                false_negative = True
            else:
                false_accept = True
    assert false_negative, "vector no longer catches a dropping impl REJECTING a valid document"
    assert false_accept, "vector no longer catches a dropping impl ACCEPTING an invalid one"

"""Python `verify_signed_payload` (Workstream 3) — the request-PoP verifier the
Python package previously lacked. Its result must agree with the Rust
`vaid_pop::verify_signed_payload` on the frozen operator_pop_v1 vector: both verify
the same signature over the same canonical digest, so a `True` here means the two
languages agree on that byte-identical input.
"""

from __future__ import annotations

import json
from pathlib import Path

from vaid_pop import verify_signed_payload

VECTOR = (
    Path(__file__).resolve().parents[1] / "vaid_pop" / "vectors" / "operator_pop_v1.json"
)


def _vector() -> dict:
    return json.loads(VECTOR.read_text())


def test_verifies_the_frozen_operator_pop_vector():
    v = _vector()
    public_key = bytes.fromhex(v["ed25519"]["public_key_hex"])
    signature = bytes.fromhex(v["ed25519"]["signature_hex"])
    assert verify_signed_payload(v["input"], public_key, signature), (
        "the frozen operator_pop vector must verify — this is what the Rust "
        "vaid_pop::verify_signed_payload also asserts, on the same bytes"
    )


def test_tampered_payload_fails():
    v = _vector()
    public_key = bytes.fromhex(v["ed25519"]["public_key_hex"])
    signature = bytes.fromhex(v["ed25519"]["signature_hex"])
    tampered = dict(v["input"])
    tampered["path"] = "/vaid/mint/../admin"
    assert not verify_signed_payload(tampered, public_key, signature), "a changed field breaks the proof"


def test_wrong_key_and_malformed_inputs_are_false_not_errors():
    v = _vector()
    signature = bytes.fromhex(v["ed25519"]["signature_hex"])
    # Wrong (but well-formed) key.
    wrong = bytes(32)
    assert verify_signed_payload(v["input"], wrong, signature) is False
    # Malformed key / signature must be a result, never an exception.
    assert verify_signed_payload(v["input"], b"short", signature) is False
    assert verify_signed_payload(v["input"], bytes(32), b"\x00" * 10) is False

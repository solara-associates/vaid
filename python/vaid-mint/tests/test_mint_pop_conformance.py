"""Mint proof-of-possession conformance gate (Python side of the cross-language
firewall).

The vendored vector ``vaid_mint/vectors/mint_pop_v1.json`` is byte-identical to
the Rust and TypeScript copies (a CI drift-check enforces that). It pins
``MintPopPayload`` — the payload a holder signs to prove it controls the BYO
public key it registers at mint.

Why this gate arrived after the other four: ``MintPopPayload`` was the one
**signed** structure in VAID with no frozen artifact (``docs/spec/encoding.md``
E.11). The three reference implementations agreed on it *by construction* — they
share the ``vaid-pop`` primitive and were written against each other — not because
anything held them to it. A fourth implementation could have encoded it
differently, passed every conformance gate in the repo, and failed only later as
an unexplained proof-of-possession rejection at mint.

What this vector pins that the other four do not:

- **A JSON ``null`` inside signed bytes.** It is the root case, so ``parentVaid``
  is null. No other frozen vector contains a null, so nothing previously held an
  implementation to E.7 — an absent value is ``null`` with its key retained, never
  an omitted key.
- **The registered key is the signing key**, so the vector is checkable end-to-end
  through ``verify_signed_payload`` — the same call the mint makes before issuing.

A mismatch is a BLOCKER. The Rust ``mint_pop_conformance`` test and the TypeScript
``mint_pop_conformance.test.ts`` assert the same vector.
"""

from __future__ import annotations

import json
from importlib.resources import files

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.conformance import ConformanceError, check_mint_pop
from vaid_mint.mint_types import VaidSeed, build_mint_pop_payload
from vaid_pop import canonical_request_signing_bytes, verify_signed_payload


def vector() -> dict:
    return json.loads(
        files("vaid_mint").joinpath("vectors/mint_pop_v1.json").read_text()
    )


def holder_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector()["ed25519"]["private_key_seed_hex"])
    )


def test_reproduces_frozen_mint_pop_digest() -> None:
    v = vector()
    digest = canonical_request_signing_bytes(v["input"])
    assert digest.hex() == v["digest_sha256_hex"], (
        "Python mint-PoP digest diverged from the frozen vector — BLOCKER"
    )
    assert len(digest) == 32


def test_reproduces_frozen_mint_pop_signature() -> None:
    v = vector()
    sk = holder_key()
    assert sk.public_key().public_bytes_raw().hex() == v["ed25519"]["public_key_hex"]
    sig = sk.sign(canonical_request_signing_bytes(v["input"]))
    assert sig.hex() == v["ed25519"]["signature_hex"], (
        "Python mint-PoP signature diverged from the frozen vector — BLOCKER"
    )
    assert len(sig) == 64


def test_payload_constructor_reproduces_the_frozen_payload() -> None:
    """``build_mint_pop_payload`` is the single constructor both holder and mint
    use. Reading ``input`` back would only prove a dict round-trips; this proves
    the code path that actually runs at mint emits these bytes."""
    v = vector()
    registered = holder_key().public_key().public_bytes_raw()
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
    assert payload == v["input"], (
        "the mint's own PoP payload constructor diverged from the frozen vector — BLOCKER"
    )
    assert canonical_request_signing_bytes(payload).hex() == v["digest_sha256_hex"]


def test_parent_vaid_is_a_present_null_not_an_omitted_key() -> None:
    """THE E.7 GUARD. This is the only frozen vector carrying a JSON null."""
    v = vector()
    assert "parentVaid" in v["input"], "the key must be present — encoding.md E.7"
    assert v["input"]["parentVaid"] is None, "this is the root case; parentVaid is null"

    without = {k: x for k, x in v["input"].items() if k != "parentVaid"}
    assert canonical_request_signing_bytes(without).hex() != v["digest_sha256_hex"], (
        "omitting parentVaid MUST change the digest — otherwise E.7 is untested"
    )


def test_frozen_signature_verifies_against_the_registered_key() -> None:
    """THE PoP SEMANTIC: the signature verifies against the key the payload
    REGISTERS — the same check the mint performs before issuing."""
    v = vector()
    registered = bytes(v["input"]["publicKeyDer"])
    signature = bytes.fromhex(v["ed25519"]["signature_hex"])

    assert registered.hex() == v["ed25519"]["public_key_hex"], (
        "publicKeyDer must BE the holder's public key — that is what PoP means"
    )
    assert verify_signed_payload(v["input"], registered, signature), (
        "the frozen PoP must verify against the registered key — BLOCKER"
    )

    escalated = dict(v["input"], capabilitySet=["read", "write"])
    assert not verify_signed_payload(escalated, registered, signature), (
        "a captured PoP must not be replayable to mint a higher-privilege VAID"
    )


@pytest.mark.parametrize(
    "label,mutate",
    [
        ("digest", lambda v: dict(v, digest_sha256_hex="00" * 32)),
        ("signature", lambda v: dict(v, ed25519=dict(v["ed25519"], signature_hex="00" * 64))),
        (
            "parentVaid omitted",
            lambda v: dict(v, input={k: x for k, x in v["input"].items() if k != "parentVaid"}),
        ),
        (
            "capabilitySet escalated",
            lambda v: dict(v, input=dict(v["input"], capabilitySet=["read", "write"])),
        ),
    ],
)
def test_packaged_check_is_load_bearing(label, mutate) -> None:
    """The packaged ``check_mint_pop`` must FAIL on a divergent vector. A check
    that cannot fail proves nothing about the one that passes."""
    with pytest.raises(ConformanceError):
        check_mint_pop(mutate(vector()))

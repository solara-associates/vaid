"""Canonical PoP conformance gate (Python side of the cross-language firewall).

The vendored vector ``vaid_pop/vectors/operator_pop_v1.json`` is byte-identical
to the canonical cross-language vector in the ``vaid`` repo (a CI drift-check
enforces that). These tests assert the Python signer reproduces the frozen
digest + Ed25519 signature byte-for-byte; a mismatch is a BLOCKER, not a
ship-anyway. The Rust client (`vaid-client`) asserts the same vector, and the
repo-level ``pop-conformance`` job proves Rust output == Python output == vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    HEADER_VAID,
    RequestSigner,
    canonical_request_signing_bytes,
)


def _vector() -> dict:
    # Read the vector the package SHIPS — the firewall is only real if a consumer
    # runs it against the copy bundled with the signer it actually installed.
    data = files("vaid_pop").joinpath("vectors/operator_pop_v1.json").read_text()
    return json.loads(data)


def test_canonical_digest_matches_frozen_vector():
    """Python JCS + SHA-256 over the camelCase RequestAuthPayload reproduces the
    Rust-frozen digest byte-for-byte."""
    v = _vector()
    digest = canonical_request_signing_bytes(v["input"])
    assert digest.hex() == v["digest_sha256_hex"], (
        "Python canonical digest diverged from the frozen vector — BLOCKER"
    )
    assert len(digest) == 32


def test_deterministic_signature_matches_frozen_vector():
    """From the frozen seed, Python derives the same public key and produces the
    same deterministic Ed25519 signature the Rust vector froze."""
    v = _vector()
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    assert pub.hex() == v["ed25519"]["public_key_hex"], "public key diverged — BLOCKER"

    digest = canonical_request_signing_bytes(v["input"])
    sig = sk.sign(digest)
    assert sig.hex() == v["ed25519"]["signature_hex"], "signature diverged — BLOCKER"
    assert len(sig) == 64

    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def test_request_signer_produces_verifiable_pop_headers():
    """The real signer path: RequestSigner.sign_headers builds the camelCase
    RequestAuthPayload, signs it, and X-Synthera-Signature verifies against the
    agent key over the reconstructed digest."""
    v = _vector()
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key()

    vaid = {
        "vaid_id": v["input"]["vaidId"],
        "tenant_id": v["input"]["tenantId"],
        "agent_id": "22222222-2222-2222-2222-222222222222",
    }
    signer = RequestSigner(vaid=vaid, private_key=sk)

    fixed_now = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)
    body = b""  # vector bodySha256 = sha256("") = e3b0c442...
    headers = signer.sign_headers(
        "POST", "/vaid/mint", body, now=fixed_now, nonce=v["input"]["clientNonce"]
    )

    assert headers[HEADER_TIMESTAMP] == v["input"]["timestamp"]
    assert headers[HEADER_NONCE] == v["input"]["clientNonce"]

    payload = {
        "vaidId": vaid["vaid_id"],
        "method": "POST",
        "path": "/vaid/mint",
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "tenantId": vaid["tenant_id"],
        "timestamp": headers[HEADER_TIMESTAMP],
        "clientNonce": headers[HEADER_NONCE],
    }
    digest = canonical_request_signing_bytes(payload)
    # The signer must reproduce the frozen digest AND signature for this input.
    assert digest.hex() == v["digest_sha256_hex"]
    sig = base64.b64decode(headers[HEADER_SIGNATURE])
    assert sig.hex() == v["ed25519"]["signature_hex"], "header signature diverged — BLOCKER"
    assert len(sig) == 64
    pub.verify(sig, digest)  # raises on failure → the header signature is valid

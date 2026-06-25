"""Packaged cross-language PoP conformance check — the firewall, shipped in the wheel.

This module is the externally-consumable form of the conformance gate. Unlike the
repo test suite under ``tests/`` (which does not ship in the wheel), this lives
*inside* the installed package, so a consumer who has only ``pip install
vaid-pop`` — no repo checkout — can prove the signer they installed reproduces
the frozen cross-language vector byte-for-byte:

    python -m vaid_pop.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-pop-conformance                # same, via the console entry point

Programmatically::

    from vaid_pop.conformance import run
    run()  # raises ConformanceError on any divergence; returns the vector on PASS

The vector it checks against is the one bundled with the signer
(``vaid_pop/vectors/operator_pop_v1.json``) — the firewall is only real if a
consumer runs it against the exact bytes the installed signer was proven against.
The Rust client (``vaid-client``) asserts the identical vector; the repo-level
``pop-conformance`` job proves Rust output == Python output == vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    RequestSigner,
    canonical_request_signing_bytes,
)


class ConformanceError(AssertionError):
    """A cross-language byte-identity divergence — a hard BLOCKER, never ship-anyway."""


def load_vector() -> dict:
    """The conformance vector bundled with the installed package."""
    data = files("vaid_pop").joinpath("vectors/operator_pop_v1.json").read_text()
    return json.loads(data)


def check_digest(v: dict) -> None:
    """Python JCS + SHA-256 over the camelCase RequestAuthPayload == frozen digest."""
    digest = canonical_request_signing_bytes(v["input"])
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError(
            f"canonical digest diverged from the frozen vector — BLOCKER\n"
            f"  got    = {digest.hex()}\n  vector = {v['digest_sha256_hex']}"
        )
    if len(digest) != 32:
        raise ConformanceError(f"digest is {len(digest)} bytes, expected 32")


def check_signature(v: dict) -> None:
    """From the frozen seed, derive the same public key + deterministic signature."""
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    if pub.hex() != v["ed25519"]["public_key_hex"]:
        raise ConformanceError(
            f"public key diverged — BLOCKER\n"
            f"  got    = {pub.hex()}\n  vector = {v['ed25519']['public_key_hex']}"
        )

    digest = canonical_request_signing_bytes(v["input"])
    sig = sk.sign(digest)
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError(
            f"signature diverged — BLOCKER\n"
            f"  got    = {sig.hex()}\n  vector = {v['ed25519']['signature_hex']}"
        )
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def check_request_signer(v: dict) -> None:
    """The real signer path: RequestSigner.sign_headers produces the frozen signature
    and a header that verifies against the agent key over the reconstructed digest."""
    from datetime import datetime, timezone

    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key()

    inp = v["input"]
    vaid = {"vaid_id": inp["vaidId"], "tenant_id": inp["tenantId"]}
    signer = RequestSigner(vaid=vaid, private_key=sk)

    now = datetime.strptime(inp["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    body = b""  # vector bodySha256 = sha256("")
    headers = signer.sign_headers(
        inp["method"], inp["path"], body, now=now, nonce=inp["clientNonce"]
    )

    if headers[HEADER_TIMESTAMP] != inp["timestamp"]:
        raise ConformanceError("header timestamp diverged — BLOCKER")
    if headers[HEADER_NONCE] != inp["clientNonce"]:
        raise ConformanceError("header nonce diverged — BLOCKER")

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
    sig = base64.b64decode(headers[HEADER_SIGNATURE])
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError("header signature diverged — BLOCKER")
    pub.verify(sig, digest)  # raises on failure → header signature is valid


def run() -> dict:
    """Run all firewall checks against the bundled vector. Raises ConformanceError
    on any divergence; returns the vector on PASS."""
    v = load_vector()
    check_digest(v)
    check_signature(v)
    check_request_signer(v)
    return v


# --- pytest discovery (so `pytest --pyargs vaid_pop` runs the firewall) ---


def test_packaged_digest_matches_frozen_vector() -> None:
    check_digest(load_vector())


def test_packaged_signature_matches_frozen_vector() -> None:
    check_signature(load_vector())


def test_packaged_request_signer_matches_frozen_vector() -> None:
    check_request_signer(load_vector())


def main() -> int:
    try:
        v = run()
    except ConformanceError as exc:
        print(f"CROSS-LANGUAGE PoP FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    print(
        "CROSS-LANGUAGE PoP FIREWALL: PASS — installed signer == frozen vector, "
        "byte-for-byte\n"
        f"  digest    = {v['digest_sha256_hex']}\n"
        f"  signature = {v['ed25519']['signature_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

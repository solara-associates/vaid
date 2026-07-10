"""Packaged path-with-query conformance check — the firewall, shipped in the wheel.

Mirror of ``vaid_pop.conformance`` / ``vaid_mint.conformance``. A consumer who has
only ``pip install vaid-langchain`` can prove the adapter they installed reproduces
the frozen ``pathquery_v1.json`` vector byte-for-byte, using only the installed
package (and its ``vaid-pop`` dependency under the hood)::

    python -m vaid_langchain.conformance     # exit 0 = PASS, 1 = BLOCKER
    vaid-langchain-conformance               # same, via the console entry point

Programmatically::

    from vaid_langchain.conformance import run
    run()  # raises ConformanceError on any divergence; returns the vector on PASS

The vector it checks is the one bundled with the package
(``vaid_langchain/vectors/pathquery_v1.json``). The Rust ``vaid-client``
``pathquery_conformance`` test asserts the identical vector; a repo-level
drift-check proves the two copies are byte-identical ⇒ Rust == Python == vector.

What is distinct here vs. the raw PoP firewall: this also confirms the adapter's
own pinned request-target convention — ``request_target`` (httpx ``raw_path`` =
percent-encoded path + query) reproduces the frozen ``path`` — before reproducing
the digest + signature over it. That ties the byte-identity proof to the exact
convention the adapter signs with.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from importlib.resources import files

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import (
    HEADER_SIGNATURE,
    RequestSigner,
    build_request_auth_payload,
    canonical_request_signing_bytes,
)

from vaid_langchain._target import request_target


class ConformanceError(AssertionError):
    """A cross-language byte-identity divergence — a hard BLOCKER, never ship-anyway."""


def load_vector() -> dict:
    """The path-with-query conformance vector bundled with the installed package."""
    data = files("vaid_langchain").joinpath("vectors/pathquery_v1.json").read_text()
    return json.loads(data)


def check_target_convention(v: dict) -> None:
    """The adapter's own request-target rule (``request_target`` = httpx raw_path)
    reproduces the frozen `path`, and that path carries a query — the pinned,
    security-relevant convention this vector exists to lock."""
    path = v["input"]["path"]
    if "?" not in path:
        raise ConformanceError("pathquery vector's `path` must include a query string")
    req = httpx.Request("POST", f"https://host{path}", content=b"")
    got = request_target(req)
    if got != path:
        raise ConformanceError(
            f"request_target diverged from the frozen path — BLOCKER\n"
            f"  got    = {got}\n  vector = {path}"
        )


def check_digest(v: dict) -> None:
    """Python JCS + SHA-256 over the camelCase RequestAuthPayload (path+query) ==
    frozen digest."""
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
    """End-to-end: the real signer path (vaid-pop RequestSigner) over the pinned
    request target reproduces the frozen header signature byte-for-byte."""
    inp = v["input"]
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signer = RequestSigner(
        vaid={"vaid_id": inp["vaidId"], "tenant_id": inp["tenantId"]}, private_key=sk
    )
    # Re-derive the signed target through the adapter's own convention.
    req = httpx.Request("POST", f"https://host{inp['path']}", content=b"")
    target = request_target(req)
    now = datetime.strptime(inp["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = signer.sign_headers(inp["method"], target, b"", now=now, nonce=inp["clientNonce"])

    payload = build_request_auth_payload(
        vaid_id=inp["vaidId"],
        method=inp["method"].upper(),
        path=target,
        body_sha256=hashlib.sha256(b"").hexdigest(),
        tenant_id=inp["tenantId"],
        timestamp=inp["timestamp"],
        client_nonce=inp["clientNonce"],
    )
    digest = canonical_request_signing_bytes(payload)
    sig = base64.b64decode(headers[HEADER_SIGNATURE])
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError("header signature diverged — BLOCKER")
    sk.public_key().verify(sig, digest)  # raises on failure → header signature valid


def run() -> dict:
    """Run all firewall checks against the bundled vector. Raises ConformanceError
    on any divergence; returns the vector on PASS."""
    v = load_vector()
    check_target_convention(v)
    check_digest(v)
    check_signature(v)
    check_request_signer(v)
    return v


# --- pytest discovery (so `pytest --pyargs vaid_langchain` runs the firewall) ---


def test_packaged_target_convention_matches_frozen_vector() -> None:
    check_target_convention(load_vector())


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
        print(f"CROSS-LANGUAGE PATHQUERY FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    print(
        "CROSS-LANGUAGE PATHQUERY FIREWALL: PASS — installed adapter == frozen vector, "
        "byte-for-byte\n"
        f"  path      = {v['input']['path']}\n"
        f"  digest    = {v['digest_sha256_hex']}\n"
        f"  signature = {v['ed25519']['signature_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

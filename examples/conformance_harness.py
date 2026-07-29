#!/usr/bin/env python3
"""VAID conformance harness — published packages only, one file, one command.

VAID is an interoperability contract: any conforming client produces bytes that
any conforming verifier accepts. This harness proves that against the *frozen
conformance vector* that ships inside the installed ``vaid-pop`` package — so it
checks the signer you actually installed, not a copy in this repo.

    pip install vaid-pop
    python conformance_harness.py

No server, no API key, no network. It runs the frozen PoP vector and reports
PASS/FAIL per check, with a byte-level diff on failure. Exit code 0 = all pass.

──────────────────────────────────────────────────────────────────────────────
Certifying YOUR OWN implementation
──────────────────────────────────────────────────────────────────────────────
Replace the body of ``digest_fn`` below with your implementation of the VAID
canonicalization step — JCS (RFC 8785) over the payload, then SHA-256, returning
the 32-byte digest. If your bytes match the frozen vector, your canonicalizer is
conformant; if they don't, the diff shows exactly where you diverged. Ed25519
signing itself is standard and deterministic (RFC 8032), so canonicalization is
the only place a conforming implementation can drift — that is what you swap.
"""
from __future__ import annotations

import json
import sys
from importlib.metadata import version
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import canonical_request_signing_bytes


# ─── THE ONE FUNCTION AN EVALUATOR SWAPS ─────────────────────────────────────
# Default is the reference vaid-pop canonicalizer. To certify your own code,
# replace the body with your JCS(RFC 8785) -> SHA-256 over `payload`, returning
# the raw 32-byte digest.
def digest_fn(payload: dict) -> bytes:
    return canonical_request_signing_bytes(payload)
# ─────────────────────────────────────────────────────────────────────────────


def _load_vector() -> dict:
    # The vector the INSTALLED package ships — the firewall is only real if you
    # run it against the copy bundled with the signer you installed.
    return json.loads(
        files("vaid_pop").joinpath("vectors/operator_pop_v1.json").read_text()
    )


def _diff(label: str, expected: str, actual: str) -> str:
    return f"      expected {label}: {expected}\n      actual   {label}: {actual}"


def _check_digest(v: dict) -> tuple[bool, str]:
    try:
        digest = digest_fn(v["input"])
    except Exception as e:  # a broken canonicalizer must fail loudly, not pass
        return False, f"      digest_fn raised: {e!r}"
    if len(digest) != 32:
        return False, f"      digest is {len(digest)} bytes, expected 32"
    if digest.hex() != v["digest_sha256_hex"]:
        return False, _diff("digest", v["digest_sha256_hex"], digest.hex())
    return True, ""


def _check_signature(v: dict) -> tuple[bool, str]:
    try:
        seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes_raw()
        digest = digest_fn(v["input"])
        sig = sk.sign(digest)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on bad
    except Exception as e:
        return False, f"      signing/verify raised: {e!r}"
    detail = ""
    if pub.hex() != v["ed25519"]["public_key_hex"]:
        detail += _diff("public_key", v["ed25519"]["public_key_hex"], pub.hex()) + "\n"
    if sig.hex() != v["ed25519"]["signature_hex"]:
        detail += _diff("signature", v["ed25519"]["signature_hex"], sig.hex())
    return (detail == ""), detail


def main() -> int:
    try:
        v = _load_vector()
        pkg = version("vaid-pop")
    except Exception as e:
        print(f"FATAL: could not load vaid-pop / its frozen vector ({e!r}).")
        print("Is vaid-pop installed?  ->  pip install vaid-pop")
        return 2

    checks = [
        ("canonical digest (JCS RFC 8785 -> SHA-256) matches frozen vector", _check_digest(v)),
        ("deterministic Ed25519 signature matches frozen vector", _check_signature(v)),
    ]

    print(f"VAID conformance — vector operator_pop_v1 — vaid-pop {pkg}")
    print(f"scheme: {v.get('scheme', '')}\n")
    npass = 0
    for name, (ok, detail) in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if ok:
            npass += 1
        elif detail:
            print(detail)
    print(f"\n{npass}/{len(checks)} checks PASS")
    return 0 if npass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())

"""PIN THE PATH/QUERY CONVENTION (Investigation 3's silent-failure landmine).

Proves that the request-target string the adapter signs (``request_target`` =
httpx ``raw_path`` = percent-encoded path+query):

  1. is exactly what we intend, WITH and WITHOUT a query string present;
  2. round-trips: sign → a verifier reconstructing the SAME target verifies OK;
  3. is byte-identical to what the canonical RUST signer produces for the same
     with-query target — asserted against the frozen, vendored vector
     ``pathquery_v1.json`` (regenerate via
     ``cargo run -p vaid-client --example emit_pop_pathquery``; a CI drift-check
     enforces the Rust and Python copies are byte-identical);
  4. fails closed if the WRONG attribute (``.path``, which drops the query) is
     used on one side — the landmine bites loudly, not silently-at-runtime.
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

from vaid_pop import RequestSigner, build_request_auth_payload, canonical_request_signing_bytes

from vaid_langchain._target import request_target


def _vector() -> dict:
    """The frozen path-with-query vector bundled with the package (byte-identical
    to the Rust copy under crates/vaid-client/tests/vectors/)."""
    data = files("vaid_langchain").joinpath("vectors/pathquery_v1.json").read_text()
    return json.loads(data)


V = _vector()
SEED_HEX = V["ed25519"]["private_key_seed_hex"]
VAID_ID = V["input"]["vaidId"]
TENANT_ID = V["input"]["tenantId"]
TIMESTAMP = V["input"]["timestamp"]
NONCE = V["input"]["clientNonce"]
QUERY_PATH = V["input"]["path"]  # "/vaid/mint?tenant=acme&limit=10"


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))


def _signer() -> RequestSigner:
    return RequestSigner(vaid={"vaid_id": VAID_ID, "tenant_id": TENANT_ID}, private_key=_key())


def _verify(method: str, path: str, body: bytes, headers: dict) -> bool:
    """A stand-in verifier: reconstruct the payload from the SAME (method, path,
    body) rule and check the signature against the agent public key."""
    payload = build_request_auth_payload(
        vaid_id=VAID_ID,
        method=method.upper(),
        path=path,
        body_sha256=hashlib.sha256(body).hexdigest(),
        tenant_id=TENANT_ID,
        timestamp=headers["x-synthera-timestamp"],
        client_nonce=headers["x-synthera-nonce"],
    )
    digest = canonical_request_signing_bytes(payload)
    sig = base64.b64decode(headers["x-synthera-signature"])
    pub = _key().public_key().public_bytes_raw()
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)
        return True
    except Exception:
        return False


def test_httpx_raw_path_yields_intended_target_without_query():
    r = httpx.Request("POST", "https://api.example.com/vaid/mint", content=b"{}")
    assert request_target(r) == "/vaid/mint"


def test_httpx_raw_path_yields_intended_target_with_query():
    r = httpx.Request("POST", f"https://api.example.com{QUERY_PATH}", content=b"{}")
    # The query IS included in the signed target — the whole point.
    assert request_target(r) == QUERY_PATH


def test_roundtrip_sign_then_verify_no_query():
    r = httpx.Request("POST", "https://api.example.com/vaid/mint", content=b"")
    path = request_target(r)
    now = datetime.strptime(TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = _signer().sign_headers("POST", path, b"", now=now, nonce=NONCE)
    assert _verify("POST", path, b"", headers)


def test_roundtrip_sign_then_verify_with_query():
    r = httpx.Request("POST", f"https://api.example.com{QUERY_PATH}", content=b"")
    path = request_target(r)
    now = datetime.strptime(TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = _signer().sign_headers("POST", path, b"", now=now, nonce=NONCE)
    assert _verify("POST", path, b"", headers)


def test_cross_language_signature_matches_frozen_vector_for_with_query_target():
    """Python signing of the httpx-extracted with-query target reproduces the
    canonical RUST signature (the frozen vector) byte-for-byte — proving the exact
    path string flows identically through both reference implementations."""
    r = httpx.Request("POST", f"https://api.example.com{QUERY_PATH}", content=b"")
    path = request_target(r)
    assert path == V["input"]["path"]

    payload = build_request_auth_payload(
        vaid_id=VAID_ID,
        method="POST",
        path=path,
        body_sha256=hashlib.sha256(b"").hexdigest(),
        tenant_id=TENANT_ID,
        timestamp=TIMESTAMP,
        client_nonce=NONCE,
    )
    digest = canonical_request_signing_bytes(payload)
    assert digest.hex() == V["digest_sha256_hex"], "digest diverged from the frozen vector — BLOCKER"

    now = datetime.strptime(TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = _signer().sign_headers("POST", path, b"", now=now, nonce=NONCE)
    sig_hex = base64.b64decode(headers["x-synthera-signature"]).hex()
    assert sig_hex == V["ed25519"]["signature_hex"], "signature diverged from the vector — BLOCKER"


def test_wrong_attribute_dot_path_drops_query_and_fails_closed():
    """THE LANDMINE: if the signer uses raw_path (with query) but a verifier uses
    .path (query dropped), verification FAILS — the mismatch is caught, not
    silently accepted. Proves picking the wrong attribute breaks loudly."""
    r = httpx.Request("POST", f"https://api.example.com{QUERY_PATH}", content=b"")
    signed_path = request_target(r)          # raw_path: includes ?query
    verifier_path = r.url.path               # WRONG: query dropped
    assert signed_path != verifier_path

    now = datetime.strptime(TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = _signer().sign_headers("POST", signed_path, b"", now=now, nonce=NONCE)
    assert not _verify("POST", verifier_path, b"", headers)

"""VAID proof-of-possession request signing — canonical Python signer.

The Rust `vaid-pop` crate (the operator-signing port and the `vaid_pop`
verifier) defines the CANONICAL contract; this is the Python **mirror**, not a
second definition. Byte-identity is locked by the shared cross-language vector
``operator_pop_v1.json`` (vendored into this package at ``vaid_pop/vectors/`` and
drift-checked against the canonical source): if these bytes ever diverge from
Rust, the conformance test is a BLOCKER.

This module is the single source of the Python PoP signer. Language-specific
agent integrations DEPEND ON this package and re-export ``RequestSigner`` /
``canonical_request_signing_bytes`` — they no longer carry their own copy. Any
framework-free consumer imports ``vaid_pop`` directly and pulls in nothing else.

Contract: RFC 8785 (JCS) over the camelCase ``RequestAuthPayload`` -> SHA-256 ->
32-byte digest -> **pure Ed25519 over the digest as the raw message** -> raw
64-byte signature. The four headers below carry it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# VAID PoP wire headers — the fixed `x-synthera-*` header namespace a conforming
# verifier reads (the wire contract; the prefix is not a package dependency).
HEADER_VAID = "x-synthera-vaid"
HEADER_TIMESTAMP = "x-synthera-timestamp"
HEADER_NONCE = "x-synthera-nonce"
HEADER_SIGNATURE = "x-synthera-signature"


def canonical_request_signing_bytes(payload: dict) -> bytes:
    """The 32-byte signing digest: RFC 8785 (JCS) of `payload`, then SHA-256.

    Mirror of the Rust `vaid_pop::canonical_request_signing_bytes`. The
    payload MUST use the camelCase `RequestAuthPayload` field names
    (`vaidId`, `method`, `path`, `bodySha256`, `tenantId`, `timestamp`,
    `clientNonce`) — JCS sorts keys, so order is irrelevant, but names are not.
    """
    return hashlib.sha256(rfc8785.dumps(payload)).digest()


def build_request_auth_payload(
    *,
    vaid_id: str,
    method: str,
    path: str,
    body_sha256: str,
    tenant_id: str,
    timestamp: str,
    client_nonce: str,
) -> dict:
    """The seven ADR-mandated fields, camelCase (mirrors `RequestAuthPayload`)."""
    return {
        "vaidId": vaid_id,
        "method": method,
        "path": path,
        "bodySha256": body_sha256,
        "tenantId": tenant_id,
        "timestamp": timestamp,
        "clientNonce": client_nonce,
    }


def utc_whole_second_rfc3339(now: datetime | None = None) -> str:
    """Whole-second UTC RFC 3339 with `Z`.

    This is the chrono-serde fixed point: the verifier parses the
    `x-synthera-timestamp` header into a `DateTime<Utc>` and re-serializes it
    when it recomputes the canonical bytes; a whole-second `...Z` string parses
    and re-serializes to itself, so the client's signed-payload timestamp matches
    the server's. Sub-second precision would risk a re-serialization mismatch.
    """
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RequestSigner:
    """Signs requests with the agent's per-agent Ed25519 key (build-3 PoP).

    The agent's VAID document (as minted) and its private key are INPUTS here;
    durable provisioning/injection of the key is the agent template's job,
    not this client's.
    """

    def __init__(self, *, vaid: dict, private_key: Ed25519PrivateKey) -> None:
        # The VAID document is snake_case (`Vaid` has no serde rename), unlike
        # the camelCase `RequestAuthPayload`. Extract identity by snake_case keys.
        try:
            self._vaid_id = str(vaid["vaid_id"])
            self._tenant_id = str(vaid["tenant_id"])
        except KeyError as exc:
            raise ValueError(f"VAID document missing required field {exc}") from exc
        self._private_key = private_key
        # X-Synthera-Vaid = base64 of the VAID document JSON. The verifier
        # re-deserializes by field and recomputes the VAID's own canonical bytes
        # for signature verification, so a compact re-encoding is fine.
        self._vaid_header = base64.b64encode(
            json.dumps(vaid, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    def sign_headers(
        self,
        method: str,
        path: str,
        body: bytes,
        *,
        now: datetime | None = None,
        nonce: str | None = None,
    ) -> dict[str, str]:
        """Produce the four PoP headers for `(method, path, body)`.

        `now`/`nonce` are injectable for deterministic tests; in production they
        default to the current UTC second and a fresh 128-bit random nonce.
        """
        timestamp = utc_whole_second_rfc3339(now)
        nonce = nonce or secrets.token_hex(16)
        body_sha256 = hashlib.sha256(body).hexdigest()
        payload = build_request_auth_payload(
            vaid_id=self._vaid_id,
            method=method.upper(),
            path=path,
            body_sha256=body_sha256,
            tenant_id=self._tenant_id,
            timestamp=timestamp,
            client_nonce=nonce,
        )
        digest = canonical_request_signing_bytes(payload)
        signature = self._private_key.sign(digest)  # pure Ed25519, raw 64 bytes
        return {
            HEADER_VAID: self._vaid_header,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: base64.b64encode(signature).decode("ascii"),
        }

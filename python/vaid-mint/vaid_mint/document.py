"""VAID document canonicalization — Python mirror of the Rust `vaid-mint` crate.

The Rust `vaid_mint::document` module defines the CANONICAL contract; this is the
Python mirror, not a second definition. Byte-identity of the signed VAID document
is locked by the shared cross-language vector ``mint_v1.json`` (vendored into this
package at ``vaid_mint/vectors/`` and drift-checked against the Rust copy).

Contract: the VAID document is snake_case (the Rust `Vaid` struct has no serde
rename). ``canonical_vaid_signing_bytes`` nulls ``kernel_signature`` (a signature
cannot cover its own value), canonicalizes the whole document per RFC 8785 (JCS),
and SHA-256s it — the 32-byte digest the kernel key signs.

Per Decision B this is self-consistent WITHIN this repo (Rust == Python); it is
NOT byte-conformant against the managed authority's (still-moving) VAID format.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import rfc8785

# Signature-scheme discriminant; ``2`` for every VAID minted here. Covered by the
# signature and gated at verify.
VAID_SIG_VERSION_V2 = 2


def canonical_vaid_signing_bytes(vaid: dict) -> bytes:
    """The 32-byte signing digest of a VAID document.

    Mirror of the Rust ``canonical_vaid_signing_bytes``: copy the document, force
    ``kernel_signature`` to JSON ``null``, canonicalize per RFC 8785 (JCS), then
    SHA-256. Byte-array fields (``public_key_der``, ``kernel_signature``) are lists
    of ints, exactly as Rust serializes ``Vec<u8>``.
    """
    payload = dict(vaid)
    payload["kernel_signature"] = None
    return hashlib.sha256(rfc8785.dumps(payload)).digest()


def compute_lineage_hash(parent_vaid: str | None, agent_id: str) -> str:
    """Lineage hash from the parent chain — mirror of the Rust
    ``compute_lineage_hash``. Root agents (no parent) get a genesis hash. Lowercase
    hex of ``SHA-256`` over ``"{parent}:{agent_id}"`` or ``"GENESIS:{agent_id}"``.
    """
    if parent_vaid is None:
        material = f"GENESIS:{agent_id}"
    else:
        material = f"{parent_vaid}:{agent_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_unsigned_vaid_document(
    *,
    vaid_id: str,
    agent_id: str,
    agent_class: str,
    version: str,
    tenant_id: str,
    issued_at: str,
    expires_at: str,
    public_key_der: list[int],
    parent_vaid: str | None,
    scope_boundary: list[str],
    lineage_hash: str,
    capability_set: list[str],
) -> dict:
    """Assemble the snake_case VAID document with an empty ``kernel_signature``.

    The field set and names mirror the Rust ``Vaid`` struct exactly; the issuer
    signs the canonical bytes of this and attaches the signature.
    """
    return {
        "sig_version": VAID_SIG_VERSION_V2,
        "vaid_id": vaid_id,
        "agent_id": agent_id,
        "agent_class": agent_class,
        "version": version,
        "tenant_id": tenant_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "public_key_der": list(public_key_der),
        "kernel_signature": [],
        "parent_vaid": parent_vaid,
        "scope_boundary": list(scope_boundary),
        "lineage_hash": lineage_hash,
        "capability_set": list(capability_set),
    }


def is_expired(vaid: dict) -> bool:
    """Has the document passed its ``expires_at``? Mirror of ``Vaid::is_expired``
    (``Utc::now() > self.expires_at``).

    Parses the whole-second RFC 3339 ``"...Z"`` ``expires_at`` this package writes
    at issuance. Expiry is a hard reject in
    :meth:`~vaid_mint.issuer.ReferenceIssuer.verify_vaid`; this stays available for
    a caller that needs to distinguish "forged" from "expired" beforehand.
    """
    expires_at = datetime.strptime(vaid["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return datetime.now(timezone.utc) > expires_at


def is_in_scope(vaid: dict, resource: str) -> bool:
    """Is ``resource`` within the document's scope boundary? Empty = unrestricted.
    The single scope matcher — mirror of ``Vaid::is_in_scope``."""
    scope = vaid["scope_boundary"]
    if not scope:
        return True
    return any(resource.startswith(s) for s in scope)


def has_capability(vaid: dict, capability: str) -> bool:
    """Does the document hold ``capability`` (exact membership)? Mirror of
    ``Vaid::has_capability``."""
    return capability in vaid["capability_set"]

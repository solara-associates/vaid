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
import re
from datetime import datetime, timezone

import rfc8785

# Signature-scheme discriminant; ``3`` for every VAID minted here. Covered by the
# signature and gated at verify.
#
# v3 (ADR-0004) adds ``trust_domain`` and ``kernel_key_thumbprint``. The v2
# constant is deliberately REMOVED rather than retained, mirroring Rust: no code
# can accidentally accept a v2 document, and there is no dual-version path — a v2
# document must not verify under a v3 verifier, because accepting both would
# recreate the downgrade surface that signing ``sig_version`` exists to close.
VAID_SIG_VERSION_V3 = 3

#: The exact timestamp profile inside signed bytes (``docs/spec/encoding.md``
#: E.6): whole-second RFC 3339 in UTC with a literal ``Z``. Narrower than RFC 3339
#: on purpose — it is the round-trip fixed point, so a verifier that re-serializes
#: while recomputing canonical bytes agrees with the signer.
_E6_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


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
    trust_domain: str,
    kernel_key_thumbprint: str,
) -> dict:
    """Assemble the snake_case VAID document with an empty ``kernel_signature``.

    The field set and names mirror the Rust ``Vaid`` struct exactly; the issuer
    signs the canonical bytes of this and attaches the signature.
    """
    return {
        "sig_version": VAID_SIG_VERSION_V3,
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
        "trust_domain": trust_domain,
        "kernel_key_thumbprint": kernel_key_thumbprint,
    }


def _parse_rfc3339(value: object) -> datetime | None:
    """Permissively parse an RFC 3339 timestamp to an aware UTC datetime, or
    ``None`` if it is not one.

    Permissive on purpose: this is the parser :func:`is_expired` uses, and
    :func:`is_expired` must be TOTAL. Conformance to the narrower E.6 profile is a
    separate question, asked separately by :func:`has_conforming_timestamps`.
    """
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # RFC 3339 requires an offset. A naive timestamp is not one, and guessing
        # UTC would silently invent a value the signer never wrote.
        return None
    return dt.astimezone(timezone.utc)


def is_expired(vaid: dict) -> bool:
    """Has the document passed its ``expires_at``? Mirror of ``Vaid::is_expired``.

    **Total: never raises** (issue #10). Previously this parsed with a fixed format
    string and raised ``ValueError`` on any timestamp that was valid RFC 3339 but
    not whole-second ``Z`` — from a function whose signature promises a ``bool``,
    with no mention of it in the docstring, so callers did not guard. Rust and
    TypeScript returned a bool for the same inputs. Two of three implementations
    were permissive by accident of which parser each language makes idiomatic, and
    majority-by-accident was becoming the de facto standard.

    Settled by splitting the surface rather than by picking a winner:

    - this function stays total and answers only "is it past expiry";
    - :func:`has_conforming_timestamps` answers the E.6 profile question
      explicitly, so a caller that wants strictness asks for it and can tell the
      two failures apart.

    An unparseable or absent ``expires_at`` returns ``True`` — **fail closed**. A
    document whose expiry cannot be read is not a document that can be shown to be
    unexpired.
    """
    expires_at = _parse_rfc3339(vaid.get("expires_at"))
    if expires_at is None:
        return True
    return datetime.now(timezone.utc) > expires_at


def has_conforming_timestamps(vaid: dict) -> bool:
    """Do ``issued_at`` and ``expires_at`` match the E.6 profile exactly —
    whole-second RFC 3339 in UTC with a literal ``Z``?

    The explicit half of the issue #10 split. E.6 says implementations SHOULD
    reject other forms rather than silently normalizing them; this is how a caller
    asks. Sub-second precision (``...:00.000Z``, which JavaScript's
    ``toISOString`` emits by default) and a numeric offset (``+00:00``) are both
    valid RFC 3339 and both non-conforming here.

    Not consulted by authenticity verification: a document that reached a verifier
    with a non-conforming timestamp will already fail the signature check, because
    the verifier re-serializes into the profile and recomputes different bytes.
    This exists so that failure can be *explained* rather than merely observed.
    """
    for field in ("issued_at", "expires_at"):
        value = vaid.get(field)
        if not isinstance(value, str) or not _E6_TIMESTAMP.match(value):
            return False
        if _parse_rfc3339(value) is None:
            return False
    return True


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

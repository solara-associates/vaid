"""Public-key-only VAID document verification (Workstream 3) — Python mirror of
the Rust tests/document_verify.rs. The verifying party holds ONLY the kernel public
key: no ReferenceIssuer, no private key. Revocation is not consulted; these are
authenticity tests.

`test_verifies_the_frozen_mint_vector...` verifies the SAME frozen mint_v1 vector
the Rust suite verifies — the cross-language agreement anchor.
"""

from __future__ import annotations

import json
from pathlib import Path

from vaid_mint import (
    ReferenceIssuer,
    verify_lineage_hash,
    verify_vaid_authenticity,
)
from vaid_mint.document import is_expired

MINT_VECTOR = Path(__file__).resolve().parents[1] / "vaid_mint" / "vectors" / "mint_v1.json"


def _public_key_and_doc() -> tuple[bytes, dict]:
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    vaid = issuer.issue_vaid_with_lineage(
        agent_class="root",
        version="1.0.0",
        tenant_id="t",
        parent_vaid=None,
        scope_boundary=["data.x"],
        capability_set=["read"],
    )
    # Return only the public key + document; the issuer goes out of scope.
    return issuer.kernel_public_key(), vaid


def test_third_party_verifies_with_public_key_only():
    public_key, vaid = _public_key_and_doc()
    assert verify_vaid_authenticity(public_key, vaid), "a genuine VAID verifies under the public key alone"


def test_tampered_document_fails():
    public_key, vaid = _public_key_and_doc()
    forged = dict(vaid)
    forged["scope_boundary"] = ["data.x", "data.everything"]
    assert not verify_vaid_authenticity(public_key, forged), "a rewritten field must fail"


def test_a_different_key_does_not_verify():
    _pk, vaid = _public_key_and_doc()
    other = ReferenceIssuer.ephemeral(1, "vaid.example").kernel_public_key()
    assert not verify_vaid_authenticity(other, vaid), "another issuer's key must not verify it"


def test_lineage_hash_mismatch_detected_explicitly():
    _pk, vaid = _public_key_and_doc()
    assert verify_lineage_hash(vaid), "the genuine document's lineage_hash is consistent"
    bad = dict(vaid)
    bad["lineage_hash"] = "00000000000000000000000000000000000000000000000000000000deadbeef"
    assert not verify_lineage_hash(bad), "an inconsistent lineage_hash must be caught explicitly"


def test_verifies_the_frozen_mint_vector_with_public_key_only():
    v = json.loads(MINT_VECTOR.read_text())
    doc = dict(v["input"])
    doc["kernel_signature"] = list(bytes.fromhex(v["ed25519"]["signature_hex"]))
    public_key = bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    assert verify_vaid_authenticity(public_key, doc), "the frozen mint vector verifies under its public key alone"

    bad = dict(v["input"])
    sig = bytearray(bytes.fromhex(v["ed25519"]["signature_hex"]))
    sig[0] ^= 0x01
    bad["kernel_signature"] = list(sig)
    assert not verify_vaid_authenticity(public_key, bad), "a one-byte signature flip must fail"


# ── RFC 3339 requires an offset (vaid#79, Session 240) ──


def test_an_offsetless_expiry_is_expired_not_live() -> None:
    """The three implementations must agree, and for a while they did not.

    JavaScript's ``Date.parse`` reads a date-time with no offset as LOCAL time, so
    the TypeScript twin called such a document **live** — and gave a different
    answer on a UTC+2 laptop than on a UTC runner. Python and Rust both refuse it
    and call it expired, fail-closed. Pinned in all three so the agreement is a
    tested property rather than a coincidence of three parsers.

    ``verdict_v1.json`` covers an unreadable expiry and a numeric-offset expiry. It
    has no offsetless case, which is why nothing caught this.
    """
    assert is_expired({"expires_at": "2999-01-01T00:00:00"}) is True
    assert is_expired({"expires_at": "2999-01-01T00:00:00Z"}) is False
    assert is_expired({"expires_at": "2999-01-01T00:00:00+00:00"}) is False

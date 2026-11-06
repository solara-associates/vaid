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

import pytest

from vaid_mint import (
    ExpectedCaller,
    ReferenceIssuer,
    VaidVerdict,
    verify_lineage_hash,
    verify_vaid_authenticity,
    verify_vaid_standing_bound,
    verify_vaid_standing_bound_from_json,
    verify_vaid_standing_from_json,
)
from vaid_mint.document import is_expired, require_vaid_shape
from vaid_mint.document import prefix_entry
from vaid_mint.error import CallerMismatchError, MalformedDocumentError
from vaid_mint.revocation import RevocationStatus, assemble_lineage

MINT_VECTOR = Path(__file__).resolve().parents[1] / "vaid_mint" / "vectors" / "mint_v1.json"


def _public_key_and_doc() -> tuple[bytes, dict]:
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    vaid = issuer.issue_vaid_with_lineage(
        agent_class="root",
        version="1.0.0",
        tenant_id="t",
        parent_vaid=None,
        scope_boundary=[prefix_entry("data.x")],
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


# ── Malformed documents refuse with a typed error (AiSOC review of
# beenuar/AiSOC#1741, finding 1) — never a bare KeyError/AttributeError. ──


class _NoneResolver:
    def resolve_parent(self, vaid_id: str):  # pragma: no cover - never reached
        raise AssertionError("resolver must not be consulted for a malformed leaf")


@pytest.mark.parametrize(
    "bad_leaf",
    [
        None,
        [],
        "not-a-document",
        42,
        {},
        {"parent_vaid": "p"},
        {"vaid_id": None},
        {"vaid_id": 123},
        {"vaid_id": ""},
        {"vaid_id": "a", "parent_vaid": 123},
    ],
)
def test_assemble_lineage_refuses_malformed_leaf(bad_leaf) -> None:
    with pytest.raises(MalformedDocumentError):
        assemble_lineage(bad_leaf, _NoneResolver())


@pytest.mark.parametrize("bad_doc", [None, [], "not-a-document", 42, {}, {"vaid_id": 1}])
def test_require_vaid_shape_refuses_malformed_input(bad_doc) -> None:
    with pytest.raises(MalformedDocumentError):
        require_vaid_shape(bad_doc)


@pytest.mark.parametrize("bad_vaid", [None, [], "not-a-document", 42])
def test_verify_vaid_standing_refuses_malformed_input_with_typed_error(bad_vaid) -> None:
    public_key, _ = _public_key_and_doc()
    with pytest.raises(MalformedDocumentError):
        from vaid_mint import verify_vaid_standing

        verify_vaid_standing(public_key, bad_vaid, RevocationStatus.NOT_REVOKED)


def test_empty_and_missing_field_json_is_unparseable_never_a_crash() -> None:
    public_key, _ = _public_key_and_doc()
    assert verify_vaid_standing_from_json(public_key, "", RevocationStatus.NOT_REVOKED) is VaidVerdict.UNPARSEABLE
    assert (
        verify_vaid_standing_from_json(public_key, "{}", RevocationStatus.NOT_REVOKED)
        is VaidVerdict.UNPARSEABLE
    )


def test_missing_required_field_json_is_unparseable_never_a_crash() -> None:
    public_key, doc = _public_key_and_doc()
    broken = dict(doc)
    del broken["vaid_id"]
    verdict = verify_vaid_standing_from_json(
        public_key, json.dumps(broken), RevocationStatus.NOT_REVOKED
    )
    assert verdict is VaidVerdict.UNPARSEABLE


def test_wrong_typed_field_json_is_unparseable_never_a_crash() -> None:
    public_key, doc = _public_key_and_doc()
    broken = dict(doc)
    broken["vaid_id"] = 12345
    verdict = verify_vaid_standing_from_json(
        public_key, json.dumps(broken), RevocationStatus.NOT_REVOKED
    )
    assert verdict is VaidVerdict.UNPARSEABLE


# ── Caller binding (AiSOC review of beenuar/AiSOC#1741, finding 2) ──────────
#
# VALID standing proves a VAID is real, unexpired and unrevoked; it proves
# nothing about who presented it. These pin that verify_vaid_standing_bound(...)
# refuses a genuine document presented by the wrong caller, and that leaving
# every field of ExpectedCaller unset behaves exactly like plain standing.


def test_unbound_caller_check_matches_plain_standing() -> None:
    public_key, doc = _public_key_and_doc()
    verdict = verify_vaid_standing_bound(
        public_key, doc, RevocationStatus.NOT_REVOKED, ExpectedCaller.none()
    )
    assert verdict is VaidVerdict.VALID


def test_caller_binding_accepts_the_genuine_caller() -> None:
    public_key, doc = _public_key_and_doc()
    expected = ExpectedCaller(
        agent_id=doc["agent_id"], agent_class=doc["agent_class"], tenant_id=doc["tenant_id"]
    )
    verdict = verify_vaid_standing_bound(public_key, doc, RevocationStatus.NOT_REVOKED, expected)
    assert verdict is VaidVerdict.VALID


def test_caller_binding_refuses_a_valid_vaid_presented_by_someone_else() -> None:
    public_key, doc = _public_key_and_doc()
    wrong_agent = ExpectedCaller(agent_id="not-the-agent-this-was-issued-to")
    with pytest.raises(CallerMismatchError):
        verify_vaid_standing_bound(public_key, doc, RevocationStatus.NOT_REVOKED, wrong_agent)

    wrong_tenant = ExpectedCaller(tenant_id="not-the-tenant")
    with pytest.raises(CallerMismatchError):
        verify_vaid_standing_bound(public_key, doc, RevocationStatus.NOT_REVOKED, wrong_tenant)


def test_caller_binding_never_upgrades_a_failing_verdict() -> None:
    """A mismatched expected caller must not matter when the document itself
    does not verify — the document's own problem is reported, never masked by
    (or mistaken for) a caller-mismatch refusal."""
    _signing_key, doc = _public_key_and_doc()
    wrong_key = ReferenceIssuer.ephemeral(1, "vaid.example").kernel_public_key()
    mismatched = ExpectedCaller(agent_id="someone-else")
    verdict = verify_vaid_standing_bound(wrong_key, doc, RevocationStatus.NOT_REVOKED, mismatched)
    assert verdict is VaidVerdict.ISSUER_MISMATCH


def test_caller_binding_from_json_mirrors_the_dict_entry_point() -> None:
    public_key, doc = _public_key_and_doc()
    document_json = json.dumps(doc)
    expected = ExpectedCaller(agent_id=doc["agent_id"])
    verdict = verify_vaid_standing_bound_from_json(
        public_key, document_json, RevocationStatus.NOT_REVOKED, expected
    )
    assert verdict is VaidVerdict.VALID

    mismatched = ExpectedCaller(agent_id="someone-else")
    with pytest.raises(CallerMismatchError):
        verify_vaid_standing_bound_from_json(
            public_key, document_json, RevocationStatus.NOT_REVOKED, mismatched
        )

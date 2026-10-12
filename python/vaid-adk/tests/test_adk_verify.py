"""Unit tests for vaid_adk._verify.verify_presentation: fixed seeds, fixed
verification time. Mirrors the six scenarios the session brief calls out:
allowed, out-of-scope (capability) denied, expired denied, revoked-parent
denied, missing-VAID denied, wider-than-parent child denied."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_adk import (
    TrustedIssuers,
    VaidPresentation,
    VerifyCode,
    verify_presentation,
)
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    prefix_entry,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import InMemoryRevocationList

_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32)
_PUBLIC = _KEY.public_key().public_bytes_raw()
_THUMBPRINT = kernel_key_thumbprint(_PUBLIC)
_DOMAIN = "vaid.example"
_KEYS = TrustedIssuers.from_raw_keys([(_DOMAIN, _PUBLIC)])
NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _sign(unsigned: dict) -> dict:
    signature = _KEY.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def _doc(
    *,
    parent_vaid: str | None,
    scope: list[str],
    caps: list[str],
    expires_at: str = "2999-01-01T00:00:00Z",
) -> dict:
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-06-01T00:00:00Z",
        expires_at=expires_at,
        public_key_der=list(range(32)),
        parent_vaid=parent_vaid,
        scope_boundary=[prefix_entry(v) for v in scope],
        lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
        capability_set=caps,
        trust_domain="vaid.example",
        kernel_key_thumbprint=_THUMBPRINT,
    )
    return _sign(unsigned)


def _root(scope: list[str], caps: list[str], expires_at: str = "2999-01-01T00:00:00Z") -> dict:
    return _doc(parent_vaid=None, scope=scope, caps=caps, expires_at=expires_at)


def _child(parent: dict, scope: list[str], caps: list[str], expires_at: str = "2999-01-01T00:00:00Z") -> dict:
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id=parent["tenant_id"],
        issued_at="2026-06-01T00:00:00Z",
        expires_at=expires_at,
        public_key_der=list(range(32)),
        parent_vaid=parent["vaid_id"],
        scope_boundary=[prefix_entry(v) for v in scope],
        lineage_hash=compute_lineage_hash(parent["vaid_id"], agent_id),
        capability_set=caps,
        trust_domain="vaid.example",
        kernel_key_thumbprint=_THUMBPRINT,
    )
    return _sign(unsigned)


def _vouching_revocation() -> InMemoryRevocationList:
    return InMemoryRevocationList.assume_nothing_revoked()


def _root_with_boundary(boundary: list[dict], caps: list[str]) -> dict:
    """A root carrying ``boundary`` verbatim and authentically signed over it.
    Separate from :func:`_root`, which types bare strings as ``prefix`` entries;
    these tests need an entry of a kind this verifier does NOT recognise."""
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-06-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=boundary,
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=caps,
        trust_domain="vaid.example",
        kernel_key_thumbprint=_THUMBPRINT,
    )
    return _sign(unsigned)


#: An entry of a kind this verifier does not implement, shaped like the amount
#: limit ADR-0009 names as the motivating future kind — so the case is an entry
#: that NARROWS authority, not a nonsense one.
_FUTURE_KIND_ENTRY = {"kind": "amount_limit", "value": 100}


def test_unknown_scope_kind_is_refused_with_no_requested_resource() -> None:
    """ADR-0009 S.10, and the case that makes the check load-bearing.

    Authentic, unexpired, a root (no attenuation runs over it) and no
    ``requested_resource``, so the leaf's own scope is never consulted. Every
    other gate has nothing to say, and without an explicit evaluability step
    this is ALLOWED while carrying a constraint the verifier could not read."""
    root = _root_with_boundary([_FUTURE_KIND_ENTRY], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=root),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource=None,
        requested_capability=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.UNKNOWN_SCOPE_KIND


def test_unknown_scope_kind_is_not_reported_as_inauthentic() -> None:
    """A verdict over an AUTHENTIC document, not a signature or parse failure
    (ADR-0009 decision 3): calling a correctly signed future-version credential
    forged is false and unactionable."""
    root = _root_with_boundary([_FUTURE_KIND_ENTRY], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=root),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource="data.orders",
        requested_capability="read",
        now=NOW,
    )
    assert result.code is not VerifyCode.INAUTHENTIC
    assert result.code is VerifyCode.UNKNOWN_SCOPE_KIND


def test_one_unreadable_entry_refuses_a_boundary_that_also_matches() -> None:
    """S.10 refuses the WHOLE boundary (ADR-0009 decision 4). The readable
    ``prefix`` entry here does contain the requested resource, so a union
    implemented as "at least one entry matched" would allow the call without
    ever reaching the entry it cannot evaluate."""
    root = _root_with_boundary(
        [prefix_entry("data.orders"), _FUTURE_KIND_ENTRY], ["read"]
    )
    result = verify_presentation(
        VaidPresentation(leaf=root),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource="data.orders",
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.UNKNOWN_SCOPE_KIND


def test_unknown_scope_kind_in_a_presented_ancestor_is_refused() -> None:
    """The check covers the presented chain, not only the leaf. An ancestor
    whose boundary cannot be read bounds nothing this verifier can compute, so
    no child is provably within it."""
    root = _root_with_boundary([_FUTURE_KIND_ENTRY], ["read"])
    child = _child(root, ["data.orders"], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource="data.orders",
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.UNKNOWN_SCOPE_KIND


def test_allowed_tool_call_within_scope_and_capability() -> None:
    root = _root(["data.orders", "data.payments"], ["read", "write"])
    child = _child(root, ["data.orders"], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource="data.orders",
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is True
    assert result.code is VerifyCode.ALLOWED


def test_out_of_scope_capability_is_denied() -> None:
    root = _root(["data.orders", "data.payments"], ["read", "write"])
    child = _child(root, ["data.orders"], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_resource="data.payments",
        requested_capability="write",
        now=NOW,
    )
    assert result.allowed is False
    # scope check (data.payments) fires before capability — either is a correct
    # fail-closed outcome; assert the denial, not which bound tripped first.
    assert result.code in (VerifyCode.OUT_OF_SCOPE, VerifyCode.MISSING_CAPABILITY)


def test_expired_leaf_is_denied() -> None:
    root = _root(["data.orders"], ["read"])
    child = _child(root, ["data.orders"], ["read"], expires_at="2026-01-01T00:00:00Z")
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_capability="read",
        now=NOW,  # 2026-07-01, well after the leaf's 2026-01-01 expiry
    )
    assert result.allowed is False
    assert result.code is VerifyCode.EXPIRED


def test_revoked_parent_denies_the_child() -> None:
    root = _root(["data.orders"], ["read"])
    child = _child(root, ["data.orders"], ["read"])
    revocation = InMemoryRevocationList()
    revocation.revoke(root["vaid_id"])  # revoke the PARENT, not the leaf
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=revocation,
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.REVOKED


def test_missing_vaid_is_denied() -> None:
    result = verify_presentation(
        None,
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.NO_VAID


def test_wider_than_parent_child_is_denied() -> None:
    root = _root(["data.orders"], ["read"])
    # child claims a scope the parent never held
    child = _child(root, ["data.orders", "data.payments"], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=_vouching_revocation(),
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.NOT_ATTENUATED


def test_revocation_unavailable_fails_closed_as_indeterminate() -> None:
    root = _root(["data.orders"], ["read"])
    child = _child(root, ["data.orders"], ["read"])
    result = verify_presentation(
        VaidPresentation(leaf=child, chain=(root,)),
        keys=_KEYS,
        revocation=InMemoryRevocationList(),  # absent store: UNAVAILABLE
        requested_capability="read",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.INDETERMINATE

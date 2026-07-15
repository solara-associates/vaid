"""Revocation-seam and TTL parity tests — the Python mirror of the Rust
``vaid_mint::revocation`` unit tests and the revocation/expiry tests in
``vaid_mint::issuer``.

Covers the seam itself (:class:`NeverRevoked`, :class:`InMemoryRevocationList`),
the issuer's built-in in-memory revoked set, the hard expiry reject, and the
additive layering of an injected backend on top of the built-in set.
"""

from __future__ import annotations

import uuid

from vaid_mint import (
    DEFAULT_VAID_TTL_HOURS,
    InMemoryRevocationList,
    NeverRevoked,
    ReferenceIssuer,
    RevocationCheck,
    is_expired,
)


def issue_root(issuer: ReferenceIssuer) -> dict:
    return issuer.issue_vaid_with_lineage(
        agent_class="root",
        version="1.0.0",
        tenant_id="t",
        parent_vaid=None,
        scope_boundary=[],
        capability_set=[],
    )


# ── the seam types ──


def test_never_revoked_reports_nothing_revoked():
    check = NeverRevoked()
    assert not check.is_revoked(str(uuid.uuid4()))


def test_in_memory_list_reports_only_revoked_ids():
    list_ = InMemoryRevocationList()
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    assert list_.is_empty()
    list_.revoke(a)
    assert list_.is_revoked(a)
    assert not list_.is_revoked(b), "an un-revoked id is not revoked"
    assert len(list_) == 1


def test_seam_implementations_satisfy_the_protocol():
    # ``RevocationCheck`` is runtime_checkable, mirroring the AuthorizationGate
    # convention — both shipped implementations must structurally satisfy it.
    assert isinstance(NeverRevoked(), RevocationCheck)
    assert isinstance(InMemoryRevocationList(), RevocationCheck)


# ── the issuer's built-in set ──


def test_revocation_fails_verification():
    issuer = ReferenceIssuer.ephemeral(1)
    vaid = issue_root(issuer)
    assert issuer.verify_vaid(vaid)
    issuer.revoke(vaid["vaid_id"])
    assert not issuer.verify_vaid(vaid), "a revoked VAID must not verify"


# ── TTL is a hard reject ──


def test_expired_vaid_fails_verification():
    # A negative TTL issues a VAID whose ``expires_at`` is already in the past;
    # its kernel signature is valid but verification must hard-reject it. This
    # mirrors the Rust fixture (`ReferenceIssuer::ephemeral(-1)`) and needs no
    # sleep or time mocking — the suite has no time-mocking convention.
    issuer = ReferenceIssuer.ephemeral(-1)
    vaid = issue_root(issuer)
    assert is_expired(vaid), "fixture must be expired"
    assert not issuer.verify_vaid(
        vaid
    ), "an expired VAID must fail verification even with a valid kernel signature"


def test_unexpired_vaid_is_not_reported_expired():
    issuer = ReferenceIssuer.ephemeral(DEFAULT_VAID_TTL_HOURS)
    vaid = issue_root(issuer)
    assert not is_expired(vaid)
    assert issuer.verify_vaid(vaid)


def test_default_vaid_ttl_hours_matches_the_rust_constant():
    assert DEFAULT_VAID_TTL_HOURS == 1


# ── the injected seam ──


def test_injected_revocation_check_is_consulted():
    list_ = InMemoryRevocationList()
    issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(list_)
    vaid = issue_root(issuer)
    assert issuer.verify_vaid(vaid), "not yet revoked → verifies"
    # Revoke via the injected backend only (not the issuer's built-in set).
    list_.revoke(vaid["vaid_id"])
    assert not issuer.verify_vaid(
        vaid
    ), "an injected revocation backend must be consulted at verification"
    assert not issuer.is_revoked(vaid["vaid_id"]), "built-in set untouched by the injected one"


def test_injected_never_revoked_does_not_break_normal_verification():
    issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(NeverRevoked())
    vaid = issue_root(issuer)
    assert issuer.verify_vaid(vaid)
    # The built-in set still works even with a no-op backend injected.
    issuer.revoke(vaid["vaid_id"])
    assert not issuer.verify_vaid(vaid), "built-in revoked set still enforced"

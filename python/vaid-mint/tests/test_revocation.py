"""Revocation-seam gate (spec ``docs/spec/revocation.md`` R.4) and TTL parity —
the Python mirror of the Rust ``vaid_mint::revocation`` unit tests and
``crates/vaid-mint/tests/revocation_seam.rs``.

Revocation is **outside the conformance surface** (R.1): nothing here is a frozen
vector. :func:`test_cross_language_scenarios` asserts the identical
(scenario -> status) mapping the Rust ``cross_language_scenarios`` test asserts;
the two languages agree by construction, not by a shared artifact.
"""

from __future__ import annotations

from vaid_mint import (
    DEFAULT_VAID_TTL_HOURS,
    InMemoryRevocationList,
    ReferenceIssuer,
    RevocationCheck,
    RevocationStatus,
    is_expired,
)


def issue_root(issuer: ReferenceIssuer, agent_class: str = "root") -> dict:
    return issuer.issue_vaid_with_lineage(
        agent_class=agent_class,
        version="1.0.0",
        tenant_id="t",
        parent_vaid=None,
        scope_boundary=[],
        capability_set=[],
    )


def issue_child(issuer: ReferenceIssuer, parent: dict, agent_class: str = "child") -> dict:
    return issuer.issue_vaid_with_lineage(
        agent_class=agent_class,
        version="1.0.0",
        tenant_id="t",
        parent_vaid=parent["vaid_id"],
        scope_boundary=[],
        capability_set=[],
    )


# ── the store's three states (R.4.3, R.4.6) ──


def test_absent_store_is_unavailable_vouching_store_is_not_revoked():
    absent = InMemoryRevocationList()  # never populated
    assert absent.check_lineage(["x"]) is RevocationStatus.UNAVAILABLE
    empty = InMemoryRevocationList.assume_nothing_revoked()
    assert empty.check_lineage(["x"]) is RevocationStatus.NOT_REVOKED


def test_revoking_makes_a_store_available_and_reports_any_hop():
    store = InMemoryRevocationList()
    store.revoke("root")
    assert store.is_available()
    # Revoked if ANY id in the lineage is revoked, in any position (R.4.4).
    assert store.check_lineage(["root", "leaf"]) is RevocationStatus.REVOKED
    assert store.check_lineage(["leaf"]) is RevocationStatus.NOT_REVOKED


def test_mark_unavailable_flips_back_to_unavailable():
    store = InMemoryRevocationList.assume_nothing_revoked()
    assert store.check_lineage(["x"]) is RevocationStatus.NOT_REVOKED
    store.mark_unavailable()
    assert store.check_lineage(["x"]) is RevocationStatus.UNAVAILABLE


def test_in_memory_list_satisfies_the_protocol():
    assert isinstance(InMemoryRevocationList(), RevocationCheck)


# ── the gate (mirrors revocation_seam.rs) ──


def test1_bypass_revoking_parent_rejects_child():
    """Revoking a parent must revoke a child attenuated from it (R.4.4)."""
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    child = issue_child(issuer, root)

    assert issuer.verify_vaid(child), "child verifies before revocation"
    issuer.revoke(root["vaid_id"])

    assert issuer.revocation_status(child) is RevocationStatus.REVOKED
    assert not issuer.verify_vaid(child), "BYPASS: a child of a revoked parent must not verify"


def test2_restart_truncation_is_unavailable_not_notrevoked():
    """A cleared lineage map (restart) makes a child Unavailable, not NotRevoked."""
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    child = issue_child(issuer, root)
    issuer.revoke(root["vaid_id"])

    issuer.clear_lineage()  # simulate a process restart: resolver state gone

    status = issuer.revocation_status(child)
    assert status is RevocationStatus.UNAVAILABLE, "child with unresolvable parent is Unavailable"
    assert status is not RevocationStatus.NOT_REVOKED, "must NOT silently pass — the point of R.4.2"
    assert not issuer.verify_vaid(child), "fails closed on Unavailable (R.4.5)"


def test3_store_failure_is_unavailable_and_rejects():
    """An unreachable revocation store yields Unavailable and fails closed."""
    issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(
        InMemoryRevocationList.unavailable()
    )
    vaid = issue_root(issuer)

    assert issuer.revocation_status(vaid) is RevocationStatus.UNAVAILABLE
    assert not issuer.verify_vaid(vaid), "fails closed when the store is unavailable"


def test4_rootless_clean_is_notrevoked_and_verifies():
    """A rootless VAID with nothing revoked is NotRevoked and verifies — the case
    tests 1 and 2 must not have broken."""
    issuer = ReferenceIssuer.ephemeral(1)
    vaid = issue_root(issuer)

    assert issuer.revocation_status(vaid) is RevocationStatus.NOT_REVOKED
    assert issuer.verify_vaid(vaid)


def test_cross_language_scenarios():
    """The (scenario -> status) table both languages agree on. Identical to the
    Rust ``cross_language_scenarios`` test."""
    # clean_root: rootless, nothing revoked        -> NOT_REVOKED
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    assert issuer.revocation_status(root) is RevocationStatus.NOT_REVOKED

    # revoked_root: rootless, itself revoked        -> REVOKED
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    issuer.revoke(root["vaid_id"])
    assert issuer.revocation_status(root) is RevocationStatus.REVOKED

    # child_parent_revoked: child of a revoked root -> REVOKED (R.4.4)
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    child = issue_child(issuer, root)
    issuer.revoke(root["vaid_id"])
    assert issuer.revocation_status(child) is RevocationStatus.REVOKED

    # child_clean: child of a clean root            -> NOT_REVOKED
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    child = issue_child(issuer, root)
    assert issuer.revocation_status(child) is RevocationStatus.NOT_REVOKED

    # child_parent_unresolvable: restart truncation -> UNAVAILABLE (R.4.2)
    issuer = ReferenceIssuer.ephemeral(1)
    root = issue_root(issuer)
    child = issue_child(issuer, root)
    issuer.clear_lineage()
    assert issuer.revocation_status(child) is RevocationStatus.UNAVAILABLE

    # store_unavailable: store unreachable          -> UNAVAILABLE (R.4.3)
    issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(
        InMemoryRevocationList.unavailable()
    )
    root = issue_root(issuer)
    assert issuer.revocation_status(root) is RevocationStatus.UNAVAILABLE


# ── TTL parity (unchanged behaviour, kept alongside the seam) ──


def test_revocation_fails_verification():
    issuer = ReferenceIssuer.ephemeral(1)
    vaid = issue_root(issuer)
    assert issuer.verify_vaid(vaid)
    issuer.revoke(vaid["vaid_id"])
    assert not issuer.verify_vaid(vaid), "a revoked VAID must not verify"


def test_expired_vaid_fails_verification():
    # A negative TTL issues a VAID already past its expiry.
    issuer = ReferenceIssuer.ephemeral(-1)
    vaid = issue_root(issuer)
    assert is_expired(vaid), "fixture must be expired"
    assert not issuer.verify_vaid(vaid), "an expired VAID must fail even with a valid signature"


def test_default_vaid_ttl_hours_matches_the_rust_constant():
    assert DEFAULT_VAID_TTL_HOURS == 1

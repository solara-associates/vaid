"""Behavior parity tests — the Python mint mirrors the Rust ``vaid_mint::mint``
unit tests (attenuation matrix, proof-of-possession, the authorization gate, and
end-to-end verify). These are behavioral, not byte-identity; the frozen vector
(``test_mint_conformance.py``) covers cross-language byte-identity of the document.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_mint import (
    DenyAll,
    InMemoryAudit,
    MintService,
    ReferenceIssuer,
    VaidSeed,
    build_mint_pop_payload,
    build_unsigned_vaid_document,
    compute_lineage_hash,
    has_capability,
    is_in_scope,
)
from vaid_mint.error import IdentityError, UnauthorizedError
from vaid_mint.mint_types import MintPop


# ── fixtures / helpers ──


def fixture():
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1)
    return MintService(issuer, audit), audit, issuer


def holder_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pub_bytes(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes_raw()


def make_pop(seed, registered_key, signing_key, nonce, issued_at=None) -> MintPop:
    issued_at = issued_at or utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(
        seed, public_key_der=registered_key, nonce=nonce, issued_at=issued_at
    )
    digest = canonical_request_signing_bytes(payload)
    return MintPop(nonce=nonce, issued_at=issued_at, signature=signing_key.sign(digest))


def byo_seed(public_key_der: bytes) -> VaidSeed:
    return VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="codex",
        scope_boundary=["data.x"],
        capability_set=["read"],
        public_key_der=public_key_der,
    )


def parent_doc(tenant, scope, caps) -> dict:
    vid = str(uuid.uuid4())
    return build_unsigned_vaid_document(
        vaid_id=vid,
        agent_id=vid,
        agent_class="parent",
        version="1.0.0",
        tenant_id=tenant,
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2026-06-05T12:00:00Z",
        public_key_der=[],
        parent_vaid=None,
        scope_boundary=list(scope),
        lineage_hash="lineage",
        capability_set=list(caps),
    )


def child_seed(parent, scope, caps, child_pub) -> VaidSeed:
    return VaidSeed(
        agent_class="child",
        version="1.0.0",
        tenant_id=parent["tenant_id"],
        parent_vaid=parent["vaid_id"],
        scope_boundary=list(scope),
        capability_set=list(caps),
        public_key_der=child_pub,
    )


def signed_child(parent, scope, caps, nonce):
    k = holder_key()
    pub = pub_bytes(k)
    seed = child_seed(parent, scope, caps, pub)
    return seed, make_pop(seed, pub, k, nonce)


# ── mint_root ──


def test_root_generate_and_discard_mints_and_audits():
    svc, audit, _ = fixture()
    seed = VaidSeed(
        agent_class="researcher",
        version="1.0.0",
        tenant_id="codex",
        scope_boundary=["data.governance"],
        capability_set=["read.documents"],
    )
    vaid = svc.mint_root(seed)
    assert vaid["agent_class"] == "researcher"
    assert vaid["scope_boundary"] == ["data.governance"]
    assert vaid["parent_vaid"] is None
    assert len(audit.entries) == 1
    assert audit.entries[0].details["delegated"] is False


def test_root_byo_key_with_valid_pop_binds_key():
    svc, audit, _ = fixture()
    k = holder_key()
    registered = pub_bytes(k)
    seed = byo_seed(registered)
    pop = make_pop(seed, registered, k, "nonce-aaa")
    vaid = svc.mint_root(seed, pop)
    assert bytes(vaid["public_key_der"]) == registered
    assert audit.entries[0].details["byo_key"] is True


def test_root_byo_key_with_pop_for_different_key_is_rejected():
    svc, audit, _ = fixture()
    victim, attacker = holder_key(), holder_key()
    victim_pub = pub_bytes(victim)
    seed = byo_seed(victim_pub)
    pop = make_pop(seed, victim_pub, attacker, "nonce-bbb")  # signed by attacker
    with pytest.raises(IdentityError, match="does not verify"):
        svc.mint_root(seed, pop)
    assert audit.is_empty()


def test_root_byo_key_without_pop_is_rejected():
    svc, _, _ = fixture()
    seed = byo_seed(pub_bytes(holder_key()))
    with pytest.raises(IdentityError, match="proof-of-possession required"):
        svc.mint_root(seed, None)


def test_root_byo_key_replay_is_rejected():
    svc, _, _ = fixture()
    k = holder_key()
    registered = pub_bytes(k)
    seed = byo_seed(registered)
    pop = make_pop(seed, registered, k, "nonce-replay")
    svc.mint_root(seed, pop)
    with pytest.raises(IdentityError, match="replay"):
        svc.mint_root(seed, pop)


def test_root_mint_denied_by_gate_has_no_side_effects():
    audit = InMemoryAudit()
    svc = MintService(ReferenceIssuer.ephemeral(1), audit, DenyAll())
    seed = VaidSeed(agent_class="x", version="1.0.0", tenant_id="codex")
    with pytest.raises(UnauthorizedError, match="denied by gate"):
        svc.mint_root(seed)
    assert audit.is_empty()


# ── mint_child — attenuated delegation ──


def test_child_within_bounds_is_minted_with_lineage_and_delegated_audit():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read", "write"])
    seed, pop = signed_child(parent, ["data.aifactory.sub"], ["read"], "ok-1")
    vaid = svc.mint_child(seed, parent, pop)
    assert vaid["parent_vaid"] == parent["vaid_id"]
    assert audit.entries[0].details["delegated"] is True
    assert audit.entries[0].details["attenuation_verified"] is True


def test_child_scope_exceeding_parent_is_denied():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    seed, pop = signed_child(parent, ["data.somewhere-else"], ["read"], "deny-scope")
    with pytest.raises(UnauthorizedError, match="scope_boundary exceeds"):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty()


def test_empty_child_scope_under_restricted_parent_is_denied():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    seed, pop = signed_child(parent, [], ["read"], "deny-empty-scope")
    with pytest.raises(UnauthorizedError, match="scope_boundary exceeds"):
        svc.mint_child(seed, parent, pop)


def test_empty_parent_scope_permits_any_child_scope():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", [], ["read"])
    s1, p1 = signed_child(parent, ["data.anything"], ["read"], "u-1")
    svc.mint_child(s1, parent, p1)
    s2, p2 = signed_child(parent, [], ["read"], "u-2")
    svc.mint_child(s2, parent, p2)


def test_child_caps_exceeding_parent_are_denied():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    seed, pop = signed_child(parent, ["data.aifactory.sub"], ["read", "write"], "deny-caps")
    with pytest.raises(UnauthorizedError, match="capability_set exceeds"):
        svc.mint_child(seed, parent, pop)


def test_empty_parent_caps_may_delegate_nothing_but_empty_child_caps_ok():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", [], [])
    s1, p1 = signed_child(parent, [], ["read"], "caps-deny")
    with pytest.raises(UnauthorizedError, match="capability_set exceeds"):
        svc.mint_child(s1, parent, p1)
    s2, p2 = signed_child(parent, [], [], "caps-ok")
    svc.mint_child(s2, parent, p2)


def test_cross_tenant_child_is_denied():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    k = holder_key()
    pub = pub_bytes(k)
    seed = child_seed(parent, ["data.aifactory.sub"], ["read"], pub)
    seed.tenant_id = "codex"  # forge a foreign tenant
    pop = make_pop(seed, pub, k, "forge-tenant")
    with pytest.raises(UnauthorizedError, match="cross-tenant delegation is denied"):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty()


def test_child_claiming_a_different_parent_vaid_is_denied():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    k = holder_key()
    pub = pub_bytes(k)
    seed = child_seed(parent, ["data.aifactory.sub"], ["read"], pub)
    seed.parent_vaid = str(uuid.uuid4())  # forge a different parent
    pop = make_pop(seed, pub, k, "forge-parent")
    with pytest.raises(UnauthorizedError, match="parent_vaid"):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty()


def test_mint_child_without_parent_context_is_denied():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    seed, pop = signed_child(parent, ["data.aifactory.sub"], ["read"], "no-parent")
    with pytest.raises(UnauthorizedError, match="no verified parent VAID"):
        svc.mint_child(seed, None, pop)


def test_mint_child_without_byo_key_is_denied():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    seed = child_seed(parent, ["data.aifactory.sub"], ["read"], None)
    with pytest.raises(IdentityError, match="BYO-key required"):
        svc.mint_child(seed, parent, None)


def test_rejected_attenuation_does_not_consume_the_pop_nonce():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read"])
    # Scope-exceeding request with nonce "N" → denied at attenuation, before insert.
    s_denied, p_denied = signed_child(parent, ["data.elsewhere"], ["read"], "N")
    with pytest.raises(UnauthorizedError):
        svc.mint_child(s_denied, parent, p_denied)
    # A VALID request reusing nonce "N" now succeeds — "N" was never consumed.
    s_ok, p_ok = signed_child(parent, ["data.aifactory.sub"], ["read"], "N")
    svc.mint_child(s_ok, parent, p_ok)


def test_minted_child_verifies_and_is_contained_by_parent():
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1)
    svc = MintService(issuer, audit)
    parent = parent_doc("aifactory", ["data.aifactory"], ["read", "write"])
    seed, pop = signed_child(parent, ["data.aifactory.reports"], ["read"], "e2e")
    child = svc.mint_child(seed, parent, pop)

    assert issuer.verify_vaid(child)
    assert all(is_in_scope(parent, s) for s in child["scope_boundary"])
    assert all(has_capability(parent, c) for c in child["capability_set"])
    # sanity: the derived lineage_hash on the child is self-consistent
    assert child["lineage_hash"] == compute_lineage_hash(child["parent_vaid"], child["agent_id"])

"""Behavior parity tests — the Python mint mirrors the Rust ``vaid_mint::mint``
unit tests (attenuation matrix, proof-of-possession, the authorization gate, and
end-to-end verify). These are behavioral, not byte-identity; the frozen vector
(``test_mint_conformance.py``) covers cross-language byte-identity of the document.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_mint.document import (
    canonical_vaid_signing_bytes,
    entry_claimed_resource,
    is_well_formed_scope_boundary,
    prefix_entry,
)
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
    validate_max_delegation_depth,
)
from vaid_mint.error import ConfigError, IdentityError, MintError, UnauthorizedError
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.mint_types import MintPop
from vaid_mint.revocation import (
    MAX_LINEAGE_DEPTH,
    InMemoryRevocationList,
    ParentResolution,
    RevocationBackend,
    RevocationStatus,
)
from vaid_mint.verify import (
    VaidVerdict,
    parse_vaid_document,
    verify_vaid_authenticity,
    verify_vaid_standing,
)


# ── fixtures / helpers ──


def fixture():
    audit = InMemoryAudit()
    # `assuming_nothing_revoked()` because these tests are about minting, attenuation
    # and scope containment. Since 0.9.0 a bare issuer's revocation store is absent,
    # so `verify_vaid` would fail closed on UNAVAILABLE regardless of what the child's
    # scope says — a rejection for the wrong reason.
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
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
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.x")],
        capability_set=["read"],
        public_key_der=public_key_der,
    )


def parent_doc(tenant, scope, caps) -> dict:
    """``scope`` is given as bare strings for readability and normalised to
    ``prefix`` entries here, exactly as :func:`child_seed` does."""
    vid = str(uuid.uuid4())
    return build_unsigned_vaid_document(
        vaid_id=vid,
        agent_id=vid,
        agent_class="parent",
        version="1.0.0",
        tenant_id=tenant,
        issued_at="2026-06-04T12:00:00Z",
        # Far-future by convention (verdict_v1: "pinned by distance, not by a
        # clock"). This fixture carried 2026-06-05, a date that was future when
        # it was written and is past now — so every delegation below was a
        # delegation from an ALREADY-EXPIRED parent, which only passed because
        # nothing compared the two expiries (vaid#79).
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=[],
        parent_vaid=None,
        scope_boundary=[e if isinstance(e, dict) else prefix_entry(e) for e in scope],
        lineage_hash="lineage",
        capability_set=list(caps),
        trust_domain="vaid.example",
        kernel_key_thumbprint=kernel_key_thumbprint(bytes(32)),
    )


def child_seed(parent, scope, caps, child_pub) -> VaidSeed:
    """``scope`` is given as bare strings for readability and normalised to
    ``prefix`` entries here. The test fixture is the only place that conversion
    lives; the mint itself takes typed entries (S.8)."""
    return VaidSeed(
        agent_class="child",
        version="1.0.0",
        tenant_id=parent["tenant_id"],
        parent_vaid=parent["vaid_id"],
        scope_boundary=[e if isinstance(e, dict) else prefix_entry(e) for e in scope],
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
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.governance")],
        capability_set=["read.documents"],
    )
    vaid = svc.mint_root(seed)
    assert vaid["agent_class"] == "researcher"
    assert vaid["scope_boundary"] == [prefix_entry("data.governance")]
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
    svc = MintService(ReferenceIssuer.ephemeral(1, "vaid.example"), audit, DenyAll())
    seed = VaidSeed(agent_class="x", version="1.0.0", tenant_id="acme")
    with pytest.raises(UnauthorizedError, match="denied by gate"):
        svc.mint_root(seed)
    assert audit.is_empty()


# ── mint_child — attenuated delegation ──


def test_child_within_bounds_is_minted_with_lineage_and_delegated_audit():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory"], ["read", "write"])
    seed, pop = signed_child(parent, ["data.aifactory.sub"], ["read"], "ok-1")
    vaid = svc.mint_child(seed, parent, pop).vaid
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
    seed.tenant_id = "acme"  # forge a foreign tenant
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


# ── DELEGATION-DEPTH ENFORCEMENT (0.11.0): default 1, configurable. ──


def mint_real_root(svc: MintService, tenant_id: str) -> dict:
    """Mint a real root through ``svc``, so the issuer's lineage map records it
    as a known root. Depth checking beyond the immediate parent walks that
    map, and a hand-built document the issuer never minted resolves as
    unknown there, not as a root — so any test exercising depth > 1 must
    build its whole chain through the mint, never through ``parent_doc``."""
    return svc.mint_root(
        VaidSeed(
            agent_class="root",
            version="1.0.0",
            tenant_id=tenant_id,
            scope_boundary=[prefix_entry("data.aifactory")],
            capability_set=["read"],
        )
    )


def mint_real_child(svc: MintService, parent: dict, nonce: str) -> dict:
    """Mint a real child of ``parent`` through ``svc``, so the issuer's
    lineage map actually records the hop."""
    seed, pop = signed_child(parent, ["data.aifactory"], ["read"], nonce)
    return svc.mint_child(seed, parent, pop).vaid


def test_default_depth_mints_a_root_child_but_refuses_a_grandchild():
    svc, audit, _ = fixture()  # default max_delegation_depth == 1
    root = mint_real_root(svc, "aifactory")

    # Root (depth 0) -> child (depth 1): allowed.
    child = mint_real_child(svc, root, "root-to-child")
    events_after_child = len(audit.entries)
    assert events_after_child == 2  # root mint + child mint

    # Child (depth 1) -> grandchild (depth 2): refused — exceeds the
    # default max_delegation_depth of 1.
    seed, pop = signed_child(child, ["data.aifactory"], ["read"], "child-to-grandchild")
    with pytest.raises(UnauthorizedError, match="delegation depth"):
        svc.mint_child(seed, child, pop)
    assert len(audit.entries) == events_after_child, "no grandchild minted"


def test_a_root_child_is_always_allowed_regardless_of_configured_depth():
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    svc = MintService(issuer, InMemoryAudit(), max_delegation_depth=1)
    root = mint_real_root(svc, "aifactory")
    child = mint_real_child(svc, root, "root-to-child-explicit-1")
    assert child["parent_vaid"] == root["vaid_id"]


def test_depth_2_mints_a_grandchild_but_refuses_a_great_grandchild():
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    svc = MintService(issuer, InMemoryAudit(), max_delegation_depth=2)
    root = mint_real_root(svc, "aifactory")
    child = mint_real_child(svc, root, "depth2-root-to-child")
    # Grandchild (depth 2): allowed under max_delegation_depth = 2.
    grandchild = mint_real_child(svc, child, "depth2-child-to-grandchild")
    assert grandchild["parent_vaid"] == child["vaid_id"]

    # Great-grandchild (depth 3): refused.
    seed, pop = signed_child(
        grandchild, ["data.aifactory"], ["read"], "depth2-grandchild-to-greatgrandchild"
    )
    with pytest.raises(UnauthorizedError, match="delegation depth"):
        svc.mint_child(seed, grandchild, pop)


def test_depth_refusal_happens_before_any_lineage_write():
    """A depth-exceeding mint_child must be refused before the issuer does any
    key work or lineage write — proven the same way the PoP-nonce ordering
    tests do: the audit sink stays empty and the parent's own lineage record
    is unaffected."""
    svc, audit, _ = fixture()
    root = mint_real_root(svc, "aifactory")
    child = mint_real_child(svc, root, "before-write-root-to-child")
    events_before = len(audit.entries)

    seed, pop = signed_child(
        child, ["data.aifactory"], ["read"], "before-write-child-to-grandchild"
    )
    with pytest.raises(UnauthorizedError):
        svc.mint_child(seed, child, pop)
    assert len(audit.entries) == events_before, "a refused mint must not audit a mint"


# ── max_delegation_depth VALIDATION: fails closed at construction, never
#    "unlimited". ──


def test_max_delegation_depth_zero_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(0)


def test_max_delegation_depth_negative_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(-1)


def test_max_delegation_depth_float_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(1.5)


def test_max_delegation_depth_nan_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(float("nan"))


def test_max_delegation_depth_infinity_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(float("inf"))


def test_max_delegation_depth_none_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(None)


def test_max_delegation_depth_string_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth("1")


def test_max_delegation_depth_bool_is_rejected():
    # bool is a subclass of int in Python — must be explicitly excluded, or
    # True/False would silently pass as 1/0.
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(True)


def test_max_delegation_depth_above_the_lineage_bound_is_rejected():
    with pytest.raises(ConfigError):
        validate_max_delegation_depth(MAX_LINEAGE_DEPTH + 1)


def test_max_delegation_depth_at_the_lineage_bound_is_accepted():
    assert validate_max_delegation_depth(MAX_LINEAGE_DEPTH) == MAX_LINEAGE_DEPTH


def test_max_delegation_depth_one_is_accepted():
    assert validate_max_delegation_depth(1) == 1


def test_constructing_a_mint_with_an_invalid_depth_fails_closed():
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    with pytest.raises(ConfigError):
        MintService(issuer, InMemoryAudit(), max_delegation_depth=0)


# ── DELEGATION DEPTH FAILS CLOSED when ancestry cannot be fully resolved
#    (334 follow-up, 14 Oct 2026). Four properties: ──


def doc_with_parent(tenant: str, parent_vaid: str) -> dict:
    """A hand-built doc with no mint behind it, carrying ``parent_vaid``. Depth
    checking must never need the referenced parent to actually exist anywhere;
    it only needs the LEAF's own signed field, which is why this is enough for
    every test below."""
    vid = str(uuid.uuid4())
    return build_unsigned_vaid_document(
        vaid_id=vid,
        agent_id=vid,
        agent_class="child",
        version="1.0.0",
        tenant_id=tenant,
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=[],
        parent_vaid=parent_vaid,
        scope_boundary=[prefix_entry("data.aifactory")],
        lineage_hash="lineage",
        capability_set=["read"],
        trust_domain="vaid.example",
        kernel_key_thumbprint=kernel_key_thumbprint(bytes(32)),
    )


def fresh_vaid_id() -> str:
    """A fresh, unique id to name as "the parent" below — nothing is ever
    minted for it."""
    return str(uuid.uuid4())


def test_depth_1_refuses_when_the_grandparent_cannot_be_resolved_after_a_restart():
    """1. RESTART TRUNCATION, default depth 1. A real root -> child chain is
    minted, then the issuer's lineage map is cleared (the ops/test primitive
    that models a process restart). ``child``'s OWN document still names its
    parent, but the map can no longer vouch that the named parent is a
    genuine root. The naive bug this guards is treating "can't resolve" as
    "assume it's a root", which would wrongly compute parent_depth = 0 here
    and ALLOW the mint. The correct answer is incomplete assembly, and
    refusal."""
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    audit = InMemoryAudit()
    svc = MintService(issuer, audit)  # default depth 1
    root = mint_real_root(svc, "aifactory")
    child = mint_real_child(svc, root, "restart-root-to-child")

    issuer.clear_lineage()  # "process restart": the map forgets everything

    seed, pop = signed_child(
        child, ["data.aifactory"], ["read"], "restart-child-to-grandchild"
    )
    with pytest.raises(UnauthorizedError, match="could not be determined"):
        svc.mint_child(seed, child, pop)


def test_depth_2_refuses_when_an_ancestor_beyond_the_first_hop_is_unresolvable():
    """2. An ancestor SEVERAL HOPS UP is unresolvable, after resolution has
    already succeeded partway. A naive implementation might stop at the
    first unresolved hop and accept the chain built so far as complete
    (treating it as shorter than it really is). Here the resolver knows
    ``child``'s parent is ``root`` (one hop resolves cleanly) but has no
    record of ``root`` itself, so the assembly must still fail as a whole,
    never settle for "2 hops, that's enough"."""

    class PartialLineageStore:
        def __init__(self, known: dict[str, ParentResolution]) -> None:
            self._known = known

        def record(self, vaid_id: str, parent: str | None) -> None:
            pass

        def resolve_parent(self, vaid_id: str) -> ParentResolution:
            return self._known.get(vaid_id, ParentResolution.unknown())

    root_id = fresh_vaid_id()
    child = doc_with_parent("aifactory", root_id)
    grandchild = doc_with_parent("aifactory", child["vaid_id"])

    # The resolver knows child -> root (one hop resolves), but has NO entry
    # for root_id at all: it cannot vouch root is a genuine root, nor
    # resolve any further. This must be incomplete, not "stop here".
    store = PartialLineageStore({child["vaid_id"]: ParentResolution.of_parent(root_id)})

    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").with_revocation_backend(
        RevocationBackend(
            check=InMemoryRevocationList.assume_nothing_revoked(), lineage=store
        )
    )
    svc = MintService(issuer, InMemoryAudit(), max_delegation_depth=2)

    seed, pop = signed_child(
        grandchild,
        ["data.aifactory"],
        ["read"],
        "partial-grandchild-to-greatgrandchild",
    )
    with pytest.raises(UnauthorizedError, match="could not be determined"):
        svc.mint_child(seed, grandchild, pop)


def test_depth_1_refuses_regardless_of_what_a_lying_resolver_claims():
    """3. The CHEAP, STATE-INDEPENDENT rule at depth 1: if the presented
    parent's own document names a ``parent_vaid`` at all, the mint must
    refuse, regardless of what the lineage resolver answers about that
    named id. Proven with a deliberately WRONG resolver that claims every
    id is a genuine root: even then, the presented parent's OWN
    ``parent_vaid`` field contributes one guaranteed hop the resolver did
    not invent, so the assembled chain is still length 2 and depth 1 is
    still exceeded."""

    class AlwaysRootLineageStore:
        def record(self, vaid_id: str, parent: str | None) -> None:
            pass

        def resolve_parent(self, vaid_id: str) -> ParentResolution:
            return ParentResolution.root()  # wrong for every id but a real root

    root_id = fresh_vaid_id()
    child_as_parent = doc_with_parent("aifactory", root_id)

    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").with_revocation_backend(
        RevocationBackend(
            check=InMemoryRevocationList.assume_nothing_revoked(),
            lineage=AlwaysRootLineageStore(),
        )
    )
    svc = MintService(issuer, InMemoryAudit())  # default depth 1

    seed, pop = signed_child(
        child_as_parent,
        ["data.aifactory"],
        ["read"],
        "lying-resolver-depth-2-attempt",
    )
    with pytest.raises(UnauthorizedError, match="delegation depth"):
        svc.mint_child(seed, child_as_parent, pop)


def test_depth_check_refuses_with_the_existing_typed_error_on_a_lineage_store_failure():
    """4. A lineage READ failure (the store cannot be consulted at all, not
    merely "doesn't know this id yet") refuses with the SAME typed error as
    every other denial in mint_child: UnauthorizedError, never a silent
    allow and never an unhandled exception escaping. Modelled by a resolver
    that always answers "unknown" — the only representable "failure" a
    resolver can report, mirroring how revocation fails closed: there is no
    distinct "errored" case to swallow, UNKNOWN is the fail-closed signal."""

    class FailingLineageStore:
        def record(self, vaid_id: str, parent: str | None) -> None:
            pass

        def resolve_parent(self, vaid_id: str) -> ParentResolution:
            return ParentResolution.unknown()

    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").with_revocation_backend(
        RevocationBackend(
            check=InMemoryRevocationList.assume_nothing_revoked(),
            lineage=FailingLineageStore(),
        )
    )
    audit = InMemoryAudit()
    svc = MintService(issuer, audit)

    root_id = fresh_vaid_id()
    parent = doc_with_parent("aifactory", root_id)
    seed, pop = signed_child(parent, ["data.aifactory"], ["read"], "store-failure-attempt")

    with pytest.raises(UnauthorizedError):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty(), "a refused mint must not audit a mint"


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
    # Vouching: the subject is attenuation and scope containment, not the 0.9.0
    # fail-closed default (see test_revocation.py::test_cross_language_scenarios).
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    svc = MintService(issuer, audit)
    # Mint a REAL parent root through the issuer, so its lineage is recorded and the
    # child's ancestry is resolvable at verification (R.4.2). A synthetic parent
    # never minted here would — correctly — leave the child's lineage incomplete and
    # fail closed.
    parent = svc.mint_root(
        VaidSeed(
            agent_class="parent",
            version="1.0.0",
            tenant_id="aifactory",
            scope_boundary=[prefix_entry("data.aifactory")],
            capability_set=["read", "write"],
        )
    )
    seed, pop = signed_child(parent, ["data.aifactory.reports"], ["read"], "e2e")
    child = svc.mint_child(seed, parent, pop).vaid

    assert issuer.verify_vaid(child)
    assert all(
        is_in_scope(parent, entry_claimed_resource(e)) for e in child["scope_boundary"]
    )
    assert all(has_capability(parent, c) for c in child["capability_set"])
    # sanity: the derived lineage_hash on the child is self-consistent
    assert child["lineage_hash"] == compute_lineage_hash(child["parent_vaid"], child["agent_id"])


# ── expiry containment at mint (vaid#79) ──


def _parent_expiring_in(seconds: int) -> dict:
    """A parent whose expiry sits ``seconds`` either side of now. Anchored to the
    clock rather than to a hard-coded date, because a hard-coded date is how this
    file's own parent fixture quietly became an expired parent."""
    p = parent_doc("acme", ["data.x"], ["read"])
    p["expires_at"] = (
        datetime.now(timezone.utc) + timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return p


def test_a_child_is_clamped_to_its_parents_expiry():
    """The mint half of vaid#79. The issuer's TTL is an hour; the parent has ten
    minutes left; the child gets the parent's expiry, not the issuer's."""
    svc, _, issuer = fixture()  # ReferenceIssuer.ephemeral(1, ...) — a 1-hour TTL
    parent = _parent_expiring_in(600)

    seed, pop = signed_child(parent, ["data.x"], ["read"], "clamp-1")
    child = svc.mint_child(seed, parent, pop).vaid

    assert child["expires_at"] == parent["expires_at"], (
        "the child must end exactly when its parent does, not an hour later"
    )


def test_a_child_keeps_the_issuer_ttl_when_it_is_the_earlier_bound():
    """THE CONTROL on the clamp. A clamp that always returned the parent's expiry
    would pass the test above and would be wrong: the issuer's own TTL still binds
    when it is the shorter of the two. Without this case, `min` and `parent` are
    indistinguishable."""
    svc, _, _ = fixture()
    parent = _parent_expiring_in(86_400)  # a day out; the issuer's TTL is an hour

    seed, pop = signed_child(parent, ["data.x"], ["read"], "clamp-2")
    child = svc.mint_child(seed, parent, pop).vaid

    assert child["expires_at"] < parent["expires_at"], (
        "the issuer's TTL is the earlier bound here and must still apply"
    )


def test_delegation_works_across_a_second_boundary():
    """The regression this policy exists for. Under a refuse-instead-of-clamp rule,
    ONE issuer with ONE TTL could only delegate inside the same whole second as the
    parent's mint: `expires = now + ttl` is re-evaluated at every mint, so a child
    minted a second later outlived its parent by a second and was refused. Measured,
    not assumed — this test sleeps past a second boundary."""
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    svc = MintService(issuer, audit)
    parent = svc.mint_root(
        VaidSeed(
            agent_class="parent",
            version="1.0.0",
            tenant_id="aifactory",
            scope_boundary=[prefix_entry("data.aifactory")],
            capability_set=["read"],
        )
    )

    time.sleep(1.1)

    seed, pop = signed_child(parent, ["data.aifactory"], ["read"], "boundary")
    child = svc.mint_child(seed, parent, pop).vaid

    assert child["expires_at"] <= parent["expires_at"]


def test_delegating_from_an_already_expired_parent_is_refused():
    """The one case a clamp cannot answer: the ceiling is in the past, so the child
    would be issued dead. Refused before the PoP, with both expiries named."""
    svc, _, _ = fixture()
    parent = _parent_expiring_in(-60)

    seed, pop = signed_child(parent, ["data.x"], ["read"], "dead-parent")
    with pytest.raises(UnauthorizedError) as e:
        svc.mint_child(seed, parent, pop)

    message = str(e.value)
    assert parent["expires_at"] in message, (
        "the refusal must name the parent's expiry — a caller that cannot see which "
        "bound it hit has to guess"
    )
    assert "expired" in message


def test_an_unreadable_parent_expiry_refuses_the_delegation():
    """Fail closed: an expiry that cannot be read is expired, so it is refused by
    the same line rather than clamped to a ceiling nobody can evaluate."""
    svc, _, _ = fixture()
    parent = parent_doc("acme", ["data.x"], ["read"])
    parent["expires_at"] = "whenever"

    seed, pop = signed_child(parent, ["data.x"], ["read"], "unreadable")
    with pytest.raises(UnauthorizedError):
        svc.mint_child(seed, parent, pop)


def test_refusing_a_dead_parent_does_not_consume_the_pop_nonce():
    """The refusal sits with the other containment checks, BEFORE the PoP, so a
    caller that renews the parent and retries is not denied for the wrong reason."""
    svc, _, _ = fixture()
    dead = _parent_expiring_in(-60)
    live = _parent_expiring_in(600)

    seed, pop = signed_child(dead, ["data.x"], ["read"], "shared-nonce")
    with pytest.raises(UnauthorizedError):
        svc.mint_child(seed, dead, pop)

    seed_ok, pop_ok = signed_child(live, ["data.x"], ["read"], "shared-nonce")
    assert svc.mint_child(seed_ok, live, pop_ok).vaid["vaid_id"]


def test_an_issuer_that_ignores_the_ceiling_is_caught_and_the_child_withheld():
    """Step 7a. `not_after` is an instruction to a seam a deployment supplies; the
    invariant is a property of the document. An issuer written before this rule — or
    one that simply gets it wrong — must not be able to put an over-long child into
    circulation through this mint."""
    svc, _, issuer = fixture()
    parent = _parent_expiring_in(600)

    class IgnoresTheCeiling:
        """Delegates everything to the real issuer but drops the ceiling."""

        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def issue_vaid_with_key(self, **kwargs):
            kwargs.pop("not_after", None)
            return self._inner.issue_vaid_with_key(**kwargs)

    svc._issuer = IgnoresTheCeiling(issuer)
    seed, pop = signed_child(parent, ["data.x"], ["read"], "bad-issuer")

    with pytest.raises(UnauthorizedError) as e:
        svc.mint_child(seed, parent, pop)
    assert "not_after" in str(e.value)


def test_the_root_path_is_unclamped():
    """A root has no parent to be contained by, so nothing bounds its TTL. Stated as
    a test because a clamp applied indiscriminately would silently shorten every
    root mint in the estate."""
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example")
    svc = MintService(issuer, InMemoryAudit())

    root = svc.mint_root(
        VaidSeed(
            agent_class="root",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=[prefix_entry("data.acme")],
            capability_set=["read"],
        )
    )

    issued = datetime.strptime(root["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.strptime(root["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    assert expires - issued == timedelta(hours=1), "the issuer's full TTL applies"


# ── the clamp is visible to the caller, not only in a shorter expires_at ──


def test_a_clamped_child_says_so_on_the_response():
    """A silent shortening was the objection to clamping. `expires_at` alone looks
    like an ordinary expiry: a caller would have to know the issuer's TTL and
    subtract to notice its delegation had been cut short. The response says it."""
    svc, _, _ = fixture()  # ReferenceIssuer.ephemeral(1, ...) — a 1-hour TTL
    parent = _parent_expiring_in(600)  # ten minutes left

    seed, pop = signed_child(parent, ["data.x"], ["read"], "visible-1")
    response = svc.mint_child(seed, parent, pop)

    assert response.expiry_bounded_by_parent is True
    assert response.parent_expires_at == parent["expires_at"]
    assert response.vaid["expires_at"] == parent["expires_at"]


def test_an_unclamped_child_says_that_too():
    """THE CONTROL. A flag that is always true carries no information, and would
    pass the test above while telling a caller nothing. Here the issuer's own TTL is
    the earlier bound, nothing was taken away, and the flag must be false."""
    svc, _, _ = fixture()
    parent = _parent_expiring_in(86_400)  # a day out; the issuer's TTL is an hour

    seed, pop = signed_child(parent, ["data.x"], ["read"], "visible-2")
    response = svc.mint_child(seed, parent, pop)

    assert response.expiry_bounded_by_parent is False
    assert response.parent_expires_at == parent["expires_at"]
    assert response.vaid["expires_at"] < parent["expires_at"]


def test_the_clamp_is_recorded_in_the_audit_trail():
    """A caller that ignores the response still leaves a record. Without this, the
    only evidence that a credential was deliberately shortened would be the caller's
    own memory of a field it did not read."""
    svc, audit, _ = fixture()
    parent = _parent_expiring_in(600)

    seed, pop = signed_child(parent, ["data.x"], ["read"], "visible-3")
    svc.mint_child(seed, parent, pop)

    entry = audit.entries[-1].details
    assert entry["expiry_bounded_by_parent"] is True
    assert entry["expires_at"] == parent["expires_at"]
    assert entry["parent_expires_at"] == parent["expires_at"]


# ── S.8 well-formedness: the producer refuses what the wire parser would ──
#
# These exist because the two disagreed. Python has no string-to-entry coercion
# (Rust's `From<&str> for ScopeBoundaryEntry` has no Python twin), so the
# pre-0.10.0 spelling `scope_boundary=["data.acme"]` was carried through the
# mint, signed, and accepted by `verify_vaid`, and refused only by
# `parse_vaid_document` once the credential was read back off the wire. A
# producer could mint an unparseable credential and be told it was fine.
#
# Every case below uses the SAME predicate the wire parser uses
# (`is_well_formed_scope_boundary`), so there is one rule and not a mint-time
# copy of it.

#: The malformed shapes S.8 names, each a separate reason to refuse.
MALFORMED_BOUNDARIES = [
    pytest.param(["data.acme"], id="bare-v3-string"),
    pytest.param([{"kind": "prefix"}], id="missing-value"),
    pytest.param([{"value": "data.acme"}], id="missing-kind"),
    pytest.param([{"kind": "prefix", "value": "data.acme", "max": 5}], id="extra-member"),
    pytest.param([{"kind": "", "value": "data.acme"}], id="empty-kind"),
    pytest.param([{"kind": "prefix", "value": 100}], id="prefix-value-not-a-string"),
    pytest.param([prefix_entry("data.acme"), "data.other"], id="one-good-one-bare"),
    pytest.param("data.acme", id="boundary-not-a-list"),
    # `null` is malformed, NOT "absent". An ABSENT boundary is legitimate and
    # normalises to [] (unrestricted, E.7), which is why the seed default is a
    # real list. Collapsing null into absent would make a caller passing null
    # mint the WIDEST possible boundary from a value the spec calls malformed.
    # TypeScript had exactly that bug via `??`, caught by this vector case.
    pytest.param(None, id="boundary-is-null"),
]


@pytest.mark.parametrize("boundary", MALFORMED_BOUNDARIES)
def test_mint_root_refuses_a_malformed_scope_boundary(boundary) -> None:
    mint, _audit, _issuer = fixture()
    with pytest.raises(MintError):
        mint.mint_root(
            VaidSeed(
                agent_class="orchestrator",
                version="1.0.0",
                tenant_id="acme",
                scope_boundary=boundary,
                capability_set=["read"],
            )
        )


@pytest.mark.parametrize("boundary", MALFORMED_BOUNDARIES)
def test_mint_child_refuses_a_malformed_scope_boundary(boundary) -> None:
    mint, _audit, _issuer = fixture()
    parent = parent_doc("acme", ["data.acme"], ["read"])
    k = holder_key()
    seed = VaidSeed(
        agent_class="child",
        version="1.0.0",
        tenant_id="acme",
        parent_vaid=parent["vaid_id"],
        scope_boundary=boundary,
        capability_set=["read"],
        public_key_der=pub_bytes(k),
    )
    with pytest.raises(MintError):
        mint.mint_child(seed, parent)


def test_mint_root_refusal_signs_nothing_and_records_nothing() -> None:
    """The refusal is before any key work and before the audit record, so a
    rejected mint leaves no trace and consumes no nonce."""
    mint, audit, _issuer = fixture()
    with pytest.raises(MintError):
        mint.mint_root(
            VaidSeed(
                agent_class="orchestrator",
                version="1.0.0",
                tenant_id="acme",
                scope_boundary=["data.acme"],
                capability_set=["read"],
            )
        )
    assert audit.entries == []


#: A fixed kernel seed, so these tests hold the signing key and can sign a
#: hand-built document the issuer will then be asked to verify.
_SIGNING_SEED = bytes([0x5A]) * 32


def _signing_fixture():
    key = Ed25519PrivateKey.from_private_bytes(_SIGNING_SEED)
    issuer = ReferenceIssuer.from_seed(
        _SIGNING_SEED, 1, "vaid.example"
    ).assuming_nothing_revoked()
    return key, issuer


def _hand_built(key, issuer, boundary) -> dict:
    """An authentically signed document carrying ``boundary`` verbatim. Signed
    over its own bytes, so a denial cannot be a signature failure in disguise."""
    vid = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=vid,
        agent_id=vid,
        agent_class="hand-built",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=[],
        parent_vaid=None,
        # A placeholder, replaced below. The builder normalises its argument
        # with ``list(...)``, so it cannot carry every malformed shape under
        # test (``None`` raises there). Injecting the member afterwards and
        # signing over the RESULT is what keeps this a test of the verifier
        # rather than of the builder.
        scope_boundary=[],
        lineage_hash=compute_lineage_hash(None, vid),
        capability_set=["read"],
        trust_domain="vaid.example",
        kernel_key_thumbprint=kernel_key_thumbprint(issuer.kernel_public_key()),
    )
    unsigned["scope_boundary"] = boundary
    signature = key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


@pytest.mark.parametrize("boundary", MALFORMED_BOUNDARIES)
def test_verify_vaid_denies_a_malformed_scope_boundary(boundary) -> None:
    """A hand-built document, authentically signed over its own bytes, whose
    boundary is malformed. The signature is valid, so this is specifically the
    local verifier refusing to accept what ``parse_vaid_document`` rejects."""
    key, issuer = _signing_fixture()
    signed = _hand_built(key, issuer, boundary)
    # The signature really is valid over these bytes. Without this line the
    # test would pass for the wrong reason on any future change.
    assert verify_vaid_authenticity(issuer.kernel_public_key(), signed) is True
    # And the wire parser rejects it, which is the behaviour verify_vaid must
    # now agree with rather than contradict.
    assert parse_vaid_document(json.dumps(signed)) is None
    assert issuer.verify_vaid(signed) is False


def test_verify_vaid_accepts_the_same_document_with_typed_entries() -> None:
    """Positive control for the parametrized denial above: the identical
    construction with a well-formed boundary verifies AND parses."""
    key, issuer = _signing_fixture()
    signed = _hand_built(key, issuer, [prefix_entry("data.acme")])
    assert issuer.verify_vaid(signed) is True
    assert parse_vaid_document(json.dumps(signed)) is not None


def test_well_formed_entries_mint_verify_and_parse() -> None:
    """Positive control for every negative above. Without it, a mint that
    refused EVERY boundary would pass the whole section."""
    mint, audit, issuer = fixture()
    vaid = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=[prefix_entry("data.acme")],
            capability_set=["read"],
        )
    )
    assert is_well_formed_scope_boundary(vaid["scope_boundary"])
    assert issuer.verify_vaid(vaid) is True
    # The property the split used to break: what verifies locally also parses
    # off the wire.
    assert parse_vaid_document(json.dumps(vaid)) is not None
    assert audit.entries != []


def test_an_absent_boundary_mints_as_unrestricted() -> None:
    """The counterpart to the ``boundary-is-null`` denial. An absent
    ``scope_boundary`` is legitimate: the seed default is a real ``[]``, which
    is the unrestricted boundary (E.7). Without this control the new shape gate
    could be tightened to require a non-empty boundary and nothing would
    notice."""
    mint, _audit, issuer = fixture()
    vaid = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            capability_set=["read"],
        )
    )
    assert vaid["scope_boundary"] == []
    assert issuer.verify_vaid(vaid) is True
    assert parse_vaid_document(json.dumps(vaid)) is not None


def test_an_unrecognised_kind_still_mints_and_parses() -> None:
    """S.8 (shape) is not S.10 (recognised kinds), and conflating them would
    break extensibility. ``{"kind": "amount_limit", "value": 100}`` is WELL
    FORMED and its kind is simply unknown here, so it must mint and parse. It
    is refused at VERIFY as ``unknown_scope_kind``, which is what makes a
    future narrowing kind additive rather than a 2.0.

    This is the test that stops the new shape gate from being written as "only
    a prefix entry is acceptable", which would pass every other test in this
    section and silently close the extension point ADR-0009 exists to open."""
    mint, _audit, issuer = fixture()
    vaid = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=[{"kind": "amount_limit", "value": 100}],
            capability_set=["read"],
        )
    )
    assert parse_vaid_document(json.dumps(vaid)) is not None
    assert (
        verify_vaid_standing(
            issuer.kernel_public_key(), vaid, RevocationStatus.NOT_REVOKED
        )
        is VaidVerdict.UNKNOWN_SCOPE_KIND
    )

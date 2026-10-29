"""Integration tests: :class:`vaid_spiffe.SpiffeMint` end to end, and proof
that ordinary vaid_mint delegation (``mint_child``) is unaffected by a root
minted over an SVID."""

from __future__ import annotations

from dataclasses import replace

import pytest
from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_mint.error import IdentityError, UnauthorizedError

from vaid_spiffe import SpiffeMint, SvidPresentation

from helpers import make_mint_pop, make_svid_possession, operating_keypair, seed_with_operating_key


def build_mint(tenant_id: str = "acme"):
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    return MintService(issuer, audit), audit, issuer


def test_valid_svid_mints_and_verifies_and_carries_spiffe_id(valid_svid, trust_domain):
    mint, audit, issuer = build_mint()
    spiffe_mint = SpiffeMint(
        mint, audit, trust_bundle=valid_svid["trust_bundle_der"], expected_trust_domain=trust_domain
    )
    operating_key, operating_pub = operating_keypair()
    seed = seed_with_operating_key(operating_pub)
    pop = make_mint_pop(seed, operating_pub, operating_key)
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    presentation = SvidPresentation(
        leaf=valid_svid["leaf_der"], intermediates=[], possession=possession
    )

    result = spiffe_mint.mint_root_with_svid(seed, presentation, pop)

    assert issuer.verify_vaid(result.vaid)
    assert result.spiffe_id == valid_svid["spiffe_id"]
    assert result.trust_domain == trust_domain
    # The signed document is unmodified vaid_mint shape - no SPIFFE field.
    assert "external_identity" not in result.vaid
    assert "spiffe_id" not in result.vaid

    # The binding is recorded in the audit trail, alongside the ordinary
    # vaid_minted record the unmodified mint_root call itself wrote.
    event_types = [e.event_type for e in audit.entries]
    assert "vaid_minted" in event_types
    assert "vaid_minted_with_external_identity" in event_types
    binding_event = next(
        e for e in audit.entries if e.event_type == "vaid_minted_with_external_identity"
    )
    assert binding_event.details["spiffe_id"] == valid_svid["spiffe_id"]
    assert binding_event.details["vaid_id"] == result.vaid["vaid_id"]


def test_invalid_svid_mints_nothing(valid_svid, trust_domain):
    mint, audit, issuer = build_mint()
    spiffe_mint = SpiffeMint(
        mint,
        audit,
        trust_bundle=valid_svid["trust_bundle_der"],
        expected_trust_domain="some-other-domain.test",  # mismatch -> door refuses
    )
    operating_key, operating_pub = operating_keypair()
    seed = seed_with_operating_key(operating_pub)
    pop = make_mint_pop(seed, operating_pub, operating_key)
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    presentation = SvidPresentation(
        leaf=valid_svid["leaf_der"], intermediates=[], possession=possession
    )

    with pytest.raises(IdentityError):
        spiffe_mint.mint_root_with_svid(seed, presentation, pop)

    # Nothing was minted and nothing was audited - the refusal happened before
    # the mint was ever reached.
    assert audit.is_empty()


def test_mint_without_operating_key_is_refused(valid_svid, trust_domain):
    mint, audit, issuer = build_mint()
    spiffe_mint = SpiffeMint(
        mint, audit, trust_bundle=valid_svid["trust_bundle_der"], expected_trust_domain=trust_domain
    )
    seed = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=None,  # no operating key
    )
    possession = make_svid_possession(valid_svid["leaf_key"], b"\x00" * 32)
    presentation = SvidPresentation(
        leaf=valid_svid["leaf_der"], intermediates=[], possession=possession
    )
    with pytest.raises(IdentityError, match="BYO Ed25519 operating"):
        spiffe_mint.mint_root_with_svid(seed, presentation, pop=None)
    assert audit.is_empty()


def test_tampered_possession_is_refused(valid_svid, trust_domain):
    mint, audit, issuer = build_mint()
    spiffe_mint = SpiffeMint(
        mint, audit, trust_bundle=valid_svid["trust_bundle_der"], expected_trust_domain=trust_domain
    )
    operating_key, operating_pub = operating_keypair()
    seed = seed_with_operating_key(operating_pub)
    pop = make_mint_pop(seed, operating_pub, operating_key)
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    tampered_possession = replace(possession, signature=b"\x00" * len(possession.signature))
    presentation = SvidPresentation(
        leaf=valid_svid["leaf_der"], intermediates=[], possession=tampered_possession
    )
    with pytest.raises(IdentityError):
        spiffe_mint.mint_root_with_svid(seed, presentation, pop)
    assert audit.is_empty()


def test_child_delegation_from_svid_rooted_vaid_still_narrows(valid_svid, trust_domain):
    """Once minted, the root behaves exactly like any other vaid_mint root: a
    child must still attenuate scope/capabilities, through the UNMODIFIED
    MintService.mint_child - nothing about the SPIFFE binding changes that
    path, because the signed document carries no trace of it."""
    mint, audit, issuer = build_mint()
    spiffe_mint = SpiffeMint(
        mint, audit, trust_bundle=valid_svid["trust_bundle_der"], expected_trust_domain=trust_domain
    )
    operating_key, operating_pub = operating_keypair()
    seed = seed_with_operating_key(operating_pub)
    pop = make_mint_pop(seed, operating_pub, operating_key)
    possession = make_svid_possession(valid_svid["leaf_key"], operating_pub)
    presentation = SvidPresentation(
        leaf=valid_svid["leaf_der"], intermediates=[], possession=possession
    )
    root_result = spiffe_mint.mint_root_with_svid(seed, presentation, pop)
    root = root_result.vaid

    child_operating_key, child_operating_pub = operating_keypair()
    # A WIDER child scope must be refused - attenuation still holds.
    wide_child_seed = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        parent_vaid=root["vaid_id"],
        scope_boundary=[prefix_entry("data")],  # wider than the parent's "data.acme"
        capability_set=["read"],
        public_key_der=child_operating_pub,
    )
    wide_pop = make_mint_pop(wide_child_seed, child_operating_pub, child_operating_key)
    with pytest.raises(UnauthorizedError):
        mint.mint_child(wide_child_seed, root, wide_pop)

    # A narrower child scope mints fine and verifies, like any other delegation.
    narrow_child_seed = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        parent_vaid=root["vaid_id"],
        scope_boundary=[prefix_entry("data.acme.sub")],
        capability_set=["read"],
        public_key_der=child_operating_pub,
    )
    narrow_pop = make_mint_pop(narrow_child_seed, child_operating_pub, child_operating_key)
    child_response = mint.mint_child(narrow_child_seed, root, narrow_pop)
    assert issuer.verify_vaid(child_response.vaid)
    assert child_response.vaid["parent_vaid"] == root["vaid_id"]

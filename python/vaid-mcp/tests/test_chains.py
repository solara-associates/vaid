from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.chain import ChainVerification

from vaid_mcp.chains import ChainFormatError, parse_chain, verify_chain_result
from vaid_mcp.keys import resolve_keys


def test_valid_chain_is_attenuated(chain_fixture):
    result = verify_chain_result(chain_fixture.chain(), chain_fixture.keys())
    assert result.verdict is ChainVerification.ATTENUATED
    assert result.verdict.is_attenuated()
    assert len(result.hops) == 2
    assert all(h.authentic for h in result.hops)


def test_standalone_root_with_no_ancestors_verifies(chain_fixture):
    result = verify_chain_result({"leaf": chain_fixture.root}, chain_fixture.keys())
    assert result.verdict is ChainVerification.ATTENUATED


def test_tampered_leaf_is_inauthentic(chain_fixture):
    tampered = dict(chain_fixture.child)
    tampered["capability_set"] = list(tampered["capability_set"]) + ["admin"]
    result = verify_chain_result({"leaf": tampered, "ancestors": [chain_fixture.root]}, chain_fixture.keys())
    assert result.verdict is ChainVerification.INAUTHENTIC
    assert not result.hops[0].authentic


def test_widened_scope_is_not_attenuated(chain_fixture):
    """A child whose scope was never attenuated from its parent cannot be
    produced through MintService.mint_child (it refuses), so this calls the
    issuer directly — bypassing the mint's own attenuation gate, the same
    way a buggy or malicious issuer implementation would — to prove
    verify_chain_at's OWN containment check catches a genuinely signed but
    over-scoped child rather than relying on the minter to have been honest."""
    from vaid_mint.document import prefix_entry

    widened = chain_fixture.issuer.issue_vaid_with_lineage(
        agent_class="worker",
        version="1.0.0",
        tenant_id="acme",
        parent_vaid=chain_fixture.root["vaid_id"],
        scope_boundary=[prefix_entry("data.other-tenant-entirely")],
        capability_set=["read"],
    )

    result = verify_chain_result({"leaf": widened, "ancestors": [chain_fixture.root]}, chain_fixture.keys())
    assert result.verdict is ChainVerification.NOT_ATTENUATED


def test_expired_ancestor_is_expired_verdict(chain_fixture):
    far_future = datetime.now(timezone.utc) + timedelta(days=3650)
    result = verify_chain_result(chain_fixture.chain(), chain_fixture.keys(), now=far_future)
    assert result.verdict is ChainVerification.EXPIRED


def test_unknown_signing_key_is_inauthentic(chain_fixture):
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    wrong_keys = resolve_keys(public_key=other.hex(), key_url=None)
    result = verify_chain_result(chain_fixture.chain(), wrong_keys)
    assert result.verdict is ChainVerification.INAUTHENTIC


def test_missing_ancestor_is_unverifiable(chain_fixture):
    result = verify_chain_result({"leaf": chain_fixture.child}, chain_fixture.keys())
    assert result.verdict is ChainVerification.UNVERIFIABLE


def test_parse_chain_rejects_missing_leaf():
    with pytest.raises(ChainFormatError):
        parse_chain({"ancestors": []})


def test_parse_chain_rejects_non_dict_leaf():
    with pytest.raises(ChainFormatError):
        parse_chain({"leaf": "not-a-document"})


def test_parse_chain_rejects_non_list_ancestors():
    with pytest.raises(ChainFormatError):
        parse_chain({"leaf": {}, "ancestors": "nope"})

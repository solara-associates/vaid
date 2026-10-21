from __future__ import annotations

from vaid_mint.chain import ChainVerification

from vaid_mcp.chains import verify_chain_result
from vaid_mcp.demo import mint_demo_chain
from vaid_mcp.keys import resolve_keys


def test_demo_chain_verifies_against_its_own_key():
    demo = mint_demo_chain(resource="demo.widgets", capability="list")
    keys = resolve_keys(public_key=demo.kernel_public_key_hex, key_url=None)
    result = verify_chain_result({"leaf": demo.child, "ancestors": [demo.root]}, keys)
    assert result.verdict is ChainVerification.ATTENUATED


def test_demo_chain_is_labelled():
    demo = mint_demo_chain()
    assert "DEMO ONLY" in demo.label


def test_two_demo_calls_use_different_keys():
    first = mint_demo_chain()
    second = mint_demo_chain()
    assert first.kernel_public_key_hex != second.kernel_public_key_hex


def test_demo_chain_carries_requested_capability_and_resource():
    demo = mint_demo_chain(resource="demo.orders", capability="write")
    assert demo.child["capability_set"] == ["write"]

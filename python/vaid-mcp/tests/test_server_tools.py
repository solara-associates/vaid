"""Exercises the functions `server.py` registers as MCP tools, called
directly (not over a transport) with the exact plain dict/str/None argument
shapes an MCP client would send. Transport-level wiring is covered by the
end-to-end stdio transcript in ~/solara/lz2026/s384-uat/, not here.
"""

from __future__ import annotations

from vaid_mcp.server import (
    check_scope_tool,
    explain_vaid_tool,
    mint_demo_chain_tool,
    verify_chain,
)


def test_mint_then_verify_round_trip():
    demo = mint_demo_chain_tool(resource="server.test", capability="read")
    result = verify_chain(demo["chain"], public_key=demo["public_key_hex"])
    assert result["is_valid"] is True
    assert result["verdict"] == "attenuated"


def test_mint_then_check_scope_round_trip():
    demo = mint_demo_chain_tool(resource="server.test", capability="read")
    allowed = check_scope_tool(
        demo["chain"], "read", "server.test", public_key=demo["public_key_hex"]
    )
    assert allowed["permitted"] is True

    denied = check_scope_tool(
        demo["chain"], "admin", "server.test", public_key=demo["public_key_hex"]
    )
    assert denied["permitted"] is False


def test_explain_tool_on_minted_leaf():
    demo = mint_demo_chain_tool(resource="server.test", capability="read")
    explanation = explain_vaid_tool(demo["chain"]["leaf"])
    assert explanation["is_root"] is False
    assert "DECODING" in explanation["warning"]


def test_verify_chain_rejects_neither_key_arg():
    demo = mint_demo_chain_tool()
    try:
        verify_chain(demo["chain"])
    except ValueError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("expected ValueError for missing trust source")


def test_verify_chain_wrong_key_is_inauthentic():
    demo = mint_demo_chain_tool()
    other = mint_demo_chain_tool()
    result = verify_chain(demo["chain"], public_key=other["public_key_hex"])
    assert result["verdict"] == "inauthentic"
    assert result["is_valid"] is False

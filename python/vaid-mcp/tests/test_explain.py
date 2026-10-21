from __future__ import annotations

from vaid_mcp.explain import explain_vaid


def test_explains_root_credential(chain_fixture):
    explanation = explain_vaid(chain_fixture.root)
    assert explanation.is_root
    assert explanation.parent_vaid is None
    assert "nobody" in explanation.plain_english
    assert "read" in explanation.capabilities
    assert "This is a DECODING, not a verification" in explanation.warning


def test_explains_delegated_child(chain_fixture):
    explanation = explain_vaid(chain_fixture.child)
    assert not explanation.is_root
    assert explanation.parent_vaid == chain_fixture.root["vaid_id"]
    assert "another credential" in explanation.plain_english


def test_empty_scope_boundary_is_described_as_unrestricted():
    vaid = {
        "agent_id": "a1",
        "agent_class": "x",
        "tenant_id": "acme",
        "trust_domain": "vaid.example",
        "parent_vaid": None,
        "scope_boundary": [],
        "capability_set": ["read"],
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-02-01T00:00:00Z",
    }
    explanation = explain_vaid(vaid)
    assert "ANY resource" in explanation.scope_summary


def test_explain_never_raises_on_sparse_document():
    assert explain_vaid({}) is not None


def test_no_expiry_is_flagged():
    vaid = {"scope_boundary": [], "capability_set": []}
    explanation = explain_vaid(vaid)
    assert "unusual" in explanation.plain_english

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mcp.keys import resolve_keys
from vaid_mcp.scope import check_scope


def test_permits_capability_within_scope(chain_fixture):
    result = check_scope(chain_fixture.chain(), chain_fixture.keys(), "read", "data.acme.sub")
    assert result.answerable
    assert result.permitted is True


def test_denies_capability_not_held(chain_fixture):
    result = check_scope(chain_fixture.chain(), chain_fixture.keys(), "write", "data.acme.sub")
    assert result.answerable
    assert result.permitted is False
    assert "write" in result.reason


def test_denies_resource_outside_scope(chain_fixture):
    result = check_scope(chain_fixture.chain(), chain_fixture.keys(), "read", "data.someone-else")
    assert result.answerable
    assert result.permitted is False
    assert "data.someone-else" in result.reason


def test_refuses_to_answer_for_an_invalid_chain(chain_fixture):
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    wrong_keys = resolve_keys(public_key=other.hex(), key_url=None)
    result = check_scope(chain_fixture.chain(), wrong_keys, "read", "data.acme.sub")
    assert not result.answerable
    assert result.permitted is None
    assert "cannot determine permission" in result.reason

"""`act` nesting for a 3-hop chain (docs/jwt/v1/profile.md SS4), plus the two
degenerate cases the same construction must handle with no special-casing:
a 2-node chain (one delegation) and a 1-node chain (no delegation, root is
leaf)."""

from __future__ import annotations

from vaid_jwt_bridge import ExchangeRequest, Issued, exchange
from vaid_jwt_bridge.claims import build_sub_and_act


def test_three_hop_act_nesting_matches_spec(three_hop_chain):
    root, child, leaf = three_hop_chain
    chain_docs = [root, child, leaf]

    sub, act = build_sub_and_act(chain_docs)

    assert sub == root["vaid_id"]
    # Outermost act = current (most recent) actor = the leaf.
    assert act["sub"] == leaf["vaid_id"]
    # Nested act = prior actor = the root's immediate child.
    assert act["act"]["sub"] == child["vaid_id"]
    # No third level: child has no further nested act.
    assert "act" not in act["act"]


def test_two_hop_chain_single_act_level(mint, issuer):
    from vaid_jwt_bridge.claims import build_sub_and_act
    from vaid_mint import VaidSeed
    from tests.conftest import mint_child_byo, LEAF_SEED

    root = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=["data.acme"],
            capability_set=["read"],
        )
    )
    leaf = mint_child_byo(
        mint,
        root,
        key_seed=LEAF_SEED,
        agent_class="leafagent",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=["data.acme"],
        capability_set=["read"],
    )

    sub, act = build_sub_and_act([root, leaf])

    assert sub == root["vaid_id"]
    assert act == {"sub": leaf["vaid_id"]}  # one level, no nested act.act


def test_trivial_chain_no_delegation_no_act_claim():
    # A single-node chain: the leaf IS the root (no parent_vaid at all).
    trivial_leaf = {"vaid_id": "only-node"}
    sub, act = build_sub_and_act([trivial_leaf])
    assert sub == "only-node"
    assert act is None


def test_issued_jwt_omits_act_for_a_root_only_chain(
    mint, issuer, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    import jwt as pyjwt
    import json
    from vaid_jwt_bridge import KeyRing
    from vaid_mint import VaidSeed

    root = mint.mint_root(
        VaidSeed(
            agent_class="orchestrator",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=["data.acme"],
            capability_set=["read"],
        )
    )
    keyring = KeyRing([eddsa_signer])
    result = exchange(
        ExchangeRequest(leaf=root, chain=(), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Issued)
    signing_key = pyjwt.PyJWK.from_json(json.dumps(keyring.jwks()["keys"][0]))
    decoded = pyjwt.decode(
        result.access_token, key=signing_key, algorithms=["EdDSA"], audience="aud", issuer="https://bridge.example.com"
    )
    assert decoded["sub"] == root["vaid_id"]
    assert "act" not in decoded

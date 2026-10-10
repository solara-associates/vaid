"""Building the issued JWT's identity claims from a verified VAID chain.

Everything here operates on ``chain_docs``: the ordered list of VAID documents
produced the same way ``vaid_mint.chain.verify_chain_at`` builds it internally
— root first, leaf last — for a chain that has already verified
``ChainVerification.ATTENUATED``. Nothing in this module re-verifies anything;
it only re-describes an already-trusted chain as RFC 8693 claims.
See docs/jwt/v1/profile.md SS4-5 for the normative mapping this implements.
"""

from __future__ import annotations

import hashlib

import rfc8785


def build_sub_and_act(chain_docs: list[dict]) -> tuple[str, dict | None]:
    """RFC 8693 SS4.1 ``sub``/``act`` for a verified chain (profile SS4).

    ``chain_docs[0]`` (the root) becomes ``sub``. Every other hop becomes one
    level of ``act``, nested oldest-innermost to leaf-outermost — RFC 8693's
    rule that the *current* (most recent) actor is the outermost ``act`` and
    the *least recent* actor is the most deeply nested. Returns ``(sub, None)``
    when the chain has no hops beyond the root (no delegation occurred, so no
    ``act`` claim is emitted at all).
    """
    root = chain_docs[0]
    actors = chain_docs[1:]  # oldest (root's immediate child) first, leaf last
    if not actors:
        return root["vaid_id"], None

    node: dict = {"sub": actors[0]["vaid_id"]}
    for hop in actors[1:]:
        node = {"sub": hop["vaid_id"], "act": node}
    return root["vaid_id"], node


def chain_sha256(chain_docs: list[dict]) -> str:
    """SHA-256 of the RFC 8785 (JCS) canonical encoding of the full verified
    chain (root first, leaf last), lowercase hex. Lets a party already
    holding (or able to refetch) the same documents confirm independently
    that the bridge verified exactly these — profile SS5."""
    return hashlib.sha256(rfc8785.dumps(list(chain_docs))).hexdigest()


def build_vaid_claim(leaf: dict, chain_docs: list[dict]) -> dict:
    """The ``vaid`` claim (profile SS5): the leaf's own identity and
    authority, plus a hash an auditor can check the verified chain against."""
    return {
        "vaid_id": leaf["vaid_id"],
        "trust_domain": leaf["trust_domain"],
        "scope_boundary": list(leaf["scope_boundary"]),
        "capability_set": list(leaf["capability_set"]),
        "chain_sha256": chain_sha256(chain_docs),
    }

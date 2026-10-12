"""Every denial path issues nothing. Each test confirms both the
`DenialReason` and — the part that actually matters — that `exchange()`
returned `Denied`, never `Issued`, so a caller cannot reach for
`access_token` on a refused exchange by accident.

Two cases (a child claiming wider authority than its parent, and a
cross-tenant hop) cannot be produced through ``MintService`` — it refuses
both at mint time, fail-closed, before a document is ever signed. That
refusal is the correct behavior, not an obstacle to route around: this
suite's job for those two cases is to confirm the BRIDGE also refuses an
adversarially-shaped but authentically-signed chain, i.e. one that did not
go through ``MintService`` at all. ``LocalMint`` below is the same pattern
``vaid-mint``'s own ``tests/test_chain_verification.py`` uses for exactly
this reason: a kernel keypair plus the issuer's own public
document-building/signing calls, with attenuation deliberately
unenforced, so a child can be signed claiming authority its parent never
held."""

from __future__ import annotations

import uuid
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_jwt_bridge import (
    DenialReason,
    Denied,
    ExchangeRequest,
    TrustedIssuers,
    exchange,
)
from vaid_mint import ReferenceIssuer, VaidSeed
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    prefix_entry,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.mint_types import MintPop, build_mint_pop_payload
from vaid_mint.revocation import InMemoryRevocationList
from vaid_pop import canonical_request_signing_bytes

from tests.conftest import OTHER_ISSUER_SEED, mint_child_byo


class LocalMint:
    """A kernel keypair plus the issuer's own document-building/signing
    calls, with NO attenuation enforcement — produces authentic-but-
    adversarially-shaped documents a hostile presenter could construct.
    Mirrors ``vaid_mint/tests/test_chain_verification.py``'s helper of the
    same name and purpose."""

    def __init__(self, seed_byte: int = 7) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        self.public_key = self._key.public_key().public_bytes_raw()

    def sign(self, agent_id, parent_vaid, scope, caps, *, trust_domain="vaid.example", tenant="acme"):
        unsigned = build_unsigned_vaid_document(
            vaid_id=agent_id,
            agent_id=agent_id,
            agent_class="test",
            version="1.0.0",
            tenant_id=tenant,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2999-01-01T00:00:00Z",
            public_key_der=list(range(32)),
            parent_vaid=parent_vaid,
            scope_boundary=[prefix_entry(v) for v in scope],
            lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
            capability_set=caps,
            trust_domain=trust_domain,
            kernel_key_thumbprint=kernel_key_thumbprint(self.public_key),
        )
        signature = self._key.sign(canonical_vaid_signing_bytes(unsigned))
        return {**unsigned, "kernel_signature": list(signature)}


def _vid(n: int) -> str:
    return str(uuid.UUID(int=n))


#: An entry of a kind this bridge does not implement, shaped like the amount
#: limit ADR-0009 names as the motivating future kind, so the case is an entry
#: that NARROWS authority rather than a nonsense one.
_FUTURE_KIND_ENTRY = {"kind": "amount_limit", "value": 100}


def _root_with_boundary(kernel_key, issuer, boundary: list[dict]) -> dict:
    """An authentic ROOT carrying ``boundary`` verbatim, signed by the kernel
    key the ``trusted_keys`` fixture trusts.

    Built with ``build_unsigned_vaid_document`` rather than through
    ``MintService`` for the reason this module's docstring gives about
    ``LocalMint``: mint refuses an unreadable boundary at mint time, which is
    correct and is not the behaviour under test. The question here is what the
    BRIDGE does with an adversarially-shaped but authentically-signed document
    it is handed."""
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=boundary,
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=["read"],
        trust_domain="vaid.example",
        kernel_key_thumbprint=kernel_key_thumbprint(issuer.kernel_public_key()),
    )
    signature = kernel_key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def test_unknown_scope_kind_issues_nothing(
    kernel_key, issuer, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    """ADR-0009 S.10 at the bridge, where the stake is highest.

    The bridge authorises no specific resource, so there is no containment
    check to fail closed later, and ``build_vaid_claim`` copies
    ``scope_boundary`` verbatim into the issued token. Without an explicit
    evaluability step the bridge would mint a signed, audience-scoped JWT
    asserting a boundary it could not evaluate, and hand it to a relying party
    even less likely to recognise the kind: the narrowing constraint laundered
    through a token that looks fully verified."""
    leaf = _root_with_boundary(kernel_key, issuer, [_FUTURE_KIND_ENTRY])

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.UNKNOWN_SCOPE_KIND
    assert not hasattr(result, "access_token")


def test_unknown_scope_kind_is_not_reported_as_inauthentic(
    kernel_key, issuer, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    """A verdict over an AUTHENTIC document (ADR-0009 decision 3), not a
    signature failure. Calling a correctly signed future-version credential
    forged is false, and it is the answer a missing enum member produces."""
    leaf = _root_with_boundary(kernel_key, issuer, [_FUTURE_KIND_ENTRY])

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason != DenialReason.INAUTHENTIC
    assert result.reason == DenialReason.UNKNOWN_SCOPE_KIND


def test_one_unreadable_entry_refuses_a_boundary_that_also_matches(
    kernel_key, issuer, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    """S.10 refuses the WHOLE boundary (ADR-0009 decision 4), even when a
    readable ``prefix`` entry sits alongside the one that cannot be read."""
    leaf = _root_with_boundary(
        kernel_key, issuer, [prefix_entry("data.acme"), _FUTURE_KIND_ENTRY]
    )

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.UNKNOWN_SCOPE_KIND


def test_expired_leaf_issues_nothing(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    far_future = verification_now + timedelta(days=3650)  # certainly past the 24h TTL

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=far_future,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.LEAF_EXPIRED


def test_revoked_middle_link_issues_nothing(
    three_hop_chain, trusted_keys, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    revocation = InMemoryRevocationList.assume_nothing_revoked()
    revocation.revoke(child["vaid_id"])  # the MIDDLE link, not the leaf

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.REVOKED


def test_revocation_unavailable_issues_nothing(
    three_hop_chain, trusted_keys, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    unavailable = InMemoryRevocationList.unavailable()  # absent, never "not revoked"

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=unavailable,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.REVOCATION_UNAVAILABLE


def test_wider_than_parent_child_issues_nothing(trusted_keys, vouching_revocation, eddsa_signer, verification_now):
    """A child authentically signed under the bridge's trusted kernel key,
    claiming scope its parent never held. ``MintService`` would refuse to
    mint this; the bridge must independently refuse to exchange it."""
    local = LocalMint()
    root = local.sign(_vid(1), None, ["data.tenant"], ["read"])
    leaf = local.sign(_vid(2), _vid(1), ["data.other"], ["read"])  # NOT a subset of root's scope

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root,), audience="aud"),
        keys=TrustedIssuers.from_raw_keys([("vaid.example", local.public_key)]),
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.CHAIN_NOT_ATTENUATED


def test_unknown_issuer_key_issues_nothing(
    three_hop_chain, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    other_issuer = ReferenceIssuer.from_seed(OTHER_ISSUER_SEED, vaid_ttl_hours=24, trust_domain="other.example")
    # Binds only the OTHER issuer's key, so our kernel key resolves to nothing.
    untrusted_keys = TrustedIssuers.from_raw_keys(
        [("other.example", other_issuer.kernel_public_key())]
    )

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience="aud"),
        keys=untrusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.ISSUER_MISMATCH


def test_same_key_hop_crossing_trust_domains_is_issuer_mismatch(
    vouching_revocation, eddsa_signer, verification_now
):
    """A same-key hop whose LEAF declares a different ``trust_domain`` than
    its parent, both signed by one kernel key.

    This asserted ``CHAIN_NOT_ATTENUATED`` before the GHSA-hfjh-v2x2-r58v fix,
    which is what ``verify_chain_at`` returns for it. It is now
    ``ISSUER_MISMATCH``, and that is the stronger reading: the trust anchor
    binds this key to exactly one domain, so the leaf claiming the other one
    is refused at step 1, before chain verification is reached at all. A key
    is trusted for the domain it is paired with, not for any domain a document
    claims.

    The route is therefore unreachable from this entry point now: whichever of
    the two domains the key is bound to, the other document is misbound, so the
    binding always refuses first. ``verify_chain_at``'s own NOT_ATTENUATED
    verdict for this shape stays pinned where it belongs, in
    ``python/vaid-mint/tests/test_chain_verification.py``
    (``test_same_tenant_name_in_a_different_trust_domain_is_not_attenuated``),
    rather than being asserted here through a check that no longer owns it."""
    local = LocalMint()
    root = local.sign(_vid(3), None, ["data.tenant"], ["read"], trust_domain="vaid.example", tenant="acme")
    leaf = local.sign(_vid(4), _vid(3), ["data.tenant.sub"], ["read"], trust_domain="other.example", tenant="acme")

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root,), audience="aud"),
        keys=TrustedIssuers.from_raw_keys([("vaid.example", local.public_key)]),
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.ISSUER_MISMATCH


def test_missing_audience_issues_nothing(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, child), audience=None),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.MISSING_AUDIENCE


def test_no_leaf_issues_nothing(trusted_keys, vouching_revocation, eddsa_signer, verification_now):
    result = exchange(
        ExchangeRequest(leaf=None, audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.NO_LEAF


def test_incomplete_chain_is_unverifiable(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    """The leaf is presented WITHOUT its ancestors — the chain cannot be
    assembled back to a trusted root."""
    root, child, leaf = three_hop_chain

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(), audience="aud"),  # missing root + child
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.CHAIN_UNVERIFIABLE


def test_unsupported_requested_token_type_issues_nothing(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    result = exchange(
        ExchangeRequest(
            leaf=leaf,
            chain=(root, child),
            audience="aud",
            requested_token_type="urn:ietf:params:oauth:token-type:saml2",
        ),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.UNSUPPORTED_REQUESTED_TOKEN_TYPE


def test_tampered_leaf_signature_is_inauthentic(
    three_hop_chain, trusted_keys, vouching_revocation, eddsa_signer, verification_now
):
    root, child, leaf = three_hop_chain
    tampered = dict(leaf)
    # A WIDER but still well-formed boundary. The point of this test is that
    # the signature no longer covers the bytes, so the tamper has to leave a
    # document that is otherwise valid: a bare string here would be a
    # malformed entry under ADR-0009 and would test parsing, not authenticity.
    tampered["scope_boundary"] = list(leaf["scope_boundary"]) + [
        prefix_entry("data.acme.everything")
    ]

    result = exchange(
        ExchangeRequest(leaf=tampered, chain=(root, child), audience="aud"),
        keys=trusted_keys,
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.INAUTHENTIC

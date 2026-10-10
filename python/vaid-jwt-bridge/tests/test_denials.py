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

from vaid_jwt_bridge import DenialReason, Denied, ExchangeRequest, exchange
from vaid_mint import ReferenceIssuer, VaidSeed
from vaid_mint.chain import SingleKernelKey
from vaid_mint.document import build_unsigned_vaid_document, canonical_vaid_signing_bytes, compute_lineage_hash
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
            scope_boundary=scope,
            lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
            capability_set=caps,
            trust_domain=trust_domain,
            kernel_key_thumbprint=kernel_key_thumbprint(self.public_key),
        )
        signature = self._key.sign(canonical_vaid_signing_bytes(unsigned))
        return {**unsigned, "kernel_signature": list(signature)}


def _vid(n: int) -> str:
    return str(uuid.UUID(int=n))


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
        keys=SingleKernelKey(local.public_key),
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
    untrusted_keys = SingleKernelKey(other_issuer.kernel_public_key())  # does NOT trust our kernel key

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


def test_trust_domain_mismatch_is_not_attenuated(trusted_keys, vouching_revocation, eddsa_signer, verification_now):
    """Same trust domain declared on both documents is required for a
    same-key hop's tenant binding to even be meaningful; here the LEAF
    declares a different ``trust_domain`` string than its parent while
    sharing a kernel key — a same-key hop crossing trust domains, which
    ``verify_chain_at`` treats as NOT_ATTENUATED (profile SS2 step 4)."""
    local = LocalMint()
    root = local.sign(_vid(3), None, ["data.tenant"], ["read"], trust_domain="vaid.example", tenant="acme")
    leaf = local.sign(_vid(4), _vid(3), ["data.tenant.sub"], ["read"], trust_domain="other.example", tenant="acme")

    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root,), audience="aud"),
        keys=SingleKernelKey(local.public_key),
        revocation=vouching_revocation,
        issuer="https://bridge.example.com",
        signer=eddsa_signer,
        now=verification_now,
    )

    assert isinstance(result, Denied)
    assert result.reason == DenialReason.CHAIN_NOT_ATTENUATED


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
    tampered["scope_boundary"] = list(leaf["scope_boundary"]) + ["data.acme.everything"]

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

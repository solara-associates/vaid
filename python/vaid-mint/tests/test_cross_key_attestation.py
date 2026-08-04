"""Cross-key chain verification and detached consent attestations. Adversarial
tests, Python side.

Mirror of ``crates/vaid-mint/tests/cross_key_attestation.rs``: the same scenarios,
asserting the same (scenario -> verdict) mapping.

The first test is the one the whole feature turns on: a hop that crosses a kernel
key, with no attestation, must NOT verify. Everything else here is a way of getting
that wrong more subtly.

Nothing here is a frozen vector and this file must never become one. The attestation
format is deliberately UNFROZEN — see ``scripts/attestation_byte_agreement.py`` for
the byte-agreement evidence that stands in for a vector until it is.

Two organisations throughout: ``A`` (``a.example``) and ``B`` (``b.example``), each
with its own kernel key. ``A`` is the delegating parent; ``B`` mints the child.
"""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.attestation import (
    AttestationBundle,
    build_unsigned_attestation,
    canonical_attestation_signing_bytes,
)
from vaid_mint.chain import (
    ChainVerification,
    KernelKeyMap,
    PresentedBundle,
    SingleKernelKey,
    verify_chain_with,
)
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint


class Org:
    """One organisation: a kernel key plus a trust domain. Signs both VAID documents
    and consent attestations, using the same public calls the reference issuer uses.
    Enforces nothing — the point, since these tests present authentic but
    adversarially shaped material."""

    def __init__(self, seed_byte: int, trust_domain: str) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        self.public_key = self._key.public_key().public_bytes_raw()
        self.trust_domain = trust_domain

    def thumbprint(self) -> str:
        return kernel_key_thumbprint(self.public_key)

    def sign(
        self,
        agent_id: str,
        parent_vaid: str | None,
        tenant: str,
        scope: list[str],
        caps: list[str],
    ) -> dict:
        unsigned = build_unsigned_vaid_document(
            vaid_id=agent_id,
            agent_id=agent_id,
            agent_class="test",
            version="1.0.0",
            tenant_id=tenant,
            issued_at="2026-06-04T12:00:00Z",
            expires_at="2026-06-05T12:00:00Z",
            public_key_der=list(range(32)),
            parent_vaid=parent_vaid,
            scope_boundary=scope,
            lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
            capability_set=caps,
            trust_domain=self.trust_domain,
            kernel_key_thumbprint=self.thumbprint(),
        )
        signature = self._key.sign(canonical_vaid_signing_bytes(unsigned))
        return {**unsigned, "kernel_signature": list(signature)}

    def attest(
        self,
        parent_vaid: str,
        child_vaid: str,
        child_trust_domain: str,
        child_tenant: str,
        scope: list[str],
        caps: list[str],
    ) -> dict:
        """Sign a consent attestation as the parent's issuer."""
        unsigned = build_unsigned_attestation(
            parent_vaid=parent_vaid,
            child_vaid=child_vaid,
            child_trust_domain=child_trust_domain,
            child_tenant_id=child_tenant,
            scope_boundary=scope,
            capability_set=caps,
            trust_domain=self.trust_domain,
            kernel_key_thumbprint=self.thumbprint(),
        )
        signature = self._key.sign(canonical_attestation_signing_bytes(unsigned))
        return {**unsigned, "signature": list(signature)}


def vid(n: int) -> str:
    return str(uuid.UUID(int=n))


def org_a() -> Org:
    return Org(1, "a.example")


def org_b() -> Org:
    return Org(2, "b.example")


def both_keys(a: Org, b: Org) -> KernelKeyMap:
    """A verifier accepting BOTH organisations' keys — the strongest position an
    adversary could hope for. Both issuers trusted, and the chain must still fail
    without consent."""
    return KernelKeyMap([a.public_key, b.public_key])


# ── THE LOAD-BEARING TEST ───────────────────────────────────────────────────────


def test_cross_key_hop_without_an_attestation_is_never_attenuated() -> None:
    """Written first, deliberately. Both kernel keys are trusted, every document is
    authentic, the chain assembles, authority is properly contained — the ONLY thing
    missing is the parent's consent."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read", "write"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])

    verdict = verify_chain_with(
        both_keys(a, b), child, PresentedBundle([root]), AttestationBundle()
    )

    assert verdict is not ChainVerification.ATTENUATED, (
        "a cross-key hop without consent must NEVER verify"
    )
    assert verdict is ChainVerification.INAUTHENTIC


# ── POSITIVE CONTROLS ───────────────────────────────────────────────────────────


def test_cross_key_hop_with_valid_consent_verifies() -> None:
    """Without this the suite could pass by rejecting every cross-key chain."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read", "write"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])
    attestation = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([attestation]),
        )
        is ChainVerification.ATTENUATED
    ), "a cross-key hop with the parent issuer's signed consent must verify"


def test_same_key_chain_needs_no_attestation() -> None:
    """A single-key chain is unchanged by any of this."""
    a = org_a()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = a.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])

    assert (
        verify_chain_with(
            SingleKernelKey(a.public_key),
            child,
            PresentedBundle([root]),
            AttestationBundle(),
        )
        is ChainVerification.ATTENUATED
    ), "same-key hops keep their existing behaviour"


# ── ADVERSARIAL ─────────────────────────────────────────────────────────────────


def test_forged_sibling_without_consent_is_not_attenuated() -> None:
    """THE FORGED SIBLING. B mints a document naming A's root as its parent, with a
    strict subset of A's authority, signed with B's key, no attestation. B needs only
    to KNOW A's root vaid_id — which every chain presentation discloses."""
    a, b = org_a(), org_b()

    a_root = a.sign(vid(1), None, "acme", ["data.acme"], ["read", "write", "admin"])
    forged = b.sign(vid(99), vid(1), "acme", ["data.acme.stolen"], ["read"])

    assert (
        verify_chain_with(
            both_keys(a, b), forged, PresentedBundle([a_root]), AttestationBundle()
        )
        is not ChainVerification.ATTENUATED
    ), "FORGED SIBLING: an unconsented cross-issuer child must not verify"


def test_attestation_signed_by_the_wrong_key_is_inauthentic() -> None:
    """B signs its own permission slip."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])
    self_signed = b.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([self_signed]),
        )
        is ChainVerification.INAUTHENTIC
    ), "only the issuer that minted the parent may consent on its behalf"


def test_attestation_for_a_different_child_does_not_apply() -> None:
    """A consented to one child; a second, unconsented child tries to ride it."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    blessed = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )
    other = b.sign(vid(3), vid(1), "acme", ["data.acme.sub"], ["read"])

    assert (
        verify_chain_with(
            both_keys(a, b), other, PresentedBundle([root]), AttestationBundle([blessed])
        )
        is ChainVerification.INAUTHENTIC
    ), "consent names one child; another cannot borrow it"


def test_attestation_narrower_than_the_child_claims_is_not_attenuated() -> None:
    """A consented to `read`; the child claims `read` and `write`, both within the
    root's authority so hop containment alone passes."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read", "write"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read", "write"])
    attestation = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([attestation]),
        )
        is ChainVerification.NOT_ATTENUATED
    ), "a child may hold no more than the parent consented to"


def test_attestation_for_a_different_subtree_is_not_attenuated() -> None:
    """The scope counterpart: consent to one subtree, child claims a sibling still
    inside the root's."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.other"], ["read"])
    attestation = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.blessed"], ["read"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([attestation]),
        )
        is ChainVerification.NOT_ATTENUATED
    ), "consent to one subtree does not authorize a sibling"


def test_attestation_replayed_onto_a_different_chain_does_not_apply() -> None:
    """A genuine attestation, signed by A, presented against a chain whose parent is
    a different root. It is filed under the pair it names, so the lookup simply does
    not find it — replay is structurally inert rather than rejected."""
    a, b = org_a(), org_b()

    genuine = a.attest(
        vid(1), vid(3), "b.example", "acme", ["data.acme.sub"], ["read"]
    )
    other_root = a.sign(vid(2), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(3), vid(2), "acme", ["data.acme.sub"], ["read"])

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([other_root]),
            AttestationBundle([genuine]),
        )
        is ChainVerification.INAUTHENTIC
    ), "consent is bound to one (parent, child) pair and cannot be replayed"


def test_mid_chain_cross_key_hop_unattested_is_not_attenuated() -> None:
    """A(root) -> B(mid) -> B(leaf): the leaf hop is same-key and needs nothing,
    while the mid hop crosses and is unattested. An attestation IS presented — for
    the wrong hop. A verifier that stopped at the hop nearest the leaf, or accepted
    "some attestation was presented", would pass this."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    mid = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])
    leaf = b.sign(vid(3), vid(2), "acme", ["data.acme.sub.task"], ["read"])
    irrelevant = b.attest(
        vid(2), vid(3), "b.example", "acme", ["data.acme.sub.task"], ["read"]
    )

    verdict = verify_chain_with(
        both_keys(a, b),
        leaf,
        PresentedBundle([root, mid]),
        AttestationBundle([irrelevant]),
    )

    assert verdict is not ChainVerification.ATTENUATED, (
        "an unattested cross-key hop anywhere on the chain must fail the whole chain"
    )
    assert verdict is ChainVerification.INAUTHENTIC


def test_attestation_exceeding_the_parent_authority_is_not_attenuated() -> None:
    """Consent to more than the parent holds. The child stays within the
    attestation, so only the attestation-vs-parent check catches it."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])
    over_broad = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read", "write"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([over_broad]),
        )
        is ChainVerification.NOT_ATTENUATED
    ), "a parent cannot consent to more than it holds"


def test_attestation_naming_a_different_tenant_is_not_attenuated() -> None:
    """Cross-key hops skip pair-equality (they cross domains by definition), so the
    attestation is the only thing binding the child's claimed identity."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(2), vid(1), "other", ["data.acme.sub"], ["read"])
    attestation = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([attestation]),
        )
        is ChainVerification.NOT_ATTENUATED
    ), "consent must name the identity the child actually claims"


def test_an_unaccepted_kernel_key_is_inauthentic() -> None:
    """Accepting a key is the verifier's trust decision; an unaccepted issuer is not
    a degraded issuer, it is somebody else."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read"])
    attestation = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )

    assert (
        verify_chain_with(
            KernelKeyMap([a.public_key]),
            child,
            PresentedBundle([root]),
            AttestationBundle([attestation]),
        )
        is ChainVerification.INAUTHENTIC
    ), "a document signed by an unaccepted key must fail closed"


def test_tampered_attestation_is_inauthentic() -> None:
    """Genuine consent to `read`, widened to `write` while keeping A's signature."""
    a, b = org_a(), org_b()

    root = a.sign(vid(1), None, "acme", ["data.acme"], ["read", "write"])
    child = b.sign(vid(2), vid(1), "acme", ["data.acme.sub"], ["read", "write"])
    tampered = a.attest(
        vid(1), vid(2), "b.example", "acme", ["data.acme.sub"], ["read"]
    )
    tampered["capability_set"] = ["read", "write"]

    assert (
        verify_chain_with(
            both_keys(a, b),
            child,
            PresentedBundle([root]),
            AttestationBundle([tampered]),
        )
        is ChainVerification.INAUTHENTIC
    ), "widening consent after signing must break its signature"

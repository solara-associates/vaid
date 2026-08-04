"""Third-party end-to-end lineage verification (ADR-0003). Integration tests.

The Python mirror of ``crates/vaid-mint/tests/chain_verification.rs``: the same
scenarios, asserting the same (scenario -> outcome) mapping. There is deliberately
no shared vector — ADR-0003 §3 calls for a chain-presentation vector as *additive*
conformance work, and it is deliberately not generated or frozen here, so the
verifier semantics can be reviewed before anything is frozen against them. The
languages agree by construction, as the revocation suite does.

Why these documents are signed locally rather than minted
---------------------------------------------------------

Most cases below are constructible through ``ReferenceIssuer``, but two are not: a
**cycle** and a **depth overflow** both require choosing a document's ``vaid_id``,
and the issuer generates a fresh UUIDv4 per mint and never accepts one. That is a
security property, not an obstacle to route around — it is exactly what makes chain
substitution infeasible.

So the suite drives a local ``LocalMint``: a kernel keypair plus the same public
document-building and canonical-signing calls the issuer itself makes. Documents it
produces are genuinely authentic under its own kernel key, which is the point: it
lets a test present an *authentic but adversarially shaped* chain. It also
deliberately does not enforce attenuation, so a child claiming authority its parent
never held can be signed and presented.
"""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.chain import ChainVerification, PresentedBundle, verify_chain
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import MAX_LINEAGE_DEPTH, ParentResolution, assemble_lineage


class LocalMint:
    """A kernel key plus the issuer's own document-building and signing calls.
    Produces authentic documents while leaving ``agent_id``, lineage and authority
    under the test's control. Attenuation is NOT enforced — see module docstring."""

    def __init__(self, seed_byte: int = 1) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        self.public_key = self._key.public_key().public_bytes_raw()

    def sign(
        self,
        agent_id: str,
        parent_vaid: str | None,
        scope: list[str],
        caps: list[str],
    ) -> dict:
        """Build and kernel-sign a VAID with a caller-chosen id, parent and
        authority."""
        unsigned = build_unsigned_vaid_document(
            vaid_id=agent_id,
            agent_id=agent_id,
            agent_class="test",
            version="1.0.0",
            tenant_id="t",
            issued_at="2026-06-04T12:00:00Z",
            expires_at="2026-06-05T12:00:00Z",
            public_key_der=list(range(32)),
            parent_vaid=parent_vaid,
            scope_boundary=scope,
            lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
            capability_set=caps,
            # RFC 2606 reserved, matching the frozen vector's reasoning: a suite
            # that publishes signable keys must not name a bindable domain.
            trust_domain="vaid.example",
            kernel_key_thumbprint=kernel_key_thumbprint(self.public_key),
        )
        signature = self._key.sign(canonical_vaid_signing_bytes(unsigned))
        return {**unsigned, "kernel_signature": list(signature)}


def vid(n: int) -> str:
    """A stable id from a small integer, so a test can name the ids it wants to
    arrange into a cycle or a long chain."""
    return str(uuid.UUID(int=n))


# ── POSITIVE CONTROLS ───────────────────────────────────────────────────────────


def test_positive_control_complete_attenuated_chain_verifies() -> None:
    """A complete, authentic, properly attenuated three-hop chain verifies.

    Without this the whole suite could pass by rejecting everything."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read", "write"])
    mid = mint.sign(vid(2), vid(1), ["data.tenant.sub"], ["read", "write"])
    leaf = mint.sign(vid(3), vid(2), ["data.tenant.sub.leaf"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root, mid]))
        is ChainVerification.ATTENUATED
    ), "a complete, authentic, contained chain must verify"


def test_positive_control_rootless_leaf_verifies_against_empty_bundle() -> None:
    """A rootless leaf is trivially complete: one hop, nothing to contain."""
    mint = LocalMint()
    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])

    assert (
        verify_chain(mint.public_key, root, PresentedBundle())
        is ChainVerification.ATTENUATED
    ), "a VAID with no parent_vaid is its own root and needs no ancestors"


# ── FAIL-CLOSED CASES ───────────────────────────────────────────────────────────


def test_missing_ancestor_is_unverifiable() -> None:
    """MISSING ANCESTOR. The middle document is withheld, so the hop above the leaf
    resolves to unknown. Never a chain silently shortened to what happens to be
    present."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    mint.sign(vid(2), vid(1), ["data.tenant.sub"], ["read"])  # withheld
    leaf = mint.sign(vid(3), vid(2), ["data.tenant.sub.leaf"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root]))
        is ChainVerification.UNVERIFIABLE
    ), "an unpresented ancestor must be attenuation-unverifiable, not satisfied"


def test_unreachable_resolver_empty_bundle_is_unverifiable() -> None:
    """UNREACHABLE RESOLVER. Nothing at all is presented for a leaf that names a
    parent — the third-party analogue of a resolver that cannot be consulted."""
    mint = LocalMint()
    leaf = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle())
        is ChainVerification.UNVERIFIABLE
    ), "no presented ancestors must fail closed, not resolve the leaf as a root"


def test_tampered_parent_vaid_is_inauthentic() -> None:
    """TAMPERED ``parent_vaid``. The leaf's parent pointer is swapped to a
    more-privileged ancestor while its original kernel signature is kept.
    ``parent_vaid`` is inside the canonical signing bytes, so this breaks the
    signature; ``lineage_hash`` no longer matches either."""
    mint = LocalMint()

    privileged = mint.sign(vid(1), None, ["data"], ["read", "write"])
    restricted = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])
    leaf = mint.sign(vid(3), vid(2), ["data.tenant.sub"], ["read"])

    forged = {**leaf, "parent_vaid": vid(1)}

    assert (
        verify_chain(mint.public_key, forged, PresentedBundle([privileged, restricted]))
        is ChainVerification.INAUTHENTIC
    ), "a re-pointed parent_vaid must break the kernel signature"


def test_ancestor_signed_by_another_kernel_key_is_inauthentic() -> None:
    """A presented ancestor signed by a DIFFERENT kernel key. The v3 thumbprint
    check rejects it before its signature is even considered."""
    mint = LocalMint(1)
    other = LocalMint(2)

    root = other.sign(vid(1), None, ["data"], ["read"])
    leaf = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root]))
        is ChainVerification.INAUTHENTIC
    ), "a chain crossing kernel keys must be rejected, not verified under a key that did not sign it"


def test_child_exceeding_parent_scope_is_not_attenuated() -> None:
    """A CHILD CLAIMING SCOPE ITS PARENT NEVER HELD. Every document is authentic and
    the chain is complete — the only defect is containment, which is precisely what a
    third party could not previously check."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    leaf = mint.sign(vid(2), vid(1), ["data.other"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root]))
        is ChainVerification.NOT_ATTENUATED
    ), "a child must not hold scope outside its parent's, however well signed"


def test_mid_chain_scope_escalation_is_not_attenuated() -> None:
    """Containment is checked at EVERY hop. The leaf is contained by its parent but
    the parent escaped the root, so a leaf-only check would have passed this."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    mid = mint.sign(vid(2), vid(1), ["data.other"], ["read"])
    leaf = mint.sign(vid(3), vid(2), ["data.other.sub"], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root, mid]))
        is ChainVerification.NOT_ATTENUATED
    ), "containment must hold at every hop, not only the one nearest the leaf"


def test_child_exceeding_parent_capabilities_is_not_attenuated() -> None:
    """A child claiming a CAPABILITY its parent never held."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    leaf = mint.sign(vid(2), vid(1), ["data.tenant.sub"], ["read", "write"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root]))
        is ChainVerification.NOT_ATTENUATED
    ), "a child must not hold a capability its parent lacks"


def test_empty_child_scope_under_restricted_parent_is_not_attenuated() -> None:
    """THE ⊤ ESCALATION. An empty child scope means *unrestricted*, so a naive
    ``all()`` over zero entries is vacuously true and would admit an unrestricted
    child under a restricted parent. Reusing the mint-time matcher is what carries
    this guard to verify time; reimplementing containment is how it would be lost."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    leaf = mint.sign(vid(2), vid(1), [], ["read"])

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle([root]))
        is ChainVerification.NOT_ATTENUATED
    ), "an empty (unrestricted) child scope under a restricted parent is an escalation"


def test_cycle_is_unverifiable() -> None:
    """A CYCLE. Two authentic documents each naming the other as parent. Assembly
    must terminate and fail closed rather than loop.

    This shape cannot arise from ``ReferenceIssuer`` — a cycle needs a document to
    name a ``vaid_id`` that does not exist yet, and the issuer mints a fresh UUIDv4
    every time."""
    mint = LocalMint()

    a = mint.sign(vid(1), vid(2), ["data.tenant"], ["read"])
    b = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])

    assert (
        verify_chain(mint.public_key, a, PresentedBundle([a, b]))
        is ChainVerification.UNVERIFIABLE
    ), "a cyclic presentation must fail closed, not loop or resolve"


def test_depth_overflow_is_unverifiable() -> None:
    """DEPTH OVERFLOW. A chain longer than ``MAX_LINEAGE_DEPTH`` must fail closed on
    the bound rather than being walked. Authority is identical at every hop, so the
    ONLY reason this can fail is the depth bound."""
    mint = LocalMint()

    depth = MAX_LINEAGE_DEPTH + 1
    docs = [mint.sign(vid(0), None, ["data.tenant"], ["read"])]
    for n in range(1, depth + 1):
        docs.append(mint.sign(vid(n), vid(n - 1), ["data.tenant"], ["read"]))

    leaf = docs.pop()

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle(docs))
        is ChainVerification.UNVERIFIABLE
    ), "a chain deeper than MAX_LINEAGE_DEPTH must fail closed"


def test_chain_at_the_depth_bound_still_verifies() -> None:
    """Boundary control for the test above. A chain of exactly ``MAX_LINEAGE_DEPTH``
    documents still verifies, so the overflow case is failing on the bound rather
    than on some incidental property of a long chain."""
    mint = LocalMint()

    hops = MAX_LINEAGE_DEPTH - 1
    docs = [mint.sign(vid(0), None, ["data.tenant"], ["read"])]
    for n in range(1, hops + 1):
        docs.append(mint.sign(vid(n), vid(n - 1), ["data.tenant"], ["read"]))

    leaf = docs.pop()

    assert (
        verify_chain(mint.public_key, leaf, PresentedBundle(docs))
        is ChainVerification.ATTENUATED
    ), "a chain exactly at the depth bound must still verify"


# ── RESOLVER CONTRACT ───────────────────────────────────────────────────────────


def test_bundle_resolver_distinguishes_root_from_unknown() -> None:
    """Conflating a genuine root with an unpresented document is the R.4.2 bug that
    lets a leaf whose ancestors were withheld pass as rootless."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    child = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])
    bundle = PresentedBundle([root, child])

    assert bundle.resolve_parent(vid(1)) == ParentResolution.root()
    assert bundle.resolve_parent(vid(2)) == ParentResolution.of_parent(vid(1))
    assert bundle.resolve_parent(vid(99)) == ParentResolution.unknown()


def test_bundle_assembles_ordered_lineage_root_first() -> None:
    """The bundle drives the existing ``assemble_lineage`` unchanged, root first."""
    mint = LocalMint()

    root = mint.sign(vid(1), None, ["data.tenant"], ["read"])
    mid = mint.sign(vid(2), vid(1), ["data.tenant"], ["read"])
    leaf = mint.sign(vid(3), vid(2), ["data.tenant"], ["read"])

    assert assemble_lineage(leaf, PresentedBundle([root, mid])) == [
        vid(1),
        vid(2),
        vid(3),
    ], "ordered root first, leaf last"

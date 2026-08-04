"""Third-party end-to-end lineage verification, by **detached chain presentation**
(ADR-0003). Mirror of the Rust ``vaid_mint::chain``.

:func:`~vaid_mint.verify.verify_vaid_authenticity` answers "is this document real".
It cannot answer "was the authority written into it legitimately derived from its
parent's" — a leaf carries its own ``scope_boundary`` and ``capability_set``, not
its ancestors'. Under that alone, attenuation is a property of the mint's word.

This module closes that without touching the document format. The **presenter**
supplies the ancestor documents alongside the leaf; the verifier walks them. No new
signed field, no ``mint_v1`` re-freeze, no ``sig_version`` bump.

Why no document field is needed
-------------------------------

The leaf does not carry its ancestors' authority, but it carries their **identity,
signed**:

- ``parent_vaid`` is inside the canonical signing bytes, so it cannot be altered
  without breaking the kernel signature;
- :func:`~vaid_mint.verify.verify_lineage_hash` independently recomputes
  ``lineage_hash`` from ``parent_vaid`` and ``agent_id``, so an inconsistent value
  is caught explicitly rather than incidentally.

An ancestor VAID is itself a kernel-signed, self-authenticating statement of its own
authority. The verifier does not need the leaf to *describe* its ancestors; it needs
the ancestors, plus a pinned reference saying which ones are real. Both already
exist.

Chain substitution is prevented by the existing signature
---------------------------------------------------------

To present a more privileged parent, an adversary needs a kernel-signed document
whose ``vaid_id`` equals the ``parent_vaid`` pinned inside the leaf's signed bytes.
Because ``vaid_id`` equals ``agent_id`` and is a fresh UUIDv4 per mint, that
requires a kernel-key compromise or a UUID collision. No new field contributes to
this property; the pin is already signed.

Relationship to R.4.2
---------------------

``docs/spec/revocation.md`` R.4.2 says the full lineage is not recoverable from the
VAID itself, and that assembly needs a resolver whose reference implementation is
the issuer's in-process lineage map — precisely what a third party lacks. That is
true **for revocation**, where assembly starts from a bare identifier and must
resolve upward.

It is not a constraint here. The presenter supplies documents rather than
identifiers, and every document carries its own ``parent_vaid``, so the resolver
becomes a lookup over the presented bundle. No issuer, no network, no new protocol:
:class:`PresentedBundle` is a new implementation of the existing
:class:`~vaid_mint.revocation.LineageResolver`, and the three-state shape is
already correct.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable

from vaid_mint.mint import caps_attenuate, scope_attenuates
from vaid_mint.revocation import ParentResolution, assemble_lineage
from vaid_mint.verify import verify_vaid_authenticity


class ChainVerification(enum.Enum):
    """The outcome of an end-to-end chain verification.

    Only ``ATTENUATED`` is success. The three failure states are kept apart
    deliberately, because collapsing them is how a verifier ends up reporting
    *attenuation satisfied* when it means *attenuation unverifiable* — the same
    conflation R.4.2 forbids for revocation.
    """

    #: Every presented document is authentic, the chain assembles completely from
    #: the leaf to a root, and authority is contained at every hop.
    ATTENUATED = "attenuated"
    #: A presented document — or the leaf — failed authenticity. Nothing further
    #: was checked.
    INAUTHENTIC = "inauthentic"
    #: The chain could not be assembled: an ancestor named by a signed
    #: ``parent_vaid`` was not presented, or assembly hit a cycle or
    #: ``MAX_LINEAGE_DEPTH``. Means **attenuation unverifiable** — never
    #: attenuation satisfied.
    UNVERIFIABLE = "unverifiable"
    #: The chain is complete and authentic, but some child claims authority its
    #: parent does not hold.
    NOT_ATTENUATED = "not_attenuated"

    def is_attenuated(self) -> bool:
        """Whether the chain verified. Provided so callers do not treat a
        non-success state as acceptance by accident."""
        return self is ChainVerification.ATTENUATED


class PresentedBundle:
    """The ancestor documents a presenter supplies alongside a leaf, indexed by
    ``vaid_id``. The third-party stand-in for the issuer's in-process lineage map:
    it resolves ancestry from documents the presenter already holds, so no issuer
    and no network are involved.

    Implements :class:`~vaid_mint.revocation.LineageResolver`, so
    :func:`~vaid_mint.revocation.assemble_lineage` — including its cycle detection
    and its ``MAX_LINEAGE_DEPTH`` bound — is reused unchanged.

    The bundle need not contain the leaf: :func:`verify_chain` takes the leaf
    separately, and ``assemble_lineage`` reads the leaf's parent from the leaf's own
    signed document, only resolving hops **above** it through this bundle.
    """

    def __init__(self, documents: Iterable[dict] = ()) -> None:
        """Build a bundle from the presented ancestor documents.

        Documents are keyed by their own ``vaid_id``. A later document with a
        ``vaid_id`` already present replaces the earlier one; this cannot be used to
        substitute a more privileged ancestor, because every document on the
        assembled chain is authenticated against the kernel key and pinned by a
        signed ``parent_vaid`` (see the module docstring).
        """
        self._documents: dict[str, dict] = {d["vaid_id"]: d for d in documents}

    def get(self, vaid_id: str) -> dict | None:
        """Look up a presented document by ``vaid_id``."""
        return self._documents.get(vaid_id)

    def documents(self) -> list[dict]:
        """Every presented document, in insertion order."""
        return list(self._documents.values())

    def __len__(self) -> int:
        return len(self._documents)

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        """Resolve one hop from the presented documents. A presented document with
        no ``parent_vaid`` is a **known root**; one with a ``parent_vaid`` is a
        **child**; an id that was not presented is **unknown** — the R.4.2
        distinction, which is what makes an incomplete presentation fail closed
        instead of looking like a legitimately rootless VAID."""
        doc = self._documents.get(vaid_id)
        if doc is None:
            return ParentResolution.unknown()
        parent = doc.get("parent_vaid")
        if parent is None:
            return ParentResolution.root()
        return ParentResolution.of_parent(parent)


def verify_chain(
    kernel_public_key: bytes, leaf: dict, bundle: PresentedBundle
) -> ChainVerification:
    """Verify a full delegation chain end to end, as a third party holding only the
    issuer's kernel **public** key and the documents the presenter supplied.

    The procedure is ADR-0003's, in order:

    1. **Authenticate every document** — the leaf and every presented ancestor, via
       :func:`~vaid_mint.verify.verify_vaid_authenticity`. Any failure is
       ``INAUTHENTIC``.
    2. **Pin each hop** — :func:`~vaid_mint.revocation.assemble_lineage` requires a
       presented document whose ``vaid_id`` equals the ``parent_vaid`` pinned inside
       the child's signed bytes, and recurses until a document with no
       ``parent_vaid`` is reached.
    3. **Fail closed on an incomplete chain** — a ``parent_vaid`` that is present but
       not resolvable, a cycle, or an implausible depth all yield ``UNVERIFIABLE``.
    4. **Check containment** — ``scope_L ⊆ scope_P1 ⊆ … ⊆ scope_root``, and the same
       for capabilities, using the **mint-time** matchers
       (:func:`~vaid_mint.mint.scope_attenuates` /
       :func:`~vaid_mint.mint.caps_attenuate`) so the verify-time check cannot drift
       from the one that gated issuance.

    What this does not check
    ------------------------

    Consistent with ``verify_vaid_authenticity``, this answers *authenticity and
    attenuation*, not *standing*. It does not consult **expiry** (call
    :func:`~vaid_mint.document.is_expired`) and does not consult **revocation**
    (evaluate a :class:`~vaid_mint.revocation.RevocationCheck` separately). A third
    party generally cannot assemble lineage for revocation from identifiers alone —
    that is the R.4.2 constraint, and it is unchanged by this module.

    Single trust domain
    -------------------

    All documents on the chain must be signed by ``kernel_public_key``. Each
    document's ``kernel_key_thumbprint`` is checked against that key inside
    ``verify_vaid_authenticity``, so a chain crossing issuers returns ``INAUTHENTIC``
    rather than being accepted under a key that did not sign it. Verifying a chain
    whose hops were signed by *different* kernel keys would need a key-lookup seam
    keyed on ``kernel_key_thumbprint``; that is not built here, and until it is,
    cross-issuer chains are out of scope rather than silently mis-verified.
    """
    # Step 1 — authenticate the leaf and EVERY presented document, before any of
    # them is allowed to influence assembly. Authenticating the whole bundle rather
    # than only the documents that end up on the chain is the stricter reading of
    # ADR-0003 step 1, and it means a presenter cannot mix an unauthenticated
    # document into a bundle and have it ignored.
    if not verify_vaid_authenticity(kernel_public_key, leaf):
        return ChainVerification.INAUTHENTIC
    for doc in bundle.documents():
        if not verify_vaid_authenticity(kernel_public_key, doc):
            return ChainVerification.INAUTHENTIC

    # Steps 2 and 3 — pin each hop against the signed ``parent_vaid``, failing
    # closed on any gap. Cycle detection and MAX_LINEAGE_DEPTH come from
    # ``assemble_lineage`` unchanged.
    chain_ids = assemble_lineage(leaf, bundle)
    if chain_ids is None:
        return ChainVerification.UNVERIFIABLE

    # Resolve each id on the chain back to its document, root first. The leaf is
    # supplied separately and need not appear in the bundle, so it is matched first.
    # Any id that cannot be resolved to a document is a gap, and a gap is
    # UNVERIFIABLE — never a silently shortened chain.
    chain_docs: list[dict] = []
    for vaid_id in chain_ids:
        if vaid_id == leaf["vaid_id"]:
            chain_docs.append(leaf)
            continue
        doc = bundle.get(vaid_id)
        if doc is None:
            return ChainVerification.UNVERIFIABLE
        chain_docs.append(doc)

    # Step 4 — containment at every hop, root first, using the mint-time matchers.
    for parent, child in zip(chain_docs, chain_docs[1:]):
        if not scope_attenuates(parent, child["scope_boundary"]):
            return ChainVerification.NOT_ATTENUATED
        if not caps_attenuate(parent, child["capability_set"]):
            return ChainVerification.NOT_ATTENUATED

    return ChainVerification.ATTENUATED

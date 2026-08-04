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
from datetime import datetime, timezone
from typing import Protocol

from vaid_mint.attestation import (
    AttestationBundle,
    is_current,
    verify_attestation_authenticity,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.mint import (
    caps_attenuate,
    caps_attenuate_within,
    scope_attenuates,
    scope_attenuates_within,
    tenant_attenuates,
)
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
    #: A cross-key hop's consent attestation is **authentic but outside its validity
    #: window** — lapsed, or not yet valid beyond the permitted clock skew.
    #:
    #: Kept distinct on purpose. An expired attestation is not forged: the parent
    #: really did sign it, so ``INAUTHENTIC`` would misdescribe it. Nor did the child
    #: overreach, so ``NOT_ATTENUATED`` would be wrong too. The operational
    #: difference is the point — this says *renew the attestation*, the other two say
    #: *you were never authorized*. **Not withdrawal:** see
    #: :mod:`vaid_mint.attestation`.
    CONSENT_EXPIRED = "consent_expired"

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


class KernelKeyResolver(Protocol):
    """Resolves the kernel public key that signed a document, by its
    ``kernel_key_thumbprint``.

    **Why a seam and not a parameter.** A single-issuer chain needs one key and
    could take it as an argument — which is what :func:`verify_chain` does. A chain
    that crosses organisations needs the key that signed *each* document, selected
    by the thumbprint the document commits to (ADR-0004). That selection is the
    verifier's trust decision and belongs to the caller.

    **Returning a key is an assertion of trust.** A resolver that answers for a
    thumbprint is saying "I accept documents signed by this key". Resolving it from
    the document itself, or any source the presenter controls, verifies that a
    number equals itself — see ``docs/trust-anchor.md``.
    """

    def resolve_key(self, thumbprint: str) -> bytes | None:
        """The raw 32-byte Ed25519 public key for ``thumbprint``, or ``None`` if
        this verifier does not accept that key. ``None`` fails closed."""
        ...


class SingleKernelKey:
    """A resolver holding exactly one kernel key: the single-trust-domain case, and
    what :func:`verify_chain` wraps."""

    def __init__(self, public_key: bytes) -> None:
        # Derived from the key rather than supplied, so the two cannot disagree.
        self._thumbprint = kernel_key_thumbprint(bytes(public_key))
        self._public_key = bytes(public_key)

    def resolve_key(self, thumbprint: str) -> bytes | None:
        return self._public_key if thumbprint == self._thumbprint else None


class KernelKeyMap:
    """A resolver over a map of accepted kernel keys, for chains that cross issuers.

    Every key placed here is one this verifier accepts. The map is the trust bundle;
    populating it from a channel the presenter controls defeats the purpose.
    """

    def __init__(self, public_keys: Iterable[bytes] = ()) -> None:
        # Each key is filed under its OWN derived thumbprint, so a key cannot be
        # registered under a thumbprint that is not its own.
        self._keys = {kernel_key_thumbprint(bytes(k)): bytes(k) for k in public_keys}

    def resolve_key(self, thumbprint: str) -> bytes | None:
        return self._keys.get(thumbprint)

    def __len__(self) -> int:
        return len(self._keys)


def verify_chain(
    kernel_public_key: bytes, leaf: dict, bundle: PresentedBundle
) -> ChainVerification:
    """Verify a full delegation chain end to end against a **single** kernel key.

    Convenience over :func:`verify_chain_with` for the single-trust-domain case:
    every document must be signed by ``kernel_public_key``. Because no hop can cross
    a kernel key, no consent attestation is required or consulted.
    """
    return verify_chain_with(
        SingleKernelKey(kernel_public_key), leaf, bundle, AttestationBundle()
    )


def verify_chain_with(
    keys: KernelKeyResolver,
    leaf: dict,
    bundle: PresentedBundle,
    attestations: AttestationBundle,
) -> ChainVerification:
    """:func:`verify_chain_at` against the system clock.

    Convenience for callers with no reason to control time. Anything that needs a
    reproducible verdict — a conformance vector, a boundary test, replaying a
    historical decision — must call :func:`verify_chain_at` with an explicit instant
    instead, or it is asserting against whenever it happened to run.
    """
    return verify_chain_at(
        keys, leaf, bundle, attestations, datetime.now(timezone.utc)
    )


def verify_chain_at(
    keys: KernelKeyResolver,
    leaf: dict,
    bundle: PresentedBundle,
    attestations: AttestationBundle,
    now: datetime,
) -> ChainVerification:
    """Verify a full delegation chain end to end, selecting a kernel key per
    document and requiring parental consent for any hop that crosses one.

    ADR-0003's procedure, extended at the two points where crossing a kernel key
    changes what can be concluded:

    1. **Authenticate every document** — key selected from ``keys`` by the
       document's own ``kernel_key_thumbprint``. An unaccepted thumbprint or a
       failed signature is ``INAUTHENTIC``.
    2. **Pin each hop** against the signed ``parent_vaid``.
    3. **Fail closed on an incomplete chain** — ``UNVERIFIABLE``.
    4. **Check containment** — tenant (same-key hops), scope, capabilities.
    5. **Require consent on a cross-key hop**, current at ``now`` — a valid
       :func:`~vaid_mint.attestation.build_unsigned_attestation` object for exactly
       that ``(parent, child)`` pair, signed by the issuer that minted the parent.
       Same-key hops need none: the single issuer enforced consent at mint time.

    **Why step 5 exists.** Without it, an issuer B holding its own kernel key could
    mint a document naming issuer A's root ``vaid_id`` as ``parent_vaid``, with
    authority inside A's, and have it verify as ``ATTENUATED`` — while A delegated
    nothing. See :mod:`vaid_mint.attestation`.

    **Verdict mapping.** Authenticity failures (missing consent, signed by a key
    that did not issue the parent, naming another hop) are ``INAUTHENTIC``. Authority
    failures (consent narrower than the child claims, or broader than the parent
    holds) are ``NOT_ATTENUATED``. No cross-key hop reaches ``ATTENUATED`` without
    valid consent.
    """

    # Step 1 — authenticate the leaf and EVERY presented document, before any of
    # them is allowed to influence assembly.
    def authenticate(doc: dict) -> bool:
        key = keys.resolve_key(doc.get("kernel_key_thumbprint"))
        # An unaccepted issuer is not a degraded issuer, it is somebody else.
        return False if key is None else verify_vaid_authenticity(key, doc)

    if not authenticate(leaf):
        return ChainVerification.INAUTHENTIC
    for doc in bundle.documents():
        if not authenticate(doc):
            return ChainVerification.INAUTHENTIC

    # Steps 2 and 3 — pin each hop, failing closed on any gap. Cycle detection and
    # MAX_LINEAGE_DEPTH come from ``assemble_lineage`` unchanged.
    chain_ids = assemble_lineage(leaf, bundle)
    if chain_ids is None:
        return ChainVerification.UNVERIFIABLE

    chain_docs: list[dict] = []
    for vaid_id in chain_ids:
        if vaid_id == leaf["vaid_id"]:
            chain_docs.append(leaf)
            continue
        doc = bundle.get(vaid_id)
        if doc is None:
            return ChainVerification.UNVERIFIABLE
        chain_docs.append(doc)

    # Steps 4 and 5 — containment at every hop, root first, plus consent wherever a
    # hop crosses a kernel key.
    for parent, child in zip(chain_docs, chain_docs[1:]):
        same_key = parent["kernel_key_thumbprint"] == child["kernel_key_thumbprint"]

        # Tenant as the qualified pair — on SAME-KEY hops. A CROSS-KEY hop crosses
        # trust domains by definition, so requiring equality would forbid the very
        # case attestations exist to enable; the crossing is instead named and
        # signed in the attestation below. The pair is still checked on every hop —
        # against a signed statement rather than the parent's own values.
        if same_key and not tenant_attenuates(
            parent, child["trust_domain"], child["tenant_id"]
        ):
            return ChainVerification.NOT_ATTENUATED
        if not scope_attenuates(parent, child["scope_boundary"]):
            return ChainVerification.NOT_ATTENUATED
        if not caps_attenuate(parent, child["capability_set"]):
            return ChainVerification.NOT_ATTENUATED

        # Same kernel key: one issuer signed both ends and enforced consent at mint
        # time. Behaviour unchanged from before cross-key support.
        if same_key:
            continue

        # Cross-key hop. Consent must be presented, and must be the PARENT issuer's.
        attestation = attestations.get(parent["vaid_id"], child["vaid_id"])
        if attestation is None:
            # Also the outcome for an attestation minted for a different hop: it is
            # filed under that hop's pair and is simply not found here. Replay is
            # inert rather than rejected.
            return ChainVerification.INAUTHENTIC

        # The consenting party must be the party that issued the parent. Without
        # this, any accepted key could consent on any parent's behalf.
        if (
            attestation["kernel_key_thumbprint"] != parent["kernel_key_thumbprint"]
            or attestation["trust_domain"] != parent["trust_domain"]
        ):
            return ChainVerification.INAUTHENTIC

        key = keys.resolve_key(attestation["kernel_key_thumbprint"])
        if key is None or not verify_attestation_authenticity(key, attestation):
            return ChainVerification.INAUTHENTIC

        # The consent must be current. Checked AFTER authenticity, so a forged
        # attestation is reported as forged rather than as merely stale — the
        # stronger statement is the more useful one.
        #
        # NOTE: this consults the ATTESTATION's window only. Document expiry is
        # deliberately not consulted here, exactly as elsewhere in this module; an
        # attestation may outlive the parent VAID it delegates from, and whether that
        # should change is a separate decision.
        if not is_current(attestation, now):
            return ChainVerification.CONSENT_EXPIRED

        # The consent must name the identity the child actually claims, or an
        # attestation for a child in one tenant would authorize the same vaid_id
        # claiming any other.
        if (
            attestation["child_trust_domain"] != child["trust_domain"]
            or attestation["child_tenant_id"] != child["tenant_id"]
        ):
            return ChainVerification.NOT_ATTENUATED

        # The child may hold no more than the parent consented to...
        if not scope_attenuates_within(
            attestation["scope_boundary"], child["scope_boundary"]
        ) or not caps_attenuate_within(
            attestation["capability_set"], child["capability_set"]
        ):
            return ChainVerification.NOT_ATTENUATED

        # ...and the parent cannot consent to more than it holds. Checked separately
        # from the hop containment above: that compares child to parent, this
        # compares the ATTESTATION to parent — an over-broad attestation with a
        # well-behaved child would otherwise pass.
        if not scope_attenuates(
            parent, attestation["scope_boundary"]
        ) or not caps_attenuate(parent, attestation["capability_set"]):
            return ChainVerification.NOT_ATTENUATED

    return ChainVerification.ATTENUATED

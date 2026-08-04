"""**Detached consent attestation**: a parent issuer's signed statement that a
particular child may hold particular authority under a particular parent. Mirror of
the Rust ``vaid_mint::attestation``.

The gap this closes
-------------------

Nothing in a VAID document proves the parent *consented* to the delegation.
``mint_child`` requires an authenticated parent principal and pins the child's
``parent_vaid`` to that verified parent — but that enforcement is a property of the
mint's session, in-process, at mint time. None of it lands in the child document.
What the child carries is ``parent_vaid`` (a UUID its own issuer writes and signs
with its own kernel key) and ``lineage_hash``, computed from that same
issuer-chosen value. The proof-of-possession proves the child controls its key, not
that the parent authorized anything.

Under **one** kernel key this is invisible and the design is sound: the single mint
is the only thing that can sign, and it enforced consent before signing. Widen the
key set and it stops being sound. An issuer B, holding its own kernel key, can mint
a document naming issuer A's root ``vaid_id`` as ``parent_vaid``, with scope and
capabilities inside A's, and sign it with B's key. Every document authenticates
under its own key, the chain assembles, containment holds — and A never delegated
anything to B. B needs only to *know* A's root ``vaid_id``, which is disclosed to
every verifier in any chain presentation.

This is why cross-key hops require an attestation and same-key hops do not.

Additive, by construction
-------------------------

No VAID document changes. No new field, no ``sig_version`` bump, no ``mint_v1``
re-freeze. This is a **separate signed object** presented alongside the chain — the
same move ADR-0003 made for the ancestors themselves.

Canonicalization
----------------

Identical discipline to the VAID document: force the signature field to JSON
``null`` (a signature cannot cover its own value), canonicalize per RFC 8785 (JCS),
SHA-256. Byte-array fields are lists of ints, exactly as Rust serializes
``Vec<u8>``.

Replayed and absent consent are indistinguishable in the verdict
---------------------------------------------------------------

:class:`AttestationBundle` indexes attestations by the ``(parent_vaid,
child_vaid)`` hop they name. The verifier asks for the hop in front of it, so an
attestation minted for a *different* delegation is filed under a different key and
is simply not found. It is never **rejected** — there is no rejection path, and
therefore no rejection path to get wrong.

**The cost, stated because it is real:** a presenter who replays a genuine
attestation onto the wrong chain and a presenter who supplies nothing at all receive
the *same* verdict, ``INAUTHENTIC``. Both are safe — neither can reach
``ATTENUATED`` — but the verdict alone cannot tell an operator which happened.
Diagnosing "I presented consent and it was ignored" means comparing the
attestation's own ``parent_vaid``/``child_vaid`` against the hop by hand, outside
the verifier.

This was chosen deliberately over an explicit "this attestation names a different
hop" check. Such a check is a second code path that must agree with the lookup, and
a disagreement between the two is precisely the shape of bug that lets a mismatched
attestation through. Structural inertness has no such failure mode. If a deployment
needs to tell the two apart, the right fix is a *diagnostic* that reports which hops
lacked consent — not a rejection branch in the verifier.

A time bound is a mitigation, not withdrawal
-------------------------------------------

An attestation carries ``issued_at`` and ``expires_at``, and
:func:`~vaid_mint.chain.verify_chain_at` refuses one outside its window with
``ChainVerification.CONSENT_EXPIRED``.

**This does not let a parent withdraw consent.** It bounds how long stale consent
remains usable; it does nothing about consent an organisation wants to retract
*inside* its window. Retraction needs durable revocation, and **durable revocation
does not exist in this implementation** — the reference stores are in-memory and do
not survive restart (``docs/spec/revocation.md`` R.4.6). Until it does, the honest
statement is that consent is time-bounded, not revocable.

This is the same distinction R.5 draws for VAID time-to-live, and it is stated here
for the same reason: a validity window is exactly the kind of field that gets read
as solving withdrawal when it does not. Choosing a short ``expires_at`` is the whole
of the mitigation.

``expires_at`` is **required and has no default**. Consent that outlives its purpose
should be somebody's stated intention, never a value that arrived by omission.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_mint.issuer_identity import is_valid_trust_domain, kernel_key_thumbprint
from vaid_mint.mint import MINT_POP_FRESHNESS_SECS

#: Attestation format discriminant. Independent of ``sig_version``: this is a
#: separate object with its own shape, and bumping one must not imply the other.
ATTESTATION_VERSION = 1


def build_unsigned_attestation(
    *,
    parent_vaid: str,
    child_vaid: str,
    child_trust_domain: str,
    child_tenant_id: str,
    issued_at: str,
    expires_at: str,
    scope_boundary: list[str],
    capability_set: list[str],
    trust_domain: str,
    kernel_key_thumbprint: str,
) -> dict:
    """Assemble the snake_case attestation with an empty ``signature``.

    The field set and names mirror the Rust ``ConsentAttestation`` exactly; the
    parent's issuer signs the canonical bytes of this and attaches the signature.

    Read it as: *the issuer holding the kernel key identified by
    ``kernel_key_thumbprint``, in trust domain ``trust_domain``, consents to
    ``child_vaid`` — claiming ``child_trust_domain``/``child_tenant_id`` — holding
    at most ``scope_boundary``/``capability_set`` under ``parent_vaid``.*

    ``child_trust_domain`` is why a cross-key hop can legitimately change trust
    domain when a same-key hop cannot: a cross-organisation delegation crosses that
    boundary by definition, so the crossing must be *named and signed* by the
    consenting parent rather than merely permitted.
    """
    return {
        "att_version": ATTESTATION_VERSION,
        "parent_vaid": parent_vaid,
        "child_vaid": child_vaid,
        "child_trust_domain": child_trust_domain,
        "child_tenant_id": child_tenant_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "scope_boundary": scope_boundary,
        "capability_set": capability_set,
        "trust_domain": trust_domain,
        "kernel_key_thumbprint": kernel_key_thumbprint,
        "signature": [],
    }


def canonical_attestation_signing_bytes(attestation: dict) -> bytes:
    """The 32-byte signing digest of an attestation.

    Same discipline as :func:`~vaid_mint.document.canonical_vaid_signing_bytes`:
    copy, force ``signature`` to JSON ``null``, canonicalize per RFC 8785, SHA-256.
    """
    payload = dict(attestation)
    payload["signature"] = None
    return hashlib.sha256(rfc8785.dumps(payload)).digest()


def verify_attestation_authenticity(kernel_public_key: bytes, attestation: dict) -> bool:
    """Verify an attestation's **authenticity** against a kernel public key.

    Checks the format discriminant, that ``trust_domain`` is well-formed, that
    ``kernel_key_thumbprint`` **corresponds to** ``kernel_public_key`` (the same
    key-commitment check the document verifier makes — "verified under some key we
    hold" is a verdict nobody can audit), and the Ed25519 signature.

    This answers only *is this attestation real*. Whether it applies to the hop in
    front of you is checked by :func:`~vaid_mint.chain.verify_chain_with`, which has
    the documents.

    A malformed key, a bad signature, or any tampered field is ``False``, never an
    exception.
    """
    if attestation.get("att_version") != ATTESTATION_VERSION:
        return False
    if not is_valid_trust_domain(attestation.get("trust_domain")):
        return False
    try:
        expected = kernel_key_thumbprint(bytes(kernel_public_key))
    except (TypeError, ValueError):
        return False
    if attestation.get("kernel_key_thumbprint") != expected:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(kernel_public_key)).verify(
            bytes(attestation.get("signature") or []),
            canonical_attestation_signing_bytes(attestation),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _parse_e6(value: object) -> datetime | None:
    """Parse an E.6 timestamp (whole-second RFC 3339 UTC, literal ``Z``).

    Returns ``None`` for anything unparseable, and every caller treats ``None`` as
    *outside the window*. That direction is deliberate: a timestamp that cannot be
    read is not a timestamp that can be shown to be current. TypeScript's
    ``isExpired`` had the opposite behaviour once — ``Date.parse`` yields ``NaN``,
    every comparison against ``NaN`` is false, and unreadable expiry silently read
    as "not expired". That fail-open is not repeated here.
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def is_current(attestation: dict, now: datetime) -> bool:
    """Is this consent inside its validity window at ``now``? Mirror of the Rust
    ``ConsentAttestation::is_current``.

    Both directions are checked, and they are treated asymmetrically on purpose:

    - **Expiry is exact.** ``now > expires_at`` is lapsed, with no grace. Being
      generous at the end of a validity window is being generous in the one
      direction that extends unauthorized access.
    - **Not-yet-valid tolerates skew**, by ``MINT_POP_FRESHNESS_SECS`` — the same
      allowance the mint already makes for a proof-of-possession, reused rather than
      reinvented. A verifier whose clock is a few seconds behind the attesting
      issuer should not reject consent that is merely young.

    A window where ``expires_at <= issued_at`` is never current: it cannot be
    satisfied at any instant, and treating it as valid-forever would be the worst
    available reading of a malformed window. An unparseable timestamp is likewise
    never current.
    """
    issued = _parse_e6(attestation.get("issued_at"))
    expires = _parse_e6(attestation.get("expires_at"))
    if issued is None or expires is None:
        return False
    if expires <= issued:
        return False
    if now > expires:
        return False
    return now >= issued - timedelta(seconds=MINT_POP_FRESHNESS_SECS)


class AttestationBundle:
    """The attestations a presenter supplies alongside a chain, indexed by the
    ``(parent_vaid, child_vaid)`` hop they cover.

    Lookup is by hop rather than by list scan, which is what makes a **replayed**
    attestation structurally inert: one minted for a different delegation is filed
    under that pair and is simply not found when a different pair is asked for. It
    never has to be *rejected*, so there is no rejection path to get wrong.
    """

    def __init__(self, attestations: Iterable[dict] = ()) -> None:
        self._by_hop: dict[tuple[str, str], dict] = {
            (a["parent_vaid"], a["child_vaid"]): a for a in attestations
        }

    def get(self, parent_vaid: str, child_vaid: str) -> dict | None:
        """The attestation covering this hop, if one was presented."""
        return self._by_hop.get((parent_vaid, child_vaid))

    def __len__(self) -> int:
        return len(self._by_hop)

"""Standalone, public-key-only verification of a VAID document — Python mirror of
the Rust ``vaid_mint::verify``.

:meth:`~vaid_mint.issuer.ReferenceIssuer.verify_vaid` can only be called by a party
holding a ``ReferenceIssuer``, and every issuer constructor needs the kernel
**private** key. An Ed25519 signature needs only the **public** key to verify, so
this module exposes that: a third party holding just the issuer's kernel public key
can confirm a VAID document is authentic — no issuer instance, no private key.

Scope: **authenticity**, not standing. :func:`verify_vaid_authenticity` checks the
signature-scheme version, the kernel Ed25519 signature over the canonical document,
and the consistency of ``lineage_hash``. It deliberately does **not** check expiry
(a temporal concern — use :func:`~vaid_mint.document.is_expired`) and does **not**
consult revocation: a resolver-less verifier answers authenticity, and gating that
on a lineage/revocation lookup it cannot perform would make every third-party check
fail closed (rebuilding the R.4.2 problem in a new place).
"""

from __future__ import annotations

import enum
import json
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_mint.issuer_identity import (
    is_valid_trust_domain,
    kernel_key_thumbprint,
)
from vaid_mint.document import (
    VAID_SIG_VERSION_V3,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    is_expired,
)
from vaid_mint.revocation import RevocationStatus


def verify_lineage_hash(vaid: dict) -> bool:
    """Recompute ``lineage_hash`` from the document's own ``parent_vaid`` and
    ``agent_id`` and compare. Catches an inconsistent ``lineage_hash`` **explicitly**,
    not incidentally via the kernel signature. Mirror of the Rust
    ``verify_lineage_hash``."""
    agent_id = vaid.get("agent_id")
    if agent_id is None:
        return False
    return compute_lineage_hash(vaid.get("parent_vaid"), agent_id) == vaid.get("lineage_hash")


def verify_vaid_authenticity(kernel_public_key: bytes, vaid: dict) -> bool:
    """Verify a VAID document's **authenticity** against an issuer's kernel
    **public** key (raw 32 bytes) — no issuer instance, no private key. Mirror of the
    Rust ``vaid_mint::verify::verify_vaid_authenticity``.

    This answers *authenticity* — "genuinely issued under this key, and internally
    consistent" — **not** *standing* ("valid and unrevoked right now"). A ``True``
    result does not mean the VAID is currently usable; it means it is real.

    Checks (all must hold for ``True``):

    - the signature-scheme version is current;
    - ``lineage_hash`` is internally consistent (:func:`verify_lineage_hash`);
    - the kernel Ed25519 signature is valid over the canonical document.

    Does NOT check — the caller must handle these separately:

    - **the E.6 timestamp profile** — call
      :func:`~vaid_mint.document.has_conforming_timestamps`; a non-conforming
      timestamp already fails the signature check here, and that function is how
      the failure is explained rather than merely observed;
    - **expiry** — call :func:`~vaid_mint.document.is_expired`; an expired-but-signed
      VAID returns ``True`` here;
    - **revocation** — evaluate a :class:`~vaid_mint.revocation.RevocationCheck` (or,
      in the reference, :meth:`~vaid_mint.issuer.ReferenceIssuer.revocation_status`)
      on a separate path. Revocation is deliberately *not* consulted here.

    A malformed key, a bad signature, or any tampered signed field is ``False``,
    never an exception.
    """
    # Expressed in terms of the graded verdict rather than duplicating its
    # branches. Two parallel implementations of the same check are two things that
    # can drift; this way the boolean IS the graded verdict, read narrowly, and a
    # future edit cannot change one without changing the other.
    return verify_vaid_authenticity_graded(kernel_public_key, vaid) is VaidVerdict.VALID


# ── the graded verdict ───────────────────────────────────────────────────────


class VaidVerdict(enum.Enum):
    """Why a VAID was or was not honoured — the reason alongside the boolean.
    Mirror of the Rust ``vaid_mint::verify::VaidVerdict``.

    **Why a boolean was not enough.** ``False`` collapses "this document is forged"
    into "I could not reach a revocation list". Both are refusals; only one is an
    accusation. A caller that cannot tell them apart cannot log the difference,
    cannot alert on the difference, and cannot retry the one worth retrying.

    **Two rules inherited from decisions this repo has already made:**

    1. *"I could not determine this" is its own state.* It is :attr:`INDETERMINATE`,
       and it is never folded into a negative. The same rule already governs
       :attr:`~vaid_mint.revocation.RevocationStatus.UNAVAILABLE`, the four-valued
       chain verdict, and the packaged firewall's refusal to report PASS over zero
       vectors.
    2. *Fail closed on ambiguity.* :attr:`INDETERMINATE` is not valid:
       :meth:`is_valid` is true for :attr:`VALID` and nothing else. Unavailable
       never reads as usable.

    **Additive.** Nothing here changes an existing verdict or an existing
    signature. :func:`verify_vaid_authenticity` keeps its exact signature and its
    exact behaviour — it is now *defined as*
    ``verify_vaid_authenticity_graded(...) is VALID``, the same function read
    narrowly rather than a second copy of it.

    **The states are the ones the vectors distinguish.** Each member is reachable
    by at least one case in ``verdict_v1.json``. A state no vector can produce
    would be a claim with no evidence behind it, so there are none: candidates no
    case could separate were merged rather than kept for symmetry with anyone
    else's list.

    The value of each member is its stable wire string — the vocabulary the vector
    is written in, and the thing three implementations must agree on. Two
    implementations that reject the same document for *different* reasons disagree
    even though their booleans match, and that is only visible if the reason has a
    name both of them spell the same way.
    """

    #: Authentic, unexpired, and revocation was consulted and reported clean. The
    #: only member for which :meth:`is_valid` is true.
    VALID = "valid"
    #: The bytes are not a VAID document: truncated, not JSON, a required member
    #: absent, or a member of the wrong type. Nothing downstream was evaluated
    #: because there was nothing to evaluate.
    UNPARSEABLE = "unparseable"
    #: Parsed, but the signature-scheme discriminant is not the current one. A v2
    #: document reaches this; so does a forged document with no ``sig_version``.
    UNSUPPORTED_SIG_VERSION = "unsupported_sig_version"
    #: Parsed, but ``trust_domain`` is not a well-formed DNS-shaped name
    #: (ADR-0004). The document names an issuer nobody can look up.
    MALFORMED_TRUST_DOMAIN = "malformed_trust_domain"
    #: The document's ``kernel_key_thumbprint`` does not correspond to the key it
    #: is being verified against — the v3 key-commitment check. This is the verdict
    #: for a document signed by a non-kernel key that also rewrote the thumbprint
    #: to match its own: the signature is internally consistent, and it is the
    #: *wrong issuer*. Distinct from :attr:`INAUTHENTIC`, which is the same forgery
    #: that left the thumbprint alone.
    ISSUER_MISMATCH = "issuer_mismatch"
    #: ``lineage_hash`` does not recompute from the document's own ``parent_vaid``
    #: and ``agent_id``. Caught explicitly rather than incidentally via the
    #: signature, so a document whose mint signed a malformed lineage is named.
    LINEAGE_INCONSISTENT = "lineage_inconsistent"
    #: The kernel signature does not verify over the presented bytes. Payload
    #: tampered, signature tampered, or signed by a key that is not the one the
    #: document commits to. This is the accusation; everything above it is a
    #: structural complaint.
    INAUTHENTIC = "inauthentic"
    #: Authentic, and past ``expires_at``. Checked *after* authenticity on purpose:
    #: a forged expired document is :attr:`INAUTHENTIC`, not :attr:`EXPIRED` — the
    #: more serious reason wins, because "expired" invites a renewal that would
    #: hand a forger a fresh document.
    EXPIRED = "expired"
    #: Authentic and unexpired, but some VAID in its lineage is revoked (R.4.4).
    REVOKED = "revoked"
    #: Standing could not be determined: the revocation store could not be
    #: consulted, or the lineage could not be completely assembled. **Not** a
    #: negative and **not** a positive — the third state, reported as itself. Fails
    #: closed: :meth:`is_valid` is false.
    INDETERMINATE = "indeterminate"

    def is_valid(self) -> bool:
        """True for :attr:`VALID` alone.

        This is the fail-closed rule in one line: every other member, including
        :attr:`INDETERMINATE`, is not usable. A caller that only wants the boolean
        gets exactly the pre-existing behaviour.
        """
        return self is VaidVerdict.VALID

    @property
    def code(self) -> str:
        """The stable wire string — the vocabulary ``verdict_v1.json`` uses."""
        return self.value

    @classmethod
    def from_code(cls, code: str) -> VaidVerdict | None:
        """Parse a wire string back to a verdict, or ``None`` if it names no known
        state.

        ``None`` rather than a fallback member: an unrecognised reason code is not
        a verdict, and silently mapping it to one would let a vector naming a state
        this build does not have report agreement it never established.
        """
        try:
            return cls(code)
        except ValueError:
            return None


def _is_byte_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value
    )


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(s, str) for s in value)


def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _is_timestamp(value: object) -> bool:
    from vaid_mint.document import _parse_rfc3339

    return _parse_rfc3339(value) is not None


#: The structural contract a VAID document must satisfy to be *parseable at all*,
#: as distinct from *valid*.
#:
#: This mirrors, member for member, the Rust ``Vaid`` struct — which is a typed
#: struct, so in Rust this gate is `serde`'s and costs nothing to state. Python and
#: TypeScript hand their verifiers a plain map, which has no such gate, so without
#: this table the three implementations would answer *different questions* about
#: malformed input and a conformance vector comparing them would compare nothing.
#: Keeping it as data rather than a hand-rolled sequence of ``if`` statements is
#: what makes it reviewable against the struct it mirrors.
_REQUIRED_MEMBERS: tuple[tuple[str, object], ...] = (
    ("vaid_id", _is_uuid),
    ("agent_id", _is_uuid),
    ("agent_class", lambda v: isinstance(v, str)),
    ("version", lambda v: isinstance(v, str)),
    ("tenant_id", lambda v: isinstance(v, str)),
    ("issued_at", _is_timestamp),
    ("expires_at", _is_timestamp),
    ("public_key_der", _is_byte_list),
    ("kernel_signature", _is_byte_list),
    ("scope_boundary", _is_str_list),
    ("lineage_hash", lambda v: isinstance(v, str)),
    ("capability_set", _is_str_list),
    ("trust_domain", lambda v: isinstance(v, str)),
    ("kernel_key_thumbprint", lambda v: isinstance(v, str)),
)


def parse_vaid_document(document_json: str) -> dict | None:
    """Parse JSON **text** into a VAID document mapping, or ``None`` if the bytes
    are not one. Mirror of Rust's ``serde_json::from_str::<Vaid>``.

    Structure only — this says nothing about whether the document is authentic,
    unexpired or unrevoked. It answers the strictly earlier question: is there a
    document here to have an opinion about?

    Unknown members are **preserved**, not dropped (ADR-0006): a verifier
    canonicalizes the document it was *presented*, and an additive extension is
    inside the signed bytes. This function is a gate, never a filter.

    ``sig_version`` is deliberately optional and defaults to ``0``, matching the
    Rust field's ``#[serde(default)]``: a pre-v3 or forged document with the member
    missing must deserialize cleanly and then be *rejected at verify* as
    :attr:`VaidVerdict.UNSUPPORTED_SIG_VERSION`, rather than being reported as
    unparseable. The two failures are different accusations and a caller is
    entitled to tell them apart.

    ``parent_vaid`` is optional and nullable, matching ``Option<VaidId>``: absent
    and present-null both mean "root".
    """
    try:
        document = json.loads(document_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    for member, is_well_typed in _REQUIRED_MEMBERS:
        if member not in document or not is_well_typed(document[member]):
            return None
    sig_version = document.get("sig_version", 0)
    if not isinstance(sig_version, int) or isinstance(sig_version, bool):
        return None
    # Bounded to a byte because the Rust field is `u8`. Without this, `sig_version:
    # 999` is UNPARSEABLE in Rust and UNSUPPORTED_SIG_VERSION here — the booleans
    # agree, the reasons do not, and that is exactly the divergence class this
    # mirror exists to prevent. Found by differential probe, not by review.
    if not 0 <= sig_version <= 255:
        return None
    parent = document.get("parent_vaid")
    if parent is not None and not _is_uuid(parent):
        return None
    return document


def verify_vaid_authenticity_graded(kernel_public_key: bytes, vaid: dict) -> VaidVerdict:
    """Graded :func:`verify_vaid_authenticity`: the same checks, in the same order,
    saying which one refused.

    The branch order is **load-bearing and unchanged** — ``sig_version``,
    ``trust_domain``, thumbprint, ``lineage_hash``, signature. It is not the only
    defensible order, but it is the order all three implementations already had,
    and reordering it here would silently change which reason a document gets while
    leaving every boolean identical. That is precisely the class of divergence
    ``verdict_v1.json`` exists to catch, so this function must not introduce one.

    Never returns :attr:`~VaidVerdict.EXPIRED`, :attr:`~VaidVerdict.REVOKED` or
    :attr:`~VaidVerdict.INDETERMINATE`: authenticity is not standing. Use
    :func:`verify_vaid_standing` for that.
    """
    if vaid.get("sig_version") != VAID_SIG_VERSION_V3:
        return VaidVerdict.UNSUPPORTED_SIG_VERSION
    if not is_valid_trust_domain(vaid.get("trust_domain")):
        return VaidVerdict.MALFORMED_TRUST_DOMAIN
    # The v3 key-commitment check: does the document's thumbprint CORRESPOND to
    # the key we were handed? Without it a caller could verify a document against
    # a key the document never named, and "verified under some key we hold" is a
    # verdict nobody can audit. Ordered before the signature check — one hash is
    # cheaper than an Ed25519 verification already known to fail.
    #
    # A key that is not even bytes cannot correspond to any commitment, so it lands
    # here rather than in a state of its own: the accurate statement is "the key
    # you handed me is not the one this document names", which is exactly
    # ISSUER_MISMATCH. Rust reaches the same verdict by a different route — its
    # thumbprint function hashes whatever bytes it is given and simply fails to
    # match — so the two agree on the answer without agreeing on the mechanism.
    try:
        expected = kernel_key_thumbprint(bytes(kernel_public_key))
    except (TypeError, ValueError):
        return VaidVerdict.ISSUER_MISMATCH
    if vaid.get("kernel_key_thumbprint") != expected:
        return VaidVerdict.ISSUER_MISMATCH
    if not verify_lineage_hash(vaid):
        return VaidVerdict.LINEAGE_INCONSISTENT
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(kernel_public_key))
        public_key.verify(bytes(vaid["kernel_signature"]), canonical_vaid_signing_bytes(vaid))
        return VaidVerdict.VALID
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return VaidVerdict.INAUTHENTIC


def verify_vaid_standing(
    kernel_public_key: bytes,
    vaid: dict,
    revocation: RevocationStatus,
) -> VaidVerdict:
    """The full standing verdict: authenticity, then expiry, then revocation.

    Revocation is **passed in**, not looked up. This module still performs no
    resolution — gating third-party verification on a lookup the verifier cannot do
    is the R.4.2 problem, and adding a graded return is not a licence to rebuild
    it. The caller assembles the lineage and consults its
    :class:`~vaid_mint.revocation.RevocationCheck`; this function says what the
    answer means. An incomplete assembly is
    :attr:`~vaid_mint.revocation.RevocationStatus.UNAVAILABLE`, which arrives here
    as :attr:`~VaidVerdict.INDETERMINATE`.

    **Order, and why it is this one:**

    1. *Authenticity.* A document that is not real has no standing to discuss. A
       forgery that happens to be expired is reported as a forgery.
    2. *Expiry.* Determinable from the document alone. Checked before revocation so
       that a definite answer is never displaced by :attr:`~VaidVerdict.INDETERMINATE`
       — reporting "I could not tell" about a document we can positively see has
       expired discards information we already hold.
    3. *Revocation.* The only input that can be unavailable, so it is last.

    Expiry uses :func:`~vaid_mint.document.is_expired`, which reads the wall clock.
    """
    authenticity = verify_vaid_authenticity_graded(kernel_public_key, vaid)
    if not authenticity.is_valid():
        return authenticity
    if is_expired(vaid):
        return VaidVerdict.EXPIRED
    if revocation is RevocationStatus.NOT_REVOKED:
        return VaidVerdict.VALID
    if revocation is RevocationStatus.REVOKED:
        return VaidVerdict.REVOKED
    return VaidVerdict.INDETERMINATE


def verify_vaid_standing_from_json(
    kernel_public_key: bytes,
    document_json: str,
    revocation: RevocationStatus,
) -> VaidVerdict:
    """:func:`verify_vaid_standing` over JSON **text**, so that "these bytes are not
    a VAID" is a *verdict* rather than an exception the caller has to catch.

    This exists for a cross-language reason as much as an ergonomic one. Rust's
    ``Vaid`` is a typed struct, so a truncated or structurally invalid document
    cannot even be constructed — the failure happens at deserialization, before any
    verifier sees it. Python and TypeScript hand their verifiers a plain map, which
    has no such gate. Without a shared entry point that starts from *text*, the
    three implementations would be answering different questions about malformed
    input, and a conformance vector comparing them would be comparing nothing.

    Parse failure is :attr:`~VaidVerdict.UNPARSEABLE` — a refusal, never a raise.
    """
    document = parse_vaid_document(document_json)
    if document is None:
        return VaidVerdict.UNPARSEABLE
    return verify_vaid_standing(kernel_public_key, document, revocation)

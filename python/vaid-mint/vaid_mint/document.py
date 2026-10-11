"""VAID document canonicalization — Python mirror of the Rust `vaid-mint` crate.

The Rust `vaid_mint::document` module defines the CANONICAL contract; this is the
Python mirror, not a second definition. Byte-identity of the signed VAID document
is locked by the shared cross-language vector ``mint_v1.json`` (vendored into this
package at ``vaid_mint/vectors/`` and drift-checked against the Rust copy).

Contract: the VAID document is snake_case (the Rust `Vaid` struct has no serde
rename). ``canonical_vaid_signing_bytes`` nulls ``kernel_signature`` (a signature
cannot cover its own value), canonicalizes the whole document per RFC 8785 (JCS),
and SHA-256s it — the 32-byte digest the kernel key signs.

Per Decision B this is self-consistent WITHIN this repo (Rust == Python); it is
NOT byte-conformant against the managed authority's (still-moving) VAID format.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

import rfc8785

# Signature-scheme discriminant; ``3`` for every VAID minted here. Covered by the
# signature and gated at verify.
#
# v3 (ADR-0004) adds ``trust_domain`` and ``kernel_key_thumbprint``. The v2
# constant is deliberately REMOVED rather than retained, mirroring Rust: no code
# can accidentally accept a v2 document, and there is no dual-version path — a v2
# document must not verify under a v3 verifier, because accepting both would
# recreate the downgrade surface that signing ``sig_version`` exists to close.
# v4 (ADR-0009) types ``scope_boundary``: its entries become
# ``{"kind": ..., "value": ...}`` objects rather than bare strings. No member is
# added or removed, but the type of an existing member's elements changes, so the
# canonical bytes of every document with a non-empty boundary move.
#
# The v3 constant is removed for exactly the reason the v2 one was. Keeping both
# would also be forbidden rather than merely unwise: ADR-0008 states that a
# verifier MAY accept two ``sig_version`` values only where they require the SAME
# members, and that if two accepted values do not, one is a downgrade of the
# other. A v3 document's boundary entries are strings; a v4 document's are
# objects. ``{3, 4}`` is therefore forbidden and there is no legacy acceptance to
# write.
VAID_SIG_VERSION_V4 = 4

#: The exact timestamp profile inside signed bytes (``docs/spec/encoding.md``
#: E.6): whole-second RFC 3339 in UTC with a literal ``Z``. Narrower than RFC 3339
#: on purpose — it is the round-trip fixed point, so a verifier that re-serializes
#: while recomputing canonical bytes agrees with the signer.
_E6_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def canonical_vaid_signing_bytes(vaid: dict) -> bytes:
    """The 32-byte signing digest of a VAID document.

    Mirror of the Rust ``canonical_vaid_signing_bytes``: copy the document, force
    ``kernel_signature`` to JSON ``null``, canonicalize per RFC 8785 (JCS), then
    SHA-256. Byte-array fields (``public_key_der``, ``kernel_signature``) are lists
    of ints, exactly as Rust serializes ``Vec<u8>``.
    """
    payload = dict(vaid)
    payload["kernel_signature"] = None
    return hashlib.sha256(rfc8785.dumps(payload)).digest()


def compute_lineage_hash(parent_vaid: str | None, agent_id: str) -> str:
    """Lineage hash from the parent chain — mirror of the Rust
    ``compute_lineage_hash``. Root agents (no parent) get a genesis hash. Lowercase
    hex of ``SHA-256`` over ``"{parent}:{agent_id}"`` or ``"GENESIS:{agent_id}"``.
    """
    if parent_vaid is None:
        material = f"GENESIS:{agent_id}"
    else:
        material = f"{parent_vaid}:{agent_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_unsigned_vaid_document(
    *,
    vaid_id: str,
    agent_id: str,
    agent_class: str,
    version: str,
    tenant_id: str,
    issued_at: str,
    expires_at: str,
    public_key_der: list[int],
    parent_vaid: str | None,
    scope_boundary: list[dict],
    lineage_hash: str,
    capability_set: list[str],
    trust_domain: str,
    kernel_key_thumbprint: str,
) -> dict:
    """Assemble the snake_case VAID document with an empty ``kernel_signature``.

    The field set and names mirror the Rust ``Vaid`` struct exactly; the issuer
    signs the canonical bytes of this and attaches the signature.
    """
    return {
        "sig_version": VAID_SIG_VERSION_V4,
        "vaid_id": vaid_id,
        "agent_id": agent_id,
        "agent_class": agent_class,
        "version": version,
        "tenant_id": tenant_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "public_key_der": list(public_key_der),
        "kernel_signature": [],
        "parent_vaid": parent_vaid,
        "scope_boundary": list(scope_boundary),
        "lineage_hash": lineage_hash,
        "capability_set": list(capability_set),
        "trust_domain": trust_domain,
        "kernel_key_thumbprint": kernel_key_thumbprint,
    }


def _parse_rfc3339(value: object) -> datetime | None:
    """Permissively parse an RFC 3339 timestamp to an aware UTC datetime, or
    ``None`` if it is not one.

    Permissive on purpose: this is the parser :func:`is_expired` uses, and
    :func:`is_expired` must be TOTAL. Conformance to the narrower E.6 profile is a
    separate question, asked separately by :func:`has_conforming_timestamps`.
    """
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # RFC 3339 requires an offset. A naive timestamp is not one, and guessing
        # UTC would silently invent a value the signer never wrote.
        return None
    return dt.astimezone(timezone.utc)


def is_expired(vaid: dict) -> bool:
    """Has the document passed its ``expires_at``? Mirror of ``Vaid::is_expired``.

    **Total: never raises** (issue #10). Previously this parsed with a fixed format
    string and raised ``ValueError`` on any timestamp that was valid RFC 3339 but
    not whole-second ``Z`` — from a function whose signature promises a ``bool``,
    with no mention of it in the docstring, so callers did not guard. Rust and
    TypeScript returned a bool for the same inputs. Two of three implementations
    were permissive by accident of which parser each language makes idiomatic, and
    majority-by-accident was becoming the de facto standard.

    Settled by splitting the surface rather than by picking a winner:

    - this function stays total and answers only "is it past expiry";
    - :func:`has_conforming_timestamps` answers the E.6 profile question
      explicitly, so a caller that wants strictness asks for it and can tell the
      two failures apart.

    An unparseable or absent ``expires_at`` returns ``True`` — **fail closed**. A
    document whose expiry cannot be read is not a document that can be shown to be
    unexpired.
    """
    return is_expired_at(vaid, datetime.now(timezone.utc))


def is_expired_at(vaid: dict, now: datetime) -> bool:
    """:func:`is_expired` against a **given** instant rather than the wall clock.

    The same predicate, with the clock read lifted out. :func:`is_expired` is the
    convenience for a caller with no reason to control time; anything that must be
    reproducible — a conformance vector, a boundary case, replaying a historical
    decision — asks at a stated instant instead, and
    :func:`~vaid_mint.chain.verify_chain_at` passes its own ``now`` down here so a
    chain's verdict does not depend on when the suite happened to run (BACKLOG B9,
    on the verify side).

    Fails closed identically: an unparseable or absent ``expires_at`` is expired.
    The boundary is ``now > expires_at``, so a document is live **at** its own
    ``expires_at`` and expired the first instant after it — stated here because the
    three implementations must agree on the boundary, not merely on the interior.
    """
    expires_at = _parse_rfc3339(vaid.get("expires_at"))
    if expires_at is None:
        return True
    return now.astimezone(timezone.utc) > expires_at


def has_conforming_timestamps(vaid: dict) -> bool:
    """Do ``issued_at`` and ``expires_at`` match the E.6 profile exactly —
    whole-second RFC 3339 in UTC with a literal ``Z``?

    The explicit half of the issue #10 split. E.6 says implementations SHOULD
    reject other forms rather than silently normalizing them; this is how a caller
    asks. Sub-second precision (``...:00.000Z``, which JavaScript's
    ``toISOString`` emits by default) and a numeric offset (``+00:00``) are both
    valid RFC 3339 and both non-conforming here.

    Not consulted by authenticity verification: a document that reached a verifier
    with a non-conforming timestamp will already fail the signature check, because
    the verifier re-serializes into the profile and recomputes different bytes.
    This exists so that failure can be *explained* rather than merely observed.
    """
    for field in ("issued_at", "expires_at"):
        value = vaid.get(field)
        if not isinstance(value, str) or not _E6_TIMESTAMP.match(value):
            return False
        if _parse_rfc3339(value) is None:
            return False
    return True


#: The reserved hierarchy separators (spec ``docs/spec/scope.md`` S.2).
#:
#: Both are normative and both are always honoured. A scope segment MUST NOT
#: contain either — that constraint is what makes honouring both safe rather than
#: widening, and it is why the set is fixed by the specification instead of being
#: a property of a deployment. See :func:`scope_contains`.
SCOPE_SEPARATORS: tuple[str, str] = ("/", ".")


#: The one scope-boundary kind v4 defines: today's resource-prefix semantics,
#: unchanged from the bare-string form it replaces (spec S.3).
SCOPE_KIND_PREFIX = "prefix"

#: THE recognised-kind registry (spec S.7, S.10).
#:
#: Stated once, and consulted by both the matcher (:func:`scope_contains`) and the
#: standing verdict (:func:`vaid_mint.verify.verify_vaid_standing`). Two copies of
#: this list is how a kind gets recognised by one and not the other, which is the
#: fail-closed rule of S.10 failing open. ``scope_kinds_v1.json`` declares the
#: same list and is checked against this tuple directly, so a kind added here
#: without being added to the specification fails conformance, and so does the
#: reverse.
RECOGNISED_SCOPE_KINDS: tuple[str, ...] = (SCOPE_KIND_PREFIX,)

#: The members a boundary entry carries, and no others (spec S.8).
_ENTRY_MEMBERS = frozenset({"kind", "value"})


def prefix_entry(value: str) -> dict:
    """A ``prefix`` boundary entry over ``value``. The only kind v4 defines, so
    this is the constructor a producer wants. Mirror of Rust
    ``ScopeBoundaryEntry::prefix``."""
    return {"kind": SCOPE_KIND_PREFIX, "value": value}


def is_well_formed_scope_entry(entry: object) -> bool:
    """Is ``entry`` a well-formed boundary entry (spec S.8)?

    An object with EXACTLY ``kind`` (a non-empty string) and ``value``, whose
    type is fixed by the kind. For a RECOGNISED kind the value type is checked
    here, so a ``prefix`` entry carrying a number makes the document unparseable.
    For an unrecognised kind the value is NOT inspected: this implementation does
    not know what type a later kind's value takes, and guessing would mean
    refusing an authentic future document for a reason it invented. That entry is
    well formed, and S.10 refuses it at verify instead.

    This is the Python half of the gate Rust gets from ``serde``'s typed struct
    plus ``deny_unknown_fields``. Without it the three implementations would
    answer different questions about a malformed boundary and a conformance
    vector comparing them would be comparing nothing.

    ``_ENTRY_MEMBERS`` being exact is the S.11 asymmetry with ADR-0006. At
    DOCUMENT level an unknown member is preserved, because it sits outside every
    predicate a verifier computes. Inside an entry there is no outside: every
    member is part of the authority the entry states, so a verifier that ignored
    ``{"kind": "prefix", "value": "a", "max": 5}`` would compute a boundary
    strictly wider than the one the signer committed to, and would do it
    silently.
    """
    if not isinstance(entry, dict):
        return False
    if set(entry) != _ENTRY_MEMBERS:
        return False
    kind = entry["kind"]
    if not isinstance(kind, str) or kind == "":
        return False
    if kind == SCOPE_KIND_PREFIX and not isinstance(entry["value"], str):
        return False
    return True


def is_well_formed_scope_boundary(boundary: object) -> bool:
    """Is ``boundary`` a well-formed ``scope_boundary`` (spec S.8)?

    A list of well-formed entries. There is no per-entry fallback: one malformed
    entry is a malformed boundary, which is what makes the bare-string form of v3
    refused outright rather than reinterpreted.
    """
    if not isinstance(boundary, list):
        return False
    return all(is_well_formed_scope_entry(e) for e in boundary)


def entry_claimed_resource(entry: dict) -> str | None:
    """The resource a child entry CLAIMS, for the attenuation predicate. ``None``
    when the entry is not one this implementation can evaluate.

    For the ``prefix`` kind a boundary and a resource are the same shape, which is
    why attenuation has always been decidable with the containment predicate: a
    child entry is fed to the matcher as if it were a resource, so mint-time and
    verify-time cannot answer differently. A future kind whose boundary is not
    resource-shaped will need its own containment rule rather than this
    projection; ``docs/spec/scope.md`` S.13 records that as a constraint on the
    next revision.

    This is the module's SECOND and last branch on ``kind``.
    ``test_every_registered_kind_is_evaluable`` asserts that it and
    :func:`_entry_contains` both answer for every name in
    :data:`RECOGNISED_SCOPE_KINDS`.
    """
    if not isinstance(entry, dict) or entry.get("kind") != SCOPE_KIND_PREFIX:
        return None
    value = entry.get("value")
    return value if isinstance(value, str) else None


def _entry_contains(entry: dict, resource: str) -> bool | None:
    """Evaluate ONE entry against ``resource``.

    ``None`` means this implementation cannot evaluate the entry at all: its kind
    is not in :data:`RECOGNISED_SCOPE_KINDS`, or it is of a recognised kind whose
    ``value`` is not the type that kind fixes. This is the only place a kind's
    containment rule is written; adding a kind means adding a branch here and a
    name to the registry.
    """
    if not isinstance(entry, dict) or entry.get("kind") != SCOPE_KIND_PREFIX:
        return None
    value = entry.get("value")
    if not isinstance(value, str):
        return None
    return _prefix_contains(value, resource)


def entry_is_evaluable(entry: dict) -> bool:
    """Can ``entry`` be evaluated here at all?

    DERIVED from :func:`_entry_contains` rather than restated, so a kind cannot be
    added to one and forgotten in the other. Whether ``_entry_contains`` returns
    a verdict is a property of the entry alone and never of the resource, which is
    what makes deriving it from a single arbitrary resource exact rather than
    approximate; ``test_evaluability_does_not_depend_on_the_resource`` asserts
    that over every boundary in the conformance vector.
    """
    return _entry_contains(entry, "") is not None


def boundary_is_evaluable(boundary: list[dict]) -> bool:
    """Can every entry of ``boundary`` be evaluated here (spec S.10)?

    ``False`` is the S.10 refusal condition, and it is a property of the boundary
    alone: a verifier reports it over a document rather than over a request, so
    the standing verdict can reach it without having a resource in hand.
    """
    return all(entry_is_evaluable(e) for e in boundary)


def _prefix_contains(prefix: str, resource: str) -> bool:
    """Does a single boundary entry contain ``resource``? The one-entry core of
    :func:`scope_contains`, split out so the rule is stated exactly once.

    An empty entry matches everything, preserving the match-all an empty string
    had under prefix matching. It is unreachable from a well-formed boundary (an
    empty *list* is how ⊤ is expressed) and is kept only so the rule is total.
    """
    if prefix == "":
        return True
    if resource == prefix:
        return True
    # A trailing separator already marks the boundary, so plain prefixing is
    # containment — ``data.`` contains ``data.x`` without needing a second dot.
    if any(prefix.endswith(sep) for sep in SCOPE_SEPARATORS):
        return resource.startswith(prefix)
    return any(resource.startswith(prefix + sep) for sep in SCOPE_SEPARATORS)


def scope_contains(boundary: list[dict], resource: str) -> bool:
    """Is ``resource`` within ``boundary``? An empty boundary means unrestricted (⊤).

    THE scope matcher. :func:`is_in_scope` delegates here rather than implementing
    it, so a caller holding a bare boundary — a consent attestation's
    ``scope_boundary``, which is attached to no document — is matched by exactly the
    same rule as a document's own. Duplicating the rule for the detached case is how
    the two would drift.

    **Containment is segment-bounded (spec S.3).** An entry ``P`` contains a
    resource ``R`` iff ``R == P``, or ``P`` ends with a separator and ``R`` starts
    with ``P``, or ``R`` starts with ``P`` followed by a separator. Bare prefix
    matching is not containment.

    Until 0.5.0 this was ``resource.startswith(s)``, which made
    ``data.governance`` contain ``data.governance-secret`` — a *sibling*, sharing
    a textual prefix and nothing else. Because this same predicate decides
    mint-time attenuation and third-party chain verification, that let a child be
    delegated authority its parent never held, and let a verifier confirm the
    delegation. The rule here is **strictly narrower**: it denies cases the old
    one allowed and permits nothing new.

    Both separators are always honoured, and a segment MUST NOT contain either
    (S.2) — that constraint is doing the safety work. Without it, an implementer
    treating ``/`` as their separator and ``.`` as an ordinary character would
    find ``data/user`` containing ``data/user.admin``: the same sibling-capture
    bug in the other separator. The segment constraint is normative on producers
    but is **not enforced here** in 0.5.0 (S.6).

    Written with only ``==``, ``startswith``, ``endswith`` and concatenation — no
    character indexing — so Rust (bytes), Python (code points) and TypeScript
    (UTF-16) cannot diverge on a multi-byte boundary.

    **An entry this implementation cannot read refuses the WHOLE boundary**
    (S.10), not just itself. The natural implementation of a union is
    ``any(...)``, and the natural implementation returns ``True`` for a boundary
    of a satisfied ``prefix`` entry plus one unrecognised entry: it finds the
    match and never reaches the entry it cannot read. An unrecognised kind can
    only ever NARROW what the signer meant, so skipping it grants authority the
    signer withheld. The loop below therefore refuses on the first unevaluable
    entry even when a match is already in hand. This is reachable from a bare
    boundary that never passed document verify, so the refusal lives here and not
    only in the standing verdict.
    """
    contained = False
    for entry in boundary:
        verdict = _entry_contains(entry, resource)
        if verdict is None:
            # S.10: refuse the whole boundary, even with a match already found.
            return False
        contained = contained or verdict
    return not boundary or contained


def caps_contain(capabilities: list[str], capability: str) -> bool:
    """Does ``capabilities`` hold ``capability`` (exact membership)? THE capability
    matcher; :func:`has_capability` delegates here, for the same reason."""
    return capability in capabilities


def is_in_scope(vaid: dict, resource: str) -> bool:
    """Is ``resource`` within the document's scope boundary? Empty = unrestricted.
    The single scope matcher — mirror of ``Vaid::is_in_scope``."""
    return scope_contains(vaid["scope_boundary"], resource)


def has_capability(vaid: dict, capability: str) -> bool:
    """Does the document hold ``capability`` (exact membership)? Mirror of
    ``Vaid::has_capability``."""
    return caps_contain(vaid["capability_set"], capability)

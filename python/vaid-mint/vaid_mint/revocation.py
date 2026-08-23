"""The revocation seam — Python mirror of the Rust ``vaid_mint::revocation``.

Spec: ``docs/spec/revocation.md`` R.4. Revocation is **outside the VAID
conformance surface** (R.1): no frozen vector polices anything here, and nothing
in this module is normative. It is specified in prose, and pinned down here,
precisely because no vector would otherwise stop the Rust and Python references
from drifting into different shapes.

Shape (0.2.0, replacing the 0.1.2 boolean seam)
-----------------------------------------------
The 0.1.2 seam was a boolean, leaf-only check: ``is_revoked(vaid_id) -> bool``. It
could not express that a check was *unavailable*, and it consulted only the
presented leaf, so revoking a parent left an attenuated child verifiable. This
module replaces it — a breaking change — with the three-state, lineage-aware seam
the spec defines. There is deliberately no shim keeping the old signature alive:
two protocols named ``RevocationCheck`` with different safety properties is the
outcome being avoided.

Two jobs kept apart (R.4.1)
---------------------------
- **The verifier assembles the lineage.** :func:`assemble_lineage` resolves the
  ordered ancestry of the VAID under verification, root first, leaf last, using a
  :class:`LineageResolver`. The check is never handed the resolver.
- **The check answers about a lineage it is handed.** :class:`RevocationCheck`
  receives an already-ordered ``list[str]`` and reports :class:`RevocationStatus`.
  A VAID is revoked if **any** VAID in its lineage is (R.4.4).

Three states, failing closed (R.4.3, R.4.5)
-------------------------------------------
:class:`RevocationStatus` is three-valued — ``NOT_REVOKED`` / ``REVOKED`` /
``UNAVAILABLE`` — never a boolean, and ``UNAVAILABLE`` is a first-class return the
caller can see, never an exception to be swallowed. Verification fails closed on
``UNAVAILABLE``. There is no fail-open option in this reference.

Detectability of state loss (R.4.2, R.4.6)
------------------------------------------
The full lineage is **not** recoverable from a VAID: it carries only its immediate
``parent_vaid`` (one hop) and a one-way ``lineage_hash``. Assembly needs a
resolver, and the reference resolver — the issuer's in-process lineage map — is
empty after a restart. A child verified against an empty map must resolve to
``UNAVAILABLE``, never be mistaken for a rootless VAID. This module refuses that
collapse in two places: :meth:`LineageResolver.resolve_parent` distinguishes a
**known root** from an **unknown** id (:class:`ParentResolution`), and
:class:`InMemoryRevocationList` represents **absent** state (``UNAVAILABLE``)
distinctly from a **vouching** store (``NOT_REVOKED``).
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Defensive bound on lineage depth. A resolver map corrupted into a cycle, or an
# implausibly deep chain, yields an incomplete assembly rather than looping —
# incomplete fails closed, so this never fails *open*.
MAX_LINEAGE_DEPTH = 1024


class RevocationStatus(enum.Enum):
    """The three-state result of a revocation check (spec R.4.3). Not a boolean.

    The caller MUST be able to tell ``UNAVAILABLE`` from ``NOT_REVOKED``: the first
    means "status could not be determined" and fails closed, the second means
    "checked, and clean".
    """

    NOT_REVOKED = "not_revoked"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"


@runtime_checkable
class RevocationCheck(Protocol):
    """The revocation seam (R.4.1). Consulted at verification time with the full
    ordered lineage (root first, leaf last) the verifier has **already** assembled.
    The check performs no lineage resolution and is not given the means to."""

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        """Report revocation for an already-assembled, ordered lineage.

        :class:`RevocationStatus.REVOKED` if **any** id in ``lineage`` is revoked
        (R.4.4), ``NOT_REVOKED`` if the store was consulted and none are, and
        ``UNAVAILABLE`` if the backing store could not be consulted (R.4.3) — never
        collapse that last case into ``NOT_REVOKED``.
        """
        ...


@dataclass(frozen=True)
class ParentResolution:
    """The result of resolving one hop of ancestry (spec R.4.2). ``root`` and
    ``unknown`` are kept distinct on purpose: conflating them is the exact bug that
    lets a post-restart child masquerade as rootless."""

    kind: str  # "root" | "parent" | "unknown"
    parent: str | None = None

    @classmethod
    def root(cls) -> "ParentResolution":
        """Known to the resolver, with no parent: a genuine root."""
        return cls("root")

    @classmethod
    def of_parent(cls, parent: str) -> "ParentResolution":
        """Known to the resolver, with this parent."""
        return cls("parent", parent)

    @classmethod
    def unknown(cls) -> "ParentResolution":
        """Not known to the resolver — ancestry cannot be completed."""
        return cls("unknown")


@runtime_checkable
class LineageResolver(Protocol):
    """Resolves a VAID's immediate parent, one hop at a time (R.4.1/R.4.2). The
    verifier owns this; the :class:`RevocationCheck` never sees it."""

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        """Resolve the parent of ``vaid_id``. MUST distinguish a known root
        (:meth:`ParentResolution.root`) from an id it cannot resolve
        (:meth:`ParentResolution.unknown`)."""
        ...


def assemble_lineage(leaf: dict, resolver: LineageResolver) -> list[str] | None:
    """Assemble the ordered ancestor lineage of ``leaf``, root first, leaf last
    (spec R.4.2).

    The leaf's immediate parent comes from its own signed document; every hop above
    that is resolved through ``resolver``. Returns the ordered list on success, or
    ``None`` for an **incomplete** assembly — a present ``parent_vaid`` that
    resolves to unknown, a cycle, or an implausible depth. ``None`` MUST be treated
    as :class:`RevocationStatus.UNAVAILABLE` and MUST NOT be silently truncated to
    the leaf alone. A leaf with no ``parent_vaid`` is its own root and returns a
    one-element list ("trivially complete").
    """
    chain = [leaf["vaid_id"]]
    next_parent = leaf.get("parent_vaid")

    while next_parent is not None:
        if next_parent in chain or len(chain) >= MAX_LINEAGE_DEPTH:
            # A cycle, or an implausibly deep chain: cannot vouch for completeness.
            return None
        chain.append(next_parent)
        res = resolver.resolve_parent(next_parent)
        if res.kind == "root":
            next_parent = None
        elif res.kind == "parent":
            next_parent = res.parent
        else:  # "unknown"
            return None

    chain.reverse()  # built leaf→root; the check wants root→leaf.
    return chain


class InMemoryRevocationList:
    """A standalone, injectable in-memory revocation store implementing the
    three-state seam. Non-durable: it does not survive a restart.

    It represents two conditions the spec (R.4.6) insists be kept apart:

    - **absent** (``InMemoryRevocationList()`` / :meth:`unavailable` /
      :meth:`mark_unavailable`) — the store has not been populated and cannot vouch
      for anything, so :meth:`check_lineage` returns
      :class:`RevocationStatus.UNAVAILABLE`. This is what a freshly reconstructed
      store looks like after a restart.
    - **vouching** (:meth:`assume_nothing_revoked`, or after any :meth:`revoke`) —
      the store vouches for its contents, possibly empty, so an unrevoked lineage
      returns :class:`RevocationStatus.NOT_REVOKED`.

    A durable backend implements :class:`RevocationCheck` itself and returns
    ``UNAVAILABLE`` when *its* store is unreachable; this in-memory type is for
    tests and for wiring the seam before such a backend exists.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # ``None`` = absent (cannot vouch → UNAVAILABLE); a set = vouching.
        self._revoked: set[str] | None = None

    @classmethod
    def assume_nothing_revoked(cls) -> "InMemoryRevocationList":
        """A store that **vouches "nothing is revoked"** over an empty set.

        The name states the posture, not the state, because the state ("empty") is
        the dangerous part read alone. This store answers ``NOT_REVOKED`` for every
        VAID it is not told about — and, being non-durable, it **cannot detect its
        own restart**: after a process restart it is reconstructed empty and again
        vouches ``NOT_REVOKED``, so a VAID revoked before the restart verifies clean.
        That is a fail-*open* posture reached by assumption. Fine for local
        development and tests; for anything that must survive a restart, inject a
        durable :class:`RevocationCheck`, or hold the store in absent state (the
        default constructor) until you have re-loaded revocation state into it.
        """
        inst = cls()
        inst._revoked = set()
        return inst

    @classmethod
    def unavailable(cls) -> "InMemoryRevocationList":
        """Alias for the default constructor that reads as intent at a call site —
        e.g. modelling a backing store that cannot be reached."""
        return cls()

    def revoke(self, vaid_id: str) -> None:
        """Mark a VAID revoked. Populating the store also makes it **available**: a
        store you have revoked into can vouch for what it holds."""
        with self._lock:
            if self._revoked is None:
                self._revoked = set()
            self._revoked.add(vaid_id)

    def mark_unavailable(self) -> None:
        """Drop the store back to **absent** state (modelling state loss).
        Subsequent checks report ``UNAVAILABLE`` rather than silently
        ``NOT_REVOKED``."""
        with self._lock:
            self._revoked = None

    def is_available(self) -> bool:
        """True when the store has authoritative contents, False when absent."""
        with self._lock:
            return self._revoked is not None

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        with self._lock:
            if self._revoked is None:
                return RevocationStatus.UNAVAILABLE
            if any(vaid_id in self._revoked for vaid_id in lineage):
                return RevocationStatus.REVOKED
            return RevocationStatus.NOT_REVOKED


# ─────────────────────────────────────────────────────────────────────────────
# The durable seam (spec R.4.6). Two stores, injected as one.
# ─────────────────────────────────────────────────────────────────────────────
#
# Durability under R.4.6 is TWO stores, not one — the revoked set and the lineage
# resolver — and getting exactly one of them durable is an outage, not a hole.
# Persist the revoked set, leave the resolver in memory, restart:
#
#   - every ROOT VAID keeps verifying (trivially complete under R.4.2, no
#     resolution needed, the durable set answers cleanly);
#   - every CHILD VAID stops verifying (its ``parent_vaid`` is now unresolvable,
#     so assembly is incomplete → UNAVAILABLE → fails closed under R.4.5).
#
# Total for delegated credentials, invisible for root ones, arriving at restart
# rather than at deploy, and first diagnosed as a signing or clock problem because
# revocation is the last subsystem anyone suspects when nothing was revoked. The
# system is choosing an outage over a security hole, correctly — but it is the
# wrong outage to have to diagnose from scratch.
#
# Until 0.7.0 that half-state was not merely *reachable*, it was the ONLY
# reachable state: ``with_revocation_check`` injected the revoked set, and no
# injection point for the resolver existed at all. A self-hoster following the
# documented path built exactly the half that produces the outage.
#
# :class:`RevocationBackend` closes that by construction. It cannot be built
# without both halves, and it is the only way to replace either, so the half-state
# is no longer reachable **by omission** — only by explicitly naming
# :class:`InMemoryLineageStore` as the durable resolver's replacement, which is a
# legitimate single-process choice and is visible at the call site.
#
# The two halves stay separate objects. A single protocol carrying both methods
# would make the half-state unrepresentable too, and would violate R.4.1: "the
# check does not perform lookups and is not given the means to."


@runtime_checkable
class LineageStore(Protocol):
    """The write half of the lineage resolver (spec R.4.2), alongside
    :class:`LineageResolver`'s ``resolve_parent``.

    A read-only durable resolver is inert: nothing would ever populate it, because
    the issuer records every mint into its own map. A durable resolver therefore
    needs :meth:`record` — the method whose absence made durable lineage
    unimplementable from outside the package.

    Implementations MUST record roots as ``None`` rather than omitting them. An
    unrecorded root is *unknown*, and a store that omits roots turns every root
    VAID into ``UNAVAILABLE`` at verification.
    """

    def record(self, vaid_id: str, parent: str | None) -> None:
        """Record one mint: ``parent`` is the parent id for a child and ``None``
        for a root. Called on every successful mint."""
        ...

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        """As :class:`LineageResolver`."""
        ...


class InMemoryLineageStore:
    """The reference lineage store: an in-process dict, non-durable, empty after
    restart. Extracted from :class:`~vaid_mint.issuer.ReferenceIssuer` so that the
    thing a durable store replaces is a named, injectable object rather than a
    private attribute.

    Records roots as ``None`` and children as their parent id, which is what lets
    :meth:`resolve_parent` tell a **known root** from an **unknown** id — the
    distinction spec R.4.2 turns on.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, str | None] = {}

    def record(self, vaid_id: str, parent: str | None) -> None:
        with self._lock:
            self._entries[vaid_id] = parent

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        with self._lock:
            if vaid_id not in self._entries:
                return ParentResolution.unknown()
            parent = self._entries[vaid_id]
        return ParentResolution.root() if parent is None else ParentResolution.of_parent(parent)

    def clear(self) -> None:
        """Drop every recorded mint, modelling the loss of resolver state across a
        process restart. Afterwards any VAID carrying a ``parent_vaid`` resolves to
        ``UNAVAILABLE`` while a genuinely rootless VAID still verifies. An ops/test
        primitive."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True)
class RevocationBackend:
    """Both halves of durable revocation, injected together (spec R.4.6).

    There is no constructor that takes one half. That is the point: the failure
    this type exists to prevent is not a wrong value, it is a **missing second
    argument**, and a missing argument is the one class of mistake a type can
    refuse outright::

        issuer = ReferenceIssuer.ephemeral(1, "vaid.example").with_revocation_backend(
            RevocationBackend(check=durable_revoked, lineage=durable_lineage)
        )

    Ordering note for anyone migrating a live deployment: make the **resolver**
    durable first, or both in the same change. Doing the revoked set first is the
    ordering that produces the delegated-credential outage described above.
    """

    check: RevocationCheck
    lineage: LineageStore

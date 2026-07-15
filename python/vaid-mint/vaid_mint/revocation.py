"""The revocation seam — Python mirror of the Rust ``vaid_mint::revocation``.

In the closed managed authority, revocation is a durable, hash-chained store that
survives restart and is broadcast across verifiers. This open reference has only
an in-memory set (see :class:`~vaid_mint.issuer.ReferenceIssuer`); this protocol
makes the *seam* real so a self-hoster can inject a durable backend without
patching the package — the missing piece is the backend, not the extension point.

:class:`RevocationCheck` is the seam; :class:`InMemoryRevocationList` is a
standalone injectable in-memory implementation; :class:`NeverRevoked` is an honest
no-op a caller may opt into. A production deployment implements
:class:`RevocationCheck` over its own durable, restart-surviving store and injects
it via :meth:`~vaid_mint.issuer.ReferenceIssuer.with_revocation_check`.

**The seam is additive-only.** An injected :class:`RevocationCheck` is consulted
*in addition to* the reference issuer's built-in in-memory revoked set, never
instead of it — a VAID is rejected if *either* reports it revoked. The built-in
set cannot currently be disabled through this seam, only supplemented.

Why there is no honest-no-op *default*
--------------------------------------

This seam deliberately departs from the
:class:`~vaid_mint.authz.AuthorizationGate` / :class:`~vaid_mint.audit.AuditSink`
convention in one way, on purpose: **the package default is NOT an honest no-op.**
``AuthorizationGate`` defaults to :class:`~vaid_mint.authz.PermitAll` and
``AuditSink`` offers :class:`~vaid_mint.audit.NoopAudit`; for *those* seams a no-op
default is a neutral "not wired yet" state. For revocation it would be a
functional **regression** — a no-op means nothing is ever checked, silently. So
the reference issuer keeps its working in-memory revocation set as the default and
layers any injected :class:`RevocationCheck` on top. :class:`NeverRevoked` exists
for callers who explicitly want the no-op, but it is opt-in, never the default.

(The Rust seam is also documented as synchronous-by-design, since it is consulted
inside a sync, CPU-only, no-I/O ``verify_vaid``. The same holds here: a
durable/pollable backend is normally consumed as a periodically-refreshed
in-memory snapshot the check reads without blocking.)
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable


@runtime_checkable
class RevocationCheck(Protocol):
    """The revocation seam. Consulted at verification time: return ``True`` to
    treat ``vaid_id`` as revoked (which fails
    :meth:`~vaid_mint.issuer.ReferenceIssuer.verify_vaid`), ``False`` otherwise."""

    def is_revoked(self, vaid_id: str) -> bool:
        """Is this VAID revoked according to this backend? A production
        implementation reads its durable, restart-surviving store (or a locally
        cached snapshot of it) without blocking."""
        ...


class NeverRevoked:
    """An honest no-op revocation check: nothing is ever reported revoked by
    *this* backend.

    This performs **no actual revocation checking whatsoever** — every VAID is
    treated as un-revoked by this implementation.

    **It does not, and cannot, disable the reference issuer's built-in in-memory
    revoked set.** :meth:`~vaid_mint.issuer.ReferenceIssuer.verify_vaid` consults
    the built-in set *unconditionally* and treats any injected
    :class:`RevocationCheck` as an *additional* check layered on top — a VAID is
    rejected if *either* reports it revoked (see
    :meth:`~vaid_mint.issuer.ReferenceIssuer.with_revocation_check`). Because this
    type never reports anything revoked, injecting it adds no additional
    rejections and removes none: it is functionally identical to injecting nothing
    at all. In particular, injecting it does **not** mean "this package performs no
    revocation checks" — the built-in set still runs.

    There is currently **no way to bypass revocation checking entirely through this
    seam**: the built-in set cannot be turned off from here. If you need the mint's
    revocation check bypassed, front it with an external gateway that answers
    before ``verify_vaid`` is ever called, rather than injecting this type.

    It exists as an explicit, honest placeholder for a :class:`RevocationCheck`
    slot (in tests or wiring) where you deliberately want the injected backend to
    be a no-op. It is **not** the default.
    """

    def is_revoked(self, vaid_id: str) -> bool:  # noqa: D102
        return False


class InMemoryRevocationList:
    """A standalone, injectable in-memory revocation list — the same non-durable
    behavior as the reference issuer's built-in set, exposed as a
    :class:`RevocationCheck` a caller can share across verifiers in one process.

    Like the built-in set, this does **not** survive a restart. It is useful for
    tests and for wiring the seam before a durable backend exists.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked: set[str] = set()

    def revoke(self, vaid_id: str) -> None:
        """Mark a VAID revoked (in-memory, non-durable)."""
        with self._lock:
            self._revoked.add(vaid_id)

    def is_revoked(self, vaid_id: str) -> bool:
        """Is this VAID in the list?"""
        with self._lock:
            return vaid_id in self._revoked

    def __len__(self) -> int:
        """Number of revoked entries."""
        with self._lock:
            return len(self._revoked)

    def is_empty(self) -> bool:
        """True if nothing has been revoked."""
        return len(self) == 0

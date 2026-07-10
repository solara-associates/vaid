"""Root-mint authorization seam — Python mirror of the Rust ``vaid_mint::authz``.

``mint_root`` issues a root VAID. In the closed managed authority that path is
operator-gated; this open reference does NOT carry that gate — but the absence is
made VISIBLE as a seam, exactly like the audit sink, rather than silently missing.

:class:`AuthorizationGate` is the seam; :class:`PermitAll` is the default. A
production deployment supplies a real gate to
``MintService.with_authorization(...)``. ``mint_child`` is deliberately NOT routed
through this gate — its authorization IS the intrinsic attenuation check.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vaid_mint.error import UnauthorizedError
from vaid_mint.mint_types import VaidSeed


@runtime_checkable
class AuthorizationGate(Protocol):
    """The root-mint authorization seam. Raise
    :class:`~vaid_mint.error.UnauthorizedError` to deny; return to permit."""

    def authorize_root_mint(self, seed: VaidSeed) -> None:
        ...


class PermitAll:
    """The default gate: permits every root mint.

    This is a REFERENCE-IMPLEMENTATION CHOICE, not a security recommendation. With
    ``PermitAll`` in place, anyone who can reach the mint can issue a root VAID; a
    production deployment should supply a real :class:`AuthorizationGate`.
    """

    def authorize_root_mint(self, seed: VaidSeed) -> None:  # noqa: D102
        return None


class DenyAll:
    """A gate that denies every root mint — the negative reference/testing gate."""

    def authorize_root_mint(self, seed: VaidSeed) -> None:  # noqa: D102
        raise UnauthorizedError("root mint denied by gate")

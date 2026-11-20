"""Root-mint authorization seam — Python mirror of the Rust ``vaid_mint::authz``.

``mint_root`` issues a root VAID. In the closed managed authority that path is
operator-gated; this open reference does NOT carry that gate — but the absence is
made VISIBLE as a seam, exactly like the audit sink, rather than silently missing.

:class:`AuthorizationGate` is the seam; :class:`DenyAll` is the default — **deny by
default**. A production deployment supplies a real gate to
``MintService(..., authz=...)``. :class:`InsecurePermitAll` is the explicit,
clearly-named opt-in for local self-hosting, tests and demos — never for
production. ``mint_child`` is deliberately NOT routed through this gate — its
authorization IS the intrinsic attenuation check.
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


class DenyAll:
    """The default gate: denies every root mint.

    ``mint_root`` has no authority to check against out of the box, so the safe
    default is to issue nothing until a real :class:`AuthorizationGate` is
    supplied to ``MintService(..., authz=...)``. For local self-hosting, tests, or
    demos that intentionally want every root mint to succeed, opt in explicitly
    with :class:`InsecurePermitAll`.
    """

    def authorize_root_mint(self, seed: VaidSeed) -> None:  # noqa: D102
        raise UnauthorizedError(
            "root mint denied: no AuthorizationGate configured (deny-by-default). "
            "Construct MintService(..., authz=...) with a real gate, or opt into "
            "InsecurePermitAll for tests/demos only"
        )


class InsecurePermitAll:
    """An explicit, clearly-named opt-in that permits every root mint.

    **INSECURE. For tests and local demos only — never use in production.**
    Anyone who can reach a mint constructed with this gate can issue a root VAID.
    A production deployment must supply a real :class:`AuthorizationGate` to
    ``MintService(..., authz=...)`` instead.
    """

    def authorize_root_mint(self, seed: VaidSeed) -> None:  # noqa: D102
        return None

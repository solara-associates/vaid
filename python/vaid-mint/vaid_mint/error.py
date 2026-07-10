"""Minimal error surface for the reference mint — mirror of the Rust ``MintError``.

Three kinds, matching the Rust enum variants:

- :class:`UnauthorizedError` — an authorization/attenuation denial (child exceeds
  parent, cross-tenant, forged lineage, missing verified parent, gate deny).
- :class:`IdentityError` — a proof-of-possession / key failure (missing/stale PoP,
  replayed nonce, a signature that does not verify, a missing BYO-key).
- :class:`AuditError` — the audit sink refused a write; the mint is treated as
  failed.

A signature *verification* result is NOT an error: a bad signature is a ``False``
from the PoP verifier that the mint turns into an :class:`IdentityError`.
"""

from __future__ import annotations


class MintError(Exception):
    """Base class for reference-mint errors."""


class UnauthorizedError(MintError):
    """An authorization or attenuation denial."""


class IdentityError(MintError):
    """A proof-of-possession / key failure."""


class AuditError(MintError):
    """The audit sink refused the write."""

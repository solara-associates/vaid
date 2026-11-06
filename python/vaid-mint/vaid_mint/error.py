"""Minimal error surface for the reference mint — mirror of the Rust ``MintError``.

Three kinds, matching the Rust enum variants:

- :class:`UnauthorizedError` — an authorization/attenuation denial (child exceeds
  parent, cross-tenant, forged lineage, missing verified parent, gate deny).
- :class:`IdentityError` — a proof-of-possession / key failure (missing/stale PoP,
  replayed nonce, a signature that does not verify, a missing BYO-key).
- :class:`AuditError` — the audit sink refused a write; the mint is treated as
  failed.
- :class:`ConfigError` — a mint was constructed with an invalid configuration
  value (e.g. ``max_delegation_depth``). Raised at construction, before any
  request is served, so a misconfigured mint never starts minting.
- :class:`MalformedDocumentError` — a document handed to lineage assembly or
  chain verification is not shaped like a VAID at all (not a mapping, or its
  ``vaid_id``/``parent_vaid`` is missing or the wrong type). Distinct from
  :class:`~vaid_mint.verify.VaidVerdict.UNPARSEABLE`, which is the graceful
  verdict :func:`~vaid_mint.verify.verify_vaid_standing_from_json` returns for
  JSON **text** that is not a VAID: this is raised by the functions that take an
  already-parsed mapping and would otherwise fail with a bare ``KeyError`` or
  ``AttributeError`` deep inside lineage assembly.

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


class ConfigError(MintError):
    """A mint was constructed with an invalid configuration value."""


class MalformedDocumentError(MintError):
    """A document is not shaped like a VAID: not a mapping, or ``vaid_id`` /
    ``parent_vaid`` is missing or the wrong type. Raised by
    :func:`~vaid_mint.document.require_vaid_shape`."""


class CallerMismatchError(MintError):
    """A VAID verified as :attr:`~vaid_mint.verify.VaidVerdict.VALID`, but does
    not belong to the caller presenting it: at least one field of the
    :class:`~vaid_mint.verify.ExpectedCaller` passed to
    :func:`~vaid_mint.verify.verify_vaid_standing_bound` did not match the
    document's own. Raised rather than folded into :class:`~vaid_mint.verify.VaidVerdict`:
    that enum is the conformance surface ``verdict_v1.json`` pins across all
    three implementations, and caller binding is a property of the request the
    document arrived on, not of the document itself."""

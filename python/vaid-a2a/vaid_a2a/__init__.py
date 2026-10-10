"""Reference verifier for the VAID A2A extension (``docs/a2a/v1/extension.md``,
draft).

Public surface: :func:`~vaid_a2a.verifier.verify_a2a_message`,
:class:`~vaid_a2a.verifier.VerifyResult`, :class:`~vaid_a2a.verifier.VerifyCode`,
:class:`~vaid_a2a.verifier.TrustedIssuersConfigError`, and the two metadata key
constants :data:`~vaid_a2a.verifier.METADATA_VAID_KEY` /
:data:`~vaid_a2a.verifier.METADATA_CHAIN_KEY`.
"""

from __future__ import annotations

from vaid_a2a.verifier import (
    EXTENSION_URI,
    METADATA_CHAIN_KEY,
    METADATA_VAID_KEY,
    TrustedIssuersConfigError,
    VerifyCode,
    VerifyResult,
    verify_a2a_message,
)

__all__ = [
    "EXTENSION_URI",
    "METADATA_CHAIN_KEY",
    "METADATA_VAID_KEY",
    "TrustedIssuersConfigError",
    "VerifyCode",
    "VerifyResult",
    "verify_a2a_message",
]

__version__ = "0.1.0"

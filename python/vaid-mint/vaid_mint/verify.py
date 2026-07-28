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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaid_mint.document import (
    VAID_SIG_VERSION_V2,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
)


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

    - **expiry** — call :func:`~vaid_mint.document.is_expired`; an expired-but-signed
      VAID returns ``True`` here;
    - **revocation** — evaluate a :class:`~vaid_mint.revocation.RevocationCheck` (or,
      in the reference, :meth:`~vaid_mint.issuer.ReferenceIssuer.revocation_status`)
      on a separate path. Revocation is deliberately *not* consulted here.

    A malformed key, a bad signature, or any tampered signed field is ``False``,
    never an exception.
    """
    if vaid.get("sig_version") != VAID_SIG_VERSION_V2:
        return False
    if not verify_lineage_hash(vaid):
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(kernel_public_key))
        public_key.verify(bytes(vaid["kernel_signature"]), canonical_vaid_signing_bytes(vaid))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False

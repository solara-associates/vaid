"""The two v3 issuer-identity values — Python mirror of the Rust
``vaid_mint::issuer_identity`` module (ADR-0004).

The Rust module defines the CANONICAL contract; this is the mirror, not a second
definition. Both values live inside the signed VAID document, so both are inside
the canonical bytes and neither may be normalized at verification — a verifier
that "corrects" a value recomputes different bytes from the ones the signer
covered, which is the ``docs/spec/encoding.md`` E.6 timestamp failure in a new
place. Producers emit the conforming form; non-conforming input is rejected,
never repaired.

What each one answers:

- :func:`kernel_key_thumbprint` answers *which key signed this*. Given a document
  and a candidate key, correspondence is decidable offline by one hash — no
  network, no issuer.
- :func:`is_valid_trust_domain` constrains *who claims to have issued it*, so a
  verifier has something to look the thumbprint up **under**. A thumbprint alone
  is selection with nothing to select within.

Neither establishes attribution. A self-signed document whose thumbprint matches
its own key is internally consistent and entirely unauthorized. The binding from
a trust domain to an authorized key set is out-of-band, static and cached — see
ADR-0004.
"""

from __future__ import annotations

import base64
import hashlib

import rfc8785

#: RFC 9278 JWK Thumbprint URI prefix. SHA-256 is mandatory-to-implement there
#: and is the only algorithm this version emits; the prefix carries the algorithm
#: so a later move off SHA-256 needs no new field.
THUMBPRINT_URI_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"

#: Maximum total length of a trust domain, in bytes (the DNS name limit).
TRUST_DOMAIN_MAX_LEN = 253
#: Maximum length of a single label, in bytes.
TRUST_DOMAIN_MAX_LABEL_LEN = 63

_RESERVED_TLDS = frozenset(
    {"example", "invalid", "localhost", "test", "local", "internal"}
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def kernel_key_thumbprint(public_key: bytes) -> str:
    """RFC 9278 thumbprint URI over the RFC 7638 JWK thumbprint of a raw 32-byte
    Ed25519 public key.

    **Why this is not hand-rolled.** RFC 7638's substance is the canonicalization:
    take only the required members, order them lexicographically, emit no
    whitespace. For an OKP key the required members are exactly ``crv``, ``kty``,
    ``x`` (RFC 8037 §2) — and that is precisely what RFC 8785 (JCS) produces for
    the same object, since JCS sorts keys by UTF-16 code unit and
    ``crv`` < ``kty`` < ``x``. So the risky half is delegated to ``rfc8785``, the
    same JCS implementation the signing path already uses and the frozen vectors
    already prove. Only the three-member JWK is written here.

    Correctness is pinned against the published RFC 8037 Appendix A.3 thumbprint
    vector in the tests, so this is checked against the standard rather than only
    against itself — and, separately, against Rust and TypeScript by the frozen
    ``mint_v1`` vector.
    """
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(bytes(public_key))}
    canonical = rfc8785.dumps(jwk)
    return THUMBPRINT_URI_PREFIX + _b64url(hashlib.sha256(canonical).digest())


def is_valid_trust_domain(s: str) -> bool:
    """Is ``s`` a well-formed trust domain (ADR-0004)?

    Lowercase ASCII letters, digits, ``-`` and ``.``; at least two labels; each
    label 1–63 bytes with no leading or trailing ``-``; no empty label and no
    trailing dot; 1–253 bytes total; and a final label that is not all-numeric.

    Two deliberate divergences from SPIFFE's trust-domain grammar:

    - **No underscore.** SPIFFE permits it. An underscore cannot appear in a
      hostname, so such a name cannot be bound by the WebPKI or DNS anchor this
      identifier exists to be bound by.
    - **No case-insensitive comparison.** SPIFFE normalizes case when comparing.
      This cannot: the value is inside signed bytes, so comparison is byte
      equality and an uppercase producer is non-conforming rather than corrected.

    The all-numeric final label rule excludes dotted-quad IP literals. SPIFFE
    deliberately permits IPs; this does not, because an IP has no controller to
    bind to.

    Special-use names are **permitted by this grammar** — the frozen vector needs
    one, and uses ``vaid.example``. Policy, not grammar, forbids them in
    production; see :func:`is_special_use_trust_domain`.
    """
    if not isinstance(s, str) or not s:
        return False
    # Length is in BYTES, not characters: a non-ASCII string is rejected by the
    # character rule below, but measuring bytes keeps the bound identical to Rust.
    if len(s.encode("utf-8")) > TRUST_DOMAIN_MAX_LEN:
        return False
    labels = s.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label.encode("utf-8")) > TRUST_DOMAIN_MAX_LABEL_LEN:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        for ch in label:
            if not ("a" <= ch <= "z" or "0" <= ch <= "9" or ch == "-"):
                return False
    # A final label that is all digits would admit `192.0.2.1`.
    return not labels[-1].isdigit()


def is_special_use_trust_domain(s: str) -> bool:
    """Is ``s`` a special-use name reserved by RFC 2606 / RFC 6761?

    Advisory, not a conformance rule. A verifier SHOULD refuse to hold a trust
    bundle for one of these, which is what makes the frozen vector's issuer
    (``vaid.example``) unbindable by rule rather than by convention — the vector
    publishes its own kernel private seed, so anyone can sign documents under it.
    """
    if not isinstance(s, str) or "." not in s:
        return False
    return s.rsplit(".", 1)[-1] in _RESERVED_TLDS

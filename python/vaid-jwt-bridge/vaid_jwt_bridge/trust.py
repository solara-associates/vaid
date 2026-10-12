"""The bridge's trust anchor: kernel public keys, each bound to the one trust
domain it is trusted for.

**Why this module exists.** ``vaid_mint.chain.KernelKeyMap`` /
``SingleKernelKey`` resolve a key by ``kernel_key_thumbprint`` and keep only
the key bytes, which is correct for their own job — selecting a key to check a
signature against. They cannot answer "which trust domain is this key trusted
for", so a verifier built on one accepts a document signed by *any* trusted key
while claiming *any* trust domain. Given two legitimately trusted issuers, A
and B, a document signed by B's key while claiming A's ``trust_domain``
verifies perfectly against B's key: B's key vouching for A's identity, with no
forged signature and no compromised key anywhere in the attack
(GHSA-hfjh-v2x2-r58v). For this bridge the consequence is an issued JWT whose
``sub``/``act``/``vaid`` claims name an identity the signing issuer never
granted, which a downstream gateway then honours on the bridge's word.

Holding the domain-to-key pairing is the half ``vaid_mint`` keeps deliberately
out of band (see ``vaid_mint.mint.tenant_attenuates``), so each consumer holds
it itself. This mirrors ``vaid_a2a.verifier``'s resolved ``trustedIssuers`` map
and ``vaid_adk.TrustedIssuers`` deliberately: same rule, same config shape,
same spec paragraph (``docs/a2a/v1/extension.md`` section 2.1). It is
re-derived here against ``vaid_mint`` rather than imported from either sibling,
for the same reason ``exchange()`` re-derives the verification order: neither
package has a release cadence this one should couple to.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass

from vaid_mint.issuer_identity import kernel_key_thumbprint

#: Length of a raw Ed25519 public key. A trust configuration carries raw keys,
#: never DER or PEM, so this is the only accepted length.
_ED25519_PUBLIC_KEY_BYTES = 32

#: Unpadded base64url alphabet, anchored and non-empty. ``=`` is deliberately
#: absent: the configured form is unpadded, so a padded string is a padding
#: error rather than an alternative spelling.
_B64URL_UNPADDED = re.compile(r"[A-Za-z0-9_-]+")


def _strict_b64url_decode(value: str) -> bytes:
    """Decode ``value`` as **strict unpadded base64url**, raising
    :class:`ValueError` on anything that is not exactly that.

    Strict means all three of the following are errors, not inputs to be
    repaired, because each makes the decoded bytes something other than what
    the configuration literally says:

    - a character outside the unpadded base64url alphabet, ``=`` included,
      which :func:`base64.urlsafe_b64decode` would otherwise DISCARD, so
      ``"!!!!"`` decodes to ``b""`` and would be accepted as a key;
    - a length no base64 string can have (``len % 4 == 1``), and the empty
      string, which decodes to zero bytes;
    - a non-canonical encoding: a final character whose unused low bits are
      not zero, so two distinct strings decode to the same bytes and the
      thumbprint a reader derives by hand from the configured text need not
      be the one this loader files the key under.

    Canonicality is checked by re-encoding rather than by masking bits, so the
    assertion is the one that matters directly: this string is the one and only
    base64url spelling of these bytes.
    """
    if not _B64URL_UNPADDED.fullmatch(value):
        raise ValueError(
            "not strict unpadded base64url (allowed characters are A-Z, a-z, "
            "0-9, '-' and '_', with no '=' padding, and the value must not "
            "be empty)"
        )
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError(
            "non-canonical base64url: the trailing bits of the final "
            "character are not zero, so this is not the unique encoding of "
            "the bytes it decodes to"
        )
    return decoded


class TrustedIssuersConfigError(ValueError):
    """The bridge's trust configuration is itself malformed, rather than
    merely resolving to no trusted key. Raised by :class:`TrustedIssuers`, and
    by :func:`require_domain_binding` when the bridge is handed a resolver that
    cannot name the domain a key is trusted for. Never swallowed: profile
    section 1 makes the trusted issuer config the bridge's trust anchor, so an
    operator who misconfigures it must find out when the deployment starts, not
    have it silently narrowed to "the entries we could make sense of"."""


@dataclass(frozen=True)
class _TrustedIssuer:
    """One resolved entry: a kernel key, filed under its own derived
    thumbprint, paired with the one trust domain that key is trusted for."""

    public_key: bytes
    trust_domain: str


class TrustedIssuers:
    """The bridge's trusted issuer config (profile section 1): kernel public
    keys, each **bound to the one trust domain it is trusted for**.

    Entries use the VAID A2A extension's ``trustedIssuers`` shape (section
    2.1) — ``{"trustDomain": ..., "kernelPublicKey": "<unpadded base64url>"}``
    — so one operator's trust configuration reads the same whether it is
    serving A2A, running under ADK, or anchoring this bridge. Use
    :meth:`from_raw_keys` when the keys are already raw bytes in the process
    rather than text in a config file.

    Every shape below is a configuration error, raised rather than skipped or
    narrowed to a best-guess reading (A2A extension section 2.1):

    - An entry that is not an object. It names neither a key nor a domain.
    - An entry with no parseable ``kernelPublicKey``: absent, not a string, or
      not **strict unpadded base64url decoding to exactly 32 bytes**. There is
      no reading of such an entry that resolves to key material a loader could
      actually trust.
    - An entry with no ``trustDomain``. A key with no domain attached binds to
      nothing, so accepting it would leave every document's claimed
      ``trust_domain`` effectively unchecked for that key — the very gap this
      type exists to close.
    - The same kernel public key listed more than once. Whichever domain a
      lookup happened to land on last would otherwise decide, silently, which
      domain that key is actually trusted for.

    As profile section 1 requires of the trust anchor, this MUST NOT be
    populated from anything the presenter controls.
    """

    def __init__(self, trusted_issuers: Iterable[dict]) -> None:
        entries: dict[str, _TrustedIssuer] = {}
        domains_by_thumbprint: dict[str, list[str]] = {}
        for entry in trusted_issuers:
            if not isinstance(entry, dict):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry {entry!r} is not an object, every "
                    "entry must be {'trustDomain': ..., 'kernelPublicKey': ...}"
                )
            raw = entry.get("kernelPublicKey")
            if not isinstance(raw, str):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry {entry!r} has no parseable "
                    "kernelPublicKey, every entry must name the raw kernel "
                    "public key it trusts"
                )
            try:
                key_bytes = _strict_b64url_decode(raw)
            except (binascii.Error, ValueError) as exc:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernelPublicKey {raw!r} could "
                    f"not be decoded as strict unpadded base64url: {exc}"
                ) from exc
            if len(key_bytes) != _ED25519_PUBLIC_KEY_BYTES:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernelPublicKey {raw!r} decodes "
                    f"to {len(key_bytes)} bytes, a raw Ed25519 public key is "
                    f"exactly {_ED25519_PUBLIC_KEY_BYTES} bytes"
                )
            domain = entry.get("trustDomain")
            if not isinstance(domain, str):
                raise TrustedIssuersConfigError(
                    f"trustedIssuers entry for kernel public key {raw!r} has "
                    "no trustDomain, every entry must name the domain its key "
                    "is trusted for"
                )
            # Filed under the thumbprint the key itself derives to, never a
            # caller-supplied one: a thumbprint alone is not key material.
            thumbprint = kernel_key_thumbprint(key_bytes)
            domains_by_thumbprint.setdefault(thumbprint, []).append(domain)
            entries[thumbprint] = _TrustedIssuer(public_key=key_bytes, trust_domain=domain)

        for thumbprint, domains in domains_by_thumbprint.items():
            if len(domains) > 1:
                raise TrustedIssuersConfigError(
                    f"trustedIssuers lists kernel key thumbprint {thumbprint!r} "
                    f"more than once, for domains {domains!r}, a key must be "
                    "trusted for exactly one trust_domain, never whichever "
                    "domain the last entry happened to list"
                )
        self._entries = entries

    @classmethod
    def from_raw_keys(cls, pairs: Iterable[tuple[str, bytes]]) -> "TrustedIssuers":
        """Build the same configuration from ``(trust_domain, raw_public_key)``
        pairs, for a deployment that already holds key bytes in the process (a
        local issuer, a test, a key just fetched from a KMS) rather than
        base64url text in a config file.

        One trust domain may legitimately appear in several pairs — an issuer
        rotating or running more than one kernel key — but one key may not
        appear under two domains, the same rule :class:`TrustedIssuers`
        enforces over config entries, and for the same reason.
        """
        return cls(
            [
                {
                    "trustDomain": domain,
                    "kernelPublicKey": base64.urlsafe_b64encode(bytes(key))
                    .rstrip(b"=")
                    .decode("ascii"),
                }
                for domain, key in pairs
            ]
        )

    def resolve_key(self, thumbprint: str) -> bytes | None:
        """The raw Ed25519 public key for ``thumbprint``, or ``None`` if this
        configuration does not trust that key. Satisfies
        :class:`~vaid_mint.chain.KernelKeyResolver`, so an instance can be
        passed straight to :func:`~vaid_mint.chain.verify_chain_at`."""
        entry = self._entries.get(thumbprint)
        return entry.public_key if entry else None

    def trust_domain_for(self, thumbprint: str) -> str | None:
        """The one trust domain this configuration binds to ``thumbprint``, or
        ``None`` if ``thumbprint`` resolves to no trusted key."""
        entry = self._entries.get(thumbprint)
        return entry.trust_domain if entry else None

    def __len__(self) -> int:
        return len(self._entries)


def require_domain_binding(keys: object) -> None:
    """Raise :class:`TrustedIssuersConfigError` unless ``keys`` can say which
    trust domain each key it resolves is trusted for.

    A resolver that only answers :meth:`resolve_key` — ``KernelKeyMap`` and
    ``SingleKernelKey`` are both such resolvers — cannot have its documents'
    claimed ``trust_domain`` checked against anything, which is exactly the
    posture GHSA-hfjh-v2x2-r58v describes. Accepting one and skipping the
    binding check would leave that gap open by omission, so it is refused
    outright, and refused as early as the configuration is handed over
    (:class:`~vaid_jwt_bridge.service.BridgeConfig`) rather than at the first
    exchange: a missing control must fail where an operator sees it, not
    quietly per-request.

    Duck-typed rather than an ``isinstance`` check against
    :class:`TrustedIssuers`, so a deployment whose keys live in a KMS or a
    directory can supply its own resolver — provided it answers both questions.
    """
    binding = getattr(keys, "trust_domain_for", None)
    if not callable(binding):
        raise TrustedIssuersConfigError(
            f"keys={keys!r} resolves kernel keys but cannot name the trust "
            "domain each key is trusted for (no callable trust_domain_for), so "
            "a document's claimed trust_domain could not be checked against "
            "the key that signed it. Pass a vaid_jwt_bridge.TrustedIssuers (or "
            "any resolver answering both resolve_key and trust_domain_for); a "
            "bare vaid_mint KernelKeyMap/SingleKernelKey is not sufficient "
            "(GHSA-hfjh-v2x2-r58v)."
        )

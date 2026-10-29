"""Bind-by-reference SPIFFE mint: compose the SVID door, the possession
proof, and the unmodified vaid_mint BYO-key root mint.

The VAID that comes out of :class:`SpiffeMint` operates under its own
Ed25519 key (the normal vaid_mint BYO-key path, unchanged) - it is NOT signed
with the SVID's key, which is typically ECDSA or RSA and cannot sit in
vaid_mint's Ed25519-only ``public_key_der`` field. The SPIFFE identity is
bound *by reference*: the SVID chain is verified, the presenter proves it
holds the SVID's private key, and the resulting ``spiffe://`` ID is recorded
as metadata alongside the signed VAID - not inside it. See the README "Scope"
section for exactly what that does and does not give a verifier, and
``docs/SPEC-GAP.md`` for why.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from vaid_mint import MintPop, MintService, VaidSeed
from vaid_mint.audit import AuditSink
from vaid_mint.error import IdentityError

from vaid_spiffe.possession import SvidPossession, verify_svid_possession
from vaid_spiffe.svid import VerifiedSvid, verify_svid_chain

__all__ = ["SvidPresentation", "SpiffeMintResult", "SpiffeMint"]


@dataclass(frozen=True)
class SvidPresentation:
    """What the holder presents at mint: the SVID chain, plus proof it holds
    the SVID's private key."""

    #: SVID leaf certificate, DER-encoded.
    leaf: bytes
    #: Any intermediate CA certificates, DER-encoded, leaf's issuer first.
    intermediates: list[bytes]
    #: Proof the holder controls the SVID's private key.
    possession: SvidPossession


@dataclass(frozen=True)
class SpiffeMintResult:
    """What :meth:`SpiffeMint.mint_root_with_svid` returns: the signed VAID,
    plus the SPIFFE identity it was bound to by reference. The caller gets
    both from one place rather than having to separately recover the binding
    from the audit log."""

    #: The newly-minted, signed VAID document (unmodified vaid_mint shape -
    #: carries no SPIFFE-specific field).
    vaid: dict
    #: The full ``spiffe://trust-domain/path`` the mint bound this VAID to.
    spiffe_id: str
    #: The SPIFFE trust domain component of ``spiffe_id``.
    trust_domain: str


class SpiffeMint:
    """Mints a VAID over a verified SPIFFE SVID, bound by reference.

    Wraps a :class:`~vaid_mint.mint.MintService` (unmodified) and an
    :class:`~vaid_mint.audit.AuditSink` - the same sink the ``MintService``
    itself was constructed with, so a mint that binds an SVID produces one
    audit trail, not two disconnected ones.
    """

    def __init__(
        self,
        mint: MintService,
        audit: AuditSink,
        *,
        trust_bundle: list[bytes],
        expected_trust_domain: str,
    ) -> None:
        self._mint = mint
        self._audit = audit
        self._trust_bundle = trust_bundle
        self._trust_domain = expected_trust_domain
        self._consumed_svid_nonces: set[str] = set()

    def mint_root_with_svid(
        self,
        seed: VaidSeed,
        svid: SvidPresentation,
        pop: MintPop,
        *,
        time: datetime | None = None,
    ) -> SpiffeMintResult:
        """Mint a root VAID bound to a verified SPIFFE SVID.

        Fail-closed order:

        1. The SVID chain verifies against ``trust_bundle`` and carries
           exactly one ``spiffe://`` URI SAN in ``expected_trust_domain``
           (:func:`vaid_spiffe.svid.verify_svid_chain`).
        2. ``seed.public_key_der`` (the VAID operating key) is present - this
           entry point is always BYO-key; there is no generate-and-discard
           SPIFFE mint, because an operator holding neither the SVID key nor
           the operating key would be minting on someone else's behalf.
        3. The holder proves it controls the SVID's private key, over a
           payload binding the operating key being registered
           (:func:`vaid_spiffe.possession.verify_svid_possession`).
        4. The unmodified ``vaid_mint`` BYO-key PoP and root-mint path runs -
           :meth:`~vaid_mint.mint.MintService.mint_root` - exactly as it
           would for a BYO-key mint with no SPIFFE involvement at all.
        5. A second audit event records the SPIFFE binding, through the same
           sink the mint itself audits through.

        Every step before (4) fails closed: a bad SVID or a failed
        possession proof never reaches the mint, so no PoP nonce is consumed
        and no VAID is issued for a presenter who has not proven both that
        the SVID is valid and that they hold its key.
        """
        verified: VerifiedSvid = verify_svid_chain(
            leaf=svid.leaf,
            intermediates=svid.intermediates,
            trust_bundle=self._trust_bundle,
            expected_trust_domain=self._trust_domain,
            time=time,
        )

        if seed.public_key_der is None:
            raise IdentityError(
                "mint_root_with_svid: a BYO Ed25519 operating public_key_der is "
                "required - the SVID is bound by reference; the VAID operates "
                "under its own Ed25519 key, never the SVID's"
            )

        verify_svid_possession(
            leaf=verified.leaf,
            operating_public_key_der=seed.public_key_der,
            possession=svid.possession,
            consumed_nonces=self._consumed_svid_nonces,
        )

        vaid = self._mint.mint_root(seed, pop)

        self._audit.record(
            "vaid_minted_with_external_identity",
            {
                "vaid_id": vaid["vaid_id"],
                "spiffe_id": verified.spiffe_id,
                "trust_domain": verified.trust_domain,
                "binding": "by_reference",
            },
        )

        return SpiffeMintResult(
            vaid=vaid,
            spiffe_id=verified.spiffe_id,
            trust_domain=verified.trust_domain,
        )

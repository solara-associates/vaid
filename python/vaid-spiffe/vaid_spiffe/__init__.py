"""vaid-spiffe - mint a VAID over a verified SPIFFE X.509-SVID.

SPIFFE answers "who is calling" (a verified ``spiffe://`` identity, rooted in
an X.509 chain of trust); VAID carries the delegation (scope- and
capability-attenuated authority, chained across hops). This package is the
bridge: it verifies a presented SVID (chain, expiry, single SPIFFE ID, trust
domain), proves the presenter holds the SVID's private key, and then mints a
VAID through the unmodified ``vaid_mint`` BYO-key root-mint path, recording
the SPIFFE ID alongside the signed document rather than inside it. See the
README "Scope" section for exactly what that binding does and does not
establish for a downstream verifier, and ``docs/SPEC-GAP.md`` for the open
question it leaves (an open, cross-language field for this).

Usage::

    from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer
    from vaid_spiffe import SpiffeMint, SvidPresentation

    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    audit = InMemoryAudit()
    mint = SpiffeMint(
        MintService(issuer, audit),
        audit,
        trust_bundle=[root_ca_der],
        expected_trust_domain="example.org",
    )
    result = mint.mint_root_with_svid(seed, SvidPresentation(leaf, [], possession), pop)
    assert issuer.verify_vaid(result.vaid)
    assert result.spiffe_id == "spiffe://example.org/agent/researcher"
"""

from vaid_spiffe.mint import SpiffeMint, SpiffeMintResult, SvidPresentation
from vaid_spiffe.possession import (
    POSSESSION_FRESHNESS_SECS,
    SvidPossession,
    build_svid_possession_payload,
    canonical_svid_possession_bytes,
    verify_svid_possession,
)
from vaid_spiffe.svid import VerifiedSvid, verify_svid_chain

__all__ = [
    "SpiffeMint",
    "SpiffeMintResult",
    "SvidPresentation",
    "SvidPossession",
    "POSSESSION_FRESHNESS_SECS",
    "build_svid_possession_payload",
    "canonical_svid_possession_bytes",
    "verify_svid_possession",
    "VerifiedSvid",
    "verify_svid_chain",
]

__version__ = "0.1.0"

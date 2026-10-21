"""Parsing a "pasted VAID chain" and walking it hop by hop with vaid-mint.

The wire shape a caller pastes is:

    {"leaf": {...signed VAID document...}, "ancestors": [{...}, ...]}

A standalone root VAID is the degenerate case: `{"leaf": {...root...}}` with
no `ancestors`. Every per-hop result vaid-mint's `verify_chain_at` can produce
is translated here into a plain-English reason — the thing an MCP client's
user actually wants to read, not an enum name.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from vaid_mint.attestation import AttestationBundle
from vaid_mint.chain import ChainVerification, PresentedBundle, verify_chain_at
from vaid_mint.document import is_expired_at
from vaid_mint.verify import verify_vaid_authenticity

from vaid_mcp.keys import KeySourceError, ResolvedKeys


class ChainFormatError(ValueError):
    """The supplied chain JSON is not shaped like `{"leaf": ..., "ancestors": [...]}`."""


@dataclass(frozen=True)
class HopResult:
    vaid_id: str | None
    role: str  # "leaf" or "ancestor"
    authentic: bool
    reason: str


@dataclass(frozen=True)
class ChainVerifyResult:
    verdict: ChainVerification
    plain_reason: str
    hops: tuple[HopResult, ...]
    trust_source: str
    trust_thumbprints: tuple[str, ...]


_VERDICT_EXPLANATIONS = {
    ChainVerification.ATTENUATED: (
        "Every document in the chain is genuinely signed, each child's authority "
        "fits entirely inside its parent's, and nothing in the chain has expired."
    ),
    ChainVerification.INAUTHENTIC: (
        "At least one document's signature does not check out against the trusted "
        "key(s) supplied — either it was tampered with, or it was signed by a key "
        "this check was not told to trust."
    ),
    ChainVerification.UNVERIFIABLE: (
        "The chain cannot be followed all the way to a root: a document further up "
        "the delegation chain was not included in what was pasted, or the chain "
        "loops back on itself. This is 'cannot tell', not 'denied' — paste the "
        "missing ancestor(s) and try again."
    ),
    ChainVerification.NOT_ATTENUATED: (
        "The chain is genuine and complete, but somewhere in it a child claims "
        "authority (scope, capabilities, tenant, or expiry) that its parent did "
        "not actually hold. That is scope widening, and it is denied."
    ),
    ChainVerification.EXPIRED: (
        "The chain is genuine and every hop fits inside the one above it, but an "
        "ancestor further up the chain has already passed its own expiry. The "
        "authority at the top of the chain has lapsed, even though nothing was "
        "forged."
    ),
    ChainVerification.CONSENT_EXPIRED: (
        "A hop that crosses from one signing key to another needs the first key's "
        "explicit, time-bound consent to the second. That consent is genuine but "
        "is no longer within its own validity window — it needs renewing."
    ),
}


def parse_chain(chain: dict) -> tuple[dict, list[dict]]:
    if not isinstance(chain, dict) or "leaf" not in chain:
        raise ChainFormatError(
            'expected an object shaped {"leaf": {...}, "ancestors": [...]}'
        )
    leaf = chain["leaf"]
    if not isinstance(leaf, dict):
        raise ChainFormatError('"leaf" must be a VAID document object')
    ancestors = chain.get("ancestors", [])
    if not isinstance(ancestors, list) or not all(isinstance(a, dict) for a in ancestors):
        raise ChainFormatError('"ancestors", if present, must be a list of VAID document objects')
    return leaf, ancestors


def verify_chain_result(
    chain: dict, keys: ResolvedKeys, *, now: datetime | None = None
) -> ChainVerifyResult:
    leaf, ancestors = parse_chain(chain)
    bundle = PresentedBundle(ancestors)
    when = now or datetime.now(timezone.utc)

    verdict = verify_chain_at(keys.resolver, leaf, bundle, AttestationBundle(), when)

    hops: list[HopResult] = []

    def describe(doc: dict, role: str) -> HopResult:
        key = keys.resolver.resolve_key(doc.get("kernel_key_thumbprint"))
        if key is None:
            return HopResult(doc.get("vaid_id"), role, False, "signed by a key not in the trusted set")
        if not verify_vaid_authenticity(key, doc):
            return HopResult(doc.get("vaid_id"), role, False, "signature does not match the trusted key")
        if is_expired_at(doc, when):
            return HopResult(doc.get("vaid_id"), role, True, "signature valid, but this document has expired")
        return HopResult(doc.get("vaid_id"), role, True, "signature valid and current")

    hops.append(describe(leaf, "leaf"))
    for doc in bundle.documents():
        hops.append(describe(doc, "ancestor"))

    return ChainVerifyResult(
        verdict=verdict,
        plain_reason=_VERDICT_EXPLANATIONS[verdict],
        hops=tuple(hops),
        trust_source=keys.source,
        trust_thumbprints=keys.thumbprints,
    )

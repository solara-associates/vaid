"""Does a VAID chain's leaf permit a requested action on a resource?

Fails closed in the one way that matters for an authorization question: if
the chain itself is not genuine and fully attenuated, this refuses to answer
"permitted" or "denied" at all — it says the question is unanswerable and
names why, the same INDETERMINATE-vs-DENIED distinction vaid-mint's own
revocation handling makes (R.4.5 in this repo's spec). A chain that cannot be
trusted is never treated as silently permissive.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from vaid_mint.chain import ChainVerification
from vaid_mint.document import has_capability, is_in_scope

from vaid_mcp.chains import ChainVerifyResult, verify_chain_result
from vaid_mcp.keys import ResolvedKeys


@dataclass(frozen=True)
class ScopeCheckResult:
    chain_result: ChainVerifyResult
    answerable: bool
    permitted: bool | None
    reason: str


def check_scope(
    chain: dict,
    keys: ResolvedKeys,
    requested_action: str,
    resource: str,
    *,
    now: datetime | None = None,
) -> ScopeCheckResult:
    chain_result = verify_chain_result(chain, keys, now=now)

    if chain_result.verdict is not ChainVerification.ATTENUATED:
        return ScopeCheckResult(
            chain_result=chain_result,
            answerable=False,
            permitted=None,
            reason=(
                "cannot determine permission: the chain itself did not verify "
                f"({chain_result.verdict.value}) — {chain_result.plain_reason}"
            ),
        )

    leaf = chain["leaf"]
    has_cap = has_capability(leaf, requested_action)
    in_scope = is_in_scope(leaf, resource)

    if has_cap and in_scope:
        return ScopeCheckResult(
            chain_result=chain_result,
            answerable=True,
            permitted=True,
            reason=(
                f"the chain is genuine and the leaf credential holds the "
                f"\"{requested_action}\" capability, which covers \"{resource}\""
            ),
        )

    missing = []
    if not has_cap:
        missing.append(f'does not hold the capability "{requested_action}"')
    if not in_scope:
        missing.append(f'does not have "{resource}" within its scope boundary')
    return ScopeCheckResult(
        chain_result=chain_result,
        answerable=True,
        permitted=False,
        reason=(
            "the chain is genuine, but the leaf credential " + " and ".join(missing)
        ),
    )

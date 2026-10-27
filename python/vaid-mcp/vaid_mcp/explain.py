"""Decode a VAID document into plain language, without verifying anything.

Deliberately separate from `chains.verify_chain_result`: a caller who just
wants to read what a credential CLAIMS — who, delegated by whom, what it
claims it may do, until when — should get an answer even for a document with
no key to check it against, and that answer must never be mistaken for "this
is genuine". Every field below is read off the document as presented and
could be entirely fabricated; nothing here is a security decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from vaid_mint.document import entry_claimed_resource


@dataclass(frozen=True)
class VaidExplanation:
    agent_id: str | None
    agent_class: str | None
    tenant_id: str | None
    trust_domain: str | None
    is_root: bool
    parent_vaid: str | None
    scope_summary: str
    capabilities: tuple[str, ...]
    issued_at: str | None
    expires_at: str | None
    plain_english: str
    warning: str


def explain_vaid(vaid: dict) -> VaidExplanation:
    agent_id = vaid.get("agent_id")
    agent_class = vaid.get("agent_class")
    tenant_id = vaid.get("tenant_id")
    trust_domain = vaid.get("trust_domain")
    parent_vaid = vaid.get("parent_vaid")
    is_root = parent_vaid is None
    boundary = vaid.get("scope_boundary") or []
    capabilities = tuple(vaid.get("capability_set") or [])
    issued_at = vaid.get("issued_at")
    expires_at = vaid.get("expires_at")

    if not boundary:
        scope_summary = "ANY resource (an empty scope boundary is unrestricted, not empty — see vaid-mint's is_in_scope)"
    else:
        claimed = [entry_claimed_resource(e) for e in boundary if isinstance(e, dict)]
        named = [c for c in claimed if c]
        scope_summary = (
            "resources under: " + ", ".join(named)
            if named
            else f"{len(boundary)} scope rule(s) in a form this explainer cannot summarise by name"
        )

    who = agent_id or "an agent with no agent_id set"
    delegated_by = (
        "nobody — this is a root credential, issued directly by the trust domain"
        if is_root
        else f"another credential (parent_vaid: {parent_vaid})"
    )
    may_do = (
        f"use the capabilities [{', '.join(capabilities)}] on {scope_summary}"
        if capabilities
        else f"act on {scope_summary}, but claims no capabilities at all"
    )
    until = f"until {expires_at}" if expires_at else "with no expiry claimed (unusual — treat as invalid)"

    plain_english = (
        f"This says it identifies {who}, class \"{agent_class or 'unspecified'}\", "
        f"for tenant \"{tenant_id or 'unspecified'}\" under trust domain "
        f"\"{trust_domain or 'unspecified'}\". It was delegated by {delegated_by}. "
        f"It claims it may {may_do}, {until}."
    )

    return VaidExplanation(
        agent_id=agent_id,
        agent_class=agent_class,
        tenant_id=tenant_id,
        trust_domain=trust_domain,
        is_root=is_root,
        parent_vaid=parent_vaid,
        scope_summary=scope_summary,
        capabilities=capabilities,
        issued_at=issued_at,
        expires_at=expires_at,
        plain_english=plain_english,
        warning=(
            "This is a DECODING, not a verification. Nothing above has been checked "
            "against a signature, a trust key, or revocation — every word of it "
            "could be fabricated. Use the verify_chain tool to find out whether it "
            "is genuine."
        ),
    )

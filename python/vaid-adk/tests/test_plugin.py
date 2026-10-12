"""Tests for VaidAuthPlugin's dispatch through the real BasePlugin hook
signatures (before_agent_callback / before_tool_callback), using minimal
duck-typed stand-ins for ADK's Agent/Tool/ToolContext — the plugin reads
only `.name` and `.agent_name` from them, so a full Runner is not needed to
exercise the wiring itself (the examples/ script exercises it through a real
Runner)."""

from __future__ import annotations

import uuid
from datetime import timezone, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_adk import (
    ToolAuthorization,
    TrustedIssuers,
    VaidAuthPlugin,
    VaidPresentation,
)
from vaid_mint.document import build_unsigned_vaid_document, canonical_vaid_signing_bytes, compute_lineage_hash
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import InMemoryRevocationList

_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x22]) * 32)
_PUBLIC = _KEY.public_key().public_bytes_raw()
_THUMBPRINT = kernel_key_thumbprint(_PUBLIC)


class _Agent:
    def __init__(self, name: str) -> None:
        self.name = name


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _ToolContext:
    def __init__(self, agent_name: str) -> None:
        self.agent_name = agent_name


def _root_vaid(scope: list[str], caps: list[str]) -> dict:
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-06-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=scope,
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=caps,
        trust_domain="vaid.example",
        kernel_key_thumbprint=_THUMBPRINT,
    )
    signature = _KEY.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def _plugin(tool_authorizations: dict[str, ToolAuthorization] | None = None) -> VaidAuthPlugin:
    return VaidAuthPlugin(
        keys=TrustedIssuers.from_raw_keys([("vaid.example", _PUBLIC)]),
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        tool_authorizations=tool_authorizations or {},
    )


@pytest.mark.asyncio
async def test_before_agent_callback_allows_registered_identity() -> None:
    plugin = _plugin()
    plugin.register("worker", VaidPresentation(leaf=_root_vaid(["data.x"], ["read"])))
    result = await plugin.before_agent_callback(agent=_Agent("worker"), callback_context=None)
    assert result is None


@pytest.mark.asyncio
async def test_before_agent_callback_denies_unregistered_agent() -> None:
    plugin = _plugin()
    result = await plugin.before_agent_callback(agent=_Agent("ghost"), callback_context=None)
    assert result is not None
    assert "ghost" in result.parts[0].text


@pytest.mark.asyncio
async def test_before_tool_callback_denies_unmapped_tool_never_default_allow() -> None:
    plugin = _plugin(tool_authorizations={})  # nothing mapped
    plugin.register("worker", VaidPresentation(leaf=_root_vaid(["data.x"], ["read"])))
    result = await plugin.before_tool_callback(
        tool=_Tool("anything"), tool_args={}, tool_context=_ToolContext("worker")
    )
    assert result is not None
    assert result["code"] == "unmapped_tool"


@pytest.mark.asyncio
async def test_before_tool_callback_allows_authorized_call() -> None:
    plugin = _plugin({"lookup": ToolAuthorization(capability="read", resource="data.x")})
    plugin.register("worker", VaidPresentation(leaf=_root_vaid(["data.x"], ["read"])))
    result = await plugin.before_tool_callback(
        tool=_Tool("lookup"), tool_args={}, tool_context=_ToolContext("worker")
    )
    assert result is None


@pytest.mark.asyncio
async def test_before_tool_callback_denies_call_outside_capability_set() -> None:
    plugin = _plugin({"write_tool": ToolAuthorization(capability="write", resource="data.x")})
    plugin.register("worker", VaidPresentation(leaf=_root_vaid(["data.x"], ["read"])))
    result = await plugin.before_tool_callback(
        tool=_Tool("write_tool"), tool_args={}, tool_context=_ToolContext("worker")
    )
    assert result is not None
    assert result["code"] == "missing_capability"


@pytest.mark.asyncio
async def test_before_tool_callback_denies_missing_vaid() -> None:
    plugin = _plugin({"lookup": ToolAuthorization(capability="read", resource="data.x")})
    # "worker" never registered.
    result = await plugin.before_tool_callback(
        tool=_Tool("lookup"), tool_args={}, tool_context=_ToolContext("worker")
    )
    assert result is not None
    assert result["code"] == "no_vaid"

"""The ADK extension point: a ``BasePlugin`` that verifies a VAID before an
agent runs (including as a delegated sub-agent) and before any tool call,
denying fail-closed on anything it cannot positively verify.

**Why a plugin, not a per-agent callback.** ADK's ``BaseAgent``/``LlmAgent``
accept ``before_agent_callback`` and ``before_tool_callback`` directly, and
the June 2026 ADK adapter in ``forge-agents`` wired its governed-delegation
gate that way (``before_agent_callback`` closing over one sub-agent's mint
call). That shape is reused here for *where* enforcement attaches — before an
agent runs, before a tool is called — but this package registers through
``BasePlugin`` instead of per-agent fields, for one reason: a per-agent
callback is opt-in per agent, so an agent constructed without one runs
ungoverned by omission. A ``BasePlugin`` is registered once on the app/runner
and ``invocation_context.plugin_manager`` consults it for *every* agent and
*every* tool call in the invocation tree — including a sub-agent added after
this gate was wired, and including ADK's own native delegation
(``transfer_to_agent`` / ``sub_agents``) with no further code at the call
site. There is no agent that can be forgotten.

**What is NOT in scope here.** This package verifies and authorizes; it does
not mint. Minting an attenuated child VAID for a sub-agent is the caller's
job, using ``vaid_mint.mint.MintService.mint_child`` directly (as the
forge-agents/synthera ADK adapters already do) — this plugin only checks
whatever VAID presentation has been registered for an agent, the same way a
server checks a bearer token it did not issue.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from google.adk.plugins.base_plugin import BasePlugin
from google.genai import types as gtypes

from vaid_mint.revocation import RevocationCheck

from ._verify import (
    TrustedIssuers,
    VaidPresentation,
    VerifyResult,
    require_domain_binding,
    verify_presentation,
)

if TYPE_CHECKING:
    from google.adk.agents.base_agent import BaseAgent
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext


@dataclass(frozen=True)
class ToolAuthorization:
    """What a tool call requires of the leaf VAID, for exactly one tool name.

    ``capability`` is required and has no default — a tool with no mapping is
    a tool :class:`VaidAuthPlugin` denies, never one it lets through
    unauthorized (see the plugin's docstring: never default to allow).
    ``resource`` is optional; give it when the tool reads or writes something
    a ``scope_boundary`` entry should gate (e.g. ``"data.customer_records"``).
    """

    capability: str
    resource: str | None = None


def _denial_content(reason: str) -> gtypes.Content:
    return gtypes.Content(role="model", parts=[gtypes.Part(text=f"VAID DENIED: {reason}")])


def _denial_response(code: str, reason: str) -> dict:
    return {"error": "vaid_denied", "code": code, "reason": reason}


class VaidAuthPlugin(BasePlugin):
    """Verifies a presented VAID before an agent runs and before any tool
    call, denying fail-closed.

    Construct once per process/app and register it on the ``Runner``/``App``:

        plugin = VaidAuthPlugin(
            keys=TrustedIssuers.from_raw_keys([("vaid.example", issuer_public_key)]),
            revocation=my_revocation_check,
            tool_authorizations={"lookup_order": ToolAuthorization(capability="read")},
        )
        plugin.register("sub_agent_name", VaidPresentation(leaf=child_vaid, chain=(parent_vaid,)))
        runner = Runner(..., plugins=[plugin])

    ``keys`` and ``revocation`` are REQUIRED constructor arguments, not
    defaulted — there is deliberately no ``assume_nothing_revoked()`` default
    here the way ``vaid_mint.issuer.ReferenceIssuer`` names its fail-open
    opt-in explicitly; a library wiring itself into every tool call and every
    delegation must never pick a revocation posture on the caller's behalf.

    ``keys`` is a :class:`~vaid_adk.TrustedIssuers`: kernel keys each bound to
    the one trust domain it is trusted for. A bare ``vaid_mint`` resolver
    (``KernelKeyMap``, ``SingleKernelKey``) is refused **in this constructor**,
    not at the first request — a resolver that cannot name a key's domain
    leaves every document's claimed ``trust_domain`` unchecked for that key
    (GHSA-hfjh-v2x2-r58v), and a missing control must fail where an operator
    sees it rather than silently per-call.
    An agent with no registered presentation is denied — never treated as
    exempt — because an unregistered agent is indistinguishable from one that
    was simply never given an identity.
    """

    def __init__(
        self,
        *,
        keys: TrustedIssuers,
        revocation: RevocationCheck,
        tool_authorizations: dict[str, ToolAuthorization] | None = None,
        name: str = "vaid_auth",
    ) -> None:
        # Before super().__init__, so a plugin that cannot bind a trust domain
        # to a key never comes into existence at all — there is no half-built
        # instance for a caller to register on a Runner by mistake.
        require_domain_binding(keys)
        super().__init__(name=name)
        self.keys = keys
        self.revocation = revocation
        self.tool_authorizations: dict[str, ToolAuthorization] = dict(tool_authorizations or {})
        self._presentations: dict[str, VaidPresentation] = {}

    def register(self, agent_name: str, presentation: VaidPresentation) -> None:
        """Register the VAID presentation for one agent, by its ADK agent
        ``name``. Call this for every agent — root and sub-agent — that
        should be allowed to run or call a tool; an agent with no entry here
        is denied by :meth:`before_agent_callback` and
        :meth:`before_tool_callback`."""
        self._presentations[agent_name] = presentation

    def unregister(self, agent_name: str) -> None:
        """Drop a registered presentation, e.g. once a delegated sub-agent's
        attenuated VAID has expired or its task has completed."""
        self._presentations.pop(agent_name, None)

    def _verify_for(
        self,
        agent_name: str,
        *,
        requested_resource: str | None = None,
        requested_capability: str | None = None,
        now: datetime | None = None,
    ) -> VerifyResult:
        return verify_presentation(
            self._presentations.get(agent_name),
            keys=self.keys,
            revocation=self.revocation,
            requested_resource=requested_resource,
            requested_capability=requested_capability,
            now=now,
        )

    async def before_agent_callback(
        self, *, agent: "BaseAgent", callback_context: "CallbackContext"
    ) -> gtypes.Content | None:
        """Verify the agent's own registered VAID before ADK runs it at all
        — root invocation or delegated sub-agent alike. A failure returns
        ``Content``, which ADK reads as ``end_invocation`` for this agent and
        skips its ``_run_async_impl`` (the same contained-by-construction
        shape the forge-agents ADK template uses for its mint gate)."""
        result = self._verify_for(agent.name)
        if result.allowed:
            return None
        return _denial_content(
            f"agent {agent.name!r} not permitted to run: {result.reason}"
        )

    async def before_tool_callback(
        self, *, tool: "BaseTool", tool_args: dict, tool_context: "ToolContext"
    ) -> dict | None:
        """Verify the calling agent's VAID covers this specific tool before
        ADK invokes it. A failure returns a dict, which ADK uses as the
        tool's function response directly — the tool itself is never called.

        The tool name is looked up in ``tool_authorizations``, required and
        with no fallback: a tool absent from that map is denied, never
        allowed by omission."""
        authz = self.tool_authorizations.get(tool.name)
        if authz is None:
            return _denial_response(
                "unmapped_tool",
                f"tool {tool.name!r} has no entry in tool_authorizations — "
                "never defaulting to allow",
            )
        result = self._verify_for(
            tool_context.agent_name,
            requested_resource=authz.resource,
            requested_capability=authz.capability,
        )
        if result.allowed:
            return None
        return _denial_response(result.code.value, result.reason)

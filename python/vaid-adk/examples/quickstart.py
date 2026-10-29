"""VAID-ADK five-line quickstart. Offline, no model/API key: the agent is a
plain BaseAgent that issues two tool calls directly through the real ADK
plugin manager, so the ALLOWED/DENIED outcome below comes from
VaidAuthPlugin's own check, not a mock of it.

Run: python examples/quickstart.py
"""

import asyncio
import os
from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_mint.revocation import InMemoryRevocationList
from vaid_adk import ToolAuthorization, TrustedIssuers, VaidAuthPlugin, VaidPresentation
from google.adk.agents import BaseAgent
from google.adk.events import Event
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as gtypes

TRUST_DOMAIN = "vaid.example"  # RFC 2606 reserved domain, demo only


class Worker(BaseAgent):
    async def _run_async_impl(self, ctx):
        for tool_name, resource in (("lookup_order", "data.orders"), ("issue_refund", "data.payments")):
            denial = await ctx.plugin_manager.run_before_tool_callback(
                tool=_Tool(tool_name), tool_args={"resource": resource}, tool_context=_Ctx(self.name)
            )
            outcome = "ALLOWED" if denial is None else f"DENIED ({denial['code']})"
            yield Event(invocation_id=ctx.invocation_id, author=self.name,
                        content=gtypes.Content(role="model", parts=[gtypes.Part(text=f"{tool_name}: {outcome}")]))


class _Tool:
    def __init__(self, name): self.name = name


class _Ctx:
    def __init__(self, agent_name): self.agent_name = agent_name


async def main():
    # Ordinary vaid_mint: mint a root VAID, then a child attenuated to
    # read-only access over data.orders (no data.payments, no write).
    issuer = ReferenceIssuer.from_seed(os.urandom(32), vaid_ttl_hours=1, trust_domain=TRUST_DOMAIN)
    mint = MintService(issuer, InMemoryAudit())
    root = mint.mint_root(VaidSeed(
        agent_class="worker", version="1.0.0", tenant_id="acme",
        scope_boundary=[prefix_entry("data.orders")], capability_set=["read"],
    ))

    # --- the five lines: register the plugin on a real ADK Runner ---
    plugin = VaidAuthPlugin(
        keys=TrustedIssuers.from_raw_keys([(TRUST_DOMAIN, issuer.kernel_public_key())]),
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        tool_authorizations={
            "lookup_order": ToolAuthorization(capability="read", resource="data.orders"),
            "issue_refund": ToolAuthorization(capability="write", resource="data.payments"),
        },
    )
    plugin.register("worker", VaidPresentation(leaf=root))
    sessions = InMemorySessionService()
    await sessions.create_session(app_name="quickstart", user_id="u", session_id="s1")
    runner = Runner(app_name="quickstart", agent=Worker(name="worker"), session_service=sessions, plugins=[plugin])
    # --- end five lines ---

    async for event in runner.run_async(
        user_id="u", session_id="s1",
        new_message=gtypes.Content(role="user", parts=[gtypes.Part(text="go")]),
    ):
        if event.content and event.content.parts and event.content.parts[0].text:
            print(event.content.parts[0].text)


if __name__ == "__main__":
    asyncio.run(main())

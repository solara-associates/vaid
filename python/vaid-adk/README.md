# vaid-adk

## VAID-ADK in five lines

```
pip install vaid-adk
```

Register the plugin on an existing ADK `Runner` and it checks every tool
call before the tool runs:

```python
plugin = VaidAuthPlugin(
    keys=TrustedIssuers.from_raw_keys([(TRUST_DOMAIN, issuer.kernel_public_key())]),
    revocation=InMemoryRevocationList.assume_nothing_revoked(),  # see "Production note" below
    tool_authorizations={
        "lookup_order": ToolAuthorization(capability="read", resource="data.orders"),
        "issue_refund": ToolAuthorization(capability="write", resource="data.payments"),
    },
)
plugin.register("worker", VaidPresentation(leaf=worker_vaid))
runner = Runner(app_name="quickstart", agent=worker_agent, session_service=sessions, plugins=[plugin])
```

The worker's VAID carries `data.orders`/`read` only. Run that `runner`
against an agent that attempts both tools (full script:
`examples/quickstart.py`, verified against the published `vaid-adk==0.2.1`
package in a fresh venv, output below unedited):

```
lookup_order: ALLOWED
issue_refund: DENIED (out_of_scope)
```

`lookup_order` is within the worker's VAID; `issue_refund` needs
`data.payments`/`write`, which the worker's VAID never held, so
`VaidAuthPlugin` denies it before the tool runs. That is `VaidAuthPlugin`'s
own check deciding each outcome, not a condition written for the demo.

VAID verification for Google's Agent Development Kit (ADK): a `BasePlugin`
that checks a presented VAID's signature, expiry, delegation-chain
attenuation and revocation status before an agent runs, before it is
delegated to as a sub-agent, and before it calls a tool. It denies
fail-closed whenever any of that cannot be positively confirmed.

ADK has no built-in mechanism for this (google/adk-python#4992, #6551). This
package adds it for an agent that already carries a VAID
(https://github.com/solara-associates/vaid), using only `vaid_mint`'s
existing signature, chain and revocation primitives. It does not mint
credentials; minting an attenuated child VAID for a sub-agent is the
caller's job, via `vaid_mint.mint.MintService.mint_child`, exactly what
`examples/two_agent_delegation.py` does before wiring the plugin.

## Why a plugin, not a per-agent callback

ADK's `BaseAgent`/`LlmAgent` accept `before_agent_callback` and
`before_tool_callback` directly, and that is the hook an ADK adapter built
in June 2026 (`forge-agents` commit `85fdaa8`, `synthera` commit `dd0503c`)
used for its governed-delegation gate: `before_agent_callback` closing over
one sub-agent's `mint_child` call. That shape, enforce before an agent
runs and before a tool is called, is reused here, but `vaid-adk` registers
through `BasePlugin` instead of per-agent fields, for one reason: a
per-agent callback is opt-in per agent, so an agent constructed without one
runs ungoverned by omission. A `BasePlugin` is registered once on the
`Runner`/`App`, and ADK's `plugin_manager` consults it for every agent and
every tool call in the invocation tree, including a sub-agent added after
the gate was wired, and including ADK's own native delegation
(`transfer_to_agent` / `sub_agents`) with no further code at the call site.

Confirmed directly against the ADK source (`google-adk==2.11.0`):

- `BaseAgent._run_with_lifecycle` calls `self._handle_before_agent_callback(ctx)`
  on **every** `run_async`, which runs `ctx.plugin_manager.run_before_agent_callback`
  before the agent's own canonical callbacks; returning `Content` sets
  `ctx.end_invocation`, skipping the agent entirely, including a sub-agent
  reached through ADK's native delegation loop.
- `_caller.py`'s `_call_tool_async` runs
  `invocation_context.plugin_manager.run_before_tool_callback(tool=tool,
  tool_args=function_args, tool_context=tool_context)` before any canonical
  callback; a non-`None` return becomes the tool's function response
  directly, and the tool itself is never called.

## Usage

```python
from vaid_adk import (
    ToolAuthorization,
    TrustedIssuers,
    VaidAuthPlugin,
    VaidPresentation,
)

plugin = VaidAuthPlugin(
    # Each trusted kernel key is bound to the ONE trust domain it is trusted
    # for. Read from an `AgentCard`-shaped config instead with
    # `TrustedIssuers([{"trustDomain": ..., "kernelPublicKey": "<base64url>"}])`.
    keys=TrustedIssuers.from_raw_keys([("vaid.example", issuer_kernel_public_key)]),
    revocation=my_revocation_check,                   # see "Production note" below
    tool_authorizations={
        "lookup_order": ToolAuthorization(capability="read", resource="data.orders"),
        "issue_refund": ToolAuthorization(capability="write", resource="data.payments"),
    },
)

# Register the VAID each agent presents: its own signed document (`leaf`)
# plus the ancestor chain back to a trusted root (`chain`), not including
# the leaf itself.
plugin.register("coordinator", VaidPresentation(leaf=root_vaid))
plugin.register("worker", VaidPresentation(leaf=worker_child_vaid, chain=(root_vaid,)))

# runner = Runner(..., plugins=[plugin])
```

A tool with no entry in `tool_authorizations` is **denied**, never allowed
by omission. An agent with no registered presentation is denied the same
way: it is indistinguishable from one that was simply never given an
identity.

## Run the example

```
pip install -e python/vaid-mint
pip install -e python/vaid-adk[test]
python python/vaid-adk/examples/two_agent_delegation.py
```

A coordinator mints an attenuated child VAID for a worker sub-agent (scope
`data.orders` only, capability `read` only, narrower than the coordinator's
own `data.orders` + `data.payments`, `read` + `write`), registers both
agents' presentations with the plugin, and runs them through a real ADK
`Runner`. The worker then attempts two tool calls:

```
[coordinator] delegating to worker
[worker] lookup_order: ALLOWED
[worker] issue_refund: DENIED (out_of_scope)
```

`lookup_order` is within the worker's attenuated `data.orders`/`read`
bounds; `issue_refund` needs `data.payments`/`write`, which the worker's
VAID never held, so the plugin denies it before the tool runs.

## Trust configuration: a key is trusted for one domain

`keys` is a `TrustedIssuers`, and each kernel key in it is bound to the **one
trust domain it is trusted for**. A document signed by a trusted key is
accepted only if it also claims that key's domain.

Binding matters because without it a trusted key vouches for any domain a
document cares to claim. Given two legitimately trusted issuers, A and B, a
document signed by B's key while claiming A's `trust_domain` verifies
perfectly against B's key and was accepted: B's key vouching for A's
identity, with no forged signature and no compromised key anywhere in the
attack (GHSA-hfjh-v2x2-r58v). A key is trusted for the domain it is paired
with, never for a domain a document asserts.

Two spellings of the same configuration:

```python
# From an AgentCard-shaped config: the VAID A2A extension's `trustedIssuers`
# shape (docs/a2a/v1/extension.md section 2.1), so one agent's trust
# configuration reads the same whether it serves A2A or runs under ADK.
keys = TrustedIssuers([
    {"trustDomain": "vaid.example",  "kernelPublicKey": "IVL40Zt5HSRF..."},
    {"trustDomain": "other.example", "kernelPublicKey": "My6-jSfLcyOz..."},
])

# From key bytes already held in the process (a local issuer, a key just
# fetched from a KMS).
keys = TrustedIssuers.from_raw_keys([("vaid.example", issuer_kernel_public_key)])
```

`kernelPublicKey` is decoded as **strict unpadded base64url to exactly 32
bytes**. A padded, non-canonical, out-of-alphabet, empty or wrong-length
value raises `TrustedIssuersConfigError` rather than being repaired or
skipped, as do a non-object entry, an entry with no `trustDomain`, and the
same key listed under two domains. One domain may hold several keys (an
issuer rotating); one key may not hold two domains.

A bare `vaid_mint.chain.KernelKeyMap` or `SingleKernelKey` is **not** accepted
as `keys`. Those resolve a key by thumbprint and cannot say which domain it is
trusted for, so the binding could not be checked at all; `VaidAuthPlugin`
refuses one in its constructor, so the gap cannot be left open by omission.
Any resolver answering both `resolve_key` and `trust_domain_for` is accepted.

## What this package checks, in order

1. The leaf VAID's own trust-domain binding — its claimed `trust_domain`
   equals the domain its `kernel_key_thumbprint` is bound to in `keys` — and
   only then its kernel signature, against the key that thumbprint resolved
   to. The binding is checked first so an unrecognised or misbound issuer
   (`issuer_mismatch`) stays distinguishable from a correctly-bound issuer
   whose signature does not verify (`inauthentic`).
2. The leaf's own `expires_at`.
3. Each presented ancestor's own trust-domain binding, by the same rule and
   reporting the same code, and then the presented chain's integrity and
   attenuation back to a trusted root (`vaid_mint.chain.verify_chain_at`):
   scope, capabilities, tenant and expiry contained at every hop.
4. The specific tool call's mapped `resource`/`capability` against the
   leaf's own `scope_boundary`/`capability_set`.
5. Revocation of every VAID in the assembled lineage, via the
   `RevocationCheck` passed to `VaidAuthPlugin`.

The order is load-bearing, not incidental. Step 1 reaches its verdict on the
leaf alone before step 3 examines any presented document, so a leaf whose own
signature does not verify is `inauthentic` regardless of what else was
presented alongside it — a defect found in the chain never pre-empts a verdict
step 1 would already have reached.

Any step that cannot be positively confirmed denies the call. "Could not
determine" (an unassembled chain, an unavailable revocation store) is never
read as "not revoked"; see `vaid_mint.revocation.RevocationStatus` and
`vaid_mint.verify.VaidVerdict`, whose fail-closed rule this package inherits
rather than re-deciding.

## Production note: wire a real RevocationCheck

`VaidAuthPlugin` takes `revocation` as a **required** constructor argument
with no default. The example above uses
`InMemoryRevocationList.assume_nothing_revoked()` only because it has no
production revocation store to call. That store is non-durable and fails
*open* after a restart (a VAID revoked before the restart verifies clean
again), which is fine for a demo and wrong for anything that must survive
one. For production, inject a durable `RevocationCheck` backed by your own
revoked-credential store (see `vaid_mint.revocation.RevocationBackend` for
the reference shape: both the revoked-set half and the lineage-resolver half
durable together, never one without the other) and let it report
`RevocationStatus.UNAVAILABLE` whenever it cannot be reached; this plugin
already denies on that outcome.

## What this package does not do

- **It does not mint.** Issuing a root VAID or an attenuated child VAID for
  a sub-agent is ordinary `vaid_mint` usage (`MintService.mint_root` /
  `mint_child`), done by the caller before `VaidAuthPlugin.register` is
  called.
- **It does not depend on `forge-agents` or `synthera`.** The June 2026 ADK
  adapters in those repos are prior art for the hook choice; this package
  reuses only `vaid_mint`.
- **It does not depend on `vaid-a2a`.** The verification order in
  `vaid_adk._verify` mirrors `vaid_a2a.verifier.verify_a2a_message`'s order
  deliberately (both are "how do you check a presented VAID end to end"),
  but each is self-contained against `vaid_mint` rather than one importing
  the other.

## Packaged conformance firewall

An installed copy can be checked without this repository:

```
vaid-adk-conformance           # exit 0 = PASS, 1 = BLOCKER
python -m vaid_adk.conformance  # same
```

It verifies the frozen three-hop delegation chain bundled in `vaid-mint`
(`chain_v1.json`), at the instant that vector names rather than the wall clock,
and asserts eight outcomes: one that must be **allowed**, and seven that must
each be **denied with a different code** (cross-domain key, out-of-scope
resource, missing capability, no VAID, withheld ancestry, revoked ancestor,
revocation unavailable). It also asserts that a trust resolver which cannot bind
a domain to a key is refused outright, which is the half of
GHSA-hfjh-v2x2-r58v no single request can demonstrate.

The allowed case is load-bearing: without it, a build that denied everything
would satisfy every other check. It pins **verdicts**, not bytes - this package
signs nothing of its own.

## Install

**Local dev only**, from a repo checkout:

```
pip install -e python/vaid-pop
pip install -e python/vaid-mint
pip install -e python/vaid-adk[test]
```

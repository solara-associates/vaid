# vaid-langchain

Sign every outbound HTTP request a LangChain agent makes with a **VAID
proof-of-possession**, without forking LangChain.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vaid_pop import RequestSigner
from vaid_langchain import make_vaid_tool

signer = RequestSigner(vaid=my_vaid_doc, private_key=my_key)   # hand-provisioned
tool = make_vaid_tool(signer, base_url="https://api.example.com")
# give `tool` to a LangChain agent — every call it makes to the backend is
# VAID-signed with the four x-synthera-* headers.
```

Run the zero-dependency demo (mock backend, no server/LLM/API key):

```
python examples/quickstart.py
```

## How it works — the seam is the HTTP client, not the tool layer

Agent frameworks hook at the *tool-call* layer (a function name + kwargs). VAID
proof-of-possession signs an *HTTP request* — it binds `(method, request-target,
body_sha256)`. So the clean, non-forking seam is the **HTTP client** the tool
uses: **`VaidAuth`** is an `httpx.Auth` subclass that runs on every outbound
request and attaches the PoP headers.

That means `VaidAuth` is the whole reusable adapter — usable with any `httpx`
client, LangChain not required:

```python
import httpx
from vaid_langchain import VaidAuth
client = httpx.Client(base_url="https://api.example.com", auth=VaidAuth(signer))
client.post("/vaid/mint", json={...})   # signed
```

`make_vaid_tool` is just LangChain's idiomatic wrapper (a `StructuredTool`) around
a client carrying that auth. Signing itself defers to `vaid_pop.RequestSigner` —
canonicalization is never reimplemented, so a conforming verifier derives
identical bytes.

## The signed request target includes the query string — a security decision

The signed `path` is the **on-the-wire request target: percent-encoded path +
`?query`** (httpx `request.url.raw_path`), never path-only.

This is a **security decision, not a demo convenience.** Signing path-only would
leave query parameters (`?tenant=…`, `?limit=…`, ids, filters) **outside the
signature**, so an attacker could alter them under a still-valid signature. Since
the query frequently carries authorization-relevant material, it must be part of
the signed target. The convention is pinned and covered by an explicit
cross-language round-trip test (`tests/test_path_convention.py`), including a case
proving that using the wrong attribute (query-dropping `.path`) fails verification
**loudly** rather than silently. A verifier MUST reconstruct the same target
(path + query) it received.

## Provisioning is hand-done — NOT managed by this SDK

This adapter signs requests; it does **not** provision identity. Getting the
agent's **VAID document** and its **Ed25519 private key** into the process is the
caller's responsibility:

- **Mint the VAID** with the reference mint (`vaid-mint`) or your deployment's
  managed authority.
- **Load the private key** from your own secret store / env / file.

The quickstart hard-codes a demo VAID + key purely to run offline. Do not ship
hard-coded keys — treat the agent's private key (and, per the mint's delegation
model, any parent VAID it holds) as a credential.

## Install (local dev)

Depends on `vaid-pop`. For a local checkout:

```
pip install -e python/vaid-pop
pip install -e python/vaid-langchain[test]   # includes langchain-core + pytest
```

## Other frameworks

CrewAI and Google ADK integrate through the **same `VaidAuth` seam** (subclass
`crewai.tools.BaseTool` / wrap an ADK `FunctionTool` over a `VaidAuth`-bearing
client). Only LangChain ships today; the shared auth is what makes the others
near-copies.

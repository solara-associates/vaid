"""5-minute quickstart: a LangChain tool whose calls are VAID-signed.

Run:  python examples/quickstart.py

This uses an in-process mock backend (httpx.MockTransport) so it runs with no
server, no network, and no LLM/API key — it prints the four x-synthera-* PoP
headers the tool attaches to its outbound request, and verifies the signature.

IMPORTANT — provisioning is hand-done here, NOT managed by the SDK:
the VAID document and the Ed25519 private key below are hard-coded demo values.
In a real deployment you mint the VAID (see vaid-mint) and load the agent's
private key from your own secret store; the vaid SDK does not provision either.
"""

from __future__ import annotations

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_pop import RequestSigner
from vaid_langchain import VaidAuth, make_vaid_tool

# ── Hand-provisioned demo identity (NOT SDK-managed) ──
DEMO_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
DEMO_VAID = {
    "vaid_id": "11111111-1111-1111-1111-111111111111",
    "tenant_id": "acme",
}


def main() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(DEMO_SEED)
    signer = RequestSigner(vaid=DEMO_VAID, private_key=private_key)

    # A mock backend that echoes back the PoP headers it received.
    def backend(request: httpx.Request) -> httpx.Response:
        pop = {k: v for k, v in request.headers.items() if k.startswith("x-synthera-")}
        print("── request arrived at the protected backend ──")
        print(f"  {request.method} {request.url.raw_path.decode('ascii')}")
        for k, v in pop.items():
            shown = v if len(v) < 60 else v[:57] + "..."
            print(f"  {k}: {shown}")
        return httpx.Response(200, json={"minted": True})

    client = httpx.Client(
        base_url="https://api.example.com",
        auth=VaidAuth(signer),
        transport=httpx.MockTransport(backend),
    )
    tool = make_vaid_tool(signer, "https://api.example.com", client=client)

    # An agent would call this tool; here we invoke it directly (no LLM needed).
    result = tool.invoke(
        {"path": "/vaid/mint?tenant=acme", "payload": {"seed": {"agentClass": "runner"}}}
    )
    print("\nbackend response:", result)


if __name__ == "__main__":
    main()

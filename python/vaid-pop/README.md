# vaid-pop

Canonical Python proof-of-possession (PoP) request signer for the
[VAID](https://github.com/solara-associates/vaid) standard.

This is the **single Python definition** of the PoP signing contract. A
VAID-bound request carries a fresh, replay-protected Ed25519 signature; this
package builds the four `x-synthera-*` headers that carry it. Import it
directly — no extra runtime, no framework.

```python
from vaid_pop import RequestSigner

signer = RequestSigner(vaid=vaid_doc, private_key=agent_key)
headers = signer.sign_headers("POST", "/vaid/mint", body_bytes)
# -> {"x-synthera-vaid": ..., "x-synthera-timestamp": ...,
#     "x-synthera-nonce": ..., "x-synthera-signature": ...}
```

> The `x-synthera-*` header names are the VAID wire contract — the prefix is the
> fixed header namespace a conforming verifier reads, not a package dependency.

## The firewall

Cross-language byte-identity is the whole point. The signer is locked against the
frozen cross-language vector (vendored here at
`vaid_pop/vectors/operator_pop_v1.json`), which the Rust client (`vaid-client`)
and the verifier (`vaid_pop`) assert against too. The `pop-conformance` CI job
proves **Rust output == Python output == vector** byte-for-byte. A mismatch is a
hard blocker.

Contract: RFC 8785 (JCS) over the camelCase `RequestAuthPayload` → SHA-256 →
pure Ed25519 over the 32-byte digest → raw 64-byte signature.

> Standardized on `rfc8785` for JCS — the byte-for-byte JCS implementation the
> vector is proven against. Do not substitute another JCS library without
> re-proving byte-equality.

## Relationship to other packages

- **`vaid-client`** (Rust) is the cross-language peer, proven against the same vector.
- Language-specific agent integrations depend on this package and re-export `RequestSigner`.
- Clients consume this directly to authenticate a VAID-bound request.

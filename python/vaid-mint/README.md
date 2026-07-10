# vaid-mint (Python)

The Python mirror of the Rust `vaid-mint` crate: the open, self-hostable
**reference mint** for the VAID (Verifiable Agent Identity) standard.

- **`mint_root`** — mint a root/operator VAID (BYO-key with proof-of-possession,
  or generate-and-discard), gated by an explicit `AuthorizationGate`.
- **`mint_child`** — **attenuated delegation**: an authenticated parent mints a
  child whose authority is always a subset of its own (`child ⊆ parent`).

## Trust model — read this before using the mint

This is a reference implementation with two deliberate, **unguarded** defaults:

1. **`mint_root` has no authorization gate by default (`PermitAll`).** Anyone who
   can call this code can mint a root VAID. Supply a real `AuthorizationGate` for
   anything beyond local experimentation.
2. **`mint_child` is intentionally ungated — attenuation *is* the authorization.**
   Any holder of a valid parent VAID can mint children from it; a child can only
   *narrow* scope/capabilities relative to its parent, never widen
   (`child ⊆ parent`). Possession of a parent VAID is itself the authorization
   boundary for delegation here. **Treat parent-VAID custody with the same care as
   a credential.**

Neither of these is a security recommendation for production use — they are the
honest defaults of a self-hostable reference mint. See the sections below for
where each is enforced in code.

```python
from vaid_mint import ReferenceIssuer, InMemoryAudit, MintService, VaidSeed

issuer = ReferenceIssuer.ephemeral(24)
mint = MintService(issuer, InMemoryAudit())
root = mint.mint_root(VaidSeed(
    agent_class="orchestrator", version="1.0.0", tenant_id="acme",
    scope_boundary=["data.acme"], capability_set=["read", "write"],
))
assert issuer.verify_vaid(root)
```

## The split

This is the open engine of a HashiCorp-Vault-style split. Durable revocation,
KMS-backed kernel keys, and the audit-of-record are the closed managed authority
and are **not** here. `mint_root` is gated by an `AuthorizationGate` that defaults
to `PermitAll` — a reference-implementation choice, **not** a security
recommendation; production deployments should pass a real gate to `MintService`.

`mint_child` is intentionally **ungated because attenuation *is* the
authorization**: any holder of a valid parent VAID can mint children from it, and
a child can only narrow scope/capabilities relative to that parent, never widen
(`child ⊆ parent`). So **possession of a parent VAID is itself the authorization
boundary for delegation** — treat parent-VAID custody with the same care as a
credential.

## Cross-language byte-identity

Proof-of-possession reuses the `vaid-pop` primitive verbatim. The signed VAID
**document** is proven byte-identical to the Rust mint by the vendored frozen
vector `vaid_mint/vectors/mint_v1.json` (the same `mint_v1.json` the Rust
`mint_conformance` test asserts). Run the packaged firewall:

```
vaid-mint-conformance          # exit 0 = PASS (installed mint == frozen vector)
```

Per **Decision B** this is self-consistent within this repo (Rust == Python); it
is **not** byte-conformant against the closed substrate's (still-moving) VAID
format.

## Install (local dev)

`vaid-mint` depends on `vaid-pop`. For a local checkout, install both editable:

```
pip install -e python/vaid-pop
pip install -e python/vaid-mint --no-deps
```

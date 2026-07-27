# vaid-mint (Python)

The Python mirror of the Rust `vaid-mint` crate: the open, self-hostable
**reference mint** for the VAID (Verifiable Agent Identity) standard.

- **`mint_root`** — mint a root/operator VAID (BYO-key with proof-of-possession,
  or generate-and-discard), gated by an explicit `AuthorizationGate`.
- **`mint_child`** — **attenuated delegation**: an authenticated parent mints a
  child whose authority is always a subset of its own (`child ⊆ parent`).

## Trust model — read this before using the mint

> **Upgrading from 0.1.1?** Expiry enforcement is a ⚠️ **breaking behavioral
> change** despite the patch version bump: `verify_vaid` now returns `False` for
> expired VAIDs that previously passed. See
> [CHANGELOG.md](https://github.com/solara-associates/vaid/blob/main/python/vaid-mint/CHANGELOG.md#012)
> before upgrading.

| Concern | Reference mint (this package) | Hosted / commercial |
|---|---|---|
| Revocation | Pluggable, three-state & lineage-aware (`RevocationCheck`); default in-memory, non-durable | Durable, hash-chained |
| Expiry (TTL) | Enforced at verification (hard reject) | Enforced |
| Auth | Pluggable (`AuthorizationGate`) | Pluggable |
| Audit | Pluggable (`AuditSink`) | Pluggable |

**Revocation is a three-state, lineage-aware seam (0.2.0); the shipped default is
non-durable.** Per `docs/spec/revocation.md` R.4 — a breaking replacement of the
0.1.2 boolean, leaf-only check — the verifier assembles the VAID's ordered ancestry
and hands it to `RevocationCheck.check_lineage`, which returns a `RevocationStatus`
of `NOT_REVOKED`, `REVOKED`, or `UNAVAILABLE`. A VAID is revoked if **any** ancestor
is (revoking a parent revokes its children), and verification **fails closed** on
`UNAVAILABLE` — an incomplete lineage (e.g. an empty resolver after restart) or an
unreachable store rejects rather than silently passing. Inject your own durable,
restart-surviving backend via `ReferenceIssuer.with_revocation_check`; what ships
*by default* is a non-durable in-memory store, so if the process restarts and you
have not wired a durable backend, previously revoked VAIDs may become revocable
again. The seam closes the "no extension point" gap; it does **not** by itself make
revocation durable. That is your responsibility to wire, or the hosted authority's
to provide.

```python
from vaid_mint import InMemoryRevocationList, ReferenceIssuer, RevocationStatus

class MyDurableRevocations:
    """Your own restart-surviving store (or a refreshed snapshot of one). It is
    handed the full ordered lineage, root first, and returns a three-state status —
    return UNAVAILABLE when the backing store cannot be reached, so verification
    fails closed rather than passing silently."""
    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        try:
            deny = load_deny_list()
        except StoreUnreachable:
            return RevocationStatus.UNAVAILABLE
        if any(vaid_id in deny for vaid_id in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED

# The injected check REPLACES the default store consulted at verification.
issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(MyDurableRevocations())

# Or wire the seam with the shipped in-memory list before a durable backend exists:
revocations = InMemoryRevocationList.initialised_empty()
issuer = ReferenceIssuer.ephemeral(1).with_revocation_check(revocations)
revocations.revoke(vaid["vaid_id"])
assert not issuer.verify_vaid(vaid)
```

**If you're running this in production, mitigate as follows:**

- **Mint short-lived VAIDs.** `vaid_ttl_hours` controls issuance TTL, and
  `DEFAULT_VAID_TTL_HOURS` (1h) is the recommended baseline. Expiry is now
  *enforced* at verification — an expired VAID hard-fails `verify_vaid`, not
  merely reported — so a short TTL is a real backstop that shrinks the exposure
  window for a leaked or compromised VAID even without durable revocation. Treat
  TTL as your primary control today.
- **Inject a durable `RevocationCheck`** (e.g. backed by a shared store or a
  periodically-refreshed snapshot of one) if you need revocation to survive
  restarts. The injected check is consulted *in addition to* the built-in
  in-memory set, so enabling it never disables existing behavior.
- **Or front the mint with a revocation-aware proxy or allowlist** — e.g. a
  sidecar or gateway that checks a durable deny-list before forwarding to
  `verify_vaid`.
- **Do not rely on the default configuration alone** for revocation guarantees
  that must survive a process restart.

The `RevocationCheck` seam mirrors the *injection style* of `AuthorizationGate`
and `AuditSink`, with one deliberate difference: its default is **not** an honest
no-op. For revocation, a no-op default would mean nothing is ever checked — a
silent functional regression, not a neutral "not wired yet" state — so the
reference keeps its working in-memory set as the default. A `NeverRevoked` no-op is
available as an explicit opt-in. The hosted product additionally offers a durable,
hash-chained revocation store; the open package now gives you the seam to plug your
own into.

### Unguarded defaults: authorization and delegation

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

This is the open engine of a HashiCorp-Vault-style split. KMS-backed kernel keys
and the **durable, hash-chained** audit-of-record are the closed managed
authority and are **not** here. The audit *seam* is here — `AuditSink`, with
`InMemoryAudit` and `NoopAudit` — so what is closed is the durable ledger, not
the ability to audit.
**Revocation is the seam worth naming plainly rather than filing under
"commercial":** as of 0.1.2 this package ships a pluggable `RevocationCheck` seam
— additive, with a non-durable in-memory default — and VAID expiry (TTL) is
hard-enforced at verification. What stays commercial is *durable* revocation
itself: a restart-surviving, hash-chained store. The package ships the seam, not
the durability.

| Concern | Here (open) | Hosted / commercial |
|---|---|---|
| Kernel signing key | ephemeral or caller/seed-supplied bytes | KMS-backed, rotated |
| Revocation | pluggable (`RevocationCheck`), in-memory default — see **Trust model** | durable, hash-chained |
| Expiry (TTL) | enforced at verification (hard reject) | enforced |
| Audit | in-memory / no-op sink | audit-of-record |
| Policy / mesh / federation | — | control plane |

`mint_root` is gated by an `AuthorizationGate` that defaults
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
is **not** byte-conformant against the managed authority's (still-moving) VAID
format.

## Install (local dev)

`vaid-mint` depends on `vaid-pop`. For a local checkout, install both editable:

```
pip install -e python/vaid-pop
pip install -e python/vaid-mint --no-deps
```

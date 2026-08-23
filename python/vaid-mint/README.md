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
restart-surviving backend via `ReferenceIssuer.with_revocation_backend`; what ships
*by default* is a non-durable in-memory store, so if the process restarts and you
have not wired a durable backend, previously revoked VAIDs may become revocable
again. The seam closes the "no extension point" gap; it does **not** by itself make
revocation durable. That is your responsibility to wire, or the hosted authority's
to provide.

**Durable revocation is two stores, not one.** Durable revocation *and* durable
lineage resolution are both host-application responsibilities. `RevocationCheck`
answers about an already-assembled lineage; `LineageStore` records every mint and
resolves ancestry, and a VAID's full ancestry is not recoverable from the document
itself. Persist only the revoked set and, after a restart, every **child** VAID
fails closed — its ancestry cannot be assembled, which is `UNAVAILABLE`, which
fails closed (R.4.2 / R.4.5) — while every **root** VAID keeps verifying, because
a root is trivially complete and never consults the resolver. The outage is total
for delegated credentials and invisible for root ones, appears at restart rather
than at deploy, and is first mistaken for a signing or clock problem.
`RevocationBackend` takes both halves and has no single-half constructor, so that
state cannot be reached by omitting an argument; pass `InMemoryLineageStore` as the
second half to say "in-memory lineage, deliberately". Make the resolver durable
first, or both in the same change — the revoked set first is the ordering that
produces the outage. `ReferenceIssuer.with_revocation_check` replaced only one half
and was **removed in 0.8.0** for this reason.

**Since 0.8.0 the default fails closed.** A bare `ReferenceIssuer`'s revocation store
is *absent* — never populated, so it reports `UNAVAILABLE` and `verify_vaid` returns
`False` until state is loaded. Until 0.8.0 the default vouched `NOT_REVOKED` over an
empty set, which is a fail-open posture and, being non-durable, could not detect its
own restart. R.4.5 requires that fail-open never be the default and always be named;
`ReferenceIssuer.assuming_nothing_revoked()` is that name. Minting, attenuation and
`verify_vaid_authenticity` are unchanged.

```python
from vaid_mint import (
    InMemoryLineageStore,
    InMemoryRevocationList,
    ReferenceIssuer,
    RevocationBackend,
    RevocationStatus,
)

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

# The injected backend REPLACES BOTH default stores consulted at verification. Both
# halves are required: MyDurableLineage records every mint and resolves ancestry
# across a restart (see `LineageStore`), and without it every CHILD VAID would fail
# closed after a restart while every root kept verifying.
issuer = ReferenceIssuer.ephemeral(1).with_revocation_backend(
    RevocationBackend(check=MyDurableRevocations(), lineage=MyDurableLineage())
)

# Or wire the seam with the shipped in-memory stores before a durable backend
# exists. Naming InMemoryLineageStore is how you say "in-memory lineage,
# deliberately" — this issuer does not survive a restart, and nothing pretends it does.
revocations = InMemoryRevocationList.assume_nothing_revoked()
issuer = ReferenceIssuer.ephemeral(1).with_revocation_backend(
    RevocationBackend(check=revocations, lineage=InMemoryLineageStore())
)

# Shorthand for exactly the pre-0.8.0 posture — a vouching in-memory revoked set and
# an in-memory lineage store. Same fail-open behaviour; the difference is the name.
dev = ReferenceIssuer.ephemeral(1).assuming_nothing_revoked()
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
  restarts. It *replaces* the default store consulted at verification, and should
  return `RevocationStatus.UNAVAILABLE` when its backing store is unreachable —
  verification then fails closed.
- **Or front the mint with a revocation-aware proxy or allowlist** — e.g. a
  sidecar or gateway that checks a durable deny-list before forwarding to
  `verify_vaid`.
- **Do not rely on the default configuration alone** for revocation guarantees
  that must survive a process restart.

The default store, `InMemoryRevocationList.assume_nothing_revoked()`, is named for
its posture, not its state: it vouches `NOT_REVOKED` over an empty set and, being
non-durable, **cannot detect its own restart** — after a restart it is
reconstructed empty and again vouches clean, so a VAID revoked before the restart
verifies clean. That is a fail-*open* posture reached by assumption. The two safe
alternatives are to inject a durable `RevocationCheck`, or to hold the store in
absent state (the default `InMemoryRevocationList()` constructor, which reports
`UNAVAILABLE` and so fails closed) until you have re-loaded revocation state into
it. The hosted product additionally offers a durable, hash-chained revocation
store; the open package gives you the seam to plug your own into.

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

# `assuming_nothing_revoked()` is the pre-0.8.0 default, asked for BY NAME. Since
# 0.8.0 a bare issuer's revocation store is ABSENT: it reports UNAVAILABLE and
# `verify_vaid` fails closed until revocation state is loaded (R.4.5). This is a
# fail-OPEN posture — fine for a quickstart with no revocation store, and it does not
# survive a restart. For anything that must, use `with_revocation_backend`.
issuer = ReferenceIssuer.ephemeral(24).assuming_nothing_revoked()
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
"commercial":** as of 0.2.0 this package ships a three-state, lineage-aware
`RevocationCheck` seam (spec R.4), with a non-durable in-memory default, and VAID
expiry (TTL) is hard-enforced at verification. What stays commercial is *durable*
revocation itself: a restart-surviving, hash-chained store. The package ships the seam, not
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

## Install

From PyPI (pulls `vaid-pop`, `cryptography`, `rfc8785` automatically):

```
pip install vaid-mint
```

**Local dev only** — from a repo checkout, install both editable:

```
pip install -e python/vaid-pop
pip install -e python/vaid-mint --no-deps
```

`--no-deps` is used **only** here, and only because `vaid-pop` was just installed
editable from the same checkout on the line above — without it, pip would fetch the
published `vaid-pop` from PyPI and shadow your local one. Do **not** use `--no-deps`
with the PyPI install above; there you want pip to resolve the dependencies.

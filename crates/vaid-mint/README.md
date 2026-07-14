# vaid-mint

The open, self-hostable **reference mint** for the VAID (Verifiable Agent
Identity) standard. It does two things:

- **`mint_root`** — mint a root (or operator) VAID. Bring-your-own-key with a
  verified proof-of-possession, or generate-and-discard.
- **`mint_child`** — **attenuated delegation**: an authenticated parent VAID
  mints a child whose authority is always a *subset* of its own
  (`child ⊆ parent`), verified fail-closed at mint time.

## Trust model — read this before using the mint

| Concern | Reference mint (this crate) | Hosted / commercial |
|---|---|---|
| Revocation | Pluggable (`RevocationCheck`); default is in-memory, non-durable | Durable, hash-chained |
| Expiry (TTL) | Enforced at verification (hard reject) | Enforced |
| Auth | Pluggable (`AuthorizationGate`) | Pluggable |
| Audit | Pluggable (`AuditSink`) | Pluggable |

**Revocation now has a pluggable seam, but the shipped default is still
non-durable.** As of 0.1.2 there is a `RevocationCheck` trait: a
self-hoster can inject their own durable, restart-surviving backend via
`ReferenceIssuer::with_revocation_check` without patching the crate. What
ships *by default*, however, is still the concrete in-memory revoked set
— it does not survive a restart. If the mint process restarts and you
have not wired a durable `RevocationCheck`, previously revoked VAIDs are
revocable again. The seam closes the "no extension point" gap; it does
**not** by itself make revocation durable. That is your responsibility to
wire, or the hosted authority's to provide.

**If you're running this in production, mitigate as follows:**

- **Mint short-lived VAIDs.** `vaid_ttl_hours` controls issuance TTL, and
  `DEFAULT_VAID_TTL_HOURS` (1h) is the recommended baseline. Expiry is now
  *enforced* at verification — an expired VAID hard-fails `verify_vaid`,
  not merely reported — so a short TTL is a real backstop that shrinks the
  exposure window for a leaked or compromised VAID even without durable
  revocation. Treat TTL as your primary control today.
- **Inject a durable `RevocationCheck`** (e.g. backed by a shared store or
  a periodically-refreshed snapshot of one) if you need revocation to
  survive restarts. The injected check is consulted *in addition to* the
  built-in in-memory set, so enabling it never disables existing behavior.
- **Or front the mint with a revocation-aware proxy or allowlist** — e.g.
  a sidecar or gateway that checks a durable deny-list before forwarding
  to `verify_vaid`.
- **Do not rely on the default configuration alone** for revocation
  guarantees that must survive a process restart.

The `RevocationCheck` seam mirrors the *injection style* of
`AuthorizationGate` and `AuditSink`, with one deliberate difference: its
default is **not** an honest no-op. For revocation, a no-op default would
mean nothing is ever checked — a silent functional regression, not a
neutral "not wired yet" state — so the reference keeps its working
in-memory set as the default. A `NeverRevoked` no-op is available as an
explicit opt-in. The hosted product additionally offers a durable,
hash-chained revocation store; the open crate now gives you the seam to
plug your own into.

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
honest defaults of a self-hostable reference mint. See the sections below (and the
`AuthorizationGate` / attenuation notes) for where each is enforced in code.

## The split (why this is only the engine)

This crate is the open half of a HashiCorp-Vault-style split: the mint *logic* is
open and self-hostable. A hosted authority layers durable, operational hardening
on top — KMS-backed kernel keys, an audit-of-record, a durable hash-chained
revocation store, and a policy/mesh/federation control plane. Of these,
revocation *durability* is the one with production impact for self-hosters today:
the crate provides a `RevocationCheck` seam, but the shipped default is in-memory
and non-durable. See the **Trust model** section above for how to mitigate it.

| Concern | Here (open) | Hosted / commercial |
|---|---|---|
| Kernel signing key | ephemeral or caller-supplied bytes | KMS-backed, rotated |
| Revocation | pluggable (`RevocationCheck`), in-memory default — see **Trust model** | durable, hash-chained |
| Audit | in-memory / no-op sink | audit-of-record |
| Policy / mesh / federation | — | control plane |

### `mint_root` has no authorization gate by default

`mint_root` is gated by an explicit **`AuthorizationGate` seam that defaults to
`PermitAll`** — mirroring how `AuditSink` defaults to an in-memory/no-op sink.
This is a **reference-implementation choice, not a security recommendation**:
with `PermitAll` in place, anyone who can reach the mint can issue a root VAID.
Production deployments should supply a real gate via
`MintService::with_authorization(issuer, audit, gate)`. The gap is made *visible
as a seam* rather than silently absent.

`mint_child` is intentionally **ungated because attenuation *is* the
authorization**: any holder of a valid parent VAID can mint children from it, and
a child can only *narrow* scope/capabilities relative to that parent, never widen
(`child ⊆ parent`). This means **possession of a parent VAID is itself the
authorization boundary for delegation** in this reference implementation — anyone
relying on it should treat parent-VAID custody with the same care as a
credential.

## Attenuation, precisely

`mint_child` denies unless **all** hold, checked before any key work or nonce is
consumed:

1. a verified parent VAID is present (no parent in context → deny);
2. the child's tenant equals the **verified** parent's tenant (no cross-tenant);
3. the child's `parent_vaid` equals the **authenticated** parent's id (no forged
   lineage);
4. every child scope entry is within the parent's scope (`is_in_scope`, with an
   empty-child guard: empty child scope = ⊤ is allowed only under an empty/⊤
   parent);
5. every child capability is held by the parent (`has_capability`);
6. the child proves possession of its BYO key.

Scope and capabilities use the **single** matchers on the VAID document, so
mint-time containment and any runtime check cannot drift.

## Reuse, not reimplementation

Proof-of-possession reuses the `vaid-pop` primitive verbatim (RFC 8785 JCS →
SHA-256 → Ed25519); the VAID identity newtypes are the same ones the per-request
PoP payload binds. The VAID-document canonicalizer applies the identical JCS
discipline to the whole signed document.

## Self-consistent, not cross-repo-conformant

This is an **independent** reference implementation. Its VAID document shape is
self-consistent within this repo and is **not** pinned byte-for-byte against the
managed authority's (still-moving) VAID format. The forthcoming frozen mint vector
proves only that this repo's Rust and (planned) Python minters agree with each
other.

## Status

Rust + Python reference complete (`mint_root` + `mint_child`, incl. the
`AuthorizationGate`/`PermitAll` seam). Byte-identity of the signed VAID document
across both languages is locked by the frozen `mint_v1.json` vector (Rust
`tests/mint_conformance.rs` and Python `vaid_mint/conformance.py` both reproduce
it; a CI drift-check enforces the two vendored copies are identical). Self-consistent
within this repo per Decision B — not conformant against the closed VAID format.

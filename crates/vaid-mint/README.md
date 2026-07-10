# vaid-mint

The open, self-hostable **reference mint** for the VAID (Verifiable Agent
Identity) standard. It does two things:

- **`mint_root`** — mint a root (or operator) VAID. Bring-your-own-key with a
  verified proof-of-possession, or generate-and-discard.
- **`mint_child`** — **attenuated delegation**: an authenticated parent VAID
  mints a child whose authority is always a *subset* of its own
  (`child ⊆ parent`), verified fail-closed at mint time.

## The split (why this is only the engine)

This is the open half of a HashiCorp-Vault-style split. The mint *logic* is open
and runnable by anyone. The **managed authority** — durable hash-chained
revocation, KMS-backed kernel keys, and the audit-of-record — is the closed
commercial product and deliberately lives outside this crate.

| Concern | Here (open) | Closed managed authority |
|---|---|---|
| Kernel signing key | ephemeral or caller-supplied bytes | KMS-backed, rotated |
| Revocation | in-memory, non-durable | durable, hash-chained |
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
closed substrate's (still-moving) VAID format. The forthcoming frozen mint vector
proves only that this repo's Rust and (planned) Python minters agree with each
other.

## Status

Rust + Python reference complete (`mint_root` + `mint_child`, incl. the
`AuthorizationGate`/`PermitAll` seam). Byte-identity of the signed VAID document
across both languages is locked by the frozen `mint_v1.json` vector (Rust
`tests/mint_conformance.rs` and Python `vaid_mint/conformance.py` both reproduce
it; a CI drift-check enforces the two vendored copies are identical). Self-consistent
within this repo per Decision B — not conformant against the closed VAID format.

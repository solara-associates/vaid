# vaid-mint (TypeScript)

The TypeScript mirror of the Rust `vaid-mint` crate: the open, self-hostable
**reference mint** for the [VAID](https://github.com/solara-associates/vaid)
(Verifiable Agent Identity) standard.

- **`mintRoot`** — mint a root/operator VAID (BYO-key with proof-of-possession,
  or generate-and-discard), gated by an explicit `AuthorizationGate`.
- **`mintChild`** — **attenuated delegation**: an authenticated parent mints a
  child whose authority is always a subset of its own (`child ⊆ parent`).
- **`verifyVaidAuthenticity`** — confirm a document is real from the issuer's
  **public key alone**: no issuer instance, no private key.

## Install

```
npm install vaid-mint
```

(From a repo checkout: `cd typescript && npm install && npm run build --workspaces`.)

ESM only, and typed. Node ≥ 20.19; CommonJS consumers on that version can
`require('vaid-mint')` via `require(esm)`.

```ts
import { InMemoryAudit, MintService, ReferenceIssuer } from 'vaid-mint';

const issuer = ReferenceIssuer.ephemeral(24);
const mint = new MintService(issuer, new InMemoryAudit());

const { vaid } = await mint.mintRoot({
  seed: {
    agentClass: 'orchestrator',
    version: '1.0.0',
    tenantId: 'acme',
    scopeBoundary: ['data.acme'],
    capabilitySet: ['read'],
  },
});

issuer.verifyVaid(vaid); // true
```

## Trust model — read this before using the mint

| Concern | Reference mint (this package) | Hosted / commercial |
|---|---|---|
| Revocation | Pluggable, three-state & lineage-aware (`RevocationCheck`); default in-memory, non-durable | Durable, hash-chained |
| Expiry (TTL) | Enforced at verification (hard reject) | Enforced |
| Auth | Pluggable (`AuthorizationGate`) | Pluggable |
| Audit | Pluggable (`AuditSink`) | Pluggable |

**Revocation is a three-state, lineage-aware seam; the shipped default is
non-durable.** Per
[`docs/spec/revocation.md`](https://github.com/solara-associates/vaid/blob/main/docs/spec/revocation.md)
R.4, the verifier assembles the VAID's ordered ancestry and hands it to
`RevocationCheck.checkLineage`, which returns `NotRevoked`, `Revoked`, or
`Unavailable`. A VAID is revoked if **any** ancestor is (revoking a parent
revokes its children), and verification **fails closed** on `Unavailable` — an
incomplete lineage (e.g. an empty resolver after restart) or an unreachable store
rejects rather than silently passing. There is no fail-open option here.

Inject your own durable, restart-surviving backend via
`ReferenceIssuer.withRevocationCheck`. What ships *by default* is a non-durable
in-memory store, so if the process restarts and you have not wired a durable
backend, previously revoked VAIDs become verifiable again. The seam closes the
"no extension point" gap; it does **not** by itself make revocation durable.

```ts
import { InMemoryRevocationList, ReferenceIssuer, RevocationStatus } from 'vaid-mint';

// Your own restart-surviving store. It is handed the full ordered lineage, root
// first, and returns a three-state status — return Unavailable when the backing
// store cannot be reached, so verification fails closed rather than passing.
const durable = {
  checkLineage(lineage: readonly string[]): RevocationStatus {
    let denyList: Set<string>;
    try {
      denyList = loadDenyList();
    } catch {
      return RevocationStatus.Unavailable;
    }
    return lineage.some((id) => denyList.has(id))
      ? RevocationStatus.Revoked
      : RevocationStatus.NotRevoked;
  },
};

const issuer = ReferenceIssuer.ephemeral(1).withRevocationCheck(durable);

// Or wire the seam with the shipped in-memory list before a durable backend exists:
const revocations = InMemoryRevocationList.assumeNothingRevoked();
const dev = ReferenceIssuer.ephemeral(1).withRevocationCheck(revocations);
revocations.revoke(vaid.vaid_id);
dev.verifyVaid(vaid); // false
```

**If you are running this in production, mitigate as follows:**

- **Mint short-lived VAIDs.** `vaidTtlHours` controls issuance TTL, and expiry is
  a hard reject at verification. A short TTL bounds the exposure window of a
  leaked VAID — but TTL is *not* revocation (spec R.5); it closes the window on a
  schedule, never on demand.
- **Wire a durable `RevocationCheck`**, or hold the store absent until you have
  loaded revocation state into it. An absent store reports `Unavailable`, so
  verification fails closed until the load completes.
- **Supply a real `AuthorizationGate`.** The default is `PermitAll`: a
  reference-implementation choice, not a security recommendation. With it in
  place, anyone who can reach the mint can issue a root VAID.
- **Supply a real `AuditSink`.** The reference sinks are in-memory and no-op.

## Authenticity is not standing

`verifyVaidAuthenticity(kernelPublicKey, vaid)` answers *"was this genuinely
issued under this key, and is it internally consistent"* — the signature-scheme
version, the kernel Ed25519 signature over the canonical document, and
`lineage_hash` consistency. It deliberately does **not** check **expiry** and does
**not** consult **revocation**; those are *standing*, evaluated by the party
holding the relevant state (spec R.7). A `true` result means the VAID is real, not
that it is usable right now. Use `isExpired()` and `ReferenceIssuer.verifyVaid()`
(or your own `RevocationCheck`) for standing.

Third-party **attenuation** verification is out of scope in 0.2: per ADR-0003 the
leaf does not carry ancestor authority, so a third party cannot confirm from the
leaf alone that a child's authority is within its parent's.

## The firewall

Byte-identity of the signed VAID document with the Rust and Python mints is locked
by the vendored cross-language vector `vectors/mint_v1.json`. CI proves **Rust
output == Python output == TypeScript output == vector**, byte-for-byte.

```
npx vaid-mint-conformance      # exit 0 = PASS, 1 = BLOCKER
```

The document is **snake_case** (the Rust `Vaid` struct has no serde rename, unlike
the camelCase `RequestAuthPayload`), byte fields (`public_key_der`,
`kernel_signature`) are **arrays of numbers** (how Rust serializes `Vec<u8>`), and
`kernel_signature` is set to **null** — not removed — when canonicalizing for
signing, because a signature cannot cover its own value.

Per Decision B this proves self-consistency WITHIN this repo (Rust == Python ==
TypeScript); it is **not** byte-conformant against the managed authority's
(still-moving) VAID format.

## License

Apache-2.0. See [LICENSE](https://github.com/solara-associates/vaid/blob/main/LICENSE).

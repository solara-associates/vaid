# vaid-pop (TypeScript)

Canonical TypeScript proof-of-possession (PoP) request signing primitive for the
[VAID](https://github.com/solara-associates/vaid) standard.

This is the **single TypeScript definition** of the PoP signing contract: RFC 8785
(JCS) canonicalization, the per-request payload, the completion record, and the
Ed25519 sign/verify over the canonical digest. `vaid-mint` and `vaid-client` both
depend on it and never reimplement any of it.

```ts
import { canonicalRequestSigningBytes, signPayload, verifySignedPayload } from 'vaid-pop';

const payload = {
  vaidId: '11111111-1111-1111-1111-111111111111',
  method: 'POST',
  path: '/vaid/mint',
  bodySha256: 'e3b0c442…',
  tenantId: 'acme',
  timestamp: '2026-06-04T12:00:00Z',
  clientNonce: '0123456789abcdef0123456789abcdef',
};

const signature = signPayload(payload, agentPrivateSeed);   // raw 64 bytes
verifySignedPayload(payload, agentPublicKey, signature);    // true
```

If you want the HTTP transport (the four `x-synthera-*` headers), use
[`vaid-client`](https://www.npmjs.com/package/vaid-client), which builds on this.

## Install

```
npm install vaid-pop
```

(From a repo checkout: `cd typescript && npm install && npm run build --workspaces`.)

ESM only, and typed. It runs on Node ≥ 20.19, and — because the crypto comes from
`@noble/*` rather than `node:crypto` — in browsers, Deno, Bun, and edge runtimes
too. CommonJS consumers on Node ≥ 20.19 can `require('vaid-pop')` via
`require(esm)`.

## The firewall

Cross-language byte-identity is the whole point. The primitive is locked against
the frozen cross-language vectors (vendored here at `vectors/`), which the Rust
crates and the Python packages assert against too. CI proves **Rust output ==
Python output == TypeScript output == vector**, byte-for-byte. A mismatch is a
hard blocker, not a bug report.

Run the packaged firewall against your installed copy:

```
npx vaid-pop-conformance      # exit 0 = PASS, 1 = BLOCKER
```

Contract: RFC 8785 (JCS) over the camelCase payload → SHA-256 → 32-byte digest →
**pure Ed25519 over that digest as the raw message** → raw 64-byte signature.

### Two encoding facts that carry the contract

- **Payloads are camelCase.** `RequestAuthPayload` and `CompletionRecord` use
  camelCase field names, matching the Rust structs' `rename_all = "camelCase"`.
  JCS sorts keys, so declaration order is irrelevant — the *names* are not.
  (The VAID *document* in `vaid-mint` is the exception: it is snake_case.)
- **Timestamps are whole-second RFC 3339 `…Z`.** This is the chrono-serde fixed
  point: a whole-second `…Z` string parses and re-serializes to itself, so a
  client's signed timestamp matches the server's recomputation. Use
  `utcWholeSecondRfc3339()` — `Date.prototype.toISOString()` emits milliseconds
  and would put a sub-second component inside the signed bytes.

## What is in here

| Export | What it is |
|---|---|
| `canonicalize` / `canonicalizeToString` | RFC 8785 (JCS) serialization. Rejects values it cannot represent rather than coercing them — silently substituting a value inside signed bytes is the failure mode being prevented. |
| `canonicalRequestSigningBytes` | JCS → SHA-256. The 32-byte digest both sides derive. |
| `signPayload` / `verifySignedPayload` | Detached Ed25519 over that digest. Verification is a result (`false`), never a fault. |
| `RequestAuthPayload` | The seven fields a holder signs per request. |
| `CompletionRecord` / `AssuranceTier` | Signed statement that a VAID-authorized action finished. |
| `sha256` / `toHex` / `toBase64` / … | The byte helpers the wire format needs. |

## Scope of the completion record

`CompletionRecord` carries exactly **one** detached signature, by
`signerVaidId`. That proves "this signer signed this record" and nothing more, so
`assuranceTier` is **declared, not proven**:

- `selfReported` is the only tier this repo substantiates on its own.
- `counterSigned` and `thirdPartyAttested` are **not independently verifiable
  here.** A self-reporting signer can set either and the single signature still
  verifies. Treat them as unverified claims.

## License

Apache-2.0. See [LICENSE](https://github.com/solara-associates/vaid/blob/main/LICENSE).

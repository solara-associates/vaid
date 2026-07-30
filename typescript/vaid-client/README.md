# vaid-client (TypeScript)

The TypeScript request signer for the
[VAID](https://github.com/solara-associates/vaid) standard: assemble
`(method, path, body)` into the canonical proof-of-possession payload, sign it,
and emit the four `x-synthera-*` headers a conforming verifier checks.

```ts
import { RequestSigner, popHeaderRecord } from 'vaid-client';

const signer = new RequestSigner(vaidDocumentJson, agentPrivateSeed);
const headers = signer.signHeaders('POST', '/vaid/mint?tenant=acme', body);

await fetch(url, { method: 'POST', body, headers: popHeaderRecord(headers) });
```

> The `x-synthera-*` header names are the VAID wire contract — the fixed header
> namespace a conforming verifier reads, not a package dependency.

## Install

```
npm install vaid-client
```

(From a repo checkout: `cd typescript && npm install && npm run build --workspaces`.)

ESM only, and typed. Node ≥ 20.19; CommonJS consumers on that version can
`require('vaid-client')` via `require(esm)`.

## Two key custodies

| | Holder holds the key | Key stays in a keystore |
|---|---|---|
| Class | `RequestSigner` | `PortRequestSigner` |
| Takes | a raw 32-byte Ed25519 seed | an `OperatorSigningPort` |
| The key | in process | never leaves the keystore |

The port is handed the already-canonical **32-byte digest** — never the payload,
never the key. Both paths canonicalize through the same `vaid-pop` primitive, and
the conformance suite asserts they produce identical signatures.

```ts
import { PortRequestSigner, type OperatorSigningPort } from 'vaid-client';

const port: OperatorSigningPort = {
  async sign(digest) { return kms.signEd25519(keyId, digest); },
  async publicKey() { return kms.publicKey(keyId); },
};

const headers = await new PortRequestSigner(vaidDocumentJson, port)
  .signHeaders('POST', '/vaid/mint', body);
```

## The `path` convention — a security decision

The signed `path` is the **on-the-wire request target, including the query
string**, not path-only. Signing path-only would leave the query outside the
signature and therefore tamperable: `?limit=10` could be rewritten to
`?limit=1000000` under a signature that still verifies.

This is pinned by the frozen `pathquery_v1.json` vector, and the suite asserts
that signing path-only produces a *different* signature — so the convention
cannot quietly regress.

## Identity comes from the VAID, never from the caller

`vaidId` and `tenantId` are read out of the VAID document you construct the signer
with — they are not arguments to `signHeaders`. A caller can therefore only ever
produce a valid signature for its own tenant. Note that the document is
**snake_case** (`vaid_id`, `tenant_id`), unlike the camelCase signed payload; a
camelCase document is rejected at construction rather than silently mis-signed.

## The firewall

Byte-identity with the Rust and Python clients is locked by two vendored
cross-language vectors, `operator_pop_v1.json` and `pathquery_v1.json`. CI proves
**Rust output == Python output == TypeScript output == vector**, byte-for-byte. A
mismatch is a hard blocker.

```
npx vaid-client-conformance      # exit 0 = PASS, 1 = BLOCKER
```

Contract: RFC 8785 (JCS) over the camelCase `RequestAuthPayload` → SHA-256 →
32-byte digest → **pure Ed25519 over that digest as the raw message** → raw
64-byte signature, base64 in `x-synthera-signature`.

Timestamps are whole-second RFC 3339 `…Z` — the chrono-serde fixed point, so the
client's signed timestamp and the server's recomputation are the same string.

## License

Apache-2.0. See [LICENSE](https://github.com/solara-associates/vaid/blob/main/LICENSE).

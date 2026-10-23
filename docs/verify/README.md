# VAID verifier (standalone, browser-only)

A paste-and-verify page for VAID credentials. Runs entirely in the browser,
against the published `vaid-mint` npm package. Makes no network request except
"Fetch key from URL", and only when you click it.

## Develop

```
npm install
npm run generate-samples   # regenerate samples/*.json from vaid-mint (only needed if you change scripts/generate-samples.mjs)
npm run build               # bundles src/main.ts -> dist/bundle.js
npm run typecheck
```

Then open `index.html` directly, or serve the directory statically
(`python3 -m http.server`, or any static file server).

## Why this needed a small compatibility shim

`vaid-mint` 0.11.0 is published as a Node-first package: `issuerIdentity.ts`
calls `node:crypto`'s `createHash` and the global `Buffer`, even though its
sibling `vaid-pop` already ships a browser-safe SHA-256
(`@noble/hashes`) for exactly this reason. Neither call is reachable from a
browser without a shim.

`src/polyfills/node-crypto-shim.ts` and `src/polyfills/buffer-global.ts` cover
exactly the two calls `vaid-mint` makes (`createHash("sha256").update(..).digest()`
and `Buffer.from(..).toString("base64url")` / `Buffer.byteLength(.., "utf8")`).
No `vaid-mint` source is copied, forked, or modified; esbuild's `--alias` swaps
only the `node:crypto` import at bundle time, and the `Buffer` global is filled
in before any `vaid-mint` code runs.

This is a real gap in the published package, not a workaround to route around
silently: it should be reported upstream and `vaid-mint` should use
`vaid-pop`'s hash the way `document.ts` already does. See the PR description.

## "Check a Solara production credential"

A separate button from the four synthetic examples. On click, and only on
click, it fetches `https://solara.associates/.well-known/synthera-kernel-keys.json`
(Solara's published production trust anchor) and verifies a real credential
production actually minted (`samples/production-credential.json`, captured
read-only from the live `solara.associates/vaid/verify` page's own "LOAD A
REAL ONE" sample on 2026-10-21).

That credential is `sig_version: 3`; this package verifies `sig_version: 4`
only, so it correctly reports `Fail: Authenticity` with the reason "this page
does not recognize" that signature format, alongside `Fail: Expiry` (it is
also, genuinely, long past its `expires_at`). Both are real, honest findings
about the credential, not bugs in this page.

**Known limitation:** `solara.associates/.well-known/synthera-kernel-keys.json`
is not served with CORS headers, so this fetch only succeeds when this page is
hosted on the same origin as `solara.associates` (or the endpoint later adds
`Access-Control-Allow-Origin`). Elsewhere, the button fails gracefully with a
clear message. The fetch-and-verify logic itself is confirmed working against
a same-origin mirror of the real key file; only the cross-origin fetch is
host-dependent.

## Samples

`scripts/generate-samples.mjs` mints the four "Try an example" fixtures using
`vaid-mint` and `vaid-pop` directly (not `MintService`'s attenuation checks,
for the two negative cases that need an authentic-but-adversarial document,
the same technique `vaid-mint`'s own `test/chain_verification.test.ts` uses).
Output is committed under `samples/`, so the page needs no build step to show
them and makes no request to fetch them.

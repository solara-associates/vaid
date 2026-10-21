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

## Samples

`scripts/generate-samples.mjs` mints the four "Try an example" fixtures using
`vaid-mint` and `vaid-pop` directly (not `MintService`'s attenuation checks,
for the two negative cases that need an authentic-but-adversarial document,
the same technique `vaid-mint`'s own `test/chain_verification.test.ts` uses).
Output is committed under `samples/`, so the page needs no build step to show
them and makes no request to fetch them.

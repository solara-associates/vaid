# Backlog

Known defects and deferred work in this repository. Entries are numbered and never
renumbered, so a reference to `B1` in a commit or an issue stays valid.

An entry here is a defect that has been **observed**, not a wish. Each one records
what breaks, how it presents (which is often not how it is described), the shape
of the fix, and why it has not been done yet.

---

## B1 — `vaid-mint` depends on the ambient `Buffer` global, and cannot run in a browser

**Status:** open. Blocked by the release freeze — the fix touches frozen code.
**Observed:** 2026-08-10, building the public verify page at `/vaid/verify`.
**Affects:** `typescript/vaid-mint` (all published versions through 0.6.0).

### What breaks

`vaid-mint` reaches for two Node-only platform facilities on the **verification**
path — not in an optional corner, but in code every call to
`verifyVaidAuthenticity` executes:

| where | what | reached from |
|---|---|---|
| `issuerIdentity.ts` | `createHash('sha256')` from `node:crypto` | `kernelKeyThumbprint` |
| `issuerIdentity.ts` | `Buffer.from(bytes).toString('base64url')` | `kernelKeyThumbprint` |
| `issuerIdentity.ts` | `Buffer.byteLength(s, 'utf8')` ×2 | `isValidTrustDomain` |

`verifyVaidAuthenticity` calls `isValidTrustDomain` and then compares the
document's `kernel_key_thumbprint` against `kernelKeyThumbprint(key)`, so a
browser build reaches all three on the first verification it attempts.

**Nothing is unexported.** The VAID API is complete: a browser can verify a real
substrate-minted document against the published anchor using only what
`vaid-mint` exports. This is purely a runtime-environment dependency.

### Why it is worse than it sounds: it is invisible to bundlers

`node:crypto` is an *import*, so a bundler reports it and an alias fixes it.

`Buffer` is an **ambient global**. Nothing resolves it, so nothing complains. The
bundle builds clean, ships, and throws `Buffer is not defined` at the first
verification — in the browser, at runtime, in front of whoever is trying to check
a credential. No build-time check in any toolchain catches this. It was found by
an actual browser test and could not have been found any other way.

### This breaks a property `vaid-pop` deliberately holds

`typescript/vaid-pop/src/crypto.ts` carries the comment:

> *Written against `btoa` rather than `Buffer` so the packages stay
> runtime-neutral.*

`vaid-pop` is runtime-neutral on purpose. `vaid-mint` sits directly on top of it
and is not, which means the stated property does not survive one layer up — and
`vaid-mint` is the layer a third-party verifier actually calls.

### Fix shape

Substitute what is already in the dependency tree. No new dependency, and no new
SHA-256 — `@noble/hashes` is what the rest of the standard already hashes with via
`vaid-pop`.

- `Buffer.byteLength(s, 'utf8')` → `new TextEncoder().encode(s).length`
- `Buffer.from(bytes).toString('base64url')` → the base64url encoder that already
  exists in `vaid-pop`'s runtime-neutral `crypto.ts`, re-exported rather than
  rewritten
- `createHash('sha256')` → `sha256` from `@noble/hashes/sha2.js` (already a
  transitive dependency through `vaid-pop`)

All three are drop-in and byte-identical to what they replace. The conformance
vectors are what should prove that, not review.

**Add a browser guard to CI at the same time.** A source-level fix without one
leaves the same trap open: the next Node-only global added to this package will
also build clean and throw at runtime. A test that imports `vaid-mint` and
verifies the frozen vector in a real browser (or at minimum a `no-node-globals`
lint over `dist/`) is what makes the property hold rather than merely be true
today.

### Interim

`synthera-site-redesign` carries build-time shims at
`src/lib/node-crypto-browser-shim.mjs` and `src/lib/node-buffer-browser-shim.mjs`,
aliased in `astro.config.mjs`, with `tests/unit/shim-parity.test.mjs` asserting the
SHA-256 shim byte-identical to `node:crypto`. That is a workaround in one consumer;
it does not help anyone else who bundles `vaid-mint` for a browser, and they will
each rediscover this the same way.

A divergent shim is worth calling out as its own hazard: it does not crash. It
computes a *wrong thumbprint*, so every VAID is rejected as signed by an unknown
key, which reads like a trust-anchor failure and is not one. Hence the parity test.

---

## B2 — the release workflow cannot release `vaid-skill`

**Status:** FIXED 2026-08-10 by `release-map.json` + `scripts/verify-release-map.mjs`.
Three releases (0.1.0, 0.1.1, 0.1.2) were published **by hand** before the fix, and
so carry no provenance attestation; 0.1.3 is the first released through the
workflow. The history below is kept because the failure shape — deriving a
package's location from its ecosystem — is worth recognising again.

**Originally:** open. `vaid-skill@0.1.0` was published **by hand** on 2026-08-10.
**Observed:** 2026-08-10, preparing that release.
**Affects:** `.github/workflows/release.yml`.

### What breaks

`release.yml` resolves a tag to a directory by ecosystem alone:

```bash
case "$ECO" in
  rust)   DIR="crates/$PKG" ;;
  python) DIR="python/$PKG" ;;
  npm)    DIR="typescript/$PKG" ;;
esac
```

Every npm package is assumed to live at `typescript/<pkg>` and to be a member of
the `typescript` workspace — the publish step is
`npm publish --workspace <pkg> --prefix typescript`.

`vaid-skill` lives at `skill/`. It is deliberately not in the `typescript`
workspace: it depends on the **published** `vaid-mint` and `vaid-pop` from the
registry rather than on this repo's sources, so that it breaks when what users
actually install breaks, rather than when `main` moves. Being a workspace member
would resolve those dependencies locally and destroy that property.

So the tag `npm-vaid-skill-v0.1.0` resolves to `typescript/vaid-skill`, which does
not exist, and the workflow exits at the resolve step:

```
::error::Tag 'npm-vaid-skill-v0.1.0' resolves to 'typescript/vaid-skill', which does not exist.
```

That is a correct refusal — the workflow declines rather than publishing something
wrong — but the consequence is that this package has no automated release path.

### Why the by-hand publish is a real cost, not a formality

`release.yml` is not just a convenience. Its preflight re-runs the repo's own
verifiers *on the tagged commit* precisely because "a tag can point anywhere", and
its `release-complete` job uses `if: always()` so a partial publish exits
non-zero. A manual `npm publish` has none of that: no manifest-equals-tag check,
no self-consistency check, no post-publish verification that what landed on the
registry is what was tagged.

For 0.1.0 those were run by hand and recorded — the published tarball's
`dist.shasum` `7c80c898…` was confirmed to reproduce exactly from `npm pack` at
`b5e4f10`, and a clean install from the registry was exercised end to end. That is
evidence for one release, not a property of the next one.

### Fix shape

Make the directory a property of the package rather than of the ecosystem. Either:

- a small `release-map.json` at the repo root mapping `<eco>/<pkg>` → directory,
  read by the resolve step, so a package in a new location is one entry rather
  than a workflow edit; **or**
- keep the `case` but let `npm` fall back to `skill/$PKG`-style lookup by scanning
  known roots for a `package.json` whose `name` matches `$PKG` — the manifest
  already states the name, so nothing new has to be kept in step.

The publish step also needs to stop assuming `--workspace`/`--prefix typescript`
and publish from the resolved directory. Both changes are contained; neither
touches frozen code.

### What was done

The first option. `release-map.json` declares, per package: its directory, whether
it is an npm workspace member, and how a consumer verifies the published artifact.
`resolve` reads it instead of a `case` on the ecosystem, and refuses a tag naming a
package that is not in it — or an npm package that declares no way to be verified,
because a published artifact nobody checks is not a release.

`publish` no longer assumes `--workspace`/`--prefix typescript`: a workspace member
publishes through its root, a standalone package publishes from its own directory.
`verify-artifact` no longer assumes a `<pkg>-conformance` binary, which `vaid-skill`
does not ship — it implements no cryptography, so the byte-identity a firewall would
assert belongs to `vaid-mint`. What is worth proving for it is that the documented
commands run from what a stranger installs, and that is what its `verify_cmd` does.

`scripts/verify-release-map.mjs` keeps the map from becoming the next instance of
this bug. It asserts both directions — every entry resolves to the package it names,
and every publishable package found **in the tree** has an entry — because a list of
things to check cannot notice something that was never added to it. It runs in CI, so
a missing entry fails in the PR that adds the package rather than at tag time, after
a bump and a changelog. Control-tested against all three failure shapes.
